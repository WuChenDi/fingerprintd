import { env, SELF } from 'cloudflare:test'
import { beforeEach, describe, expect, it } from 'vitest'
import { D1FingerprintStore } from '../src/fingerprint-store-d1'
import { DurableNonceStore } from '../src/nonce-do'
import type { ScoreOutcome } from '../src/types'

// The PCF4 state layer against the real runtime: the nonce Durable Object burns
// atomically, and the D1 store recalls + drifts templates. These run in
// workerd/miniflare with the wrangler.toml bindings live — no fakes.

/** A minimal ScoreOutcome for a given decision + id (the fields persist reads). */
function outcome(
  decision: ScoreOutcome['decision'],
  visitorId: string,
): ScoreOutcome {
  return {
    visitor_id: visitorId,
    is_new_device: decision === 'new_device',
    decision,
    confidence: 0.9,
    score: decision === 'new_device' ? null : 20,
    compared_components: 4,
    collision_risk: false,
  }
}

/** Empty the D1 tables so each test starts clean (isolated storage also resets,
 *  but this keeps the intent explicit and order-independent). */
beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM blocking_index'),
    env.DB.prepare('DELETE FROM templates'),
  ])
})

describe('nonce Durable Object (atomic burn)', () => {
  it('issues a nonce, admits it once, then rejects the replay', async () => {
    const store = new DurableNonceStore(env.NONCE, 30)
    const { nonce, ttlSecs } = await store.issue()
    expect(typeof nonce).toBe('string')
    expect(ttlSecs).toBe(30)

    // First consume burns it; the replay finds nothing.
    expect(await store.consume(nonce)).toBe('valid')
    expect(await store.consume(nonce)).toBe('unknown')
  })

  it('rejects a never-issued nonce as unknown', async () => {
    const store = new DurableNonceStore(env.NONCE, 30)
    expect(await store.consume('never-issued')).toBe('unknown')
  })

  it('reports an elapsed TTL as expired, still burning the nonce', async () => {
    // ttl 0 ⇒ the record expires immediately; a later consume (a separate DO
    // invocation, so time has advanced) sees it past expiry.
    const store = new DurableNonceStore(env.NONCE, 0)
    const { nonce } = await store.issue()
    expect(await store.consume(nonce)).toBe('expired')
    // Expired nonces are still removed, so a retry is unknown, not re-expired.
    expect(await store.consume(nonce)).toBe('unknown')
  })
})

describe('D1 fingerprint store (recall + drift)', () => {
  it('recalls nothing for empty or unknown keys', async () => {
    const store = new D1FingerprintStore(env.DB)
    expect(await store.recall([])).toEqual([])
    expect(await store.recall(['no-such-key'])).toEqual([])
  })

  it('persists a new device and recalls it by any of its keys', async () => {
    const store = new D1FingerprintStore(env.DB)
    const components = { platform: 'Linux', webgl: 'Intel' }
    await store.persist(
      outcome('new_device', 'v1'),
      components,
      ['k1', 'k2'],
      1000,
    )

    const byK1 = await store.recall(['k1'])
    expect(byK1).toEqual([{ visitor_id: 'v1', components }])
    // A visitor matched by several supplied keys is returned once.
    expect(await store.recall(['k1', 'k2'])).toHaveLength(1)
  })

  it('drifts a matched template: overwrites present, retains absent, adds keys', async () => {
    const store = new D1FingerprintStore(env.DB)
    await store.persist(
      outcome('new_device', 'v1'),
      { platform: 'Linux', user_agent: 'Chrome/120' },
      ['k1'],
      1000,
    )

    // A later observation upgrades the UA and adds a font; platform is absent
    // here and must be retained. A fresh blocking key extends recall.
    await store.persist(
      outcome('match', 'v1'),
      { user_agent: 'Chrome/121', fonts: ['Arial'] },
      ['k2'],
      2000,
    )

    const [candidate] = await store.recall(['k1'])
    expect(candidate).toEqual({
      visitor_id: 'v1',
      components: {
        platform: 'Linux', // retained (absent from the drift observation)
        user_agent: 'Chrome/121', // overwritten
        fonts: ['Arial'], // added
      },
    })
    // The drift indexed k2 under the same visitor.
    expect(await store.recall(['k2'])).toEqual([candidate])
  })

  it('does not write on a review verdict (anti-poisoning)', async () => {
    const store = new D1FingerprintStore(env.DB)
    await store.persist(
      outcome('review', 'v9'),
      { platform: 'Linux' },
      ['k9'],
      1000,
    )
    expect(await store.recall(['k9'])).toEqual([])
  })
})

describe('end-to-end through the Worker (WASM + DO + D1)', () => {
  /** A rich probe the fuzzy engine can score into a confident match. */
  const probe = {
    webgl: 'ANGLE (Intel)',
    platform: 'Linux x86_64',
    timezone: 'Asia/Shanghai',
    audio: '124.04',
    cpu_cores: 8,
    device_memory: 8,
    fonts: ['Arial', 'Helvetica', 'Courier', 'Times', 'Verdana'],
    user_agent: 'Chrome/120',
  }

  async function identify(components: unknown): Promise<{
    status: number
    body: { visitorId: string; is_new_device: boolean; decision: string }
  }> {
    const challenge = await SELF.fetch('https://edge.test/challenge')
    const { nonce } = (await challenge.json()) as { nonce: string }
    const resp = await SELF.fetch('https://edge.test/identify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ nonce, stable_components: components }),
    })
    return { status: resp.status, body: (await resp.json()) as never }
  }

  it('records a device on first sight and re-identifies it on the second', async () => {
    const first = await identify(probe)
    expect(first.status).toBe(200)
    expect(first.body.is_new_device).toBe(true)
    expect(first.body.decision).toBe('new_device')

    // The same device returns: recalled from D1, scored a match, same id.
    const second = await identify(probe)
    expect(second.status).toBe(200)
    expect(second.body.is_new_device).toBe(false)
    expect(second.body.decision).toBe('match')
    expect(second.body.visitorId).toBe(first.body.visitorId)
  })

  it('burns the nonce across the real Durable Object', async () => {
    const challenge = await SELF.fetch('https://edge.test/challenge')
    const { nonce } = (await challenge.json()) as { nonce: string }
    const send = () =>
      SELF.fetch('https://edge.test/identify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ nonce, stable_components: probe }),
      })
    expect((await send()).status).toBe(200)
    // Replaying the same nonce is rejected: the DO already burned it.
    expect((await send()).status).toBe(401)
  })
})
