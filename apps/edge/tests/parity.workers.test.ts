import { env, SELF } from 'cloudflare:test'
import { beforeEach, describe, expect, it } from 'vitest'
import type { IdentifyResponse } from '../src/lib/types'
import parityFixture from './fixtures/parity.json'

// Edge half of the cross-stack parity proof.
//
// This drives the SAME `fixtures/parity.json` vectors as the native Rust test
// (`crates/fingerprintd/tests/parity.rs`) through the full edge stack — the WASM
// engine, the nonce Durable Object, and the D1 candidate index — in real
// workerd/miniflare. Both stacks assert the SAME committed `expect` block, so
// "Worker == native" holds field-by-field: visitorId, decision, is_new_device,
// collision_risk, and confidence (to the fixture's floating-point tolerance).
//
// The determinism hinges on the salt: `vitest.workers.config.ts` binds
// `FP_SALT_SECRET` to the fixture's `salt_secret` (asserted below), so the edge
// derives the same blocking keys and stored hashes the native reference did.

/** The parity assertion for one `/identify` step (mirrors the Rust `Expect`). */
interface Expect {
  decision: IdentifyResponse['decision']
  is_new_device: boolean
  /** Symbolic visitor label, asserted stable across the steps that share it. */
  visitor: string
  /** Absolute derived id, pinned on the step that first mints the visitor. */
  visitor_id?: string
  collision_risk: boolean
  confidence: number
}

interface Step {
  input: string
  expect: Expect
}

interface Scenario {
  name: string
  steps: Step[]
}

interface ParityFixture {
  salt_secret: string
  confidence_tolerance: number
  components: Record<string, Record<string, unknown>>
  scenarios: Scenario[]
}

const fixture = parityFixture as ParityFixture

/** Run one `/identify` against the real Worker: fresh nonce, then score. */
async function identify(
  components: Record<string, unknown>,
): Promise<{ status: number; body: IdentifyResponse }> {
  const challenge = await SELF.fetch('https://edge.test/challenge')
  const { nonce } = (await challenge.json()) as { nonce: string }
  const resp = await SELF.fetch('https://edge.test/identify', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ nonce, stable_components: components }),
  })
  return { status: resp.status, body: (await resp.json()) as IdentifyResponse }
}

// Storage isolation is per test FILE in pool-workers 0.18 (not per test), so
// reset the D1 store before each scenario — matching the fresh
// `FuzzyStore::deterministic` the native test builds per scenario.
beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM blocking_index'),
    env.DB.prepare('DELETE FROM templates'),
  ])
})

describe('cross-stack parity (Worker == native)', () => {
  // Guard the coupling: the deterministic salt the Worker runs with MUST be the
  // one the native reference used, or the vectors are not comparable.
  it('runs with the salt the fixture was generated under', () => {
    expect(env.FP_SALT_SECRET).toBe(fixture.salt_secret)
  })

  // Each scenario is an independent `it`: `beforeEach` empties the D1 store so
  // it starts fresh — matching the fresh `FuzzyStore::deterministic` the native
  // test builds per scenario.
  for (const scenario of fixture.scenarios) {
    it(scenario.name, async () => {
      const resolved = new Map<string, string>()

      for (const [i, step] of scenario.steps.entries()) {
        const components = fixture.components[step.input]
        expect(components, `component input ${step.input}`).toBeDefined()
        if (components === undefined) return

        const { status, body } = await identify(components)
        const e = step.expect

        expect(status, `status @ step ${i}`).toBe(200)
        expect(body.decision, `decision @ step ${i}`).toBe(e.decision)
        expect(body.is_new_device, `is_new_device @ step ${i}`).toBe(
          e.is_new_device,
        )
        expect(body.collision_risk, `collision_risk @ step ${i}`).toBe(
          e.collision_risk,
        )
        expect(
          Math.abs(body.confidence - e.confidence),
          `confidence @ step ${i}: got ${body.confidence}, expected ${e.confidence}`,
        ).toBeLessThanOrEqual(fixture.confidence_tolerance)

        // Absolute id pin (present on the step that mints the visitor).
        if (e.visitor_id !== undefined) {
          expect(body.visitorId, `visitor_id @ step ${i}`).toBe(e.visitor_id)
        }
        // Symbolic-label stability: steps sharing a visitor resolve to one id.
        const seen = resolved.get(e.visitor)
        if (seen === undefined) {
          resolved.set(e.visitor, body.visitorId)
        } else {
          expect(
            body.visitorId,
            `visitor '${e.visitor}' stable @ step ${i}`,
          ).toBe(seen)
        }
      }
    })
  }
})
