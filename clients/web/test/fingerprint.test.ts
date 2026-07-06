/**
 * Unit tests for the STABLE-half collector. There is NO headless browser here,
 * so FingerprintJS/BotD are MOCKED: we inject fake loaders (and, once, mock the
 * modules themselves) and assert the WIRING, never real fingerprint values.
 *
 * Contract under test (PRD §4.1 / §4.4):
 *  - raw FingerprintJS components are passed through into `stable_components`;
 *  - the FingerprintJS `visitorId`/hash is DISCARDED (never in the payload);
 *  - BotD detection + signals are present under `stable_components.botd`;
 *  - NO `challenge_response`/`probe` is emitted by this half.
 */

import { describe, expect, it, vi } from 'vitest'
import type { BotdDetector, FingerprintAgent } from '../src/fingerprint'
import { createFingerprintCollector } from '../src/fingerprint'
import { sampleChallenge } from './helpers'

/** A fake FingerprintJS agent returning canned components + a hash to discard. */
function fakeFingerprint(
  components: Record<string, unknown>,
  visitorId = 'HASH_SHOULD_BE_DISCARDED',
): () => Promise<FingerprintAgent> {
  return () =>
    Promise.resolve({ get: () => Promise.resolve({ visitorId, components }) })
}

/** A fake BotD detector recording call order and returning canned signals. */
function fakeBotd(
  detection: unknown,
  signals: unknown,
  order: string[] = [],
): () => Promise<BotdDetector> {
  return () =>
    Promise.resolve({
      collect: () => {
        order.push('collect')
        return Promise.resolve(undefined)
      },
      detect: () => {
        order.push('detect')
        return detection
      },
      getComponents: () => {
        order.push('getComponents')
        return signals
      },
    })
}

describe('createFingerprintCollector', () => {
  it('passes raw FingerprintJS components through into stable_components', async () => {
    const components = {
      fonts: { value: ['Arial'], duration: 3 },
      timezone: { value: 'UTC', duration: 1 },
    }
    const collect = createFingerprintCollector({
      loadFingerprint: fakeFingerprint(components),
      loadBotd: fakeBotd({ bot: false }, { webdriver: false }),
    })

    const { stable_components } = await collect(sampleChallenge())

    expect(stable_components.fonts).toEqual({ value: ['Arial'], duration: 3 })
    expect(stable_components.timezone).toEqual({ value: 'UTC', duration: 1 })
  })

  it('DISCARDS the FingerprintJS visitorId/hash (never in the payload)', async () => {
    const collect = createFingerprintCollector({
      loadFingerprint: fakeFingerprint({ ua: { value: 'x' } }, 'v_client_side'),
      loadBotd: fakeBotd({ bot: false }, {}),
    })

    const { stable_components } = await collect(sampleChallenge())

    expect(stable_components.visitorId).toBeUndefined()
    expect(stable_components.visitor_id).toBeUndefined()
    expect(stable_components.hash).toBeUndefined()
    expect(JSON.stringify(stable_components)).not.toContain('v_client_side')
  })

  it('merges BotD detection + signals under a botd sub-object', async () => {
    const detection = { bot: true, botKind: 'headless_chrome' }
    const signals = {
      webdriver: { value: true },
      languages: { value: [['en']] },
    }
    const order: string[] = []
    const collect = createFingerprintCollector({
      loadFingerprint: fakeFingerprint({ ua: { value: 'x' } }),
      loadBotd: fakeBotd(detection, signals, order),
    })

    const { stable_components } = await collect(sampleChallenge())

    expect(stable_components.botd).toEqual({ detection, signals })
    // detect()/getComponents() must run only after collect() gathered sources.
    expect(order).toEqual(['collect', 'detect', 'getComponents'])
  })

  it('emits ONLY stable_components — no challenge_response or probe', async () => {
    const collect = createFingerprintCollector({
      loadFingerprint: fakeFingerprint({ ua: { value: 'x' } }),
      loadBotd: fakeBotd({ bot: false }, {}),
    })

    const collected = await collect(sampleChallenge())

    expect(collected.challenge_response).toBeUndefined()
    expect(collected.probe).toBeUndefined()
    expect(Object.keys(collected)).toEqual(['stable_components'])
  })

  it('does not mix the challenge nonce into stable_components (PRD §4.1)', async () => {
    const collect = createFingerprintCollector({
      loadFingerprint: fakeFingerprint({ ua: { value: 'x' } }),
      loadBotd: fakeBotd({ bot: false }, {}),
    })

    const { stable_components } = await collect(sampleChallenge())

    // sampleChallenge()'s nonce must not have leaked into the stable half.
    expect(JSON.stringify(stable_components)).not.toContain('nonce-abc')
  })
})

describe('createFingerprintCollector default loaders', () => {
  it('loads the real FingerprintJS + BotD modules when no deps injected', async () => {
    // MOCK the modules to prove the DEFAULT wiring calls their `load()`.
    vi.resetModules()
    const fpGet = vi
      .fn()
      .mockResolvedValue({ visitorId: 'v', components: { ua: { value: 'x' } } })
    const fpLoad = vi.fn().mockResolvedValue({ get: fpGet })
    const botdLoad = vi.fn().mockResolvedValue({
      collect: vi.fn().mockResolvedValue(undefined),
      detect: vi.fn().mockReturnValue({ bot: false }),
      getComponents: vi.fn().mockReturnValue({ webdriver: false }),
    })
    vi.doMock('@fingerprintjs/fingerprintjs', () => ({
      default: { load: fpLoad },
    }))
    vi.doMock('@fingerprintjs/botd', () => ({ load: botdLoad }))

    const { createFingerprintCollector: create } = await import(
      '../src/fingerprint'
    )
    const { stable_components } = await create()(sampleChallenge())

    expect(fpLoad).toHaveBeenCalledOnce()
    // BotD monitoring must be OFF so the OSS detector never phones home.
    expect(botdLoad).toHaveBeenCalledWith({ monitoring: false })
    expect(stable_components.ua).toEqual({ value: 'x' })
    expect(stable_components.botd).toEqual({
      detection: { bot: false },
      signals: { webdriver: false },
    })

    vi.doUnmock('@fingerprintjs/fingerprintjs')
    vi.doUnmock('@fingerprintjs/botd')
    vi.resetModules()
  })
})
