/**
 * The STABLE half of a real {@link Collector}: FingerprintJS (OSS) raw
 * components + BotD signals. This is the "who is this device" evidence the
 * SERVER matches on — it is NOT a verdict.
 *
 * DESIGN (architecture §4.1 / §4.4):
 *  - We take FingerprintJS's RAW `components` and DISCARD its `visitorId`/hash.
 *    The client never ships a client-side id; the authoritative visitorId is
 *    whatever the server returns from `/identify`.
 *  - BotD signals are merged under a `botd` sub-object of `stable_components`.
 *  - This module emits ONLY `stable_components`. The nonce-seeded `probe` is a
 *    SEPARATE freshness proof and must never become a matching signal — so
 *    it is absent here.
 *
 * TREE-SHAKING: kept in its own module (not `collect.ts`) so importing the
 * stub/interface does not pull in FingerprintJS or BotD. The heavy deps load
 * only when a consumer imports {@link createFingerprintCollector}.
 *
 * INJECTABLE: the two loaders are injectable so tests can supply fakes and
 * assert the WIRING (component pass-through, visitorId discard, BotD merge)
 * without a real browser. There is no headless browser in this environment, so
 * real component VALUES are never exercised — only the plumbing is tested.
 */

import { load as loadBotd } from '@fingerprintjs/botd'
import FingerprintJS from '@fingerprintjs/fingerprintjs'
import { adaptFingerprintComponents } from './adapter'
import type { Collected, Collector } from './collect'

/** Minimal structural view of a loaded FingerprintJS agent — only the surface
 *  this collector uses. `get()` returns the raw components plus the `visitorId`
 *  hash we deliberately throw away. */
export interface FingerprintAgent {
  get(): Promise<{ visitorId: string; components: Record<string, unknown> }>
}

/** Minimal structural view of a loaded BotD detector. `collect()` gathers the
 *  raw signals, `detect()` runs the (discarded) client-side verdict, and
 *  `getComponents()` returns the raw signals we forward to the server. */
export interface BotdDetector {
  collect(): Promise<unknown>
  detect(): unknown
  getComponents(): unknown
}

/** Injectable module loaders (defaulted to the real OSS packages). */
export interface FingerprintCollectorDeps {
  /** Load a FingerprintJS agent. Defaults to `FingerprintJS.load()`. */
  loadFingerprint?: () => Promise<FingerprintAgent>
  /** Load a BotD detector. Defaults to `botd.load({ monitoring: false })` —
   *  monitoring is off so the OSS detector never phones home. */
  loadBotd?: () => Promise<BotdDetector>
}

/**
 * Build a real {@link Collector} over FingerprintJS + BotD.
 *
 * The returned collector ignores the challenge (the stable half is nonce-free
 * by design — architecture §4.1) and produces only `stable_components`:
 *  - every FingerprintJS component, ADAPTED to the server matching schema
 *    ({@link adaptFingerprintComponents} unwraps the FJS
 *    `{ value, duration }` wrapper and renames keys; a verbatim spread would be
 *    silently dropped by the server matcher), and
 *  - the BotD detection result + raw signals under a `botd` key (BotD is not
 *    adapted — it rides untouched under `botd`).
 * The FingerprintJS `visitorId`/hash is never read into the payload.
 */
export function createFingerprintCollector(
  deps: FingerprintCollectorDeps = {},
): Collector {
  const loadFingerprint = deps.loadFingerprint ?? (() => FingerprintJS.load())
  const load = deps.loadBotd ?? (() => loadBotd({ monitoring: false }))

  return async (): Promise<Collected> => {
    const agent = await loadFingerprint()
    // Take the RAW components only; the `visitorId` hash is intentionally
    // discarded (architecture §4.4 — the client-side verdict is thrown away).
    const { components } = await agent.get()

    const detector = await load()
    await detector.collect()
    const botd = {
      detection: detector.detect(),
      signals: detector.getComponents(),
    }

    // Adapt FJS components to the server matching schema before they become
    // stable_components; botd is merged untouched under its own key.
    const stable_components: Record<string, unknown> = {
      ...adaptFingerprintComponents(components),
      botd,
    }
    // ONLY stable_components — the nonce probe is a separate freshness proof
    // and must never ride along as a matching signal.
    return { stable_components }
  }
}
