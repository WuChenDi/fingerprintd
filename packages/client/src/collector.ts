/**
 * The FULL {@link Collector} (TC5) — it composes the stable half plus the probe
 * and a client timestamp into the single evidence payload `run()` submits:
 *
 *   { stable_components, probe?, ts }
 *
 * DESIGN (PRD §4.1):
 *  - STABLE half (TC2, `createFingerprintCollector`) — the "who is this device"
 *    matching input.
 *  - PROBE (TC4 WASM, `wasmProbeFn`) — `hex(HMAC-SHA256(key, nonce))` (T8),
 *    computed ONLY when the challenge advertises `collect.challenge.verify`
 *    (i.e. the server has a probe key configured). Kept SEPARATE from
 *    `stable_components`; it is NEVER a matching signal, only a freshness proof.
 *  - `ts` — the client clock at collection (T9).
 *
 * Every backend is injectable so the whole assembly is testable without a real
 * browser or the WASM (there is no headless browser in this environment).
 */

import type { Collected, Collector } from './collect'
import type { FingerprintCollectorDeps } from './fingerprint'
import { createFingerprintCollector } from './fingerprint'
import type { ProbeFn } from './probe'
import { wasmProbeFn } from './probe'

/** Injectable backends for the full collector. All default to the real
 *  implementations; tests override them with deterministic fakes. */
export interface FullCollectorOptions {
  /** Stable-half (FingerprintJS + BotD) loaders. */
  fingerprint?: FingerprintCollectorDeps
  /** Nonce-probe function. Defaults to the WASM {@link wasmProbeFn}. */
  probe?: ProbeFn
  /** Client clock in Unix ms. Injectable for deterministic tests; defaults to
   *  `Date.now`. */
  now?: () => number
}

/**
 * Build the full {@link Collector}.
 *
 * The returned collector runs the stable half, computes the probe when the
 * challenge asks to `verify` it, stamps the client `ts`, and returns the
 * assembled evidence. `stable_components` and `probe` stay separate by
 * construction.
 */
export function createCollector(options: FullCollectorOptions = {}): Collector {
  const stableCollector = createFingerprintCollector(options.fingerprint)
  const probeFn = options.probe ?? wasmProbeFn
  const now = options.now ?? (() => Date.now())

  return async (challenge): Promise<Collected> => {
    const { stable_components } = await stableCollector(challenge)

    const collected: Collected = {
      stable_components,
      ts: now(),
    }
    // Compute the probe only when the server advertises it (probe_key set).
    if (challenge.collect.challenge.verify !== undefined) {
      collected.probe = await probeFn(challenge.nonce)
    }
    return collected
  }
}
