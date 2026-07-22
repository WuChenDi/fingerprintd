/**
 * WASM nonce-probe loader.
 *
 * Wraps the wasm-bindgen `fp-wasm` glue (vendored under `../wasm`) so the full
 * collector can compute the nonce probe `hex(HMAC-SHA256(key, nonce))` client-side.
 * The transform is byte-for-byte identical to the server verifier
 * (`crates/fingerprintd/src/probe.rs`); the shared parity vector is asserted in
 * `test/probe.test.ts`.
 *
 * KEY DEPTH, NOT A LOCK: the probe key is baked into the `.wasm` at build time.
 * A determined attacker can extract it from the shipped artifact — this is
 * defense in depth, not a decisive control (architecture). The one-time nonce remains the
 * primary anti-replay guarantee.
 *
 * VENDORED ARTIFACT: `../wasm/fp_wasm_bg.wasm` is a DEV build keyed with the test
 * vector secret (`test-probe-secret`) — the key the parity test asserts (not the
 * `fp-wasm-dev-probe-key` SOURCE default in `crates/fp-wasm/src/lib.rs`, which
 * applies only to a build with `FP_PROBE_KEY` unset). A real deployment must
 * rebuild BOTH bake points with the server's key — the client SDK WASM
 * (`packages/client/wasm`, this artifact) and the edge WASM (`apps/edge/wasm`) —
 * via `FP_PROBE_KEY=<server probe_key> wasm-pack build --target web crates/fp-wasm`
 * so the embedded key matches the server. See `README.md`.
 *
 * ENVIRONMENT LIMIT: there is no headless browser here. In the browser the
 * default {@link initProbe} fetches the co-located `fp_wasm_bg.wasm`; in Node
 * (tests) callers pass the wasm bytes/module explicitly.
 */

import type { InitInput } from '../wasm/fp_wasm.js'
import * as fpWasm from '../wasm/fp_wasm.js'

/** Computes the nonce-probe hex for a challenge nonce. Injectable into the full
 *  collector so tests can supply a deterministic fake without the WASM. */
export type ProbeFn = (nonce: string) => Promise<string>

/** Single in-flight/completed init — the wasm-bindgen module is a singleton. */
let ready: Promise<void> | null = null

/**
 * Initialize the WASM probe module (idempotent).
 *
 * - Browser (default): `initProbe()` fetches the co-located `fp_wasm_bg.wasm`.
 * - Node/tests: pass the wasm bytes or a compiled `WebAssembly.Module`.
 *
 * The first call wins; later calls await the same initialization.
 */
export function initProbe(input?: InitInput): Promise<void> {
  if (ready === null) {
    ready = fpWasm
      .default(input === undefined ? undefined : { module_or_path: input })
      .then(() => undefined)
  }
  return ready
}

/**
 * Compute the probe for `nonce` using the embedded key, initializing the WASM on
 * first use. In the browser this triggers the default fetch-based
 * {@link initProbe}; pre-call {@link initProbe} with explicit bytes elsewhere.
 */
export const wasmProbeFn: ProbeFn = async (nonce) => {
  await initProbe()
  return fpWasm.probe(nonce)
}
