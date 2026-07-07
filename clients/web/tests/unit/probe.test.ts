/**
 * WASM ↔ server PARITY (TC5 acceptance).
 *
 * Instantiates the vendored `fp-wasm` module headlessly (reading the `.wasm`
 * bytes and letting the wasm-bindgen glue instantiate them — `--target web`
 * would otherwise fetch by URL, which does not work in Node) and asserts that
 * `probe("fixed-nonce-000")` equals the SHARED vector in
 * `crates/fp-wasm/tests/vectors/probe.json`.
 *
 * The vendored `wasm/fp_wasm_bg.wasm` is a dev build keyed with the vector's
 * `test-probe-secret`, so this proves the client probe output is byte-for-byte
 * what the server verifier (`crates/fingerprintd/src/probe.rs`) expects for the
 * same key + nonce — client/server agreement without a browser.
 */

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { initProbe, wasmProbeFn } from '../../src/probe'

// vitest runs with cwd = clients/web (see the gate); resolve the vendored wasm
// from there — jsdom's `import.meta.url` is not a file URL.
const WASM_PATH = resolve(process.cwd(), 'wasm/fp_wasm_bg.wasm')
// The shared vector — key "test-probe-secret", nonce "fixed-nonce-000".
const EXPECTED =
  'ad83144894f917b94072c2f7b3246af66d3bc5a450562ccf3671ed64d33137d0'

describe('wasm probe parity', () => {
  it('matches the shared server vector for the test-probe-secret key', async () => {
    // Feed the raw bytes so the wasm-bindgen glue instantiates them directly
    // (no URL fetch), keeping the test headless.
    await initProbe(new Uint8Array(readFileSync(WASM_PATH)))
    expect(await wasmProbeFn('fixed-nonce-000')).toBe(EXPECTED)
  })

  it('is deterministic and nonce-bound', async () => {
    await initProbe(new Uint8Array(readFileSync(WASM_PATH)))
    const a = await wasmProbeFn('fixed-nonce-000')
    const b = await wasmProbeFn('fixed-nonce-000')
    const c = await wasmProbeFn('a-different-nonce')
    expect(a).toBe(b)
    expect(a).not.toBe(c)
    expect(c).toMatch(/^[0-9a-f]{64}$/)
  })
})
