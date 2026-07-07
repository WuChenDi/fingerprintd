/**
 * Typed host wrapper around the WASM compute engine (`crates/fp-wasm`).
 *
 * The `FpEngine` WASM class is the SINGLE source of the fingerprinting compute,
 * shared with the native Axum server via `fp-core`: blocking-key derivation,
 * Fellegi–Sunter scoring, probe verification, and response signing. This module
 * owns the wasm-bindgen module lifecycle (a one-time `initSync`) and marshals
 * the JSON string boundary so the router in `handler.ts` deals in typed values.
 *
 * The engine holds NO request state: `score` rebuilds the host-recalled candidate
 * block in a transient store per call and discards it. All persistence (nonce
 * burn, candidate recall, drift write-back) is the host's, so this stays pure.
 */

import { FpEngine, initSync } from '../wasm/fp_wasm.js'
import type { EdgeConfig } from './config'
import type { Candidate } from './state'
import type { ScoreOutcome } from './types'

/** One-time wasm-bindgen module init (the module is a process-wide singleton). */
let initialized = false

/**
 * Initialize the WASM runtime from a compiled module or raw bytes (idempotent).
 *
 * - In the Worker, `src/index.ts` passes the `import`ed `.wasm` module, which
 *   wrangler bundles as a `WebAssembly.Module`.
 * - In tests (Node), the caller passes the `.wasm` bytes read from disk.
 *
 * We use `initSync` (never the default async `__wbg_init`) because the latter's
 * fallback resolves the artifact via `import.meta.url`, which is not meaningful
 * in the Workers runtime.
 */
export function initEngineRuntime(
  module: WebAssembly.Module | BufferSource,
): void {
  if (initialized) return
  initSync({ module })
  initialized = true
}

/**
 * A configured, state-free compute engine for one isolate. Construct once per
 * isolate from the resolved secrets; call per request.
 */
export class EdgeEngine {
  private readonly inner: FpEngine

  /** {@link initEngineRuntime} MUST have run before constructing this. */
  constructor(config: EdgeConfig) {
    // Probe / signing keys are only consulted when their feature is enabled;
    // when unset, an empty key is harmless because the host never calls the
    // corresponding method. The salt secret is always meaningful.
    this.inner = new FpEngine(
      config.saltSecret,
      config.probeKey ?? '',
      config.signingKey ?? '',
    )
  }

  /** Blocking keys (hex) for a probe's components — the host queries its
   *  candidate index with these. */
  blockingKeys(components: Record<string, unknown>): string[] {
    return JSON.parse(
      this.inner.blocking_keys(JSON.stringify(components)),
    ) as string[]
  }

  /** Score a probe against host-recalled candidates, without mutating state. */
  score(
    components: Record<string, unknown>,
    candidates: Candidate[],
  ): ScoreOutcome {
    const request = JSON.stringify({ components, candidates })
    return JSON.parse(this.inner.score(request)) as ScoreOutcome
  }

  /** Constant-time check that `probe` is the correct nonce probe (T8). */
  verifyProbe(nonce: string, probe: string): boolean {
    return this.inner.verify_probe(nonce, probe)
  }

  /** The expected probe `hex(HMAC-SHA256(probe_key, nonce))` a client should
   *  echo, computed with the configured key. Used to exercise the probe path. */
  expectedProbe(nonce: string): string {
    return this.inner.expected_probe(nonce)
  }

  /** `hex(HMAC-SHA256(signing_key, issued_ms_be ++ body))` over the exact
   *  response bytes (T9). `issuedMs` is Unix milliseconds. */
  sign(issuedMs: number, body: Uint8Array): string {
    return this.inner.sign(BigInt(issuedMs), body)
  }
}
