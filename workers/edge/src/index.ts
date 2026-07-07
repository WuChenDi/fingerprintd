/**
 * Cloudflare Worker entry point for the fingerprintd edge deployment.
 *
 * This is the ONLY module that imports the `.wasm` artifact (wrangler bundles it
 * as a `WebAssembly.Module`), so the router and its dependencies stay importable
 * by Node tests without the Workers `.wasm` loader. Per isolate it initializes
 * the WASM runtime once, builds the configured engine and the host state, and
 * delegates each request to the state-free router in `handler.ts`.
 *
 * State (PCF4): when the `NONCE` Durable Object and `DB` D1 bindings are present
 * the Worker uses the durable nonce store and the D1 fingerprint index; unbound
 * (e.g. a bare `wrangler dev` without state, or a Node unit test) it falls back
 * to the in-isolate stubs, so the router runs either way. The nonce Durable
 * Object class is re-exported here so wrangler can bind it.
 */

import wasmModule from '../wasm/fp_wasm_bg.wasm'
import type { Env } from './config'
import { resolveConfig } from './config'
import { EdgeEngine, initEngineRuntime } from './engine'
import { D1FingerprintStore } from './fingerprint-store-d1'
import type { Deps } from './handler'
import { handleRequest } from './handler'
import { DurableNonceStore } from './nonce-do'
import type { CandidateSource, NonceStore } from './state'
import { EmptyCandidateSource, InMemoryNonceStore } from './state'

export { NonceDurableObject } from './nonce-do'

/** Per-isolate singletons, lazily built on the first request. */
let deps: Deps | undefined

/** Build (once per isolate) the engine + host state from the environment. */
function buildDeps(env: Env): Deps {
  if (deps) return deps
  initEngineRuntime(wasmModule)
  const config = resolveConfig(env)
  deps = {
    engine: new EdgeEngine(config),
    nonces: nonceStore(env, config.nonceTtlSecs),
    candidates: candidateSource(env),
    config,
  }
  return deps
}

/** The durable nonce store when the DO is bound, else the in-isolate stub. */
function nonceStore(env: Env, ttlSecs: number): NonceStore {
  return env.NONCE
    ? new DurableNonceStore(env.NONCE, ttlSecs)
    : new InMemoryNonceStore(ttlSecs)
}

/** The D1 fingerprint index when bound, else the empty stub (all new devices). */
function candidateSource(env: Env): CandidateSource {
  return env.DB ? new D1FingerprintStore(env.DB) : new EmptyCandidateSource()
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, buildDeps(env))
  },
}
