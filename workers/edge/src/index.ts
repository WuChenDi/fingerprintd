/**
 * Cloudflare Worker entry point for the fingerprintd edge deployment.
 *
 * This is the ONLY module that imports the `.wasm` artifact (wrangler bundles it
 * as a `WebAssembly.Module`), so the router and its dependencies stay importable
 * by Node tests without the Workers `.wasm` loader. Per isolate it initializes
 * the WASM runtime once, builds the configured engine and the STUBBED host state
 * (PCF3), and delegates each request to the state-free router in `handler.ts`.
 *
 * PCF4 replaces the in-memory nonce store with a Durable Object and the empty
 * candidate source with a D1-backed index; nothing else here changes.
 */

import wasmModule from '../wasm/fp_wasm_bg.wasm'
import type { Env } from './config'
import { resolveConfig } from './config'
import { EdgeEngine, initEngineRuntime } from './engine'
import type { Deps } from './handler'
import { handleRequest } from './handler'
import { EmptyCandidateSource, InMemoryNonceStore } from './state'

/** Per-isolate singletons, lazily built on the first request. */
let deps: Deps | undefined

/** Build (once per isolate) the engine + STUBBED state from the environment. */
function buildDeps(env: Env): Deps {
  if (deps) return deps
  initEngineRuntime(wasmModule)
  const config = resolveConfig(env)
  deps = {
    engine: new EdgeEngine(config),
    nonces: new InMemoryNonceStore(config.nonceTtlSecs),
    candidates: new EmptyCandidateSource(),
    config,
  }
  return deps
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, buildDeps(env))
  },
}
