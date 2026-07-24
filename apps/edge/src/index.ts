/**
 * Cloudflare Worker entry point for the fingerprintd edge deployment.
 *
 * This is the ONLY module that imports the `.wasm` artifact (wrangler bundles it
 * as a `WebAssembly.Module`), so the Hono app and its dependencies stay
 * importable by Node tests without the Workers `.wasm` loader. Per isolate it
 * initializes the WASM runtime once, builds the configured engine and the host
 * state, and hands each request to the Hono app in `app.ts`.
 *
 * State: when the `NONCE` Durable Object and `DB` D1 bindings are present
 * the Worker uses the durable nonce store and the D1 fingerprint index; unbound
 * (e.g. a bare `wrangler dev` without state, or a Node unit test) it falls back
 * to the in-isolate stubs, so the app runs either way. The nonce Durable Object
 * class is re-exported here so wrangler can bind it.
 */

import wasmModule from '../wasm/fp_wasm_bg.wasm'
import type { Deps } from './app'
import { createApp } from './app'
import type { Env } from './config'
import { resolveConfig } from './config'
import { DurableNonceStore } from './lib/do/nonce-do'
import { VelocityStore } from './lib/do/velocity-do'
import type { CandidateSource, NonceStore } from './lib/state'
import { EmptyCandidateSource, InMemoryNonceStore } from './lib/state'
import { D1CheckinStore, EmptyCheckinStore } from './modules/checkin'
import {
  D1FingerprintStore,
  EdgeEngine,
  initEngineRuntime,
} from './modules/fingerprint'

export { NonceDurableObject } from './lib/do/nonce-do'
export { VelocityDurableObject } from './lib/do/velocity-do'

/** Per-isolate singletons, lazily built on the first request. */
let deps: Deps | undefined
let app: ReturnType<typeof createApp> | undefined

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
    checkin: env.DB ? new D1CheckinStore(env.DB) : new EmptyCheckinStore(),
    // The VELOCITY Durable Object backs the cross-session new-device velocity
    // signal; unbound ⇒ omitted, and the /identify path degrades to the neutral
    // `low` band (fail-open), like the pre-DO stateless edge.
    velocity: env.VELOCITY ? new VelocityStore(env.VELOCITY) : undefined,
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
  async fetch(request: Request, env: Env): Promise<Response> {
    app ??= createApp(buildDeps(env))
    return app.fetch(request)
  },

  /**
   * D1 retention purge, driven by the `wrangler.jsonc` cron trigger. Two
   * independent purges run in this one invocation:
   *   - fingerprint templates: when `FP_RETENTION_SECS` > 0 and `DB` is bound,
   *     delete every template last seen beyond the window plus its
   *     blocking-index rows;
   *   - check-in events: when `CHECKIN_RETENTION_SECS` > 0 and `DB` is
   *     bound, delete every check-in event older than the window.
   * Either disabled (0) ⇒ that purge is a no-op. The purge queries live on the
   * respective stores so they are unit-testable without the cron.
   */
  async scheduled(
    _controller: ScheduledController,
    env: Env,
    _ctx: ExecutionContext,
  ): Promise<void> {
    const config = resolveConfig(env)
    if (config.retentionMs > 0 && env.DB) {
      const purged = await new D1FingerprintStore(env.DB).purgeOlderThan(
        Date.now(),
        config.retentionMs,
      )
      if (purged > 0) {
        console.log(`retention purge: removed ${purged} stale template(s)`)
      }
    }
    if (config.checkinRetentionMs > 0 && env.DB) {
      const purged = await new D1CheckinStore(env.DB).purgeOlderThan(
        Date.now() - config.checkinRetentionMs,
      )
      if (purged > 0) {
        console.log(
          `retention purge: removed ${purged} stale check-in event(s)`,
        )
      }
    }
  },
}
