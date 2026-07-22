/**
 * Cloudflare Worker entry point for the check-in risk deployment.
 *
 * Mirrors `apps/edge/src/index.ts`: per isolate it builds the host state
 * ({@link Deps}) once and hands each request to the Hono app in `app.ts`. The
 * storage layer adds two bindings — the `DB` D1 event log and the
 * `VELOCITY` Durable Object for hot velocity counters — plus a `scheduled`
 * retention purge. Both bindings are optional: unbound (a bare `wrangler dev` or
 * a Node unit test) the Worker still serves, exactly like the edge Worker. The
 * rule engine and `/assess` wire the store into
 * {@link Deps} and the app; this task only exports the DO and runs the cron.
 */

import type { Deps } from './app'
import { createApp } from './app'
import { D1CheckinStore } from './checkin-store-d1'
import { EmptyCheckinStore } from './state'

export { VelocityDurableObject } from './velocity-do'

/**
 * Cloudflare Worker environment bindings. All optional so the Worker runs
 * unbound (Node test / bare `wrangler dev`), mirroring apps/edge.
 */
export interface Env {
  /** Check-in event D1 database (the relationship-graph log). */
  DB?: D1Database
  /** Hot atomic velocity counters (`VelocityDurableObject`). */
  VELOCITY?: DurableObjectNamespace
  /** Retention window in seconds for the scheduled purge; 0/unset ⇒ no-op. */
  CHECKIN_RETENTION_SECS?: string
}

/** Per-isolate singletons, lazily built on the first request. */
let deps: Deps | undefined
let app: ReturnType<typeof createApp> | undefined

/** Build (once per isolate) the host state from the environment. The D1-backed
 *  store when the `DB` binding is present, else the empty fallback (all-zero
 *  aggregates), so `/checkin/assess` runs unbound. Threshold profiles use the
 *  defaults. */
function buildDeps(env: Env): Deps {
  if (deps) return deps
  deps = {
    store: env.DB ? new D1CheckinStore(env.DB) : new EmptyCheckinStore(),
  }
  return deps
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    app ??= createApp(buildDeps(env))
    return app.fetch(request)
  },

  /**
   * Retention purge, driven by the `wrangler.jsonc` cron trigger. When
   * `CHECKIN_RETENTION_SECS` is set (> 0) and D1 is bound, delete every check-in
   * event older than the window; disabled (0/unset) or unbound ⇒ no-op. The
   * purge query lives on {@link D1CheckinStore.purgeOlderThan} so it is
   * unit-testable without the cron.
   */
  async scheduled(
    _controller: ScheduledController,
    env: Env,
    _ctx: ExecutionContext,
  ): Promise<void> {
    const retentionSecs = Number(env.CHECKIN_RETENTION_SECS ?? '0')
    if (retentionSecs <= 0 || !env.DB) return
    const cutoffTs = Date.now() - retentionSecs * 1000
    const purged = await new D1CheckinStore(env.DB).purgeOlderThan(cutoffTs)
    if (purged > 0) {
      console.log(`retention purge: removed ${purged} stale check-in event(s)`)
    }
  },
}
