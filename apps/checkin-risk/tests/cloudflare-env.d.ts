/// <reference types="@cloudflare/vitest-pool-workers/types" />

// Types for the `env` exposed by the miniflare-backed Workers test pool: the
// storage bindings from wrangler.jsonc plus the migrations the setup file
// applies. Only the `*.workers.test.ts` suite (real workerd) uses these.
//
// pool-workers 0.18 types `env` as `Cloudflare.Env`, so the bindings are
// declared by augmenting that global interface.

import type { D1Migration } from 'cloudflare:test'

declare global {
  namespace Cloudflare {
    interface Env {
      /** Check-in event D1 database (created locally by miniflare). */
      DB: D1Database
      /** Velocity Durable Object namespace. */
      VELOCITY: DurableObjectNamespace
      /** Schema migrations, read at config time and applied in the setup file. */
      TEST_MIGRATIONS: D1Migration[]
    }
  }
}
