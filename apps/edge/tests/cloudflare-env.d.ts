/// <reference types="@cloudflare/vitest-pool-workers/types" />

// Types for the `env` exposed by the miniflare-backed Workers test pool: the
// state bindings from wrangler.jsonc plus the migrations the setup file
// applies. Only the `*.workers.test.ts` suite (real workerd) uses these.
//
// pool-workers 0.18 types `env` as `Cloudflare.Env`, so the bindings are
// declared by augmenting that global interface (the older `cloudflare:test`
// `ProvidedEnv` augmentation no longer applies).

import type { D1Migration } from 'cloudflare:test'

declare global {
  namespace Cloudflare {
    interface Env {
      /** D1 fingerprint database (created locally by miniflare). */
      DB: D1Database
      /** D1 check-in event database (created locally by miniflare). */
      CHECKIN_DB: D1Database
      /** Nonce Durable Object namespace. */
      NONCE: DurableObjectNamespace
      /** Velocity Durable Object namespace (hot check-in fan-out counters). */
      VELOCITY: DurableObjectNamespace
      /** Fingerprint schema migrations, read at config time and applied in setup. */
      TEST_MIGRATIONS: D1Migration[]
      /** Check-in schema migrations, read at config time and applied in setup. */
      TEST_CHECKIN_MIGRATIONS: D1Migration[]
      /** Deterministic salt secret, pinned to the parity fixture's `salt_secret`
       *  so the cross-stack parity suite reproduces the native reference. */
      FP_SALT_SECRET: string
    }
  }
}
