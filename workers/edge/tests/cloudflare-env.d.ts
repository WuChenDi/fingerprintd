/// <reference types="@cloudflare/vitest-pool-workers" />

// Types for the `env` exposed by the miniflare-backed Workers test pool: the
// PCF4 state bindings from wrangler.toml plus the migrations the setup file
// applies. Only the `*.workers.test.ts` suite (real workerd) uses these.

import type { D1Migration } from 'cloudflare:test'

declare module 'cloudflare:test' {
  interface ProvidedEnv {
    /** D1 fingerprint database (created locally by miniflare). */
    DB: D1Database
    /** Nonce Durable Object namespace. */
    NONCE: DurableObjectNamespace
    /** Schema migrations, read at config time and applied in the setup file. */
    TEST_MIGRATIONS: D1Migration[]
  }
}
