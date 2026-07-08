import {
  cloudflareTest,
  readD1Migrations,
} from '@cloudflare/vitest-pool-workers'
import { defineConfig } from 'vitest/config'

// The state suite (`*.workers.test.ts`) runs inside real workerd/miniflare with
// the wrangler.jsonc bindings live — the nonce Durable Object, the D1 database,
// and the WASM-loading Worker entry — so the Durable Object burn and the D1
// recall/persist round-trips are exercised against the actual runtime, not a
// fake. There is no CF account here, but miniflare needs none (local-only per
// the campaign ENV LIMIT). The state-free router unit contract stays in the
// Node project (`vitest.node.config.ts`); this is the other half.
//
// Vitest 4 / pool-workers 0.18: the worker pool is now wired as the
// `cloudflareTest(...)` Vite plugin (the old `defineWorkersConfig` +
// `test.poolOptions.workers` shape was removed). Storage isolation is now
// per-test-FILE (not per-test), so state suites reset D1 in `beforeEach`.
export default defineConfig(async () => {
  const migrations = await readD1Migrations('./src/database')
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.jsonc' },
        miniflare: {
          // Required by the Workers pool; harmless for this Worker.
          compatibilityFlags: ['nodejs_compat'],
          // Read at config time, applied by the setup file. `FP_SALT_SECRET`
          // pins the deterministic salt so the cross-stack parity suite
          // (`parity.workers.test.ts`) reproduces the native reference — it MUST
          // equal `salt_secret` in `tests/fixtures/parity.json` (the suite
          // asserts the coupling). In a real deployment this is a Worker Secret.
          bindings: {
            TEST_MIGRATIONS: migrations,
            FP_SALT_SECRET: 'fp-parity-vector-secret',
          },
        },
      }),
    ],
    test: {
      // Explicit, slash-free project name: the default (package.json
      // `@cdlab/fingerprintd-edge`) leaks a `/` into the Durable Object storage path
      // and workerd rejects it.
      name: 'workers',
      include: ['tests/**/*.workers.test.ts'],
      setupFiles: ['./tests/apply-migrations.ts'],
    },
  }
})
