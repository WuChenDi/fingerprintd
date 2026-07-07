import {
  defineWorkersConfig,
  readD1Migrations,
} from '@cloudflare/vitest-pool-workers/config'

// The state suite (`*.workers.test.ts`) runs inside real workerd/miniflare with
// the wrangler.toml bindings live — the nonce Durable Object, the D1 database,
// and the WASM-loading Worker entry — so the Durable Object burn and the D1
// recall/persist round-trips are exercised against the actual runtime, not a
// fake. There is no CF account here, but miniflare needs none (local-only per
// the campaign ENV LIMIT). The state-free router unit contract stays in the
// Node project (`vitest.config.ts`); this config is the other half of the
// workspace.
export default defineWorkersConfig(async () => {
  const migrations = await readD1Migrations('./migrations')
  return {
    test: {
      // Explicit, slash-free project name: the default (package.json
      // `@fingerprintd/edge`) leaks a `/` into the Durable Object storage path
      // and workerd rejects it.
      name: 'workers',
      include: ['tests/**/*.workers.test.ts'],
      setupFiles: ['./tests/apply-migrations.ts'],
      poolOptions: {
        workers: {
          // One miniflare instance for the suite; per-test isolated storage
          // still resets D1/DO state between tests.
          singleWorker: true,
          wrangler: { configPath: './wrangler.toml' },
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
        },
      },
    },
  }
})
