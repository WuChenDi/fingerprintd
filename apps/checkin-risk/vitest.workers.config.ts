import {
  cloudflareTest,
  readD1Migrations,
} from '@cloudflare/vitest-pool-workers'
import { defineConfig } from 'vitest/config'

// The storage suite (`*.workers.test.ts`) runs inside real workerd/miniflare
// with the wrangler.jsonc bindings live — the `DB` D1 database and the
// `VelocityDurableObject` — so the windowed aggregate queries and the Durable
// Object velocity counter are exercised against the actual runtime, not a fake.
// There is no CF account here, but miniflare needs none (local-only). The
// state-free unit contract stays in the Node project (`vitest.node.config.ts`).
//
// Vitest 4 / pool-workers 0.18: the worker pool is the `cloudflareTest(...)`
// Vite plugin. Storage isolation is per-test-FILE, so state suites reset D1 in
// `beforeEach`. The migrations are read here and applied by the setup file.
export default defineConfig(async () => {
  const migrations = await readD1Migrations('./src/database')
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.jsonc' },
        miniflare: {
          // Required by the Workers pool; harmless for this Worker.
          compatibilityFlags: ['nodejs_compat'],
          bindings: {
            TEST_MIGRATIONS: migrations,
          },
        },
      }),
    ],
    test: {
      // Explicit, slash-free project name: the package.json name
      // (`@cdlab/fingerprintd-checkin-risk`) leaks a `/` into the Durable Object
      // storage path and workerd rejects it.
      name: 'workers',
      include: ['tests/**/*.workers.test.ts'],
      setupFiles: ['./tests/apply-migrations.ts'],
    },
  }
})
