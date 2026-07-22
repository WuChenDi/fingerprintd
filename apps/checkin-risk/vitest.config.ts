import { defineConfig } from 'vitest/config'

// Two projects run under one `vitest run`, mirroring apps/edge. Vitest 4 uses
// `test.projects` (the standalone workspace file was removed):
//   - vitest.node.config.ts    — Node: the state-free router / aggregate pure
//                                logic that needs no Workers runtime.
//   - vitest.workers.config.ts — workerd/miniflare: the storage layer (D1 event
//                                aggregates, velocity Durable Object) against the
//                                real runtime with the wrangler.jsonc bindings live.
export default defineConfig({
  test: {
    projects: ['./vitest.node.config.ts', './vitest.workers.config.ts'],
  },
})
