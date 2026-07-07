import { defineConfig } from 'vitest/config'

// Two projects run under one `vitest run`. Vitest 4 removed the standalone
// workspace file (`vitest.workspace.ts`) in favour of `test.projects`:
//   - vitest.node.config.ts    — Node: the state-free router contract over the
//                                vendored WASM bytes (no Workers runtime).
//   - vitest.workers.config.ts — workerd/miniflare: the PCF4 state layer (nonce
//                                Durable Object, D1 recall/persist) against the
//                                real runtime with live bindings.
export default defineConfig({
  test: {
    projects: ['./vitest.node.config.ts', './vitest.workers.config.ts'],
  },
})
