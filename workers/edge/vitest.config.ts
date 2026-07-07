import { defineConfig } from 'vitest/config'

// The router is state-free and dependency-injected, so it runs under plain Node
// with the WASM engine loaded from the vendored bytes — no Workers runtime
// needed for the unit contract. Real workerd/miniflare execution is exercised
// separately via `wrangler dev --local` (there is no CF account here, so a real
// deploy is deferred to a human — see README).
export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
  },
})
