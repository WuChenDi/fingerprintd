import { defineConfig } from 'vitest/config'

// Unit/mock tests only. There is NO headless browser in this environment, so
// canvas/audio/webgl cannot be exercised for real — jsdom + mocked `fetch`
// cover the wire contract and crypto only (see README). Real in-browser
// certification is deferred to a human.
export default defineConfig({
  test: {
    environment: 'jsdom',
    include: ['test/**/*.test.ts'],
  },
})
