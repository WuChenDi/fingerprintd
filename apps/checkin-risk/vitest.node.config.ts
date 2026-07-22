import { configDefaults, defineConfig } from 'vitest/config'

// The Hono app is state-free and dependency-injected, so the walking-skeleton
// contract runs under plain Node — no Workers runtime needed. The storage layer
// (D1 aggregates, velocity Durable Object) needs real workerd, so those
// `*.workers.test.ts` files run in the sibling Workers project
// (`vitest.workers.config.ts`) and are excluded here.
export default defineConfig({
  test: {
    name: 'node',
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'tests/**/*.workers.test.ts'],
  },
})
