import { describe, expect, it } from 'vitest'
import { createApp } from '../src/app'

// Walking-skeleton contract: the app is state-free, so a fresh app over empty
// deps is enough to exercise the liveness route.
describe('GET /health', () => {
  it('returns 200 ok', async () => {
    const app = createApp({})
    const res = await app.request('https://checkin.test/health')
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('ok')
  })
})
