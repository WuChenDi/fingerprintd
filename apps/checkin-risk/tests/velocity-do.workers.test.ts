import { env } from 'cloudflare:test'
import { describe, expect, it } from 'vitest'
import { VelocityStore } from '../src/velocity-do'

// The hot velocity counter against the real runtime: the VelocityDurableObject
// maintains a rolling distinct-member window per entity, exercised through
// workerd/miniflare with the wrangler.jsonc `VELOCITY` binding live.

const MINUTE = 60 * 1000

/** Sleep `ms` real milliseconds (miniflare advances real time). */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

describe('device_account_fanout velocity', () => {
  it('counts distinct accounts on a device and dedups repeats', async () => {
    const store = new VelocityStore(env.VELOCITY)
    expect(await store.deviceAccountFanout('dev1', 'a1', MINUTE)).toBe(1)
    expect(await store.deviceAccountFanout('dev1', 'a2', MINUTE)).toBe(2)
    // The same account again does not grow the distinct count.
    expect(await store.deviceAccountFanout('dev1', 'a1', MINUTE)).toBe(2)
    expect(await store.deviceAccountFanout('dev1', 'a3', MINUTE)).toBe(3)
  })

  it('keeps every device window independent', async () => {
    const store = new VelocityStore(env.VELOCITY)
    await store.deviceAccountFanout('devA', 'a1', MINUTE)
    await store.deviceAccountFanout('devA', 'a2', MINUTE)
    // A different device is a different instance, starting from empty.
    expect(await store.deviceAccountFanout('devB', 'a1', MINUTE)).toBe(1)
  })
})

describe('ip_account velocity', () => {
  it('counts distinct accounts on an IP, independent of the device scope', async () => {
    const store = new VelocityStore(env.VELOCITY)
    expect(await store.ipAccountVelocity('proxy', 'a1', MINUTE)).toBe(1)
    expect(await store.ipAccountVelocity('proxy', 'a2', MINUTE)).toBe(2)
    // The `ip:` scope never collides with a same-named `v:` device instance.
    expect(await store.deviceAccountFanout('proxy', 'a1', MINUTE)).toBe(1)
  })
})

describe('window expiry', () => {
  it('drops members whose window has lapsed', async () => {
    const store = new VelocityStore(env.VELOCITY)
    // Tiny window: the first account lapses before the second bump.
    expect(await store.deviceAccountFanout('expdev', 'a1', 5)).toBe(1)
    await sleep(25)
    // a1 has expired and is pruned; only a2 survives ⇒ distinct stays 1.
    expect(await store.deviceAccountFanout('expdev', 'a2', 5)).toBe(1)
  })
})
