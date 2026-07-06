import { describe, expect, it } from 'vitest'
import { verifySignature } from '../src/signature'
import { serverSign } from './helpers'

const KEY = new TextEncoder().encode('test-signing-secret')
const ISSUED_MS = 1_700_000_000_000

describe('verifySignature', () => {
  it('accepts a correct server signature', async () => {
    const body = new TextEncoder().encode('{"visitorId":"abc"}')
    const sig = await serverSign(KEY, ISSUED_MS, body)

    expect(await verifySignature(KEY, ISSUED_MS, body, sig)).toBe(true)
  })

  it('rejects a tampered body', async () => {
    const body = new TextEncoder().encode('{"visitorId":"abc"}')
    const sig = await serverSign(KEY, ISSUED_MS, body)
    const tampered = new TextEncoder().encode('{"visitorId":"xyz"}')

    expect(await verifySignature(KEY, ISSUED_MS, tampered, sig)).toBe(false)
  })

  it('rejects a different issue timestamp (freshness is signed)', async () => {
    const body = new TextEncoder().encode('{"visitorId":"abc"}')
    const sig = await serverSign(KEY, ISSUED_MS, body)

    expect(await verifySignature(KEY, ISSUED_MS + 1, body, sig)).toBe(false)
  })

  it('rejects a signature made with the wrong key', async () => {
    const body = new TextEncoder().encode('{"visitorId":"abc"}')
    const sig = await serverSign(
      new TextEncoder().encode('wrong-key'),
      ISSUED_MS,
      body,
    )

    expect(await verifySignature(KEY, ISSUED_MS, body, sig)).toBe(false)
  })

  it('rejects malformed (odd-length / non-hex) signatures without throwing', async () => {
    const body = new TextEncoder().encode('{}')
    expect(await verifySignature(KEY, ISSUED_MS, body, 'abc')).toBe(false)
    expect(await verifySignature(KEY, ISSUED_MS, body, 'zz')).toBe(false)
  })
})
