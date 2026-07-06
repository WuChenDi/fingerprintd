/**
 * Test helpers: a mocked `fetch` and a server-side response signer that mirrors
 * `crates/fingerprintd/src/signing.rs`, so a test can produce a signature the
 * client's `verifySignature` must accept.
 */

import type { ChallengeResponse, IdentifyResponse } from '../src/types'

/** A single canned HTTP exchange for the mock fetch. */
export interface MockRoute {
  status?: number
  headers?: Record<string, string>
  /** Raw body bytes/string the response returns. Objects are JSON-encoded. */
  body: string | object
}

/** A recorded request the mock fetch saw. */
export interface RecordedRequest {
  url: string
  method: string
  body: string | undefined
}

/** Build a mock `fetch` that answers `/challenge` then `/identify` in order,
 *  recording every request it received into `recorded`. */
export function mockFetch(
  routes: { challenge?: MockRoute; identify?: MockRoute },
  recorded: RecordedRequest[] = [],
): typeof globalThis.fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    recorded.push({
      url,
      method: init?.method ?? 'GET',
      body: typeof init?.body === 'string' ? init.body : undefined,
    })
    const route = url.endsWith('/challenge')
      ? routes.challenge
      : routes.identify
    if (!route) throw new Error(`no mock route for ${url}`)
    const body =
      typeof route.body === 'string' ? route.body : JSON.stringify(route.body)
    return new Response(body, {
      status: route.status ?? 200,
      headers: { 'content-type': 'application/json', ...route.headers },
    })
  }) as typeof globalThis.fetch
}

/** Lowercase hex of bytes. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** 8-byte big-endian u64, matching Rust `u64::to_be_bytes`. */
function be64(value: number): Uint8Array {
  const buf = new Uint8Array(8)
  new DataView(buf.buffer).setBigUint64(0, BigInt(value), false)
  return buf
}

/** Compute the server-side signature `hex(HMAC-SHA256(key, be64(ms) ++ body))`. */
export async function serverSign(
  key: Uint8Array,
  issuedMs: number,
  body: Uint8Array,
): Promise<string> {
  const message = new Uint8Array(8 + body.length)
  message.set(be64(issuedMs), 0)
  message.set(body, 8)
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key.slice(),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  return toHex(
    new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, message)),
  )
}

/** A minimal, valid `/challenge` body. */
export function sampleChallenge(): ChallengeResponse {
  return {
    nonce: 'nonce-abc',
    expires_in: 30,
    collect: {
      stable: ['userAgent', 'timezone'],
      challenge: { seed: 'nonce-abc', targets: ['canvas', 'audio'] },
    },
  }
}

/** A minimal, valid `/identify` success body. */
export function sampleIdentify(): IdentifyResponse {
  return {
    visitorId: 'v_123',
    confidence: 0.87,
    is_new_device: true,
    decision: 'new_device',
    collision_risk: false,
    signals: { ua_tls_consistent: true, ip_risk: 'low' },
  }
}
