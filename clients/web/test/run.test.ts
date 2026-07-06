import { describe, expect, it } from 'vitest'
import type { Collector } from '../src/collect'
import { run, stubCollector } from '../src/index'
import type { RecordedRequest } from './helpers'
import {
  mockFetch,
  sampleChallenge,
  sampleIdentify,
  serverSign,
} from './helpers'

const KEY = new TextEncoder().encode('test-signing-secret')
const ISSUED_MS = 1_700_000_000_000

describe('run', () => {
  it('drives challenge -> collect -> identify and returns the server identity', async () => {
    const recorded: RecordedRequest[] = []
    const fetch = mockFetch(
      {
        challenge: { body: sampleChallenge() },
        identify: { body: sampleIdentify() },
      },
      recorded,
    )

    const { identity, signatureValid } = await run({
      baseUrl: 'https://fp.example.com',
      collect: stubCollector,
      fetch,
    })

    expect(identity.visitorId).toBe('v_123')
    expect(identity.decision).toBe('new_device')
    // No signing key supplied -> verification not attempted.
    expect(signatureValid).toBeUndefined()

    // The identify body echoed the challenge nonce and the collector's evidence.
    const identifyRequest = recorded.find((r) => r.url.endsWith('/identify'))
    const sent = JSON.parse(identifyRequest?.body ?? '{}')
    expect(sent.nonce).toBe('nonce-abc')
    expect(sent.stable_components._stub).toBe(true)
    expect(sent.stable_components.collected_targets).toEqual([
      'canvas',
      'audio',
    ])
  })

  it('verifies the response signature when a signing key is supplied', async () => {
    // Pre-serialize the exact identify body so we can sign those same bytes.
    const identifyBody = JSON.stringify(sampleIdentify())
    const signature = await serverSign(
      KEY,
      ISSUED_MS,
      new TextEncoder().encode(identifyBody),
    )
    const fetch = mockFetch({
      challenge: { body: sampleChallenge() },
      identify: {
        headers: {
          'x-fp-timestamp': String(ISSUED_MS),
          'x-fp-signature': signature,
        },
        body: identifyBody,
      },
    })

    const { signatureValid } = await run({
      baseUrl: 'https://fp.example.com',
      collect: stubCollector,
      signingKey: KEY,
      fetch,
    })

    expect(signatureValid).toBe(true)
  })

  it('reports an invalid signature when the body does not match the tag', async () => {
    // Sign a DIFFERENT body than the one the server returns -> tag mismatch.
    const signature = await serverSign(
      KEY,
      ISSUED_MS,
      new TextEncoder().encode('{"tampered":1}'),
    )
    const fetch = mockFetch({
      challenge: { body: sampleChallenge() },
      identify: {
        headers: {
          'x-fp-timestamp': String(ISSUED_MS),
          'x-fp-signature': signature,
        },
        body: sampleIdentify(),
      },
    })

    const { signatureValid } = await run({
      baseUrl: 'https://fp.example.com',
      collect: stubCollector,
      signingKey: KEY,
      fetch,
    })

    expect(signatureValid).toBe(false)
  })

  it('forwards probe and challenge_response from a custom collector', async () => {
    const recorded: RecordedRequest[] = []
    const fetch = mockFetch(
      {
        challenge: { body: sampleChallenge() },
        identify: { body: sampleIdentify() },
      },
      recorded,
    )
    const collector: Collector = (challenge) =>
      Promise.resolve({
        stable_components: { userAgent: 'Chrome/120' },
        challenge_response: { canvas: `rendered:${challenge.nonce}` },
        probe: 'cafebabe',
      })

    await run({ baseUrl: 'https://fp.example.com', collect: collector, fetch })

    const identifyRequest = recorded.find((r) => r.url.endsWith('/identify'))
    const sent = JSON.parse(identifyRequest?.body ?? '{}')
    expect(sent.probe).toBe('cafebabe')
    expect(sent.challenge_response).toEqual({ canvas: 'rendered:nonce-abc' })
    expect(sent.stable_components).toEqual({ userAgent: 'Chrome/120' })
  })
})
