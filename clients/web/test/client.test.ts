import { describe, expect, it } from 'vitest'
import { getChallenge, identify } from '../src/client'
import type { IdentifyRequest } from '../src/types'
import type { RecordedRequest } from './helpers'
import { mockFetch, sampleChallenge, sampleIdentify } from './helpers'

describe('getChallenge', () => {
  it('fetches and parses the challenge body', async () => {
    const recorded: RecordedRequest[] = []
    const fetch = mockFetch(
      { challenge: { body: sampleChallenge() } },
      recorded,
    )

    const challenge = await getChallenge('https://fp.example.com/', { fetch })

    expect(challenge.nonce).toBe('nonce-abc')
    expect(challenge.expires_in).toBe(30)
    expect(challenge.collect.challenge.targets).toEqual(['canvas', 'audio'])
    // Trailing slash collapsed, GET to /challenge.
    expect(recorded[0]?.url).toBe('https://fp.example.com/challenge')
    expect(recorded[0]?.method).toBe('GET')
  })

  it('throws on a non-ok status', async () => {
    const fetch = mockFetch({ challenge: { status: 500, body: {} } })
    await expect(
      getChallenge('https://fp.example.com', { fetch }),
    ).rejects.toThrow('500')
  })
})

describe('identify', () => {
  it('posts the full body shape when optional fields are present', async () => {
    const recorded: RecordedRequest[] = []
    const fetch = mockFetch({ identify: { body: sampleIdentify() } }, recorded)

    const body: IdentifyRequest = {
      nonce: 'n1',
      ts: 1_700_000_000_000,
      probe: 'deadbeef',
      stable_components: { userAgent: 'Chrome/120' },
      challenge_response: { canvas: 'abc' },
    }
    await identify('https://fp.example.com', body, { fetch })

    const sent = JSON.parse(recorded[0]?.body ?? '{}')
    expect(sent).toEqual(body)
    expect(recorded[0]?.method).toBe('POST')
  })

  it('omits optional fields left unset', async () => {
    const recorded: RecordedRequest[] = []
    const fetch = mockFetch({ identify: { body: sampleIdentify() } }, recorded)

    await identify(
      'https://fp.example.com',
      { nonce: 'n1', stable_components: { ua: 'x' } },
      { fetch },
    )

    const sent = JSON.parse(recorded[0]?.body ?? '{}')
    expect(sent).toEqual({ nonce: 'n1', stable_components: { ua: 'x' } })
    expect('ts' in sent).toBe(false)
    expect('probe' in sent).toBe(false)
    expect('challenge_response' in sent).toBe(false)
  })

  it('returns the parsed body plus signature headers when signed', async () => {
    const fetch = mockFetch({
      identify: {
        headers: {
          'x-fp-timestamp': '1700000000000',
          'x-fp-signature': 'ab12',
        },
        body: sampleIdentify(),
      },
    })

    const { result, timestamp, signature } = await identify(
      'https://fp.example.com',
      { nonce: 'n1', stable_components: {} },
      { fetch },
    )

    expect(result.visitorId).toBe('v_123')
    expect(timestamp).toBe('1700000000000')
    expect(signature).toBe('ab12')
  })

  it('leaves signature fields undefined when the response is unsigned', async () => {
    const fetch = mockFetch({ identify: { body: sampleIdentify() } })
    const { timestamp, signature } = await identify(
      'https://fp.example.com',
      { nonce: 'n1', stable_components: {} },
      { fetch },
    )
    expect(timestamp).toBeUndefined()
    expect(signature).toBeUndefined()
  })
})
