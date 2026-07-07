import { describe, expect, it } from 'vitest'
import type { AudioToneParams, CanvasSurface } from '../../src/challenge'
import {
  challengeCollector,
  collectChallengeResponse,
} from '../../src/challenge'
import type { ChallengeResponse } from '../../src/types'
import type { RecordedRequest } from '../helpers'
import { mockFetch, sampleIdentify } from '../helpers'

/**
 * There is NO headless browser here, so canvas/audio are MOCKED. Both mocks are
 * deterministic functions of the collector's nonce-derived draw/tone plan, so
 * they exercise the collector's determinism and separation guarantees without a
 * real GPU/audio stack. They do NOT validate real rendering fidelity.
 */

/** A canvas mock whose serialization is the log of every draw command. Same
 *  draw plan -> same log -> same hash. */
function mockCanvasSurface(): CanvasSurface {
  const log: string[] = []
  return {
    context: {
      fillStyle: '#000',
      font: '10px sans',
      textBaseline: 'alphabetic',
      fillRect(x, y, w, h) {
        log.push(`rect|${this.fillStyle}|${x},${y},${w},${h}`)
      },
      fillText(text, x, y) {
        log.push(`text|${this.fillStyle}|${this.font}|${text}|${x},${y}`)
      },
      beginPath() {
        log.push('begin')
      },
      arc(x, y, r, s, e) {
        log.push(`arc|${this.fillStyle}|${x},${y},${r},${s},${e}`)
      },
      fill() {
        log.push('fill')
      },
    },
    serialize: () => log.join(';'),
  }
}

/** An audio mock: a deterministic tone buffer computed from the tone params. No
 *  real oscillator — same params -> same samples. */
function mockAudioRenderer(params: AudioToneParams): Promise<Float32Array> {
  const samples = new Float32Array(params.frames)
  for (let i = 0; i < params.frames; i++) {
    samples[i] =
      params.gain * Math.sin((2 * Math.PI * params.frequency * i) / 44100)
  }
  return Promise.resolve(samples)
}

function challengeWith(nonce: string, targets: string[]): ChallengeResponse {
  return {
    nonce,
    expires_in: 30,
    collect: {
      stable: [],
      challenge: { seed: nonce, targets },
    },
  }
}

const mocks = { canvas: mockCanvasSurface, audio: mockAudioRenderer }

describe('collectChallengeResponse', () => {
  it('hashes every requested target into hex digests', async () => {
    const response = await collectChallengeResponse(
      challengeWith('nonce-abc', ['canvas', 'audio']),
      mocks,
    )
    expect(Object.keys(response).sort()).toEqual(['audio', 'canvas'])
    // SHA-256 hex = 64 lowercase hex chars.
    expect(response.canvas).toMatch(/^[0-9a-f]{64}$/)
    expect(response.audio).toMatch(/^[0-9a-f]{64}$/)
  })

  it('is deterministic: the same seed yields an identical response', async () => {
    const a = await collectChallengeResponse(
      challengeWith('same-seed', ['canvas', 'audio']),
      mocks,
    )
    const b = await collectChallengeResponse(
      challengeWith('same-seed', ['canvas', 'audio']),
      mocks,
    )
    expect(a).toEqual(b)
  })

  it('is nonce-sensitive: a different seed changes every target', async () => {
    const a = await collectChallengeResponse(
      challengeWith('seed-one', ['canvas', 'audio']),
      mocks,
    )
    const b = await collectChallengeResponse(
      challengeWith('seed-two', ['canvas', 'audio']),
      mocks,
    )
    expect(a.canvas).not.toBe(b.canvas)
    expect(a.audio).not.toBe(b.audio)
  })

  it('emits only the targets the challenge asks for', async () => {
    const canvasOnly = await collectChallengeResponse(
      challengeWith('nonce-abc', ['canvas']),
      mocks,
    )
    expect(Object.keys(canvasOnly)).toEqual(['canvas'])

    const audioOnly = await collectChallengeResponse(
      challengeWith('nonce-abc', ['audio']),
      mocks,
    )
    expect(Object.keys(audioOnly)).toEqual(['audio'])
  })

  it('ignores unknown targets without failing', async () => {
    const response = await collectChallengeResponse(
      challengeWith('nonce-abc', ['canvas', 'webgl']),
      mocks,
    )
    expect(Object.keys(response)).toEqual(['canvas'])
  })
})

describe('challengeCollector', () => {
  it('fills challenge_response and keeps stable_components empty (separate)', async () => {
    const collector = challengeCollector(mocks)
    const collected = await collector(
      challengeWith('nonce-abc', ['canvas', 'audio']),
    )
    // The challenge proof lives ONLY in challenge_response...
    expect(collected.challenge_response).toBeDefined()
    expect(collected.challenge_response?.canvas).toMatch(/^[0-9a-f]{64}$/)
    // ...never merged into the matching input.
    expect(collected.stable_components).toEqual({})
  })

  it('drives run() end-to-end with the freshness proof kept out of matching', async () => {
    const { run } = await import('../../src/index')
    const recorded: RecordedRequest[] = []
    const fetch = mockFetch(
      {
        challenge: { body: challengeWith('nonce-xyz', ['canvas', 'audio']) },
        identify: { body: sampleIdentify() },
      },
      recorded,
    )

    await run({
      baseUrl: 'https://fp.example.com',
      collect: challengeCollector(mocks),
      fetch,
    })

    const identifyRequest = recorded.find((r) => r.url.endsWith('/identify'))
    const sent = JSON.parse(identifyRequest?.body ?? '{}')
    expect(sent.stable_components).toEqual({})
    expect(sent.challenge_response.canvas).toMatch(/^[0-9a-f]{64}$/)
    expect(sent.challenge_response.audio).toMatch(/^[0-9a-f]{64}$/)
  })
})
