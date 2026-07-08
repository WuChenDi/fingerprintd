/**
 * Nonce-seeded active-challenge collector (TC3).
 *
 * Produces the `challenge_response` half of a {@link import('./collect').Collector}:
 * for each target the server asks for (`collect.challenge.targets`), it renders
 * an output SEEDED BY THE NONCE (`collect.challenge.seed`), hashes that output
 * with SHA-256, and returns the hex digest, e.g. `{ canvas: <hex>, audio: <hex> }`.
 *
 * This is a self-written collector (PRD §4.4): it borrows the canvas/audio
 * technique as a stylistic base but derives its own nonce-seeded draw/tone plan
 * and never reuses FingerprintJS's visitorId path.
 *
 * DESIGN (PRD §4.1): `challenge_response` is a FRESHNESS proof ONLY. A different
 * nonce yields a different response BY CONSTRUCTION — that is the whole point, so
 * it can never be a matching signal. This module fills ONLY `challenge_response`
 * and never touches `stable_components` (owned by TC2).
 *
 * ENVIRONMENT LIMIT: there is no headless browser here, so the real canvas/audio
 * stacks cannot be exercised. The rendering surfaces are INJECTABLE — the DOM
 * defaults draw to a real `<canvas>` / `OfflineAudioContext`; tests inject
 * deterministic mocks. Real GPU/audio rendering is validated by a human; this
 * module does not claim real rendering fidelity.
 */

import type { Collector } from './collect'
import type { ChallengeResponse } from './types'

// --- deterministic seeding ---------------------------------------------------

/** FNV-1a 32-bit hash of a UTF-16 code-unit stream — a cheap, stable way to turn
 *  the nonce string into a numeric PRNG seed. Not cryptographic; only used to
 *  spread the nonce across the draw/tone plan. */
function fnv1a(input: string): number {
  let hash = 0x811c9dc5
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i)
    // FNV prime multiply in 32-bit space via Math.imul.
    hash = Math.imul(hash, 0x01000193)
  }
  return hash >>> 0
}

/** mulberry32 PRNG. Given a 32-bit seed, returns a generator of deterministic
 *  floats in `[0, 1)` — same seed always yields the same sequence. */
function mulberry32(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (state + 0x6d2b79f5) >>> 0
    let t = state
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

// --- hashing -----------------------------------------------------------------

/** Lowercase hex of bytes. */
function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, '0')
  }
  return out
}

/** SHA-256 → lowercase hex. WebCrypto is present in browsers and in the test
 *  runtime; there is no third-party hash dependency. */
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as BufferSource)
  return toHex(new Uint8Array(digest))
}

// --- canvas target -----------------------------------------------------------

/** The 2D drawing operations this collector uses. Deliberately a structural
 *  subset of the DOM `CanvasRenderingContext2D`, so the real context satisfies
 *  it and a test mock can implement just these members. */
export interface CanvasContext2D {
  fillStyle: string | CanvasGradient | CanvasPattern
  font: string
  textBaseline: CanvasTextBaseline
  fillRect(x: number, y: number, w: number, h: number): void
  fillText(text: string, x: number, y: number, maxWidth?: number): void
  beginPath(): void
  arc(
    x: number,
    y: number,
    radius: number,
    startAngle: number,
    endAngle: number,
    counterclockwise?: boolean,
  ): void
  fill(fillRule?: CanvasFillRule): void
}

/** A drawable canvas surface: a 2D context plus a stable serialization of what
 *  was drawn, which is the input to the hash. */
export interface CanvasSurface {
  /** The 2D drawing context. */
  context: CanvasContext2D
  /** Serialize the rendered surface to a stable string (e.g. `toDataURL()`). */
  serialize(): string
}

/** Builds a fresh {@link CanvasSurface}. Returns `null` when no canvas backend
 *  is available (e.g. headless/jsdom with no `<canvas>` support). */
export type CanvasSurfaceFactory = () => CanvasSurface | null

const CANVAS_WIDTH = 240
const CANVAS_HEIGHT = 60

/** Default DOM surface: an offscreen `<canvas>` serialized via `toDataURL()`. */
function domCanvasSurface(): CanvasSurface | null {
  if (typeof document === 'undefined') return null
  const canvas = document.createElement('canvas')
  canvas.width = CANVAS_WIDTH
  canvas.height = CANVAS_HEIGHT
  const context = canvas.getContext('2d')
  if (context === null) return null
  return { context, serialize: () => canvas.toDataURL() }
}

/** Draw a nonce-seeded scene into `context` and return its serialization.
 *  The draw plan (colours, positions, radii, and the stamped nonce text) is
 *  fully derived from `seed`, so identical seeds paint identical surfaces. */
function renderCanvas(surface: CanvasSurface, seed: string): string {
  const { context } = surface
  const rand = mulberry32(fnv1a(`canvas:${seed}`))

  // Opaque background so the readback is stable regardless of surface init.
  context.fillStyle = '#101820'
  context.fillRect(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT)

  // Stamp the nonce as text — this is what makes the output nonce-specific even
  // when the pseudo-random shape stream happens to collide.
  context.textBaseline = 'alphabetic'
  context.font = '18px serif'
  context.fillStyle = `hsl(${Math.floor(rand() * 360)}, 70%, 60%)`
  context.fillText(`fp:${seed}`, 4, 40)

  // A handful of nonce-seeded arcs on top of the text.
  for (let i = 0; i < 6; i++) {
    context.fillStyle = `hsl(${Math.floor(rand() * 360)}, 80%, 50%)`
    context.beginPath()
    context.arc(
      rand() * CANVAS_WIDTH,
      rand() * CANVAS_HEIGHT,
      2 + rand() * 8,
      0,
      Math.PI * 2,
    )
    context.fill()
  }

  return surface.serialize()
}

async function hashCanvas(
  seed: string,
  factory: CanvasSurfaceFactory,
): Promise<string> {
  const surface = factory()
  if (surface === null) {
    throw new Error('canvas challenge target unavailable: no 2D context')
  }
  const serialized = renderCanvas(surface, seed)
  return sha256Hex(new TextEncoder().encode(serialized))
}

// --- audio target ------------------------------------------------------------

/** Nonce-seeded tone parameters for the audio target. */
export interface AudioToneParams {
  /** Oscillator frequency in Hz. */
  frequency: number
  /** Linear gain applied to the tone. */
  gain: number
  /** Number of PCM frames to render. */
  frames: number
}

/** Renders a nonce-seeded tone and returns its PCM samples. Injectable so tests
 *  can supply a deterministic buffer without a real audio stack. */
export type AudioRenderer = (params: AudioToneParams) => Promise<Float32Array>

const AUDIO_SAMPLE_RATE = 44100
const AUDIO_FRAMES = 4096

/** Derive tone parameters from the nonce. Frequency and gain span audible,
 *  well-separated ranges so distinct nonces render distinguishable tones. */
function audioParams(seed: string): AudioToneParams {
  const rand = mulberry32(fnv1a(`audio:${seed}`))
  return {
    frequency: 120 + rand() * 1080,
    gain: 0.4 + rand() * 0.5,
    frames: AUDIO_FRAMES,
  }
}

/** Default DOM renderer: an `OfflineAudioContext` triangle oscillator. */
async function domAudioRenderer(
  params: AudioToneParams,
): Promise<Float32Array> {
  if (typeof OfflineAudioContext === 'undefined') {
    throw new Error(
      'audio challenge target unavailable: no OfflineAudioContext',
    )
  }
  const context = new OfflineAudioContext(1, params.frames, AUDIO_SAMPLE_RATE)
  const oscillator = context.createOscillator()
  oscillator.type = 'triangle'
  oscillator.frequency.value = params.frequency
  const gain = context.createGain()
  gain.gain.value = params.gain
  oscillator.connect(gain)
  gain.connect(context.destination)
  oscillator.start(0)
  const rendered = await context.startRendering()
  return rendered.getChannelData(0).slice()
}

async function hashAudio(
  seed: string,
  renderer: AudioRenderer,
): Promise<string> {
  const samples = await renderer(audioParams(seed))
  const bytes = new Uint8Array(
    samples.buffer,
    samples.byteOffset,
    samples.byteLength,
  )
  return sha256Hex(bytes)
}

// --- assembly ----------------------------------------------------------------

/** Injectable backends for the challenge targets. Both default to the DOM
 *  implementations; tests override them with deterministic mocks. */
export interface ChallengeCollectorOptions {
  /** Canvas surface factory (default: an offscreen DOM `<canvas>`). */
  canvas?: CanvasSurfaceFactory
  /** Audio renderer (default: an `OfflineAudioContext` tone). */
  audio?: AudioRenderer
}

/**
 * Compute the nonce-seeded `challenge_response` for a challenge.
 *
 * Renders each requested target (`collect.challenge.targets`), hashes it, and
 * returns `{ <target>: <hex digest> }`. Unknown targets are ignored so a server
 * can advertise a target this build does not implement yet. Same seed → same
 * response; different seed → different response.
 */
export async function collectChallengeResponse(
  challenge: ChallengeResponse,
  options: ChallengeCollectorOptions = {},
): Promise<Record<string, string>> {
  const canvasFactory = options.canvas ?? domCanvasSurface
  const audioRenderer = options.audio ?? domAudioRenderer
  const { seed, targets } = challenge.collect.challenge

  const response: Record<string, string> = {}
  for (const target of targets) {
    if (target === 'canvas') {
      response.canvas = await hashCanvas(seed, canvasFactory)
    } else if (target === 'audio') {
      response.audio = await hashAudio(seed, audioRenderer)
    }
  }
  return response
}

/**
 * A {@link Collector} that fills ONLY the challenge half — it emits the
 * nonce-seeded `challenge_response` and leaves `stable_components` empty (the
 * stable half is TC2's responsibility). Composed with a stable collector for a
 * full flow; usable on its own to drive `run()` end-to-end in tests.
 */
export function challengeCollector(
  options: ChallengeCollectorOptions = {},
): Collector {
  return async (challenge) => ({
    stable_components: {},
    challenge_response: await collectChallengeResponse(challenge, options),
  })
}
