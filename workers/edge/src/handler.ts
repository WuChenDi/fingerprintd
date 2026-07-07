/**
 * The edge request router (PRD §5), state-free and dependency-injected so it is
 * unit-testable without the Workers runtime.
 *
 * It serves the same three routes as the native server
 * (`crates/fingerprintd/src/lib.rs`) with byte-compatible bodies, so a client
 * works against either:
 *   - `GET  /health`    — liveness, always `200`.
 *   - `GET  /challenge` — mint a one-time nonce + collection plan.
 *   - `POST /identify`  — burn the nonce, then score via the WASM engine.
 *
 * The nonce and candidate index are injected ({@link Deps}); PCF3 wires the
 * STUBBED in-memory / empty implementations, PCF4 swaps in the Durable Object
 * and D1. The orchestration here — derive blocking keys → recall candidates →
 * score → persist — is the real edge host flow, unchanged when state lands.
 */

import type { EdgeConfig } from './config'
import type { EdgeEngine } from './engine'
import { SIGNATURE_HEADER, SIGNATURE_TIMESTAMP_HEADER } from './signature'
import type { CandidateSource, NonceStore } from './state'
import type {
  ChallengeResponse,
  IdentifyRequest,
  IdentifyResponse,
  ProbeDescriptor,
  Signals,
} from './types'

/** Everything the router needs, injected so tests supply fakes. */
export interface Deps {
  engine: EdgeEngine
  nonces: NonceStore
  candidates: CandidateSource
  config: EdgeConfig
}

/** Stable probe identifiers advertised in `GET /challenge` (matches the server). */
const STABLE_PROBES = ['userAgent', 'languages', 'timezone', 'platform']
/** Active challenge targets seeded with the nonce. */
const CHALLENGE_TARGETS = ['canvas', 'audio']
/** The fixed nonce-probe transform advertised under probe enforcement (T8). */
const PROBE_DESCRIPTOR: ProbeDescriptor = {
  alg: 'HMAC-SHA256',
  input: 'nonce',
  encoding: 'hex',
}

/** Route a request to its handler; unknown routes yield `404`. */
export async function handleRequest(
  request: Request,
  deps: Deps,
): Promise<Response> {
  const { pathname } = new URL(request.url)
  if (request.method === 'GET' && pathname === '/health') {
    return new Response(null, { status: 200 })
  }
  if (request.method === 'GET' && pathname === '/challenge') {
    return handleChallenge(deps)
  }
  if (request.method === 'POST' && pathname === '/identify') {
    return handleIdentify(request, deps)
  }
  return new Response('not found', { status: 404 })
}

/** `GET /challenge` — mint a one-time nonce and return the collection plan. */
async function handleChallenge(deps: Deps): Promise<Response> {
  const { nonce, ttlSecs } = await deps.nonces.issue()
  // Advertise the probe transform only when probe enforcement is on, so a
  // probe-capable client knows to compute it (T8).
  const verify = deps.config.probeKey ? PROBE_DESCRIPTOR : undefined
  const body: ChallengeResponse = {
    nonce,
    expires_in: ttlSecs,
    collect: {
      stable: STABLE_PROBES,
      challenge: { seed: nonce, targets: CHALLENGE_TARGETS, verify },
    },
  }
  return jsonResponse(body)
}

/**
 * `POST /identify` — burn the nonce (anti-replay), optionally verify the probe
 * and timestamp window, then score the device via the WASM engine.
 *
 * A non-`valid` nonce, a bad probe, or an out-of-window timestamp yields `401`
 * before any scoring runs — fail-closed once each check is enabled.
 */
async function handleIdentify(request: Request, deps: Deps): Promise<Response> {
  let req: IdentifyRequest
  try {
    req = (await request.json()) as IdentifyRequest
  } catch {
    return new Response('invalid JSON', { status: 400 })
  }

  // Primary anti-replay lock: consume the one-time nonce first.
  if ((await deps.nonces.consume(req.nonce)) !== 'valid') {
    return unauthorized()
  }

  // Depth check on top of the nonce (T8): require a correct probe when a probe
  // key is configured. A missing or forged probe is rejected before scoring.
  if (deps.config.probeKey) {
    if (!req.probe || !deps.engine.verifyProbe(req.nonce, req.probe)) {
      return unauthorized()
    }
  }

  const now = Date.now()

  // Timestamp window (T9): when enabled, require the client `ts` within the
  // configured skew of server time. Fail-closed: missing/out-of-window ⇒ 401.
  if (deps.config.enforceTsWindow) {
    if (req.ts === undefined || !inWindow(req.ts, now, deps.config.tsSkewMs)) {
      return unauthorized()
    }
  }

  // Host I/O orchestration: derive blocking keys → recall the candidate block
  // → score → persist the verdict. The engine is pure; the host owns state, so
  // it writes back per the decision (drift a match, mint a new device, leave a
  // review untouched) — mirroring `fp_core`'s `identify`.
  const components = req.stable_components
  const blockingKeys = deps.engine.blockingKeys(components)
  const candidates = await deps.candidates.recall(blockingKeys)
  const outcome = deps.engine.score(components, candidates)
  await deps.candidates.persist(outcome, components, blockingKeys, now)

  // The engine returns the pure match verdict; the passive-signal summary is a
  // host concern. The JA4/IP fusion (`crates/fingerprintd/src/signals.rs`) is
  // HeaderMap-coupled and not in the WASM compute, so PCF3 emits the server's
  // neutral "degraded" default (no Bot Management headers). Porting the fusion
  // is deferred to a later step; the response shape is already correct.
  const response: IdentifyResponse = {
    visitorId: outcome.visitor_id,
    confidence: outcome.confidence,
    is_new_device: outcome.is_new_device,
    decision: outcome.decision,
    collision_risk: outcome.collision_risk,
    signals: neutralSignals(),
  }

  return signedJson(response, deps.config, deps.engine, now)
}

/** Whether a client `ts` sits within `±skewMs` of `now` (both Unix ms). */
function inWindow(clientTs: number, now: number, skewMs: number): boolean {
  return Math.abs(now - clientTs) <= skewMs
}

/** The neutral passive-signal summary emitted when connection signals are
 *  absent — matches the native server's graceful-degrade default (§4.2). */
function neutralSignals(): Signals {
  return { ua_tls_consistent: true, ip_risk: 'low' }
}

/** A `200 application/json` response over a stable serialization. */
function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

/**
 * Serialize the `/identify` body once and, when signing is enabled, attach the
 * `x-fp-timestamp` / `x-fp-signature` headers over those EXACT bytes so what is
 * signed equals what is sent (T9).
 */
function signedJson(
  response: IdentifyResponse,
  config: EdgeConfig,
  engine: EdgeEngine,
  issuedMs: number,
): Response {
  const body = new TextEncoder().encode(JSON.stringify(response))
  const headers = new Headers({ 'content-type': 'application/json' })
  if (config.signingKey) {
    headers.set(SIGNATURE_TIMESTAMP_HEADER, String(issuedMs))
    headers.set(SIGNATURE_HEADER, engine.sign(issuedMs, body))
  }
  return new Response(body, { status: 200, headers })
}

/** Uniform `401` used for every failed anti-replay / verification check. */
function unauthorized(): Response {
  return new Response('unauthorized', { status: 401 })
}
