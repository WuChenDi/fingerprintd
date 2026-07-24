/**
 * The edge Hono app (architecture §5), state-free and dependency-injected so it is
 * unit-testable without the Workers runtime.
 *
 * It serves the same three routes as the native server
 * (`crates/fingerprintd/src/lib.rs`) with byte-compatible bodies, so a client
 * works against either:
 *   - `GET  /health`    — liveness, always `200`.
 *   - `GET  /challenge` — mint a one-time nonce + collection plan.
 *   - `POST /identify`  — burn the nonce, then score via the WASM engine.
 *
 * The nonce and candidate index are injected ({@link Deps}); `index.ts` wires
 * the Durable Object + D1 adapters per isolate, tests supply fakes. The
 * orchestration — derive blocking keys → recall candidates → score → persist —
 * is the real edge host flow. `/identify` bodies are validated with Zod; the
 * emitted responses (including the signed `x-fp-*` headers) are byte-identical
 * to the pre-Hono handler so the cross-stack parity is unaffected.
 */

import { zValidator } from '@hono/zod-validator'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import * as z from 'zod'
import type { CheckinStore } from './checkin-state'
import type { AggregateResult } from './checkin-store-d1'
import type { EdgeConfig } from './config'
import type { EdgeEngine } from './engine'
import type { Aggregates } from './risk-config'
import { defaultProfiles } from './risk-config'
import { assess } from './risk-engine'
import { SIGNATURE_HEADER, SIGNATURE_TIMESTAMP_HEADER } from './signature'
import type { CandidateSource, NonceStore } from './state'
import type {
  AssessRequest,
  ChallengeResponse,
  IdentifyResponse,
  PassiveVerdict,
  ProbeDescriptor,
} from './types'

/** Everything the routes need, injected so tests supply fakes. */
export interface Deps {
  engine: EdgeEngine
  nonces: NonceStore
  candidates: CandidateSource
  config: EdgeConfig
  checkin: CheckinStore
}

/** Stable probe identifiers advertised in `GET /challenge` (matches the server). */
const STABLE_PROBES = ['userAgent', 'languages', 'timezone', 'platform']
/** Active challenge targets seeded with the nonce. */
const CHALLENGE_TARGETS = ['canvas', 'audio']
/** The fixed nonce-probe transform advertised under probe enforcement. */
const PROBE_DESCRIPTOR: ProbeDescriptor = {
  alg: 'HMAC-SHA256',
  input: 'nonce',
  encoding: 'hex',
}

/** Trusted edge headers carrying the passive signals, injected by Cloudflare —
 *  the SAME names the native adapter reads (`crates/fingerprintd/src/signals.rs`).
 *  Trusted only behind a trusted edge; a client-supplied copy is never trusted. */
const JA4_HEADER = 'cf-bot-management-ja4'
const CF_CONNECTING_IP = 'cf-connecting-ip'
/** Client-reported UA key spellings, in native precedence order
 *  (`crates/fingerprintd/src/lib.rs` `claimed_ua`). First string value wins. */
const CLAIMED_UA_KEYS = ['userAgent', 'user_agent', 'ua']

/**
 * `POST /identify` request body (architecture §5). `stable_components` is an arbitrary
 * component object (nested keys unrestricted); `probe`/`ts` are optional depth
 * checks. The schema is `.strict()` — any UNKNOWN top-level key (e.g. a stray
 * `challenge_response`) is REJECTED with a `400`, mirroring the native
 * `deny_unknown_fields`. This removes the former forward-compat
 * tolerance: a client must send exactly these fields.
 */
const identifySchema = z
  .object({
    nonce: z.string(),
    stable_components: z.record(z.string(), z.unknown()),
    probe: z.string().optional(),
    ts: z.number().optional(),
  })
  .strict()

/**
 * `POST /checkin/assess` request body. `.strict()` at the top level REJECTS any
 * unknown key — a body carrying edge-observed `ip`/`ts` is a `400`, since those
 * are observed edge-side and never client-supplied. `identify` is `.loose()` so
 * the full pass-through `IdentifyResponse` (confidence, decision, …) is accepted
 * while only the load-bearing `visitorId` / `signals` are validated.
 */
const assessSchema = z
  .object({
    accountId: z.string().min(1),
    action: z.literal('daily_checkin'),
    identify: z
      .object({
        visitorId: z.string().min(1),
        signals: z.object({
          ua_tls_consistent: z.boolean(),
          ip_risk: z.enum(['low', 'medium', 'high']),
        }),
      })
      .loose(),
  })
  .strict()

/** Build the edge Hono app over the injected {@link Deps}. */
export function createApp(deps: Deps): Hono {
  const app = new Hono()

  // Browser CORS for the playground. Off unless origins are configured
  // (`FP_CORS_ORIGINS`); when on, expose the signature headers so the browser
  // client can read them, and let the middleware answer preflight `OPTIONS`.
  const { corsOrigins } = deps.config
  if (corsOrigins.length > 0) {
    const allowAny = corsOrigins.includes('*')
    app.use(
      '*',
      cors({
        origin: allowAny ? '*' : corsOrigins,
        allowMethods: ['GET', 'POST', 'OPTIONS'],
        allowHeaders: ['Content-Type'],
        exposeHeaders: [SIGNATURE_TIMESTAMP_HEADER, SIGNATURE_HEADER],
        maxAge: 86400,
      }),
    )
  }

  app.get('/health', (c) => c.body(null, 200))

  app.get('/challenge', async () => {
    const { nonce, ttlSecs } = await deps.nonces.issue()
    // Advertise the probe transform only when probe enforcement is on, so a
    // probe-capable client knows to compute it.
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
  })

  app.post('/identify', zValidator('json', identifySchema), async (c) => {
    const req = c.req.valid('json')

    // Primary anti-replay lock: consume the one-time nonce first.
    if ((await deps.nonces.consume(req.nonce)) !== 'valid') {
      return unauthorized()
    }

    // Depth check on top of the nonce: require a correct probe when a probe
    // key is configured. A missing or forged probe is rejected before scoring.
    if (deps.config.probeKey) {
      if (!req.probe || !deps.engine.verifyProbe(req.nonce, req.probe)) {
        return unauthorized()
      }
    }

    const now = Date.now()

    // Timestamp window: when enabled, require the client `ts` within the
    // configured skew of server time. Fail-closed: missing/out-of-window ⇒ 401.
    if (deps.config.enforceTsWindow) {
      if (
        req.ts === undefined ||
        !inWindow(req.ts, now, deps.config.tsSkewMs)
      ) {
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

    // Cross-check the client-reported UA against the unforgeable edge-observed
    // TLS stack / IP and fuse the passive adjustment into confidence, exactly as
    // native (`crates/fingerprintd/src/lib.rs`). The verdict comes from the shared
    // WASM compute; the host only wires the trusted inputs and clamps.
    const verdict = edgeSignals(c.req.raw, components, deps)
    const confidence = clamp(outcome.confidence + verdict.confidence_adjustment)

    const response: IdentifyResponse = {
      visitorId: outcome.visitor_id,
      confidence,
      is_new_device: outcome.is_new_device,
      decision: outcome.decision,
      collision_risk: outcome.collision_risk,
      signals: {
        ua_tls_consistent: verdict.ua_tls_consistent,
        ip_risk: verdict.ip_risk,
        // Edge is stateless/score-only per request — it holds no cross-session
        // velocity store, so it always reports the neutral `low` band (the native
        // server computes the real one), mirroring an empty u_i/m_i store.
        new_device_velocity: 'low',
      },
    }

    return signedJson(response, deps.config, deps.engine, now)
  })

  // Check-in anti-farming decision layer: score a business `accountId` + the
  // fingerprintd verdict into an allow/challenge/deny gate. Independent of
  // `/identify` — the caller passes through an already-obtained identify body.
  // `ip`/`ts` are observed edge-side (never from the body); the event is
  // recorded BEFORE the aggregates are read so this check-in is reflected.
  app.post('/checkin/assess', zValidator('json', assessSchema), async (c) => {
    const req = c.req.valid('json')
    const { accountId, identify } = req

    const ip = c.req.raw.headers.get(CF_CONNECTING_IP)?.trim() ?? ''
    const ts = Date.now()

    await deps.checkin.record({
      accountId,
      visitorId: identify.visitorId,
      ip,
      ts,
    })
    const agg = await deps.checkin.getAggregates(
      accountId,
      identify.visitorId,
      ip,
      ts,
    )
    const result = assess(
      req as unknown as AssessRequest,
      toAggregates(agg),
      defaultProfiles[req.action],
    )
    return c.json(result)
  })

  // GDPR erasure: remove every trace of a visitor. Fail-closed and
  // admin-gated — never exposed without an explicit key, never leaks existence.
  //   - no admin key configured ⇒ endpoint DISABLED ⇒ 404 (as if unrouted).
  //   - missing/wrong `Authorization: Bearer <key>` ⇒ 401 (constant-time compare).
  //   - authorized ⇒ erase then 204, idempotent even for an unknown id.
  app.delete('/visitor/:id', async (c) => {
    const { adminKey } = deps.config
    if (!adminKey) return c.body(null, 404)

    const bearer = bearerToken(c.req.header('authorization'))
    if (bearer === undefined || !constantTimeEqual(bearer, adminKey)) {
      return c.body(null, 401)
    }

    await deps.candidates.erase(c.req.param('id'))
    return c.body(null, 204)
  })

  return app
}

/** Extract the token from an `Authorization: Bearer <token>` header, or
 *  `undefined` when the header is absent or not a bearer credential. */
function bearerToken(header: string | undefined): string | undefined {
  if (header === undefined) return undefined
  const match = /^Bearer (.+)$/.exec(header)
  return match ? match[1] : undefined
}

/**
 * Constant-time string equality for the admin credential check: unequal lengths
 * fail fast, but equal-length inputs are compared by XOR-accumulating every
 * char code so the loop never short-circuits on the first mismatch — a timing
 * side channel must not leak how many leading characters matched.
 */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return diff === 0
}

/** Whether a client `ts` sits within `±skewMs` of `now` (both Unix ms). */
function inWindow(clientTs: number, now: number, skewMs: number): boolean {
  return Math.abs(now - clientTs) <= skewMs
}

/**
 * Compute the passive-signal verdict for a request via the shared WASM compute.
 *
 * The trust boundary (architecture §4.2): edge-injected JA4/IP are read ONLY behind a
 * trusted edge. When `trustEdgeHeaders` is off we pass `undefined` for all three
 * inputs — an untrusted origin ignores any client-supplied copy — so the WASM
 * returns the degraded neutral verdict (`ua_tls_consistent: true`, `ip_risk:
 * "low"`, adjustment `0`). Fail-closed. Absent JA4 behind a trusted edge degrades
 * the same way, mirroring native (`crates/fingerprintd/src/lib.rs`).
 */
function edgeSignals(
  raw: Request,
  components: Record<string, unknown>,
  deps: Deps,
): PassiveVerdict {
  if (!deps.config.trustEdgeHeaders) {
    return deps.engine.passiveSignals(undefined, undefined, undefined)
  }
  const ja4 = (raw.headers.get(JA4_HEADER) ?? cfJa4(raw))?.trim() || undefined
  const clientIp = raw.headers.get(CF_CONNECTING_IP)?.trim() || undefined
  return deps.engine.passiveSignals(ja4, clientIp, claimedUa(components))
}

/** The Cloudflare-computed JA4 fallback from `request.cf.botManagement` when the
 *  header is absent. The property is not in the base workers-types, so read it
 *  defensively. */
function cfJa4(raw: Request): string | undefined {
  const cf = (raw as { cf?: { botManagement?: { ja4?: string } } }).cf
  return cf?.botManagement?.ja4
}

/** The client-reported UA under suspicion, taken from the body's stable
 *  components by native key precedence — the value the TLS stack cross-checks. */
function claimedUa(components: Record<string, unknown>): string | undefined {
  for (const key of CLAIMED_UA_KEYS) {
    const value = components[key]
    if (typeof value === 'string') return value
  }
  return undefined
}

/** Clamp a fused confidence into `[0, 1]` (fuzzy-matching §6). */
function clamp(value: number): number {
  return Math.min(1, Math.max(0, value))
}

/**
 * Reconcile the check-in store's nested {@link AggregateResult} to the risk
 * engine's flat {@link Aggregates}: the single window/metric each threshold is
 * defined against (fan-out on 24h, IP sharing on 1h, the churn `rate` and timing
 * `regularity` scalars). `account_device_count` and `batch_clustering` are not
 * thresholded today but carried so the shape is complete (batch as the larger of
 * the device/IP burst).
 */
function toAggregates(r: AggregateResult): Aggregates {
  return {
    device_account_fanout: r.device_account_fanout.h24,
    account_device_count: r.account_device_count.d7,
    account_new_device_rate: r.account_new_device_rate.rate,
    ip_account_count: r.ip_account_count.h1,
    checkin_interval_regularity: r.checkin_interval_regularity.regularity,
    batch_clustering: Math.max(
      r.batch_clustering.device,
      r.batch_clustering.ip,
    ),
  }
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
 * signed equals what is sent.
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
