/**
 * The check-in risk Hono app.
 *
 * State-free and dependency-injected — mirroring `apps/edge/src/app.ts` — so it
 * is unit-testable without the Workers runtime. It serves `GET /health` plus
 * `POST /checkin/assess` (CHECKIN-004): validate the request, persist the event,
 * derive the PLAN-001 aggregates, and score them through the pure rule engine.
 * The storage layer (CHECKIN-002) and threshold profiles (CHECKIN-003) are
 * injected via {@link Deps}; `index.ts` wires the D1 store per isolate, tests
 * supply fakes. Both deps are optional so the app runs on empty fallbacks.
 */

import { Hono } from 'hono'
import type { AggregateResult } from './checkin-store-d1'
import type { Aggregates, ThresholdProfile } from './risk-config'
import { defaultProfiles } from './risk-config'
import { assess } from './risk-engine'
import type { CheckinStore } from './state'
import { EmptyCheckinStore } from './state'
import type { AssessRequest } from './types'

/** Everything the routes need, injected so tests supply fakes. Both fields are
 *  optional: unbound the app falls back to an empty store and the default
 *  threshold profiles, so `createApp({})` runs. */
export interface Deps {
  /** Append + aggregate backend; defaults to {@link EmptyCheckinStore}. */
  store?: CheckinStore
  /** Per-action threshold profiles (env override hook); defaults to
   *  {@link defaultProfiles}. */
  profiles?: Record<AssessRequest['action'], ThresholdProfile>
}

/** Header carrying the edge-observed client IP, injected by Cloudflare. Trusted
 *  only behind the edge; a client-supplied copy in the body is rejected. */
const CF_CONNECTING_IP = 'cf-connecting-ip'

/** Build the check-in risk Hono app over the injected {@link Deps}. */
export function createApp(deps: Deps): Hono {
  const app = new Hono()
  const store = deps.store ?? new EmptyCheckinStore()
  const profiles = deps.profiles ?? defaultProfiles

  app.get('/health', (c) => c.text('ok', 200))

  app.post('/checkin/assess', async (c) => {
    let body: unknown
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'invalid JSON body' }, 400)
    }

    const parsed = validateAssessRequest(body)
    if (!parsed.ok) return c.json({ error: parsed.error }, 400)
    const req = parsed.value

    // Edge-observed context — NEVER read from the body (PLAN-001: ip/ts are
    // observed edge-side). Mirror the edge Worker's cf-connecting-ip extraction;
    // absent (bare `wrangler dev` / test) it degrades to an empty IP.
    const ip = c.req.raw.headers.get(CF_CONNECTING_IP)?.trim() ?? ''
    const ts = Date.now()

    // Persist BEFORE scoring: the aggregates/verdict must reflect this check-in
    // (PLAN-001 acceptance ordering). No-op under the empty fallback.
    await store.record({
      accountId: req.accountId,
      visitorId: req.identify.visitorId,
      ip,
      ts,
    })

    const result = await store.getAggregates(
      req.accountId,
      req.identify.visitorId,
      ip,
      ts,
    )
    const response = assess(req, toAggregates(result), profiles[req.action])
    return c.json(response)
  })

  return app
}

/**
 * Reconcile the store's nested {@link AggregateResult} (CHECKIN-002) to the
 * engine's flat {@link Aggregates} (CHECKIN-003). The top-level keys already
 * match PLAN-001; this picks the single window/metric each threshold is defined
 * against: fan-out on the 24h window, IP sharing on the 1h window, the churn
 * `rate` and timing `regularity` scalars. `account_device_count` and
 * `batch_clustering` are not thresholded by `assess()` today but are carried so
 * the shape is complete (batch as the larger of the device/IP burst).
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

/** Outcome of {@link validateAssessRequest}: the typed request or a reason. */
type Validated =
  | { ok: true; value: AssessRequest }
  | { ok: false; error: string }

/** Accepted `ip_risk` bands (fingerprintd identify contract). */
const IP_RISK_VALUES = new Set(['low', 'medium', 'high'])
/** The ONLY top-level keys an {@link AssessRequest} may carry. */
const ALLOWED_KEYS = new Set(['accountId', 'action', 'identify'])

/**
 * Strictly validate an untrusted JSON body as an {@link AssessRequest}. Rejects
 * (as a 400 reason) anything but exactly `{ accountId, action, identify }`: any
 * unknown top-level key, a body carrying edge-observed `ip`/`ts`, a wrong
 * `action`, or an `identify` missing the load-bearing `visitorId` / `signals`
 * fields the engine reads. Extra fields WITHIN `identify` are tolerated so a
 * full pass-through `IdentifyResponse` (confidence, decision, …) is accepted.
 */
function validateAssessRequest(body: unknown): Validated {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return { ok: false, error: 'body must be a JSON object' }
  }
  const record = body as Record<string, unknown>

  // ip/ts are observed edge-side, never client-reported — reject, don't ignore.
  if ('ip' in record || 'ts' in record) {
    return {
      ok: false,
      error: 'ip/ts are observed edge-side, not client-supplied',
    }
  }
  for (const key of Object.keys(record)) {
    if (!ALLOWED_KEYS.has(key))
      return { ok: false, error: `unknown field: ${key}` }
  }

  if (typeof record.accountId !== 'string' || record.accountId.length === 0) {
    return { ok: false, error: 'accountId must be a non-empty string' }
  }
  if (record.action !== 'daily_checkin') {
    return { ok: false, error: "action must be 'daily_checkin'" }
  }

  const identify = record.identify
  if (
    typeof identify !== 'object' ||
    identify === null ||
    Array.isArray(identify)
  ) {
    return { ok: false, error: 'identify must be an object' }
  }
  const id = identify as Record<string, unknown>
  if (typeof id.visitorId !== 'string' || id.visitorId.length === 0) {
    return { ok: false, error: 'identify.visitorId must be a non-empty string' }
  }

  const signals = id.signals
  if (
    typeof signals !== 'object' ||
    signals === null ||
    Array.isArray(signals)
  ) {
    return { ok: false, error: 'identify.signals must be an object' }
  }
  const sig = signals as Record<string, unknown>
  if (typeof sig.ua_tls_consistent !== 'boolean') {
    return {
      ok: false,
      error: 'identify.signals.ua_tls_consistent must be a boolean',
    }
  }
  if (typeof sig.ip_risk !== 'string' || !IP_RISK_VALUES.has(sig.ip_risk)) {
    return {
      ok: false,
      error: 'identify.signals.ip_risk must be low|medium|high',
    }
  }

  return { ok: true, value: record as unknown as AssessRequest }
}
