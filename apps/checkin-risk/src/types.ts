/**
 * Wire types for the check-in risk Worker.
 *
 * {@link IdentifyResponse} (and its {@link Signals}) is a COPY of the
 * fingerprintd identify contract (`apps/edge/src/types.ts`), kept byte-compatible
 * so the caller can pass a verdict obtained from either the Axum server or the
 * edge Worker straight through. {@link AssessRequest} / {@link AssessResponse}
 * are the new check-in surface (PLAN-001); the rule engine (CHECKIN-003) and the
 * endpoint (CHECKIN-004) fill these in.
 */

/** Passive network-signal risk summary (fingerprintd identify contract). */
export interface Signals {
  /** Whether the UA and edge-observed TLS fingerprint agree. */
  ua_tls_consistent: boolean
  /** Coarse IP risk band, e.g. `low` / `high`. */
  ip_risk: 'low' | 'medium' | 'high'
}

/**
 * fingerprintd `POST /identify` success body. Copied byte-for-byte from
 * `apps/edge/src/types.ts` — must stay compatible with that contract and the
 * Axum server so a caller-supplied verdict deserializes unchanged.
 */
export interface IdentifyResponse {
  /** Stable device identifier (server-computed; serde-renamed from visitor_id). */
  visitorId: string
  /** Fused match confidence in `[0.0, 1.0]`. DECISION confidence, not identity
   *  trust: a first-ever new device can carry HIGH confidence yet is entirely
   *  unestablished — key trust off `is_new_device` / `decision`, never
   *  `confidence` alone. */
  confidence: number
  /** Whether this device was newly recorded. */
  is_new_device: boolean
  /** Verdict from the weighted engine. */
  decision: 'match' | 'review' | 'new_device'
  /** Set when a runner-up candidate also cleared the match threshold. */
  collision_risk: boolean
  /** Passive network-signal risk summary. */
  signals: Signals
}

/**
 * `POST /assess` request body (PLAN-001).
 *
 * `accountId` is the core new dimension: the business identity the caller wants
 * scored for check-in farming. `identify` is the fingerprintd verdict the caller
 * already obtained and passes through. IP and timestamp are observed edge-side
 * (never client-reported), so they are deliberately NOT fields here.
 */
export interface AssessRequest {
  /** Business identity being assessed — the core new dimension. */
  accountId: string
  /** Scenario tag selecting a threshold profile. MVP: this value only. */
  action: 'daily_checkin'
  /** fingerprintd identify verdict, obtained and passed through by the caller. */
  identify: IdentifyResponse
}

/** A single reason contributing to an {@link AssessResponse} decision. */
export interface AssessReason {
  /** Stable machine code for the reason, e.g. `NEW_DEVICE`. */
  code: string
  /** Human-readable explanation for logs/debugging. */
  detail: string
}

/** `POST /assess` success body (PLAN-001). */
export interface AssessResponse {
  /** Gate action the caller should take. */
  decision: 'allow' | 'challenge' | 'deny'
  /** Interpreted risk label. */
  verdict: 'human' | 'suspicious' | 'farming'
  /** Continuous risk score in `[0.0, 1.0]`. */
  risk: number
  /** Ordered reasons that produced the decision. */
  reasons: AssessReason[]
  /** The device identifier carried through from {@link IdentifyResponse}. */
  visitorId: string
}
