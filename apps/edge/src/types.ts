/**
 * Wire types for the fingerprintd HTTP surface, as served by this edge Worker.
 *
 * These MUST stay byte-compatible with the shipped Axum server
 * (`crates/fingerprintd/src/lib.rs`) and the browser SDK
 * (`packages/client/src/types.ts`) so a client works against EITHER deployment. The
 * server renames `visitor_id` -> `visitorId` via serde; keep that here too.
 */

/** Advertised nonce-probe transform (T8). Present in `GET /challenge` only when
 *  the Worker has a probe key configured; omitted otherwise. The client computes
 *  `encoding(alg(shared_key, input))` — `hex(HMAC-SHA256(key, nonce))` — and
 *  echoes it as {@link IdentifyRequest.probe}. The shared key is never advertised. */
export interface ProbeDescriptor {
  /** Keyed-hash algorithm, e.g. `HMAC-SHA256`. */
  alg: string
  /** Transform input identifier — currently the string `nonce`. */
  input: string
  /** Output encoding of the computed tag, e.g. `hex`. */
  encoding: string
}

/** Active challenge descriptor (canvas/audio seeded with the nonce). */
export interface ChallengeProbe {
  /** Nonce used to seed the rendered challenge (equals the top-level nonce). */
  seed: string
  /** Probe targets to render, e.g. `['canvas', 'audio']`. */
  targets: string[]
  /** Nonce-probe transform to compute; present only under probe enforcement. */
  verify?: ProbeDescriptor
}

/** Client-side collection plan carried in a challenge response. */
export interface Collect {
  /** Stable probe identifiers to gather (e.g. userAgent, timezone). */
  stable: string[]
  /** Nonce-seeded active challenge. */
  challenge: ChallengeProbe
}

/** `GET /challenge` response body (architecture §5). */
export interface ChallengeResponse {
  /** The one-time nonce the client must echo on `identify`. */
  nonce: string
  /** Nonce lifetime in seconds. */
  expires_in: number
  /** Client-side collection plan. */
  collect: Collect
}

/**
 * `POST /identify` request body.
 *
 * Only `nonce` and `stable_components` are always meaningful. The Worker reads
 * `probe` (T8) and `ts` (T9) only when the matching enforcement is configured;
 * otherwise they are ignored. The request schema is strict (M6a/L1): any unknown
 * top-level field is REJECTED with `400` — there is no forward-compat
 * `challenge_response` tolerance.
 */
export interface IdentifyRequest {
  /** The nonce previously minted by `GET /challenge`. */
  nonce: string
  /** Client timestamp in Unix milliseconds (T9). Checked only when the Worker's
   *  timestamp window is enforced; a missing/out-of-window value then yields 401. */
  ts?: number
  /** Nonce-probe response `hex(HMAC-SHA256(shared_key, nonce))` (T8). Verified
   *  only when the Worker has a probe key; a missing/wrong value then yields 401. */
  probe?: string
  /** Raw stable components (no nonce mixed in). Arbitrary JSON — the engine
   *  scores these but never derives an id from the client's copy. */
  stable_components: Record<string, unknown>
}

/** Passive network-signal risk summary (architecture §5). */
export interface Signals {
  /** Whether the UA and edge-observed TLS fingerprint agree. */
  ua_tls_consistent: boolean
  /** Coarse IP risk band, e.g. `low` / `high`. */
  ip_risk: string
}

/**
 * Passive-signal verdict returned by the shared WASM `passive_signals` export
 * (`fp_core::signals`). The host maps the boolean + band into {@link Signals} and
 * fuses `confidence_adjustment` into `/identify` confidence — never the visitorId.
 */
export interface PassiveVerdict {
  /** Whether the UA claim and the edge-observed TLS stack agree (false ⇒ forgery). */
  ua_tls_consistent: boolean
  /** Coarse IP risk band, `low` / `medium` / `high`. */
  ip_risk: string
  /** Signed confidence delta: positive boost, negative downgrade, `0` degraded. */
  confidence_adjustment: number
}

/** `POST /identify` success body (architecture §5). */
export interface IdentifyResponse {
  /** Stable device identifier (server-computed; serde-renamed from visitor_id). */
  visitorId: string
  /** Fused match confidence in `[0.0, 1.0]`. This is DECISION confidence, not
   *  identity trust (M3): a first-ever new device can carry a HIGH confidence yet
   *  is entirely unestablished. Consumers must key trust off `is_new_device` /
   *  `decision`, never off `confidence` alone. */
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
 * The raw verdict returned by the WASM engine's `score` (snake_case, from
 * `fp_core::fuzzy::MatchOutcome`). The host maps it into {@link IdentifyResponse},
 * dropping the diagnostic-only `score` / `compared_components` fields and adding
 * the host-owned `signals`.
 */
export interface ScoreOutcome {
  visitor_id: string
  is_new_device: boolean
  decision: 'match' | 'review' | 'new_device'
  confidence: number
  score: number | null
  compared_components: number
  collision_risk: boolean
}
