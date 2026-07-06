/**
 * Wire types for the fingerprintd HTTP surface.
 *
 * These are typed against the ACTUAL server structs (authoritative:
 * `crates/fingerprintd/src/lib.rs`), not the PRD prose. Keep them in sync with
 * that file — the server renames `visitor_id` -> `visitorId` via serde, and the
 * request field is `probe` (a hex string), NOT `probe_response`.
 */

/** Advertised nonce-probe transform (T8). Present in `GET /challenge` only when
 *  the server has a probe key configured; omitted otherwise. The client computes
 *  `encoding(alg(shared_key, input))` — i.e. `hex(HMAC-SHA256(key, nonce))` — and
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

/** `GET /challenge` response body (PRD §5). */
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
 * Only `nonce` and `stable_components` are always meaningful. The server reads
 * `probe` (T8) and `ts` (T9) only when the matching enforcement is configured;
 * otherwise they are ignored. `challenge_response` is a PRD §5 forward-compat
 * field the current server struct does NOT declare — but the server does not use
 * `deny_unknown_fields`, so sending it is safe and it is simply ignored today.
 */
export interface IdentifyRequest {
  /** The nonce previously minted by `GET /challenge`. */
  nonce: string
  /** Client timestamp in Unix milliseconds (T9). Checked only when the server's
   *  timestamp window is enforced; a missing/out-of-window value then yields 401. */
  ts?: number
  /** Nonce-probe response `hex(HMAC-SHA256(shared_key, nonce))` (T8). Verified
   *  only when the server has a probe key; a missing/wrong value then yields 401. */
  probe?: string
  /** Raw stable components (no nonce mixed in). Arbitrary JSON — the server
   *  scores these but the client never derives an id from them. */
  stable_components: Record<string, unknown>
  /** Freshness proof of the active challenge (PRD §5, forward-compat). Currently
   *  ignored by the server; NEVER a matching signal, only a liveness proof. */
  challenge_response?: Record<string, unknown>
}

/** Passive network-signal risk summary (PRD §5). */
export interface Signals {
  /** Whether the UA and edge-observed TLS fingerprint agree. */
  ua_tls_consistent: boolean
  /** Coarse IP risk band, e.g. `low` / `high`. */
  ip_risk: string
}

/** `POST /identify` success body (PRD §5). */
export interface IdentifyResponse {
  /** Stable device identifier (server-computed; serde-renamed from visitor_id). */
  visitorId: string
  /** Fused match confidence in `[0.0, 1.0]`. */
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
