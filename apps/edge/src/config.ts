/**
 * Edge Worker configuration, resolved from the runtime environment.
 *
 * The defaults mirror the native server's `Config::default`
 * (`crates/fingerprintd/src/config.rs`): probe enforcement OFF, response signing
 * OFF, timestamp window OFF, nonce TTL 30s, ±30s skew. With no bindings set the
 * Worker therefore behaves like a default `fingerprintd`, so a client works
 * against either unchanged.
 *
 * In a real deployment `FP_SALT_SECRET`, `FP_PROBE_KEY`, and `FP_SIGNING_KEY`
 * are Worker Secrets; the rest are `[vars]`. Secrets are never embedded.
 */

/** Cloudflare Worker environment bindings: string-typed config vars plus the
 *  PCF4 state bindings. All optional so the router stays unit-testable with
 *  injected stubs and the Worker degrades to in-isolate state when unbound. */
export interface Env {
  /** Nonce Durable Object namespace (PCF4). Unbound ⇒ the in-isolate stub. */
  NONCE?: DurableObjectNamespace
  /** D1 fingerprint database (PCF4). Unbound ⇒ the empty candidate stub. */
  DB?: D1Database
  /** Seeds the deterministic salt + MinHash family so blocking keys are stable
   *  across isolates (Worker Secret). Falls back to a dev-only placeholder. */
  FP_SALT_SECRET?: string
  /** Pre-shared nonce-probe key (T8, Worker Secret). Empty/unset ⇒ probe OFF. */
  FP_PROBE_KEY?: string
  /** Response-signing key (T9, Worker Secret). Empty/unset ⇒ signing OFF. */
  FP_SIGNING_KEY?: string
  /** `"1"`/`"true"` enables the request timestamp window (T9). Default OFF. */
  FP_ENFORCE_TS_WINDOW?: string
  /** Allowed clock skew in seconds when the timestamp window is on. Default 30. */
  FP_TS_SKEW_SECS?: string
  /** Nonce lifetime in seconds. Default 30. */
  FP_NONCE_TTL_SECS?: string
  /** `"1"`/`"true"` trusts edge-injected passive-signal headers. Default OFF. */
  FP_TRUST_EDGE_HEADERS?: string
  /** Comma-separated allowed CORS origins for the browser playground, e.g.
   *  `https://fingerprintd-web.example.workers.dev`. `*` allows any origin.
   *  Empty/unset ⇒ no CORS headers (same-origin / server-to-server only). */
  FP_CORS_ORIGINS?: string
}

/** Resolved, typed configuration for one Worker isolate. */
export interface EdgeConfig {
  /** Salt/MinHash seed passed to the WASM engine. Always non-empty. */
  saltSecret: string
  /** Nonce-probe key; `undefined` ⇒ probe verification is skipped (OFF). */
  probeKey?: string
  /** Response-signing key; `undefined` ⇒ responses are not signed (OFF). */
  signingKey?: string
  /** Whether to enforce the request timestamp window. */
  enforceTsWindow: boolean
  /** Allowed skew in milliseconds when the window is on. */
  tsSkewMs: number
  /** Nonce lifetime in seconds, advertised as `expires_in`. */
  nonceTtlSecs: number
  /** Whether edge-injected passive-signal headers are trusted. */
  trustEdgeHeaders: boolean
  /** Allowed CORS origins for the browser playground; `['*']` allows any.
   *  Empty ⇒ CORS disabled (no `Access-Control-*` headers emitted). */
  corsOrigins: string[]
}

/** A dev-only salt seed used when `FP_SALT_SECRET` is unset. A real deployment
 *  MUST set the secret, or blocking keys are neither private nor deployment-bound. */
const DEV_SALT_SECRET = 'fp-edge-dev-salt'

/** Read a boolean flag var: `"1"`, `"true"`, `"yes"` (case-insensitive) ⇒ true. */
function flag(value: string | undefined): boolean {
  if (value === undefined) return false
  const v = value.trim().toLowerCase()
  return v === '1' || v === 'true' || v === 'yes'
}

/** Read a non-negative integer var, falling back to `fallback` on absent/invalid. */
function intVar(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback
  const n = Number.parseInt(value, 10)
  return Number.isFinite(n) && n >= 0 ? n : fallback
}

/** Treat an empty/whitespace secret as unset so it disables its feature. */
function secret(value: string | undefined): string | undefined {
  if (value === undefined) return undefined
  const trimmed = value.trim()
  return trimmed.length > 0 ? value : undefined
}

/** Parse a comma-separated origin list, trimming blanks. Empty ⇒ CORS off. */
function originList(value: string | undefined): string[] {
  if (value === undefined) return []
  return value
    .split(',')
    .map((o) => o.trim())
    .filter((o) => o.length > 0)
}

/** Resolve the typed {@link EdgeConfig} from raw environment bindings. */
export function resolveConfig(env: Env): EdgeConfig {
  return {
    saltSecret: secret(env.FP_SALT_SECRET) ?? DEV_SALT_SECRET,
    probeKey: secret(env.FP_PROBE_KEY),
    signingKey: secret(env.FP_SIGNING_KEY),
    enforceTsWindow: flag(env.FP_ENFORCE_TS_WINDOW),
    tsSkewMs: intVar(env.FP_TS_SKEW_SECS, 30) * 1000,
    nonceTtlSecs: intVar(env.FP_NONCE_TTL_SECS, 30),
    trustEdgeHeaders: flag(env.FP_TRUST_EDGE_HEADERS),
    corsOrigins: originList(env.FP_CORS_ORIGINS),
  }
}
