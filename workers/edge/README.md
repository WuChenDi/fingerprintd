# @fingerprintd/edge

Cloudflare Worker deployment of the fingerprintd challenge/identify flow:
a **TypeScript host** that owns I/O and routing, calling **Rust compiled to WASM**
(`crates/fp-wasm` → `crates/fp-core`) for the pure compute. It is the second
deployment target for the same engine as the native Axum server
(`crates/fingerprintd`) — a client works against **either** unchanged.

## Status: PCF4 — state layer wired (nonce Durable Object + D1)

The request surface, the WASM engine, **and** the externalized state now run:

| Concern | Status | Notes |
| --- | --- | --- |
| Router `/health` `/challenge` `/identify` | ✅ real, byte-compatible with the server | |
| WASM compute (blocking keys, scoring, probe, signing) | ✅ real (`FpEngine`) | |
| One-time nonce | ✅ Durable Object (`NonceDurableObject`) | atomic check-and-burn + TTL alarm |
| Fingerprint library + blocking index | ✅ D1 (`templates`, `blocking_index`) | recall → score → drift write-back |
| `value_frequency` (global `u_i`) | 🟡 schema provisioned, not yet wired | PCF5 refinement (see below) |
| Passive signals (JA4/IP) | 🟡 neutral degraded default | host-side port deferred |

The orchestration in `src/handler.ts` — derive blocking keys → recall candidates
→ score → persist per the verdict — is the **real edge host flow**, mirroring
`fp_core`'s `identify`. State is injected (`NonceStore` / `CandidateSource`), so
the router is unchanged whether it runs on the Durable Object + D1 (Worker) or
the in-isolate stubs (Node unit tests, or a bare `wrangler dev` with no bindings).

### Deferred to PCF5 (parity)

- **Global frequency (`u_i`).** The native scorer reads a global `value_hash →
  count` table; the WASM `score` approximates `u_i` over the recalled candidate
  block. The `value_frequency` table is provisioned (migration `0001`) so wiring
  the global snapshot — and populating it via a WASM-exposed salted hasher — is a
  pure addition, not a migration.
- **Template-merge edge cases.** Drift merges raw components per key (present
  overwrites, absent retained). Native additionally drops null/invalid values
  from the stored form; the WASM re-derivation drops them at score time, so the
  scoring input matches, but the stored blob can differ. Finalized in PCF5.

## Layout

```
src/
  index.ts                Worker entry — imports the .wasm, builds engine + state
                          per isolate, re-exports the nonce Durable Object
  handler.ts              state-free router (dependency-injected, unit-testable)
  engine.ts               typed wrapper around the FpEngine WASM class + one-time init
  state.ts                NonceStore / CandidateSource contracts + in-isolate stubs
  nonce-do.ts             NonceDurableObject (atomic burn) + DurableNonceStore adapter
  fingerprint-store-d1.ts D1 recall + drift persistence (templates + blocking index)
  config.ts               resolve typed config + state bindings from env
  types.ts                wire types, kept in sync with the server + browser SDK
  signature.ts            response-signature header names (T9)
migrations/               D1 schema (applied with `wrangler d1 migrations apply`)
wasm/                     vendored `wasm-pack --target web` build of crates/fp-wasm
```

## Configuration

With **no** environment set the Worker mirrors a default `fingerprintd`: probe
enforcement off, response signing off, timestamp window off, 30s nonce TTL. All
secrets are read at runtime — never embedded.

| Binding | Role | Default |
| --- | --- | --- |
| `FP_SALT_SECRET` (secret) | seeds the deterministic salt + MinHash family | dev placeholder |
| `FP_PROBE_KEY` (secret) | nonce-probe key (T8); unset ⇒ probe check off | off |
| `FP_SIGNING_KEY` (secret) | response-signing key (T9); unset ⇒ signing off | off |
| `FP_ENFORCE_TS_WINDOW` (var) | `"1"`/`"true"` enables the timestamp window | off |
| `FP_TS_SKEW_SECS` (var) | allowed clock skew when the window is on | 30 |
| `FP_NONCE_TTL_SECS` (var) | nonce lifetime, advertised as `expires_in` | 30 |
| `FP_TRUST_EDGE_HEADERS` (var) | trust edge-injected passive-signal headers | off |
| `NONCE` (Durable Object) | one-time nonce store; unbound ⇒ in-isolate stub | — |
| `DB` (D1) | fingerprint library + blocking index; unbound ⇒ empty stub | — |

Set real secrets with `wrangler secret put FP_SALT_SECRET` (etc.); never commit them.
The `NONCE` / `DB` bindings are wired in `wrangler.toml`; a bare `wrangler dev`
without them falls back to the stubs (single-isolate nonce, every probe new).

## Develop & verify

```bash
bun install
bun run lint        # biome check .
bun run typecheck   # tsc --noEmit
bun run test        # vitest run — two projects:
                    #   node    — router contract over the vendored WASM
                    #   workers — state layer (nonce DO + D1) in real miniflare
bun run deploy:dry  # wrangler deploy --dry-run (bundles the Worker + .wasm + bindings)
bun run dev         # wrangler dev --local (local workerd; no account needed)
```

The `workers` test project (`*.workers.test.ts`) runs under
`@cloudflare/vitest-pool-workers`, so the Durable Object burn and the D1
recall/persist round-trips execute against the actual workerd runtime with the
`wrangler.toml` bindings live — a fresh local D1 with `migrations/` applied. No
Cloudflare account is needed; miniflare provides D1/DO locally.

Apply migrations to a real (or persistent local) D1 with:

```bash
wrangler d1 migrations apply fingerprintd --local   # local sqlite
wrangler d1 migrations apply fingerprintd            # remote (needs an account)
```

### Rebuilding the vendored WASM

`wasm/` is a committed `wasm-pack` artifact. Rebuild it after changing
`crates/fp-core` or `crates/fp-wasm`:

```bash
wasm-pack build --target web --out-dir workers/edge/wasm crates/fp-wasm
rm -f workers/edge/wasm/.gitignore workers/edge/wasm/package.json  # keep only the glue + .wasm
```

The server-side `FpEngine` takes its keys at runtime, so no build-time key
injection is needed here (unlike the browser probe in `clients/web`).

## Environment limit

There is **no Cloudflare account** in this environment and Durable Objects + D1
are paid, so only **local** execution is wired: `wrangler dev --local`,
`wrangler deploy --dry-run`, and the miniflare-backed `workers` test project.
The Durable Object and D1 bindings are fully declared in `wrangler.toml` and the
`database_id` is a local placeholder; a real remote deploy — swapping in the id
from `wrangler d1 create` and running `wrangler d1 migrations apply` — is
deferred to a human with an account.
