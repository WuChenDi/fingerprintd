# fingerprintd

**English** · [中文](README.zh-CN.md)

A **server-authoritative** device-fingerprinting service for anti-fraud and
anti-automation. The client only **collects** evidence; the server issues a
one-time challenge, fuzzy-matches the evidence against its fingerprint library,
and returns a `visitorId` + `confidence` + `decision`. The identity is never
computed on the client, so it cannot be forged or replayed.

- **Two deployment targets, one engine.** A native [Axum server](crates/fingerprintd)
  and a [Cloudflare Worker](apps/edge) host the same compute core
  ([`crates/fp-core`](crates/fp-core), compiled to WASM via
  [`crates/fp-wasm`](crates/fp-wasm)); a client works against either unchanged.
- **Browser SDK.** [`@cdlab/fingerprintd-client`](packages/client) integrates
  FingerprintJS/BotD, computes the nonce freshness probe in WASM, and submits —
  it never derives an id.
- **Stack.** Rust (edition 2024, `#![forbid(unsafe_code)]`) for the engine and
  native server; TypeScript/Bun + Biome for the SDK, edge Worker, and playground.

## What it does

At high-risk actions (login, signup, checkout, coupon redemption) the caller gets
a stable `visitorId` and a `confidence` for its risk engine: is this a new device,
is it consistent with a known device, and do the self-reported browser signals
agree with the unforgeable network-layer signals (bot detection)?

It deliberately does **not** aim for unbreakable defense — an L3 adversary can
forge any single signal. Its value is raising the cost of forgery and cross-checking
multiple signals for consistency. It is an anti-fraud tool, **not** a cross-site
tracker. The full rationale, threat model, and matching engine live in
[`DESIGN.md`](DESIGN.md).

## How it works

```
1. GET /challenge
   server mints a one-time nonce (short TTL, single-use) and returns
   it plus the collection plan

2. client collects (packages/client):
   - stable_components — canvas / webgl / fonts / audio / screen / UA …
     (NO nonce mixed in) → the identity-matching input
   - probe — hex(HMAC-SHA256(key, nonce)) computed in WASM
     → a freshness proof, NEVER a matching signal (defense in depth)

3. POST /identify  { nonce, stable_components, probe?, ts? }
   server:
     a. consume the nonce (burn-on-use)                    ← replay protection
     b. blocking-key recall → Fellegi–Sunter scoring       ← de-avalanche, high precision
     c. fuse passive JA4 / IP signals (UA↔TLS consistency) ← anti-forgery cross-check
     → visitorId + confidence + decision (+ passive signals)
```

## Endpoints

Both stacks serve the same wire contract; see [`DESIGN.md` architecture §5](DESIGN.md#5-http-interface).

| Endpoint        | Method | Purpose                                           |
| --------------- | ------ | ------------------------------------------------- |
| `/health`       | GET    | Liveness (`200 OK`)                               |
| `/challenge`    | GET    | Issue a one-time nonce challenge                  |
| `/identify`     | POST   | Compute `visitorId` + `confidence` + `decision`   |
| `/visitor/{id}` | DELETE | GDPR erasure — remove a visitor (admin-key gated) |

## Quick start

Run the native server (listens on `127.0.0.1:8080` by default):

```bash
cargo run -p fingerprintd

# override the bind address
FINGERPRINTD_BIND_ADDR=0.0.0.0:9000 cargo run -p fingerprintd

# probe liveness
curl -i http://127.0.0.1:8080/health
```

Log level is controlled by `RUST_LOG` (defaults to `info`).

To call it from a browser, use the SDK:

```ts
import { createCollector, run } from '@cdlab/fingerprintd-client'

const { identity } = await run({
  baseUrl: 'https://fp.example.com',
  collect: createCollector(),          // FingerprintJS + BotD + WASM probe
})
// identity: { visitorId, confidence, decision, is_new_device, collision_risk, signals }
```

For the serverless deployment (Cloudflare Worker + Durable Object nonce + D1
library) see [`apps/edge`](apps/edge/README.md). The
[playground](apps/web/README.md) drives the whole flow in a browser and visualizes
what the client sends vs. what the server judges.

## Configuration

Layered (increasing priority): built-in defaults → `fingerprintd.toml` →
`FINGERPRINTD_`-prefixed environment variables.

| Key                          | Env var                                   | Default          | Meaning                                                                     |
| ---------------------------- | ----------------------------------------- | ---------------- | --------------------------------------------------------------------------- |
| `bind_addr`                  | `FINGERPRINTD_BIND_ADDR`                  | `127.0.0.1:8080` | Listen address.                                                             |
| `nonce_ttl_secs`             | `FINGERPRINTD_NONCE_TTL_SECS`             | `30`             | One-time nonce lifetime, advertised as `expires_in`.                        |
| `trust_edge_headers`         | `FINGERPRINTD_TRUST_EDGE_HEADERS`         | `false`          | Trust edge-injected passive-signal headers (JA4/IP). **Fail-closed:** enable only behind a trusted edge; a directly-reachable origin must leave it off. |
| `probe_key`                  | `FINGERPRINTD_PROBE_KEY`                  | *(unset)*        | HMAC key enabling nonce-probe verification (defense in depth). Off if unset. |
| `response_signing_key`       | `FINGERPRINTD_RESPONSE_SIGNING_KEY`       | *(unset)*        | HMAC key enabling `/identify` response signatures. Off if unset.            |
| `enforce_ts_window`          | `FINGERPRINTD_ENFORCE_TS_WINDOW`          | `false`          | Enforce the request timestamp window.                                       |
| `ts_skew_secs`               | `FINGERPRINTD_TS_SKEW_SECS`               | `30`             | Allowed clock skew when the window is on.                                   |
| `admin_key`                  | `FINGERPRINTD_ADMIN_KEY`                  | *(unset)*        | Bearer key gating `DELETE /visitor/{id}`. Erasure is disabled if unset.     |
| `retention_secs`             | `FINGERPRINTD_RETENTION_SECS`             | `0`              | Evict stored records past this age (seconds). `0` disables the sweep.       |
| `fuzzy_max_records`          | `FINGERPRINTD_FUZZY_MAX_RECORDS`          | `1000000`        | Max distinct visitors; oldest-seen is evicted over cap.                     |
| `fuzzy_record_ttl_secs`      | `FINGERPRINTD_FUZZY_RECORD_TTL_SECS`      | `0`              | Evict records not seen within this window. `0` disables the TTL.            |
| `fuzzy_max_block`            | `FINGERPRINTD_FUZZY_MAX_BLOCK`            | `1024`           | Per-block visitor cap for the blocking index; over-cap inserts are dropped. |
| `fuzzy_max_frequency_values` | `FINGERPRINTD_FUZZY_MAX_FREQUENCY_VALUES` | `1000000`        | Cap on distinct tracked `u_i` frequency values; new values over cap drop.   |

The `probe_key` / `response_signing_key` / `admin_key` controls are **fail-closed
and off by default** — a control activates only once its key is set. The in-memory
capacity bounds are generous and fail-safe: a small workload behaves exactly like
an unbounded store, and every eviction or drop is counted, never silent. These
bounds apply to the native server only; the stateless edge is per-request.

## Design

[`DESIGN.md`](DESIGN.md) ([中文](DESIGN.zh-CN.md)) is the authoritative spec — the
architecture (background, threat model, challenge-response split, passive-signal
trust boundary, HTTP contract, privacy/compliance, deployment targets) and the
fuzzy-matching engine (two-stage blocking + Fellegi–Sunter scoring, drift,
cold-start, offline evaluation). Source doc-comments reference its section numbers
as `architecture §N` / `fuzzy-matching §N`.

## Project structure

```
crates/
  fp-core/          framework-free compute + storage traits (shared engine)
  fingerprintd/     native Axum server (challenge / identify / erasure)
  fp-wasm/          Rust→WASM probe core + edge FpEngine
packages/
  client/           TypeScript browser SDK (FingerprintJS/BotD + collector)
apps/
  edge/             Cloudflare Worker (TS host + WASM engine + Durable Object/D1)
  web/              React/Vite playground for the challenge/identify flow
DESIGN.md           architecture + fuzzy-matching spec (bilingual)
```

`crates/fingerprintd/src/lib.rs` exposes `build_router() -> axum::Router`, the
single place HTTP routes are mounted.

## Build & quality gate

The full green bar (run from the workspace root):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features          # or: cargo test --all-features
cargo build --all-targets
cargo deny check
```

The deny-warnings policy lives in `[workspace.lints]`; CI runs the same commands
plus the SDK and edge Worker suites (`.github/workflows/ci.yml`). The two Rust/TS
stacks are held to one behavior by a shared **parity fixture** exercised on both
sides (see [`apps/edge/README.md`](apps/edge/README.md)).

Per-component tooling:

- **SDK** — `cd packages/client && bun run lint && bun run typecheck && bun run test`
- **Edge Worker** — `cd apps/edge && bun run test` (router + state + parity in miniflare)
- **Playground** — `cd apps/web && bun run typecheck && bun run build`

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability-reporting policy. The probe
and response-signing keys shipped in client WASM/JS are **defense in depth, not a
decisive control** — the one-time nonce and TLS remain the primary guarantees.

## License

[Apache-2.0](LICENSE)
