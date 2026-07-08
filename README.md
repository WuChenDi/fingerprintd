# fingerprintd

Server-side device fingerprinting service (anti-fraud / anti-automation). The
service issues one-time challenges and computes a `visitorId` + `confidence`
server-side; the client only collects signals. See `docs/prd.md` for the full
product spec.

## Status

The server implements the full **P0–P3** feature set: one-time nonce
`/challenge` issuance and lifecycle, `/identify` with server-side `visitorId` +
`confidence`, fuzzy matching, passive signal collection, and server-side
hardening (probe key, response signing, timestamp-window enforcement — the
hardening controls are config-gated). Alongside it ships the **PC client shell**
under `packages/client`: a TypeScript SDK integrating FingerprintJS/BotD, a
nonce-challenge collector, and a Rust/WASM probe core (`crates/fp-wasm`).

A second **Cloudflare Workers** deployment target ships under `apps/edge`: a
TypeScript host (nonce Durable Object + D1 candidate index + routing) calling the
same engine compiled to WASM (`crates/fp-wasm` → `crates/fp-core`), so a client
works against **either** the Axum server or the edge Worker. The two stacks are
parity-verified against a shared fixture — see
[`apps/edge/README.md`](apps/edge/README.md).

| Endpoint     | Method | Purpose                                          |
| ------------ | ------ | ------------------------------------------------ |
| `/health`    | GET    | Liveness (`200 OK`)                              |
| `/challenge` | GET    | Issue a one-time nonce challenge                 |
| `/identify`  | POST   | Compute `visitorId` + `confidence` from signals  |

Verified test counts:

- **Rust workspace: 96** — `cargo nextest run --all-features` (46 in `fp-core`,
  40 in `fingerprintd` incl. cross-stack parity, 10 in `fp-wasm`)
- **Client: 34** — `vitest` (in `packages/client`)
- **Edge Worker: 27** — `cd apps/edge && bun run test` (router + state +
  cross-stack parity in miniflare)

**Environment limits:** the client tests run without a headless browser (jsdom +
mocked `fetch`, canvas, and audio backends only); the edge Worker runs
local-only (miniflare, no Cloudflare account). Real in-browser certification and
a real Cloudflare deploy are deferred to a human — see `packages/client/README.md`
and `apps/edge/README.md`.

## Project structure

```
Cargo.toml                       # workspace root (edition 2024, lints, deps)
crates/
  fp-core/                       # framework-free compute + storage traits (shared)
  fingerprintd/                  # Axum server (challenge / identify / matching)
  fp-wasm/                       # Rust/WASM probe core + edge FpEngine
packages/
  client/                        # TypeScript SDK (FingerprintJS/BotD + collector)
apps/
  edge/                          # Cloudflare Worker (TS host + WASM engine + DO/D1)
  web/                           # React/Vite playground for the challenge/identify flow
docs/
  prd.md                         # product spec
  design-fuzzy-matching.md       # fuzzy-matching design
  audit/audit-report.md          # PRD audit report
```

`crates/fingerprintd/src/lib.rs` exposes `build_router() -> axum::Router`, the
single place HTTP routes are mounted.

Design and specification docs live under [`docs/`](docs/):

- [`docs/prd.md`](docs/prd.md) — product spec
- [`docs/design-fuzzy-matching.md`](docs/design-fuzzy-matching.md) — fuzzy-matching design
- [`docs/audit/audit-report.md`](docs/audit/audit-report.md) — PRD audit report

## Configuration

Layered (increasing priority): built-in defaults → `fingerprintd.toml` →
`FINGERPRINTD_`-prefixed environment variables.

| Key         | Env var                   | Default          |
| ----------- | ------------------------- | ---------------- |
| `bind_addr` | `FINGERPRINTD_BIND_ADDR`  | `127.0.0.1:8080` |

## Build & run

```bash
# Run the server (listens on 127.0.0.1:8080 by default)
cargo run -p fingerprintd

# Override the bind address
FINGERPRINTD_BIND_ADDR=0.0.0.0:9000 cargo run -p fingerprintd

# Probe liveness
curl -i http://127.0.0.1:8080/health
```

Log level is controlled by `RUST_LOG` (defaults to `info`).

## Quality gate

The full green bar (run from the workspace root):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features   # or: cargo test --all-features
cargo build --all-targets
cargo deny check
```

The deny-warnings policy lives in `[workspace.lints]` (pma-rust Lock 4); CI runs
the same commands (`.github/workflows/ci.yml`).
