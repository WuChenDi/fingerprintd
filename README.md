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
under `clients/web`: a TypeScript SDK integrating FingerprintJS/BotD, a
nonce-challenge collector, and a Rust/WASM probe core (`crates/fp-wasm`).

| Endpoint     | Method | Purpose                                          |
| ------------ | ------ | ------------------------------------------------ |
| `/health`    | GET    | Liveness (`200 OK`)                              |
| `/challenge` | GET    | Issue a one-time nonce challenge                 |
| `/identify`  | POST   | Compute `visitorId` + `confidence` from signals  |

Verified test counts:

- **Core + server: 85** — `cargo nextest run` (46 in `fp-core`, 39 in `fingerprintd`)
- **Client: 34** — `vitest` (in `clients/web`)
- **WASM: 3** — `cargo test -p fp-wasm`

**Environment limit:** the client tests run without a headless browser (jsdom +
mocked `fetch`, canvas, and audio backends only). Real in-browser certification
is deferred to a human — see `clients/web/README.md`.

## Project structure

```
Cargo.toml                       # workspace root (edition 2024, lints, deps)
crates/
  fp-core/                       # framework-free compute + storage traits (shared)
  fingerprintd/                  # Axum server (challenge / identify / matching)
  fp-wasm/                       # Rust/WASM probe core
clients/
  web/                           # TypeScript SDK (FingerprintJS/BotD + collector)
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
