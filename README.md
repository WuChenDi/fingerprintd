# fingerprintd

Server-side device fingerprinting service (anti-fraud / anti-automation). The
service issues one-time challenges and computes a `visitorId` + `confidence`
server-side; the client only collects signals. See `docs/prd.md` for the full
product spec.

## Status — P0 skeleton

This is the **T1 skeleton** only: a runnable Axum server, layered configuration,
and the CI quality gate. It exposes a single liveness endpoint. The
`/challenge` and `/identify` endpoints, nonce lifecycle, and fuzzy matching are
delivered in later tasks and mount onto `build_router` (see below).

| Endpoint      | Method | Response         |
| ------------- | ------ | ---------------- |
| `/health`     | GET    | `200 OK`         |

## Layout

```
Cargo.toml                       # workspace root (edition 2024, lints, deps)
crates/fingerprintd/
  src/lib.rs                     # build_router() — the HTTP extension point
  src/config.rs                  # Config + Config::load()
  src/main.rs                    # #[tokio::main] entry point
```

`build_router() -> axum::Router` is the single place routes are mounted; later
tasks chain additional `.route(...)` calls (and, when state is introduced,
switch to `Router::with_state`).

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
