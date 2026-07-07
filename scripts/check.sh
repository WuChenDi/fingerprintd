#!/usr/bin/env bash
# check.sh — cross-stack quality gate for fingerprintd.
# Runs the Rust, WASM, and TypeScript gates in sequence and fails on the
# first red (lint + typecheck + test + build across every stack).
# Idempotent and self-contained; run from anywhere inside the repo.
set -euo pipefail

# Resolve repo root so the script works regardless of the caller's cwd.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- Rust gate -------------------------------------------------------------
# shellcheck source=/dev/null
source "$HOME/.cargo/env"
echo "==> Rust gate"
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
cargo build --all-targets
cargo deny check

# --- WASM gate -------------------------------------------------------------
# Covered by --all-features above; run explicitly to guarantee the WASM
# probe core stays green on its own.
echo "==> WASM gate"
cargo test -p fp-wasm

# --- TypeScript gate -------------------------------------------------------
echo "==> TypeScript gate"
cd "$ROOT/clients/web"
bun install
bunx @biomejs/biome check .
bun run typecheck
bun run test
bun run build

echo "==> All gates green"
