#!/usr/bin/env bash
# clean.sh — remove build artifacts across every stack.
# Guards each removal with an existence check; never touches source.
# Idempotent: safe to run repeatedly.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- Rust ------------------------------------------------------------------
# shellcheck source=/dev/null
source "$HOME/.cargo/env"
echo "==> cargo clean"
cargo clean

# --- TypeScript ------------------------------------------------------------
for dir in clients/web/node_modules clients/web/dist; do
  if [ -d "$ROOT/$dir" ]; then
    echo "==> rm -rf $dir"
    rm -rf "${ROOT:?}/$dir"
  fi
done

echo "==> Clean complete"
