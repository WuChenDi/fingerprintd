#!/usr/bin/env bash
# build-wasm.sh — build the vendored WASM (a BUILD ARTIFACT, not committed) from
# crates/fp-wasm into both consumer dirs:
#   apps/edge/wasm        the edge Worker bundles it; edge tests read it from disk
#   packages/client/wasm  the SDK glue; the repo-root `prepare` build imports it
#
# Run this once after a fresh clone (and after `bun run clean`) BEFORE `bun
# install` — install triggers the root `prepare` (SDK build) which imports the
# client glue, so it fails if the WASM is absent.
#
# Bakes the shared TEST probe key so the parity/vector fixtures pass — matches CI
# (ci-ts `wasm` job). A real deploy rebuilds with the deployment's FP_PROBE_KEY
# (see deploy-edge.yml / deploy-web.yml). Override by exporting FP_PROBE_KEY.
# Idempotent: safe to run repeatedly.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck source=/dev/null
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "error: wasm-pack not found — install it (cargo install wasm-pack)" >&2
  exit 1
fi

: "${FP_PROBE_KEY:=test-probe-secret}"
export FP_PROBE_KEY

# Build once into the edge dir, then mirror into the client dir — both consumers
# use the identical build, so a second wasm-pack pass would only waste time.
echo "==> wasm-pack build --target web (FP_PROBE_KEY=${FP_PROBE_KEY})"
wasm-pack build --target web --out-dir "$ROOT/apps/edge/wasm" crates/fp-wasm

echo "==> mirror apps/edge/wasm -> packages/client/wasm"
mkdir -p "$ROOT/packages/client/wasm"
cp -R "$ROOT/apps/edge/wasm/." "$ROOT/packages/client/wasm/"

echo "==> WASM build complete"
