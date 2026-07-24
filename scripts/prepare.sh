#!/usr/bin/env bash
# prepare.sh — runs during `bun install` (the repo-root `prepare` lifecycle).
# Builds the workspace packages (the SDK) so a fresh install yields a
# ready-to-consume @cdlab/fingerprintd-client.
#
# The SDK imports the vendored WASM under packages/client/wasm, which is a BUILD
# ARTIFACT and NOT committed. On a fresh clone it isn't there yet and the SDK
# build would fail — so skip (exit 0) with a hint instead of breaking install.
# Generate it with `bun run build:wasm`; the next `bun run build` (or install)
# then builds the SDK.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -f "$ROOT/packages/client/wasm/fp_wasm.js" ]; then
  echo "prepare: vendored WASM missing (packages/client/wasm) — skipping SDK prebuild."
  echo "prepare: run 'bun run build:wasm' to generate it, then 'bun run build'."
  exit 0
fi

exec bun run --filter=./packages/* build
