# @fingerprintd/edge

Cloudflare Worker deployment of the fingerprintd challenge/identify flow:
a **TypeScript host** that owns I/O and routing, calling **Rust compiled to WASM**
(`crates/fp-wasm` → `crates/fp-core`) for the pure compute. It is the second
deployment target for the same engine as the native Axum server
(`crates/fingerprintd`) — a client works against **either** unchanged.

## Status: PCF3 scaffold — router + WASM, state STUBBED

This step wires the request surface and the WASM engine; **request state is
stubbed** and replaced in PCF4:

| Concern | PCF3 (here) | PCF4 |
| --- | --- | --- |
| Router `/health` `/challenge` `/identify` | ✅ real, byte-compatible with the server | unchanged |
| WASM compute (blocking keys, scoring, probe, signing) | ✅ real (`FpEngine`) | unchanged |
| One-time nonce | in-memory `Map` (single isolate only) | Durable Object (atomic burn) |
| Candidate index | empty (every probe ⇒ new device) | D1 inverted index |
| Passive signals (JA4/IP) | neutral degraded default | host-side port |

The orchestration in `src/handler.ts` — derive blocking keys → recall candidates
→ score → sign — is the **real edge host flow**; only the injected `NonceStore`
and `CandidateSource` implementations change in PCF4.

## Layout

```
src/
  index.ts     Worker entry — imports the .wasm, builds engine + STUB state per isolate
  handler.ts   state-free router (dependency-injected, unit-testable)
  engine.ts    typed wrapper around the FpEngine WASM class + one-time init
  state.ts     STUBBED in-memory nonce store + empty candidate source
  config.ts    resolve typed config from env / Worker Secrets
  types.ts     wire types, kept in sync with the server + browser SDK
  signature.ts response-signature header names (T9)
wasm/          vendored `wasm-pack --target web` build of crates/fp-wasm (committed)
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

Set real secrets with `wrangler secret put FP_SALT_SECRET` (etc.); never commit them.

## Develop & verify

```bash
bun install
bun run lint        # biome check .
bun run typecheck   # tsc --noEmit
bun run test        # vitest run (router contract over the vendored WASM, in Node)
bun run deploy:dry  # wrangler deploy --dry-run (bundles the Worker + .wasm)
bun run dev         # wrangler dev --local (local workerd; no account needed)
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
are paid, so only **local** execution is wired: `wrangler dev --local` and
`wrangler deploy --dry-run`. A real deploy — and the DO/D1 bindings PCF4 adds —
is deferred to a human with an account.
