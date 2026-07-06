# @fingerprintd/client

Browser SDK for the [`fingerprintd`](../../crates/fingerprintd) challenge/identify
flow. It **collects** client-observed evidence and submits it; the **server**
judges. The client never derives a `visitorId` or a hash — the identity returned
by the server is authoritative.

## Flow

```
GET  /challenge   -> nonce + collection plan
collect(challenge) -> { stable_components, challenge_response?, probe? }
POST /identify    -> { visitorId, confidence, decision, signals, ... }
```

`run()` wires these together with an injected `Collector`. Stable components and
the active-challenge proof stay separate: `challenge_response` is a freshness
proof, never a matching signal.

## Usage

```ts
import { run, stubCollector } from '@fingerprintd/client'

const { identity, signatureValid } = await run({
  baseUrl: 'https://fp.example.com',
  collect: stubCollector, // replace with a real collector (TC2/TC3/TC5)
  signingKey: /* optional Uint8Array */ undefined,
})
```

## Environment limit — no real browser here

This package was scaffolded in an environment with **no headless browser**, so
canvas / audio / webgl cannot be exercised for real and there is **no real
in-browser e2e**. The shipped `stubCollector` gathers **no real fingerprint**.
Tests are **unit/mock only** (jsdom + mocked `fetch`) and cover the wire contract
and the response-signature crypto — they do **not** validate real fingerprints.
Real in-browser certification is **deferred to a human**.

## Response signatures (T9)

When the server is configured with a signing key, `/identify` responses carry
`x-fp-timestamp` and `x-fp-signature` headers. `verifySignature` recomputes
`hex(HMAC-SHA256(key, be64(issuedMs) ++ body))` — matching
`crates/fingerprintd/src/signing.rs` — and compares constant-time.

**Shared-secret caveat:** client-side verification needs the same signing key
the server holds. Embedding that secret in shipped browser code is only shallow
defense-in-depth (same caveat as an embedded WASM probe key). TLS is the real
transport trust; this verify is a tamper/forgery tripwire.

## Scripts

```
bun run lint       # biome check .
bun run typecheck  # tsc --noEmit
bun run test       # vitest run
bun run build      # tsup (ESM + d.ts)
```
