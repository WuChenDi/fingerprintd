# fingerprintd Architecture &amp; Implementation Audit

> Type: implementation + architecture audit (code-level, both stacks) | Auditor: L1 | 2026-07-08
> Scope: `crates/{fp-core,fingerprintd,fp-wasm}`, `apps/{edge,web}`, `packages/client`, `.github/workflows`
> Related: BKD project `qdxgw8qt` / L1 issue `ln15f357`
> Companion: `docs/audit/audit-report.md` (the earlier PRD-level audit)

---

## 1. Verdict

Engineering quality is high: `fp-core` cleanly separates framework-free compute
and storage from the HTTP hosts; `unsafe` is forbidden; `unwrap/expect/panic`
are `deny`-linted out of runtime paths; secrets are Debug-redacted; HMAC uses
constant-time comparison; defaults are fail-closed; and native↔edge share one
compute core (`crates/fp-wasm`) verified by a byte-level parity fixture.

However the product is not yet production-shaped. Two structural problems
dominate: (a) the **Axum server has no persistence**, so the core value
proposition — a server-authoritative, cross-request-stable `visitorId` — does
not survive a restart; and (b) the **two stacks have drifted**: routes, wire
types, signing constants, timestamp-window logic, and verdict→persistence
semantics are hand-duplicated across Rust and TypeScript, the edge stack drops
the entire passive-signal capability, and the only guard (a parity fixture) is
not even run in CI.

Findings are ID'd for the remediation campaign. Severity: **H** (high) /
**M** (medium) / **L** (low/informational).

---

## 2. Findings

### High

| ID | Area | Finding | Evidence |
| -- | ---- | ------- | -------- |
| **H1** | Axum persistence | `AppState.matcher: Arc<FuzzyStore>` is in-memory only; `RecordStore`/`BlockingIndex`/`FrequencyTable`/`InMemoryNonceStore` are `Mutex<HashMap>`. A restart loses the entire fingerprint library → every device re-judged `new_device`, defeating PRD §3 stability targets. `NonceStore`/`FingerprintStore`/`CandidateSource` are traits, but `FuzzyStore` is a concrete aggregate that `new`s concrete stores, so swapping backends means refactoring `FuzzyStore` internals, not injecting. | `state.rs:20`, `nonce.rs:59-69`, `fuzzy/mod.rs:53-101`, `record.rs:49-52` |
| **H2** | Unbounded growth (both stacks) | `InMemoryNonceStore.consume` never removes expired entries and `issue` only inserts → unbounded memory; no reaper, no cap. `RecordStore`/`BlockingIndex`/`FrequencyTable` have no TTL/eviction. Edge D1 `templates`/`blocking_index` have no retention/cleanup either (only the nonce DO has an expiry alarm). | `nonce.rs:108-121`, `fuzzy/mod.rs`, `fingerprint-store-d1.ts` |
| **H2b** | Edge secret fail-open | `FP_SALT_SECRET` unset falls back to a hardcoded `DEV_SALT_SECRET='fp-edge-dev-salt'`, only a comment warns. A deploy that forgets the secret silently ships guessable, non-deployment-bound blocking keys. Unlike native (empty key ⇒ feature off), salt is always meaningful — should fail-closed. | `apps/edge/src/config.ts:64-66` |
| **H3** | Cross-stack drift (scaling) | Native `BlockingIndex` caps blocks at `DEFAULT_MAX_BLOCK=1024` with drop accounting; edge `D1FingerprintStore.recall` has **no `LIMIT`/cap** — a hot blocking key recalls an unbounded candidate set, each scored in-isolate by WASM → P99 blowup + D1 read cost. Not covered by the parity fixture. | `blocking.rs:23,77-90` vs `fingerprint-store-d1.ts:42-59` |
| **H4** | CI gap | `apps/edge` vitest suites (router + state + **cross-stack parity**) are **not run in CI** — `ci.yml` `web` job covers only `packages/client`. Committed `fp_wasm_bg.wasm` artifacts are never rebuilt-and-diffed against `crates/fp-wasm` source in CI, so they can silently drift; only manual deploy workflows rebuild. | `.github/workflows/ci.yml:47-116` |
| **H5** | Client↔server schema mismatch (latent) | `createFingerprintCollector` spreads FingerprintJS `components` verbatim into `stable_components`, but (1) FJS components are nested `{value,duration}` objects — the server's `canonical_scalar` returns `None` for objects → not stored/matchable; (2) FJS key names (`screenResolution`/`hardwareConcurrency`/…) don't match the server schema (`webgl`/`platform`/`cpu_cores`/…). No adapter maps them. Mock-only tests bypass this; real browser probes would be nearly unmatchable. | `fingerprint.ts:82`, `fuzzy/mod.rs:241-272`, `fuzzy/mod.rs:265` |

### Medium

| ID | Area | Finding | Evidence |
| -- | ---- | ------- | -------- |
| **M1** | Concurrency | `FuzzyStore::identify` = `evaluate` (blocking + per-candidate record reads) then `observe` (frequency+blocking+record writes), each grabbing a separate global `Mutex`. Under load `/identify` serializes (conflicts with PRD §3 ≥2k RPS); read-then-write is non-atomic so scores are non-reproducible under concurrency. | `engine.rs:110-217`, `record.rs`, `blocking.rs`, `frequency.rs` |
| **M2** | Edge capability gap | Edge `/identify` always returns `neutralSignals()`; the JA4/IP UA-consistency anti-forgery fusion (native `signals.rs`) is absent on edge, though Cloudflare is the natural JA4 source. `trustEdgeHeaders` is resolved/typed but **never read** anywhere in `apps/edge/src` — dead config. Same forged request gets different confidence on the two stacks. | `app.ts:145-173`, `config.ts:58,107`, `signals.rs`, `lib.rs:128-144` |
| **M3** | API semantics | `confidence` conflates decision-confidence with identity-trust: a first-ever unseen device returns `confidence=1.0` (`NewDevice`, no candidate ⇒ `closeness=0` ⇒ base 1.0). A risk consumer may read "brand-new device" as "high-trust identity". Consider splitting fields or documenting/lowering new-device trust. | `engine.rs:301-333` |
| **M4** | Cross-stack scoring divergence | Edge estimates `u_i` over only the recalled candidate block; native uses a global `FrequencyTable`. Documented as decision-preserving, but a real divergence at boundary samples as the library grows; the D1 `value_frequency` table is provisioned but unpopulated. | `fp-wasm/src/lib.rs:138-141`, `apps/edge/src/db/schema.ts` |
| **M5** | Ops / supply chain | No rate limiting on `/challenge` or `/identify` (unbounded nonce minting feeds H2). No `/metrics` / structured metrics (P99, `BlockingIndex.dropped`, hit rates unobservable — the very PRD §3 acceptance metrics). JS side has zero SCA (no `npm audit`/CodeQL/secret-scanning); `cargo deny` covers Rust only. No coverage anywhere; `apps/web` has no test step. | `main.rs`, `ci.yml` |
| **M6** | Compliance (PRD §7 "blocking") | Storage minimizes via salt+hash (good), but there is no retention period, no delete/erasure interface (GDPR RTBF), and no `deny_unknown_fields`. PRD §7 marks these non-optional. | `record.rs`, `fingerprint-store-d1.ts`, `lib.rs:312` |

### Low / Informational

| ID | Area | Finding | Evidence |
| -- | ---- | ------- | -------- |
| **L1** | Spec-vs-impl | `challenge_response` (client canvas/audio freshness collector, ~287 lines) is sent by the SDK but consumed by neither backend — Rust `IdentifyRequest` has no such field (serde ignores it), edge Zod strips it. The PRD §4.1 nonce-challenge freshness proof is never verified server-side; only the HMAC `probe` provides depth. Decide: verify it or remove the dead path. | `challenge.ts`, `lib.rs:312-328`, `app.ts:59-64`, `index.ts:99-101` |
| **L2** | Dead code | `FrequencyTable::u_estimate` is unused by the engine (engine reimplements a Jeffreys-smoothed version); duplicate implementations invite drift. | `frequency.rs:60`, `engine.rs:270-274` |
| **L3** | Placeholders | `StaticIpIntel` (4 IPv4 blocks, IPv6 all low) and `classify_ja4` (structural counts only) are honest placeholders; production needs a real ASN/reputation feed + JA4 database. | `signals.rs:192-197,323-334` |
| **L4** | Edge cost | One Durable Object instance per nonce (`idFromName(nonce)`) is correct but adds two DO round-trips per flow and ~2k DO instantiations/s at target RPS; consider KV+conditional-write or sharded DO. | `nonce-do.ts:101-124` |
| **L5** | Client secrets | Probe key baked into client WASM and signing key shippable to browsers are documented "depth, not a lock" — correct framing; do not promote to a decisive control. | `fp-wasm/src/lib.rs:50-58`, `packages/client/src/signature.ts:10-15` |
| **L6** | Doc/repro footgun | `probe.ts` claims committed WASM is keyed with `test-probe-secret`, but the `fp-wasm` source default is `fp-wasm-dev-probe-key`; two independent bake points (edge WASM + client WASM) must be kept in sync manually. | `packages/client/src/probe.ts:16-18`, `fp-wasm/src/lib.rs:57` |
| **L7** | Robustness | `DurableNonceStore.consume` casts the response body to `NonceOutcome` without checking `response.ok` (unlike `issue`); a DO 5xx is coerced to a non-`valid` string — safe (401) but masks errors. | `nonce-do.ts:113-118` |
| **L8** | Single-source-of-truth | Wire types are triplicated (Rust serde / edge `types.ts` / SDK `types.ts`), signing header constants triplicated, ts-window logic and verdict→persist semantics duplicated. Only the (un-CI'd, see H4) parity fixture guards them. | `lib.rs`, `apps/edge/src/*`, `packages/client/src/*` |

---

## 3. Remediation Roadmap (priority order)

**P0 — make the server production-shaped**
- H1: trait-ize `FuzzyStore`'s backends and unify the native/edge persistence
  abstraction so both stacks are hosts of one engine.
- H2 + H2b: add nonce reaper + store TTL/eviction + D1 retention cleanup;
  fail-closed on unset edge salt secret.
- H4: run `apps/edge` tests in CI + gate committed WASM against a fresh
  source rebuild.

**P1 — kill cross-stack drift; lock correctness**
- H3: mirror the native block cap in edge `recall`.
- M2: wire Cloudflare JA4/IP passive signals on edge (push UA↔TLS consistency
  into `fp-core` for reuse).
- H5: add a FingerprintJS→server-schema adapter + a real-shape matching test.

**P2 — observability, limits, compliance, semantics**
- M5: `/metrics` + rate limiting; JS SCA in CI.
- M3: clarify or split `confidence` semantics.
- M6: retention + erasure interface + `deny_unknown_fields`.
- L1: decide `challenge_response` (verify or remove).
- L2/L7/L8: dedupe `u_estimate`; harden DO response handling; extract a
  single wire-contract source.

Start with H1/H2/H4 (they gate "production-ready"); H3/H5/M2 turn the
dual-stack parity claim into something CI-enforced.
