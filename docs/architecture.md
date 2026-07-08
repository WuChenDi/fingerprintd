# fingerprintd architecture

**English** · [中文](architecture.zh-CN.md)

> Server-side device fingerprinting for **anti-fraud / anti-automation**. Judgment
> is server-authoritative: the client only collects; the server issues a one-time
> challenge, fuzzy-matches, fuses passive signals, and returns
> `visitorId` + `confidence`.

This document is the authoritative **architecture spec**; the implementation
follows it. Section numbers are stable anchors — source doc-comments reference
them as `§N`. The stage-two matching engine has its own spec:
[fuzzy-matching.md](fuzzy-matching.md).

---

## 1. Background

Pure client-side fingerprinting (as in the open-source FingerprintJS) has
structural flaws:

- **Forgeable** — the id is computed on the client from client-controlled values.
- **No replay protection** — a static id is captured once and resubmitted freely.
- **Imprecise** — an exact client hash *avalanches*: any one component changing
  makes the same device look new, while same-model devices collide.
- **Weak against adversaries** — privacy browsers / anti-fingerprint extensions
  actively add noise.

| Problem | Root cause | Direction |
|---|---|---|
| Forgeable | trusts client-reported values | cross-check with **passive signals the client cannot self-report** |
| No replay protection | id is static | **one-time challenge** bound to a freshness proof |
| Imprecise | exact client hash + avalanche | **server-side fuzzy matching + multi-source fusion** |

Judgment moves entirely server-side; the client only collects — the path
FingerprintJS Pro / DataDome / Akamai all take.

---

## 2. Goals and threat model

At high-risk actions (login, signup, checkout, coupon redemption) each request
yields a stable `visitorId` and a `confidence` for the risk engine: is this a new
device, is it linked to a known device, and do the self-reported browser features
agree with the network layer (bot detection)?

### Threat model

| Adversary | Capability | System goal |
|---|---|---|
| **L1 script** | curl / scripts, no JS | must reject (no collection / TLS mismatch) |
| **L2 automation** | headless browser, runs JS, forges UA/JS values | catch via passive signals + consistency |
| **L3 advanced** | curl-impersonate / uTLS forging JA3/JA4 + full stack | **lower confidence + cross-verify**, not absolute blocking |

No absolute defense is claimed. An L3 adversary can forge any single signal; the
value is in **raising forgery cost** and **multi-signal consistency detection**,
not in being unbeatable.

### Goals

- **G1** — server issues a one-time challenge; the result is bound to freshness, so replay is invalid.
- **G2** — fuse client components + passive network signals into `visitorId` + `confidence`.
- **G3** — fuzzy matching replaces the exact hash, removing avalanche; stability over uniqueness.
- **G4** — P99 decision latency ≤ 50ms (excluding client collection); ≥ 2k RPS per instance.

### Non-goals

- No full client SDK UI/telemetry framework — only a minimal collect + challenge shell.
- No unbreakable tamper-proofing (the WASM shell raises hook cost, it is not decisive).
- No cross-site tracking / ad attribution.
- No device-association graph (account ↔ device clustering) in the current version; data is reserved for it.

---

## 3. Success metrics

| Metric | Definition | Target |
|---|---|---|
| Stability rate | same device re-resolved to one `visitorId` across visits over two weeks | ≥ 95% |
| Collision rate | distinct devices resolved to one `visitorId` | ≤ 1% |
| L1/L2 detection | scripted / forged requests flagged low-confidence | ≥ 90% |
| Decision P99 | submit → `visitorId` returned | ≤ 50ms |
| Replay rejection | expired / reused nonce refused | 100% |

> The stability/collision targets are gated behind an **offline evaluation against
> a labelled corpus** — see [fuzzy-matching.md §10](fuzzy-matching.md#10-offline-evaluation).
> They must not be reported from synthetic fixtures.

---

## 4. Architecture: challenge-response + server-side fusion

### 4.1 Freshness vs. identity (the core split)

Matching requires that the same device produces the **same** stable output each
time. So evidence is split into two lanes that never mix:

- **`stable_components`** — no nonce mixed in; raw values enter the fingerprint
  library and drive identity matching.
- **freshness proof** — depends on the server-issued nonce and proves the
  collection is live; it **never** participates in identity matching.

**Replay protection** rests on two layers, in order of authority:

1. **One-time nonce (primary lock).** The server mints a short-TTL, single-use
   nonce and burns it on consumption. A reused or expired nonce is rejected with
   `401`. This is the decisive guarantee.
2. **Nonce probe (defense in depth, optional).** When a `probe_key` is configured,
   the server advertises a deterministic transform in the challenge; the client
   returns `hex(HMAC-SHA256(key, nonce))`, computed in WASM. This proves the client
   computed live per protocol rather than replaying a fixed value. It is depth on
   top of the one-time nonce, not the primary lock — the key ships in client WASM
   and is extractable, so it raises the bar without being decisive.

> An earlier design mixed the nonce into canvas/audio draw seeds (`challenge_response`).
> It was removed: freshness that depends on "the output differs every time" cannot
> be independently verified by the server, whereas the one-time nonce can. The HMAC
> probe replaces it as the live-collection proof.

### 4.2 Passive signals and the trust boundary

TLS JA3/JA4 is **not** a high-entropy per-device identifier and **not**
unforgeable:

- Low entropy — millions of same-model Chrome instances share one JA3, so it
  cannot be a `visitorId` source.
- Forgeable — curl-impersonate / uTLS can construct any ClientHello.

Its real value is **consistency cross-checking**, weighted into `confidence`, never
into `visitorId`:

- JS claims Chrome/Windows but JA4 is a Python/Go stack → strong anomaly, confidence sharply lowered.
- IP reputation (datacenter / proxy / risk feed) → auxiliary, not decisive.

**Deployment constraint (hard).** Connection-layer signals can only be captured by
the party terminating the client's TLS connection. Behind Cloudflare's proxy the
origin sees the CF↔origin segment, so client-layer signals must be passed through.

- **Current topology** — Cloudflare extracts JA3/JA4 and forwards them via header.
  Availability depends on the account (JA4 headers are bound to Bot Management,
  Enterprise): present → used; **absent → auto-degrade** (connection-layer signals
  are neutralized and de-weighted, the request is **not** blocked; the real client
  IP via `CF-Connecting-IP` still feeds IP reputation).
- **Trust boundary (fail-closed).** Edge-injected passive-signal headers are read
  **only** when the deployment is configured to trust the edge
  (`trust_edge_headers`); otherwise any client-supplied copy is ignored. This
  prevents a client stuffing a forged JA4. A self-managed nginx/envoy edge that
  injects its own trusted JA4 header is a future extension.

### 4.3 Fuzzy matching and candidate generation

Matching is **not** a hash lookup and cannot linearly scan the whole library. Two
stages: (1) blocking / LSH recall compresses the library to tens–hundreds of
candidates; (2) weighted probabilistic scoring (Fellegi–Sunter) ranks them and
decides. Full spec: [fuzzy-matching.md](fuzzy-matching.md).

### 4.4 Client collection: reuse FingerprintJS / BotD

The client only collects; judgment is server-side (§4). The collector reuses
existing MIT libraries rather than reinventing them:

| Library | License | How reused | Boundary |
|---|---|---|---|
| **FingerprintJS** (OSS) | MIT | npm dependency; take its **raw `components`** as `stable_components` | discard its client-side `visitorId` hash |
| **BotD** (OSS) | MIT | npm dependency; bot signals fold into server `confidence` | client signals are forgeable, secondary input |

The nonce probe (§4.1) is written in-house — FingerprintJS does not compute a
keyed transform over a server nonce. A client-side adapter maps FingerprintJS's
nested `{value, duration}` component shape and key names onto the server's schema
before submission, so real browser probes are matchable. See
[`packages/client`](../packages/client/README.md).

---

## 5. HTTP interface

Both deployment targets (§8) serve the same wire contract.

### GET /challenge

```
200: {
  nonce: string,          // one-time, server-issued
  expires_in: 30,         // seconds (nonce_ttl_secs)
  collect: {
    stable: [...],                 // components to gather
    challenge: {
      verify?: { ... }             // advertised only when a probe_key is configured
    }
  }
}
```

### POST /identify

```
Req: {
  nonce: string,
  stable_components: { ... },   // raw values, no nonce mixed in
  probe?: string,               // hex(HMAC-SHA256(key, nonce)); required when the server enforces the probe
  ts?: number                   // client Unix ms; checked only when the timestamp window is enforced
}
200: {
  visitorId: string,
  confidence: 0.0..1.0,         // DECISION confidence, not identity trust — see §6
  decision: "match" | "review" | "new_device",
  is_new_device: boolean,
  collision_risk: boolean,
  signals: {                    // for the risk engine; raw passive signals are never echoed
    ua_tls_consistent: boolean,
    ip_risk: "low" | "medium" | "high"
  }
}
401: nonce expired / reused, or an enforced probe / timestamp check failed
```

The request body is `deny_unknown_fields` — an unexpected top-level key is rejected
`400` (both stacks). When `response_signing_key` is set, a success additionally
carries `x-fp-timestamp` + `x-fp-signature` (`hex(HMAC-SHA256(key, be64(issuedMs) ++ body))`).

Passive signals (JA4/IP) are obtained server-side from the connection (§4.2) and
are **never** accepted from the client body.

### DELETE /visitor/{id}

GDPR right-to-be-forgotten (§7). Admin-key gated (`admin_key`): unset ⇒ the route
is disabled. Erasure is idempotent — `204` even when the visitor did not exist.

---

## 6. Data model

- **fingerprints** — `visitorId` → per-component salted hashes, blocking keys,
  first/last-seen, observation count. Raw values are **not** stored (§7); category
  components are salted hashes and set components are per-element hashes (preserving
  Jaccard). See [fuzzy-matching.md §3](fuzzy-matching.md#3-storage-representation).
- **nonce** — `nonce` → `{issued_at, used}`, TTL = `expires_in`, burned on use.
- **frequency** — per-value counts for the `u_i` rarity estimate
  ([fuzzy-matching.md §9](fuzzy-matching.md#9-parameter-estimation-and-cold-start)).

**`confidence` semantics.** `confidence` is **decision confidence**, not
identity-trust: a first-ever unseen device resolves as `new_device` with high
decision confidence (the engine is sure it is new). A risk consumer must read
`is_new_device` / `decision` for identity trust and must not treat a high-confidence
`new_device` as a high-trust identity.

---

## 7. Privacy and compliance

Storing derived fingerprints is higher-sensitivity than a pure client scheme, so:

- **Legal basis** — under GDPR/CCPA/PIPL device fingerprints are typically personal
  data; anti-fraud usually rests on legitimate interest, which requires a DPIA
  record.
- **Data minimization** — only salted hashes are stored, never raw component values
  (§6 / [fuzzy-matching.md §3](fuzzy-matching.md#3-storage-representation)).
- **Retention** — records past `retention_secs` are swept and deleted; `0` disables
  the sweep.
- **Erasure** — `DELETE /visitor/{id}` (§5) implements right-to-be-forgotten.
- **Strict input** — `deny_unknown_fields` on the request body prevents silently
  accepting unmodeled fields.
- **Purpose limitation** — anti-fraud only; using it for advertising/tracking
  changes the legal basis and is out of scope.
- **Transparency** — disclose device fingerprinting in the privacy policy.

---

## 8. Deployment targets

One engine ([`crates/fp-core`](../crates/fp-core)), two hosts. A client works
against either unchanged; the two are held to identical behavior by a shared parity
fixture run on both sides.

| Concern | Native server (`crates/fingerprintd`) | Edge Worker (`apps/edge`) |
|---|---|---|
| Runtime | Axum / Tokio, long-lived process | Cloudflare Worker (V8 isolate, per-request) |
| Nonce store | in-memory, single-use + TTL, bounded + reaped | Durable Object (atomic check-and-burn + TTL alarm) |
| Fingerprint library | in-memory inverted index + frequency table, bounded/evicting | D1 (SQLite): `templates` + `blocking_index` |
| Compute | native `fp_core` | `fp_core` compiled to WASM (`crates/fp-wasm`) |
| Passive signals | full JA4/IP fusion (§4.2) | neutral by default; JA4/IP behind a trusted edge |
| Secrets | config / env | Worker Secrets |

The native store is process-local: a restart re-mints devices, so a durable backend
(the D1/Durable Object seam, or an external store behind the `NonceStore` /
`FingerprintStore` / `CandidateSource` traits) is required for a production
single-instance-stable `visitorId`. See [`apps/edge`](../apps/edge/README.md) for
the persisted deployment.

---

## 9. Defense-in-depth controls (config-gated, off by default)

All three are fail-closed and activate only once their key is set:

- **Nonce probe** (`probe_key`, §4.1) — verifies the WASM-computed `probe`; wrong/
  missing ⇒ `401`. The same key must be baked into the client WASM build.
- **Response signing** (`response_signing_key`, §5) — signs each `/identify` success
  so the client can detect tampering.
- **Timestamp window** (`enforce_ts_window` + `ts_skew_secs`, §5) — bounds how stale
  a request `ts` may be.

They are depth on top of the one-time nonce and TLS, which remain primary. Embedded
client secrets are extractable and must not be promoted to decisive controls.
