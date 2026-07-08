# Fuzzy matching engine

**English** · [中文](fuzzy-matching.zh-CN.md)

> The stage-two matching engine behind
> [architecture.md §4.3](architecture.md#43-fuzzy-matching-and-candidate-generation).
> Targets ([architecture.md §3](architecture.md#3-success-metrics)): stability ≥ 95%,
> collision ≤ 1%, decision P99 ≤ 50ms, ≥ 2k RPS per instance.

Section numbers are stable anchors — source doc-comments reference them as `§N`.

---

## 1. Problem statement

Input: the stable-component set of one observation, `probe = {c_1, …, c_n}`.
Output: the matched `visitorId` (same device) or a new-device verdict, plus a
`confidence`.

Three constraints pull against each other:

- **De-avalanche** — one component changing (a browser auto-upgrade, a new font, an
  external monitor) must not mint a new `visitorId`.
- **Anti-collision** — two distinct devices of the same model + browser version must
  not resolve to one `visitorId`.
- **High throughput** — a million-record library cannot be linearly scanned per
  request.

Two core decisions:

1. **Two stages** — candidate generation (§4) → probabilistic scoring (§5).
2. **Scoring uses the Fellegi–Sunter (FS) probabilistic record-linkage model** (§5)
   rather than a hand-tuned weighted average — FS's two parameters `m_i / u_i`
   model *stability* and *distinctiveness* separately, aligning naturally with the
   two failure modes above.

---

## 2. Component classification (the modeling premise)

Each component is characterized on two orthogonal axes — the source of every weight:

- **Stability** — probability the component is unchanged across visits of the same
  device (→ FS `m_i`).
- **Distinctiveness** — probability two distinct devices share the value (→ FS `u_i`;
  rarer = lower `u`).

| Component | Type | Stability | Distinctiveness | Notes |
|---|---|---|---|---|
| WebGL vendor+renderer | category | high | medium | GPU hardware, rarely changes |
| Canvas hash | category | med-high | high | flips wholesale on driver/browser upgrade |
| Audio fingerprint | category | high | med-high | audio stack, stable |
| Font list | set | medium | high | incremental change → Jaccard/MinHash |
| Timezone / language / platform | category | high | low | low entropy, insufficient alone |
| Screen resolution + depth | numeric | medium | med-low | external display changes it |
| CPU cores / device memory | numeric | high | low | |
| Browser version / UA | version | **low** | medium | **the avalanche source**, auto-upgrades every few weeks |
| Plugins / mimeTypes | set | medium | medium | |

> Key insight: UA/browser version changes frequently — an exact hash keeps minting
> "new devices," which is exactly FingerprintJS's avalanche. Under FS its `m_i` is
> low, so a mismatch barely penalizes; it fades automatically.

---

## 3. Storage representation

To satisfy data minimization
([architecture.md §7](architecture.md#7-privacy-and-compliance)), raw values are
never stored while matching is preserved:

- **Category components** — store salted hashes `H(salt || value)`. Still supports
  equality comparison + frequency counting (for `u_i`).
- **Set components (fonts, …)** — store the **per-element hashed** set
  `{H(f) for f in fonts}`. Per-element hashing **preserves Jaccard**, so set
  similarity + MinHash still work.
- **Numeric components** — store the value or a bucketed value.
- Per `visitorId` also store: each component's latest value, `first_seen`,
  `last_seen`, `observation_count`, and per-component freshness for drift (§7).

---

## 4. Stage one: candidate generation (blocking)

Goal: from a million-record library, get tens–hundreds of candidates in near O(1)
**without missing the true match** (recall first).

A single exact key cannot be used — any one component changing misses. Use
**multiple independent blocking keys, unioned** for recall redundancy:

- `K1 = H(webgl_renderer || platform || timezone)` — one high-stability subset
- `K2 = H(audio_hash || cpu_cores || device_memory)` — a disjoint high-stability subset
- `K3 = MinHash-LSH(font set)` band buckets — tolerates incremental font change
- (optional) `K4 = Simhash(all-component tokens)` Hamming neighbor buckets

Recall = 1 − P(all keys miss). Each key uses a disjoint stable-component subset, so
when one component happens to change another key still hits. Candidate set = ∪(the
`visitorId`s each key hits).

**Index** — `blocking_key → set<visitorId>` inverted index. MinHash-LSH:
`band signature → bucket → visitorId`.

**Hot-block inflation** — a popular config (default-Safari iPhone) makes one block
huge (low information). Mitigation:

- cap block size; over the cap the key carries little information and cannot narrow
  candidates — stage-two scoring (§5) must disambiguate;
- over-cap drops **must be logged** (no silent truncation), so "looks covered but
  isn't" cannot happen.

---

## 5. Stage two: probabilistic scoring (Fellegi–Sunter)

For each candidate `cand` vs `probe`, compare component-wise and accumulate the
log-likelihood ratio.

### 5.1 Per-component agreement `agree_i`

- Category — hash equal → agree, else disagree.
- Set — Jaccard `J = |A∩B| / |A∪B|`; `J ≥ τ` → agree (τ ≈ 0.8), else linearly
  interpolated (see 5.3).
- Numeric — equal or same bucket → agree.
- Version — same major → agree; adjacent major → partial (see 5.3); else disagree.

### 5.2 The two parameters

- `m_i = P(agree_i | same device)` — estimated from **high-confidence match revisits**;
  models stability.
- `u_i = P(agree_i | different device)` — estimated from the **library frequency** of
  that component's value; models distinctiveness. A rare value → very low `u_i` →
  equality is strong evidence; a common Chrome/Windows value → high `u_i` → equality
  barely counts.

### 5.3 Per-component weight

```
agree:      w_i = log2( m_i / u_i )                      // positive; rarer = larger
disagree:   w_i = log2( (1 - m_i) / (1 - u_i) )          // negative; more stable = more negative
partial (set/version): w_i = J · log2(m_i/u_i) + (1-J) · log2((1-m_i)/(1-u_i))
missing (either side lacks it): w_i = 0                  // not compared, not scored (see §8)
```

Total: `score(cand) = Σ_i w_i`.

**Why the model is right:**

- **De-avalanche** — UA `m_i` is low → `(1-m_i)/(1-u_i)` ≈ 1, `log` ≈ 0 → a UA
  mismatch barely penalizes.
- **Anti-collision** — two same-model devices disagree on high-entropy components
  (canvas/fonts) whose `m_i` is high → the disagreement carries a large negative,
  pulling the total below threshold → judged distinct.
- **Low-entropy auto-fade** — timezone/language `u_i` is high → agreement barely
  adds, so "both in the same zone" never forces a match.

### 5.4 Decision

Take the top candidate `best`; two thresholds `T_hi > T_lo`:

- `score(best) ≥ T_hi` → **same device**; return its `visitorId`, apply drift (§7).
- `T_lo ≤ score(best) < T_hi` → **suspected**; return the `visitorId` with lowered
  confidence and a `review` flag.
- `score(best) < T_lo` → **new device**; mint a fresh `visitorId`.
- **≥ 2 candidates ≥ T_hi with a small gap** → collision risk; take the top and raise
  a `collision_risk` flag.

---

## 6. Confidence output

`confidence ∈ [0,1]`, fused from three parts (rule-weighted; no learned model in the
current version):

- **Match margin** — how far `score(best)` clears `T_hi` + the gap to the runner-up
  (larger gap → more certain).
- **Passive-signal consistency** — JA4/UA consistent → boost; inconsistent → sharp
  cut (the anti-forgery core,
  [architecture.md §4.2](architecture.md#42-passive-signals-and-the-trust-boundary)).
- **Component completeness** — how many components participated; more missing → lower
  confidence (§8).

---

## 7. Drift (template adaptation) and poisoning defense

Without drift, stored components (UA, …) go stale and matching degrades after a few
browser upgrades. Rules:

- **Only on a high-confidence match (≥ T_hi)** refresh that `visitorId`'s latest
  component values and `last_seen`.
- **Template-poisoning defense** — an attacker might slowly morph A's fingerprint into
  B via repeated low-confidence matches. So:
  - low-confidence / review hits **do not** trigger an update;
  - the original observation history is retained; updates overwrite only the
    "latest value" layer, never the history;
  - the per-update change magnitude is bounded; an abnormal jump is flagged.

---

## 8. Edge cases

- **Privacy browser blocks canvas (null/empty)** — a missing component scores `w_i = 0`
  and does not participate. Never treat "null canvas" as a matchable value — otherwise
  all privacy users agree on that component → mass collision. More missing → lower
  confidence.
- **Brave-style per-session canvas randomization** — the component changes every visit
  of the same device → `m_i → 0`, so FS ignores it automatically, falling back to
  fonts/audio/webgl. Advanced: detect a cohort with an always-changing canvas and mask
  that component for it (future).
- **Corporate golden image / identical VMs** — genuinely distinct devices with
  identical fingerprints; fuzzy matching cannot resolve them and will collide. Must
  fall back to IP + account behavior; this is a **known capability boundary**, not
  solved by this engine.

---

## 9. Parameter estimation and cold start

- `u_i` — maintain per-component-value frequency counts, updated incrementally in the
  store.
- `m_i` — needs "same-device revisit" labels. Cold start uses **priors** (per the §2
  classification: high-stability = 0.95, medium = 0.80, low = 0.50); after launch,
  **EM iteration** over high-confidence-match revisits converges it. This is an
  iterative process, not one-shot.
- Cold-library phase: everything reads as a new device; the blocking index and
  frequency stats accumulate over time.

---

## 10. Offline evaluation

Proving the §3 targets requires a labelled evaluation set first:

- **Ground truth** — use login state / long-lived cookies to label "multiple visits of
  one device."
- **Stability rate** — fraction of same-device revisits resolved to one `visitorId`
  (sweep `T_hi`).
- **Collision rate** — fraction of distinct devices resolved to one `visitorId`.
- Grid-search `T_lo / T_hi / τ` and the component priors; plot the
  stability–collision trade-off curve to set thresholds.
- After launch, continuously re-feed review/collision_risk samples for manual review
  to refine `m_i/u_i` and thresholds.

> The repository ships a synthetic fixture that exercises the scoring wiring
> **directionally** — it is a smoke test, not evidence for the numeric targets. The
> rates it prints must not be reported as production stability/collision figures.

---

## 11. Data structures and performance

| Use | Structure | Notes |
|---|---|---|
| Blocking inverted index | `key → set<visitorId>` | in-memory / Redis Set / PG GIN |
| MinHash-LSH | `band signature → bucket` | recall for set components |
| Fingerprint library | `visitorId → component hashes + frequency material + timestamps` | KV / D1 / PG |
| Frequency stats | `component value hash → count` | estimates `u_i` |

Performance: stage one is O(candidates); stage two is O(candidates × constant
components). Keeping candidates in the low hundreds satisfies P99 ≤ 50ms. On the
native server the inverted index + scoring stay in memory; the frequency/library
persistence layer flushes asynchronously.

---

## 12. Open questions

1. MinHash band count / τ for set components — needs real-data measurement.
2. How many labelled revisit samples EM needs to converge `m_i`.
3. The block-size cap and the fallback for over-cap cohorts (force high-entropy agreement?).
4. Time-decay window for frequency stats (down-weight stale values?).
5. Whether to stratify parameter estimation by device cohort (mobile vs desktop `m/u` differ).
