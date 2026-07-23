# @cdlab/fingerprintd-checkin-risk

A Cloudflare Worker that turns a fingerprintd identify verdict plus a business
`accountId` into a check-in risk decision (`allow` / `challenge` / `deny`),
targeting the daily check-in anti-farming scenario.

fingerprintd is a signal provider, not a fraud judge: it exposes a stable device
identity and network cross-checks (UA↔TLS, IP-risk band) but holds no
account/device relationship state. This Worker owns exactly that missing
dimension — the `accountId` and the account/device/IP/time relationship graph —
and fuses fingerprintd's signals with its own aggregates into an explainable
verdict. It does not modify or proxy fingerprintd (`crates/*`, `apps/edge`); it
only consumes the existing `/identify` wire contract.

## Contract

### `POST /checkin/assess`

Request (`AssessRequest`, see `src/types.ts`):

```ts
interface AssessRequest {
  accountId: string           // business identity — the core new dimension
  action: 'daily_checkin'     // scenario tag selecting a threshold profile (MVP: this value only)
  identify: IdentifyResponse  // the fingerprintd verdict, obtained and passed through by the caller
  // ip / ts are NOT fields — see below
}
```

Response (`AssessResponse`):

```ts
interface AssessResponse {
  decision: 'allow' | 'challenge' | 'deny'
  verdict: 'human' | 'suspicious' | 'farming'
  risk: number                                      // 0.0..1.0, explainable
  reasons: Array<{ code: string; detail: string }>  // audit / appeal trail
  visitorId: string                                 // pass-through for the business join
}
```

The caller obtains `IdentifyResponse` from fingerprintd (Axum server or the edge
Worker) and passes it straight through — this layer never proxies
`/identify`/`/challenge`. A malformed body returns `400` with an `{ error }`
reason; a body carrying an unknown top-level key is rejected.

### `ip` / `ts` are edge-observed, never client-supplied

The client IP is read from the `cf-connecting-ip` header Cloudflare injects, and
the timestamp is stamped server-side. Both feed the relationship aggregates, so
accepting them from the request body would let a caller forge its own
farming-evasion history. A body that carries an `ip` or `ts` field is therefore
**rejected with `400`**, not silently ignored. Unbound (a bare `wrangler dev` or
a Node test) the IP degrades to empty.

## Aggregates (the state fingerprintd lacks)

Derived from an append-only D1 event log `checkin_events(account_id, visitor_id,
ip, ts)` via windowed `COUNT(DISTINCT ...)` queries (`src/checkin-store-d1.ts`):

| Signal | Key | Window | Catches |
|---|---|---|---|
| `device_account_fanout` | visitorId → distinct(accountId) | 24h / 7d | device farm |
| `account_device_count` | accountId → distinct(visitorId) | 7d / 30d | account cultivation |
| `account_new_device_rate` | accountId | last N events | fingerprint reset / emulator |
| `ip_account_count` | ip → distinct(accountId) | 1h / 24h | datacenter / proxy batch |
| `checkin_interval_regularity` | accountId | last K check-ins | scripted timing |
| `batch_clustering` | minute-bucket × (visitorId \| ip) | live | batch bursts |

The event is recorded **before** aggregates are read, so the verdict reflects the
current check-in.

## Decision logic (MVP: rules, not ML)

Two stages — cheap fingerprintd hard-signals first, then aggregates. Every fired
trigger adds its weight; the summed risk is clamped to `[0,1]` and banded. All
numbers are config data (`ThresholdProfile` in `src/risk-config.ts`), selected by
`action`, so tuning never touches the scoring path (`src/risk-engine.ts`). The
committed `daily_checkin` defaults:

| Trigger | Reason code | Fires when | Weight |
|---|---|---|---|
| UA/TLS mismatch | `UA_TLS_MISMATCH` | `!signals.ua_tls_consistent` | 0.5 |
| Datacenter IP | `DATACENTER_IP` | `signals.ip_risk === 'high'` | 0.3 |
| Device farm | `DEVICE_FARM` | `device_account_fanout > 5` | 0.6 |
| Fingerprint reset | `FP_RESET` | `account_new_device_rate > 0.5` | 0.4 |
| IP batch | `IP_BATCH` | `ip_account_count > 10` | 0.3 |
| Scripted timing | `SCRIPTED_TIMING` | `checkin_interval_regularity > 0.8` | 0.3 |

Bands: `risk >= 0.7` → `deny` / `farming`; `>= 0.35` → `challenge` /
`suspicious`; else `allow` / `human`.

The `deny` band is deliberately conservative — a single strong aggregate (e.g. a
device farm at 0.6) is **challenged, not denied**, and a shared-egress benign
case (high `ip_account_count` alone, 0.3) stays `allow`. This favours challenge
over deny on corporate/campus NAT false positives; `reasons[]`
carries the audit/appeal trail. A real device farm reaches `deny` only by
combining signals (fan-out + datacenter egress = 0.9).

## Run

From the repo root (Bun workspace):

```bash
bun install
bun run --filter '@cdlab/fingerprintd-checkin-risk' test        # vitest: node + workers projects
bun run --filter '@cdlab/fingerprintd-checkin-risk' typecheck    # tsc --noEmit
bun run --filter '@cdlab/fingerprintd-checkin-risk' build        # wrangler deploy --dry-run
bunx @biomejs/biome check apps/checkin-risk                      # lint
```

Local dev server:

```bash
cd apps/checkin-risk
bun run dev          # wrangler dev --local
```

Tests run under two vitest projects (`vitest.config.ts`): a Node project for the
state-free router and pure logic (including `tests/integration.assess.test.ts`,
which drives the endpoint over an injected store), and a workerd/miniflare
project (`*.workers.test.ts`) for the D1 aggregate queries and the velocity
Durable Object against the real runtime.

### Bindings (`wrangler.jsonc`)

- **`DB`** (D1) — the `checkin_events` relationship log. Migrations are generated
  by Drizzle Kit (`bun run db:gen`), never hand-authored.
- **`VELOCITY`** (Durable Object, `VelocityDurableObject`) — hot atomic velocity
  counters.
- **`CHECKIN_RETENTION_SECS`** — retention window for the scheduled cron purge;
  `0`/unset ⇒ no-op.

All bindings are optional: unbound the Worker still serves, falling back to an
empty store (all-zero aggregates), so a request then scores on its fingerprintd
hard signals alone.

## Scope (MVP)

Rule-based, `action = 'daily_checkin'` only. Out of scope: any change under
`crates/`, `apps/edge`, or `packages/client`; a trained ML model; a UI. The
interface is model-ready — the rule engine can be swapped for a trained model
behind the same `assess()` signature once labelled data exists.
