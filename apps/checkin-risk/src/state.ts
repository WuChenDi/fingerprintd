/**
 * Host state for the check-in risk Worker (CHECKIN-004).
 *
 * Mirrors `apps/edge/src/state.ts`: the `/checkin/assess` handler depends on an
 * async {@link CheckinStore} interface, never on the concrete D1 wrapper, so the
 * router stays unit-testable without the Workers runtime. `index.ts` injects the
 * D1-backed {@link D1CheckinStore} when the `DB` binding is present; unbound (a
 * bare `wrangler dev` or a Node test) it falls back to {@link EmptyCheckinStore},
 * exactly like the edge Worker's stub stores.
 */

import type { AggregateResult, CheckinEvent } from './checkin-store-d1'

/**
 * The append + aggregate surface the handler consumes. `D1CheckinStore`
 * implements it over D1; {@link EmptyCheckinStore} is the unbound fallback. Only
 * these two methods are needed on the assess path (the retention purge lives on
 * the concrete class and is driven by the cron).
 */
export interface CheckinStore {
  /** Append one check-in observation. No-op in the empty fallback. */
  record(event: CheckinEvent): Promise<void>
  /** Windowed PLAN-001 aggregates for the `(account, device, ip)` triple as of
   *  `now` (Unix ms). All-zero in the empty fallback. */
  getAggregates(
    accountId: string,
    visitorId: string,
    ip: string,
    now: number,
  ): Promise<AggregateResult>
}

/** A fresh all-zero {@link AggregateResult} — the neutral aggregate bundle the
 *  empty store returns, so a clean identify scores allow/human. Returned as a
 *  new object each call so no caller can mutate a shared instance. */
export function zeroAggregateResult(): AggregateResult {
  return {
    device_account_fanout: { h24: 0, d7: 0 },
    account_device_count: { d7: 0, d30: 0 },
    account_new_device_rate: { rate: 0, sampled: 0 },
    ip_account_count: { h1: 0, h24: 0 },
    checkin_interval_regularity: { regularity: 0, samples: 0 },
    batch_clustering: { device: 0, ip: 0 },
  }
}

/**
 * In-isolate fallback store (STUB): `record` drops the event and `getAggregates`
 * always returns zeros, so the Worker runs unbound without a crash — every
 * request then scores on its fingerprintd hard signals alone. Replaced by the
 * D1-backed store the moment the `DB` binding is present.
 */
export class EmptyCheckinStore implements CheckinStore {
  record(_event: CheckinEvent): Promise<void> {
    return Promise.resolve()
  }

  getAggregates(): Promise<AggregateResult> {
    return Promise.resolve(zeroAggregateResult())
  }
}
