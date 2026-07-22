/**
 * Pure check-in risk scoring (CHECKIN-003, PLAN-001 §Decision logic).
 *
 * {@link assess} fuses fingerprintd hard signals with the account/device/IP/time
 * aggregates into an explainable allow/challenge/deny verdict. It performs NO
 * I/O — deterministic given its inputs — so the storage layer (CHECKIN-002) and
 * the endpoint (CHECKIN-004) stay separately testable.
 */

import type { Aggregates, ReasonCode, ThresholdProfile } from './risk-config'
import { defaultProfiles } from './risk-config'
import type { AssessReason, AssessRequest, AssessResponse } from './types'

/** Human-readable `detail` for each fired reason code. */
const REASON_DETAIL: Record<ReasonCode, string> = {
  UA_TLS_MISMATCH: 'User-Agent and edge-observed TLS fingerprint disagree',
  DATACENTER_IP: 'Request originates from a high-risk (datacenter/proxy) IP',
  DEVICE_FARM: 'Device is shared across an unusual number of accounts',
  FP_RESET: 'Account shows a high rate of never-before-seen devices',
  IP_BATCH: 'IP is shared across an unusual number of accounts',
  SCRIPTED_TIMING: 'Check-in intervals are unnaturally regular',
}

/**
 * Score a check-in request into a verdict. Two stages (PLAN-001): cheap
 * fingerprintd hard-signals first, then aggregates. Every fired trigger adds its
 * configured weight and appends a reason; the summed risk is clamped to `[0,1]`
 * and banded into a decision/verdict pair.
 */
export function assess(
  req: AssessRequest,
  agg: Aggregates,
  cfg: ThresholdProfile = defaultProfiles[req.action],
): AssessResponse {
  const { weights, thresholds, bands } = cfg
  const reasons: AssessReason[] = []
  let risk = 0

  const fire = (code: ReasonCode): void => {
    risk += weights[code]
    reasons.push({ code, detail: REASON_DETAIL[code] })
  }

  // Stage 1 — fingerprintd hard signals.
  const { signals } = req.identify
  if (!signals.ua_tls_consistent) fire('UA_TLS_MISMATCH')
  if (signals.ip_risk === 'high') fire('DATACENTER_IP')

  // Stage 2 — account/device/IP/time aggregates.
  if (agg.device_account_fanout > thresholds.device_account_fanout)
    fire('DEVICE_FARM')
  if (agg.account_new_device_rate > thresholds.account_new_device_rate)
    fire('FP_RESET')
  if (agg.ip_account_count > thresholds.ip_account_count) fire('IP_BATCH')
  if (
    agg.checkin_interval_regularity > thresholds.checkin_interval_regularity
  ) {
    fire('SCRIPTED_TIMING')
  }

  risk = Math.min(1, Math.max(0, risk))

  let decision: AssessResponse['decision']
  let verdict: AssessResponse['verdict']
  if (risk >= bands.deny) {
    decision = 'deny'
    verdict = 'farming'
  } else if (risk >= bands.challenge) {
    decision = 'challenge'
    verdict = 'suspicious'
  } else {
    decision = 'allow'
    verdict = 'human'
  }

  return { decision, verdict, risk, reasons, visitorId: req.identify.visitorId }
}
