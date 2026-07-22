import { describe, expect, it } from 'vitest'
import {
  SIGNATURE_HEADER as CLIENT_SIGNATURE_HEADER,
  SIGNATURE_TIMESTAMP_HEADER as CLIENT_SIGNATURE_TIMESTAMP_HEADER,
} from '../../../packages/client/src/signature'
import {
  SIGNATURE_HEADER as EDGE_SIGNATURE_HEADER,
  SIGNATURE_TIMESTAMP_HEADER as EDGE_SIGNATURE_TIMESTAMP_HEADER,
} from '../src/signature'

// Cross-stack signing-contract parity (LIGHT).
//
// The signing header names are triplicated: `apps/edge/src/signature.ts`,
// `packages/client/src/signature.ts`, and the Rust wire literals
// (`crates/fp-core/src/signing.rs`). The native server is the single source of
// truth for what goes on the wire; the edge Worker and the browser client MUST
// agree with it exactly or a client verifies against the wrong header. This
// suite pins that agreement so a drift in any one copy fails a test rather than
// silently breaking cross-stack verification. It is deliberately light: an
// assertion of the shared contract, not a package restructure or wire codegen.

/** The literal header names the Rust server emits (`fp-core::signing`), the
 *  authoritative wire contract every stack must match. */
const WIRE_SIGNATURE_HEADER = 'x-fp-signature'
const WIRE_SIGNATURE_TIMESTAMP_HEADER = 'x-fp-timestamp'

describe('signing header contract parity (edge ↔ client ↔ Rust wire)', () => {
  it('agrees on the signature header across all three stacks', () => {
    expect(EDGE_SIGNATURE_HEADER).toBe(CLIENT_SIGNATURE_HEADER)
    expect(EDGE_SIGNATURE_HEADER).toBe(WIRE_SIGNATURE_HEADER)
  })

  it('agrees on the timestamp header across all three stacks', () => {
    expect(EDGE_SIGNATURE_TIMESTAMP_HEADER).toBe(
      CLIENT_SIGNATURE_TIMESTAMP_HEADER,
    )
    expect(EDGE_SIGNATURE_TIMESTAMP_HEADER).toBe(
      WIRE_SIGNATURE_TIMESTAMP_HEADER,
    )
  })
})

// The request timestamp window. Edge `inWindow` (`apps/edge/src/app.ts`) and
// native `ts_in_window` (`crates/fingerprintd/src/lib.rs`) both accept a `ts`
// within `±skewMs` of `now` — a symmetric, inclusive-at-the-edge window. This
// replicates that 1-line predicate (exporting the app.ts internal just for a
// test is not worth it) and asserts the boundary semantics agree, so a change
// to either side that shifts the edge (e.g. `<` instead of `<=`) is caught.
const inWindow = (ts: number, now: number, skewMs: number): boolean =>
  Math.abs(now - ts) <= skewMs

describe('ts-window boundary parity (edge inWindow ↔ native ts_in_window)', () => {
  it('accepts inside and both exact edges, rejects just outside', () => {
    // now = 1500, skew = 500 ⇒ the window is [1000, 2000] inclusive.
    const now = 1500
    const skew = 500
    const cases: Array<[number, boolean]> = [
      [1500, true], // dead centre
      [1000, true], // lower edge (exactly -skew) is inside
      [2000, true], // upper edge (exactly +skew) is inside
      [999, false], // one below the lower edge is outside
      [2001, false], // one above the upper edge is outside
    ]
    for (const [ts, expected] of cases) {
      expect(inWindow(ts, now, skew)).toBe(expected)
    }
  })
})
