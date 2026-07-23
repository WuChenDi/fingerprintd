/**
 * FingerprintJS → server-schema adapter (part a).
 *
 * PROBLEM: FingerprintJS `get()` returns each component as a nested
 * `{ value, duration }` wrapper keyed by FJS names (`hardwareConcurrency`,
 * `webGlBasics`, …). The Rust server's fuzzy matcher
 * (`crates/fp-core/src/fuzzy/mod.rs` `classify()` + `canonical_scalar` /
 * `value_to_i64`) recognizes a FIXED schema of snake_case names and stores only
 * scalars (Category/Numeric) or string arrays (Set) — it silently drops objects
 * and unknown-shaped values. Spreading FJS output verbatim therefore leaves real
 * probes unmatchable.
 *
 * This module is the pure, browser-free transform that reshapes FJS `components`
 * into the server schema:
 *  1. unwrap the `{ value, duration }` wrapper (dropping FJS error components,
 *     which carry `{ error, duration }` and no `value`);
 *  2. rename FJS keys to their server-schema counterparts ({@link KEY_MAP});
 *  3. normalize each value to the storable kind the server expects, dropping
 *     anything it cannot store.
 *
 * SCOPE: this is the wrapper + key-name mismatch only. Some real FJS values
 * (webgl/canvas) are objects and so drop here — recovering that entropy needs a
 * per-field canonicalization pass, which is a documented follow-up, NOT this
 * unit. Wiring this adapter into `fingerprint.ts` and the cross-stack proof are
 * a SEPARATE unit (part b); this file only defines and tests the transform.
 */

/**
 * FJS component name → server-schema name. The target names are exactly the set
 * `crates/fp-core/src/fuzzy/mod.rs` `classify()` recognizes; keep this table in
 * sync with that authoritative list.
 *
 * `webGlExtensions` also maps to `webgl`: when both it and `webGlBasics` are
 * present the later-iterated entry wins (last-wins). FingerprintJS exposes NO
 * raw userAgent among its stable components, so `user_agent` is intentionally
 * left unmapped — the UA rides separately under `botd`, which this unit does not
 * touch.
 */
const KEY_MAP: Record<string, string> = {
  hardwareConcurrency: 'cpu_cores',
  deviceMemory: 'device_memory',
  screenResolution: 'screen',
  languages: 'languages',
  timezone: 'timezone',
  platform: 'platform',
  fonts: 'fonts',
  plugins: 'plugins',
  audio: 'audio',
  canvas: 'canvas',
  webGlBasics: 'webgl',
  webGlExtensions: 'webgl',
}

/**
 * Server-schema targets stored as a Set (`classify()` → `Kind::Set`), which the
 * server keeps only when the value is a string array. Every other mapped target
 * is a scalar Category/Numeric field.
 */
const SET_TARGETS = new Set(['fonts', 'plugins'])

/** A value the server can store as a scalar (Category / Numeric). */
function isScalar(value: unknown): value is string | number | boolean {
  return (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  )
}

/**
 * Reshape raw FingerprintJS `components` into the Rust server's matching schema.
 *
 * Per entry: unwrap `{ value, duration }` (dropping error components without a
 * `value`), then either rename via {@link KEY_MAP} and type-normalize, or — for
 * unrecognized names — pass the unwrapped value through under its ORIGINAL FJS
 * name when it is a scalar. On a name collision the mapped value wins.
 */
export function adaptFingerprintComponents(
  components: Record<string, unknown>,
): Record<string, unknown> {
  // Passthroughs are written first; mapped targets are spread last so a mapped
  // value always wins a collision against an unmapped passthrough of the same
  // name (rule 5).
  const passthrough: Record<string, unknown> = {}
  const mapped: Record<string, unknown> = {}

  for (const [key, entry] of Object.entries(components)) {
    // Unwrap the FJS wrapper. An entry without an own `value` (an FJS error
    // component `{ error, duration }`, or any non-object) is dropped.
    if (
      typeof entry !== 'object' ||
      entry === null ||
      !Object.hasOwn(entry, 'value')
    ) {
      continue
    }
    const value = (entry as { value: unknown }).value

    const target = KEY_MAP[key]
    if (target !== undefined) {
      if (SET_TARGETS.has(target)) {
        // Set fields keep only arrays; the server drops non-array Set values.
        if (Array.isArray(value)) {
          mapped[target] = value
        }
      } else if (isScalar(value)) {
        // Category/Numeric fields keep only scalars. Real FJS webgl/canvas
        // values are objects and drop here — out of this adapter's scope (see file doc).
        mapped[target] = value
      }
    } else if (isScalar(value)) {
      // Unknown FJS name: the server defaults it to a medium-stability category,
      // so a scalar still carries entropy. Non-scalars are undroppable
      // server-side, so drop them here.
      passthrough[key] = value
    }
  }

  return { ...passthrough, ...mapped }
}
