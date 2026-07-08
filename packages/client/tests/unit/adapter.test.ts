/**
 * Unit tests for the FingerprintJS → server-schema adapter (audit H5, part a).
 *
 * Fixtures are FJS-SHAPED: real FJS key names with values wrapped as
 * `{ value, duration }`. The assertions pin the three transforms the server
 * (`crates/fp-core/src/fuzzy/mod.rs` `classify()`) requires — wrapper unwrap,
 * key-name mapping, and drop of unstorable kinds — with NO browser involved.
 */

import { describe, expect, it } from 'vitest'
import { adaptFingerprintComponents } from '../../src/adapter'

describe('adaptFingerprintComponents', () => {
  it('unwraps the { value, duration } wrapper to a bare scalar', () => {
    const out = adaptFingerprintComponents({
      timezone: { value: 'Asia/Shanghai', duration: 1 },
    })
    expect(out.timezone).toBe('Asia/Shanghai')
  })

  it('never emits a { value, duration } wrapper', () => {
    const out = adaptFingerprintComponents({
      timezone: { value: 'UTC', duration: 1 },
      hardwareConcurrency: { value: 8, duration: 0 },
      colorDepth: { value: 24, duration: 0 },
    })
    for (const v of Object.values(out)) {
      expect(v).not.toHaveProperty('value')
      expect(v).not.toHaveProperty('duration')
    }
  })

  it('applies the FJS → server key-name map', () => {
    const out = adaptFingerprintComponents({
      hardwareConcurrency: { value: 8, duration: 0 },
      deviceMemory: { value: 8, duration: 0 },
      screenResolution: { value: 1080, duration: 0 },
      webGlBasics: { value: 'ANGLE (Intel)', duration: 5 },
    })
    expect(out.cpu_cores).toBe(8)
    expect(out.device_memory).toBe(8)
    expect(out.screen).toBe(1080)
    expect(out.webgl).toBe('ANGLE (Intel)')
    // Original FJS names must not survive the rename.
    expect(out).not.toHaveProperty('hardwareConcurrency')
    expect(out).not.toHaveProperty('deviceMemory')
    expect(out).not.toHaveProperty('webGlBasics')
  })

  it('keeps an array for a Set field (fonts)', () => {
    const out = adaptFingerprintComponents({
      fonts: { value: ['Arial', 'Helvetica'], duration: 3 },
    })
    expect(out.fonts).toEqual(['Arial', 'Helvetica'])
  })

  it('drops a Set field whose unwrapped value is not an array', () => {
    const out = adaptFingerprintComponents({
      fonts: { value: 'Arial', duration: 3 },
      plugins: { value: { count: 2 }, duration: 1 },
    })
    expect(out).not.toHaveProperty('fonts')
    expect(out).not.toHaveProperty('plugins')
  })

  it('drops a category/numeric mapped field whose value is an object', () => {
    // Real FJS webgl/canvas values are objects — the server cannot store them,
    // so they drop (H5 scope: wrapper+key mismatch, not canonicalization).
    const out = adaptFingerprintComponents({
      webGlBasics: { value: { version: 'WebGL 2.0' }, duration: 5 },
      canvas: { value: { winding: true }, duration: 9 },
    })
    expect(out).not.toHaveProperty('webgl')
    expect(out).not.toHaveProperty('canvas')
  })

  it('passes an unmapped scalar through under its FJS name', () => {
    const out = adaptFingerprintComponents({
      colorDepth: { value: 24, duration: 0 },
    })
    expect(out.colorDepth).toBe(24)
  })

  it('drops an unmapped non-scalar (object or array)', () => {
    const out = adaptFingerprintComponents({
      domBlockers: { value: ['x'], duration: 2 },
      math: { value: { sin: 1 }, duration: 4 },
    })
    expect(out).not.toHaveProperty('domBlockers')
    expect(out).not.toHaveProperty('math')
  })

  it('drops an FJS error component (no value property)', () => {
    const out = adaptFingerprintComponents({
      audio: { error: 'unsupported', duration: 2 },
    })
    expect(out).not.toHaveProperty('audio')
    expect(Object.keys(out)).toHaveLength(0)
  })

  it('maps webGlExtensions to webgl with last-wins on collision', () => {
    // Both map to `webgl`; the later-iterated entry wins.
    const out = adaptFingerprintComponents({
      webGlBasics: { value: 'basics', duration: 1 },
      webGlExtensions: { value: 'extensions', duration: 1 },
    })
    expect(out.webgl).toBe('extensions')
  })

  it('lets a mapped value win a collision with an unmapped passthrough', () => {
    // An unmapped FJS key literally named `cpu_cores` must not shadow the
    // mapped hardwareConcurrency target (rule 5: mapped wins).
    const out = adaptFingerprintComponents({
      cpu_cores: { value: 2, duration: 0 },
      hardwareConcurrency: { value: 8, duration: 0 },
    })
    expect(out.cpu_cores).toBe(8)
  })

  it('treats a stray visitorId component as a plain scalar passthrough', () => {
    // The adapter only receives `components`; discarding the FJS visitorId hash
    // is fingerprint.ts's job. If a `visitorId` slips in as a component it is
    // just an unmapped scalar passthrough — not special-cased here.
    const out = adaptFingerprintComponents({
      visitorId: { value: 'v', duration: 0 },
    })
    expect(out.visitorId).toBe('v')
  })
})
