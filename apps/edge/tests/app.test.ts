import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import type { Deps } from '../src/app'
import { createApp } from '../src/app'
import type { Env } from '../src/config'
import { resolveConfig } from '../src/config'
import { EdgeEngine, initEngineRuntime } from '../src/engine'
import { SIGNATURE_HEADER, SIGNATURE_TIMESTAMP_HEADER } from '../src/signature'
import { EmptyCandidateSource, InMemoryNonceStore } from '../src/state'
import type { ChallengeResponse, IdentifyResponse } from '../src/types'

/** Drive the Hono app with injected deps; state lives in `deps`, so a fresh app
 *  per call is fine (a shim over the pre-Hono `handleRequest(req, deps)`). */
const handleRequest = (req: Request, deps: Deps) => createApp(deps).request(req)

// Load the vendored WASM engine once for the whole suite (mirrors how the
// Worker inits per isolate, but from disk bytes instead of an `import`).
beforeAll(() => {
  const wasmPath = fileURLToPath(
    new URL('../wasm/fp_wasm_bg.wasm', import.meta.url).href,
  )
  const bytes = readFileSync(wasmPath)
  initEngineRuntime(bytes)
})

/** Build injected deps + a fresh STUBBED state for a given environment. */
function makeDeps(env: Env = {}): Deps {
  const config = resolveConfig(env)
  return {
    engine: new EdgeEngine(config),
    nonces: new InMemoryNonceStore(config.nonceTtlSecs),
    candidates: new EmptyCandidateSource(),
    config,
  }
}

const get = (path: string) =>
  new Request(`https://edge.test${path}`, { method: 'GET' })

const postIdentify = (body: unknown) =>
  new Request('https://edge.test/identify', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

/** GET /challenge and return its parsed body. */
async function challenge(deps: Deps): Promise<ChallengeResponse> {
  const resp = await handleRequest(get('/challenge'), deps)
  expect(resp.status).toBe(200)
  return (await resp.json()) as ChallengeResponse
}

/** A rich, realistic stable-component probe the fuzzy engine can score. */
function probeComponents(): Record<string, unknown> {
  return {
    webgl: 'ANGLE (Intel)',
    platform: 'Linux x86_64',
    timezone: 'Asia/Shanghai',
    audio: '124.04',
    cpu_cores: 8,
    device_memory: 8,
    fonts: ['Arial', 'Helvetica', 'Courier', 'Times', 'Verdana'],
    user_agent: 'Chrome/120',
  }
}

describe('routing', () => {
  it('health returns 200', async () => {
    const resp = await handleRequest(get('/health'), makeDeps())
    expect(resp.status).toBe(200)
  })

  it('unknown route returns 404', async () => {
    const resp = await handleRequest(get('/nope'), makeDeps())
    expect(resp.status).toBe(404)
  })
})

describe('GET /challenge', () => {
  it('mints a nonce with the collection plan (probe transform omitted by default)', async () => {
    const body = await challenge(makeDeps())
    expect(typeof body.nonce).toBe('string')
    expect(body.expires_in).toBe(30)
    expect(body.collect.challenge.seed).toBe(body.nonce)
    expect(body.collect.stable).toContain('userAgent')
    expect(body.collect.challenge.targets).toEqual(['canvas', 'audio'])
    // No probe key ⇒ transform not advertised.
    expect(body.collect.challenge.verify).toBeUndefined()
  })

  it('advertises the probe transform when a probe key is configured', async () => {
    const body = await challenge(
      makeDeps({ FP_PROBE_KEY: 'test-probe-secret' }),
    )
    expect(body.collect.challenge.verify).toEqual({
      alg: 'HMAC-SHA256',
      input: 'nonce',
      encoding: 'hex',
    })
  })
})

describe('POST /identify', () => {
  it('identifies a first-ever probe as a new device', async () => {
    const deps = makeDeps()
    const { nonce } = await challenge(deps)
    const resp = await handleRequest(
      postIdentify({ nonce, stable_components: probeComponents() }),
      deps,
    )
    expect(resp.status).toBe(200)
    const body = (await resp.json()) as IdentifyResponse
    expect(typeof body.visitorId).toBe('string')
    expect(body.is_new_device).toBe(true)
    expect(body.decision).toBe('new_device')
    expect(body.confidence).toBeGreaterThanOrEqual(0)
    expect(body.confidence).toBeLessThanOrEqual(1)
    // Neutral degraded signals when no Bot Management headers are present.
    expect(body.signals).toEqual({ ua_tls_consistent: true, ip_risk: 'low' })
  })

  it('rejects an unknown top-level field with 400 (strict schema, M6a/L1)', async () => {
    const deps = makeDeps()
    const { nonce } = await challenge(deps)
    // A stray `challenge_response` (or any extra top-level key) is no longer
    // tolerated: the strict schema fails zValidator, yielding a 400 before the
    // handler runs — the nonce is NOT consumed.
    const resp = await handleRequest(
      postIdentify({
        nonce,
        stable_components: { ua: 'x' },
        challenge_response: { canvas: 'abc' },
      }),
      deps,
    )
    expect(resp.status).toBe(400)
  })

  it('rejects an unknown nonce with 401', async () => {
    const resp = await handleRequest(
      postIdentify({ nonce: 'never-issued', stable_components: { ua: 'x' } }),
      makeDeps(),
    )
    expect(resp.status).toBe(401)
  })

  it('rejects a replayed nonce with 401', async () => {
    const deps = makeDeps()
    const { nonce } = await challenge(deps)
    const body = { nonce, stable_components: { ua: 'x' } }
    expect((await handleRequest(postIdentify(body), deps)).status).toBe(200)
    // Same nonce again: the one-time nonce is burned.
    expect((await handleRequest(postIdentify(body), deps)).status).toBe(401)
  })
})

describe('nonce-probe enforcement (T8)', () => {
  const env: Env = { FP_PROBE_KEY: 'test-probe-secret' }

  it('accepts a correct probe and rejects a missing/forged one', async () => {
    const deps = makeDeps(env)

    // Missing probe when enforced ⇒ 401.
    const { nonce: n1 } = await challenge(deps)
    expect(
      (
        await handleRequest(
          postIdentify({ nonce: n1, stable_components: { ua: 'x' } }),
          deps,
        )
      ).status,
    ).toBe(401)

    // Correct probe ⇒ 200.
    const { nonce: n2 } = await challenge(deps)
    const probe = deps.engine.expectedProbe(n2)
    expect(
      (
        await handleRequest(
          postIdentify({ nonce: n2, probe, stable_components: { ua: 'x' } }),
          deps,
        )
      ).status,
    ).toBe(200)

    // Forged probe ⇒ 401.
    const { nonce: n3 } = await challenge(deps)
    expect(
      (
        await handleRequest(
          postIdentify({
            nonce: n3,
            probe: 'deadbeef',
            stable_components: { ua: 'x' },
          }),
          deps,
        )
      ).status,
    ).toBe(401)
  })

  it('reproduces the shared probe parity vector', () => {
    // Ties the edge probe check to the browser collector's vendored artifact
    // (packages/client) and the native server — same key, same nonce, same hex.
    const engine = new EdgeEngine(
      resolveConfig({ FP_PROBE_KEY: 'test-probe-secret' }),
    )
    expect(engine.expectedProbe('fixed-nonce-000')).toBe(
      'ad83144894f917b94072c2f7b3246af66d3bc5a450562ccf3671ed64d33137d0',
    )
  })
})

describe('response signing (T9)', () => {
  it('omits signature headers when no signing key is configured', async () => {
    const deps = makeDeps()
    const { nonce } = await challenge(deps)
    const resp = await handleRequest(
      postIdentify({ nonce, stable_components: { ua: 'x' } }),
      deps,
    )
    expect(resp.headers.get(SIGNATURE_HEADER)).toBeNull()
    expect(resp.headers.get(SIGNATURE_TIMESTAMP_HEADER)).toBeNull()
  })

  it('signs the exact response bytes when a signing key is configured', async () => {
    const deps = makeDeps({ FP_SIGNING_KEY: 'test-signing-secret' })
    const { nonce } = await challenge(deps)
    const resp = await handleRequest(
      postIdentify({ nonce, stable_components: { ua: 'x' } }),
      deps,
    )
    expect(resp.status).toBe(200)

    const issuedMs = Number(resp.headers.get(SIGNATURE_TIMESTAMP_HEADER))
    const signature = resp.headers.get(SIGNATURE_HEADER)
    expect(signature).toMatch(/^[0-9a-f]{64}$/)

    // The advertised signature recomputes over the received timestamp + body.
    const bodyBytes = new Uint8Array(await resp.arrayBuffer())
    expect(deps.engine.sign(issuedMs, bodyBytes)).toBe(signature)

    // Tampering the body breaks the signature.
    const tampered = new Uint8Array([...bodyBytes, 0x20])
    expect(deps.engine.sign(issuedMs, tampered)).not.toBe(signature)
  })

  it('reproduces the shared signing vector', () => {
    // Ties the edge signer to the native `fp_core::signing::ResponseSigner`
    // (crates/fp-wasm `engine_sign_matches_shared_vector`): same signing key,
    // same timestamp + body, same hex — the response-signing analogue of the
    // probe parity vector, proving the signing Worker Secret path is identical.
    const engine = new EdgeEngine(
      resolveConfig({ FP_SIGNING_KEY: 'test-signing-secret' }),
    )
    const body = new TextEncoder().encode('{"visitorId":"abc"}')
    expect(engine.sign(1_700_000_000_000, body)).toBe(
      '11e764ff987d7be6e4f9e272c9c9fbb9c29fc8c5e3dcc5b935dfa11b9c751792',
    )
  })
})

describe('timestamp window (T9)', () => {
  const env: Env = { FP_ENFORCE_TS_WINDOW: '1', FP_TS_SKEW_SECS: '30' }

  it('accepts a fresh ts and rejects stale/future/missing', async () => {
    const deps = makeDeps(env)
    const now = Date.now()
    const send = async (extra: Record<string, unknown>) => {
      const { nonce } = await challenge(deps)
      return handleRequest(
        postIdentify({ nonce, stable_components: { ua: 'x' }, ...extra }),
        deps,
      )
    }
    expect((await send({ ts: now })).status).toBe(200)
    expect((await send({ ts: now - 60_000 })).status).toBe(401)
    expect((await send({ ts: now + 60_000 })).status).toBe(401)
    expect((await send({})).status).toBe(401)
  })
})

describe('passive signals (edge JA4/IP fusion, M2)', () => {
  // Shared JA4/UA vectors, identical to the native `signals` tests
  // (crates/fingerprintd/src/signals.rs) so the edge verdict is provably the same.
  /** A JA4 whose structural counts read as a real browser (15 ciphers, 16 ext). */
  const BROWSER_JA4 = 't13d1516h2_8daaf6152771_02713d6af862'
  /** A JA4 whose counts read as a minimal automation stack (3/4). */
  const AUTOMATION_JA4 = 't13d0304h1_aaaaaaaaaaaa_bbbbbbbbbbbb'

  const postIdentifyWith = (body: unknown, headers: Record<string, string>) =>
    new Request('https://edge.test/identify', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
    })

  /** Run a full challenge→identify and return the parsed body. `probeComponents`
   *  reports a Chrome UA (`user_agent`), so a browser JA4 is consistent and an
   *  automation JA4 is the forgery. The candidate source is empty ⇒ the base
   *  score is identical across calls, so confidences are comparable. */
  async function identifyWith(
    deps: Deps,
    headers: Record<string, string>,
  ): Promise<IdentifyResponse> {
    const { nonce } = await challenge(deps)
    const resp = await handleRequest(
      postIdentifyWith(
        { nonce, stable_components: probeComponents() },
        headers,
      ),
      deps,
    )
    expect(resp.status).toBe(200)
    return (await resp.json()) as IdentifyResponse
  }

  const trustedDeps = () => makeDeps({ FP_TRUST_EDGE_HEADERS: '1' })

  it('trusted browser JA4 over a Chrome UA is consistent and boosts confidence', async () => {
    const deps = trustedDeps()
    // Degraded baseline: trusted edge, but no Bot Management header present.
    const degraded = await identifyWith(deps, {})
    expect(degraded.signals).toEqual({
      ua_tls_consistent: true,
      ip_risk: 'low',
    })

    const consistent = await identifyWith(deps, {
      'cf-bot-management-ja4': BROWSER_JA4,
    })
    expect(consistent.signals.ua_tls_consistent).toBe(true)
    // The consistency boost (fuzzy-matching §6) lifts confidence above the degraded base.
    expect(consistent.confidence).toBeGreaterThan(degraded.confidence)
  })

  it('trusted automation JA4 under a Chrome UA is a forgery: inconsistent + downgraded', async () => {
    const deps = trustedDeps()
    const degraded = await identifyWith(deps, {})
    const forgery = await identifyWith(deps, {
      'cf-bot-management-ja4': AUTOMATION_JA4,
    })
    // The anti-forgery core (architecture §4.2): Chrome UA riding an automation TLS stack.
    expect(forgery.signals.ua_tls_consistent).toBe(false)
    expect(forgery.confidence).toBeLessThan(degraded.confidence)
  })

  it('cf-connecting-ip drives the ip_risk band (datacenter high / residential low)', async () => {
    const deps = trustedDeps()
    const datacenter = await identifyWith(deps, {
      'cf-bot-management-ja4': BROWSER_JA4,
      'cf-connecting-ip': '34.120.5.6',
    })
    expect(datacenter.signals.ip_risk).toBe('high')

    const residential = await identifyWith(deps, {
      'cf-bot-management-ja4': BROWSER_JA4,
      'cf-connecting-ip': '198.51.100.7',
    })
    expect(residential.signals.ip_risk).toBe('low')

    // No IP header at all ⇒ low (no adverse evidence).
    const absent = await identifyWith(deps, {
      'cf-bot-management-ja4': BROWSER_JA4,
    })
    expect(absent.signals.ip_risk).toBe('low')
  })

  it('trusted edge with JA4 absent auto-degrades: consistent, low, no penalty', async () => {
    const deps = trustedDeps()
    const baseline = await identifyWith(deps, {})
    // IP present but Bot Management absent ⇒ degraded (neutral), IP still classified.
    const degraded = await identifyWith(deps, {
      'cf-connecting-ip': '198.51.100.7',
    })
    expect(degraded.signals.ua_tls_consistent).toBe(true)
    expect(degraded.signals.ip_risk).toBe('low')
    // A missing connection signal never penalises (§4.2 auto-degrade).
    expect(degraded.confidence).toBeCloseTo(baseline.confidence, 12)
  })

  it('untrusted edge ignores a forged client-supplied JA4/IP copy', async () => {
    // trustEdgeHeaders defaults OFF: a request-supplied automation JA4 +
    // datacenter IP must NOT be trusted — the untrusted path auto-degrades.
    const deps = makeDeps()
    const baseline = await identifyWith(deps, {})
    const forged = await identifyWith(deps, {
      'cf-bot-management-ja4': AUTOMATION_JA4,
      'cf-connecting-ip': '34.120.5.6',
    })
    expect(forged.signals).toEqual({ ua_tls_consistent: true, ip_risk: 'low' })
    // The forged copy neither downgrades confidence nor raises the IP band.
    expect(forged.confidence).toBeCloseTo(baseline.confidence, 12)
  })
})

describe('DELETE /visitor/:id erasure (M6b)', () => {
  /** Deps with an injected candidate source whose `erase` is spy-able. */
  function eraseDeps(env: Env = {}) {
    const candidates = new EmptyCandidateSource()
    const erase = vi.spyOn(candidates, 'erase')
    return { deps: { ...makeDeps(env), candidates }, erase }
  }

  const del = (id: string, headers: Record<string, string> = {}) =>
    new Request(`https://edge.test/visitor/${id}`, {
      method: 'DELETE',
      headers,
    })

  it('returns 404 when no admin key is configured (endpoint disabled)', async () => {
    const { deps, erase } = eraseDeps()
    const resp = await handleRequest(
      del('v1', { authorization: 'Bearer x' }),
      deps,
    )
    expect(resp.status).toBe(404)
    expect(erase).not.toHaveBeenCalled()
  })

  it('returns 401 on a missing or wrong bearer credential', async () => {
    const { deps, erase } = eraseDeps({ FP_ADMIN_KEY: 'admin-secret' })
    // Missing header.
    expect((await handleRequest(del('v1'), deps)).status).toBe(401)
    // Wrong key.
    expect(
      (await handleRequest(del('v1', { authorization: 'Bearer nope' }), deps))
        .status,
    ).toBe(401)
    // Not a bearer scheme.
    expect(
      (await handleRequest(del('v1', { authorization: 'admin-secret' }), deps))
        .status,
    ).toBe(401)
    expect(erase).not.toHaveBeenCalled()
  })

  it('returns 204 and erases the visitor when authorized', async () => {
    const { deps, erase } = eraseDeps({ FP_ADMIN_KEY: 'admin-secret' })
    const resp = await handleRequest(
      del('visitor-42', { authorization: 'Bearer admin-secret' }),
      deps,
    )
    expect(resp.status).toBe(204)
    expect(erase).toHaveBeenCalledWith('visitor-42')
  })
})

describe('CORS (browser playground)', () => {
  const ORIGIN = 'https://app.test'
  const corsDeps = () =>
    makeDeps({ FP_CORS_ORIGINS: `${ORIGIN}, https://other.test` })

  const withOrigin = (path: string, origin: string) =>
    new Request(`https://edge.test${path}`, {
      method: 'GET',
      headers: { origin },
    })

  it('answers preflight for an allowed origin with the POST method allowed', async () => {
    const resp = await handleRequest(
      new Request('https://edge.test/identify', {
        method: 'OPTIONS',
        headers: {
          origin: ORIGIN,
          'access-control-request-method': 'POST',
          'access-control-request-headers': 'content-type',
        },
      }),
      corsDeps(),
    )
    expect(resp.status).toBe(204)
    expect(resp.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    expect(resp.headers.get('access-control-allow-methods')).toContain('POST')
  })

  it('reflects an allowed origin and exposes the T9 signature headers', async () => {
    const resp = await handleRequest(
      withOrigin('/challenge', ORIGIN),
      corsDeps(),
    )
    expect(resp.status).toBe(200)
    expect(resp.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    expect(
      resp.headers.get('access-control-expose-headers')?.toLowerCase(),
    ).toContain(SIGNATURE_HEADER)
  })

  it('does not echo an unlisted origin', async () => {
    const resp = await handleRequest(
      withOrigin('/challenge', 'https://evil.test'),
      corsDeps(),
    )
    expect(resp.headers.get('access-control-allow-origin')).not.toBe(
      'https://evil.test',
    )
  })

  it('emits no CORS headers when unconfigured', async () => {
    const resp = await handleRequest(
      withOrigin('/challenge', ORIGIN),
      makeDeps(),
    )
    expect(resp.headers.get('access-control-allow-origin')).toBeNull()
  })
})
