#!/usr/bin/env bun
/**
 * verify-deploy.ts — end-to-end verification of a deployed fingerprintd edge Worker.
 *
 * Exercises the three live routes (`/health`, `/challenge`, `/identify`) against
 * a running Worker and asserts the full T8 (nonce probe) + T9 (response signing,
 * timestamp window) contract. Runtime-agnostic: uses only global `fetch` and Web
 * Crypto, so it runs identically under `bun` and `node` (>= 20).
 *
 *   bun  scripts/verify-deploy.ts
 *   node scripts/verify-deploy.ts      # node >= 23, or: node --experimental-strip-types
 *
 * The probe/signing accept-paths need the SAME secret values set on the Worker;
 * pass them via env (they are never printed):
 *
 *   FP_PROBE_KEY=... FP_SIGNING_KEY=... bun scripts/verify-deploy.ts
 *   FP_ENFORCE_TS_WINDOW=1 ...          # also exercises the timestamp window
 *
 * Env:
 *   BASE                 Worker origin (default: the cdlab.workers.dev deployment)
 *   FP_PROBE_KEY         runtime nonce-probe key; unset ⇒ probe accept-path skipped
 *   FP_SIGNING_KEY       runtime response-signing key; unset ⇒ signing checks skipped
 *   FP_ENFORCE_TS_WINDOW "1"/"true"/"yes" ⇒ also assert stale-ts ⇒ 401
 *
 * Exit code is 0 only when every executed check passes.
 */

const BASE = (
  process.env.BASE ?? 'https://fingerprintd-edge.cdlab.workers.dev'
).replace(/\/$/, '')
const PROBE_KEY = process.env.FP_PROBE_KEY ?? ''
const SIGNING_KEY = process.env.FP_SIGNING_KEY ?? ''
const TS_WINDOW = ['1', 'true', 'yes'].includes(
  (process.env.FP_ENFORCE_TS_WINDOW ?? '').toLowerCase(),
)

/** A stable stub of the `stable_components` object; content is arbitrary. */
const COMPONENTS = {
  userAgent: 'UA',
  languages: 'en',
  timezone: 'UTC',
  platform: 'Linux',
}

let passed = 0
let failed = 0
let skipped = 0

function check(name: string, cond: boolean, extra = ''): void {
  const tag = cond ? 'PASS' : 'FAIL'
  cond ? passed++ : failed++
  console.log(`  [${tag}] ${name}${extra ? `  ${extra}` : ''}`)
}

function skip(name: string, why: string): void {
  skipped++
  console.log(`  [SKIP] ${name}  (${why})`)
}

/** hex(HMAC-SHA256(key, msg)) using Web Crypto. */
async function hmacHex(keyBytes: Uint8Array, msg: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', key, msg)
  return [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/** Big-endian u64 prefix ++ body — the exact bytes the server signs (T9). */
function signingMessage(issuedMs: string, body: Uint8Array): Uint8Array {
  const prefix = new Uint8Array(8)
  new DataView(prefix.buffer).setBigUint64(0, BigInt(issuedMs))
  const out = new Uint8Array(prefix.length + body.length)
  out.set(prefix)
  out.set(body, prefix.length)
  return out
}

async function mintNonce(): Promise<string> {
  const res = await fetch(`${BASE}/challenge`)
  const body = (await res.json()) as { nonce: string }
  return body.nonce
}

interface IdentifyBody {
  nonce: string
  stable_components: Record<string, unknown>
  probe?: string
  ts?: number
}

async function identify(
  patch: Partial<IdentifyBody> & { nonce: string },
): Promise<{ status: number; headers: Headers; bytes: Uint8Array }> {
  const body: IdentifyBody = { stable_components: COMPONENTS, ...patch }
  const res = await fetch(`${BASE}/identify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  return {
    status: res.status,
    headers: res.headers,
    bytes: new Uint8Array(await res.arrayBuffer()),
  }
}

const enc = new TextEncoder()

async function main(): Promise<void> {
  console.log(`BASE=${BASE}`)

  // --- Liveness + challenge shape -----------------------------------------
  console.log('\n== liveness + challenge ==')
  const health = await fetch(`${BASE}/health`)
  check('GET /health -> 200', health.status === 200, `got ${health.status}`)

  const chalRes = await fetch(`${BASE}/challenge`)
  const chal = (await chalRes.json()) as {
    nonce?: string
    expires_in?: number
    collect?: { challenge?: { verify?: unknown } }
  }
  check('GET /challenge has nonce', typeof chal.nonce === 'string')
  check(
    'GET /challenge has expires_in',
    typeof chal.expires_in === 'number',
    `ttl=${chal.expires_in}s`,
  )
  const probeAdvertised = chal.collect?.challenge?.verify !== undefined
  console.log(
    `  (info) probe enforcement ${probeAdvertised ? 'ON  (verify descriptor present)' : 'OFF'}`,
  )

  // --- T8 reject paths (no key needed) ------------------------------------
  console.log('\n== T8 reject paths ==')
  const rNoProbe = await identify({ nonce: await mintNonce() })
  const rBadProbe = await identify({
    nonce: await mintNonce(),
    probe: 'deadbeef',
  })
  const rBadHex = await identify({
    nonce: await mintNonce(),
    probe: 'a'.repeat(64),
  })
  if (probeAdvertised) {
    check(
      'missing probe -> 401',
      rNoProbe.status === 401,
      `got ${rNoProbe.status}`,
    )
    check(
      'forged probe -> 401',
      rBadProbe.status === 401,
      `got ${rBadProbe.status}`,
    )
    check(
      'forged 64-hex probe -> 401',
      rBadHex.status === 401,
      `got ${rBadHex.status}`,
    )
  } else {
    skip('probe reject paths', 'probe enforcement OFF on this Worker')
  }

  // Replay: consume a nonce, then reuse it — always rejected regardless of probe.
  const replayNonce = await mintNonce()
  await identify({ nonce: replayNonce, probe: 'x' })
  const replay = await identify({ nonce: replayNonce, probe: 'x' })
  check('replayed nonce -> 401', replay.status === 401, `got ${replay.status}`)

  const badNonce = await identify({
    nonce: '00000000-0000-0000-0000-000000000000',
    probe: 'x',
  })
  check(
    'unknown nonce -> 401',
    badNonce.status === 401,
    `got ${badNonce.status}`,
  )

  const schemaBad = await fetch(`${BASE}/identify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ nonce: 'x' }),
  })
  check(
    'schema violation -> 400',
    schemaBad.status === 400,
    `got ${schemaBad.status}`,
  )

  // --- T8 accept path (needs FP_PROBE_KEY) --------------------------------
  console.log('\n== T8 probe accept ==')
  let accepted: { status: number; headers: Headers; bytes: Uint8Array } | null =
    null
  if (PROBE_KEY) {
    const nonce = await mintNonce()
    const probe = await hmacHex(enc.encode(PROBE_KEY), enc.encode(nonce))
    const patch: Partial<IdentifyBody> & { nonce: string } = { nonce, probe }
    if (TS_WINDOW) patch.ts = Date.now()
    accepted = await identify(patch)
    check(
      'correct probe -> 200',
      accepted.status === 200,
      `got ${accepted.status}`,
    )
    if (accepted.status === 200) {
      const resp = JSON.parse(new TextDecoder().decode(accepted.bytes)) as {
        visitorId?: string
      }
      check(
        'body has visitorId',
        typeof resp.visitorId === 'string',
        `${resp.visitorId?.slice(0, 16)}…`,
      )
    }
  } else {
    skip('correct probe -> 200', 'FP_PROBE_KEY not set')
  }

  // --- T9 signing (needs a 200 from the accept path + FP_SIGNING_KEY) ------
  console.log('\n== T9 signing ==')
  if (accepted?.status === 200) {
    const ts = accepted.headers.get('x-fp-timestamp')
    const sig = accepted.headers.get('x-fp-signature')
    if (SIGNING_KEY) {
      check('x-fp-timestamp present', ts !== null, ts ?? '')
      check('x-fp-signature present', sig !== null)
      if (ts && sig) {
        const expect = await hmacHex(
          enc.encode(SIGNING_KEY),
          signingMessage(ts, accepted.bytes),
        )
        check(
          'signature == HMAC(signing_key, be(ts)++body)',
          timingSafeEqualHex(expect, sig),
        )
      }
    } else if (ts || sig) {
      console.log(
        '  (info) signing headers present but FP_SIGNING_KEY unset — cannot verify value',
      )
      skip('signature verification', 'FP_SIGNING_KEY not set')
    } else {
      console.log(
        '  (info) no signing headers — response signing OFF on this Worker',
      )
    }
  } else {
    skip('signing checks', 'no 200 accept-path response (set FP_PROBE_KEY)')
  }

  // --- T9 timestamp window (only when enabled) ----------------------------
  if (TS_WINDOW && PROBE_KEY) {
    console.log('\n== T9 timestamp window ==')
    const nonce = await mintNonce()
    const probe = await hmacHex(enc.encode(PROBE_KEY), enc.encode(nonce))
    const stale = await identify({ nonce, probe, ts: Date.now() - 3_600_000 })
    check('stale ts -> 401', stale.status === 401, `got ${stale.status}`)
  }

  console.log(
    `\n${failed === 0 ? 'OK' : 'FAILED'} — ${passed} passed, ${failed} failed, ${skipped} skipped`,
  )
  process.exit(failed === 0 ? 0 : 1)
}

/** Constant-time hex-string compare, so the verifier itself leaks no timing. */
function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

main().catch((err) => {
  console.error(err)
  process.exit(2)
})
