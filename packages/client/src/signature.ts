/**
 * Response-signature verification (T9).
 *
 * The server signs each `/identify` response as
 *   `hex(HMAC-SHA256(key, issued_ms.to_be_bytes() ++ body))`
 * where `issued_ms` is an 8-byte big-endian u64 (the `x-fp-timestamp` header)
 * prepended to the RAW response body bytes. This MUST match
 * `crates/fingerprintd/src/signing.rs` exactly.
 *
 * SHARED-SECRET CAVEAT: client-side verification needs the same signing key the
 * server holds. Embedding that secret in shipped browser code is only shallow
 * defense-in-depth — the same embedded-secret depth caveat as the WASM probe
 * key. Real trust-on-the-wire is TLS; this verify is a tamper/forgery tripwire,
 * not a substitute for it.
 */

/** Response header carrying the server's signing time (Unix milliseconds). */
export const SIGNATURE_TIMESTAMP_HEADER = 'x-fp-timestamp'
/** Response header carrying the hex HMAC-SHA256 signature of the response. */
export const SIGNATURE_HEADER = 'x-fp-signature'

/** Encode a Unix-millisecond timestamp as an 8-byte big-endian u64, matching
 *  Rust's `u64::to_be_bytes`. Uses BigInt so the full u64 range is exact. */
function be64(issuedMs: number): Uint8Array {
  const buf = new Uint8Array(8)
  new DataView(buf.buffer).setBigUint64(0, BigInt(issuedMs), false)
  return buf
}

/** Parse an even-length hex string into bytes; `null` on malformed input. */
function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0) return null
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    if (Number.isNaN(byte)) return null
    out[i] = byte
  }
  return out
}

/** Constant-time byte comparison — no early return on the first mismatch. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] as number) ^ (b[i] as number)
  }
  return diff === 0
}

/**
 * Verify a response signature.
 *
 * @param key      the shared HMAC-SHA256 key
 * @param issuedMs the `x-fp-timestamp` value (Unix ms)
 * @param bodyBytes the RAW response body bytes that were signed
 * @param sigHex   the `x-fp-signature` header value (hex)
 * @returns `true` iff the recomputed tag matches `sigHex` (constant-time)
 */
export async function verifySignature(
  key: Uint8Array,
  issuedMs: number,
  bodyBytes: Uint8Array,
  sigHex: string,
): Promise<boolean> {
  const expected = hexToBytes(sigHex)
  if (expected === null) return false

  const message = new Uint8Array(8 + bodyBytes.length)
  message.set(be64(issuedMs), 0)
  message.set(bodyBytes, 8)

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    // Copy into a fresh ArrayBuffer so a Uint8Array view/offset can't leak in.
    key.slice(),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const tag = new Uint8Array(
    await crypto.subtle.sign('HMAC', cryptoKey, message),
  )
  return constantTimeEqual(tag, expected)
}
