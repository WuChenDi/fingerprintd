/**
 * Response-signature header names (T9).
 *
 * The Worker signs `/identify` responses via the WASM engine as
 *   `hex(HMAC-SHA256(key, issued_ms.to_be_bytes() ++ body))`
 * carried in these headers. They MUST match the native server
 * (`crates/fp-core/src/signing.rs`) and the browser verifier
 * (`clients/web/src/signature.ts`) exactly, so a client verifies either.
 */

/** Response header carrying the server's signing time (Unix milliseconds). */
export const SIGNATURE_TIMESTAMP_HEADER = 'x-fp-timestamp'
/** Response header carrying the hex HMAC-SHA256 signature of the response. */
export const SIGNATURE_HEADER = 'x-fp-signature'
