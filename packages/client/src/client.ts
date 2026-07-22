/**
 * Thin HTTP client for the two fingerprintd endpoints. Transport only — it does
 * no collection and no judging. `fetch` is injectable so tests can mock it
 * without a network or a browser.
 */

import { SIGNATURE_HEADER, SIGNATURE_TIMESTAMP_HEADER } from './signature'
import type {
  ChallengeResponse,
  IdentifyRequest,
  IdentifyResponse,
} from './types'

/** A `fetch`-compatible function. Defaults to `globalThis.fetch`. */
export type FetchLike = typeof globalThis.fetch

/** Options accepted by the request helpers. */
export interface ClientOptions {
  /** Override the `fetch` implementation (for mocking/tests). */
  fetch?: FetchLike
}

/** The parsed `/identify` body plus the response-signature headers, if the
 *  server signed the response. Both headers are absent when signing is off. */
export interface IdentifyResult {
  /** The parsed success body. */
  result: IdentifyResponse
  /** The RAW response body bytes exactly as received. Signature verification
   *  must run over these — re-serializing `result` would not reproduce the
   *  server's byte layout, so the tag would not match. */
  bodyBytes: Uint8Array
  /** `x-fp-timestamp` header — server issue time in Unix ms (string), if signed. */
  timestamp?: string
  /** `x-fp-signature` header — hex HMAC-SHA256 of the response, if signed. */
  signature?: string
}

/** Join a base URL and a path without doubling or dropping the slash. */
function endpoint(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/+$/, '')}${path}`
}

/** GET `/challenge` — mint a one-time nonce and collection plan. */
export async function getChallenge(
  baseUrl: string,
  options: ClientOptions = {},
): Promise<ChallengeResponse> {
  const doFetch = options.fetch ?? globalThis.fetch
  const response = await doFetch(endpoint(baseUrl, '/challenge'), {
    method: 'GET',
    headers: { accept: 'application/json' },
  })
  if (!response.ok) {
    throw new Error(`GET /challenge failed: ${response.status}`)
  }
  return (await response.json()) as ChallengeResponse
}

/**
 * POST `/identify` — submit the collected components under the nonce.
 *
 * Returns the parsed body together with the raw response-signature headers so a
 * caller can verify them (see {@link import('./signature').verifySignature}).
 * A non-2xx status throws before parsing.
 */
export async function identify(
  baseUrl: string,
  body: IdentifyRequest,
  options: ClientOptions = {},
): Promise<IdentifyResult> {
  const doFetch = options.fetch ?? globalThis.fetch
  const response = await doFetch(endpoint(baseUrl, '/identify'), {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    throw new Error(`POST /identify failed: ${response.status}`)
  }
  // Read raw bytes (not `.json()`) so the exact signed body is available to
  // verify, then parse from those same bytes.
  const bodyBytes = new Uint8Array(await response.arrayBuffer())
  const result = JSON.parse(
    new TextDecoder().decode(bodyBytes),
  ) as IdentifyResponse
  const timestamp =
    response.headers.get(SIGNATURE_TIMESTAMP_HEADER) ?? undefined
  const signature = response.headers.get(SIGNATURE_HEADER) ?? undefined
  return { result, bodyBytes, timestamp, signature }
}
