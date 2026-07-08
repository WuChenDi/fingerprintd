/**
 * Playground flow runner.
 *
 * Drives the collect-only SDK end-to-end against a fingerprintd server and
 * returns every intermediate the UI visualizes. The four evidence lanes
 * (`stable_components` / `challenge_response` / `probe` / `ts`) come straight
 * out of the SDK's {@link Collected} — the client never derives an id, the
 * server judges.
 */
import type {
  ChallengeResponse,
  Collected,
  IdentifyRequest,
  IdentifyResponse,
} from '@fingerprintd/client'
import {
  createCollector,
  getChallenge,
  identify,
  initProbe,
  verifySignature,
} from '@fingerprintd/client'
import wasmUrl from '@fingerprintd/client/wasm?url'

/**
 * Init the WASM probe once with the Vite-resolved asset URL. Passing the URL
 * explicitly is more robust under Vite than the SDK's default `import.meta.url`
 * fetch (which is brittle across a pre-bundled dependency). Idempotent: the
 * SDK's own `initProbe()` inside the collector reuses this singleton.
 */
let probeReady: Promise<void> | null = null
function ensureProbe(): Promise<void> {
  if (probeReady === null) probeReady = initProbe(wasmUrl)
  return probeReady
}

/** Response-signature (T9) summary for the UI. */
export interface SignatureInfo {
  /** The server sent both the timestamp and signature headers. */
  signed: boolean
  /** `x-fp-timestamp` — server issue time in Unix ms (string). */
  timestamp?: string
  /** `x-fp-signature` — hex HMAC-SHA256 of the response. */
  signature?: string
  /** Verification result; set only when a signing key was supplied AND signed. */
  valid?: boolean
}

/** Everything a single flow run produces. */
export interface FlowResult {
  challenge: ChallengeResponse
  collected: Collected
  identity: IdentifyResponse
  signature: SignatureInfo
}

/**
 * Run `getChallenge -> collect -> identify`, verifying the response signature
 * when `signingKey` is a non-empty UTF-8 key. Throws on transport/HTTP errors.
 */
export async function runFlow(
  baseUrl: string,
  signingKey: string,
): Promise<FlowResult> {
  await ensureProbe()

  const challenge = await getChallenge(baseUrl)
  const collected = await createCollector()(challenge)

  const request: IdentifyRequest = {
    nonce: challenge.nonce,
    stable_components: collected.stable_components,
  }
  if (collected.ts !== undefined) request.ts = collected.ts
  if (collected.probe !== undefined) request.probe = collected.probe
  if (collected.challenge_response !== undefined) {
    request.challenge_response = collected.challenge_response
  }

  const { result, bodyBytes, timestamp, signature } = await identify(
    baseUrl,
    request,
  )

  const signed = timestamp !== undefined && signature !== undefined
  const info: SignatureInfo = { signed, timestamp, signature }
  if (signed && signingKey.trim() !== '') {
    const key = new TextEncoder().encode(signingKey)
    info.valid = await verifySignature(
      key,
      Number(timestamp),
      bodyBytes,
      signature as string,
    )
  }

  return { challenge, collected, identity: result, signature: info }
}
