/* tslint:disable */
/* eslint-disable */

/**
 * Server-side edge compute, configured with a deployment's secrets.
 *
 * A Cloudflare Worker host constructs one `FpEngine` per isolate from its
 * Worker Secrets and calls it for the pure compute of a `/identify` request. It
 * holds no request state: [`FpEngine::score`] rebuilds the recalled candidate
 * block in a transient store per call and discards it, leaving persistence to
 * the host.
 */
export class FpEngine {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Blocking keys for a probe's `components`, as a JSON array of hex strings.
     *
     * `components_json` is the raw component object from `POST /identify`; the
     * host queries its candidate index (D1) with the returned keys. Invalid JSON
     * surfaces as a thrown JS exception.
     */
    blocking_keys(components_json: string): string;
    /**
     * Expected probe `hex(HMAC-SHA256(probe_key, nonce))` for `nonce` — the
     * value a probe-capable client should echo, computed with the configured
     * key. Fails closed to an empty string on the unreachable keying error.
     */
    expected_probe(nonce: string): string;
    /**
     * Construct an engine from the deployment's configured secrets.
     *
     * `salt_secret` seeds the deterministic salt and `MinHash` family so
     * blocking keys and stored hashes are reproducible across isolates;
     * `probe_key` is the pre-shared nonce-probe key; `signing_key` signs
     * response bodies. In a real deployment all three are Worker Secrets.
     */
    constructor(salt_secret: string, probe_key: string, signing_key: string);
    /**
     * Score a probe against host-supplied candidates and return the verdict as
     * JSON, **without** mutating any state.
     *
     * `request_json` is `{ "components": {..}, "candidates": [{ "visitor_id":
     * "..", "components": {..} }, ..] }` — the recalled candidate templates the
     * host fetched from D1. The reply is
     * `{ "visitor_id", "is_new_device", "decision", "confidence", "score",
     * "compared_components", "collision_risk" }` (see [`fp_core`]'s
     * `MatchOutcome`). The host applies its own persistence per the returned
     * `decision` (drift a match, mint a new device, leave a review untouched).
     *
     * `u_i` rarity is estimated over the supplied candidate block, a local
     * approximation of the native server's global frequency table; a global
     * frequency snapshot is a later (D1) refinement. Invalid JSON surfaces as a
     * thrown JS exception.
     */
    score(request_json: string): string;
    /**
     * Sign a response body: `hex(HMAC-SHA256(signing_key, issued_ms_be ++ body))`,
     * carried in the `x-fp-signature` header alongside `x-fp-timestamp`.
     * `issued_ms` is the server's issue time in Unix milliseconds. Fails closed
     * to an empty string on the unreachable keying error.
     */
    sign(issued_ms: bigint, body: Uint8Array): string;
    /**
     * Constant-time check that `candidate_hex` is the correct probe for `nonce`.
     * A missing, malformed, or wrong probe fails closed to `false`.
     */
    verify_probe(nonce: string, candidate_hex: string): boolean;
}

/**
 * Passive-signals verdict for one request, computed exactly as the native
 * server ([`fp_core::signals::compute`]) does — so the edge Worker reaches the
 * SAME UA↔TLS / IP-risk verdict.
 *
 * Needs no secrets (unlike [`FpEngine`]), so it is a free `#[wasm_bindgen]`
 * function. Constructs the dependency-free [`StaticIpIntel`] classifier, cross-
 * checks the trusted JA4 stack against the claimed UA, and returns JSON:
 * `{"ua_tls_consistent": <bool>, "ip_risk": "<low|medium|high>",
 * "confidence_adjustment": <f64>}`. A missing/unparseable JA4 auto-degrades
 * (neutral); a missing/unparseable IP defaults to `"low"` (§4.2).
 *
 * The owned `Option<String>` parameters are the wasm-bindgen boundary shape (JS
 * strings arrive owned); the body only borrows them, hence the local allow.
 */
export function passive_signals(ja4?: string | null, client_ip?: string | null, claimed_ua?: string | null): string;

/**
 * Compute the probe for `nonce` using the embedded [`PROBE_KEY`].
 *
 * This is the WASM export a browser collector calls: it returns the hex probe
 * echoed on `POST /identify`. Fails closed to an empty string on the
 * unreachable keying error rather than panicking.
 */
export function probe(nonce: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_fpengine_free: (a: number, b: number) => void;
    readonly fpengine_blocking_keys: (a: number, b: number, c: number) => [number, number, number, number];
    readonly fpengine_expected_probe: (a: number, b: number, c: number) => [number, number];
    readonly fpengine_new: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly fpengine_score: (a: number, b: number, c: number) => [number, number, number, number];
    readonly fpengine_sign: (a: number, b: bigint, c: number, d: number) => [number, number];
    readonly fpengine_verify_probe: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly passive_signals: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly probe: (a: number, b: number) => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
