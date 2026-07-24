/**
 * Fingerprint module barrel — the domain's public surface: the scoring engine,
 * the D1 candidate store, and the Hono sub-router. Consumers (the composition
 * root in `index.ts`, `app.ts`, tests) import from here rather than reaching into
 * the module's files.
 */

export { EdgeEngine, initEngineRuntime } from './engine'
export type { FingerprintDeps } from './fingerprint.routes'
export { fingerprintRoutes } from './fingerprint.routes'
export { D1FingerprintStore, DEFAULT_MAX_BLOCK } from './fingerprint-store-d1'
