// Two test projects run under one `vitest run`:
//   - vitest.config.ts         — Node: the state-free router contract over the
//                                vendored WASM bytes (no Workers runtime).
//   - vitest.workers.config.ts — workerd/miniflare: the PCF4 state layer (nonce
//                                Durable Object, D1 recall/persist) against the
//                                real runtime with live bindings.
export default ['./vitest.config.ts', './vitest.workers.config.ts']
