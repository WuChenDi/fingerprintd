import { defineConfig } from 'tsup'

// ESM library build with a bundled `.d.ts`. Browser SDK — no Node shims.
//
// The vendored wasm-bindgen glue loads the probe wasm via
// `new URL('fp_wasm_bg.wasm', import.meta.url)`, i.e. a sibling of the bundle at
// runtime. esbuild leaves that reference as-is, so we copy the `.wasm` next to
// `dist/index.js` to keep the build self-contained (a real deployment rebuilds
// the wasm with its own probe key — see README).
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'es2022',
  platform: 'browser',
  onSuccess: 'cp wasm/fp_wasm_bg.wasm dist/fp_wasm_bg.wasm',
})
