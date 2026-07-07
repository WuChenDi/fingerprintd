/**
 * Ambient declaration for `import`ed `.wasm` modules. In the Workers runtime
 * (and under `wrangler`'s esbuild bundler) a `.wasm` import resolves to a
 * compiled `WebAssembly.Module`; this teaches `tsc` that shape.
 */
declare module '*.wasm' {
  const module: WebAssembly.Module
  export default module
}
