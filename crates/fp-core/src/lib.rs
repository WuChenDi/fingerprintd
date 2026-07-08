//! `fp-core` — the framework-free fingerprinting core.
//!
//! This crate holds the pure compute and the storage contracts shared by every
//! deployment target: the native Axum server (`crates/fingerprintd`) depends on
//! it directly, and the WebAssembly build (`crates/fp-wasm`, deferred to a later
//! step) exposes the same pure functions to a JavaScript host.
//!
//! The split is deliberate:
//! - **Pure compute** — blocking-key derivation, the Fellegi–Sunter scorer,
//!   confidence fusion, the probe HMAC ([`probe`]), the response-signing HMAC
//!   ([`signing`]), and the nonce transform ([`nonce`]). None of it touches an
//!   HTTP framework, an async runtime, or a socket, so it runs unchanged on a
//!   V8 isolate.
//! - **Storage traits** — [`nonce::NonceStore`], [`fuzzy::record::FingerprintStore`],
//!   and [`fuzzy::blocking::CandidateSource`] abstract the state the engine reads
//!   and writes. In-memory implementations live alongside each trait and back the
//!   single-instance server; an externalized backend (Cloudflare D1 / Durable
//!   Objects, a later step) slots in behind the same contracts.
//!
//! [`fuzzy::FuzzyStore`] ties the compute and the in-memory storage together
//! behind one observe/identify surface.

#![forbid(unsafe_code)]

pub mod fuzzy;
// The in-memory nonce store needs OS entropy and a wall clock
// (`std::time::Instant`), neither available on `wasm32-unknown-unknown`; on the
// edge the nonce lifecycle is a Durable Object, so the WASM build omits it.
#[cfg(feature = "rng")]
pub mod nonce;
pub mod probe;
pub mod signals;
pub mod signing;
