//! `fp-wasm` — the client-side nonce probe core, compiled to WebAssembly.
//!
//! A probe-capable browser collector calls [`probe`] with the one-time nonce
//! advertised by `GET /challenge` and echoes the result on `POST /identify`.
//! The transform is byte-for-byte identical to the server verifier
//! (`crates/fingerprintd/src/probe.rs`, `ProbeVerifier::expected_hex`):
//!
//! ```text
//! probe(nonce) = hex(HMAC-SHA256(key, nonce))
//! ```
//!
//! matching the advertised `PROBE_ALG = "HMAC-SHA256"`, `PROBE_INPUT = "nonce"`,
//! `PROBE_ENCODING = "hex"`. The parity proof is the native `#[cfg(test)]`
//! vector below — it reproduces the server's `expected_probe` output with the
//! shared test secret, so server/client agreement is verified without a browser.
//!
//! ## Embedded key — depth, not a hard lock
//!
//! The probe key is baked into this module at build time ([`PROBE_KEY`], overridable
//! via the `FP_PROBE_KEY` compile-time env var). Because it ships inside the
//! `.wasm` artifact, a determined attacker can extract it — this is **defense in
//! depth, not a decisive control** (PRD: "WASM 纵深防御，非决定性"). The one-time
//! nonce remains the primary anti-replay guarantee; the probe only raises the bar
//! against blind replay. In a real deployment the build injects the same secret
//! configured as the server's `probe_key`.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use wasm_bindgen::prelude::wasm_bindgen;

/// The probe HMAC key embedded at build time.
///
/// Defaults to a placeholder; a deployment build overrides it with the server's
/// `probe_key` via `FP_PROBE_KEY=<secret> wasm-pack build ...`. Extractable from
/// the shipped artifact — see the module docs on why this is depth, not a lock.
const PROBE_KEY: &str = match option_env!("FP_PROBE_KEY") {
    Some(key) => key,
    None => "fp-wasm-dev-probe-key",
};

/// Compute `hex(HMAC-SHA256(key, nonce))` — the injectable core.
///
/// Kept key-parametric so the native parity test can key it with the server's
/// shared secret. HMAC accepts a key of any length, so keying is infallible in
/// practice; `None` is returned only on the unreachable keying error rather than
/// panicking (Lock 6).
fn probe_with_key(key: &[u8], nonce: &str) -> Option<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(nonce.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Compute the probe for `nonce` using the embedded [`PROBE_KEY`].
///
/// This is the WASM export a browser collector calls: it returns the hex probe
/// echoed on `POST /identify`. Fails closed to an empty string on the
/// unreachable keying error rather than panicking.
#[wasm_bindgen]
pub fn probe(nonce: &str) -> String {
    probe_with_key(PROBE_KEY.as_bytes(), nonce).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{PROBE_KEY, probe, probe_with_key};

    /// Server-parity proof — reproduces `crates/fingerprintd` `expected_probe`
    /// keyed with the `test-probe-secret` shared secret over `fixed-nonce-000`.
    /// The expected hex is the shared vector in `tests/vectors/probe.json`.
    #[test]
    fn matches_server_probe_vector() {
        let got = probe_with_key(b"test-probe-secret", "fixed-nonce-000").unwrap();
        assert_eq!(
            got,
            "ad83144894f917b94072c2f7b3246af66d3bc5a450562ccf3671ed64d33137d0"
        );
    }

    /// The transform is deterministic and nonce-bound.
    #[test]
    fn is_deterministic_and_nonce_bound() {
        let a = probe_with_key(b"k", "nonce-1").unwrap();
        assert_eq!(a, probe_with_key(b"k", "nonce-1").unwrap());
        assert_ne!(a, probe_with_key(b"k", "nonce-2").unwrap());
    }

    /// The public export wraps the embedded key and yields non-empty hex.
    #[test]
    fn export_uses_embedded_key() {
        let via_export = probe("nonce-1");
        assert_eq!(
            via_export,
            probe_with_key(PROBE_KEY.as_bytes(), "nonce-1").unwrap()
        );
        assert_eq!(via_export.len(), 64); // hex of a 32-byte SHA-256 tag
    }
}
