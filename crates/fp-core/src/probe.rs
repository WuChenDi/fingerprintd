//! Nonce probe verification — the freshness-proof depth layer (architecture §4.1 pt 3).
//!
//! `GET /challenge` advertises a deterministic transform of the one-time nonce
//! (HMAC-SHA256, hex-encoded). A probe-capable client recomputes the transform
//! with the pre-shared key baked into its collector and echoes the result on
//! `POST /identify`; the server independently recomputes the expected value and
//! rejects a request whose probe is missing or wrong (constant-time compare).
//!
//! This is **defense in depth, not the primary anti-replay lock** — the one-time
//! nonce ([`crate::nonce`]) remains the primary guarantee. The probe proves the
//! caller actually executed the advertised transform over *this* fresh nonce
//! with the shared key, raising the bar beyond blindly echoing a captured
//! payload. The key is secret (server config + client build): a caller that does
//! not hold it cannot forge a valid probe, even though the transform itself is
//! advertised.
//!
//! Enforcement is opt-in — it activates only when a probe key is configured
//! (`config.probe_key`). Until the probe-capable client ships (WASM collector,
//! deferred), a deployment leaves the key unset and behaviour is unchanged.

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Advertised transform algorithm (challenge `verify.alg`).
pub const PROBE_ALG: &str = "HMAC-SHA256";
/// Advertised transform input (challenge `verify.input`): the issued nonce.
pub const PROBE_INPUT: &str = "nonce";
/// Advertised output encoding (challenge `verify.encoding`).
pub const PROBE_ENCODING: &str = "hex";

/// Server-side probe verifier holding the pre-shared HMAC key.
///
/// Built from the configured `probe_key` when probe enforcement is enabled. The
/// key is never surfaced: [`fmt::Debug`] is redacted.
#[derive(Clone)]
pub struct ProbeVerifier {
    /// The pre-shared HMAC-SHA256 key.
    key: Vec<u8>,
}

impl ProbeVerifier {
    /// Build a verifier keyed by `key` (the configured shared secret).
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Compute the expected probe for `nonce`: `hex(HMAC-SHA256(key, nonce))`.
    ///
    /// This is the value a probe-capable client returns on `POST /identify`;
    /// exposed so the client — and tests — can derive it. HMAC accepts a key of
    /// any length, so keying is infallible in practice; `None` is returned only
    /// on the unreachable keying error rather than panicking (Lock 6).
    pub fn expected_hex(&self, nonce: &str) -> Option<String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).ok()?;
        mac.update(nonce.as_bytes());
        Some(hex::encode(mac.finalize().into_bytes()))
    }

    /// Verify a client-supplied `candidate_hex` against `hex(HMAC(key, nonce))`.
    ///
    /// Returns `true` only on an exact match. The comparison is constant-time
    /// ([`Mac::verify_slice`]); a malformed (non-hex), empty, or wrong candidate,
    /// or an unreachable keying error, all fail closed to `false`.
    pub fn verify(&self, nonce: &str, candidate_hex: &str) -> bool {
        let Ok(candidate) = hex::decode(candidate_hex) else {
            return false;
        };
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.key) else {
            return false;
        };
        mac.update(nonce.as_bytes());
        mac.verify_slice(&candidate).is_ok()
    }
}

impl fmt::Debug for ProbeVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose the key material.
        f.debug_struct("ProbeVerifier").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::ProbeVerifier;

    #[test]
    fn expected_round_trips_through_verify() {
        let verifier = ProbeVerifier::new(b"shared-secret");
        let tag = verifier.expected_hex("nonce-abc").unwrap();
        assert!(verifier.verify("nonce-abc", &tag));
    }

    #[test]
    fn expected_is_deterministic() {
        let verifier = ProbeVerifier::new(b"shared-secret");
        assert_eq!(
            verifier.expected_hex("nonce-abc").unwrap(),
            verifier.expected_hex("nonce-abc").unwrap()
        );
    }

    #[test]
    fn wrong_key_nonce_or_encoding_fails_closed() {
        let verifier = ProbeVerifier::new(b"shared-secret");
        let tag = verifier.expected_hex("nonce-abc").unwrap();

        // Same key, different nonce → no match (freshness bound to the nonce).
        assert!(!verifier.verify("nonce-xyz", &tag));
        // A caller without the shared key cannot forge the tag.
        assert!(!ProbeVerifier::new(b"other-secret").verify("nonce-abc", &tag));
        // Malformed / empty candidates fail closed rather than erroring.
        assert!(!verifier.verify("nonce-abc", "zz-not-hex"));
        assert!(!verifier.verify("nonce-abc", ""));
    }

    #[test]
    fn debug_redacts_key() {
        let shown = format!("{:?}", ProbeVerifier::new(b"top-secret-key"));
        assert!(!shown.contains("top-secret-key"));
        assert!(!shown.contains("116")); // no raw key bytes either
    }
}
