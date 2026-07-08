//! Response signing — tamper-evident `/identify` responses (architecture §4.1, P3).
//!
//! When a signing key is configured (`config.response_signing_key`), each
//! successful `POST /identify` carries two headers:
//!
//! - `x-fp-timestamp` — the server's issue time in Unix milliseconds; and
//! - `x-fp-signature` — `hex(HMAC-SHA256(key, issued_ms.to_be_bytes() ++ body))`.
//!
//! A consumer holding the pre-shared key recomputes the tag over the received
//! timestamp (parsed to a `u64`, big-endian bytes) concatenated with the raw
//! response body and compares it constant-time; a mismatch means the response
//! was tampered with in transit or forged without the key. The signature is
//! carried in **headers**, so the JSON body shape is unchanged.
//!
//! Signing is opt-in — it activates only when a non-empty key is configured.
//! Until a signature-verifying client ships, a deployment leaves the key unset
//! and behaviour is unchanged (fail-open on an absent key, unlike the request
//! timestamp window which fails closed once enabled).

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Response header carrying the server's signing time (Unix milliseconds).
pub const SIGNATURE_TIMESTAMP_HEADER: &str = "x-fp-timestamp";
/// Response header carrying the hex HMAC-SHA256 signature of the response.
pub const SIGNATURE_HEADER: &str = "x-fp-signature";

/// Server-side response signer holding the pre-shared HMAC key.
///
/// Built from the configured `response_signing_key` when signing is enabled.
/// The key is never surfaced: [`fmt::Debug`] is redacted.
#[derive(Clone)]
pub struct ResponseSigner {
    /// The pre-shared HMAC-SHA256 key.
    key: Vec<u8>,
}

impl ResponseSigner {
    /// Build a signer keyed by `key` (the configured shared secret).
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Sign a response: `hex(HMAC-SHA256(key, issued_ms.to_be_bytes() ++ body))`.
    ///
    /// `issued_ms` is the server's issue time in Unix milliseconds (echoed in the
    /// `x-fp-timestamp` header); `body` is the exact serialized response bytes. A
    /// verifying client recomputes the same tag over the received timestamp and
    /// body. HMAC accepts a key of any length, so keying is infallible in
    /// practice; `None` is returned only on the unreachable keying error rather
    /// than panicking (Lock 6).
    pub fn sign(&self, issued_ms: u64, body: &[u8]) -> Option<String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).ok()?;
        mac.update(&issued_ms.to_be_bytes());
        mac.update(body);
        Some(hex::encode(mac.finalize().into_bytes()))
    }
}

impl fmt::Debug for ResponseSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose the key material.
        f.debug_struct("ResponseSigner").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::ResponseSigner;

    #[test]
    fn sign_is_deterministic() {
        let signer = ResponseSigner::new(b"signing-secret");
        let body = br#"{"visitorId":"abc"}"#;
        assert_eq!(
            signer.sign(1_700_000_000_000, body),
            signer.sign(1_700_000_000_000, body)
        );
    }

    #[test]
    fn signature_binds_timestamp_and_body() {
        let signer = ResponseSigner::new(b"signing-secret");
        let body = br#"{"visitorId":"abc"}"#;
        let sig = signer.sign(1_700_000_000_000, body).unwrap();

        // A different issue time yields a different tag (freshness is signed).
        assert_ne!(Some(&sig), signer.sign(1_700_000_000_001, body).as_ref());
        // A tampered body yields a different tag (integrity is signed).
        assert_ne!(
            Some(&sig),
            signer
                .sign(1_700_000_000_000, br#"{"visitorId":"xyz"}"#)
                .as_ref()
        );
        // A caller without the shared key cannot forge the tag.
        assert_ne!(
            Some(&sig),
            ResponseSigner::new(b"other-secret")
                .sign(1_700_000_000_000, body)
                .as_ref()
        );
    }

    #[test]
    fn debug_redacts_key() {
        let shown = format!("{:?}", ResponseSigner::new(b"top-secret-key"));
        assert!(!shown.contains("top-secret-key"));
        assert!(!shown.contains("116")); // no raw key bytes either
    }
}
