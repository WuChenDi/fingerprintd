//! Shared, request-scoped application state.

use std::{fmt, sync::Arc};

use crate::{
    config::Config,
    fuzzy::FuzzyStore,
    nonce::{InMemoryNonceStore, NonceStore},
    probe::ProbeVerifier,
    signing::ResponseSigner,
};

/// State shared by every handler, cloned per request (all fields are `Arc` or
/// `Copy`, so cloning is cheap).
#[derive(Clone)]
pub struct AppState {
    /// Backing store for one-time challenge nonces.
    pub nonce_store: Arc<dyn NonceStore>,
    /// Weighted fuzzy matching engine and its fingerprint library.
    pub matcher: Arc<FuzzyStore>,
    /// Nonce lifetime advertised to clients as `expires_in`.
    pub nonce_ttl_secs: u64,
    /// Whether edge-injected passive-signal headers are trusted (PRD §4.2). When
    /// `false`, `/identify` ignores client-supplied `CF-Connecting-IP` /
    /// `cf-bot-management-ja4` copies (fail-closed).
    pub trust_edge_headers: bool,
    /// Nonce-probe verifier (T8). `Some` only when a `probe_key` is configured;
    /// then `/challenge` advertises the transform and `/identify` requires a
    /// correct probe. `None` disables probe enforcement (default).
    pub probe: Option<Arc<ProbeVerifier>>,
    /// Response signer (T9). `Some` only when a `response_signing_key` is
    /// configured; then each `/identify` success carries `x-fp-timestamp` and
    /// `x-fp-signature` headers. `None` disables signing (default).
    pub signer: Option<Arc<ResponseSigner>>,
    /// Whether to enforce the request timestamp window on `/identify` (T9). When
    /// `false`, `ts` is ignored (default).
    pub enforce_ts_window: bool,
    /// Allowed clock skew, in milliseconds, for the request timestamp window when
    /// `enforce_ts_window` is on (T9). Derived from `config.ts_skew_secs`.
    pub ts_skew_ms: u64,
}

impl AppState {
    /// Build state from configuration, using the in-memory backends.
    pub fn from_config(config: &Config) -> Self {
        let ttl = std::time::Duration::from_secs(config.nonce_ttl_secs);
        let probe = config
            .probe_key
            .as_ref()
            .filter(|key| key.is_configured())
            .map(|key| Arc::new(ProbeVerifier::new(key.as_bytes())));
        let signer = config
            .response_signing_key
            .as_ref()
            .filter(|key| key.is_configured())
            .map(|key| Arc::new(ResponseSigner::new(key.as_bytes())));
        Self {
            nonce_store: Arc::new(InMemoryNonceStore::new(ttl)),
            matcher: Arc::new(FuzzyStore::new()),
            nonce_ttl_secs: config.nonce_ttl_secs,
            trust_edge_headers: config.trust_edge_headers,
            probe,
            signer,
            enforce_ts_window: config.enforce_ts_window,
            ts_skew_ms: config.ts_skew_secs.saturating_mul(1000),
        }
    }
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `dyn NonceStore` is not `Debug`; expose only the plain field.
        f.debug_struct("AppState")
            .field("nonce_ttl_secs", &self.nonce_ttl_secs)
            .field("trust_edge_headers", &self.trust_edge_headers)
            .field("probe_enabled", &self.probe.is_some())
            .field("signing_enabled", &self.signer.is_some())
            .field("enforce_ts_window", &self.enforce_ts_window)
            .field("ts_skew_ms", &self.ts_skew_ms)
            .finish_non_exhaustive()
    }
}
