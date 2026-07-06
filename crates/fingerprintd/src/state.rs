//! Shared, request-scoped application state.

use std::{fmt, sync::Arc};

use crate::{
    config::Config,
    fuzzy::FuzzyStore,
    nonce::{InMemoryNonceStore, NonceStore},
    probe::ProbeVerifier,
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
        Self {
            nonce_store: Arc::new(InMemoryNonceStore::new(ttl)),
            matcher: Arc::new(FuzzyStore::new()),
            nonce_ttl_secs: config.nonce_ttl_secs,
            trust_edge_headers: config.trust_edge_headers,
            probe,
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
            .finish_non_exhaustive()
    }
}
