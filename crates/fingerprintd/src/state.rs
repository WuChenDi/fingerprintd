//! Shared, request-scoped application state.

use std::{fmt, sync::Arc};

use crate::{
    config::Config,
    fingerprint::FingerprintStore,
    nonce::{InMemoryNonceStore, NonceStore},
};

/// State shared by every handler, cloned per request (all fields are `Arc` or
/// `Copy`, so cloning is cheap).
#[derive(Clone)]
pub struct AppState {
    /// Backing store for one-time challenge nonces.
    pub nonce_store: Arc<dyn NonceStore>,
    /// Exact-match fingerprint store.
    pub fingerprints: Arc<FingerprintStore>,
    /// Nonce lifetime advertised to clients as `expires_in`.
    pub nonce_ttl_secs: u64,
}

impl AppState {
    /// Build state from configuration, using the in-memory P0 backends.
    pub fn from_config(config: &Config) -> Self {
        let ttl = std::time::Duration::from_secs(config.nonce_ttl_secs);
        Self {
            nonce_store: Arc::new(InMemoryNonceStore::new(ttl)),
            fingerprints: Arc::new(FingerprintStore::new()),
            nonce_ttl_secs: config.nonce_ttl_secs,
        }
    }
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `dyn NonceStore` is not `Debug`; expose only the plain field.
        f.debug_struct("AppState")
            .field("nonce_ttl_secs", &self.nonce_ttl_secs)
            .finish_non_exhaustive()
    }
}
