//! Exact-fallback device matching (P0).
//!
//! P0 performs **exact** matching only: the stable components are canonicalized
//! into a deterministic byte string and hashed into a stable `visitorId`. Two
//! requests with identical components therefore collapse to the same visitor.
//! Weighted/fuzzy matching (blocking key + scoring) is P1 and deliberately out
//! of scope here.

use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Outcome of an [`FingerprintStore::identify`] call.
#[derive(Debug, Clone)]
pub struct Identification {
    /// Stable identifier derived from the canonical stable components.
    pub visitor_id: String,
    /// `true` when this canonical fingerprint had not been seen before.
    pub is_new_device: bool,
    /// Number of times this visitor has been seen, including this call.
    pub seen_count: u64,
}

/// In-memory exact-match fingerprint store.
///
/// Keyed by the derived `visitorId`; the value tracks how many times the
/// fingerprint has been observed. First-/last-seen timestamps from the PRD data
/// model are deferred (not required for the P0 exact-match acceptance).
#[derive(Debug, Default)]
pub struct FingerprintStore {
    /// visitorId -> observation count.
    records: Mutex<HashMap<String, u64>>,
}

impl FingerprintStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve `components` to a visitor, recording the observation.
    ///
    /// Returns the existing visitor with `is_new_device = false` when the
    /// canonical fingerprint has been seen before, otherwise inserts a new
    /// record with `is_new_device = true`.
    pub fn identify(&self, components: &Value) -> Identification {
        let visitor_id = derive_visitor_id(components);
        let mut records = self.records.lock().unwrap_or_else(PoisonError::into_inner);

        let count = records.entry(visitor_id.clone()).or_insert(0);
        let is_new_device = *count == 0;
        *count += 1;

        Identification {
            visitor_id,
            is_new_device,
            seen_count: *count,
        }
    }
}

/// Derive a deterministic `visitorId` from stable components.
///
/// The components are re-serialized with `serde_json`, whose object maps are
/// key-sorted by default (the `preserve_order` feature is off), giving a
/// canonical form independent of the client's key ordering. The canonical bytes
/// are then SHA-256 hashed and hex-encoded.
fn derive_visitor_id(components: &Value) -> String {
    let canonical = serde_json::to_vec(components).unwrap_or_default();
    hex::encode(Sha256::digest(&canonical))
}

#[cfg(test)]
mod tests {
    use super::FingerprintStore;
    use serde_json::json;

    #[test]
    fn identical_components_map_to_same_visitor() {
        let store = FingerprintStore::new();
        let a = store.identify(&json!({"ua": "x", "tz": "UTC"}));
        let b = store.identify(&json!({"ua": "x", "tz": "UTC"}));

        assert!(a.is_new_device);
        assert!(!b.is_new_device);
        assert_eq!(a.visitor_id, b.visitor_id);
        assert_eq!(b.seen_count, 2);
    }

    #[test]
    fn key_order_does_not_affect_visitor_id() {
        let store = FingerprintStore::new();
        let a = store.identify(&json!({"ua": "x", "tz": "UTC"}));
        let b = store.identify(&json!({"tz": "UTC", "ua": "x"}));
        assert_eq!(a.visitor_id, b.visitor_id);
        assert!(!b.is_new_device);
    }

    #[test]
    fn different_components_map_to_different_visitors() {
        let store = FingerprintStore::new();
        let a = store.identify(&json!({"ua": "x"}));
        let b = store.identify(&json!({"ua": "y"}));
        assert_ne!(a.visitor_id, b.visitor_id);
        assert!(a.is_new_device);
        assert!(b.is_new_device);
    }
}
