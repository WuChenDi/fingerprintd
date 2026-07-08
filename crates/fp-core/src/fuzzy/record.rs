//! The fingerprint library: `visitorId → template` records (design §3/§11).
//!
//! Each visitor keeps the most recent stored value per component (the template
//! that drift updates in design §7 will refresh), a per-component freshness
//! timestamp, `first_seen` / `last_seen`, and an `observation_count`. Timestamps
//! are supplied by the caller (Unix milliseconds) so the store stays clock-free
//! and deterministic under test.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use super::component::Stored;

/// A stored fingerprint template for one visitor (design §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintRecord {
    /// Most recent stored value per component name.
    pub components: BTreeMap<String, Stored>,
    /// Last-updated timestamp (Unix ms) per component — freshness for drift (§7).
    pub freshness: BTreeMap<String, u64>,
    /// When the visitor was first recorded (Unix ms).
    pub first_seen: u64,
    /// When the visitor was most recently observed (Unix ms).
    pub last_seen: u64,
    /// Number of observations folded into this record.
    pub observation_count: u64,
}

/// Storage contract for the `visitorId → template` fingerprint library
/// (design §3/§11).
///
/// The in-memory [`RecordStore`] is the single-instance implementation. An
/// externalized backend (a Cloudflare D1 template table, a later step) lives
/// behind the same contract, so the engine folds observations and reads
/// templates without knowing where the library is stored.
pub trait FingerprintStore: Send + Sync {
    /// Fold an observation into `visitor`'s record, creating it if new. Returns
    /// `true` when the visitor was newly recorded.
    fn observe(&self, visitor: &str, components: BTreeMap<String, Stored>, now_ms: u64) -> bool;

    /// Snapshot of `visitor`'s template, if present.
    fn get(&self, visitor: &str) -> Option<FingerprintRecord>;
}

/// In-memory `visitorId → record` fingerprint library (design §11).
///
/// Bounded, fail-safe growth: an optional record cap evicts the least-recently
/// seen (smallest `last_seen`) visitor once exceeded, and an optional TTL drops
/// entries not seen within the window on the next `observe`. Both bounds are
/// generous by default so a small workload behaves exactly as an unbounded
/// store; every eviction is counted via [`RecordStore::evicted`], never silent
/// (matching the blocking `dropped()` precedent, design §4).
#[derive(Debug, Default)]
pub struct RecordStore {
    /// `visitorId → template`.
    records: Mutex<HashMap<String, FingerprintRecord>>,
    /// Retain at most this many visitors; `None` is unbounded.
    max_records: Option<usize>,
    /// Drop entries whose `now_ms - last_seen` exceeds this on observe; `None`
    /// is unbounded.
    record_ttl_ms: Option<u64>,
    /// Count of records evicted by cap or TTL (observability, not silent).
    evicted: AtomicU64,
}

impl RecordStore {
    /// Create an empty, unbounded store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty store bounded by an optional record cap and TTL.
    ///
    /// `max_records` caps the number of retained visitors (evicting the oldest
    /// `last_seen` when exceeded); `record_ttl_ms` drops entries not seen within
    /// the window on the next `observe`. `None` for either means unbounded.
    pub fn with_capacity(max_records: Option<usize>, record_ttl_ms: Option<u64>) -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            max_records,
            record_ttl_ms,
            evicted: AtomicU64::new(0),
        }
    }

    /// Fold an observation into `visitor`'s record, creating it if new.
    ///
    /// The supplied `components` overwrite the visitor's recent values and bump
    /// their freshness to `now_ms`; `last_seen` and `observation_count` advance.
    /// Components not present in this observation retain their prior value and
    /// freshness. Returns `true` when the visitor was newly created.
    pub fn observe(
        &self,
        visitor: &str,
        components: BTreeMap<String, Stored>,
        now_ms: u64,
    ) -> bool {
        let mut records = self.lock();
        let is_new = if let Some(record) = records.get_mut(visitor) {
            for (name, value) in components {
                record.freshness.insert(name.clone(), now_ms);
                record.components.insert(name, value);
            }
            record.last_seen = now_ms;
            record.observation_count += 1;
            false
        } else {
            let freshness = components.keys().map(|k| (k.clone(), now_ms)).collect();
            records.insert(
                visitor.to_string(),
                FingerprintRecord {
                    components,
                    freshness,
                    first_seen: now_ms,
                    last_seen: now_ms,
                    observation_count: 1,
                },
            );
            true
        };
        self.evict(&mut records, visitor, now_ms);
        is_new
    }

    /// Enforce the TTL then the record cap, counting every eviction.
    ///
    /// Runs after each upsert under the same lock: TTL drops entries not seen
    /// within `record_ttl_ms` (the just-observed `visitor` has `last_seen ==
    /// now_ms`, so it is never dropped); the cap then evicts the smallest
    /// `last_seen` (oldest) entries until within `max_records`.
    fn evict(&self, records: &mut HashMap<String, FingerprintRecord>, visitor: &str, now_ms: u64) {
        let mut evicted = 0u64;
        if let Some(ttl) = self.record_ttl_ms {
            let stale: Vec<String> = records
                .iter()
                .filter(|(_, r)| now_ms.saturating_sub(r.last_seen) > ttl)
                .map(|(id, _)| id.clone())
                .collect();
            for id in stale {
                records.remove(&id);
                evicted += 1;
            }
        }
        if let Some(cap) = self.max_records {
            while records.len() > cap {
                // Evict the oldest (smallest `last_seen`); never the entry just
                // observed, which carries the largest `last_seen` of `now_ms`.
                let Some(oldest) = records
                    .iter()
                    .filter(|(id, _)| id.as_str() != visitor)
                    .min_by_key(|(_, r)| r.last_seen)
                    .map(|(id, _)| id.clone())
                else {
                    break;
                };
                records.remove(&oldest);
                evicted += 1;
            }
        }
        if evicted > 0 {
            self.evicted.fetch_add(evicted, Ordering::Relaxed);
        }
    }

    /// Total records evicted by cap or TTL so far.
    pub fn evicted(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }

    /// Snapshot of `visitor`'s record, if present.
    pub fn get(&self, visitor: &str) -> Option<FingerprintRecord> {
        self.lock().get(visitor).cloned()
    }

    /// Number of distinct visitors recorded.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the library holds no visitors.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Lock the record map, recovering the guard if a prior holder panicked.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, FingerprintRecord>> {
        self.records.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl FingerprintStore for RecordStore {
    fn observe(&self, visitor: &str, components: BTreeMap<String, Stored>, now_ms: u64) -> bool {
        RecordStore::observe(self, visitor, components, now_ms)
    }

    fn get(&self, visitor: &str) -> Option<FingerprintRecord> {
        RecordStore::get(self, visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::RecordStore;
    use crate::fuzzy::component::{Salt, Stored};
    use std::collections::BTreeMap;

    fn category(salt: &Salt, name: &str, value: &str) -> BTreeMap<String, Stored> {
        let mut map = BTreeMap::new();
        map.insert(name.to_string(), Stored::Category(salt.hash(value)));
        map
    }

    #[test]
    fn first_observation_creates_record() {
        let salt = Salt::random();
        let store = RecordStore::new();
        let is_new = store.observe("v1", category(&salt, "ua", "Chrome/120"), 1_000);
        assert!(is_new);

        let record = store.get("v1").unwrap();
        assert_eq!(record.first_seen, 1_000);
        assert_eq!(record.last_seen, 1_000);
        assert_eq!(record.observation_count, 1);
        assert_eq!(record.freshness.get("ua"), Some(&1_000));
    }

    #[test]
    fn revisit_updates_recent_value_and_advances_counters() {
        let salt = Salt::random();
        let store = RecordStore::new();
        store.observe("v1", category(&salt, "ua", "Chrome/120"), 1_000);
        let is_new = store.observe("v1", category(&salt, "ua", "Chrome/121"), 2_000);
        assert!(!is_new);

        let record = store.get("v1").unwrap();
        assert_eq!(record.first_seen, 1_000); // unchanged
        assert_eq!(record.last_seen, 2_000); // advanced
        assert_eq!(record.observation_count, 2);
        // Recent value drifted to the new UA; freshness advanced.
        assert_eq!(
            record.components.get("ua"),
            Some(&Stored::Category(salt.hash("Chrome/121")))
        );
        assert_eq!(record.freshness.get("ua"), Some(&2_000));
    }

    #[test]
    fn absent_components_retain_prior_freshness() {
        let salt = Salt::random();
        let store = RecordStore::new();
        let mut both = category(&salt, "ua", "Chrome/120");
        both.insert("tz".to_string(), Stored::Category(salt.hash("UTC")));
        store.observe("v1", both, 1_000);

        // Second observation carries only `ua`; `tz` must keep its old freshness.
        store.observe("v1", category(&salt, "ua", "Chrome/121"), 2_000);
        let record = store.get("v1").unwrap();
        assert_eq!(record.freshness.get("ua"), Some(&2_000));
        assert_eq!(record.freshness.get("tz"), Some(&1_000));
    }

    #[test]
    fn cap_evicts_oldest_and_counts() {
        let salt = Salt::random();
        // Cap of 3; observe 5 distinct visitors with strictly increasing
        // `last_seen`, so v1/v2 (oldest) are evicted and v3/v4/v5 survive.
        let store = RecordStore::with_capacity(Some(3), None);
        for i in 1..=5u64 {
            store.observe(&format!("v{i}"), category(&salt, "ua", "x"), i * 1_000);
        }
        assert_eq!(store.len(), 3);
        assert_eq!(store.evicted(), 2);
        assert!(store.get("v1").is_none());
        assert!(store.get("v2").is_none());
        assert!(store.get("v3").is_some());
        assert!(store.get("v4").is_some());
        assert!(store.get("v5").is_some());
    }

    #[test]
    fn ttl_drops_stale_entry_on_later_observe() {
        let salt = Salt::random();
        // TTL of 1_000 ms, no cap. v1 seen at t=1_000; a later observe at
        // t=3_000 (age 2_000 > 1_000) evicts it while recording v2.
        let store = RecordStore::with_capacity(None, Some(1_000));
        store.observe("v1", category(&salt, "ua", "x"), 1_000);
        assert_eq!(store.len(), 1);
        store.observe("v2", category(&salt, "ua", "y"), 3_000);
        assert!(store.get("v1").is_none());
        assert!(store.get("v2").is_some());
        assert_eq!(store.evicted(), 1);
    }

    #[test]
    fn distinct_visitors_are_separate() {
        let salt = Salt::random();
        let store = RecordStore::new();
        store.observe("v1", category(&salt, "ua", "x"), 1);
        store.observe("v2", category(&salt, "ua", "y"), 1);
        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
    }
}
