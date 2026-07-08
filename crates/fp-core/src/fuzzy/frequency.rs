//! Per-value frequency counts — the material for estimating `u_i` (design §9/§11).
//!
//! `u_i = P(agree | different device)` is the rarity of a value: common values
//! (Chrome-on-Windows) carry little evidence when they agree, rare values carry
//! a lot. The estimate is the value's observed frequency across the library.

use std::{
    collections::HashMap,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use super::component::Hash32;

/// Storage contract for the per-value frequency material behind `u_i` estimation
/// (design §9/§11).
///
/// The in-memory [`FrequencyTable`] is the single-instance implementation. An
/// externalized backend (a shared counter store, a later step) lives behind the
/// same contract, so the engine records sightings and reads counts without
/// knowing where the frequency material is kept. Only the raw counting surface
/// is exposed here; the smoothed `u_i` estimate lives in the scorer.
pub trait FrequencyStore: Send + Sync {
    /// Record one sighting of `value`.
    fn record(&self, value: Hash32);

    /// Sightings recorded for `value`.
    fn count(&self, value: Hash32) -> u64;

    /// Total scalar values recorded (the frequency denominator).
    fn total(&self) -> u64;
}

/// `value hash → count`, with a running total, for `u_i` estimation (design §9).
///
/// Updated incrementally as fingerprints are observed. The counter maps a
/// salted value hash to its number of sightings; `total` is the number of
/// scalar values recorded (the denominator of the frequency estimate).
///
/// Growth is bounded, fail-safe: an optional cap on the number of *distinct*
/// tracked values drops a never-before-seen value once the cap is reached
/// (already-tracked values keep counting), so the table cannot grow without
/// limit. The default cap is generous, so a small workload is unaffected; every
/// drop is counted via [`FrequencyTable::dropped`], never silent.
#[derive(Debug, Default)]
pub struct FrequencyTable {
    counts: Mutex<Counts>,
    /// Cap on distinct tracked values; `None` is unbounded.
    max_values: Option<usize>,
    /// Count of new values dropped at the distinct-value cap (not silent).
    dropped: AtomicU64,
}

/// Inner counter state guarded by the table's mutex.
#[derive(Debug, Default)]
struct Counts {
    /// Sightings per salted value hash.
    per_value: HashMap<Hash32, u64>,
    /// Total scalar values recorded across all keys.
    total: u64,
}

impl FrequencyTable {
    /// Create an empty, unbounded table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty table bounded by a cap on distinct tracked values.
    ///
    /// `max_frequency_values` caps how many *distinct* value hashes the table
    /// tracks; a new value beyond the cap is dropped and counted. `None` is
    /// unbounded.
    pub fn with_capacity(max_frequency_values: Option<usize>) -> Self {
        Self {
            counts: Mutex::new(Counts::default()),
            max_values: max_frequency_values,
            dropped: AtomicU64::new(0),
        }
    }

    /// Record one sighting of `value`.
    ///
    /// An already-tracked value always increments. A never-before-seen value is
    /// tracked unless the distinct-value cap is reached, in which case it is
    /// dropped (not inserted, not counted toward `total`) and tallied in
    /// [`FrequencyTable::dropped`].
    pub fn record(&self, value: Hash32) {
        let mut counts = self.lock();
        if let Some(existing) = counts.per_value.get_mut(&value) {
            *existing += 1;
            counts.total += 1;
            return;
        }
        if let Some(cap) = self.max_values
            && counts.per_value.len() >= cap
        {
            drop(counts);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        counts.per_value.insert(value, 1);
        counts.total += 1;
    }

    /// Total new values dropped at the distinct-value cap so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Sightings recorded for `value`.
    pub fn count(&self, value: Hash32) -> u64 {
        self.lock().per_value.get(&value).copied().unwrap_or(0)
    }

    /// Total scalar values recorded (the frequency denominator).
    pub fn total(&self) -> u64 {
        self.lock().total
    }

    /// Estimate `u_i` for `value` as its observed relative frequency.
    ///
    /// Returns `0.0` on an empty table (cold start) — no evidence yet.
    #[allow(clippy::cast_precision_loss)] // frequency ratio; precision loss is immaterial
    pub fn u_estimate(&self, value: Hash32) -> f64 {
        let counts = self.lock();
        if counts.total == 0 {
            return 0.0;
        }
        let hits = counts.per_value.get(&value).copied().unwrap_or(0);
        hits as f64 / counts.total as f64
    }

    /// Lock the counter, recovering the guard if a prior holder panicked.
    fn lock(&self) -> std::sync::MutexGuard<'_, Counts> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl FrequencyStore for FrequencyTable {
    fn record(&self, value: Hash32) {
        FrequencyTable::record(self, value);
    }

    fn count(&self, value: Hash32) -> u64 {
        FrequencyTable::count(self, value)
    }

    fn total(&self) -> u64 {
        FrequencyTable::total(self)
    }
}

#[cfg(test)]
mod tests {
    use super::FrequencyTable;
    use crate::fuzzy::component::Salt;

    #[test]
    fn counts_and_total_track_sightings() {
        let salt = Salt::random();
        let table = FrequencyTable::new();
        let common = salt.hash("Chrome/Windows");
        let rare = salt.hash("Lynx/Plan9");

        table.record(common);
        table.record(common);
        table.record(common);
        table.record(rare);

        assert_eq!(table.count(common), 3);
        assert_eq!(table.count(rare), 1);
        assert_eq!(table.total(), 4);
    }

    #[test]
    fn rare_values_have_lower_u_than_common() {
        let salt = Salt::random();
        let table = FrequencyTable::new();
        let common = salt.hash("common");
        let rare = salt.hash("rare");
        for _ in 0..9 {
            table.record(common);
        }
        table.record(rare);

        assert!(table.u_estimate(rare) < table.u_estimate(common));
        assert!((table.u_estimate(rare) - 0.1).abs() < 1e-9);
    }

    #[test]
    fn distinct_value_cap_drops_overflow_but_keeps_counting_tracked() {
        let salt = Salt::random();
        // Cap of 2 distinct values. Record two values (fills the cap), then a
        // third distinct value that overflows, and re-record a tracked one.
        let table = FrequencyTable::with_capacity(Some(2));
        let a = salt.hash("a");
        let b = salt.hash("b");
        let c = salt.hash("c");

        table.record(a);
        table.record(b);
        table.record(c); // over cap -> dropped
        table.record(c); // still a new value -> dropped again
        table.record(a); // already tracked -> counts

        assert_eq!(table.count(a), 2);
        assert_eq!(table.count(b), 1);
        assert_eq!(table.count(c), 0); // never tracked
        assert_eq!(table.dropped(), 2);
        // Only the tracked sightings feed the denominator (3 = a×2 + b×1).
        assert_eq!(table.total(), 3);
    }

    #[test]
    fn cold_table_returns_zero() {
        let table = FrequencyTable::new();
        assert!(table.u_estimate(Salt::random().hash("x")).abs() < f64::EPSILON);
    }
}
