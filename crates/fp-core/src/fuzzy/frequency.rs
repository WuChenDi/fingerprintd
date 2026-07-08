//! Per-value frequency counts — the material for estimating `u_i` (design §9/§11).
//!
//! `u_i = P(agree | different device)` is the rarity of a value: common values
//! (Chrome-on-Windows) carry little evidence when they agree, rare values carry
//! a lot. The estimate is the value's observed frequency across the library.

use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
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
#[derive(Debug, Default)]
pub struct FrequencyTable {
    counts: Mutex<Counts>,
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
    /// Create an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one sighting of `value`.
    pub fn record(&self, value: Hash32) {
        let mut counts = self.lock();
        *counts.per_value.entry(value).or_insert(0) += 1;
        counts.total += 1;
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
    fn cold_table_returns_zero() {
        let table = FrequencyTable::new();
        assert!(table.u_estimate(Salt::random().hash("x")).abs() < f64::EPSILON);
    }
}
