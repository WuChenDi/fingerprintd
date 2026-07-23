//! Per-component agreement counts — the material for estimating `m_i` (fuzzy-matching §9/§11).
//!
//! `m_i = P(agree | same device)` is a component's reliability: a value that
//! agrees whenever two probes are the same device (a stable component) carries
//! strong evidence when it agrees, a flaky one carries little. The estimate is
//! the component's observed agreement rate across confirmed same-device pairs.

use std::{
    collections::HashMap,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

/// Storage contract for the per-component agreement material behind `m_i`
/// estimation (fuzzy-matching §9/§11).
///
/// The in-memory [`AgreementTable`] is the single-instance implementation. An
/// externalized backend (a shared counter store, a later step) lives behind the
/// same contract, so the engine records agreement outcomes and reads counts
/// without knowing where the material is kept. Only the raw counting surface is
/// exposed here; the smoothed `m_i` estimate lives in the scorer.
pub trait AgreementStore: Send + Sync {
    /// Record one same-device comparison of the component `name`: whether the
    /// two stored values `agreed`.
    fn record(&self, name: &str, agreed: bool);

    /// Agreement counts recorded for `name`, as `(agree, total)`.
    fn stats(&self, name: &str) -> (u64, u64);
}

/// `component name → (agree, total)` for `m_i` estimation (fuzzy-matching §9).
///
/// Updated incrementally as confirmed same-device pairs are compared. Each key
/// maps a component name to how often its stored value agreed and how often it
/// was compared; the ratio is the agreement rate `m_i` is estimated from.
///
/// Growth is bounded, fail-safe: an optional cap on the number of *distinct*
/// tracked components drops a never-before-seen name once the cap is reached
/// (already-tracked names keep counting), so the table cannot grow without
/// limit. The default cap is generous, so a small workload is unaffected; every
/// drop is counted via [`AgreementTable::dropped`], never silent.
#[derive(Debug, Default)]
pub struct AgreementTable {
    stats: Mutex<HashMap<String, (u64, u64)>>,
    /// Cap on distinct tracked components; `None` is unbounded.
    max_components: Option<usize>,
    /// Count of new components dropped at the distinct-key cap (not silent).
    dropped: AtomicU64,
}

impl AgreementTable {
    /// Create an empty, unbounded table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty table bounded by a cap on distinct tracked components.
    ///
    /// `max_components` caps how many *distinct* component names the table
    /// tracks; a new name beyond the cap is dropped and counted. `None` is
    /// unbounded.
    pub fn with_capacity(max_components: Option<usize>) -> Self {
        Self {
            stats: Mutex::new(HashMap::new()),
            max_components,
            dropped: AtomicU64::new(0),
        }
    }

    /// Record one same-device comparison of the component `name`.
    ///
    /// An already-tracked name always increments `total` (and `agree` iff
    /// `agreed`). A never-before-seen name is tracked unless the distinct-key
    /// cap is reached, in which case it is dropped (not inserted, not counted)
    /// and tallied in [`AgreementTable::dropped`].
    pub fn record(&self, name: &str, agreed: bool) {
        let mut stats = self.lock();
        if let Some(entry) = stats.get_mut(name) {
            entry.1 += 1;
            if agreed {
                entry.0 += 1;
            }
            return;
        }
        if let Some(cap) = self.max_components
            && stats.len() >= cap
        {
            drop(stats);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        stats.insert(name.to_owned(), (u64::from(agreed), 1));
    }

    /// Total new components dropped at the distinct-key cap so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Agreement counts recorded for `name`, as `(agree, total)`; `(0, 0)` if
    /// the name was never tracked.
    pub fn stats(&self, name: &str) -> (u64, u64) {
        self.lock().get(name).copied().unwrap_or((0, 0))
    }

    /// Lock the counter, recovering the guard if a prior holder panicked.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (u64, u64)>> {
        self.stats.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl AgreementStore for AgreementTable {
    fn record(&self, name: &str, agreed: bool) {
        AgreementTable::record(self, name, agreed);
    }

    fn stats(&self, name: &str) -> (u64, u64) {
        AgreementTable::stats(self, name)
    }
}

#[cfg(test)]
mod tests {
    use super::AgreementTable;

    #[test]
    fn record_tracks_agree_and_total() {
        let table = AgreementTable::new();
        table.record("webgl", true);
        table.record("webgl", true);
        table.record("webgl", false);

        assert_eq!(table.stats("webgl"), (2, 3));
    }

    #[test]
    fn unseen_name_returns_zero() {
        let table = AgreementTable::new();
        assert_eq!(table.stats("nope"), (0, 0));
    }

    #[test]
    fn distinct_key_cap_drops_overflow_but_keeps_counting_tracked() {
        // Cap of 2 distinct components. Record two names (fills the cap), then a
        // third distinct name that overflows, and re-record a tracked one.
        let table = AgreementTable::with_capacity(Some(2));

        table.record("a", true);
        table.record("b", false);
        table.record("c", true); // over cap -> dropped
        table.record("c", true); // still a new name -> dropped again
        table.record("a", false); // already tracked -> counts

        assert_eq!(table.stats("a"), (1, 2));
        assert_eq!(table.stats("b"), (0, 1));
        assert_eq!(table.stats("c"), (0, 0)); // never tracked
        assert_eq!(table.dropped(), 2);
    }
}
