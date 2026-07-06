//! Stage-one candidate generation: a `key → set<visitorId>` inverted index
//! (design §4/§11).
//!
//! Recall is prioritized over precision: several independent blocking keys are
//! queried and their hits unioned, so a single changed component does not drop
//! the true match. Popular configurations (e.g. stock iPhone Safari) inflate a
//! block; over-capacity blocks carry little information and — per the PRD's
//! no-silent-truncation rule — dropped members are logged, never hidden.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

/// A blocking key: a 256-bit digest of a stable-component subset (design §4).
pub type BlockingKey = [u8; 32];

/// Default per-block size cap. Blocks larger than this are low-information and
/// left to stage-two scoring to disambiguate (design §4).
pub const DEFAULT_MAX_BLOCK: usize = 1024;

/// Inverted index mapping each blocking key to the visitors that hash into it.
#[derive(Debug)]
pub struct BlockingIndex {
    /// Maximum visitors retained per block before over-capacity drops begin.
    max_block: usize,
    /// `blocking key → visitors`.
    index: Mutex<HashMap<BlockingKey, HashSet<String>>>,
    /// Count of over-capacity insertions dropped (observability, not silent).
    dropped: AtomicU64,
}

impl Default for BlockingIndex {
    fn default() -> Self {
        Self::with_max_block(DEFAULT_MAX_BLOCK)
    }
}

impl BlockingIndex {
    /// Create an index with the default block-size cap.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an index with an explicit block-size cap.
    pub fn with_max_block(max_block: usize) -> Self {
        Self {
            max_block,
            index: Mutex::new(HashMap::new()),
            dropped: AtomicU64::new(0),
        }
    }

    /// Add `visitor` under `key`.
    ///
    /// If the block is already at capacity and does not yet contain `visitor`,
    /// the insertion is dropped and counted (see [`BlockingIndex::dropped`]); a
    /// `warn` is emitted so over-capacity blocks are visible rather than silent.
    pub fn insert(&self, key: BlockingKey, visitor: &str) {
        let mut index = self.lock();
        let block = index.entry(key).or_default();
        if block.len() >= self.max_block && !block.contains(visitor) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                block_size = block.len(),
                max_block = self.max_block,
                "blocking block over capacity; dropped visitor (not silently truncated)",
            );
            return;
        }
        block.insert(visitor.to_string());
    }

    /// Union of visitors across every supplied `key` — the candidate set (design §4).
    pub fn candidates(&self, keys: &[BlockingKey]) -> HashSet<String> {
        let index = self.lock();
        let mut candidates = HashSet::new();
        for key in keys {
            if let Some(block) = index.get(key) {
                candidates.extend(block.iter().cloned());
            }
        }
        candidates
    }

    /// Total over-capacity insertions dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Lock the index, recovering the guard if a prior holder panicked.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<BlockingKey, HashSet<String>>> {
        self.index.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::BlockingIndex;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn candidates_union_across_keys() {
        let index = BlockingIndex::new();
        index.insert(key(1), "alice");
        index.insert(key(2), "bob");
        index.insert(key(2), "carol");

        // A probe touching both keys recalls every visitor behind either.
        let got = index.candidates(&[key(1), key(2)]);
        assert_eq!(got.len(), 3);
        assert!(got.contains("alice") && got.contains("bob") && got.contains("carol"));

        // A miss key contributes nothing.
        assert!(index.candidates(&[key(9)]).is_empty());
    }

    #[test]
    fn recall_survives_one_changed_key() {
        // alice indexed under two independent keys; if the K1 key changes, the
        // K2 key still recalls her.
        let index = BlockingIndex::new();
        index.insert(key(1), "alice");
        index.insert(key(2), "alice");

        let recalled = index.candidates(&[key(7), key(2)]);
        assert!(recalled.contains("alice"));
    }

    #[test]
    fn over_capacity_is_dropped_and_counted() {
        let index = BlockingIndex::with_max_block(2);
        index.insert(key(0), "a");
        index.insert(key(0), "b");
        index.insert(key(0), "c"); // over cap -> dropped

        let block = index.candidates(&[key(0)]);
        assert_eq!(block.len(), 2);
        assert!(!block.contains("c"));
        assert_eq!(index.dropped(), 1);
    }

    #[test]
    fn re_inserting_existing_member_at_capacity_is_not_dropped() {
        let index = BlockingIndex::with_max_block(2);
        index.insert(key(0), "a");
        index.insert(key(0), "b");
        index.insert(key(0), "a"); // already present -> idempotent, not a drop
        assert_eq!(index.dropped(), 0);
        assert_eq!(index.candidates(&[key(0)]).len(), 2);
    }
}
