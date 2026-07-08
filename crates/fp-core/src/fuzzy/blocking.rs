//! Stage-one candidate generation: a `key → set<visitorId>` inverted index
//! (fuzzy-matching §4/§11).
//!
//! Recall is prioritized over precision: several independent blocking keys are
//! queried and their hits unioned, so a single changed component does not drop
//! the true match. Popular configurations (e.g. stock iPhone Safari) inflate a
//! block; over-capacity blocks carry little information and — per the architecture's
//! no-silent-truncation rule — dropped members are logged, never hidden.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

/// A blocking key: a 256-bit digest of a stable-component subset (fuzzy-matching §4).
pub type BlockingKey = [u8; 32];

/// Default per-block size cap. Blocks larger than this are low-information and
/// left to stage-two scoring to disambiguate (fuzzy-matching §4).
pub const DEFAULT_MAX_BLOCK: usize = 1024;

/// Storage contract for stage-one candidate recall: the `key → set<visitorId>`
/// inverted index (fuzzy-matching §4/§11).
///
/// The in-memory [`BlockingIndex`] is the single-instance implementation. An
/// externalized backend (a Cloudflare D1 table of `(key, visitorId)` rows, a
/// later step) lives behind the same contract, so the engine recalls candidates
/// without knowing where the index is stored.
pub trait CandidateSource: Send + Sync {
    /// Index `visitor` under `key`.
    fn insert(&self, key: BlockingKey, visitor: &str);

    /// Union of visitors across every supplied `key` — the candidate set (§4).
    fn candidates(&self, keys: &[BlockingKey]) -> HashSet<String>;

    /// Over-capacity insertions dropped so far (observability, not silent).
    ///
    /// Defaults to `0` for backends that never drop (e.g. an unbounded external
    /// index); the in-memory [`BlockingIndex`] overrides it with its real count.
    fn dropped(&self) -> u64 {
        0
    }

    /// Purge `visitor` from every block (GDPR right-to-be-forgotten).
    ///
    /// Defaults to a no-op for backends that erase out of band (e.g. an external
    /// index deleted by row); the in-memory [`BlockingIndex`] overrides it.
    fn remove_visitor(&self, _visitor: &str) {}
}

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

    /// Union of visitors across every supplied `key` — the candidate set (fuzzy-matching §4).
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

    /// Remove `visitor` from every block, dropping any block left empty (GDPR
    /// right-to-be-forgotten). Idempotent: a visitor not present is a no-op.
    pub fn remove_visitor(&self, visitor: &str) {
        let mut index = self.lock();
        index.retain(|_, block| {
            block.remove(visitor);
            !block.is_empty()
        });
    }

    /// Lock the index, recovering the guard if a prior holder panicked.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<BlockingKey, HashSet<String>>> {
        self.index.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl CandidateSource for BlockingIndex {
    fn insert(&self, key: BlockingKey, visitor: &str) {
        BlockingIndex::insert(self, key, visitor);
    }

    fn candidates(&self, keys: &[BlockingKey]) -> HashSet<String> {
        BlockingIndex::candidates(self, keys)
    }

    fn dropped(&self) -> u64 {
        BlockingIndex::dropped(self)
    }

    fn remove_visitor(&self, visitor: &str) {
        BlockingIndex::remove_visitor(self, visitor);
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
    fn remove_visitor_purges_from_every_block_and_drops_empties() {
        let index = BlockingIndex::new();
        index.insert(key(1), "alice");
        index.insert(key(1), "bob");
        index.insert(key(2), "alice");

        index.remove_visitor("alice");

        // alice is gone from both blocks; bob (sharing key(1)) is retained.
        let recalled = index.candidates(&[key(1), key(2)]);
        assert!(!recalled.contains("alice"));
        assert!(recalled.contains("bob"));
        // key(2) held only alice, so the now-empty block is dropped.
        assert!(index.candidates(&[key(2)]).is_empty());
        // Idempotent: removing an absent visitor is a no-op.
        index.remove_visitor("alice");
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
