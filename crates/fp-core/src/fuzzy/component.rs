//! Compliance-preserving stored representations of fingerprint components
//! (design §3) and the cold-start stability priors (design §2/§9).
//!
//! Per PRD §7 data minimization, raw values are never retained: category and
//! set values are salted-hashed before storage while still supporting equality
//! comparison, frequency counting, and set similarity.

use std::collections::BTreeSet;

use rand::{RngCore, rng};
use sha2::{Digest, Sha256};

/// A 256-bit salted digest — the on-store form of a scalar value or a set element.
pub type Hash32 = [u8; 32];

/// Per-instance secret prepended before hashing every stored value.
///
/// A random salt makes stored hashes non-reversible via precomputed tables
/// while still permitting equality comparison and frequency counting within one
/// instance (design §3). It is fixed for the store's lifetime, so a given value
/// hashes identically across observations.
#[derive(Clone)]
pub struct Salt([u8; 16]);

impl Salt {
    /// Generate a fresh random salt.
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Salted category hash `H(salt || value)`.
    pub fn hash(&self, value: &str) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        hasher.update(value.as_bytes());
        hasher.finalize().into()
    }

    /// Salted per-element hashes of a set component.
    ///
    /// Hashing each element independently preserves the set structure — and
    /// therefore `Jaccard` similarity — while storing no raw element (design §3).
    pub fn hash_set<I, S>(&self, elements: I) -> BTreeSet<Hash32>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        elements
            .into_iter()
            .map(|e| self.hash(e.as_ref()))
            .collect()
    }
}

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the salt bytes.
        f.debug_struct("Salt").finish_non_exhaustive()
    }
}

/// The stored form of one fingerprint component (design §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    /// A category value, kept as its salted hash for equality + frequency use.
    Category(Hash32),
    /// A set component (e.g. fonts), kept as per-element salted hashes so that
    /// set similarity survives storage.
    Set(BTreeSet<Hash32>),
    /// A numeric component, kept as an (optionally bucketed) integer.
    Numeric(i64),
}

/// `Jaccard` similarity `|A ∩ B| / |A ∪ B|` between two stored hash sets.
///
/// Two empty sets are defined as identical (`1.0`). Because elements are hashed
/// independently, this equals the `Jaccard` similarity of the raw sets.
#[allow(clippy::cast_precision_loss)] // ratio of small counts; precision loss is immaterial
pub fn jaccard(a: &BTreeSet<Hash32>, b: &BTreeSet<Hash32>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.len() + b.len() - intersection;
    intersection as f64 / union as f64
}

/// Stability tier of a component — the source of its cold-start `m_i` prior
/// (design §2/§9). `m_i` is `P(agree | same device)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stability {
    /// Rarely changes for the same device (`WebGL`, audio, timezone, `CPU`).
    High,
    /// Changes occasionally (canvas, fonts, screen).
    Medium,
    /// Changes frequently — the avalanche source (`UA` / browser version).
    Low,
}

impl Stability {
    /// Cold-start prior for `m_i` (design §9): high `0.95`, medium `0.80`,
    /// low `0.50`. Refined post-launch via `EM` over high-confidence revisits.
    pub fn m_prior(self) -> f64 {
        match self {
            Stability::High => 0.95,
            Stability::Medium => 0.80,
            Stability::Low => 0.50,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Salt, Stability, jaccard};

    #[test]
    fn same_value_hashes_stably_under_one_salt() {
        let salt = Salt::random();
        assert_eq!(salt.hash("Chrome/120"), salt.hash("Chrome/120"));
        assert_ne!(salt.hash("Chrome/120"), salt.hash("Chrome/121"));
    }

    #[test]
    fn different_salts_diverge() {
        // Compliance: without the salt a value is not linkable across instances.
        assert_ne!(Salt::random().hash("UTC"), Salt::random().hash("UTC"));
    }

    #[test]
    fn per_element_hashing_preserves_jaccard() {
        let salt = Salt::random();
        let a = salt.hash_set(["Arial", "Helvetica", "Courier", "Times"]);
        // One font added, one removed: raw Jaccard = 3/5 = 0.6.
        let b = salt.hash_set(["Arial", "Helvetica", "Courier", "Verdana"]);
        assert!((jaccard(&a, &b) - 0.6).abs() < 1e-9);
        assert!((jaccard(&a, &a) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn empty_sets_are_identical() {
        let empty = Salt::random().hash_set(Vec::<String>::new());
        assert!((jaccard(&empty, &empty) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn priors_follow_stability_tier() {
        assert!(Stability::High.m_prior() > Stability::Medium.m_prior());
        assert!(Stability::Medium.m_prior() > Stability::Low.m_prior());
    }
}
