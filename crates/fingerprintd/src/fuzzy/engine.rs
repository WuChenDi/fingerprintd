//! Stage-two probabilistic scoring, decision, and drift (design §5/§6/§7/§8).
//!
//! Given a probe, [`FuzzyStore::identify`] performs the full two-stage match:
//! stage one recalls candidates from the blocking indexes (design §4, in
//! [`super`]), stage two scores each candidate with the Fellegi–Sunter model
//! (§5) and applies the double-threshold decision (§5.4), drift update (§7), and
//! confidence fusion (§6).
//!
//! The Fellegi–Sunter weights use two per-component parameters:
//! - `m_i = P(agree | same device)` — the cold-start stability prior (§2/§9),
//!   read from [`super::classify`].
//! - `u_i = P(agree | different device)` — the value's rarity, estimated from
//!   the frequency table (§9). Rare values that agree are strong evidence;
//!   common ones (Chrome-on-Windows) carry almost none.
//!
//! Thresholds and priors here are **cold-start defaults**; the design's offline
//! evaluation (§10) tunes them against a labelled set. They are deliberately
//! separated so the eval harness (T5) can grid-search without touching scoring.

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    FuzzyStore, classify,
    component::{Hash32, Stored, jaccard},
    record::FingerprintRecord,
};

/// Score at or above which the best candidate is accepted as the same device
/// (design §5.4 `T_hi`). Units are bits of summed log-likelihood ratio.
const T_HI: f64 = 12.0;
/// Score below which the best candidate is rejected as a different device; the
/// `[T_LO, T_HI)` band is the "suspected" review zone (design §5.4 `T_lo`).
const T_LO: f64 = 8.0;
/// Jaccard threshold above which a set component counts as a full agreement
/// (design §5.1 `τ`); below it the score interpolates by Jaccard (§5.3).
const TAU: f64 = 0.5;
/// Two candidates both `≥ T_hi` within this many bits are flagged as a
/// collision risk (design §5.4).
const COLLISION_GAP: f64 = 2.0;
/// Prior `u_i` for set components (fonts/plugins). The frequency table holds no
/// per-set material, so set rarity uses this distinctive-by-default constant.
const SET_U: f64 = 0.05;
/// Lower/upper clamps keeping `u_i` in `(0, 1)` so the log-ratios stay finite.
const U_FLOOR: f64 = 1e-4;
const U_CEIL: f64 = 0.9999;
/// Score scale (bits) over which confidence margins saturate (design §6).
const CONF_SCALE: f64 = 4.0;
/// Component count of a full rich fingerprint. Confidence scales the number of
/// components that actually took part in scoring against this, so a sparse probe
/// (many missing) is less certain (design §6/§8).
const FULL_COMPONENTS: f64 = 8.0;

/// The double-threshold verdict for a probe (design §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Best candidate scored `≥ T_hi` — accepted as the same device.
    Match,
    /// Best candidate scored in `[T_lo, T_hi)` — suspected; returned but the
    /// template is **not** updated (anti-poisoning, design §7).
    Review,
    /// No candidate cleared `T_lo` — a fresh `visitorId` is minted.
    NewDevice,
}

impl Decision {
    /// Stable wire label for the response body.
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Match => "match",
            Decision::Review => "review",
            Decision::NewDevice => "new_device",
        }
    }
}

/// Outcome of [`FuzzyStore::identify`].
#[derive(Debug, Clone)]
pub struct MatchOutcome {
    /// Resolved device identifier (existing on match/review, freshly minted new).
    pub visitor_id: String,
    /// `true` only when a new `visitorId` was minted.
    pub is_new_device: bool,
    /// Fused confidence in `[0, 1]` (design §6).
    pub confidence: f64,
    /// The verdict that produced this outcome (design §5.4).
    pub decision: Decision,
    /// Best candidate's score in bits, if any candidate was scored.
    pub score: Option<f64>,
    /// Number of components that actually participated in scoring (design §8).
    pub compared_components: usize,
    /// Whether a runner-up also cleared `T_hi` within [`COLLISION_GAP`].
    pub collision_risk: bool,
}

/// Per-candidate stage-two score and its comparison count.
struct Scored {
    score: f64,
    compared: usize,
}

impl FuzzyStore {
    /// Identify `components`, folding the observation in per the verdict.
    ///
    /// Two-stage (design §4/§5): recall candidates, score each with
    /// Fellegi–Sunter, then apply the double-threshold decision (§5.4). A match
    /// drifts the winning template (§7); a review returns the suspected visitor
    /// without updating it (anti-poisoning, §7); a new device is minted and
    /// stored. `now_ms` is Unix milliseconds for the stored timestamps.
    pub fn identify(&self, components: &Value, now_ms: u64) -> MatchOutcome {
        let probe = self.stored_map(components);

        // Stage one: recall, then score every candidate against the probe.
        let mut scored: Vec<(String, Scored)> = self
            .candidates(components)
            .into_iter()
            .map(|id| {
                let record = self.record(&id);
                let s = record.map_or(
                    Scored {
                        score: f64::NEG_INFINITY,
                        compared: 0,
                    },
                    |r| self.score_candidate(&probe, &r),
                );
                (id, s)
            })
            .collect();
        // Highest score first; a runner-up (if any) drives collision detection.
        scored.sort_by(|a, b| b.1.score.total_cmp(&a.1.score));

        let best = scored.first();
        let second_score = scored.get(1).map(|(_, s)| s.score);
        let best_score = best.map(|(_, s)| s.score);
        let compared = best.map_or(0, |(_, s)| s.compared);

        let decision = match best_score {
            Some(s) if s >= T_HI => Decision::Match,
            Some(s) if s >= T_LO => Decision::Review,
            _ => Decision::NewDevice,
        };

        let confidence = confidence(decision, best_score, second_score, compared);

        // `decision` is `Match`/`Review` only when `best` is `Some`, so the
        // matched arms always bind the winning candidate; the fallthrough covers
        // `NewDevice` (and the unreachable no-candidate case).
        match (decision, best) {
            (Decision::Match, Some((id, top))) => {
                let collision_risk =
                    second_score.is_some_and(|s2| s2 >= T_HI && (top.score - s2) < COLLISION_GAP);
                // High-confidence match: drift the template toward this observation (§7).
                self.observe(id, components, now_ms);
                MatchOutcome {
                    visitor_id: id.clone(),
                    is_new_device: false,
                    confidence,
                    decision,
                    score: best_score,
                    compared_components: compared,
                    collision_risk,
                }
            }
            (Decision::Review, Some((id, _))) => {
                // Suspected only: no template update, to resist poisoning (§7).
                MatchOutcome {
                    visitor_id: id.clone(),
                    is_new_device: false,
                    confidence,
                    decision,
                    score: best_score,
                    compared_components: compared,
                    collision_risk: false,
                }
            }
            _ => {
                let id = derive_visitor_id(components);
                self.observe(&id, components, now_ms);
                MatchOutcome {
                    visitor_id: id,
                    is_new_device: true,
                    confidence,
                    decision: Decision::NewDevice,
                    score: best_score,
                    compared_components: compared,
                    collision_risk: false,
                }
            }
        }
    }

    /// Fellegi–Sunter score of a candidate template against the probe (design §5).
    ///
    /// Sums the per-component log-likelihood weight over components present on
    /// both sides; components missing on either side are skipped, contributing
    /// zero (design §5.3/§8).
    fn score_candidate(&self, probe: &ProbeMap, template: &FingerprintRecord) -> Scored {
        let mut score = 0.0;
        let mut compared = 0;
        for (name, probe_value) in probe {
            let Some(template_value) = template.components.get(name) else {
                continue; // missing on the template side → not compared (§8)
            };
            let Some((sim, u)) = self.compare(probe_value, template_value) else {
                continue; // kind mismatch → not comparable
            };
            let m = classify(name).stability.m_prior();
            score += agreement_weight(m, u, sim);
            compared += 1;
        }
        Scored { score, compared }
    }

    /// Compare one component, returning its agreement fraction `sim ∈ [0, 1]`
    /// and its rarity `u_i` (design §5.1/§5.3). `None` if the two stored forms
    /// are of different kinds and cannot be compared.
    fn compare(&self, probe: &Stored, template: &Stored) -> Option<(f64, f64)> {
        match (probe, template) {
            (Stored::Category(a), Stored::Category(b)) => {
                let sim = f64::from(u8::from(a == b));
                Some((sim, self.u_estimate(*a)))
            }
            (Stored::Numeric(a), Stored::Numeric(b)) => {
                let sim = f64::from(u8::from(a == b));
                Some((sim, self.u_estimate(self.salt.hash(&a.to_string()))))
            }
            (Stored::Set(a), Stored::Set(b)) => {
                let j = jaccard(a, b);
                // `J ≥ τ` counts as full agreement; below it, interpolate by J (§5.3).
                let sim = if j >= TAU { 1.0 } else { j };
                Some((sim, SET_U))
            }
            _ => None,
        }
    }

    /// Estimate `u_i` for a value hash: its smoothed relative frequency across
    /// the library (design §9), clamped to keep the log-ratios finite.
    ///
    /// Add-`0.5` (Jeffreys) smoothing keeps a never-before-seen value from
    /// collapsing `u` to zero on a small library.
    #[allow(clippy::cast_precision_loss)] // frequency ratio; precision loss immaterial
    fn u_estimate(&self, value: Hash32) -> f64 {
        let hits = self.frequency.count(value) as f64;
        let total = self.frequency.total() as f64;
        ((hits + 0.5) / (total + 1.0)).clamp(U_FLOOR, U_CEIL)
    }
}

/// Alias to name the probe map inside method signatures without leaking the
/// `BTreeMap` spelling everywhere.
type ProbeMap = std::collections::BTreeMap<String, Stored>;

/// Per-component Fellegi–Sunter weight in bits (design §5.3).
///
/// `sim` blends the agree and disagree log-ratios: `1.0` is a full agreement
/// (`log2(m/u)`), `0.0` a full disagreement (`log2((1-m)/(1-u))`), and a set's
/// partial Jaccard interpolates between them.
fn agreement_weight(m: f64, u: f64, sim: f64) -> f64 {
    let agree = (m / u).log2();
    let disagree = ((1.0 - m) / (1.0 - u)).log2();
    sim * agree + (1.0 - sim) * disagree
}

/// Fuse the confidence in `[0, 1]` from the decision, score margins, and probe
/// completeness (design §6).
///
/// Three factors combine: how far the best score sits past its decision
/// boundary, its separation from the runner-up, and the fraction of the probe's
/// components that took part in scoring (a sparse probe is less certain, §8).
/// The passive JA4/UA consistency input (design §6) is a P2 signal, left
/// neutral here.
#[allow(clippy::cast_precision_loss)] // small component counts; precision loss immaterial
fn confidence(
    decision: Decision,
    best_score: Option<f64>,
    second_score: Option<f64>,
    compared: usize,
) -> f64 {
    // Completeness pulls a sparse decision (few components scored) toward
    // uncertainty (§6/§8): fewer participating components → lower confidence.
    let completeness = (compared as f64 / FULL_COMPONENTS).min(1.0);
    let completeness_scale = 0.5 + 0.5 * completeness;

    let base = match decision {
        Decision::Match => {
            let s = best_score.unwrap_or(T_HI);
            let margin = logistic((s - T_HI) / CONF_SCALE);
            let gap = second_score.map_or(1.0, |s2| logistic((s - s2) / CONF_SCALE));
            0.5 + 0.5 * margin.min(gap)
        }
        Decision::Review => {
            let s = best_score.unwrap_or(T_LO);
            let position = ((s - T_LO) / (T_HI - T_LO)).clamp(0.0, 1.0);
            0.25 + 0.25 * position
        }
        Decision::NewDevice => {
            // Confident it is new when the best score sits well below `T_lo`;
            // a competitor near the band makes "new" less certain.
            let closeness = best_score.map_or(0.0, |s| logistic((s - T_LO) / CONF_SCALE));
            0.5 + 0.5 * (1.0 - closeness)
        }
    };

    (base * completeness_scale).clamp(0.0, 1.0)
}

/// Standard logistic `1 / (1 + e^-x)`, mapping a score margin to `(0, 1)`.
fn logistic(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// Derive a fresh deterministic `visitorId` for a new device: the SHA-256 of the
/// canonical component bytes, hex-encoded. Deterministic so an identical probe
/// that somehow escaped recall still resolves to one id.
fn derive_visitor_id(components: &Value) -> String {
    let canonical = serde_json::to_vec(components).unwrap_or_default();
    hex::encode(Sha256::digest(&canonical))
}

#[cfg(test)]
mod tests {
    use super::{Decision, T_LO};
    use crate::fuzzy::FuzzyStore;
    use serde_json::{Value, json};

    /// A full, high-signal probe (8 components across all three kinds).
    fn full_probe() -> Value {
        json!({
            "webgl": "ANGLE (Intel)",
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
            "audio": "124.04",
            "cpu_cores": 8,
            "device_memory": 8,
            "fonts": ["Arial", "Helvetica", "Courier", "Times", "Verdana"],
            "user_agent": "Chrome/120",
        })
    }

    /// (a) De-avalanche: a single browser upgrade plus one changed font must not
    /// mint a new device — the stable components carry the match (design §5/§8).
    #[test]
    fn a_single_component_drift_stays_the_same_device() {
        let store = FuzzyStore::new();
        let first = store.identify(&full_probe(), 1_000);
        assert!(first.is_new_device);

        // Browser auto-upgraded (UA) and one font swapped: everything stable is
        // unchanged, so the FS score clears T_hi and the id is preserved.
        let mut drifted = full_probe();
        drifted["user_agent"] = json!("Chrome/121");
        drifted["fonts"] = json!(["Arial", "Helvetica", "Courier", "Times", "Segoe"]);
        let second = store.identify(&drifted, 2_000);

        assert_eq!(second.decision, Decision::Match);
        assert!(!second.is_new_device);
        assert_eq!(second.visitor_id, first.visitor_id);
        assert!(
            second.confidence > 0.7,
            "confidence was {}",
            second.confidence
        );
    }

    /// (b) Anti-collision: two different devices that collide on a blocking key
    /// (shared audio+cpu+memory) but disagree on the high-stability discriminants
    /// (webgl/platform/timezone/fonts) must be scored apart, not merged (§5).
    #[test]
    fn b_shared_block_but_distinct_device_is_not_merged() {
        let store = FuzzyStore::new();
        let first = store.identify(&full_probe(), 1_000);

        // Same K2 subset (audio + cpu_cores + device_memory) so `first` is
        // recalled, but every high-stability discriminant disagrees.
        let other = json!({
            "webgl": "Mali-G78",
            "platform": "Linux armv8",
            "timezone": "America/New_York",
            "audio": "124.04",
            "cpu_cores": 8,
            "device_memory": 8,
            "fonts": ["Roboto", "Noto", "Droid", "Ubuntu"],
            "user_agent": "Firefox/119",
        });
        // The collision is real at stage one: `first` is in the candidate set.
        assert!(store.candidates(&other).contains(&first.visitor_id));

        let second = store.identify(&other, 2_000);
        assert_eq!(second.decision, Decision::NewDevice);
        assert!(second.is_new_device);
        assert_ne!(second.visitor_id, first.visitor_id);
    }

    /// (c) Low-entropy fade: agreeing only on components that are common across
    /// the library (timezone/platform/languages, high `u_i`) carries almost no
    /// evidence, so a bare low-entropy overlap does not merge (design §5.3).
    #[test]
    fn c_low_entropy_only_overlap_does_not_merge() {
        let store = FuzzyStore::new();
        let low = json!({
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
            "languages": "en-US",
        });
        // A crowd shares these exact low-entropy values, inflating their `u_i`.
        for i in 0..30 {
            store.observe(&format!("bg{i}"), &low, 1_000);
        }

        // The victim is recalled against the crowd (they share the K0 key)...
        assert!(!store.candidates(&low).is_empty());
        // ...but the common agreements never clear T_lo, so it is judged new.
        let out = store.identify(&low, 2_000);
        assert_eq!(out.decision, Decision::NewDevice);
        assert!(out.is_new_device);
        assert!(out.score.unwrap() < T_LO, "score was {:?}", out.score);
    }

    /// (d) Missing components: a null canvas (privacy browser) is never a
    /// matchable value, so two distinct privacy devices do not collide on it; and
    /// a match built from fewer components is less confident (design §6/§8).
    #[test]
    fn d_missing_components_neither_collide_nor_inflate_confidence() {
        // A null canvas must not link two otherwise-distinct privacy devices.
        let privacy = FuzzyStore::new();
        let a = privacy.identify(
            &json!({ "webgl": "GPU-A", "platform": "Linux", "timezone": "UTC", "canvas": null }),
            1_000,
        );
        let b = privacy.identify(
            &json!({ "webgl": "GPU-B", "platform": "Windows", "timezone": "GMT", "canvas": null }),
            2_000,
        );
        assert!(a.is_new_device && b.is_new_device);
        assert_ne!(a.visitor_id, b.visitor_id);

        // Completeness: a full match is more confident than a match resting on
        // only a few components.
        let store = FuzzyStore::new();
        store.identify(&full_probe(), 1_000);
        let full = store.identify(&full_probe(), 2_000);
        assert_eq!(full.decision, Decision::Match);

        // A sparse probe carrying only three of the stable components.
        let sparse = json!({
            "webgl": "ANGLE (Intel)",
            "platform": "Linux x86_64",
            "timezone": "Asia/Shanghai",
        });
        let partial = store.identify(&sparse, 3_000);
        assert!(partial.compared_components < full.compared_components);
        assert!(
            partial.confidence < full.confidence,
            "partial {} should be below full {}",
            partial.confidence,
            full.confidence,
        );
    }
}
