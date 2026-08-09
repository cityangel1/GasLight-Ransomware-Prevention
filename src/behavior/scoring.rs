// Risk scoring.
//
// Deliberately not an AI model — per the doc: "The behavioral engine
// should work even if the AI is removed." This is a transparent weighted
// scorer where every point awarded gets a human-readable reason attached,
// so a blocked process's owner sees exactly why instead of "Blocked by AI."

use crate::behavior::feature_extractor::Features;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ScoreResult {
    pub score: f32, // normalized 0-100
    pub raw_total: f32,
    pub reasons: Vec<String>,
}

/// Matches the worked example in the architecture doc: Writes 25, Entropy
/// 20, Deletes 15, Rename burst 15, Honey files 40, Registry persistence
/// 10 — summing to a raw maximum of 125, normalized down to 100.
#[derive(Debug, Clone)]
pub struct ScoringWeights {
    pub files_per_second: f32,
    pub entropy: f32,
    pub deletes: f32,
    pub rename_burst: f32,
    pub honey_file: f32,
    pub registry_persistence: f32,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        ScoringWeights {
            files_per_second: 25.0,
            entropy: 20.0,
            deletes: 15.0,
            rename_burst: 15.0,
            honey_file: 40.0,
            registry_persistence: 10.0,
        }
    }
}

/// Sum of the weights above — the raw ceiling before normalization. Kept
/// as a function of the weights actually in use (rather than a hardcoded
/// 125.0) so a customized `ScoringWeights` still normalizes correctly.
fn max_raw(weights: &ScoringWeights) -> f32 {
    weights.files_per_second
        + weights.entropy
        + weights.deletes
        + weights.rename_burst
        + weights.honey_file
        + weights.registry_persistence
}

// Rates (per second / per window) that earn a feature its *full* weight.
// Below this, the contribution scales down linearly rather than being
// all-or-nothing, so a process ramping up toward these levels shows a
// rising score instead of jumping straight from 0 to full points.
const FILES_PER_SEC_SATURATION: f32 = 40.0;
const DELETE_RATE_SATURATION: f32 = 10.0;
const SUSPICIOUS_RENAMES_SATURATION: u64 = 5;

pub fn score(features: &Features, weights: &ScoringWeights) -> ScoreResult {
    let mut reasons = Vec::new();
    let mut raw = 0.0f32;

    let velocity_pts =
        (features.files_per_second / FILES_PER_SEC_SATURATION).clamp(0.0, 1.0) * weights.files_per_second;
    if velocity_pts >= 1.0 {
        reasons.push(format!(
            "{:.0} file writes/sec (+{:.0} pts)",
            features.files_per_second, velocity_pts
        ));
    }
    raw += velocity_pts;

    let entropy_pts = if features.entropy_spike { weights.entropy } else { 0.0 };
    if entropy_pts > 0.0 {
        reasons.push(format!(
            "entropy spiked to {:.2} (+{:.0} pts)",
            features.avg_entropy, entropy_pts
        ));
    }
    raw += entropy_pts;

    let delete_pts = (features.delete_rate / DELETE_RATE_SATURATION).clamp(0.0, 1.0) * weights.deletes;
    if delete_pts >= 1.0 {
        reasons.push(format!(
            "{:.0} deletes/sec — originals being removed (+{:.0} pts)",
            features.delete_rate, delete_pts
        ));
    }
    raw += delete_pts;

    let rename_pts = (features.suspicious_renames_in_window as f32 / SUSPICIOUS_RENAMES_SATURATION as f32)
        .clamp(0.0, 1.0)
        * weights.rename_burst;
    if rename_pts >= 1.0 {
        reasons.push(format!(
            "{} files renamed to suspicious extensions (+{:.0} pts)",
            features.suspicious_renames_in_window, rename_pts
        ));
    }
    raw += rename_pts;

    let honey_pts = if features.honey_hit { weights.honey_file } else { 0.0 };
    if honey_pts > 0.0 {
        reasons.push(format!("accessed a honeypot file (+{:.0} pts)", honey_pts));
    }
    raw += honey_pts;

    let registry_signal = features.registry_persistence || features.vss_deletion;
    let registry_pts = if registry_signal { weights.registry_persistence } else { 0.0 };
    if registry_pts > 0.0 {
        let mut detail = Vec::new();
        if features.vss_deletion {
            detail.push("shadow-copy deletion attempted");
        }
        if features.registry_persistence {
            detail.push("registry persistence");
        }
        reasons.push(format!("{} (+{:.0} pts)", detail.join(" + "), registry_pts));
    }
    raw += registry_pts;

    let normalized = ((raw / max_raw(weights)) * 100.0).clamp(0.0, 100.0);

    ScoreResult {
        score: normalized,
        raw_total: raw,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idle_features() -> Features {
        Features {
            files_per_second: 0.0,
            rename_rate: 0.0,
            delete_rate: 0.0,
            avg_entropy: 3.0,
            entropy_spike: false,
            suspicious_renames_in_window: 0,
            honey_hit: false,
            registry_persistence: false,
            vss_deletion: false,
            unsigned_executable: false,
            privilege_escalation: false,
        }
    }

    #[test]
    fn idle_process_scores_zero() {
        let result = score(&idle_features(), &ScoringWeights::default());
        assert_eq!(result.score, 0.0);
        assert!(result.reasons.is_empty());
    }

    #[test]
    fn honeypot_touch_alone_crosses_into_warning_band() {
        let mut features = idle_features();
        features.honey_hit = true;
        let result = score(&features, &ScoringWeights::default());
        // 40 / 125 * 100 = 32 — Monitor band on its own, as it should be:
        // a single decoy touch is suspicious but the doc treats honeypot
        // hits as a strong signal, not an automatic kill by itself.
        assert!(result.score > 30.0 && result.score < 35.0);
        assert_eq!(result.reasons.len(), 1);
    }

    #[test]
    fn full_ransomware_pattern_saturates_near_max() {
        let features = Features {
            files_per_second: 600.0,
            rename_rate: 250.0,
            delete_rate: 250.0,
            avg_entropy: 7.95,
            entropy_spike: true,
            suspicious_renames_in_window: 500,
            honey_hit: true,
            registry_persistence: true,
            vss_deletion: true,
            unsigned_executable: false,
            privilege_escalation: false,
        };
        let result = score(&features, &ScoringWeights::default());
        assert!(result.score >= 99.0);
    }
}
