use crate::behavior::feature_extractor::{self, ExtractorConfig};
use crate::behavior::process_state::ProcessState;
use crate::behavior::rules::RiskLevel;
use crate::behavior::scoring::{self, ScoringWeights};
use crate::behavior::types::DecisionReport;

pub struct DetectorConfig {
    pub extractor: ExtractorConfig,
    pub weights: ScoringWeights,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        DetectorConfig {
            extractor: ExtractorConfig {
                entropy_spike_threshold: 7.8,
            },
            weights: ScoringWeights::default(),
        }
    }
}

/// The full "Feature Extractor -> Risk Scoring -> Decision" pipeline from
/// the architecture doc, run for one process's current state.
pub fn evaluate(state: &ProcessState, cfg: &DetectorConfig) -> DecisionReport {
    let features = feature_extractor::extract(state, &cfg.extractor);
    let result = scoring::score(&features, &cfg.weights);
    let level = RiskLevel::from_score(result.score);

    DecisionReport {
        pid: state.pid,
        process_name: state.process_name.clone(),
        score: result.score,
        risk_level: level.as_str(),
        decision: level.default_decision(),
        reasons: result.reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_process_is_allowed() {
        let state = ProcessState::new(1, "explorer.exe".to_string(), 0);
        let report = evaluate(&state, &DetectorConfig::default());
        assert_eq!(report.decision, crate::behavior::types::Decision::Allow);
        assert_eq!(report.risk_level, "Safe");
    }

    #[test]
    fn honeypot_hit_pushes_process_out_of_safe_band() {
        let mut state = ProcessState::new(2, "evil.exe".to_string(), 0);
        state.record_honeypot_hit();
        let report = evaluate(&state, &DetectorConfig::default());
        assert_ne!(report.risk_level, "Safe");
        assert!(!report.reasons.is_empty());
    }
}
