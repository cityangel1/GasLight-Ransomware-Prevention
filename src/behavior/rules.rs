use crate::behavior::types::Decision;

/// Fixed risk bands from the architecture doc. Deliberately not
/// configurable — the doc presents these as the stable contract between
/// "what score means what," which is exactly the kind of thing that should
/// stay predictable across config changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Safe,
    Monitor,
    Warning,
    HighRisk,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: f32) -> RiskLevel {
        if score < 25.0 {
            RiskLevel::Safe
        } else if score < 50.0 {
            RiskLevel::Monitor
        } else if score < 70.0 {
            RiskLevel::Warning
        } else if score < 85.0 {
            RiskLevel::HighRisk
        } else {
            RiskLevel::Critical
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Safe => "Safe",
            RiskLevel::Monitor => "Monitor",
            RiskLevel::Warning => "Warning",
            RiskLevel::HighRisk => "High Risk",
            RiskLevel::Critical => "Critical",
        }
    }

    /// The engine's recommended decision for this risk band. `Suspend` at
    /// High Risk pairs with a filesystem block (see `response.rs`) rather
    /// than being purely informational — the doc's own explainability
    /// example shows "Filesystem protected" and "Process suspended"
    /// happening together, not as separate risk bands.
    pub fn default_decision(&self) -> Decision {
        match self {
            RiskLevel::Safe => Decision::Allow,
            RiskLevel::Monitor => Decision::Monitor,
            RiskLevel::Warning => Decision::Alert,
            RiskLevel::HighRisk => Decision::Suspend,
            RiskLevel::Critical => Decision::Terminate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bands_match_the_architecture_doc() {
        assert_eq!(RiskLevel::from_score(0.0), RiskLevel::Safe);
        assert_eq!(RiskLevel::from_score(24.9), RiskLevel::Safe);
        assert_eq!(RiskLevel::from_score(25.0), RiskLevel::Monitor);
        assert_eq!(RiskLevel::from_score(49.9), RiskLevel::Monitor);
        assert_eq!(RiskLevel::from_score(50.0), RiskLevel::Warning);
        assert_eq!(RiskLevel::from_score(69.9), RiskLevel::Warning);
        assert_eq!(RiskLevel::from_score(70.0), RiskLevel::HighRisk);
        assert_eq!(RiskLevel::from_score(84.9), RiskLevel::HighRisk);
        assert_eq!(RiskLevel::from_score(85.0), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(100.0), RiskLevel::Critical);
    }
}
