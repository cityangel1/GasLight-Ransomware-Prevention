use serde::Serialize;

/// What the engine recommends doing about a process. The engine only ever
/// *emits* a decision — see `response.rs` for what actually acts on it.
/// Keeping these separate is what makes the engine testable: you can
/// assert on the decision a given feature set produces without needing a
/// live process to kill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Decision {
    Allow,
    Monitor,
    Alert,
    Suspend,
    ProtectFilesystem,
    Terminate,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "Allow",
            Decision::Monitor => "Monitor",
            Decision::Alert => "Alert",
            Decision::Suspend => "Suspend",
            Decision::ProtectFilesystem => "ProtectFilesystem",
            Decision::Terminate => "Terminate",
        }
    }
}

/// The full explainable output for one process at one point in time —
/// this is what should be logged, streamed to the dashboard, and shown to
/// an analyst. Never just "Blocked by AI."
#[derive(Debug, Clone, Serialize)]
pub struct DecisionReport {
    pub pid: u32,
    pub process_name: String,
    pub score: f32,
    pub risk_level: &'static str,
    pub decision: Decision,
    pub reasons: Vec<String>,
}
