// Feature extractor.
//
// Turns raw counters into the meaningful measurements the doc describes:
// "PID 881 performed 120 writes in 2 seconds" becomes "files_per_second =
// 60" — the number the scorer actually cares about.

use crate::behavior::process_state::{ProcessState, SHORT_WINDOW};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Features {
    pub files_per_second: f32,
    pub rename_rate: f32,
    pub delete_rate: f32,
    pub avg_entropy: f32,
    pub entropy_spike: bool,
    pub suspicious_renames_in_window: u64,
    pub honey_hit: bool,
    pub registry_persistence: bool,
    pub vss_deletion: bool,

    // Milestone 2 stubs: both need data sources this agent doesn't collect
    // yet (Authenticode/codesign verification, and privilege token
    // inspection). Kept as explicit `false` fields — not omitted — so this
    // struct and the doc's Feature List table stay 1:1, ready to wire up
    // later without reshaping the scorer.
    pub unsigned_executable: bool,
    pub privilege_escalation: bool,
}

pub struct ExtractorConfig {
    pub entropy_spike_threshold: f64,
}

pub fn extract(state: &ProcessState, cfg: &ExtractorConfig) -> Features {
    Features {
        files_per_second: state.writes_in_window(SHORT_WINDOW) as f32 / SHORT_WINDOW.as_secs_f32(),
        rename_rate: state.renames_in_window(SHORT_WINDOW) as f32 / SHORT_WINDOW.as_secs_f32(),
        delete_rate: state.deletes_in_window(SHORT_WINDOW) as f32 / SHORT_WINDOW.as_secs_f32(),
        avg_entropy: state.entropy_average,
        entropy_spike: state.entropy_tracker.is_spike(cfg.entropy_spike_threshold),
        suspicious_renames_in_window: state.suspicious_renames_in_window(SHORT_WINDOW),
        honey_hit: state.honey_hit,
        registry_persistence: state.registry_changes > 0,
        vss_deletion: state.vss_delete_attempted,
        unsigned_executable: false,
        privilege_escalation: false,
    }
}
