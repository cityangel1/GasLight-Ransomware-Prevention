// Behavioral engine — the top-level object from the architecture doc's
// Rust sketch:
//
//   pub struct BehavioralEngine {
//       processes: HashMap<u32, ProcessState>,
//       scorer: RiskScorer,
//       extractor: FeatureExtractor,
//       responder: ResponseManager,
//   }
//
// PID ATTRIBUTION NOTE (important): this agent's user-space filesystem
// watcher (see collector/filesystem.rs) cannot tell you which process
// performed a given write — only kernel-level interception can. Every
// file event that arrives with `pid: None` is bucketed under the
// `UNATTRIBUTED_PID` sentinel below rather than dropped, so the engine
// still reacts to real ransomware behavior today. Once real per-process
// file attribution exists, that bucket should stay empty and each event's
// `Some(pid)` will route to its own ProcessState automatically — nothing
// else in this file needs to change.

use crate::behavior::detector::{self, DetectorConfig};
use crate::behavior::process_state::ProcessState;
use crate::behavior::response::ResponseManager;
use crate::behavior::types::DecisionReport;
use crate::deception::SharedHoneyRegistry;
use crate::driver::DriverClient;
use crate::telemetry::Event;
use std::collections::HashMap;

pub const UNATTRIBUTED_PID: u32 = 0;
const UNATTRIBUTED_NAME: &str = "SYSTEM (unattributed file activity)";

pub struct BehavioralEngine {
    processes: HashMap<u32, ProcessState>,
    cfg: DetectorConfig,
    honey_registry: SharedHoneyRegistry,
    responder: ResponseManager,
}

impl BehavioralEngine {
    /// `honey_registry` should be the same handle returned by
    /// `deception::DeceptionManager::registry_handle()` — this is what
    /// replaced the old marker-substring approach (see the note at the
    /// top of `deception/metadata.rs` for why that had to change).
    pub fn new(cfg: DetectorConfig, honey_registry: SharedHoneyRegistry) -> Self {
        BehavioralEngine {
            processes: HashMap::new(),
            cfg,
            honey_registry,
            responder: ResponseManager::new(),
        }
    }

    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    pub fn state_of(&self, pid: u32) -> Option<&ProcessState> {
        self.processes.get(&pid)
    }

    /// Feeds one telemetry event into the engine: updates the relevant
    /// ProcessState, re-evaluates its risk, dispatches any resulting
    /// mitigation, and returns the explainable report. Returns `None`
    /// for lifecycle-only events (ProcessExit) that don't produce a
    /// fresh score.
    pub fn ingest(&mut self, event: &Event, driver: &impl DriverClient) -> Option<DecisionReport> {
        let pid = event.pid().unwrap_or(UNATTRIBUTED_PID);

        if let Event::ProcessExit(e) = event {
            self.processes.remove(&e.pid);
            return None;
        }

        if let Event::ProcessStart(e) = event {
            self.processes
                .insert(e.pid, ProcessState::new(e.pid, e.image.clone(), e.timestamp_ms));
            // A fresh process has nothing to score yet.
            return None;
        }

        let honey_registry = &self.honey_registry;
        let state = self.processes.entry(pid).or_insert_with(|| {
            let name = if pid == UNATTRIBUTED_PID {
                UNATTRIBUTED_NAME.to_string()
            } else {
                "unknown".to_string()
            };
            ProcessState::new(pid, name, now_ms())
        });

        apply_to_state(state, event, honey_registry);

        let report = detector::evaluate(state, &self.cfg);
        state.score = report.score;

        self.responder.dispatch(&report, driver);
        Some(report)
    }
}

/// Free function (rather than a `&self` method) deliberately: it needs a
/// `&mut ProcessState` borrowed out of `self.processes` at the same time
/// as `&self.honey_registry`, which the borrow checker only allows when
/// the honeypot check doesn't go through another `&self` method call.
fn apply_to_state(state: &mut ProcessState, event: &Event, honey_registry: &SharedHoneyRegistry) {
    match event {
        Event::FileWrite(e) => {
            let ext = extension_of(&e.path);
            state.record_write(e.entropy, ext.as_deref());
            if touches_honeypot(honey_registry, &e.path) {
                state.record_honeypot_hit();
            }
        }
        Event::FileRename(e) => {
            state.record_rename(e.is_suspicious_extension);
            if touches_honeypot(honey_registry, &e.from) || touches_honeypot(honey_registry, &e.to) {
                state.record_honeypot_hit();
            }
        }
        Event::FileDelete(e) => {
            state.record_delete();
            if touches_honeypot(honey_registry, &e.path) {
                state.record_honeypot_hit();
            }
        }
        Event::FileCreate(_) => { /* tracked implicitly via the write that usually follows */ }
        Event::RegistryWrite(e) => {
            let key_lower = e.key.to_lowercase();
            let looks_like_vss = key_lower.contains("vss") || key_lower.contains("shadow");
            state.record_registry_change(looks_like_vss);
        }
        Event::NetworkConnect(_) => {
            state.record_network_connection();
        }
        Event::ProcessStart(_) | Event::ProcessExit(_) => {
            unreachable!("handled by the caller before apply_to_state is invoked")
        }
    }
}

/// Exact-path lookup against the real, currently-deployed decoy registry
/// — see `deception/metadata.rs` for why this replaced substring matching
/// against a fixed marker list. Fails safe (returns false) if the lock is
/// poisoned, since a poisoned honeypot registry shouldn't take down
/// scoring for every other signal.
fn touches_honeypot(registry: &SharedHoneyRegistry, path: &str) -> bool {
    registry.read().map(|g| g.contains(path)).unwrap_or(false)
}

fn extension_of(path: &str) -> Option<String> {
    std::path::Path::new(path)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
