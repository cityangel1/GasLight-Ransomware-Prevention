// Response manager.
//
// "The engine shouldn't directly kill processes. Instead it emits
// decisions." — this module is the one place that turns a `Decision` into
// an actual call against `DriverClient` (the Milestone 1 mitigation
// layer). Keeping it separate from the scorer is what lets you swap in a
// different response policy (e.g. always Alert instead of Terminate, for
// a dry-run demo mode) without touching the scoring logic at all.

use crate::behavior::types::{Decision, DecisionReport};
use crate::driver::DriverClient;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Minimum time between consecutive enforcement actions for the same PID,
/// so a sustained high score doesn't re-trigger kill/suspend on every
/// single telemetry event.
const COOLDOWN: Duration = Duration::from_secs(5);

pub struct ResponseManager {
    last_action: HashMap<u32, Instant>,
}

impl ResponseManager {
    pub fn new() -> Self {
        ResponseManager {
            last_action: HashMap::new(),
        }
    }

    pub fn dispatch(&mut self, report: &DecisionReport, driver: &impl DriverClient) {
        match report.decision {
            Decision::Allow | Decision::Monitor => {
                // Expected path for the vast majority of processes — no
                // action, no log spam.
            }
            Decision::Alert => {
                crate::utils::logger::warn(&format!(
                    "[response] ALERT pid={} ({}) score={:.0} — {}",
                    report.pid,
                    report.process_name,
                    report.score,
                    reasons_or_default(report)
                ));
            }
            Decision::Suspend => {
                if self.should_act(report.pid) {
                    let reason = format!("score {:.0}: {}", report.score, reasons_or_default(report));
                    driver.block_writes(report.pid, &reason);
                    driver.suspend_process(report.pid, &reason);
                    self.mark(report.pid);
                }
            }
            Decision::ProtectFilesystem => {
                if self.should_act(report.pid) {
                    driver.block_writes(
                        report.pid,
                        &format!("score {:.0}: {}", report.score, reasons_or_default(report)),
                    );
                    self.mark(report.pid);
                }
            }
            Decision::Terminate => {
                if self.should_act(report.pid) {
                    let reason = format!("score {:.0}: {}", report.score, reasons_or_default(report));
                    driver.block_writes(report.pid, &reason);
                    driver.kill_process(report.pid, &reason);
                    self.mark(report.pid);
                }
            }
        }
    }

    fn should_act(&self, pid: u32) -> bool {
        match self.last_action.get(&pid) {
            Some(t) => t.elapsed() >= COOLDOWN,
            None => true,
        }
    }

    fn mark(&mut self, pid: u32) {
        self.last_action.insert(pid, Instant::now());
    }
}

impl Default for ResponseManager {
    fn default() -> Self {
        Self::new()
    }
}

fn reasons_or_default(report: &DecisionReport) -> String {
    if report.reasons.is_empty() {
        "no individual signal crossed its own threshold, but combined score is elevated".to_string()
    } else {
        report.reasons.join("; ")
    }
}
