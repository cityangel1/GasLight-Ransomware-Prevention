use crate::deception::metadata::HoneyRegistry;
use serde::Serialize;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HoneyOperation {
    Open,
    Write,
    Rename,
    Delete,
}

/// Matches the doc's `HoneyFileAccess` example almost field-for-field —
/// this is what should reach the dashboard as "Honey File Triggered"
/// evidence.
#[derive(Debug, Clone, Serialize)]
pub struct HoneyFileEvent {
    pub pid: Option<u32>,
    pub path: String,
    pub operation: HoneyOperation,
    pub honey_id: u64,
    pub timestamp_ms: u64,
}

/// Thread-safe handle to the live honey registry, shared between the
/// deception manager (writer, on deploy/rotate) and the behavioral
/// engine's ingest loop (reader, on every file event — see
/// `behavior/engine.rs`'s `touches_honeypot`).
pub type SharedHoneyRegistry = Arc<RwLock<HoneyRegistry>>;

pub struct HoneyMonitor;

impl HoneyMonitor {
    /// Checks whether `path` is a currently-deployed decoy and, if so,
    /// returns the `HoneyFileEvent` describing this interaction. Cheap —
    /// a single `RwLock` read plus a hash lookup — safe to call from a
    /// hot ingest path. Returns `None` for anything that isn't a decoy,
    /// which is the overwhelming majority of file events on a real
    /// system. Called from `main.rs`'s `classify_honey_event`, feeding
    /// the dashboard's Honey File Monitor panel.
    pub fn classify(
        registry: &SharedHoneyRegistry,
        pid: Option<u32>,
        path: &str,
        operation: HoneyOperation,
    ) -> Option<HoneyFileEvent> {
        let guard = registry.read().ok()?;
        let metadata = guard.get(path)?;

        Some(HoneyFileEvent {
            pid,
            path: path.to_string(),
            operation,
            honey_id: metadata.honey_id,
            timestamp_ms: now_ms(),
        })
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
