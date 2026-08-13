// Process state — the "medical chart" for one running process, per the
// architecture doc. Lifetime counters (writes, renames, deletes, ...) are
// kept for display purposes; actual scoring always goes through the
// sliding-window methods below, never the lifetime totals directly — see
// the doc's "Time Windows" section on why (an 8-hour document-editing
// session shouldn't score the same as a 2-second encryption burst).

use crate::behavior::entropy::EntropyTracker;
use serde::Serialize;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Short window used for rate features (files/sec, rename rate, delete
/// rate) — matches the doc's "Last 5 seconds" example.
pub const SHORT_WINDOW: Duration = Duration::from_secs(5);
/// Longer window lifetime counters are trimmed against, just to bound
/// memory for long-running processes without affecting short-window rates.
pub const LONG_WINDOW: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Serialize)]
pub struct ProcessState {
    pub pid: u32,
    pub process_name: String,
    pub score: f32,
    pub writes: u64,
    pub renames: u64,
    pub deletes: u64,
    pub created: u64, // unix ms
    pub entropy_average: f32,
    pub extensions_changed: u64,
    pub files_per_second: f32,
    pub suspicious_paths: u64,
    pub registry_changes: u64,
    pub network_connections: u64,

    #[serde(skip)]
    pub(crate) entropy_tracker: EntropyTracker,
    #[serde(skip)]
    write_timestamps: VecDeque<Instant>,
    #[serde(skip)]
    rename_timestamps: VecDeque<Instant>,
    #[serde(skip)]
    suspicious_rename_timestamps: VecDeque<Instant>,
    #[serde(skip)]
    delete_timestamps: VecDeque<Instant>,
    #[serde(skip)]
    pub(crate) vss_delete_attempted: bool,
    #[serde(skip)]
    pub(crate) honey_hit: bool,
}

impl ProcessState {
    pub fn new(pid: u32, process_name: String, created_ms: u64) -> Self {
        ProcessState {
            pid,
            process_name,
            score: 0.0,
            writes: 0,
            renames: 0,
            deletes: 0,
            created: created_ms,
            entropy_average: 0.0,
            extensions_changed: 0,
            files_per_second: 0.0,
            suspicious_paths: 0,
            registry_changes: 0,
            network_connections: 0,
            entropy_tracker: EntropyTracker::new(),
            write_timestamps: VecDeque::new(),
            rename_timestamps: VecDeque::new(),
            suspicious_rename_timestamps: VecDeque::new(),
            delete_timestamps: VecDeque::new(),
            vss_delete_attempted: false,
            honey_hit: false,
        }
    }

    pub fn record_write(&mut self, entropy: f64, extension: Option<&str>) {
        let now = Instant::now();
        self.writes += 1;
        self.write_timestamps.push_back(now);
        trim(&mut self.write_timestamps, now, LONG_WINDOW);
        self.entropy_tracker.observe(entropy, extension);
        self.entropy_average = self.entropy_tracker.average() as f32;
        self.files_per_second = rate(&self.write_timestamps, now, SHORT_WINDOW);
    }

    pub fn record_rename(&mut self, suspicious_extension: bool) {
        let now = Instant::now();
        self.renames += 1;
        self.rename_timestamps.push_back(now);
        trim(&mut self.rename_timestamps, now, LONG_WINDOW);
        if suspicious_extension {
            self.extensions_changed += 1;
            self.suspicious_rename_timestamps.push_back(now);
            trim(&mut self.suspicious_rename_timestamps, now, LONG_WINDOW);
        }
    }

    pub fn record_delete(&mut self) {
        let now = Instant::now();
        self.deletes += 1;
        self.delete_timestamps.push_back(now);
        trim(&mut self.delete_timestamps, now, LONG_WINDOW);
    }

    pub fn record_honeypot_hit(&mut self) {
        self.honey_hit = true;
        self.suspicious_paths += 1;
    }

    pub fn record_registry_change(&mut self, looks_like_vss_delete: bool) {
        self.registry_changes += 1;
        if looks_like_vss_delete {
            self.vss_delete_attempted = true;
        }
    }

    pub fn record_network_connection(&mut self) {
        self.network_connections += 1;
    }

    pub fn writes_in_window(&self, window: Duration) -> u64 {
        count_in_window(&self.write_timestamps, window)
    }

    pub fn renames_in_window(&self, window: Duration) -> u64 {
        count_in_window(&self.rename_timestamps, window)
    }

    pub fn suspicious_renames_in_window(&self, window: Duration) -> u64 {
        count_in_window(&self.suspicious_rename_timestamps, window)
    }

    pub fn deletes_in_window(&self, window: Duration) -> u64 {
        count_in_window(&self.delete_timestamps, window)
    }
}

fn trim(deque: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while let Some(front) = deque.front() {
        if now.duration_since(*front) > window {
            deque.pop_front();
        } else {
            break;
        }
    }
}

fn rate(deque: &VecDeque<Instant>, now: Instant, window: Duration) -> f32 {
    let count = deque.iter().filter(|t| now.duration_since(**t) <= window).count();
    count as f32 / window.as_secs_f32()
}

fn count_in_window(deque: &VecDeque<Instant>, window: Duration) -> u64 {
    let now = Instant::now();
    deque.iter().filter(|t| now.duration_since(**t) <= window).count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_process_has_zero_rates() {
        let state = ProcessState::new(1234, "test.exe".to_string(), 0);
        assert_eq!(state.files_per_second, 0.0);
        assert_eq!(state.writes_in_window(SHORT_WINDOW), 0);
    }

    #[test]
    fn writes_accumulate_lifetime_and_window_counts() {
        let mut state = ProcessState::new(1234, "test.exe".to_string(), 0);
        state.record_write(3.1, Some(".txt"));
        state.record_write(3.2, Some(".txt"));
        assert_eq!(state.writes, 2);
        assert_eq!(state.writes_in_window(SHORT_WINDOW), 2);
    }

    #[test]
    fn honeypot_hit_is_sticky() {
        let mut state = ProcessState::new(1234, "evil.exe".to_string(), 0);
        assert!(!state.honey_hit);
        state.record_honeypot_hit();
        assert!(state.honey_hit);
    }
}
