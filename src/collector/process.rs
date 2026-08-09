// Process monitor.
//
// NOTE ON API STABILITY: `sysinfo`'s public API has shifted a few times
// across minor versions (particularly around `refresh_processes` and
// whether `Process::name()` returns `&str` vs `&OsStr`). This file targets
// the `sysinfo = "0.30"` line pinned in Cargo.toml. If `cargo build` flags
// a mismatch here, check `cargo doc --open -p sysinfo` for the exact
// signatures on whatever version actually resolved — this is the single
// most likely spot in the whole agent to need a small tweak.

use crate::telemetry::{Event, EventSender};
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use sysinfo::System;

pub fn run(tx: EventSender, poll_interval_ms: u64) {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut known_pids: HashSet<u32> = sys.processes().keys().map(|pid| pid.as_u32()).collect();

    crate::utils::logger::info(&format!(
        "[process] monitor started — {} processes at baseline",
        known_pids.len()
    ));

    loop {
        thread::sleep(Duration::from_millis(poll_interval_ms));
        sys.refresh_all();

        let current_pids: HashSet<u32> = sys.processes().keys().map(|pid| pid.as_u32()).collect();

        // New processes since last poll.
        for pid in current_pids.difference(&known_pids) {
            if let Some(process) = sys
                .processes()
                .iter()
                .find(|(p, _)| p.as_u32() == *pid)
                .map(|(_, proc)| proc)
            {
                let parent_pid = process.parent().map(|p| p.as_u32());
                let image = process.name().to_string();
                let cmdline = process
                    .cmd()
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");

                let event = Event::process_start(*pid, parent_pid, image, cmdline);
                if tx.try_send(event).is_err() {
                    crate::utils::logger::warn(
                        "[process] telemetry queue full — dropped a ProcessStart event",
                    );
                }
            }
        }

        // Processes that vanished since last poll.
        for pid in known_pids.difference(&current_pids) {
            // The process object is already gone from `sys` by the time we
            // notice an exit, so we only have the PID to report.
            let event = Event::process_exit(*pid, "unknown".to_string());
            if tx.try_send(event).is_err() {
                crate::utils::logger::warn(
                    "[process] telemetry queue full — dropped a ProcessExit event",
                );
            }
        }

        known_pids = current_pids;
    }
}
