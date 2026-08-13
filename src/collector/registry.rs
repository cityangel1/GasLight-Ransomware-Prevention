// Persistence monitor.
//
// Linux has no registry, so this watches the handful of well-known
// files and directories where persistence and security-relevant
// tampering actually show up: cron, systemd units, `/etc/ld.so.preload`
// (library-injection persistence), and shell startup scripts. This
// reuses the same `notify` crate the main filesystem collector already
// depends on — the right tool for "watch a handful of specific paths
// for changes," no new dependency needed here.

use crate::telemetry::{Event, EventSender};

#[cfg(target_os = "linux")]
pub fn run(tx: EventSender) {
    use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::path::PathBuf;
    use std::sync::mpsc as std_mpsc;

    // Well-known Linux persistence vectors worth watching: cron,
    // systemd units, ld.so.preload (a classic library-injection
    // persistence vector), and shell startup scripts.
    let mut watched: Vec<(&str, PathBuf)> = vec![
        ("cron.d", PathBuf::from("/etc/cron.d")),
        ("cron.daily", PathBuf::from("/etc/cron.daily")),
        ("cron.hourly", PathBuf::from("/etc/cron.hourly")),
        ("cron.weekly", PathBuf::from("/etc/cron.weekly")),
        ("cron.spool", PathBuf::from("/var/spool/cron/crontabs")),
        ("systemd.system", PathBuf::from("/etc/systemd/system")),
        ("ld.so.preload", PathBuf::from("/etc/ld.so.preload")),
        ("profile.d", PathBuf::from("/etc/profile.d")),
    ];

    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        watched.push(("systemd.user", home.join(".config/systemd/user")));
        watched.push(("bashrc", home.join(".bashrc")));
        watched.push(("profile", home.join(".profile")));
    }

    let (raw_tx, raw_rx) = std_mpsc::channel::<notify::Result<notify::Event>>();

    let mut watcher: RecommendedWatcher = match notify::recommended_watcher(move |res| {
        let _ = raw_tx.send(res);
    }) {
        Ok(w) => w,
        Err(e) => {
            crate::utils::logger::critical(&format!("[registry] failed to initialize watcher: {e}"));
            return;
        }
    };

    let mut watched_any = false;
    for (label, path) in &watched {
        if !path.exists() {
            // Most of these are legitimately absent on a given machine
            // (no cron.d, no ld.so.preload, ...) — not an error, and
            // worth noting since e.g. ld.so.preload's presence *at all*
            // is itself unusual and can't be watched until it exists.
            crate::utils::logger::info(&format!(
                "[registry] persistence path does not exist, skipping: {label} ({})",
                path.display()
            ));
            continue;
        }
        match watcher.watch(path, RecursiveMode::NonRecursive) {
            Ok(_) => {
                watched_any = true;
                crate::utils::logger::info(&format!("[registry] watching {label} ({})", path.display()));
            }
            Err(e) => {
                crate::utils::logger::warn(&format!("[registry] failed to watch {label}: {e}"));
            }
        }
    }

    if !watched_any {
        crate::utils::logger::warn("[registry] no persistence paths were watchable — monitor is idle");
        return;
    }

    for res in raw_rx {
        let event = match res {
            Ok(e) => e,
            Err(e) => {
                crate::utils::logger::warn(&format!("[registry] watcher error: {e}"));
                continue;
            }
        };

        if matches!(event.kind, EventKind::Access(_)) {
            continue; // pure reads aren't a persistence signal
        }

        for path in &event.paths {
            let label = watched
                .iter()
                .find(|(_, p)| path.starts_with(p) || p == path)
                .map(|(label, _)| *label)
                .unwrap_or("unknown");

            let value_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());

            let ev = Event::registry_write(label.to_string(), value_name);
            if tx.try_send(ev).is_err() {
                crate::utils::logger::warn(
                    "[registry] telemetry queue full — dropped a persistence-change event",
                );
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run(tx: EventSender) {
    let _ = tx;
    crate::utils::logger::info(
        "[registry] persistence monitoring is implemented for Linux only — no-op on this platform",
    );
}
