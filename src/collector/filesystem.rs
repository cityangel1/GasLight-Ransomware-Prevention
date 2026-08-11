// File monitor — the busiest collector.
//
// NOTE: OS-level filesystem notifications (inotify / ReadDirectoryChangesW /
// FSEvents) do not include which process performed the write, so every
// event from this collector carries `pid: None`. Attribution to a specific
// process would require kernel-level interception — on Windows that's the
// minifilter driver in `driver/`; on Linux, `collector/fanotify.rs`
// already solves this for writes specifically (from user space, no
// kernel module needed — see that file for why). When fanotify is
// available, `skip_writes` is set so this collector doesn't emit a
// second, unattributed copy of the same write events — it still handles
// create/rename/delete either way, since fanotify's classic (non-FID)
// event API doesn't cover those.
//
// NOTE ON RENAME HANDLING: rename semantics differ across platforms. On
// Linux, a single `mv` typically arrives as two separate inotify events
// (IN_MOVED_FROM / IN_MOVED_TO) that `notify` may or may not coalesce into
// one `ModifyKind::Name(RenameMode::Both)` event depending on version/OS.
// The handling below covers both the coalesced case and the split case.

use crate::collector::entropy;
use crate::telemetry::{Event, EventSender};
use notify::event::{ModifyKind, RenameMode};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc as std_mpsc;

pub fn run(tx: EventSender, watch_paths: &[String], entropy_sample_bytes: usize, skip_writes: bool) {
    let (raw_tx, raw_rx) = std_mpsc::channel::<notify::Result<notify::Event>>();

    let mut watcher: RecommendedWatcher = match notify::recommended_watcher(move |res| {
        // Errors are forwarded rather than dropped so the main loop below
        // can log them instead of silently losing filesystem visibility.
        let _ = raw_tx.send(res);
    }) {
        Ok(w) => w,
        Err(e) => {
            crate::utils::logger::critical(&format!(
                "[filesystem] failed to initialize watcher: {e}"
            ));
            return;
        }
    };

    let mut watched_any = false;
    for path in watch_paths {
        let p = Path::new(path);
        if !p.exists() {
            crate::utils::logger::warn(&format!(
                "[filesystem] configured watch path does not exist, skipping: {path}"
            ));
            continue;
        }
        match watcher.watch(p, RecursiveMode::Recursive) {
            Ok(_) => {
                watched_any = true;
                crate::utils::logger::info(&format!("[filesystem] watching {path}"));
            }
            Err(e) => {
                crate::utils::logger::critical(&format!(
                    "[filesystem] failed to watch {path}: {e}"
                ));
            }
        }
    }

    if !watched_any {
        crate::utils::logger::critical(
            "[filesystem] no watch paths were successfully registered — file monitor is idle",
        );
        return;
    }

    // Holds the source path of a split rename (`RenameMode::From`) until its
    // matching `RenameMode::To` arrives, so we can still emit one coherent
    // FileRename event instead of two half-events.
    let mut pending_rename_from: Option<String> = None;

    for res in raw_rx {
        let event = match res {
            Ok(e) => e,
            Err(e) => {
                crate::utils::logger::warn(&format!("[filesystem] watcher error: {e}"));
                continue;
            }
        };

        match event.kind {
            EventKind::Create(_) => {
                for path in &event.paths {
                    send(&tx, Event::file_create(None, path_to_string(path)));
                }
            }

            EventKind::Modify(ModifyKind::Data(_)) => {
                // fanotify (collector/fanotify.rs) already emits
                // PID-attributed FileWrite events for this same activity
                // when it's available — a second, unattributed copy from
                // here would just double the apparent write rate without
                // adding information.
                if !skip_writes {
                    for path in &event.paths {
                        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                        let ent = entropy::entropy_of_file(path, entropy_sample_bytes).unwrap_or(0.0);
                        send(&tx, Event::file_write(None, path_to_string(path), size, ent));
                    }
                }
            }

            EventKind::Modify(ModifyKind::Name(rename_mode)) => match rename_mode {
                RenameMode::Both => {
                    if event.paths.len() >= 2 {
                        let from = path_to_string(&event.paths[0]);
                        let to = path_to_string(&event.paths[1]);
                        send(&tx, Event::file_rename(None, from, to));
                    }
                }
                RenameMode::From => {
                    if let Some(p) = event.paths.first() {
                        pending_rename_from = Some(path_to_string(p));
                    }
                }
                RenameMode::To => {
                    if let Some(p) = event.paths.first() {
                        let to = path_to_string(p);
                        let from = pending_rename_from.take().unwrap_or_else(|| "unknown".to_string());
                        send(&tx, Event::file_rename(None, from, to));
                    }
                }
                RenameMode::Any | RenameMode::Other => {
                    // Platform gave us a rename notification without enough
                    // detail to pair from/to reliably — log it as a create
                    // so the entropy/velocity signals still fire rather than
                    // dropping the event entirely.
                    for path in &event.paths {
                        send(&tx, Event::file_create(None, path_to_string(path)));
                    }
                }
            },

            EventKind::Remove(_) => {
                for path in &event.paths {
                    send(&tx, Event::file_delete(None, path_to_string(path)));
                }
            }

            _ => { /* Access / metadata-only / other events: not relevant to ransomware behavior */ }
        }
    }
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn send(tx: &EventSender, event: Event) {
    if tx.try_send(event).is_err() {
        crate::utils::logger::warn("[filesystem] telemetry queue full — dropped an event");
    }
}
