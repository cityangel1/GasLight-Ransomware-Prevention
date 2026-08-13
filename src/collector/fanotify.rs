// Fanotify collector (Linux-only) — real, PID-attributed file-write
// events, entirely from user space.
//
// WHY THIS EXISTS: every other collector in this project — the
// cross-platform `notify`-based filesystem watcher included — cannot
// tell you *which process* performed a file write; that's been the
// single most-repeated limitation across this whole codebase (see
// `collector/filesystem.rs`, `behavior/engine.rs`'s UNATTRIBUTED_PID
// bucket, the dashboard README). `fanotify_event_metadata` has included
// the originating PID since the API's introduction (kernel 2.6.37), with
// no elevated kernel-module build required — real per-process file
// attribution entirely from user space.
//
// SCOPE, DELIBERATELY LIMITED:
//   - Uses the *classic* fanotify event types (FAN_CLOSE_WRITE), which
//     hand back a plain file descriptor you resolve to a path via
//     `/proc/self/fd/<fd>`. The newer directory-entry events
//     (FAN_CREATE/FAN_DELETE/FAN_MOVED_FROM/FAN_MOVED_TO) need
//     `FAN_REPORT_FID` and file-handle resolution via
//     `open_by_handle_at` (its own privilege requirement, CAP_DAC_READ_SEARCH,
//     and a meaningfully larger FFI surface) — not attempted here. This
//     collector handles **writes only**; create/rename/delete still come
//     from the existing `notify`-based collector (unattributed, as
//     before). See `main.rs` for how the two are coordinated so writes
//     aren't double-counted.
//   - Requires CAP_SYS_ADMIN (in practice: running as root) — real
//     endpoint protection needs elevated privileges. Falls back
//     gracefully (not a crash) if unavailable; see `is_available()`.
//   - Marks the whole filesystem containing `/` (`FAN_MARK_FILESYSTEM`)
//     rather than walking and marking every subdirectory individually.
//     This is a deliberate simplicity-over-precision choice: recursive
//     per-directory marking needs the same "track new subdirectories as
//     they're created" logic `notify` already implements, which would
//     just be duplicating that work inside a much less forgiving FFI
//     surface. Filesystem-wide events are filtered down to
//     `watch_paths` in code instead — more events processed, far less
//     that can go subtly wrong. Multi-mount setups (separate
//     partitions/network mounts for watched paths) aren't fully covered
//     by a single root-filesystem mark — a known, reasonable limitation
//     for this scope.

use crate::collector::entropy;
use crate::telemetry::{Event, EventSender};

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::ffi::CString;
    use std::io;

    /// Cheap capability probe: attempts fanotify_init and immediately
    /// closes it, without setting up any marks. Used by main.rs *before*
    /// deciding whether to spawn this collector and whether to tell the
    /// `notify`-based filesystem collector to skip write events (see the
    /// module doc comment above).
    pub fn is_available() -> bool {
        unsafe {
            let fd = libc::fanotify_init(libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC, libc::O_RDONLY as u32);
            if fd < 0 {
                false
            } else {
                libc::close(fd);
                true
            }
        }
    }

    pub fn run(tx: EventSender, watch_paths: Vec<String>, entropy_sample_bytes: usize) {
        let fd = unsafe { libc::fanotify_init(libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC, libc::O_RDONLY as u32) };
        if fd < 0 {
            crate::utils::logger::critical(&format!(
                "[fanotify] fanotify_init failed (errno {}) — needs CAP_SYS_ADMIN (root). Falling back to unattributed file monitoring only.",
                io::Error::last_os_error()
            ));
            return;
        }

        // Mark the filesystem containing "/" — see the module doc
        // comment for why filesystem-wide rather than per-directory.
        let root = match CString::new("/") {
            Ok(c) => c,
            Err(_) => {
                crate::utils::logger::critical("[fanotify] internal error building root path — aborting");
                unsafe { libc::close(fd) };
                return;
            }
        };

        let mark_result = unsafe {
            libc::fanotify_mark(
                fd,
                libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                libc::FAN_CLOSE_WRITE as u64,
                libc::AT_FDCWD,
                root.as_ptr(),
            )
        };

        if mark_result < 0 {
            crate::utils::logger::critical(&format!(
                "[fanotify] fanotify_mark failed (errno {}) — falling back to unattributed file monitoring only.",
                io::Error::last_os_error()
            ));
            unsafe { libc::close(fd) };
            return;
        }

        // Canonicalize every watch path exactly once, up front — not on
        // every event. `std::fs::canonicalize` is a real filesystem
        // syscall; doing it per-event (as an earlier version of this
        // file did) means a real syscall for every watch path on every
        // single fanotify event, which is precisely the wrong place to
        // add overhead: a genuine ransomware write burst is hundreds of
        // events/sec, exactly when this collector needs to stay fast.
        let canonical_watch_paths: Vec<String> = watch_paths
            .iter()
            .map(|w| {
                std::fs::canonicalize(w)
                    .map(|c| c.to_string_lossy().to_string())
                    .unwrap_or_else(|_| w.clone())
            })
            .collect();

        crate::utils::logger::info(&format!(
            "[fanotify] PID-attributed write monitor active (root, {} watch prefix(es) applied client-side)",
            canonical_watch_paths.len()
        ));

        // fanotify_event_metadata records are packed back-to-back in
        // whatever's read from the fd; FAN_EVENT_METADATA_LEN (24 bytes
        // on every architecture this targets) is the fixed header size,
        // but event_len can exceed that for extra info records we don't
        // use here — we always advance by event_len, not the fixed
        // struct size, to stay correctly positioned regardless.
        let metadata_len = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut buf = vec![0u8; 4096];
        let mut consecutive_errors: u32 = 0;

        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

            if n <= 0 {
                let err = io::Error::last_os_error();

                // EINTR (interrupted system call, e.g. by a signal) is
                // common and benign — the standard response is just to
                // retry immediately, no backoff, no log spam.
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }

                // Anything else: back off before retrying, so a
                // persistent failure (fd somehow closed elsewhere, the
                // filesystem going away, ...) degrades to a slow,
                // bounded retry loop instead of a CPU-burning busy loop
                // logging warnings as fast as the CPU allows.
                consecutive_errors += 1;
                let backoff_ms = (200u64.saturating_mul(consecutive_errors as u64)).min(5000);
                crate::utils::logger::warn(&format!(
                    "[fanotify] read failed: {err} — retrying in {backoff_ms}ms (consecutive failures: {consecutive_errors})"
                ));
                std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                continue;
            }
            consecutive_errors = 0;

            let mut offset: usize = 0;
            while offset + metadata_len <= n as usize {
                let meta: libc::fanotify_event_metadata =
                    unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata) };

                // Sanity-check event_len in both directions before
                // trusting it to advance `offset`: too small means a
                // malformed/truncated record; too large would walk
                // `offset` past the bytes actually read, which — left
                // unchecked — risks reprocessing stale buffer contents
                // as if they were a new event on the next read() cycle.
                let remaining = n as usize - offset;
                if meta.event_len < metadata_len as u32 || meta.event_len as usize > remaining {
                    crate::utils::logger::warn(&format!(
                        "[fanotify] malformed event record (event_len={}, remaining={}) — discarding rest of this read",
                        meta.event_len, remaining
                    ));
                    break;
                }

                handle_event(&meta, &tx, &canonical_watch_paths, entropy_sample_bytes);

                offset += meta.event_len as usize;
            }
        }
    }

    fn handle_event(
        meta: &libc::fanotify_event_metadata,
        tx: &EventSender,
        canonical_watch_paths: &[String],
        entropy_sample_bytes: usize,
    ) {
        // FAN_Q_OVERFLOW means events were dropped by the kernel because
        // we weren't reading fast enough — no fd is attached to this
        // record. Log it (it matters — it means we may have missed
        // writes) and move on.
        if meta.mask & libc::FAN_Q_OVERFLOW as u64 != 0 {
            crate::utils::logger::warn(
                "[fanotify] event queue overflow — some file-write events were dropped",
            );
            return;
        }

        if meta.fd < 0 {
            return; // no fd to resolve (shouldn't happen for FAN_CLOSE_WRITE, defensive)
        }

        // The kernel hands us a fresh, our-own fd per event that we're
        // responsible for closing — every return path below must close
        // it exactly once.
        let path = resolve_fd_path(meta.fd);
        unsafe { libc::close(meta.fd) };

        let path = match path {
            Some(p) => p,
            None => return, // file already gone by the time we resolved it — not an error
        };

        // Filesystem-wide marking means we see everything on the root
        // filesystem; only forward events under a configured watch path.
        // `canonical_watch_paths` was resolved once at startup (see
        // `run()`) — this is now a cheap string-prefix check, no
        // filesystem syscall per event.
        if !canonical_watch_paths.is_empty()
            && !canonical_watch_paths.iter().any(|w| path.starts_with(w.as_str()))
        {
            return;
        }

        let pid = if meta.pid > 0 { Some(meta.pid as u32) } else { None };
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let ent = entropy::entropy_of_file(std::path::Path::new(&path), entropy_sample_bytes).unwrap_or(0.0);

        let event = Event::file_write(pid, path, size, ent);
        if tx.try_send(event).is_err() {
            crate::utils::logger::warn("[fanotify] telemetry queue full — dropped a FileWrite event");
        }
    }

    fn resolve_fd_path(fd: i32) -> Option<String> {
        let link = format!("/proc/self/fd/{fd}");
        std::fs::read_link(&link)
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::{is_available, run};

#[cfg(not(target_os = "linux"))]
pub fn is_available() -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
pub fn run(tx: EventSender, watch_paths: Vec<String>, entropy_sample_bytes: usize) {
    let _ = (tx, watch_paths, entropy_sample_bytes);
    // Never actually spawned on this platform (main.rs only spawns this
    // collector when `is_available()` returns true, which is always
    // false here) — present for symmetry with the other collectors.
}
