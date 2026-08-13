// Fanotify PERMISSION-event enforcement (Linux-only) — the only place in
// this codebase where `block_writes()` does something real instead of
// logging an intent (see driver/client.rs).
//
// ============================================================================
// READ THIS BEFORE ENABLING IT (gaslight.toml: [enforcement] enabled = true)
// ============================================================================
//
// `FAN_OPEN_PERM` events pause the calling process's `open()` syscall
// until this code writes a response back — ALLOW or DENY. If a response
// is never sent, that `open()` call hangs *forever*. This is a
// structurally more dangerous failure mode than anything else in this
// project: a bug here can silently hang any process trying to open a
// file under a watched path, indefinitely, with no crash and no obvious
// error message pointing at this agent.
//
// Mitigations built into this file, in priority order:
//   1. Every code path guarantees exactly one response is sent. There is
//      no early-return, no `?`, no panic-risking operation between
//      "event received" and "response sent" — see `handle_event`, which
//      computes the response value first (defaulting to ALLOW under any
//      uncertainty) and cannot exit without sending it.
//   2. Marks are scoped to the exact configured `watch_paths` only — NOT
//      filesystem-wide (unlike the read-only notification collector in
//      `collector/fanotify.rs`, where filesystem-wide marking is safe
//      because the worst case is an extra log line, not a hang). A bug
//      here can only affect opens under the small watched/demo folder,
//      not the whole system.
//   3. Fail-open by design: the only way to get FAN_DENY is an explicit
//      PID match in the block list. Everything else — including any
//      internal error resolving state — defaults to FAN_ALLOW.
//   4. Off by default. `gaslight.toml`'s `[enforcement] enabled` must be
//      explicitly set to `true`. This is not something that should turn
//      on quietly as a side effect of upgrading.
//
// SCOPE: only denies *new* file opens for a blocked PID under a watched
// path. A file the process already had open before being blocked can
// still be written to via that existing file descriptor — fanotify
// permission events fire at open() time, not per write() on an
// already-open fd. Combined with `suspend_process`/`kill_process` (which
// *do* stop further activity on existing fds), this is still a
// meaningful layer, just not an absolute guarantee on its own.

use crate::enforcement::policy::{is_blocked, SharedBlockList};

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::ffi::CString;
    use std::io;

    const FAN_ALLOW: u32 = 0x01;
    const FAN_DENY: u32 = 0x02;

    #[repr(C)]
    struct FanotifyResponse {
        fd: i32,
        response: u32,
    }

    /// Cheap capability probe — same shape as `collector::fanotify::is_available`.
    pub fn is_available() -> bool {
        unsafe {
            let fd = libc::fanotify_init(libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC, libc::O_RDONLY as u32);
            if fd < 0 {
                false
            } else {
                libc::close(fd);
                true
            }
        }
    }

    pub fn run(block_list: SharedBlockList, watch_paths: Vec<String>) {
        let fd = unsafe { libc::fanotify_init(libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC, libc::O_RDONLY as u32) };
        if fd < 0 {
            crate::utils::logger::critical(&format!(
                "[enforcement] fanotify_init failed (errno {}) — needs CAP_SYS_ADMIN (root). Enforcement disabled; ProtectFilesystem/Suspend/Terminate decisions will still log and still suspend/kill, just won't block new file opens.",
                io::Error::last_os_error()
            ));
            return;
        }

        // Deliberately per-path, NOT filesystem-wide — see the module
        // doc comment. Non-recursive: only the exact configured paths,
        // not their subdirectories, are marked. New directories created
        // after startup under a watched path won't get permission
        // enforcement — a real, honest limitation, not a silent gap
        // (the read-only notification collector still sees everything
        // there; only *blocking* is narrower in scope).
        let mut marked_any = false;
        for path in &watch_paths {
            let cpath = match CString::new(path.as_str()) {
                Ok(c) => c,
                Err(_) => {
                    crate::utils::logger::warn(&format!(
                        "[enforcement] watch path contains a NUL byte, skipping: {path}"
                    ));
                    continue;
                }
            };

            let result = unsafe {
                libc::fanotify_mark(
                    fd,
                    libc::FAN_MARK_ADD,
                    libc::FAN_OPEN_PERM as u64,
                    libc::AT_FDCWD,
                    cpath.as_ptr(),
                )
            };

            if result < 0 {
                crate::utils::logger::warn(&format!(
                    "[enforcement] failed to mark {path} for permission enforcement (errno {}) — this path won't be enforced",
                    io::Error::last_os_error()
                ));
            } else {
                marked_any = true;
                crate::utils::logger::info(&format!("[enforcement] enforcing opens under {path}"));
            }
        }

        if !marked_any {
            crate::utils::logger::warn(
                "[enforcement] no watch paths could be marked — enforcement is active but has nothing to enforce",
            );
        }

        crate::utils::logger::action(
            "[enforcement] fanotify permission enforcement ACTIVE — blocked PIDs will have new file opens under watched paths denied",
        );

        let metadata_len = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut buf = vec![0u8; 4096];
        let mut consecutive_errors: u32 = 0;

        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

            if n <= 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                consecutive_errors += 1;
                let backoff_ms = (200u64.saturating_mul(consecutive_errors as u64)).min(5000);
                crate::utils::logger::warn(&format!(
                    "[enforcement] read failed: {err} — retrying in {backoff_ms}ms"
                ));
                std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                continue;
            }
            consecutive_errors = 0;

            let mut offset: usize = 0;
            while offset + metadata_len <= n as usize {
                let meta: libc::fanotify_event_metadata =
                    unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata) };

                let remaining = n as usize - offset;
                if meta.event_len < metadata_len as u32 || meta.event_len as usize > remaining {
                    crate::utils::logger::warn(
                        "[enforcement] malformed event record — discarding rest of this read",
                    );
                    break;
                }

                handle_event(fd, &meta, &block_list);

                offset += meta.event_len as usize;
            }
        }
    }

    /// Handles exactly one permission event. Structured so a response is
    /// always sent for any event that has a real fd attached — this is
    /// the single most important correctness property in this file.
    fn handle_event(group_fd: i32, meta: &libc::fanotify_event_metadata, block_list: &SharedBlockList) {
        // Overflow records carry no fd and represent no pending
        // decision — nothing to respond to, just a signal that some
        // *notification* events elsewhere may have been dropped.
        if meta.mask & libc::FAN_Q_OVERFLOW as u64 != 0 {
            crate::utils::logger::warn("[enforcement] event queue overflow");
            return;
        }

        if meta.fd < 0 {
            return; // no fd, nothing to respond to (defensive — shouldn't happen for OPEN_PERM)
        }

        // Decide the response FIRST, before anything else, with ALLOW as
        // the unconditional default. The only path to DENY is an
        // explicit, positive PID match against the block list.
        let response = if meta.pid > 0 && is_blocked(block_list, meta.pid as u32) {
            crate::utils::logger::action(&format!(
                "[enforcement] DENIED file open — pid {} is blocked",
                meta.pid
            ));
            FAN_DENY
        } else {
            FAN_ALLOW
        };

        let reply = FanotifyResponse {
            fd: meta.fd,
            response,
        };

        // Responses are written to the *group* fd (the one fanotify_init
        // returned), not the per-event fd — that distinction matters and
        // is easy to get backwards.
        let reply_bytes = unsafe {
            std::slice::from_raw_parts(
                &reply as *const FanotifyResponse as *const u8,
                std::mem::size_of::<FanotifyResponse>(),
            )
        };
        let written = unsafe {
            libc::write(group_fd, reply_bytes.as_ptr() as *const libc::c_void, reply_bytes.len())
        };
        if written < 0 {
            crate::utils::logger::warn(&format!(
                "[enforcement] failed to write permission response for pid {}: {} — the calling process's open() may hang",
                meta.pid,
                io::Error::last_os_error()
            ));
        }

        // Always close the event's own fd, regardless of whether the
        // response write above succeeded — it's a separate resource from
        // the response itself and leaking it is a slower-burning but
        // real problem (fd exhaustion in a long-running agent).
        unsafe { libc::close(meta.fd) };
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::{is_available, run};

#[cfg(not(target_os = "linux"))]
pub fn is_available() -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
pub fn run(block_list: SharedBlockList, watch_paths: Vec<String>) {
    let _ = (block_list, watch_paths);
    // Never actually spawned on this platform — main.rs only spawns this
    // collector when is_available() returns true.
}
