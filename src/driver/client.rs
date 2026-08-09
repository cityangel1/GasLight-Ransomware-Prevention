// Driver client — the agent's side of the "Protection Layer" in the
// architecture doc.
//
// `block_writes()` used to be a permanent no-op everywhere — a logged
// intent with nothing behind it. On Linux, it's now real: see
// `enforcement/fanotify_guard.rs` for how a blocked PID actually gets
// its file opens denied, entirely from user space, no kernel module
// required. On every other platform it's still the logged placeholder,
// same as before — the Windows equivalent needs the kernel filter driver
// in `driver/`, which isn't wired into this agent's IPC yet.

use crate::enforcement::SharedBlockList;
use sysinfo::{Pid, System};

pub trait DriverClient {
    /// Blocks `pid` from opening new files under the enforced watch
    /// paths (Linux, when `[enforcement] enabled = true` in
    /// gaslight.toml and the process has CAP_SYS_ADMIN). Files the
    /// process already had open remain writable — see
    /// `enforcement/fanotify_guard.rs`'s module doc comment for exactly
    /// what this does and doesn't cover. Logs and does nothing further
    /// everywhere enforcement isn't active.
    fn block_writes(&self, pid: u32, reason: &str);

    /// Medium mitigation: pause a process without killing it (used by the
    /// behavioral engine's `Suspend` decision — see `behavior/response.rs`).
    /// Returns true if the OS reports the suspend succeeded.
    fn suspend_process(&self, pid: u32, reason: &str) -> bool;

    /// Hard mitigation: terminate a process outright. Returns true if the
    /// OS reports the kill succeeded.
    fn kill_process(&self, pid: u32, reason: &str) -> bool;
}

/// Default implementation: uses `sysinfo` for kill/suspend, and — when
/// constructed with `Some(block_list)` — a real shared block list that
/// `enforcement::fanotify_guard` reads from to actually deny file opens.
pub struct SysinfoDriverClient {
    block_list: Option<SharedBlockList>,
}

impl SysinfoDriverClient {
    /// Pass `None` to keep `block_writes` as a logged no-op (matches the
    /// old behavior — used on any platform/config where enforcement
    /// isn't active). Pass `Some(list)` — the same handle given to
    /// `enforcement::fanotify_guard::run` — to make it real.
    pub fn new(block_list: Option<SharedBlockList>) -> Self {
        SysinfoDriverClient { block_list }
    }
}

impl DriverClient for SysinfoDriverClient {
    fn block_writes(&self, pid: u32, reason: &str) {
        match &self.block_list {
            Some(list) => {
                crate::enforcement::policy::block(list, pid);
                crate::utils::logger::action(&format!(
                    "[driver] BLOCK enforced — pid {pid} denied further file opens under watched paths ({reason})"
                ));
            }
            None => {
                crate::utils::logger::action(&format!(
                    "[driver] BLOCK requested for pid {pid} ({reason}) — enforcement not active (see gaslight.toml's [enforcement] section), logging only"
                ));
            }
        }
    }

    /// Real on both Unix (SIGSTOP via the `kill` utility) and Windows
    /// (per-thread `SuspendThread` via a Toolhelp snapshot — there's no
    /// single "SuspendProcess" API, this is the same technique Task
    /// Manager and Process Explorer use). Any other target falls back to
    /// a logged no-op.
    #[cfg(unix)]
    fn suspend_process(&self, pid: u32, reason: &str) -> bool {
        use std::process::Command;
        match Command::new("kill").arg("-STOP").arg(pid.to_string()).status() {
            Ok(status) if status.success() => {
                crate::utils::logger::action(&format!(
                    "[driver] SUSPEND succeeded — pid {pid} paused (SIGSTOP) ({reason})"
                ));
                true
            }
            Ok(status) => {
                crate::utils::logger::warn(&format!(
                    "[driver] SUSPEND failed — `kill -STOP {pid}` exited with {status} ({reason})"
                ));
                false
            }
            Err(e) => {
                crate::utils::logger::warn(&format!(
                    "[driver] SUSPEND failed — could not invoke `kill`: {e} ({reason})"
                ));
                false
            }
        }
    }

    #[cfg(windows)]
    fn suspend_process(&self, pid: u32, reason: &str) -> bool {
        // No single "SuspendProcess" Win32 API exists — the standard
        // technique (used by Task Manager's "Suspend" and by Process
        // Explorer) is to enumerate every thread belonging to the target
        // PID via a Toolhelp snapshot and call SuspendThread on each one
        // individually.
        use std::ffi::c_void;

        const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
        const THREAD_SUSPEND_RESUME: u32 = 0x0002;

        #[repr(C)]
        struct ThreadEntry32 {
            dw_size: u32,
            cnt_usage: u32,
            th32_thread_id: u32,
            th32_owner_process_id: u32,
            tp_base_pri: i32,
            tp_delta_pri: i32,
            dw_flags: u32,
        }

        #[link(name = "kernel32")]
        extern "system" {
            fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
            fn Thread32First(snapshot: *mut c_void, entry: *mut ThreadEntry32) -> i32;
            fn Thread32Next(snapshot: *mut c_void, entry: *mut ThreadEntry32) -> i32;
            fn OpenThread(access: u32, inherit_handle: i32, thread_id: u32) -> *mut c_void;
            fn SuspendThread(thread: *mut c_void) -> u32;
            fn CloseHandle(handle: *mut c_void) -> i32;
        }

        // INVALID_HANDLE_VALUE is defined as (HANDLE)(LONG_PTR)-1 — i.e.
        // all bits set, which is what casting -1isize to a pointer gives.
        let invalid_handle = (-1isize) as *mut c_void;

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot.is_null() || snapshot == invalid_handle {
            crate::utils::logger::warn(&format!(
                "[driver] SUSPEND failed — could not snapshot threads for pid {pid} ({reason})"
            ));
            return false;
        }

        let mut entry = ThreadEntry32 {
            dw_size: std::mem::size_of::<ThreadEntry32>() as u32,
            cnt_usage: 0,
            th32_thread_id: 0,
            th32_owner_process_id: 0,
            tp_base_pri: 0,
            tp_delta_pri: 0,
            dw_flags: 0,
        };

        let mut suspended_count = 0u32;
        let mut has_entry = unsafe { Thread32First(snapshot, &mut entry) } != 0;

        while has_entry {
            if entry.th32_owner_process_id == pid {
                let thread_handle = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32_thread_id) };
                if !thread_handle.is_null() {
                    // SuspendThread returns the thread's previous suspend
                    // count on success, or 0xFFFFFFFF (u32::MAX) on failure.
                    if unsafe { SuspendThread(thread_handle) } != u32::MAX {
                        suspended_count += 1;
                    }
                    unsafe { CloseHandle(thread_handle) };
                }
            }
            has_entry = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }

        unsafe { CloseHandle(snapshot) };

        if suspended_count > 0 {
            crate::utils::logger::action(&format!(
                "[driver] SUSPEND succeeded — {suspended_count} thread(s) paused for pid {pid} ({reason})"
            ));
            true
        } else {
            crate::utils::logger::warn(&format!(
                "[driver] SUSPEND found no threads for pid {pid} — already exited? ({reason})"
            ));
            false
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn suspend_process(&self, pid: u32, reason: &str) -> bool {
        crate::utils::logger::warn(&format!(
            "[driver] SUSPEND requested for pid {pid} ({reason}) — no suspend primitive implemented for this platform; logging only"
        ));
        false
    }

    fn kill_process(&self, pid: u32, reason: &str) -> bool {
        let mut sys = System::new_all();
        sys.refresh_all();

        match sys.process(Pid::from_u32(pid)) {
            Some(process) => {
                let killed = process.kill();
                if killed {
                    crate::utils::logger::action(&format!(
                        "[driver] KILL succeeded — pid {pid} terminated ({reason})"
                    ));
                } else {
                    crate::utils::logger::warn(&format!(
                        "[driver] KILL failed — OS refused to terminate pid {pid} ({reason})"
                    ));
                }
                killed
            }
            None => {
                crate::utils::logger::warn(&format!(
                    "[driver] KILL skipped — pid {pid} no longer exists ({reason})"
                ));
                false
            }
        }
    }
}
