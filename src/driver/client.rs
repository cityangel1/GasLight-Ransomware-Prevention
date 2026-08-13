// Driver client — the agent's side of the "Protection Layer" in the
// architecture doc.
//
// `block_writes()` used to be a permanent no-op — a logged intent with
// nothing behind it. It's now real: see `enforcement/fanotify_guard.rs`
// for how a blocked PID actually gets its file opens denied, entirely
// from user space, no kernel module required.

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

    /// Real on Unix (SIGSTOP via the `kill` utility). Any other target
    /// falls back to a logged no-op.
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

    #[cfg(not(unix))]
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
