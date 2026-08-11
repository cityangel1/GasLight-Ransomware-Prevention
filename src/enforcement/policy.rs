// Enforcement policy state.
//
// Deliberately minimal: a set of "currently blocked" PIDs, not a richer
// per-path policy table. The Windows filter driver (driver/policy.c) has
// a proper Allow/Monitor/Block/Redirect/Terminate table because it's
// enforcing fine-grained decisions from a separate kernel module. Here,
// the enforcement decision is binary and already made by
// `behavior/response.rs` before this is ever touched: a PID is either
// blocked from opening files under the watched paths, or it isn't. A
// `HashSet<u32>` is the simplest thing that's still correct, and simple
// is what you want in the one subsystem where a bug's failure mode is
// "some process's file open hangs forever" (see fanotify_guard.rs's
// module doc comment for why that's the risk being managed here).

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

pub type SharedBlockList = Arc<RwLock<HashSet<u32>>>;

pub fn new_block_list() -> SharedBlockList {
    Arc::new(RwLock::new(HashSet::new()))
}

pub fn block(list: &SharedBlockList, pid: u32) {
    if let Ok(mut guard) = list.write() {
        guard.insert(pid);
    }
}

/// Called on process exit — critical for correctness, not just cleanup.
/// PIDs get reused by the OS; a stale block entry left behind after the
/// original (malicious) process exited would incorrectly apply to
/// whatever unrelated process the kernel later reuses that PID for.
pub fn unblock(list: &SharedBlockList, pid: u32) {
    if let Ok(mut guard) = list.write() {
        guard.remove(&pid);
    }
}

pub fn is_blocked(list: &SharedBlockList, pid: u32) -> bool {
    list.read().map(|guard| guard.contains(&pid)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_and_unblock_round_trip() {
        let list = new_block_list();
        assert!(!is_blocked(&list, 42));
        block(&list, 42);
        assert!(is_blocked(&list, 42));
        unblock(&list, 42);
        assert!(!is_blocked(&list, 42));
    }

    #[test]
    fn unblocking_an_untracked_pid_is_a_harmless_no_op() {
        let list = new_block_list();
        unblock(&list, 999); // never blocked — must not panic
        assert!(!is_blocked(&list, 999));
    }
}
