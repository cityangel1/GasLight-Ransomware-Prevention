// Network monitor.
//
// Useful signal (ransomware frequently reaches out to key servers, TOR
// exit nodes, or C2/payment infrastructure right before or during
// encryption). Uses `/proc/net/tcp` (connection table, no PID)
// cross-referenced against every process's `/proc/<pid>/fd/*` entries
// (which PID matches which connection, via the socket's inode number) —
// the same technique `netstat`/`ss` use under the hood. No new crate
// needed, pure `std::fs`.
//
// Any other platform stays a no-op — see the tail of this file.

use crate::telemetry::EventSender;

#[cfg(target_os = "linux")]
pub fn run(tx: EventSender) {
    use crate::telemetry::Event;
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::thread;
    use std::time::Duration;

    const POLL_INTERVAL: Duration = Duration::from_secs(3);

    crate::utils::logger::info(&format!(
        "[network] monitor started — polling /proc/net/tcp every {POLL_INTERVAL:?}"
    ));

    // IPv4 only for now — /proc/net/tcp6's addresses are four
    // byte-order-flipped 32-bit words per address rather than one, which
    // is meaningfully more to get right without a way to test it; IPv4
    // covers the overwhelmingly common case. A clearly-scoped follow-up,
    // not a silent gap.

    // (pid-or-0, remote_addr_raw, remote_port) — dedup key so a
    // long-lived connection doesn't re-fire every poll.
    let mut seen: HashSet<(u32, u32, u16)> = HashSet::new();
    let mut warned_unreadable = false;

    loop {
        let inode_to_pid = build_inode_pid_map();

        match fs::read_to_string("/proc/net/tcp") {
            Ok(content) => {
                for line in content.lines().skip(1) {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() < 10 {
                        continue;
                    }

                    let remote = fields[2];
                    let inode_field = fields[9];

                    let (remote_addr_hex, remote_port_hex) = match remote.split_once(':') {
                        Some(pair) => pair,
                        None => continue,
                    };

                    let remote_port = match u16::from_str_radix(remote_port_hex, 16) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if remote_port == 0 {
                        continue; // listening socket, not an outbound connection
                    }

                    let remote_addr_raw = match u32::from_str_radix(remote_addr_hex, 16) {
                        Ok(a) => a,
                        Err(_) => continue,
                    };

                    let inode: u64 = match inode_field.parse() {
                        Ok(i) => i,
                        Err(_) => continue,
                    };

                    let pid = inode_to_pid.get(&inode).copied();
                    let key = (pid.unwrap_or(0), remote_addr_raw, remote_port);

                    if seen.insert(key) {
                        let event = Event::network_connect(pid, format_ipv4_hex(remote_addr_raw), remote_port);
                        if tx.try_send(event).is_err() {
                            crate::utils::logger::warn(
                                "[network] telemetry queue full — dropped a NetworkConnect event",
                            );
                        }
                    }
                }
            }
            Err(e) => {
                // Only warn once — if /proc/net/tcp is permanently
                // unreadable (unusual container/namespace setup, etc.),
                // repeating this every 3 seconds forever would just be
                // log noise. One clear signal is enough to explain why
                // network telemetry is empty.
                if !warned_unreadable {
                    crate::utils::logger::warn(&format!(
                        "[network] could not read /proc/net/tcp: {e} — network monitoring will stay empty on this system"
                    ));
                    warned_unreadable = true;
                }
            }
        }

        if seen.len() > 10_000 {
            seen.clear();
        }

        thread::sleep(POLL_INTERVAL);
    }
}

/// `/proc/net/tcp` addresses are a native-endian u32 formatted as plain
/// hex text. On a little-endian host, re-splitting that value with
/// `to_le_bytes()` recovers the original dotted-quad octet order — the
/// canonical worked example that confirms this: hex "0100007F" parses to
/// 0x0100007F, whose little-endian bytes are [0x7F, 0x00, 0x00, 0x01] =
/// 127.0.0.1 (loopback), which is exactly what that entry always is.
#[cfg(target_os = "linux")]
fn format_ipv4_hex(raw: u32) -> String {
    let b = raw.to_le_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// Cross-references every visible process's open file descriptors
/// against `/proc/net/tcp`'s socket inodes — the same technique
/// `netstat`/`ss` use. Best-effort: another user's `/proc/<pid>/fd/`
/// directory is only readable without CAP_SYS_PTRACE/root for your own
/// processes, so on an unprivileged run this only attributes your own
/// connections. That's a real (and honest) limitation, not a bug — full
/// system-wide attribution needs root, same as the fanotify collector.
#[cfg(target_os = "linux")]
fn build_inode_pid_map() -> std::collections::HashMap<u64, u32> {
    use std::collections::HashMap;
    use std::fs;

    let mut map = HashMap::new();

    let proc_entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return map,
    };

    for entry in proc_entries.flatten() {
        let pid: u32 = match entry.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue, // not a PID directory (e.g. "self", "net", "cpuinfo", ...)
        };

        let fd_entries = match fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(e) => e,
            Err(_) => continue, // permission denied (another user's process) — skip, not fatal
        };

        for fd_entry in fd_entries.flatten() {
            if let Ok(link) = fs::read_link(fd_entry.path()) {
                let link_str = link.to_string_lossy();
                if let Some(inode_str) = link_str.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        map.insert(inode, pid);
                    }
                }
            }
        }
    }

    map
}

#[cfg(not(target_os = "linux"))]
pub fn run(tx: EventSender) {
    let _ = tx;
    crate::utils::logger::info(
        "[network] network monitor is implemented for Linux only — no-op on this platform",
    );
    // Park this thread rather than busy-looping or exiting, so it behaves
    // like the other collector threads on platforms with an implementation.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
