// Network monitor.
//
// Useful signal (ransomware frequently reaches out to key servers, TOR
// exit nodes, or C2/payment infrastructure right before or during
// encryption). Implemented for real on both platforms this project
// targets:
//   - Windows: `GetExtendedTcpTable` (iphlpapi.dll) — connections come
//     with their owning PID built in.
//   - Linux: `/proc/net/tcp` (connection table, no PID) cross-referenced
//     against every process's `/proc/<pid>/fd/*` entries (which PID
//     matches which connection, via the socket's inode number) — the
//     same technique `netstat`/`ss` use under the hood. No new crate
//     needed, pure `std::fs`.
//
// Any other platform stays a no-op — see the tail of this file.

use crate::telemetry::EventSender;

#[cfg(windows)]
pub fn run(tx: EventSender) {
    use crate::telemetry::Event;
    use std::collections::HashSet;
    use std::ffi::c_void;
    use std::thread;
    use std::time::Duration;

    const POLL_INTERVAL: Duration = Duration::from_secs(3);
    const AF_INET: u32 = 2;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const NO_ERROR: u32 = 0;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibTcpRowOwnerPid {
        state: u32,
        local_addr: u32,
        local_port: u32,
        remote_addr: u32,
        remote_port: u32,
        owning_pid: u32,
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            tcp_table: *mut c_void,
            size: *mut u32,
            order: i32,
            af: u32,
            table_class: u32,
            reserved: u32,
        ) -> u32;
    }

    fn format_ipv4(raw: u32) -> String {
        // The DWORD's in-memory bytes (little-endian host) are already
        // the four address octets in order — see the module doc comment
        // for the worked example confirming this.
        let b = raw.to_le_bytes();
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }

    fn read_port(raw: u32) -> u16 {
        // Low 16 bits hold the port in network byte order.
        u16::from_be((raw & 0xFFFF) as u16)
    }

    crate::utils::logger::info(&format!(
        "[network] monitor started — polling established TCP connections every {POLL_INTERVAL:?}"
    ));

    let mut seen: HashSet<(u32, u32, u16, u32)> = HashSet::new(); // (pid, remote_addr, remote_port, local_port)

    loop {
        // First call: pass a null buffer to learn the required size.
        let mut size: u32 = 0;
        let ret = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };

        if ret != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            crate::utils::logger::warn(&format!(
                "[network] GetExtendedTcpTable size query failed (ret={ret}) — retrying next cycle"
            ));
            thread::sleep(POLL_INTERVAL);
            continue;
        }

        // Allocate as Vec<u32> rather than Vec<u8> so the buffer is
        // guaranteed 4-byte aligned for the MibTcpRowOwnerPid reads below
        // — a Vec<u8> allocation's *type* only guarantees 1-byte
        // alignment even though most allocators happen to over-align in
        // practice, which isn't something safe code should rely on.
        let word_count = (size as usize + 3) / 4;
        let mut buffer: Vec<u32> = vec![0u32; word_count];

        let ret = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut c_void,
                &mut size,
                0,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };

        if ret != NO_ERROR {
            crate::utils::logger::warn(&format!(
                "[network] GetExtendedTcpTable fetch failed (ret={ret}) — retrying next cycle"
            ));
            thread::sleep(POLL_INTERVAL);
            continue;
        }

        let num_entries = buffer[0] as usize;
        // SAFETY: `buffer` was sized from the exact byte count
        // GetExtendedTcpTable itself reported as required, the call
        // above returned NO_ERROR (meaning it filled `num_entries` full
        // rows starting right after the header DWORD), and the pointer
        // is 4-byte aligned because `buffer` is a `Vec<u32>` — matching
        // `MibTcpRowOwnerPid`'s alignment requirement exactly.
        let rows: &[MibTcpRowOwnerPid] = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().add(1) as *const MibTcpRowOwnerPid, num_entries)
        };

        for row in rows {
            if read_port(row.remote_port) == 0 {
                continue; // listening socket, not an outbound connection
            }

            let key = (row.owning_pid, row.remote_addr, read_port(row.remote_port), read_port(row.local_port));
            if seen.insert(key) {
                let pid = if row.owning_pid == 0 { None } else { Some(row.owning_pid) };
                let event = Event::network_connect(pid, format_ipv4(row.remote_addr), read_port(row.remote_port));
                if tx.try_send(event).is_err() {
                    crate::utils::logger::warn(
                        "[network] telemetry queue full — dropped a NetworkConnect event",
                    );
                }
            }
        }

        // Bound memory growth — a long-running agent shouldn't accumulate
        // every connection ever seen forever. Simple full reset rather
        // than a time-windowed structure; the cost is that a connection
        // which drops and immediately reconnects after a reset could
        // re-fire once more than strictly necessary, which is harmless
        // for a telemetry signal like this.
        if seen.len() > 10_000 {
            seen.clear();
        }

        thread::sleep(POLL_INTERVAL);
    }
}

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

#[cfg(not(any(windows, target_os = "linux")))]
pub fn run(tx: EventSender) {
    let _ = tx;
    crate::utils::logger::info(
        "[network] network monitor implemented for Windows and Linux only — no-op on this platform",
    );
    // Park this thread rather than busy-looping or exiting, so it behaves
    // like the other collector threads on platforms with an implementation.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
