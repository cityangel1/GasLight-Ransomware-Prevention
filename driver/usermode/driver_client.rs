//! GasLight filter driver client (user mode).
//!
//! Talks to the kernel driver's `\GasLightPort` communication port via
//! `FilterConnectCommunicationPort` / `FilterSendMessage` (from `fltlib`,
//! the standard Win32 API for minifilter <-> user-mode IPC — see
//! `communication.c` on the kernel side for the matching implementation).
//!
//! WIRE FORMAT: message structs here are `#[repr(C)]` and must stay
//! byte-for-byte compatible with `GL_SET_POLICY_MESSAGE` /
//! `GL_REMOVE_POLICY_MESSAGE` in `include/structures.h`. If you change one
//! side, change the other.
//!
//! INTEGRATION NOTE: this is a standalone, self-contained client — it is
//! *not* wired into the main `gaslight-agent` crate's `DriverClient` trait
//! (`src/driver/client.rs`) yet. That trait's `block_writes()` and
//! `suspend_process()` don't currently take a PID, because they predate
//! this kernel driver and were designed around `SysinfoDriverClient`'s
//! process-wide actions. The kernel driver's actual protection model is
//! inherently per-PID (see the policy table in policy.c), so wiring this
//! in properly means extending `DriverClient`'s signatures to carry a PID
//! consistently — real surgery on code from an earlier milestone, not
//! something to bolt on silently. Left as a clearly-scoped follow-up
//! rather than a half-correct integration. In the meantime this file
//! works standalone: `FilterDriverClient::connect()`, then
//! `.set_policy(pid, policy)` / `.remove_policy(pid)`.
//!
//! Only compiles on Windows — `fltlib` and the communication port concept
//! are Windows-specific.

#![cfg(windows)]

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

/// Mirrors `GL_POLICY` in `include/structures.h` exactly — same variants,
/// same order, same discriminant values.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Allow = 0,
    Monitor = 1,
    Block = 2,
    Redirect = 3,
    Terminate = 4,
}

/// Mirrors `GL_MESSAGE_TYPE` in `include/structures.h`.
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
enum MessageType {
    SetPolicy = 1,
    RemovePolicy = 2,
    // EnforcementEvent = 3 is kernel -> user mode only; not sent from here.
}

/// Mirrors `GL_SET_POLICY_MESSAGE` byte-for-byte: three 4-byte fields, all
/// naturally aligned, no padding.
#[repr(C)]
struct SetPolicyMessage {
    message_type: u32,
    pid: u32,
    policy: u32,
}

/// Mirrors `GL_REMOVE_POLICY_MESSAGE` byte-for-byte.
#[repr(C)]
struct RemovePolicyMessage {
    message_type: u32,
    pid: u32,
}

const FILTER_PORT_NAME: &str = "\\GasLightPort";

// --- Raw FFI surface -------------------------------------------------
//
// Deliberately hand-declared rather than pulling in the `windows` or
// `windows-sys` crate: this file only needs three functions, and keeping
// the FFI surface this small makes it easy to audit against the MSDN
// signatures by eye (which matters since none of this could be
// compile-checked in the environment that wrote it — see the top-level
// README's caveat).

#[allow(non_snake_case)]
extern "system" {
    // fltuser.h / FltLib.lib
    fn FilterConnectCommunicationPort(
        lpFilterPortName: *const u16,
        dwOptions: u32,
        lpContext: *const c_void,
        wSizeOfContext: u16,
        lpSecurityAttributes: *const c_void,
        hPort: *mut *mut c_void,
    ) -> i32; // HRESULT

    fn FilterSendMessage(
        hPort: *mut c_void,
        lpInBuffer: *const c_void,
        dwInBufferSize: u32,
        lpOutBuffer: *mut c_void,
        dwOutBufferSize: u32,
        lpBytesReturned: *mut u32,
    ) -> i32; // HRESULT
}

#[allow(non_snake_case)]
extern "system" {
    // kernel32.dll
    fn CloseHandle(hObject: *mut c_void) -> i32; // BOOL
}

fn hresult_to_io_result(hr: i32, what: &str) -> io::Result<()> {
    // HRESULT S_OK == 0. Anything else is a failure; we don't attempt to
    // decode the specific facility/code, just surface it for logging.
    if hr == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("{what} failed, HRESULT=0x{hr:08X}"),
        ))
    }
}

fn to_wide_null_terminated(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// A connected handle to the GasLight filter driver's communication port.
pub struct FilterDriverClient {
    port: *mut c_void,
}

// The port handle is only ever used through FilterSendMessage, which is
// documented as safe to call from multiple threads on the same handle
// (it's a thin wrapper over an I/O completion-style kernel call) — safe
// to mark Send. Not marking Sync: serialize concurrent senders behind a
// Mutex at the call site if needed, rather than assuming un-synchronized
// concurrent sends are fine.
unsafe impl Send for FilterDriverClient {}

impl FilterDriverClient {
    /// Connects to `\GasLightPort`. Fails if the driver isn't loaded, or
    /// if another agent instance is already connected (the driver only
    /// accepts one client at a time — see `GlpPortConnectNotify` in
    /// communication.c).
    pub fn connect() -> io::Result<Self> {
        let port_name = to_wide_null_terminated(FILTER_PORT_NAME);
        let mut port: *mut c_void = ptr::null_mut();

        let hr = unsafe {
            FilterConnectCommunicationPort(
                port_name.as_ptr(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                &mut port,
            )
        };

        hresult_to_io_result(hr, "FilterConnectCommunicationPort")?;

        Ok(FilterDriverClient { port })
    }

    /// Tells the driver what policy to enforce for `pid` going forward.
    /// Idempotent — safe to call again to escalate (e.g. Monitor -> Block)
    /// or to re-affirm the same policy.
    pub fn set_policy(&self, pid: u32, policy: Policy) -> io::Result<()> {
        let msg = SetPolicyMessage {
            message_type: MessageType::SetPolicy as u32,
            pid,
            policy: policy as u32,
        };

        self.send(&msg)
    }

    /// Tells the driver to stop tracking `pid` (call this on process
    /// exit — PIDs get reused, and a stale Block entry could otherwise
    /// wrongly apply to a completely unrelated future process).
    pub fn remove_policy(&self, pid: u32) -> io::Result<()> {
        let msg = RemovePolicyMessage {
            message_type: MessageType::RemovePolicy as u32,
            pid,
        };

        self.send(&msg)
    }

    fn send<T>(&self, message: &T) -> io::Result<()> {
        let mut bytes_returned: u32 = 0;

        let hr = unsafe {
            FilterSendMessage(
                self.port,
                message as *const T as *const c_void,
                std::mem::size_of::<T>() as u32,
                ptr::null_mut(),
                0,
                &mut bytes_returned,
            )
        };

        hresult_to_io_result(hr, "FilterSendMessage")
    }
}

impl Drop for FilterDriverClient {
    fn drop(&mut self) {
        if !self.port.is_null() {
            unsafe {
                CloseHandle(self.port);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_structs_match_kernel_wire_size() {
        // GL_SET_POLICY_MESSAGE: three 4-byte C enum/ULONG fields, no
        // padding expected on any common ABI.
        assert_eq!(std::mem::size_of::<SetPolicyMessage>(), 12);
        // GL_REMOVE_POLICY_MESSAGE: two 4-byte fields.
        assert_eq!(std::mem::size_of::<RemovePolicyMessage>(), 8);
    }
}
