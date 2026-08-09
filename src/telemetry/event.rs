use serde::Serialize;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessStart {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image: String,
    pub cmdline: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessExit {
    pub pid: u32,
    pub image: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileWrite {
    pub pid: Option<u32>,
    pub path: String,
    pub size_bytes: u64,
    pub entropy: f64,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileCreate {
    pub pid: Option<u32>,
    pub path: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileRename {
    pub pid: Option<u32>,
    pub from: String,
    pub to: String,
    pub is_suspicious_extension: bool,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileDelete {
    pub pid: Option<u32>,
    pub path: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistryWrite {
    pub key: String,
    pub value_name: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkConnect {
    pub pid: Option<u32>,
    pub destination_ip: String,
    pub port: u16,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum Event {
    ProcessStart(ProcessStart),
    ProcessExit(ProcessExit),
    FileCreate(FileCreate),
    FileWrite(FileWrite),
    FileRename(FileRename),
    FileDelete(FileDelete),
    RegistryWrite(RegistryWrite),
    NetworkConnect(NetworkConnect),
}

impl Event {
    /// Best-effort PID extraction — used by the detector to attribute an
    /// event to a process's running behavioral score. Events with no known
    /// PID (e.g. registry/network in their current stub form) return None.
    pub fn pid(&self) -> Option<u32> {
        match self {
            Event::ProcessStart(e) => Some(e.pid),
            Event::ProcessExit(e) => Some(e.pid),
            Event::FileCreate(e) => e.pid,
            Event::FileWrite(e) => e.pid,
            Event::FileRename(e) => e.pid,
            Event::FileDelete(e) => e.pid,
            Event::RegistryWrite(_) => None,
            Event::NetworkConnect(e) => e.pid,
        }
    }

    pub fn process_start(pid: u32, parent_pid: Option<u32>, image: String, cmdline: String) -> Event {
        Event::ProcessStart(ProcessStart {
            pid,
            parent_pid,
            image,
            cmdline,
            timestamp_ms: now_ms(),
        })
    }

    pub fn process_exit(pid: u32, image: String) -> Event {
        Event::ProcessExit(ProcessExit {
            pid,
            image,
            timestamp_ms: now_ms(),
        })
    }

    pub fn file_create(pid: Option<u32>, path: String) -> Event {
        Event::FileCreate(FileCreate {
            pid,
            path,
            timestamp_ms: now_ms(),
        })
    }

    pub fn file_write(pid: Option<u32>, path: String, size_bytes: u64, entropy: f64) -> Event {
        Event::FileWrite(FileWrite {
            pid,
            path,
            size_bytes,
            entropy,
            timestamp_ms: now_ms(),
        })
    }

    pub fn file_rename(pid: Option<u32>, from: String, to: String) -> Event {
        const SUSPICIOUS_EXTENSIONS: &[&str] = &[
            ".locked", ".encrypted", ".crypto", ".enc", ".crypt", ".ransom", ".wcry", ".wncry",
        ];
        let lower = to.to_lowercase();
        let is_suspicious_extension = SUSPICIOUS_EXTENSIONS.iter().any(|ext| lower.ends_with(ext));
        Event::FileRename(FileRename {
            pid,
            from,
            to,
            is_suspicious_extension,
            timestamp_ms: now_ms(),
        })
    }

    pub fn file_delete(pid: Option<u32>, path: String) -> Event {
        Event::FileDelete(FileDelete {
            pid,
            path,
            timestamp_ms: now_ms(),
        })
    }

    pub fn registry_write(key: String, value_name: String) -> Event {
        Event::RegistryWrite(RegistryWrite {
            key,
            value_name,
            timestamp_ms: now_ms(),
        })
    }

    pub fn network_connect(pid: Option<u32>, destination_ip: String, port: u16) -> Event {
        Event::NetworkConnect(NetworkConnect {
            pid,
            destination_ip,
            port,
            timestamp_ms: now_ms(),
        })
    }
}
