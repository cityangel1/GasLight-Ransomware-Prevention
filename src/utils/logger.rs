use chrono::Local;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Critical,
    Action,
}

impl Level {
    fn as_str(&self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Warn => "WARNING",
            Level::Critical => "CRITICAL",
            Level::Action => "ACTION",
        }
    }
}

struct LoggerState {
    file: Mutex<File>,
    path: String,
    max_bytes: u64,
}

static LOGGER: OnceLock<LoggerState> = OnceLock::new();

/// Must be called once at startup before any `log()` calls, though `log()`
/// will still work (falling back to a default path) if you forget.
pub fn init(log_path: &str, max_bytes: u64) {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .unwrap_or_else(|e| panic!("[logger] Could not open log file {log_path}: {e}"));

    let _ = LOGGER.set(LoggerState {
        file: Mutex::new(file),
        path: log_path.to_string(),
        max_bytes,
    });
}

fn state() -> &'static LoggerState {
    LOGGER.get_or_init(|| {
        let path = "./gaslight-agent.log".to_string();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("[logger] Could not open fallback log file");
        LoggerState {
            file: Mutex::new(file),
            path,
            max_bytes: 5 * 1024 * 1024,
        }
    })
}

/// Rotates the active log to `<path>.1` once it exceeds `max_bytes`.
/// Best-effort: any I/O error here is logged to stderr but never panics,
/// since a rotation failure shouldn't take the whole agent down.
fn rotate_if_needed(st: &LoggerState, file: &mut File) {
    use std::io::{Seek, SeekFrom};

    if let Ok(meta) = file.metadata() {
        if meta.len() >= st.max_bytes {
            let backup = format!("{}.1", st.path);
            // Copy current contents out to the backup, then truncate the
            // active handle in place. This deliberately avoids close/rename,
            // which can fail on Windows while the file is held open.
            if fs::copy(&st.path, &backup).is_ok() {
                let _ = file.set_len(0);
                let _ = file.seek(SeekFrom::Start(0));
            }
        }
    }
}

/// Writes one structured line to both stdout and the rotating log file.
/// Format: `[HH:MM:SS] LEVEL  message`
pub fn log(level: Level, message: &str) {
    let ts = Local::now().format("%H:%M:%S%.3f");
    let line = format!("[{ts}] {:<9} {message}\n", level.as_str());

    print!("{line}");
    let _ = std::io::stdout().flush();

    let st = state();
    if let Ok(mut file) = st.file.lock() {
        rotate_if_needed(st, &mut file);
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
    }
}

pub fn info(msg: &str) {
    log(Level::Info, msg);
}
pub fn warn(msg: &str) {
    log(Level::Warn, msg);
}
pub fn critical(msg: &str) {
    log(Level::Critical, msg);
}
pub fn action(msg: &str) {
    log(Level::Action, msg);
}

#[allow(dead_code)]
pub fn ensure_parent_dir(log_path: &str) {
    if let Some(parent) = Path::new(log_path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
}
