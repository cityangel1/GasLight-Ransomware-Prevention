use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct FileConfig {
    pub watch_paths: Vec<String>,
    pub entropy_sample_bytes: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProcessConfig {
    pub poll_interval_ms: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DetectorConfig {
    // Weights matching the worked example in the behavioral-engine
    // architecture doc (max raw total = 125, normalized to 0-100).
    pub files_per_second_weight: f32,
    pub entropy_weight: f32,
    pub delete_weight: f32,
    pub rename_burst_weight: f32,
    pub honey_file_weight: f32,
    pub registry_persistence_weight: f32,
    // Shannon entropy at/above this is treated as a genuine encryption
    // spike (subject to the compressed-format baseline check — see
    // behavior/entropy.rs).
    pub entropy_spike_threshold: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DashboardConfig {
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    pub log_path: String,
    pub max_log_bytes: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EnforcementConfig {
    /// Off by default, deliberately — real fanotify-permission-based
    /// write blocking (see enforcement/fanotify_guard.rs). Must be
    /// explicitly opted into after reading that file's module doc
    /// comment on the risk: a bug here can hang a process's file open
    /// indefinitely, not just fail to protect it.
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub file: FileConfig,
    pub process: ProcessConfig,
    pub detector: DetectorConfig,
    pub dashboard: DashboardConfig,
    pub logging: LoggingConfig,
    pub deception: crate::deception::DeceptionConfig,
    pub enforcement: EnforcementConfig,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            file: FileConfig {
                watch_paths: vec!["./watched".to_string()],
                entropy_sample_bytes: 65536,
            },
            process: ProcessConfig {
                poll_interval_ms: 500,
            },
            detector: DetectorConfig {
                files_per_second_weight: 25.0,
                entropy_weight: 20.0,
                delete_weight: 15.0,
                rename_burst_weight: 15.0,
                honey_file_weight: 40.0,
                registry_persistence_weight: 10.0,
                entropy_spike_threshold: 7.8,
            },
            dashboard: DashboardConfig { port: 7878 },
            logging: LoggingConfig {
                log_path: "./gaslight-agent.log".to_string(),
                max_log_bytes: 5 * 1024 * 1024,
            },
            deception: crate::deception::DeceptionConfig::default(),
            enforcement: EnforcementConfig { enabled: false },
        }
    }
}

impl Settings {
    /// Loads `gaslight.toml` from the given path if it exists; otherwise
    /// falls back to built-in defaults. A missing config file is not an
    /// error — it's a normal first-run state.
    pub fn load(path: &str) -> Settings {
        if Path::new(path).exists() {
            match fs::read_to_string(path) {
                Ok(contents) => match toml::from_str::<Settings>(&contents) {
                    Ok(settings) => {
                        return settings;
                    }
                    Err(e) => {
                        eprintln!(
                            "[config] Failed to parse {path}: {e}. Falling back to defaults."
                        );
                    }
                },
                Err(e) => {
                    eprintln!("[config] Failed to read {path}: {e}. Falling back to defaults.");
                }
            }
        }
        Settings::default()
    }
}
