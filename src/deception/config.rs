use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct DeceptionConfig {
    /// Root folders to scatter decoys under — typically the same paths
    /// the file monitor already watches (`file.watch_paths` in
    /// gaslight.toml), so a decoy touch and a real-protected-folder touch
    /// get equal priority and equal visibility.
    pub roots: Vec<String>,
    /// How many honey files to place per generated directory.
    pub files_per_directory: usize,
    /// Whether to also deploy simulated honey shares (see shares.rs).
    pub enable_shares: bool,
    /// Rotation interval in hours — the doc's default is 24.
    pub rotation_hours: u64,
}

impl Default for DeceptionConfig {
    fn default() -> Self {
        DeceptionConfig {
            roots: vec!["./watched".to_string()],
            files_per_directory: 2,
            enable_shares: false,
            rotation_hours: 24,
        }
    }
}

impl DeceptionConfig {
    pub fn rotation_duration(&self) -> Duration {
        Duration::from_secs(self.rotation_hours.saturating_mul(3600))
    }
}
