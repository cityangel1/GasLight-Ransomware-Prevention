// Deception manager — the top-level object from the doc's Rust sketch:
//
//   pub struct DeceptionManager {
//       honey_files: HoneyFileManager,
//       directories: DirectoryManager,
//       monitor: HoneyMonitor,
//       templates: TemplateEngine,
//   }
//
// Deliberately does NOT detect ransomware, kill processes, or block
// writes — per the doc's "Responsibilities" list, those belong to the
// behavioral engine and the filter driver. This manager's only job is to
// generate believable bait, place it naturally, keep it fresh, and make
// sure the registry that `behavior/engine.rs` reads from stays accurate.

use crate::deception::cleanup::{Cleanup, RotationPolicy};
use crate::deception::config::DeceptionConfig;
use crate::deception::directories::DirectoryManager;
use crate::deception::honeyfiles::HoneyFileManager;
use crate::deception::metadata::HoneyRegistry;
use crate::deception::monitor::SharedHoneyRegistry;
use crate::deception::shares::{self, HoneyShare, ShareManager};
use crate::deception::templates::{SimpleRng, TemplateKind};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

pub struct DeceptionManager {
    registry: SharedHoneyRegistry,
    directories: Vec<PathBuf>,
    shares: Vec<HoneyShare>,
    config: DeceptionConfig,
    next_honey_id: u64,
}

impl DeceptionManager {
    pub fn new(config: DeceptionConfig) -> Self {
        let roots: Vec<PathBuf> = config.roots.iter().map(PathBuf::from).collect();
        let directories = DirectoryManager::plan(&roots);
        let shares = if config.enable_shares {
            ShareManager::plan(&roots)
        } else {
            Vec::new()
        };

        DeceptionManager {
            registry: Arc::new(RwLock::new(HoneyRegistry::new())),
            directories,
            shares,
            config,
            next_honey_id: 0,
        }
    }

    /// Generates and writes the initial set of decoys. Call once at
    /// startup, *before* the collectors/behavioral engine start consuming
    /// telemetry — otherwise the very first honeypot touch of the session
    /// could land before any decoy exists to be touched.
    pub fn deploy(&mut self) {
        let mut rng = SimpleRng::seeded();

        let mut all_dirs = self.directories.clone();
        all_dirs.extend(shares::real_paths(&self.shares));

        let mut registry = match self.registry.write() {
            Ok(g) => g,
            Err(_) => {
                crate::utils::logger::critical("[deception] registry lock poisoned — skipping deployment");
                return;
            }
        };

        let mut deployed = 0usize;
        for dir in &all_dirs {
            for _ in 0..self.config.files_per_directory {
                let kind = *rng.pick(TemplateKind::ALL);
                self.next_honey_id += 1;
                if HoneyFileManager::deploy_one(dir, kind, self.next_honey_id, &mut rng, &mut registry).is_some() {
                    deployed += 1;
                }
            }
        }

        crate::utils::logger::info(&format!(
            "[deception] deployed {} decoy file(s) across {} location(s){}",
            deployed,
            all_dirs.len(),
            if self.shares.is_empty() {
                String::new()
            } else {
                format!(" ({} simulated share(s))", self.shares.len())
            }
        ));
    }

    /// Spawns the background rotation thread and returns immediately; the
    /// thread runs for the lifetime of the process. Must be called after
    /// `deploy()` — it captures `self.next_honey_id` at call time so
    /// rotation-generated IDs continue from wherever the initial
    /// deployment left off, rather than restarting from zero and risking
    /// a collision.
    pub fn spawn_rotation_thread(&self) {
        let registry = self.registry.clone();
        let fallback_directory = self
            .directories
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("."));
        let policy = RotationPolicy {
            max_age: self.config.rotation_duration(),
        };
        let mut next_honey_id = self.next_honey_id;

        thread::spawn(move || {
            let mut rng = SimpleRng::seeded();
            loop {
                // Checking hourly is cheap (a handful of RwLock reads
                // over a small map) and keeps actual rotations close to
                // the configured max_age without needing a precise timer.
                thread::sleep(Duration::from_secs(3600));
                Cleanup::rotate(&registry, &fallback_directory, &policy, &mut rng, &mut next_honey_id);
            }
        });
    }

    /// The shared registry handle the behavioral engine reads from on
    /// every file event. See `behavior/engine.rs`.
    pub fn registry_handle(&self) -> SharedHoneyRegistry {
        self.registry.clone()
    }

    pub fn decoy_count(&self) -> usize {
        self.registry.read().map(|g| g.len()).unwrap_or(0)
    }
}
