use crate::deception::metadata::{HoneyMetadata, HoneyRegistry};
use crate::deception::templates::{self, SimpleRng, TemplateKind};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct HoneyFileManager;

impl HoneyFileManager {
    /// Writes one freshly-generated decoy file into `directory`, records
    /// it in `registry`, and returns the path written. Best-effort:
    /// failures (permission denied, disk full, whatever) are logged and
    /// simply skip that one decoy rather than aborting the whole
    /// deployment pass — a partial deployment is still far better than
    /// none.
    pub fn deploy_one(
        directory: &Path,
        kind: TemplateKind,
        honey_id: u64,
        rng: &mut SimpleRng,
        registry: &mut HoneyRegistry,
    ) -> Option<PathBuf> {
        if let Err(e) = std::fs::create_dir_all(directory) {
            crate::utils::logger::warn(&format!(
                "[deception] could not create honey directory {}: {e}",
                directory.display()
            ));
            return None;
        }

        let (filename, content) = templates::generate(kind, rng);
        let path = directory.join(&filename);

        match std::fs::write(&path, &content) {
            Ok(_) => {
                let now = now_ms();
                registry.insert(
                    &path,
                    HoneyMetadata {
                        honey_id,
                        created_at_ms: now,
                        version: 1,
                        last_refresh_ms: now,
                        template_tag: kind.tag().to_string(),
                        is_directory: false,
                        real_path: path.clone(),
                    },
                );
                Some(path)
            }
            Err(e) => {
                crate::utils::logger::warn(&format!(
                    "[deception] failed to write honey file {}: {e}",
                    path.display()
                ));
                None
            }
        }
    }

    /// Removes a decoy from disk and the registry. Used by cleanup.rs
    /// during rotation. Best-effort: if the file is already gone (user
    /// deleted it, ransomware already consumed it, whatever), that's not
    /// treated as an error — the registry entry is removed regardless.
    pub fn remove_one(path: &Path, registry: &mut HoneyRegistry) {
        let _ = std::fs::remove_file(path);
        registry.remove(path);
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
