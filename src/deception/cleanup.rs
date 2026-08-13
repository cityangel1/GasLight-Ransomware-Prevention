use crate::deception::honeyfiles::HoneyFileManager;
use crate::deception::monitor::SharedHoneyRegistry;
use crate::deception::templates::{SimpleRng, TemplateKind};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct RotationPolicy {
    pub max_age: Duration,
}

pub struct Cleanup;

impl Cleanup {
    /// Removes every decoy older than `policy.max_age` and immediately
    /// redeploys a fresh one in its place (new name, new timestamp, new
    /// content) — never leaves a location with zero decoys for long, and
    /// never lets a decoy's name/content sit still long enough to become
    /// a fingerprint. See the doc's "Rotation" section (default: 24h).
    pub fn rotate(
        registry: &SharedHoneyRegistry,
        fallback_directory: &PathBuf,
        policy: &RotationPolicy,
        rng: &mut SimpleRng,
        next_honey_id: &mut u64,
    ) {
        let now = now_ms();
        let max_age_ms = policy.max_age.as_millis() as u64;

        // Phase 1 (read lock only): figure out which decoys are stale and
        // grab their real (OS-native) paths from metadata, then drop the
        // lock before doing any file I/O — writes to disk should never
        // happen while holding the lock the ingest loop needs to keep
        // reading. Deliberately uses `meta.real_path`, not a path
        // reconstructed from the normalized lookup key — see the comment
        // on `HoneyMetadata::real_path` for why that would silently break
        // file removal.
        let stale: Vec<PathBuf> = {
            let guard = match registry.read() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard
                .paths()
                .filter_map(|key| {
                    let meta = guard.get_by_key(key)?;
                    if now.saturating_sub(meta.created_at_ms) >= max_age_ms {
                        Some(meta.real_path.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        if stale.is_empty() {
            return;
        }

        crate::utils::logger::info(&format!("[deception] rotating {} stale decoy(s)", stale.len()));

        for path in stale {
            let directory = path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| fallback_directory.clone());

            // Phase 2: remove the stale entry (file + registry) under a
            // short-lived write lock.
            {
                let mut guard = match registry.write() {
                    Ok(g) => g,
                    Err(_) => continue,
                };
                HoneyFileManager::remove_one(&path, &mut guard);
            }

            // Phase 3: deploy a replacement, again under its own
            // short-lived write lock — kept separate from the removal
            // lock above so a failure writing the new file never leaves
            // the removal half-done in a way that's hard to reason about.
            let kind = *rng.pick(TemplateKind::ALL);
            *next_honey_id += 1;

            let mut guard = match registry.write() {
                Ok(g) => g,
                Err(_) => continue,
            };
            HoneyFileManager::deploy_one(&directory, kind, *next_honey_id, rng, &mut guard);
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
