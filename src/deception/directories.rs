use std::path::PathBuf;

/// Believable subdirectory trees to scatter honey files under, matching
/// the doc's Component 2 examples (Finance, HR, Backups, Legal,
/// Contracts, Executive, ...) — deliberately ordinary names, not
/// "Honey1" / "DoNotTouch" style giveaways, and deliberately only a
/// handful of files per location rather than one folder dense with
/// decoys (see the doc's "Placement Strategy" and "Avoiding Detection"
/// sections).
const HONEY_SUBDIRS: &[&[&str]] = &[
    &["Documents"],
    &["Finance"],
    &["Finance", "Payroll"],
    &["HR"],
    &["Legal", "Contracts"],
    &["Backups"],
    &["Executive"],
];

pub struct DirectoryManager;

impl DirectoryManager {
    /// Returns the full set of decoy directories to place files under,
    /// rooted at each of `roots`. Doesn't create anything on disk itself
    /// — honeyfiles.rs creates each directory lazily (via
    /// `create_dir_all`) when it writes the first file into it, so a
    /// failure here never leaves an empty, obviously-synthetic directory
    /// with nothing in it.
    pub fn plan(roots: &[PathBuf]) -> Vec<PathBuf> {
        let mut plan = Vec::new();
        for root in roots {
            for subdir_parts in HONEY_SUBDIRS {
                let mut path = root.clone();
                for part in *subdir_parts {
                    path.push(part);
                }
                plan.push(path);
            }
        }
        plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_produces_one_path_per_root_per_subdir() {
        let roots = vec![PathBuf::from("/watched")];
        let plan = DirectoryManager::plan(&roots);
        assert_eq!(plan.len(), HONEY_SUBDIRS.len());
        assert!(plan.iter().any(|p| p.ends_with("Finance/Payroll") || p.to_string_lossy().contains("Finance")));
    }
}
