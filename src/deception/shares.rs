// Honey shares (Component 5, optional per the doc).
//
// The doc's own framing is explicit: "For a lightweight demo mode, you can
// simulate network shares" — not "create real SMB shares." Real share
// creation is a privileged, Windows-specific operation (NetShareAdd) that
// needs admin rights and, done wrong, is a bigger attack surface than a
// smaller one (an actually-shared decoy is reachable over the network by
// anything that can see the share). Out of scope here, deliberately.
//
// What's implemented instead: ordinary local decoy folders whose
// *display name* (used in logging/dashboard telemetry) looks like a UNC
// path (\\GasLight\Finance), so the demo narrative matches the doc,
// while the actual filesystem object underneath is just a regular local
// honey directory — same monitoring, same policy-table integration, no
// elevated privileges or real network exposure required.

use std::path::{Path, PathBuf};

pub struct HoneyShare {
    pub display_name: String, // e.g. "\\GasLight\Finance"
    pub real_path: PathBuf,
}

pub struct ShareManager;

impl ShareManager {
    pub fn plan(roots: &[PathBuf]) -> Vec<HoneyShare> {
        const SHARE_NAMES: &[&str] = &["Finance", "Payroll", "Accounting"];

        let mut shares = Vec::new();
        for root in roots {
            for name in SHARE_NAMES {
                let real_path = root.join("Shares").join(name);
                shares.push(HoneyShare {
                    display_name: format!("\\\\GasLight\\{name}"),
                    real_path,
                });
            }
        }
        shares
    }
}

/// Directories every planned share needs, for callers (manager.rs) that
/// want a flat list to deploy files into alongside the ordinary honey
/// directories from directories.rs.
pub fn real_paths(shares: &[HoneyShare]) -> Vec<PathBuf> {
    shares.iter().map(|s| s.real_path.clone()).collect()
}

#[allow(dead_code)]
pub fn display_name_for(shares: &[HoneyShare], real_path: &Path) -> Option<&str> {
    shares
        .iter()
        .find(|s| s.real_path == real_path)
        .map(|s| s.display_name.as_str())
}
