// Entropy analysis.
//
// Note the split of responsibility with `collector/entropy.rs`: that
// module computes the *raw* Shannon entropy of one file's bytes.
// This module interprets a *stream* of those readings over time for one
// process — the running average the doc's ProcessState wants, plus the
// "don't confuse ordinary compressed formats for encryption" caveat the
// doc calls out explicitly:
//
//   "be careful not to score already-compressed formats the same way.
//    Compare before-and-after content where practical."
//
// True before/after comparison would mean diffing file content across
// writes, which needs more I/O than a lightweight agent should be doing
// per-event. The practical middle ground implemented here: skip the
// "spike" classification for extensions whose *legitimate* baseline
// entropy already sits in the same range as encrypted content.

const HIGH_BASELINE_EXTENSIONS: &[&str] = &[
    ".zip", ".rar", ".7z", ".gz", ".tar.gz", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4",
    ".mp3", ".mov", ".mkv", ".pdf", ".docx", ".xlsx", ".pptx",
];

#[derive(Debug, Clone)]
pub struct EntropyTracker {
    sum: f64,
    count: u64,
    pub last: f64,
    pub last_was_high_baseline: bool,
}

impl EntropyTracker {
    pub fn new() -> Self {
        EntropyTracker {
            sum: 0.0,
            count: 0,
            last: 0.0,
            last_was_high_baseline: false,
        }
    }

    /// Records one file-write's entropy reading. `extension` should
    /// include the leading dot (e.g. `.docx`) — pass `None` if unknown.
    pub fn observe(&mut self, entropy: f64, extension: Option<&str>) {
        self.sum += entropy;
        self.count += 1;
        self.last = entropy;
        self.last_was_high_baseline = extension
            .map(|ext| {
                let ext = ext.to_lowercase();
                HIGH_BASELINE_EXTENSIONS.iter().any(|known| ext.ends_with(known))
            })
            .unwrap_or(false);
    }

    pub fn average(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / self.count as f64
        }
    }

    /// True if the most recent write looks like a genuine encryption
    /// event rather than an already-compressed file being written
    /// normally.
    pub fn is_spike(&self, threshold: f64) -> bool {
        self.last >= threshold && !self.last_was_high_baseline
    }
}

impl Default for EntropyTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_not_a_spike() {
        let mut t = EntropyTracker::new();
        t.observe(3.1, Some(".txt"));
        assert!(!t.is_spike(7.8));
    }

    #[test]
    fn encrypted_content_is_a_spike() {
        let mut t = EntropyTracker::new();
        t.observe(7.95, Some(".xlsx.locked"));
        assert!(t.is_spike(7.8));
    }

    #[test]
    fn ordinary_zip_is_not_flagged_despite_high_entropy() {
        let mut t = EntropyTracker::new();
        t.observe(7.9, Some(".zip"));
        assert!(!t.is_spike(7.8));
    }

    #[test]
    fn average_tracks_across_observations() {
        let mut t = EntropyTracker::new();
        t.observe(2.0, None);
        t.observe(4.0, None);
        assert_eq!(t.average(), 3.0);
    }
}
