// GasLight Endpoint Agent
//
// Milestone 1 ("observability core"):
//   - Process start/exit monitoring                    [collector/process.rs]
//   - Filesystem create/write/rename/delete monitoring  [collector/filesystem.rs]
//   - Thread-safe telemetry queue                       [telemetry/queue.rs]
//   - Console + rotating file logging                   [utils/logger.rs]
//   - Live WebSocket stream for a dashboard              [dashboard/websocket.rs]
//
// Milestone 2 ("behavioral engine"), wired in as the real decision
// pipeline in place of Milestone 1's placeholder system-wide scorer:
//   - Per-process state, sliding-window features, explainable scoring,
//     and Allow/Monitor/Alert/Suspend/ProtectFilesystem/Terminate
//     decisions            [behavior/*]
//
// Deception engine, wired in ahead of the behavioral engine so real
// decoys exist before any telemetry starts flowing:
//   - Generates realistic honey files across believable directory
//     structures, tracks them by exact path (replacing Milestone 2's
//     naive substring-marker approach — see deception/metadata.rs),
//     and rotates them periodically so names/content never go stale
//     enough to fingerprint            [deception/*]
//
// Persistence and network monitoring are real on Linux (see
// collector/registry.rs and collector/network.rs for what each one
// actually does). Linux additionally gets collector/fanotify.rs: real,
// PID-attributed file-write events from user space — see that file for
// why fanotify makes this possible without a kernel module.

// Enforcement (Linux-only, opt-in via gaslight.toml's [enforcement]
// section): real fanotify-permission-based write blocking. Everything
// above this collects and decides; this is the one place `block_writes`
// does something other than log — see enforcement/fanotify_guard.rs's
// module doc comment before enabling it, the risk profile is genuinely
// different from everything else in this project.

mod behavior;
mod collector;
mod config;
mod dashboard;
mod deception;
mod driver;
mod enforcement;
mod telemetry;
mod utils;

use behavior::detector::DetectorConfig;
use behavior::engine::BehavioralEngine;
use behavior::feature_extractor::ExtractorConfig;
use config::Settings;
use deception::DeceptionManager;
use driver::SysinfoDriverClient;
use std::thread;
use telemetry::new_queue;

fn main() {
    let settings = Settings::load("gaslight.toml");

    utils::logger::ensure_parent_dir(&settings.logging.log_path);
    utils::logger::init(&settings.logging.log_path, settings.logging.max_log_bytes);

    utils::logger::info("=== GasLight Endpoint Agent starting ===");
    utils::logger::info(&format!(
        "watch_paths={:?} dashboard_port={} entropy_spike_threshold={}",
        settings.file.watch_paths, settings.dashboard.port, settings.detector.entropy_spike_threshold
    ));

    // Ensure the demo watch directory exists so a fresh checkout works out
    // of the box even before the user edits gaslight.toml.
    for path in &settings.file.watch_paths {
        let _ = std::fs::create_dir_all(path);
    }

    // --- Deception engine (deployed before anything starts watching, so
    // the first honeypot touch of the session is never missed) ---
    let mut deception_manager = DeceptionManager::new(settings.deception.clone());
    deception_manager.deploy();
    deception_manager.spawn_rotation_thread();
    let honey_registry = deception_manager.registry_handle();
    utils::logger::info(&format!(
        "[deception] {} decoy(s) live",
        deception_manager.decoy_count()
    ));

    let (tx, rx) = new_queue(4096);

    // --- Collector threads ---
    {
        let tx = tx.clone();
        let interval = settings.process.poll_interval_ms;
        thread::spawn(move || collector::process::run(tx, interval));
    }

    // fanotify (Linux only, needs CAP_SYS_ADMIN/root) gives real
    // PID-attributed file-write events — when it's available, the
    // ordinary filesystem watcher is told to skip emitting its own
    // (unattributed) write events so the two don't double-count the same
    // activity. See collector/fanotify.rs and collector/filesystem.rs.
    let fanotify_available = collector::fanotify::is_available();
    if fanotify_available {
        let tx = tx.clone();
        let watch_paths = settings.file.watch_paths.clone();
        let sample_bytes = settings.file.entropy_sample_bytes;
        thread::spawn(move || collector::fanotify::run(tx, watch_paths, sample_bytes));
    } else {
        utils::logger::info(
            "[fanotify] not available on this platform/privilege level — file writes will be unattributed (see behavior/engine.rs's UNATTRIBUTED_PID note)",
        );
    }
    {
        let tx = tx.clone();
        let watch_paths = settings.file.watch_paths.clone();
        let sample_bytes = settings.file.entropy_sample_bytes;
        thread::spawn(move || collector::filesystem::run(tx, &watch_paths, sample_bytes, fanotify_available));
    }
    {
        let tx = tx.clone();
        thread::spawn(move || collector::registry::run(tx));
    }
    {
        let tx = tx.clone();
        thread::spawn(move || collector::network::run(tx));
    }
    // Original sender no longer needed in main — collectors keep the queue
    // alive via their own clones.
    drop(tx);

    // --- Dashboard WebSocket server ---
    let dashboard_registry = dashboard::websocket::new_registry();
    {
        let dashboard_registry = dashboard_registry.clone();
        let port = settings.dashboard.port;
        thread::spawn(move || dashboard::websocket::start(dashboard_registry, port));
    }

    // --- Enforcement (Linux-only, opt-in) ---
    // Computed once, used for both the thread-spawn decision AND the
    // driver client's block_list below — deliberately the same boolean
    // for both, so `block_writes()` never claims "BLOCK enforced" in a
    // log line when nothing is actually consuming the block list (e.g.
    // config says enabled=true but the process isn't root).
    let enforcement_active = settings.enforcement.enabled && enforcement::fanotify_guard::is_available();
    let block_list = enforcement::new_block_list();
    if settings.enforcement.enabled && !enforcement_active {
        utils::logger::critical(
            "[enforcement] enabled in gaslight.toml but fanotify permission events are unavailable (needs CAP_SYS_ADMIN/root) — falling back to log-only blocking, same as everywhere else",
        );
    }
    if enforcement_active {
        let block_list = block_list.clone();
        let watch_paths = settings.file.watch_paths.clone();
        thread::spawn(move || enforcement::fanotify_guard::run(block_list, watch_paths));
    }

    // --- Behavioral engine (owns all per-process mutable state) ---
    let driver_client = SysinfoDriverClient::new(if enforcement_active { Some(block_list.clone()) } else { None });
    let detector_cfg = DetectorConfig {
        extractor: ExtractorConfig {
            entropy_spike_threshold: settings.detector.entropy_spike_threshold,
        },
        weights: behavior::scoring::ScoringWeights {
            files_per_second: settings.detector.files_per_second_weight,
            entropy: settings.detector.entropy_weight,
            deletes: settings.detector.delete_weight,
            rename_burst: settings.detector.rename_burst_weight,
            honey_file: settings.detector.honey_file_weight,
            registry_persistence: settings.detector.registry_persistence_weight,
        },
    };
    let mut engine = BehavioralEngine::new(detector_cfg, honey_registry.clone());

    utils::logger::info("[behavior] engine online, waiting for events");

    // This blocks the main thread forever, draining the telemetry queue —
    // matches the "Wait forever" step in the architecture doc's main loop,
    // just done as useful work instead of an idle sleep.
    for event in rx.iter() {
        if let telemetry::Event::ProcessExit(e) = &event {
            // PIDs get reused by the OS — a stale block entry left behind
            // after the original (blocked) process exited would
            // incorrectly apply to whatever unrelated process the kernel
            // later hands that PID to. See enforcement/policy.rs.
            enforcement::policy::unblock(&block_list, e.pid);
        }

        let report = engine.ingest(&event, &driver_client);
        let honey_event = classify_honey_event(&event, &honey_registry);

        broadcast_event(&dashboard_registry, &event, report.as_ref(), honey_event.as_ref());

        if let Some(honey_event) = &honey_event {
            utils::logger::critical(&format!(
                "[deception] honeypot {:?} — {} touched by pid={}",
                honey_event.operation,
                honey_event.path,
                honey_event.pid.map(|p| p.to_string()).unwrap_or_else(|| "unknown".to_string())
            ));
        }

        if let Some(report) = &report {
            if report.score >= 50.0 {
                // Warning band and above: worth a line in the main log even
                // though response.rs already logs Alert/Suspend/Terminate
                // on its own — this keeps a single readable timeline of
                // every process that got interesting, regardless of which
                // decision it ultimately received.
                utils::logger::info(&format!(
                    "[behavior] pid={} ({}) score={:.0} risk={} decision={}",
                    report.pid,
                    report.process_name,
                    report.score,
                    report.risk_level,
                    report.decision.as_str()
                ));
            }
        }
    }

    utils::logger::critical(
        "[main] telemetry queue closed unexpectedly — all collectors have exited. Shutting down.",
    );
}

/// Checks a telemetry event against the live deception registry and, if
/// it touched a decoy, returns the explainable `HoneyFileEvent` for the
/// dashboard's Honey File Monitor panel. For renames, checks the
/// destination name first (a rename *into* a decoy-shaped name matters
/// most) and falls back to the source path.
fn classify_honey_event(
    event: &telemetry::Event,
    honey_registry: &deception::SharedHoneyRegistry,
) -> Option<deception::HoneyFileEvent> {
    use deception::{HoneyMonitor, HoneyOperation};
    use telemetry::Event;

    let pid = event.pid();

    match event {
        Event::FileCreate(e) => HoneyMonitor::classify(honey_registry, pid, &e.path, HoneyOperation::Open),
        Event::FileWrite(e) => HoneyMonitor::classify(honey_registry, pid, &e.path, HoneyOperation::Write),
        Event::FileDelete(e) => HoneyMonitor::classify(honey_registry, pid, &e.path, HoneyOperation::Delete),
        Event::FileRename(e) => HoneyMonitor::classify(honey_registry, pid, &e.to, HoneyOperation::Rename)
            .or_else(|| HoneyMonitor::classify(honey_registry, pid, &e.from, HoneyOperation::Rename)),
        Event::ProcessStart(_) | Event::ProcessExit(_) | Event::RegistryWrite(_) | Event::NetworkConnect(_) => None,
    }
}

fn broadcast_event(
    dashboard_registry: &dashboard::websocket::SubscriberRegistry,
    event: &telemetry::Event,
    report: Option<&behavior::DecisionReport>,
    honey_event: Option<&deception::HoneyFileEvent>,
) {
    let payload = serde_json::json!({
        "event": event,
        "report": report,
        "honey_event": honey_event,
    });
    match serde_json::to_string(&payload) {
        Ok(json) => dashboard::websocket::broadcast(dashboard_registry, &json),
        Err(e) => utils::logger::warn(&format!("[main] failed to serialize event: {e}")),
    }
}
