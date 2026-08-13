# GasLight Endpoint Agent

The observability core *and* the behavioral engine from the GasLight
architecture docs — telemetry collection feeding a real, explainable,
per-process risk-scoring pipeline, now with real (opt-in) enforcement.

> **Linux-only.** The public site, install script, and all active
> development target Linux specifically — see
> `scripts/install-linux.sh` and `website/get-linux.html`. Live site:
> [gaslightv1.vercel.app](https://gaslightv1.vercel.app/). Source:
> [github.com/cityangel1/GasLight-Ransomware-Prevention](https://github.com/cityangel1/GasLight-Ransomware-Prevention).

## Scope: Milestones 1 + 2

**Milestone 1 — observability core:**

- [x] Process start/exit detection
- [x] File create / write / rename / delete monitoring
- [x] Thread-safe telemetry queue
- [x] Console + rotating log file
- [x] Live WebSocket stream for a dashboard (`ws://127.0.0.1:7878`)

**Milestone 2 — behavioral engine** (`src/behavior/`), replacing
Milestone 1's placeholder system-wide scorer:

- [x] Per-process `ProcessState` ("medical chart") with sliding time
      windows — never lifetime totals — for writes, renames, deletes
- [x] Feature extraction (files/sec, rename rate, delete rate, entropy
      spike detection that skips already-compressed formats, honeypot
      hits, registry persistence / shadow-copy signals)
- [x] Transparent weighted risk scoring (matches the doc's worked
      example: writes 25 / entropy 20 / deletes 15 / renames 15 /
      honeypot 40 / registry 10, normalized 0–100) with a human-readable
      reason attached to every point awarded
- [x] Risk bands (Safe / Monitor / Warning / High Risk / Critical) mapped
      to decisions (`Allow` / `Monitor` / `Alert` / `Suspend` /
      `ProtectFilesystem` / `Terminate`)
- [x] `ResponseManager` dispatching decisions to real driver actions
      (block / suspend / kill) with a per-PID cooldown
- [x] Unit tests for the risk bands, the scorer's saturation behavior, and
      the entropy tracker's compressed-format exemption

Registry/persistence and network monitoring (`src/collector/registry.rs`,
`src/collector/network.rs`) are **real, Linux-native implementations**:

| | Linux |
|---|---|
| Persistence | `notify` — watches cron.d/daily/hourly/weekly, systemd units, `/etc/ld.so.preload`, shell rc files |
| Network | `/proc/net/tcp` + `/proc/<pid>/fd/*` inode cross-reference (the same technique `ss`/`netstat` use) |

Both remain no-ops on any other platform.

`src/collector/fanotify.rs` uses Linux's `fanotify` API
to get real, PID-attributed file-write events **entirely from user
space** — `fanotify_event_metadata` has included the originating PID
since the API's introduction, no kernel module required. This directly
fixes the single most-repeated limitation in this project (see
`behavior/engine.rs`'s `UNATTRIBUTED_PID` bucket). It needs
`CAP_SYS_ADMIN` (in practice, root) and only covers write completion
(`FAN_CLOSE_WRITE`) — create/rename/delete still come from the ordinary
`notify`-based watcher, unattributed as before; the newer
directory-entry fanotify events that would cover those need
`FAN_REPORT_FID` and file-handle resolution, a separately-scoped
follow-up. `main.rs` probes availability at startup and automatically
falls back to the pre-existing unattributed behavior if fanotify isn't
available (not root) — nothing crashes either way.

**Linux hardening pass** — a focused re-review of `fanotify.rs` and
`network.rs` caught three real issues, since Linux is the current
priority platform for active development:
- `fanotify.rs`'s watch-path filtering was calling `std::fs::canonicalize`
  (a real filesystem syscall) on *every single event*, for every
  configured watch path — exactly the wrong place to add overhead, since
  a genuine write burst is hundreds of events/sec. Now canonicalized once
  at startup.
- The fanotify read loop had no backoff on error — a persistent failure
  (not the common, benign `EINTR`) would have spun at 100% CPU logging
  warnings as fast as possible. Now backs off (200ms × consecutive
  failures, capped at 5s) for anything other than `EINTR`.
- `event_len` was checked for being too *small* (malformed) but never
  checked against the actual bytes read — a corrupted or oversized value
  could have walked the parse cursor past the buffer. Now bounds-checked
  both directions.
- `network.rs`'s `/proc/net/tcp` read failure was silently swallowed
  forever — if it were ever unreadable (unusual container/namespace
  setup), network telemetry would just stay empty with zero explanation.
  Now logs once, clearly, instead of either spamming or staying silent.

**Milestone 6 (real enforcement)** lives in `src/enforcement/` — the
piece that closes the actual "protect" gap. Every mitigation action in
this project — `Suspend`, `ProtectFilesystem`, `Terminate` — routes
through `driver::client::DriverClient`, and until now `block_writes()`
was a permanent no-op: it logged an intent and did nothing.
Detection and deception were real; enforcement wasn't. Now it is:

- **`enforcement/fanotify_guard.rs`** uses fanotify *permission* events
  (`FAN_OPEN_PERM`) — a different fanotify mode from
  `collector/fanotify.rs`'s read-only notifications — to actually deny
  file opens for a blocked PID, entirely from user space, no kernel
  module. This is genuinely more dangerous than anything else in this
  project: a permission event pauses the calling process's `open()`
  until this code responds, so a bug that fails to respond hangs that
  `open()` forever, not just fails to protect it. Read that file's module
  doc comment before touching it — it explains every mitigation built in
  (fail-open by design, narrow per-path marking instead of
  filesystem-wide, a response guaranteed on every code path) and why
  each one is there.
- **Off by default.** `gaslight.toml`'s `[enforcement] enabled` must be
  explicitly set to `true`. Needs root either way.
- **`driver::client::DriverClient`'s `block_writes` signature changed**
  to take a `pid: u32` — a real signature change, not additive, because
  the old signature (no PID) genuinely couldn't express a per-process
  block. Every call site (`behavior/response.rs`) and the trait's sole
  implementation (`SysinfoDriverClient`, now constructed with
  `SysinfoDriverClient::new(Option<SharedBlockList>)` instead of as a
  unit struct) were updated together.
- **PID reuse is handled explicitly** — `main.rs` unblocks a PID on
  `ProcessExit`, so a stale block never outlives the process it was
  meant for (`enforcement/policy.rs`).

**Milestone 4 (deception engine)** lives in `src/deception/` — generates
realistic decoy files across believable directory structures, tracks them
by exact path, and rotates them periodically. It also **fixes a real
issue in Milestone 2**: the original `HONEY_PATH_MARKERS` approach
matched honeypot paths by substring (`"00_"`, `"confidential"`,
`"passwords"`) — exactly the kind of guessable naming the deception
engine's own design doc warns against. Real decoys use ordinary names, so
`behavior/engine.rs` now does exact-path lookup against the actual
deployed-decoy registry instead. See `src/deception/metadata.rs` for the
full explanation.

**Milestone 5 (SOC dashboard + public site)** — the dashboard now lives at
`website/dashboard.html`, as part of a full `website/` folder: a real,
deployable marketing/docs site (`index.html`, OS-specific setup guides,
the architecture deep-dive, and the dashboard itself), all zero-build-step
static HTML. See `website/README.md` for the site structure and
deployment notes. This milestone also completed a loose end from
Milestone 4: `deception::HoneyMonitor::classify` was built but never
called anywhere — `src/main.rs` now actually wires it into
`broadcast_event()`, so the dashboard's Honey File Monitor panel is real,
not inferred from score-reason text.

**Platform-hardening pass** — `collector/registry.rs` and
`collector/network.rs` went from stubs to real, Linux-native
implementations (`notify`-based persistence watching,
`/proc/net/tcp` + fd inode matching). Linux additionally got
`collector/fanotify.rs` — real, PID-attributed file-write events from
user space, no kernel module needed, which fixes the
single most-repeated limitation in this project. See the "Registry/
persistence and network monitoring" section above for details, and
`scripts/install-linux.sh` for how it gets installed (clone-and-build).

## Build & run

```
cargo build --release
cargo test          # unit tests for behavior/{rules,scoring,entropy,detector,process_state}
cargo run --release
```

Or, on Linux, `./scripts/install-linux.sh` does all three (plus a Rust
toolchain install if you don't have one) in one step.

Edit `gaslight.toml` (created alongside the binary) to point `watch_paths`
at real directories. A `./watched` folder is created automatically on
first run if you haven't configured anything, and the deception engine
deploys real decoy files into it on startup (check the log for
`[deception] deployed N decoy file(s)` — see `website/README.md` for
where they land). Try it out with:

```
# touch a real generated decoy directly — check the log for its exact
# name/path first, e.g.:
echo "test" >> watched/Finance/Payroll_2026_Q1.xlsx

# or simulate generic ransomware-like behavior against the watched folder:
for i in $(seq 1 50); do head -c 4096 /dev/urandom > "watched/f$i.tmp"; mv "watched/f$i.tmp" "watched/f$i.locked"; done
```
then watch the log / websocket feed react.

**On Linux, run as root (or with `sudo`) for full attribution.** Without
it, `collector/fanotify.rs` can't initialize (needs `CAP_SYS_ADMIN`) and
the agent silently falls back to unattributed file events — the log will
say `[fanotify] not available on this platform/privilege level` on
startup if this happens. This is expected and not a crash; it just means
file writes land in the `SYSTEM (unattributed)` bucket instead of their
real process.

Connect any WebSocket client to `ws://127.0.0.1:7878` to see the live
JSON feed: each message is `{ "event": <telemetry event>, "report":
<DecisionReport|null>, "honey_event": <HoneyFileEvent|null> }`, where
`report` carries the score, risk band, decision, and human-readable
reasons for whatever PID that event touched.

> **This sandbox couldn't compile-verify the code** (no network, no Rust
> toolchain installed here). It's been written carefully and reviewed by
> hand — braces/parens balance-checked and every module path
> cross-referenced — but run `cargo build` locally and expect to fix minor
> API drift. Two spots carry the most risk: `src/collector/process.rs`
> (`sysinfo`'s API has shifted across versions), and
> `src/collector/fanotify.rs` (raw `libc` fanotify bindings — the byte
> layout and byte-order math were worked through by hand with concrete
> examples rather than trusted from memory, but the exact symbol names
> `libc::fanotify_init`/`fanotify_mark`/`fanotify_event_metadata` and
> constants like `FAN_MARK_FILESYSTEM` couldn't be checked against the
> resolved crate version here).

## Known limitations (intentional, not bugs)

- **File events carry no PID — except on Linux-with-root, now.**
  OS-level filesystem watchers (inotify) don't tell you which process
  performed a write. `collector/fanotify.rs` fixes this for
  file writes specifically, from user space — see that file and the
  Milestone-4 section above. Every file event that still lacks a PID
  (not running as root, or for create/rename/delete, which fanotify's
  classic API doesn't cover) is
  bucketed under a single `UNATTRIBUTED_PID` (0) "SYSTEM" process rather
  than dropped — see the note at the top of `src/behavior/engine.rs`. The
  engine's per-process design already handles real PIDs correctly with no
  further changes needed anywhere else once they're available — which is
  exactly what happened when fanotify was added: zero changes to
  `behavior/`, `deception/`, or the dashboard were needed.
- **`Suspend` is real on Unix (SIGSTOP).** Any other target platform
  falls back to a logged no-op.
- **`block_writes()` (`ProtectFilesystem`) is real, opt-in, and
  narrower than the name implies.** With `[enforcement] enabled = true`
  and root, it denies *new file opens* for a blocked PID under the
  configured `watch_paths` — see `src/enforcement/fanotify_guard.rs`.
  Files the process already had open before being blocked remain
  writable through that existing descriptor; fanotify permission events
  fire at `open()` time, not per `write()` call. Combined with
  `suspend_process`/`kill_process` (which do stop activity on existing
  descriptors), this is a real layer, not an absolute guarantee on its
  own. Off by default — read the file's module doc comment before
  enabling it; the failure mode of a bug here (a hung `open()` call,
  potentially system-wide if misconfigured) is more severe than anywhere
  else in this project. Everywhere else (running without root, or with
  enforcement disabled), it's still log-only.
- **Unsigned-executable and privilege-escalation features are stubbed
  `false`** (`src/behavior/feature_extractor.rs`) — both need data
  sources (Authenticode/codesign checks, privilege token inspection) not
  wired up yet. Kept as explicit fields, not omitted, so the scorer and
  the doc's Feature List table stay 1:1.
- **Dashboard WebSocket is send-only** (see comment in
  `src/dashboard/websocket.rs`) — fine for a live feed, not spec-complete.

## Project layout

```
gaslight-agent/
├── Cargo.toml
├── gaslight.toml            # runtime config, see comments inline
├── scripts/
│   └── install-linux.sh      # clone → build → test → run, one command
├── .github/workflows/
│   └── release.yml           # builds Linux binaries via CI, attaches to GitHub Releases
├── website/                  # the public site — see website/README.md
│   ├── index.html             # brief overview + Get for Linux
│   ├── get-linux.html         # Linux setup guide
│   ├── architecture.html      # full technical deep-dive (formerly gaslight-showcase.html)
│   └── dashboard.html         # the live SOC dashboard
└── src/
    ├── main.rs               # wiring: config → collectors → behavioral engine → dashboard
    ├── collector/            # process.rs, filesystem.rs, entropy.rs, registry.rs, network.rs, fanotify.rs (Linux-only, PID-attributed writes)
    ├── telemetry/            # event.rs (Event enum), queue.rs (channel)
    ├── behavior/             # the Milestone 2 behavioral engine:
    │   ├── process_state.rs    # per-PID rolling state ("medical chart")
    │   ├── entropy.rs          # running-average entropy + compressed-format exemption
    │   ├── feature_extractor.rs
    │   ├── scoring.rs          # weighted, explainable risk scoring
    │   ├── rules.rs             # risk bands -> default decision
    │   ├── detector.rs          # ties extraction + scoring + rules together
    │   ├── response.rs          # dispatches decisions to driver/ actions
    │   ├── engine.rs            # BehavioralEngine — owns per-PID state, ingests events
    │   └── types.rs             # Decision, DecisionReport
    ├── deception/             # Milestone 4 — decoy generation, rotation, honeypot registry
    ├── enforcement/           # Milestone 6 — real (opt-in) fanotify-permission write blocking
    ├── driver/                # client.rs (block/suspend/kill actions)
    ├── dashboard/             # websocket.rs (live telemetry + decision feed)
    ├── config/                # settings.rs (gaslight.toml loader)
    └── utils/                 # logger.rs (rotating logger)
```

