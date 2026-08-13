# GasLight Website

The full public site — brief overview, a Linux setup guide, the
technical architecture deep-dive, and the live SOC dashboard. All static
HTML, zero build step. Live at
[gaslightv1.vercel.app](https://gaslightv1.vercel.app/), source at
[github.com/cityangel1/GasLight-Ransomware-Prevention](https://github.com/cityangel1/GasLight-Ransomware-Prevention).

> **Linux-only.** Development is focused entirely on Linux.

## Assets

`assets/gaslight-logo.png` is the dark-navy-on-transparent logo, used on
the light-background pages (`index.html`, `get-linux.html`,
`architecture.html`). `assets/gaslight-logo-light.png` is a white/orange
variant of the same mark for dark backgrounds — currently only
`dashboard.html`, which uses a dark Splunk-Enterprise-Security-style
theme. Regenerate the light variant from the source PNG if the logo
changes; don't hand-edit it directly.

`assets/favicon.ico` and the `favicon-*.png` / `apple-touch-icon.png`
files are the browser-tab icon — just the smiley face cropped out of the
wordmark, on a rounded orange square so it stays visible on both light
and dark tab bars. All four pages link to the same set. The 16px size
uses a simplified circle-and-eyes crop (no smile arc) since the full
mark turns to mush at that resolution; regenerate both crops together
if the logo changes.

## Pages

| File | What it is |
|---|---|
| `index.html` | Landing page — brief overview + "Get for Linux" |
| `get-linux.html` | Linux setup guide (clone, `scripts/install-linux.sh`, root/fanotify note, optional real enforcement, verify it's working) |
| `architecture.html` | Full technical walkthrough — all five modules, the behavioral scoring model, the deception engine, an interactive attack-replay demo |
| `dashboard.html` | The live SOC dashboard (documented in full below) |

## Deploying

Already deployed at [gaslightv1.vercel.app](https://gaslightv1.vercel.app/)
via Vercel's root-directory override (repo root: this whole project;
Vercel project root directory: `website/`). To redeploy after changes:

```
git add website/
git commit -m "Update site"
git push
```

Vercel redeploys automatically on push if the GitHub integration is
connected (Vercel dashboard → Project → Settings → Git).

No environment variables, no build command, no framework detection
needed — it's plain HTML/CSS/JS.

---

## The dashboard, in detail

Open `dashboard.html` directly in a browser, no build step, no npm
install.

### Usage

1. Run the agent (`cargo run --release`, or `./scripts/install-linux.sh`
   on Linux) so it's listening on `ws://127.0.0.1:7878` (the default
   `dashboard.port` in `gaslight.toml`).
2. Open `dashboard.html`. The connection pill in the top-right should
   flip from "CONNECTING…" to "LIVE".
3. Trigger some file activity under your configured `watch_paths` (or
   touch a decoy under `Finance/`, `HR/`, etc. — see the deception
   engine config) and watch the process table, timeline, and charts
   update.

No agent running? Click **"Run Demo Attack"** — a scripted
`wannacry_payload.bin` incident plays through the exact same rendering
pipeline as real telemetry (same `handleMessage()` function, same wire
format), so the whole dashboard is provable without needing malware, a
live agent, or even a network connection.

### What's implemented

- **System Threat Meter** — a gas-lamp flame motif carried through from
  the site's branding: calm idle glow, escalating flicker through
  Watch/Warning, snapping to a steady red glow at Critical.
- **Live charts** — peak risk score and aggregate write-events/sec,
  hand-rolled inline SVG (no charting library/CDN dependency).
- **Live Process Table** — sortable by risk score, click a row for full
  detail including the real **Behavior Breakdown** (the actual
  `reasons` array from `DecisionReport` — genuine explainability, not
  placeholder text).
- **Honey File Monitor** — real honeypot interactions, broadcast over
  the wire via the `honey_event` field in `broadcast_event()` (see
  `src/main.rs`).
- **Event Timeline** — filtered to risk-band escalations and
  enforcement moments, not every single file write — a real ransomware
  run can be hundreds of events/sec, and the timeline stays readable by
  design rather than becoming a raw firehose.
- **Alert toasts** — a WARNING → CRITICAL → SUCCESS sequence as a
  process escalates and gets neutralized.
- **Threat Replay** — any process that reaches `Terminate` has its full
  score/decision history captured; the process detail panel gets a
  "Replay Incident" button that plays it back as a step-by-step modal.

### Scope decisions (left out, deliberately, not silently)

- **Single page, not seven routed pages.** Overview/Processes/Threats/
  Honey/Timeline all live on one screen instead of behind navigation —
  not having to click between pages during a live walkthrough is a real
  advantage, and everything still fits without feeling cramped. Reports
  and Settings pages are not implemented.
- **No PDF/JSON/CSV export.** Would need real backend support (the
  WebSocket feed is live-only, no historical query endpoint) rather than
  something that belongs client-side.
- **No persistent storage.** This dashboard is intentionally
  stateless/live-only (all state lives in a JS `Map` that resets on page
  reload). Real persistence would mean either a browser-side database
  or a backend storage layer in the Rust agent — a genuine feature, not
  a small addition, left as a clearly-scoped follow-up.
- **No search bar, no Settings UI for live threshold tuning.** Config
  changes go through `gaslight.toml` and an agent restart today.
- **Writes/sec and entropy per-process depend on privilege.** File
  events only carry a real PID when running as root (via `fanotify` —
  see `src/collector/fanotify.rs`). Otherwise, file-write
  telemetry shows up under a single "SYSTEM (unattributed)" row rather
  than the real process. The dashboard shows this honestly instead of
  hiding it. Demo Mode sidesteps this by using a synthetic (clearly
  fake) PID, since it's meant to prove the dashboard's rendering path
  works, not to misrepresent real attribution capability.

### Wire format

```json
{
  "event": { "type": "FileWrite", "pid": null, "path": "...", "size_bytes": 1234, "entropy": 7.95, "timestamp_ms": 173... },
  "report": { "pid": 4417, "process_name": "...", "score": 91.0, "risk_level": "Critical", "decision": "ProtectFilesystem", "reasons": ["..."] },
  "honey_event": { "pid": 4417, "path": "...", "operation": "Write", "honey_id": 7, "timestamp_ms": 173... }
}
```

`report` and `honey_event` are `null` when not applicable to that
particular event — see `src/main.rs`'s `broadcast_event()` /
`classify_honey_event()` for exactly how each field gets populated.
