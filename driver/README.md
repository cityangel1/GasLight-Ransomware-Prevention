# GasLight Filter Driver (Milestone 3)

A Windows filesystem minifilter implementing the "user mode decides,
kernel mode enforces" split described in the architecture doc: this
driver never scores anything or decides what's malicious — it looks up a
PID's policy (set by the behavioral engine, via the Rust agent) and
allows/denies I/O accordingly.

## ⚠️ Before you do anything else

**This code has never been compiled.** The sandbox that wrote it has no
Windows machine, no WDK, and no network — every WDK API call here was
written from documented signatures and cross-checked by eye, not by a
compiler. Kernel-mode bugs don't just crash a process; a bad one bugchecks
(BSODs) the whole machine, and a wrong pointer/IRQL mistake can be a real
security bug in its own right, not just a crash.

**Rules for working with this:**
1. Build and test only in a disposable VM with test-signing enabled
   (`bcdedit /set testsigning on`). Never load an unsigned/experimental
   filter driver on a machine you'd be upset to lose.
2. Take a VM snapshot before loading the driver for the first time.
3. Go through every row of the Testing Strategy table below, on a VM,
   before trusting this with anything that matters.
4. Read the code — especially `callbacks.c` and `policy.c` — rather than
   just building and running it. You should understand exactly what it
   denies and why before it's anywhere near real files.

## Build

This needs Visual Studio + the WDK (Windows Driver Kit) extension — there's
no build tooling in this repo itself (no `.vcxproj`/`.sln` is included,
deliberately: a subtly-wrong project file is a worse failure mode than no
project file, since it'd silently build something other than what's
intended). To build:

1. Install Visual Studio (Community is fine) + the WDK extension for your
   VS version.
2. **File → New → Project → "Filter Driver"** (under Windows Driver
   Kit templates).
3. Delete the template's generated stub `.c`/`.h` files and add this
   folder's `*.c` files and `include/*.h` instead (add `include/` to the
   project's Additional Include Directories).
4. Build. Fix whatever the compiler flags — see "Known risk spots" below
   for where I'd bet a first build fails.
5. Sign appropriately for your test environment (test certificate is
   fine for a VM), then install via `gaslight_filter.inf` — right-click →
   Install, or `pnputil /add-driver gaslight_filter.inf /install`.
6. `fltmc filters` should list `GasLightFilter`; `fltmc instances` should
   show it attached to your test volume.

## Known risk spots (where I'd expect a first build to need fixes)

- **`FLT_REGISTRATION` field list** in `DriverEntry.c` — this struct has
  gained fields across WDK versions. Designated initializers are used
  specifically so an outdated/newer field list mostly just works, but
  double check against your WDK's `fltKernel.h`.
- **`GlUtilsDosPathToNtPath`** in `utils.c` (object manager symbolic link
  resolution) — the trickiest function in the whole driver. Test this in
  isolation (e.g. a `DbgPrint` right after calling it in
  `GlLoadConfiguration`) before trusting the protected-path matching.
- **`FltCreateCommunicationPort`** parameter order in `communication.c` —
  cross-check against your WDK's `fltKernel.h` if it doesn't compile;
  this signature has been stable for a long time but "long time stable"
  isn't the same as "verified."

## Testing Strategy

Exactly the table from the architecture doc — go through all of it before
trusting the driver with real policy decisions:

| Test                                     | Expected Result                  |
| ----------------------------------------- | --------------------------------- |
| Notepad saves a document                  | Allowed                           |
| Word edits a file                         | Allowed                           |
| Custom test app writes rapidly            | Allowed until engine raises risk  |
| Behavioral engine sets policy to BLOCK    | Future writes denied              |
| Rename protected file after BLOCK         | Denied                            |
| Delete protected file after BLOCK         | Denied                            |
| Access unprotected folder                 | Allowed                           |

To drive the last four manually before the Rust agent is wired up: write
a tiny test harness using `usermode/driver_client.rs` (or even a raw
`FilterConnectCommunicationPort` call from any language) that connects and
calls `set_policy(<your test process's PID>, Policy::Block)`, then try
writing to a file under a protected path from that process.

## What's implemented vs. deferred

**Implemented (Milestone 3 MVP, per the doc):**
- Minifilter registration, attached to all suitable volumes
- CREATE (observe-only), WRITE, SET_INFORMATION (rename/delete/etc.),
  CLEANUP (registered, no-op) callbacks
- Protected-path and honey-root prefix matching
- O(1)-average PID → Policy table (fixed-size, tombstone-based deletion,
  spinlock-protected — safe at any IRQL)
- `FltCreateCommunicationPort`-based IPC: user mode sets/removes policy;
  driver reports enforcement + honeypot-touch events back
- Fail-open default for unknown PIDs (per the doc's demo-friendly
  recommendation)

**Deliberately deferred, not silently skipped:**
- **Redirect** (`GlPolicyRedirect`) currently **degrades to Block** — see
  the comment in `callbacks.c`. True redirection means handing the write a
  different target file entirely, which the doc itself flags as
  significantly harder than blocking and worth prototyping separately.
- **Registry-based configuration** — protected paths and the honey root
  are hardcoded in `GlLoadConfiguration` (`DriverEntry.c`) rather than read
  from the registry `Parameters` key. Getting a registry schema right
  without a machine to test it against seemed more likely to introduce a
  bug than to help; the function is structured so swapping in
  `ZwQueryValueKey` calls is a contained change.
- **Fail-closed mode** — the doc recommends fail-open for a demo
  (if the user-mode agent disconnects, already-set policies stay static
  rather than everything locking down); an enterprise build would want
  this configurable. `GlCommunicationIsAgentConnected` is exposed as the
  hook point for that, unused by `callbacks.c` today.
- **Integrating `usermode/driver_client.rs` into the main agent's
  `DriverClient` trait** — see the file's own header comment for why this
  needs a small signature change (adding a PID parameter) to the existing
  trait rather than a quick bolt-on.

## Project layout

```
driver/
├── DriverEntry.c        # registration, startup/shutdown sequencing
├── callbacks.c           # the actual enforcement points (CREATE/WRITE/SET_INFORMATION/CLEANUP)
├── policy.c              # PID -> Policy table (fixed-size, O(1) average)
├── communication.c       # FltCreateCommunicationPort — IPC with user mode
├── protected_paths.c     # protected-folder and honey-root prefix matching
├── logging.c             # DbgPrint-based, enforcement-events-only logging
├── utils.c               # DOS-path -> NT-path resolution
├── include/
│   ├── structures.h       # shared types + wire-format message structs
│   ├── globals.h          # the driver's entire state, in one struct
│   ├── policy.h
│   ├── communication.h
│   ├── protected_paths.h
│   ├── callbacks.h
│   ├── logging.h
│   └── utils.h
├── usermode/
│   └── driver_client.rs   # Rust IPC client (FilterConnectCommunicationPort / FilterSendMessage)
└── gaslight_filter.inf    # driver installation INF
```
