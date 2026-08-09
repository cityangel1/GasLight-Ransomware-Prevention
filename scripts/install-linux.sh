#!/usr/bin/env bash
#
# install-linux.sh — clone, build, and (optionally) run GasLight on Linux.
#
# Usage:
#   git clone <your-repo-url> gaslight-agent
#   cd gaslight-agent
#   ./scripts/install-linux.sh
#
# What this does, in order:
#   1. Checks for a Rust toolchain; installs one via rustup if missing.
#   2. Builds the agent in release mode.
#   3. Runs the test suite (fast — no root, no real filesystem I/O).
#   4. Prints how to run it, and offers to run it immediately.
#
# Safe to re-run — every step is idempotent.

set -euo pipefail

BOLD="$(tput bold 2>/dev/null || true)"
RESET="$(tput sgr0 2>/dev/null || true)"
GREEN="$(tput setaf 2 2>/dev/null || true)"
YELLOW="$(tput setaf 3 2>/dev/null || true)"
RED="$(tput setaf 1 2>/dev/null || true)"

info()  { echo "${BOLD}==>${RESET} $1"; }
ok()    { echo "${GREEN}✓${RESET} $1"; }
warn()  { echo "${YELLOW}!${RESET} $1"; }
fail()  { echo "${RED}✗${RESET} $1"; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ ! -f "Cargo.toml" ]; then
    fail "Cargo.toml not found in $REPO_ROOT — run this script from inside the cloned repo (scripts/install-linux.sh)."
fi

# --- 1. Rust toolchain -------------------------------------------------
info "Checking for a Rust toolchain..."
if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
    ok "Found $(rustc --version)"
else
    warn "No Rust toolchain found."
    read -r -p "Install one now via rustup? [Y/n] " reply
    reply=${reply:-Y}
    if [[ "$reply" =~ ^[Yy] ]]; then
        info "Installing rustup (this only touches \$HOME/.cargo)..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck disable=SC1090
        source "$HOME/.cargo/env"
        ok "Installed $(rustc --version)"
    else
        fail "A Rust toolchain is required. Install one (rustup, or your distro's cargo/rustc packages) and re-run this script."
    fi
fi

# --- 2. Build ------------------------------------------------------------
info "Building in release mode (this can take a few minutes the first time)..."
cargo build --release
ok "Build complete: target/release/gaslight-agent"

# --- 3. Tests --------------------------------------------------------------
info "Running the test suite..."
if cargo test --release; then
    ok "All tests passed"
else
    warn "Some tests failed — see output above. The build itself still succeeded; you can continue, but please check before relying on this."
fi

# --- 4. Root note for full attribution -------------------------------------
echo ""
info "One thing worth knowing before you run it:"
cat <<'EOF'
  GasLight can attribute file writes to the real process that made them
  on Linux via fanotify — but that needs root (CAP_SYS_ADMIN). Without
  root, it still runs fine, just with file events bucketed under a
  generic "SYSTEM (unattributed)" process instead of the real one.

    sudo ./target/release/gaslight-agent      # full attribution
    ./target/release/gaslight-agent           # works, less precise
EOF

# --- 5. Offer to run now ----------------------------------------------------
echo ""
read -r -p "Run GasLight now? [y/N] " run_now
if [[ "${run_now:-N}" =~ ^[Yy] ]]; then
    if [ "$(id -u)" -ne 0 ]; then
        warn "Not running as root — file-write attribution will be limited (see above)."
    fi
    info "Starting GasLight. Open dashboard/gaslight-dashboard.html in a browser to watch it live."
    exec ./target/release/gaslight-agent
else
    echo ""
    ok "Setup complete. Run it with:"
    echo "    ./target/release/gaslight-agent"
    echo "Then open dashboard/gaslight-dashboard.html in a browser."
fi
