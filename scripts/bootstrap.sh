#!/usr/bin/env bash
# Spindle dev bootstrap (ADR-010). Installs the pinned toolchain via mise, runs
# per-OS native-dependency checks (warnings only, never fatal), and installs JS deps.
#
# Usage: bash scripts/bootstrap.sh   (or, once `just` exists: `just bootstrap`)
set -euo pipefail

pass() { printf '  [PASS] %s\n' "$1"; }
warn() { printf '  [WARN] %s\n' "$1"; }

# --- (a) mise must be on PATH -------------------------------------------------
if ! command -v mise >/dev/null 2>&1; then
  echo "mise was not found on PATH. Install it, then re-run this script:"
  echo
  echo "  macOS (Homebrew):   brew install mise"
  echo "  Linux/macOS (curl): curl https://mise.run | sh"
  echo "  Windows (winget):   winget install jdx.mise"
  echo
  echo "See https://mise.jdx.dev/getting-started.html for other install methods."
  exit 1
fi

# --- (b) provision pinned tool versions ---------------------------------------
echo "==> Installing pinned toolchain versions (mise install)"
mise install

# --- (c) per-OS native dependency checks (warn, never hard-fail) --------------
echo "==> Checking native build dependencies"
uname_s="$(uname -s 2>/dev/null || echo unknown)"

case "$uname_s" in
  Darwin)
    if xcode-select -p >/dev/null 2>&1; then
      pass "Xcode Command Line Tools installed"
    else
      warn "Xcode Command Line Tools not found — run: xcode-select --install"
    fi
    ;;
  Linux)
    if pkg-config --exists webkit2gtk-4.1 2>/dev/null || pkg-config --exists webkit2gtk-4.0 2>/dev/null; then
      pass "webkit2gtk found (Tauri Linux dependency)"
    else
      warn "webkit2gtk not found — Tauri builds need it. On Debian/Ubuntu:"
      warn "  sudo apt install libwebkit2gtk-4.1-dev build-essential libssl-dev pkg-config"
    fi
    ;;
  MINGW*|MSYS*)
    warn "Windows detected — Tauri builds need the MSVC C++ Build Tools:"
    warn "  https://visualstudio.microsoft.com/visual-cpp-build-tools/"
    warn "mise on Windows works best run from PowerShell, not Git Bash/MSYS."
    ;;
  *)
    warn "Unrecognized OS ($uname_s) — skipping native dependency check."
    ;;
esac

# --- (d) JS dependencies --------------------------------------------------------
echo "==> Installing JS dependencies (pnpm install)"
pnpm install

# --- (e) success summary ---------------------------------------------------------
echo "==> Bootstrap complete. Tool versions:"
mise exec -- cargo --version 2>/dev/null || warn "cargo --version failed"
mise exec -- rustc --version 2>/dev/null || warn "rustc --version failed"
mise exec -- node --version  2>/dev/null || warn "node --version failed"
mise exec -- pnpm --version  2>/dev/null || warn "pnpm --version failed"
mise exec -- just --version  2>/dev/null || warn "just --version failed"

echo
echo "Ready. Try: just build   (or just --list for all targets)"
