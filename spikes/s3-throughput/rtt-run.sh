#!/usr/bin/env bash
# S3 RTT-shaped throughput matrix runner (docs/SPIKES.md §S3 / docs/DESIGN.md §A13).
#
# Runs the DataChannel throughput harness (this crate's `spike-s3-throughput` binary) at
# 0/20/50/100 ms RTT against a couple of SCTP buffer configs, inside the `spindle-toolchain:local`
# Docker image — Linux, so `tc netem` is available (macOS has no netns-level netem equivalent for
# shaping loopback the way this script needs). Appends one row per (RTT, buffer-config) cell to
# RESULTS.md.
#
# Usage (from anywhere — path-independent):
#   spikes/s3-throughput/rtt-run.sh
#
# Requires: docker, and the `spindle-toolchain:local` image already built locally (this script
# does not build it — see the repo's dev docs / deploy/ for that).
#
# Idempotent: `tc qdisc del ... || true` before every `add`, and a final cleanup at the end, so
# re-running (or a prior run dying mid-matrix) never leaves stale shaping or an error from
# `replace`-on-nothing. Each invocation gets a fresh, throwaway container (`--rm`), so there is no
# host-level `lo` state to worry about either.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SPIKE_DIR="spikes/s3-throughput"

if [ "${1:-}" = "--in-container" ]; then
  # ── Everything below runs INSIDE the container, as root (tc qdisc needs CAP_NET_ADMIN) ──
  cd /workspace

  # iproute2 (tc) isn't in the toolchain image by default — install once, idempotently.
  if ! command -v tc >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq iproute2 >/dev/null
  fi

  # IMPORTANT: redirect the target dir to a container-local path, NOT the mounted repo's
  # `target/` — the host's `target/` holds macOS/arm64 build artifacts; a Linux build writing
  # into the same directory would produce cross-OS-incompatible binaries fighting over the same
  # fingerprint/incremental cache (actively wrong, not just wasteful). This is why
  # CARGO_TARGET_DIR is set here rather than left to the workspace default.
  export CARGO_TARGET_DIR=/tmp/target-linux

  # Build once, in release mode, before the matrix — so per-cell timing measures the transfer,
  # not first-run compilation.
  cargo build -p spike-s3-throughput --release
  BIN="$CARGO_TARGET_DIR/release/spike-s3-throughput"

  RESULTS="$SPIKE_DIR/RESULTS.md"
  ENV_LABEL="Linux container ($(uname -r)), tc netem on lo, spindle-toolchain:local"
  DATE_STR="$(date -u +%Y-%m-%d)"

  # RTT matrix per docs/SPIKES.md §S3.
  RTTS="0 20 50 100"

  # Buffer configs to sweep at each RTT point: the harness default (4 MiB) and a deliberately
  # small window (256 KiB), to show a too-small SCTP receive window starving throughput as RTT
  # grows (bandwidth-delay-product: at 100 ms RTT a 256 KiB window caps throughput far below what
  # a 4 MiB window sustains). threshold (bufferedAmountLowThreshold) is left at the harness
  # default (1 MiB) for every cell — it isn't expected to matter at this transfer size and isn't
  # part of the S3 pass/fail matrix.
  BUFFERS="4194304 262144"

  # Payload per cell. Large enough to be a sustained transfer, not an initial burst (per the S3
  # method sketch), while keeping the higher-RTT / smaller-buffer cells (which are genuinely
  # slow, by design — that's the point of the sweep) finish in a reasonable time.
  BYTES=128

  for rtt in $RTTS; do
    half=$((rtt / 2))
    # `tc netem delay` on `lo` applies once per packet transmitted on that interface. A round
    # trip (request out + reply back) crosses the shaped `lo` egress path twice, so one netem
    # delay of RTT/2 on `lo` yields a measured round-trip delay of RTT — NOT RTT/2 applied twice
    # on two distinct interfaces (that's the two-physical-hosts case, which doesn't apply here).
    tc qdisc del dev lo root >/dev/null 2>&1 || true
    if [ "$half" -gt 0 ]; then
      tc qdisc add dev lo root netem delay "${half}ms"
    fi

    for buf in $BUFFERS; do
      echo "== RTT=${rtt}ms sctp_buf=${buf}B ==" >&2
      out="$("$BIN" --bytes "$BYTES" --sctp-buf "$buf" --json)"
      mb_per_s="$(printf '%s' "$out" | sed -n 's/.*"mb_per_s":\([0-9.]*\).*/\1/p')"
      printf '| %s | %s | %s | send=%s/recv=%s/threshold=1048576 | %s | bytes=%sMiB chunk=64KiB; raw=%s |\n' \
        "$DATE_STR" "$ENV_LABEL" "$rtt" "$buf" "$buf" "$mb_per_s" "$BYTES" "$out" \
        >>"$RESULTS"
    done
  done

  # Leave `lo` unshaped even though the container is `--rm` and about to disappear — cheap
  # insurance if this script is ever changed to run without `--rm` or on a longer-lived container.
  tc qdisc del dev lo root >/dev/null 2>&1 || true

  echo "Done. Rows appended to $RESULTS." >&2
  exit 0
fi

# ── Runs on the HOST: launch the container, then re-invoke this same script inside it ──
exec docker run --rm \
  --cap-add NET_ADMIN \
  --user root \
  -v "$REPO_ROOT:/workspace" \
  -w /workspace \
  spindle-toolchain:local \
  bash "/workspace/$SPIKE_DIR/rtt-run.sh" --in-container
