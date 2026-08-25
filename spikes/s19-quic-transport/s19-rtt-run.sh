#!/usr/bin/env bash
# S19 RTT-shaped quinn QUIC throughput matrix runner (docs/SPIKES.md §S19 / docs/DESIGN.md §A13).
#
# Leg 1 only (see src/bin/quic-peer.rs's module doc comment for what legs 2-4 are and why they're
# not here yet): runs the `quic-peer` harness — one `--mode recv` (quinn server) process, one
# `--mode send` (quinn client) process, on `127.0.0.1` — at 0/20/50/100 ms RTT, for BOTH `--cc
# cubic` and `--cc bbr`, inside the `spindle-toolchain:local` Docker image (Linux, so `tc netem` is
# available — same reasoning as spikes/s3-throughput/rtt-run.sh). Much simpler than that script's
# skeleton or browser-rtt-run.sh's: no Chromium, no WebSocket signaling relay, no SCTP-buffer
# sweep — just the two `quic-peer` processes directly, with the cert fingerprint handed from recv's
# stderr to send's `--cert-fp` on the command line (this harness's stand-in for the A7-verified
# envelope; see quic-peer.rs's "Certificate pinning" doc section).
#
# Usage (from anywhere — path-independent):
#   spikes/s19-quic-transport/s19-rtt-run.sh
#
# Requires: docker, and the `spindle-toolchain:local` image already built locally (this script
# does not build it — see the repo's dev docs / deploy/ for that).
#
# Idempotent / safe to re-run: `tc qdisc del ... || true` before every `add` and a final cleanup;
# each invocation gets a fresh, throwaway container (`--rm`), so there is no host-level `lo` state
# to worry about between runs. Per-cell failures (recv never reports "listening", send times out or
# exits non-zero) are recorded as FAILED rows and the matrix continues — this script does not abort
# on a single cell's failure.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SPIKE_DIR="spikes/s19-quic-transport"

if [ "${1:-}" = "--in-container" ]; then
  # ── Everything below runs INSIDE the container, as root (tc qdisc needs CAP_NET_ADMIN) ──
  cd /workspace

  # iproute2 (tc) isn't in the toolchain image by default — install once, idempotently (same
  # convention as rtt-run.sh / browser-rtt-run.sh: every container run starts from the same fresh,
  # throwaway image, so this is really "first time in this container").
  if ! command -v tc >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq iproute2 >/dev/null
  fi

  # See rtt-run.sh for why CARGO_TARGET_DIR is redirected off the mounted repo's target/ (avoids a
  # macOS/arm64-host vs. Linux-container artifact collision).
  export CARGO_TARGET_DIR=/tmp/target-linux

  cargo build -p spike-s19-quic-transport --release --bin quic-peer
  BIN="$CARGO_TARGET_DIR/release/quic-peer"

  RESULTS_TMP="$SPIKE_DIR/.s19-rtt-results.tmp"
  RAW_DIR="$SPIKE_DIR/.s19-raw"
  QDISC_FILE="$SPIKE_DIR/.s19-rtt-qdisc.tmp"
  mkdir -p "$RAW_DIR"
  : >"$RESULTS_TMP"
  : >"$QDISC_FILE"

  ENV_LABEL="Linux container ($(uname -r)), tc netem on lo, spindle-toolchain:local"
  DATE_STR="$(date -u +%Y-%m-%d)"

  # Diagnostic overrides (all optional, default to the full matrix's original behavior):
  #   RTTS="20 50"          -> only run the given RTT list instead of "0 20 50 100"
  #   CELLS="cubic"         -> only run the given --cc value(s) instead of "cubic bbr" (reuses the
  #                            same CELLS override name browser-rtt-run.sh uses for its own
  #                            per-cell axis — here the axis is congestion controller, not
  #                            direction)
  #   BYTES_MIB=32          -> fixed transfer size for every RTT instead of bytes_for_rtt()
  #   PER_RUN_TIMEOUT_S=60  -> override the per-cell watchdog below
  #   OVERALL_TIMEOUT_S=... -> override the outer `timeout` wrapper (see bottom of this file)
  RTTS="${RTTS:-0 20 50 100}"
  CCS="${CELLS:-cubic bbr}"

  # Per-cell watchdog: generous but bounded. Wraps BOTH the recv process (background) and the send
  # process (foreground) independently — a stalled connect/transfer must not hang the whole matrix.
  PER_RUN_TIMEOUT_S="${PER_RUN_TIMEOUT_S:-120}"

  # Bytes per RTT point: large enough to be a sustained transfer, smaller at the slow cells so a
  # collapsed-throughput cell still finishes in bounded time. Overridden entirely by BYTES_MIB.
  bytes_for_rtt() {
    if [ -n "${BYTES_MIB:-}" ]; then
      echo "$BYTES_MIB"
      return
    fi
    case "$1" in
      0|20) echo 128 ;;
      50|100) echo 32 ;;
    esac
  }

  port=5701

  for rtt in $RTTS; do
    half=$((rtt / 2))

    # Same RTT/2-on-lo technique as rtt-run.sh / browser-rtt-run.sh — one netem delay applied once
    # per packet transmitted on `lo`, crossed twice per round trip, yielding a measured round-trip
    # delay of RTT. `limit 10000` raises netem's internal packet queue well above its 1000-packet
    # default so a burst under delay isn't itself a netem-induced drop source.
    tc qdisc del dev lo root >/dev/null 2>&1 || true
    if [ "$half" -gt 0 ]; then
      tc qdisc add dev lo root netem delay "${half}ms" limit 10000
    fi

    bytes="$(bytes_for_rtt "$rtt")"

    for cc in $CCS; do
      cell="rtt${rtt}_${cc}"
      addr="127.0.0.1:${port}"
      port=$((port + 1))

      echo "== RTT=${rtt}ms cc=${cc} bytes=${bytes}MiB addr=${addr} ==" >&2

      recv_out="$RAW_DIR/${cell}-recv.json"
      recv_err="$RAW_DIR/${cell}-recv.err"
      send_out="$RAW_DIR/${cell}-send.json"
      send_err="$RAW_DIR/${cell}-send.err"
      stats_out="$RAW_DIR/${cell}-stats.jsonl"
      : >"$recv_out"; : >"$recv_err"; : >"$send_out"; : >"$send_err"; : >"$stats_out"

      set +e
      timeout "${PER_RUN_TIMEOUT_S}s" "$BIN" \
        --mode recv --listen "$addr" --bytes "$bytes" --cc "$cc" --json \
        --stats-interval-ms 500 --stats-out "$stats_out" \
        >"$recv_out" 2>"$recv_err" &
      recv_pid=$!

      # Wait for recv to report "listening" AND print its cert-fp before starting send — send
      # needs the fingerprint on its command line (this harness's stand-in for the A7-verified
      # envelope; see quic-peer.rs's module doc comment). Polled against recv's own stderr,
      # bounded well under PER_RUN_TIMEOUT_S so a recv-side startup failure surfaces as a failed
      # cell instead of hanging here.
      listening=0
      fp=""
      for _ in $(seq 1 50); do
        if grep -q "listening on" "$recv_err" 2>/dev/null; then
          fp="$(sed -n 's/.*cert-fp \(sha256:[0-9a-f]*\).*/\1/p' "$recv_err" | head -1)"
          if [ -n "$fp" ]; then
            listening=1
            break
          fi
        fi
        if ! kill -0 "$recv_pid" 2>/dev/null; then
          break
        fi
        sleep 0.2
      done

      send_rc=1
      if [ "$listening" -eq 1 ]; then
        timeout "${PER_RUN_TIMEOUT_S}s" "$BIN" \
          --mode send --connect "$addr" --cert-fp "$fp" --bytes "$bytes" --cc "$cc" --json \
          >"$send_out" 2>"$send_err"
        send_rc=$?
      else
        echo "s19-rtt-run: recv never reported \"listening\"+cert-fp for $cell" >&2
      fi

      wait "$recv_pid"
      recv_rc=$?
      set -e

      {
        echo "== RTT=${rtt}ms cc=${cc}, after cell =="
        tc -s qdisc show dev lo
        echo
      } >>"$QDISC_FILE"

      if [ "$recv_rc" -eq 0 ] && [ "$send_rc" -eq 0 ] && [ -s "$recv_out" ]; then
        raw="$(cat "$recv_out")"
        mb_per_s="$(printf '%s' "$raw" | sed -n 's/.*"mb_per_s":\([0-9.]*\).*/\1/p')"
        printf '| %s | %s | %s | %s | %s | bytes=%sMiB chunk=64KiB window=16MiB; recv=%s; send_raw=%s |\n' \
          "$DATE_STR" "$ENV_LABEL" "$rtt" "$cc" "$mb_per_s" "$bytes" "$raw" "$(cat "$send_out")" \
          >>"$RESULTS_TMP"
      else
        reason="recv_exit=${recv_rc} send_exit=${send_rc}"
        if [ "$recv_rc" -eq 124 ] || [ "$send_rc" -eq 124 ]; then
          reason="TIMEOUT after ${PER_RUN_TIMEOUT_S}s ($reason)"
        fi
        tail_err="$(tail -c 400 "$recv_err" 2>/dev/null | tr '\n' ' ')"
        printf '| %s | %s | %s | %s | FAILED | %s; bytes=%sMiB; recv_stderr_tail=%s |\n' \
          "$DATE_STR" "$ENV_LABEL" "$rtt" "$cc" "$reason" "$bytes" "$tail_err" \
          >>"$RESULTS_TMP"
        echo "s19-rtt-run: CELL FAILED rtt=${rtt} cc=${cc} ($reason)" >&2
      fi
    done
  done

  tc qdisc del dev lo root >/dev/null 2>&1 || true

  echo "" >&2
  echo "== Matrix done. Results table: ==" >&2
  cat "$RESULTS_TMP"
  echo "" >&2
  echo "== qdisc drop stats (per cell): $QDISC_FILE ==" >&2
  cat "$QDISC_FILE" >&2
  echo "" >&2
  echo "== Raw per-cell JSON/stats/logs: $RAW_DIR/ ==" >&2

  exit 0
fi

# ── Runs on the HOST: launch the container, then re-invoke this same script inside it ──
# -e VAR (no value) forwards the host's current value of VAR into the container, so the diagnostic
# overrides (CELLS/RTTS/BYTES_MIB/PER_RUN_TIMEOUT_S) set on the host actually reach the
# --in-container invocation above instead of silently falling back to matrix defaults.
#
# Belt-and-braces overall watchdog, same convention as browser-rtt-run.sh (post-mortem there: a
# hang inside the container before any per-cell `timeout` wrapper ever engaged silently wedged the
# whole script for 2+ hours). `timeout` (GNU coreutils, present in this Linux image, unlike the
# macOS host) wraps the ENTIRE --in-container run. Overridable via OVERALL_TIMEOUT_S; default
# (1800s) comfortably covers the full default matrix (RTTS="0 20 50 100" x CCS="cubic bbr" = 8
# cells x up to 120s default PER_RUN_TIMEOUT_S each, plus build/apt-get overhead) with headroom.
exec docker run --rm \
  --cap-add NET_ADMIN \
  --user root \
  -e CELLS \
  -e RTTS \
  -e BYTES_MIB \
  -e PER_RUN_TIMEOUT_S \
  -e OVERALL_TIMEOUT_S \
  -v "$REPO_ROOT:/workspace" \
  -w /workspace \
  spindle-toolchain:local \
  timeout "${OVERALL_TIMEOUT_S:-1800}s" bash "/workspace/$SPIKE_DIR/s19-rtt-run.sh" --in-container
