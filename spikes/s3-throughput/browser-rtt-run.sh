#!/usr/bin/env bash
# A10.29 browser-peer RTT matrix — fully containerized (docs/DESIGN.md §A8 / RESULTS.md
# "Browser-peer (dcSCTP) measurement plan").
#
# Runs the `browser-peer` harness (src/bin/browser-peer.rs + browser-peer.html) at 0/20/50/100 ms
# RTT, BOTH directions (--mode send and --mode recv), entirely inside the
# `spindle-toolchain:local` Docker image: a Rust `webrtc-rs` peer AND headless Chromium (a real
# `dcSCTP` implementation) in the same Linux container, with `tc netem` shaping loopback.
#
# Why containerized, not the macOS host: RESULTS.md's "Results — 0 ms (loopback, macOS host)"
# subsection ran the 0 ms cell on the host with a real (non-headless) Chrome, but the ~50 ms
# dummynet recipe documented there was never exercised successfully — a follow-up investigation
# found that on this machine's modern macOS, `dnctl`/`pfctl` dummynet pipes configure without
# error (pipes present, the `spindle-s3-dummynet` pf anchor evaluated) but the kernel applies NO
# delay: loopback UDP measured ~0.1 ms round-trip with a 25 ms pipe active on the path. That's
# dead — not a configuration mistake to retry, a documented modern-macOS dummynet rot. This script
# replaces the host/dummynet approach entirely: same technique `rtt-run.sh` already uses for the
# Rust↔Rust matrix (a disposable Linux container, `tc netem delay` on `lo`, CAP_NET_ADMIN), with
# headless Chromium added as a second process in the same container/network-namespace so BOTH
# peers sit behind the same netem shaping.
#
# Chromium, not "Chrome": the toolchain image is Debian 12 (bookworm) aarch64, which packages
# `chromium` (Debian's Chromium build) at version 151.0.7922.137 — no `google-chrome` package
# exists for this distro/arch. Same major version (151) as the Chrome 151.0.7922.172 used for the
# host-side 0 ms baseline in RESULTS.md, and the same underlying `dcSCTP` DataChannel/SCTP
# implementation Chromium and Chrome both ship — only the browser's own branding/updater differs,
# not the SCTP stack under test.
#
# Driving Chromium: the harness page is fully self-driving (see browser-peer.rs's module doc
# comment and browser-peer.html's `connect()` call at the bottom of its <script> — it auto-connects
# to ws://127.0.0.1:9333 on load and runs the whole session, posting its own throughput result back
# over that WebSocket). So headless Chromium only needs to OPEN the page; no CDP/automation driving
# is needed here, unlike the host session's earlier use of browser automation. Verified empirically
# that `file://` + `ws://127.0.0.1` both work under `--headless=new` with
# `--allow-file-access-from-files` (no http.server fallback needed) — see the smoke test this
# script's per-cell logic was built from.
#
# Usage (from anywhere — path-independent):
#   spikes/s3-throughput/browser-rtt-run.sh
#
# Requires: docker, and the `spindle-toolchain:local` image already built locally (this script
# does not build it).
#
# Idempotent / safe to re-run: `tc qdisc del ... || true` before every `add` and a final cleanup;
# each invocation gets a fresh, throwaway container (`--rm`), so there is no host-level `lo` state
# or stale Chromium process to worry about between runs. Per-cell failures (a stalled transfer, a
# WebRTC/ICE failure, a timeout) are recorded as FAILED rows and the matrix continues — this
# script does not abort on a single cell's failure (`set -e` is deliberately relaxed around the
# per-cell `wait`s; see below).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SPIKE_DIR="spikes/s3-throughput"

if [ "${1:-}" = "--in-container" ]; then
  # ── Everything below runs INSIDE the container, as root (tc qdisc needs CAP_NET_ADMIN) ──
  cd /workspace

  # iproute2 (tc) and chromium aren't in the toolchain image by default — install once,
  # idempotently, gated on `tc` alone (same convention as rtt-run.sh: every container run starts
  # from the same fresh, throwaway image, so this is really "first time in this container").
  # Verified interactively before writing this script: `apt-cache policy chromium` on this image
  # resolves to 151.0.7922.137-1~deb12u1 (arm64, bookworm-security) — no `chromium-browser` alias
  # needed, the plain `chromium` package installs and runs headless out of the box.
  if ! command -v tc >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq iproute2 chromium >/dev/null
  fi

  # See rtt-run.sh for why CARGO_TARGET_DIR is redirected off the mounted repo's target/ (avoids
  # a macOS/arm64-host vs. Linux-container artifact collision).
  export CARGO_TARGET_DIR=/tmp/target-linux

  cargo build -p spike-s3-throughput --release --bin browser-peer
  BIN="$CARGO_TARGET_DIR/release/browser-peer"
  CHROMIUM_VERSION="$(chromium --version)"
  echo "== $CHROMIUM_VERSION ==" >&2

  RESULTS_TMP="$SPIKE_DIR/.browser-rtt-results.tmp"
  RAW_DIR="$SPIKE_DIR/.browser-rtt-raw"
  QDISC_FILE="$SPIKE_DIR/.browser-rtt-qdisc.tmp"
  mkdir -p "$RAW_DIR"
  : >"$RESULTS_TMP"
  : >"$QDISC_FILE"

  ENV_LABEL="Linux container ($(uname -r), aarch64), $CHROMIUM_VERSION, tc netem on lo, spindle-toolchain:local"
  DATE_STR="$(date -u +%Y-%m-%d)"

  # Per-cell watchdog: generous but bounded — a stalled transfer (e.g. ICE/WebRTC never connects)
  # must not hang the whole matrix. 300s comfortably covers even the slowest expected cell (the
  # Rust↔Rust matrix's worst case at 100 ms was ~129s for 128 MiB; browser-peer's dcSCTP peer is
  # not expected to be dramatically slower than that per direction here). Overridable via
  # PER_RUN_TIMEOUT_S for short diagnostic-only reruns.
  PER_RUN_TIMEOUT_S="${PER_RUN_TIMEOUT_S:-300}"

  # Diagnostic overrides (all optional, default to the full matrix's original behavior):
  #   CELLS=recv            -> only run the given direction(s) instead of "send recv"
  #   RTTS="20 50 100"      -> only run the given RTT list instead of "0 20 50 100"
  #   BYTES_MIB=16          -> fixed transfer size for every RTT instead of bytes_for_rtt()
  #   PER_RUN_TIMEOUT_S=120 -> override the per-cell watchdog below
  #   DCSCTP_LOG=1          -> add verbose dcSCTP chromium logging (see chromium invocation)
  #   RUST_LOG=...          -> passed through to the `browser-peer` (Rust) process, e.g.
  #                            RUST_LOG=rtc_sctp=trace for webrtc-rs's SCTP-layer congestion-
  #                            control logging (cwnd/a_rwnd/SACK/T3-rtx) on stderr — see
  #                            src/bin/browser-peer.rs's env_logger::try_init() call. Chromium's
  #                            dcSCTP debug logs are compiled out of release Chromium, so this is
  #                            the only side of the connection where verbose SCTP logging works.
  RTTS="${RTTS:-0 20 50 100}"
  DIRECTIONS="${CELLS:-send recv}"

  # Bytes per RTT point: large enough to be a sustained transfer, smaller at the slow cells so a
  # collapsed-throughput cell still finishes in a bounded time rather than eating the whole
  # per-run timeout on transfer alone. Overridden entirely by BYTES_MIB when set.
  bytes_for_rtt() {
    if [ -n "${BYTES_MIB:-}" ]; then
      echo "$BYTES_MIB"
      return
    fi
    case "$1" in
      0|20) echo 128 ;;
      50|100) echo 64 ;;
    esac
  }

  # Kills chromium (and any child renderer/GPU processes) launched with a given --user-data-dir,
  # by matching that flag in the process's cmdline — more robust than tracking a single PID, since
  # `chromium --headless=new` forks helper processes that don't share the launcher's PID group in
  # a way plain `kill $PID` reliably reaps.
  kill_chromium() {
    pkill -9 -f -- "--user-data-dir=$1" >/dev/null 2>&1 || true
  }

  # Cross-check against socket-layer UDP drops (nstat is preferred — it resets counters on read,
  # so consecutive before/after calls report deltas; falls back to netstat -su's cumulative
  # counters if nstat isn't available in the image).
  capture_udp_stats() {
    {
      echo "-- UDP error counters ($1) --"
      nstat -az UdpInErrors UdpRcvbufErrors 2>/dev/null || netstat -su
      echo
    } >>"$QDISC_FILE"
  }

  for rtt in $RTTS; do
    half=$((rtt / 2))
    bytes="$(bytes_for_rtt "$rtt")"

    tc qdisc del dev lo root >/dev/null 2>&1 || true
    if [ "$half" -gt 0 ]; then
      # Same RTT/2-on-lo technique as rtt-run.sh — one netem delay applied once per packet
      # transmitted on `lo`, crossed twice per round trip (request + reply), yielding a measured
      # round-trip delay of RTT. `limit 10000` raises netem's internal packet queue well above its
      # 1000-packet default so a burst under delay isn't itself a netem-induced drop source.
      tc qdisc add dev lo root netem delay "${half}ms" limit 10000
    fi

    for dir in $DIRECTIONS; do
      cell="rtt${rtt}_${dir}"
      echo "== RTT=${rtt}ms dir=${dir} bytes=${bytes}MiB ==" >&2

      out_json="$RAW_DIR/${cell}.json"
      err_log="$RAW_DIR/${cell}.err"
      stats_out="$RAW_DIR/${cell}.jsonl"
      chrome_log="$RAW_DIR/${cell}-chrome.log"
      udd="/tmp/chrome-${cell}"
      : >"$out_json"
      : >"$err_log"
      : >"$stats_out"
      : >"$chrome_log"
      rm -rf "$udd"
      mkdir -p "$udd"

      capture_udp_stats "before rtt=${rtt} dir=${dir}"

      set +e
      timeout "${PER_RUN_TIMEOUT_S}s" "$BIN" \
        --mode "$dir" --bytes "$bytes" --json \
        --stats-interval-ms 500 --stats-out "$stats_out" \
        >"$out_json" 2>"$err_log" &
      rust_pid=$!

      # Wait for the signaling WebSocket to actually be listening before opening the page — the
      # page auto-connects exactly once on load and does not retry on failure (see
      # browser-peer.html's connect()), so launching Chromium before the port is up would strand
      # the whole cell. Polled against the Rust side's own stderr log line rather than a fixed
      # sleep; bounded at 10s (well under PER_RUN_TIMEOUT_S) so a Rust-side startup failure still
      # surfaces as a timed-out/failed cell instead of hanging here.
      listening=0
      for _ in $(seq 1 50); do
        if grep -q "listening on" "$err_log" 2>/dev/null; then
          listening=1
          break
        fi
        if ! kill -0 "$rust_pid" 2>/dev/null; then
          break
        fi
        sleep 0.2
      done

      if [ "$listening" -eq 1 ]; then
        # DCSCTP_LOG=1 turns on Chromium's verbose dcSCTP logging into the per-cell chrome log
        # (congestion-control internals: cwnd, a_rwnd/SACKs, T3-rtx, "fully utilized" gating —
        # see webrtc-rs/dcsctp source for the exact log tags). Log volume is large by design;
        # only enabled on request, never by default.
        chrome_extra_args=()
        if [ "${DCSCTP_LOG:-0}" = "1" ]; then
          chrome_extra_args+=(--enable-logging=stderr --vmodule=*dcsctp*=9 --v=0)
        fi
        timeout "${PER_RUN_TIMEOUT_S}s" chromium \
          --headless=new --no-sandbox --disable-gpu \
          --allow-file-access-from-files \
          --autoplay-policy=no-user-gesture-required \
          --user-data-dir="$udd" \
          "${chrome_extra_args[@]}" \
          "file:///workspace/$SPIKE_DIR/browser-peer.html" \
          >"$chrome_log" 2>&1 &
        chrome_pid=$!
      else
        echo "browser-rtt-run: Rust side never reported 'listening' — not launching Chromium for $cell" >&2
        chrome_pid=""
      fi

      wait "$rust_pid"
      rust_rc=$?
      set -e

      if [ -n "$chrome_pid" ]; then
        kill "$chrome_pid" >/dev/null 2>&1 || true
        wait "$chrome_pid" >/dev/null 2>&1 || true
      fi
      kill_chromium "$udd"

      # When RUST_LOG is set, the Rust side's log::{trace,debug,warn}! output (SCTP-layer
      # congestion control) is already inside err_log alongside browser-peer's own eprintln!
      # diagnostics — duplicated here into a clearly-named sibling file so it's easy to grep in
      # isolation without the rest of err_log's noise.
      if [ -n "${RUST_LOG:-}" ]; then
        cp "$err_log" "$RAW_DIR/${cell}-rust-trace.log"
      fi

      capture_udp_stats "after rtt=${rtt} dir=${dir}"

      {
        echo "== RTT=${rtt}ms dir=${dir}, after cell =="
        tc -s qdisc show dev lo
        echo
      } >>"$QDISC_FILE"

      if [ "$rust_rc" -eq 0 ] && [ -s "$out_json" ]; then
        raw="$(cat "$out_json")"
        mb_per_s="$(printf '%s' "$raw" | sed -n 's/.*"mb_per_s":\([0-9.]*\).*/\1/p')"
        printf '| %s | %s | %s | %s | %s | bytes=%sMiB chunk=64KiB; default buffers; raw=%s |\n' \
          "$DATE_STR" "$ENV_LABEL" "$rtt" "$dir" "$mb_per_s" "$bytes" "$raw" \
          >>"$RESULTS_TMP"
      else
        reason="rust_exit=${rust_rc}"
        if [ "$rust_rc" -eq 124 ]; then
          reason="TIMEOUT after ${PER_RUN_TIMEOUT_S}s"
        fi
        tail_err="$(tail -c 400 "$err_log" 2>/dev/null | tr '\n' ' ')"
        printf '| %s | %s | %s | %s | FAILED | %s; bytes=%sMiB; stderr_tail=%s |\n' \
          "$DATE_STR" "$ENV_LABEL" "$rtt" "$dir" "$reason" "$bytes" "$tail_err" \
          >>"$RESULTS_TMP"
        echo "browser-rtt-run: CELL FAILED rtt=${rtt} dir=${dir} ($reason)" >&2
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
# -e VAR (no value) forwards the host's current value of VAR into the container, so the
# diagnostic overrides (CELLS/RTTS/BYTES_MIB/PER_RUN_TIMEOUT_S/DCSCTP_LOG) set on the host actually
# reach the --in-container invocation above instead of silently falling back to matrix defaults.
exec docker run --rm \
  --cap-add NET_ADMIN \
  --user root \
  -e CELLS \
  -e RTTS \
  -e BYTES_MIB \
  -e PER_RUN_TIMEOUT_S \
  -e DCSCTP_LOG \
  -e RUST_LOG \
  -v "$REPO_ROOT:/workspace" \
  -w /workspace \
  spindle-toolchain:local \
  bash "/workspace/$SPIKE_DIR/browser-rtt-run.sh" --in-container
