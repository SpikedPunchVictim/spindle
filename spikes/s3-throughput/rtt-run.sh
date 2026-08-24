#!/usr/bin/env bash
# S3 RTT-shaped throughput matrix runner (docs/SPIKES.md §S3 / docs/DESIGN.md §A13).
#
# Runs the DataChannel throughput harness at 0/20/50/100 ms RTT, inside the
# `spindle-toolchain:local` Docker image — Linux, so `tc netem` is available (macOS has no
# netns-level netem equivalent for shaping loopback the way this script needs) — against BOTH
# backends this crate builds:
#
#   - `spike-s3-throughput` (the `webrtc` crate backend, src/main.rs): swept against a couple of
#     SCTP buffer configs. Appends one row per (RTT, buffer-config) cell directly to the existing
#     table in RESULTS.md (`>>`), as before.
#   - `dc-throughput` (the `datachannel-rs`/libdatachannel fallback backend named in
#     docs/DESIGN.md §A8, src/bin/dc-throughput.rs): one cell per RTT (no `--sctp-buf` sweep — see
#     that file's module doc comment for why). Its rows are written to a scratch file
#     ($SPIKE_DIR/.rtt-dc-rows.tmp, NOT appended to RESULTS.md directly) since they belong under a
#     new "datachannel-rs backend" section/table, not the existing webrtc-backend table this
#     script already appends to — splicing that section in (with its own header + verdict
#     paragraph) is a one-time follow-up edit, not something worth this script special-casing.
#
# Two follow-up sections after both backends above (docs/SPIKES.md §S3 follow-up: "is the
# collapse partly a tc-netem artifact, and does parallelism scale throughput back up?"), rows
# also written to scratch files rather than appended straight to RESULTS.md, same reasoning:
#
#   - TCP baseline (`tcp-baseline`, src/bin/tcp-baseline.rs, std-only): same 0/20/50/100 ms
#     matrix, PLUS a raised-netem-queue rerun at 50 ms (`limit 100000` vs netem's default ~1000
#     packets) for both TCP and the webrtc backend, to test whether the SCTP collapse is partly a
#     netem queue-drop artifact rather than purely SCTP congestion control. `tc -s qdisc show dev
#     lo` is captured after every cell in this section (not just TCP's) so drop counts are
#     directly visible alongside each throughput number. Rows: $SPIKE_DIR/.rtt-tcp-rows.tmp
#     (TCP + the one bonus raised-limit webrtc row); qdisc dumps: $SPIKE_DIR/.rtt-qdisc-stats.tmp.
#   - Parallel associations (`spike-s3-throughput --parallel N`, N=1/2/4/8, default netem queue,
#     50 ms RTT, default 4 MiB buffer config): does splitting the transfer across N independent
#     SCTP associations (N congestion windows) scale aggregate throughput back up? Rows:
#     $SPIKE_DIR/.rtt-parallel-rows.tmp.
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

  # iproute2 (tc) isn't in the toolchain image by default — install once, idempotently. cmake and
  # libclang-dev are also missing (needed below to build the datachannel-rs backend's vendored
  # libdatachannel: cmake drives the C++ build, and datachannel-sys's build script separately runs
  # `bindgen` over libdatachannel's headers, which needs `libclang.so` — not provided by cmake or
  # a plain C++ toolchain. g++, pkg-config and libssl-dev are already present in this image).
  # Installed here, before ANY `cargo build` of this package: the `dc-throughput` binary build
  # below (line ~134, `--features datachannel-backend --bin dc-throughput`) needs both, and this
  # is the one place in the script that installs apt packages. `datachannel` is now an optional
  # dependency behind the `datachannel-backend` feature (not default — see this crate's
  # Cargo.toml), so the plain `--bin spike-s3-throughput` build just below does NOT pull in
  # datachannel-sys/cmake/bindgen at all; that build no longer needs these packages, but the
  # dc-throughput build later in this script still does. Gated on `tc` alone (not each package
  # individually) — every container run starts from the same fresh, throwaway image (`--rm`), so
  # this is really "first time in this container", not a true incremental cache; checking one
  # representative binary keeps the guard simple.
  if ! command -v tc >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq iproute2 cmake libclang-dev >/dev/null
  fi

  # IMPORTANT: redirect the target dir to a container-local path, NOT the mounted repo's
  # `target/` — the host's `target/` holds macOS/arm64 build artifacts; a Linux build writing
  # into the same directory would produce cross-OS-incompatible binaries fighting over the same
  # fingerprint/incremental cache (actively wrong, not just wasteful). This is why
  # CARGO_TARGET_DIR is set here rather than left to the workspace default.
  export CARGO_TARGET_DIR=/tmp/target-linux

  # Build once, in release mode, before the matrix — so per-cell timing measures the transfer,
  # not first-run compilation. `--bin`-scoped so this doesn't also drag in the datachannel-rs
  # backend's build.
  cargo build -p spike-s3-throughput --release --bin spike-s3-throughput
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

  echo "Done. webrtc-backend rows appended to $RESULTS." >&2

  # ── datachannel-rs backend matrix (docs/DESIGN.md §A8 fallback) ──
  #
  # `vendored-libdatachannel` (this crate's Cargo.toml) builds libdatachannel from source via
  # cmake and needs a C++ toolchain + OpenSSL dev headers. g++, pkg-config and libssl-dev are
  # already in this image; cmake was installed above, alongside `tc`. (Reported as a build hurdle
  # in RESULTS.md; the macOS host needed the equivalent `brew install cmake`.)
  #
  # `datachannel` is an optional dependency behind the `datachannel-backend` feature (not
  # default — see this crate's Cargo.toml), and the `dc-throughput` binary carries
  # `required-features = ["datachannel-backend"]`, so it must be requested explicitly here. No
  # RUSTFLAGS override needed in this container (unlike macOS): libssl-dev already puts libssl on
  # a standard linker search path.
  cargo build -p spike-s3-throughput --release --features datachannel-backend --bin dc-throughput
  DC_BIN="$CARGO_TARGET_DIR/release/dc-throughput"

  DC_ROWS_FILE="$SPIKE_DIR/.rtt-dc-rows.tmp"
  : >"$DC_ROWS_FILE"

  for rtt in $RTTS; do
    half=$((rtt / 2))
    tc qdisc del dev lo root >/dev/null 2>&1 || true
    if [ "$half" -gt 0 ]; then
      tc qdisc add dev lo root netem delay "${half}ms"
    fi

    echo "== [datachannel] RTT=${rtt}ms ==" >&2
    out="$("$DC_BIN" --bytes "$BYTES" --json)"
    mb_per_s="$(printf '%s' "$out" | sed -n 's/.*"mb_per_s":\([0-9.]*\).*/\1/p')"
    printf '| %s | %s | %s | threshold=1048576 (fixed high-water=4194304; no --sctp-buf — see src/bin/dc-throughput.rs) | %s | bytes=%sMiB chunk=64KiB; raw=%s |\n' \
      "$DATE_STR" "$ENV_LABEL" "$rtt" "$mb_per_s" "$BYTES" "$out" \
      >>"$DC_ROWS_FILE"
  done

  echo "Done. datachannel-rs-backend rows written to $DC_ROWS_FILE (not yet in RESULTS.md):" >&2
  cat "$DC_ROWS_FILE" >&2

  # ── TCP baseline (environment/artifact check, follow-up) ──
  #
  # Answers: is the environment (`tc netem`-shaped loopback in this container) itself capable of
  # >= 15 MB/s @ 50 ms RTT, or is part of the SCTP collapse actually netem's default ~1000-packet
  # queue dropping packets under a bandwidth-delay-product burst? std-only binary
  # (src/bin/tcp-baseline.rs), no new crate dependencies. `tc -s qdisc show dev lo` is captured
  # after every cell so drop counts are directly visible next to each throughput number.
  cargo build -p spike-s3-throughput --release --bin tcp-baseline
  TCP_BIN="$CARGO_TARGET_DIR/release/tcp-baseline"

  TCP_ROWS_FILE="$SPIKE_DIR/.rtt-tcp-rows.tmp"
  QDISC_FILE="$SPIKE_DIR/.rtt-qdisc-stats.tmp"
  : >"$TCP_ROWS_FILE"
  : >"$QDISC_FILE"

  for rtt in $RTTS; do
    half=$((rtt / 2))
    tc qdisc del dev lo root >/dev/null 2>&1 || true
    if [ "$half" -gt 0 ]; then
      tc qdisc add dev lo root netem delay "${half}ms"
    fi

    echo "== [tcp] RTT=${rtt}ms (default netem queue limit) ==" >&2
    out="$("$TCP_BIN" --bytes "$BYTES" --json)"
    mb_per_s="$(printf '%s' "$out" | sed -n 's/.*"mb_per_s":\([0-9.]*\).*/\1/p')"
    printf '| %s | %s | %s | default netem queue limit | %s | bytes=%sMiB chunk=64KiB; raw=%s |\n' \
      "$DATE_STR" "$ENV_LABEL" "$rtt" "$mb_per_s" "$BYTES" "$out" \
      >>"$TCP_ROWS_FILE"

    {
      echo "== RTT=${rtt}ms (default netem queue limit), after tcp-baseline =="
      tc -s qdisc show dev lo
      echo
    } >>"$QDISC_FILE"
  done

  # ── 50 ms cell, netem queue limit raised (`limit 100000` packets, vs netem's default ~1000) ──
  # Re-run BOTH the TCP baseline and the webrtc backend (default 4 MiB buffer config) at 50 ms
  # with the larger queue, so the artifact question is answered for the SCTP collapse itself, not
  # only for TCP — a cheap, high-value addition beyond the literal TCP-only ask.
  tc qdisc del dev lo root >/dev/null 2>&1 || true
  tc qdisc add dev lo root netem delay 25ms limit 100000

  echo "== [tcp] RTT=50ms (raised netem queue limit=100000) ==" >&2
  out="$("$TCP_BIN" --bytes "$BYTES" --json)"
  mb_per_s="$(printf '%s' "$out" | sed -n 's/.*"mb_per_s":\([0-9.]*\).*/\1/p')"
  printf '| %s | %s | 50 | netem limit=100000 (raised from default ~1000) | %s | bytes=%sMiB chunk=64KiB; raw=%s |\n' \
    "$DATE_STR" "$ENV_LABEL" "$mb_per_s" "$BYTES" "$out" \
    >>"$TCP_ROWS_FILE"
  {
    echo "== RTT=50ms (raised netem queue limit=100000), after tcp-baseline =="
    tc -s qdisc show dev lo
    echo
  } >>"$QDISC_FILE"

  echo "== [webrtc, bonus artifact check] RTT=50ms (raised netem queue limit=100000) ==" >&2
  out="$("$BIN" --bytes "$BYTES" --sctp-buf 4194304 --json)"
  mb_per_s="$(printf '%s' "$out" | sed -n 's/.*"mb_per_s":\([0-9.]*\).*/\1/p')"
  printf '| %s | %s | 50 | webrtc backend, send=4194304/recv=4194304/threshold=1048576, netem limit=100000 (raised) | %s | bytes=%sMiB chunk=64KiB; raw=%s |\n' \
    "$DATE_STR" "$ENV_LABEL" "$mb_per_s" "$BYTES" "$out" \
    >>"$TCP_ROWS_FILE"
  {
    echo "== RTT=50ms (raised netem queue limit=100000), after webrtc backend (default 4 MiB buf) =="
    tc -s qdisc show dev lo
    echo
  } >>"$QDISC_FILE"

  tc qdisc del dev lo root >/dev/null 2>&1 || true

  echo "Done. TCP-baseline (+ bonus webrtc raised-limit) rows written to $TCP_ROWS_FILE, qdisc stats in $QDISC_FILE:" >&2
  cat "$TCP_ROWS_FILE" >&2
  echo "---" >&2
  cat "$QDISC_FILE" >&2

  # ── Parallel associations (follow-up): does N independent SCTP associations scale throughput? ──
  #
  # N=1/2/4/8 independent RTCPeerConnection pairs (`spike-s3-throughput --parallel N`), 50 ms RTT,
  # default netem queue limit, default 4 MiB buffer config, --bytes held fixed across N so this is
  # an apples-to-apples aggregate-throughput comparison (each connection gets total_bytes/N).
  PARALLEL_ROWS_FILE="$SPIKE_DIR/.rtt-parallel-rows.tmp"
  : >"$PARALLEL_ROWS_FILE"

  tc qdisc del dev lo root >/dev/null 2>&1 || true
  tc qdisc add dev lo root netem delay 25ms

  for n in 1 2 4 8; do
    echo "== [parallel] RTT=50ms parallel=${n} ==" >&2
    out="$("$BIN" --bytes "$BYTES" --parallel "$n" --json)"
    mb_per_s="$(printf '%s' "$out" | sed -n 's/.*"mb_per_s":\([0-9.]*\).*/\1/p')"
    printf '| %s | %s | 50 | parallel=%s, send=4194304/recv=4194304/threshold=1048576 (default) | %s | bytes=%sMiB chunk=64KiB; raw=%s |\n' \
      "$DATE_STR" "$ENV_LABEL" "$n" "$mb_per_s" "$BYTES" "$out" \
      >>"$PARALLEL_ROWS_FILE"
  done

  # Leave `lo` unshaped even though the container is `--rm` and about to disappear — cheap
  # insurance if this script is ever changed to run without `--rm` or on a longer-lived container.
  tc qdisc del dev lo root >/dev/null 2>&1 || true

  echo "Done. Parallel-association rows written to $PARALLEL_ROWS_FILE (not yet in RESULTS.md):" >&2
  cat "$PARALLEL_ROWS_FILE" >&2
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
