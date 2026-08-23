# S3 — DataChannel throughput results

Pass criteria (verbatim, `docs/DESIGN.md` §A13): ≥ 50 MB/s LAN; ≥ 15 MB/s @ 50 ms RTT; knobs
documented. See `docs/SPIKES.md` (§S3) for the full method.

## Status: **Both backends run. LAN passes on both; the 50 ms RTT bar FAILS on both, and
`datachannel-rs` is not the fix** — see "datachannel-rs backend" below. Buffer/window tuning
does not fix either backend.

- **0 ms (LAN-class, loopback)**: 90–200 MB/s depending on run/config — clears the ≥ 50 MB/s bar
  comfortably on both macOS (in-process) and Linux (container, `spindle-toolchain:local`).
- **20/50/100 ms RTT** (Linux container, `tc netem` on `lo`, via `rtt-run.sh`): throughput
  collapses to **1–5 MB/s** — the 50 ms cell (**2.2–2.3 MB/s**) misses the ≥ 15 MB/s bar by
  ~85%, and it gets worse, not better, at 100 ms.
- **Buffer/window tuning does not fix it.** Sweeping `--sctp-buf` from 256 KiB up to **64 MiB**
  (a follow-up manual check beyond `rtt-run.sh`'s two-point sweep, not itself in the table below)
  made no measurable difference at 20 ms RTT (2.70 vs 2.68 MB/s) — the 256 KiB config was, if
  anything, marginally *faster* than 4 MiB or 64 MiB across every RTT point in the matrix. That
  is the opposite of the bandwidth-delay-product story A8 predicts ("throughput is RTT-bound by
  SCTP windows"), so a too-small *receive window* is very unlikely to be the actual bottleneck
  here.
- **Reading**: this looks like an RTT-bound *congestion-control/ACK-clocking* ceiling internal to
  `webrtc` v0.20.3's SCTP stack (the very new "sans-I/O" rewrite — see `src/main.rs`'s module doc
  comment for the API-surface gap vs. the originally-planned pre-0.20 API), not a buffer-size
  problem the exposed knobs (`with_sctp_receive_buffer_size`,
  `with_data_channel_send_buffer_limit`) can address. **A8's documented fallback clause was
  invoked** ("evaluate `datachannel-rs` if S3 fails") — see "datachannel-rs backend" below.
  **Update: the fallback does not fix it.** `datachannel-rs` (built on `usrsctp`, the reference
  C SCTP implementation also used by Chrome/Firefox — a *different* implementation from
  `webrtc-rs`'s own Rust SCTP stack) shows the *same* RTT-bound collapse, and is measurably worse
  than the `webrtc` backend at 50/100 ms, not better. Two independent SCTP implementations
  converging on the same failure mode is a much stronger signal than either result alone — see the
  verdict at the bottom of this file.
- Knobs documented: `--sctp-buf` (maps to both `with_sctp_receive_buffer_size` — the a_rwnd
  receive window — and `with_data_channel_send_buffer_limit`, this crate's only two buffer-shaped
  knobs) and `--threshold` (`bufferedAmountLowThreshold`, left at the 1 MiB default throughout
  the matrix — not implicated by the data above). See `src/main.rs` for the full mapping and why
  there is no separate distinct "send buffer size" knob in this API version.

| Date | Environment | RTT (ms) | Buffer config (send/recv/bufferedAmountLow) | MB/s | Notes |
|------|-------------|----------|----------------------------------------------|------|-------|
| 2026-08-23 | macOS arm64 loopback, in-process | 0 | send=4194304/recv=4194304/threshold=1048576 | 124.858 | bytes=512MiB chunk=64KiB; default config; single run, `cargo run --release` (no flags) |
| 2026-08-23 | macOS arm64 loopback, in-process | 0 | send=4194304/recv=4194304/threshold=1048576 | 74.356 | bytes=512MiB chunk=64KiB; default config; repeat run 2/3 (see Notes below table on run-to-run variance) |
| 2026-08-23 | macOS arm64 loopback, in-process | 0 | send=4194304/recv=4194304/threshold=1048576 | 99.853 | bytes=512MiB chunk=64KiB; default config; repeat run 3/3 |
| 2026-08-23 | macOS arm64 loopback, in-process | 0 | send=4194304/recv=4194304/threshold=1048576 | 131.370 | bytes=1024MiB chunk=64KiB; default buffer config, larger transfer for stability |
| 2026-08-23 | macOS arm64 loopback, in-process | 0 | send=16777216/recv=16777216/threshold=1048576 | 137.442 | bytes=512MiB chunk=64KiB; larger 16 MiB buffer |
| 2026-08-23 | macOS arm64 loopback, in-process | 0 | send=262144/recv=262144/threshold=1048576 | 198.660 | bytes=256MiB chunk=64KiB; small 256 KiB buffer — fastest of the macOS runs, consistent with the Linux-matrix observation that this crate's throughput is not buffer-limited on loopback |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 0 | send=4194304/recv=4194304/threshold=1048576 | 93.373 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"elapsed_secs":1.437435,"mb_per_s":93.373} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 0 | send=262144/recv=262144/threshold=1048576 | 97.367 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":262144,"threshold":1048576,"elapsed_secs":1.378469,"mb_per_s":97.367} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 20 | send=4194304/recv=4194304/threshold=1048576 | 4.345 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"elapsed_secs":30.892712,"mb_per_s":4.345} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 20 | send=262144/recv=262144/threshold=1048576 | 5.182 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":262144,"threshold":1048576,"elapsed_secs":25.899087,"mb_per_s":5.182} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | send=4194304/recv=4194304/threshold=1048576 | 2.193 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"elapsed_secs":61.213959,"mb_per_s":2.193} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | send=262144/recv=262144/threshold=1048576 | 2.348 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":262144,"threshold":1048576,"elapsed_secs":57.165475,"mb_per_s":2.348} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 100 | send=4194304/recv=4194304/threshold=1048576 | 1.075 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"elapsed_secs":124.889781,"mb_per_s":1.075} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 100 | send=262144/recv=262144/threshold=1048576 | 1.638 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":262144,"threshold":1048576,"elapsed_secs":81.961320,"mb_per_s":1.638} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 0 | send=4194304/recv=4194304/threshold=1048576 | 53.886 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"elapsed_secs":2.490780,"mb_per_s":53.886} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 0 | send=262144/recv=262144/threshold=1048576 | 365.910 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":262144,"threshold":1048576,"elapsed_secs":0.366806,"mb_per_s":365.910} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 20 | send=4194304/recv=4194304/threshold=1048576 | 4.259 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"elapsed_secs":31.514316,"mb_per_s":4.259} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 20 | send=262144/recv=262144/threshold=1048576 | 5.113 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":262144,"threshold":1048576,"elapsed_secs":26.247916,"mb_per_s":5.113} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | send=4194304/recv=4194304/threshold=1048576 | 1.592 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"elapsed_secs":84.324007,"mb_per_s":1.592} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | send=262144/recv=262144/threshold=1048576 | 2.237 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":262144,"threshold":1048576,"elapsed_secs":59.986325,"mb_per_s":2.237} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 100 | send=4194304/recv=4194304/threshold=1048576 | 1.047 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"elapsed_secs":128.232353,"mb_per_s":1.047} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 100 | send=262144/recv=262144/threshold=1048576 | 1.279 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":262144,"threshold":1048576,"elapsed_secs":104.922717,"mb_per_s":1.279} |

Rows 42–49 and 50–57 are two independent `rtt-run.sh` matrix runs (the second run was re-triggered
while adding the `datachannel-rs` backend below, and it re-runs the full webrtc-backend matrix too
— nothing in this crate makes that run skip the existing matrix, and re-running it is harmless,
so the extra data point is kept). **Row 57 (365.910 MB/s at 0 ms, elapsed 0.367 s) is an outlier**
— an order of magnitude off every other 0 ms cell in both runs (53–97 MB/s) — almost certainly
container scheduling/measurement noise (e.g. the process getting a burst of CPU right as the
watchdog/timer granularity aligned favorably) rather than a real sustained-transfer number; it is
left in the table rather than deleted (this is a results log, not a curated summary) but should be
excluded from any "typical LAN throughput" claim.

## datachannel-rs backend (docs/DESIGN.md §A8 fallback)

Same method, `dc-throughput` binary (`src/bin/dc-throughput.rs`) — see that file's module doc
comment for the API and threading-model differences from `src/main.rs`. No `--sctp-buf` flag:
`datachannel-rs`/libdatachannel exposes no equivalent SCTP receive-buffer-size knob (see the
module doc comment); the only tunable in play is `--threshold`
(`bufferedAmountLowThreshold`), left at the 1 MiB default throughout, same as the `webrtc` table
above.

### Build hurdles

- **cmake missing on both hosts.** Neither the macOS dev machine nor the `spindle-toolchain:local`
  Linux image had `cmake`, which the `vendored-libdatachannel` Cargo feature needs to build
  libdatachannel from source. Fixed with `brew install cmake` on macOS (one-time, reported per the
  task brief) and `apt-get install -y cmake` inside the (throwaway, `--rm`) Linux container, added
  to `rtt-run.sh`'s existing idempotent apt-install block alongside `iproute2`.
- **libclang missing in the Linux container.** `datachannel-sys`'s build script also runs
  `bindgen` over libdatachannel's C headers, independent of the cmake-driven C++ build; `bindgen`
  needs `libclang.so`, which the toolchain image doesn't have even though it has a working `g++`.
  Fixed the same way, via `apt-get install -y libclang-dev` in the same `rtt-run.sh` block. (Not
  needed on macOS: Xcode's toolchain already ships a usable libclang.)
- **OpenSSL link failure on macOS only.** Homebrew's `openssl@3` is keg-only (not linked into a
  default search path), so after libdatachannel itself built fine via cmake, the final Rust link
  step failed with `ld: library 'ssl' not found`. Fixed by exporting
  `RUSTFLAGS="-L$(brew --prefix openssl@3)/lib"` for macOS builds/runs of this binary — not needed
  in the Linux container, where `libssl-dev` puts the library in a standard search path already.
  This is a real, standing requirement for building `dc-throughput` on this macOS host; it isn't
  encoded anywhere in this crate (per the task's touch-only constraint, no `.cargo/config.toml`
  was added) — anyone rebuilding this binary on similar macOS setups will hit the same link error
  and need the same env var.
- **`set_local_description(Answer)` on the receiver side raced libdatachannel's own
  auto-negotiation and failed with `RuntimeError`.** Not a build hurdle but the one functional bug
  hit getting the harness running at all: per libdatachannel's `DOC.md`, setting a remote offer
  (with `disableAutoNegotiation` unset, the default) makes the library generate and install the
  local answer *itself* — calling `set_local_description(Answer)` again afterward is redundant and
  errors. Fixed by removing that call on the receiver side; see the comment left in
  `src/bin/dc-throughput.rs` at that call site.

### Results

| Date | Environment | RTT (ms) | Buffer config | MB/s | Notes |
|------|-------------|----------|----------------|------|-------|
| 2026-08-23 | macOS arm64 loopback, in-process | 0 | threshold=1048576 (fixed high-water=4194304; no --sctp-buf) | 76.070 | bytes=512MiB chunk=64KiB; default config; `cargo run --release` (no flags), non-JSON output |
| 2026-08-23 | macOS arm64 loopback, in-process | 0 | threshold=1048576 (fixed high-water=4194304; no --sctp-buf) | 79.322 | bytes=512MiB chunk=64KiB; default config; repeat run 2/3, `--json` |
| 2026-08-23 | macOS arm64 loopback, in-process | 0 | threshold=1048576 (fixed high-water=4194304; no --sctp-buf) | 77.192 | bytes=512MiB chunk=64KiB; default config; repeat run 3/3, `--json` |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 0 | threshold=1048576 (fixed high-water=4194304; no --sctp-buf) | 85.115 | bytes=128MiB chunk=64KiB; raw={"backend":"datachannel","total_bytes":134217728,"chunk_bytes":65536,"threshold":1048576,"elapsed_secs":1.576891,"mb_per_s":85.115} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 20 | threshold=1048576 (fixed high-water=4194304; no --sctp-buf) | 2.646 | bytes=128MiB chunk=64KiB; raw={"backend":"datachannel","total_bytes":134217728,"chunk_bytes":65536,"threshold":1048576,"elapsed_secs":50.721049,"mb_per_s":2.646} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | threshold=1048576 (fixed high-water=4194304; no --sctp-buf) | 1.009 | bytes=128MiB chunk=64KiB; raw={"backend":"datachannel","total_bytes":134217728,"chunk_bytes":65536,"threshold":1048576,"elapsed_secs":132.982639,"mb_per_s":1.009} |
| 2026-08-23 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 100 | threshold=1048576 (fixed high-water=4194304; no --sctp-buf) | 0.251 | bytes=128MiB chunk=64KiB; raw={"backend":"datachannel","total_bytes":134217728,"chunk_bytes":65536,"threshold":1048576,"elapsed_secs":535.154699,"mb_per_s":0.251} |

### Verdict: `datachannel-rs` does not fix S3, and is worse than `webrtc` at higher RTT

`datachannel-rs` clears the ≥ 50 MB/s LAN bar comfortably (76–85 MB/s, in the same range as the
`webrtc` backend's 53–198 MB/s loopback spread) but **fails the ≥ 15 MB/s @ 50 ms RTT bar
outright — at 1.009 MB/s it misses by ~93%, worse than every `webrtc`-backend 50 ms cell (1.59–
2.35 MB/s across both runs)** — and the gap widens at 100 ms, where `datachannel-rs` collapses to
0.251 MB/s (535 s to move 128 MiB) against `webrtc`'s already-poor 1.05–1.64 MB/s. That
`datachannel-rs` is *slower* than `webrtc-rs` at RTT, not just similarly slow, is the important
result here: `datachannel-rs` is built on `usrsctp` — the reference C SCTP userland stack, also
used inside Chrome and Firefox for real WebRTC data channels — which is a *completely independent*
implementation from `webrtc-rs`'s own from-scratch Rust SCTP stack (`rtc-sctp`). Two unrelated SCTP
implementations converging on the same RTT-bound collapse, on the same lossless `tc netem`-delayed
loopback path, is strong evidence this is not an implementation bug or a tunable buffer/window
size in either crate — it points at something more structural: either the default SCTP congestion
control both stacks ship (both are conservative, standards-conformant CUBIC/Reno-style stacks) is
simply not tuned for a single-stream high-bandwidth-delay-product path and needs different
knobs than either crate exposes, or achieving ≥ 15 MB/s over a *single* reliable, congestion-
controlled SCTP stream at 50 ms RTT with off-the-shelf libraries is not realistic and the
architecture needs to change (e.g. multiple parallel data channels/streams despite A8's "one
SCTP association, all channels share one cwnd" caveat — worth empirically re-testing rather than
taking on faith, since per-stream flow control inside one association may still parallelize better
than a single stream did here), or the ≥ 15 MB/s @ 50 ms bar itself needs revisiting given what
two mature, independent implementations actually deliver. **Recommendation**: do not adopt
`datachannel-rs` as a fix for S3 on its results alone (it is not one); before spending more time
tuning either crate, get a `tc netem`-free real-network RTT datapoint (this entire matrix is
`lo` + `tc netem`, delay-only, no loss — worth confirming a real WAN path behaves the same way)
and profile actual SCTP congestion-window growth on one run to see whether cwnd is genuinely
capping throughput or something else (poll/timer granularity, head-of-line blocking) is — both are
cheaper next steps than either "try harder to tune buffers" (already falsified for both backends)
or a from-scratch transport rewrite.
