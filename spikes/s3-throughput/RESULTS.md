# S3 — DataChannel throughput results

Pass criteria (verbatim, `docs/DESIGN.md` §A13): ≥ 50 MB/s LAN; ≥ 15 MB/s @ 50 ms RTT; knobs
documented. See `docs/SPIKES.md` (§S3) for the full method.

## Status: **Run. LAN passes; the 50 ms RTT bar FAILS, badly, and buffer tuning does not fix it.**

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
  `with_data_channel_send_buffer_limit`) can address. **Recommendation: invoke A8's documented
  fallback clause** ("evaluate `datachannel-rs` if S3 fails") — re-run this same method against
  `datachannel-rs` before concluding ADR-005's transport choice, since the buffer knobs this crate
  exposes were tried and did not move the number.
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
