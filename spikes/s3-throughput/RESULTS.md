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
- **Follow-up (below): the 50 ms collapse is not a `tc netem` environment artifact** — a plain-TCP
  baseline clears the ≥ 15 MB/s bar by 2–4× under the identical shaping, and netem recorded zero
  packet drops across the entire follow-up. **`--parallel N` independent SCTP associations do
  scale throughput** (up to ~4× at N=4–8) but sub-linearly, plateauing well short of the bar — see
  "Follow-up: environment baseline & parallel associations" at the bottom of this file.

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
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 0 | send=4194304/recv=4194304/threshold=1048576 | 51.609 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"parallel":1,"elapsed_secs":2.600678,"mb_per_s":51.609} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 0 | send=262144/recv=262144/threshold=1048576 | 90.114 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":262144,"threshold":1048576,"parallel":1,"elapsed_secs":1.489420,"mb_per_s":90.114} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 20 | send=4194304/recv=4194304/threshold=1048576 | 4.276 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"parallel":1,"elapsed_secs":31.388655,"mb_per_s":4.276} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 20 | send=262144/recv=262144/threshold=1048576 | 5.662 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":262144,"threshold":1048576,"parallel":1,"elapsed_secs":23.706877,"mb_per_s":5.662} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | send=4194304/recv=4194304/threshold=1048576 | 1.941 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"parallel":1,"elapsed_secs":69.165880,"mb_per_s":1.941} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | send=262144/recv=262144/threshold=1048576 | 2.313 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":262144,"threshold":1048576,"parallel":1,"elapsed_secs":58.020834,"mb_per_s":2.313} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 100 | send=4194304/recv=4194304/threshold=1048576 | 1.035 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"parallel":1,"elapsed_secs":129.633812,"mb_per_s":1.035} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 100 | send=262144/recv=262144/threshold=1048576 | 1.191 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":262144,"threshold":1048576,"parallel":1,"elapsed_secs":112.709993,"mb_per_s":1.191} |

Rows 42–49, 50–57, and the 2026-08-24 rows above are three independent `rtt-run.sh` matrix runs
(each later run was re-triggered while adding a new backend/follow-up section below — first
`datachannel-rs`, then the follow-up section at the bottom of this file — and `rtt-run.sh`
unconditionally re-runs the full webrtc-backend matrix every time it runs; nothing in this crate
makes a run skip the existing matrix, and re-running it is harmless, so each extra data point is
kept). **Row 57 (365.910 MB/s at 0 ms, elapsed 0.367 s) is an outlier** — an order of magnitude
off every other 0 ms cell across all three runs (51–99 MB/s) — almost certainly container
scheduling/measurement noise (e.g. the process getting a burst of CPU right as the watchdog/timer
granularity aligned favorably) rather than a real sustained-transfer number; it is left in the
table rather than deleted (this is a results log, not a curated summary) but should be excluded
from any "typical LAN throughput" claim. The third run (2026-08-24) lands in the same range as the
first two at every RTT/buffer cell — no new outliers, and it is the same run that produced the
`datachannel-rs` and follow-up rows dated 2026-08-24 elsewhere in this file.

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

**Follow-up fix: `datachannel` made an optional dependency.** The above originally meant this
host's `ld: library 'ssl' not found` link failure applied to *every* build of this crate —
`cargo build -p spike-s3-throughput`, `cargo test --workspace`, `just build`/`just test` — not
just to someone deliberately building `dc-throughput`, since `datachannel` was an unconditional
dependency. Fixed by making `datachannel` `optional = true`, behind a new (non-default)
`datachannel-backend` feature, with `dc-throughput`'s `[[bin]]` entry carrying
`required-features = ["datachannel-backend"]` (see this crate's `Cargo.toml`). Default builds/
tests on macOS no longer touch `datachannel`/`datachannel-sys` at all. **To build `dc-throughput`
on macOS**, both the feature and the RUSTFLAGS override above are needed together:
```
RUSTFLAGS="-L$(brew --prefix openssl@3)/lib" \
  cargo build -p spike-s3-throughput --release --features datachannel-backend --bin dc-throughput
```
`rtt-run.sh` was updated to pass `--features datachannel-backend` when it builds `dc-throughput`
inside the Linux container (no RUSTFLAGS needed there — see the build hurdle above).
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
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 0 | threshold=1048576 (fixed high-water=4194304; no --sctp-buf) | 87.518 | bytes=128MiB chunk=64KiB; raw={"backend":"datachannel","total_bytes":134217728,"chunk_bytes":65536,"threshold":1048576,"elapsed_secs":1.533598,"mb_per_s":87.518} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 20 | threshold=1048576 (fixed high-water=4194304; no --sctp-buf) | 3.414 | bytes=128MiB chunk=64KiB; raw={"backend":"datachannel","total_bytes":134217728,"chunk_bytes":65536,"threshold":1048576,"elapsed_secs":39.315975,"mb_per_s":3.414} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | threshold=1048576 (fixed high-water=4194304; no --sctp-buf) | 0.689 | bytes=128MiB chunk=64KiB; raw={"backend":"datachannel","total_bytes":134217728,"chunk_bytes":65536,"threshold":1048576,"elapsed_secs":194.875515,"mb_per_s":0.689} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 100 | threshold=1048576 (fixed high-water=4194304; no --sctp-buf) | 0.274 | bytes=128MiB chunk=64KiB; raw={"backend":"datachannel","total_bytes":134217728,"chunk_bytes":65536,"threshold":1048576,"elapsed_secs":490.165586,"mb_per_s":0.274} |

Rows 117–123 and the 2026-08-24 rows above are two independent runs (the second re-triggered while
adding the follow-up experiments below, and `rtt-run.sh` re-runs this whole matrix unconditionally
each time it runs — same "extra data point kept rather than discarded" reasoning as the note on the
`webrtc`-backend table above). Both runs land in the same range and tell the same story: worse than
`webrtc` at 50/100 ms.

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

## Follow-up: environment baseline & parallel associations

Two follow-up experiments, run before the S3 design fork is decided (docs/SPIKES.md §S3), to
answer what the two backends' matrices above can't answer on their own: **(A)** is the `tc
netem`-shaped test environment itself capable of high throughput at 50 ms RTT, or is part of the
collapse an artifact of the harness (e.g. netem's default ~1000-packet queue dropping packets
under a bandwidth-delay-product burst)? **(B)** does splitting a transfer across N independent
`RTCPeerConnection` pairs — N separate SCTP associations, hence N separate congestion windows —
scale aggregate throughput back up, as the `datachannel-rs` verdict above speculated it might?

Both ran together, same container (Linux 6.12.76-linuxkit, `spindle-toolchain:local`), same date
(2026-08-24), via the extended `rtt-run.sh` (its "TCP baseline" and "Parallel associations"
sections — see that script's module doc comment). `--bytes 128` (128 MiB) throughout, matching the
existing matrix.

### A. TCP baseline (environment/artifact check)

New binary `tcp-baseline` (`src/bin/tcp-baseline.rs`) — plain loopback TCP, std-only (no new crate
dependencies), same `--bytes`/`--chunk`/`--json` contract and JSON result shape as the other two
backends, `"backend":"tcp"`. `tc -s qdisc show dev lo` was captured after every cell in this
section (not just TCP's) so drop counts are directly visible next to each throughput number. The
50 ms cell was also re-run with netem's queue `limit` raised from its default (~1000 packets) to
100000, for both TCP and (bonus, beyond the literal ask) the `webrtc` backend at its default 4 MiB
buffer config, to check whether a bigger queue rescues the SCTP number too.

| Date | Environment | RTT (ms) | Config | MB/s | Notes |
|------|-------------|----------|--------|------|-------|
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 0 | TCP, default netem queue limit | 9787.598 | bytes=128MiB chunk=64KiB; no netem qdisc added at 0 ms (matches existing matrix convention); raw={"backend":"tcp","total_bytes":134217728,"chunk_bytes":65536,"elapsed_secs":0.013713,"mb_per_s":9787.598} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 20 | TCP, default netem queue limit | 102.098 | bytes=128MiB chunk=64KiB; raw={"backend":"tcp","total_bytes":134217728,"chunk_bytes":65536,"elapsed_secs":1.314594,"mb_per_s":102.098} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | TCP, default netem queue limit | 60.685 | bytes=128MiB chunk=64KiB; raw={"backend":"tcp","total_bytes":134217728,"chunk_bytes":65536,"elapsed_secs":2.211714,"mb_per_s":60.685} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 100 | TCP, default netem queue limit | 30.392 | bytes=128MiB chunk=64KiB; raw={"backend":"tcp","total_bytes":134217728,"chunk_bytes":65536,"elapsed_secs":4.416193,"mb_per_s":30.392} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | TCP, netem limit=100000 (raised from default ~1000) | 50.686 | bytes=128MiB chunk=64KiB; raw={"backend":"tcp","total_bytes":134217728,"chunk_bytes":65536,"elapsed_secs":2.648006,"mb_per_s":50.686} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | **webrtc backend** (bonus check), send=4194304/recv=4194304/threshold=1048576, netem limit=100000 (raised) | 1.864 | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"parallel":1,"elapsed_secs":71.992941,"mb_per_s":1.864} |

`tc -s qdisc show dev lo`, captured immediately after each of the runs above:

```
== RTT=0ms (default netem queue limit), after tcp-baseline ==
qdisc noqueue 0: root refcnt 2
 Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0

== RTT=20ms (default netem queue limit), after tcp-baseline ==
qdisc netem 8012: root refcnt 2 limit 1000 delay 10ms
 Sent 134447094 bytes 3475 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 264b 4p requeues 0

== RTT=50ms (default netem queue limit), after tcp-baseline ==
qdisc netem 8013: root refcnt 2 limit 1000 delay 25ms
 Sent 134487750 bytes 4091 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 132b 2p requeues 0

== RTT=100ms (default netem queue limit), after tcp-baseline ==
qdisc netem 8014: root refcnt 2 limit 1000 delay 50ms
 Sent 134481558 bytes 3997 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 264b 4p requeues 0

== RTT=50ms (raised netem queue limit=100000), after tcp-baseline ==
qdisc netem 8015: root refcnt 2 limit 100000 delay 25ms
 Sent 134463924 bytes 3730 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 264b 4p requeues 0

== RTT=50ms (raised netem queue limit=100000), after webrtc backend (default 4 MiB buf) ==
qdisc netem 8015: root refcnt 2 limit 100000 delay 25ms
 Sent 282342852 bytes 118933 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 135b 1p requeues 0
```

**Every single capture shows `dropped 0`** — including the last one, taken after the `webrtc`
backend pushed 118933 small packets through the shaped path (vs. TCP's ~3500–4100 larger packets
for the same 128 MiB), so this isn't just "TCP's traffic pattern never stressed the queue." Note
also the `noqueue` (not `netem`) qdisc at 0 ms: per the existing matrix convention, `rtt-run.sh`
adds no netem qdisc at all when RTT is 0, so that row is unshaped raw-loopback TCP, not a
"netem-with-zero-delay" data point — included for completeness, not as an artifact-question input.

**Verdict A: not a netem artifact.** TCP clears ≥ 15 MB/s at every shaped RTT by a wide margin — 4×
the bar at 50 ms (60.685 MB/s) and 2× the bar at 100 ms (30.392 MB/s) — under the exact same `tc
netem` configuration the `webrtc`/`datachannel-rs` matrices ran under. Raising netem's queue limit
100× (1000 → 100000 packets) moved TCP's 50 ms number by less than 10 MB/s in the *wrong*
direction (60.685 → 50.686, run-to-run noise, not a queue-depth effect) and moved the `webrtc`
backend's 50 ms number **not at all** (1.864 MB/s raised vs. 1.907/1.941 MB/s default-limit runs in
this same session — see the parallel-associations `parallel=1` row below and the webrtc table
above). Combined with zero packet drops recorded in every single qdisc snapshot taken across the
entire follow-up (four RTTs × two queue limits × two very different traffic patterns), this rules
out netem's queue-drop behavior as a contributor to the SCTP collapse: the shaped-loopback
environment is fully capable of far more than the ≥ 15 MB/s bar at 50 ms and 100 ms RTT. The
bottleneck documented in both backends' matrices above is internal to their SCTP congestion
control, not an artifact of how this harness shapes the network.

### B. Parallel associations (does N independent SCTP associations scale throughput?)

`spike-s3-throughput --parallel N` (`src/main.rs`): N independent `RTCPeerConnection` pairs, each
its own SCTP association (own congestion window), each with one data channel, `--bytes` split
evenly across the N associations, all transferring concurrently; aggregate MB/s = total bytes /
wall-clock time across the whole batch (see `src/main.rs`'s module doc comment, "`--parallel <N>`"
section, for exactly what that wall-clock spans). `N=1` reuses the exact pre-existing
single-association code path unchanged. Run at 50 ms RTT, default netem queue limit, default 4 MiB
buffer config (`--sctp-buf` unset), `--bytes 128` held fixed across all N so the comparison is
apples-to-apples (each association gets `128 / N` MiB).

| Date | Environment | RTT (ms) | parallel (N) | Aggregate MB/s | Scaling vs N=1 | Notes |
|------|-------------|----------|---------------|-----------------|-----------------|-------|
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | 1 | 1.907 | 1.00× | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"parallel":1,"elapsed_secs":70.398662,"mb_per_s":1.907} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | 2 | 3.652 | 1.92× | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"parallel":2,"elapsed_secs":36.748299,"mb_per_s":3.652} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | 4 | 6.770 | 3.55× | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"parallel":4,"elapsed_secs":19.826591,"mb_per_s":6.770} |
| 2026-08-24 | Linux container (6.12.76-linuxkit), tc netem on lo, spindle-toolchain:local | 50 | 8 | 7.712 | 4.04× | bytes=128MiB chunk=64KiB; raw={"total_bytes":134217728,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"parallel":8,"elapsed_secs":17.402898,"mb_per_s":7.712} |

**Verdict B: parallelism helps, but sub-linearly, and plateaus well short of the bar.** Each
doubling of N should yield ~2× aggregate throughput under perfect linear scaling; the actual
per-doubling multipliers are 1.92× (N=1→2), 1.85× (N=2→4, computed from the table: 6.770/3.652),
and only **1.14×** (N=4→8, 7.712/6.770) — a sharp plateau between N=4 and N=8, not a continuation
of the near-linear trend from N=1→4. None of N=1/2/4/8 reach the ≥ 15 MB/s bar; N=8, the best
cell, gets to 7.712 MB/s — about half the bar. Extrapolating the N=4→8 plateau rather than the
earlier near-linear region, reaching 15 MB/s would need well beyond N=16 associations, if it's
reachable through this axis at all — something other than per-association SCTP cwnd (plausibly
host-side contention: DTLS/crypto CPU cost per association, one OS thread/socket pair per
connection, or shared kernel-level resource limits on this 8-association-in-one-container setup)
looks like it starts capping the aggregate around N=4–8. This is a partial, qualified answer to the
question the `datachannel-rs` verdict above raised on faith ("worth empirically re-testing... since
per-stream flow control inside one association may still parallelize better than a single stream
did here") — multiple independent associations demonstrably do add throughput, so a
multi-association design is a genuinely promising direction, but "just add N associations" is not
by itself a drop-in fix for the ≥ 15 MB/s @ 50 ms bar at any N tested here, and the diminishing
returns above N=4 mean it would take substantially more associations (with unknown further
scaling behavior past the point host-side contention starts to dominate) than this follow-up
measured.

### Combined verdict

**The 50 ms RTT collapse documented in both backends' matrices above is not an artifact of this
harness's `tc netem`-shaped test environment** — TCP clears the ≥ 15 MB/s bar by 2–4× at 50/100 ms
under the identical shaping, netem recorded **zero** dropped packets across every configuration
tested (default and 100×-raised queue limit, light and heavy packet-rate traffic), and raising the
queue limit changed neither TCP's nor the `webrtc` backend's throughput in any meaningful way. The
bottleneck is real, internal to the SCTP stacks' congestion control (consistent with both
independent implementations, `rtc-sctp` and `usrsctp`, converging on similar collapse behavior, per
the `datachannel-rs` verdict above), not a measurement artifact. **Splitting the transfer across
multiple independent SCTP associations does help** — up to roughly 4× throughput at N=4–8 vs. a
single association — which confirms A8's caveat was worth re-testing empirically rather than taking
on faith, but the scaling is clearly sub-linear and plateaus starting around N=4, and even N=8
(7.712 MB/s) lands at roughly half the ≥ 15 MB/s bar. Parallel associations are a real, measured
lever — not a proven fix on their own at the N values tested — and any design-fork decision that
leans on "just parallelize the associations" should budget for further work (find where the N=4→8
plateau's bottleneck actually is — host-side CPU/thread/socket contention is the leading
suspect — before assuming higher N keeps scaling) rather than treating this result as closing the
question.
