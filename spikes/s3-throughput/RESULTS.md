# S3 — DataChannel throughput results

Pass criteria (verbatim, `docs/DESIGN.md` §A13): ≥ 50 MB/s LAN; ≥ 15 MB/s @ 50 ms RTT; knobs
documented. See `docs/SPIKES.md` (§S3) for the full method.

## Status: **Both backends run. LAN passes on both; the 50 ms RTT bar FAILS on both, and
`datachannel-rs` is not the fix** — see "datachannel-rs backend" below. Buffer/window tuning
does not fix either backend.

**A10.29 (real Chrome dcSCTP peer + cwnd profiling): DONE — the full 0/20/50/100 ms matrix, both
directions, has been measured.** Both directions fail the ≥ 15 MB/s @ 50 ms bar against a real
Chrome `dcSCTP` peer, for two independently-diagnosed reasons — see "Results — RTT matrix (Linux
container, headless Chromium 151.0.7922.137, tc netem)" near the bottom of this file for the
matrix, the `rtc_sctp`-trace-based diagnosis, and the verdict. The runbook immediately below
("Browser-peer (dcSCTP) measurement plan") is kept for its harness/protocol documentation and its
0 ms macOS-host results; its macOS `dummynet` 50 ms recipe was superseded by a Linux-container
approach (`browser-rtt-run.sh`, `tc netem`) — see the dummynet dead-end note in the new section.

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

## Browser-peer (dcSCTP) measurement plan (A10.29)

Decision A10.29 (`docs/DESIGN.md` §A8): before revising the ≥ 15 MB/s @ 50 ms bar or reopening the
transport question, measure DataChannel throughput against a **real Chrome peer** (`dcSCTP`, a
third, independent SCTP implementation alongside `rtc-sctp` and `usrsctp`) instead of only
`webrtc-rs`/`datachannel-rs` talking to themselves, and get visibility into SCTP congestion-window
behavior during a run. This section is a **runbook — no measurements have been taken yet**. A
later session drives Chrome and records results here (append a results table under this section
the same way the tables above do, rather than replacing this runbook text).

### What's here

- `src/bin/browser-peer.rs` — Rust half: a signaling WebSocket server (`tokio-tungstenite`) plus
  the same `webrtc` 0.20.3 harness conventions as `src/main.rs` (one unordered-reliable data
  channel, `--sctp-buf`/`--chunk`/`--bytes`/`--threshold`, `--json` summary). Always the SDP
  offerer/data-channel creator; `--mode send|recv` controls which side pushes payload bytes once
  the channel is open. Full flag reference: `browser-peer --help`.
- `browser-peer.html` — Chrome half: a plain-JS page (no build step) opened directly via `file://`,
  connects out to the signaling WebSocket, does the offer/answer/ICE dance, and implements both
  transfer roles (receive-and-count, or send in fixed 64 KiB chunks with `bufferedAmountLow`
  backpressure). Shows live progress and posts its own measured result back over the WebSocket so
  the Rust side can print one merged `--json` summary.
- See `src/bin/browser-peer.rs`'s module doc comment for the full signaling protocol and exactly
  which side's number is authoritative for each `--mode`.

### How to run — LAN-class (loopback, no added RTT)

```
export PATH="$HOME/.local/share/mise/shims:$PATH"
cd spikes/s3-throughput

# Direction 1: send — Rust pushes bytes to Chrome (download path, the primary A9 metric)
cargo run --release --bin browser-peer -- --mode send --bytes 128

# Direction 2: recv — Chrome pushes bytes to Rust (upload path)
cargo run --release --bin browser-peer -- --mode recv --bytes 128 --json
```

Then open `browser-peer.html` (this directory) directly in Chrome — e.g. `open -a "Google Chrome"
browser-peer.html` on macOS, or drag the file into a tab. The page auto-connects to
`ws://127.0.0.1:9333/` on load (change the port field + click Connect if `--port` was overridden)
and drives the rest of the session automatically: SDP offer/answer, data channel open, the
transfer itself, live progress on the page, and a final result posted back to the terminal running
`browser-peer`, which prints one merged summary (human-readable by default, or `--json`).

With stats sampling (either direction):

```
cargo run --release --bin browser-peer -- --mode send --bytes 128 \
  --stats-interval-ms 200 --stats-out /tmp/browser-peer-stats.jsonl
```

Run both directions at least once at 0 ms before attempting the 50 ms recipe below — confirms the
harness itself (signaling, data channel open, backpressure) works before adding network shaping as
a variable.

### With ~50 ms RTT — macOS dummynet recipe (ABANDONED — kernel applies no delay on modern macOS)

macOS has no `tc netem` equivalent (that's why `rtt-run.sh`'s existing 0/20/50/100 ms matrix runs
inside a Linux container instead — see that script's module doc comment); shaping loopback
directly on macOS goes through the BSD firewall stack instead: `pfctl` (packet filter, decides
*which* packets get shaped) handing packets to `dnctl`/`ipfw` **dummynet** pipes (which *apply* the
delay).

**Update: this recipe was tried and does not work on this development host — see the "macOS
dummynet: non-functional" note in the "Results — RTT matrix" section near the bottom of this file
for the finding (pipes/anchor configure without error; the kernel applies no delay). The recipe
below is kept for reference only — do not spend more time on it on this class of macOS host.**
`browser-rtt-run.sh` (a Linux-container `tc netem` harness, same technique as `rtt-run.sh`)
replaced this approach entirely for the matrix in that section.

**Caveat before running**: both peers in this harness bind to an ephemeral UDP port
(`with_udp_addrs(vec!["127.0.0.1:0"])` in `src/bin/browser-peer.rs`/`src/main.rs` — port `0` means
"OS picks one"), so the exact port isn't known ahead of time. The rule below scopes by loopback
interface + protocol instead of by port, which is fine in an otherwise-quiet dev environment (nothing
else should be pushing UDP over `lo0` during a timed run) but will shape *all* loopback UDP
traffic system-wide while the pipe is active, not just this harness's traffic — worth being aware
of if anything else on the machine is sensitive to loopback latency during the test window.

```
# 1. One dummynet pipe per direction, 25 ms delay each way = 50 ms RTT round trip.
#    (Two separate pipes, not one pipe referenced twice, so each direction's queue is independent.)
sudo dnctl pipe 1 config delay 25ms
sudo dnctl pipe 2 config delay 25ms

# 2. pf rule set (a scoped anchor, not /etc/pf.conf directly) steering loopback UDP through the
#    pipes — one file, loaded into a named anchor so it can be removed cleanly later.
cat <<'EOF' | sudo pfctl -a spindle-s3-dummynet -f -
dummynet in  quick on lo0 proto udp from any to any pipe 1
dummynet out quick on lo0 proto udp from any to any pipe 2
EOF

# 3. Enable pf if it isn't already running (idempotent; harmless if already enabled).
sudo pfctl -e 2>/dev/null || true

# 4. Run the harness exactly as in the 0 ms section above (both --mode send and --mode recv).

# 5. Tear down — remove ONLY this anchor's rules (leaves any other pf configuration alone) and
#    delete both pipes. Do this even if a run fails/is interrupted, before doing anything else
#    that depends on normal loopback latency.
sudo pfctl -a spindle-s3-dummynet -F all
sudo dnctl -q flush
```

If `pfctl -e` reports pf was already enabled by something else (e.g. an existing firewall
configuration), do **not** run `sudo pfctl -d` during teardown — that would disable pf entirely,
not just remove this anchor. `pfctl -a spindle-s3-dummynet -F all` alone is sufficient and scoped.

### What to capture per cell

- **Rust `--json` summary** (`elapsed_secs`, `mb_per_s`, `peer_bytes`, `peer_elapsed_secs`,
  `peer_mb_per_s`) — one line per run, both `--mode send` and `--mode recv`, at 0 ms and ~50 ms.
- **`--stats-out` JSON-lines samples** — `t_ms`, `dc_bytes_sent`/`dc_bytes_received`,
  `transport_bytes_sent`/`transport_bytes_received`, `transport_packets_sent`/`transport_packets_received`,
  `candidate_pair_current_rtt_secs`, `candidate_pair_available_outgoing_bitrate`/`available_incoming_bitrate`
  (see "Stats field availability" below for what these mean and what's missing).
- **`chrome://webrtc-internals`** (open this tab *before* opening `browser-peer.html`, so it's
  capturing from the start of the session): find the peer connection's SCTP transport / data
  channel stats graphs and record dcSCTP's congestion window and RTT over time — this is the only
  side of this harness that can show real SCTP cwnd (see below). The page has a "Download the
  PeerConnection updates and stats data" control that exports the full session as a single file;
  save that alongside the Rust-side `--json`/`--stats-out` output for the same run.

### Stats field availability (Deliverable 3 finding)

`--stats-interval-ms`/`--stats-out` (both `src/main.rs` and `src/bin/browser-peer.rs`) sample
`PeerConnection::get_stats(Instant::now(), StatsSelector::None)` — `webrtc` 0.20.3's only public
stats surface, re-exported from the `rtc` crate as the W3C `RTCStatsReport` shape
(`webrtc::peer_connection::{RTCStatsReport, RTCStatsReportEntry, StatsSelector}`). Confirmed by
reading the vendored source directly (`~/.cargo/registry/src/.../rtc-0.20.3/src/statistics/`), not
by trial and error:

**Reachable and sampled by this harness** (`RTCDataChannelStats` via `report.data_channels()`,
`RTCTransportStats` via `report.transport()`, `RTCIceCandidatePairStats` via
`report.candidate_pairs()`):

| Field | Source stat | Notes |
|---|---|---|
| `dc_bytes_sent` / `dc_bytes_received` | `RTCDataChannelStats.bytes_sent`/`bytes_received` | Application data only, no SCTP/DTLS overhead |
| `dc_messages_sent` / `dc_messages_received` | `RTCDataChannelStats.messages_sent`/`messages_received` | |
| `transport_bytes_sent` / `transport_bytes_received` | `RTCTransportStats.bytes_sent`/`bytes_received` | Includes STUN/DTLS/SCTP overhead — always ≥ the `dc_*` counters |
| `transport_packets_sent` / `transport_packets_received` | `RTCTransportStats.packets_sent`/`packets_received` | |
| `candidate_pair_current_rtt_secs` | `RTCIceCandidatePairStats.current_round_trip_time` | **ICE/STUN connectivity-check RTT, not SCTP RTT** — a reasonable proxy on an otherwise-idle path (this harness's only traffic) but not literally the same number dcSCTP's own RTT estimator computes |
| `candidate_pair_available_outgoing_bitrate` / `available_incoming_bitrate` | `RTCIceCandidatePairStats.available_outgoing_bitrate`/`available_incoming_bitrate` | Congestion-feedback-derived bandwidth *estimate*, not a raw counter |

Also present in the report but not currently sampled by this harness (available if a future need
justifies extending the sampler): `RTCTransportStats` DTLS/ICE role and state, cipher suite, TLS
version, selected-candidate-pair-change count; `RTCIceCandidatePairStats` request/response counts,
discarded packets/bytes, nominated flag.

**NOT reachable through any public API — confirmed, not assumed** (this is the Deliverable 3
"cwnd?" answer): `webrtc` 0.20.3's `RTCStatsReportEntry` enum (the complete list of stats object
types `get_stats()` can ever return) has **no SCTP-transport-specific variant at all** — no
`RTCSctpTransportStats`, nothing analogous. Confirmed by reading
`rtc-0.20.3/src/statistics/report.rs`'s `RTCStatsReportEntry` enum definition directly: its
variants are `PeerConnection`, `Transport`, `IceCandidatePair`, `LocalCandidate`, `RemoteCandidate`,
`Certificate`, `Codec`, `DataChannel`, `InboundRtp`, `OutboundRtp`, `RemoteInboundRtp`,
`RemoteOutboundRtp`, `AudioSource`, `VideoSource`, `AudioPlayout` — an SCTP association's
congestion-control state isn't among them. Tracing further, in `rtc-sctp-0.20.3/src/association/mod.rs`,
the association's congestion-control fields are declared:

```rust
pub(crate) cwnd: u32,
rwnd: u32,
pub(crate) ssthresh: u32,
```

— `cwnd`/`ssthresh` are `pub(crate)` (visible only inside the `rtc-sctp` crate itself, not
re-exported anywhere), and `rwnd` (the receive window) isn't even `pub(crate)`, just private. The
`sctp::Association` struct that owns these fields is itself reachable only via a `pub(crate)`
field (`sctp_associations: HashMap<AssociationHandle, Association>`) buried inside `webrtc`'s own
internal peer-connection state (`peer_connection/transport/sctp/mod.rs`) — there is no public
method anywhere in `webrtc`, `rtc`, or `rtc-sctp` that returns cwnd, ssthresh, the receive window,
or bytes-in-flight for an SCTP association. Per the task brief's constraint (use what IS public;
do not fork or patch the crate), this harness does not attempt to reach these fields — doing so
would require either a patched fork of `rtc-sctp` or reflection-style unsafe code reaching into
`pub(crate)` internals from outside the crate, neither of which this task allows.

**The practical consequence**: on the Rust side, this harness can only *infer* backpressure/window
behavior indirectly — from throughput over time, `dc_bytes_sent`/`dc_bytes_received` growth
between samples, and (loosely) `transport_bytes_sent` vs. `dc_bytes_sent` as an overhead ratio —
never cwnd/rwnd/bytes-in-flight directly. **`chrome://webrtc-internals` is the only side of this
harness that can show real dcSCTP congestion-window behavior**: Chrome's `dcSCTP` implementation
exposes its own internal stats (including congestion window and RTT) through that page's data
channel / SCTP transport graphs, independent of whatever the W3C `getStats()` API surfaces to page
JavaScript. When a later session runs this harness, `chrome://webrtc-internals`'s cwnd/rtt graphs
are the authoritative source for "what did the congestion window actually do during this
transfer" — the Rust-side `--stats-out` samples are the throughput-and-byte-counter half of the
picture, not a substitute for it.

### Results — 0 ms (loopback, macOS host)

Date 2026-08-24 (early, same working session as the runbook above). macOS arm64 host, in-host
loopback (no shaping) — the ~50 ms dummynet leg above remains untested. Chrome 151.0.7922.172 (host
install), driven via browser automation. `browser-peer.html` was served over
`http://127.0.0.1:8377` (plain `python3 -m http.server`) rather than opened via `file://` as the
runbook above suggests — the automation extension refuses `file://` navigation, and `ws://` from an
`http://127.0.0.1` origin behaves identically to `ws://` from a `file://` page for this harness's
purposes; the page's own "never talks beyond 127.0.0.1" property is unchanged. Rust side:
`browser-peer --mode <send|recv> --bytes 256 --json --stats-interval-ms 200 --stats-out <path>`,
default buffers (`sctp_buf`=4194304, `threshold`=1048576), 64 KiB chunks.

| Date | Environment | RTT (ms) | Mode / direction | MB/s | Notes |
|------|-------------|----------|-------------------|------|-------|
| 2026-08-24 | macOS arm64 host, in-host loopback, real Chrome dcSCTP peer | 0 | send (Rust webrtc-rs → Chrome, download path) | 70.893 (Rust-side); peer-side 71.643 | bytes=256MiB chunk=64KiB; default buffers; raw={"mode":"send","total_bytes":268435456,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"elapsed_secs":3.786500,"mb_per_s":70.893,"peer_bytes":268435456,"peer_elapsed_secs":3.746849,"peer_mb_per_s":71.643} |
| 2026-08-24 | macOS arm64 host, in-host loopback, real Chrome dcSCTP peer | 0 | recv (Chrome → Rust webrtc-rs, upload path) | 60.236 (Rust-side); peer-side 62.004 | bytes=256MiB chunk=64KiB; default buffers; raw={"mode":"recv","total_bytes":268435456,"chunk_bytes":65536,"sctp_buf":4194304,"threshold":1048576,"elapsed_secs":4.456408,"mb_per_s":60.236,"peer_bytes":268435456,"peer_elapsed_secs":4.329300,"peer_mb_per_s":62.004} |

Both directions clear the ≥ 50 MB/s LAN-class bar against a **real Chrome dcSCTP peer** on the
first run — the harness (signaling, ICE, data channel open, backpressure, merged `--json` summary)
works end to end. 70.9 MB/s Rust→Chrome sits inside the 74–125 MB/s band the Rust↔Rust in-process
loopback runs produced elsewhere in this file, so interop with a third, independent SCTP
implementation (dcSCTP, alongside `rtc-sctp` and `usrsctp`) costs little at 0 ms — consistent with
the datachannel-rs verdict above, where the two mature stacks it compared also converged at low
RTT. The upload direction (recv, 60.2 MB/s) is ~15% slower than download; a plausible explanation is
that `browser-peer.html`'s JS-side 64 KiB send loop + `bufferedAmountLow` scheduling is the pacing
constraint here rather than SCTP itself, but this is a single run each direction — no repeat runs or
variance data yet, so treat the ~15% gap as suggestive rather than confirmed.

The decisive cells — 20/50/100 ms RTT — were **not** obtained via the dummynet recipe above; that
approach was later confirmed non-functional on this macOS host (see the "macOS dummynet:
non-functional" note in "Results — RTT matrix" below) and abandoned in favor of a Linux-container
`tc netem` harness (`browser-rtt-run.sh`), which produced the full matrix — see that section.
Stats sampling (`--stats-out`) captured 20 samples on the send run; candidate-pair RTT
(`candidate_pair_current_rtt_secs`) was ~0.5 ms throughout, confirming the path was in fact
unshaped as intended.

One environment note on measurement agreement: the throughput numbers here are Rust-process-
measured wall-clock over 256 MiB, and the peer's (Chrome's) own measurement of the same transfer
agrees within ~2.5% in both directions — the two independently-clocked sides corroborate each
other, which is some evidence against either side's number being a measurement artifact.

### Results — RTT matrix (Linux container, headless Chromium 151.0.7922.137, tc netem)

The decisive A10.29 leg: the full 0/20/50/100 ms matrix, both directions, against a real Chrome
`dcSCTP` peer. **Environment**: Debian 12 (bookworm) aarch64 container (`spindle-toolchain:local`),
headless Chromium 151.0.7922.137 (`--headless=new`), `webrtc` 0.20.3 (the `rtc-sctp` 0.20.3 crate)
on the Rust side, `tc netem delay <RTT/2>ms limit 10000` applied to `lo` (crossed twice per round
trip, same RTT/2-on-`lo` convention as `rtt-run.sh`), driven by `browser-rtt-run.sh` (this
directory) — a fully containerized harness that builds and runs `src/bin/browser-peer.rs` and
launches headless Chromium against `browser-peer.html` inside the same network namespace, so both
peers sit behind identical shaping.

| Date | Environment | RTT (ms) | Direction | MB/s | Notes |
|------|-------------|----------|-----------|------|-------|
| 2026-08-24 | Linux container (aarch64), Chromium 151.0.7922.137, tc netem on lo, spindle-toolchain:local | 0 | send (webrtc-rs → Chrome, download path) | 9.776 | bytes=128MiB chunk=64KiB; default buffers |
| 2026-08-24 | Linux container (aarch64), Chromium 151.0.7922.137, tc netem on lo, spindle-toolchain:local | 20 | send (webrtc-rs → Chrome, download path) | 2.076 | bytes=128MiB chunk=64KiB; default buffers |
| 2026-08-24 | Linux container (aarch64), Chromium 151.0.7922.137, tc netem on lo, spindle-toolchain:local | 50 | send (webrtc-rs → Chrome, download path) | 0.885 | bytes=64MiB chunk=64KiB; default buffers |
| 2026-08-24 | Linux container (aarch64), Chromium 151.0.7922.137, tc netem on lo, spindle-toolchain:local | 100 | send (webrtc-rs → Chrome, download path) | 0.484 | bytes=64MiB chunk=64KiB; default buffers |
| 2026-08-24 | Linux container (aarch64), Chromium 151.0.7922.137, tc netem on lo, spindle-toolchain:local | 0 | recv (Chrome dcSCTP → webrtc-rs, upload path) | 90.360 | bytes=128MiB chunk=64KiB; default buffers |
| 2026-08-24 | Linux container (aarch64), Chromium 151.0.7922.137, tc netem on lo, spindle-toolchain:local | 20 | recv (Chrome dcSCTP → webrtc-rs, upload path) | 0.179 | bytes=128MiB chunk=64KiB; default buffers; **hit the 300 s per-cell timeout** — MB/s computed from bytes actually transferred, not a completed run |
| 2026-08-24 | Linux container (aarch64), Chromium 151.0.7922.137, tc netem on lo, spindle-toolchain:local | 50 | recv (Chrome dcSCTP → webrtc-rs, upload path) | 0.083 | bytes=64MiB chunk=64KiB; default buffers; **hit the 300 s per-cell timeout** — MB/s computed from bytes actually transferred, not a completed run |
| 2026-08-24 | Linux container (aarch64), Chromium 151.0.7922.137, tc netem on lo, spindle-toolchain:local | 100 | recv (Chrome dcSCTP → webrtc-rs, upload path) | 0.044 | bytes=64MiB chunk=64KiB; default buffers; **hit the 300 s per-cell timeout** — MB/s computed from bytes actually transferred, not a completed run |

Both directions clear the ≥ 50 MB/s LAN bar at 0 ms (9.776 and 90.360 MB/s — the send/recv
asymmetry at 0 ms is consistent with the ~15% send/recv gap already noted in the macOS-host 0 ms
result above). **Both directions miss the ≥ 15 MB/s @ 50 ms bar (docs/DESIGN.md §A13) by a wide
margin** — send at 0.885 MB/s (~94% short), recv at 0.083 MB/s (~99.4% short) — and both get worse,
not better, at 100 ms. For scale: plain TCP on this exact same shaped path already measured
60.685 MB/s at 50 ms (see "Follow-up: environment baseline & parallel associations" above) — 4×
the bar and ~69× this section's send number — so the shaped environment itself is nowhere near the
bottleneck.

#### Why the shaped `recv` cells crawl

The `recv`-direction numbers (Chrome `dcSCTP` is the sender, `webrtc-rs` the receiver) show the
same signature seen earlier in this file's host-level `webrtc-rs`↔`webrtc-rs` matrix: throughput
that looks like **a fixed number of bytes moved once per RTT**, not a ramping congestion window.
Working out bytes-per-RTT from the measured rates (`MB/s × RTT`) lands at **~4.3–4.6 KB per
round trip at every shaped RTT** — RFC 4960's default *initial* congestion window,
`min(4·MTU, max(2·MTU, 4380))`, which for this harness's ~1228 B SCTP MTU evaluates to exactly
4380 B. The number never grows past that value for the life of a multi-second-to-multi-minute
transfer with zero loss.

**Harness artifacts ruled out**:
- **Not a `tc netem` queue-drop artifact.** Re-running the 50 ms `recv` cell with netem's queue
  raised to `limit 10000` (this section's harness now applies that limit unconditionally, up from
  the implicit ~1000-packet default) still shows **zero drops** (`tc -s qdisc show dev lo`:
  `dropped 0` after the cell) and **zero UDP-socket-layer errors**
  (`nstat -az UdpInErrors UdpRcvbufErrors`: both `0` before and after) — consistent with the
  existing "Follow-up: environment baseline" section's zero-drop finding for the `webrtc-rs`↔
  `webrtc-rs` matrix.
- **Not JS-side pacing.** `browser-peer.html`'s send loop is event-driven (`bufferedamountlow`,
  64 KiB chunks, 8 MiB high-water mark) — it keeps up to 8 MiB queued ahead of the SCTP layer, far
  more than the ~4.4 KB/RTT actually being drained, so the page is never the limiting stage.
- **Wire overhead is normal.** `transport_bytes_received` vs. `dc_bytes_received` in the stats
  samples runs ~6% over application bytes throughout — SCTP/DTLS header cost, not a sign of
  retransmission or excess control traffic.

**The `rtc_sctp`-trace evidence exonerates the `webrtc-rs` receiver.** Added `env_logger` (gated
behind `RUST_LOG`, e.g. `RUST_LOG=rtc_sctp=trace`) to `browser-peer.rs` so `rtc-sctp` 0.20.3's own
`log`-facade tracing (module target `rtc_sctp::association` — this is webrtc-rs 0.20's
restructured SCTP crate, *not* a crate literally named `webrtc-sctp`) reaches stderr. An 8 MiB
`recv` cell at 50 ms RTT recorded:

- **6,087 DATA fragments** received, average payload 1,139.5 B (SCTP-MTU-bound fragmentation of
  the page's 64 KiB chunks).
- **1,494 outgoing SACKs** — 4.07 DATA fragments acked per SACK on average; **1,378/1,494 (92%)**
  advance the cumulative TSN by exactly 4, matching the ~4.3–4.6 KB/RTT invariant almost exactly.
- Steady-state cadence **~17–19 SACKs/sec**, i.e. roughly **one SACK per RTT** (≈55–59 ms apart,
  tracking the configured 50 ms RTT, not a slow fixed delayed-ack timer) — corroborated
  independently by `candidate_pair_current_rtt_secs` ≈ 0.0513–0.0529 s in the same run's stats.
- Advertised receive window (`a_rwnd`) healthy and stable throughout, **~4.13–4.19 MB** (default
  `max_receive_buffer_size` minus whatever is briefly queued in the reassembly queue) — never
  remotely close to being the limiting factor for a ~4.4 KB cwnd.
- **`dupTsn=[]` in all 1,494 SACKs** — zero loss, zero gap-ack blocks, zero reneging — and **no
  `T3-rtx timed out` events** anywhere in the log (only harmless startup timer-start noise).

Representative lines (`.browser-rtt-raw/rtt50_recv-rust-trace.log`):

```
[2026-08-24T18:06:38Z DEBUG rtc_sctp::association] [Server] DATA: tsn=1252081413 peer_last_tsn=1252081412 immediateSack=false len=1160, unordered=true
[2026-08-24T18:06:38Z DEBUG rtc_sctp::association] [Server] sending SACK: SACK cumTsnAck=1252081423 arwnd=4182592 dupTsn=[]
[2026-08-24T18:06:38Z DEBUG rtc_sctp::association] [Server] sending SACK: SACK cumTsnAck=1252081427 arwnd=4177952 dupTsn=[]
```

**Conclusion**: every RTT, Chrome sends almost exactly one initial-cwnd's worth of data (~4 SCTP
fragments) and gets back one clean cumulative SACK acking all of it, with no loss and no
artificial ACK delay — the textbook RFC 4960 slow-start growth precondition (bytes acked == cwnd,
no loss) is satisfied on essentially every RTT for the whole transfer, yet the effective congestion
window never grows. With the receiver's behavior clean by every wire-visible measure, the freeze
is inside Chrome `dcSCTP`'s own cwnd-growth ("was cwnd fully utilized when this data was sent")
gating, evaluated against this clean 1-SACK-per-RTT cadence — not a defect reachable or fixable
from the `webrtc-rs` receiver side. Confirming the exact internal cause would need either a
debug/non-release Chromium build (dcSCTP's own verbose logging, `RTC_DLOG`, is compiled out of
release Chromium — confirmed empirically: `--enable-logging=stderr --vmodule=*dcsctp*=9` produced
zero matching lines even though other Chromium `stderr` logging worked) or a raw packet capture
correlated against dcSCTP's source — both out of scope for this harness.

#### Why the shaped `send` cells crawl

The `send`-direction numbers (`webrtc-rs` is the sender, Chrome `dcSCTP` the receiver) show the
same RTT-bound collapse already documented for the host-level `webrtc-rs`↔`webrtc-rs` matrix
earlier in this file (e.g. 4.3–5.7 MB/s at 20 ms, 1.6–2.3 MB/s at 50 ms in that matrix) — this
section's 2.076 MB/s at 20 ms and 0.885 MB/s at 50 ms against a *real* Chrome receiver land in the
same range and follow the same shape, consistent with the congestion-window collapse being
internal to `webrtc-rs`'s own SCTP sender logic rather than specific to talking to another
`webrtc-rs` process. As already documented in "Stats field availability" above, `rtc-sctp`'s
`cwnd`/`ssthresh` fields are `pub(crate)` — not reachable through any public API — so this harness
cannot read the sender's congestion window directly the way `chrome://webrtc-internals` can for
Chrome. Unlike the `recv` direction, this session did not run `RUST_LOG=rtc_sctp=trace` against
the `send` cells; `rtc-sctp`'s `trace!`/`debug!` cwnd-update log lines (`"updated cwnd=... (SS)"`,
`"cwnd did not grow: ..."`) fire on whichever side is transmitting bulk data, so a send-direction
trace run would likely surface `webrtc-rs`'s own cwnd trajectory directly from Rust-side logs —
that is a natural, low-cost follow-up this session did not have time to take.

#### macOS dummynet: non-functional

On this development host (Darwin 25.3, modern macOS), the `dnctl pipe` / `pfctl` anchor recipe
documented earlier in this file (see the "macOS dummynet recipe" section above) configures without
any error — the pipes are created and the `spindle-s3-dummynet` pf anchor loads and evaluates, pf
itself reports enabled — but the kernel applies **no delay at all**: a 25 ms pipe per direction
(50 ms round trip configured) left measured loopback UDP RTT at ~0.1 ms, indistinguishable from
unshaped. This is a recorded dead end on this macOS version, not a one-off configuration mistake,
and it is why the RTT matrix in this section moved entirely into a Linux container
(`spindle-toolchain:local`, `tc netem`) instead.

#### Verdict (A10.29)

**The `webrtc-rs`↔Chrome pairing fails the ≥ 15 MB/s @ 50 ms bar in both directions, for two
independent reasons**: sender-side congestion-control collapse internal to `webrtc-rs` (`send`
direction, consistent with the pre-existing `webrtc-rs`↔`webrtc-rs` matrix), and a receiver-clean,
Chrome-`dcSCTP`-side cwnd-growth freeze (`recv` direction, positively diagnosed via `rtc_sctp`
trace evidence above). Zero packet loss on the path in either case (0 netem drops, 0 UDP-socket
errors), and plain TCP on the identical shaped path already clears the bar 4× over — so the
bottleneck is squarely the Rust WebRTC stack's SCTP implementation, not this harness's environment
and not a hard protocol ceiling. This does not decide ADR-005; it narrows the open options:

1. **Upstream `webrtc-rs`/`rtc-sctp` congestion-control work** — file the evidence in this section
   against the crate, focusing on the sender-side collapse (directly reachable/fixable) and the
   `recv`-direction interop freeze (would need dcSCTP-side collaboration or a debug Chromium build
   to pin down further).
2. **Switch the Rust SCTP stack.** Already tried once as S3's designated fallback —
   `datachannel-rs`/libdatachannel (`usrsctp`) shows the *same* RTT-bound collapse and is measurably
   *worse* than `webrtc-rs` at 50/100 ms (see "datachannel-rs backend" above) — so this option's
   track record in this codebase so far is poor, not a clean escape hatch.
3. **A Chromium↔Chromium control cell** (two headless Chrome peers, no Rust SCTP stack on either
   end) — would isolate whether dcSCTP itself is RTT-bound in this environment independent of
   `webrtc-rs`, or whether the freeze is specific to pairing with `webrtc-rs`. Not run in this
   session.
4. **Revise the A9 ≥ 15 MB/s @ 50 ms WAN bar** — if none of the above close the gap in a reasonable
   timeframe.

#### Reproduction

```
export PATH="$HOME/.local/share/mise/shims:$PATH"
cd spikes/s3-throughput

# Default: full 0/20/50/100 ms matrix, both directions (this section's table).
./browser-rtt-run.sh

# Single-cell diagnostic form (env-var overrides; all optional, default to the full matrix above):
#   CELLS=recv                 -> only this direction ("send" or "recv")
#   RTTS="50"                  -> only this RTT list
#   BYTES_MIB=8                -> fixed transfer size instead of the matrix's per-RTT default
#   PER_RUN_TIMEOUT_S=90       -> override the per-cell watchdog (default 300 s)
#   RUST_LOG=rtc_sctp=trace    -> webrtc-rs/rtc-sctp SCTP-layer congestion-control logging on
#                                  stderr (also copied to .browser-rtt-raw/<cell>-rust-trace.log)
CELLS=recv RTTS="50" BYTES_MIB=8 PER_RUN_TIMEOUT_S=90 RUST_LOG=rtc_sctp=trace ./browser-rtt-run.sh

# DCSCTP_LOG=1 also exists (adds --enable-logging=stderr --vmodule=*dcsctp*=9 to the Chromium
# invocation) but is a confirmed dead end — dcSCTP's verbose logs are compiled out of release
# Chromium; it produces zero matching lines. Kept in the script for completeness, not recommended.
```

Raw per-cell artifacts (`.jsonl` stats, `.err`/`-rust-trace.log`, `-chrome.log`, qdisc/UDP-error
snapshots) live under `.browser-rtt-raw/` and `.browser-rtt-qdisc.tmp` — not committed (see
`.gitignore`), regenerable by the reproduction commands above.
