//! # S3 — DataChannel throughput spike
//!
//! Answers `docs/DESIGN.md` §A13, spike **S3**: *"DataChannel throughput at 0/20/50/100 ms RTT;
//! SCTP tuning."* Full writeup and gating: `docs/SPIKES.md` (§S3). Do not edit the pass criterion
//! here — `docs/DESIGN.md` §A13 is authoritative; this file only plans how to reach it.
//!
//! ## Experiment plan
//!
//! **Peers**: two processes using the `webrtc` crate (workspace pin `>=0.20`, sans-I/O core, per
//! `docs/DESIGN.md` §A8/§A9c). If `webrtc` cannot clear the pass bar, the documented fallback is
//! `datachannel-rs` (§A8: "evaluate `datachannel-rs` if S3 fails") — that is a separate spike run,
//! not a silent swap.
//!
//! **Channel shape** (fixed by design, not a variable in this spike): one reliable-ordered control
//! channel + one unordered-reliable data channel, sharing a single SCTP association/congestion
//! window (§A8: "more channels don't add throughput" — §A11 already rejected the N-data-channel
//! alternative). 64 KiB chunks (§A8's chosen chunk size); backpressure signaled via
//! `bufferedAmountLow`.
//!
//! **RTT matrix**: 0 / 20 / 50 / 100 ms, injected with `tc netem` (Linux), Network Link
//! Conditioner (macOS), or an equivalent WAN emulator (Windows). Each RTT point is a separate run,
//! not an average across a ramp.
//!
//! **Buffer knobs to vary at each RTT point**:
//! - SCTP send buffer size
//! - SCTP receive buffer size
//! - `bufferedAmountLowThreshold` (backpressure trigger point)
//!
//! **Metrics to record per (RTT, buffer-config) cell**:
//! - sustained throughput (MB/s) over a large transfer, not an initial burst
//! - which buffer settings were required to clear the bar at each RTT (this is the "knobs
//!   documented" half of the pass criterion — write it to `RESULTS.md`, not just this file)
//!
//! **Pass criteria (verbatim, `docs/DESIGN.md` §A13)**: ≥ 50 MB/s on a LAN (0 ms) path; ≥ 15 MB/s
//! at 50 ms RTT; the buffer/knob configuration needed to hit those numbers is documented. These
//! numbers also become the v1 UX bar in §A9 ("S3 sets the v1 numbers").
//!
//! Results go in `spikes/s3-throughput/RESULTS.md`. This crate has no dependencies yet — see the
//! commented block in `Cargo.toml`.

fn main() {
    println!("spike-s3-throughput: DataChannel throughput spike (docs/DESIGN.md §A13, S3)");
    println!("Status: not run — see docs/SPIKES.md (S3) and RESULTS.md in this directory.");
    println!();
    println!("TODO steps:");
    println!("  1. Enable the `webrtc` (and `tokio`) deps in Cargo.toml.");
    println!("  2. Stand up two peers exchanging one control channel + one data channel over a");
    println!("     single SCTP association (no extra data channels — see the doc comment above).");
    println!("  3. Wrap the pair in a controlled-latency link: tc netem / Network Link");
    println!("     Conditioner / WAN emulator, set to 0 / 20 / 50 / 100 ms RTT.");
    println!("  4. At each RTT point, sweep SCTP send/recv buffer sizes and bufferedAmountLow");
    println!("     threshold; transfer a large payload in 64 KiB chunks; measure sustained MB/s.");
    println!("  5. Record every (RTT, buffer-config) result in RESULTS.md.");
    println!("  6. Confirm >= 50 MB/s at 0 ms RTT and >= 15 MB/s at 50 ms RTT; if webrtc can't");
    println!("     clear the bar, rerun against datachannel-rs per the A8 fallback clause.");
}
