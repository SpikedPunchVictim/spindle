//! # S3 — DataChannel throughput spike
//!
//! Answers `docs/DESIGN.md` §A13, spike **S3**: *"DataChannel throughput at 0/20/50/100 ms RTT;
//! SCTP tuning."* Full writeup and gating: `docs/SPIKES.md` (§S3). Do not edit the pass criterion
//! here — `docs/DESIGN.md` §A13 is authoritative; this file only measures against it.
//!
//! ## What this harness actually does
//!
//! Two `RTCPeerConnection`s (`webrtc` crate, workspace pin `>=0.20`, resolved to **0.20.3** — the
//! sans-I/O rewrite per §A8/§A9c) are built in-process on `127.0.0.1`. They exchange one SDP
//! offer/answer with full (non-trickle) ICE gathering — appropriate for a loopback/LAN harness;
//! `S2` is the spike that covers trickle ICE over NATS. One **unordered, reliable** data channel
//! is opened (`ordered: false`, `max_retransmits: None`, `max_packet_life_time: None` — both
//! `None` means SCTP retransmits until delivered or the connection dies, i.e. reliable). Per A8
//! ("more channels don't add throughput — all channels share one SCTP association/cwnd") this
//! harness intentionally opens only the one data channel under measurement; no separate control
//! channel is spiked here since it would not change the throughput number.
//!
//! The sender pushes `--bytes` MiB of payload in `--chunk` KiB chunks; the receiver counts bytes
//! as they arrive. Wall time is measured from just before the first chunk is sent to the instant
//! the receiver's byte counter reaches the target. Reported throughput is decimal MB/s (bytes /
//! 1e6 / seconds), matching the pass-bar convention in `docs/DESIGN.md` §A13.
//!
//! ## API reality vs. the original plan (read before re-deriving this)
//!
//! The originally sketched plan (`SettingEngine::detach_data_channels()`, `bufferedAmount` +
//! `bufferedAmountLowThreshold` manual polling loops) describes the **pre-0.20 callback-based
//! `webrtc-rs` API**. The `>=0.20` pin resolves to the sans-I/O rewrite, which has a different
//! shape entirely:
//!
//! - There is no "detach" concept. `DataChannel` is a `poll()`-based event stream
//!   (`DataChannelEvent::{OnOpen, OnMessage, OnClose, ...}`) plus async `send`/`send_text`; the
//!   library drives a background per-connection driver task itself.
//! - The **SCTP receive buffer** knob *is* exposed:
//!   `PeerConnectionBuilder::with_sctp_receive_buffer_size(bytes)` — the a_rwnd flow-control
//!   window (default 1 MiB). This harness's `--sctp-buf` flag maps directly to this, applied to
//!   *both* peers.
//! - There is no separate distinct "SCTP send buffer size" knob. What the library exposes instead
//!   is `PeerConnectionBuilder::with_data_channel_send_buffer_limit(bytes)` — a per-channel
//!   app-level send back-pressure cap on *outstanding* (unacked) bytes; once set, `DataChannel::send`
//!   blocks until under the limit (`try_send` fails fast instead). This harness also reuses
//!   `--sctp-buf` for this cap, so `send()` naturally paces itself against the same knob instead of
//!   a hand-rolled `bufferedAmountLow`-driven loop — the underlying mechanism (bound outstanding
//!   bytes) is the same one `bufferedAmountLow` backpressure exists to implement in the classic API.
//! - `bufferedAmountLowThreshold` **is** still present (`set_buffered_amount_low_threshold`) and is
//!   configured from `--threshold`, matching the CLI contract, even though this harness's
//!   backpressure comes from the blocking `send()` limit above rather than a manual
//!   `OnBufferedAmountLow` poll loop.
//!
//! ## RTT matrix
//!
//! This binary only measures one (RTT, buffer-config) cell per invocation — RTT itself is shaped
//! *externally* (Linux `tc netem`; loopback, so run inside `spikes/s3-throughput/rtt-run.sh`,
//! which drives the 0/20/50/100 ms matrix in a Linux container and appends rows to `RESULTS.md`).
//!
//! ## Pass criteria (verbatim, `docs/DESIGN.md` §A13)
//!
//! ≥ 50 MB/s on a LAN (0 ms) path; ≥ 15 MB/s at 50 ms RTT; the buffer/knob configuration needed to
//! hit those numbers is documented. These numbers also become the v1 UX bar in §A9 ("S3 sets the
//! v1 numbers"). Results: `spikes/s3-throughput/RESULTS.md`.

use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use tokio::sync::oneshot;
use tokio::time::interval;
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceGatheringState,
};
use webrtc::runtime::{default_runtime, Runtime};

/// Watchdog: if the receiver makes no forward progress for this long, the run is a stall, not a
/// slow transfer — abort loudly instead of hanging CI/dev machines forever.
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(60);

/// Harness configuration, either from CLI flags or their documented defaults.
struct Config {
    /// Total payload size in bytes (`--bytes`, MiB).
    total_bytes: usize,
    /// Chunk size in bytes (`--chunk`, KiB).
    chunk_bytes: usize,
    /// SCTP receive-buffer size AND per-channel send back-pressure limit, in bytes (`--sctp-buf`)
    /// — see the module doc comment for why one flag drives both knobs in this API version.
    sctp_buf: usize,
    /// `bufferedAmountLowThreshold`, in bytes (`--threshold`).
    threshold: u32,
    /// Emit a single machine-readable JSON result line instead of the human-readable report.
    json: bool,
}

impl Config {
    fn from_args() -> Result<Self> {
        const DEFAULT_BYTES_MIB: usize = 512;
        const DEFAULT_CHUNK_KIB: usize = 64;
        const DEFAULT_SCTP_BUF: usize = 4 * 1024 * 1024;
        const DEFAULT_THRESHOLD: u32 = 1024 * 1024;

        let mut bytes_mib = DEFAULT_BYTES_MIB;
        let mut chunk_kib = DEFAULT_CHUNK_KIB;
        let mut sctp_buf = DEFAULT_SCTP_BUF;
        let mut threshold = DEFAULT_THRESHOLD;
        let mut json = false;

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--bytes" => {
                    bytes_mib = next_val(&mut args, "--bytes")?;
                }
                "--chunk" => {
                    chunk_kib = next_val(&mut args, "--chunk")?;
                }
                "--sctp-buf" => {
                    sctp_buf = next_val(&mut args, "--sctp-buf")?;
                }
                "--threshold" => {
                    threshold = next_val(&mut args, "--threshold")?;
                }
                "--json" => json = true,
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return Err(anyhow!("unrecognized argument: {other} (see --help)")),
            }
        }

        Ok(Config {
            total_bytes: bytes_mib * 1024 * 1024,
            chunk_bytes: chunk_kib * 1024,
            sctp_buf,
            threshold,
            json,
        })
    }
}

fn next_val<T: std::str::FromStr>(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<T> {
    let raw = args
        .next()
        .ok_or_else(|| anyhow!("{flag} requires a value"))?;
    raw.parse::<T>()
        .map_err(|_| anyhow!("{flag} value {raw:?} is not a valid number"))
}

fn print_usage() {
    println!("spike-s3-throughput — S3 DataChannel throughput harness (docs/DESIGN.md §A13)");
    println!();
    println!("USAGE:");
    println!("    spike-s3-throughput [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --bytes <MiB>       total payload size to transfer (default: 512)");
    println!("    --chunk <KiB>       per-message chunk size (default: 64)");
    println!(
        "    --sctp-buf <bytes>  SCTP receive-buffer size AND send back-pressure limit (default: 4194304)"
    );
    println!("    --threshold <bytes> bufferedAmountLowThreshold (default: 1048576)");
    println!("    --json              print one machine-readable JSON result line");
}

/// Waits for `RTCIceGatheringState::Complete`, then unblocks a oneshot for the caller. Used for
/// both peers since this harness does full (non-trickle) ICE gathering, not `S2`'s trickle path.
struct GatherHandler {
    gather_tx: Mutex<Option<oneshot::Sender<()>>>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for GatherHandler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            if let Some(tx) = self.gather_tx.lock().expect("gather mutex poisoned").take() {
                let _ = tx.send(());
            }
        }
    }
}

/// Receiver-side handler: waits for ICE gathering to complete (like `GatherHandler`), then counts
/// bytes as they arrive on the (single, remotely-opened) data channel and reports completion once
/// `target` bytes have been received.
struct ReceiverHandler {
    runtime: Arc<dyn Runtime>,
    gather_tx: Mutex<Option<oneshot::Sender<()>>>,
    target: usize,
    received: Arc<AtomicUsize>,
    done_tx: Mutex<Option<oneshot::Sender<Instant>>>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for ReceiverHandler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            if let Some(tx) = self.gather_tx.lock().expect("gather mutex poisoned").take() {
                let _ = tx.send(());
            }
        }
    }

    async fn on_data_channel(&self, dc: Arc<dyn DataChannel>) {
        let target = self.target;
        let received = self.received.clone();
        let done_tx = self.done_tx.lock().expect("done_tx mutex poisoned").take();
        // Must spawn: returning from on_data_channel unblocks the connection driver.
        self.runtime.spawn(Box::pin(async move {
            let mut got = 0usize;
            while let Some(event) = dc.poll().await {
                match event {
                    DataChannelEvent::OnMessage(msg) => {
                        got += msg.data.len();
                        received.fetch_add(msg.data.len(), Ordering::Relaxed);
                        if got >= target {
                            if let Some(tx) = done_tx {
                                let _ = tx.send(Instant::now());
                            }
                            return;
                        }
                    }
                    DataChannelEvent::OnClose | DataChannelEvent::OnError => {
                        // Closed/errored before hitting target: let the caller's watchdog (or a
                        // short final wait) notice the shortfall instead of hanging forever.
                        return;
                    }
                    _ => {}
                }
            }
        }));
    }
}

/// Builds one peer connection bound to loopback, with the SCTP receive-buffer size and
/// per-channel send back-pressure limit set from `sctp_buf`.
async fn build_peer_connection(
    runtime: Arc<dyn Runtime>,
    sctp_buf: usize,
    handler: Arc<dyn PeerConnectionEventHandler>,
) -> Result<Arc<dyn PeerConnection>> {
    let pc = PeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_handler(handler)
        .with_runtime(runtime)
        .with_udp_addrs(vec!["127.0.0.1:0".to_string()])
        .with_sctp_receive_buffer_size(sctp_buf as u32)
        .with_data_channel_send_buffer_limit(sctp_buf)
        .build()
        .await
        .context("building RTCPeerConnection")?;
    Ok(Arc::new(pc) as Arc<dyn PeerConnection>)
}

async fn wait_gather_complete(rx: oneshot::Receiver<()>) -> Result<()> {
    rx.await.context("ICE gathering never completed")
}

fn main() -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to start tokio runtime");
    match rt.block_on(async_main()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("spike-s3-throughput: error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn async_main() -> Result<ExitCode> {
    let cfg = Config::from_args()?;
    let runtime = default_runtime().ok_or_else(|| anyhow!("no webrtc runtime available"))?;

    // ── Set up sender ("requester") and receiver ("responder") peer connections ──
    let (sender_gather_tx, sender_gather_rx) = oneshot::channel();
    let sender_pc = build_peer_connection(
        runtime.clone(),
        cfg.sctp_buf,
        Arc::new(GatherHandler {
            gather_tx: Mutex::new(Some(sender_gather_tx)),
        }),
    )
    .await?;

    let dc = sender_pc
        .create_data_channel(
            "throughput",
            Some(RTCDataChannelInit {
                ordered: false,
                max_retransmits: None,
                max_packet_life_time: None,
                ..Default::default()
            }),
        )
        .await
        .context("creating data channel")?;
    dc.set_buffered_amount_low_threshold(cfg.threshold)
        .await
        .context("setting bufferedAmountLowThreshold")?;

    let offer = sender_pc.create_offer(None).await.context("create_offer")?;
    sender_pc
        .set_local_description(offer)
        .await
        .context("sender set_local_description")?;
    wait_gather_complete(sender_gather_rx).await?;
    let offer_sdp = sender_pc
        .local_description()
        .await
        .ok_or_else(|| anyhow!("sender has no local description after gathering"))?;

    let received = Arc::new(AtomicUsize::new(0));
    let (done_tx, done_rx) = oneshot::channel();
    let (receiver_gather_tx, receiver_gather_rx) = oneshot::channel();
    let receiver_pc = build_peer_connection(
        runtime.clone(),
        cfg.sctp_buf,
        Arc::new(ReceiverHandler {
            runtime: runtime.clone(),
            gather_tx: Mutex::new(Some(receiver_gather_tx)),
            target: cfg.total_bytes,
            received: received.clone(),
            done_tx: Mutex::new(Some(done_tx)),
        }),
    )
    .await?;
    receiver_pc
        .set_remote_description(offer_sdp)
        .await
        .context("receiver set_remote_description")?;
    let answer = receiver_pc
        .create_answer(None)
        .await
        .context("create_answer")?;
    receiver_pc
        .set_local_description(answer)
        .await
        .context("receiver set_local_description")?;
    wait_gather_complete(receiver_gather_rx).await?;
    let answer_sdp = receiver_pc
        .local_description()
        .await
        .ok_or_else(|| anyhow!("receiver has no local description after gathering"))?;
    sender_pc
        .set_remote_description(answer_sdp)
        .await
        .context("sender set_remote_description")?;

    // ── Wait for the data channel to open ──
    loop {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) => break,
            Some(DataChannelEvent::OnClose) | None => {
                return Err(anyhow!("data channel closed before opening"));
            }
            _ => {}
        }
    }

    // ── Shared outcome channel ──
    //
    // Enqueueing all chunks (`sender_task` returning `Ok`) happens almost instantly on
    // loopback — it just means SCTP has accepted the bytes into its send pipeline, not that the
    // receiver has them yet. So a normal, successful `sender_task` completion must NOT race
    // `done_rx`/the watchdog for "first to finish" (an earlier version of this harness did
    // exactly that and misreported every run as a stall). Only two things end the run: the
    // receiver reaching `target` (success) or a genuine failure (a `send()` error, or the
    // watchdog's no-progress timeout) — both funnelled into one `outcome` channel so `main` just
    // awaits the first real outcome instead of racing "sender loop exited" against it.
    let (outcome_tx, mut outcome_rx) = tokio::sync::mpsc::channel::<Result<Instant>>(1);

    // Bridge the receiver's oneshot completion into the shared outcome channel.
    {
        let outcome_tx = outcome_tx.clone();
        tokio::spawn(async move {
            if let Ok(end) = done_rx.await {
                let _ = outcome_tx.send(Ok(end)).await;
            }
        });
    }

    // ── Watchdog: abort if the receiver stalls ──
    let watchdog_received = received.clone();
    let watchdog_tx = outcome_tx.clone();
    tokio::spawn(async move {
        let mut last_seen = watchdog_received.load(Ordering::Relaxed);
        let mut last_progress = Instant::now();
        let mut ticker = interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let now_seen = watchdog_received.load(Ordering::Relaxed);
            if now_seen != last_seen {
                last_seen = now_seen;
                last_progress = Instant::now();
            } else if last_progress.elapsed() > WATCHDOG_TIMEOUT {
                let _ = watchdog_tx
                    .send(Err(anyhow!(
                        "transfer stalled: no progress for {:?} ({now_seen} / {} bytes received)",
                        WATCHDOG_TIMEOUT,
                        cfg.total_bytes,
                    )))
                    .await;
                return;
            }
        }
    });

    // ── Sender loop: push `total_bytes` in `chunk_bytes`-sized messages ──
    let payload = vec![0xABu8; cfg.chunk_bytes];
    let total_bytes = cfg.total_bytes;
    let chunk_bytes = cfg.chunk_bytes;
    let start = Instant::now();
    let sender_tx = outcome_tx.clone();
    tokio::spawn(async move {
        let mut sent = 0usize;
        while sent < total_bytes {
            let this_chunk = chunk_bytes.min(total_bytes - sent);
            let buf = BytesMut::from(&payload[..this_chunk]);
            if let Err(e) = dc.send(buf).await.context("send() failed") {
                let _ = sender_tx.send(Err(e)).await;
                return;
            }
            sent += this_chunk;
        }
        // Successful enqueue is not itself completion — see the comment above. Just drop this
        // sender to release its outcome-channel handle; `outcome_rx` keeps waiting for the
        // receiver (or the watchdog) to report the real outcome.
    });
    drop(outcome_tx);

    // ── Wait for the first real outcome: receiver hit target, a send error, or a stall ──
    let end = outcome_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("all worker tasks exited without producing an outcome"))??;

    let elapsed = end.duration_since(start);
    let mb = cfg.total_bytes as f64 / 1_000_000.0;
    let mbps = mb / elapsed.as_secs_f64();

    if cfg.json {
        println!(
            "{{\"total_bytes\":{},\"chunk_bytes\":{},\"sctp_buf\":{},\"threshold\":{},\"elapsed_secs\":{:.6},\"mb_per_s\":{:.3}}}",
            cfg.total_bytes,
            cfg.chunk_bytes,
            cfg.sctp_buf,
            cfg.threshold,
            elapsed.as_secs_f64(),
            mbps,
        );
    } else {
        println!("spike-s3-throughput: DataChannel throughput spike (docs/DESIGN.md §A13, S3)");
        println!(
            "config: bytes={} MiB ({} B), chunk={} KiB, sctp_buf={} B, threshold={} B",
            cfg.total_bytes / (1024 * 1024),
            cfg.total_bytes,
            cfg.chunk_bytes / 1024,
            cfg.sctp_buf,
            cfg.threshold,
        );
        println!(
            "result: {:.3} MB/s ({:.3} s for {:.1} MB, decimal)",
            mbps,
            elapsed.as_secs_f64(),
            mb
        );
    }

    let _ = sender_pc.close().await;
    let _ = receiver_pc.close().await;

    Ok(ExitCode::SUCCESS)
}
