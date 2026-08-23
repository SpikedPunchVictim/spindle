//! # S3 — DataChannel throughput spike, `datachannel-rs` backend
//!
//! Same question as `src/main.rs` (`docs/DESIGN.md` §A13, spike **S3**), same measurement
//! protocol, different transport crate: this binary is the fallback named in §A8 ("evaluate
//! `datachannel-rs` if S3 fails") — invoked because the `webrtc`-backend harness (`src/main.rs`)
//! cleared the 0 ms bar but missed the ≥ 15 MB/s @ 50 ms bar badly (see `RESULTS.md`). Do not
//! edit the pass criterion here — `docs/DESIGN.md` §A13 is authoritative; this file only measures
//! against it, using a different backend.
//!
//! ## Why this file exists as a *separate* binary, not a feature flag on `src/main.rs`
//!
//! `webrtc` (sans-I/O, async, `PeerConnection`/`DataChannel` as a `poll()` event stream) and
//! `datachannel` (thin bindings over `libdatachannel`, a C++ library — callback-based: every
//! event is delivered by libdatachannel invoking a Rust callback from its own internal thread,
//! there is no async/`poll()` surface at all) have incompatible execution models. Mixing both
//! under one Tokio runtime in one binary would mean either wrapping every `datachannel` callback
//! in channel plumbing just to feed a `poll()`-shaped facade nobody else needs, or running two
//! unrelated concurrency models side by side in one `main` for no benefit — two `[[bin]]` targets
//! sharing this crate's `Cargo.toml` is the boring option. Per the task brief: std threads +
//! channels here, no forced `tokio::block_on` around a callback API.
//!
//! ## `datachannel-rs` API shape (0.16.1 / libdatachannel 0.23.2, vendored via cmake)
//!
//! - `RtcPeerConnection::new(&RtcConfig, handler)` takes a `PeerConnectionHandler` impl directly
//!   (not `Arc<dyn Trait>` — ownership, not shared reference); `create_data_channel_ex(label,
//!   dc_handler, &DataChannelInit)` similarly takes a `DataChannelHandler` impl by value. Both
//!   traits use `&mut self` callback methods invoked by libdatachannel's internal thread(s) —
//!   `RtcPeerConnection`'s own callbacks are serialized by an internal `ReentrantMutex` (see the
//!   crate source, `src/peerconnection.rs`); `DataChannelHandler` callbacks are not further
//!   locked by the crate, but per this harness's usage (one channel, one direction of traffic)
//!   they're only ever invoked from libdatachannel's single per-channel delivery path.
//! - **No trickle ICE plumbing needed here**: like `src/main.rs`, this harness waits for
//!   `GatheringState::Complete` on each side and reads back the *full* SDP (all host candidates
//!   already embedded) via `local_description()`, then hands that whole blob to the other peer's
//!   `set_remote_description`. That means no `on_candidate`/`add_remote_candidate` signaling loop
//!   at all — simpler than the crate's own `tests/local.rs` example (which trickles candidates
//!   because it targets a real STUN-reachable scenario); this harness is two in-process loopback
//!   peers, so full gathering is the right (and simpler) fit, same as the `webrtc` backend.
//! - **No SCTP receive-buffer-size knob.** `RtcConfig` (see the crate's `src/config.rs`) exposes
//!   `mtu`, `max_message_size`, ICE/proxy/bind settings — no equivalent of `webrtc`'s
//!   `with_sctp_receive_buffer_size` (libdatachannel manages its vendored `usrsctp` receive
//!   window internally, unconfigured from the public C API). That's why this binary has no
//!   `--sctp-buf` flag — there is nothing to point it at. `--threshold` is still real: it drives
//!   `RtcDataChannel::set_buffered_amount_low_threshold`, libdatachannel's actual exposed knob,
//!   the same one `on_buffered_amount_low` fires against.
//! - Backpressure is manual and threshold-driven, the "classic" WebRTC pattern the task brief
//!   asks for: before every `send()`, check `buffered_amount()` against a fixed high-water mark;
//!   if over, block the sending thread on a condvar that `on_buffered_amount_low` notifies
//!   (with a short poll-timeout fallback in case a notify races the wait — see `BufferedLow`).
//!
//! ## Threading model
//!
//! Everything through SDP exchange (peer/channel setup) runs on `main`'s thread — synchronous,
//! blocking on `mpsc::Receiver::recv_timeout` for each libdatachannel callback it needs
//! (gathering-complete, channel-open). The bulk transfer then runs as: `main`'s thread loops
//! `send()`ing chunks (blocking on the backpressure condvar between them); one small watchdog
//! thread polls the receiver's byte counter once a second and aborts the run if it stalls; the
//! receiver's byte counting happens inline inside libdatachannel's own callback delivery (no
//! extra thread needed there — unlike `src/main.rs`'s `ReceiverHandler`, there is no `poll()` loop
//! to drive, so nothing to spawn a receiver task for).
//!
//! ## RTT matrix / pass criteria
//!
//! Same as `src/main.rs`: RTT is shaped externally by `rtt-run.sh` (which runs both backends'
//! binaries through the same 0/20/50/100 ms `tc netem` matrix in the Linux container); pass bar
//! is `docs/DESIGN.md` §A13, ≥ 50 MB/s @ 0 ms / ≥ 15 MB/s @ 50 ms. Results: `RESULTS.md`.

use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use datachannel::{
    DataChannelHandler, DataChannelInfo, DataChannelInit, GatheringState, PeerConnectionHandler,
    Reliability, RtcConfig, RtcDataChannel, RtcPeerConnection, SdpType,
};

/// Watchdog: if the receiver makes no forward progress for this long, the run is a stall, not a
/// slow transfer — abort loudly instead of hanging CI/dev machines forever. Also used as the
/// timeout for one-off setup waits (ICE gathering, data-channel open): those should complete in
/// milliseconds on loopback, so a hang past this point is itself a (setup-phase) stall.
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(60);

/// Backpressure high-water mark for `RtcDataChannel::buffered_amount()`: once the sender's
/// outstanding (unacked) bytes exceed this, the sender thread blocks until
/// `on_buffered_amount_low` fires. Not a CLI flag (unlike `src/main.rs`'s `--sctp-buf`) — see the
/// module doc comment on why `datachannel-rs` has no exposed knob to sweep here. Matches
/// `src/main.rs`'s `DEFAULT_SCTP_BUF` so the two backends' default backpressure caps line up.
const SEND_HIGH_WATER_MARK: usize = 4 * 1024 * 1024;

/// Fallback poll period for the backpressure wait: `Condvar::wait_timeout` re-checks
/// `buffered_amount()` on every wakeup regardless of whether it woke via `notify` or timeout, so
/// this only bounds how long a missed/racy `on_buffered_amount_low` notification can delay a
/// send — it is not the primary wakeup path.
const BACKPRESSURE_POLL: Duration = Duration::from_millis(10);

/// Harness configuration, either from CLI flags or their documented defaults. Deliberately the
/// same shape as `src/main.rs`'s `Config` minus `sctp_buf` (see module doc comment).
struct Config {
    /// Total payload size in bytes (`--bytes`, MiB).
    total_bytes: usize,
    /// Chunk size in bytes (`--chunk`, KiB).
    chunk_bytes: usize,
    /// `bufferedAmountLowThreshold`, in bytes (`--threshold`).
    threshold: usize,
    /// Emit a single machine-readable JSON result line instead of the human-readable report.
    json: bool,
}

impl Config {
    fn from_args() -> Result<Self> {
        const DEFAULT_BYTES_MIB: usize = 512;
        const DEFAULT_CHUNK_KIB: usize = 64;
        const DEFAULT_THRESHOLD: usize = 1024 * 1024;

        let mut bytes_mib = DEFAULT_BYTES_MIB;
        let mut chunk_kib = DEFAULT_CHUNK_KIB;
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
    println!("dc-throughput — S3 DataChannel throughput harness, datachannel-rs backend (docs/DESIGN.md §A13)");
    println!();
    println!("USAGE:");
    println!("    dc-throughput [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --bytes <MiB>       total payload size to transfer (default: 512)");
    println!("    --chunk <KiB>       per-message chunk size (default: 64)");
    println!("    --threshold <bytes> bufferedAmountLowThreshold (default: 1048576)");
    println!("    --json              print one machine-readable JSON result line");
    println!();
    println!("Note: no --sctp-buf flag — datachannel-rs exposes no SCTP receive-buffer-size knob");
    println!("(see the module doc comment in src/bin/dc-throughput.rs).");
}

/// Bridges `DataChannelHandler::on_buffered_amount_low` (fired on a libdatachannel-owned thread)
/// to the sending thread blocked on backpressure in `run`'s send loop.
#[derive(Default)]
struct BufferedLow {
    mutex: Mutex<()>,
    condvar: Condvar,
}

impl BufferedLow {
    fn notify(&self) {
        self.condvar.notify_all();
    }

    /// Blocks for up to `BACKPRESSURE_POLL`, or until `notify()` is called. Callers loop this
    /// against a fresh `buffered_amount()` check each time — see the module doc comment.
    fn wait_once(&self) {
        let guard = self.mutex.lock().expect("BufferedLow mutex poisoned");
        let _ = self.condvar.wait_timeout(guard, BACKPRESSURE_POLL);
    }
}

/// Handler for the sender's own (locally-created) data channel: signals open + forwards
/// backpressure release. The actual `send()` calls happen on `main`'s thread once open, not
/// inside this handler — see the module doc comment's "Threading model".
struct SenderDc {
    open_tx: Mutex<Option<mpsc::Sender<()>>>,
    low: Arc<BufferedLow>,
}

impl DataChannelHandler for SenderDc {
    fn on_open(&mut self) {
        if let Some(tx) = self.open_tx.lock().expect("open_tx mutex poisoned").take() {
            let _ = tx.send(());
        }
    }

    fn on_buffered_amount_low(&mut self) {
        self.low.notify();
    }

    fn on_error(&mut self, err: &str) {
        eprintln!("dc-throughput: sender data channel error: {err}");
    }
}

/// Handler for the receiver's remotely-opened data channel: counts bytes as they arrive,
/// signalling completion once `target` bytes have been received. `got` is a plain (non-atomic)
/// field — safe because, per this harness's traffic pattern (one channel, sender-to-receiver
/// only), `on_message` is only ever invoked from libdatachannel's single delivery path for this
/// channel; `received` is still an `Arc<AtomicUsize>` because the watchdog thread reads it
/// concurrently.
struct ReceiverDc {
    target: usize,
    received: Arc<AtomicUsize>,
    got: usize,
    done_tx: Mutex<Option<mpsc::Sender<Instant>>>,
}

impl DataChannelHandler for ReceiverDc {
    fn on_message(&mut self, msg: &[u8]) {
        self.got += msg.len();
        self.received.fetch_add(msg.len(), Ordering::Relaxed);
        if self.got >= self.target {
            if let Some(tx) = self.done_tx.lock().expect("done_tx mutex poisoned").take() {
                let _ = tx.send(Instant::now());
            }
        }
    }

    fn on_error(&mut self, err: &str) {
        eprintln!("dc-throughput: receiver data channel error: {err}");
    }
}

/// Sender-side `RtcPeerConnection` handler. This harness only ever opens one channel, from
/// sender to receiver — the sender side never receives a remote-created data channel, so
/// `data_channel_handler`/`on_data_channel` are unreachable here; `SenderDc` is reused as the
/// (never-instantiated) associated handler type purely to avoid declaring a second dummy type.
struct SenderPc {
    gather_tx: Mutex<Option<mpsc::Sender<()>>>,
}

impl PeerConnectionHandler for SenderPc {
    type DCH = SenderDc;

    fn data_channel_handler(&mut self, _info: DataChannelInfo) -> Self::DCH {
        unreachable!(
            "sender side never receives a remote-created data channel in this harness \
             (see the SenderPc doc comment)"
        )
    }

    fn on_gathering_state_change(&mut self, state: GatheringState) {
        if state == GatheringState::Complete {
            if let Some(tx) = self.gather_tx.lock().expect("gather mutex poisoned").take() {
                let _ = tx.send(());
            }
        }
    }
}

/// Receiver-side `RtcPeerConnection` handler: waits for ICE gathering to complete (like
/// `SenderPc`), then accepts the sender's data channel and keeps it alive (a `RtcDataChannel`
/// stops delivering — and libdatachannel closes it — once dropped) for the rest of the run.
struct ReceiverPc {
    gather_tx: Mutex<Option<mpsc::Sender<()>>>,
    target: usize,
    received: Arc<AtomicUsize>,
    done_tx: Mutex<Option<mpsc::Sender<Instant>>>,
    /// Keeps the accepted `RtcDataChannel` alive for the harness's duration. Never read back —
    /// held only so it isn't dropped.
    dc_slot: Mutex<Option<Box<RtcDataChannel<ReceiverDc>>>>,
}

impl PeerConnectionHandler for ReceiverPc {
    type DCH = ReceiverDc;

    fn data_channel_handler(&mut self, _info: DataChannelInfo) -> Self::DCH {
        ReceiverDc {
            target: self.target,
            received: self.received.clone(),
            got: 0,
            done_tx: Mutex::new(self.done_tx.lock().expect("done_tx mutex poisoned").take()),
        }
    }

    fn on_gathering_state_change(&mut self, state: GatheringState) {
        if state == GatheringState::Complete {
            if let Some(tx) = self.gather_tx.lock().expect("gather mutex poisoned").take() {
                let _ = tx.send(());
            }
        }
    }

    fn on_data_channel(&mut self, dc: Box<RtcDataChannel<ReceiverDc>>) {
        *self.dc_slot.lock().expect("dc_slot mutex poisoned") = Some(dc);
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("dc-throughput: error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let cfg = Config::from_args()?;

    // Loopback only, like `src/main.rs`'s `with_udp_addrs(vec!["127.0.0.1:0"])` — no STUN/TURN
    // needed for two in-process peers, and binding restricts ICE gathering to `127.0.0.1` rather
    // than every local interface.
    let conf = RtcConfig::new::<&str>(&[]).bind_address(&"127.0.0.1");

    // ── Sender ("requester") side: build peer connection + create the data channel ──
    let (sender_gather_tx, sender_gather_rx) = mpsc::channel();
    let mut sender_pc = RtcPeerConnection::new(
        &conf,
        SenderPc {
            gather_tx: Mutex::new(Some(sender_gather_tx)),
        },
    )
    .map_err(|e| anyhow!("building sender RtcPeerConnection: {e}"))?;

    let (open_tx, open_rx) = mpsc::channel();
    let low = Arc::new(BufferedLow::default());
    let dc_init = DataChannelInit::default().reliability(Reliability::default().unordered());
    let mut dc = sender_pc
        .create_data_channel_ex(
            "throughput",
            SenderDc {
                open_tx: Mutex::new(Some(open_tx)),
                low: low.clone(),
            },
            &dc_init,
        )
        .map_err(|e| anyhow!("creating data channel: {e}"))?;
    dc.set_buffered_amount_low_threshold(cfg.threshold)
        .map_err(|e| anyhow!("setting bufferedAmountLowThreshold: {e}"))?;

    sender_pc
        .set_local_description(SdpType::Offer)
        .map_err(|e| anyhow!("sender set_local_description: {e}"))?;
    sender_gather_rx
        .recv_timeout(WATCHDOG_TIMEOUT)
        .context("sender ICE gathering never completed")?;
    let offer_sdp = sender_pc
        .local_description()
        .ok_or_else(|| anyhow!("sender has no local description after gathering"))?;

    // ── Receiver ("responder") side ──
    let received = Arc::new(AtomicUsize::new(0));
    let (done_tx, done_rx) = mpsc::channel();
    let (receiver_gather_tx, receiver_gather_rx) = mpsc::channel();
    let mut receiver_pc = RtcPeerConnection::new(
        &conf,
        ReceiverPc {
            gather_tx: Mutex::new(Some(receiver_gather_tx)),
            target: cfg.total_bytes,
            received: received.clone(),
            done_tx: Mutex::new(Some(done_tx)),
            dc_slot: Mutex::new(None),
        },
    )
    .map_err(|e| anyhow!("building receiver RtcPeerConnection: {e}"))?;

    // No explicit `set_local_description(Answer)` here: per libdatachannel's DOC.md ("If the
    // remote description is an offer and `disableAutoNegotiation` was not set ..., the library
    // will automatically answer by calling `rtcSetLocalDescription` internally"), setting the
    // remote offer below auto-generates and installs the local answer (and starts ICE gathering
    // for it) — calling `set_local_description` again ourselves races that and fails with
    // `RuntimeError` (confirmed empirically). `disable_auto_negotiation` is left unset on
    // `RtcConfig`, so this auto-answer path is exactly what's in effect.
    receiver_pc
        .set_remote_description(&offer_sdp)
        .map_err(|e| anyhow!("receiver set_remote_description: {e}"))?;
    receiver_gather_rx
        .recv_timeout(WATCHDOG_TIMEOUT)
        .context("receiver ICE gathering never completed")?;
    let answer_sdp = receiver_pc
        .local_description()
        .ok_or_else(|| anyhow!("receiver has no local description after gathering"))?;

    sender_pc
        .set_remote_description(&answer_sdp)
        .map_err(|e| anyhow!("sender set_remote_description: {e}"))?;

    // ── Wait for the data channel to open ──
    open_rx
        .recv_timeout(WATCHDOG_TIMEOUT)
        .context("data channel never opened")?;

    // ── Shared outcome channel: the receiver hitting `target`, or a genuine failure (a `send()`
    // error, or the watchdog's no-progress timeout), funnel into one channel so the send loop
    // (below) and `run` just wait for the first real outcome. ──
    let (outcome_tx, outcome_rx) = mpsc::channel::<Result<Instant>>();
    {
        let outcome_tx = outcome_tx.clone();
        std::thread::spawn(move || {
            if let Ok(end) = done_rx.recv() {
                let _ = outcome_tx.send(Ok(end));
            }
        });
    }

    // ── Watchdog: abort if the receiver stalls. `aborted` lets the send loop below notice a
    // watchdog-triggered abort instead of blocking forever on backpressure that will never
    // release (e.g. a dead connection: no more `on_buffered_amount_low` will ever fire). ──
    let aborted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let watchdog_received = received.clone();
        let watchdog_tx = outcome_tx.clone();
        let watchdog_aborted = aborted.clone();
        let total_bytes = cfg.total_bytes;
        std::thread::spawn(move || {
            let mut last_seen = watchdog_received.load(Ordering::Relaxed);
            let mut last_progress = Instant::now();
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let now_seen = watchdog_received.load(Ordering::Relaxed);
                if now_seen >= total_bytes {
                    return; // receiver finished; nothing left to watch
                }
                if now_seen != last_seen {
                    last_seen = now_seen;
                    last_progress = Instant::now();
                } else if last_progress.elapsed() > WATCHDOG_TIMEOUT {
                    watchdog_aborted.store(true, Ordering::Relaxed);
                    let _ = watchdog_tx.send(Err(anyhow!(
                        "transfer stalled: no progress for {:?} ({now_seen} / {total_bytes} bytes received)",
                        WATCHDOG_TIMEOUT,
                    )));
                    return;
                }
            }
        });
    }

    // ── Sender loop: push `total_bytes` in `chunk_bytes`-sized messages, on this thread ──
    let payload = vec![0xABu8; cfg.chunk_bytes];
    let start = Instant::now();
    let mut sent = 0usize;
    'send: while sent < cfg.total_bytes {
        while dc.buffered_amount() > SEND_HIGH_WATER_MARK {
            if aborted.load(Ordering::Relaxed) {
                break 'send;
            }
            low.wait_once();
        }
        if aborted.load(Ordering::Relaxed) {
            break 'send;
        }
        let this_chunk = cfg.chunk_bytes.min(cfg.total_bytes - sent);
        dc.send(&payload[..this_chunk])
            .map_err(|e| anyhow!("send() failed: {e}"))?;
        sent += this_chunk;
    }
    drop(outcome_tx);

    // ── Wait for the first real outcome: receiver hit target, a send error, or a stall ──
    let end = outcome_rx
        .recv()
        .context("all worker tasks exited without producing an outcome")??;

    let elapsed = end.duration_since(start);
    let mb = cfg.total_bytes as f64 / 1_000_000.0;
    let mbps = mb / elapsed.as_secs_f64();

    if cfg.json {
        println!(
            "{{\"backend\":\"datachannel\",\"total_bytes\":{},\"chunk_bytes\":{},\"threshold\":{},\"elapsed_secs\":{:.6},\"mb_per_s\":{:.3}}}",
            cfg.total_bytes,
            cfg.chunk_bytes,
            cfg.threshold,
            elapsed.as_secs_f64(),
            mbps,
        );
    } else {
        println!("dc-throughput: DataChannel throughput spike (docs/DESIGN.md §A13, S3), datachannel-rs backend");
        println!(
            "config: bytes={} MiB ({} B), chunk={} KiB, threshold={} B",
            cfg.total_bytes / (1024 * 1024),
            cfg.total_bytes,
            cfg.chunk_bytes / 1024,
            cfg.threshold,
        );
        println!(
            "result: {:.3} MB/s ({:.3} s for {:.1} MB, decimal)",
            mbps,
            elapsed.as_secs_f64(),
            mb
        );
    }

    // Explicit drops (not strictly required — both go out of scope right after — but documents
    // shutdown order: tear down peer connections before the process exits).
    drop(sender_pc);
    drop(receiver_pc);

    Ok(ExitCode::SUCCESS)
}
