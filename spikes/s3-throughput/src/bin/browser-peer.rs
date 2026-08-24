//! # A10.29 — DataChannel throughput vs. a REAL Chrome peer (dcSCTP)
//!
//! Answers decision **A10.29** (`docs/DESIGN.md` §A8): S3's `src/main.rs` only ever measured
//! throughput between two `webrtc-rs` processes talking to *themselves* — the same Rust SCTP
//! stack on both ends. A10.29 asks for a measurement against a genuinely different SCTP
//! implementation on the other end: Chrome's `dcSCTP`. This binary is the Rust half of that
//! harness; `browser-peer.html` (same directory) is the Chrome half. **This is the harness only —
//! it does not itself drive Chrome or take a measurement.** See `RESULTS.md`'s "Browser-peer
//! (dcSCTP) measurement plan" section for exactly how a later session runs it and what to record.
//!
//! ## Why a WebSocket, not NATS/manual copy-paste
//!
//! `browser-peer.html` is opened directly via `file://` — no HTTP server, no build step, per the
//! task brief. A `file://` page cannot open a listening socket itself, so *this* binary runs a
//! tiny WebSocket signaling server (`tokio-tungstenite`) that the page connects out to
//! (`ws://127.0.0.1:<port>/`). That's the only role the WebSocket plays: relaying the SDP
//! offer/answer handshake and, once the data channel is up and the transfer under measurement is
//! done, one final JSON "result" message so this binary can print a single merged `--json`
//! summary. All of the actual payload bytes under measurement cross the `RTCDataChannel`
//! (DTLS/SCTP), never the WebSocket.
//!
//! ## Signaling protocol (JSON text frames over the WebSocket)
//!
//! This binary is **always** the SDP offerer and **always** creates the one data channel
//! (`ordered: false, max_retransmits: None, max_packet_life_time: None` — unordered-reliable,
//! same as `src/main.rs`; see that file's module doc comment for why `None`/`None` means
//! "reliable"). Direction of the *payload* (which side pushes bytes once the channel is open) is
//! controlled by `--mode`, independent of who created the channel — WebRTC data channels are
//! full-duplex once open.
//!
//! - bin → page: `{"type":"offer","sdp":"...","mode":"send"|"recv","bytes":N,"chunk":C}` — the
//!   SDP offer plus the handshake info the page needs (which role to play, and the target byte
//!   count). Sent only after this side's own ICE gathering completes (non-trickle — host-only
//!   candidates on loopback gather in well under a second, so there is no need for a separate
//!   `ice` trickle-relay message in either direction; both sides wait for their own
//!   `icegatheringstate === "complete"` before sending SDP, matching `src/main.rs`'s existing
//!   non-trickle convention. `browser-peer.html` still ignores/no-ops a stray incoming `ice`
//!   message rather than erroring on one, for robustness).
//! - page → bin: `{"type":"answer","sdp":"..."}` — sent once the page's own ICE gathering
//!   completes.
//! - page → bin: `{"type":"result","bytes":N,"elapsed_secs":S,"mb_per_s":M}` — sent once the
//!   page's role in the transfer finishes (received `bytes` total in `--mode send`, or sent
//!   `bytes` total in `--mode recv`), with the page's own measured throughput for its side. This
//!   binary treats this message as **required** (bounded by the same watchdog timeout as the
//!   transfer itself) — the transfer isn't considered complete without it, since `--mode send`'s
//!   authoritative number (see below) comes only from this message.
//! - page → bin: `{"type":"error","message":"..."}` — surfaced as a proper `anyhow::Error`
//!   instead of a deserialize failure, so a page-side exception reads as a clear cause, not a
//!   confusing signaling-parse error.
//!
//! ## Which side's number is authoritative
//!
//! Per A9 ("send = Rust pushes `--bytes` to the browser, the download path, the primary A9
//! metric"): in `--mode send`, throughput is only meaningful as measured by the *receiver*
//! (the page) — this binary's own "enqueue" timing just measures how fast `webrtc-rs` accepted
//! bytes into its send pipeline, not delivery (see `src/main.rs`'s module doc comment for the
//! same caveat there). In `--mode recv`, the reverse holds: this binary is the receiver and its
//! own byte-counted elapsed time is authoritative, while the page's self-reported number is the
//! auxiliary cross-check. The final summary always reports one `elapsed_secs`/`mb_per_s` pair (the
//! authoritative direction) plus `peer_elapsed_secs`/`peer_mb_per_s`/`peer_bytes` (the other
//! side's self-report), so both numbers are always visible even though only one is "the" result.
//!
//! ## Stats sampling (`--stats-interval-ms`/`--stats-out`) and cwnd
//!
//! See `RESULTS.md`'s "Browser-peer (dcSCTP) measurement plan" section for the full field list
//! and, importantly, **which fields are NOT reachable**: `webrtc` 0.20.3's public `get_stats()`
//! surface has no SCTP-transport-specific stats type at all (checked directly in the vendored
//! `rtc`/`rtc-sctp` source under `~/.cargo/registry/src/.../rtc-sctp-0.20.3/src/association/mod.rs`
//! — `cwnd`/`ssthresh` are `pub(crate)` fields on `sctp::Association`, itself reachable only via a
//! `pub(crate)` field deep inside `webrtc`'s own peer-connection internals, never exposed through
//! any public accessor). Chrome's `chrome://webrtc-internals` is the only side of this harness
//! that can show real dcSCTP cwnd/rwnd; the alternative on the Rust side is inferring
//! backpressure from throughput + `DataChannelStats` byte counters over time, which is what this
//! binary's stats samples give you instead.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::interval;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceConnectionState, RTCIceGatheringState, RTCPeerConnectionState, RTCSessionDescription,
    StatsSelector,
};
use webrtc::runtime::{default_runtime, Runtime};

/// Watchdog: if a transfer (or a required signaling message) makes no forward progress for this
/// long, treat it as a stall, not a slow transfer — same constant/rationale as `src/main.rs`.
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(60);

type WsSender = SplitSink<WebSocketStream<TcpStream>, Message>;
type WsReceiver = SplitStream<WebSocketStream<TcpStream>>;

/// Which side pushes payload bytes over the data channel once it's open. This binary always
/// creates the offer/data channel regardless of `--mode` — see the module doc comment.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Rust → browser (download path; the primary A9 metric).
    Send,
    /// Browser → Rust (upload path).
    Recv,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Send => "send",
            Mode::Recv => "recv",
        }
    }
}

impl std::str::FromStr for Mode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "send" => Ok(Mode::Send),
            "recv" => Ok(Mode::Recv),
            other => Err(anyhow!(
                "--mode must be \"send\" or \"recv\", got {other:?}"
            )),
        }
    }
}

struct Config {
    /// Signaling WebSocket port, `127.0.0.1:<port>` (`--port`).
    port: u16,
    /// Which side sends payload bytes once the data channel opens (`--mode`, required).
    mode: Mode,
    /// Total payload size in bytes (`--bytes`, MiB).
    total_bytes: usize,
    /// Chunk size in bytes (`--chunk`, KiB) — only governs this binary's own `--mode send` send
    /// loop; `browser-peer.html`'s `--mode recv` send loop uses its own fixed 64 KiB chunks (see
    /// that file).
    chunk_bytes: usize,
    /// SCTP receive-buffer size AND per-channel send back-pressure limit, in bytes (`--sctp-buf`)
    /// — same mapping as `src/main.rs`; see that file's module doc comment.
    sctp_buf: usize,
    /// `bufferedAmountLowThreshold`, in bytes (`--threshold`).
    threshold: u32,
    /// Emit a single machine-readable JSON result line instead of the human-readable report.
    json: bool,
    /// Stats-sampling interval in milliseconds; 0 (default) disables sampling (`--stats-interval-ms`).
    stats_interval_ms: u64,
    /// JSON-lines output path for stats samples (`--stats-out`); required together with
    /// `--stats-interval-ms`.
    stats_out: Option<PathBuf>,
}

impl Config {
    fn from_args() -> Result<Self> {
        const DEFAULT_PORT: u16 = 9333;
        const DEFAULT_BYTES_MIB: usize = 512;
        const DEFAULT_CHUNK_KIB: usize = 64;
        const DEFAULT_SCTP_BUF: usize = 4 * 1024 * 1024;
        const DEFAULT_THRESHOLD: u32 = 1024 * 1024;

        let mut port = DEFAULT_PORT;
        let mut mode: Option<Mode> = None;
        let mut bytes_mib = DEFAULT_BYTES_MIB;
        let mut chunk_kib = DEFAULT_CHUNK_KIB;
        let mut sctp_buf = DEFAULT_SCTP_BUF;
        let mut threshold = DEFAULT_THRESHOLD;
        let mut json = false;
        let mut stats_interval_ms = 0u64;
        let mut stats_out: Option<PathBuf> = None;

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--port" => port = next_val(&mut args, "--port")?,
                "--mode" => {
                    let raw: String = next_val(&mut args, "--mode")?;
                    mode = Some(raw.parse()?);
                }
                "--bytes" => bytes_mib = next_val(&mut args, "--bytes")?,
                "--chunk" => chunk_kib = next_val(&mut args, "--chunk")?,
                "--sctp-buf" => sctp_buf = next_val(&mut args, "--sctp-buf")?,
                "--threshold" => threshold = next_val(&mut args, "--threshold")?,
                "--json" => json = true,
                "--stats-interval-ms" => {
                    stats_interval_ms = next_val(&mut args, "--stats-interval-ms")?
                }
                "--stats-out" => {
                    let raw: String = next_val(&mut args, "--stats-out")?;
                    stats_out = Some(PathBuf::from(raw));
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return Err(anyhow!("unrecognized argument: {other} (see --help)")),
            }
        }

        let mode = mode.ok_or_else(|| {
            anyhow!("--mode is required (\"send\" or \"recv\"); run with --help for usage")
        })?;

        match (stats_interval_ms > 0, &stats_out) {
            (true, None) => {
                return Err(anyhow!(
                    "--stats-interval-ms requires --stats-out <path> (nothing to write samples to)"
                ))
            }
            (false, Some(_)) => {
                return Err(anyhow!(
                    "--stats-out requires --stats-interval-ms <N> (nothing would ever be sampled)"
                ))
            }
            _ => {}
        }

        Ok(Config {
            port,
            mode,
            total_bytes: bytes_mib * 1024 * 1024,
            chunk_bytes: chunk_kib * 1024,
            sctp_buf,
            threshold,
            json,
            stats_interval_ms,
            stats_out,
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
    println!(
        "browser-peer — A10.29 DataChannel throughput vs. a real Chrome peer (docs/DESIGN.md §A8)"
    );
    println!();
    println!("USAGE:");
    println!("    browser-peer --mode <send|recv> [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --mode <send|recv>  required: send = Rust pushes bytes to the browser (download");
    println!("                        path); recv = browser pushes bytes to Rust (upload path)");
    println!("    --port <N>          signaling WebSocket port on 127.0.0.1 (default: 9333)");
    println!("    --bytes <MiB>       total payload size to transfer (default: 512)");
    println!("    --chunk <KiB>       this binary's own send-loop chunk size, --mode send only");
    println!("                        (default: 64; browser-peer.html's --mode recv send loop");
    println!("                        always uses 64 KiB chunks, independent of this flag)");
    println!(
        "    --sctp-buf <bytes>  SCTP receive-buffer size AND send back-pressure limit (default: 4194304)"
    );
    println!("    --threshold <bytes> bufferedAmountLowThreshold (default: 1048576)");
    println!("    --json              print one machine-readable JSON result line");
    println!("    --stats-interval-ms <N>  sample stats every N ms (default: 0, disabled)");
    println!("    --stats-out <path>  JSON-lines file for stats samples (required with the above)");
    println!();
    println!("EXAMPLES:");
    println!("    browser-peer --mode send --bytes 128");
    println!("    browser-peer --mode recv --bytes 128 --json");
    println!("    browser-peer --mode send --stats-interval-ms 200 --stats-out /tmp/stats.jsonl");
    println!();
    println!("Then open browser-peer.html (same directory) in Chrome — see RESULTS.md's");
    println!("\"Browser-peer (dcSCTP) measurement plan\" section for the full runbook.");
}

/// Waits for `RTCIceGatheringState::Complete` (unblocking `gather_tx`, same non-trickle pattern
/// as `src/main.rs`'s `GatherHandler`), and logs ICE/peer connection state transitions to stderr
/// — useful diagnostics for whoever drives the actual Chrome session against this harness.
struct Handler {
    gather_tx: Mutex<Option<oneshot::Sender<()>>>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            if let Some(tx) = self.gather_tx.lock().expect("gather mutex poisoned").take() {
                let _ = tx.send(());
            }
        }
    }

    async fn on_ice_connection_state_change(&self, state: RTCIceConnectionState) {
        eprintln!("browser-peer: ICE connection state: {state:?}");
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        eprintln!("browser-peer: peer connection state: {state:?}");
    }
}

/// Builds the (single) peer connection bound to loopback, with the SCTP receive-buffer size and
/// per-channel send back-pressure limit set from `sctp_buf` — same construction as
/// `src/main.rs`'s `build_peer_connection`.
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

#[derive(Serialize)]
struct OfferMsg<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    sdp: &'a str,
    mode: &'static str,
    bytes: usize,
    chunk: usize,
}

#[derive(Deserialize)]
struct AnswerMsg {
    sdp: String,
}

#[derive(Deserialize)]
struct ResultMsg {
    bytes: u64,
    elapsed_secs: f64,
    mb_per_s: f64,
}

async fn send_json<T: Serialize>(tx: &mut WsSender, value: &T) -> Result<()> {
    let text = serde_json::to_string(value).context("serializing signaling message")?;
    tx.send(Message::Text(text))
        .await
        .context("sending signaling message")
}

/// Reads WebSocket text frames until one with `"type": expected_type` arrives, deserializing it
/// into `T`. Unrelated message types are ignored (logged and skipped) rather than erroring;
/// `{"type":"error","message":"..."}` from the page is surfaced as a proper `anyhow::Error`. See
/// the module doc comment's "Signaling protocol" section.
async fn recv_typed<T: DeserializeOwned>(rx: &mut WsReceiver, expected_type: &str) -> Result<T> {
    loop {
        let msg = rx
            .next()
            .await
            .ok_or_else(|| {
                anyhow!("signaling connection closed while waiting for a {expected_type:?} message")
            })?
            .context("reading signaling message")?;
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => {
                return Err(anyhow!(
                    "browser closed the signaling connection while waiting for a {expected_type:?} message"
                ))
            }
            _ => continue,
        };
        let value: serde_json::Value =
            serde_json::from_str(&text).context("parsing signaling message as JSON")?;
        let typ = value
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("signaling message missing a \"type\" field: {text}"))?;
        if typ == "error" {
            let message = value
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("(no message)");
            return Err(anyhow!("browser reported an error: {message}"));
        }
        if typ != expected_type {
            eprintln!(
                "browser-peer: ignoring signaling message type {typ:?} (waiting for {expected_type:?})"
            );
            continue;
        }
        return serde_json::from_value(value)
            .with_context(|| format!("parsing {expected_type:?} signaling message"));
    }
}

/// `--mode send`: pushes `cfg.total_bytes` over `dc` in `cfg.chunk_bytes`-sized messages. Returns
/// this side's own "enqueue" elapsed time and byte count — **not** the authoritative number for
/// this direction; see the module doc comment's "Which side's number is authoritative" section.
/// Each individual `send()` call is bounded by `WATCHDOG_TIMEOUT`: if back-pressure never clears
/// (the browser stopped reading), that call — and this function — errors out instead of hanging.
async fn run_send(
    dc: &Arc<dyn DataChannel>,
    cfg: &Config,
    start: Instant,
) -> Result<(Duration, usize)> {
    let payload = vec![0xABu8; cfg.chunk_bytes];
    let mut sent = 0usize;
    while sent < cfg.total_bytes {
        let this_chunk = cfg.chunk_bytes.min(cfg.total_bytes - sent);
        let buf = BytesMut::from(&payload[..this_chunk]);
        tokio::time::timeout(WATCHDOG_TIMEOUT, dc.send(buf))
            .await
            .map_err(|_| {
                anyhow!(
                    "send stalled: no progress for {WATCHDOG_TIMEOUT:?} ({sent} / {} bytes enqueued)",
                    cfg.total_bytes
                )
            })?
            .context("send() failed")?;
        sent += this_chunk;
    }
    Ok((start.elapsed(), sent))
}

/// `--mode recv`: waits for `cfg.total_bytes` to arrive on `dc`, counting bytes as `OnMessage`
/// events arrive. Mirrors `src/main.rs`'s `ReceiverHandler` + watchdog + shared-outcome-channel
/// pattern exactly (see that file's comments for why a plain "first future to finish" race is the
/// wrong shape here) — a poll-loop task and a watchdog task both funnel into one `outcome`
/// channel; this function just awaits the first real outcome. Returns the elapsed time and byte
/// count, which **is** the authoritative number for this direction.
async fn run_recv(
    dc: Arc<dyn DataChannel>,
    cfg: &Config,
    start: Instant,
) -> Result<(Duration, usize)> {
    let received = Arc::new(AtomicUsize::new(0));
    let target = cfg.total_bytes;
    let (outcome_tx, mut outcome_rx) = tokio::sync::mpsc::channel::<Result<usize>>(1);

    {
        let dc = dc.clone();
        let received = received.clone();
        let outcome_tx = outcome_tx.clone();
        tokio::spawn(async move {
            let mut got = 0usize;
            while let Some(event) = dc.poll().await {
                match event {
                    DataChannelEvent::OnMessage(msg) => {
                        got += msg.data.len();
                        received.fetch_add(msg.data.len(), Ordering::Relaxed);
                        if got >= target {
                            let _ = outcome_tx.send(Ok(got)).await;
                            return;
                        }
                    }
                    DataChannelEvent::OnClose | DataChannelEvent::OnError => {
                        let _ = outcome_tx
                            .send(Err(anyhow!(
                                "data channel closed before receiving all bytes ({got} / {target} received)"
                            )))
                            .await;
                        return;
                    }
                    _ => {}
                }
            }
        });
    }

    {
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
                            "transfer stalled: no progress for {WATCHDOG_TIMEOUT:?} ({now_seen} / {target} bytes received)"
                        )))
                        .await;
                    return;
                }
            }
        });
    }
    drop(outcome_tx);

    let got = outcome_rx
        .recv()
        .await
        .ok_or_else(|| anyhow!("all worker tasks exited without producing an outcome"))??;
    Ok((start.elapsed(), got))
}

/// Samples `pc`'s stats every `interval_ms` and appends one JSON line per sample to `file` — see
/// the module doc comment's "Stats sampling" section for exactly which fields are populated and
/// why SCTP cwnd/ssthresh/rwnd are not among them. Runs until the process exits (detached task;
/// no explicit stop signal — matches this crate's existing convention of relying on process exit
/// to clean up detached tasks, e.g. `src/main.rs`'s watchdog).
async fn sample_stats_loop(
    pc: Arc<dyn PeerConnection>,
    mut file: std::fs::File,
    interval_ms: u64,
    run_start: Instant,
) {
    let mut ticker = interval(Duration::from_millis(interval_ms));
    loop {
        ticker.tick().await;
        let now = Instant::now();
        let t_ms = now.duration_since(run_start).as_millis();
        let report = pc.get_stats(now, StatsSelector::None).await;

        let dc = report.data_channels().next();
        let transport = report.transport();
        let pair = report.candidate_pairs().next();

        let line = format!(
            "{{\"t_ms\":{t_ms},\"dc_bytes_sent\":{},\"dc_bytes_received\":{},\"dc_messages_sent\":{},\"dc_messages_received\":{},\"transport_bytes_sent\":{},\"transport_bytes_received\":{},\"transport_packets_sent\":{},\"transport_packets_received\":{},\"candidate_pair_current_rtt_secs\":{},\"candidate_pair_available_outgoing_bitrate\":{},\"candidate_pair_available_incoming_bitrate\":{}}}",
            dc.map(|d| d.bytes_sent).unwrap_or(0),
            dc.map(|d| d.bytes_received).unwrap_or(0),
            dc.map(|d| d.messages_sent).unwrap_or(0),
            dc.map(|d| d.messages_received).unwrap_or(0),
            transport.map(|t| t.bytes_sent).unwrap_or(0),
            transport.map(|t| t.bytes_received).unwrap_or(0),
            transport.map(|t| t.packets_sent).unwrap_or(0),
            transport.map(|t| t.packets_received).unwrap_or(0),
            pair.map(|p| p.current_round_trip_time.to_string())
                .unwrap_or_else(|| "null".to_string()),
            pair.map(|p| p.available_outgoing_bitrate.to_string())
                .unwrap_or_else(|| "null".to_string()),
            pair.map(|p| p.available_incoming_bitrate.to_string())
                .unwrap_or_else(|| "null".to_string()),
        );
        if let Err(e) = writeln!(file, "{line}") {
            eprintln!("browser-peer: warning: failed to write stats sample: {e}");
        }
    }
}

/// Waits for either Ctrl-C (SIGINT) or, on Unix, SIGTERM — standard graceful-shutdown idiom.
/// Returns the POSIX-convention exit code for whichever signal fired (128 + signal number).
async fn shutdown_signal() -> ExitCode {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            eprintln!("browser-peer: interrupted (SIGINT)");
            ExitCode::from(130)
        }
        _ = terminate => {
            eprintln!("browser-peer: terminated (SIGTERM)");
            ExitCode::from(143)
        }
    }
}

fn main() -> ExitCode {
    // Diagnostic-only: installs a `log`-facade logger to stderr, controlled by `RUST_LOG` (e.g.
    // `RUST_LOG=rtc_sctp=trace`). Without this, `webrtc`/`rtc-sctp`'s internal `log::{trace,debug,
    // warn}!` calls (cwnd, a_rwnd, SACK send/receive) are silently dropped — no logger was ever
    // installed. `try_init()` (not `init()`) so a second call in a future harness doesn't panic;
    // failure (e.g. already initialized) is intentionally ignored.
    let _ = env_logger::try_init();

    let rt = tokio::runtime::Runtime::new().expect("failed to start tokio runtime");
    rt.block_on(async {
        tokio::select! {
            result = run() => match result {
                Ok(code) => code,
                Err(err) => {
                    eprintln!("browser-peer: error: {err:#}");
                    ExitCode::FAILURE
                }
            },
            code = shutdown_signal() => code,
        }
    })
}

async fn run() -> Result<ExitCode> {
    let cfg = Config::from_args()?;
    let runtime = default_runtime().ok_or_else(|| anyhow!("no webrtc runtime available"))?;

    eprintln!(
        "browser-peer: mode={} bytes={} MiB ({} B) chunk={} KiB sctp_buf={} B threshold={} B",
        cfg.mode.as_str(),
        cfg.total_bytes / (1024 * 1024),
        cfg.total_bytes,
        cfg.chunk_bytes / 1024,
        cfg.sctp_buf,
        cfg.threshold,
    );

    let listener = TcpListener::bind(("127.0.0.1", cfg.port))
        .await
        .with_context(|| format!("binding signaling port 127.0.0.1:{}", cfg.port))?;
    eprintln!(
        "browser-peer: signaling WebSocket listening on ws://127.0.0.1:{}/ — open browser-peer.html in Chrome to connect",
        cfg.port
    );

    let (stream, peer_addr) = listener
        .accept()
        .await
        .context("accepting signaling connection")?;
    eprintln!("browser-peer: signaling connection from {peer_addr}");
    let ws = tokio_tungstenite::accept_async(stream)
        .await
        .context("WebSocket handshake")?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    let stats_file = match (&cfg.stats_out, cfg.stats_interval_ms) {
        (Some(path), ms) if ms > 0 => Some(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("opening --stats-out {path:?}"))?,
        ),
        _ => None,
    };

    let (gather_tx, gather_rx) = oneshot::channel();
    let pc = build_peer_connection(
        runtime,
        cfg.sctp_buf,
        Arc::new(Handler {
            gather_tx: Mutex::new(Some(gather_tx)),
        }),
    )
    .await?;

    let dc = pc
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

    let offer = pc.create_offer(None).await.context("create_offer")?;
    pc.set_local_description(offer)
        .await
        .context("set_local_description")?;
    wait_gather_complete(gather_rx).await?;
    let local_desc = pc
        .local_description()
        .await
        .ok_or_else(|| anyhow!("no local description after ICE gathering completed"))?;

    send_json(
        &mut ws_tx,
        &OfferMsg {
            kind: "offer",
            sdp: &local_desc.sdp,
            mode: cfg.mode.as_str(),
            bytes: cfg.total_bytes,
            chunk: cfg.chunk_bytes,
        },
    )
    .await
    .context("sending offer")?;

    let answer = recv_typed::<AnswerMsg>(&mut ws_rx, "answer").await?;
    pc.set_remote_description(
        RTCSessionDescription::answer(answer.sdp).context("parsing browser's answer SDP")?,
    )
    .await
    .context("set_remote_description")?;

    loop {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) => break,
            Some(DataChannelEvent::OnClose) | None => {
                return Err(anyhow!("data channel closed before opening"))
            }
            _ => {}
        }
    }
    eprintln!("browser-peer: data channel open");

    let run_start = Instant::now();

    if let Some(file) = stats_file {
        let pc = pc.clone();
        let interval_ms = cfg.stats_interval_ms;
        tokio::spawn(sample_stats_loop(pc, file, interval_ms, run_start));
    }

    let (rust_elapsed, rust_bytes) = match cfg.mode {
        Mode::Send => run_send(&dc, &cfg, run_start).await?,
        Mode::Recv => run_recv(dc.clone(), &cfg, run_start).await?,
    };

    let peer_result = tokio::time::timeout(
        WATCHDOG_TIMEOUT,
        recv_typed::<ResultMsg>(&mut ws_rx, "result"),
    )
    .await
    .map_err(|_| anyhow!("timed out waiting for the browser's result message"))?
    .context("reading browser's result message")?;

    let _ = pc.close().await;
    let _ = ws_tx.close().await;

    let (elapsed_secs, mb_per_s, peer_elapsed_secs, peer_mb_per_s) = match cfg.mode {
        // Rust enqueue timing is not authoritative for `send` — see the module doc comment.
        Mode::Send => (
            peer_result.elapsed_secs,
            peer_result.mb_per_s,
            rust_elapsed.as_secs_f64(),
            (rust_bytes as f64 / 1_000_000.0) / rust_elapsed.as_secs_f64(),
        ),
        Mode::Recv => (
            rust_elapsed.as_secs_f64(),
            (rust_bytes as f64 / 1_000_000.0) / rust_elapsed.as_secs_f64(),
            peer_result.elapsed_secs,
            peer_result.mb_per_s,
        ),
    };

    if cfg.json {
        println!(
            "{{\"mode\":\"{}\",\"total_bytes\":{},\"chunk_bytes\":{},\"sctp_buf\":{},\"threshold\":{},\"elapsed_secs\":{elapsed_secs:.6},\"mb_per_s\":{mb_per_s:.3},\"peer_bytes\":{},\"peer_elapsed_secs\":{peer_elapsed_secs:.6},\"peer_mb_per_s\":{peer_mb_per_s:.3}}}",
            cfg.mode.as_str(),
            cfg.total_bytes,
            cfg.chunk_bytes,
            cfg.sctp_buf,
            cfg.threshold,
            peer_result.bytes,
        );
    } else {
        println!("browser-peer: A10.29 DataChannel throughput vs. Chrome (docs/DESIGN.md §A8)");
        println!(
            "config: mode={} bytes={} MiB ({} B) chunk={} KiB sctp_buf={} B threshold={} B",
            cfg.mode.as_str(),
            cfg.total_bytes / (1024 * 1024),
            cfg.total_bytes,
            cfg.chunk_bytes / 1024,
            cfg.sctp_buf,
            cfg.threshold,
        );
        println!(
            "result (authoritative, {} side): {mb_per_s:.3} MB/s ({elapsed_secs:.3} s)",
            match cfg.mode {
                Mode::Send => "browser-measured, receiver",
                Mode::Recv => "Rust-measured, receiver",
            }
        );
        println!(
            "peer self-report ({} side): {peer_mb_per_s:.3} MB/s ({peer_elapsed_secs:.3} s, {} bytes)",
            match cfg.mode {
                Mode::Send => "Rust enqueue, not delivery",
                Mode::Recv => "browser send",
            },
            peer_result.bytes,
        );
    }

    Ok(ExitCode::SUCCESS)
}
