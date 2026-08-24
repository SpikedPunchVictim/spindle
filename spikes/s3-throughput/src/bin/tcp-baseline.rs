//! # S3 — environment baseline: raw TCP throughput
//!
//! Follow-up to the `webrtc` (`src/main.rs`) and `datachannel-rs` (`src/bin/dc-throughput.rs`)
//! backends, both of which collapse to 1–2 MB/s at 50 ms RTT under `tc netem` on `lo`
//! (`RESULTS.md`) despite clearing the ≥ 50 MB/s LAN bar. Before concluding that's an SCTP/
//! congestion-control ceiling, this binary answers a narrower question: is the *environment*
//! itself (Linux container + `tc netem`-shaped loopback) capable of ≥ 15 MB/s at 50 ms RTT over a
//! transport those two backends don't use — plain TCP? If TCP also collapses under the same
//! `netem` settings, the harness/environment (e.g. `netem`'s default 1000-packet queue dropping
//! packets under a bandwidth-delay-product burst) is implicated, not the SCTP stacks specifically.
//!
//! Deliberately **std-only, no new crate dependencies** — this is a baseline, not a feature; it
//! should not need `tokio` or `webrtc` to answer "can TCP get there." One loopback
//! `TcpListener`/`TcpStream` pair, one sender thread pushing `--chunk`-sized `write_all` calls,
//! one receiver thread reading until `--bytes` bytes have arrived, `TCP_NODELAY` set on both ends
//! (Nagle's algorithm batches small writes — since this harness already writes chunk-sized bufs
//! back-to-back, NODELAY just removes the corresponding ack-delay interaction as a confound, same
//! spirit as the other two backends not fighting their own transport's default batching).
//!
//! Same CLI contract as the other two backends where it applies (`--bytes` MiB, `--chunk` KiB,
//! `--json`) and the same JSON result shape (`total_bytes`, `chunk_bytes`, `elapsed_secs`,
//! `mb_per_s`), plus `"backend":"tcp"` so `RESULTS.md` rows can be told apart from the other two
//! backends' JSON blobs. No `--sctp-buf`/`--threshold` flags — those name SCTP-specific knobs
//! (`webrtc`'s a_rwnd window, `bufferedAmountLowThreshold`) that have no TCP equivalent in this
//! harness; TCP send/receive buffer sizing is left at the OS default throughout (not itself under
//! test here — this binary asks "does the environment support high throughput at all," not "how
//! do TCP buffers tune").
//!
//! RTT is shaped externally exactly like the other two backends: this binary only measures one
//! (RTT, netem-queue-limit) cell per invocation; `rtt-run.sh`'s `tcp` section drives the matrix
//! (including the default-vs-raised `netem` queue `limit` comparison at 50 ms) and records
//! `tc -s qdisc show dev lo` alongside each cell so drops are visible.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// Watchdog: if the receiver makes no forward progress for this long, the run is a stall, not a
/// slow transfer — abort loudly instead of hanging CI/dev machines forever. Same value as the
/// other two backends' `WATCHDOG_TIMEOUT`.
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(60);

/// Read buffer size for the receiver thread's `TcpStream::read` calls. Independent from
/// `--chunk` (which sizes the *sender's* `write_all` calls) — TCP is a byte stream, so message
/// boundaries aren't preserved across the connection, unlike the SCTP-backed harnesses' framed
/// messages. Large enough that read-loop overhead doesn't itself become the bottleneck at high
/// throughput.
const RECV_BUF_BYTES: usize = 1024 * 1024;

struct Config {
    /// Total payload size in bytes (`--bytes`, MiB).
    total_bytes: usize,
    /// Per-`write_all` chunk size in bytes (`--chunk`, KiB).
    chunk_bytes: usize,
    /// Emit a single machine-readable JSON result line instead of the human-readable report.
    json: bool,
}

impl Config {
    fn from_args() -> Result<Self, String> {
        const DEFAULT_BYTES_MIB: usize = 512;
        const DEFAULT_CHUNK_KIB: usize = 64;

        let mut bytes_mib = DEFAULT_BYTES_MIB;
        let mut chunk_kib = DEFAULT_CHUNK_KIB;
        let mut json = false;

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--bytes" => bytes_mib = next_val(&mut args, "--bytes")?,
                "--chunk" => chunk_kib = next_val(&mut args, "--chunk")?,
                "--json" => json = true,
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return Err(format!("unrecognized argument: {other} (see --help)")),
            }
        }

        Ok(Config {
            total_bytes: bytes_mib * 1024 * 1024,
            chunk_bytes: chunk_kib * 1024,
            json,
        })
    }
}

fn next_val<T: std::str::FromStr>(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<T, String> {
    let raw = args
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))?;
    raw.parse::<T>()
        .map_err(|_| format!("{flag} value {raw:?} is not a valid number"))
}

fn print_usage() {
    println!("tcp-baseline — S3 environment baseline: raw TCP loopback throughput");
    println!();
    println!("USAGE:");
    println!("    tcp-baseline [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --bytes <MiB>  total payload size to transfer (default: 512)");
    println!("    --chunk <KiB>  per-write_all chunk size (default: 64)");
    println!("    --json         print one machine-readable JSON result line");
    println!();
    println!("Note: no --sctp-buf/--threshold flags — this is a plain-TCP baseline, no SCTP");
    println!("involved (see the module doc comment in src/bin/tcp-baseline.rs).");
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("tcp-baseline: error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let cfg = Config::from_args()?;

    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;

    let received = Arc::new(AtomicUsize::new(0));
    let target = cfg.total_bytes;

    // ── Shared outcome channel: the receiver hitting `target`, or a genuine failure (a read
    // error, or the watchdog's no-progress timeout) — both funnel into one channel, same pattern
    // as `src/main.rs`/`src/bin/dc-throughput.rs`, so the main thread just waits for the first
    // real outcome instead of racing "receiver thread exited" against it. ──
    let (outcome_tx, outcome_rx) = mpsc::channel::<Result<Instant, String>>();

    // ── Receiver thread: accept the one connection, read until `target` bytes have arrived ──
    {
        let outcome_tx = outcome_tx.clone();
        let received = received.clone();
        std::thread::spawn(move || {
            let result = (|| -> Result<Instant, String> {
                let (mut stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
                stream
                    .set_nodelay(true)
                    .map_err(|e| format!("set_nodelay (receiver): {e}"))?;
                let mut buf = vec![0u8; RECV_BUF_BYTES];
                let mut got = 0usize;
                while got < target {
                    let n = stream.read(&mut buf).map_err(|e| format!("read: {e}"))?;
                    if n == 0 {
                        return Err(format!(
                            "connection closed early: {got} / {target} bytes received"
                        ));
                    }
                    got += n;
                    received.fetch_add(n, Ordering::Relaxed);
                }
                Ok(Instant::now())
            })();
            let _ = outcome_tx.send(result);
        });
    }

    // ── Watchdog: abort if the receiver stalls ──
    {
        let watchdog_received = received.clone();
        let watchdog_tx = outcome_tx.clone();
        std::thread::spawn(move || {
            let mut last_seen = watchdog_received.load(Ordering::Relaxed);
            let mut last_progress = Instant::now();
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let now_seen = watchdog_received.load(Ordering::Relaxed);
                if now_seen >= target {
                    return; // receiver finished; nothing left to watch
                }
                if now_seen != last_seen {
                    last_seen = now_seen;
                    last_progress = Instant::now();
                } else if last_progress.elapsed() > WATCHDOG_TIMEOUT {
                    let _ = watchdog_tx.send(Err(format!(
                        "transfer stalled: no progress for {WATCHDOG_TIMEOUT:?} \
                         ({now_seen} / {target} bytes received)"
                    )));
                    return;
                }
            }
        });
    }
    drop(outcome_tx);

    // ── Sender: connect, then push `total_bytes` in `chunk_bytes`-sized `write_all` calls ──
    let mut sender = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
    sender
        .set_nodelay(true)
        .map_err(|e| format!("set_nodelay (sender): {e}"))?;

    let payload = vec![0xABu8; cfg.chunk_bytes];
    let start = Instant::now();
    let mut sent = 0usize;
    while sent < cfg.total_bytes {
        let this_chunk = cfg.chunk_bytes.min(cfg.total_bytes - sent);
        sender
            .write_all(&payload[..this_chunk])
            .map_err(|e| format!("write_all: {e}"))?;
        sent += this_chunk;
    }
    // Nothing more to send; keep the socket open until the receiver has actually read
    // everything (dropping it early could reset the connection mid-drain on some platforms).

    // ── Wait for the first real outcome: receiver hit target, a read error, or a stall ──
    let end = outcome_rx.recv().map_err(|_| {
        "receiver/watchdog threads exited without producing an outcome".to_string()
    })??;

    let elapsed = end.duration_since(start);
    let mb = cfg.total_bytes as f64 / 1_000_000.0;
    let mbps = mb / elapsed.as_secs_f64();

    if cfg.json {
        println!(
            "{{\"backend\":\"tcp\",\"total_bytes\":{},\"chunk_bytes\":{},\"elapsed_secs\":{:.6},\"mb_per_s\":{:.3}}}",
            cfg.total_bytes, cfg.chunk_bytes, elapsed.as_secs_f64(), mbps,
        );
    } else {
        println!("tcp-baseline: S3 environment baseline (raw TCP loopback)");
        println!(
            "config: bytes={} MiB ({} B), chunk={} KiB",
            cfg.total_bytes / (1024 * 1024),
            cfg.total_bytes,
            cfg.chunk_bytes / 1024,
        );
        println!(
            "result: {:.3} MB/s ({:.3} s for {:.1} MB, decimal)",
            mbps,
            elapsed.as_secs_f64(),
            mb
        );
    }

    drop(sender);

    Ok(ExitCode::SUCCESS)
}
