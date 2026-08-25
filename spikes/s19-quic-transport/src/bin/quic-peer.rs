//! # S19 (leg 1) — quinn QUIC throughput harness, native process pair
//!
//! Answers the throughput portion of `docs/DESIGN.md` §A13, spike **S19**: *"quinn-over-punched-
//! ICE-socket native↔native: punch rate across NATs, throughput at 0/20/50/100 ms, TURN-relay
//! fallback, real-two-host validation of the netem numbers."* Full method/gating: `docs/SPIKES.md`
//! (§S19). Decisions this spike validates: **A10.31** (native↔native transport moves to QUIC via
//! `quinn`) and **A10.32** (standalone-ICE punching + per-session self-signed cert pinned by
//! fingerprint), both in `docs/DESIGN.md` §A8 and `docs/adr/ADR-005-transport-vfs-rpc-file-
//! safety.md`'s 2026-08-24 amendment. Do not edit the pass criterion here — `docs/DESIGN.md` §A13
//! is authoritative; this file only measures against it.
//!
//! ## What this binary actually does (and does not) measure
//!
//! Two OS processes — one `--mode recv` (the quinn **server**), one `--mode send` (the quinn
//! **client**) — talk QUIC directly over a plain UDP socket pair on `127.0.0.1`. This is **leg 1**
//! of S19's method sketch only: raw quinn throughput under `tc netem`-shaped loopback (see
//! `s19-rtt-run.sh`), with congestion-control comparison (`--cc cubic|bbr`) folded in per the
//! spike's method sketch ("vary ... buffer sizes at each RTT point"). It deliberately does **not**
//! cover:
//!
//! - **NAT punching** (leg 2): the socket here is a bound-and-connected loopback UDP pair, not a
//!   `webrtc-rs` `ice`-crate-punched one. See "Why the ICE↔quinn adapter is deferred" below.
//! - **TURN-relay fallback** (leg 3) or **real-two-host validation** (leg 4).
//!
//! `RESULTS.md` records all four legs and their status; only leg 1 has a harness in this
//! directory today.
//!
//! ## Why the ICE↔quinn adapter is deferred (leg 2)
//!
//! `docs/DESIGN.md` §A8/A10.32: standalone ICE (reusing `webrtc-rs`'s `ice` crate rather than
//! duplicating it) punches the NAT, and "the resulting punched UDP socket is handed to `quinn`,
//! which owns the QUIC connection from there." That sentence hides the actual integration work:
//! quinn does not take a `std::net::UdpSocket` or a `tokio::net::UdpSocket` as its I/O — it takes
//! an [`quinn::AsyncUdpSocket`] (a `quinn-udp`-flavored trait with GSO/GRO/ECN-aware batch
//! send/recv methods and a poll-based readiness model, wired in via
//! [`quinn::Endpoint::new_with_abstract_socket`]). `webrtc-rs`'s `ice::Conn` is a plain async
//! `send`/`recv` socket trait built for one-packet-at-a-time SCTP/DTLS traffic, not quinn's batched
//! `Transmit`/`RecvMeta` shape. Bridging the two means writing a `quinn::AsyncUdpSocket` adapter
//! that queues `ice::Conn::send`/`recv` under quinn's poll contract — real work, but *orthogonal*
//! to the throughput question this leg answers (once bytes are flowing over *any* UDP socket,
//! quinn's congestion control and stream layer behave identically regardless of how that socket's
//! packets got NAT-traversed). Building the adapter now would spend budget on plumbing before
//! knowing whether the pass bar is even reachable; this harness answers that question first with a
//! loopback-bound socket pair, exactly as S3's `src/main.rs` measured `webrtc-rs`↔`webrtc-rs`
//! throughput before A10.29 spent budget on a real-Chrome harness. The adapter is scoped as
//! follow-up work once this leg's numbers are in.
//!
//! ## Certificate pinning (A10.32, mirrors the DTLS `a=fingerprint` rule)
//!
//! `--mode recv` generates a fresh self-signed certificate (`rcgen`) every run and prints its
//! SHA-256 fingerprint (`cert-fp sha256:<hex>`) to stderr. `--mode send` takes that fingerprint via
//! `--cert-fp` and installs a custom `rustls::client::danger::ServerCertVerifier`
//! ([`PinnedFingerprintVerifier`], below) that accepts *exactly* the certificate whose DER SHA-256
//! digest matches — no CA, no hostname check, no TOFU. In production this fingerprint arrives
//! inside the A7-verified `connect` envelope (the same place the WebRTC DTLS `a=fingerprint`
//! travels today, restated for this transport per §A8); here, with no envelope/signaling channel in
//! this harness, it is passed out-of-band on the CLI, exactly as the task brief for this spike
//! specifies. The signature-verification methods still run rustls's normal WebPKI cryptographic
//! checks (via `rustls::crypto::verify_tls{12,13}_signature`) — only chain-of-trust validation is
//! replaced by the pin, not proof-of-possession of the certified key.
//!
//! ## quinn 0.11 API notes (read before re-deriving this)
//!
//! - `quinn::ClientConfig`/`quinn::ServerConfig` are dumb data holders around
//!   `Arc<dyn quinn::crypto::ClientConfig/ServerConfig>`. The convenience constructors
//!   (`ServerConfig::with_single_cert`, `ClientConfig::with_root_certificates`) don't expose ALPN
//!   configuration afterward, and QUIC's RFC 9001 §8.1 requires ALPN negotiation to succeed — so,
//!   like quinn's own `examples/{client,server}.rs`, this file builds `rustls::{Client,Server}Config`
//!   by hand (`builder_with_provider(rustls::crypto::ring::default_provider())`, matching this
//!   crate's `rustls-ring`/`ring` feature selection — no aws-lc-sys/cmake in this dep tree, see
//!   `Cargo.toml`), sets `.alpn_protocols` directly, and wraps the result via
//!   `quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig}`'s `TryFrom` impls.
//! - Path/congestion stats: `Connection::stats() -> ConnectionStats { udp_tx, udp_rx, frame_tx,
//!   frame_rx, path: PathStats { rtt, cwnd, congestion_events, lost_packets, lost_bytes,
//!   sent_packets, current_mtu, .. } }` (`quinn-proto` 0.11.17 `connection::stats`). This is a
//!   genuinely richer surface than S3 had available from `webrtc` 0.20.3's `get_stats()` (which,
//!   per `spikes/s3-throughput/src/main.rs`'s `spawn_stats_sampler` doc comment, exposes no SCTP
//!   congestion-window field at all) — `--stats-out` below reports `rtt`/`cwnd`/
//!   `congestion_events`/`lost_packets` every sample, all directly public.
//! - Congestion control is pluggable via `TransportConfig::congestion_controller_factory` —
//!   `quinn::congestion::{CubicConfig, BbrConfig}` (both re-exported at `quinn::congestion`) are
//!   both present in 0.11's `quinn-proto`, so `--cc bbr` is a real, already-implemented alternative
//!   to the Cubic default, not a stub — worth comparing per the spike's method sketch.
//! - `SendStream::write`/`write_all` are already backpressure-aware: they internally await send
//!   capacity (flow-control window + congestion window) rather than buffering unboundedly, so a
//!   plain `.await`ed `write_all` loop is correct backpressure with no manual polling needed.
//!
//! ## Pass criterion (verbatim, `docs/DESIGN.md` §A13)
//!
//! *"≥ 15 MB/s @ 50 ms; punch or relay success on all tested NAT combos; netem ceiling confirmed
//! on a real link."* This binary + `s19-rtt-run.sh` measure only the throughput clause, at
//! 0/20/50/100 ms under container `tc netem` (RTT matrix) — see `RESULTS.md` for the other three
//! clauses' status.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use quinn::congestion::{BbrConfig, CubicConfig};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Endpoint, TransportConfig, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::time::interval;

/// Fixed ALPN identifier for this harness. QUIC (RFC 9001 §8.1) requires ALPN negotiation to
/// succeed; both sides must offer/accept the same protocol id. Not meant to be stable across
/// spikes/versions — this is a throughput harness, not a wire protocol.
const ALPN: &[u8] = b"spindle-s19-quic-peer/0";

// ── CLI ──────────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// quinn client: opens one uni stream and pushes `--bytes` MiB of payload.
    Send,
    /// quinn server: accepts one connection, receives the transfer on one uni stream.
    Recv,
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cc {
    Cubic,
    Bbr,
}

impl Cc {
    fn as_str(self) -> &'static str {
        match self {
            Cc::Cubic => "cubic",
            Cc::Bbr => "bbr",
        }
    }
}

impl std::str::FromStr for Cc {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "cubic" => Ok(Cc::Cubic),
            "bbr" => Ok(Cc::Bbr),
            other => Err(anyhow!("--cc must be \"cubic\" or \"bbr\", got {other:?}")),
        }
    }
}

struct Config {
    mode: Mode,
    /// Total payload size in bytes (`--bytes`, MiB, default 64). Passed to BOTH sides by
    /// convention (mirrors `spikes/s3-throughput`'s symmetric `--sctp-buf`): `--mode recv` uses
    /// this only to verify the byte count it actually received matches what the caller expects.
    total_bytes: usize,
    /// Chunk size in bytes (`--chunk`, KiB, default 64) — governs `--mode send`'s write-loop chunk
    /// size only.
    chunk_bytes: usize,
    /// `--mode recv` only: address to bind the quinn server endpoint on.
    listen: Option<SocketAddr>,
    /// `--mode send` only: address of the running `--mode recv` peer to connect to.
    connect: Option<SocketAddr>,
    /// Congestion controller (`--cc`, default cubic).
    cc: Cc,
    /// Stream + connection receive window, and send window, in bytes (`--window`, MiB, default
    /// 16) — generous vs. the ~750 KB bandwidth-delay product at the 15 MB/s @ 50 ms pass bar, so
    /// flow control never masks the congestion-control number under test.
    window_bytes: u64,
    /// Stats-sampling interval in milliseconds; 0 (default) disables sampling.
    stats_interval_ms: u64,
    /// JSON-lines output path for stats samples (`--stats-out`); required together with
    /// `--stats-interval-ms`.
    stats_out: Option<PathBuf>,
    /// `--mode send` only, required: SHA-256 fingerprint of the cert `--mode recv` printed
    /// (`cert-fp sha256:<hex>` on its stderr), `sha256:<64 hex chars>`.
    cert_fp: Option<[u8; 32]>,
    /// Emit a single machine-readable JSON result line instead of the human-readable report.
    json: bool,
}

impl Config {
    fn from_args() -> Result<Self> {
        const DEFAULT_BYTES_MIB: usize = 64;
        const DEFAULT_CHUNK_KIB: usize = 64;
        const DEFAULT_WINDOW_MIB: u64 = 16;

        let mut mode: Option<Mode> = None;
        let mut bytes_mib = DEFAULT_BYTES_MIB;
        let mut chunk_kib = DEFAULT_CHUNK_KIB;
        let mut listen: Option<SocketAddr> = None;
        let mut connect: Option<SocketAddr> = None;
        let mut cc = Cc::Cubic;
        let mut window_mib = DEFAULT_WINDOW_MIB;
        let mut stats_interval_ms = 0u64;
        let mut stats_out: Option<PathBuf> = None;
        let mut cert_fp: Option<[u8; 32]> = None;
        let mut json = false;

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--mode" => mode = Some(next_val::<String>(&mut args, "--mode")?.parse()?),
                "--bytes" => bytes_mib = next_val(&mut args, "--bytes")?,
                "--chunk" => chunk_kib = next_val(&mut args, "--chunk")?,
                "--listen" => listen = Some(next_val(&mut args, "--listen")?),
                "--connect" => connect = Some(next_val(&mut args, "--connect")?),
                "--cc" => cc = next_val::<String>(&mut args, "--cc")?.parse()?,
                "--window" => window_mib = next_val(&mut args, "--window")?,
                "--stats-interval-ms" => {
                    stats_interval_ms = next_val(&mut args, "--stats-interval-ms")?
                }
                "--stats-out" => {
                    stats_out = Some(PathBuf::from(next_val::<String>(&mut args, "--stats-out")?))
                }
                "--cert-fp" => {
                    cert_fp = Some(parse_fingerprint(&next_val::<String>(
                        &mut args,
                        "--cert-fp",
                    )?)?)
                }
                "--json" => json = true,
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

        match mode {
            Mode::Recv => {
                if listen.is_none() {
                    return Err(anyhow!("--mode recv requires --listen <addr>"));
                }
                if connect.is_some() {
                    return Err(anyhow!("--mode recv does not take --connect"));
                }
            }
            Mode::Send => {
                if connect.is_none() {
                    return Err(anyhow!("--mode send requires --connect <addr>"));
                }
                if listen.is_some() {
                    return Err(anyhow!("--mode send does not take --listen"));
                }
                if cert_fp.is_none() {
                    return Err(anyhow!(
                        "--mode send requires --cert-fp sha256:<hex> (from --mode recv's \"cert-fp\" stderr line)"
                    ));
                }
            }
        }

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
            mode,
            total_bytes: bytes_mib * 1024 * 1024,
            chunk_bytes: chunk_kib * 1024,
            listen,
            connect,
            cc,
            window_bytes: window_mib * 1024 * 1024,
            stats_interval_ms,
            stats_out,
            cert_fp,
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
        .map_err(|_| anyhow!("{flag} value {raw:?} is not valid"))
}

fn parse_fingerprint(raw: &str) -> Result<[u8; 32]> {
    let hex = raw.strip_prefix("sha256:").ok_or_else(|| {
        anyhow!("--cert-fp must be in the form sha256:<64 hex chars>, got {raw:?}")
    })?;
    if hex.len() != 64 {
        return Err(anyhow!(
            "--cert-fp hex part must be 64 characters (32 bytes), got {} in {raw:?}",
            hex.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow!("--cert-fp is not valid hex: {raw:?}"))?;
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn print_usage() {
    println!("quic-peer — S19 quinn QUIC throughput harness (docs/DESIGN.md §A13, S19)");
    println!();
    println!("USAGE:");
    println!("    quic-peer --mode recv --listen 127.0.0.1:5701 [OPTIONS]");
    println!("    quic-peer --mode send --connect 127.0.0.1:5701 --cert-fp sha256:<hex> [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --mode <send|recv>  required");
    println!("    --bytes <MiB>       total payload size to transfer (default: 64)");
    println!("    --chunk <KiB>       --mode send write-loop chunk size (default: 64)");
    println!("    --listen <addr>     --mode recv: address to bind the quinn server on");
    println!("    --connect <addr>    --mode send: address of the running --mode recv peer");
    println!("    --cc <cubic|bbr>    congestion controller (default: cubic)");
    println!(
        "    --window <MiB>      stream+connection receive window and send window (default: 16)"
    );
    println!(
        "    --stats-interval-ms <N>  sample quinn path stats every N ms (default: 0, disabled)"
    );
    println!("    --stats-out <path>  JSON-lines file for stats samples (required with --stats-interval-ms)");
    println!("    --cert-fp sha256:<hex>  --mode send: required, pins the server cert by SHA-256");
    println!("    --json              print one machine-readable JSON result line");
    println!();
    println!("EXAMPLES:");
    println!("    quic-peer --mode recv --listen 127.0.0.1:5701 --bytes 64 --json");
    println!("    quic-peer --mode send --connect 127.0.0.1:5701 --cert-fp sha256:ab12... --bytes 64 --json");
}

// ── Certificate pinning (A10.32) ────────────────────────────────────────────────────────────

/// Accepts exactly the certificate whose DER SHA-256 digest matches `expected` — no CA, no
/// hostname check, no TOFU. This IS the envelope-pin model: mirrors the DTLS `a=fingerprint` rule
/// (`docs/DESIGN.md` §A8), restated for QUIC per A10.32. In production `expected` arrives inside
/// the A7-verified `connect` envelope; this harness takes it on the CLI instead (`--cert-fp`),
/// since there is no signaling channel here. Signature verification (proof the peer holds the
/// certified private key) still runs rustls's normal cryptographic checks — only chain-of-trust
/// validation is replaced.
#[derive(Debug)]
struct PinnedFingerprintVerifier {
    expected: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "quic-peer: certificate fingerprint mismatch: expected sha256:{}, got sha256:{}",
                hex_encode(&self.expected),
                hex_encode(&actual),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── Transport config ─────────────────────────────────────────────────────────────────────────

fn build_transport_config(cc: Cc, window_bytes: u64) -> Result<Arc<TransportConfig>> {
    let mut transport = TransportConfig::default();
    let window = VarInt::from_u64(window_bytes)
        .map_err(|_| anyhow!("--window value {window_bytes} does not fit in a QUIC varint"))?;
    transport.stream_receive_window(window);
    transport.receive_window(window);
    transport.send_window(window_bytes);
    match cc {
        Cc::Cubic => {
            transport.congestion_controller_factory(Arc::new(CubicConfig::default()));
        }
        Cc::Bbr => {
            transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
        }
    }
    Ok(Arc::new(transport))
}

// ── Stats sampling (quinn path stats: rtt, cwnd, congestion_events, lost_packets) ──────────────

/// Spawns a task that samples `connection.stats().path` every `interval_ms` and appends one JSON
/// line per sample to `path`, alongside the cumulative byte count (`bytes_counter`, updated by the
/// transfer loop) and an interval-local throughput rate. Returns a `JoinHandle` the caller must
/// `abort()` once the transfer finishes.
fn spawn_stats_sampler(
    connection: quinn::Connection,
    bytes_counter: Arc<AtomicU64>,
    interval_ms: u64,
    path: PathBuf,
    start: Instant,
) -> Result<tokio::task::JoinHandle<()>> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening --stats-out {path:?}"))?;
    Ok(tokio::spawn(async move {
        use std::io::Write as _;
        let mut ticker = interval(Duration::from_millis(interval_ms));
        let mut prev_t_ms: u128 = 0;
        let mut prev_bytes: u64 = 0;
        loop {
            ticker.tick().await;
            let now = Instant::now();
            let t_ms = now.duration_since(start).as_millis();
            let bytes = bytes_counter.load(Ordering::Relaxed);
            let dt_secs = (t_ms - prev_t_ms) as f64 / 1000.0;
            let rate_mb_per_s = if dt_secs > 0.0 {
                (bytes.saturating_sub(prev_bytes)) as f64 / 1_000_000.0 / dt_secs
            } else {
                0.0
            };
            prev_t_ms = t_ms;
            prev_bytes = bytes;

            let path_stats = connection.stats().path;
            let line = format!(
                "{{\"t_ms\":{t_ms},\"bytes\":{bytes},\"rate_mb_per_s\":{rate_mb_per_s:.3},\"rtt_ms\":{:.3},\"cwnd\":{},\"congestion_events\":{},\"lost_packets\":{}}}",
                path_stats.rtt.as_secs_f64() * 1000.0,
                path_stats.cwnd,
                path_stats.congestion_events,
                path_stats.lost_packets,
            );
            if let Err(e) = writeln!(file, "{line}") {
                eprintln!("quic-peer: warning: failed to write stats sample: {e}");
            }
        }
    }))
}

// ── recv (quinn server) ─────────────────────────────────────────────────────────────────────

async fn run_recv(cfg: &Config) -> Result<(u64, f64)> {
    let listen = cfg.listen.expect("validated by Config::from_args");

    // Fresh self-signed cert every run (A10.32: per-session cert). `rcgen::generate_simple_self_signed`
    // returns a `CertifiedKey { cert, key_pair }` (rcgen 0.13); `cert.cert` converts to
    // `CertificateDer<'static>` and `cert.key_pair.serialize_der()` gives the matching PKCS#8
    // private key DER.
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("generating self-signed certificate (rcgen)")?;
    let key_der: PrivateKeyDer<'static> =
        PrivatePkcs8KeyDer::from(certified_key.key_pair.serialize_der()).into();
    let cert_der: CertificateDer<'static> = certified_key.cert.into();

    let fingerprint = Sha256::digest(cert_der.as_ref());
    eprintln!("quic-peer: cert-fp sha256:{}", hex_encode(&fingerprint));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("selecting TLS 1.3 (required for QUIC)")?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("building rustls ServerConfig from self-signed cert")?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let quic_server_crypto = QuicServerConfig::try_from(server_crypto)
        .context("wrapping rustls ServerConfig for quinn")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_crypto));
    server_config.transport_config(build_transport_config(cfg.cc, cfg.window_bytes)?);

    let endpoint = Endpoint::server(server_config, listen)
        .with_context(|| format!("binding quinn server endpoint on {listen}"))?;
    eprintln!(
        "quic-peer: listening on {} (cc={}, window={} MiB)",
        endpoint.local_addr()?,
        cfg.cc.as_str(),
        cfg.window_bytes / (1024 * 1024),
    );

    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| anyhow!("endpoint closed before any connection arrived"))?;
    let connection = incoming.await.context("accepting quinn connection")?;
    eprintln!(
        "quic-peer: connection established from {}",
        connection.remote_address()
    );

    let mut recv_stream = connection
        .accept_uni()
        .await
        .context("accepting uni stream")?;

    let bytes_counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let sampler = match &cfg.stats_out {
        Some(path) if cfg.stats_interval_ms > 0 => Some(spawn_stats_sampler(
            connection.clone(),
            bytes_counter.clone(),
            cfg.stats_interval_ms,
            path.clone(),
            start,
        )?),
        _ => None,
    };

    let mut buf = vec![0u8; cfg.chunk_bytes];
    let mut total_received: u64 = 0;
    let mut first_byte_at: Option<Instant> = None;
    let mut last_byte_at = Instant::now();

    loop {
        match recv_stream
            .read(&mut buf)
            .await
            .context("reading from uni stream")?
        {
            Some(0) => continue,
            Some(n) => {
                let now = Instant::now();
                if first_byte_at.is_none() {
                    first_byte_at = Some(now);
                }
                last_byte_at = now;
                total_received += n as u64;
                bytes_counter.store(total_received, Ordering::Relaxed);
            }
            None => break, // peer finished the stream (FIN)
        }
    }

    if let Some(handle) = sampler {
        handle.abort();
    }

    let first_byte_at = first_byte_at.ok_or_else(|| {
        anyhow!("stream closed before any bytes were received (0-byte transfer?)")
    })?;
    let elapsed = last_byte_at.duration_since(first_byte_at);

    if total_received as usize != cfg.total_bytes {
        eprintln!(
            "quic-peer: warning: received {total_received} bytes, expected {} (--bytes mismatch between send/recv invocations?)",
            cfg.total_bytes
        );
    }

    // Best-effort graceful shutdown; the measurement above is already complete.
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok((total_received, elapsed.as_secs_f64()))
}

// ── send (quinn client) ──────────────────────────────────────────────────────────────────────

async fn run_send(cfg: &Config) -> Result<(u64, f64)> {
    let connect_addr = cfg.connect.expect("validated by Config::from_args");
    let expected_fp = cfg.cert_fp.expect("validated by Config::from_args");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedFingerprintVerifier {
        expected: expected_fp,
        provider: provider.clone(),
    });
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("selecting TLS 1.3 (required for QUIC)")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let quic_client_crypto = QuicClientConfig::try_from(client_crypto)
        .context("wrapping rustls ClientConfig for quinn")?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_crypto));
    client_config.transport_config(build_transport_config(cfg.cc, cfg.window_bytes)?);

    let bind_addr: SocketAddr = if connect_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let mut endpoint = Endpoint::client(bind_addr)
        .with_context(|| format!("binding quinn client endpoint on {bind_addr}"))?;
    endpoint.set_default_client_config(client_config);

    eprintln!("quic-peer: connecting to {connect_addr}");
    let connection = endpoint
        .connect(connect_addr, "localhost")
        .context("initiating quinn connection")?
        .await
        .context("establishing quinn connection")?;
    eprintln!("quic-peer: connection established");

    let mut send_stream = connection.open_uni().await.context("opening uni stream")?;

    let bytes_counter = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let sampler = match &cfg.stats_out {
        Some(path) if cfg.stats_interval_ms > 0 => Some(spawn_stats_sampler(
            connection.clone(),
            bytes_counter.clone(),
            cfg.stats_interval_ms,
            path.clone(),
            start,
        )?),
        _ => None,
    };

    // Payload content is irrelevant to the throughput measurement (mirrors
    // spikes/s3-throughput/src/main.rs's `vec![0xABu8; chunk_bytes]` convention).
    let payload = vec![0xABu8; cfg.chunk_bytes];
    let mut remaining = cfg.total_bytes;
    let send_start = Instant::now();
    while remaining > 0 {
        let this_chunk = remaining.min(cfg.chunk_bytes);
        // `write_all` awaits send capacity internally (flow-control + congestion window) — this
        // IS the required backpressure; no separate readiness poll is needed (see module doc
        // comment).
        send_stream
            .write_all(&payload[..this_chunk])
            .await
            .context("writing to uni stream")?;
        remaining -= this_chunk;
        bytes_counter.store((cfg.total_bytes - remaining) as u64, Ordering::Relaxed);
    }
    send_stream.finish().context("finishing uni stream")?;
    // Wait for the peer to acknowledge stream completion so `elapsed` reflects delivery, not just
    // local buffering.
    send_stream
        .stopped()
        .await
        .context("waiting for stream stop")?;
    let elapsed = send_start.elapsed();

    if let Some(handle) = sampler {
        handle.abort();
    }

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok((cfg.total_bytes as u64, elapsed.as_secs_f64()))
}

// ── main ─────────────────────────────────────────────────────────────────────────────────────

fn print_summary(cfg: &Config, bytes: u64, elapsed_secs: f64) {
    let mb = bytes as f64 / 1_000_000.0;
    let mb_per_s = if elapsed_secs > 0.0 {
        mb / elapsed_secs
    } else {
        0.0
    };

    if cfg.json {
        println!(
            "{{\"mode\":\"{}\",\"total_bytes\":{bytes},\"chunk_bytes\":{},\"cc\":\"{}\",\"window_bytes\":{},\"elapsed_secs\":{elapsed_secs:.6},\"mb_per_s\":{mb_per_s:.3}}}",
            match cfg.mode { Mode::Send => "send", Mode::Recv => "recv" },
            cfg.chunk_bytes,
            cfg.cc.as_str(),
            cfg.window_bytes,
        );
    } else {
        println!("quic-peer: S19 quinn QUIC throughput harness (docs/DESIGN.md §A13, S19)");
        println!(
            "config: mode={} bytes={} MiB chunk={} KiB cc={} window={} MiB",
            match cfg.mode {
                Mode::Send => "send",
                Mode::Recv => "recv",
            },
            cfg.total_bytes / (1024 * 1024),
            cfg.chunk_bytes / 1024,
            cfg.cc.as_str(),
            cfg.window_bytes / (1024 * 1024),
        );
        println!("result: {mb_per_s:.3} MB/s ({elapsed_secs:.3} s for {mb:.1} MB, decimal)");
    }
}

fn main() -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to start tokio runtime");
    match rt.block_on(async_main()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("quic-peer: error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn async_main() -> Result<ExitCode> {
    let cfg = Config::from_args()?;

    let (bytes, elapsed_secs) = match cfg.mode {
        Mode::Recv => run_recv(&cfg).await?,
        Mode::Send => run_send(&cfg).await?,
    };

    print_summary(&cfg, bytes, elapsed_secs);
    Ok(ExitCode::SUCCESS)
}
