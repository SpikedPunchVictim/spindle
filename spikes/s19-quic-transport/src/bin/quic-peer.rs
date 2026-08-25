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
//! **client**) — talk QUIC over UDP. `--transport direct` (default, leg 1): a plain bound UDP
//! socket pair on `127.0.0.1`, addressed directly via `--listen`/`--connect` — raw quinn throughput
//! under `tc netem`-shaped loopback (see `s19-rtt-run.sh`), with congestion-control comparison
//! (`--cc cubic|bbr`). `--transport ice` (leg 2): the UDP socket is punched by a standalone
//! `rtc_ice::agent::Agent` first (candidates/credentials exchanged over a minimal TCP `--signal`
//! channel — this harness's stand-in for the A7-verified `connect` envelope), and *that* punched
//! socket is handed to quinn — see "The ICE↔quinn adapter" below for why this needed no custom
//! `quinn::AsyncUdpSocket` implementation at all. Still not covered by this binary:
//!
//! - **TURN-relay fallback** (leg 3) or **real-two-host validation** (leg 4).
//!
//! `RESULTS.md` records all four legs and their status.
//!
//! ## The ICE↔quinn adapter (leg 2)
//!
//! `docs/DESIGN.md` §A8/A10.32: standalone ICE (reusing `webrtc-rs`'s ICE implementation rather
//! than duplicating it) punches the NAT, and "the resulting punched UDP socket is handed to
//! `quinn`, which owns the QUIC connection from there." The task brief anticipated needing to
//! choose between (a) a bare socket handoff or (b) a custom `quinn::AsyncUdpSocket` bridging some
//! `Conn`-like async abstraction, depending on what the ICE crate exposes. Empirically, no such
//! choice exists here:
//!
//! - **Which crate `webrtc` 0.20.3 actually uses**: `rtc-ice`, not the older standalone
//!   `webrtc-ice` — confirmed via `Cargo.lock` (`webrtc` 0.20.3 depends on a `rtc` facade crate,
//!   which depends on `rtc-ice`; plain `webrtc-ice` does not appear anywhere in this workspace's
//!   dependency graph). Same restructuring already established empirically for SCTP in
//!   `spikes/s3-throughput/Cargo.toml` (`rtc-sctp`) — webrtc-rs 0.20.x replaced its entire
//!   ice/dtls/sctp/etc. internals with a family of **sans-I/O** `rtc-*` crates. `rtc-ice` resolves
//!   and builds standalone (verified via `cargo add --dry-run` before depending on it for real) —
//!   it does not require the rest of `webrtc`/`rtc`.
//! - **What "sans-I/O" means for the adapter question**: `rtc_ice::agent::Agent`'s own doc comment
//!   states it plainly — the agent "owns no sockets and no clock." The caller always owns the UDP
//!   socket: bind it, feed every inbound datagram to `Agent::handle_read` (via its
//!   `sansio::Protocol` impl), and send whatever `Agent::poll_write` emits. There is no `Conn`
//!   object, async or otherwise, ever handed back — design (b) in the task brief doesn't apply to
//!   this crate at all, because there is nothing socket-shaped to bridge. Once the agent reports a
//!   selected pair (`Event::SelectedCandidatePairChange` / `get_selected_candidate_pair()`), the
//!   caller *already holds* the exact `std::net::UdpSocket` quinn needs, punched and nominated.
//! - **The handoff itself**: quinn 0.11 has `Endpoint::new(EndpointConfig, Option<ServerConfig>,
//!   std::net::UdpSocket, Arc<dyn Runtime>) -> io::Result<Self>` (`quinn::default_runtime()` for
//!   the last argument) — a `std::net::UdpSocket`, not an `AsyncUdpSocket` impl, is exactly the
//!   input type. `Endpoint::server`/`Endpoint::client` (used by `--transport direct` below) are
//!   thin convenience wrappers around this same function that bind their own fresh socket; ICE
//!   mode just supplies an already-punched one instead. **Design (a), zero custom trait
//!   implementation — no `AsyncUdpSocket` adapter was written, because none was needed.**
//!
//! One real limitation this surfaced: `rtc_ice::agent::Agent`'s `poll_read` always returns `None`
//! — the sans-I/O agent has no built-in STUN-vs-application-data demuxing on a shared socket (that
//! demuxing is the *full* `rtc` facade's job, one layer up, not this crate's). This harness accepts
//! that: once a pair is selected, it stops feeding the socket's future datagrams to the ICE agent
//! at all and hands the socket to quinn outright, foregoing ICE's RFC 7675 consent-freshness
//! keepalives for the life of the QUIC connection. Acceptable for a throughput/punch-success spike;
//! a production implementation sharing one socket between ongoing consent checks and QUIC traffic
//! would need that demux layer. Also surprising: `AgentConfig.urls` (meant for STUN/TURN server
//! URLs) is accepted but not wired to any actual gathering logic in this crate version — server-
//! reflexive candidate gathering, where needed (the NAT-punch matrix), is done by hand with
//! `rtc-stun` rather than by passing `urls` and expecting the agent to gather automatically.
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

use std::io::{BufRead, BufReader, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use quinn::congestion::{BbrConfig, CubicConfig};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Endpoint, EndpointConfig, TransportConfig, VarInt};
use rtc_ice::agent::agent_config::AgentConfig as IceAgentConfig;
use rtc_ice::agent::Agent as IceAgent;
use rtc_ice::candidate::candidate_host::CandidateHostConfig;
use rtc_ice::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use rtc_ice::candidate::{unmarshal_candidate, CandidateConfig};
use rtc_ice::state::ConnectionState as IceConnectionState;
use rtc_ice::Event as IceEvent;
use rtc_shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc_stun::message::{Getter as _, Message as StunMessage, TransactionId, BINDING_REQUEST};
use rtc_stun::xoraddr::XorMappedAddress;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sansio::Protocol as _;
use serde::{Deserialize, Serialize};
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

/// `--transport` (S19 leg 2): `direct` (default) is leg 1's unmodified bound-UDP-socket-pair
/// behavior — zero regression, `--listen`/`--connect` address the QUIC socket exactly as before.
/// `ice` is leg 2: the UDP socket is punched by a standalone `rtc_ice::agent::Agent` first (see
/// this file's module doc comment for why that needed no `quinn::AsyncUdpSocket` adapter), and
/// candidates/credentials/the cert fingerprint are exchanged over `--signal` instead of
/// `--listen`/`--connect`/`--cert-fp`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Transport {
    Direct,
    Ice,
}

impl std::str::FromStr for Transport {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "direct" => Ok(Transport::Direct),
            "ice" => Ok(Transport::Ice),
            other => Err(anyhow!(
                "--transport must be \"direct\" or \"ice\", got {other:?}"
            )),
        }
    }
}

/// `--signal listen:<port>` / `--signal connect:<host:port>` (S19 leg 2 only): a minimal TCP
/// channel the two `quic-peer` processes use to exchange ICE credentials, candidates, and the cert
/// fingerprint before ICE connectivity checks start. This is this harness's stand-in for the
/// A7-verified `connect` envelope (`docs/DESIGN.md` §A8) — in production this JSON blob's contents
/// travel inside that envelope; here, with no envelope in this harness, they travel over a plain,
/// unauthenticated TCP socket instead. The two roles have a fixed, deadlock-free message order
/// (see `run_signal_listen`/`run_signal_connect`): `connect` always writes its own message first,
/// then reads the peer's; `listen` always reads first, then writes.
#[derive(Clone, Copy)]
enum Signal {
    Listen(SocketAddr),
    Connect(SocketAddr),
}

impl std::str::FromStr for Signal {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        if let Some(rest) = s.strip_prefix("listen:") {
            // Bare port, matching the flag's own documented shape (`listen:<port>`); binds
            // 0.0.0.0 so the container NAT-namespace harness (leg 2 milestone 6) can reach it from
            // outside its own namespace.
            let port: u16 = rest
                .parse()
                .map_err(|_| anyhow!("--signal listen:<port> port {rest:?} is not valid"))?;
            Ok(Signal::Listen(SocketAddr::from(([0, 0, 0, 0], port))))
        } else if let Some(rest) = s.strip_prefix("connect:") {
            let addr: SocketAddr = rest.parse().map_err(|_| {
                anyhow!("--signal connect:<host:port> address {rest:?} is not valid")
            })?;
            Ok(Signal::Connect(addr))
        } else {
            Err(anyhow!(
                "--signal must be \"listen:<port>\" or \"connect:<host:port>\", got {s:?}"
            ))
        }
    }
}

/// The JSON message exchanged over `--signal` (S19 leg 2's envelope stand-in — see `Signal`'s doc
/// comment). `candidates` are SDP `a=candidate` lines (`rtc_ice::candidate::Candidate::marshal`);
/// `cert_fp` is `Some("sha256:<hex>")` only from the side that has already generated a certificate
/// (`--mode recv`, which always generates one — see `run_recv`) — the `--mode send` side's own
/// message carries `cert_fp: None`, it has no certificate of its own to offer.
#[derive(Serialize, Deserialize)]
struct SignalMessage {
    ufrag: String,
    pwd: String,
    candidates: Vec<String>,
    cert_fp: Option<String>,
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
    /// `--mode send` only when `--transport direct`, required: SHA-256 fingerprint of the cert
    /// `--mode recv` printed (`cert-fp sha256:<hex>` on its stderr), `sha256:<64 hex chars>`. When
    /// `--transport ice`, this fingerprint normally arrives over `--signal` instead (see
    /// `SignalMessage`); passing `--cert-fp` explicitly in `ice` mode OVERRIDES the signaled
    /// fingerprint — the harness's hook for testing that a wrong pin is still rejected under ICE
    /// (see RESULTS.md's loopback verification).
    cert_fp: Option<[u8; 32]>,
    /// Emit a single machine-readable JSON result line instead of the human-readable report.
    json: bool,
    /// `--transport direct` (default) or `--transport ice` (S19 leg 2). See `Transport`'s doc
    /// comment.
    transport: Transport,
    /// `--signal listen:<port>` / `--signal connect:<host:port>`, required (and only valid) when
    /// `--transport ice`. See `Signal`'s doc comment.
    signal: Option<Signal>,
    /// `--stun <addr>` (S19 leg 2 NAT-punch matrix only): a STUN server to gather a server-
    /// reflexive candidate from, in addition to the host candidate. Unused (and harmless to omit)
    /// on loopback, where both peers can already reach each other's host candidates directly.
    stun: Option<SocketAddr>,
    /// `--ice-bind <ip>` (`--transport ice` only, default `127.0.0.1`): which local interface
    /// address to bind the ICE/QUIC UDP socket on and advertise as the host candidate. Binding the
    /// wildcard address (`0.0.0.0`) instead would advertise an unroutable `0.0.0.0` host candidate
    /// to the peer — found empirically (`No route to host`) during this leg's loopback
    /// verification, not assumed. The NAT-punch matrix (milestone 6) overrides this per network
    /// namespace (e.g. its own private bridge IP), since each namespace's "the" outbound interface
    /// differs.
    ice_bind_ip: std::net::IpAddr,
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
        let mut transport = Transport::Direct;
        let mut signal: Option<Signal> = None;
        let mut stun: Option<SocketAddr> = None;
        let mut ice_bind_ip: std::net::IpAddr = std::net::IpAddr::from([127, 0, 0, 1]);

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
                "--transport" => {
                    transport = next_val::<String>(&mut args, "--transport")?.parse()?
                }
                "--signal" => signal = Some(next_val::<String>(&mut args, "--signal")?.parse()?),
                "--stun" => stun = Some(next_val(&mut args, "--stun")?),
                "--ice-bind" => ice_bind_ip = next_val(&mut args, "--ice-bind")?,
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

        match transport {
            Transport::Direct => {
                if signal.is_some() {
                    return Err(anyhow!("--signal requires --transport ice"));
                }
                if stun.is_some() {
                    return Err(anyhow!("--stun requires --transport ice"));
                }
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
            }
            Transport::Ice => {
                if listen.is_some() || connect.is_some() {
                    return Err(anyhow!(
                        "--transport ice punches its own socket; it does not take --listen/--connect (use --signal instead)"
                    ));
                }
                match (mode, signal) {
                    (Mode::Recv, Some(Signal::Listen(_))) | (Mode::Send, Some(Signal::Connect(_))) => {}
                    (Mode::Recv, Some(Signal::Connect(_))) => {
                        return Err(anyhow!(
                            "--mode recv with --transport ice requires --signal listen:<port>, not connect:"
                        ))
                    }
                    (Mode::Send, Some(Signal::Listen(_))) => {
                        return Err(anyhow!(
                            "--mode send with --transport ice requires --signal connect:<host:port>, not listen:"
                        ))
                    }
                    (_, None) => {
                        return Err(anyhow!(
                            "--transport ice requires --signal listen:<port> (recv side) or --signal connect:<host:port> (send side)"
                        ))
                    }
                }
                // --cert-fp is optional and meaningful only as an override for both modes under
                // ice (see Config::cert_fp's doc comment) — no requiredness check here.
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
            transport,
            signal,
            stun,
            ice_bind_ip,
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
    println!("    --cert-fp sha256:<hex>  --transport direct/--mode send: required, pins the server cert by SHA-256");
    println!("                        --transport ice: optional override of the --signal-exchanged fingerprint");
    println!("    --json              print one machine-readable JSON result line");
    println!(
        "    --transport <direct|ice>  direct (default): --listen/--connect address the QUIC socket."
    );
    println!("                        ice (S19 leg 2): punch the socket via rtc-ice first, see --signal");
    println!(
        "    --signal <listen:<port>|connect:<host:port>>  required with --transport ice: TCP"
    );
    println!("                        channel exchanging ICE credentials/candidates/cert-fp before punching");
    println!("    --stun <addr>       --transport ice only: STUN server for a server-reflexive candidate");
    println!("                        (NAT-punch matrix; unused/unneeded on loopback)");
    println!("    --ice-bind <ip>     --transport ice only: local interface IP to bind+advertise (default 127.0.0.1)");
    println!();
    println!("EXAMPLES:");
    println!("    quic-peer --mode recv --listen 127.0.0.1:5701 --bytes 64 --json");
    println!("    quic-peer --mode send --connect 127.0.0.1:5701 --cert-fp sha256:ab12... --bytes 64 --json");
    println!(
        "    quic-peer --mode recv --transport ice --signal listen:6000 --bytes 64 --json"
    );
    println!(
        "    quic-peer --mode send --transport ice --signal connect:127.0.0.1:6000 --bytes 64 --json"
    );
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

// ── S19 leg 2: signaling channel (--signal), stand-in for the A7-verified envelope ─────────────

fn write_signal_line(stream: &mut TcpStream, msg: &SignalMessage) -> Result<()> {
    let line = serde_json::to_string(msg).context("encoding SignalMessage as JSON")?;
    stream
        .write_all(line.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .context("writing signal message")
}

fn read_signal_line(reader: &mut BufReader<TcpStream>) -> Result<SignalMessage> {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .context("reading signal message")?;
    if n == 0 {
        return Err(anyhow!(
            "signal peer closed the connection before sending a message"
        ));
    }
    serde_json::from_str(line.trim_end()).context("decoding peer's SignalMessage JSON")
}

/// Exchanges `local` with the peer over `--signal`. Fixed, deadlock-free message order (see
/// `Signal`'s doc comment): `Connect` (the offerer) always writes first, then reads; `Listen` (the
/// answerer) always reads first, then writes. Blocking std TCP I/O on the async runtime: fine here
/// — a one-shot, sub-millisecond-to-low-seconds JSON exchange before any other task exists on this
/// process's (multi-worker-thread, see `main`) tokio runtime, not a steady-state hot path.
fn exchange_signal(signal: Signal, local: &SignalMessage) -> Result<SignalMessage> {
    match signal {
        Signal::Listen(addr) => {
            let listener = TcpListener::bind(addr)
                .with_context(|| format!("binding --signal listener on {addr}"))?;
            eprintln!("quic-peer: signal: listening on {addr}, waiting for peer...");
            let (mut stream, peer) = listener.accept().context("accepting signal connection")?;
            eprintln!("quic-peer: signal: peer connected from {peer}");
            let mut reader = BufReader::new(stream.try_clone().context("cloning signal stream")?);
            let remote = read_signal_line(&mut reader)?;
            write_signal_line(&mut stream, local)?;
            Ok(remote)
        }
        Signal::Connect(addr) => {
            eprintln!("quic-peer: signal: connecting to {addr}...");
            let mut stream = TcpStream::connect(addr)
                .with_context(|| format!("connecting --signal to {addr}"))?;
            write_signal_line(&mut stream, local)?;
            let mut reader = BufReader::new(stream);
            read_signal_line(&mut reader)
        }
    }
}

// ── S19 leg 2: ICE punch (rtc_ice::agent::Agent -> std::net::UdpSocket handoff) ─────────────────

/// Drives `agent` (already given its local candidate, remote credentials, and remote
/// candidate(s), with `start_connectivity_checks` already called) until it reports a selected
/// candidate pair, returning the peer's punched address. Once this returns, the caller stops
/// feeding the socket's datagrams to `agent` entirely and hands the raw socket to quinn instead —
/// see the module doc comment for why (no STUN/application-data demuxing exists in this crate to
/// let the two share the socket afterward).
async fn drive_ice_agent(
    agent: &mut IceAgent,
    socket: &tokio::net::UdpSocket,
    timeout: Duration,
) -> Result<SocketAddr> {
    let local_addr = socket.local_addr().context("reading ICE socket local addr")?;
    let mut buf = vec![0u8; 2048];
    let deadline = Instant::now() + timeout;

    loop {
        while let Some(transmit) = agent.poll_write() {
            socket
                .send_to(&transmit.message[..], transmit.transport.peer_addr)
                .await
                .context("sending ICE packet")?;
        }

        while let Some(event) = agent.poll_event() {
            if let IceEvent::ConnectionStateChange(state) = event {
                eprintln!("quic-peer: ice: connection state -> {state}");
                if state == IceConnectionState::Failed {
                    return Err(anyhow!(
                        "ICE punch failed: connectivity checks exhausted with no pair selected"
                    ));
                }
            }
        }

        if let Some((_local, remote)) = agent.get_selected_candidate_pair() {
            return Ok(remote.addr());
        }

        if Instant::now() >= deadline {
            return Err(anyhow!(
                "ICE punch timed out after {:.1}s with no pair selected",
                timeout.as_secs_f64()
            ));
        }

        let wake_at = agent
            .poll_timeout()
            .unwrap_or_else(|| Instant::now() + Duration::from_millis(100));
        let sleep_for = wake_at
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));

        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {
                agent
                    .handle_timeout(Instant::now())
                    .context("ICE agent timeout handling failed")?;
            }
            res = socket.recv_from(&mut buf) => {
                let (n, peer_addr) = res.context("receiving ICE packet")?;
                agent
                    .handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr,
                            peer_addr,
                            transport_protocol: TransportProtocol::UDP,
                            ecn: None,
                        },
                        message: BytesMut::from(&buf[..n]),
                    })
                    .with_context(|| format!("ICE agent rejected inbound packet from {peer_addr}"))?;
            }
        }
    }
}

/// Result of a successful ICE punch: the raw punched socket (ready to hand straight to
/// `quinn::Endpoint::new` — see the module doc comment for why no adapter trait is needed), the
/// peer's selected address, and — `--mode send` only — the peer's cert fingerprint as learned over
/// `--signal` (unless `--cert-fp` was passed to override it; see `Config::cert_fp`).
struct IcePunchResult {
    socket: std::net::UdpSocket,
    remote_addr: SocketAddr,
    remote_cert_fp: Option<[u8; 32]>,
}

/// Sends one STUN Binding Request (RFC 5389) to `stun_addr` over `socket` and returns the
/// XOR-MAPPED-ADDRESS from the response — this harness's server-reflexive gathering (S19 leg 2
/// milestone 6). Hand-rolled directly against `rtc-stun` rather than reusing `rtc_ice::Agent`'s
/// own driving loop, which has no STUN-server concept at all (only peer-to-peer connectivity
/// checks — see the module doc comment). One-shot, no retries: fine for a spike hitting a STUN
/// server on the same container/bridge; a production gatherer would retry with backoff per
/// RFC 5389 §7.2.1.
async fn stun_gather(
    socket: &tokio::net::UdpSocket,
    stun_addr: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr> {
    let mut req = StunMessage::new();
    req.build(&[Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)])
        .context("building STUN Binding Request")?;
    socket
        .send_to(&req.raw, stun_addr)
        .await
        .context("sending STUN Binding Request")?;

    let mut buf = [0u8; 1500];
    let (n, from) = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
        .await
        .context("STUN Binding Request timed out waiting for a response")?
        .context("receiving STUN Binding Response")?;
    if from != stun_addr {
        return Err(anyhow!(
            "STUN response arrived from {from}, expected the server at {stun_addr}"
        ));
    }

    let mut resp = StunMessage::new();
    resp.raw = buf[..n].to_vec();
    resp.decode().context("decoding STUN Binding Response")?;

    let mut mapped = XorMappedAddress::default();
    mapped
        .get_from(&resp)
        .context("reading XOR-MAPPED-ADDRESS from STUN Binding Response")?;
    Ok(SocketAddr::new(mapped.ip, mapped.port))
}

/// Punches a UDP socket to the peer named by `signal`'s counterpart process, via a standalone
/// `rtc_ice::agent::Agent`. `is_controlling` follows this harness's fixed role mapping: `--signal
/// listen:` (the `--mode recv` side, by convention) is ICE-controlled; `--signal connect:` (the
/// `--mode send` side) is ICE-controlling — mirrors send-initiates-the-TCP-connection /
/// send-is-the-offerer already true of `--signal`'s own message order.
async fn ice_punch(
    is_controlling: bool,
    signal: Signal,
    own_cert_fp_hex: Option<String>,
    stun: Option<SocketAddr>,
    bind_ip: std::net::IpAddr,
    handshake_timeout: Duration,
) -> Result<IcePunchResult> {
    // Bind a concrete interface address, not the wildcard `0.0.0.0` — found empirically (`No
    // route to host`) when this bound `0.0.0.0:0` and then advertised `0.0.0.0` itself as the
    // host candidate's address: an address the peer obviously cannot route packets back to. See
    // `Config::ice_bind_ip`'s doc comment.
    let udp = tokio::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .context("binding ICE UDP socket")?;
    let local_addr = udp
        .local_addr()
        .context("reading ICE UDP socket local addr")?;

    let mut agent = IceAgent::new(Arc::new(IceAgentConfig {
        is_controlling,
        disconnected_timeout: Some(Duration::from_secs(5)),
        failed_timeout: Some(handshake_timeout),
        ..Default::default()
    }))
    .context("constructing rtc_ice::Agent")?;

    let host_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_string(),
            address: local_addr.ip().to_string(),
            port: local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .context("constructing local host candidate")?;
    agent
        .add_local_candidate(host_candidate.clone())
        .context("adding local host candidate")?;

    // S19 leg 2 milestone 6 (NAT-punch matrix): server-reflexive gathering, hand-rolled directly
    // against `rtc-stun` — `rtc_ice::agent::AgentConfig.urls` is accepted but not wired to any
    // gathering logic in rtc-ice 0.20.3 (verified by grepping every `agent/*.rs`: the field is
    // only ever stored, never read). Not needed on loopback (milestones 1-5), where both peers
    // already reach each other's host candidates directly with no NAT in the way.
    let mut candidates = vec![host_candidate.marshal()];
    if let Some(stun_addr) = stun {
        let mapped = stun_gather(&udp, stun_addr, Duration::from_secs(5))
            .await
            .context("STUN server-reflexive gathering")?;
        let srflx_candidate = CandidateServerReflexiveConfig {
            base_config: CandidateConfig {
                network: "udp".to_string(),
                address: mapped.ip().to_string(),
                port: mapped.port(),
                component: 1,
                ..Default::default()
            },
            rel_addr: local_addr.ip().to_string(),
            rel_port: local_addr.port(),
            url: Some(format!("stun:{stun_addr}")),
        }
        .new_candidate_server_reflexive()
        .context("constructing server-reflexive candidate")?;
        agent
            .add_local_candidate(srflx_candidate.clone())
            .context("adding local server-reflexive candidate")?;
        eprintln!(
            "quic-peer: ice: gathered server-reflexive candidate {mapped} via STUN {stun_addr}"
        );
        candidates.push(srflx_candidate.marshal());
    }

    let credentials = agent.get_local_credentials();
    let local_msg = SignalMessage {
        ufrag: credentials.ufrag.clone(),
        pwd: credentials.pwd.clone(),
        candidates,
        cert_fp: own_cert_fp_hex,
    };

    let remote_msg = exchange_signal(signal, &local_msg)?;

    for raw in &remote_msg.candidates {
        let remote_candidate = unmarshal_candidate(raw)
            .with_context(|| format!("unmarshaling remote candidate {raw:?}"))?;
        agent
            .add_remote_candidate(remote_candidate)
            .context("adding remote candidate")?;
    }

    agent
        .start_connectivity_checks(is_controlling, remote_msg.ufrag.clone(), remote_msg.pwd.clone())
        .context("starting ICE connectivity checks")?;

    let remote_addr = drive_ice_agent(&mut agent, &udp, handshake_timeout).await?;
    eprintln!("quic-peer: ice: punched — selected remote address {remote_addr}");

    let std_socket = udp
        .into_std()
        .context("converting ICE tokio UdpSocket to std::net::UdpSocket for quinn")?;

    let remote_cert_fp = remote_msg
        .cert_fp
        .as_deref()
        .map(parse_fingerprint)
        .transpose()
        .context("parsing peer's signaled cert-fp")?;

    Ok(IcePunchResult {
        socket: std_socket,
        remote_addr,
        remote_cert_fp,
    })
}

// ── recv (quinn server) ─────────────────────────────────────────────────────────────────────

async fn run_recv(cfg: &Config) -> Result<(u64, f64)> {
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

    let endpoint = match cfg.transport {
        Transport::Direct => {
            let listen = cfg.listen.expect("validated by Config::from_args");
            Endpoint::server(server_config, listen)
                .with_context(|| format!("binding quinn server endpoint on {listen}"))?
        }
        Transport::Ice => {
            let signal = cfg.signal.expect("validated by Config::from_args");
            let punch = ice_punch(
                /* is_controlling = */ false,
                signal,
                Some(format!("sha256:{}", hex_encode(&fingerprint))),
                cfg.stun,
                cfg.ice_bind_ip,
                Duration::from_secs(15),
            )
            .await
            .context("ICE punch (recv side)")?;
            Endpoint::new(
                EndpointConfig::default(),
                Some(server_config),
                punch.socket,
                quinn::default_runtime().ok_or_else(|| anyhow!("no quinn async runtime found"))?,
            )
            .context("constructing quinn endpoint over the ICE-punched socket")?
        }
    };
    eprintln!(
        "quic-peer: listening on {} (cc={}, window={} MiB, transport={})",
        endpoint.local_addr()?,
        cfg.cc.as_str(),
        cfg.window_bytes / (1024 * 1024),
        match cfg.transport {
            Transport::Direct => "direct",
            Transport::Ice => "ice",
        },
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

/// Builds the quinn client config (rustls `ClientConfig` wrapped for QUIC, ALPN set, transport
/// config applied) around a fingerprint-pinning verifier for `expected_fp`. Shared by both
/// `--transport direct` (where `expected_fp` comes straight from `--cert-fp`) and `--transport
/// ice` (where it comes from the `--signal` exchange, or `--cert-fp` if given as an override —
/// see `Config::cert_fp`'s doc comment) — the verifier and transport config don't care which.
fn build_client_config(cfg: &Config, expected_fp: [u8; 32]) -> Result<quinn::ClientConfig> {
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
    Ok(client_config)
}

async fn run_send(cfg: &Config) -> Result<(u64, f64)> {
    let (endpoint, connect_addr) = match cfg.transport {
        Transport::Direct => {
            let connect_addr = cfg.connect.expect("validated by Config::from_args");
            let expected_fp = cfg.cert_fp.expect("validated by Config::from_args");
            let client_config = build_client_config(cfg, expected_fp)?;

            let bind_addr: SocketAddr = if connect_addr.is_ipv6() {
                "[::]:0".parse().unwrap()
            } else {
                "0.0.0.0:0".parse().unwrap()
            };
            let mut endpoint = Endpoint::client(bind_addr)
                .with_context(|| format!("binding quinn client endpoint on {bind_addr}"))?;
            endpoint.set_default_client_config(client_config);
            (endpoint, connect_addr)
        }
        Transport::Ice => {
            let signal = cfg.signal.expect("validated by Config::from_args");
            let punch = ice_punch(
                /* is_controlling = */ true,
                signal,
                None, // send side never has a cert of its own to offer
                cfg.stun,
                cfg.ice_bind_ip,
                Duration::from_secs(15),
            )
            .await
            .context("ICE punch (send side)")?;
            // --cert-fp, if given under --transport ice, OVERRIDES the signaled fingerprint (see
            // Config::cert_fp's doc comment) — this is the hook the loopback verification uses to
            // confirm a wrong pin is still rejected even when ICE punching itself succeeds.
            let expected_fp = cfg.cert_fp.or(punch.remote_cert_fp).ok_or_else(|| {
                anyhow!(
                    "peer's --signal message carried no cert-fp and no --cert-fp override was given"
                )
            })?;
            let client_config = build_client_config(cfg, expected_fp)?;

            let mut endpoint = Endpoint::new(
                EndpointConfig::default(),
                None,
                punch.socket,
                quinn::default_runtime().ok_or_else(|| anyhow!("no quinn async runtime found"))?,
            )
            .context("constructing quinn endpoint over the ICE-punched socket")?;
            endpoint.set_default_client_config(client_config);
            (endpoint, punch.remote_addr)
        }
    };

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
