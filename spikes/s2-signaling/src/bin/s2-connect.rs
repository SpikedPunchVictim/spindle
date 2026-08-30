//! S2 leg A step B — trickle ICE + quinn QUIC punch, carried over the real A7-verified NATS
//! envelope path (docs/SPIKES.md §S2; docs/DESIGN.md §A6/§A7/§A8, v0.9.14's two-key schedule
//! amendment). Step A (`s2-tests.rs`) proved the §A6 connect/trickle-ICE *subject and envelope*
//! mechanics against the live composed stack with opaque placeholder payloads and no ICE/QUIC at
//! all. This binary replaces the placeholders with the real thing and answers the one question
//! step A explicitly deferred: does a real `rtc_ice::agent::Agent` → punched
//! `std::net::UdpSocket` → `quinn::Endpoint` handshake (proven working over a plain TCP+JSON
//! stand-in channel by `spikes/s19-quic-transport`'s leg 2) still work when that stand-in channel
//! is replaced by the real thing — A7-sealed envelopes over NATS, with trickled candidates
//! arriving as separate, asynchronous envelopes rather than a batch?
//!
//! # Architecture
//! One OS process, same shape as `s2-tests.rs`: the "host" is an in-process `tokio::spawn`ed task
//! holding its own real `async-nats` connection (`spike_s1_callout::fixtures`, exactly as step A
//! and `spike-s5-presence` do it) — a genuine NATS peer under the composed helper's real Auth
//! Callout scoping. The "client" drives the connect from `main`. Every connect (offer → answer →
//! trickled ICE → punched QUIC → one stream round trip) runs `N_RUNS` times in a loop for the
//! latency sample, plus one deliberate negative run with a corrupted expected server-cert
//! fingerprint (docs/SPIKES.md's "prove both directions" requirement).
//!
//! # What changed vs. `spikes/s19-quic-transport`'s leg 2
//! S19 exchanged `{ufrag, pwd, candidates[], cert_fp}` over a plain TCP+JSON socket
//! (`SignalMessage`/`exchange_signal`) as a stand-in for signaling, with every candidate batched
//! into that one message before connectivity checks ever start. Here: ICE credentials + the QUIC
//! cert fingerprint travel inside the real offer/answer envelopes (`OfferPayload`/`AnswerPayload`,
//! `spike_s2_signaling::lib.rs`); candidates trickle as separate `KIND_ICE` envelopes on
//! `host.<h>.sess.<c>.<sid>.c2h`/`.h2c`, each with a fresh `seq`, published *after* the
//! offer/answer round trip and consumed by [`drive_ice_agent_trickle`]'s `tokio::select!` loop
//! concurrently with the UDP socket and the agent's own timers — never collected into a batch
//! before `start_connectivity_checks` runs. `ice_punch`/`drive_ice_agent`'s ICE↔quinn handoff
//! itself (`rtc_ice::agent::Agent` → punched socket → `quinn::Endpoint::new`) is unchanged from
//! S19: proven in that spike, ported here, not redesigned.
//!
//! # Mutual QUIC fingerprint pinning
//! Both the offer and the answer carry a QUIC cert fingerprint (`OfferPayload.cert_fp`/
//! `AnswerPayload.cert_fp`), so both directions are pinned — matching the mutual-pinning model
//! `crates/spindle-net/src/quic.rs` already implements for the (not-yet-signaling-integrated) real
//! slice, not S19's one-directional `PinnedFingerprintVerifier`. [`PinServerCert`]/[`PinClientCert`]
//! below are hand-rolled copies of that module's `PinnedServerCertVerifier`/
//! `PinnedClientCertVerifier` (both private to that crate, so not reusable directly) — same logic,
//! spike-local. `spindle-net`'s `QuicServer::bind`/`QuicClient::connect` are NOT used here: both
//! bind their own UDP socket (`Endpoint::server`/`Endpoint::client`), and ICE hands this binary an
//! *already-punched* socket — see RESULTS.md's Q6 finding for exactly what constructor the real
//! slice needs to add.
//!
//! # Env vars
//! - `NATS_URL` — default `nats://127.0.0.1:4222` (the compose stack's published TCP listener).

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use futures_util::StreamExt;
use nkeys::KeyPair;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Endpoint, EndpointConfig};
use rand::Rng;
use rtc_ice::agent::agent_config::AgentConfig as IceAgentConfig;
use rtc_ice::agent::Agent as IceAgent;
use rtc_ice::candidate::candidate_host::CandidateHostConfig;
use rtc_ice::candidate::{unmarshal_candidate, CandidateConfig};
use rtc_ice::state::ConnectionState as IceConnectionState;
use rtc_ice::Event as IceEvent;
use rtc_shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sansio::Protocol as _;
use sha2::{Digest, Sha256};
use spike_s1_callout::fixtures;
use spike_s2_signaling::{
    boot_open_payload, boot_seal_payload, derive_boot_key, open_payload, seal_payload,
    x25519_public_from_bytes, AnswerPayload, BootOpenPayloadParams, BootSealPayloadParams,
    EphemeralKey, IcePayload, OfferPayload, PayloadError, SealPayloadParams, ALG_ID_V1,
    KIND_ANSWER, KIND_ICE, KIND_OFFER, V1,
};
use spindle_core::envelope::EnvelopeError;
use spindle_core::identity::DeviceKey;
use spindle_core::{derive_session_key, Fingerprint, OpenParams, SessionKey, VerifyingKey};
use spindle_proto::artifacts::{Capability, Envelope};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use x25519_dalek::PublicKey as X25519PublicKey;

/// Fixed ALPN identifier for this harness. QUIC (RFC 9001 §8.1) requires ALPN negotiation to
/// succeed. Not meant to be stable across spikes — this is a connect-latency/correctness harness,
/// not a wire protocol.
const ALPN: &[u8] = b"spindle-s2-connect/0";

/// Number of full connect runs in the latency sample (docs/SPIKES.md: "n >= 5").
const N_RUNS: usize = 7;

// ================================================================================================
// Small helpers
// ================================================================================================

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sid_token(sid: &[u8]) -> String {
    sid.iter().map(|b| format!("{b:02x}")).collect()
}

fn fresh_sid() -> Vec<u8> {
    let mut sid = [0u8; 16];
    rand::thread_rng().fill(&mut sid);
    sid.to_vec()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses `"sha256:<64 hex chars>"` (this crate's on-wire cert-fp convention, matching
/// `spikes/s19-quic-transport`'s `SignalMessage.cert_fp`) back into raw bytes.
fn parse_fp_hex(raw: &str) -> Result<[u8; 32]> {
    let hex = raw
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("cert_fp must be sha256:<hex>, got {raw:?}"))?;
    if hex.len() != 64 {
        return Err(anyhow!(
            "cert_fp hex part must be 64 characters (32 bytes), got {} in {raw:?}",
            hex.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow!("cert_fp is not valid hex: {raw:?}"))?;
    }
    Ok(out)
}

async fn connect_device(
    url: &str,
    device: &fixtures::DeviceIdentity,
    caps: Vec<Capability>,
    exp: u64,
) -> Result<async_nats::Client> {
    let session = KeyPair::new_user();
    let nats_fp = fixtures::nats_fp_of_nkey(&session.public_key())?;
    let cert = fixtures::device_certificate(device, nats_fp, now(), exp);
    let root_pk_bytes = device.root.public_key().to_bytes();
    let token = fixtures::device_auth_token(&root_pk_bytes, &cert, &caps);
    let inbox_prefix = format!("_INBOX_{}", device.device_fp);
    let client = async_nats::ConnectOptions::new()
        .nkey(session.seed()?)
        .token(token)
        .custom_inbox_prefix(inbox_prefix)
        .connection_timeout(Duration::from_secs(5))
        .connect(url)
        .await?;
    Ok(client)
}

// ================================================================================================
// Per-session self-signed QUIC certificate (A10.32) — same shape as
// `crates/spindle-net/src/quic.rs`'s `SessionCert` / `spikes/s19-quic-transport`'s `run_recv`
// inline generation, reproduced spike-locally rather than depending on spindle-net for one struct
// (see the module doc comment for why this binary doesn't otherwise use that crate).
// ================================================================================================

struct GeneratedCert {
    cert_der: CertificateDer<'static>,
    key_pkcs8_der: Vec<u8>,
    fingerprint: [u8; 32],
}

impl GeneratedCert {
    fn generate() -> Result<Self> {
        let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .context("generating self-signed certificate (rcgen)")?;
        let key_pkcs8_der = certified_key.key_pair.serialize_der();
        let cert_der: CertificateDer<'static> = certified_key.cert.into();
        let fingerprint: [u8; 32] = Sha256::digest(cert_der.as_ref()).into();
        Ok(Self {
            cert_der,
            key_pkcs8_der,
            fingerprint,
        })
    }

    fn cert_der(&self) -> CertificateDer<'static> {
        self.cert_der.clone()
    }

    fn key_der(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.key_pkcs8_der.clone()).into()
    }

    fn fingerprint_hex(&self) -> String {
        format!("sha256:{}", hex_encode(&self.fingerprint))
    }
}

// ================================================================================================
// Mutual fingerprint pinning (A10.32) — hand-rolled copies of
// `crates/spindle-net/src/quic.rs`'s private `PinnedServerCertVerifier`/`PinnedClientCertVerifier`
// (not reusable directly — private to that crate, and that crate's constructors bind their own
// socket; see the module doc comment).
// ================================================================================================

#[derive(Debug)]
struct PinServerCert {
    expected: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinServerCert {
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
                "s2-connect: server certificate fingerprint mismatch: expected sha256:{}, got sha256:{}",
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

#[derive(Debug)]
struct PinClientCert {
    expected: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ClientCertVerifier for PinClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if actual == self.expected {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "s2-connect: client certificate fingerprint mismatch: expected sha256:{}, got sha256:{}",
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

fn build_server_config(
    cert: &GeneratedCert,
    expected_client_fp: [u8; 32],
) -> Result<quinn::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_verifier = Arc::new(PinClientCert {
        expected: expected_client_fp,
        provider: provider.clone(),
    });
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("selecting TLS 1.3 (required for QUIC)")?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![cert.cert_der()], cert.key_der())
        .context("building rustls ServerConfig")?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let quic_server_crypto = QuicServerConfig::try_from(server_crypto)
        .context("wrapping rustls ServerConfig for quinn")?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        quic_server_crypto,
    )))
}

fn build_client_config(
    cert: &GeneratedCert,
    expected_server_fp: [u8; 32],
) -> Result<quinn::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_verifier = Arc::new(PinServerCert {
        expected: expected_server_fp,
        provider: provider.clone(),
    });
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("selecting TLS 1.3 (required for QUIC)")?
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_client_auth_cert(vec![cert.cert_der()], cert.key_der())
        .context("building rustls ClientConfig")?;
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let quic_client_crypto = QuicClientConfig::try_from(client_crypto)
        .context("wrapping rustls ClientConfig for quinn")?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_client_crypto)))
}

// ================================================================================================
// ICE: local gathering + trickle-aware driving loop (ported from
// spikes/s19-quic-transport/src/bin/quic-peer.rs's `ice_punch`/`drive_ice_agent` — see that
// file's module doc comment for the empirical groundwork; the handoff itself is unchanged, only
// the credential/candidate *source* changes, from `--signal` to trickled NATS envelopes).
// ================================================================================================

struct LocalIce {
    agent: IceAgent,
    socket: tokio::net::UdpSocket,
    ufrag: String,
    pwd: String,
    /// This side's own single host candidate, already marshaled (SDP `a=candidate` line) —
    /// loopback-only (no STUN/TURN; see RESULTS.md's "Not exercised").
    candidate_line: String,
}

/// Binds a UDP socket on `bind_ip` and constructs an `rtc_ice::agent::Agent` with one local host
/// candidate already added, but connectivity checks NOT yet started (the remote ufrag/pwd aren't
/// known yet — that's exactly the offer/answer round trip's job).
async fn start_local_ice(is_controlling: bool, bind_ip: IpAddr) -> Result<LocalIce> {
    let udp = tokio::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .context("binding ICE UDP socket")?;
    let local_addr = udp
        .local_addr()
        .context("reading ICE UDP socket local addr")?;

    let mut agent = IceAgent::new(Arc::new(IceAgentConfig {
        is_controlling,
        disconnected_timeout: Some(Duration::from_secs(5)),
        failed_timeout: Some(Duration::from_secs(15)),
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
    let candidate_line = host_candidate.marshal();

    let credentials = agent.get_local_credentials();
    let ufrag = credentials.ufrag.clone();
    let pwd = credentials.pwd.clone();

    Ok(LocalIce {
        agent,
        socket: udp,
        ufrag,
        pwd,
        candidate_line,
    })
}

/// One decoded, already-verified trickled ICE message, handed from the envelope layer to the ICE
/// driving loop.
enum TrickleEvent {
    Candidate(String),
    EndOfCandidates,
}

#[derive(Default)]
struct TrickleStats {
    /// How many trickled candidates this side actually fed into `add_remote_candidate` before (or
    /// after) selection — answers "does trickle work at all" empirically per run.
    candidates_applied: u32,
    end_of_candidates_seen: bool,
}

/// Drives `agent` to a selected candidate pair. Unlike S19's `drive_ice_agent` (which is handed
/// every remote candidate up front, before this loop ever starts), `candidate_rx` is a THIRD
/// `tokio::select!` branch alongside the UDP socket and the agent's own timers: candidates arrive
/// asynchronously, one envelope at a time, for the whole lifetime of this loop, and are fed into
/// `agent.add_remote_candidate` the moment they're decoded — this is the trickle mechanic itself
/// (docs/SPIKES.md Q1). Once a pair is selected, this returns immediately (any not-yet-arrived
/// candidates, e.g. a same-run end-of-candidates racing selection, are simply never applied — see
/// RESULTS.md for how often that raced in practice).
async fn drive_ice_agent_trickle(
    agent: &mut IceAgent,
    socket: &tokio::net::UdpSocket,
    mut candidate_rx: mpsc::UnboundedReceiver<TrickleEvent>,
    timeout: Duration,
) -> Result<(SocketAddr, TrickleStats)> {
    let local_addr = socket
        .local_addr()
        .context("reading ICE socket local addr")?;
    let mut buf = vec![0u8; 2048];
    let deadline = Instant::now() + timeout;
    let mut stats = TrickleStats::default();

    loop {
        while let Some(transmit) = agent.poll_write() {
            socket
                .send_to(&transmit.message[..], transmit.transport.peer_addr)
                .await
                .context("sending ICE packet")?;
        }

        while let Some(event) = agent.poll_event() {
            if let IceEvent::ConnectionStateChange(state) = event {
                if state == IceConnectionState::Failed {
                    return Err(anyhow!(
                        "ICE punch failed: connectivity checks exhausted with no pair selected"
                    ));
                }
            }
        }

        if let Some((_local, remote)) = agent.get_selected_candidate_pair() {
            return Ok((remote.addr(), stats));
        }

        if Instant::now() >= deadline {
            return Err(anyhow!(
                "ICE trickle timed out after {:.1}s with no pair selected",
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
            msg = candidate_rx.recv() => {
                match msg {
                    Some(TrickleEvent::Candidate(line)) => match unmarshal_candidate(&line) {
                        Ok(c) => {
                            let _ = agent.add_remote_candidate(c);
                            stats.candidates_applied += 1;
                        }
                        Err(e) => eprintln!(
                            "s2-connect: warning: failed to unmarshal trickled candidate {line:?}: {e}"
                        ),
                    },
                    Some(TrickleEvent::EndOfCandidates) => stats.end_of_candidates_seen = true,
                    None => {}
                }
            }
        }
    }
}

/// Consumes a NATS subscriber carrying `KIND_ICE` envelopes for ONE session/direction (used by the
/// client, which owns a dedicated per-run `h2c` subscription — the host instead inlines this
/// logic in `handle_ice_c2h` since its `c2h` subscription is a single wildcard shared across every
/// session). Verifies every A7 receiver MUST-check via the real `spindle_core::envelope::open`
/// (k1, unchanged by the two-key schedule amendment), forwards successfully-opened candidates/
/// end-of-candidates into `tx`, and counts `EnvelopeError::ReplaySeq` rejections into
/// `replay_seq_drops` (docs/SPIKES.md Q5).
#[allow(clippy::too_many_arguments)]
async fn run_ice_rx_task(
    mut sub: async_nats::Subscriber,
    session_key: SessionKey,
    pinned_sender_key: VerifyingKey,
    self_fp: Fingerprint,
    peer_fp: Fingerprint,
    sid: Vec<u8>,
    tx: mpsc::UnboundedSender<TrickleEvent>,
    replay_seq_drops: Arc<AtomicU64>,
) {
    let mut min_seq_exclusive: Option<u64> = Some(0);
    while let Some(msg) = sub.next().await {
        let env = match Envelope::from_canonical_bytes(&msg.payload) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let open_params = OpenParams {
            session_key: &session_key,
            pinned_sender_key: &pinned_sender_key,
            self_fp: &self_fp,
            expected_sid: &sid,
            bound_from_fp: Some(&peer_fp),
            min_seq_exclusive,
            now: now(),
            min_v: V1,
            min_alg_id: ALG_ID_V1,
            expected_kind: KIND_ICE,
            sender_revoked: false,
        };
        match open_payload::<IcePayload>(open_params, &env) {
            Ok(ice) => {
                min_seq_exclusive = Some(env.seq);
                let event = match ice.candidate {
                    Some(c) => TrickleEvent::Candidate(c),
                    None => TrickleEvent::EndOfCandidates,
                };
                if tx.send(event).is_err() {
                    break;
                }
            }
            Err(PayloadError::Envelope(EnvelopeError::ReplaySeq)) => {
                replay_seq_drops.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => { /* uniform silent drop, per DESIGN.md §A5 -- not this run's concern */ }
        }
    }
}

// ================================================================================================
// Host side
// ================================================================================================

struct HostSessionState {
    sid: Vec<u8>,
    session_key: SessionKey,
    min_seq_c2h: Option<u64>,
    /// Forwards decoded trickled candidates (from `handle_ice_c2h`) into this session's live
    /// `drive_ice_agent_trickle` loop, running in a background task spawned by `handle_connect`.
    candidate_tx: mpsc::UnboundedSender<TrickleEvent>,
}

type HostSessions = Arc<Mutex<HashMap<Fingerprint, HostSessionState>>>;

struct HostState {
    nats_client: async_nats::Client,
    host_fp: Fingerprint,
    host_device: DeviceKey,
    host_device_fp: Fingerprint,
    known_device_fp: Fingerprint,
    known_device_sign_pk: VerifyingKey,
    known_device_agree_pk: X25519PublicKey,
    sessions: HostSessions,
    /// docs/SPIKES.md Q5: count of `c2h` `KIND_ICE` envelopes rejected for non-monotonic `seq`,
    /// across every run.
    ice_replay_seq_drops: Arc<AtomicU64>,
}

/// Drives one session's ICE punch to a selected pair, then hands the punched socket to quinn as
/// the QUIC SERVER (host = ICE-controlled = quinn server, mirroring S19's role convention),
/// accepts the client's one control stream, and completes the "ping"/"pong" round trip. Wrapped in
/// a timeout by the caller so a deliberately-broken run (the fingerprint-corruption negative test)
/// cannot leak a task that blocks forever in `accept()`.
async fn host_session_ice_and_quic(
    mut agent: IceAgent,
    socket: tokio::net::UdpSocket,
    candidate_rx: mpsc::UnboundedReceiver<TrickleEvent>,
    cert: GeneratedCert,
    expected_client_fp: [u8; 32],
) -> Result<()> {
    let (remote_addr, stats) =
        drive_ice_agent_trickle(&mut agent, &socket, candidate_rx, Duration::from_secs(15))
            .await
            .context("host ICE punch")?;
    eprintln!(
        "s2-connect: host: ICE selected pair -> {remote_addr} (candidates_applied={}, eoc_seen={})",
        stats.candidates_applied, stats.end_of_candidates_seen
    );

    let std_socket = socket
        .into_std()
        .context("converting host ICE socket to std::net::UdpSocket for quinn")?;
    let server_config = build_server_config(&cert, expected_client_fp)?;
    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        std_socket,
        quinn::default_runtime().ok_or_else(|| anyhow!("no quinn async runtime found"))?,
    )
    .context("constructing quinn endpoint over the ICE-punched socket (host)")?;

    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| anyhow!("host: endpoint closed before a connection arrived"))?;
    let connection = incoming
        .await
        .context("accepting quinn connection (host)")?;
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .context("accepting control stream (host)")?;

    let mut buf = [0u8; 4];
    recv.read_exact(&mut buf)
        .await
        .context("reading ping (host)")?;
    if &buf != b"ping" {
        return Err(anyhow!("host: expected b\"ping\", got {buf:?}"));
    }
    send.write_all(b"pong")
        .await
        .context("writing pong (host)")?;
    send.finish().context("finishing host send stream")?;
    eprintln!("s2-connect: host: stream round trip complete, waiting for client to close");
    // IMPORTANT (found by running this against the live stack): quinn's `Connection`/`Endpoint`
    // implicitly send a CONNECTION_CLOSE (error code 0) when their last handle is dropped. Without
    // this wait, returning here immediately after `finish()` raced the client's `read_exact` of
    // "pong" against that implicit close on every single run -- the client saw "connection lost:
    // closed by peer: 0" instead of the four bytes it had already been sent. Waiting for the
    // client's own explicit `connection.close(...)` (sent only after it finishes reading "pong")
    // makes the teardown ordering deterministic instead of a race. Bounded so a hung/misbehaving
    // client can't leak this task forever (the outer `tokio::time::timeout` in `handle_connect`
    // is a second, longer backstop).
    let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
    eprintln!("s2-connect: host: connection closed by client");
    Ok(())
}

/// Handles one `host.<h>.connect` request — every §A6/§A7 receiver MUST-check step A already
/// implemented, plus (new in step B): decrypting under `k0` (not `k1`), gathering the host's own
/// local ICE candidate + minting its per-session QUIC cert, and spawning the background
/// ICE+QUIC task for this session before replying.
async fn handle_connect(state: &HostState, msg: async_nats::Message) {
    let env = match Envelope::from_canonical_bytes(&msg.payload) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("s2-connect: host: envelope decode failed: {e}");
            return;
        }
    };
    let from_fp = match Fingerprint::from_slice(&env.from_fp) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("s2-connect: host: bad from_fp: {e}");
            return;
        }
    };

    // MUST (§A6, cheap, before crypto): reply subject starts with `_INBOX_<from_fp>.`.
    let expected_prefix = format!("_INBOX_{from_fp}.");
    let reply_ok = msg
        .reply
        .as_deref()
        .map(|r| r.starts_with(&expected_prefix))
        .unwrap_or(false);
    if !reply_ok {
        return; // uniform silent drop -- DESIGN.md §A5
    }

    // MUST (§A5, cheap, before crypto): sender is an active member device.
    if from_fp != state.known_device_fp {
        return;
    }

    let Some(eph_pk_c_bytes) = env.eph_pk.as_ref() else {
        eprintln!("s2-connect: host: offer envelope missing eph_pk");
        return;
    };
    let eph_pk_c = match x25519_public_from_bytes(eph_pk_c_bytes) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("s2-connect: host: bad eph_pk: {e:#}");
            return;
        }
    };

    // k0 (DESIGN.md v0.9.14): ephemeral(client)-static(host) bootstrap DH.
    let dev_dh = state
        .host_device
        .diffie_hellman(&state.known_device_agree_pk);
    let eph_dh_offer = state.host_device.diffie_hellman(&eph_pk_c);
    let k0 = derive_boot_key(
        &eph_dh_offer,
        &dev_dh,
        &env.sid,
        &from_fp,
        &state.host_device_fp,
    );

    let offer: OfferPayload = match boot_open_payload(
        BootOpenPayloadParams {
            boot_key: &k0,
            pinned_sender_key: &state.known_device_sign_pk,
            self_fp: &state.host_device_fp,
            expected_sid: &env.sid,
            now: now(),
            min_v: V1,
            min_alg_id: ALG_ID_V1,
            expected_kind: KIND_OFFER,
        },
        &env,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("s2-connect: host: offer open/verify failed: {e:#}");
            return;
        }
    };
    if offer.transport != "quic" {
        eprintln!(
            "s2-connect: host: unsupported transport {:?}",
            offer.transport
        );
        return;
    }
    let expected_client_fp = match parse_fp_hex(&offer.cert_fp) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("s2-connect: host: bad offer cert_fp: {e:#}");
            return;
        }
    };

    // Accepted: derive k1 (unchanged formula), gather host-side ICE + mint the per-session cert.
    let eph_h = EphemeralKey::generate();
    let eph_dh_final = eph_h.diffie_hellman(&eph_pk_c);
    let session_key_final = derive_session_key(
        &eph_dh_final,
        &dev_dh,
        &env.sid,
        &from_fp,
        &state.host_device_fp,
    );

    let host_ice = match start_local_ice(false, IpAddr::from([127, 0, 0, 1])).await {
        Ok(ice) => ice,
        Err(e) => {
            eprintln!("s2-connect: host: local ICE setup failed: {e:#}");
            return;
        }
    };
    let host_cert = match GeneratedCert::generate() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("s2-connect: host: cert generation failed: {e:#}");
            return;
        }
    };

    let mut agent = host_ice.agent;
    if let Err(e) = agent.start_connectivity_checks(false, offer.ufrag.clone(), offer.pwd.clone()) {
        eprintln!("s2-connect: host: start_connectivity_checks failed: {e:#}");
        return;
    }

    let (candidate_tx, candidate_rx) = mpsc::unbounded_channel::<TrickleEvent>();
    state.sessions.lock().unwrap().insert(
        from_fp,
        HostSessionState {
            sid: env.sid.clone(),
            session_key: session_key_final.clone(),
            min_seq_c2h: Some(0),
            candidate_tx,
        },
    );

    let answer_payload = AnswerPayload {
        transport: "quic".to_string(),
        ufrag: host_ice.ufrag.clone(),
        pwd: host_ice.pwd.clone(),
        cert_fp: host_cert.fingerprint_hex(),
    };
    let answer_env = seal_payload(
        SealPayloadParams {
            session_key: &session_key_final,
            signer: &state.host_device,
            v: V1,
            alg_id: ALG_ID_V1,
            from_fp: state.host_device_fp,
            to_fp: from_fp,
            sid: env.sid.clone(),
            kind: KIND_ANSWER,
            seq: 0,
            ts: now(),
            eph_pk: Some(eph_h.public_bytes()),
        },
        &answer_payload,
    );

    let reply_subject = match msg.reply.clone() {
        Some(r) => r,
        None => return, // checked Some above via reply_ok
    };
    if let Err(e) = state
        .nats_client
        .publish(reply_subject, answer_env.to_canonical_bytes().into())
        .await
    {
        eprintln!("s2-connect: host: publishing answer failed: {e:#}");
        return;
    }

    // Trickle the host's own local candidate, then end-of-candidates, as two SEPARATE envelopes
    // (never batched) on h2c.
    let h2c_subject = format!(
        "host.{}.sess.{}.{}.h2c",
        state.host_fp,
        from_fp,
        sid_token(&env.sid)
    );
    let cand_env = seal_payload(
        SealPayloadParams {
            session_key: &session_key_final,
            signer: &state.host_device,
            v: V1,
            alg_id: ALG_ID_V1,
            from_fp: state.host_device_fp,
            to_fp: from_fp,
            sid: env.sid.clone(),
            kind: KIND_ICE,
            seq: 1,
            ts: now(),
            eph_pk: None,
        },
        &IcePayload {
            candidate: Some(host_ice.candidate_line.clone()),
            end_of_candidates: false,
        },
    );
    if let Err(e) = state
        .nats_client
        .publish(h2c_subject.clone(), cand_env.to_canonical_bytes().into())
        .await
    {
        eprintln!("s2-connect: host: publishing candidate failed: {e:#}");
    }
    let eoc_env = seal_payload(
        SealPayloadParams {
            session_key: &session_key_final,
            signer: &state.host_device,
            v: V1,
            alg_id: ALG_ID_V1,
            from_fp: state.host_device_fp,
            to_fp: from_fp,
            sid: env.sid.clone(),
            kind: KIND_ICE,
            seq: 2,
            ts: now(),
            eph_pk: None,
        },
        &IcePayload {
            candidate: None,
            end_of_candidates: true,
        },
    );
    if let Err(e) = state
        .nats_client
        .publish(h2c_subject, eoc_env.to_canonical_bytes().into())
        .await
    {
        eprintln!("s2-connect: host: publishing end-of-candidates failed: {e:#}");
    }

    let socket = host_ice.socket;
    tokio::spawn(async move {
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            host_session_ice_and_quic(agent, socket, candidate_rx, host_cert, expected_client_fp),
        )
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("s2-connect: host: session task failed: {e:#}"),
            Err(_) => eprintln!("s2-connect: host: session task timed out after 20s"),
        }
    });
}

/// Handles one trickled `KIND_ICE` envelope on `host.<h>.sess.*.*.c2h` — a single wildcard
/// subscription shared across every session (unlike the client, which owns a dedicated `h2c`
/// subscription per run), so this looks the session up by `from_fp` rather than owning its own
/// `run_ice_rx_task`.
async fn handle_ice_c2h(state: &HostState, msg: async_nats::Message) {
    let env = match Envelope::from_canonical_bytes(&msg.payload) {
        Ok(e) => e,
        Err(_) => return,
    };
    let from_fp = match Fingerprint::from_slice(&env.from_fp) {
        Ok(fp) => fp,
        Err(_) => return,
    };

    let mut sessions = state.sessions.lock().unwrap();
    let Some(sess) = sessions.get_mut(&from_fp) else {
        return;
    };

    let open_params = OpenParams {
        session_key: &sess.session_key,
        pinned_sender_key: &state.known_device_sign_pk,
        self_fp: &state.host_device_fp,
        expected_sid: &sess.sid,
        bound_from_fp: Some(&from_fp),
        min_seq_exclusive: sess.min_seq_c2h,
        now: now(),
        min_v: V1,
        min_alg_id: ALG_ID_V1,
        expected_kind: KIND_ICE,
        sender_revoked: false,
    };
    match open_payload::<IcePayload>(open_params, &env) {
        Ok(ice) => {
            sess.min_seq_c2h = Some(env.seq);
            let event = match ice.candidate {
                Some(c) => TrickleEvent::Candidate(c),
                None => TrickleEvent::EndOfCandidates,
            };
            let _ = sess.candidate_tx.send(event);
        }
        Err(PayloadError::Envelope(EnvelopeError::ReplaySeq)) => {
            state.ice_replay_seq_drops.fetch_add(1, Ordering::Relaxed);
        }
        Err(_) => {}
    }
}

async fn run_host(state: Arc<HostState>) {
    let connect_sub = state
        .nats_client
        .subscribe(format!("host.{}.connect", state.host_fp))
        .await;
    let c2h_sub = state
        .nats_client
        .subscribe(format!("host.{}.sess.*.*.c2h", state.host_fp))
        .await;
    let (mut connect_sub, mut c2h_sub) = match (connect_sub, c2h_sub) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            eprintln!("s2-connect: host failed to subscribe: connect={a:?} c2h={b:?}");
            return;
        }
    };
    loop {
        tokio::select! {
            msg = connect_sub.next() => {
                match msg {
                    Some(msg) => handle_connect(&state, msg).await,
                    None => break,
                }
            }
            msg = c2h_sub.next() => {
                match msg {
                    Some(msg) => handle_ice_c2h(&state, msg).await,
                    None => break,
                }
            }
        }
    }
}

// ================================================================================================
// Client side: one full connect (offer -> answer -> trickled ICE -> punched QUIC -> stream)
// ================================================================================================

struct RunLatencies {
    /// (a) offer publish -> answer received AND verified.
    offer_to_answer_ms: f64,
    /// (b) answer received -> ICE selected pair.
    answer_to_selected_ms: f64,
    /// (c) selected pair -> QUIC handshake complete.
    selected_to_quic_ms: f64,
    /// (d) total: offer publish -> usable stream (first payload round trip complete).
    offer_to_stream_ms: f64,
    candidates_applied: u32,
    end_of_candidates_seen: bool,
}

/// Runs one full connect. `corrupt_server_fp`: if true, deliberately flips a bit in the server
/// fingerprint extracted from the (still genuinely verified) answer envelope before building the
/// quinn client config — the docs/SPIKES.md Q3 negative-case hook. Everything else (envelope
/// crypto, ICE punch) proceeds identically; only the QUIC-layer pin uses the wrong value, so a
/// failure here isolates the pin itself, not a broken envelope or ICE path.
#[allow(clippy::too_many_arguments)]
async fn run_connect_once(
    nats_client: &async_nats::Client,
    host_fp: Fingerprint,
    host_device_fp: Fingerprint,
    host_device_sign_pk: VerifyingKey,
    host_device_agree_pk: X25519PublicKey,
    device: &fixtures::DeviceIdentity,
    client_replay_seq_drops: Arc<AtomicU64>,
    corrupt_server_fp: bool,
) -> Result<RunLatencies> {
    let sid = fresh_sid();
    let sid_tok = sid_token(&sid);
    let h2c_subject = format!("host.{host_fp}.sess.{}.{sid_tok}.h2c", device.device_fp);
    let h2c_sub = nats_client
        .subscribe(h2c_subject.clone())
        .await
        .context("subscribing h2c")?;
    nats_client
        .flush()
        .await
        .context("flushing h2c subscribe")?;
    // Mirrors step A's check-3 guard (`s2-tests.rs`): ensure the subscription is installed
    // server-side before the host could possibly publish to it.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Local ICE + QUIC cert prep happens BEFORE t0: this is real work a caller must do before it
    // can even construct a valid offer, so counting it against "offer publish -> answer" (which
    // starts only once the offer is actually on the wire) would be measuring the wrong thing.
    let client_ice = start_local_ice(true, IpAddr::from([127, 0, 0, 1]))
        .await
        .context("client local ICE setup")?;
    let client_cert = GeneratedCert::generate().context("client cert generation")?;

    let eph_c = EphemeralKey::generate();
    let dev_dh = device.device.diffie_hellman(&host_device_agree_pk);
    let eph_dh_offer = eph_c.diffie_hellman(&host_device_agree_pk);
    let k0 = derive_boot_key(
        &eph_dh_offer,
        &dev_dh,
        &sid,
        &device.device_fp,
        &host_device_fp,
    );

    let offer_payload = OfferPayload {
        inbox: format!("_INBOX_{}", device.device_fp),
        transport: "quic".to_string(),
        ufrag: client_ice.ufrag.clone(),
        pwd: client_ice.pwd.clone(),
        cert_fp: client_cert.fingerprint_hex(),
    };
    let offer_env = boot_seal_payload(
        BootSealPayloadParams {
            boot_key: &k0,
            signer: &device.device,
            v: V1,
            alg_id: ALG_ID_V1,
            from_fp: device.device_fp,
            to_fp: host_device_fp,
            sid: sid.clone(),
            kind: KIND_OFFER,
            seq: 0,
            ts: now(),
            eph_pk: Some(eph_c.public_bytes()),
        },
        &offer_payload,
    );

    let t0 = Instant::now();
    let reply = nats_client
        .request(
            format!("host.{host_fp}.connect"),
            offer_env.to_canonical_bytes().into(),
        )
        .await
        .context("requesting connect")?;
    let answer_env = Envelope::from_canonical_bytes(&reply.payload)
        .map_err(|e| anyhow!("answer envelope decode failed: {e}"))?;
    let eph_pk_h_bytes = answer_env
        .eph_pk
        .as_ref()
        .ok_or_else(|| anyhow!("answer envelope missing eph_pk"))?;
    let eph_pk_h = x25519_public_from_bytes(eph_pk_h_bytes)?;
    let eph_dh_final = eph_c.diffie_hellman(&eph_pk_h);
    let k1 = derive_session_key(
        &eph_dh_final,
        &dev_dh,
        &sid,
        &device.device_fp,
        &host_device_fp,
    );

    let answer: AnswerPayload = open_payload(
        OpenParams {
            session_key: &k1,
            pinned_sender_key: &host_device_sign_pk,
            self_fp: &device.device_fp,
            expected_sid: &sid,
            bound_from_fp: None,
            min_seq_exclusive: None,
            now: now(),
            min_v: V1,
            min_alg_id: ALG_ID_V1,
            expected_kind: KIND_ANSWER,
            sender_revoked: false,
        },
        &answer_env,
    )
    .map_err(|e| anyhow!("answer open/verify failed: {e}"))?;
    let t1 = Instant::now();

    if answer.transport != "quic" {
        return Err(anyhow!(
            "host answered with unsupported transport {:?}",
            answer.transport
        ));
    }
    let real_server_fp = parse_fp_hex(&answer.cert_fp)?;
    let expected_server_fp = if corrupt_server_fp {
        let mut fp = real_server_fp;
        fp[0] ^= 0xFF;
        fp
    } else {
        real_server_fp
    };

    // Trickle the client's own local candidate, then end-of-candidates, as two SEPARATE envelopes
    // on c2h, under k1 (the two-key schedule: everything after the offer uses k1).
    let (candidate_tx, candidate_rx) = mpsc::unbounded_channel::<TrickleEvent>();
    let ice_rx_handle = tokio::spawn(run_ice_rx_task(
        h2c_sub,
        k1.clone(),
        host_device_sign_pk,
        device.device_fp,
        host_device_fp,
        sid.clone(),
        candidate_tx,
        client_replay_seq_drops,
    ));

    let mut agent = client_ice.agent;
    agent
        .start_connectivity_checks(true, answer.ufrag.clone(), answer.pwd.clone())
        .context("client start_connectivity_checks")?;

    let c2h_subject = format!("host.{host_fp}.sess.{}.{sid_tok}.c2h", device.device_fp);
    let cand_env = seal_payload(
        SealPayloadParams {
            session_key: &k1,
            signer: &device.device,
            v: V1,
            alg_id: ALG_ID_V1,
            from_fp: device.device_fp,
            to_fp: host_device_fp,
            sid: sid.clone(),
            kind: KIND_ICE,
            seq: 1,
            ts: now(),
            eph_pk: None,
        },
        &IcePayload {
            candidate: Some(client_ice.candidate_line.clone()),
            end_of_candidates: false,
        },
    );
    nats_client
        .publish(c2h_subject.clone(), cand_env.to_canonical_bytes().into())
        .await
        .context("publishing client candidate")?;
    let eoc_env = seal_payload(
        SealPayloadParams {
            session_key: &k1,
            signer: &device.device,
            v: V1,
            alg_id: ALG_ID_V1,
            from_fp: device.device_fp,
            to_fp: host_device_fp,
            sid: sid.clone(),
            kind: KIND_ICE,
            seq: 2,
            ts: now(),
            eph_pk: None,
        },
        &IcePayload {
            candidate: None,
            end_of_candidates: true,
        },
    );
    nats_client
        .publish(c2h_subject, eoc_env.to_canonical_bytes().into())
        .await
        .context("publishing client end-of-candidates")?;

    let (remote_addr, stats) = drive_ice_agent_trickle(
        &mut agent,
        &client_ice.socket,
        candidate_rx,
        Duration::from_secs(15),
    )
    .await
    .context("client ICE punch")?;
    let t2 = Instant::now();

    ice_rx_handle.abort();

    let std_socket = client_ice
        .socket
        .into_std()
        .context("converting client ICE socket to std::net::UdpSocket for quinn")?;
    let client_config = build_client_config(&client_cert, expected_server_fp)?;
    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        std_socket,
        quinn::default_runtime().ok_or_else(|| anyhow!("no quinn async runtime found"))?,
    )
    .context("constructing quinn endpoint over the ICE-punched socket (client)")?;

    let connecting = endpoint
        .connect_with(client_config, remote_addr, "localhost")
        .context("starting quinn connect")?;
    let connection = connecting.await.context("quinn handshake (client)")?;
    let t3 = Instant::now();

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("opening control stream (client)")?;
    send.write_all(b"ping")
        .await
        .context("writing ping (client)")?;
    send.finish().context("finishing client send stream")?;
    let mut buf = [0u8; 4];
    recv.read_exact(&mut buf)
        .await
        .context("reading pong (client)")?;
    if &buf != b"pong" {
        return Err(anyhow!("client: expected b\"pong\", got {buf:?}"));
    }
    let t4 = Instant::now();

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(RunLatencies {
        offer_to_answer_ms: t1.duration_since(t0).as_secs_f64() * 1000.0,
        answer_to_selected_ms: t2.duration_since(t1).as_secs_f64() * 1000.0,
        selected_to_quic_ms: t3.duration_since(t2).as_secs_f64() * 1000.0,
        offer_to_stream_ms: t4.duration_since(t0).as_secs_f64() * 1000.0,
        candidates_applied: stats.candidates_applied,
        end_of_candidates_seen: stats.end_of_candidates_seen,
    })
}

fn median(values: &[f64]) -> f64 {
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n == 0 {
        return f64::NAN;
    }
    if n.is_multiple_of(2) {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    } else {
        v[n / 2]
    }
}

// ================================================================================================
// main
// ================================================================================================

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let exp = now() + 3600;

    // ---- identities (mirrors s2-tests.rs exactly) ----
    let host_seed = [0x52u8; 32];
    let host_identity = fixtures::new_host_identity(host_seed, host_seed);
    let host_fp = host_identity.host_fp;
    let host_device = DeviceKey::from_seeds([0x53; 32], [0x54; 32]);
    let host_device_fp = host_device.device_fp();
    let host_device_sign_pk = host_device.sign_public_key();
    let host_device_agree_pk = host_device.agree_public_key();

    let device_a = fixtures::new_device_identity([0x61; 32], [0x62; 32], [0x63; 32]);
    let cap_a_host1 =
        fixtures::member_capability(&host_identity, device_a.root_fp, 0, exp, vec![0xA1]);

    let host_nats_client = {
        let session = KeyPair::new_user();
        let nats_fp = fixtures::nats_fp_of_nkey(&session.public_key())?;
        let cert = fixtures::host_op_key_cert(&host_identity, nats_fp, now(), exp);
        let root_pk_bytes = host_identity.root.public_key().to_bytes();
        let token = fixtures::host_auth_token(&root_pk_bytes, &cert, None);
        async_nats::ConnectOptions::new()
            .nkey(session.seed()?)
            .token(token)
            .connection_timeout(Duration::from_secs(5))
            .connect(&url)
            .await?
    };
    println!("s2-connect: host_fp={host_fp}");

    let host_state = Arc::new(HostState {
        nats_client: host_nats_client,
        host_fp,
        host_device,
        host_device_fp,
        known_device_fp: device_a.device_fp,
        known_device_sign_pk: device_a.device.sign_public_key(),
        known_device_agree_pk: device_a.device.agree_public_key(),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        ice_replay_seq_drops: Arc::new(AtomicU64::new(0)),
    });
    {
        let state = host_state.clone();
        tokio::spawn(async move {
            run_host(state).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(300)).await; // let host subs land server-side

    let client_a = connect_device(&url, &device_a, vec![cap_a_host1], exp).await?;
    println!("s2-connect: client device_fp={}", device_a.device_fp);

    // ---- N_RUNS successful connects: the latency sample ----
    let client_replay_seq_drops = Arc::new(AtomicU64::new(0));
    let mut runs: Vec<RunLatencies> = Vec::with_capacity(N_RUNS);
    println!("\n==== CONNECT RUNS (n={N_RUNS}) ====");
    for i in 0..N_RUNS {
        match run_connect_once(
            &client_a,
            host_fp,
            host_device_fp,
            host_device_sign_pk,
            host_device_agree_pk,
            &device_a,
            client_replay_seq_drops.clone(),
            false,
        )
        .await
        {
            Ok(r) => {
                println!(
                    "run {i}: offer->answer={:.2}ms answer->selected={:.2}ms selected->quic={:.2}ms offer->stream={:.2}ms candidates_applied={} eoc_seen={}",
                    r.offer_to_answer_ms,
                    r.answer_to_selected_ms,
                    r.selected_to_quic_ms,
                    r.offer_to_stream_ms,
                    r.candidates_applied,
                    r.end_of_candidates_seen,
                );
                runs.push(r);
            }
            Err(e) => println!("run {i}: FAILED: {e:#}"),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let a: Vec<f64> = runs.iter().map(|r| r.offer_to_answer_ms).collect();
    let b: Vec<f64> = runs.iter().map(|r| r.answer_to_selected_ms).collect();
    let c: Vec<f64> = runs.iter().map(|r| r.selected_to_quic_ms).collect();
    let d: Vec<f64> = runs.iter().map(|r| r.offer_to_stream_ms).collect();
    println!(
        "\n==== LATENCY SUMMARY (n={}/{N_RUNS} runs succeeded) ====",
        runs.len()
    );
    println!(
        "(a) offer publish -> answer received+verified: values={a:.2?} median={:.2}ms",
        median(&a)
    );
    println!(
        "(b) answer received -> ICE selected pair:       values={b:.2?} median={:.2}ms",
        median(&b)
    );
    println!(
        "(c) selected pair -> QUIC handshake complete:   values={c:.2?} median={:.2}ms",
        median(&c)
    );
    println!(
        "(d) TOTAL offer -> usable stream:                values={d:.2?} median={:.2}ms",
        median(&d)
    );

    // ---- fingerprint-pin negative test (docs/SPIKES.md Q3: "prove both directions") ----
    println!("\n==== FINGERPRINT PIN NEGATIVE TEST ====");
    println!(
        "(positive direction already proven by every one of the {} successful runs above: each \
         connected using the fingerprint extracted from the verified answer envelope)",
        runs.len()
    );
    match run_connect_once(
        &client_a,
        host_fp,
        host_device_fp,
        host_device_sign_pk,
        host_device_agree_pk,
        &device_a,
        client_replay_seq_drops.clone(),
        true,
    )
    .await
    {
        Ok(_) => println!("[FAIL] corrupted server fingerprint was ACCEPTED -- false green"),
        Err(e) => println!("[PASS] corrupted server fingerprint was rejected -- error: {e:#}"),
    }

    // Let the host's background session tasks (including the negative test's, which will time out
    // after 20s in the background -- not awaited here) finish updating shared counters.
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("\n==== SEQ MONOTONICITY (docs/SPIKES.md Q5) ====");
    println!(
        "client-side (h2c) ICE envelopes rejected for non-monotonic seq: {}",
        client_replay_seq_drops.load(Ordering::Relaxed)
    );
    println!(
        "host-side   (c2h) ICE envelopes rejected for non-monotonic seq: {}",
        host_state.ice_replay_seq_drops.load(Ordering::Relaxed)
    );

    println!(
        "\n==== IcePayload / OfferPayload / AnswerPayload FIELD LIST (docs/SPIKES.md Q4) ===="
    );
    println!("OfferPayload  {{ inbox: String, transport: String, ufrag: String, pwd: String, cert_fp: String }}");
    println!("AnswerPayload {{ transport: String, ufrag: String, pwd: String, cert_fp: String }}");
    println!("IcePayload    {{ candidate: Option<String>, end_of_candidates: bool }}");

    println!("\n==== spindle-net::quic API GAP (docs/SPIKES.md Q6) ====");
    println!(
        "crates/spindle-net/src/quic.rs's QuicServer::bind(addr, cert, expected_client_fp) binds \
         its OWN UDP socket via quinn::Endpoint::server(...). ICE hands this binary an \
         ALREADY-PUNCHED std::net::UdpSocket instead -- this binary calls quinn::Endpoint::new( \
         EndpointConfig::default(), Some(server_config), punched_socket, runtime) directly, \
         bypassing QuicServer entirely, because QuicServer has no constructor that accepts a \
         pre-bound/punched socket. Symmetrically, QuicClient::connect(addr, server_fp, cert) calls \
         Endpoint::client(bind_addr) internally; this binary again bypasses it. The real slice \
         needs a QuicServer::from_socket(std::net::UdpSocket, cert, expected_client_fp) and a \
         QuicClient::from_socket(std::net::UdpSocket, remote_addr, server_fp, cert) (or an \
         equivalent constructor split) so the ICE-punch caller can hand off the socket it already \
         has instead of spindle-net binding a second, useless one."
    );

    Ok(ExitCode::SUCCESS)
}
