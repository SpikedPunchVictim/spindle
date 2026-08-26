//! QUIC transport for the VFS RPC control stream (DESIGN.md §A8 "Native↔native transport
//! (primary): QUIC via quinn" / §A6 "Transport negotiation" / A10.31-32), graduated from
//! `spikes/s19-quic-transport`'s proven quinn 0.11 recipe: `quinn` 0.11 with
//! `default-features = false` + `["runtime-tokio", "rustls-ring"]`, `rustls` 0.23 built by hand
//! (`ServerConfig`/`ClientConfig` construction, not the `platform-verifier`/webpki path) around
//! the `ring` crypto provider, `rcgen` 0.13 self-signed per-session certificates, and SHA-256-of-
//! DER fingerprints. See `spikes/s19-quic-transport/src/bin/quic-peer.rs`'s module doc comment for
//! the empirical groundwork this recipe rests on (why a hand-built rustls config is required for
//! QUIC's ALPN requirement, why `ring` over `aws-lc-rs`, etc.) — not re-derived here.
//!
//! # What this module adds beyond S19
//!
//! S19 pins only the *server's* certificate (one-directional — a `send`/`recv` throughput
//! harness with no notion of "the client's identity"). DESIGN.md §A8 additionally requires the
//! *client* to be authenticated for a real VFS RPC session (the session is bound to a
//! `device_fp`, per `spindle_host_core::server::SessionContext`'s doc comment) — this module adds
//! **mutual** fingerprint pinning: the server requires and pins the client's certificate exactly
//! the same way S19 pins the server's, via a second, symmetric verifier
//! (`rustls::server::danger::ClientCertVerifier` in place of
//! `rustls::client::danger::ServerCertVerifier`).
//!
//! # Envelope integration (deferred)
//!
//! Per DESIGN.md §A6, both peers' QUIC certificate fingerprints travel inside the A7-verified
//! `connect` envelope during signaling ("the same envelopes carry ICE candidates and the peer's
//! QUIC certificate fingerprint; the TLS handshake is verified against that pinned fingerprint").
//! Wiring that envelope exchange is Stage 5 (NATS/signaling), unscheduled as of this slice — here,
//! [`QuicServer::bind`]/[`QuicClient::connect`] simply take the expected fingerprint as a direct
//! parameter, exactly as S19's harness took it via `--cert-fp` in place of a real signaling
//! channel. A caller integrating this module with real signaling supplies the fingerprint it
//! extracted from the verified envelope; nothing here assumes how that fingerprint arrived.
//!
//! # ALPN
//!
//! QUIC (RFC 9001 §8.1) requires ALPN negotiation to succeed. [`ALPN`] is this protocol's token —
//! **not yet in DESIGN.md §A8** (flagged in this slice's report as a docs-amendment finding,
//! alongside [`crate::framing`]'s wire format).
//!
//! # Control stream
//!
//! DESIGN.md §A8: "One control stream (VFS RPC) + data streams." Both [`QuicServer::accept`] and
//! [`QuicClient::connect`] open/accept exactly one bidirectional QUIC stream and hand back a
//! [`ControlStream`] — a plain `{send: quinn::SendStream, recv: quinn::RecvStream}` pair. Both
//! halves already implement `tokio::io::{AsyncWrite, AsyncRead}` (quinn's `runtime-tokio`
//! feature), so [`crate::framing::read_frame`]/[`crate::framing::write_frame`] run directly over
//! them with no adapter — [`ControlStream`] does not itself implement a combined
//! `AsyncRead + AsyncWrite` trait; framing already takes read/write halves as two separate generic
//! parameters (see that module's doc comment), and a real VFS RPC loop reads/writes concurrently
//! from/to each half independently. Data streams (per-transfer, out of `read`/`upload_chunk`'s
//! inline-bytes path) remain out of scope for this slice, same as `spindle_proto::vfs_rpc`'s
//! module doc comment already states.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Fixed ALPN identifier for the VFS RPC control stream. QUIC (RFC 9001 §8.1) requires ALPN
/// negotiation to succeed — see the module doc comment's "ALPN" section for the docs-amendment
/// finding.
pub const ALPN: &[u8] = b"spindle-vfs/1";

/// Everything that can go wrong building or driving a QUIC session in this module.
#[derive(Debug, Error)]
pub enum QuicError {
    /// Generating the per-session self-signed certificate (`rcgen`) failed.
    #[error("generating self-signed session certificate: {0}")]
    CertGen(#[from] rcgen::Error),
    /// Building a `rustls::ServerConfig`/`ClientConfig` failed (e.g. no TLS 1.3 support, a
    /// malformed key).
    #[error("building rustls TLS config: {0}")]
    Tls(#[from] rustls::Error),
    /// Wrapping a validated rustls config for quinn failed — per quinn's own docs, this can only
    /// happen if the config lacks TLS 1.3 support, which this module always requests.
    #[error("wrapping TLS config for QUIC: {0}")]
    NoInitialCipherSuite(#[from] NoInitialCipherSuite),
    /// Binding the local UDP socket failed.
    #[error("binding QUIC endpoint: {0}")]
    Io(#[from] std::io::Error),
    /// `Endpoint::connect`/`connect_with` rejected the attempt before the handshake even started
    /// (e.g. an invalid remote address).
    #[error("starting QUIC connection: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// The QUIC/TLS handshake or an established connection failed — this is where a fingerprint
    /// mismatch (either direction) surfaces, since the pinning verifiers reject the peer's
    /// certificate from inside the TLS handshake itself.
    #[error("QUIC connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// The endpoint was closed (or the driver task died) before a connection arrived.
    #[error("QUIC endpoint closed before a connection arrived")]
    EndpointClosed,
}

// ── Per-session self-signed certificate (A10.32) ────────────────────────────────────────────────

/// A fresh, per-session self-signed QUIC certificate (DESIGN.md §A10.32: "Per-session self-signed
/// QUIC certificate, fingerprint pinned via the A7-verified envelope"). Generated once per
/// [`SessionCert::generate`] call — callers mint a new one per session, never reuse one across
/// sessions (mirrors S19's `run_recv`: "Fresh self-signed cert every run").
///
/// Holds the certificate's DER encoding (`Clone`, so it can be handed to as many rustls configs as
/// needed — e.g. a server built once per test) and the private key's raw PKCS#8 DER bytes (`Vec<u8>`
/// rather than `rustls::pki_types::PrivateKeyDer` directly, since that type does not implement
/// `Clone` — [`SessionCert::key_der`] rebuilds the typed wrapper on demand from the stored bytes).
pub struct SessionCert {
    cert_der: CertificateDer<'static>,
    key_pkcs8_der: Vec<u8>,
    fingerprint: [u8; 32],
}

impl SessionCert {
    /// Generates a fresh self-signed certificate using rcgen's default signing algorithm (ECDSA
    /// P-256), matching S19's `generate_simple_self_signed` call exactly. This module does not
    /// need or check a specific signature algorithm — nothing here validates a certificate chain,
    /// only a fingerprint (see the module doc comment).
    pub fn generate() -> Result<Self, QuicError> {
        let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        let key_pkcs8_der = certified_key.key_pair.serialize_der();
        let cert_der: CertificateDer<'static> = certified_key.cert.into();
        let fingerprint: [u8; 32] = Sha256::digest(cert_der.as_ref()).into();
        Ok(SessionCert {
            cert_der,
            key_pkcs8_der,
            fingerprint,
        })
    }

    /// SHA-256 of the certificate's DER encoding — the value both sides pin against (DESIGN.md
    /// §A10.32, matching S19's derivation exactly: `Sha256::digest(cert_der.as_ref())`).
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn cert_der(&self) -> CertificateDer<'static> {
        self.cert_der.clone()
    }

    fn key_der(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.key_pkcs8_der.clone()).into()
    }
}

// ── Certificate pinning (A10.32) ─────────────────────────────────────────────────────────────────

/// Accepts exactly the peer certificate whose DER SHA-256 digest matches `expected` — no CA, no
/// hostname check, no TOFU (identical model to S19's `PinnedFingerprintVerifier`, which this
/// verifies the *server's* cert; see [`PinnedClientCertVerifier`] below for the client-cert twin
/// mutual pinning adds). Signature verification (proof the peer holds the certified private key)
/// still runs rustls's normal cryptographic checks — only chain-of-trust validation is replaced.
#[derive(Debug)]
struct PinnedServerCertVerifier {
    expected: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
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
                "server certificate fingerprint mismatch: expected sha256:{}, got sha256:{}",
                hex(&self.expected),
                hex(&actual),
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

/// The server-side twin of [`PinnedServerCertVerifier`]: pins the *client's* certificate by
/// fingerprint instead of the server's. `client_auth_mandatory` returns `true` — DESIGN.md §A8's
/// VFS RPC session is bound to a `device_fp` (`spindle_host_core::server::SessionContext`), which
/// requires knowing who the client is; an optional/absent client certificate is never acceptable
/// here.
#[derive(Debug)]
struct PinnedClientCertVerifier {
    expected: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ClientCertVerifier for PinnedClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No CA/root store at all in the pinning model (same as the server-cert side): an empty
        // hint list per this method's own doc comment ("the client should always provide a client
        // certificate if it has one") is correct here since there is no trust anchor to hint.
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
                "client certificate fingerprint mismatch: expected sha256:{}, got sha256:{}",
                hex(&self.expected),
                hex(&actual),
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Control stream ───────────────────────────────────────────────────────────────────────────────

/// One bidirectional QUIC stream (DESIGN.md §A8: "One control stream (VFS RPC)"), plus the
/// [`quinn::Connection`] it belongs to (kept around so a caller can inspect
/// `remote_address()`/close the connection when the control stream ends — see
/// `spindle_host_core::serve`'s module doc comment for how the VFS RPC loop uses this).
pub struct ControlStream {
    pub connection: Connection,
    pub send: SendStream,
    pub recv: RecvStream,
}

// ── Server ───────────────────────────────────────────────────────────────────────────────────────

/// A bound QUIC endpoint accepting exactly the pinned client certificate (mutual pinning — see the
/// module doc comment). One [`QuicServer`] is one session's listener: DESIGN.md §A10.32's
/// per-session certificate means a real host mints a fresh [`SessionCert`]/[`QuicServer`] per
/// incoming session, not one long-lived server for its whole lifetime (this mirrors the A7
/// `connect` envelope's per-session nature).
pub struct QuicServer {
    endpoint: Endpoint,
}

impl QuicServer {
    /// Binds a UDP socket at `addr` and configures TLS 1.3 with mutual fingerprint pinning:
    /// presents `cert`, and accepts only a client certificate whose fingerprint is
    /// `expected_client_fp`.
    pub fn bind(
        addr: SocketAddr,
        cert: &SessionCert,
        expected_client_fp: [u8; 32],
    ) -> Result<Self, QuicError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_verifier = Arc::new(PinnedClientCertVerifier {
            expected: expected_client_fp,
            provider: provider.clone(),
        });
        let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![cert.cert_der()], cert.key_der())?;
        server_crypto.alpn_protocols = vec![ALPN.to_vec()];

        let quic_server_crypto = QuicServerConfig::try_from(server_crypto)?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_crypto));

        let endpoint = Endpoint::server(server_config, addr)?;
        Ok(QuicServer { endpoint })
    }

    /// The bound local address — useful when `addr` was passed as `0.0.0.0:0`/`[::]:0` (an
    /// ephemeral port, as every test in this slice uses).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Accepts one incoming connection and its one control stream. A fingerprint mismatch in
    /// either direction (client rejects the server's cert, or this server's
    /// [`PinnedClientCertVerifier`] rejects the client's) surfaces here as
    /// [`QuicError::Connection`] — the handshake itself fails, so no control stream is ever
    /// opened for a mispinned peer.
    pub async fn accept(&self) -> Result<ControlStream, QuicError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(QuicError::EndpointClosed)?;
        let connection = incoming.await?;
        let (send, recv) = connection.accept_bi().await?;
        Ok(ControlStream {
            connection,
            send,
            recv,
        })
    }
}

// ── Client ───────────────────────────────────────────────────────────────────────────────────────

/// Connects to a [`QuicServer`] with mutual fingerprint pinning: presents `cert` as its own client
/// certificate, and accepts only a server certificate whose fingerprint is `server_fp`.
pub struct QuicClient;

impl QuicClient {
    /// Connects to `addr`, opens one bidirectional control stream, and returns it. `server_fp` is
    /// pinned against the server's presented certificate (a mismatch fails the handshake — see
    /// [`QuicServer::accept`]'s doc comment); `cert` is presented as this client's own identity
    /// for the server's [`PinnedClientCertVerifier`] to pin.
    pub async fn connect(
        addr: SocketAddr,
        server_fp: [u8; 32],
        cert: &SessionCert,
    ) -> Result<ControlStream, QuicError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_verifier = Arc::new(PinnedServerCertVerifier {
            expected: server_fp,
            provider: provider.clone(),
        });
        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(server_verifier)
            .with_client_auth_cert(vec![cert.cert_der()], cert.key_der())?;
        client_crypto.alpn_protocols = vec![ALPN.to_vec()];

        let quic_client_crypto = QuicClientConfig::try_from(client_crypto)?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client_crypto));

        let bind_addr: SocketAddr = if addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let endpoint = Endpoint::client(bind_addr)?;

        // "localhost" as the SNI/server-name value: matches the "localhost" SAN
        // `SessionCert::generate` bakes into every certificate (S19 precedent) — irrelevant to
        // the pinning decision itself (`PinnedServerCertVerifier` ignores `_server_name`
        // entirely), but rustls/quinn require *some* well-formed server name to be supplied.
        let connection = endpoint
            .connect_with(client_config, addr, "localhost")?
            .await?;
        let (send, recv) = connection.open_bi().await?;
        Ok(ControlStream {
            connection,
            send,
            recv,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[tokio::test]
    async fn mutual_pinning_handshake_and_control_stream_round_trip() {
        // Dropping the last `Connection` handle implicitly closes it (quinn's documented
        // behavior: equivalent to `close(0, b"")`), which can discard not-yet-acknowledged stream
        // data. So both sides here explicitly synchronize before either drops its `ControlStream`:
        // the client writes "ping" and only *then* reads (so the server is never waiting on data
        // that hasn't been sent yet); the server reads "ping" before writing "pong" (so it never
        // writes before the client is listening) and then reads once more, expecting the clean
        // EOF the client produces by finishing its send stream immediately after reading "pong" —
        // that EOF cannot arrive until the client has actually finished its read, which is the
        // synchronization this test needs before either side tears down its connection.
        let server_cert = SessionCert::generate().expect("server cert");
        let client_cert = SessionCert::generate().expect("client cert");

        let server = QuicServer::bind(localhost(0), &server_cert, client_cert.fingerprint())
            .expect("bind server");
        let addr = server.local_addr().expect("local_addr");

        let server_task = tokio::spawn(async move {
            let mut control = server.accept().await.expect("server accept");
            let ping = crate::framing::read_frame(&mut control.recv)
                .await
                .expect("server read")
                .expect("Some(frame)");
            assert_eq!(ping, b"ping");
            crate::framing::write_frame(&mut control.send, b"pong")
                .await
                .expect("server write");
            let eof = crate::framing::read_frame(&mut control.recv)
                .await
                .expect("server read after pong");
            assert!(eof.is_none(), "client must cleanly finish its send side");
        });

        let mut control = QuicClient::connect(addr, server_cert.fingerprint(), &client_cert)
            .await
            .expect("client connect");
        crate::framing::write_frame(&mut control.send, b"ping")
            .await
            .expect("client write");
        let reply = crate::framing::read_frame(&mut control.recv)
            .await
            .expect("client read")
            .expect("Some(frame)");
        assert_eq!(reply, b"pong");
        control.send.finish().expect("client finish send side");

        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn wrong_expected_server_fp_fails_the_handshake() {
        let server_cert = SessionCert::generate().expect("server cert");
        let client_cert = SessionCert::generate().expect("client cert");
        let wrong_fp = SessionCert::generate().expect("decoy cert").fingerprint();

        let server = QuicServer::bind(localhost(0), &server_cert, client_cert.fingerprint())
            .expect("bind server");
        let addr = server.local_addr().expect("local_addr");

        let server_task = tokio::spawn(async move {
            // The client's handshake fails before ever completing, so `accept` never returns a
            // connection; this task's only job is to not hang the test — a timeout races it.
            let _ = server.accept().await;
        });

        let result = QuicClient::connect(addr, wrong_fp, &client_cert).await;
        assert!(
            result.is_err(),
            "connecting with the wrong expected server fingerprint must fail"
        );

        server_task.abort();
    }

    #[tokio::test]
    async fn wrong_client_cert_is_rejected_by_the_server() {
        let server_cert = SessionCert::generate().expect("server cert");
        let expected_client_cert = SessionCert::generate().expect("expected client cert");
        let actual_client_cert = SessionCert::generate().expect("actual (wrong) client cert");

        let server = QuicServer::bind(
            localhost(0),
            &server_cert,
            expected_client_cert.fingerprint(),
        )
        .expect("bind server");
        let addr = server.local_addr().expect("local_addr");

        let server_task = tokio::spawn(async move { server.accept().await });

        // TLS 1.3's client-side "connected" view can complete before the server has finished
        // processing/rejecting the client's Certificate flight (the client validates the
        // server's Finished and may consider itself connected slightly ahead of the server's own
        // decision) — so `connect` returning `Ok` here is not itself proof of a bug. The property
        // this test actually needs — the server never treats a mispinned client certificate as
        // acceptable — is checked via `server_task` below; if the client's optimistic view did
        // race ahead, its connection must still close with an error shortly after.
        let client_result =
            QuicClient::connect(addr, server_cert.fingerprint(), &actual_client_cert).await;

        let server_result = server_task.await.expect("server task");
        assert!(
            server_result.is_err(),
            "the server must reject a client certificate that doesn't match the pinned fingerprint"
        );

        if let Ok(control) = client_result {
            let reason = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                control.connection.closed(),
            )
            .await
            .expect("connection must close (not hang) after a rejected client cert");
            assert!(
                !matches!(reason, quinn::ConnectionError::LocallyClosed),
                "connection must close due to the server's rejection, not a clean local close: \
                 {reason:?}"
            );
        }
    }
}
