//! [`SignalingError`] — every failure this module's functions can produce, spanning §A7 envelope
//! verification, `spindle_proto::signaling` payload decoding, subject validation, ICE, QUIC, and
//! NATS I/O. One flat enum (mirroring `spindle_core::envelope::EnvelopeError`'s own doc comment,
//! which expects downstream code to match on the specific rejection reason) so a caller — or a
//! test, per this crate's `assert_pinning_rejected` convention in `quic.rs` — can always tell
//! "this is a real §A7/§A5 rejection" apart from "this is a transport hiccup".

use std::fmt;

use spindle_core::envelope::EnvelopeError;
use spindle_core::fingerprint::FingerprintError;
use spindle_proto::artifacts::ProtoError;
use spindle_proto::signaling::{SignalingError as ProtoSignalingError, Transport};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignalingError {
    /// One of DESIGN.md §A7's receiver MUST-checks rejected the envelope: signature, `to_fp`,
    /// revocation, `sid` binding, `seq` monotonicity, clock skew, `kind`, or the version/alg_id
    /// floor, or the AEAD tag itself.
    #[error("envelope rejected: {0}")]
    Envelope(#[from] EnvelopeError),

    /// The envelope verified, but its plaintext was not a well-formed `OfferPayload`/
    /// `AnswerPayload`/`IcePayload` (`spindle_proto::signaling`'s own decode rules: length caps,
    /// unknown fields, bad enum discriminants, non-canonical CBOR).
    #[error("signaling payload decode failed: {0}")]
    Payload(#[from] ProtoSignalingError),

    /// `Envelope::from_canonical_bytes` itself failed, before any §A7 check could run.
    #[error("envelope decode failed: {0}")]
    EnvelopeDecode(#[from] ProtoError),

    /// A `from_fp`/`to_fp`-shaped field was not exactly 32 bytes.
    #[error("malformed fingerprint: {0}")]
    Fingerprint(#[from] FingerprintError),

    /// `Envelope.eph_pk` was absent where the offer/answer requires one.
    #[error("envelope is missing the required eph_pk field")]
    MissingEphPk,

    /// `Envelope.eph_pk` was present but not exactly 32 bytes (a valid X25519 public key length).
    #[error("eph_pk must be exactly 32 bytes, got {0}")]
    BadEphPk(usize),

    /// DESIGN.md §A6: NATS's own permission system does not verify that a request's reply-to
    /// subject actually belongs to its claimed sender — proved empirically against the live
    /// composed stack by `spikes/s2-signaling`'s RESULTS.md (Check 2). The host MUST check this
    /// itself, before trusting a decrypted offer's routing.
    #[error("reply subject missing or does not start with the required _INBOX_<from_fp>. prefix")]
    BadReplyPrefix,

    /// DESIGN.md §A6/§A10.36: the offer's **signed** `inbox` did not equal the NATS reply subject
    /// the transport reported. [`SignalingError::BadReplyPrefix`] is the cheap pre-crypto *shape*
    /// check (does this reply subject even belong to this sender?); this is the post-decryption
    /// *binding* check (is it the exact subject the sender signed?). Only the latter catches a
    /// broker swapping one validly-prefixed inbox of this sender's for another, which it can
    /// therefore only turn into a counted denial of service, never a silent redirect.
    #[error("offer's signed inbox does not match the NATS reply subject")]
    ReplyInboxMismatch,

    /// DESIGN.md §A6: nobody is subscribed to `host.<hfp>.connect` — NATS answers with a 503
    /// no-responders status message on the reply subject rather than silence, which is what makes
    /// "host is offline" *instant* instead of a timeout. `async_nats::Client::request` used to
    /// recognise this for us; §A10.36's explicitly-owned reply inbox means this crate must.
    #[error("host is offline: no responders on the connect subject")]
    HostOffline,

    /// A trickled ICE envelope's NATS subject did not name the `(host_fp, client_fp, sid,
    /// direction)` the caller expected. This is the subject-level twin of
    /// `EnvelopeError::SidMismatch`/`SidBoundToDifferentSender`: NATS subject scoping and the
    /// envelope's own `sid`/`from_fp` fields are two independent bindings (nothing in DESIGN.md
    /// §A7 says the envelope itself must agree with the subject it arrived on), so this module
    /// enforces the agreement explicitly rather than trusting either alone.
    #[error("subject {subject:?} does not match the expected session (host/client/sid/direction)")]
    SubjectMismatch { subject: String },

    /// A NATS subject failed to parse as `host.<h>.sess.<c>.<sid>.<c2h|h2c>` at all.
    #[error("malformed session subject {0:?}")]
    BadSubject(String),

    /// The injected [`crate::signaling::ConnectAuthorizer`] returned `Deny` for this offer's
    /// sender.
    #[error("connect offer denied: sender is not an authorized member")]
    Denied,

    /// The offer/answer declared a [`Transport`] this crate does not implement here — only
    /// `Transport::Quic` (the WebRTC data-channel path for browser peers is a separate,
    /// unscheduled slice; see this crate's `lib.rs` module doc comment's Scope section).
    #[error("unsupported transport {0:?} (this crate only implements Transport::Quic)")]
    UnsupportedTransport(Transport),

    /// The ICE agent reported connectivity checks failed/exhausted with no pair ever selected.
    #[error("ICE connectivity checks failed: connectivity checks exhausted with no pair selected")]
    IceFailed,

    /// A lower-level ICE-agent operation failed (constructing the agent, adding a local
    /// candidate, starting connectivity checks, handling a read/timeout).
    #[error("ICE agent error: {0}")]
    Ice(#[from] rtc_shared::error::Error),

    /// The offer/answer round trip, or ICE connectivity checks, did not complete before the
    /// caller-supplied timeout elapsed.
    #[error("{0} timed out")]
    Timeout(&'static str),

    /// The QUIC handshake/control-stream setup failed (`crate::quic::QuicError`, including a
    /// fingerprint-pinning rejection).
    #[error("QUIC error: {0}")]
    Quic(#[from] crate::quic::QuicError),

    /// A NATS publish/subscribe/request/flush call failed.
    #[error("NATS error: {0}")]
    Nats(String),

    /// A local socket/IO operation failed (binding the ICE UDP socket, reading its local
    /// address, converting it to a `std::net::UdpSocket` for quinn).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl SignalingError {
    /// A log-safe `Display` view of this error — see [`RedactedSignalingError`].
    ///
    /// Use this, never the plain `Display`, anywhere a `SignalingError` reaches a `tracing::`
    /// call. Five of this enum's variants can carry content the repo's redaction policy forbids
    /// logging (see this crate's `lib.rs` and `crates/spindle-core/tests/redaction_guard.rs` —
    /// that guard inspects binding names only and cannot see content reachable through an
    /// error's `Display`).
    pub fn redacted(&self) -> RedactedSignalingError<'_> {
        RedactedSignalingError(self)
    }
}

/// A `Display` wrapper that renders a [`SignalingError`] with every peer-controlled byte and
/// every untruncated identifier replaced by its shape.
///
/// Five of this enum's variants can reach peer-controlled bytes or an untruncated identifier;
/// every other variant's payload is a numeric bound, a `&'static str`, an [`EnvelopeError`]
/// (whose whole surface is constant text and integers), or — per the `Quic` bullets below — a
/// `quinn::ConnectionError` shape that never carries a peer byte at all, so the rest render
/// exactly as they always did. The test throughout is "does this carry peer-controlled bytes or
/// an untruncated identifier", not "is this a transport error": most of `quinn::ConnectionError`
/// is exactly that and still safe.
///
/// - [`SignalingError::EnvelopeDecode`] and [`SignalingError::Payload`] can reach
///   [`ProtoError::UnknownField`], a CBOR map key taken verbatim from the peer's bytes — deferred
///   to [`ProtoError::redacted`].
/// - [`SignalingError::SubjectMismatch`] and [`SignalingError::BadSubject`] carry a NATS session
///   subject, which spells out `host.<host_fp>.sess.<client_fp>.<sid>.<dir>` — two *untruncated*
///   fingerprints, exactly what `spindle_core::Fingerprint::redacted` exists to prevent.
/// - [`SignalingError::Quic`] wrapping `quinn::ConnectionError::ApplicationClosed` or
///   `::ConnectionClosed`: quinn-proto 0.11.17's `frame::ApplicationClose`/`ConnectionClose`
///   `Display` impls (`frame.rs:262-271`, `frame.rs:312-324`) write `String::from_utf8_lossy`
///   over a `reason: Bytes` the *peer* chose when it sent the CLOSE frame — the same
///   log-injection surface (arbitrary bytes, including newlines, straight into a
///   `tracing::warn!`) the other bullets above exist to close. `error_code` is a number the
///   protocol/peer picks from a known space, not free text, so it is rendered, not withheld.
/// - Every other `quinn::ConnectionError` — including `TransportError` — is left alone, but not
///   because it is unconditionally safe. `quinn_proto::TransportError::reason` is never built from
///   bytes the *peer* put on the wire — checked against every construction site in quinn-proto
///   0.11.17's `connection/`, `transport_parameters.rs`, and `frame.rs`; a peer's CONNECTION_CLOSE
///   frame, transport-type or application-type, decodes straight into
///   `ConnectionClosed`/`ApplicationClosed` (`connection/mod.rs:3875-3876`), never into
///   `TransportError`. But `crypto/rustls.rs:112` builds `reason` from this crate's *own*
///   `rustls::Error::General` text — which is exactly how `quic.rs`'s
///   `PinnedServerCertVerifier`/`PinnedClientCertVerifier` report a pinning mismatch, and that
///   text used to carry two untruncated 32-byte fingerprint digests, an "untruncated identifier"
///   by this wrapper's own stated criterion, not peer-controlled bytes. That hazard is fixed at
///   the source in `quic.rs`'s verifiers (both mismatch messages now format an 8-hex-character
///   prefix, never the full digest) rather than here, because a `TransportError::reason` is an
///   opaque `String` by the time it reaches this wrapper — there is no reliable way to pattern-match
///   a hex digest back out of an arbitrary reason string built from other `rustls::Error` variants
///   or future quinn-proto call sites. So `TransportError` is deliberately left rendering through
///   the `safe` arm below: the peer-controlled-bytes hazard never applied to it, and the
///   untruncated-identifier hazard is closed upstream, at the one place that can fix it for every
///   consumer at once (including `QuicError::Tls(#[from] rustls::Error)`, `quic.rs:79`, the
///   shorter path to the same `rustls::Error::General` text).
#[derive(Debug, Clone, Copy)]
pub struct RedactedSignalingError<'a>(&'a SignalingError);

impl fmt::Display for RedactedSignalingError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            SignalingError::EnvelopeDecode(e) => {
                write!(f, "envelope decode failed: {}", e.redacted())
            }
            SignalingError::Payload(ProtoSignalingError::Proto(e)) => {
                write!(f, "signaling payload decode failed: {}", e.redacted())
            }
            SignalingError::SubjectMismatch { subject } => write!(
                f,
                "subject (withheld: {} bytes naming host_fp/client_fp/sid) does not match the \
                 expected session (host/client/sid/direction)",
                subject.len()
            ),
            SignalingError::BadSubject(subject) => write!(
                f,
                "malformed session subject (withheld: {} bytes)",
                subject.len()
            ),
            // The peer picks these `reason` bytes when it sends the CLOSE frame
            // (quinn-proto 0.11.17 `frame.rs:262-271`/`312-324`'s `Display` impls write them via
            // `String::from_utf8_lossy`, untruncated) — the same log-injection surface as the
            // arms above. `error_code` is a number from a known space, not free text, so it is
            // rendered, not withheld.
            SignalingError::Quic(crate::quic::QuicError::Connection(
                quinn::ConnectionError::ApplicationClosed(close),
            )) => write!(
                f,
                "closed by peer: code {} (reason withheld: {} bytes of peer-supplied text)",
                close.error_code,
                close.reason.len()
            ),
            SignalingError::Quic(crate::quic::QuicError::Connection(
                quinn::ConnectionError::ConnectionClosed(close),
            )) => write!(
                f,
                "aborted by peer: code {} (reason withheld: {} bytes of peer-supplied text)",
                close.error_code,
                close.reason.len()
            ),
            safe => write!(f, "{safe}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two decode variants can reach a peer-supplied CBOR map key; the two subject variants
    /// spell out untruncated fingerprints. All four must be withheld by `redacted()`, and every
    /// other variant must survive it unchanged.
    #[test]
    fn redacted_display_withholds_peer_bytes_and_subjects_and_nothing_else() {
        let subject = "host.ABCDEFGH.sess.IJKLMNOP.0011.c2h";
        let leaky = [
            SignalingError::EnvelopeDecode(ProtoError::UnknownField("secret-key".into())),
            SignalingError::Payload(ProtoSignalingError::Proto(ProtoError::UnknownField(
                "secret-key".into(),
            ))),
            SignalingError::BadSubject(subject.to_string()),
            SignalingError::SubjectMismatch {
                subject: subject.to_string(),
            },
        ];
        for e in &leaky {
            let plain = e.to_string();
            let redacted = e.redacted().to_string();
            assert_ne!(plain, redacted, "{plain}");
            assert!(!redacted.contains("secret-key"), "{redacted}");
            assert!(!redacted.contains(subject), "{redacted}");
        }

        for safe in [
            SignalingError::Envelope(EnvelopeError::BadSignature),
            SignalingError::BadEphPk(17),
            SignalingError::Denied,
            SignalingError::Nats("connection reset".to_string()),
            SignalingError::Payload(ProtoSignalingError::TooLong {
                field: "ufrag",
                max: 8,
                actual: 9,
            }),
        ] {
            assert_eq!(safe.to_string(), safe.redacted().to_string());
        }
    }

    /// A peer picks the CLOSE frame's `reason` bytes (quinn-proto 0.11.17 `frame.rs:262-271`/
    /// `312-324`), so `redacted()` must withhold them from both `ConnectionError` shapes while
    /// still surfacing the numeric `error_code` for diagnosability.
    #[test]
    fn redacted_display_withholds_quic_close_reasons_but_keeps_the_code() {
        let reason = "attacker-controlled close reason\nwith a forged log line";

        let application_closed = SignalingError::Quic(crate::quic::QuicError::Connection(
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(42),
                reason: bytes::Bytes::from_static(reason.as_bytes()),
            }),
        ));
        let connection_closed = SignalingError::Quic(crate::quic::QuicError::Connection(
            quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::PROTOCOL_VIOLATION,
                frame_type: None,
                reason: bytes::Bytes::from_static(reason.as_bytes()),
            }),
        ));

        for e in [&application_closed, &connection_closed] {
            let plain = e.to_string();
            let redacted = e.redacted().to_string();
            assert_ne!(plain, redacted, "{plain}");
            assert!(!redacted.contains(reason), "{redacted}");
            assert!(!redacted.contains('\n'), "{redacted}");
        }

        assert!(application_closed.redacted().to_string().contains("42"));
        // `TransportErrorCode::PROTOCOL_VIOLATION`'s `Display` (quinn-proto's `errors!` macro in
        // `transport_error.rs`) writes this fixed description, never the peer-chosen value's raw
        // bits, so asserting on it also proves the code renders through a bounded lookup table
        // rather than free text.
        assert!(connection_closed
            .redacted()
            .to_string()
            .contains("protocol compliance"));
    }
}
