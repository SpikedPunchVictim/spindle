//! [`SignalingError`] — every failure this module's functions can produce, spanning §A7 envelope
//! verification, `spindle_proto::signaling` payload decoding, subject validation, ICE, QUIC, and
//! NATS I/O. One flat enum (mirroring `spindle_core::envelope::EnvelopeError`'s own doc comment,
//! which expects downstream code to match on the specific rejection reason) so a caller — or a
//! test, per this crate's `assert_pinning_rejected` convention in `quic.rs` — can always tell
//! "this is a real §A7/§A5 rejection" apart from "this is a transport hiccup".

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
