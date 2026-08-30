//! S2 leg A step A spike shared code (docs/SPIKES.md / docs/DESIGN.md §A13, §A6, §A7): the
//! crate-local signaling payload types (offer/answer/ice), ephemeral-key plumbing, and thin
//! seal/open wrappers around `spindle_core::envelope`. THROWAWAY, spike-quality by design — see
//! `spikes/s1-callout/src/lib.rs`'s module doc for the convention this repo follows for spikes;
//! see this crate's own `RESULTS.md` for what a real slice should keep vs. redo.
//!
//! # Why these payload types are crate-local, not `spindle_proto`
//! `IMPLEMENTATION_PLAN.md` Stage 5's newest Note: signaling payload shapes are spiked
//! crate-local first and only promoted into `spindle_proto` (with golden vectors + a TS twin)
//! once the shape is settled — a wire format is expensive to reverse, so it must not be frozen
//! ahead of evidence. `spindle_proto::artifacts::Envelope.kind` is a bare `u16` with no named
//! constants today; this crate picks its own spike-local constants
//! ([`KIND_OFFER`]/[`KIND_ANSWER`]/[`KIND_ICE`]) for the three payload kinds this step needs —
//! small, sequential, and distinct, matching the three roles §A6's flow diagram sketches
//! (`env{offer}` / `env{answer}` / `env{ice}`). Real values are for the eventual
//! `spindle_proto` promotion to settle, not this spike.
//!
//! # Encoding
//! Payload bodies are JSON (`serde_json`), not canonical CBOR — nothing outside this crate ever
//! decodes them, so there is no interop requirement to satisfy, and JSON keeps this spike's
//! plumbing minimal. The envelope itself (header, AEAD, signature — the thing actually under
//! test) is unaffected either way: `plaintext` is just whatever bytes a payload serializes to.
//!
//! # The A7 key-derivation bootstrap gap — read before using [`seal_payload`]
//! DESIGN.md §A7's formula `k = HKDF(eph_dh || dev_dh, ...)` presumes both peers' ephemeral
//! public keys are already known when `k` is derived — but §A6's flow has the client send the
//! *first* message (the offer) before it has ever seen the host's ephemeral key. There is no way
//! for the client to compute a "real" ephemeral-ephemeral shared secret at that point; DESIGN.md
//! does not spell out a bootstrap for this. See `RESULTS.md` for the finding. The interpretation
//! this spike follows (a deliberate, documented decision — not a silent assumption) is:
//!
//! - **offer** (message 1 of a session): `eph_dh = X25519(eph_c, host_device_static_pk)` —
//!   ephemeral(client)-static(host) ECDH, computable by the client immediately (it already needs
//!   to know the host's static device key out-of-band — see the "pre-shared device keys" note
//!   below) and reproduced by the host as `X25519(host_device_static_sk, eph_pk_c)`.
//! - **answer and every later message of the session**: `eph_dh = X25519(eph_c, eph_pk_h) =
//!   X25519(eph_h, eph_pk_c)` — the full ephemeral-ephemeral ECDH, once both sides know both
//!   ephemeral public keys.
//!
//! This means the offer and everything after it are, under this spike's reading, sealed under
//! two **different** derived session keys within the same `sid` — a genuine ambiguity this spike
//! surfaces rather than resolves (see RESULTS.md). Callers derive both keys themselves (via
//! [`spindle_core::derive_session_key`]) and pass whichever applies to a given call of
//! [`seal_payload`]/[`open_payload`].
//!
//! # Pre-shared device keys (registry/enrollment is out of scope for this step)
//! `spindle_proto::artifacts::DeviceCertificate` carries only a device's *fingerprint* (a hash),
//! never its raw Ed25519/X25519 public keys — there is no wire artifact today that hands a peer
//! the actual public keys behind a `device_fp`. A real deployment presumably resolves this via
//! member enrollment / a registry lookup, neither of which this step exercises (explicitly out
//! of scope — see the task brief's scope note). This spike's harness sidesteps the gap by simply
//! pre-sharing both sides' public keys directly in test setup, and flags the gap in RESULTS.md.

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use spindle_core::envelope::{self, EnvelopeError, OpenParams, SealParams, SessionKey};
use spindle_core::identity::DeviceKey;
use spindle_core::Fingerprint;
use spindle_proto::artifacts::Envelope;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// The client's SDP offer + the plaintext-covered restatement of its reply inbox (§A6:
/// `env{eph_pk_c, offer, inbox, ...}`). `offer` is a deliberately opaque placeholder — step B
/// (real ICE parameters) replaces it; this step only cares about the envelope/subject/scoping
/// mechanics around it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OfferPayload {
    pub offer: String,
    pub inbox: String,
}

/// The host's SDP answer (§A6: `env{eph_pk_h, answer, ...}`). Placeholder blob, see
/// [`OfferPayload`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnswerPayload {
    pub answer: String,
}

/// One trickled ICE candidate (§A6: `env{ice}`). Placeholder string, see [`OfferPayload`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IcePayload {
    pub candidate: String,
}

/// Spike-local `Envelope.kind` values (see module doc for why these live here, not in
/// `spindle_proto`).
pub const KIND_OFFER: u16 = 1;
pub const KIND_ANSWER: u16 = 2;
pub const KIND_ICE: u16 = 3;

/// The A7 envelope version/alg-id this spike pins throughout (matches `spindle-core`'s own test
/// fixtures and `ALG_ID_V1`).
pub const V1: u8 = 1;
pub const ALG_ID_V1: u8 = spindle_core::ALG_ID_V1;

#[derive(Debug, Error)]
pub enum PayloadError {
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
    #[error("payload JSON decode failed: {0}")]
    Decode(#[from] serde_json::Error),
}

/// Everything [`seal_payload`] needs except the plaintext itself — mirrors
/// `spindle_core::envelope::SealParams`, minus `plaintext`, which this function derives by
/// JSON-encoding `payload`.
pub struct SealPayloadParams<'a> {
    pub session_key: &'a SessionKey,
    /// The sender's device key — signs the envelope (DESIGN.md §A7: `dev_sign_from`).
    pub signer: &'a DeviceKey,
    pub v: u8,
    pub alg_id: u8,
    pub from_fp: Fingerprint,
    pub to_fp: Fingerprint,
    pub sid: Vec<u8>,
    pub kind: u16,
    pub seq: u64,
    pub ts: u64,
    pub eph_pk: Option<Vec<u8>>,
}

/// Seals `payload` (JSON-encoded) into a complete, signed `Envelope` via
/// `spindle_core::envelope::seal`. This is the crate's one seal entry point — callers never build
/// a `spindle_core::envelope::SealParams`/plaintext byte vector themselves.
pub fn seal_payload<T: Serialize>(params: SealPayloadParams<'_>, payload: &T) -> Envelope {
    let plaintext = serde_json::to_vec(payload).expect("spike payload types always serialize");
    envelope::seal(SealParams {
        session_key: params.session_key,
        signer: params.signer,
        v: params.v,
        alg_id: params.alg_id,
        from_fp: params.from_fp,
        to_fp: params.to_fp,
        sid: params.sid,
        kind: params.kind,
        seq: params.seq,
        ts: params.ts,
        eph_pk: params.eph_pk,
        plaintext: &plaintext,
    })
}

/// Runs every A7 "Receiver MUST" check via `spindle_core::envelope::open`, and if (and only if)
/// all pass, JSON-decodes the plaintext into `T`. `params` is passed straight through — see
/// `spindle_core::envelope::OpenParams`'s own docs for what each field means.
pub fn open_payload<T: for<'de> Deserialize<'de>>(
    params: OpenParams<'_>,
    env: &Envelope,
) -> Result<T, PayloadError> {
    let plaintext = envelope::open(params, env)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

/// A fresh ephemeral X25519 keypair for one connect handshake (`eph_pk_c` / `eph_pk_h` —
/// DESIGN.md §A6/§A7). Generated fresh per session; never reused.
pub struct EphemeralKey {
    secret: StaticSecret,
    pub public: X25519PublicKey,
}

impl EphemeralKey {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// `X25519(self, peer)` — used both for the message-1 ephemeral-static bootstrap DH and the
    /// full ephemeral-ephemeral DH from the answer onward (see module doc); which one a given
    /// call computes depends only on what `peer` is.
    pub fn diffie_hellman(&self, peer: &X25519PublicKey) -> [u8; 32] {
        *self.secret.diffie_hellman(peer).as_bytes()
    }

    pub fn public_bytes(&self) -> Vec<u8> {
        self.public.as_bytes().to_vec()
    }
}

/// Parses a 32-byte `eph_pk` wire field back into an `x25519_dalek::PublicKey`.
pub fn x25519_public_from_bytes(bytes: &[u8]) -> anyhow::Result<X25519PublicKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("eph_pk must be 32 bytes, got {}", bytes.len()))?;
    Ok(X25519PublicKey::from(arr))
}
