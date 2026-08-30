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
//! two **different** derived session keys within the same `sid`. **Step A treated this as an
//! open ambiguity; DESIGN.md v0.9.14 (2026-08-26) settled it as a deliberate two-key schedule —
//! implemented here, not improvised:**
//!
//! - **`k0` (offer only)**: `HKDF-SHA256(X25519(eph_c, dev_agree_h) || X25519(dev_agree_c,
//!   dev_agree_h), info = "spindle-sess-boot-v1" || sid || from_fp || to_fp)` — the
//!   ephemeral-static bootstrap above, now under its own domain-separated `info` label. See
//!   [`BOOT_KEY_INFO_DOMAIN`], [`derive_boot_key`], [`boot_seal_payload`], [`boot_open_payload`].
//! - **`k1` (answer and every message after it, both directions)**: `HKDF-SHA256(X25519(eph_self,
//!   eph_peer) || X25519(dev_self, dev_agree_peer), info = "spindle-sess-v1" || sid || from_fp ||
//!   to_fp)` — unchanged: exactly [`spindle_core::derive_session_key`]/[`seal_payload`]/
//!   [`open_payload`], used as-is.
//!
//! The two `info` labels are mandatory domain separation (a `kind = offer` envelope must never
//! decrypt under `k1`, nor vice versa) — never share one label between them. A receiver decrypts
//! `kind = offer` under `k0` via [`boot_open_payload`] and every other `kind` under `k1` via
//! [`open_payload`], never both against the same envelope.
//!
//! ## Why `k0` is a hand-rolled seal/open, not a `spindle_core::envelope::SessionKey`
//! `spindle_core::envelope::SessionKey` has no public raw-bytes constructor (its single field is
//! private; [`spindle_core::derive_session_key`] is the *only* way to produce one, and that
//! function's `info` domain — `SESSION_KEY_INFO_DOMAIN`, `"spindle-sess-v1"` — is a private
//! compile-time constant, not a parameter). There is therefore no way to obtain a second,
//! distinctly-labeled `SessionKey` through `spindle-core`'s public API at all, and this crate may
//! not edit `spindle-core` to add one. [`boot_seal_payload`]/[`boot_open_payload`] work around
//! this the only way available without editing spindle-core: they replicate
//! `spindle_core::envelope::seal`/`open`'s exact AEAD/nonce/signature construction against
//! `spindle_proto::artifacts::Envelope`'s public fields and public `header_canonical_bytes`/
//! `signing_input` methods (both already public, used identically), operating on a raw `[u8; 32]`
//! `k0` instead of an opaque `SessionKey`. Every A7 receiver MUST-check `open` performs is
//! reproduced in [`boot_open_payload`] (reusing `spindle_core::envelope::EnvelopeError`'s real
//! variants, not a shadow error type) — see RESULTS.md's "spindle-core API gap" finding, filed as
//! a promotion candidate for the real slice (e.g. a `derive_session_key_with_domain(domain: &[u8],
//! ...)` or a `SessionKey::from_raw([u8; 32])` constructor).
//!
//! # Pre-shared device keys (registry/enrollment is out of scope for this step)
//! `spindle_proto::artifacts::DeviceCertificate` carries only a device's *fingerprint* (a hash),
//! never its raw Ed25519/X25519 public keys — there is no wire artifact today that hands a peer
//! the actual public keys behind a `device_fp`. A real deployment presumably resolves this via
//! member enrollment / a registry lookup, neither of which this step exercises (explicitly out
//! of scope — see the task brief's scope note). This spike's harness sidesteps the gap by simply
//! pre-sharing both sides' public keys directly in test setup, and flags the gap in RESULTS.md.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use spindle_core::envelope::{self, EnvelopeError, OpenParams, SealParams, SessionKey};
use spindle_core::identity::DeviceKey;
use spindle_core::{direction_byte, Fingerprint};
use spindle_proto::artifacts::Envelope;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// The client's connect offer (§A6: `env{eph_pk_c, offer, inbox, ...}`). Step B (this crate's
/// `s2-connect` binary) replaces step A's opaque placeholder string with the real fields a QUIC/
/// ICE connect needs: the client's own ICE short-term credentials (`ufrag`/`pwd`, RFC 8445 §5.3 —
/// sent in the offer itself, never trickled, since connectivity checks cannot start without
/// them) and its per-session QUIC certificate fingerprint (`cert_fp`, DESIGN.md §A8's `a=
/// fingerprint` restatement for QUIC, A10.32) — candidates themselves are trickled separately as
/// `KIND_ICE` envelopes (see [`IcePayload`]), never embedded here. `transport` names the transport
/// this connect is negotiating (`"quic"` is the only value `s2-connect` ever sends; carried
/// explicitly, not assumed, since DESIGN.md §A6 anticipates transport negotiation being part of
/// this same envelope in a real implementation).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OfferPayload {
    pub inbox: String,
    pub transport: String,
    pub ufrag: String,
    pub pwd: String,
    /// `"sha256:<hex>"`, matching `spikes/s19-quic-transport`'s own on-wire fingerprint
    /// convention (`SignalMessage.cert_fp`) — kept identical so a reader comparing the two spikes
    /// sees the same shape, not an arbitrary reformatting.
    pub cert_fp: String,
}

/// The host's connect answer (§A6: `env{eph_pk_h, answer, ...}`). Mirrors [`OfferPayload`]'s new
/// fields exactly (the host's own ufrag/pwd/cert_fp) — same rationale, see that type's doc
/// comment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnswerPayload {
    pub transport: String,
    pub ufrag: String,
    pub pwd: String,
    pub cert_fp: String,
}

/// One trickled ICE message (§A6: `env{ice}`) — either a single SDP `a=candidate` line
/// (`rtc_ice::candidate::Candidate::marshal`) or, once a side has exhausted its local gathering,
/// an explicit end-of-candidates marker (RFC 8445 §8.2.7's "identifying the last candidate" idea,
/// restated at the payload level since this spike's transport carries one candidate per envelope
/// rather than SDP's own `a=end-of-candidates` line). Exactly one of the two is meaningful per
/// envelope: `candidate: Some(_)` with `end_of_candidates: false` for a real trickled candidate,
/// or `candidate: None` with `end_of_candidates: true` for the marker — never both, never
/// neither; `s2-connect` never constructs the other two combinations, but the receiver does not
/// assume it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IcePayload {
    pub candidate: Option<String>,
    #[serde(default)]
    pub end_of_candidates: bool,
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

// ================================================================================================
// DESIGN.md v0.9.14's two-key schedule: k0 (offer only), hand-rolled — see the module doc's "Why
// k0 is a hand-rolled seal/open" section for why this cannot simply call
// `spindle_core::derive_session_key`/`envelope::{seal,open}`.
// ================================================================================================

/// KDF `info` domain for `k0`, the offer-only bootstrap key (DESIGN.md v0.9.14, 2026-08-26).
/// Deliberately distinct from `spindle_core::envelope::SESSION_KEY_INFO_DOMAIN`
/// (`"spindle-sess-v1"`, used for `k1`) — mandatory domain separation so a `kind = offer`
/// envelope's ciphertext can never be reinterpreted (decrypted or, for an attacker, replayed)
/// under `k1`, and vice versa.
pub const BOOT_KEY_INFO_DOMAIN: &[u8] = b"spindle-sess-boot-v1";

/// `k0 = HKDF-SHA256(eph_dh || dev_dh, info = BOOT_KEY_INFO_DOMAIN || sid || from_fp || to_fp)`.
/// Identical construction to `spindle_core::envelope::derive_session_key` (same `ikm` layout,
/// same HKDF-SHA256 call, same `info` suffix shape) with only the domain literal swapped — see the
/// module doc comment for why this cannot be produced by calling that function directly. Returns
/// a raw key, not a `spindle_core::envelope::SessionKey` (which cannot be constructed from raw
/// bytes outside `spindle-core`); [`boot_seal_payload`]/[`boot_open_payload`] consume it directly.
pub fn derive_boot_key(
    eph_dh: &[u8; 32],
    dev_dh: &[u8; 32],
    sid: &[u8],
    from_fp: &Fingerprint,
    to_fp: &Fingerprint,
) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(eph_dh);
    ikm[32..].copy_from_slice(dev_dh);

    let mut info = Vec::with_capacity(BOOT_KEY_INFO_DOMAIN.len() + sid.len() + 64);
    info.extend_from_slice(BOOT_KEY_INFO_DOMAIN);
    info.extend_from_slice(sid);
    info.extend_from_slice(from_fp.as_bytes());
    info.extend_from_slice(to_fp.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("HKDF-SHA256 output length 32 is always valid");
    okm
}

/// `direction(1) || seq(11)` nonce construction (DESIGN.md §A7) — byte-for-byte the same
/// construction as `spindle_core::envelope`'s own (private) `build_nonce`, reproduced here since
/// it isn't exported. `direction` comes from the public `spindle_core::direction_byte`.
fn boot_nonce(direction: u8, seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = direction;
    nonce[4..12].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// Everything [`boot_seal_payload`] needs except the plaintext itself — the `k0` twin of
/// [`SealPayloadParams`] (same fields, `boot_key: &[u8; 32]` in place of `session_key:
/// &SessionKey`).
pub struct BootSealPayloadParams<'a> {
    pub boot_key: &'a [u8; 32],
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

/// Seals `payload` (JSON-encoded) under `k0`, replicating `spindle_core::envelope::seal`'s exact
/// AEAD (AES-256-GCM, nonce = `direction || seq`, AAD = canonical header) and signature
/// (`Envelope::signing_input`, already public) construction — see the module doc comment for why
/// this cannot simply call that function. Used for `KIND_OFFER` only.
pub fn boot_seal_payload<T: Serialize>(params: BootSealPayloadParams<'_>, payload: &T) -> Envelope {
    let plaintext = serde_json::to_vec(payload).expect("spike payload types always serialize");
    let direction = direction_byte(&params.from_fp, &params.to_fp);
    let nonce_bytes = boot_nonce(direction, params.seq);

    let mut env = Envelope {
        v: params.v,
        alg_id: params.alg_id,
        from_fp: params.from_fp.to_vec(),
        to_fp: params.to_fp.to_vec(),
        sid: params.sid,
        kind: params.kind,
        seq: params.seq,
        ts: params.ts,
        eph_pk: params.eph_pk,
        ciphertext: Vec::new(),
        sig: Vec::new(),
    };
    let aad = env.header_canonical_bytes();

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(params.boot_key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .expect("AES-256-GCM encryption cannot fail for well-formed 32-byte keys/12-byte nonces");
    env.ciphertext = ciphertext;

    let sig = params.signer.sign(&env.signing_input());
    env.sig = sig.to_bytes().to_vec();
    env
}

/// Everything [`boot_open_payload`] needs to run the A7 receiver MUST-checks that apply to a
/// first-of-session offer — the `k0` twin of the subset of [`OpenParams`] that matters for
/// `KIND_OFFER` (no `bound_from_fp`/`min_seq_exclusive`/`sender_revoked`: an offer is always the
/// first envelope of a fresh `sid`, so those don't yet apply — exactly the fields step A's own
/// `handle_connect` already left at `None`/`false` for this same message).
pub struct BootOpenPayloadParams<'a> {
    pub boot_key: &'a [u8; 32],
    pub pinned_sender_key: &'a VerifyingKey,
    pub self_fp: &'a Fingerprint,
    pub expected_sid: &'a [u8],
    pub now: u64,
    pub min_v: u8,
    pub min_alg_id: u8,
    pub expected_kind: u16,
}

/// Opens (verifies + decrypts) an offer envelope under `k0`. Reproduces every A7 receiver
/// MUST-check that applies to a first-of-session offer, in the same order
/// `spindle_core::envelope::open` runs them, reusing that module's real `EnvelopeError` variants
/// (via [`PayloadError::Envelope`]) rather than a shadow error type — see the module doc comment
/// for why this function exists instead of calling `envelope::open` directly.
pub fn boot_open_payload<T: for<'de> Deserialize<'de>>(
    params: BootOpenPayloadParams<'_>,
    env: &Envelope,
) -> Result<T, PayloadError> {
    if env.v < params.min_v {
        return Err(EnvelopeError::VersionTooLow {
            actual: env.v,
            minimum: params.min_v,
        }
        .into());
    }
    if env.alg_id < params.min_alg_id {
        return Err(EnvelopeError::AlgIdTooLow {
            actual: env.alg_id,
            minimum: params.min_alg_id,
        }
        .into());
    }

    let sig_bytes: [u8; 64] = env
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| EnvelopeError::InvalidSignatureEncoding)?;
    let sig = Signature::from_bytes(&sig_bytes);
    params
        .pinned_sender_key
        .verify(&env.signing_input(), &sig)
        .map_err(|_| EnvelopeError::BadSignature)?;

    if !params.self_fp.matches(&env.to_fp) {
        return Err(EnvelopeError::WrongRecipient.into());
    }
    if env.sid != params.expected_sid {
        return Err(EnvelopeError::SidMismatch.into());
    }
    let skew = params.now.abs_diff(env.ts);
    if skew > envelope::CLOCK_SKEW_SECS {
        return Err(EnvelopeError::ClockSkew.into());
    }
    if env.kind != params.expected_kind {
        return Err(EnvelopeError::KindMismatch.into());
    }

    let from_fp =
        Fingerprint::from_slice(&env.from_fp).map_err(EnvelopeError::InvalidFingerprint)?;
    let to_fp = Fingerprint::from_slice(&env.to_fp).map_err(EnvelopeError::InvalidFingerprint)?;
    let direction = direction_byte(&from_fp, &to_fp);
    let nonce_bytes = boot_nonce(direction, env.seq);
    let aad = env.header_canonical_bytes();

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(params.boot_key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &env.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| EnvelopeError::DecryptFailed)?;
    Ok(serde_json::from_slice(&plaintext)?)
}
