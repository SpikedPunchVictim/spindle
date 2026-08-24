//! The A7 end-to-end signaling envelope (DESIGN.md §A7, ADR-004): session-key derivation,
//! `seal`/`open`, and every receiver MUST-check.
//!
//! ```text
//! Envelope { v, alg_id, from_fp, to_fp, sid, kind, seq, ts, eph_pk?, ciphertext, sig }
//! Session key:  k = HKDF-SHA256(X25519(eph_self, eph_peer) || X25519(dev_self, dev_agree_peer),
//!                               info = "spindle-sess-v1" || sid || from_fp || to_fp)
//! AEAD:         AES-256-GCM, nonce = direction(1) || seq(11); AAD = canonical header
//! sig:          Ed25519(dev_sign_from, "spindle-env-v1" || canonical(header) || ciphertext)
//! ```
//!
//! **Session-role convention (not spelled out verbatim in DESIGN.md, documented here as the
//! interpretation this crate follows)**: the `from_fp`/`to_fp` fed into the session-key `info`
//! are the *session's* fixed roles (conventionally the connecting client's `device_fp` as
//! `from_fp` and the host's `device_fp` as `to_fp`), established once when the session is
//! created — **not** the per-message `Envelope.from_fp`/`to_fp` fields, which flip depending on
//! which side is currently sending. Both peers must call [`derive_session_key`] with the *same*
//! `(from_fp, to_fp)` pair regardless of which of them is sealing or opening a given message, or
//! they will derive different keys. This is necessary because a session has one symmetric key `k`
//! used in both directions (only the AEAD nonce's `direction` bit differs per A7), so the KDF
//! input cannot depend on per-message sender/receiver.

use crate::fingerprint::Fingerprint;
use crate::identity::DeviceKey;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use spindle_proto::artifacts::Envelope;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// KDF `info` domain prefix (DESIGN.md §A7).
pub const SESSION_KEY_INFO_DOMAIN: &[u8] = b"spindle-sess-v1";

/// `|ts - now| <= 2 min` (DESIGN.md §A7b).
pub const CLOCK_SKEW_SECS: u64 = 120;

/// The 32-byte AES-256-GCM session key derived per A7. Owns raw secret bytes directly (unlike
/// [`crate::identity::RootKey`]/[`crate::identity::DeviceKey`], which delegate zeroization to
/// `ed25519-dalek`/`x25519-dalek`'s own secret types), so it derives `Zeroize`/`ZeroizeOnDrop`
/// itself.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `k = HKDF-SHA256(eph_dh || dev_dh, info = "spindle-sess-v1" || sid || from_fp || to_fp)`
/// (DESIGN.md §A7). `eph_dh`/`dev_dh` are the two X25519 shared secrets (ephemeral-ephemeral and
/// device-device); see the module docs for the `from_fp`/`to_fp` session-role convention.
pub fn derive_session_key(
    eph_dh: &[u8; 32],
    dev_dh: &[u8; 32],
    sid: &[u8],
    from_fp: &Fingerprint,
    to_fp: &Fingerprint,
) -> SessionKey {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(eph_dh);
    ikm[32..].copy_from_slice(dev_dh);

    let mut info = Vec::with_capacity(SESSION_KEY_INFO_DOMAIN.len() + sid.len() + 64);
    info.extend_from_slice(SESSION_KEY_INFO_DOMAIN);
    info.extend_from_slice(sid);
    info.extend_from_slice(from_fp.as_bytes());
    info.extend_from_slice(to_fp.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("HKDF-SHA256 output length 32 is always valid");
    ikm.zeroize();
    SessionKey(okm)
}

/// `direction(1) || seq(11)` nonce construction (DESIGN.md §A7). `direction` is derived from the
/// ordered `(from_fp, to_fp)` pair of the *envelope being sealed/opened* so both peers compute
/// the same value for a given message, and the two directions of one session always occupy
/// disjoint nonce spaces (nonce reuse is structurally impossible as long as `seq` is enforced
/// monotonic per direction — see [`open`]'s replay check).
pub fn direction_byte(from_fp: &Fingerprint, to_fp: &Fingerprint) -> u8 {
    if from_fp.as_bytes() < to_fp.as_bytes() {
        0
    } else {
        1
    }
}

fn build_nonce(direction: u8, seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = direction;
    nonce[4..12].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// Every distinct failure an [`open`] receiver MUST-check can produce (DESIGN.md §A7). Each
/// variant corresponds to exactly one MUST-check, so a negative test can isolate it.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("signature invalid under the pinned key for from_fp")]
    BadSignature,
    #[error("envelope version {actual} is below the pinned minimum {minimum}")]
    VersionTooLow { actual: u8, minimum: u8 },
    #[error("envelope alg_id {actual} is below the pinned minimum {minimum}")]
    AlgIdTooLow { actual: u8, minimum: u8 },
    #[error("to_fp does not match this device (self)")]
    WrongRecipient,
    #[error("sender is not active / has been revoked")]
    SenderRevoked,
    #[error("sid does not match the session this envelope was opened against")]
    SidMismatch,
    #[error("sid is bound to a different from_fp than this envelope carries")]
    SidBoundToDifferentSender,
    #[error("seq is not strictly increasing for (sid, direction)")]
    ReplaySeq,
    #[error("|ts - now| exceeds the allowed clock-skew window")]
    ClockSkew,
    #[error("kind does not match the expected subject")]
    KindMismatch,
    #[error("AEAD decryption failed")]
    DecryptFailed,
    #[error("malformed signature encoding (expected 64 bytes)")]
    InvalidSignatureEncoding,
    #[error("malformed fingerprint encoding in envelope field")]
    InvalidFingerprint(#[from] crate::fingerprint::FingerprintError),
}

/// Inputs to [`seal`].
pub struct SealParams<'a> {
    pub session_key: &'a SessionKey,
    /// The sender's device key — signs the envelope (`dev_sign_from` in DESIGN.md §A7).
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
    pub plaintext: &'a [u8],
}

/// Seals `plaintext` into a complete, signed `spindle_proto::artifacts::Envelope` (DESIGN.md
/// §A7): encrypts under AES-256-GCM with AAD = canonical header, then signs
/// `"spindle-env-v1" || canonical(header) || ciphertext` with the sender's device key.
pub fn seal(params: SealParams<'_>) -> Envelope {
    let direction = direction_byte(&params.from_fp, &params.to_fp);
    let nonce_bytes = build_nonce(direction, params.seq);

    // Header fields never depend on `ciphertext`/`sig`, so `header_canonical_bytes()` below is
    // correct even though `ciphertext` is still an empty placeholder at this point.
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

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(params.session_key.as_bytes()));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: params.plaintext,
                aad: &aad,
            },
        )
        .expect("AES-256-GCM encryption cannot fail for well-formed 32-byte keys/12-byte nonces");
    env.ciphertext = ciphertext;

    let sig = params.signer.sign(&env.signing_input());
    env.sig = sig.to_bytes().to_vec();
    env
}

/// Inputs to [`open`]. Every field corresponds to one of A7's receiver MUST-checks; callers own
/// the durable state a real deployment needs (pinned keys, revocation sets, per-`(sid,
/// direction)` replay windows) and resolve it into these plain values before calling.
pub struct OpenParams<'a> {
    pub session_key: &'a SessionKey,
    /// The pinned public key for `from_fp` (or, for an invite redemption, the key carried in the
    /// device certificate chained to a root — DESIGN.md §A7). Resolved by the caller.
    pub pinned_sender_key: &'a VerifyingKey,
    pub self_fp: &'a Fingerprint,
    /// The sid this envelope is expected to belong to (bound to the subject it arrived on, at a
    /// layer above spindle-core which knows NATS subjects).
    pub expected_sid: &'a [u8],
    /// `Some(fp)` once this sid has been bound to a sender on a prior envelope; `None` for the
    /// first envelope of a session.
    pub bound_from_fp: Option<&'a Fingerprint>,
    /// The highest `seq` already accepted for this `(sid, direction)`; the incoming envelope's
    /// `seq` must be strictly greater. `None` for the first envelope of this direction.
    pub min_seq_exclusive: Option<u64>,
    pub now: u64,
    pub min_v: u8,
    pub min_alg_id: u8,
    pub expected_kind: u16,
    /// Caller-resolved: true if `from_fp` is revoked / not an active sender.
    pub sender_revoked: bool,
}

/// Verifies every A7 receiver MUST-check and, only if all pass, decrypts and returns the
/// plaintext. Any single failure is reported as a distinct [`EnvelopeError`] variant and the
/// envelope must be dropped (never given a distinguishable reply — DESIGN.md §A5/§A7).
pub fn open(params: OpenParams<'_>, env: &Envelope) -> Result<Vec<u8>, EnvelopeError> {
    if env.v < params.min_v {
        return Err(EnvelopeError::VersionTooLow {
            actual: env.v,
            minimum: params.min_v,
        });
    }
    if env.alg_id < params.min_alg_id {
        return Err(EnvelopeError::AlgIdTooLow {
            actual: env.alg_id,
            minimum: params.min_alg_id,
        });
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
        return Err(EnvelopeError::WrongRecipient);
    }
    if params.sender_revoked {
        return Err(EnvelopeError::SenderRevoked);
    }
    if env.sid != params.expected_sid {
        return Err(EnvelopeError::SidMismatch);
    }
    if let Some(bound_fp) = params.bound_from_fp {
        if !bound_fp.matches(&env.from_fp) {
            return Err(EnvelopeError::SidBoundToDifferentSender);
        }
    }
    if let Some(min_seq) = params.min_seq_exclusive {
        if env.seq <= min_seq {
            return Err(EnvelopeError::ReplaySeq);
        }
    }
    let skew = params.now.abs_diff(env.ts);
    if skew > CLOCK_SKEW_SECS {
        return Err(EnvelopeError::ClockSkew);
    }
    if env.kind != params.expected_kind {
        return Err(EnvelopeError::KindMismatch);
    }

    let from_fp = Fingerprint::from_slice(&env.from_fp)?;
    let to_fp = Fingerprint::from_slice(&env.to_fp)?;
    let direction = direction_byte(&from_fp, &to_fp);
    let nonce_bytes = build_nonce(direction, env.seq);
    let aad = env.header_canonical_bytes();

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(params.session_key.as_bytes()));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &env.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| EnvelopeError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceKey;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    struct Fixture {
        dev_a: DeviceKey, // client role: from_fp in session-key info
        dev_b: DeviceKey, // host role: to_fp in session-key info
        dev_a_pk: VerifyingKey,
        dev_b_pk: VerifyingKey,
        dev_a_fp: Fingerprint,
        dev_b_fp: Fingerprint,
        sid: Vec<u8>,
        session_key: SessionKey,
    }

    fn build_fixture() -> Fixture {
        let dev_a = DeviceKey::from_seeds([0x10; 32], [0x11; 32]);
        let dev_b = DeviceKey::from_seeds([0x20; 32], [0x21; 32]);

        let eph_a = StaticSecret::from([0x30; 32]);
        let eph_b = StaticSecret::from([0x40; 32]);
        let eph_b_pk = X25519PublicKey::from(&eph_b);
        let eph_dh = *eph_a.diffie_hellman(&eph_b_pk).as_bytes();

        let dev_dh = dev_a.diffie_hellman(&dev_b.agree_public_key());

        let dev_a_fp = dev_a.device_fp();
        let dev_b_fp = dev_b.device_fp();
        let sid = vec![0x99; 16];
        let session_key = derive_session_key(&eph_dh, &dev_dh, &sid, &dev_a_fp, &dev_b_fp);

        Fixture {
            dev_a_pk: dev_a.sign_public_key(),
            dev_b_pk: dev_b.sign_public_key(),
            dev_a,
            dev_b,
            dev_a_fp,
            dev_b_fp,
            sid,
            session_key,
        }
    }

    fn seal_a_to_b(fx: &Fixture, seq: u64, ts: u64) -> Envelope {
        seal(SealParams {
            session_key: &fx.session_key,
            signer: &fx.dev_a,
            v: 1,
            alg_id: 1,
            from_fp: fx.dev_a_fp,
            to_fp: fx.dev_b_fp,
            sid: fx.sid.clone(),
            kind: 7,
            seq,
            ts,
            eph_pk: None,
            plaintext: b"hello host",
        })
    }

    fn base_open_params(fx: &Fixture, now: u64) -> OpenParams<'_> {
        OpenParams {
            session_key: &fx.session_key,
            pinned_sender_key: &fx.dev_a_pk,
            self_fp: &fx.dev_b_fp,
            expected_sid: &fx.sid,
            bound_from_fp: None,
            min_seq_exclusive: None,
            now,
            min_v: 1,
            min_alg_id: 1,
            expected_kind: 7,
            sender_revoked: false,
        }
    }

    #[test]
    fn round_trip_seal_then_open() {
        let fx = build_fixture();
        let env = seal_a_to_b(&fx, 0, 1_000);
        let opened = open(base_open_params(&fx, 1_000), &env).expect("valid envelope opens");
        assert_eq!(opened, b"hello host");
    }

    #[test]
    fn bidirectional_session_nonces_never_collide() {
        let fx = build_fixture();

        // A -> B (direction_byte(A,B))
        let env_ab = seal_a_to_b(&fx, 0, 1_000);
        let plaintext_ab = open(base_open_params(&fx, 1_000), &env_ab).expect("A->B opens");
        assert_eq!(plaintext_ab, b"hello host");

        // B -> A (direction_byte(B,A) — must differ from direction_byte(A,B))
        let env_ba = seal(SealParams {
            session_key: &fx.session_key,
            signer: &fx.dev_b,
            v: 1,
            alg_id: 1,
            from_fp: fx.dev_b.device_fp(),
            to_fp: fx.dev_a.device_fp(),
            sid: fx.sid.clone(),
            kind: 8,
            seq: 0,
            ts: 1_001,
            eph_pk: None,
            plaintext: b"hello client",
        });
        assert_ne!(
            direction_byte(&fx.dev_a.device_fp(), &fx.dev_b.device_fp()),
            direction_byte(&fx.dev_b.device_fp(), &fx.dev_a.device_fp()),
            "the two message directions of one session must occupy disjoint nonce spaces"
        );
        let open_params_ba = OpenParams {
            session_key: &fx.session_key,
            pinned_sender_key: &fx.dev_b_pk,
            self_fp: &fx.dev_a_fp,
            expected_sid: &fx.sid,
            bound_from_fp: None,
            min_seq_exclusive: None,
            now: 1_001,
            min_v: 1,
            min_alg_id: 1,
            expected_kind: 8,
            sender_revoked: false,
        };
        let plaintext_ba = open(open_params_ba, &env_ba).expect("B->A opens");
        assert_eq!(plaintext_ba, b"hello client");

        // A second A->B message at seq=1 must still decrypt correctly (distinct nonce from the
        // first A->B message and from either B->A message).
        let env_ab2 = seal_a_to_b(&fx, 1, 1_002);
        let mut p = base_open_params(&fx, 1_002);
        p.min_seq_exclusive = Some(0);
        let opened2 = open(p, &env_ab2).expect("second A->B opens");
        assert_eq!(opened2, b"hello host");
    }

    // ---- Negative tests: one per A7 MUST-check ----

    #[test]
    fn rejects_bad_signature() {
        let fx = build_fixture();
        let mut env = seal_a_to_b(&fx, 0, 1_000);
        env.sig[0] ^= 0xff;
        let err = open(base_open_params(&fx, 1_000), &env).unwrap_err();
        assert_eq!(err, EnvelopeError::BadSignature);
    }

    #[test]
    fn rejects_version_below_pinned_minimum() {
        let fx = build_fixture();
        let env = seal_a_to_b(&fx, 0, 1_000);
        let mut params = base_open_params(&fx, 1_000);
        params.min_v = 2;
        let err = open(params, &env).unwrap_err();
        assert_eq!(
            err,
            EnvelopeError::VersionTooLow {
                actual: 1,
                minimum: 2
            }
        );
    }

    #[test]
    fn rejects_alg_id_below_pinned_minimum() {
        let fx = build_fixture();
        let env = seal_a_to_b(&fx, 0, 1_000);
        let mut params = base_open_params(&fx, 1_000);
        params.min_alg_id = 2;
        let err = open(params, &env).unwrap_err();
        assert_eq!(
            err,
            EnvelopeError::AlgIdTooLow {
                actual: 1,
                minimum: 2
            }
        );
    }

    #[test]
    fn rejects_wrong_recipient() {
        let fx = build_fixture();
        let env = seal_a_to_b(&fx, 0, 1_000);
        let other = DeviceKey::from_seeds([0x50; 32], [0x51; 32]);
        let mut params = base_open_params(&fx, 1_000);
        let other_fp = other.device_fp();
        params.self_fp = &other_fp;
        let err = open(params, &env).unwrap_err();
        assert_eq!(err, EnvelopeError::WrongRecipient);
    }

    #[test]
    fn rejects_revoked_sender() {
        let fx = build_fixture();
        let env = seal_a_to_b(&fx, 0, 1_000);
        let mut params = base_open_params(&fx, 1_000);
        params.sender_revoked = true;
        let err = open(params, &env).unwrap_err();
        assert_eq!(err, EnvelopeError::SenderRevoked);
    }

    #[test]
    fn rejects_sid_mismatch() {
        let fx = build_fixture();
        let env = seal_a_to_b(&fx, 0, 1_000);
        let mut params = base_open_params(&fx, 1_000);
        let wrong_sid = vec![0xEE; 16];
        params.expected_sid = &wrong_sid;
        let err = open(params, &env).unwrap_err();
        assert_eq!(err, EnvelopeError::SidMismatch);
    }

    #[test]
    fn rejects_sid_bound_to_different_sender() {
        let fx = build_fixture();
        let env = seal_a_to_b(&fx, 0, 1_000);
        let impostor = DeviceKey::from_seeds([0x60; 32], [0x61; 32]);
        let mut params = base_open_params(&fx, 1_000);
        let impostor_fp = impostor.device_fp();
        params.bound_from_fp = Some(&impostor_fp);
        let err = open(params, &env).unwrap_err();
        assert_eq!(err, EnvelopeError::SidBoundToDifferentSender);
    }

    #[test]
    fn rejects_non_monotonic_seq() {
        let fx = build_fixture();
        let env = seal_a_to_b(&fx, 5, 1_000);
        let mut params = base_open_params(&fx, 1_000);
        params.min_seq_exclusive = Some(5); // seq must be > 5, envelope carries 5
        let err = open(params, &env).unwrap_err();
        assert_eq!(err, EnvelopeError::ReplaySeq);
    }

    #[test]
    fn rejects_clock_skew() {
        let fx = build_fixture();
        let env = seal_a_to_b(&fx, 0, 1_000);
        let params = base_open_params(&fx, 1_000 + CLOCK_SKEW_SECS + 1);
        let err = open(params, &env).unwrap_err();
        assert_eq!(err, EnvelopeError::ClockSkew);
    }

    #[test]
    fn rejects_kind_mismatch() {
        let fx = build_fixture();
        let env = seal_a_to_b(&fx, 0, 1_000);
        let mut params = base_open_params(&fx, 1_000);
        params.expected_kind = 9;
        let err = open(params, &env).unwrap_err();
        assert_eq!(err, EnvelopeError::KindMismatch);
    }

    #[test]
    fn rejects_tampered_ciphertext_as_decrypt_failure() {
        // A tampered ciphertext byte breaks the AEAD tag but does *not* change the signed
        // header, so it slips past the signature check on `header_canonical_bytes()`... except
        // the signature covers the ciphertext too (A7: "sig covers the canonical header AND the
        // ciphertext"), so in practice tampering the ciphertext is caught as a bad signature
        // first. This test instead tampers the session key on the receive side to exercise the
        // AEAD-failure path directly (e.g. a stale/incorrect key), which the signature check
        // cannot catch because it doesn't depend on the AEAD key at all.
        let fx = build_fixture();
        let env = seal_a_to_b(&fx, 0, 1_000);
        let wrong_key = SessionKey([0xAAu8; 32]);
        let mut params = base_open_params(&fx, 1_000);
        params.session_key = &wrong_key;
        let err = open(params, &env).unwrap_err();
        assert_eq!(err, EnvelopeError::DecryptFailed);
    }

    #[test]
    fn tampering_ciphertext_after_signing_breaks_signature_check() {
        // Documents the interaction above: because `sig` covers the ciphertext, any ciphertext
        // tamper is caught as `BadSignature`, not `DecryptFailed`.
        let fx = build_fixture();
        let mut env = seal_a_to_b(&fx, 0, 1_000);
        env.ciphertext[0] ^= 0xff;
        let err = open(base_open_params(&fx, 1_000), &env).unwrap_err();
        assert_eq!(err, EnvelopeError::BadSignature);
    }

    #[test]
    fn first_message_of_session_has_no_seq_floor() {
        let fx = build_fixture();
        let env = seal_a_to_b(&fx, 0, 1_000);
        let params = base_open_params(&fx, 1_000); // min_seq_exclusive: None
        assert!(open(params, &env).is_ok());
    }
}
