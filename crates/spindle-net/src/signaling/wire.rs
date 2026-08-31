//! Pure offer/answer/ICE envelope construction and verification (DESIGN.md §A6/§A7's two-key
//! schedule): every function here takes plain values in, returns plain values (or a
//! [`SignalingError`]) out, and touches no NATS, ICE, or QUIC. Kept separate from
//! [`super::client`]/[`super::host`] (which perform the actual network I/O) so every §A7 receiver
//! MUST-check this crate is responsible for is unit-testable without a live NATS connection: seal
//! a fixture envelope, open it back, and assert on the exact [`SignalingError`] variant a tampered
//! input produces — never a bare `is_err()` (this crate's own testing convention; see `quic.rs`'s
//! `assert_pinning_rejected` precedent and its "why" comment).
//!
//! Uses [`spindle_core::envelope::{seal, open}`] and [`spindle_proto::signaling`]'s promoted wire
//! types directly — no crate-local payload structs, no local crypto (unlike
//! `spikes/s2-signaling/src/lib.rs`'s hand-rolled `boot_seal_payload`/`boot_open_payload`, which
//! existed only because `spindle-core` had no public way to derive a session key under a
//! non-default `info` domain at spike time; `derive_bootstrap_key`/`derive_session_key` now both
//! exist on `spindle_core::envelope` directly, so `k0` needs no reimplementation here at all — see
//! this slice's report for the promotion this resolves).

use rand::rngs::OsRng;
use rand::RngCore;
use spindle_core::envelope::{self, OpenParams, SealParams, SessionKey};
use spindle_core::identity::DeviceKey;
use spindle_core::{derive_bootstrap_key, derive_session_key, Fingerprint, VerifyingKey};
use spindle_proto::artifacts::Envelope;
use spindle_proto::signaling::{
    AnswerPayload, IcePayload, OfferPayload, KIND_ANSWER, KIND_ICE, KIND_OFFER,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use super::error::SignalingError;
use super::seq::SeqFloor;
use super::subject::IceDirection;

/// Envelope wire version this crate emits and accepts as the pinned minimum (`Envelope.v`,
/// DESIGN.md §A7). Neither `spindle-core` nor `spindle-proto` exports a canonical "current
/// envelope version" constant today (only `spindle_core::ALG_ID_V1`, the ciphersuite version, is
/// exported) — this mirrors `spikes/s2-signaling/src/lib.rs`'s own crate-local `V1` constant, and
/// is flagged here (per this slice's report) as a real gap rather than silently reinvented and
/// hidden: a future call site outside this crate has nothing to import for "the current envelope
/// wire version" either.
pub const ENVELOPE_V1: u8 = 1;

const EPH_PK_LEN: usize = 32;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
}

/// A fresh session id: 16 random bytes (DESIGN.md §A6's `sid`), matching
/// `spikes/s2-signaling`'s `fresh_sid` size.
pub fn fresh_sid() -> Vec<u8> {
    let mut sid = [0u8; 16];
    OsRng.fill_bytes(&mut sid);
    sid.to_vec()
}

fn x25519_from_bytes(bytes: &[u8]) -> Result<X25519PublicKey, SignalingError> {
    let arr: [u8; EPH_PK_LEN] = bytes
        .try_into()
        .map_err(|_| SignalingError::BadEphPk(bytes.len()))?;
    Ok(X25519PublicKey::from(arr))
}

fn eph_pk_of(env: &Envelope) -> Result<X25519PublicKey, SignalingError> {
    let bytes = env.eph_pk.as_deref().ok_or(SignalingError::MissingEphPk)?;
    x25519_from_bytes(bytes)
}

// ================================================================================================
// Offer (sealed under k0) / Answer (sealed under k1) — client side
// ================================================================================================

/// The client's per-connect state needed to later process the answer: its own ephemeral X25519
/// keypair (the offer carries only the public half) and the session id it minted.
pub struct OfferContext {
    pub sid: Vec<u8>,
    eph_c: StaticSecret,
    eph_c_pk: X25519PublicKey,
}

/// Mints a fresh session id and ephemeral keypair for a new connect attempt.
pub fn new_offer_context() -> OfferContext {
    let eph_c = StaticSecret::random_from_rng(OsRng);
    let eph_c_pk = X25519PublicKey::from(&eph_c);
    OfferContext {
        sid: fresh_sid(),
        eph_c,
        eph_c_pk,
    }
}

/// Seals a connect offer under `k0` (DESIGN.md §A7's two-key schedule: the offer is the one
/// message the client can seal before it has ever seen the host's ephemeral key — `k0`'s first DH
/// term is ephemeral(client)-static(host) rather than ephemeral-ephemeral; see
/// `spindle_core::envelope`'s module doc for the full rationale).
pub fn seal_offer(
    ctx: &OfferContext,
    own_device: &DeviceKey,
    own_fp: Fingerprint,
    host_device_fp: Fingerprint,
    host_agree_pk: &X25519PublicKey,
    payload: &OfferPayload,
) -> Envelope {
    let dev_dh = own_device.diffie_hellman(host_agree_pk);
    let eph_dh = *ctx.eph_c.diffie_hellman(host_agree_pk).as_bytes();
    let k0 = derive_bootstrap_key(&eph_dh, &dev_dh, &ctx.sid, &own_fp, &host_device_fp);
    envelope::seal(SealParams {
        session_key: &k0,
        signer: own_device,
        v: ENVELOPE_V1,
        alg_id: own_device.alg_id(),
        from_fp: own_fp,
        to_fp: host_device_fp,
        sid: ctx.sid.clone(),
        kind: KIND_OFFER,
        seq: 0,
        ts: now(),
        eph_pk: Some(ctx.eph_c_pk.as_bytes().to_vec()),
        plaintext: &payload.to_canonical_bytes(),
    })
}

/// Verifies every §A7 receiver MUST-check on the answer under `k1`, decodes it, and returns the
/// derived session key alongside the payload. `bound_from_fp = Some(host_device_fp)`: the client
/// only trusts an answer claiming to be from the exact host it dialed (DESIGN.md §A7's `sid`
/// binding).
pub fn open_answer(
    env: &Envelope,
    ctx: &OfferContext,
    own_device: &DeviceKey,
    own_fp: Fingerprint,
    host_device_fp: Fingerprint,
    host_sign_pk: &VerifyingKey,
    host_agree_pk: &X25519PublicKey,
) -> Result<(SessionKey, AnswerPayload), SignalingError> {
    let eph_pk_h = eph_pk_of(env)?;
    let dev_dh = own_device.diffie_hellman(host_agree_pk);
    let eph_dh = *ctx.eph_c.diffie_hellman(&eph_pk_h).as_bytes();
    let k1 = derive_session_key(&eph_dh, &dev_dh, &ctx.sid, &own_fp, &host_device_fp);

    let plaintext = envelope::open(
        OpenParams {
            session_key: &k1,
            pinned_sender_key: host_sign_pk,
            self_fp: &own_fp,
            expected_sid: &ctx.sid,
            bound_from_fp: Some(&host_device_fp),
            min_seq_exclusive: None,
            now: now(),
            min_v: ENVELOPE_V1,
            min_alg_id: spindle_core::ALG_ID_V1,
            expected_kind: KIND_ANSWER,
            sender_revoked: false, // the client dialed this exact host; nothing to revoke-check
        },
        env,
    )?;
    let answer = AnswerPayload::from_canonical_bytes(&plaintext)?;
    Ok((k1, answer))
}

// ================================================================================================
// Offer -> Answer — host side
// ================================================================================================

/// The result of successfully opening a connect offer: everything the host needs to build and
/// seal the answer, without re-deriving any secret from scratch.
#[derive(Debug)]
pub struct OpenedOffer {
    pub offer: OfferPayload,
    pub from_fp: Fingerprint,
    pub sid: Vec<u8>,
    /// The sender's pinned signing key, carried forward from the [`super::authorize::ConnectAuthorizer`]
    /// decision that authorized this offer — needed again once trickled ICE starts (every `k1`-sealed
    /// envelope from the client must verify under this same key), so the host does not need to
    /// re-authorize the sender on every single ICE message.
    pub sender_sign_pk: VerifyingKey,
    dev_dh: [u8; 32],
    eph_pk_c: X25519PublicKey,
}

/// Verifies every §A7 receiver MUST-check on the offer under `k0` and decodes it. Does NOT check
/// the `_INBOX` reply-prefix or run the [`super::authorize::ConnectAuthorizer`] decision — neither
/// is a `spindle_core::envelope` concern; see [`super::host::process_offer`], which calls both
/// before this function, and this crate's report for why that ordering matters (cheap checks
/// first, crypto only once they pass).
///
/// `expected_sid: &env.sid`: the offer is the first message of a brand-new session, so there is no
/// previously-established `sid` to compare against yet — the `sid` this message asserts *is* the
/// one being established. This matches `spikes/s2-signaling`'s own offer-handling precedent
/// exactly (a self-referential comparison, a structural no-op for this one message only; every
/// later message in the session compares against the now-established `sid` instead).
pub fn open_offer(
    env: &Envelope,
    host_device: &DeviceKey,
    host_device_fp: Fingerprint,
    sender_sign_pk: &VerifyingKey,
    sender_agree_pk: &X25519PublicKey,
) -> Result<OpenedOffer, SignalingError> {
    let from_fp = Fingerprint::from_slice(&env.from_fp)?;
    let eph_pk_c = eph_pk_of(env)?;
    let dev_dh = host_device.diffie_hellman(sender_agree_pk);
    let eph_dh = host_device.diffie_hellman(&eph_pk_c);
    let k0 = derive_bootstrap_key(&eph_dh, &dev_dh, &env.sid, &from_fp, &host_device_fp);

    let plaintext = envelope::open(
        OpenParams {
            session_key: &k0,
            pinned_sender_key: sender_sign_pk,
            self_fp: &host_device_fp,
            expected_sid: &env.sid,
            bound_from_fp: None, // first message of the session -- nothing bound yet
            min_seq_exclusive: None,
            now: now(),
            min_v: ENVELOPE_V1,
            min_alg_id: spindle_core::ALG_ID_V1,
            expected_kind: KIND_OFFER,
            // The caller (`host::process_offer`) only reaches this function after its
            // `ConnectAuthorizer` already returned `Allow` for `from_fp` -- `Allow` means "active,
            // non-revoked" by this trait's own contract (see `authorize.rs`), so there is nothing
            // further to check here.
            sender_revoked: false,
        },
        env,
    )?;
    let offer = OfferPayload::from_canonical_bytes(&plaintext)?;

    Ok(OpenedOffer {
        offer,
        from_fp,
        sid: env.sid.clone(),
        sender_sign_pk: *sender_sign_pk,
        dev_dh,
        eph_pk_c,
    })
}

impl OpenedOffer {
    /// Generates the host's own ephemeral keypair, derives `k1`, and seals the answer under it —
    /// one operation because `k1`'s ephemeral-ephemeral DH term and the answer's embedded
    /// `eph_pk` must come from the *same* keypair; splitting "derive k1" from "seal the answer"
    /// would let a caller accidentally pass two different keypairs and silently produce an answer
    /// the client can never actually decrypt.
    pub fn seal_answer(
        &self,
        host_device: &DeviceKey,
        host_device_fp: Fingerprint,
        payload: &AnswerPayload,
    ) -> (SessionKey, Envelope) {
        let eph_h = StaticSecret::random_from_rng(OsRng);
        let eph_h_pk = X25519PublicKey::from(&eph_h);
        let eph_dh = *eph_h.diffie_hellman(&self.eph_pk_c).as_bytes();
        let k1 = derive_session_key(
            &eph_dh,
            &self.dev_dh,
            &self.sid,
            &self.from_fp,
            &host_device_fp,
        );

        let env = envelope::seal(SealParams {
            session_key: &k1,
            signer: host_device,
            v: ENVELOPE_V1,
            alg_id: host_device.alg_id(),
            from_fp: host_device_fp,
            to_fp: self.from_fp,
            sid: self.sid.clone(),
            kind: KIND_ANSWER,
            seq: 0,
            ts: now(),
            eph_pk: Some(eph_h_pk.as_bytes().to_vec()),
            plaintext: &payload.to_canonical_bytes(),
        });
        (k1, env)
    }
}

// ================================================================================================
// Trickled ICE (sealed/opened under k1, both directions)
// ================================================================================================

/// Seals one trickled-ICE message under the session key `k1` (DESIGN.md §A7: every message after
/// the offer, both directions, uses `k1`).
#[allow(clippy::too_many_arguments)]
pub fn seal_ice(
    session_key: &SessionKey,
    signer: &DeviceKey,
    from_fp: Fingerprint,
    to_fp: Fingerprint,
    sid: &[u8],
    seq: u64,
    payload: &IcePayload,
) -> Envelope {
    envelope::seal(SealParams {
        session_key,
        signer,
        v: ENVELOPE_V1,
        alg_id: signer.alg_id(),
        from_fp,
        to_fp,
        sid: sid.to_vec(),
        kind: KIND_ICE,
        seq,
        ts: now(),
        eph_pk: None,
        plaintext: &payload.to_canonical_bytes(),
    })
}

/// One decoded, fully-verified trickled ICE envelope, plus the `seq` it was accepted at (the
/// caller advances its [`SeqFloor`] with this — see that type's own doc comment for why advancing
/// is the caller's responsibility, not this function's).
#[derive(Debug)]
pub struct OpenedIce {
    pub payload: IcePayload,
    pub seq: u64,
}

/// Verifies every §A7 receiver MUST-check on a trickled ICE envelope under `k1`, PLUS the
/// subject-level binding this module's own subject/envelope split requires: the message's NATS
/// subject must name exactly the `(host_fp, client_fp, sid, direction)` the caller expects (see
/// [`super::error::SignalingError::SubjectMismatch`]'s doc comment for why the envelope's own
/// `sid`/`from_fp` fields are not, by themselves, sufficient).
#[allow(clippy::too_many_arguments)]
pub fn open_ice(
    env: &Envelope,
    subject: &str,
    expected_host_fp: &Fingerprint,
    expected_client_fp: &Fingerprint,
    expected_sid: &[u8],
    expected_direction: IceDirection,
    session_key: &SessionKey,
    pinned_sender_key: &VerifyingKey,
    self_fp: &Fingerprint,
    peer_fp: &Fingerprint,
    seq_floor: &SeqFloor,
) -> Result<OpenedIce, SignalingError> {
    let parsed = super::subject::parse_session_subject(subject)
        .ok_or_else(|| SignalingError::BadSubject(subject.to_string()))?;
    if parsed.host_fp != *expected_host_fp
        || parsed.client_fp != *expected_client_fp
        || parsed.sid != expected_sid
        || parsed.direction != expected_direction
    {
        return Err(SignalingError::SubjectMismatch {
            subject: subject.to_string(),
        });
    }

    let plaintext = envelope::open(
        OpenParams {
            session_key,
            pinned_sender_key,
            self_fp,
            expected_sid,
            bound_from_fp: Some(peer_fp),
            min_seq_exclusive: seq_floor.min_seq_exclusive(),
            now: now(),
            min_v: ENVELOPE_V1,
            min_alg_id: spindle_core::ALG_ID_V1,
            expected_kind: KIND_ICE,
            sender_revoked: false,
        },
        env,
    )?;
    let payload = IcePayload::from_canonical_bytes(&plaintext)?;
    Ok(OpenedIce {
        payload,
        seq: env.seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_proto::signaling::Transport;

    struct Peer {
        device: DeviceKey,
        fp: Fingerprint,
    }

    fn peer(sign_seed: u8, agree_seed: u8) -> Peer {
        let device = DeviceKey::from_seeds([sign_seed; 32], [agree_seed; 32]);
        let fp = device.device_fp();
        Peer { device, fp }
    }

    fn sample_offer_payload() -> OfferPayload {
        OfferPayload {
            inbox: "_INBOX_client.x".to_string(),
            transport: Transport::Quic,
            ufrag: "clientufrag".to_string(),
            pwd: "clientpassword1234567890ab".to_string(),
            cert_fp: [0x11; 32],
        }
    }

    fn sample_answer_payload() -> AnswerPayload {
        AnswerPayload {
            transport: Transport::Quic,
            ufrag: "hostufrag".to_string(),
            pwd: "hostpassword1234567890abcd".to_string(),
            cert_fp: [0x22; 32],
        }
    }

    // ---- full offer -> answer round trip ----

    #[test]
    fn offer_then_answer_round_trips_and_both_sides_derive_the_same_k1() {
        let client = peer(0x10, 0x11);
        let host = peer(0x20, 0x21);

        let ctx = new_offer_context();
        let offer_payload = sample_offer_payload();
        let offer_env = seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &offer_payload,
        );

        let opened = open_offer(
            &offer_env,
            &host.device,
            host.fp,
            &client.device.sign_public_key(),
            &client.device.agree_public_key(),
        )
        .expect("offer opens");
        assert_eq!(opened.offer, offer_payload);
        assert_eq!(opened.from_fp, client.fp);
        assert_eq!(opened.sid, ctx.sid);

        let answer_payload = sample_answer_payload();
        let (host_k1, answer_env) = opened.seal_answer(&host.device, host.fp, &answer_payload);

        let (client_k1, decoded_answer) = open_answer(
            &answer_env,
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.sign_public_key(),
            &host.device.agree_public_key(),
        )
        .expect("answer opens");

        assert_eq!(decoded_answer, answer_payload);
        assert_eq!(host_k1.as_bytes(), client_k1.as_bytes());
    }

    // ---- offer: negative tests, one per MUST-check surfaced through this wrapper ----

    #[test]
    fn open_offer_rejects_wrong_signing_key() {
        let client = peer(0x30, 0x31);
        let host = peer(0x40, 0x41);
        let impostor = peer(0x50, 0x51);

        let ctx = new_offer_context();
        let offer_env = seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(),
        );

        let err = open_offer(
            &offer_env,
            &host.device,
            host.fp,
            &impostor.device.sign_public_key(), // wrong pinned key
            &client.device.agree_public_key(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SignalingError::Envelope(spindle_core::envelope::EnvelopeError::BadSignature)
        ));
    }

    #[test]
    fn open_offer_rejects_wrong_agree_key_as_decrypt_failure() {
        // A wrong `sender_agree_pk` changes the derived k0 (a different `dev_dh`), so the offer's
        // signature still verifies (it doesn't depend on k0) but decryption fails.
        let client = peer(0x32, 0x33);
        let host = peer(0x42, 0x43);
        let impostor = peer(0x52, 0x53);

        let ctx = new_offer_context();
        let offer_env = seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(),
        );

        let err = open_offer(
            &offer_env,
            &host.device,
            host.fp,
            &client.device.sign_public_key(),
            &impostor.device.agree_public_key(), // wrong agree key -> wrong k0
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SignalingError::Envelope(spindle_core::envelope::EnvelopeError::DecryptFailed)
        ));
    }

    #[test]
    fn open_offer_rejects_missing_eph_pk() {
        let client = peer(0x34, 0x35);
        let host = peer(0x44, 0x45);

        let ctx = new_offer_context();
        let mut offer_env = seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(),
        );
        offer_env.eph_pk = None;

        let err = open_offer(
            &offer_env,
            &host.device,
            host.fp,
            &client.device.sign_public_key(),
            &client.device.agree_public_key(),
        )
        .unwrap_err();
        assert!(matches!(err, SignalingError::MissingEphPk));
    }

    #[test]
    fn open_offer_rejects_undersized_eph_pk() {
        let client = peer(0x36, 0x37);
        let host = peer(0x46, 0x47);

        let ctx = new_offer_context();
        let mut offer_env = seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(),
        );
        offer_env.eph_pk = Some(vec![0u8; 31]);

        let err = open_offer(
            &offer_env,
            &host.device,
            host.fp,
            &client.device.sign_public_key(),
            &client.device.agree_public_key(),
        )
        .unwrap_err();
        assert!(matches!(err, SignalingError::BadEphPk(31)));
    }

    #[test]
    fn open_offer_rejects_kind_mismatch() {
        // Simulates a message sealed under k0 but with the wrong `kind` -- e.g. an ICE envelope
        // that was, for whatever reason, sealed under the bootstrap key instead of k1.
        let client = peer(0x38, 0x39);
        let host = peer(0x48, 0x49);
        let ctx = new_offer_context();
        let dev_dh = client
            .device
            .diffie_hellman(&host.device.agree_public_key());
        let eph_dh = *ctx
            .eph_c_for_test()
            .diffie_hellman(&host.device.agree_public_key())
            .as_bytes();
        let k0 = derive_bootstrap_key(&eph_dh, &dev_dh, &ctx.sid, &client.fp, &host.fp);
        let env = envelope::seal(SealParams {
            session_key: &k0,
            signer: &client.device,
            v: ENVELOPE_V1,
            alg_id: client.device.alg_id(),
            from_fp: client.fp,
            to_fp: host.fp,
            sid: ctx.sid.clone(),
            kind: KIND_ICE, // wrong kind for an offer
            seq: 0,
            ts: now(),
            eph_pk: Some(ctx.eph_c_pk.as_bytes().to_vec()),
            plaintext: &sample_offer_payload().to_canonical_bytes(),
        });

        let err = open_offer(
            &env,
            &host.device,
            host.fp,
            &client.device.sign_public_key(),
            &client.device.agree_public_key(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SignalingError::Envelope(spindle_core::envelope::EnvelopeError::KindMismatch)
        ));
    }

    // ---- answer: negative tests ----

    #[test]
    fn open_answer_rejects_answer_signed_by_the_wrong_host() {
        // Note this is NOT "an impostor opens the real offer and answers instead" -- that
        // scenario is not reachable at all: `open_offer` requires the opener to hold the exact
        // static agreement secret `k0` was derived against (the real host's), so an impostor who
        // does not hold it cannot decrypt the offer in the first place (`open_offer` itself
        // already rejects that attempt, as `WrongRecipient`/`DecryptFailed` per its own negative
        // tests above). This test instead covers the case that IS reachable: a syntactically
        // valid, k1-sealed answer that merely *claims* to be from the real host but is signed by
        // someone else -- e.g. a compromised relay replaying a forged message.
        let client = peer(0x60, 0x61);
        let host = peer(0x70, 0x71);
        let impostor_host = peer(0x80, 0x81);

        let ctx = new_offer_context();
        let dev_dh = client
            .device
            .diffie_hellman(&host.device.agree_public_key());
        let eph_h = StaticSecret::random_from_rng(OsRng);
        let eph_h_pk = X25519PublicKey::from(&eph_h);
        let eph_dh = *ctx.eph_c_for_test().diffie_hellman(&eph_h_pk).as_bytes();
        let k1 = derive_session_key(&eph_dh, &dev_dh, &ctx.sid, &client.fp, &host.fp);
        let forged_answer_env = envelope::seal(SealParams {
            session_key: &k1,
            signer: &impostor_host.device, // signed by the WRONG host
            v: ENVELOPE_V1,
            alg_id: impostor_host.device.alg_id(),
            from_fp: host.fp, // claims to be from the real host
            to_fp: client.fp,
            sid: ctx.sid.clone(),
            kind: KIND_ANSWER,
            seq: 0,
            ts: now(),
            eph_pk: Some(eph_h_pk.as_bytes().to_vec()),
            plaintext: &sample_answer_payload().to_canonical_bytes(),
        });

        let result = open_answer(
            &forged_answer_env,
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.sign_public_key(), // pinned to the REAL host's key
            &host.device.agree_public_key(),
        );
        // `SessionKey` (part of the Ok type) has no `Debug` impl by design (it holds raw secret
        // material — see that type's own doc comment), so `unwrap_err()` (which requires `T:
        // Debug`) cannot be used here; match instead.
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected the answer to fail to open"),
        };
        // The forged envelope's signature never verifies under the real host's pinned key.
        assert!(matches!(
            err,
            SignalingError::Envelope(spindle_core::envelope::EnvelopeError::BadSignature)
        ));
    }

    #[test]
    fn open_answer_rejects_tampered_ciphertext_as_bad_signature() {
        // Mirrors spindle-core's own `tampering_ciphertext_after_signing_breaks_signature_check`:
        // the signature covers the ciphertext, so tampering it is caught as BadSignature.
        let client = peer(0x62, 0x63);
        let host = peer(0x72, 0x73);
        let ctx = new_offer_context();
        let offer_env = seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(),
        );
        let opened = open_offer(
            &offer_env,
            &host.device,
            host.fp,
            &client.device.sign_public_key(),
            &client.device.agree_public_key(),
        )
        .expect("offer opens");
        let (_k1, mut answer_env) =
            opened.seal_answer(&host.device, host.fp, &sample_answer_payload());
        answer_env.ciphertext[0] ^= 0xff;

        let err = open_answer(
            &answer_env,
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.sign_public_key(),
            &host.device.agree_public_key(),
        );
        // Same `SessionKey: !Debug` reason as `open_answer_rejects_answer_from_the_wrong_host`
        // above.
        let err = match err {
            Err(e) => e,
            Ok(_) => panic!("expected the answer to fail to open"),
        };
        assert!(matches!(
            err,
            SignalingError::Envelope(spindle_core::envelope::EnvelopeError::BadSignature)
        ));
    }

    // ---- ICE: round trip + subject binding + seq floor ----

    fn ice_candidate(line: &str) -> IcePayload {
        IcePayload {
            candidate: Some(line.to_string()),
            end_of_candidates: false,
        }
    }

    #[test]
    fn ice_round_trips_with_matching_subject() {
        let client = peer(0x90, 0x91);
        let host = peer(0xA0, 0xA1);
        let sid = fresh_sid();
        let session_key = derive_session_key(&[7u8; 32], &[8u8; 32], &sid, &client.fp, &host.fp);

        let payload = ice_candidate("candidate:1 1 UDP 1 10.0.0.1 1 typ host");
        let env = seal_ice(
            &session_key,
            &client.device,
            client.fp,
            host.fp,
            &sid,
            1,
            &payload,
        );
        let subject = super::super::subject::session_subject(
            &host.fp,
            &client.fp,
            &sid,
            IceDirection::ClientToHost,
        );

        let opened = open_ice(
            &env,
            &subject,
            &host.fp,
            &client.fp,
            &sid,
            IceDirection::ClientToHost,
            &session_key,
            &client.device.sign_public_key(),
            &host.fp,
            &client.fp,
            &SeqFloor::new(),
        )
        .expect("ice envelope opens");
        assert_eq!(opened.payload, payload);
        assert_eq!(opened.seq, 1);
    }

    #[test]
    fn ice_rejects_a_subject_for_a_different_session() {
        let client = peer(0x92, 0x93);
        let host = peer(0xA2, 0xA3);
        let sid = fresh_sid();
        let other_sid = fresh_sid();
        let session_key = derive_session_key(&[7u8; 32], &[8u8; 32], &sid, &client.fp, &host.fp);

        let payload = ice_candidate("candidate:1 1 UDP 1 10.0.0.1 1 typ host");
        let env = seal_ice(
            &session_key,
            &client.device,
            client.fp,
            host.fp,
            &sid,
            1,
            &payload,
        );
        // Subject names a DIFFERENT sid than the one the envelope actually carries.
        let wrong_subject = super::super::subject::session_subject(
            &host.fp,
            &client.fp,
            &other_sid,
            IceDirection::ClientToHost,
        );

        let err = open_ice(
            &env,
            &wrong_subject,
            &host.fp,
            &client.fp,
            &sid, // caller still expects the real sid...
            IceDirection::ClientToHost,
            &session_key,
            &client.device.sign_public_key(),
            &host.fp,
            &client.fp,
            &SeqFloor::new(),
        )
        .unwrap_err();
        assert!(matches!(err, SignalingError::SubjectMismatch { .. }));
    }

    #[test]
    fn ice_rejects_a_subject_for_the_wrong_direction() {
        let client = peer(0x94, 0x95);
        let host = peer(0xA4, 0xA5);
        let sid = fresh_sid();
        let session_key = derive_session_key(&[7u8; 32], &[8u8; 32], &sid, &client.fp, &host.fp);

        let payload = ice_candidate("candidate:1 1 UDP 1 10.0.0.1 1 typ host");
        let env = seal_ice(
            &session_key,
            &client.device,
            client.fp,
            host.fp,
            &sid,
            1,
            &payload,
        );
        let h2c_subject = super::super::subject::session_subject(
            &host.fp,
            &client.fp,
            &sid,
            IceDirection::HostToClient, // wrong direction for a client->host message
        );

        let err = open_ice(
            &env,
            &h2c_subject,
            &host.fp,
            &client.fp,
            &sid,
            IceDirection::ClientToHost,
            &session_key,
            &client.device.sign_public_key(),
            &host.fp,
            &client.fp,
            &SeqFloor::new(),
        )
        .unwrap_err();
        assert!(matches!(err, SignalingError::SubjectMismatch { .. }));
    }

    #[test]
    fn ice_rejects_malformed_subject() {
        let client = peer(0x96, 0x97);
        let host = peer(0xA6, 0xA7);
        let sid = fresh_sid();
        let session_key = derive_session_key(&[7u8; 32], &[8u8; 32], &sid, &client.fp, &host.fp);
        let payload = ice_candidate("candidate:1 1 UDP 1 10.0.0.1 1 typ host");
        let env = seal_ice(
            &session_key,
            &client.device,
            client.fp,
            host.fp,
            &sid,
            1,
            &payload,
        );

        let err = open_ice(
            &env,
            "not.a.session.subject",
            &host.fp,
            &client.fp,
            &sid,
            IceDirection::ClientToHost,
            &session_key,
            &client.device.sign_public_key(),
            &host.fp,
            &client.fp,
            &SeqFloor::new(),
        )
        .unwrap_err();
        assert!(matches!(err, SignalingError::BadSubject(_)));
    }

    #[test]
    fn ice_rejects_replayed_seq_via_the_floor() {
        let client = peer(0x98, 0x99);
        let host = peer(0xA8, 0xA9);
        let sid = fresh_sid();
        let session_key = derive_session_key(&[7u8; 32], &[8u8; 32], &sid, &client.fp, &host.fp);
        let payload = ice_candidate("candidate:1 1 UDP 1 10.0.0.1 1 typ host");
        let env = seal_ice(
            &session_key,
            &client.device,
            client.fp,
            host.fp,
            &sid,
            3,
            &payload,
        );
        let subject = super::super::subject::session_subject(
            &host.fp,
            &client.fp,
            &sid,
            IceDirection::ClientToHost,
        );

        let mut floor = SeqFloor::new();
        floor.advance(3); // seq=3 already accepted once

        let err = open_ice(
            &env,
            &subject,
            &host.fp,
            &client.fp,
            &sid,
            IceDirection::ClientToHost,
            &session_key,
            &client.device.sign_public_key(),
            &host.fp,
            &client.fp,
            &floor,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SignalingError::Envelope(spindle_core::envelope::EnvelopeError::ReplaySeq)
        ));
    }

    // Exposes the client's ephemeral secret for the one test above that needs to hand-construct a
    // mis-kinded envelope directly (bypassing `seal_offer`, which always uses `KIND_OFFER`).
    impl OfferContext {
        fn eph_c_for_test(&self) -> &StaticSecret {
            &self.eph_c
        }
    }
}
