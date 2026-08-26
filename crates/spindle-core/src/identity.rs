//! Identity roots and device keys (DESIGN.md §A4, ADR-003).
//!
//! - [`RootKey`] — a person's or host's Ed25519 identity root. `root_fp = SHA-256(root_pk)`.
//!   Pre-committed rotation ([`generate_next_root`], [`sign_root_rotation`],
//!   [`verify_root_rotation`]) lets a root recover from suspected compromise without any
//!   registry involvement.
//! - [`DeviceKey`] — a device's Ed25519 (sign) + X25519 (agree) keypair, `alg_id = 1`.
//!   `device_fp = SHA-256("spindle-dev-v1" || alg_id || sign_pk || agree_pk)`.
//!
//! Both wrap `ed25519-dalek`/`x25519-dalek` secret types, which zeroize their key material on
//! drop; this module adds no unsafe raw-byte copies of secret material that would need separate
//! zeroizing.

use crate::fingerprint::Fingerprint;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// The `alg_id` suite version byte (DESIGN.md §A4): `1` = Ed25519 / X25519 / AES-256-GCM. No
/// P-256 fallback (v0.6 decision, DESIGN.md §A11) — a second curve suite is downgrade surface.
pub const ALG_ID_V1: u8 = 1;

const DEVICE_FP_DOMAIN: &[u8] = b"spindle-dev-v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityError {
    #[error("root rotation signature invalid under the old root's key")]
    BadRotationSignature,
    #[error("new root public key does not match the pre-committed hash")]
    RotationHashMismatch,
    /// [`verify_bytes`]: the signature slice wasn't exactly 64 bytes, so it cannot even be parsed
    /// as an Ed25519 signature.
    #[error("signature must be exactly 64 bytes, got {0}")]
    BadSignatureLength(usize),
    /// [`verify_bytes`]: the signature was well-formed but did not verify under the given key.
    #[error("signature verification failed")]
    BadSignature,
}

// ================================================================================================
// RootKey
// ================================================================================================

/// A person's or host's identity root key (Ed25519). `root_fp = SHA-256(root_pk)` (DESIGN.md §A4).
pub struct RootKey {
    signing_key: SigningKey,
    root_fp: Fingerprint,
}

impl RootKey {
    /// Generates a fresh root key from the OS CSPRNG. Normal path for enrollment.
    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::generate(&mut OsRng))
    }

    /// Deterministic construction from a 32-byte seed. Used by the recovery-phrase path and by
    /// the crypto vector generator — **not** a substitute for [`RootKey::generate`] in normal
    /// enrollment, where the seed must come from a real CSPRNG.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self::from_signing_key(SigningKey::from_bytes(&seed))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let root_fp = root_fp_of(&signing_key.verifying_key());
        Self {
            signing_key,
            root_fp,
        }
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn root_fp(&self) -> Fingerprint {
        self.root_fp
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }
}

/// `root_fp = SHA-256(root_pk)` for a public key the caller already holds (e.g. a pinned peer or
/// host root), without needing a [`RootKey`] (which also holds the secret half).
pub fn root_fp_of(root_pk: &VerifyingKey) -> Fingerprint {
    Fingerprint::of_parts(&[root_pk.as_bytes()])
}

// ---- Pre-committed root rotation ----
//
// Root rotation is *not* one of spindle-proto's seven A7b-cataloged wire artifact types
// (Envelope, Capability, AdmissionToken, DeviceCertificate, RevocationRecord, AdminCommand,
// HostOpKeyCert — see spindle_proto::artifacts). DESIGN.md §A4 and ADR-003 describe it in prose
// only (`sig_old_root(new_root_pk)`, `hash(next_root_pk)` pre-committed), with no corresponding
// struct in spindle-proto's schema-of-record. Rather than inventing an unauthorized addition to
// spindle-proto's wire types, this module defines its own minimal domain-separated signing input
// for the rotation signature, kept entirely inside spindle-core.

const ROOT_ROTATION_TAG: &[u8] = b"spindle-root-rotation-v1";

/// A freshly generated next-root keypair plus the hash a current root commits to publish now, so
/// a future rotation to this key can be verified without the new key ever having been exposed
/// before the rotation itself.
pub struct NextRoot {
    pub next_root: RootKey,
    /// `hash(next_root_pk)` (DESIGN.md §A4) — publish this now.
    pub committed_hash: [u8; 32],
}

/// Generates a next-root keypair and its pre-committed hash (DESIGN.md §A4: "the root also
/// commits `hash(next_root_pk)`").
pub fn generate_next_root() -> NextRoot {
    let next_root = RootKey::generate();
    let committed_hash = Sha256::digest(next_root.public_key().as_bytes()).into();
    NextRoot {
        next_root,
        committed_hash,
    }
}

fn rotation_signing_input(new_root_pk: &VerifyingKey) -> Vec<u8> {
    let mut v = Vec::with_capacity(ROOT_ROTATION_TAG.len() + FINGERPRINT_KEY_LEN);
    v.extend_from_slice(ROOT_ROTATION_TAG);
    v.extend_from_slice(new_root_pk.as_bytes());
    v
}

const FINGERPRINT_KEY_LEN: usize = 32;

/// Issues `sig_old_root(new_root_pk)` (DESIGN.md §A4 root rotation).
pub fn sign_root_rotation(old_root: &RootKey, new_root_pk: &VerifyingKey) -> Signature {
    old_root.sign(&rotation_signing_input(new_root_pk))
}

/// Verifies a root rotation: `hash(new_root_pk)` must match the value the old root pre-committed
/// to, and the rotation signature must verify under the old root's key (DESIGN.md §A4).
pub fn verify_root_rotation(
    old_root_pk: &VerifyingKey,
    committed_hash: &[u8; 32],
    new_root_pk: &VerifyingKey,
    sig: &Signature,
) -> Result<(), IdentityError> {
    let actual_hash: [u8; 32] = Sha256::digest(new_root_pk.as_bytes()).into();
    if &actual_hash != committed_hash {
        return Err(IdentityError::RotationHashMismatch);
    }
    old_root_pk
        .verify(&rotation_signing_input(new_root_pk), sig)
        .map_err(|_| IdentityError::BadRotationSignature)
}

// ================================================================================================
// DeviceKey
// ================================================================================================

/// A device's Ed25519 (sign) + X25519 (agree) keypair (DESIGN.md §A4). `device_fp =
/// SHA-256("spindle-dev-v1" || alg_id || sign_pk || agree_pk)`.
pub struct DeviceKey {
    sign_key: SigningKey,
    agree_key: StaticSecret,
    device_fp: Fingerprint,
}

impl DeviceKey {
    /// Generates a fresh device keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        let sign_key = SigningKey::generate(&mut OsRng);
        let agree_key = StaticSecret::random_from_rng(OsRng);
        Self::from_keys(sign_key, agree_key)
    }

    /// Deterministic construction from two 32-byte seeds — TEST-ONLY / crypto-vector use.
    pub fn from_seeds(sign_seed: [u8; 32], agree_seed: [u8; 32]) -> Self {
        Self::from_keys(
            SigningKey::from_bytes(&sign_seed),
            StaticSecret::from(agree_seed),
        )
    }

    fn from_keys(sign_key: SigningKey, agree_key: StaticSecret) -> Self {
        let sign_pk = sign_key.verifying_key();
        let agree_pk = X25519PublicKey::from(&agree_key);
        let device_fp = device_fp_of(ALG_ID_V1, &sign_pk, &agree_pk);
        Self {
            sign_key,
            agree_key,
            device_fp,
        }
    }

    pub fn sign_public_key(&self) -> VerifyingKey {
        self.sign_key.verifying_key()
    }

    pub fn agree_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.agree_key)
    }

    pub fn device_fp(&self) -> Fingerprint {
        self.device_fp
    }

    pub fn alg_id(&self) -> u8 {
        ALG_ID_V1
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.sign_key.sign(msg)
    }

    /// `X25519(self.agree_key, peer_agree_pk)` — the static-static half of the envelope's
    /// ephemeral-static hybrid (DESIGN.md §A7).
    pub fn diffie_hellman(&self, peer_agree_pk: &X25519PublicKey) -> [u8; 32] {
        *self.agree_key.diffie_hellman(peer_agree_pk).as_bytes()
    }
}

/// `device_fp` for a device's public keys, without needing a [`DeviceKey`] (which also holds the
/// secret halves) — used by verifiers who only hold a peer's public keys.
pub fn device_fp_of(alg_id: u8, sign_pk: &VerifyingKey, agree_pk: &X25519PublicKey) -> Fingerprint {
    Fingerprint::of_parts(&[
        DEVICE_FP_DOMAIN,
        &[alg_id],
        sign_pk.as_bytes(),
        agree_pk.as_bytes(),
    ])
}

// ================================================================================================
// Raw Ed25519 sign/verify helpers
// ================================================================================================
//
// `spindle-vfs`'s audit chain (Stage 6 slice 2, DESIGN.md §A4b "Audit log") needs a `HeadSigner`
// trait so periodic signed-head custody stays out of that crate, using "spindle-core types" per
// its own design brief — but per A9c's crate-layering law `spindle-vfs` must not gain a direct
// `ed25519-dalek` dependency (it depends on `spindle-core` only). `SigningKey`/`VerifyingKey` are
// already re-exported (see `lib.rs`), so a caller can hold and construct those; what's missing is
// a way to sign/verify arbitrary already-domain-separated bytes without naming
// `ed25519_dalek::Signature` itself (not re-exported, and constructing one from raw bytes needs
// that type's own associated function, which requires a direct dependency to name). These two
// functions close that gap generically, rather than adding a one-off audit-chain-specific API
// here — any future crate-local signing need with the same crate-layering constraint can reuse
// them instead of re-deriving the same workaround.

/// Signs already domain-separated bytes (the caller is responsible for its own domain tag —
/// mirroring the discipline in [`sign_root_rotation`]), returning the raw 64-byte Ed25519
/// signature.
pub fn sign_bytes(signing_key: &SigningKey, msg: &[u8]) -> Vec<u8> {
    signing_key.sign(msg).to_bytes().to_vec()
}

/// Verifies a raw Ed25519 signature (as produced by [`sign_bytes`]) over `msg` under
/// `verifying_key`.
pub fn verify_bytes(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), IdentityError> {
    let arr: [u8; 64] = sig
        .try_into()
        .map_err(|_| IdentityError::BadSignatureLength(sig.len()))?;
    let signature = Signature::from_bytes(&arr);
    verifying_key
        .verify(msg, &signature)
        .map_err(|_| IdentityError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_bytes_verify_bytes_round_trip() {
        let signer = SigningKey::from_bytes(&[0x40; 32]);
        let sig = sign_bytes(&signer, b"spindle-audit-head-v1 payload");
        verify_bytes(&signer.verifying_key(), b"spindle-audit-head-v1 payload", &sig)
            .expect("valid signature must verify");
    }

    #[test]
    fn verify_bytes_rejects_wrong_message() {
        let signer = SigningKey::from_bytes(&[0x41; 32]);
        let sig = sign_bytes(&signer, b"original");
        let err = verify_bytes(&signer.verifying_key(), b"tampered", &sig).unwrap_err();
        assert_eq!(err, IdentityError::BadSignature);
    }

    #[test]
    fn verify_bytes_rejects_wrong_key() {
        let signer = SigningKey::from_bytes(&[0x42; 32]);
        let impostor = SigningKey::from_bytes(&[0x43; 32]);
        let sig = sign_bytes(&signer, b"payload");
        let err = verify_bytes(&impostor.verifying_key(), b"payload", &sig).unwrap_err();
        assert_eq!(err, IdentityError::BadSignature);
    }

    #[test]
    fn verify_bytes_rejects_wrong_length() {
        let signer = SigningKey::from_bytes(&[0x44; 32]);
        let err = verify_bytes(&signer.verifying_key(), b"payload", &[0u8; 10]).unwrap_err();
        assert_eq!(err, IdentityError::BadSignatureLength(10));
    }

    #[test]
    fn root_key_fp_matches_root_fp_of() {
        let root = RootKey::from_seed([0x01; 32]);
        assert_eq!(root.root_fp(), root_fp_of(&root.public_key()));
    }

    #[test]
    fn root_key_deterministic_from_seed() {
        let a = RootKey::from_seed([0x42; 32]);
        let b = RootKey::from_seed([0x42; 32]);
        assert_eq!(a.public_key().as_bytes(), b.public_key().as_bytes());
        assert_eq!(a.root_fp(), b.root_fp());
    }

    #[test]
    fn device_key_fp_matches_device_fp_of() {
        let dev = DeviceKey::from_seeds([0x10; 32], [0x11; 32]);
        let expected = device_fp_of(ALG_ID_V1, &dev.sign_public_key(), &dev.agree_public_key());
        assert_eq!(dev.device_fp(), expected);
    }

    #[test]
    fn device_key_deterministic_from_seeds() {
        let a = DeviceKey::from_seeds([0x20; 32], [0x21; 32]);
        let b = DeviceKey::from_seeds([0x20; 32], [0x21; 32]);
        assert_eq!(a.device_fp(), b.device_fp());
        assert_eq!(
            a.sign_public_key().as_bytes(),
            b.sign_public_key().as_bytes()
        );
        assert_eq!(
            a.agree_public_key().as_bytes(),
            b.agree_public_key().as_bytes()
        );
    }

    #[test]
    fn root_rotation_round_trip() {
        let old_root = RootKey::from_seed([0x30; 32]);
        let next = generate_next_root();
        let sig = sign_root_rotation(&old_root, &next.next_root.public_key());
        verify_root_rotation(
            &old_root.public_key(),
            &next.committed_hash,
            &next.next_root.public_key(),
            &sig,
        )
        .expect("valid rotation");
    }

    #[test]
    fn root_rotation_rejects_hash_mismatch() {
        let old_root = RootKey::from_seed([0x31; 32]);
        let next = generate_next_root();
        let wrong_new_root = RootKey::from_seed([0x99; 32]);
        let sig = sign_root_rotation(&old_root, &wrong_new_root.public_key());
        let err = verify_root_rotation(
            &old_root.public_key(),
            &next.committed_hash, // committed to `next`, not `wrong_new_root`
            &wrong_new_root.public_key(),
            &sig,
        )
        .unwrap_err();
        assert_eq!(err, IdentityError::RotationHashMismatch);
    }

    #[test]
    fn root_rotation_rejects_bad_signature() {
        let old_root = RootKey::from_seed([0x32; 32]);
        let impostor_root = RootKey::from_seed([0x33; 32]);
        let next = generate_next_root();
        // Signed by the wrong "old root" key, but the hash does match the commitment.
        let sig = sign_root_rotation(&impostor_root, &next.next_root.public_key());
        let err = verify_root_rotation(
            &old_root.public_key(),
            &next.committed_hash,
            &next.next_root.public_key(),
            &sig,
        )
        .unwrap_err();
        assert_eq!(err, IdentityError::BadRotationSignature);
    }
}
