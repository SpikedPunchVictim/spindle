use super::{
    check_exp, parse_signature, parse_verifying_key, verify_host_op_key_cert, ArtifactError,
};
use crate::fingerprint::Fingerprint;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use spindle_proto::artifacts::{CapKind, Capability, HostOpKeyCert};

/// Issues a capability chained to the host **root** identity (DESIGN.md §A4's "host-signed,
/// self-verifying" capability, as revised by decision A10.30, 2026-08-24).
///
/// `host_fp`/`host_root_pk` are derived from `host_root_pk`, not from the signer, so the
/// self-verifying property (`host_fp == SHA-256(host_root_pk)`) holds by construction — this is
/// the A10.30 fix: previously `host_fp` was derived from the *operating* key the host actually
/// signed with, one key-rotation away from the root identity everyone else pins/scopes `host_fp`
/// by (S1 flagged this divergence; see `spindle-helper`'s authz module docs). `op_cert` is the
/// existing [`HostOpKeyCert`] the host root issued for its current operating key (see
/// [`super::issue_host_op_key_cert`]) — embedded here as its own complete canonical CBOR
/// encoding, so [`verify_capability`] can walk the chain without any external registry lookup.
/// `op_signer` is that same operating key, and it signs the capability itself — the caller is
/// responsible for `op_signer` actually being the key `op_cert.host_op_pk` names (this function
/// does not cross-check the two; a mismatch here simply produces a capability that fails
/// [`verify_capability`]'s step 3).
#[allow(clippy::too_many_arguments)]
pub fn issue_capability(
    host_root_pk: &VerifyingKey,
    op_cert: &HostOpKeyCert,
    op_signer: &SigningKey,
    kind: CapKind,
    subject: Fingerprint,
    cap_epoch: u64,
    exp: u64,
    nonce: Vec<u8>,
) -> Capability {
    let host_fp = Fingerprint::of_parts(&[host_root_pk.as_bytes()]);
    let mut cap = Capability {
        v: 1,
        host_fp: host_fp.to_vec(),
        host_root_pk: host_root_pk.as_bytes().to_vec(),
        op_cert: op_cert.to_canonical_bytes(),
        kind,
        subject: subject.to_vec(),
        cap_epoch,
        exp,
        nonce,
        sig: Vec::new(),
    };
    cap.sig = op_signer.sign(&cap.signing_input()).to_bytes().to_vec();
    cap
}

/// Verifies a capability's full root → operating-key → capability chain (DESIGN.md §A4, decision
/// A10.30): no external root or registry lookup needed beyond the capability's own embedded
/// fields (DESIGN.md §A4: "the callout needs no registry of hosts or members").
///
/// 1. `host_fp == SHA-256(host_root_pk)` — the capability's declared root identity is
///    self-consistent with its own `host_fp`.
/// 2. The embedded `op_cert` decodes as a [`HostOpKeyCert`] and verifies under `host_root_pk`
///    (via [`verify_host_op_key_cert`], which also checks the op cert's own `exp` against `now`).
/// 3. `sig` verifies under the op cert's `host_op_pk` — i.e. the capability was actually signed
///    by the operating key the root certified, not merely by *some* key.
///
/// Each step's failure surfaces its own [`ArtifactError`] variant (steps 2/3 reuse
/// [`verify_host_op_key_cert`]'s own variants for its half of the chain, since that function
/// already distinguishes malformed/expired/wrong-root/bad-signature failures — no need to
/// duplicate that logic here).
///
/// **Ambiguity flagged, not resolved**: DESIGN.md §A7b / ADR-003's signed-artifact table lists
/// `nbf = issue ts` as part of a capability's time rule, but `spindle_proto::artifacts::Capability`
/// — the schema of record per its own module docs — has no `nbf` field. This function therefore
/// checks only `exp` for the capability itself, matching the wire schema that actually exists,
/// rather than inventing a substitute `nbf` check (e.g. treating `cap_epoch` or `nonce` as a
/// stand-in).
pub fn verify_capability(cap: &Capability, now: u64) -> Result<(), ArtifactError> {
    // 1. host_fp == SHA-256(host_root_pk) — self-consistency of the capability's own fields.
    let host_root_pk = parse_verifying_key(&cap.host_root_pk)?;
    let expected_fp = Fingerprint::of_parts(&[host_root_pk.as_bytes()]);
    if !expected_fp.matches(&cap.host_fp) {
        return Err(ArtifactError::HostFingerprintMismatch);
    }
    let host_fp = Fingerprint::from_slice(&cap.host_fp)
        .map_err(|_| ArtifactError::HostFingerprintMismatch)?;

    // 2. Decode + verify the embedded op cert chains to host_root_pk, including its own `exp`.
    let op_cert = HostOpKeyCert::from_canonical_bytes(&cap.op_cert)
        .map_err(|_| ArtifactError::MalformedOpCert)?;
    verify_host_op_key_cert(&op_cert, &host_root_pk, &host_fp, now)?;

    // 3. `sig` verifies under the op cert's own operating key.
    let op_pk = parse_verifying_key(&op_cert.host_op_pk)?;
    let sig = parse_signature(&cap.sig)?;
    op_pk
        .verify(&cap.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)?;

    check_exp(now, cap.exp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::issue_host_op_key_cert;
    use crate::identity::RootKey;

    /// A full test host: identity root + operating key + the root's certificate for that
    /// operating key. `op_cert_exp` is exposed separately (rather than hardcoded) so tests can
    /// exercise an op cert that expires independently of the capability's own `exp`.
    struct TestHost {
        root: RootKey,
        op_signer: SigningKey,
        op_cert: HostOpKeyCert,
    }

    fn test_host(root_seed: [u8; 32], op_seed: [u8; 32], op_cert_exp: u64) -> TestHost {
        let root = RootKey::from_seed(root_seed);
        let op_signer = SigningKey::from_bytes(&op_seed);
        let op_cert = issue_host_op_key_cert(
            &root,
            &op_signer.verifying_key(),
            Fingerprint::of_parts(&[b"capability-test:nats"]),
            0,
            op_cert_exp,
        );
        TestHost {
            root,
            op_signer,
            op_cert,
        }
    }

    fn issue(
        host: &TestHost,
        kind: CapKind,
        subject: Fingerprint,
        epoch: u64,
        exp: u64,
    ) -> Capability {
        issue_capability(
            &host.root.public_key(),
            &host.op_cert,
            &host.op_signer,
            kind,
            subject,
            epoch,
            exp,
            vec![0xAA; 16],
        )
    }

    #[test]
    fn issue_and_verify_round_trip_both_kinds() {
        for kind in [CapKind::Invite, CapKind::Member] {
            let host = test_host([0x11; 32], [0x12; 32], 10_000);
            let cap = issue(&host, kind, Fingerprint::of_parts(&[b"subject"]), 3, 2_000);
            verify_capability(&cap, 1_500).expect("valid capability: full chain round-trip");
        }
    }

    #[test]
    fn rejects_host_fingerprint_mismatch() {
        let host = test_host([0x11; 32], [0x12; 32], 10_000);
        let mut cap = issue(
            &host,
            CapKind::Member,
            Fingerprint::of_parts(&[b"subject"]),
            0,
            2_000,
        );
        cap.host_fp[0] ^= 0xff;
        let err = verify_capability(&cap, 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::HostFingerprintMismatch);
    }

    #[test]
    fn rejects_tampered_root_pk() {
        // host_fp is unchanged, but host_root_pk is swapped for a *different* (validly-encoded)
        // root's public key — SHA-256(host_root_pk) no longer matches the declared host_fp.
        let host = test_host([0x11; 32], [0x12; 32], 10_000);
        let mut cap = issue(
            &host,
            CapKind::Member,
            Fingerprint::of_parts(&[b"subject"]),
            0,
            2_000,
        );
        let other_root = RootKey::from_seed([0x99; 32]);
        cap.host_root_pk = other_root.public_key().as_bytes().to_vec();
        let err = verify_capability(&cap, 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::HostFingerprintMismatch);
    }

    #[test]
    fn rejects_bad_signature() {
        let host = test_host([0x11; 32], [0x12; 32], 10_000);
        let mut cap = issue(
            &host,
            CapKind::Member,
            Fingerprint::of_parts(&[b"subject"]),
            0,
            2_000,
        );
        cap.sig[0] ^= 0xff;
        let err = verify_capability(&cap, 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_expired() {
        let host = test_host([0x11; 32], [0x12; 32], 10_000);
        let cap = issue(
            &host,
            CapKind::Member,
            Fingerprint::of_parts(&[b"subject"]),
            0,
            2_000,
        );
        let err = verify_capability(&cap, 2_001).unwrap_err();
        assert_eq!(err, ArtifactError::Expired);
    }

    #[test]
    fn rejects_expired_op_cert() {
        // op_cert itself expires at 1_000, well before the capability's own exp (2_000) — step 2
        // of the chain must catch this even though the capability's own exp check would pass.
        let host = test_host([0x11; 32], [0x12; 32], 1_000);
        let cap = issue(
            &host,
            CapKind::Member,
            Fingerprint::of_parts(&[b"subject"]),
            0,
            2_000,
        );
        let err = verify_capability(&cap, 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::Expired);
    }

    #[test]
    fn rejects_op_cert_signed_by_wrong_root() {
        // The op cert is validly signed, but by a DIFFERENT root than the one the capability
        // declares as host_root_pk — so verify_host_op_key_cert's own signature check must fail
        // when re-run against the declared host_root_pk.
        let real_host = test_host([0x11; 32], [0x12; 32], 10_000);
        let impostor_root = RootKey::from_seed([0x77; 32]);
        let cap = issue_capability(
            &impostor_root.public_key(), // host_fp/host_root_pk declare the impostor root...
            &real_host.op_cert,          // ...but op_cert was actually signed by real_host's root
            &real_host.op_signer,
            CapKind::Member,
            Fingerprint::of_parts(&[b"subject"]),
            0,
            2_000,
            vec![0xAA; 16],
        );
        let err = verify_capability(&cap, 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_sig_by_non_certified_key() {
        // The op cert genuinely certifies host.op_signer, but the capability is signed by some
        // other key instead — step 3 must reject even though steps 1 and 2 both pass.
        let host = test_host([0x11; 32], [0x12; 32], 10_000);
        let impostor_signer = SigningKey::from_bytes(&[0x66; 32]);
        let cap = issue_capability(
            &host.root.public_key(),
            &host.op_cert,
            &impostor_signer, // not the key op_cert.host_op_pk names
            CapKind::Member,
            Fingerprint::of_parts(&[b"subject"]),
            0,
            2_000,
            vec![0xAA; 16],
        );
        let err = verify_capability(&cap, 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }
}
