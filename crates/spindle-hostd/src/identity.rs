//! Start-up host identity: minting this process's operating key, operating-key certificate, and
//! envelope device key from the persisted root seed, plus the human recovery phrase.
//!
//! # What persists, and what is minted per process
//!
//! DESIGN.md A10.41 keeps exactly one secret across restarts: the 32-byte root **seed**, held by
//! a [`crate::keystore::HostKeyStore`]. Everything else is derived or minted fresh here:
//!
//! - **A10.41** — only the root seed persists, never the derived keypair, so `host_fp` (which is
//!   `root_fp`, see `root_fp_of`) survives a restart while nothing else about the process does.
//! - **A10.43** — the operating key is ephemeral: it is minted at every process start, certified
//!   by the root, and never stored. A restart *is* the rotation.
//! - **A10.44** — the envelope [`DeviceKey`] is ephemeral too, for the same reason and per the
//!   same rule ("exactly one of them is persisted"). That is why `device_fp` churns at every
//!   start and per-device certified state is re-certified each start.
//! - **A10.45** — mid-process certificate renewal (re-issuing the op cert and re-signing the
//!   device cert at two-thirds of the 90-day `exp`) is **not implemented here**. This module
//!   only mints at start. That is a known gap: a process alive past `HOST_OP_CERT_TTL_SECS`
//!   presents an expired op cert, so the renewal path A10.45 specifies must be built before a
//!   long-lived headless daemon can rely on this identity remaining valid for its whole life.
//!
//! # Why the recovery phrase is grouped base32
//!
//! A10.41 requires presenting the seed once, at first run, as a recovery phrase, but does not
//! specify an encoding. This module uses the repository's existing human encoding — lowercase
//! RFC 4648 base32 with no padding, [`spindle_core::base32`] — grouped in four-character groups
//! separated by single spaces: 32 bytes encode to 52 characters, i.e. exactly thirteen groups.
//! It is the smallest choice consistent with an encoding this workspace already uses everywhere
//! a 32-byte value is shown to a human, and it reuses the one implementation rather than growing
//! a second. A wordlist encoding (BIP-39-style) is deliberately **not** invented here: it would
//! need a normative wordlist and phrase-length rule shared by Rust and TypeScript, neither of
//! which A10.41 specifies.

use rand::rngs::OsRng;
use spindle_core::artifacts::{issue_host_op_key_cert, HostOpKeyCert};
use spindle_core::{base32, DeviceKey, Fingerprint, RootKey, SigningKey};

use crate::keystore::ROOT_SEED_LEN;

/// Lifetime of the host operating-key certificate: 90 days, per DESIGN.md A7b (restated by
/// A10.43/A10.44). The same value bounds the device certificate A10.45 says must be renewed
/// alongside it.
pub const HOST_OP_CERT_TTL_SECS: u64 = 90 * 24 * 60 * 60;

/// This host process's complete signing identity, minted once per start by
/// [`mint_host_identity`].
///
/// The persisted root seed is deliberately **not** a field: it lives in the
/// [`crate::keystore::HostKeyStore`] and only the derived [`RootKey`] is handed to callers.
/// `op_signing` and `op_cert` are fresh at every start (A10.43), the envelope `device` and
/// `device_fp` are fresh at every start too (A10.44), and only `host_fp` survives a restart
/// because it is `root.root_fp()` (A10.41).
pub struct HostIdentity {
    /// The host's Ed25519 identity root, derived from the persisted seed.
    pub root: RootKey,
    /// This process's operating (signing) key. Ephemeral (A10.43); never persisted.
    pub op_signing: SigningKey,
    /// `sig_host_root(host_op_pk, ts, exp)` over `op_signing`, expiring
    /// [`HOST_OP_CERT_TTL_SECS`] after minting.
    pub op_cert: HostOpKeyCert,
    /// This process's envelope device keypair. Ephemeral (A10.44); never persisted.
    pub device: DeviceKey,
    /// `root.root_fp()` — the `<hfp>` every DESIGN.md §A5 subject is scoped by, and the identity
    /// that survives a restore from the recovery phrase.
    pub host_fp: Fingerprint,
    /// `device.device_fp()` — the envelope fingerprint a peer's `to_fp` names. Changes on every
    /// start (A10.44).
    pub device_fp: Fingerprint,
}

/// Mints this process's [`HostIdentity`] from the persisted root seed at `now` (whole seconds
/// since the Unix epoch).
///
/// This function only *derives* and *generates*; it never persists anything (A10.41: only the
/// seed is persisted) and never renews mid-process (A10.45: not implemented here — see this
/// module's doc comment).
pub fn mint_host_identity(root_seed: [u8; ROOT_SEED_LEN], now: u64) -> HostIdentity {
    let root = RootKey::from_seed(root_seed);

    // A10.43: a fresh operating key at every process start, certified by the root below.
    let op_signing = SigningKey::generate(&mut OsRng);
    let op_cert = issue_host_op_key_cert(
        &root,
        &op_signing.verifying_key(),
        now,
        now + HOST_OP_CERT_TTL_SECS,
    );

    // A10.44: the envelope DeviceKey is ephemeral per process, not per renewal.
    let device = DeviceKey::generate();

    let host_fp = root.root_fp();
    let device_fp = device.device_fp();

    HostIdentity {
        root,
        op_signing,
        op_cert,
        device,
        host_fp,
        device_fp,
    }
}

/// Renders a root seed as the human recovery phrase of DESIGN.md A10.41: lowercase RFC 4648
/// base32, no padding, grouped in four-character groups separated by single spaces.
pub fn format_recovery_phrase(seed: &[u8; ROOT_SEED_LEN]) -> String {
    let encoded: Vec<char> = base32::encode_no_pad(seed).chars().collect();
    let mut phrase = String::with_capacity(encoded.len() + encoded.len() / 4);
    for (index, group) in encoded.chunks(4).enumerate() {
        if index > 0 {
            phrase.push(' ');
        }
        phrase.extend(group);
    }
    phrase
}

/// Why [`parse_recovery_phrase`] rejected a phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryPhraseError {
    /// The phrase decoded to a number of bytes other than [`ROOT_SEED_LEN`].
    #[error(
        "recovery phrase encodes {actual} bytes; a host root seed is exactly {expected} bytes"
    )]
    WrongLength { actual: usize, expected: usize },
    /// A character outside lowercase RFC 4648 base32 (`a`-`z`, `2`-`7`) survived whitespace
    /// stripping. Uppercase is rejected rather than normalized, matching
    /// [`spindle_core::base32::decode_no_pad`]'s canonicality rule.
    #[error("recovery phrase contains a character outside lowercase RFC 4648 base32 (a-z, 2-7)")]
    InvalidCharacter,
    /// The trailing bits were non-zero — a string `format_recovery_phrase` could never produce.
    #[error("recovery phrase is not canonical base32 (non-zero trailing bits)")]
    NonCanonical,
}

/// Parses the exact inverse of [`format_recovery_phrase`].
///
/// All ASCII whitespace is stripped first, so grouped, ungrouped, and line-wrapped input parse
/// identically (people copy phrases by hand, and a line break is not a different secret). The
/// decoder remains case-sensitive: lowercase only, exactly as the formatter emits.
pub fn parse_recovery_phrase(phrase: &str) -> Result<[u8; ROOT_SEED_LEN], RecoveryPhraseError> {
    let compact: String = phrase
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let bytes = base32::decode_no_pad(&compact).map_err(|error| match error {
        base32::DecodeError::InvalidChar => RecoveryPhraseError::InvalidCharacter,
        base32::DecodeError::NonCanonicalPadding => RecoveryPhraseError::NonCanonical,
    })?;
    let actual = bytes.len();
    let seed: [u8; ROOT_SEED_LEN] =
        bytes
            .try_into()
            .map_err(|_| RecoveryPhraseError::WrongLength {
                actual,
                expected: ROOT_SEED_LEN,
            })?;
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use spindle_core::artifacts::verify_host_op_key_cert;
    use spindle_core::root_fp_of;

    use super::*;

    const SEED: [u8; ROOT_SEED_LEN] = [0x5a; ROOT_SEED_LEN];
    const NOW: u64 = 1_700_000_000;

    #[test]
    fn same_seed_mints_the_same_host_fp() {
        let first = mint_host_identity(SEED, NOW);
        let second = mint_host_identity(SEED, NOW);

        assert_eq!(first.host_fp, second.host_fp);
        assert_eq!(first.host_fp, first.root.root_fp());
    }

    #[test]
    fn different_seeds_mint_different_host_fps() {
        let first = mint_host_identity([0x5a; ROOT_SEED_LEN], NOW);
        let second = mint_host_identity([0x5b; ROOT_SEED_LEN], NOW);

        assert_ne!(first.host_fp, second.host_fp);
    }

    #[test]
    fn every_mint_has_a_fresh_device_fp() {
        let first = mint_host_identity(SEED, NOW);
        let second = mint_host_identity(SEED, NOW);

        assert_ne!(first.device_fp, second.device_fp);
        assert_eq!(first.device_fp, first.device.device_fp());
    }

    #[test]
    fn op_cert_chains_to_the_root_and_covers_the_operating_key() {
        let identity = mint_host_identity(SEED, NOW);
        let root_pk = identity.root.public_key();

        verify_host_op_key_cert(&identity.op_cert, &root_pk, &root_fp_of(&root_pk), NOW)
            .expect("fresh op cert must verify at its issue time");
        verify_host_op_key_cert(
            &identity.op_cert,
            &root_pk,
            &root_fp_of(&root_pk),
            NOW + HOST_OP_CERT_TTL_SECS,
        )
        .expect("op cert must verify through its whole lifetime");
        assert_eq!(
            identity.op_cert.host_op_pk,
            identity.op_signing.verifying_key().as_bytes().to_vec()
        );
        assert_eq!(identity.op_cert.ts, NOW);
        assert_eq!(identity.op_cert.exp, NOW + HOST_OP_CERT_TTL_SECS);
    }

    #[test]
    fn phrase_round_trips_grouped_and_whitespace_free() {
        let phrase = format_recovery_phrase(&SEED);
        assert_eq!(phrase.split(' ').count(), 13);
        assert!(phrase.split(' ').all(|group| group.len() == 4));

        assert_eq!(parse_recovery_phrase(&phrase).expect("grouped"), SEED);
        assert_eq!(
            parse_recovery_phrase(&phrase.replace(' ', "")).expect("ungrouped"),
            SEED
        );
        assert_eq!(
            parse_recovery_phrase(&format!("\t{phrase}\n ")).expect("padded whitespace"),
            SEED
        );
    }

    #[test]
    fn phrase_rejects_garbage_and_wrong_lengths() {
        assert_eq!(
            parse_recovery_phrase("not a seed!!").unwrap_err(),
            RecoveryPhraseError::InvalidCharacter
        );
        assert_eq!(
            parse_recovery_phrase(&format_recovery_phrase(&SEED).to_uppercase()).unwrap_err(),
            RecoveryPhraseError::InvalidCharacter
        );
        assert_eq!(
            parse_recovery_phrase("").unwrap_err(),
            RecoveryPhraseError::WrongLength {
                actual: 0,
                expected: ROOT_SEED_LEN,
            }
        );
        // Four base32 characters decode to two bytes, not thirty-two.
        assert_eq!(
            parse_recovery_phrase("aaaa").unwrap_err(),
            RecoveryPhraseError::WrongLength {
                actual: 2,
                expected: ROOT_SEED_LEN,
            }
        );
        // A phrase encoding 31 bytes instead of 32 is the other side of the length check.
        let short_phrase = base32::encode_no_pad(&[0x5a; ROOT_SEED_LEN - 1]);
        assert_eq!(
            parse_recovery_phrase(&short_phrase).unwrap_err(),
            RecoveryPhraseError::WrongLength {
                actual: 31,
                expected: ROOT_SEED_LEN,
            }
        );
    }
}
