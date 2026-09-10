//! Build and verify the device bootstrap state bundle (DESIGN.md §A4 "Adding a device (device
//! bootstrap)", :317-330; see also `crates/spindle-proto/src/bootstrap.rs`'s module doc for why
//! this bundle is unsigned and NOT one of A7b's eight signed artifacts). `spindle-proto::bootstrap`
//! carries the wire shape only (A9c boundary rule 3: it has zero crypto dependencies); everything
//! that touches a key or a hash — building a real bundle, verifying one, and deriving `host_fp`
//! and each host's `device_fp` — lives here.
//!
//! Neither derived value is ever present on the wire (DESIGN.md :320-322: "derived, never
//! carried ... so no field of an entry can disagree with another"):
//! - `host_fp = SHA-256(member_cap.host_root_pk)` — the same check [`super::verify_capability`]'s
//!   step 1 already performs.
//! - `host_device_fp = device_fp_of(ALG_ID_V1, sign_pk, agree_pk)`.

use super::{parse_verifying_key, ArtifactError};
use crate::fingerprint::Fingerprint;
use crate::identity::{self, device_fp_of};
use ed25519_dalek::VerifyingKey;
use spindle_proto::artifacts::Capability;
use spindle_proto::bootstrap::{
    BundleEntry, DeviceBootstrapBundle, BUNDLE_CURRENT_V, BUNDLE_MIN_V, MAX_BUNDLE_ENTRIES,
    MAX_REGISTRY_LEN, QR_V40_L_CAPACITY_BYTES, QR_V40_M_CAPACITY_BYTES,
};
use thiserror::Error;
use x25519_dalek::PublicKey as X25519PublicKey;

// ================================================================================================
// QrEcLevel
// ================================================================================================

/// Which ISO/IEC 18004 version-40 QR error-correction level a bundle is being sized for. Both
/// byte-mode data capacities below are spec constants (`spindle_proto::bootstrap`'s
/// [`QR_V40_L_CAPACITY_BYTES`] / [`QR_V40_M_CAPACITY_BYTES`]), not measurements of this crate's own
/// output — see [`build_bootstrap_bundle`]'s doc comment for how the real encoding is checked
/// against them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrEcLevel {
    /// ISO/IEC 18004 version-40 byte-mode capacity at EC level L: [`QR_V40_L_CAPACITY_BYTES`]
    /// bytes. Higher capacity, lower error tolerance — DESIGN.md :328-329's "5 hosts at level L".
    L,
    /// ISO/IEC 18004 version-40 byte-mode capacity at EC level M: [`QR_V40_M_CAPACITY_BYTES`]
    /// bytes. DESIGN.md :328-329's conservative default ("4 hosts at EC level M") — the level a
    /// caller should pick unless it has a specific reason to trade error tolerance for capacity.
    M,
}

impl QrEcLevel {
    /// The byte-mode data capacity for this EC level, at QR version 40 (the largest QR version).
    pub fn budget_bytes(self) -> usize {
        match self {
            QrEcLevel::L => QR_V40_L_CAPACITY_BYTES,
            QrEcLevel::M => QR_V40_M_CAPACITY_BYTES,
        }
    }
}

// ================================================================================================
// BundleError
// ================================================================================================

/// Errors from building or verifying a [`DeviceBootstrapBundle`]. Unlike [`ArtifactError`] (the
/// A7b signed-artifact catalog's error type), this one also covers the QR fit check, which has no
/// equivalent among the signed artifacts.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BundleError {
    /// [`verify_bootstrap_bundle`]: the bundle's own `v` is below [`BUNDLE_MIN_V`] — checked once,
    /// before touching any entry (mirrors [`super::verify_capability`]'s "cheapest rejection
    /// first" ordering). This is a distinct variant from [`ArtifactError::VersionTooLow`] rather
    /// than a reuse of it: the bundle is not an A7b signed artifact (see this module's doc
    /// comment), so its version floor is not an `ArtifactError` concern.
    #[error("bundle version {found} is below the minimum {minimum}")]
    VersionTooLow { found: u8, minimum: u8 },

    /// [`build_bootstrap_bundle`] / [`verify_bootstrap_bundle`]: `entries.len()` exceeds
    /// [`MAX_BUNDLE_ENTRIES`] (DESIGN.md :329's 32-host presentation cap). Checked before any
    /// per-entry or QR-fit work in both directions.
    #[error("bundle has {found} entries, exceeding the {max}-entry cap")]
    TooManyEntries { found: usize, max: usize },

    /// [`build_bootstrap_bundle`]: `registry`'s length in UTF-8 bytes exceeds
    /// [`MAX_REGISTRY_LEN`]. Checked before any encoding work, so a bundle that would fail
    /// [`DeviceBootstrapBundle::from_cbor`]'s own `MAX_REGISTRY_LEN` check on decode is never
    /// produced in the first place — see this module's doc comment for why the builder must not
    /// be allowed to emit a bundle its own decoder would reject.
    ///
    /// REDACTION DISCIPLINE: same as [`TooLargeForQr`](Self::TooLargeForQr) below — `#[error(...)]`
    /// reports only `actual`/`max`, a length and a cap, never the `registry` string itself.
    #[error("bundle registry is {actual} bytes long, exceeding the {max}-byte cap")]
    RegistryTooLong { max: usize, actual: usize },

    /// [`verify_bootstrap_bundle`]: entry `index` failed verification. `source` is whichever
    /// [`ArtifactError`] the per-entry checks produced — bad key encoding, a failed
    /// `verify_capability`, or a `host_fp` derivation failure.
    #[error("bundle entry {index} failed verification: {source}")]
    Entry { index: usize, source: ArtifactError },

    /// [`build_bootstrap_bundle`]: the bundle's real canonical encoding exceeds `ec_level`'s
    /// budget even after every candidate prefix length was tried. `fits` is the largest number of
    /// leading entries that DOES fit; `dropped` names every host beyond that prefix, in order.
    ///
    /// REDACTION DISCIPLINE: [`Fingerprint`]'s own `Display` emits the full base32 form of a
    /// fingerprint (see that type's module doc comment), and an error's `Display` is exactly what
    /// reaches `tracing` when this error is logged. This variant's `#[error(...)]` string
    /// therefore prints only `dropped.len()` — a count — and NEVER the `dropped` field's contents.
    /// `dropped` still carries the actual fingerprints, for the UI to render to the person doing
    /// the enrollment ("Alex, Office NAS, and 2 more didn't fit — re-invite from Settings"); it
    /// must never be interpolated into this variant's `Display`. This repo fixed three Display
    /// leaks like this one last week (see `crate::fingerprint::RedactedFingerprint`'s doc comment
    /// for the general policy) — this comment exists so a future edit doesn't add a fourth.
    #[error(
        "bundle encodes to {encoded_bytes} bytes, exceeding the {budget_bytes}-byte QR budget \
         at EC level {ec_level:?}; kept {fits} entries, dropped {} host(s) to fit",
        dropped.len()
    )]
    TooLargeForQr {
        ec_level: QrEcLevel,
        budget_bytes: usize,
        encoded_bytes: usize,
        fits: usize,
        dropped: Vec<Fingerprint>,
    },
}

// ================================================================================================
// build_bootstrap_bundle
// ================================================================================================

/// Builds a [`DeviceBootstrapBundle`] at [`BUNDLE_CURRENT_V`] and checks it against the printed
/// QR's real byte budget.
///
/// **`registry` is validated against [`MAX_REGISTRY_LEN`] before any encoding work**, so this
/// function can never emit a bundle that [`DeviceBootstrapBundle::from_cbor`]'s own
/// `MAX_REGISTRY_LEN` check would then reject on decode — a build/decode asymmetry this function
/// used to allow. This also guarantees the overflow branch below never has to consider a
/// `registry` alone large enough to bust the QR budget; see that branch's comment for why that
/// guarantee is what makes the empty-prefix case provably unreachable.
///
/// **The fit check measures the REAL canonical encoding, never
/// [`spindle_proto::bootstrap::MEASURED_ENTRY_BYTES`].** That constant is documentation for
/// DESIGN.md :328-329's "4 hosts at EC level M, 5 at level L" figures only — it is not a lower
/// bound this function is allowed to trust. A future artifact (e.g. a larger op-cert chain, or a
/// second cap embedded per entry) could grow a single entry's encoding well past 504 B; measuring
/// the real bytes here means such a change is caught by this check automatically, rather than
/// silently producing a bundle that fails to scan once printed.
///
/// On overflow, this function finds the largest prefix of `entries` that DOES fit by encoding
/// candidate bundles for `n` descending from `entries.len() - 1` down to `0` — at most
/// [`MAX_BUNDLE_ENTRIES`] (32) candidates, each a re-encode of at most 32 entries, so the O(n²)
/// cost is free in practice. It returns [`BundleError::TooLargeForQr`] naming the largest fitting
/// prefix (`fits`) and the `host_fp` of every entry beyond it (`dropped`), so the caller can tell
/// the person doing the enrollment exactly which hosts didn't make it in and let them re-invite
/// the new device to the remainder later (DESIGN.md :329: "fails loudly ... naming the hosts left
/// out").
///
/// **This function does NOT run [`super::verify_capability`] on any entry.** The primary device
/// already holds these capabilities — that's what makes it the primary for these hosts — and an
/// expired one is still useful to hand to the new device: the new device only needs to *connect*
/// to learn it should refresh, not present a live capability up front (DESIGN.md :286, :289-290).
/// Rejecting an expired-but-otherwise-valid capability here would make bundle construction less
/// useful than doing nothing at all. Verification is entirely a decode-side duty — see
/// [`verify_bootstrap_bundle`]. Do not add a `verify_capability` call here.
pub fn build_bootstrap_bundle(
    registry: &str,
    entries: Vec<BundleEntry>,
    ec_level: QrEcLevel,
) -> Result<DeviceBootstrapBundle, BundleError> {
    // `str::len()` is already UTF-8 BYTES, not chars or UTF-16 code units — this matches
    // `DeviceBootstrapBundle::from_cbor`'s own `registry.len()` check exactly, and matches the
    // TypeScript twin's `textEncoder.encode(registry).length` (never `registry.length`, which is
    // UTF-16 code units and would disagree with this byte count for any non-ASCII registry).
    let registry_len = registry.len();
    if registry_len > MAX_REGISTRY_LEN {
        return Err(BundleError::RegistryTooLong {
            max: MAX_REGISTRY_LEN,
            actual: registry_len,
        });
    }

    if entries.len() > MAX_BUNDLE_ENTRIES {
        return Err(BundleError::TooManyEntries {
            found: entries.len(),
            max: MAX_BUNDLE_ENTRIES,
        });
    }

    let bundle = DeviceBootstrapBundle {
        v: BUNDLE_CURRENT_V,
        registry: registry.to_string(),
        entries,
    };

    let budget_bytes = ec_level.budget_bytes();
    let encoded_bytes = bundle.to_canonical_bytes().len();
    if encoded_bytes <= budget_bytes {
        return Ok(bundle);
    }

    // Overflow: find the largest fitting prefix by trying n descending from len - 1 to 0. The
    // full-length bundle (n == entries.len()) already failed above, so it is not retried.
    let DeviceBootstrapBundle {
        v,
        registry,
        entries,
    } = bundle;
    let mut fits: Option<usize> = None;
    for n in (0..entries.len()).rev() {
        let candidate = DeviceBootstrapBundle {
            v,
            registry: registry.clone(),
            entries: entries[..n].to_vec(),
        };
        if candidate.to_canonical_bytes().len() <= budget_bytes {
            fits = Some(n);
            break;
        }
    }
    // PROVABLY UNREACHABLE, not a silent fallback: this loop always tries n == 0 last (the
    // empty-entries candidate), and that candidate is guaranteed to fit. `registry` was already
    // capped at MAX_REGISTRY_LEN (256 B) above, so the n == 0 candidate's canonical encoding is
    // at most a `v` byte, an up-to-256-byte `registry` string, an empty `entries` array, and the
    // map/key overhead around them — comfortably under 300 B. `budget_bytes` is one of
    // QR_V40_M_CAPACITY_BYTES (2331 B) or QR_V40_L_CAPACITY_BYTES (2953 B), either of which leaves
    // over 2000 B of headroom over that worst case. So the loop above always breaks before
    // exhausting its range, and `fits` is always `Some`. This differs from the pre-fix code, which
    // initialized `fits` to a bare `0usize` and left that value in place — indistinguishable from a
    // genuinely-verified "zero entries fit" — if the loop never broke; that could only happen when
    // `registry` itself was unbounded, which is no longer possible. `unreachable!()` here, rather
    // than a defaulted value, means a future change that reopens this gap (e.g. shrinking a QR
    // budget constant, or raising MAX_REGISTRY_LEN) panics loudly instead of silently reintroducing
    // the bug this comment describes.
    let fits = fits.unwrap_or_else(|| {
        unreachable!(
            "empty-entries bundle (registry <= {MAX_REGISTRY_LEN} B) exceeded the \
             {budget_bytes}-byte QR budget at {ec_level:?} — MAX_REGISTRY_LEN or a QR budget \
             constant must have changed since this invariant was last proven; re-derive it before \
             removing this panic"
        )
    });

    // host_fp is derived from each dropped entry's own host_root_pk (SHA-256 of the raw key
    // bytes), never trusted from the nested capability's carried `host_fp` field — the same
    // derived-not-carried discipline this module's doc comment describes for the bundle as a
    // whole, applied here even though the builder does not otherwise verify these capabilities.
    let dropped: Vec<Fingerprint> = entries[fits..]
        .iter()
        .map(|entry| Fingerprint::of_parts(&[&entry.member_cap.host_root_pk]))
        .collect();

    Err(BundleError::TooLargeForQr {
        ec_level,
        budget_bytes,
        encoded_bytes,
        fits,
        dropped,
    })
}

// ================================================================================================
// verify_bootstrap_bundle
// ================================================================================================

/// One [`BundleEntry`] after verification: the two derived fingerprints, the parsed keys, and the
/// verified capability. `sign_pk`/`agree_pk` are the **host's** envelope keys (see
/// [`BundleEntry`]'s own doc comment), not the new device's.
#[derive(Debug, Clone)]
pub struct VerifiedBundleEntry {
    /// `SHA-256(member_cap.host_root_pk)` — derived, and only reachable after
    /// [`super::verify_capability`] has already confirmed this equals `member_cap.host_fp`.
    pub host_fp: Fingerprint,
    /// `device_fp_of(ALG_ID_V1, sign_pk, agree_pk)` — this host's envelope identity.
    pub host_device_fp: Fingerprint,
    /// The host's envelope Ed25519 verifying key.
    pub sign_pk: VerifyingKey,
    /// The host's envelope X25519 public key.
    pub agree_pk: X25519PublicKey,
    /// The verified membership capability for this host.
    pub member_cap: Capability,
}

/// A [`DeviceBootstrapBundle`] after every entry has been verified.
#[derive(Debug, Clone)]
pub struct VerifiedBundle {
    pub registry: String,
    pub entries: Vec<VerifiedBundleEntry>,
}

/// Verifies every entry of a [`DeviceBootstrapBundle`] and derives each entry's `host_fp` and
/// `host_device_fp`. Order (cheapest rejection first, mirroring
/// [`super::verify_capability`]'s own ordering):
///
/// 0. [`BUNDLE_MIN_V`] floor on `bundle.v` — once, before touching any entry.
/// 1. `bundle.entries.len() <= `[`MAX_BUNDLE_ENTRIES`].
/// 2. Per entry, in order:
///    - a. `sign_pk` parses as Ed25519 ([`super::parse_verifying_key`]); `agree_pk` parses as a
///      32-byte X25519 key (the exact idiom `host_device_cert.rs` uses for the same two fields).
///    - b. `host_device_fp = device_fp_of(ALG_ID_V1, sign_pk, agree_pk)`.
///    - c. [`super::verify_capability`] — this is the step this bundle's acceptance criterion
///      names; it already enforces `host_fp == SHA-256(host_root_pk)`.
///    - d. `host_fp = Fingerprint::from_slice(member_cap.host_fp)` — safe only after (c) has
///      already proven `member_cap.host_fp` is exactly 32 bytes and self-consistent.
///
///    Any per-entry failure surfaces as [`BundleError::Entry`], carrying that entry's index.
///
/// **`ALG_ID_V1` is assumed, not read from the wire**: [`device_fp_of`] takes an `alg_id`
/// parameter, but [`BundleEntry`] carries no `alg_id` field for the host's envelope keys, so this
/// call site still hashes the constant rather than a carried value. The devices table's own
/// `device_fp_of` call used to share this same assumption, but no longer does: td-6c01e3 landed
/// `devices.alg_id` as a persisted column (`SCHEMA_V9`), `Device` now carries `alg_id: Option<u8>`,
/// and `authorize.rs`'s check 8 denies a device outright, before the binding recompute ever runs,
/// whenever its stored `alg_id` is `None` or anything other than `ALG_ID_V1`. This bundle's
/// remaining assumption is tracked separately, by open ticket td-4f520f.
///
/// Carrying `alg_id` on [`BundleEntry`] would not, by itself, let a second algorithm verify:
/// [`device_fp_of`] takes an [`ed25519_dalek::VerifyingKey`] and an [`x25519_dalek::PublicKey`], so
/// the algorithm is pinned by the *type* of the parsed keys, not by an integer alongside them.
/// Hashing a carried `alg_id = 2` while this function still parses `sign_pk`/`agree_pk` as Ed25519
/// would only manufacture a hash that matches for an entry nobody here can actually verify —
/// strictly worse than the current assumption. What carrying it *would* buy is the ability to
/// reject a non-v1 entry explicitly, instead of silently mis-verifying it as v1.
pub fn verify_bootstrap_bundle(
    bundle: &DeviceBootstrapBundle,
    now: u64,
) -> Result<VerifiedBundle, BundleError> {
    // 0. Version floor — cheapest possible rejection, before any per-entry work.
    if bundle.v < BUNDLE_MIN_V {
        return Err(BundleError::VersionTooLow {
            found: bundle.v,
            minimum: BUNDLE_MIN_V,
        });
    }

    // 1. Entry count cap.
    if bundle.entries.len() > MAX_BUNDLE_ENTRIES {
        return Err(BundleError::TooManyEntries {
            found: bundle.entries.len(),
            max: MAX_BUNDLE_ENTRIES,
        });
    }

    // 2. Per entry, in order.
    let mut entries = Vec::with_capacity(bundle.entries.len());
    for (index, entry) in bundle.entries.iter().enumerate() {
        let verified = verify_bundle_entry(entry, now)
            .map_err(|source| BundleError::Entry { index, source })?;
        entries.push(verified);
    }

    Ok(VerifiedBundle {
        registry: bundle.registry.clone(),
        entries,
    })
}

/// One entry's worth of step 2 in [`verify_bootstrap_bundle`]'s doc comment — pulled out so the
/// loop above can attach the entry's index to whichever [`ArtifactError`] this produces.
fn verify_bundle_entry(
    entry: &BundleEntry,
    now: u64,
) -> Result<VerifiedBundleEntry, ArtifactError> {
    // a. Parse sign_pk (Ed25519) and agree_pk (X25519) — same idiom as `host_device_cert.rs`.
    let sign_pk = parse_verifying_key(&entry.sign_pk)?;
    let agree_pk_bytes: [u8; 32] = entry
        .agree_pk
        .as_slice()
        .try_into()
        .map_err(|_| ArtifactError::InvalidPublicKey)?;
    let agree_pk = X25519PublicKey::from(agree_pk_bytes);

    // b. Derive this host's device fingerprint.
    let host_device_fp = device_fp_of(identity::ALG_ID_V1, &sign_pk, &agree_pk);

    // c. Verify the nested capability — already enforces host_fp == SHA-256(host_root_pk).
    super::verify_capability(&entry.member_cap, now)?;

    // d. Derive host_fp — safe only now that (c) has proven member_cap.host_fp is exactly 32
    // bytes and self-consistent with host_root_pk.
    let host_fp = Fingerprint::from_slice(&entry.member_cap.host_fp)
        .map_err(|_| ArtifactError::HostFingerprintMismatch)?;

    Ok(VerifiedBundleEntry {
        host_fp,
        host_device_fp,
        sign_pk,
        agree_pk,
        member_cap: entry.member_cap.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{issue_capability, issue_host_op_key_cert};
    use crate::identity::{DeviceKey, RootKey};
    use ed25519_dalek::SigningKey;
    use spindle_proto::artifacts::{CapKind, HostOpKeyCert};
    use spindle_proto::bootstrap::MEASURED_ENTRY_BYTES;

    /// A full test host: identity root + operating key + the root's certificate for that
    /// operating key — same shape as `capability.rs`'s and `host_device_cert.rs`'s `TestHost`.
    struct TestHost {
        root: RootKey,
        op_signer: SigningKey,
        op_cert: HostOpKeyCert,
    }

    fn test_host(root_seed: [u8; 32], op_seed: [u8; 32], op_cert_exp: u64) -> TestHost {
        let root = RootKey::from_seed(root_seed);
        let op_signer = SigningKey::from_bytes(&op_seed);
        let op_cert = issue_host_op_key_cert(&root, &op_signer.verifying_key(), 0, op_cert_exp);
        TestHost {
            root,
            op_signer,
            op_cert,
        }
    }

    /// One host's envelope device identity, for building the entry's `sign_pk`/`agree_pk`.
    fn host_envelope(seed: u8) -> DeviceKey {
        DeviceKey::from_seeds([seed; 32], [seed.wrapping_add(1); 32])
    }

    /// A real, mintable `BundleEntry`: a genuine host + a genuine `member` capability for it +
    /// genuine envelope keys, exactly as `build_bootstrap_bundle`'s caller would hold.
    fn real_entry(host_seed: u8, envelope_seed: u8, cap_exp: u64) -> (TestHost, BundleEntry) {
        let host = test_host([host_seed; 32], [host_seed.wrapping_add(1); 32], 10_000);
        let cap = issue_capability(
            &host.root.public_key(),
            &host.op_cert,
            &host.op_signer,
            CapKind::Member,
            host.root.root_fp(),
            0,
            cap_exp,
            vec![0xAA; 16],
        );
        let envelope = host_envelope(envelope_seed);
        let entry = BundleEntry {
            sign_pk: envelope.sign_public_key().as_bytes().to_vec(),
            agree_pk: envelope.agree_public_key().as_bytes().to_vec(),
            member_cap: cap,
        };
        (host, entry)
    }

    // ---- happy path ----

    #[test]
    fn build_then_verify_round_trips_two_entries() {
        let (host_a, entry_a) = real_entry(0x10, 0x20, 10_000);
        let (host_b, entry_b) = real_entry(0x11, 0x21, 10_000);

        let bundle = build_bootstrap_bundle(
            "nats://registry.example:4222",
            vec![entry_a, entry_b],
            QrEcLevel::M,
        )
        .expect("two real entries fit comfortably at EC level M");

        let verified = verify_bootstrap_bundle(&bundle, 1_500).expect("valid bundle verifies");
        assert_eq!(verified.registry, "nats://registry.example:4222");
        assert_eq!(verified.entries.len(), 2);

        for (verified_entry, host) in verified.entries.iter().zip([&host_a, &host_b]) {
            assert_eq!(
                verified_entry.host_fp,
                crate::identity::root_fp_of(&host.root.public_key())
            );
            let expected_device_fp = device_fp_of(
                identity::ALG_ID_V1,
                &verified_entry.sign_pk,
                &verified_entry.agree_pk,
            );
            assert_eq!(verified_entry.host_device_fp, expected_device_fp);
        }
    }

    // ---- version floor ----

    #[test]
    fn verify_rejects_v_below_floor_before_any_crypto_runs() {
        let (_host, entry) = real_entry(0x30, 0x31, 10_000);
        let mut bundle =
            build_bootstrap_bundle("nats://x:4222", vec![entry], QrEcLevel::M).expect("fits");
        bundle.v = 0;
        let err = verify_bootstrap_bundle(&bundle, 1_500).unwrap_err();
        assert_eq!(
            err,
            BundleError::VersionTooLow {
                found: 0,
                minimum: BUNDLE_MIN_V,
            }
        );
    }

    // ---- per-entry failures, with the right index ----

    #[test]
    fn rejects_expired_entry_at_the_right_index() {
        let (_host_a, entry_a) = real_entry(0x40, 0x41, 10_000);
        // entry_b's capability expires at 1_000 — well before `now` below.
        let (_host_b, entry_b) = real_entry(0x42, 0x43, 1_000);
        let bundle = build_bootstrap_bundle("nats://x:4222", vec![entry_a, entry_b], QrEcLevel::M)
            .expect("fits");

        let err = verify_bootstrap_bundle(&bundle, 1_500).unwrap_err();
        assert_eq!(
            err,
            BundleError::Entry {
                index: 1,
                source: ArtifactError::Expired,
            }
        );
    }

    #[test]
    fn rejects_entry_whose_cap_host_fp_is_corrupted() {
        // NEUTER VERIFICATION: corrupt the cap's *carried* host_fp field and confirm rejection
        // still happens (via HostFingerprintMismatch). This proves the DERIVED value
        // (SHA-256(host_root_pk), recomputed inside verify_capability) is what's authoritative —
        // a carried host_fp could never be trusted in its place, because corrupting it here is
        // caught rather than silently accepted or silently propagated into the verified output.
        let (_host, mut entry) = real_entry(0x44, 0x45, 10_000);
        entry.member_cap.host_fp[0] ^= 0xff;
        let bundle =
            build_bootstrap_bundle("nats://x:4222", vec![entry], QrEcLevel::M).expect("fits");

        let err = verify_bootstrap_bundle(&bundle, 1_500).unwrap_err();
        assert_eq!(
            err,
            BundleError::Entry {
                index: 0,
                source: ArtifactError::HostFingerprintMismatch,
            }
        );
    }

    #[test]
    fn rejects_entry_with_malformed_agree_pk() {
        let (_host, mut entry) = real_entry(0x46, 0x47, 10_000);
        entry.agree_pk = vec![0x01; 31]; // one byte short
        let bundle =
            build_bootstrap_bundle("nats://x:4222", vec![entry], QrEcLevel::M).expect("fits");

        let err = verify_bootstrap_bundle(&bundle, 1_500).unwrap_err();
        assert_eq!(
            err,
            BundleError::Entry {
                index: 0,
                source: ArtifactError::InvalidPublicKey,
            }
        );
    }

    // ---- QR fit check ----

    #[test]
    fn build_drops_entries_that_overflow_the_ec_m_budget() {
        // NEUTER VERIFICATION: deleting the fit check in `build_bootstrap_bundle` (i.e. always
        // returning `Ok(bundle)` regardless of encoded size) would make this test fail, since it
        // would never see `TooLargeForQr` at all.
        //
        // Real entries measure ~504 B each (see `keeps_measured_entry_bytes_honest` below); the
        // EC-M budget is 2331 B. 6 real entries safely exceed it regardless of small per-entry
        // size drift, while staying well under MAX_BUNDLE_ENTRIES (32).
        let entries: Vec<BundleEntry> = (0u8..6)
            .map(|i| real_entry(0x50 + i, 0x60 + i, 10_000).1)
            .collect();
        let entry_fps: Vec<Fingerprint> = entries
            .iter()
            .map(|e| Fingerprint::of_parts(&[&e.member_cap.host_root_pk]))
            .collect();

        let err = build_bootstrap_bundle("nats://x:4222", entries, QrEcLevel::M).unwrap_err();
        match err {
            BundleError::TooLargeForQr {
                ec_level,
                budget_bytes,
                fits,
                dropped,
                ..
            } => {
                assert_eq!(ec_level, QrEcLevel::M);
                assert_eq!(budget_bytes, QR_V40_M_CAPACITY_BYTES);
                assert!(fits < 6, "at least one entry must be dropped");
                assert_eq!(dropped.len(), 6 - fits);
                assert_eq!(dropped, &entry_fps[fits..]);
            }
            other => panic!("expected TooLargeForQr, got {other:?}"),
        }
    }

    #[test]
    fn too_large_for_qr_display_prints_no_fingerprint() {
        // Regression guard for the redaction discipline documented on `BundleError::TooLargeForQr`:
        // the Display string must report only the dropped COUNT, never a dropped fingerprint's
        // base32 form (which is what would reach `tracing` if this were ever logged).
        let entries: Vec<BundleEntry> = (0u8..6)
            .map(|i| real_entry(0x70 + i, 0x80 + i, 10_000).1)
            .collect();
        let dropped_fps: Vec<Fingerprint> = entries
            .iter()
            .map(|e| Fingerprint::of_parts(&[&e.member_cap.host_root_pk]))
            .collect();

        let err = build_bootstrap_bundle("nats://x:4222", entries, QrEcLevel::M).unwrap_err();
        let BundleError::TooLargeForQr { fits, dropped, .. } = &err else {
            panic!("expected TooLargeForQr, got {err:?}");
        };
        let rendered = err.to_string();
        assert!(rendered.contains(&dropped.len().to_string()));
        for fp in &dropped_fps[*fits..] {
            assert!(
                !rendered.contains(&fp.to_string()),
                "Display must never contain a dropped fingerprint's base32 form"
            );
        }
    }

    // ---- MEASURED_ENTRY_BYTES stays honest ----

    /// Like [`test_host`] but with a realistic Unix-seconds `ts` on the embedded
    /// `HostOpKeyCert`, rather than the small placeholder [`test_host`] hardcodes to `0`. Needed
    /// only by the byte-measurement tests below: an unrealistically small `ts` CBOR-encodes
    /// shorter than a real host's certificate ever would, so those tests must not reuse
    /// [`test_host`]/[`real_entry`] (see [`realistic_entry`]'s own doc comment).
    fn realistic_test_host(
        root_seed: [u8; 32],
        op_seed: [u8; 32],
        ts: u64,
        op_cert_exp: u64,
    ) -> TestHost {
        let root = RootKey::from_seed(root_seed);
        let op_signer = SigningKey::from_bytes(&op_seed);
        let op_cert = issue_host_op_key_cert(&root, &op_signer.verifying_key(), ts, op_cert_exp);
        TestHost {
            root,
            op_signer,
            op_cert,
        }
    }

    /// A real, mintable `BundleEntry` built with realistic Unix-seconds timestamps throughout —
    /// unlike [`real_entry`]'s small placeholder values (e.g. `exp = 10_000`), which CBOR-encode
    /// several bytes shorter than a real device would ever produce: CBOR's canonical integer
    /// encoding uses the shortest form that fits a value, so a small placeholder like `10_000`
    /// costs 3 bytes (1-byte header + 2-byte argument) while a realistic timestamp like
    /// `1_757_000_000` costs 5 bytes (1-byte header + 4-byte argument). Only this helper's output
    /// is safe to measure against [`MEASURED_ENTRY_BYTES`]. `cap_epoch = 7` (still small enough
    /// to encode in 1 byte either way — realism here is about matching the spec's example, not
    /// about byte width) and the cap's 16-byte nonce match this bundle's spec (td-0f4fb6).
    fn realistic_entry(host_seed: u8, envelope_seed: u8, now: u64) -> BundleEntry {
        const NINETY_DAYS: u64 = 90 * 86_400;
        const TWENTY_ONE_DAYS: u64 = 21 * 86_400;
        let host = realistic_test_host(
            [host_seed; 32],
            [host_seed.wrapping_add(1); 32],
            now,
            now + NINETY_DAYS,
        );
        let cap = issue_capability(
            &host.root.public_key(),
            &host.op_cert,
            &host.op_signer,
            CapKind::Member,
            host.root.root_fp(),
            7, // cap_epoch
            now + TWENTY_ONE_DAYS,
            vec![0xAA; 16], // 16-byte nonce, matching MEASURED_ENTRY_BYTES's own assumption
        );
        let envelope = host_envelope(envelope_seed);
        BundleEntry {
            sign_pk: envelope.sign_public_key().as_bytes().to_vec(),
            agree_pk: envelope.agree_public_key().as_bytes().to_vec(),
            member_cap: cap,
        }
    }

    #[test]
    fn keeps_measured_entry_bytes_honest() {
        // DESIGN.md :328-329's host-count figures (4 hosts at EC level M, 5 at level L, with a
        // short registry endpoint) are derived from MEASURED_ENTRY_BYTES. A genuine drift in a
        // real entry's encoded size means DESIGN.md and this constant must be updated together.
        // This figure assumes a 16-byte cap nonce — see MEASURED_ENTRY_BYTES's own doc comment
        // for why the nonce length, specifically, is what makes it move.
        //
        // Minted with realistic values (see `realistic_entry`'s doc comment): now =
        // 1_757_000_000, a 90-day op-cert exp, a 21-day cap exp, cap_epoch = 7, a 16-byte nonce.
        // Tolerance chosen from an actual measurement, not invented: this test module's real
        // entry measures 504 B, exactly MEASURED_ENTRY_BYTES — +/-2 B leaves room for a single
        // field crossing a CBOR shortest-form boundary (e.g. a timestamp ticking past a
        // power-of-two-scaled threshold between now and whenever this test next runs) without
        // being so loose it would fail to flag a genuine future drift (e.g. a larger op_cert
        // chain).
        let now = 1_757_000_000u64;
        let entry = realistic_entry(0x90, 0x91, now);
        let measured = entry.to_canonical_bytes().len();
        let tolerance = 2usize;
        assert!(
            measured.abs_diff(MEASURED_ENTRY_BYTES) <= tolerance,
            "entry encoded to {measured} B, expected within {tolerance} B of \
             MEASURED_ENTRY_BYTES ({MEASURED_ENTRY_BYTES} B) — update DESIGN.md :328-329's host \
             counts and MEASURED_ENTRY_BYTES together if this genuinely drifted"
        );
    }

    #[test]
    fn qr_ceiling_matches_the_documented_host_counts() {
        // This is what actually protects DESIGN.md :328-329's documented claim ("4 hosts at EC
        // level M, 5 at level L, with a short registry endpoint; 4 and 5 at MAX_REGISTRY_LEN") —
        // MEASURED_ENTRY_BYTES alone only documents the arithmetic that produced those numbers;
        // it does not prove them, since it is never consulted by the real fit check. This test
        // builds real bundles of real entries and checks their real encoded size against the QR
        // budget constants directly, the same way `build_bootstrap_bundle`'s fit check does.
        let now = 1_757_000_000u64;
        let short_registry = "nats://registry1:4222"; // 21 bytes, matches the doc comment
        assert_eq!(short_registry.len(), 21);

        let entries_for = |n: u8| -> Vec<BundleEntry> {
            (0..n)
                .map(|i| realistic_entry(0xA0 + i, 0xB0 + i, now))
                .collect()
        };
        let bundle_of = |registry: &str, n: u8| DeviceBootstrapBundle {
            v: BUNDLE_CURRENT_V,
            registry: registry.to_string(),
            entries: entries_for(n),
        };

        // EC level M: 4 real entries fit, 5 do not.
        let four = bundle_of(short_registry, 4).to_canonical_bytes().len();
        assert!(
            four <= QR_V40_M_CAPACITY_BYTES,
            "4 real entries with a short registry ({four} B) must fit the EC-M budget \
             ({QR_V40_M_CAPACITY_BYTES} B)"
        );
        let five = bundle_of(short_registry, 5).to_canonical_bytes().len();
        assert!(
            five > QR_V40_M_CAPACITY_BYTES,
            "5 real entries with a short registry ({five} B) must NOT fit the EC-M budget \
             ({QR_V40_M_CAPACITY_BYTES} B)"
        );

        // EC level L: 5 real entries fit, 6 do not.
        assert!(
            five <= QR_V40_L_CAPACITY_BYTES,
            "5 real entries with a short registry ({five} B) must fit the EC-L budget \
             ({QR_V40_L_CAPACITY_BYTES} B)"
        );
        let six = bundle_of(short_registry, 6).to_canonical_bytes().len();
        assert!(
            six > QR_V40_L_CAPACITY_BYTES,
            "6 real entries with a short registry ({six} B) must NOT fit the EC-L budget \
             ({QR_V40_L_CAPACITY_BYTES} B)"
        );

        // At MAX_REGISTRY_LEN, EC level M: 4 real entries fit, 5 do not — the same host count as
        // the short-registry case above (previously 3/4 before v0.9.31/td-583db5 shrank
        // HostOpKeyCert by dropping nats_fp; see MEASURED_ENTRY_BYTES's doc comment).
        let long_registry = "r".repeat(spindle_proto::bootstrap::MAX_REGISTRY_LEN);
        let four_long_registry = bundle_of(&long_registry, 4).to_canonical_bytes().len();
        assert!(
            four_long_registry <= QR_V40_M_CAPACITY_BYTES,
            "4 real entries with a MAX_REGISTRY_LEN registry ({four_long_registry} B) must fit \
             the EC-M budget ({QR_V40_M_CAPACITY_BYTES} B)"
        );
        let five_long_registry = bundle_of(&long_registry, 5).to_canonical_bytes().len();
        assert!(
            five_long_registry > QR_V40_M_CAPACITY_BYTES,
            "5 real entries with a MAX_REGISTRY_LEN registry ({five_long_registry} B) must NOT \
             fit the EC-M budget ({QR_V40_M_CAPACITY_BYTES} B)"
        );

        // At MAX_REGISTRY_LEN, EC level L: 5 real entries fit, 6 do not.
        assert!(
            five_long_registry <= QR_V40_L_CAPACITY_BYTES,
            "5 real entries with a MAX_REGISTRY_LEN registry ({five_long_registry} B) must fit \
             the EC-L budget ({QR_V40_L_CAPACITY_BYTES} B)"
        );
        let six_long_registry = bundle_of(&long_registry, 6).to_canonical_bytes().len();
        assert!(
            six_long_registry > QR_V40_L_CAPACITY_BYTES,
            "6 real entries with a MAX_REGISTRY_LEN registry ({six_long_registry} B) must NOT \
             fit the EC-L budget ({QR_V40_L_CAPACITY_BYTES} B)"
        );
    }

    // ---- MAX_BUNDLE_ENTRIES cap on build, before any fit work ----

    #[test]
    fn build_rejects_more_than_max_bundle_entries_before_fit_work() {
        let entries: Vec<BundleEntry> = (0..MAX_BUNDLE_ENTRIES as u8 + 1)
            .map(|i| real_entry(i, i.wrapping_add(100), 10_000).1)
            .collect();
        let err = build_bootstrap_bundle("nats://x:4222", entries, QrEcLevel::M).unwrap_err();
        assert_eq!(
            err,
            BundleError::TooManyEntries {
                found: MAX_BUNDLE_ENTRIES + 1,
                max: MAX_BUNDLE_ENTRIES,
            }
        );
    }

    // ---- registry length cap on build (defect: builder used to never check this) ----

    #[test]
    fn build_rejects_registry_one_byte_over_max_registry_len() {
        // BUILDER-side rejection, not merely the decoder's: before this fix, `build_bootstrap_
        // bundle` had no length check on `registry` at all, so this call would have produced a
        // bundle `DeviceBootstrapBundle::from_cbor` (the decode path) would then reject — the
        // build/decode asymmetry this fix closes.
        let registry = "r".repeat(MAX_REGISTRY_LEN + 1);
        let (_host, entry) = real_entry(0x64, 0x65, 10_000);
        let err = build_bootstrap_bundle(&registry, vec![entry], QrEcLevel::M).unwrap_err();
        assert_eq!(
            err,
            BundleError::RegistryTooLong {
                max: MAX_REGISTRY_LEN,
                actual: MAX_REGISTRY_LEN + 1,
            }
        );
    }

    #[test]
    fn build_rejects_multibyte_registry_over_byte_cap_but_under_utf16_cap() {
        // TWIN-DIVERGENCE GUARD: 100 repetitions of a 3-byte-in-UTF-8 CJK character is 300 UTF-8
        // bytes (over MAX_REGISTRY_LEN) but only 100 UTF-16 code units (well under it). Rust's
        // `str::len()` already measures UTF-8 bytes, so this mainly guards against a future
        // accidental switch to a char-counting length here; the point of this test existing in
        // both languages is that the SAME registry string is rejected for the SAME reason (byte
        // length) in both, rather than the TypeScript twin silently accepting what Rust rejects
        // because it measured `registry.length` (UTF-16 code units) instead of encoded bytes.
        let registry: String = "文".repeat(100);
        assert_eq!(
            registry.len(),
            300,
            "sanity: 100 * 3-byte-UTF-8 CJK chars is 300 bytes"
        );
        assert_eq!(
            registry.encode_utf16().count(),
            100,
            "sanity: 100 UTF-16 code units, under MAX_REGISTRY_LEN"
        );
        let (_host, entry) = real_entry(0x66, 0x67, 10_000);
        let err = build_bootstrap_bundle(&registry, vec![entry], QrEcLevel::M).unwrap_err();
        assert_eq!(
            err,
            BundleError::RegistryTooLong {
                max: MAX_REGISTRY_LEN,
                actual: 300,
            }
        );
    }

    #[test]
    fn retrying_with_fits_prefix_succeeds() {
        // This is the contract `BundleError::TooLargeForQr`'s doc comment promises ("re-calling
        // with `entries[..fits]` succeeds") and the test whose absence let the original defect
        // through: pre-fix, `fits` could be `0` without ever having been verified to actually fit,
        // making this exact retry fail. Here `fits` is reached via a genuine per-entry overflow
        // (a valid, short registry; six real entries exceed the EC-M budget) — the case the loop
        // has always computed correctly by finding a genuine break. Combined with
        // `build_never_lies_about_fits_even_with_an_oversized_registry` below (which exercises the
        // actual historical failure mode: an oversized registry that made even the empty-entries
        // candidate fail to fit), the two together prove the promise holds in general, not just
        // for the specific shape that happened to already work.
        let entries: Vec<BundleEntry> = (0u8..6)
            .map(|i| real_entry(0x68 + i, 0x78 + i, 10_000).1)
            .collect();
        let err = build_bootstrap_bundle("nats://x:4222", entries.clone(), QrEcLevel::M)
            .expect_err("6 real entries must overflow the EC-M budget");
        let BundleError::TooLargeForQr { fits, .. } = err else {
            panic!("expected TooLargeForQr, got {err:?}");
        };
        assert!(
            fits < entries.len(),
            "at least one entry must have been dropped"
        );

        let retried =
            build_bootstrap_bundle("nats://x:4222", entries[..fits].to_vec(), QrEcLevel::M);
        assert!(
            retried.is_ok(),
            "re-calling with entries[..fits] ({fits} entries) must succeed per the doc-comment \
             contract, got {retried:?}"
        );
    }

    #[test]
    fn build_never_lies_about_fits_even_with_an_oversized_registry() {
        // HISTORICAL DEFECT REPRODUCTION: this is the exact shape the adversarial review used to
        // confirm the bug by execution — an over-limit `registry` (here, far larger than even the
        // QR budget itself) plus a few real entries. Pre-fix, with no registry-length check at the
        // top of `build_bootstrap_bundle`, this call would proceed to the fit-search loop; even the
        // n == 0 (empty-entries) candidate's encoding is dominated by the oversized registry alone
        // and still exceeds `budget_bytes`, so the loop would never break and `fits` would keep its
        // uninitialized-in-truth value of `0` — indistinguishable from a genuinely verified "zero
        // entries fit". Retrying with `entries[..0]` (still carrying the same oversized registry)
        // would then fail too, exactly as the reviewer observed in both languages.
        //
        // Post-fix, this can no longer happen: the registry-length check runs before any encoding
        // work at all, so this call is rejected immediately with `RegistryTooLong` — a bundle this
        // oversized is never even attempted, and `TooLargeForQr` is never reached (let alone with a
        // lying `fits`). If this fix is reverted, this call instead returns `TooLargeForQr` (with
        // `fits == 0`), so this assertion fails.
        let oversized_registry = "r".repeat(5_000);
        let entries: Vec<BundleEntry> = (0u8..3)
            .map(|i| real_entry(0x90 + i, 0xA0 + i, 10_000).1)
            .collect();
        let err = build_bootstrap_bundle(&oversized_registry, entries, QrEcLevel::M).unwrap_err();
        assert_eq!(
            err,
            BundleError::RegistryTooLong {
                max: MAX_REGISTRY_LEN,
                actual: 5_000,
            },
            "an oversized registry must be rejected outright, never surfacing as a (lying) \
             TooLargeForQr"
        );
    }
}
