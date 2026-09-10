//! Device bootstrap state bundle wire types (DESIGN.md §A4 "Adding a device (device bootstrap)",
//! :317-330 is the design of record). When a new device joins by scanning a QR code, the primary
//! device signs the new device's certificate **and** hands it this bundle: `{registry endpoint,
//! [{sign_pk, agree_pk, member_cap}...]}` — one entry per host the primary already belongs to.
//! The QR transfers state, not just a signature: the new device walks away already knowing every
//! host's envelope keys and already holding a signed [`crate::artifacts::Capability`] for each,
//! with no further round trip through any of those hosts required before it can connect.
//!
//! # Not one of A7b's eight signed artifacts
//! Unlike [`crate::vfs_rpc`] and [`crate::signaling`] (see their module docs for that argument's
//! general shape), this bundle isn't unsigned because some other layer's signature already
//! covers it — it is unsigned because a signature here would have no verifier the channel
//! doesn't already establish. A signature exists to let a receiver who does *not* trust the
//! delivery channel confirm the bytes came from whoever it trusts. This bundle's only consumer
//! is the new device, over the *same* local QR channel that conveys the root identity itself
//! (DESIGN.md :317: "new device shows QR; the primary device signs its certificate and returns a
//! state bundle") — if that channel can be spoofed, the device's very enrollment is already
//! compromised regardless of anything this bundle carries. And the one field inside the bundle
//! that actually bears security weight, `member_cap`, is already an independently verifiable
//! signed [`crate::artifacts::Capability`] — wrapping it in a second signature would protect
//! nothing beyond what `spindle-core::verify_capability` already proves on its own. `registry`,
//! `sign_pk`, and `agree_pk` are configuration and public identifiers, not secrets a forged
//! bundle could turn into a privilege the new device doesn't already get from a valid
//! `member_cap`.
//!
//! **Hard constraint**: the above holds *only* while the bundle stays on the QR channel
//! (DESIGN.md :326-328). Relaying it over the network, through cloud sync, or via a file export
//! changes the trust picture entirely — the receiver can no longer assume delivery integrity for
//! free, so the bundle becomes a signed artifact requiring its own §A7b catalog entry: a
//! domain-separation tag, a time rule (an `exp`), and a replay rule (a nonce or single-use
//! semantics). Nothing in this module may be reused to satisfy that future entry without
//! re-deriving those three from scratch.
//!
//! # This crate carries bytes only
//! Like every other module here (A9c boundary rule 3: `spindle-proto` sits below `spindle-core`
//! in the crate graph and must not take a crypto dependency), this module only encodes/decodes
//! the bundle's CBOR shape and enforces length/count caps. It does not compute `host_fp` or
//! `device_fp`, and it does not run `verify_capability`. Both derivations, and bundle
//! construction/verification generally, live in `spindle-core::artifacts::bootstrap`:
//! - `host_fp = SHA-256(member_cap.host_root_pk)` — the same check `verify_capability` already
//!   performs as its first step.
//! - `device_fp = device_fp_of(ALG_ID_V1, sign_pk, agree_pk)`.
//!
//! Neither field is present on the wire at all (see the schema-choices table below) — DESIGN.md
//! :320-322: "derived, never carried... so no field of an entry can disagree with another."
//!
//! # Schema choices (this module's own additions to the table in `lib.rs`)
//!
//! | Choice | Decision |
//! |---|---|
//! | Wire shape | Two flat CBOR maps, `DeviceBootstrapBundle` containing an `entries` array of `BundleEntry` maps — same map-of-short-text-keys convention as every other type in this crate. |
//! | `BundleEntry.member_cap` | A nested [`crate::artifacts::Capability`] map (DESIGN.md :318's `{sign_pk, agree_pk, member_cap}`), following `AnswerPayload.member_cap`'s nested-map precedent in `signaling.rs`, not `Capability.op_cert`'s opaque-embedded-bytes precedent — a decoded-then-re-encoded `Capability` is byte-identical under canonical CBOR, so nesting it costs nothing and keeps the cap's own fields inspectable without a second decode pass. |
//! | `host_fp` / `device_fp` | Absent from the wire entirely, on both the entry and the bundle — derived on decode, never carried (DESIGN.md :320-322, quoted above). This is also this module's neuter-verification surface: see the `bundle_entry_fields_is_exactly_sign_pk_agree_pk_member_cap` and `rejects_entry_with_extra_host_fp_key` tests. |
//! | `v` field presence | The bundle carries an explicit wire-level `v` byte even though it is not one of the three A7b types (`Envelope`/`Capability`/`AdminCommand`) that get one per `lib.rs`'s schema table — every other A7b artifact instead derives its version from its domain-separation tag. This bundle has neither: it carries no tag at all (see "Not one of A7b's eight signed artifacts" above), and DESIGN.md's own notation for it omits `v`. Without either a tag or a table-driven `v`, a schema change would otherwise be invisible to an older decoder. A closed schema (`deny_unknown_fields`) plus an explicit `v` fixes that: a v2 bundle decoded by a v1 device fails with `UnknownField`, not a silent partial parse — and the two ends can genuinely ship apart (an old primary enrolling a brand-new device). Recorded as an exception row in `lib.rs`'s own schema-choices table. |
//! | Version-floor enforcement | This crate decodes `v` as a plain `u8` and carries it uninterpreted — it does **not** reject an under-floor `v`. `spindle-core` owns `check_min_v` (mirroring `Capability`'s own floor check) and is where [`BUNDLE_MIN_V`] gets enforced, on decode, before anything else in `spindle-core::artifacts::bootstrap::verify_bootstrap_bundle` runs. |
//! | Error type | A dedicated [`BundleWireError`] rather than reusing [`crate::artifacts::ProtoError`] directly — same reasoning as [`crate::signaling::SignalingError`]: this module's decode strictness needs two rejection kinds `ProtoError` has no variant for (`registry` over its length cap, too many `entries`). [`BundleWireError::Proto`] wraps `ProtoError` for every other rejection, reusing the shared `MapReader`/`canonical` decoding machinery unchanged. |
//!
//! # Redaction
//! No [`BundleWireError`] variant's `Display` echoes peer-supplied bytes or text. `registry` is
//! operator configuration rather than user data, but it still never appears in an error string —
//! only its length does, the same discipline [`crate::signaling::SignalingError::TooLong`]
//! already follows for `inbox`/`ufrag`/`pwd`/`candidate`.

use crate::artifacts::{Capability, MapReader, ProtoError};
use crate::canonical::{canonical_decode, canonical_encode, CborError, CborValue};

/// The floor `v` a decoder should accept — enforced by `spindle-core::check_min_v`, **not** by
/// this crate. See the module doc comment's "Version-floor enforcement" row.
pub const BUNDLE_MIN_V: u8 = 1;

/// The `v` this crate's callers emit when building a bundle today.
pub const BUNDLE_CURRENT_V: u8 = 1;

/// Maximum length, in bytes, of the `registry` field (a NATS registry endpoint string). Same
/// ceiling as [`crate::signaling::MAX_INBOX_LEN`] — the same scale of NATS endpoint text. No RFC
/// caps a URL length; 256 also bounds a pathological endpoint to under 9% of the QR level-L byte
/// budget ([`QR_V40_L_CAPACITY_BYTES`]) so it cannot silently eat the host list.
pub const MAX_REGISTRY_LEN: usize = 256;

/// Maximum number of [`BundleEntry`] items a [`DeviceBootstrapBundle`] may carry — DESIGN.md
/// :329's "32-host presentation cap in §A4". A decode-side DoS bound, and the ceiling
/// `spindle-core`'s QR fit check is measured against.
pub const MAX_BUNDLE_ENTRIES: usize = 32;

/// ISO/IEC 18004 version-40 QR byte-mode data capacity at error-correction level L. A spec
/// constant, not measured.
pub const QR_V40_L_CAPACITY_BYTES: usize = 2953;

/// ISO/IEC 18004 version-40 QR byte-mode data capacity at error-correction level M. A spec
/// constant, not measured.
pub const QR_V40_M_CAPACITY_BYTES: usize = 2331;

/// MEASURED 2026-09-10, not estimated: a member cap encodes to 424 B canonical (of which 143 B
/// is the embedded `op_cert`), plus two 32-byte keys — 521 B per entry. Measured with realistic
/// Unix-seconds timestamps (~1.757e9) and a **32-byte** cap nonce — `FINGERPRINT_LEN`, matching
/// what `spindle-host-core::authorize::default_member_cap_nonce` (the only `nonce_fn` any
/// production `CapIssuer` installs) actually produces. **This is now pinned, not assumed**:
/// `spindle-host-core`'s `default_member_cap_nonce_is_exactly_fingerprint_len_bytes` test asserts
/// that function's output length directly, so a future change to the production nonce length
/// turns that test red — this constant can no longer drift out from under the issuer silently the
/// way it did before td-331c11 (previously 504 B / 407 B cap, measured against a 16-byte nonce no
/// production issuer ever emitted). This figure last moved for a structural reason (not the nonce)
/// when v0.9.31 (td-583db5) dropped `HostOpKeyCert.nats_fp` — a new `HostSessionAttestation`
/// artifact took over the per-connect NATS binding instead — which shrank the embedded `op_cert`
/// from 185 B to 143 B and, with it, every figure below (previously: 449 B cap, 185 B op_cert,
/// 546 B entry, all still on the stale 16-byte-nonce basis). DESIGN.md :328-329 derives from this
/// (re-measured against the pinned 32-byte nonce, td-331c11) that a version-40 QR carries 4 hosts
/// at EC level M and 5 at level L with a short registry endpoint; at the 256-byte
/// [`MAX_REGISTRY_LEN`] ceiling it is now **3** at EC level M (DOWN from a previously documented
/// 4 — that number was measured against the stale 16-byte nonce) and 5 at level L. Measured
/// whole-bundle sizes: with a 21-byte registry, n=4 encodes to 2128 B (fits M's 2331) and n=5 to
/// 2649 B (fits L's 2953 but not M); with a 256-byte registry, n=3 is 1844 B (fits M), n=4 is
/// 2365 B (does NOT fit M's 2331 — the defect td-331c11 fixes), and n=5 is 2886 B (fits L's 2953
/// but not M). This constant is DOCUMENTATION for those figures only: `spindle-core`'s QR fit
/// check measures the real canonical encoding of each candidate bundle instead of trusting this
/// estimate.
pub const MEASURED_ENTRY_BYTES: usize = 521;

/// Errors produced while converting between the bootstrap bundle wire types and
/// [`CborValue`]/bytes. [`BundleWireError::Proto`] reuses every rejection kind [`ProtoError`]
/// already defines (missing/unknown field, wrong CBOR type, invalid enum discriminant, not-a-map,
/// non-text map key, non-canonical CBOR) — see the module doc's schema-choices table for why this
/// module does not simply use `ProtoError` directly.
///
/// No variant's `Display` echoes peer-supplied bytes or text — see the module doc comment's
/// "Redaction" section. [`BundleWireError::RegistryTooLong`] and
/// [`BundleWireError::TooManyEntries`] report only lengths/counts, never the `registry` string or
/// entry contents themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleWireError {
    /// Every rejection kind already covered by [`ProtoError`] (see that type's own variants).
    Proto(ProtoError),
    /// `registry`'s encoded length (in bytes) exceeded [`MAX_REGISTRY_LEN`].
    RegistryTooLong { max: usize, actual: usize },
    /// `entries`'s length exceeded [`MAX_BUNDLE_ENTRIES`].
    TooManyEntries { max: usize, actual: usize },
}

impl std::fmt::Display for BundleWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleWireError::Proto(e) => write!(f, "{e}"),
            BundleWireError::RegistryTooLong { max, actual } => write!(
                f,
                "field `registry` is {actual} bytes long, exceeding the {max}-byte cap"
            ),
            BundleWireError::TooManyEntries { max, actual } => write!(
                f,
                "bundle has {actual} entries, exceeding the {max}-entry cap"
            ),
        }
    }
}

impl std::error::Error for BundleWireError {}

impl BundleWireError {
    /// A log-safe `Display` view of this error — see [`RedactedBundleWireError`].
    ///
    /// Use this, never the plain `Display`, anywhere a `BundleWireError` reaches a `tracing::`
    /// call: [`BundleWireError::Proto`] can wrap [`ProtoError::UnknownField`], which carries a
    /// CBOR map key taken verbatim from the peer's bytes — and for this artifact specifically,
    /// "the peer" may be a hostile QR code a user scanned, not a channel that already authorized
    /// the sender the way a signed artifact's own verification does.
    pub fn redacted(&self) -> RedactedBundleWireError<'_> {
        RedactedBundleWireError(self)
    }
}

/// A `Display` wrapper that renders a [`BundleWireError`] with every peer-controlled byte
/// replaced by its shape — mirrors [`crate::artifacts::RedactedProtoError`] precisely, one layer
/// up. Only the [`BundleWireError::Proto`] arm needs rewriting (it delegates to
/// [`ProtoError::redacted`]); [`BundleWireError::RegistryTooLong`] and
/// [`BundleWireError::TooManyEntries`] already carry only lengths/counts (see this module's
/// "Redaction" section above), so they render exactly as their normal `Display` does.
///
/// # Why this type lives here, in `spindle-proto`, rather than one layer up
///
/// Every other unsigned wire type in this crate (`crate::signaling::SignalingError`) has no
/// redaction wrapper of its own: `spindle-net` wraps `SignalingError` in its own error type one
/// layer up, and redacts *there* (see `spindle-net::quic`'s `RedactedSignalingError`), because
/// `spindle-net` is where those bytes actually reach `tracing`. The bundle has no such
/// intermediate layer to redact in — its wire type is decoded directly by its consumer, which is
/// the *app* (Stage 7+ device-enrollment UI), not another `spindle-proto`-adjacent crate in this
/// workspace. With no intermediate crate positioned to own the redaction, it has to live at the
/// point of definition instead, or it would not exist anywhere until Stage 7 builds it — and a
/// QR code is exactly the input source (attacker-controlled, no delivery-channel trust
/// established yet) this repo's redaction policy exists to guard against.
#[derive(Debug, Clone, Copy)]
pub struct RedactedBundleWireError<'a>(pub &'a BundleWireError);

impl std::fmt::Display for RedactedBundleWireError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            BundleWireError::Proto(e) => write!(f, "{}", e.redacted()),
            safe @ (BundleWireError::RegistryTooLong { .. }
            | BundleWireError::TooManyEntries { .. }) => write!(f, "{safe}"),
        }
    }
}

impl From<ProtoError> for BundleWireError {
    fn from(e: ProtoError) -> Self {
        BundleWireError::Proto(e)
    }
}

impl From<CborError> for BundleWireError {
    fn from(e: CborError) -> Self {
        BundleWireError::Proto(ProtoError::from(e))
    }
}

// ================================================================================================
// BundleEntry
// ================================================================================================

/// One host's envelope identity plus the caller's current membership capability for it
/// (DESIGN.md :318 `{sign_pk, agree_pk, member_cap}`). `sign_pk`/`agree_pk` are the **host's**
/// envelope keys (DESIGN.md :319: "the entry names the host's envelope keys explicitly
/// [v0.9.22]" — not the host's root key, and not the new device's own keys). `host_fp` and this
/// host's `device_fp` are deliberately absent — see the module doc comment's "This crate carries
/// bytes only" section; `spindle-core::artifacts::bootstrap` derives both on decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEntry {
    /// The host's envelope Ed25519 verifying key.
    pub sign_pk: Vec<u8>,
    /// The host's envelope X25519 public key.
    pub agree_pk: Vec<u8>,
    /// The caller's current membership capability for this host (a nested map, not opaque
    /// bytes — see the module doc comment's schema-choices table).
    pub member_cap: Capability,
}

/// `BundleEntry`'s exactly-three-key closed schema, used by [`MapReader::deny_unknown_fields`].
/// Its exact contents are also this module's neuter-verification surface: the acceptance
/// criterion for this bundle requires that carrying `host_fp` rather than deriving it fail a
/// test outright, and adding any field here — `host_fp` included — changes this slice and breaks
/// `bundle_entry_fields_is_exactly_sign_pk_agree_pk_member_cap` immediately.
const BUNDLE_ENTRY_FIELDS: &[&str] = &["sign_pk", "agree_pk", "member_cap"];

impl BundleEntry {
    pub fn to_cbor(&self) -> CborValue {
        CborValue::map(vec![
            ("sign_pk", CborValue::bytes(self.sign_pk.clone())),
            ("agree_pk", CborValue::bytes(self.agree_pk.clone())),
            ("member_cap", self.member_cap.to_cbor()),
        ])
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, BundleWireError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(BUNDLE_ENTRY_FIELDS)?;
        Ok(BundleEntry {
            sign_pk: m.bytes("sign_pk")?,
            agree_pk: m.bytes("agree_pk")?,
            member_cap: Capability::from_cbor(m.require("member_cap")?)?,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BundleWireError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }
}

// ================================================================================================
// DeviceBootstrapBundle
// ================================================================================================

/// The full device bootstrap state bundle (DESIGN.md :317-330): a registry endpoint plus one
/// [`BundleEntry`] per host the primary device already belongs to. Unsigned — see the module doc
/// comment's "Not one of A7b's eight signed artifacts" section for why, and its hard constraint
/// on where this bundle may travel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceBootstrapBundle {
    /// Wire schema version. This crate decodes and carries it uninterpreted — see the module doc
    /// comment's "Version-floor enforcement" row; `spindle-core::check_min_v` owns the floor.
    pub v: u8,
    /// The registry endpoint the new device should use, capped at [`MAX_REGISTRY_LEN`] bytes.
    pub registry: String,
    /// One entry per host, capped at [`MAX_BUNDLE_ENTRIES`].
    pub entries: Vec<BundleEntry>,
}

/// `DeviceBootstrapBundle`'s closed schema, used by [`MapReader::deny_unknown_fields`].
const BUNDLE_FIELDS: &[&str] = &["v", "registry", "entries"];

impl DeviceBootstrapBundle {
    pub fn to_cbor(&self) -> CborValue {
        CborValue::map(vec![
            ("v", CborValue::uint(self.v as u64)),
            ("registry", CborValue::text(self.registry.clone())),
            (
                "entries",
                CborValue::array(self.entries.iter().map(BundleEntry::to_cbor).collect()),
            ),
        ])
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    /// Decodes and applies this module's decode-strictness rules: closed schema (unknown fields
    /// rejected on both this map and each entry's), `registry` length capped at
    /// [`MAX_REGISTRY_LEN`], `entries` count capped at [`MAX_BUNDLE_ENTRIES`]. Does **not**
    /// enforce a `v` floor — see the module doc comment's "Version-floor enforcement" row; that
    /// check belongs to `spindle-core::check_min_v`.
    pub fn from_cbor(v: &CborValue) -> Result<Self, BundleWireError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(BUNDLE_FIELDS)?;
        let version = m.u8("v")?;
        let registry = m.text("registry")?;
        let registry_len = registry.len();
        if registry_len > MAX_REGISTRY_LEN {
            return Err(BundleWireError::RegistryTooLong {
                max: MAX_REGISTRY_LEN,
                actual: registry_len,
            });
        }
        let raw_entries = m
            .require("entries")?
            .as_array()
            .ok_or(ProtoError::WrongType("entries"))?;
        if raw_entries.len() > MAX_BUNDLE_ENTRIES {
            return Err(BundleWireError::TooManyEntries {
                max: MAX_BUNDLE_ENTRIES,
                actual: raw_entries.len(),
            });
        }
        let entries = raw_entries
            .iter()
            .map(BundleEntry::from_cbor)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DeviceBootstrapBundle {
            v: version,
            registry,
            entries,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BundleWireError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CborError as RawCborError;

    /// A `Capability` with every field populated with distinct, recognizable filler — nested
    /// inside a `BundleEntry.member_cap` in the tests below. Field values are opaque to this
    /// crate (see `artifacts.rs`'s module doc comment), so any well-typed values exercise the
    /// nesting; nothing here needs to be cryptographically valid.
    fn sample_capability() -> Capability {
        Capability {
            v: crate::artifacts::CAPABILITY_CURRENT_V,
            host_fp: vec![0x01; 32],
            host_root_pk: vec![0x02; 32],
            op_cert: vec![0x03; 16],
            kind: crate::artifacts::CapKind::Member,
            subject: vec![0x04; 32],
            cap_epoch: 7,
            exp: 1_800_000_000,
            nonce: vec![0x05; 16],
            sig: vec![0x06; 64],
        }
    }

    fn sample_entry(byte: u8) -> BundleEntry {
        BundleEntry {
            sign_pk: vec![byte; 32],
            agree_pk: vec![byte.wrapping_add(1); 32],
            member_cap: sample_capability(),
        }
    }

    fn sample_bundle() -> DeviceBootstrapBundle {
        DeviceBootstrapBundle {
            v: BUNDLE_CURRENT_V,
            registry: "nats://registry.example:4222".to_string(),
            entries: vec![sample_entry(0x10), sample_entry(0x20)],
        }
    }

    // ---- round trip ----

    #[test]
    fn bundle_round_trips_with_two_entries() {
        let bundle = sample_bundle();
        let bytes = bundle.to_canonical_bytes();
        let decoded = DeviceBootstrapBundle::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, bundle);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    // ---- canonical key order ----

    #[test]
    fn bundle_keys_encode_in_canonical_length_first_order() {
        // Canonical order is length-first then bytewise: `v`(1) < `entries`(7) < `registry`(8).
        let bytes = sample_bundle().to_canonical_bytes();
        let decoded = canonical_decode(&bytes).expect("decode cbor");
        if let CborValue::Map(entries) = decoded {
            let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_text().unwrap()).collect();
            assert_eq!(keys, vec!["v", "entries", "registry"]);
        } else {
            panic!("expected a map");
        }
    }

    #[test]
    fn entry_keys_encode_in_canonical_length_first_order() {
        // `sign_pk`(7) < `agree_pk`(8) < `member_cap`(10).
        let bytes = sample_entry(0x10).to_canonical_bytes();
        let decoded = canonical_decode(&bytes).expect("decode cbor");
        if let CborValue::Map(entries) = decoded {
            let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_text().unwrap()).collect();
            assert_eq!(keys, vec!["sign_pk", "agree_pk", "member_cap"]);
        } else {
            panic!("expected a map");
        }
    }

    // ---- neuter verification: host_fp must never be carried ----

    #[test]
    fn bundle_entry_fields_is_exactly_sign_pk_agree_pk_member_cap() {
        // NEUTER-VERIFICATION test (spec acceptance criterion): the entry must carry ONLY these
        // three keys, ever. Carrying `host_fp` rather than deriving it in `spindle-core` — or
        // adding any other field — changes this slice and fails this assertion immediately,
        // before any decode-side check even runs.
        assert_eq!(BUNDLE_ENTRY_FIELDS, ["sign_pk", "agree_pk", "member_cap"]);
    }

    #[test]
    fn rejects_entry_with_extra_host_fp_key() {
        // NEUTER-VERIFICATION test: an implementation that (wrongly) carried `host_fp` on the
        // wire, rather than deriving it in `spindle-core`, must be rejected outright by the
        // closed schema — not silently accepted as an extra field.
        let mut cbor = sample_entry(0x10).to_cbor();
        if let CborValue::Map(entries) = &mut cbor {
            entries.push((CborValue::text("host_fp"), CborValue::bytes(vec![0u8; 32])));
        }
        let bytes = canonical_encode(&cbor);
        let err = BundleEntry::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            BundleWireError::Proto(ProtoError::UnknownField("host_fp".to_string()))
        );
    }

    // ---- negative test: unknown field at bundle level ----

    #[test]
    fn rejects_unknown_field_on_bundle() {
        let mut cbor = sample_bundle().to_cbor();
        if let CborValue::Map(entries) = &mut cbor {
            entries.push((CborValue::text("bogus"), CborValue::uint(1)));
        }
        let bytes = canonical_encode(&cbor);
        let err = DeviceBootstrapBundle::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            BundleWireError::Proto(ProtoError::UnknownField("bogus".to_string()))
        );
    }

    // ---- boundary lengths ----

    #[test]
    fn registry_accepts_exactly_the_cap_and_rejects_one_over() {
        let ok = DeviceBootstrapBundle {
            registry: "r".repeat(MAX_REGISTRY_LEN),
            ..sample_bundle()
        };
        assert!(DeviceBootstrapBundle::from_canonical_bytes(&ok.to_canonical_bytes()).is_ok());

        let too_long = DeviceBootstrapBundle {
            registry: "r".repeat(MAX_REGISTRY_LEN + 1),
            ..sample_bundle()
        };
        let err = DeviceBootstrapBundle::from_canonical_bytes(&too_long.to_canonical_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            BundleWireError::RegistryTooLong {
                max: MAX_REGISTRY_LEN,
                actual: MAX_REGISTRY_LEN + 1,
            }
        );
    }

    #[test]
    fn entries_accepts_exactly_the_cap_and_rejects_one_over() {
        let ok_entries: Vec<BundleEntry> =
            (0..MAX_BUNDLE_ENTRIES as u8).map(sample_entry).collect();
        let ok = DeviceBootstrapBundle {
            entries: ok_entries,
            ..sample_bundle()
        };
        assert!(DeviceBootstrapBundle::from_canonical_bytes(&ok.to_canonical_bytes()).is_ok());

        let too_many_entries: Vec<BundleEntry> = (0..MAX_BUNDLE_ENTRIES as u8 + 1)
            .map(sample_entry)
            .collect();
        let too_many = DeviceBootstrapBundle {
            entries: too_many_entries,
            ..sample_bundle()
        };
        let err = DeviceBootstrapBundle::from_canonical_bytes(&too_many.to_canonical_bytes())
            .unwrap_err();
        assert_eq!(
            err,
            BundleWireError::TooManyEntries {
                max: MAX_BUNDLE_ENTRIES,
                actual: MAX_BUNDLE_ENTRIES + 1,
            }
        );
    }

    // ---- negative tests: missing required field ----

    #[test]
    fn rejects_missing_v() {
        let cbor = CborValue::map(vec![
            ("registry", CborValue::text("nats://x:4222")),
            ("entries", CborValue::array(vec![])),
        ]);
        let bytes = canonical_encode(&cbor);
        let err = DeviceBootstrapBundle::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(err, BundleWireError::Proto(ProtoError::MissingField("v")));
    }

    #[test]
    fn rejects_missing_registry() {
        let cbor = CborValue::map(vec![
            ("v", CborValue::uint(1)),
            ("entries", CborValue::array(vec![])),
        ]);
        let bytes = canonical_encode(&cbor);
        let err = DeviceBootstrapBundle::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            BundleWireError::Proto(ProtoError::MissingField("registry"))
        );
    }

    #[test]
    fn rejects_missing_entries() {
        let cbor = CborValue::map(vec![
            ("v", CborValue::uint(1)),
            ("registry", CborValue::text("nats://x:4222")),
        ]);
        let bytes = canonical_encode(&cbor);
        let err = DeviceBootstrapBundle::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            BundleWireError::Proto(ProtoError::MissingField("entries"))
        );
    }

    // ---- negative tests: wrong CBOR major type ----

    #[test]
    fn rejects_wrong_type_for_entries() {
        let cbor = CborValue::map(vec![
            ("v", CborValue::uint(1)),
            ("registry", CborValue::text("nats://x:4222")),
            ("entries", CborValue::bytes(vec![0u8; 4])), // wrong major type: bytes, not array
        ]);
        let bytes = canonical_encode(&cbor);
        let err = DeviceBootstrapBundle::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            BundleWireError::Proto(ProtoError::WrongType("entries"))
        );
    }

    #[test]
    fn rejects_wrong_type_for_registry() {
        let cbor = CborValue::map(vec![
            ("v", CborValue::uint(1)),
            ("registry", CborValue::bytes(vec![0u8; 4])), // wrong major type: bytes, not text
            ("entries", CborValue::array(vec![])),
        ]);
        let bytes = canonical_encode(&cbor);
        let err = DeviceBootstrapBundle::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            BundleWireError::Proto(ProtoError::WrongType("registry"))
        );
    }

    // ---- negative test: non-canonical encoding ----

    /// Rewrites `bytes` (a canonical CBOR map) so that the single-byte uint value immediately
    /// following text key `key` is instead written in the non-shortest 1-byte-argument form
    /// (`0x18 <value>`) — everything else byte-identical. See `signaling.rs`'s identical helper
    /// for why this splice is safe (map/array headers encode an entry count, never a byte
    /// length, so no earlier header needs adjusting when the insert shifts everything after it).
    fn lengthen_uint_after_key(bytes: &[u8], key: &str) -> Vec<u8> {
        let key_bytes = canonical_encode(&CborValue::text(key));
        let pos = bytes
            .windows(key_bytes.len())
            .position(|w| w == key_bytes.as_slice())
            .expect("key not found in encoded bytes");
        let value_pos = pos + key_bytes.len();
        let value = bytes[value_pos];
        assert!(value < 24, "helper only supports an inline-form uint value");
        let mut out = bytes[..value_pos].to_vec();
        out.push(0x18);
        out.push(value);
        out.extend_from_slice(&bytes[value_pos + 1..]);
        out
    }

    #[test]
    fn rejects_non_canonical_encoding() {
        // A minimal (zero-entry) bundle avoids any accidental byte-pattern collision with the
        // `key` search below — the "v" text key encodes to two bytes that must appear nowhere
        // else in the map for the splice to target the right value.
        let bundle = DeviceBootstrapBundle {
            v: BUNDLE_CURRENT_V,
            registry: "nats://x:4222".to_string(),
            entries: vec![],
        };
        let canonical_bytes = bundle.to_canonical_bytes();
        let mutated = lengthen_uint_after_key(&canonical_bytes, "v");
        let err = DeviceBootstrapBundle::from_canonical_bytes(&mutated).unwrap_err();
        assert!(matches!(
            err,
            BundleWireError::Proto(ProtoError::Cbor(RawCborError::NonShortestForm { .. }))
        ));
    }

    // ---- redaction ----

    /// A [`BundleWireError::Proto(ProtoError::UnknownField(..))`] carries a CBOR map key taken
    /// verbatim from a peer's bytes — for this artifact, potentially a hostile QR code — so it
    /// must never reach a log line. `redacted()` is the log-safe view; every other variant is
    /// already content-free and must render unchanged, or the redaction would cost diagnosability
    /// it does not need to. Mirrors `artifacts.rs`'s
    /// `redacted_display_withholds_an_unknown_field_name_and_nothing_else` precisely, one layer up.
    #[test]
    fn redacted_display_withholds_an_unknown_field_name_and_nothing_else() {
        let leaky = BundleWireError::Proto(ProtoError::UnknownField("secret_key_name".to_string()));
        assert!(leaky.to_string().contains("secret_key_name"));
        let redacted = leaky.redacted().to_string();
        assert!(!redacted.contains("secret_key_name"), "{redacted}");

        let safe_variants = [
            BundleWireError::Proto(ProtoError::InvalidEnumValue("kind", 9)),
            BundleWireError::RegistryTooLong {
                max: MAX_REGISTRY_LEN,
                actual: MAX_REGISTRY_LEN + 1,
            },
            BundleWireError::TooManyEntries {
                max: MAX_BUNDLE_ENTRIES,
                actual: MAX_BUNDLE_ENTRIES + 1,
            },
        ];
        for safe in safe_variants {
            assert_eq!(safe.to_string(), safe.redacted().to_string());
        }
    }
}
