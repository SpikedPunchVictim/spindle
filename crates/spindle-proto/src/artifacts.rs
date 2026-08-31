//! Wire types for the A7 envelope and the seven other A7b signed-artifact kinds.
//!
//! Every type here is a thin, lossless mapping to/from [`CborValue`] plus a canonical-bytes
//! convenience wrapper. Field *values* are opaque (`Vec<u8>` for fingerprints/keys/signatures,
//! `u64` for counters/timestamps) — this crate has no crypto dependency (A9c boundary rule 3)
//! and does not know or enforce expected byte lengths for a given `alg_id`; that belongs to
//! `spindle-core`. See the schema-choices table in `lib.rs` for every representational decision
//! made here (map keys as short text strings, fingerprints/keys/sigs as byte strings, enums as
//! small unsigned integers, optional fields represented by key omission rather than CBOR null).
//!
//! Decoding is strict in two ways beyond `canonical::decode`'s own canonicality checks: a
//! missing mandatory field is rejected, and a map containing any key outside the type's declared
//! field set is rejected. This is a deliberate closed-schema choice for a v1, `v`-gated wire
//! contract — see the schema table in `lib.rs`.

use crate::canonical::{canonical_decode, canonical_encode, CborValue};
use crate::tags;
use std::fmt;

/// Errors produced while converting between wire types and [`CborValue`]/bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// The top-level CBOR item was not a map.
    NotAMap,
    /// A mandatory field was absent.
    MissingField(&'static str),
    /// A map key outside the artifact's declared field set was present.
    UnknownField(String),
    /// A map key was not a text string.
    KeyNotText,
    /// A field's CBOR value had the wrong shape (e.g. a byte string expected, an array found).
    WrongType(&'static str),
    /// An integer field's value did not fit in its Rust type (e.g. a `kind` byte > 255).
    IntOutOfRange(&'static str),
    /// An enum-valued field (e.g. `Capability.kind`) held a value outside its known set.
    InvalidEnumValue(&'static str, u64),
    /// Canonical CBOR decode failed before field extraction could begin.
    Cbor(crate::canonical::CborError),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::NotAMap => write!(f, "top-level CBOR item is not a map"),
            ProtoError::MissingField(name) => write!(f, "missing required field `{name}`"),
            ProtoError::UnknownField(name) => write!(f, "unknown field `{name}`"),
            ProtoError::KeyNotText => write!(f, "map key is not a text string"),
            ProtoError::WrongType(name) => write!(f, "field `{name}` has the wrong CBOR type"),
            ProtoError::IntOutOfRange(name) => {
                write!(f, "field `{name}` integer value is out of range")
            }
            ProtoError::InvalidEnumValue(name, v) => {
                write!(f, "field `{name}` has unrecognized enum value {v}")
            }
            ProtoError::Cbor(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProtoError {}

impl From<crate::canonical::CborError> for ProtoError {
    fn from(e: crate::canonical::CborError) -> Self {
        ProtoError::Cbor(e)
    }
}

/// Read-side helper over a decoded `CborValue::Map`: field lookup plus the closed-schema check
/// (every key must be in the caller's declared allow-list). `pub(crate)` (rather than private to
/// this module) so [`crate::vfs_rpc`] can reuse the identical field-extraction discipline for the
/// VFS RPC wire types instead of re-implementing it — same crate, same closed-schema/strict-type
/// conventions documented in `lib.rs`.
pub(crate) struct MapReader<'a> {
    entries: &'a [(CborValue, CborValue)],
}

impl<'a> MapReader<'a> {
    pub(crate) fn new(v: &'a CborValue) -> Result<Self, ProtoError> {
        let entries = v.as_map().ok_or(ProtoError::NotAMap)?;
        Ok(Self { entries })
    }

    /// Rejects the map if it contains any key not in `allowed`.
    pub(crate) fn deny_unknown_fields(&self, allowed: &[&str]) -> Result<(), ProtoError> {
        for (k, _) in self.entries {
            let key = k.as_text().ok_or(ProtoError::KeyNotText)?;
            if !allowed.contains(&key) {
                return Err(ProtoError::UnknownField(key.to_string()));
            }
        }
        Ok(())
    }

    pub(crate) fn get(&self, key: &str) -> Option<&CborValue> {
        self.entries
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    }

    pub(crate) fn require(&self, key: &'static str) -> Result<&CborValue, ProtoError> {
        self.get(key).ok_or(ProtoError::MissingField(key))
    }

    pub(crate) fn bytes(&self, key: &'static str) -> Result<Vec<u8>, ProtoError> {
        self.require(key)?
            .as_bytes()
            .map(|b| b.to_vec())
            .ok_or(ProtoError::WrongType(key))
    }

    pub(crate) fn text(&self, key: &'static str) -> Result<String, ProtoError> {
        self.require(key)?
            .as_text()
            .map(|s| s.to_string())
            .ok_or(ProtoError::WrongType(key))
    }

    pub(crate) fn u64(&self, key: &'static str) -> Result<u64, ProtoError> {
        self.require(key)?
            .as_uint()
            .ok_or(ProtoError::WrongType(key))
    }

    pub(crate) fn u8(&self, key: &'static str) -> Result<u8, ProtoError> {
        let v = self.u64(key)?;
        u8::try_from(v).map_err(|_| ProtoError::IntOutOfRange(key))
    }

    pub(crate) fn u16(&self, key: &'static str) -> Result<u16, ProtoError> {
        let v = self.u64(key)?;
        u16::try_from(v).map_err(|_| ProtoError::IntOutOfRange(key))
    }

    pub(crate) fn u32(&self, key: &'static str) -> Result<u32, ProtoError> {
        let v = self.u64(key)?;
        u32::try_from(v).map_err(|_| ProtoError::IntOutOfRange(key))
    }

    pub(crate) fn bool(&self, key: &'static str) -> Result<bool, ProtoError> {
        match self.require(key)? {
            CborValue::Bool(b) => Ok(*b),
            _ => Err(ProtoError::WrongType(key)),
        }
    }

    pub(crate) fn bytes_array(&self, key: &'static str) -> Result<Vec<Vec<u8>>, ProtoError> {
        let arr = self
            .require(key)?
            .as_array()
            .ok_or(ProtoError::WrongType(key))?;
        arr.iter()
            .map(|v| {
                v.as_bytes()
                    .map(|b| b.to_vec())
                    .ok_or(ProtoError::WrongType(key))
            })
            .collect()
    }

    pub(crate) fn optional_bytes(&self, key: &'static str) -> Result<Option<Vec<u8>>, ProtoError> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => v
                .as_bytes()
                .map(|b| Some(b.to_vec()))
                .ok_or(ProtoError::WrongType(key)),
        }
    }

    pub(crate) fn optional_u32(&self, key: &'static str) -> Result<Option<u32>, ProtoError> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => {
                let n = v.as_uint().ok_or(ProtoError::WrongType(key))?;
                Ok(Some(
                    u32::try_from(n).map_err(|_| ProtoError::IntOutOfRange(key))?,
                ))
            }
        }
    }
}

fn bytes_array_value(items: &[Vec<u8>]) -> CborValue {
    CborValue::array(items.iter().cloned().map(CborValue::bytes).collect())
}

/// `Capability.kind` (A4): `invite` (bearer, single-use) or `member` (issued post-redemption).
/// Encoded as a small unsigned integer (schema choice — see `lib.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapKind {
    Invite = 0,
    Member = 1,
}

impl CapKind {
    fn to_cbor(self) -> CborValue {
        CborValue::uint(self as u64)
    }

    fn from_u64(v: u64) -> Result<Self, ProtoError> {
        match v {
            0 => Ok(CapKind::Invite),
            1 => Ok(CapKind::Member),
            other => Err(ProtoError::InvalidEnumValue("kind", other)),
        }
    }
}

// ============================================================================================
// Envelope (A7)
// ============================================================================================

/// `Envelope { v, alg_id, from_fp, to_fp, sid, kind, seq, ts, eph_pk?, ciphertext, sig }`
/// (DESIGN.md §A7). `eph_pk` is optional (absent on non-first messages of a session once the
/// session key is established) and represented by key omission, never CBOR `null`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub v: u8,
    pub alg_id: u8,
    pub from_fp: Vec<u8>,
    pub to_fp: Vec<u8>,
    pub sid: Vec<u8>,
    pub kind: u16,
    pub seq: u64,
    pub ts: u64,
    pub eph_pk: Option<Vec<u8>>,
    pub ciphertext: Vec<u8>,
    pub sig: Vec<u8>,
}

const ENVELOPE_FIELDS: &[&str] = &[
    "v",
    "alg_id",
    "from_fp",
    "to_fp",
    "sid",
    "kind",
    "seq",
    "ts",
    "eph_pk",
    "ciphertext",
    "sig",
];

impl Envelope {
    fn header_entries(&self) -> Vec<(&str, CborValue)> {
        let mut entries = vec![
            ("v", CborValue::uint(self.v as u64)),
            ("alg_id", CborValue::uint(self.alg_id as u64)),
            ("from_fp", CborValue::bytes(self.from_fp.clone())),
            ("to_fp", CborValue::bytes(self.to_fp.clone())),
            ("sid", CborValue::bytes(self.sid.clone())),
            ("kind", CborValue::uint(self.kind as u64)),
            ("seq", CborValue::uint(self.seq)),
            ("ts", CborValue::uint(self.ts)),
        ];
        if let Some(eph_pk) = &self.eph_pk {
            entries.push(("eph_pk", CborValue::bytes(eph_pk.clone())));
        }
        entries
    }

    /// The canonical encoding of every field except `ciphertext` and `sig` — this is both the
    /// AEAD's AAD and (via [`Envelope::signing_input`]) part of the signature preimage (A7).
    pub fn header_cbor(&self) -> CborValue {
        CborValue::map(self.header_entries())
    }

    pub fn header_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.header_cbor())
    }

    pub fn to_cbor(&self) -> CborValue {
        let mut entries = self.header_entries();
        entries.push(("ciphertext", CborValue::bytes(self.ciphertext.clone())));
        entries.push(("sig", CborValue::bytes(self.sig.clone())));
        CborValue::map(entries)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, ProtoError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(ENVELOPE_FIELDS)?;
        Ok(Envelope {
            v: m.u8("v")?,
            alg_id: m.u8("alg_id")?,
            from_fp: m.bytes("from_fp")?,
            to_fp: m.bytes("to_fp")?,
            sid: m.bytes("sid")?,
            kind: m.u16("kind")?,
            seq: m.u64("seq")?,
            ts: m.u64("ts")?,
            eph_pk: m.optional_bytes("eph_pk")?,
            ciphertext: m.bytes("ciphertext")?,
            sig: m.bytes("sig")?,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }

    /// `"spindle-env-v1" || canonical(header) || ciphertext` (A7) — the Ed25519 signature
    /// preimage. Note this is *not* `tags::signing_input(tag, canonical(full envelope))`: the
    /// envelope is the one A7b artifact whose signing input is header-plus-raw-ciphertext rather
    /// than the canonical encoding of the whole signed struct minus `sig`.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = tags::signing_input(tags::ENVELOPE_V1, &self.header_canonical_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }
}

// ============================================================================================
// Capability (A4)
// ============================================================================================

/// `Capability { v, host_fp, host_root_pk, op_cert, kind, subject, cap_epoch, exp, nonce, sig }`
/// (DESIGN.md §A4, as revised by decision A10.30, 2026-08-24).
///
/// **A10.30 schema change**: the capability now carries the host **root**/op-key cert chain
/// rather than a bare operating key. Previously `host_fp` was derived from the embedded
/// operating key (`host_pk`) the host signed with, which put a capability's scoping identity one
/// key-rotation away from the root identity everyone actually pins/scopes by (§A4/§A5) — S1
/// flagged this as a real divergence between a device's capability-granted subjects and a host's
/// own `host.<host_fp>.>` subscription namespace (see `spindle-helper`'s S1 note). A10.30 fixes
/// this at the wire level:
/// - `host_fp = SHA-256(host_root_pk)` — root-derived, matching every other scoping/pinning use
///   of `host_fp` in the system.
/// - `host_root_pk` — the host's identity root public key, embedded so the capability remains
///   self-verifying (no external registry lookup needed for step 1 of verification).
/// - `op_cert` — the existing [`HostOpKeyCert`] artifact (the host root's certification of its
///   current operating key), embedded whole as its own complete canonical CBOR encoding (a byte
///   string field here, opaque to this crate — no second op-cert wire shape was invented). This
///   is what lets a capability chain root → operating key → capability signature without a
///   registry: `spindle-core::verify_capability` decodes it and re-runs
///   `spindle-core::verify_host_op_key_cert` against `host_root_pk`.
/// - `sig` — Ed25519 by the **operating key** (the same key `op_cert` certifies) over the
///   capability's own `spindle-cap-v1` signing input, unchanged from before (only the field name
///   changed, from `sig_host` to `sig`, to match the decided schema literally).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub v: u8,
    pub host_fp: Vec<u8>,
    pub host_root_pk: Vec<u8>,
    pub op_cert: Vec<u8>,
    pub kind: CapKind,
    /// `root_fp` for a `member` cap, `device_fp` for... no — per A4, `subject` is always
    /// `root_fp | device_fp` depending on cap kind; this crate does not disambiguate further,
    /// it is opaque fingerprint bytes either way.
    pub subject: Vec<u8>,
    pub cap_epoch: u64,
    pub exp: u64,
    pub nonce: Vec<u8>,
    pub sig: Vec<u8>,
}

const CAPABILITY_FIELDS: &[&str] = &[
    "v",
    "host_fp",
    "host_root_pk",
    "op_cert",
    "kind",
    "subject",
    "cap_epoch",
    "exp",
    "nonce",
    "sig",
];

impl Capability {
    fn unsigned_entries(&self) -> Vec<(&str, CborValue)> {
        vec![
            ("v", CborValue::uint(self.v as u64)),
            ("host_fp", CborValue::bytes(self.host_fp.clone())),
            ("host_root_pk", CborValue::bytes(self.host_root_pk.clone())),
            ("op_cert", CborValue::bytes(self.op_cert.clone())),
            ("kind", self.kind.to_cbor()),
            ("subject", CborValue::bytes(self.subject.clone())),
            ("cap_epoch", CborValue::uint(self.cap_epoch)),
            ("exp", CborValue::uint(self.exp)),
            ("nonce", CborValue::bytes(self.nonce.clone())),
        ]
    }

    pub fn unsigned_cbor(&self) -> CborValue {
        CborValue::map(self.unsigned_entries())
    }

    pub fn to_cbor(&self) -> CborValue {
        let mut entries = self.unsigned_entries();
        entries.push(("sig", CborValue::bytes(self.sig.clone())));
        CborValue::map(entries)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, ProtoError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(CAPABILITY_FIELDS)?;
        Ok(Capability {
            v: m.u8("v")?,
            host_fp: m.bytes("host_fp")?,
            host_root_pk: m.bytes("host_root_pk")?,
            op_cert: m.bytes("op_cert")?,
            kind: CapKind::from_u64(m.u64("kind")?)?,
            subject: m.bytes("subject")?,
            cap_epoch: m.u64("cap_epoch")?,
            exp: m.u64("exp")?,
            nonce: m.bytes("nonce")?,
            sig: m.bytes("sig")?,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }

    /// `"spindle-cap-v1" || canonical(self minus sig)` (A7b).
    pub fn signing_input(&self) -> Vec<u8> {
        tags::signing_input(
            tags::CAPABILITY_V1,
            &canonical_encode(&self.unsigned_cbor()),
        )
    }
}

// ============================================================================================
// AdmissionToken (A3b)
// ============================================================================================

/// `AdmissionToken { nonce, exp, label, quota_profile, sig_operator }` (DESIGN.md §A3b).
///
/// `exp` is encoded as an absolute Unix-seconds timestamp, consistent with every other `exp`
/// field in this crate — A3b's "exp (days)" describes the *default duration* the operator picks
/// when minting the token, not the wire unit (see the schema table in `lib.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionToken {
    pub nonce: Vec<u8>,
    pub exp: u64,
    pub label: String,
    pub quota_profile: String,
    pub sig_operator: Vec<u8>,
}

const ADMISSION_TOKEN_FIELDS: &[&str] = &["nonce", "exp", "label", "quota_profile", "sig_operator"];

impl AdmissionToken {
    fn unsigned_entries(&self) -> Vec<(&str, CborValue)> {
        vec![
            ("nonce", CborValue::bytes(self.nonce.clone())),
            ("exp", CborValue::uint(self.exp)),
            ("label", CborValue::text(self.label.clone())),
            ("quota_profile", CborValue::text(self.quota_profile.clone())),
        ]
    }

    pub fn unsigned_cbor(&self) -> CborValue {
        CborValue::map(self.unsigned_entries())
    }

    pub fn to_cbor(&self) -> CborValue {
        let mut entries = self.unsigned_entries();
        entries.push(("sig_operator", CborValue::bytes(self.sig_operator.clone())));
        CborValue::map(entries)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, ProtoError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(ADMISSION_TOKEN_FIELDS)?;
        Ok(AdmissionToken {
            nonce: m.bytes("nonce")?,
            exp: m.u64("exp")?,
            label: m.text("label")?,
            quota_profile: m.text("quota_profile")?,
            sig_operator: m.bytes("sig_operator")?,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }

    /// `"spindle-adm-v1" || canonical(self minus sig_operator)` (A7b).
    pub fn signing_input(&self) -> Vec<u8> {
        tags::signing_input(
            tags::ADMISSION_TOKEN_V1,
            &canonical_encode(&self.unsigned_cbor()),
        )
    }
}

// ============================================================================================
// DeviceCertificate (A4)
// ============================================================================================

/// `DeviceCertificate { device_fp, alg_id, sign_pk, agree_pk, nats_fp, ts, exp, sig_root }`
/// (DESIGN.md §A4).
///
/// **Label discrepancy (flagged per the task brief)**: A4's inline notation for the signature
/// itself reads `sig_root(device_fp, nats_fp, ts, label)` — appearing to include `label` in the
/// signed material. But A4's enrollment/device-bootstrap paragraph states device **labels are
/// host-local display state, renameable by the person and the host owner — never baked into
/// certificates**. Those two statements are in tension; this crate follows the later, more
/// specific rule and omits `label` entirely from `DeviceCertificate`. Baking a renameable label
/// into a signed, root-issued certificate would force a full re-sign (a root-key operation) on
/// every rename, which the "never baked into certificates" rule is clearly written to avoid — so
/// the omission is treated as the authoritative resolution rather than an oversight to preserve.
///
/// **[amended v0.9.16, A10.34]**: the certificate now also publishes `alg_id`/`sign_pk`/`agree_pk`
/// — the exact preimage `device_fp` already commits to
/// (`device_fp = base32(SHA-256("spindle-dev-v1" || alg_id || sign_pk || agree_pk))`, §A4). This
/// gives A7's `X25519(dev_self, dev_agree_peer)` term a defined source at connect time. All three
/// are signed material (present in [`DeviceCertificate::unsigned_entries`], not just
/// [`DeviceCertificate::to_cbor`]) — a verifier is expected to recompute `device_fp` from them and
/// reject on mismatch (§A7b clarification 6); this crate only carries the bytes structurally and
/// does not itself perform that recomputation or any key-length/curve validation — that belongs to
/// `spindle-core` (A9c boundary rule 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertificate {
    pub device_fp: Vec<u8>,
    pub alg_id: u8,
    pub sign_pk: Vec<u8>,
    pub agree_pk: Vec<u8>,
    pub nats_fp: Vec<u8>,
    pub ts: u64,
    pub exp: u64,
    pub sig_root: Vec<u8>,
}

const DEVICE_CERT_FIELDS: &[&str] = &[
    "device_fp",
    "alg_id",
    "sign_pk",
    "agree_pk",
    "nats_fp",
    "ts",
    "exp",
    "sig_root",
];

impl DeviceCertificate {
    fn unsigned_entries(&self) -> Vec<(&str, CborValue)> {
        vec![
            ("device_fp", CborValue::bytes(self.device_fp.clone())),
            ("alg_id", CborValue::uint(self.alg_id as u64)),
            ("sign_pk", CborValue::bytes(self.sign_pk.clone())),
            ("agree_pk", CborValue::bytes(self.agree_pk.clone())),
            ("nats_fp", CborValue::bytes(self.nats_fp.clone())),
            ("ts", CborValue::uint(self.ts)),
            ("exp", CborValue::uint(self.exp)),
        ]
    }

    pub fn unsigned_cbor(&self) -> CborValue {
        CborValue::map(self.unsigned_entries())
    }

    pub fn to_cbor(&self) -> CborValue {
        let mut entries = self.unsigned_entries();
        entries.push(("sig_root", CborValue::bytes(self.sig_root.clone())));
        CborValue::map(entries)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, ProtoError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(DEVICE_CERT_FIELDS)?;
        Ok(DeviceCertificate {
            device_fp: m.bytes("device_fp")?,
            alg_id: m.u8("alg_id")?,
            sign_pk: m.bytes("sign_pk")?,
            agree_pk: m.bytes("agree_pk")?,
            nats_fp: m.bytes("nats_fp")?,
            ts: m.u64("ts")?,
            exp: m.u64("exp")?,
            sig_root: m.bytes("sig_root")?,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }

    /// `"spindle-dev-cert-v1" || canonical(self minus sig_root)` (A7b).
    pub fn signing_input(&self) -> Vec<u8> {
        tags::signing_input(
            tags::DEVICE_CERT_V1,
            &canonical_encode(&self.unsigned_cbor()),
        )
    }
}

// ============================================================================================
// RevocationRecord (A4)
// ============================================================================================

/// `RevocationRecord { host_fp, epoch, revoked: [fp...], ts, sig }` (DESIGN.md §A4). `revoked`
/// holds `root_fp`/`device_fp` fingerprints, mixed, opaque to this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRecord {
    pub host_fp: Vec<u8>,
    pub epoch: u64,
    pub revoked: Vec<Vec<u8>>,
    pub ts: u64,
    pub sig: Vec<u8>,
}

const REVOCATION_FIELDS: &[&str] = &["host_fp", "epoch", "revoked", "ts", "sig"];

impl RevocationRecord {
    fn unsigned_entries(&self) -> Vec<(&str, CborValue)> {
        vec![
            ("host_fp", CborValue::bytes(self.host_fp.clone())),
            ("epoch", CborValue::uint(self.epoch)),
            ("revoked", bytes_array_value(&self.revoked)),
            ("ts", CborValue::uint(self.ts)),
        ]
    }

    pub fn unsigned_cbor(&self) -> CborValue {
        CborValue::map(self.unsigned_entries())
    }

    pub fn to_cbor(&self) -> CborValue {
        let mut entries = self.unsigned_entries();
        entries.push(("sig", CborValue::bytes(self.sig.clone())));
        CborValue::map(entries)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, ProtoError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(REVOCATION_FIELDS)?;
        Ok(RevocationRecord {
            host_fp: m.bytes("host_fp")?,
            epoch: m.u64("epoch")?,
            revoked: m.bytes_array("revoked")?,
            ts: m.u64("ts")?,
            sig: m.bytes("sig")?,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }

    /// `"spindle-rev-v1" || canonical(self minus sig)` (A7b).
    pub fn signing_input(&self) -> Vec<u8> {
        tags::signing_input(
            tags::REVOCATION_V1,
            &canonical_encode(&self.unsigned_cbor()),
        )
    }
}

// ============================================================================================
// AdminCommand (A3b/A7b)
// ============================================================================================

/// `AdminCommand { v, cmd, args, signer_fp, seq, nonce, ts, sig }` (DESIGN.md §A3b/§A7b).
///
/// `args` is an intentionally open CBOR value (a canonical map, typically) — the admin surface
/// covers a growing set of commands (mode switch, admit/evict, quota changes, key rotation…)
/// whose argument shapes are not enumerated in DESIGN.md; this crate carries `args` through
/// opaquely rather than pre-committing to a per-command schema at the wire-type level.
#[derive(Debug, Clone, PartialEq)]
pub struct AdminCommand {
    pub v: u8,
    pub cmd: String,
    pub args: CborValue,
    pub signer_fp: Vec<u8>,
    pub seq: u64,
    pub nonce: Vec<u8>,
    pub ts: u64,
    pub sig: Vec<u8>,
}

const ADMIN_COMMAND_FIELDS: &[&str] =
    &["v", "cmd", "args", "signer_fp", "seq", "nonce", "ts", "sig"];

impl AdminCommand {
    fn unsigned_entries(&self) -> Vec<(&str, CborValue)> {
        vec![
            ("v", CborValue::uint(self.v as u64)),
            ("cmd", CborValue::text(self.cmd.clone())),
            ("args", self.args.clone()),
            ("signer_fp", CborValue::bytes(self.signer_fp.clone())),
            ("seq", CborValue::uint(self.seq)),
            ("nonce", CborValue::bytes(self.nonce.clone())),
            ("ts", CborValue::uint(self.ts)),
        ]
    }

    pub fn unsigned_cbor(&self) -> CborValue {
        CborValue::map(self.unsigned_entries())
    }

    pub fn to_cbor(&self) -> CborValue {
        let mut entries = self.unsigned_entries();
        entries.push(("sig", CborValue::bytes(self.sig.clone())));
        CborValue::map(entries)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, ProtoError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(ADMIN_COMMAND_FIELDS)?;
        Ok(AdminCommand {
            v: m.u8("v")?,
            cmd: m.text("cmd")?,
            args: m.require("args")?.clone(),
            signer_fp: m.bytes("signer_fp")?,
            seq: m.u64("seq")?,
            nonce: m.bytes("nonce")?,
            ts: m.u64("ts")?,
            sig: m.bytes("sig")?,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }

    /// `"spindle-adm-cmd-v1" || canonical(self minus sig)` (A7b).
    pub fn signing_input(&self) -> Vec<u8> {
        tags::signing_input(
            tags::ADMIN_COMMAND_V1,
            &canonical_encode(&self.unsigned_cbor()),
        )
    }
}

// ============================================================================================
// HostOpKeyCert (A4)
// ============================================================================================

/// `HostOpKeyCert { host_op_pk, nats_fp, ts, exp, sig_host_root }` (DESIGN.md §A4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostOpKeyCert {
    pub host_op_pk: Vec<u8>,
    pub nats_fp: Vec<u8>,
    pub ts: u64,
    pub exp: u64,
    pub sig_host_root: Vec<u8>,
}

const HOST_OP_KEY_CERT_FIELDS: &[&str] = &["host_op_pk", "nats_fp", "ts", "exp", "sig_host_root"];

impl HostOpKeyCert {
    fn unsigned_entries(&self) -> Vec<(&str, CborValue)> {
        vec![
            ("host_op_pk", CborValue::bytes(self.host_op_pk.clone())),
            ("nats_fp", CborValue::bytes(self.nats_fp.clone())),
            ("ts", CborValue::uint(self.ts)),
            ("exp", CborValue::uint(self.exp)),
        ]
    }

    pub fn unsigned_cbor(&self) -> CborValue {
        CborValue::map(self.unsigned_entries())
    }

    pub fn to_cbor(&self) -> CborValue {
        let mut entries = self.unsigned_entries();
        entries.push((
            "sig_host_root",
            CborValue::bytes(self.sig_host_root.clone()),
        ));
        CborValue::map(entries)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, ProtoError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(HOST_OP_KEY_CERT_FIELDS)?;
        Ok(HostOpKeyCert {
            host_op_pk: m.bytes("host_op_pk")?,
            nats_fp: m.bytes("nats_fp")?,
            ts: m.u64("ts")?,
            exp: m.u64("exp")?,
            sig_host_root: m.bytes("sig_host_root")?,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }

    /// `"spindle-host-cert-v1" || canonical(self minus sig_host_root)` (A7b).
    pub fn signing_input(&self) -> Vec<u8> {
        tags::signing_input(
            tags::HOST_OP_KEY_CERT_V1,
            &canonical_encode(&self.unsigned_cbor()),
        )
    }
}

// ============================================================================================
// HostDeviceCert (A4/A7b, decision A10.35, 2026-08-31)
// ============================================================================================

/// `HostDeviceCert { host_fp, host_root_pk, op_cert, host_device_fp, alg_id, sign_pk, agree_pk,
/// ts, exp, sig_host_op }` (DESIGN.md §A4, as amended v0.9.16, A10.34/A10.35).
///
/// A10.35 decided a host has **two** fingerprints and they are not interchangeable: `host_fp =
/// SHA-256(host_root_pk)` scopes every §A5 NATS subject and is never an envelope field, while the
/// **host device fingerprint** is the host's §A7 envelope identity (`to_fp`/`from_fp`) and never
/// appears in a NATS subject. The host device keypair is dedicated (generated like any other
/// device — §A4 Device), certified by the host **operating** key rather than the root, chaining
/// root → op → device: `sig_host_op(host_device_fp, alg_id, sign_pk, agree_pk, ts)`. This keeps
/// the root cold (A10.30's rule) and means device-key rotation never re-walls members.
///
/// A client fetches this artifact via `helper.devcert.get.<nfp>` already pinning `host_fp` from
/// enrollment, so — exactly like [`Capability`] (decision A10.30) — this artifact is
/// **self-verifying**: it embeds `host_fp`, `host_root_pk`, and the complete canonical `op_cert`
/// encoding, needing no external registry lookup to walk root → op → device.
///
/// **Why no `nats_fp` field**: the person/device [`DeviceCertificate`] binds `nats_fp` because
/// that callout ties a NATS session key to a device identity. The host's NATS connection is
/// authenticated separately, by its own [`HostOpKeyCert`], which already carries the host's
/// `nats_fp`. This artifact is purely the §A7 envelope identity — adding `nats_fp` here would
/// duplicate (or, on a bug, contradict) the op cert's own binding rather than serve any need of
/// its own.
///
/// **[A10.34 preimage discipline, mirrored from `DeviceCertificate`]**: `alg_id`/`sign_pk`/
/// `agree_pk` are the exact preimage `host_device_fp` commits to
/// (`device_fp_of(alg_id, sign_pk, agree_pk)`, §A4) and are signed material here, not just
/// carried in `to_cbor`. A verifier is expected to recompute `host_device_fp` from them and
/// reject on mismatch, the same binding discipline as `DeviceCertificate` (§A7b clarification 6).
/// As with that type, this crate only carries the bytes structurally — no key-length, curve, or
/// `alg_id`-value validation, and no recomputation — that is `spindle-core`'s job (A9c boundary
/// rule 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDeviceCert {
    pub host_fp: Vec<u8>,
    pub host_root_pk: Vec<u8>,
    /// Complete canonical encoding of the host's current [`HostOpKeyCert`], embedded as an opaque
    /// byte string — the same "embed the whole cert, don't invent a second op-cert shape"
    /// convention [`Capability::op_cert`] already uses.
    pub op_cert: Vec<u8>,
    pub host_device_fp: Vec<u8>,
    pub alg_id: u8,
    pub sign_pk: Vec<u8>,
    pub agree_pk: Vec<u8>,
    pub ts: u64,
    pub exp: u64,
    pub sig_host_op: Vec<u8>,
}

const HOST_DEVICE_CERT_FIELDS: &[&str] = &[
    "host_fp",
    "host_root_pk",
    "op_cert",
    "host_device_fp",
    "alg_id",
    "sign_pk",
    "agree_pk",
    "ts",
    "exp",
    "sig_host_op",
];

impl HostDeviceCert {
    fn unsigned_entries(&self) -> Vec<(&str, CborValue)> {
        vec![
            ("host_fp", CborValue::bytes(self.host_fp.clone())),
            ("host_root_pk", CborValue::bytes(self.host_root_pk.clone())),
            ("op_cert", CborValue::bytes(self.op_cert.clone())),
            (
                "host_device_fp",
                CborValue::bytes(self.host_device_fp.clone()),
            ),
            ("alg_id", CborValue::uint(self.alg_id as u64)),
            ("sign_pk", CborValue::bytes(self.sign_pk.clone())),
            ("agree_pk", CborValue::bytes(self.agree_pk.clone())),
            ("ts", CborValue::uint(self.ts)),
            ("exp", CborValue::uint(self.exp)),
        ]
    }

    pub fn unsigned_cbor(&self) -> CborValue {
        CborValue::map(self.unsigned_entries())
    }

    pub fn to_cbor(&self) -> CborValue {
        let mut entries = self.unsigned_entries();
        entries.push(("sig_host_op", CborValue::bytes(self.sig_host_op.clone())));
        CborValue::map(entries)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, ProtoError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(HOST_DEVICE_CERT_FIELDS)?;
        Ok(HostDeviceCert {
            host_fp: m.bytes("host_fp")?,
            host_root_pk: m.bytes("host_root_pk")?,
            op_cert: m.bytes("op_cert")?,
            host_device_fp: m.bytes("host_device_fp")?,
            alg_id: m.u8("alg_id")?,
            sign_pk: m.bytes("sign_pk")?,
            agree_pk: m.bytes("agree_pk")?,
            ts: m.u64("ts")?,
            exp: m.u64("exp")?,
            sig_host_op: m.bytes("sig_host_op")?,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }

    /// `"spindle-host-dev-cert-v1" || canonical(self minus sig_host_op)` (A7b).
    pub fn signing_input(&self) -> Vec<u8> {
        tags::signing_input(
            tags::HOST_DEVICE_CERT_V1,
            &canonical_encode(&self.unsigned_cbor()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }
    fn sig(byte: u8) -> Vec<u8> {
        vec![byte; 64]
    }

    fn sample_envelope(with_eph_pk: bool) -> Envelope {
        Envelope {
            v: 1,
            alg_id: 1,
            from_fp: fp(0x11),
            to_fp: fp(0x22),
            sid: vec![0xaa; 16],
            kind: 2,
            seq: 42,
            ts: 1_755_907_200,
            eph_pk: with_eph_pk.then(|| vec![0xbb; 32]),
            ciphertext: vec![1, 2, 3, 4],
            sig: sig(0x99),
        }
    }

    #[test]
    fn envelope_round_trip_with_and_without_eph_pk() {
        for with_eph in [true, false] {
            let env = sample_envelope(with_eph);
            let bytes = env.to_canonical_bytes();
            let decoded = Envelope::from_canonical_bytes(&bytes).expect("decode");
            assert_eq!(decoded, env);
            assert_eq!(decoded.to_canonical_bytes(), bytes);
        }
    }

    #[test]
    fn envelope_signing_input_is_tag_header_ciphertext() {
        let env = sample_envelope(true);
        let expected = {
            let mut v = Vec::new();
            v.extend_from_slice(tags::ENVELOPE_V1);
            v.extend_from_slice(&env.header_canonical_bytes());
            v.extend_from_slice(&env.ciphertext);
            v
        };
        assert_eq!(env.signing_input(), expected);
    }

    #[test]
    fn envelope_rejects_unknown_field() {
        let env = sample_envelope(false);
        let mut entries = env.header_entries();
        entries.push(("ciphertext", CborValue::bytes(env.ciphertext.clone())));
        entries.push(("sig", CborValue::bytes(env.sig.clone())));
        entries.push(("bogus", CborValue::uint(0)));
        let bytes = canonical_encode(&CborValue::map(entries));
        let err = Envelope::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(err, ProtoError::UnknownField("bogus".to_string()));
    }

    #[test]
    fn envelope_rejects_missing_field() {
        let env = sample_envelope(false);
        let mut entries = env.header_entries();
        entries.push(("sig", CborValue::bytes(env.sig.clone())));
        // ciphertext omitted
        let bytes = canonical_encode(&CborValue::map(entries));
        let err = Envelope::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(err, ProtoError::MissingField("ciphertext"));
    }

    fn sample_capability(kind: CapKind) -> Capability {
        Capability {
            v: 1,
            host_fp: fp(0x33),
            host_root_pk: vec![0x44; 32],
            op_cert: vec![0x45; 96], // opaque embedded HostOpKeyCert canonical bytes (dummy length)
            kind,
            subject: fp(0x55),
            cap_epoch: 7,
            exp: 1_756_000_000,
            nonce: vec![0x66; 16],
            sig: sig(0x77),
        }
    }

    #[test]
    fn capability_round_trip_both_kinds() {
        for kind in [CapKind::Invite, CapKind::Member] {
            let cap = sample_capability(kind);
            let bytes = cap.to_canonical_bytes();
            let decoded = Capability::from_canonical_bytes(&bytes).expect("decode");
            assert_eq!(decoded, cap);
            assert_eq!(decoded.to_canonical_bytes(), bytes);
        }
    }

    #[test]
    fn capability_rejects_invalid_enum_value() {
        let cap = sample_capability(CapKind::Invite);
        let mut entries = cap.unsigned_entries();
        // overwrite kind with an out-of-range value
        entries.retain(|(k, _)| *k != "kind");
        entries.push(("kind", CborValue::uint(2)));
        entries.push(("sig", CborValue::bytes(cap.sig.clone())));
        let bytes = canonical_encode(&CborValue::map(entries));
        let err = Capability::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(err, ProtoError::InvalidEnumValue("kind", 2));
    }

    #[test]
    fn admission_token_round_trip() {
        let tok = AdmissionToken {
            nonce: vec![0x01; 16],
            exp: 1_756_500_000,
            label: "workshop-nas".to_string(),
            quota_profile: "default".to_string(),
            sig_operator: sig(0x02),
        };
        let bytes = tok.to_canonical_bytes();
        let decoded = AdmissionToken::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, tok);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    #[test]
    fn device_certificate_round_trip_and_no_label_field() {
        let cert = DeviceCertificate {
            device_fp: fp(0x10),
            alg_id: 1,
            sign_pk: vec![0x12; 32],
            agree_pk: vec![0x13; 32],
            nats_fp: fp(0x20),
            ts: 1_755_900_000,
            exp: 1_787_436_000,
            sig_root: sig(0x30),
        };
        let bytes = cert.to_canonical_bytes();
        let decoded = DeviceCertificate::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, cert);

        // A label field must be rejected outright (closed schema; see the discrepancy note on
        // `DeviceCertificate`).
        let mut entries = cert.unsigned_entries();
        entries.push(("label", CborValue::text("my-nas")));
        entries.push(("sig_root", CborValue::bytes(cert.sig_root.clone())));
        let bytes_with_label = canonical_encode(&CborValue::map(entries));
        let err = DeviceCertificate::from_canonical_bytes(&bytes_with_label).unwrap_err();
        assert_eq!(err, ProtoError::UnknownField("label".to_string()));
    }

    #[test]
    fn revocation_record_round_trip() {
        let rec = RevocationRecord {
            host_fp: fp(0x40),
            epoch: 3,
            revoked: vec![fp(0x50), fp(0x60)],
            ts: 1_755_910_000,
            sig: sig(0x70),
        };
        let bytes = rec.to_canonical_bytes();
        let decoded = RevocationRecord::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, rec);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    #[test]
    fn admin_command_round_trip() {
        let cmd = AdminCommand {
            v: 1,
            cmd: "evict_host".to_string(),
            args: CborValue::map(vec![("host_fp", CborValue::bytes(fp(0x80)))]),
            signer_fp: fp(0x90),
            seq: 5,
            nonce: vec![0xa0; 16],
            ts: 1_755_920_000,
            sig: sig(0xb0),
        };
        let bytes = cmd.to_canonical_bytes();
        let decoded = AdminCommand::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, cmd);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    #[test]
    fn host_op_key_cert_round_trip() {
        let cert = HostOpKeyCert {
            host_op_pk: vec![0xc0; 32],
            nats_fp: fp(0xd0),
            ts: 1_755_930_000,
            exp: 1_763_706_000,
            sig_host_root: sig(0xe0),
        };
        let bytes = cert.to_canonical_bytes();
        let decoded = HostOpKeyCert::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, cert);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    #[test]
    fn host_device_cert_round_trip() {
        let cert = HostDeviceCert {
            host_fp: fp(0xf0),
            host_root_pk: vec![0xf1; 32],
            op_cert: vec![0xf2; 96], // opaque embedded HostOpKeyCert canonical bytes (dummy length)
            host_device_fp: fp(0xf3),
            alg_id: 1,
            sign_pk: vec![0xf4; 32],
            agree_pk: vec![0xf5; 32],
            ts: 1_755_940_000,
            exp: 1_763_716_000,
            sig_host_op: sig(0xf6),
        };
        let bytes = cert.to_canonical_bytes();
        let decoded = HostDeviceCert::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, cert);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    #[test]
    fn all_eight_signing_inputs_start_with_distinct_tags() {
        let env = sample_envelope(true);
        let cap = sample_capability(CapKind::Member);
        let tok = AdmissionToken {
            nonce: vec![1],
            exp: 1,
            label: "x".into(),
            quota_profile: "y".into(),
            sig_operator: sig(1),
        };
        let cert = DeviceCertificate {
            device_fp: fp(1),
            alg_id: 1,
            sign_pk: vec![1; 32],
            agree_pk: vec![2; 32],
            nats_fp: fp(2),
            ts: 1,
            exp: 2,
            sig_root: sig(1),
        };
        let rec = RevocationRecord {
            host_fp: fp(1),
            epoch: 1,
            revoked: vec![],
            ts: 1,
            sig: sig(1),
        };
        let admin = AdminCommand {
            v: 1,
            cmd: "x".into(),
            args: CborValue::Null,
            signer_fp: fp(1),
            seq: 1,
            nonce: vec![1],
            ts: 1,
            sig: sig(1),
        };
        let host_cert = HostOpKeyCert {
            host_op_pk: vec![1; 32],
            nats_fp: fp(1),
            ts: 1,
            exp: 2,
            sig_host_root: sig(1),
        };
        let host_device_cert = HostDeviceCert {
            host_fp: fp(1),
            host_root_pk: vec![1; 32],
            op_cert: vec![1; 8],
            host_device_fp: fp(2),
            alg_id: 1,
            sign_pk: vec![1; 32],
            agree_pk: vec![2; 32],
            ts: 1,
            exp: 2,
            sig_host_op: sig(1),
        };

        let inputs = [
            env.signing_input(),
            cap.signing_input(),
            tok.signing_input(),
            cert.signing_input(),
            rec.signing_input(),
            admin.signing_input(),
            host_cert.signing_input(),
            host_device_cert.signing_input(),
        ];
        let tags = [
            tags::ENVELOPE_V1,
            tags::CAPABILITY_V1,
            tags::ADMISSION_TOKEN_V1,
            tags::DEVICE_CERT_V1,
            tags::REVOCATION_V1,
            tags::ADMIN_COMMAND_V1,
            tags::HOST_OP_KEY_CERT_V1,
            tags::HOST_DEVICE_CERT_V1,
        ];
        for (input, tag) in inputs.iter().zip(tags.iter()) {
            assert!(input.starts_with(tag));
        }
    }
}
