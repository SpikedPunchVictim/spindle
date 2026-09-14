//! Invite payload container wire types (DESIGN.md §A4's `invite` bullet and §A7b's "Not in the
//! catalog above, deliberately" paragraph, `spindle-invite-v1`). When a host admin invites a
//! person, the thing that person receives — as a QR code or a link — is not a bare capability.
//! It is this container: the already-signed `invite`-kind [`crate::artifacts::Capability`] plus
//! the transport hints the recipient needs to act on it, namely **where the registry is** and
//! **how to authenticate its TLS**.
//!
//! Without those hints a scanned capability is inert: it says who may connect and to which host
//! fingerprint, but not one byte about where to present it (DESIGN.md §A4 — "so clients need no
//! baked-in registry address"). A host has no listening address at all; it holds an outbound
//! registry connection and is addressed by fingerprint, so the registry endpoint is the only
//! address an invite *can* carry.
//!
//! # Unsigned, deliberately — read this before proposing to sign it
//!
//! This container is **not** one of §A7b's signed artifacts, and the omission is load-bearing
//! rather than an oversight. The whole invite is trusted **on first use, as one blob** — it is
//! where A10.3's `host_fp` pinning happens. An attacker who can rewrite the `endpoints` can
//! rewrite the `host_root_pk` inside `cap` in the same breath, so a signature over part of an
//! atomically-trusted blob authenticates nothing while advertising a property the trust model
//! does not provide. What a rogue endpoint actually costs is denial of service plus the metadata
//! an interceptor already read off the capability; it can never impersonate the host, because
//! every subsequent exchange is verified against the pinned `host_fp`.
//!
//! The one field that genuinely bears security weight, `cap`, is an independently verifiable
//! signed [`crate::artifacts::Capability`] — `spindle-core::verify_capability` proves it on its
//! own, and wrapping it in a second signature would prove nothing further. This mirrors
//! [`crate::bootstrap`]'s argument for the device bootstrap bundle, with one difference worth
//! stating: that bundle is unsigned because its QR channel is *already* the trust root, whereas
//! this container is unsigned because signing only *part* of a trust-on-first-use blob is
//! incoherent. Both land in the same place; the reasoning is not interchangeable.
//!
//! **Addressed, not bearer (A10.46).** The `cap` this container carries names its invitee:
//! `subject` is the invitee's identity root fingerprint, learned out of band before the invite
//! was minted. A stolen invite is therefore inert without that person's root private key. This
//! container adds no bearer-ness back — it carries no secret, and possessing it grants nothing.
//!
//! # Not a domain-separation tag
//!
//! [`INVITE_FORMAT_ID`] is a **format identifier** — what a scanner reads to know which decoder
//! to hand the bytes to — and deliberately does not live in [`crate::tags`], which owns
//! signature-preimage tags only. Nothing here is signed, so there is no preimage for a tag to
//! separate. [`INVITE_FORMAT_ID`] must never be used as a signing-preimage prefix; the test
//! `format_id_is_not_usable_as_a_signing_tag` pins it as distinct from every tag in
//! [`crate::tags`] so a later author cannot quietly promote it into one.
//!
//! # This crate carries bytes only
//!
//! Per A9c boundary rule 3, this module encodes/decodes the container's CBOR shape and enforces
//! length and count caps. It does not verify `cap`'s signature, derive `host_fp`, or open a
//! connection to any endpoint. [`base64url_encode`]/[`base64url_decode`] are hand-rolled here
//! for the same reason the canonical CBOR codec is: this crate has **zero dependencies by
//! design** (see its `Cargo.toml`), and base64url-without-padding is a great deal simpler than
//! the codec already living next door.
//!
//! # Redaction
//!
//! No [`InviteWireError`] variant's `Display` echoes peer-supplied bytes or text. An invite is
//! scanned from a QR code a user was handed — attacker-controlled input with no delivery-channel
//! trust established yet — so endpoint strings and pin bytes are reported by length and count
//! only, never by content, exactly as [`crate::bootstrap::BundleWireError`] treats `registry`.

use crate::artifacts::{Capability, MapReader, ProtoError};
use crate::canonical::{canonical_decode, canonical_encode, CborError, CborValue};

/// The format identifier a scanner uses to recognise these bytes (DESIGN.md §A7b).
///
/// **Not a domain-separation tag** — see the module doc comment's "Not a domain-separation tag"
/// section. It is deliberately absent from [`crate::tags`].
pub const INVITE_FORMAT_ID: &str = "spindle-invite-v1";

/// The floor `v` a decoder should accept. Enforced by `spindle-core::check_min_v`, **not** by
/// this crate — the same split [`crate::bootstrap::BUNDLE_MIN_V`] documents.
pub const INVITE_MIN_V: u8 = 1;

/// The `v` this crate's callers emit when building a container today.
pub const INVITE_CURRENT_V: u8 = 1;

/// Maximum length, in bytes, of a single endpoint string. Same ceiling as
/// [`crate::bootstrap::MAX_REGISTRY_LEN`] — the same scale of NATS endpoint text, and no RFC caps
/// a URL length.
pub const MAX_ENDPOINT_LEN: usize = 256;

/// Maximum number of endpoints a container may carry. The list exists for failover and
/// multi-region, not for enumeration: eight is far past any plausible registry deployment while
/// still bounding a hostile invite to under 2 KB of endpoint text alone.
pub const MAX_ENDPOINTS: usize = 8;

/// Maximum length, in bytes, of a [`TlsPin::PrivateCaRoot`]'s DER. A typical CA root is 1–2 KB;
/// this bounds the hardened profile without admitting a payload that would dwarf the capability.
///
/// Note the QR consequence, which is real and deliberately not hidden: a container carrying a
/// private CA root near this cap **will not fit** in a version-40 level-L QR code
/// ([`crate::bootstrap::QR_V40_L_CAPACITY_BYTES`] is 2953 B, and base64url inflates by 4/3). The
/// hardened profile is a link-delivered invite, not a scannable one. The baseline
/// [`TlsPin::WebPki`] case does fit comfortably; its figure is measured through the production
/// producer rather than stated here, because a number written into prose is one nothing can
/// falsify (A10.33-35 burned this ground three times).
pub const MAX_TLS_PIN_LEN: usize = 2048;

/// How the client should authenticate the registry's TLS certificate (DESIGN.md §A12 row 1's
/// optional hardened profile; §A14's "the private CA root shipped in the invite pin policy").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsPin {
    /// Baseline: validate against the platform's public web PKI roots.
    WebPki,
    /// Hardened: validate against exactly this DER-encoded CA root and nothing else.
    PrivateCaRoot(Vec<u8>),
}

impl TlsPin {
    /// The `kind` discriminant this pin encodes as. Mirrors [`crate::artifacts::CapKind`]'s
    /// integer-discriminant convention rather than inventing a string enum.
    fn kind(&self) -> u64 {
        match self {
            TlsPin::WebPki => 0,
            TlsPin::PrivateCaRoot(_) => 1,
        }
    }

    pub fn to_cbor(&self) -> CborValue {
        match self {
            // Key omission for the absent arm, per this codebase's optional-field convention:
            // a `WebPki` pin carries no root, so it carries no `root` key at all.
            TlsPin::WebPki => CborValue::map(vec![("kind", CborValue::uint(self.kind()))]),
            TlsPin::PrivateCaRoot(der) => CborValue::map(vec![
                ("kind", CborValue::uint(self.kind())),
                ("root", CborValue::bytes(der.clone())),
            ]),
        }
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, InviteWireError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(TLS_PIN_FIELDS)?;
        let kind = m.u64("kind")?;
        match kind {
            0 => {
                // A `root` alongside `kind: 0` is a contradiction, not a harmless extra: it would
                // let a sender ship a private root that every conforming client silently ignores,
                // so two implementations could disagree about which PKI was in force.
                if m.get("root").is_some() {
                    return Err(InviteWireError::WebPkiPinCarriesRoot);
                }
                Ok(TlsPin::WebPki)
            }
            1 => {
                let der = m.bytes("root")?;
                if der.len() > MAX_TLS_PIN_LEN {
                    return Err(InviteWireError::TlsPinTooLong {
                        max: MAX_TLS_PIN_LEN,
                        actual: der.len(),
                    });
                }
                if der.is_empty() {
                    return Err(InviteWireError::EmptyPrivateCaRoot);
                }
                Ok(TlsPin::PrivateCaRoot(der))
            }
            other => Err(ProtoError::InvalidEnumValue("tls_pin.kind", other).into()),
        }
    }
}

/// [`TlsPin`]'s closed schema, used by [`MapReader::deny_unknown_fields`].
const TLS_PIN_FIELDS: &[&str] = &["kind", "root"];

/// Errors produced while converting between the invite container and [`CborValue`]/bytes, or
/// while selecting an endpoint from a decoded one.
///
/// No variant's `Display` echoes peer-supplied bytes or text — see the module doc comment's
/// "Redaction" section. Lengths and counts only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteWireError {
    /// Every rejection kind already covered by [`ProtoError`].
    Proto(ProtoError),
    /// An endpoint string's length exceeded [`MAX_ENDPOINT_LEN`].
    EndpointTooLong { max: usize, actual: usize },
    /// `endpoints`'s length exceeded [`MAX_ENDPOINTS`].
    TooManyEndpoints { max: usize, actual: usize },
    /// `endpoints` was empty. An invite with nowhere to present its capability is inert, and
    /// accepting it would defer the failure to a confusing "registry degraded" much later.
    NoEndpoints,
    /// A [`TlsPin::PrivateCaRoot`]'s DER exceeded [`MAX_TLS_PIN_LEN`].
    TlsPinTooLong { max: usize, actual: usize },
    /// A `tls_pin` of kind `1` carried an empty `root`.
    EmptyPrivateCaRoot,
    /// A `tls_pin` of kind `0` (`WebPki`) also carried a `root`.
    WebPkiPinCarriesRoot,
    /// [`InvitePayload::select_endpoint`] found no endpoint whose scheme the caller supports.
    /// Reports counts only — never the endpoint text.
    NoSupportedEndpoint { offered: usize, supported: usize },
    /// [`base64url_decode`] was given text outside the base64url alphabet, or of a length no
    /// unpadded base64url encoding can produce.
    NotBase64Url,
}

impl std::fmt::Display for InviteWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InviteWireError::Proto(e) => write!(f, "{e}"),
            InviteWireError::EndpointTooLong { max, actual } => write!(
                f,
                "an endpoint is {actual} bytes long, exceeding the {max}-byte cap"
            ),
            InviteWireError::TooManyEndpoints { max, actual } => write!(
                f,
                "invite carries {actual} endpoints, exceeding the {max}-endpoint cap"
            ),
            InviteWireError::NoEndpoints => {
                write!(f, "invite carries no endpoints, so it cannot be acted on")
            }
            InviteWireError::TlsPinTooLong { max, actual } => write!(
                f,
                "tls_pin root is {actual} bytes long, exceeding the {max}-byte cap"
            ),
            InviteWireError::EmptyPrivateCaRoot => {
                write!(f, "tls_pin names a private CA root but carries no bytes")
            }
            InviteWireError::WebPkiPinCarriesRoot => {
                write!(f, "tls_pin selects web PKI but also carries a root")
            }
            InviteWireError::NoSupportedEndpoint { offered, supported } => write!(
                f,
                "none of the {offered} offered endpoints uses one of the {supported} supported \
                 schemes"
            ),
            InviteWireError::NotBase64Url => {
                write!(f, "input is not unpadded base64url")
            }
        }
    }
}

impl std::error::Error for InviteWireError {}

impl From<ProtoError> for InviteWireError {
    fn from(e: ProtoError) -> Self {
        InviteWireError::Proto(e)
    }
}

impl From<CborError> for InviteWireError {
    fn from(e: CborError) -> Self {
        InviteWireError::Proto(ProtoError::from(e))
    }
}

impl InviteWireError {
    /// A log-safe `Display` view — see [`RedactedInviteWireError`].
    pub fn redacted(&self) -> RedactedInviteWireError<'_> {
        RedactedInviteWireError(self)
    }
}

/// A `Display` wrapper rendering an [`InviteWireError`] with every peer-controlled byte replaced
/// by its shape. Only the [`InviteWireError::Proto`] arm needs rewriting — it can wrap
/// [`ProtoError::UnknownField`], which carries a CBOR map key taken verbatim from a scanned QR
/// code. Every other variant already carries lengths and counts only.
///
/// The match below is **exhaustive with no catch-all**, deliberately: `RedactedBundleWireError`'s
/// `safe =>` fallback is what let a leak through in `e8480af`, so a new variant here must be a
/// compile error rather than a silent pass.
#[derive(Debug, Clone, Copy)]
pub struct RedactedInviteWireError<'a>(pub &'a InviteWireError);

impl std::fmt::Display for RedactedInviteWireError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            InviteWireError::Proto(e) => write!(f, "{}", e.redacted()),
            e @ (InviteWireError::EndpointTooLong { .. }
            | InviteWireError::TooManyEndpoints { .. }
            | InviteWireError::NoEndpoints
            | InviteWireError::TlsPinTooLong { .. }
            | InviteWireError::EmptyPrivateCaRoot
            | InviteWireError::WebPkiPinCarriesRoot
            | InviteWireError::NoSupportedEndpoint { .. }
            | InviteWireError::NotBase64Url) => write!(f, "{e}"),
        }
    }
}

/// The invite payload container: a signed capability plus the transport hints needed to use it.
///
/// Unsigned — see the module doc comment before proposing to change that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitePayload {
    /// Wire schema version. Carried uninterpreted here; `spindle-core::check_min_v` owns the
    /// floor against [`INVITE_MIN_V`].
    pub v: u8,
    /// The signed `invite`-kind capability. `subject` is the invitee's `root_fp` (A10.46).
    pub cap: Capability,
    /// Ordered registry endpoints, most preferred first. At least one, at most
    /// [`MAX_ENDPOINTS`], each at most [`MAX_ENDPOINT_LEN`] bytes.
    pub endpoints: Vec<String>,
    /// How to authenticate the registry's TLS.
    pub tls_pin: TlsPin,
}

/// `InvitePayload`'s closed schema, used by [`MapReader::deny_unknown_fields`].
///
/// Deliberately absent: any host display name. Unauthenticated text rendered before trust is
/// established is a phishing surface — §A4 already bars labels from certificates for exactly this
/// reason — so the host sends its name over the E2E channel after connect. Adding a key here
/// breaks `invite_fields_is_exactly_v_cap_endpoints_tls_pin`, which is the point.
const INVITE_FIELDS: &[&str] = &["v", "cap", "endpoints", "tls_pin"];

impl InvitePayload {
    pub fn to_cbor(&self) -> CborValue {
        CborValue::map(vec![
            ("v", CborValue::uint(self.v as u64)),
            ("cap", self.cap.to_cbor()),
            (
                "endpoints",
                CborValue::array(
                    self.endpoints
                        .iter()
                        .map(|e| CborValue::text(e.clone()))
                        .collect(),
                ),
            ),
            ("tls_pin", self.tls_pin.to_cbor()),
        ])
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    /// The QR/link text form: unpadded base64url of the canonical CBOR (DESIGN.md §A7b).
    pub fn to_base64url(&self) -> String {
        base64url_encode(&self.to_canonical_bytes())
    }

    /// Decodes and applies this module's strictness rules: closed schema on this map and on
    /// `tls_pin`, at least one endpoint, endpoint count and lengths capped, pin well-formed.
    /// Does **not** enforce a `v` floor, and does **not** verify `cap`'s signature.
    pub fn from_cbor(v: &CborValue) -> Result<Self, InviteWireError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(INVITE_FIELDS)?;
        let version = m.u8("v")?;
        let cap = Capability::from_cbor(m.require("cap")?)?;

        let raw = m
            .require("endpoints")?
            .as_array()
            .ok_or(ProtoError::WrongType("endpoints"))?;
        if raw.is_empty() {
            return Err(InviteWireError::NoEndpoints);
        }
        if raw.len() > MAX_ENDPOINTS {
            return Err(InviteWireError::TooManyEndpoints {
                max: MAX_ENDPOINTS,
                actual: raw.len(),
            });
        }
        let mut endpoints = Vec::with_capacity(raw.len());
        for item in raw {
            let s = item
                .as_text()
                .ok_or(ProtoError::WrongType("endpoints"))?
                .to_owned();
            if s.len() > MAX_ENDPOINT_LEN {
                return Err(InviteWireError::EndpointTooLong {
                    max: MAX_ENDPOINT_LEN,
                    actual: s.len(),
                });
            }
            endpoints.push(s);
        }

        let tls_pin = TlsPin::from_cbor(m.require("tls_pin")?)?;

        Ok(InvitePayload {
            v: version,
            cap,
            endpoints,
            tls_pin,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, InviteWireError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }

    /// Decodes the QR/link text form produced by [`Self::to_base64url`].
    pub fn from_base64url(s: &str) -> Result<Self, InviteWireError> {
        Self::from_canonical_bytes(&base64url_decode(s)?)
    }

    /// Returns the first endpoint whose scheme appears in `supported`, in the container's own
    /// preference order.
    ///
    /// **Fails loudly when nothing matches.** A client that silently found no usable endpoint
    /// would surface later as an indefinite "registry degraded", which is the *other* diagnosis
    /// entirely — DESIGN.md §A4 distinguishes "registry degraded" from "host offline", and
    /// neither describes "this invite offers only schemes I cannot speak". A browser handed a
    /// `tls://`-only invite must say so at the moment it is scanned.
    ///
    /// `supported` holds scheme names without the `://`, e.g. `["wss"]` in a browser and
    /// `["tls", "wss"]` natively.
    pub fn select_endpoint(&self, supported: &[&str]) -> Result<&str, InviteWireError> {
        self.endpoints
            .iter()
            .find(|e| match e.find("://") {
                // `scheme` is everything before the first `://`. Comparison is
                // **ASCII**-case-insensitive, per RFC 3986 §3.1 (a scheme is ASCII by
                // construction). Deliberately not a full Unicode case fold: `@spindle/proto`'s
                // twin has to match this exactly, and `String.prototype.toLowerCase` folds
                // characters `eq_ignore_ascii_case` leaves alone (U+212A KELVIN SIGN → `k`), which
                // would make one implementation accept an endpoint the other refuses.
                Some(i) if i > 0 => supported.iter().any(|s| e[..i].eq_ignore_ascii_case(s)),
                _ => false,
            })
            .map(String::as_str)
            .ok_or(InviteWireError::NoSupportedEndpoint {
                offered: self.endpoints.len(),
                supported: supported.len(),
            })
    }
}

// ================================================================================================
// base64url (unpadded)
// ================================================================================================

/// RFC 4648 §5 alphabet, in index order.
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes `bytes` as unpadded base64url (RFC 4648 §5, no `=`).
///
/// Hand-rolled rather than taking a dependency — see the module doc's "This crate carries bytes
/// only" section. Total: every input encodes, and there is no error case.
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[(n >> 18) as usize & 63] as char);
        out.push(B64URL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64URL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[n as usize & 63] as char);
        }
    }
    out
}

/// Decodes unpadded base64url. Rejects padding, any byte outside the alphabet, and any length
/// that no unpadded encoding can produce (`len % 4 == 1`).
///
/// Also rejects a final character whose unused low bits are non-zero — without that check a
/// single byte string has multiple valid-looking encodings, and two implementations could
/// disagree about whether a given QR is the same invite, which is the same canonicality argument
/// [`crate::canonical`] makes for CBOR.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, InviteWireError> {
    let b = s.as_bytes();
    if b.len() % 4 == 1 {
        return Err(InviteWireError::NotBase64Url);
    }
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a') as u32 + 26),
            b'0'..=b'9' => Some((c - b'0') as u32 + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for chunk in b.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c).ok_or(InviteWireError::NotBase64Url)? << (18 - 6 * i);
        }
        match chunk.len() {
            4 => {
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            3 => {
                // 18 bits carried, 16 used: the final 2 bits must be zero.
                if n & 0xFF != 0 {
                    return Err(InviteWireError::NotBase64Url);
                }
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
            }
            2 => {
                // 12 bits carried, 8 used: the final 4 bits must be zero.
                if n & 0xFFFF != 0 {
                    return Err(InviteWireError::NotBase64Url);
                }
                out.push((n >> 16) as u8);
            }
            _ => return Err(InviteWireError::NotBase64Url),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{CapKind, CAPABILITY_CURRENT_V};

    /// An `invite`-kind capability with distinct, recognizable filler. Field values are opaque to
    /// this crate, so nothing here needs to be cryptographically valid — but `kind` is
    /// deliberately `Invite`, because that is what this container exists to carry.
    fn sample_capability() -> Capability {
        Capability {
            v: CAPABILITY_CURRENT_V,
            host_fp: vec![0x01; 32],
            host_root_pk: vec![0x02; 32],
            op_cert: vec![0x03; 16],
            kind: CapKind::Invite,
            subject: vec![0x04; 32],
            cap_epoch: 7,
            exp: 1_800_000_000,
            nonce: vec![0x05; 32],
            sig: vec![0x06; 64],
        }
    }

    fn sample_invite() -> InvitePayload {
        InvitePayload {
            v: INVITE_CURRENT_V,
            cap: sample_capability(),
            endpoints: vec![
                "wss://registry.example:443".to_string(),
                "tls://registry.example:4222".to_string(),
            ],
            tls_pin: TlsPin::WebPki,
        }
    }

    // ---- round trip ----

    #[test]
    fn invite_round_trips_through_canonical_bytes() {
        let invite = sample_invite();
        let bytes = invite.to_canonical_bytes();
        let decoded = InvitePayload::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, invite);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    #[test]
    fn invite_round_trips_through_base64url() {
        let invite = sample_invite();
        let text = invite.to_base64url();
        assert!(!text.contains('='), "the QR/link form must be unpadded");
        assert_eq!(
            InvitePayload::from_base64url(&text).expect("decode"),
            invite
        );
    }

    #[test]
    fn a_private_ca_root_pin_round_trips() {
        let invite = InvitePayload {
            tls_pin: TlsPin::PrivateCaRoot(vec![0xAB; 512]),
            ..sample_invite()
        };
        let bytes = invite.to_canonical_bytes();
        assert_eq!(
            InvitePayload::from_canonical_bytes(&bytes).expect("decode"),
            invite
        );
    }

    // ---- closed schema ----

    /// The container's schema is exactly four keys. Its most load-bearing absence is a host
    /// **display name**: unauthenticated text rendered before any trust is established is a
    /// phishing surface, so adding one must break a test rather than pass review quietly.
    #[test]
    fn invite_fields_is_exactly_v_cap_endpoints_tls_pin() {
        assert_eq!(INVITE_FIELDS, &["v", "cap", "endpoints", "tls_pin"]);
    }

    #[test]
    fn rejects_an_unknown_field_such_as_a_host_display_name() {
        let mut m = match sample_invite().to_cbor() {
            CborValue::Map(entries) => entries,
            other => panic!("expected a map, got {other:?}"),
        };
        m.push((
            CborValue::text("host_name"),
            CborValue::text("Totally Real Host"),
        ));
        let err = InvitePayload::from_cbor(&CborValue::Map(m)).expect_err("must reject");
        assert!(
            matches!(err, InviteWireError::Proto(ProtoError::UnknownField(ref k)) if k == "host_name"),
            "got {err:?}"
        );
    }

    // ---- endpoint rules ----

    #[test]
    fn rejects_an_invite_with_no_endpoints() {
        let invite = InvitePayload {
            endpoints: vec![],
            ..sample_invite()
        };
        assert_eq!(
            InvitePayload::from_cbor(&invite.to_cbor()).expect_err("must reject"),
            InviteWireError::NoEndpoints
        );
    }

    #[test]
    fn rejects_more_endpoints_than_the_cap_allows() {
        let invite = InvitePayload {
            endpoints: (0..=MAX_ENDPOINTS).map(|i| format!("wss://h{i}")).collect(),
            ..sample_invite()
        };
        assert_eq!(
            InvitePayload::from_cbor(&invite.to_cbor()).expect_err("must reject"),
            InviteWireError::TooManyEndpoints {
                max: MAX_ENDPOINTS,
                actual: MAX_ENDPOINTS + 1
            }
        );
    }

    #[test]
    fn rejects_an_endpoint_longer_than_the_cap() {
        let invite = InvitePayload {
            endpoints: vec!["w".repeat(MAX_ENDPOINT_LEN + 1)],
            ..sample_invite()
        };
        assert_eq!(
            InvitePayload::from_cbor(&invite.to_cbor()).expect_err("must reject"),
            InviteWireError::EndpointTooLong {
                max: MAX_ENDPOINT_LEN,
                actual: MAX_ENDPOINT_LEN + 1
            }
        );
    }

    // ---- endpoint selection: the loud-failure requirement ----

    #[test]
    fn select_endpoint_returns_the_first_supported_in_the_containers_own_order() {
        let invite = sample_invite();
        // The container lists wss first, then tls. A native client supporting both must still
        // honour the container's preference order, not its own argument order.
        assert_eq!(
            invite.select_endpoint(&["tls", "wss"]).expect("select"),
            "wss://registry.example:443"
        );
        assert_eq!(
            invite.select_endpoint(&["tls"]).expect("select"),
            "tls://registry.example:4222"
        );
    }

    /// AC 5. A browser handed a `tls://`-only invite must fail at scan time, not degrade into an
    /// indefinite "registry degraded" — a different diagnosis entirely (DESIGN.md §A4).
    #[test]
    fn select_endpoint_fails_loudly_when_no_scheme_is_supported() {
        let invite = InvitePayload {
            endpoints: vec![
                "tls://registry.example:4222".to_string(),
                "nats://registry.example:4222".to_string(),
            ],
            ..sample_invite()
        };
        assert_eq!(
            invite.select_endpoint(&["wss"]).expect_err("must fail"),
            InviteWireError::NoSupportedEndpoint {
                offered: 2,
                supported: 1
            }
        );
    }

    #[test]
    fn select_endpoint_matches_the_scheme_only_at_the_start_and_only_before_a_separator() {
        let invite = InvitePayload {
            // `wss` appears in the host name and as a bare prefix with no `://`; neither is a
            // scheme match. A substring search would wrongly accept both.
            endpoints: vec![
                "tls://wss.example:4222".to_string(),
                "wsshttp://example".to_string(),
            ],
            ..sample_invite()
        };
        assert_eq!(
            invite.select_endpoint(&["wss"]).expect_err("must fail"),
            InviteWireError::NoSupportedEndpoint {
                offered: 2,
                supported: 1
            }
        );
    }

    /// The twin-divergence guard for the rule above. `String.prototype.toLowerCase()` in the
    /// TypeScript twin folds characters `eq_ignore_ascii_case` leaves alone — U+212A KELVIN SIGN
    /// lowercases to `k`. If either side reached for a full Unicode fold, this would start
    /// matching on one side only, and the two would disagree about whether an invite is usable.
    #[test]
    fn scheme_matching_does_not_unicode_fold() {
        let invite = InvitePayload {
            endpoints: vec!["W\u{212A}\u{212A}://registry.example:443".to_string()],
            ..sample_invite()
        };
        assert!(
            invite.select_endpoint(&["wkk"]).is_err(),
            "a KELVIN SIGN must not fold to `k` — the TS twin's toLowerCase() would"
        );
    }

    #[test]
    fn scheme_matching_is_case_insensitive_as_rfc_3986_requires() {
        let invite = InvitePayload {
            endpoints: vec!["WSS://registry.example:443".to_string()],
            ..sample_invite()
        };
        assert_eq!(
            invite.select_endpoint(&["wss"]).expect("select"),
            "WSS://registry.example:443"
        );
    }

    // ---- tls_pin rules ----

    #[test]
    fn rejects_a_web_pki_pin_that_also_carries_a_root() {
        let v = CborValue::map(vec![
            ("kind", CborValue::uint(0)),
            ("root", CborValue::bytes(vec![0xAA; 8])),
        ]);
        assert_eq!(
            TlsPin::from_cbor(&v).expect_err("must reject"),
            InviteWireError::WebPkiPinCarriesRoot
        );
    }

    #[test]
    fn rejects_a_private_ca_root_pin_with_no_bytes() {
        let v = CborValue::map(vec![
            ("kind", CborValue::uint(1)),
            ("root", CborValue::bytes(Vec::new())),
        ]);
        assert_eq!(
            TlsPin::from_cbor(&v).expect_err("must reject"),
            InviteWireError::EmptyPrivateCaRoot
        );
    }

    #[test]
    fn rejects_a_private_ca_root_over_the_cap() {
        let v = CborValue::map(vec![
            ("kind", CborValue::uint(1)),
            ("root", CborValue::bytes(vec![0xAA; MAX_TLS_PIN_LEN + 1])),
        ]);
        assert_eq!(
            TlsPin::from_cbor(&v).expect_err("must reject"),
            InviteWireError::TlsPinTooLong {
                max: MAX_TLS_PIN_LEN,
                actual: MAX_TLS_PIN_LEN + 1
            }
        );
    }

    #[test]
    fn rejects_an_unknown_tls_pin_kind() {
        let v = CborValue::map(vec![("kind", CborValue::uint(2))]);
        assert_eq!(
            TlsPin::from_cbor(&v).expect_err("must reject"),
            InviteWireError::Proto(ProtoError::InvalidEnumValue("tls_pin.kind", 2))
        );
    }

    // ---- the format id is not a signing tag ----

    /// [`INVITE_FORMAT_ID`] identifies a container format; it is not a domain-separation tag and
    /// must never become one. Pinned here so a later author cannot quietly move it into
    /// `crate::tags` and start prefixing signature preimages with it — at which point its
    /// relationship to the real tags (prefix-freeness) would suddenly matter and nothing would
    /// have checked it.
    #[test]
    fn format_id_is_not_usable_as_a_signing_tag() {
        use crate::tags;
        let signing_tags: [&[u8]; 10] = [
            tags::ENVELOPE_V1,
            tags::CAPABILITY_V1,
            tags::ADMISSION_TOKEN_V1,
            tags::DEVICE_CERT_V2,
            tags::REVOCATION_V1,
            tags::ADMIN_COMMAND_V1,
            tags::HOST_OP_KEY_CERT_V2,
            tags::HOST_DEVICE_CERT_V1,
            tags::SESSION_ATTESTATION_V1,
            tags::HOST_SESSION_ATTESTATION_V1,
        ];
        let id = INVITE_FORMAT_ID.as_bytes();
        for t in signing_tags {
            assert_ne!(id, t, "the format id collides with a signing tag");
            assert!(
                !t.starts_with(id) && !id.starts_with(t),
                "the format id is prefix-related to a signing tag ({:?}) — if it is ever promoted \
                 into `crate::tags` it would break that module's prefix-freeness invariant",
                std::str::from_utf8(t).unwrap_or("<non-utf8>")
            );
        }
    }

    // ---- base64url ----

    #[test]
    fn base64url_matches_rfc_4648_test_vectors_unpadded() {
        // RFC 4648 §10's vectors, with padding stripped (this encoder emits none).
        for (input, expected) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(
                base64url_encode(input.as_bytes()),
                expected,
                "encode {input:?}"
            );
            assert_eq!(
                base64url_decode(expected).expect("decode"),
                input.as_bytes(),
                "decode {expected:?}"
            );
        }
    }

    #[test]
    fn base64url_uses_the_url_safe_alphabet_not_the_standard_one() {
        // 0xFB 0xFF encodes to the two indices (62, 63) that differ between the alphabets.
        let encoded = base64url_encode(&[0xFB, 0xFF, 0xBF]);
        assert_eq!(encoded, "-_-_");
        assert!(!encoded.contains('+') && !encoded.contains('/'));
    }

    #[test]
    fn base64url_decode_rejects_padding_and_impossible_lengths() {
        assert_eq!(
            base64url_decode("Zm9vYg==").expect_err("padding must be rejected"),
            InviteWireError::NotBase64Url
        );
        assert_eq!(
            base64url_decode("Zm9vY").expect_err("len % 4 == 1 is impossible"),
            InviteWireError::NotBase64Url
        );
        assert_eq!(
            base64url_decode("Zm9+").expect_err("standard-alphabet byte"),
            InviteWireError::NotBase64Url
        );
    }

    /// Without this rule a single byte has several valid-looking encodings, so two clients could
    /// disagree about whether two QR codes are the same invite — the same canonicality argument
    /// `crate::canonical` makes for CBOR, applied to the text layer.
    #[test]
    fn base64url_decode_rejects_non_zero_unused_trailing_bits() {
        // "Zg" decodes to `f`. "Zh" would too, if the unused low bits were ignored.
        assert_eq!(base64url_decode("Zg").expect("canonical"), b"f");
        assert_eq!(
            base64url_decode("Zh").expect_err("non-canonical trailing bits"),
            InviteWireError::NotBase64Url
        );
        // Same at the 3-character boundary: "Zm8" is `fo`; "Zm9" has a non-zero final 2 bits.
        assert_eq!(base64url_decode("Zm8").expect("canonical"), b"fo");
        assert_eq!(
            base64url_decode("Zm9").expect_err("non-canonical trailing bits"),
            InviteWireError::NotBase64Url
        );
    }

    // ---- redaction ----

    #[test]
    fn no_error_variant_echoes_peer_text_or_bytes() {
        let long = "e".repeat(MAX_ENDPOINT_LEN + 1);
        let invite = InvitePayload {
            endpoints: vec![long.clone()],
            ..sample_invite()
        };
        let err = InvitePayload::from_cbor(&invite.to_cbor()).expect_err("must reject");
        let rendered = format!("{err} / {}", err.redacted());
        assert!(
            !rendered.contains(&long),
            "the endpoint text leaked into an error: {rendered}"
        );
    }

    #[test]
    fn redacted_display_withholds_an_unknown_field_name() {
        let err = InviteWireError::Proto(ProtoError::UnknownField("secret_key_name".into()));
        assert!(format!("{err}").contains("secret_key_name"));
        assert!(
            !format!("{}", err.redacted()).contains("secret_key_name"),
            "redacted Display must withhold the peer-supplied key"
        );
    }

    // ---- size ----

    /// Reports the encoded size of a baseline (web-PKI, two-endpoint) container built from this
    /// module's **test fixture**, and asserts only the property that matters at this layer: it
    /// fits a level-L QR.
    ///
    /// The printed number is deliberately NOT pinned as a constant here. The fixture capability
    /// carries filler field widths (a 16-byte `op_cert`, where a real one is far larger), so
    /// pinning it would pin the fixture, not the artifact — the exact mistake of measuring a
    /// helper instead of the producer. The authoritative figure is measured through the
    /// production invite issuer.
    #[test]
    fn baseline_invite_size_is_reported() {
        let invite = sample_invite();
        let cbor = invite.to_canonical_bytes().len();
        let text = invite.to_base64url().len();
        println!("BASELINE_INVITE cbor={cbor} base64url={text}");
        assert!(
            text < crate::bootstrap::QR_V40_L_CAPACITY_BYTES,
            "a baseline invite must fit a level-L QR: {text} B"
        );
    }
}
