//! Signaling payload wire types (DESIGN.md §A6 "Signaling flows" + §A7's envelope, §A10.31/32's
//! native↔native QUIC transport decision), promoted from `spikes/s2-signaling`'s crate-local
//! `OfferPayload`/`AnswerPayload`/`IcePayload` types (see that spike's module doc for the
//! empirical work that settled these fields: a real connect/answer/trickle-ICE exchange run
//! end-to-end over the A7 envelope).
//!
//! # Not one of A7b's seven signed artifacts
//! Like [`crate::vfs_rpc`], these types carry no domain-separation tag and no `sig` field of
//! their own — see that module's doc comment for the general shape of this argument. Here it
//! applies for a different reason: an offer/answer/ICE payload is never signed or encoded on the
//! wire by itself. It is always the *plaintext* that gets AEAD-sealed inside a
//! [`crate::artifacts::Envelope`] (`k0` for the offer, `k1` for everything after — DESIGN.md §A7's
//! key schedule), and that envelope's own `spindle-env-v1` signature (over
//! `canonical(header) || ciphertext`) already covers the payload transitively. Adding a second,
//! independent signature over the payload itself would be redundant with the envelope's own
//! integrity guarantee — exactly [`crate::vfs_rpc`]'s rationale for VFS RPC messages, restated
//! here for a different transport-independent payload kind.
//!
//! # What changed from the spike (spike is intentionally read-only, throwaway)
//! `spikes/s2-signaling/src/lib.rs` used JSON encoding and stringly-typed fields for speed, since
//! nothing outside that crate ever decoded them. Promotion to this crate fixes both:
//! - **Encoding**: canonical CBOR ([`crate::canonical`]), not JSON, matching every other wire type
//!   in this crate.
//! - **`cert_fp`**: a fixed `[u8; 32]` SHA-256 digest, encoded as a CBOR byte string — not the
//!   spike's `"sha256:<hex>"` display string. This matches how `spindle-net::quic` actually
//!   carries a QUIC certificate fingerprint (`SessionCert::fingerprint(&self) -> [u8; 32]`,
//!   `crates/spindle-net/src/quic.rs`) and how this crate already encodes every other
//!   fingerprint/digest/signature as a byte string rather than text (see the schema-choices table
//!   in `lib.rs` and `artifacts.rs`'s fingerprint/signature fields). Note `spindle-net::quic`
//!   itself uses a bare `[u8; 32]`, not `spindle-core::Fingerprint` — this crate cannot depend on
//!   `spindle-core` either way (A9c boundary rule 3: `proto` sits below `core` in the crate
//!   graph), so a bare fixed-size array is the only representation available here, and it happens
//!   to match `spindle-net`'s own choice exactly.
//! - **`transport`**: a closed [`Transport`] enum with a small-uint wire discriminant, not free
//!   text. DESIGN.md §A6/§A10.31/32 define exactly two transports a connect negotiates:
//!   native↔native QUIC (`transport: quic` — A6: "a native↔native pair negotiates `transport:
//!   quic` during `connect`") and browser-peer WebRTC (A6: "browser peers always use WebRTC").
//!   No third value exists in DESIGN.md, so this crate closes the schema exactly the way
//!   `vfs_rpc.rs`'s `EntryKind`/`ReqOp` close theirs.
//! - **Length caps**: `ufrag`/`pwd`/`candidate`/`inbox` remain plain `String` (they are ICE/SDP/
//!   NATS text by nature, not binary), but decoding now enforces explicit upper bounds — see
//!   [`MAX_UFRAG_LEN`]/[`MAX_PWD_LEN`]/[`MAX_CANDIDATE_LEN`]/[`MAX_INBOX_LEN`] for the specific
//!   values and their justification. The spike enforced none of these (nothing outside the spike
//!   ever fed it adversarial input); a promoted wire type decoding bytes from a not-yet-trusted
//!   peer must.
//!
//! # Schema choices (this promotion's own additions to the table in `lib.rs`)
//!
//! | Choice | Decision |
//! |---|---|
//! | Wire shape | One flat CBOR map per payload type, field names as short text keys — same convention as every other type in this crate. No shared "kind" discriminant field inside the payload itself: [`KIND_OFFER`]/[`KIND_ANSWER`]/[`KIND_ICE`] are `Envelope.kind` values a caller sets on the *envelope* that carries the payload, not a field of the payload's own CBOR (mirrors the spike's `KIND_OFFER`/`KIND_ANSWER`/`KIND_ICE` constants exactly — DESIGN.md's `Envelope.kind` is already the discriminant DESIGN.md specifies; inventing a second one inside the payload would be redundant). |
//! | `IcePayload.candidate` | `Option<String>`, represented by key omission when `None` — this crate's established optional-field convention (see `lib.rs`'s schema table; `Envelope.eph_pk` is the precedent), not CBOR `null`. |
//! | `IcePayload.end_of_candidates` | Plain `bool`, always present (never omitted) — unlike `candidate`, this field has no "absent" state; the spike's `#[serde(default)]` was a JSON-only convenience with no equivalent needed here since the field is always written. |
//! | Error type | A dedicated [`SignalingError`] rather than reusing [`crate::artifacts::ProtoError`] directly, because this module's decode strictness needs two rejection kinds `ProtoError` has no variant for: a string field over its length cap, and a fixed-size byte field (`cert_fp`) of the wrong length. [`SignalingError::Proto`] wraps `ProtoError` for every other rejection (missing/unknown field, wrong type, invalid enum, non-canonical CBOR) so the shared [`MapReader`]/`canonical` decoding machinery is reused unchanged, exactly as `vfs_rpc.rs` reuses `ProtoError` itself rather than re-implementing field extraction. |

use crate::artifacts::{MapReader, ProtoError};
use crate::canonical::{canonical_decode, canonical_encode, CborError, CborValue};

/// Length of a `cert_fp` field in bytes — a SHA-256 digest (DESIGN.md §A10.32).
pub const CERT_FP_LEN: usize = 32;

/// Maximum length, in bytes, of an ICE `ufrag`/`pwd` field. RFC 8445 §5.3: "An agent MUST be
/// prepared to receive... a ufrag or password up to 256 characters" and "MUST NOT generate a
/// ufrag or password longer than 256 characters" — 256 is the RFC's own stated ceiling, not a
/// value this crate invented. Applied identically to both fields since the RFC gives one shared
/// upper bound for each (the RFC's lower bounds — 4 chars/24 bits for `ufrag`, 22 chars/128 bits
/// for `pwd` — are *generation* requirements on the sender, not a receiver-side acceptance floor,
/// so this crate does not enforce a minimum, mirroring `vfs_rpc.rs`'s practice of only ever
/// capping the *upper* bound of a field, e.g. [`crate::vfs_rpc::MAX_LIST_PAGE`]).
pub const MAX_UFRAG_LEN: usize = 256;
/// See [`MAX_UFRAG_LEN`] — same RFC 8445 §5.3 ceiling, applied to `pwd`.
pub const MAX_PWD_LEN: usize = 256;

/// Maximum length, in bytes, of one trickled ICE candidate line (an SDP `a=candidate` line body,
/// RFC 8839 §5.1 — carried without the `a=candidate:` prefix here since this crate's `candidate`
/// field is the attribute value only). Neither RFC 8839 nor RFC 8445 states a hard maximum candidate
/// line length; real candidate lines (including `typ relay`/`typ srflx` forms with `raddr`/`rport`
/// extensions, and `tcptype` for TCP candidates) are observed to run well under 300 bytes even with
/// every optional extension present. 1024 bytes is a generous multiple of that observed ceiling —
/// enough headroom for any legitimate candidate line, including future extension attributes, while
/// still bounding the field against a hostile peer sending an oversized line to waste memory/parse
/// time.
pub const MAX_CANDIDATE_LEN: usize = 1024;

/// Maximum length, in bytes, of the `inbox` field (a NATS subject string, DESIGN.md §A6's connect
/// flow: `env{eph_pk_c, offer, inbox, ...}`, `_INBOX_<c>.x`-shaped). NATS does not itself impose a
/// hard subject-length limit, but every subject this system actually mints is a handful of
/// dot-separated tokens built from fixed prefixes (`_INBOX_`, `host.`, `sess.`) plus base32
/// fingerprints/session ids (fixed-length per DESIGN.md's `Fingerprint` convention, at most a few
/// dozen characters each) — real inbox subjects are well under 128 bytes. 256 bytes gives a 2x
/// margin over that for future subject-shape growth while still bounding the field against a
/// hostile peer supplying an arbitrarily long subject string.
pub const MAX_INBOX_LEN: usize = 256;

/// Errors produced while converting between the signaling wire types and [`CborValue`]/bytes.
/// [`SignalingError::Proto`] reuses every rejection kind [`ProtoError`] already defines (missing/
/// unknown field, wrong CBOR type, invalid enum discriminant, not-a-map, non-text map key,
/// non-canonical CBOR) — see the module doc's schema-choices table for why this module does not
/// simply use `ProtoError` directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalingError {
    /// Every rejection kind already covered by [`ProtoError`] (see that type's own variants).
    Proto(ProtoError),
    /// A string field's encoded length (in bytes) exceeded its declared cap.
    TooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    /// A fixed-size byte-string field (`cert_fp`) was not exactly its required length.
    WrongLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
}

impl std::fmt::Display for SignalingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignalingError::Proto(e) => write!(f, "{e}"),
            SignalingError::TooLong { field, max, actual } => write!(
                f,
                "field `{field}` is {actual} bytes long, exceeding the {max}-byte cap"
            ),
            SignalingError::WrongLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "field `{field}` is {actual} bytes long, expected exactly {expected}"
            ),
        }
    }
}

impl std::error::Error for SignalingError {}

impl From<ProtoError> for SignalingError {
    fn from(e: ProtoError) -> Self {
        SignalingError::Proto(e)
    }
}

impl From<CborError> for SignalingError {
    fn from(e: CborError) -> Self {
        SignalingError::Proto(ProtoError::from(e))
    }
}

/// Rejects `s` if its byte length exceeds `max`.
fn check_max_len(field: &'static str, s: &str, max: usize) -> Result<(), SignalingError> {
    let actual = s.len();
    if actual > max {
        return Err(SignalingError::TooLong { field, max, actual });
    }
    Ok(())
}

/// Reads a required byte-string field and checks it is exactly [`CERT_FP_LEN`] bytes.
fn read_cert_fp(m: &MapReader<'_>) -> Result<[u8; CERT_FP_LEN], SignalingError> {
    let bytes = m.bytes("cert_fp")?;
    let actual = bytes.len();
    bytes.try_into().map_err(|_| SignalingError::WrongLength {
        field: "cert_fp",
        expected: CERT_FP_LEN,
        actual,
    })
}

/// Reads a required text field and enforces `max` as its byte-length cap.
fn read_capped_text(
    m: &MapReader<'_>,
    field: &'static str,
    max: usize,
) -> Result<String, SignalingError> {
    let s = m.text(field)?;
    check_max_len(field, &s, max)?;
    Ok(s)
}

// ================================================================================================
// Transport (DESIGN.md §A6/§A10.31/32) — the only two transports a connect ever negotiates.
// ================================================================================================

/// The transport a `connect` negotiates (DESIGN.md §A6: "a native↔native pair negotiates
/// `transport: quic` during `connect`... browser peers always use WebRTC"; A10.31/32 is the S3
/// decision that put native↔native on QUIC in the first place). A closed two-value enum, not free
/// text — see the module doc comment's "What changed from the spike" section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Native↔native sessions (DESIGN.md §A10.31: quinn + standalone ICE, §A10.32).
    Quic = 0,
    /// Any session with a browser peer (DESIGN.md §A10.31/32: WebRTC, WAN-ceiling caveat noted
    /// there — unrelated to this wire type).
    WebRtc = 1,
}

impl Transport {
    fn to_cbor(self) -> CborValue {
        CborValue::uint(self as u64)
    }

    fn from_u64(v: u64) -> Result<Self, ProtoError> {
        match v {
            0 => Ok(Transport::Quic),
            1 => Ok(Transport::WebRtc),
            other => Err(ProtoError::InvalidEnumValue("transport", other)),
        }
    }
}

/// Spike-local `Envelope.kind` values, now the schema-of-record (DESIGN.md §A6's flow diagram:
/// `env{offer}` / `env{answer}` / `env{ice}`) — see the module doc comment for why these are plain
/// constants rather than a field embedded in the payloads themselves.
pub const KIND_OFFER: u16 = 1;
pub const KIND_ANSWER: u16 = 2;
pub const KIND_ICE: u16 = 3;

// ================================================================================================
// OfferPayload
// ================================================================================================

/// The client's connect offer (DESIGN.md §A6: `env{eph_pk_c, offer, inbox, ...}`). `inbox` is the
/// client's NATS reply subject; `transport`/`ufrag`/`pwd`/`cert_fp` are the client's own
/// connectivity-negotiation fields — ICE short-term credentials (RFC 8445 §5.3) and, for a QUIC
/// session, the client's per-session QUIC certificate fingerprint (DESIGN.md §A10.32). Candidates
/// themselves are never embedded here; they are trickled separately as [`IcePayload`] envelopes
/// (`kind = `[`KIND_ICE`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferPayload {
    pub inbox: String,
    pub transport: Transport,
    pub ufrag: String,
    pub pwd: String,
    pub cert_fp: [u8; CERT_FP_LEN],
}

const OFFER_FIELDS: &[&str] = &["inbox", "transport", "ufrag", "pwd", "cert_fp"];

impl OfferPayload {
    pub fn to_cbor(&self) -> CborValue {
        CborValue::map(vec![
            ("inbox", CborValue::text(self.inbox.clone())),
            ("transport", self.transport.to_cbor()),
            ("ufrag", CborValue::text(self.ufrag.clone())),
            ("pwd", CborValue::text(self.pwd.clone())),
            ("cert_fp", CborValue::bytes(self.cert_fp.to_vec())),
        ])
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, SignalingError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(OFFER_FIELDS)?;
        Ok(OfferPayload {
            inbox: read_capped_text(&m, "inbox", MAX_INBOX_LEN)?,
            transport: Transport::from_u64(m.u64("transport")?)?,
            ufrag: read_capped_text(&m, "ufrag", MAX_UFRAG_LEN)?,
            pwd: read_capped_text(&m, "pwd", MAX_PWD_LEN)?,
            cert_fp: read_cert_fp(&m)?,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SignalingError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }
}

// ================================================================================================
// AnswerPayload
// ================================================================================================

/// The host's connect answer (DESIGN.md §A6: `env{eph_pk_h, answer, ...}`). Mirrors
/// [`OfferPayload`]'s new fields exactly (the host's own `ufrag`/`pwd`/`cert_fp`) minus `inbox`
/// (the answer is delivered as the `connect` request's reply; it needs no reply-subject of its
/// own).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerPayload {
    pub transport: Transport,
    pub ufrag: String,
    pub pwd: String,
    pub cert_fp: [u8; CERT_FP_LEN],
}

const ANSWER_FIELDS: &[&str] = &["transport", "ufrag", "pwd", "cert_fp"];

impl AnswerPayload {
    pub fn to_cbor(&self) -> CborValue {
        CborValue::map(vec![
            ("transport", self.transport.to_cbor()),
            ("ufrag", CborValue::text(self.ufrag.clone())),
            ("pwd", CborValue::text(self.pwd.clone())),
            ("cert_fp", CborValue::bytes(self.cert_fp.to_vec())),
        ])
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, SignalingError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(ANSWER_FIELDS)?;
        Ok(AnswerPayload {
            transport: Transport::from_u64(m.u64("transport")?)?,
            ufrag: read_capped_text(&m, "ufrag", MAX_UFRAG_LEN)?,
            pwd: read_capped_text(&m, "pwd", MAX_PWD_LEN)?,
            cert_fp: read_cert_fp(&m)?,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SignalingError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }
}

// ================================================================================================
// IcePayload
// ================================================================================================

/// One trickled ICE message (DESIGN.md §A6: `env{ice}`) — either a single SDP `a=candidate` line
/// value, or, once a side has exhausted its local gathering, an explicit end-of-candidates marker
/// (RFC 8445 §8.2.7's "identifying the last candidate" idea, restated at the payload level since
/// this wire type carries one candidate per envelope rather than SDP's own `a=end-of-candidates`
/// line). Exactly one of the two is meaningful per envelope: `candidate: Some(_)` with
/// `end_of_candidates: false` for a real trickled candidate, or `candidate: None` with
/// `end_of_candidates: true` for the marker — never both, never neither in normal operation, but
/// (matching the spike's own note) the decoder does not assume or enforce this; it accepts every
/// combination the closed schema allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcePayload {
    pub candidate: Option<String>,
    pub end_of_candidates: bool,
}

const ICE_FIELDS: &[&str] = &["candidate", "end_of_candidates"];

impl IcePayload {
    pub fn to_cbor(&self) -> CborValue {
        let mut entries = Vec::with_capacity(2);
        if let Some(c) = &self.candidate {
            entries.push(("candidate", CborValue::text(c.clone())));
        }
        entries.push(("end_of_candidates", CborValue::Bool(self.end_of_candidates)));
        CborValue::map(entries)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, SignalingError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(ICE_FIELDS)?;
        let candidate = match m.get("candidate") {
            None => None,
            Some(val) => {
                let s = val.as_text().ok_or(ProtoError::WrongType("candidate"))?;
                check_max_len("candidate", s, MAX_CANDIDATE_LEN)?;
                Some(s.to_string())
            }
        };
        Ok(IcePayload {
            candidate,
            end_of_candidates: m.bool("end_of_candidates")?,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SignalingError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CborError as RawCborError;

    fn fp(byte: u8) -> [u8; CERT_FP_LEN] {
        [byte; CERT_FP_LEN]
    }

    fn sample_offer() -> OfferPayload {
        OfferPayload {
            inbox: "_INBOX_abc123.x".to_string(),
            transport: Transport::Quic,
            ufrag: "clientufrag1".to_string(),
            pwd: "clientpassword1234567890ab".to_string(),
            cert_fp: fp(0x11),
        }
    }

    fn sample_answer() -> AnswerPayload {
        AnswerPayload {
            transport: Transport::WebRtc,
            ufrag: "hostufrag1".to_string(),
            pwd: "hostpassword1234567890abcd".to_string(),
            cert_fp: fp(0x22),
        }
    }

    // ---- round trips ----

    #[test]
    fn offer_round_trips_both_transports() {
        for transport in [Transport::Quic, Transport::WebRtc] {
            let offer = OfferPayload {
                transport,
                ..sample_offer()
            };
            let bytes = offer.to_canonical_bytes();
            let decoded = OfferPayload::from_canonical_bytes(&bytes).expect("decode");
            assert_eq!(decoded, offer);
            assert_eq!(decoded.to_canonical_bytes(), bytes);
        }
    }

    #[test]
    fn answer_round_trips_both_transports() {
        for transport in [Transport::Quic, Transport::WebRtc] {
            let answer = AnswerPayload {
                transport,
                ..sample_answer()
            };
            let bytes = answer.to_canonical_bytes();
            let decoded = AnswerPayload::from_canonical_bytes(&bytes).expect("decode");
            assert_eq!(decoded, answer);
            assert_eq!(decoded.to_canonical_bytes(), bytes);
        }
    }

    #[test]
    fn ice_round_trips_a_real_candidate() {
        let ice = IcePayload {
            candidate: Some("candidate:1 1 UDP 2130706431 10.0.0.1 54321 typ host".to_string()),
            end_of_candidates: false,
        };
        let bytes = ice.to_canonical_bytes();
        let decoded = IcePayload::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, ice);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    #[test]
    fn ice_round_trips_end_of_candidates_marker() {
        // The end-of-candidates signal: no candidate, marker set — DESIGN.md's RFC 8445 §8.2.7
        // restatement at the payload level (see IcePayload's doc comment).
        let ice = IcePayload {
            candidate: None,
            end_of_candidates: true,
        };
        let bytes = ice.to_canonical_bytes();
        let decoded = IcePayload::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(decoded, ice);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
        // `candidate` must be omitted (key omission), not encoded as CBOR null.
        if let CborValue::Map(entries) = ice.to_cbor() {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].0.as_text(), Some("end_of_candidates"));
        } else {
            panic!("expected a map");
        }
    }

    #[test]
    fn ice_round_trips_neither_and_both_combinations() {
        // The decoder does not assume exactly-one-of — see IcePayload's doc comment.
        for (candidate, end_of_candidates) in [
            (None, false),
            (
                Some("candidate:1 1 UDP 1 10.0.0.1 1 typ host".to_string()),
                true,
            ),
        ] {
            let ice = IcePayload {
                candidate,
                end_of_candidates,
            };
            let bytes = ice.to_canonical_bytes();
            let decoded = IcePayload::from_canonical_bytes(&bytes).expect("decode");
            assert_eq!(decoded, ice);
        }
    }

    // ---- boundary lengths ----

    #[test]
    fn ufrag_and_pwd_accept_exactly_the_cap_and_reject_one_over() {
        let ok_ufrag = "u".repeat(MAX_UFRAG_LEN);
        let offer = OfferPayload {
            ufrag: ok_ufrag.clone(),
            ..sample_offer()
        };
        assert!(OfferPayload::from_canonical_bytes(&offer.to_canonical_bytes()).is_ok());

        let too_long_ufrag = "u".repeat(MAX_UFRAG_LEN + 1);
        let offer = OfferPayload {
            ufrag: too_long_ufrag,
            ..sample_offer()
        };
        let err = OfferPayload::from_canonical_bytes(&offer.to_canonical_bytes()).unwrap_err();
        assert_eq!(
            err,
            SignalingError::TooLong {
                field: "ufrag",
                max: MAX_UFRAG_LEN,
                actual: MAX_UFRAG_LEN + 1,
            }
        );

        let ok_pwd = "p".repeat(MAX_PWD_LEN);
        let answer = AnswerPayload {
            pwd: ok_pwd,
            ..sample_answer()
        };
        assert!(AnswerPayload::from_canonical_bytes(&answer.to_canonical_bytes()).is_ok());

        let too_long_pwd = "p".repeat(MAX_PWD_LEN + 1);
        let answer = AnswerPayload {
            pwd: too_long_pwd,
            ..sample_answer()
        };
        let err = AnswerPayload::from_canonical_bytes(&answer.to_canonical_bytes()).unwrap_err();
        assert_eq!(
            err,
            SignalingError::TooLong {
                field: "pwd",
                max: MAX_PWD_LEN,
                actual: MAX_PWD_LEN + 1,
            }
        );
    }

    #[test]
    fn candidate_accepts_exactly_the_cap_and_rejects_one_over() {
        let ok = IcePayload {
            candidate: Some("c".repeat(MAX_CANDIDATE_LEN)),
            end_of_candidates: false,
        };
        assert!(IcePayload::from_canonical_bytes(&ok.to_canonical_bytes()).is_ok());

        let too_long = IcePayload {
            candidate: Some("c".repeat(MAX_CANDIDATE_LEN + 1)),
            end_of_candidates: false,
        };
        let err = IcePayload::from_canonical_bytes(&too_long.to_canonical_bytes()).unwrap_err();
        assert_eq!(
            err,
            SignalingError::TooLong {
                field: "candidate",
                max: MAX_CANDIDATE_LEN,
                actual: MAX_CANDIDATE_LEN + 1,
            }
        );
    }

    #[test]
    fn inbox_accepts_exactly_the_cap_and_rejects_one_over() {
        let ok = OfferPayload {
            inbox: "i".repeat(MAX_INBOX_LEN),
            ..sample_offer()
        };
        assert!(OfferPayload::from_canonical_bytes(&ok.to_canonical_bytes()).is_ok());

        let too_long = OfferPayload {
            inbox: "i".repeat(MAX_INBOX_LEN + 1),
            ..sample_offer()
        };
        let err = OfferPayload::from_canonical_bytes(&too_long.to_canonical_bytes()).unwrap_err();
        assert_eq!(
            err,
            SignalingError::TooLong {
                field: "inbox",
                max: MAX_INBOX_LEN,
                actual: MAX_INBOX_LEN + 1,
            }
        );
    }

    // ---- negative tests: unknown field ----

    #[test]
    fn rejects_unknown_field_on_offer() {
        let mut cbor = sample_offer().to_cbor();
        if let CborValue::Map(entries) = &mut cbor {
            entries.push((CborValue::text("bogus"), CborValue::uint(1)));
        }
        let bytes = canonical_encode(&cbor);
        let err = OfferPayload::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            SignalingError::Proto(ProtoError::UnknownField("bogus".to_string()))
        );
    }

    #[test]
    fn rejects_unknown_field_on_ice() {
        let mut cbor = IcePayload {
            candidate: None,
            end_of_candidates: true,
        }
        .to_cbor();
        if let CborValue::Map(entries) = &mut cbor {
            entries.push((CborValue::text("bogus"), CborValue::uint(1)));
        }
        let bytes = canonical_encode(&cbor);
        let err = IcePayload::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            SignalingError::Proto(ProtoError::UnknownField("bogus".to_string()))
        );
    }

    // ---- negative test: missing required field ----

    #[test]
    fn rejects_missing_required_field() {
        let cbor = CborValue::map(vec![
            ("transport", Transport::Quic.to_cbor()),
            ("ufrag", CborValue::text("u")),
            ("pwd", CborValue::text("p")),
            // cert_fp omitted
        ]);
        let bytes = canonical_encode(&cbor);
        let err = AnswerPayload::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            SignalingError::Proto(ProtoError::MissingField("cert_fp"))
        );
    }

    // ---- negative test: non-canonical encoding ----

    /// Rewrites `bytes` (a canonical CBOR map) so that the single-byte uint value immediately
    /// following text key `key` is instead written in the non-shortest 1-byte-argument form
    /// (`0x18 <value>`) — everything else byte-identical. Splicing is safe because CBOR map/array
    /// headers encode an *entry count*, never a total byte length, so no earlier header needs
    /// adjusting when this insert shifts everything after it.
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
        // The "transport" field (Transport::Quic = 0) re-encoded in the non-shortest
        // 1-byte-argument form instead of canonical CBOR's required inline form — rejected
        // regardless of which field in the map carries the violation.
        let answer = sample_answer();
        let canonical_bytes = answer.to_canonical_bytes();
        let mutated = lengthen_uint_after_key(&canonical_bytes, "transport");
        let err = AnswerPayload::from_canonical_bytes(&mutated).unwrap_err();
        assert!(matches!(
            err,
            SignalingError::Proto(ProtoError::Cbor(RawCborError::NonShortestForm { .. }))
        ));
    }

    // ---- negative test: bad enum discriminant ----

    #[test]
    fn rejects_bad_transport_discriminant() {
        let cbor = CborValue::map(vec![
            ("inbox", CborValue::text("x")),
            ("transport", CborValue::uint(99)),
            ("ufrag", CborValue::text("u")),
            ("pwd", CborValue::text("p")),
            ("cert_fp", CborValue::bytes(fp(0).to_vec())),
        ]);
        let bytes = canonical_encode(&cbor);
        let err = OfferPayload::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            SignalingError::Proto(ProtoError::InvalidEnumValue("transport", 99))
        );
    }

    // ---- negative test: wrong CBOR major type ----

    #[test]
    fn rejects_wrong_type_for_cert_fp() {
        let cbor = CborValue::map(vec![
            ("transport", Transport::Quic.to_cbor()),
            ("ufrag", CborValue::text("u")),
            ("pwd", CborValue::text("p")),
            ("cert_fp", CborValue::text("not-bytes")), // wrong major type: text, not bytes
        ]);
        let bytes = canonical_encode(&cbor);
        let err = AnswerPayload::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(err, SignalingError::Proto(ProtoError::WrongType("cert_fp")));
    }

    #[test]
    fn rejects_wrong_length_cert_fp() {
        let cbor = CborValue::map(vec![
            ("transport", Transport::Quic.to_cbor()),
            ("ufrag", CborValue::text("u")),
            ("pwd", CborValue::text("p")),
            ("cert_fp", CborValue::bytes(vec![0xaa; 31])), // one byte short
        ]);
        let bytes = canonical_encode(&cbor);
        let err = AnswerPayload::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(
            err,
            SignalingError::WrongLength {
                field: "cert_fp",
                expected: CERT_FP_LEN,
                actual: 31,
            }
        );
    }

    // ---- misc parity ----

    #[test]
    fn kind_constants_match_the_spike() {
        assert_eq!(KIND_OFFER, 1);
        assert_eq!(KIND_ANSWER, 2);
        assert_eq!(KIND_ICE, 3);
    }

    #[test]
    fn transport_discriminants_are_stable() {
        assert_eq!(Transport::Quic as u64, 0);
        assert_eq!(Transport::WebRtc as u64, 1);
    }
}
