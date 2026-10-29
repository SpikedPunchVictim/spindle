//! The production encoder for the CONNECT `auth_token` envelope's **host arm** (DESIGN.md §A4:
//! "caps travel in the CONNECT `auth_token` as compact CBOR ... base64url"; §A7b's catalog is
//! where the signed artifacts this envelope re-embeds are defined).
//!
//! # Why this module exists
//!
//! Before td-539ffa the envelope's shape had exactly two pins, and neither was production
//! encoding code: `spindle-helper::auth_token::decode_auth_token` (the responder, which parses
//! the CBOR but only ever consumes it) and
//! `spindle_test_fixtures::fixtures::host_auth_token` (a test-only builder). The helper module
//! doc records that split explicitly — the encode/builder side "stays test-code-only: no
//! production encoder exists anywhere in this workspace; the responder only ever needs to
//! *decode* one." That is true of the responder, but a host that must present its own CONNECT
//! has nothing to call. This module is the production encoder for that host arm.
//!
//! A third copy of the shape is only safe while it agrees byte-for-byte with the other two. The
//! tests below compare this encoder's output against an independently hand-built
//! [`CborValue::map`], and a helper-side test compares it against the fixture encoder
//! byte-for-byte — the shape is pinned by agreement, not by this module restating it.
//!
//! # Scope, deliberately narrow
//!
//! Only the host arm is encoded here. The device arm (`{kind: "device", root_pk, device_cert,
//! session_attest, caps}`) and the `@spindle/proto` TypeScript twin are deliberately not
//! included yet (td-539ffa slice 1): the host is the first production presenter, and an encoder
//! with no caller would be another hand-kept copy of the shape rather than a tested production
//! path. The host shape is:
//!
//! ```text
//! { "kind": "host", "host_root_pk": bytes32, "host_op_cert": bytes,
//!   "session_attest": bytes, "admission_token"?: bytes }
//! ```
//!
//! `host_op_cert`, `session_attest` and `admission_token` are each the corresponding artifact's
//! own `to_canonical_bytes()` output re-embedded as a CBOR byte string, exactly as the helper's
//! decoder expects. The caller passes them pre-encoded because `spindle-proto` sits below
//! `spindle-core` (A9c boundary rule 3) and has no access to the signed-artifact types that own
//! those encoders.
//!
//! `admission_token` is optional and, when absent, **omitted as a key rather than encoded as
//! CBOR `null`** — this crate's established optional-field convention (see the schema table in
//! `lib.rs`; `Envelope.eph_pk` is the precedent). It is optional because a host's second and
//! later connections legitimately carry none (DESIGN.md §A3b: an already-admitted host connects
//! on its cert alone); `session_attest` has no such case and is required (DESIGN.md §A4 step 3,
//! td-583db5).
//!
//! The envelope itself is **not** a §A7b signed artifact: it carries no domain-separation tag
//! and no signature, and only wraps artifacts §A7b already signs individually. This module
//! therefore introduces no new tag.
//!
//! # No base64
//!
//! The return value is raw canonical CBOR. DESIGN.md §A4's presentation rule base64url-encodes
//! it at the call site, where the base64 dependency lives: `spindle-proto` is dependency-free by
//! design (see its `Cargo.toml`).

use crate::canonical::{canonical_encode, CborValue};

/// Encodes the host arm of a CONNECT `auth_token` envelope as canonical CBOR (no base64 — the
/// caller wraps it per DESIGN.md §A4). See the module docs for the shape and for why the
/// artifact bytes are passed in already encoded.
pub fn encode_host_auth_token(
    host_root_pk: &[u8; 32],
    host_op_cert_bytes: &[u8],
    session_attest_bytes: &[u8],
    admission_token_bytes: Option<&[u8]>,
) -> Vec<u8> {
    let mut entries = vec![
        ("kind", CborValue::text("host")),
        ("host_root_pk", CborValue::bytes(host_root_pk.to_vec())),
        (
            "host_op_cert",
            CborValue::bytes(host_op_cert_bytes.to_vec()),
        ),
        (
            "session_attest",
            CborValue::bytes(session_attest_bytes.to_vec()),
        ),
    ];
    if let Some(token) = admission_token_bytes {
        entries.push(("admission_token", CborValue::bytes(token.to_vec())));
    }
    canonical_encode(&CborValue::map(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_decode;

    fn field<'a>(map: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
        map.iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    }

    #[test]
    fn fields_round_trip_through_canonical_parsing() {
        let host_root_pk = [0x42; 32];
        let host_op_cert = [0x01, 0x02, 0x03];
        let session_attest = [0x04; 40];
        let admission_token = [0x05; 7];

        let bytes = encode_host_auth_token(
            &host_root_pk,
            &host_op_cert,
            &session_attest,
            Some(&admission_token),
        );
        let decoded = canonical_decode(&bytes).expect("encoder emits canonical CBOR");
        let map = decoded.as_map().expect("envelope is a CBOR map");

        assert_eq!(
            field(map, "kind").and_then(CborValue::as_text),
            Some("host")
        );
        assert_eq!(
            field(map, "host_root_pk").and_then(CborValue::as_bytes),
            Some(host_root_pk.as_slice())
        );
        assert_eq!(
            field(map, "host_op_cert").and_then(CborValue::as_bytes),
            Some(host_op_cert.as_slice())
        );
        assert_eq!(
            field(map, "session_attest").and_then(CborValue::as_bytes),
            Some(session_attest.as_slice())
        );
        assert_eq!(
            field(map, "admission_token").and_then(CborValue::as_bytes),
            Some(admission_token.as_slice())
        );
        assert_eq!(map.len(), 5);
    }

    /// Independent of the implementation: the expected value is assembled here as a
    /// [`CborValue::map`] and encoded directly, so a change to the encoder's map construction
    /// (field name, ordering intent, wrapping) has to be made in two places to stay green.
    #[test]
    fn emitted_bytes_equal_an_independently_hand_built_map() {
        let host_root_pk = [0x11; 32];
        let host_op_cert = [0xC0; 3];
        let session_attest = [0x5E; 33];
        let admission_token = [0xAD; 9];

        let expected = CborValue::map(vec![
            ("kind", CborValue::text("host")),
            ("host_root_pk", CborValue::bytes(host_root_pk.to_vec())),
            ("host_op_cert", CborValue::bytes(host_op_cert.to_vec())),
            ("session_attest", CborValue::bytes(session_attest.to_vec())),
            (
                "admission_token",
                CborValue::bytes(admission_token.to_vec()),
            ),
        ]);

        assert_eq!(
            encode_host_auth_token(
                &host_root_pk,
                &host_op_cert,
                &session_attest,
                Some(&admission_token)
            ),
            canonical_encode(&expected)
        );
    }

    /// The absent case must be key omission, never a `null` value: the helper's decoder treats a
    /// present-but-not-bytes `admission_token` as a hard error, and a `null` would also change
    /// the envelope's byte shape for every host connection without a token.
    #[test]
    fn none_omits_the_admission_token_key_entirely() {
        let bytes = encode_host_auth_token(&[0x01; 32], &[0x02], &[0x03], None);
        let decoded = canonical_decode(&bytes).expect("encoder emits canonical CBOR");
        let map = decoded.as_map().expect("envelope is a CBOR map");

        assert!(
            field(map, "admission_token").is_none(),
            "admission_token must be omitted when None, not encoded as CBOR null"
        );
        assert_eq!(map.len(), 4);
    }
}
