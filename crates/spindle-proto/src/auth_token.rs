//! The production encoders for the CONNECT `auth_token` envelope's **host and device arms**
//! (DESIGN.md §A4: "caps travel in the CONNECT `auth_token` as compact CBOR ... base64url";
//! §A7b's catalog is where the signed artifacts this envelope re-embeds are defined).
//!
//! # Why this module exists
//!
//! Before td-539ffa the envelope's shape had exactly two pins, and neither was production
//! encoding code: `spindle-helper::auth_token::decode_auth_token` (the responder, which parses
//! the CBOR but only ever consumes it) and the matching test-only builders in
//! `spindle_test_fixtures::fixtures`. The helper module doc records that split explicitly — the
//! encode/builder side "stays test-code-only: no production encoder exists anywhere in this
//! workspace; the responder only ever needs to *decode* one." That is true of the responder, but
//! a host or device that must present its own CONNECT has nothing to call. This module is the
//! production encoder for both arms (host: td-539ffa; device: td-e38932).
//!
//! A third copy of the shape is only safe while it agrees byte-for-byte with the other two. The
//! tests below compare each encoder's output against an independently hand-built
//! [`CborValue::map`], and helper-side tests compare them against the fixture encoders
//! byte-for-byte — the shapes are pinned by agreement, not by this module restating them.
//!
//! # Scope
//!
//! Both arms are encoded here; the `@spindle/proto` TypeScript twin is deliberately not included
//! yet (no browser producer exists). The shapes are:
//!
//! ```text
//! device: { "kind": "device", "root_pk": bytes32, "device_cert": bytes,
//!           "session_attest": bytes, "caps": [bytes, ...] }
//! host:   { "kind": "host", "host_root_pk": bytes32, "host_op_cert": bytes,
//!   "session_attest": bytes, "admission_token"?: bytes }
//! ```
//!
//! `device_cert`, `session_attest`, each entry of `caps`, `host_op_cert` and `admission_token`
//! are each the corresponding artifact's own `to_canonical_bytes()` output re-embedded as a CBOR
//! byte string, exactly as the helper's decoder expects. The caller passes them pre-encoded
//! because `spindle-proto` sits below `spindle-core` (A9c boundary rule 3) and has no access to
//! the signed-artifact types that own those encoders.
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

/// Encodes the device arm of a CONNECT `auth_token` envelope as canonical CBOR (no base64 — the
/// caller wraps it per DESIGN.md §A4). See the module docs for the shape and for why the artifact
/// bytes are passed in already encoded.
pub fn encode_device_auth_token(
    root_pk: &[u8; 32],
    device_cert_bytes: &[u8],
    session_attest_bytes: &[u8],
    caps_bytes: &[Vec<u8>],
) -> Vec<u8> {
    let caps = caps_bytes
        .iter()
        .map(|cap| CborValue::bytes(cap.clone()))
        .collect();
    let entries = vec![
        ("kind", CborValue::text("device")),
        ("root_pk", CborValue::bytes(root_pk.to_vec())),
        ("device_cert", CborValue::bytes(device_cert_bytes.to_vec())),
        (
            "session_attest",
            CborValue::bytes(session_attest_bytes.to_vec()),
        ),
        ("caps", CborValue::array(caps)),
    ];
    canonical_encode(&CborValue::map(entries))
}

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

    // ---- device arm (td-e38932) ----

    #[test]
    fn device_fields_round_trip_through_canonical_parsing() {
        let root_pk = [0x42; 32];
        let device_cert = [0x01, 0x02, 0x03];
        let session_attest = [0x04; 40];
        let caps = vec![vec![0xA0; 5], vec![0xA1; 424]];

        let bytes = encode_device_auth_token(&root_pk, &device_cert, &session_attest, &caps);
        let decoded = canonical_decode(&bytes).expect("encoder emits canonical CBOR");
        let map = decoded.as_map().expect("envelope is a CBOR map");

        assert_eq!(
            field(map, "kind").and_then(CborValue::as_text),
            Some("device")
        );
        assert_eq!(
            field(map, "root_pk").and_then(CborValue::as_bytes),
            Some(root_pk.as_slice())
        );
        assert_eq!(
            field(map, "device_cert").and_then(CborValue::as_bytes),
            Some(device_cert.as_slice())
        );
        assert_eq!(
            field(map, "session_attest").and_then(CborValue::as_bytes),
            Some(session_attest.as_slice())
        );
        let decoded_caps = field(map, "caps")
            .and_then(CborValue::as_array)
            .expect("caps is an array");
        assert_eq!(decoded_caps.len(), 2);
        assert_eq!(decoded_caps[0].as_bytes(), Some(caps[0].as_slice()));
        assert_eq!(decoded_caps[1].as_bytes(), Some(caps[1].as_slice()));
        assert_eq!(map.len(), 5);
    }

    /// Independent of the implementation: the expected value is assembled here as a
    /// [`CborValue::map`] and encoded directly, so a change to the encoder's map construction
    /// (field name, ordering intent, wrapping) has to be made in two places to stay green.
    #[test]
    fn device_emitted_bytes_equal_an_independently_hand_built_map() {
        let root_pk = [0x11; 32];
        let device_cert = [0xC0; 3];
        let session_attest = [0x5E; 33];
        let caps = vec![vec![0xD0; 7], vec![0xD1; 9]];

        let expected = CborValue::map(vec![
            ("kind", CborValue::text("device")),
            ("root_pk", CborValue::bytes(root_pk.to_vec())),
            ("device_cert", CborValue::bytes(device_cert.to_vec())),
            ("session_attest", CborValue::bytes(session_attest.to_vec())),
            (
                "caps",
                CborValue::array(vec![
                    CborValue::bytes(caps[0].clone()),
                    CborValue::bytes(caps[1].clone()),
                ]),
            ),
        ]);

        assert_eq!(
            encode_device_auth_token(&root_pk, &device_cert, &session_attest, &caps),
            canonical_encode(&expected)
        );
    }

    /// A device token with no caps is legal at this layer (the helper's decoder accepts it); the
    /// empty array must still be present rather than omitted.
    #[test]
    fn device_empty_caps_are_encoded_as_an_empty_array() {
        let bytes = encode_device_auth_token(&[0x01; 32], &[0x02], &[0x03], &[]);
        let decoded = canonical_decode(&bytes).expect("encoder emits canonical CBOR");
        let map = decoded.as_map().expect("envelope is a CBOR map");

        assert_eq!(
            field(map, "caps")
                .and_then(CborValue::as_array)
                .map(|caps| caps.len()),
            Some(0),
            "the caps key must be present as an empty array"
        );
    }
}
