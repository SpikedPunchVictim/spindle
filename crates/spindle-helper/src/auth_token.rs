//! Decodes the CONNECT `auth_token` envelope a device or host presents (DESIGN.md §A4: "caps
//! travel in the CONNECT `auth_token` as compact CBOR ... base64url").
//!
//! Graduated (decode side only) from `spikes/s1-callout/src/fixtures.rs`'s envelope, which that
//! module's own doc comment flags as **a gap, not a resolved design decision**: DESIGN.md/ADR-002
//! describe *what* travels in `auth_token` (a device certificate, capabilities, or — for a host —
//! its operating-key certificate + admission token) but not a concrete wire *shape* bundling them
//! into one CBOR value, and `spindle_proto::artifacts` has no such envelope type. That gap is
//! still open here — this module keeps the spike's exact envelope shape (so `src/bin/helper.rs`
//! can interoperate with the S1 test suite and anything else built against the same fixtures
//! module) rather than inventing a second, incompatible one:
//!
//! ```text
//! device connection: { "kind": "device", "root_pk": bytes32, "device_cert": bytes,
//!                       "session_attest": bytes, "caps": [bytes, ...] }
//! host connection:   { "kind": "host", "host_root_pk": bytes32, "host_op_cert": bytes,
//!                       "admission_token": bytes (present only if a token accompanies this connect) }
//! ```
//! Each of `device_cert`/`session_attest`/`host_op_cert`/`caps[i]`/`admission_token` is the
//! artifact's own `to_canonical_bytes()` output re-embedded as a CBOR byte string; the whole
//! envelope is canonical-CBOR-encoded, then base64url (no padding), matching DESIGN.md's
//! presentation rule. The **encode/builder** side of this envelope (`fixtures::device_auth_token`/
//! `fixtures::host_auth_token`) stays test-fixture-only in the spike crate — nothing but test
//! harnesses need to *build* one; the responder only ever needs to *decode* one.
//!
//! `session_attest` (added v0.9.29, td-0bcab4 §A4 step 2) is **required**, unlike
//! `admission_token` on the host arm above. It carries the [`SessionAttestation`] that binds this
//! device's identity key to the connecting session nkey (DESIGN.md §A3/§A4 step 2) — the fix for
//! the bearer-token defect where `{root_pk, device_cert, caps}` alone authorized a connection from
//! *any* nkey. Making it optional here would silently reinstate exactly that property for any
//! client that simply omitted the field: an "optional-but-checked-if-present" decode would still
//! let an old or stripped-down bundle through as a bearer token. `admission_token` is optional
//! because a host's *second and later* connections legitimately have none (DESIGN.md §A3b: an
//! already-admitted host connects on its cert alone) — there is no equivalent legitimate case here.

use base64::Engine;
use spindle_core::Fingerprint;
use spindle_proto::artifacts::{
    AdmissionToken, Capability, DeviceCertificate, HostOpKeyCert, SessionAttestation,
};
use spindle_proto::canonical::CborValue;

/// Errors decoding a presented `auth_token`. Internal-only, like [`crate::natsjwt::NatsJwtError`]
/// — never put on the wire; every caller collapses this to
/// [`crate::authz::UNIFORM_REFUSAL_MESSAGE`] (DESIGN.md §A5 "uniform silent drops").
#[derive(Debug, thiserror::Error)]
pub enum AuthTokenError {
    #[error("invalid base64url: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid canonical CBOR: {0}")]
    Cbor(String),
    #[error("auth_token is not a CBOR map")]
    NotAMap,
    #[error("missing field {0}")]
    MissingField(&'static str),
    #[error("field {0} has the wrong shape")]
    BadField(&'static str),
    #[error("unknown auth_token kind {0:?}")]
    UnknownKind(String),
    #[error("bad {0}: {1}")]
    BadArtifact(&'static str, String),
}

#[derive(Debug)]
pub struct DecodedDeviceAuthToken {
    pub root_pk_bytes: [u8; 32],
    pub device_cert: DeviceCertificate,
    /// §A4 step 2 (td-0bcab4): the device identity key's attestation binding this bundle to the
    /// connecting session nkey. Required — see the module docs' note on why this field, unlike
    /// `admission_token` on the host arm, has no "absent" case.
    pub session_attest: SessionAttestation,
    pub caps: Vec<Capability>,
}

#[derive(Debug)]
pub struct DecodedHostAuthToken {
    pub host_root_pk_bytes: [u8; 32],
    pub host_op_cert: HostOpKeyCert,
    pub admission_token: Option<AdmissionToken>,
}

#[derive(Debug)]
pub enum DecodedAuthToken {
    Device(DecodedDeviceAuthToken),
    Host(DecodedHostAuthToken),
}

fn cbor_map_get<'a>(map: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

fn bytes32(map: &[(CborValue, CborValue)], key: &'static str) -> Result<[u8; 32], AuthTokenError> {
    cbor_map_get(map, key)
        .and_then(|v| v.as_bytes())
        .ok_or(AuthTokenError::MissingField(key))?
        .try_into()
        .map_err(|_| AuthTokenError::BadField(key))
}

/// Decodes a base64url canonical-CBOR `auth_token` string (see module docs for the envelope
/// shape) into its typed payload.
pub fn decode_auth_token(token: &str) -> Result<DecodedAuthToken, AuthTokenError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token)?;
    let val = spindle_proto::canonical_decode(&bytes)
        .map_err(|e| AuthTokenError::Cbor(format!("{e:?}")))?;
    let map = val.as_map().ok_or(AuthTokenError::NotAMap)?;
    let kind = cbor_map_get(map, "kind")
        .and_then(|v| v.as_text())
        .ok_or(AuthTokenError::MissingField("kind"))?;

    match kind {
        "device" => {
            let root_pk_bytes = bytes32(map, "root_pk")?;
            let device_cert_bytes = cbor_map_get(map, "device_cert")
                .and_then(|v| v.as_bytes())
                .ok_or(AuthTokenError::MissingField("device_cert"))?;
            let device_cert = DeviceCertificate::from_canonical_bytes(device_cert_bytes)
                .map_err(|e| AuthTokenError::BadArtifact("device_cert", format!("{e:?}")))?;
            // Required, not optional — see the module docs' note on `session_attest`. A missing
            // field here fails the whole decode via `?`, exactly like `device_cert` above; there
            // is deliberately no `None`-on-absent branch the way `admission_token` gets below.
            let session_attest_bytes = cbor_map_get(map, "session_attest")
                .and_then(|v| v.as_bytes())
                .ok_or(AuthTokenError::MissingField("session_attest"))?;
            let session_attest = SessionAttestation::from_canonical_bytes(session_attest_bytes)
                .map_err(|e| AuthTokenError::BadArtifact("session_attest", format!("{e:?}")))?;
            let caps_arr = cbor_map_get(map, "caps")
                .and_then(|v| v.as_array())
                .ok_or(AuthTokenError::MissingField("caps"))?;
            let mut caps = Vec::with_capacity(caps_arr.len());
            for c in caps_arr {
                let b = c.as_bytes().ok_or(AuthTokenError::BadField("caps[]"))?;
                caps.push(
                    Capability::from_canonical_bytes(b)
                        .map_err(|e| AuthTokenError::BadArtifact("capability", format!("{e:?}")))?,
                );
            }
            Ok(DecodedAuthToken::Device(DecodedDeviceAuthToken {
                root_pk_bytes,
                device_cert,
                session_attest,
                caps,
            }))
        }
        "host" => {
            let host_root_pk_bytes = bytes32(map, "host_root_pk")?;
            let host_op_cert_bytes = cbor_map_get(map, "host_op_cert")
                .and_then(|v| v.as_bytes())
                .ok_or(AuthTokenError::MissingField("host_op_cert"))?;
            let host_op_cert = HostOpKeyCert::from_canonical_bytes(host_op_cert_bytes)
                .map_err(|e| AuthTokenError::BadArtifact("host_op_cert", format!("{e:?}")))?;
            let admission_token = match cbor_map_get(map, "admission_token") {
                Some(v) => {
                    let b = v
                        .as_bytes()
                        .ok_or(AuthTokenError::BadField("admission_token"))?;
                    Some(AdmissionToken::from_canonical_bytes(b).map_err(|e| {
                        AuthTokenError::BadArtifact("admission_token", format!("{e:?}"))
                    })?)
                }
                None => None,
            };
            Ok(DecodedAuthToken::Host(DecodedHostAuthToken {
                host_root_pk_bytes,
                host_op_cert,
                admission_token,
            }))
        }
        other => Err(AuthTokenError::UnknownKind(other.to_string())),
    }
}

/// `nats_fp = hash(nats_pk)` (DESIGN.md §A4) for a connection's presented nkey public key string.
pub fn nats_fp_of_nkey(pubkey_str: &str) -> Result<Fingerprint, AuthTokenError> {
    let (_prefix, raw) = nkeys::from_public_key(pubkey_str)
        .map_err(|e| AuthTokenError::BadArtifact("nkey", e.to_string()))?;
    Ok(Fingerprint::of_parts(&[&raw]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::artifacts::{
        issue_capability, issue_device_certificate, issue_host_op_key_cert,
        issue_session_attestation,
    };
    use spindle_core::identity::{DeviceKey, RootKey};
    use spindle_proto::artifacts::CapKind;

    fn b64url(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// `session_attest` is `Option` here purely so `rejects_a_device_token_missing_session_attest`
    /// can build an envelope that omits the field entirely — every other caller passes `Some(..)`.
    fn encode_device_token(
        root_pk_bytes: &[u8; 32],
        device_cert: &DeviceCertificate,
        session_attest: Option<&SessionAttestation>,
        caps: &[Capability],
    ) -> String {
        let cap_bytes: Vec<CborValue> = caps
            .iter()
            .map(|c| CborValue::bytes(c.to_canonical_bytes()))
            .collect();
        let mut entries = vec![
            ("kind", CborValue::text("device")),
            ("root_pk", CborValue::bytes(root_pk_bytes.to_vec())),
            (
                "device_cert",
                CborValue::bytes(device_cert.to_canonical_bytes()),
            ),
        ];
        if let Some(attest) = session_attest {
            entries.push((
                "session_attest",
                CborValue::bytes(attest.to_canonical_bytes()),
            ));
        }
        entries.push(("caps", CborValue::array(cap_bytes)));
        let env = CborValue::map(entries);
        b64url(&spindle_proto::canonical_encode(&env))
    }

    fn encode_host_token(
        host_root_pk_bytes: &[u8; 32],
        host_op_cert: &HostOpKeyCert,
        admission_token: Option<&AdmissionToken>,
    ) -> String {
        let mut entries = vec![
            ("kind", CborValue::text("host")),
            (
                "host_root_pk",
                CborValue::bytes(host_root_pk_bytes.to_vec()),
            ),
            (
                "host_op_cert",
                CborValue::bytes(host_op_cert.to_canonical_bytes()),
            ),
        ];
        if let Some(tok) = admission_token {
            entries.push((
                "admission_token",
                CborValue::bytes(tok.to_canonical_bytes()),
            ));
        }
        b64url(&spindle_proto::canonical_encode(&CborValue::map(entries)))
    }

    #[test]
    fn decodes_a_device_token_with_no_caps() {
        let root = RootKey::from_seed([0x01; 32]);
        let device = DeviceKey::from_seeds([0x02; 32], [0x03; 32]);
        let cert = issue_device_certificate(
            &root,
            device.alg_id(),
            &device.sign_public_key(),
            &device.agree_public_key(),
            0,
            2_000_000,
        );
        let nats_fp = Fingerprint::of_parts(&[b"nats"]);
        let attest = issue_session_attestation(&device, nats_fp, 0);
        let token = encode_device_token(&root.public_key().to_bytes(), &cert, Some(&attest), &[]);

        let decoded = decode_auth_token(&token).expect("decode succeeds");
        let DecodedAuthToken::Device(d) = decoded else {
            panic!("expected a device payload");
        };
        assert_eq!(d.root_pk_bytes, root.public_key().to_bytes());
        assert!(d.caps.is_empty());
    }

    #[test]
    fn decodes_a_device_token_with_a_capability() {
        let root = RootKey::from_seed([0x11; 32]);
        let device = DeviceKey::from_seeds([0x12; 32], [0x13; 32]);
        let cert = issue_device_certificate(
            &root,
            device.alg_id(),
            &device.sign_public_key(),
            &device.agree_public_key(),
            0,
            2_000_000,
        );
        let nats_fp = Fingerprint::of_parts(&[b"nats"]);
        let attest = issue_session_attestation(&device, nats_fp, 0);
        let host_root = RootKey::from_seed([0x21; 32]);
        let op_signer = spindle_core::SigningKey::from_bytes(&[0x22; 32]);
        let op_cert = issue_host_op_key_cert(
            &host_root,
            &op_signer.verifying_key(),
            Fingerprint::of_parts(&[b"op-cert"]),
            0,
            u64::MAX,
        );
        let cap = issue_capability(
            &host_root.public_key(),
            &op_cert,
            &op_signer,
            CapKind::Member,
            root.root_fp(),
            0,
            2_000_000,
            vec![0xAA; 8],
        );
        let token =
            encode_device_token(&root.public_key().to_bytes(), &cert, Some(&attest), &[cap]);

        let decoded = decode_auth_token(&token).expect("decode succeeds");
        let DecodedAuthToken::Device(d) = decoded else {
            panic!("expected a device payload");
        };
        assert_eq!(d.caps.len(), 1);
    }

    /// td-0bcab4: `session_attest` is required, not optional, on the device arm (see the module
    /// docs' note above). A device token that omits it entirely must fail to decode rather than
    /// decode successfully with some placeholder/absent value — an optional field here would
    /// silently reinstate the bearer-token property this fix exists to close.
    #[test]
    fn rejects_a_device_token_missing_session_attest() {
        let root = RootKey::from_seed([0x41; 32]);
        let device = DeviceKey::from_seeds([0x42; 32], [0x43; 32]);
        let cert = issue_device_certificate(
            &root,
            device.alg_id(),
            &device.sign_public_key(),
            &device.agree_public_key(),
            0,
            2_000_000,
        );
        let token = encode_device_token(&root.public_key().to_bytes(), &cert, None, &[]);

        let err = decode_auth_token(&token).unwrap_err();
        assert!(
            matches!(err, AuthTokenError::MissingField("session_attest")),
            "expected MissingField(\"session_attest\"), got {err:?}"
        );
    }

    #[test]
    fn decodes_a_host_token_with_no_admission_token() {
        let host_root = RootKey::from_seed([0x31; 32]);
        let op_signer = spindle_core::SigningKey::from_bytes(&[0x32; 32]);
        let cert = issue_host_op_key_cert(
            &host_root,
            &op_signer.verifying_key(),
            Fingerprint::of_parts(&[b"host-nats"]),
            0,
            2_000_000,
        );
        let token = encode_host_token(&host_root.public_key().to_bytes(), &cert, None);

        let decoded = decode_auth_token(&token).expect("decode succeeds");
        let DecodedAuthToken::Host(h) = decoded else {
            panic!("expected a host payload");
        };
        assert!(h.admission_token.is_none());
    }

    #[test]
    fn rejects_an_unknown_kind() {
        let env = CborValue::map(vec![("kind", CborValue::text("bogus"))]);
        let token = b64url(&spindle_proto::canonical_encode(&env));
        let err = decode_auth_token(&token).unwrap_err();
        assert!(matches!(err, AuthTokenError::UnknownKind(k) if k == "bogus"));
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = decode_auth_token("not!valid!base64").unwrap_err();
        assert!(matches!(err, AuthTokenError::Base64(_)));
    }

    #[test]
    fn nats_fp_of_nkey_matches_fingerprint_of_the_raw_public_key() {
        let kp = nkeys::KeyPair::new_user();
        let fp = nats_fp_of_nkey(&kp.public_key()).expect("valid nkey decodes");
        let (_prefix, raw) = nkeys::from_public_key(&kp.public_key()).unwrap();
        assert_eq!(fp, Fingerprint::of_parts(&[&raw]));
    }
}
