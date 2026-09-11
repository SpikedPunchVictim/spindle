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
//!                       "session_attest": bytes, "admission_token": bytes (present only if a
//!                       token accompanies this connect) }
//! ```
//! Each of `device_cert`/`session_attest` (both arms)/`host_op_cert`/`caps[i]`/`admission_token`
//! is the artifact's own `to_canonical_bytes()` output re-embedded as a CBOR byte string; the
//! whole envelope is canonical-CBOR-encoded, then base64url (no padding), matching DESIGN.md's
//! presentation rule. The **encode/builder** side of this envelope (`fixtures::device_auth_token`/
//! `fixtures::host_auth_token`) stays test-fixture-only in the spike crate — nothing but test
//! harnesses need to *build* one; the responder only ever needs to *decode* one.
//!
//! `session_attest` (device arm added v0.9.29, td-0bcab4 §A4 step 2; host arm added v0.9.31,
//! td-583db5) is **required** on both arms, unlike `admission_token` on the host arm above. On the
//! device side it carries a [`SessionAttestation`] binding the device's identity key to the
//! connecting session nkey (DESIGN.md §A3/§A4 step 2); on the host side it carries a
//! [`HostSessionAttestation`] binding the host's operating key to the connecting session nkey —
//! the per-connect binding that td-583db5 split out of `HostOpKeyCert` once that certificate's own
//! `nats_fp` field turned out to be enforced by exactly one manual comparison at one call site
//! (the td-0bcab4 defect class). Both are the fix for the same bearer-token defect: without them,
//! `{root_pk, device_cert, caps}` / `{host_root_pk, host_op_cert}` alone authorized a connection
//! from *any* nkey. Making either field optional here would silently reinstate that property for
//! any client that simply omitted it: an "optional-but-checked-if-present" decode would still let
//! an old or stripped-down bundle through as a bearer token. `admission_token` is optional because
//! a host's *second and later* connections legitimately have none (DESIGN.md §A3b: an
//! already-admitted host connects on its cert alone) — there is no equivalent legitimate case for
//! either `session_attest`.

use base64::Engine;
use spindle_core::Fingerprint;
use spindle_proto::artifacts::{
    AdmissionToken, Capability, DeviceCertificate, HostOpKeyCert, HostSessionAttestation,
    SessionAttestation,
};
use spindle_proto::canonical::CborValue;

/// MEASURED 2026-09-10, not estimated: DESIGN.md §A4/§A5's "A full 32-cap CONNECT token measures
/// **18,820 B**, **57%** of the 32 KiB ceiling" — the base64url length of a device's CONNECT
/// `auth_token` envelope (this module's device-connection shape, above) carrying a
/// `DeviceCertificate`, a `SessionAttestation`, and 32 member `Capability`s. Measured with
/// realistic Unix-seconds `ts`/`exp` throughout (~1.76e9 — a 5-byte CBOR uint, 1 byte per field
/// wider than a toy value like `ts: 0`/`exp: 2_000_000`) and each cap's **`FINGERPRINT_LEN`**-byte
/// nonce (32 bytes) — see `spindle_proto::artifacts::MEASURED_MEMBER_CAP_BYTES`'s doc comment for
/// that per-cap figure this token-level measurement is 32 of, plus a device cert and session
/// attestation on top. **This nonce length is now pinned, not assumed**: a test in
/// `spindle-host-core` (`production_issuer_mints_caps_at_exactly_measured_member_cap_bytes`) mints
/// a capability through the production `RootKeyCapIssuer` and asserts its encoded length equals
/// `MEASURED_MEMBER_CAP_BYTES`, and `realistic_member_cap` below builds its nonce from the same
/// `FINGERPRINT_LEN` constant — so a change to the production nonce length turns that test red,
/// rather than leaving this constant to drift out from under it silently again (previously
/// 13,571 B / 18,095 B / 55.2%, measured against a 16-byte nonce no production issuer ever
/// emitted — td-331c11). This crate's own figure is in turn pinned to `MEASURED_MEMBER_CAP_BYTES`
/// by the identity assertion in `keeps_measured_32_cap_token_bytes_honest` below, which mints
/// the envelope through `encode_device_token` — the same builder every other test in this
/// module uses.
#[cfg(test)]
const MEASURED_32_CAP_TOKEN_CBOR_BYTES: usize = 14_115;
/// The base64url (no padding) encoding of [`MEASURED_32_CAP_TOKEN_CBOR_BYTES`] — the length that
/// actually counts against nats-server's `max_control_line`, since DESIGN.md §A4 presents the
/// token base64url-encoded on the wire, not as raw CBOR.
#[cfg(test)]
const MEASURED_32_CAP_TOKEN_B64_BYTES: usize = 18_820;
/// The non-capability remainder of a 32-cap CONNECT token, so the token figure can be expressed as
/// `32 * MEASURED_MEMBER_CAP_BYTES + MEASURED_TOKEN_ENVELOPE_BYTES` rather than as a bare literal
/// that happens to agree with it. That identity is asserted in
/// `keeps_measured_32_cap_token_bytes_honest` below, alongside a per-cap length check without which
/// this constant would be a free variable absorbing any drift between that test's fixture and
/// `MEASURED_MEMBER_CAP_BYTES`.
///
/// It is NOT purely envelope, and the difference matters. Caps are embedded as CBOR byte strings
/// (see `encode_device_token` above), so each carries a length header of its own:
///
/// ```text
/// 547 = 449  envelope proper -- map framing, DeviceCertificate, SessionAttestation
///     +   2  caps array header (0x98 0x20, for 32 elements)
///     +  96  32 x 3-byte bstr headers (a 3-byte header spans 256..=65535 B)
/// ```
///
/// So this value is specific to 32 caps in that length bucket: a cap smaller than 256 B or larger
/// than 65,535 B changes the header width and moves this constant by 32 B, and a different cap
/// count moves both the array header and the per-cap total. Re-derive it rather than assuming it
/// is structural (td-331c11).
#[cfg(test)]
const MEASURED_TOKEN_ENVELOPE_BYTES: usize = 547;
/// nats-server's default `max_control_line` is 4 KiB; DESIGN.md §A4/A10.10 says the registry
/// raises this ceiling to 32 KiB specifically so a full 32-cap CONNECT bundle fits.
#[cfg(test)]
const NATS_MAX_CONTROL_LINE_BYTES: usize = 32 * 1024;

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
    /// v0.9.31 (td-583db5): the host operating key's attestation binding this bundle to the
    /// connecting session nkey — the per-connect twin of `DecodedDeviceAuthToken::session_attest`.
    /// Required — see the module docs' note on why this field, unlike `admission_token` below, has
    /// no "absent" case.
    pub session_attest: HostSessionAttestation,
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
            // Required, not optional — see the module docs' note on `session_attest`. A missing
            // field here fails the whole decode via `?`, exactly like `host_op_cert` above; there
            // is deliberately no `None`-on-absent branch the way `admission_token` gets below.
            let session_attest_bytes = cbor_map_get(map, "session_attest")
                .and_then(|v| v.as_bytes())
                .ok_or(AuthTokenError::MissingField("session_attest"))?;
            let session_attest = HostSessionAttestation::from_canonical_bytes(session_attest_bytes)
                .map_err(|e| AuthTokenError::BadArtifact("session_attest", format!("{e:?}")))?;
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
                session_attest,
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
        issue_host_session_attestation, issue_session_attestation,
    };
    use spindle_core::identity::{DeviceKey, RootKey};
    use spindle_core::FINGERPRINT_LEN;
    use spindle_proto::artifacts::CapKind;
    use std::fs;
    use std::path::{Path, PathBuf};

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

    /// `session_attest` is `Option` here purely so `rejects_a_host_token_missing_session_attest`
    /// can build an envelope that omits the field entirely — every other caller passes `Some(..)`.
    fn encode_host_token(
        host_root_pk_bytes: &[u8; 32],
        host_op_cert: &HostOpKeyCert,
        session_attest: Option<&HostSessionAttestation>,
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
        if let Some(attest) = session_attest {
            entries.push((
                "session_attest",
                CborValue::bytes(attest.to_canonical_bytes()),
            ));
        }
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
        let op_cert = issue_host_op_key_cert(&host_root, &op_signer.verifying_key(), 0, u64::MAX);
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
        let cert = issue_host_op_key_cert(&host_root, &op_signer.verifying_key(), 0, 2_000_000);
        let nats_fp = Fingerprint::of_parts(&[b"host-nats"]);
        let attest = issue_host_session_attestation(&op_signer, nats_fp, 0);
        let token = encode_host_token(
            &host_root.public_key().to_bytes(),
            &cert,
            Some(&attest),
            None,
        );

        let decoded = decode_auth_token(&token).expect("decode succeeds");
        let DecodedAuthToken::Host(h) = decoded else {
            panic!("expected a host payload");
        };
        assert!(h.admission_token.is_none());
    }

    /// td-583db5: `session_attest` is required, not optional, on the host arm (see the module
    /// docs' note above), mirroring `rejects_a_device_token_missing_session_attest`. A host token
    /// that omits it entirely must fail to decode rather than decode successfully with some
    /// placeholder/absent value — an optional field here would silently reinstate the
    /// bearer-token property this fix exists to close.
    #[test]
    fn rejects_a_host_token_missing_session_attest() {
        let host_root = RootKey::from_seed([0x51; 32]);
        let op_signer = spindle_core::SigningKey::from_bytes(&[0x52; 32]);
        let cert = issue_host_op_key_cert(&host_root, &op_signer.verifying_key(), 0, 2_000_000);
        let token = encode_host_token(&host_root.public_key().to_bytes(), &cert, None, None);

        let err = decode_auth_token(&token).unwrap_err();
        assert!(
            matches!(err, AuthTokenError::MissingField("session_attest")),
            "expected MissingField(\"session_attest\"), got {err:?}"
        );
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

    // ---- MEASURED_32_CAP_TOKEN_*_BYTES stays honest ----

    /// Builds one member [`Capability`] chained to its own freshly minted host, with realistic
    /// Unix-seconds timestamps throughout and a `FINGERPRINT_LEN`-byte nonce — see
    /// [`MEASURED_32_CAP_TOKEN_CBOR_BYTES`]'s doc comment for why realism matters here (a toy
    /// timestamp like the rest of this module's tests use understates every timestamp field by a
    /// byte, which is exactly the bug this measurement exists to catch) and for why the nonce
    /// length is the named constant `spindle_core::FINGERPRINT_LEN` rather than a bare literal
    /// (td-331c11: that constant is the nonce width the production `RootKeyCapIssuer` actually
    /// emits, and a test in `spindle-host-core` pins the two together by minting through that
    /// issuer and asserting the encoded capability length).
    fn realistic_member_cap(
        host_seed: u8,
        op_seed: u8,
        subject: Fingerprint,
        now: u64,
    ) -> Capability {
        const NINETY_DAYS: u64 = 90 * 86_400;
        const TWENTY_ONE_DAYS: u64 = 21 * 86_400;
        let host_root = RootKey::from_seed([host_seed; 32]);
        let op_signer = spindle_core::SigningKey::from_bytes(&[op_seed; 32]);
        let op_cert = issue_host_op_key_cert(
            &host_root,
            &op_signer.verifying_key(),
            now,
            now + NINETY_DAYS,
        );
        issue_capability(
            &host_root.public_key(),
            &op_cert,
            &op_signer,
            CapKind::Member,
            subject,
            7, // cap_epoch, matching DESIGN.md's own example
            now + TWENTY_ONE_DAYS,
            vec![0xAA; FINGERPRINT_LEN], // matches default_member_cap_nonce's actual length
        )
    }

    #[test]
    fn keeps_measured_32_cap_token_bytes_honest() {
        // DESIGN.md §A4/§A5's 32-cap CONNECT token figures are pinned here against a real
        // envelope: a device certificate, a session attestation, and 32 member caps, each minted
        // with realistic Unix-seconds timestamps and a `FINGERPRINT_LEN`-byte cap nonce (see
        // MEASURED_32_CAP_TOKEN_CBOR_BYTES's doc comment for why realism matters — a toy
        // `ts`/`exp` understates every timestamp field by a CBOR byte, and an envelope missing
        // device_cert or session_attest undercounts the whole thing — and `realistic_member_cap`'s
        // doc comment for why the nonce length is that named constant, not a bare literal).
        //
        // Every input this test mints with (`now`, every seed byte, the nonce) is a hardcoded
        // constant — nothing here reads a wall clock — so the encoded length reproduces
        // bit-for-bit on every run. td-331c11 tightened this from a scaled +/-2 B-per-artifact
        // tolerance (left over from when this figure was believed to vary run-to-run) to equality
        // assertions for that reason.
        let now = 1_755_907_200u64; // matches DESIGN.md's own reference measurement
        let root = RootKey::from_seed([0xE0; 32]);
        let device = DeviceKey::from_seeds([0xE1; 32], [0xE2; 32]);
        const NINETY_DAYS: u64 = 90 * 86_400;
        let device_cert = issue_device_certificate(
            &root,
            device.alg_id(),
            &device.sign_public_key(),
            &device.agree_public_key(),
            now,
            now + NINETY_DAYS,
        );
        let nats_fp = Fingerprint::of_parts(&[b"nats-session"]);
        let session_attest = issue_session_attestation(&device, nats_fp, now);
        let subject = root.root_fp();
        let caps: Vec<Capability> = (0u8..32)
            .map(|i| {
                realistic_member_cap(0xA0u8.wrapping_add(i), 0xB0u8.wrapping_add(i), subject, now)
            })
            .collect();
        let token = encode_device_token(
            &root.public_key().to_bytes(),
            &device_cert,
            Some(&session_attest),
            &caps,
        );

        let b64_len = token.len();
        let cbor_len = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&token)
            .expect("valid base64url")
            .len();

        // Without this, MEASURED_TOKEN_ENVELOPE_BYTES is a free variable: it silently absorbs any
        // divergence between this crate's fixture and the pinned per-cap figure, and the identity
        // below still passes. Demonstrated: minting 425 B caps here and repairing the three
        // literals leaves the whole suite green with MEASURED_MEMBER_CAP_BYTES still 424
        // (td-331c11).
        for (i, cap) in caps.iter().enumerate() {
            let len = cap.to_canonical_bytes().len();
            assert_eq!(
                len,
                spindle_proto::artifacts::MEASURED_MEMBER_CAP_BYTES,
                "cap {i} minted by this test encodes to {len} B, not MEASURED_MEMBER_CAP_BYTES \
                 ({} B) -- this test's envelope arithmetic below assumes every cap is exactly that \
                 size (td-331c11)",
                spindle_proto::artifacts::MEASURED_MEMBER_CAP_BYTES
            );
        }

        // The coupling that makes this crate's figures move with the per-cap figure. Without it,
        // `MEASURED_MEMBER_CAP_BYTES` could change and this test would stay green on a literal
        // that no longer describes 32 of anything (td-331c11).
        assert_eq!(
            MEASURED_32_CAP_TOKEN_CBOR_BYTES,
            32 * spindle_proto::artifacts::MEASURED_MEMBER_CAP_BYTES
                + MEASURED_TOKEN_ENVELOPE_BYTES,
            "MEASURED_32_CAP_TOKEN_CBOR_BYTES ({MEASURED_32_CAP_TOKEN_CBOR_BYTES} B) must equal 32 \
             caps ({} B each) plus the {MEASURED_TOKEN_ENVELOPE_BYTES} B envelope -- if \
             MEASURED_MEMBER_CAP_BYTES moved, this crate's token figures and DESIGN.md's must be \
             re-measured with it (td-331c11)",
            spindle_proto::artifacts::MEASURED_MEMBER_CAP_BYTES
        );

        assert_eq!(
            cbor_len, MEASURED_32_CAP_TOKEN_CBOR_BYTES,
            "32-cap token's raw canonical CBOR encoded to {cbor_len} B, expected exactly \
             MEASURED_32_CAP_TOKEN_CBOR_BYTES ({MEASURED_32_CAP_TOKEN_CBOR_BYTES} B) — this \
             measurement is fully deterministic, so any difference is a genuine drift: update \
             DESIGN.md §A4/§A5's 32-cap token figures and these constants together"
        );
        assert_eq!(
            b64_len, MEASURED_32_CAP_TOKEN_B64_BYTES,
            "32-cap token's base64url encoding is {b64_len} B, expected exactly \
             MEASURED_32_CAP_TOKEN_B64_BYTES ({MEASURED_32_CAP_TOKEN_B64_BYTES} B) — this \
             measurement is fully deterministic, so any difference is a genuine drift: update \
             DESIGN.md §A4/§A5's 32-cap token figures and these constants together"
        );

        // The "share of the 32 KiB ceiling" prose figure (18,820 / 32,768 = 57.4% computed,
        // which DESIGN.md §A4/§A5 rounds to 57%) is a pure function of b64_len, already
        // pinned exactly above — a separate
        // percentage-range assertion here could never independently fail (it would only ever
        // restate the assertion above in different units), so td-331c11 deleted the dead ±range
        // check that used to sit here (see MEASURED_32_CAP_TOKEN_CBOR_BYTES's doc comment for the
        // percentage itself). What replaced it asserts the actual functional requirement DESIGN.md
        // §A4/A10.10 raised `max_control_line` for in the first place — that a full 32-cap token
        // really does fit under the raised ceiling. Note it cannot fire independently either while
        // the exact-byte assertion above it holds; it is executable documentation of the
        // requirement, kept deliberately, not a second independent guard (td-331c11).
        assert!(
            b64_len < NATS_MAX_CONTROL_LINE_BYTES,
            "32-cap token ({b64_len} B) must fit under nats-server's raised \
             {NATS_MAX_CONTROL_LINE_BYTES}-byte max_control_line ceiling (DESIGN.md §A4/A10.10) — \
             this is the actual requirement the ceiling raise exists to satisfy"
        );
    }

    // ---- td-db47f9: the ceiling is read from the deployed config, not restated ----

    /// `crates/spindle-helper` sits two directories below the workspace root
    /// (`<root>/crates/spindle-helper`); derive `<root>` from `CARGO_MANIFEST_DIR` rather than
    /// the process's current directory, so this test doesn't depend on where `cargo test` was
    /// invoked from (mirrors `redaction_guard.rs`'s `workspace_root` in `spindle-core`).
    fn workspace_root() -> PathBuf {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .unwrap_or_else(|| {
                panic!(
                    "expected {} to be two directories below the workspace root",
                    manifest_dir.display()
                )
            })
            .to_path_buf();
        assert!(
            root.join("Cargo.toml").is_file(),
            "derived workspace root {} has no Cargo.toml -- CARGO_MANIFEST_DIR layout \
             assumption is wrong",
            root.display()
        );
        root
    }

    /// Scans `deploy/nats/nats-server.conf`'s text for every `max_control_line: <value>`
    /// setting and returns the single value found. Ignores comment lines (first non-whitespace
    /// char `#`) -- this is defensive, not load-bearing today: with the current exact
    /// `key.trim() == "max_control_line"` match, a commented-out line is already rejected by
    /// the `split_once(':')` check below (no comment line in this file's prose contains a
    /// colon), but the skip means a commented-out setting can never be mistaken for a live one
    /// if that key match is ever loosened. Tolerates the file's `key: value` form with
    /// surrounding whitespace and an optional trailing `# ...` comment after the value. Panics
    /// naming `conf_path` if no `max_control_line` setting is found at all -- a silently-absent
    /// setting must fail this test, never pass it vacuously -- and also panics naming
    /// `conf_path` if more than one is found: nats-server applies the *last* occurrence in the
    /// file, so a duplicate makes this file ambiguous and the agreement check below unsound
    /// (td-db47f9). Refusing here is deliberate -- this never "takes the last one".
    fn parse_max_control_line(conf_text: &str, conf_path: &Path) -> usize {
        let mut found: Vec<usize> = Vec::new();
        for line in conf_text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            let Some((key, rest)) = trimmed.split_once(':') else {
                continue;
            };
            if key.trim() != "max_control_line" {
                continue;
            }
            let value = rest.split('#').next().unwrap_or(rest).trim();
            let parsed: usize = value.parse().unwrap_or_else(|e| {
                panic!(
                    "{} sets max_control_line to {value:?}, which does not parse as a usize: \
                     {e}",
                    conf_path.display()
                )
            });
            found.push(parsed);
        }
        match found.len() {
            0 => panic!(
                "{} has no max_control_line setting -- td-db47f9's config/constant agreement \
                 test cannot run without one",
                conf_path.display()
            ),
            1 => found[0],
            n => panic!(
                "{} declares max_control_line {n} times ({found:?}) -- nats-server applies \
                 only the LAST occurrence in the file, so a duplicate makes this file ambiguous \
                 and td-db47f9's config/constant agreement check unsound; remove the duplicate \
                 before this test can run",
                conf_path.display()
            ),
        }
    }

    /// td-db47f9: `NATS_MAX_CONTROL_LINE_BYTES` above and `deploy/nats/nats-server.conf`'s
    /// `max_control_line` setting are two hand-kept copies of one operational limit, and until
    /// this test nothing checked they agreed. That gap was real, not hypothetical: an
    /// independent reviewer demonstrated it by changing the conf's `max_control_line` to 8192
    /// alone (leaving this Rust constant at `32 * 1024`), and the whole workspace test suite
    /// still passed 870/0/17 -- even though every real 32-cap CONNECT (18,820 B, see
    /// `MEASURED_32_CAP_TOKEN_B64_BYTES` above) would then be silently dropped by the deployed
    /// nats-server. This test reads the deployed value out of the conf file rather than
    /// restating it as a second Rust literal, and it refuses to run at all against a conf that
    /// declares `max_control_line` more than once (see `parse_max_control_line` above --
    /// nats-server applies only the last occurrence, so a duplicate would make the value this
    /// test reads unsound) -- so the two cannot drift apart *silently*. Stated precisely, what
    /// this checks is that `NATS_MAX_CONTROL_LINE_BYTES` equals the reference conf's single
    /// declared value -- not that no drift can ever occur.
    ///
    /// Limitation, stated plainly: this pins the *reference* config checked into `deploy/` --
    /// DESIGN.md §A4/§A10.10's worked example -- not whatever `max_control_line` a given
    /// operator actually runs their own nats-server deployment with. An operator who copies
    /// this file and edits it afterward is outside what this test can see. It is also a check
    /// on this one file's single declared value, not on the effective limit nats-server would
    /// enforce: nats-server's own `include` directive means a real deployment could still
    /// override `max_control_line` from another file this test never reads.
    #[test]
    fn nats_max_control_line_matches_deployed_conf() {
        let conf_path = workspace_root().join("deploy/nats/nats-server.conf");
        let conf_text = fs::read_to_string(&conf_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", conf_path.display()));
        let deployed = parse_max_control_line(&conf_text, &conf_path);
        assert_eq!(
            deployed, NATS_MAX_CONTROL_LINE_BYTES,
            "deploy/nats/nats-server.conf's max_control_line ({deployed} B) and this crate's \
             NATS_MAX_CONTROL_LINE_BYTES ({NATS_MAX_CONTROL_LINE_BYTES} B) have diverged -- the \
             32-cap CONNECT token figure above (MEASURED_32_CAP_TOKEN_B64_BYTES) is measured \
             against NATS_MAX_CONTROL_LINE_BYTES as a stand-in for the real ceiling nats-server \
             enforces, so both must move together (td-db47f9, DESIGN.md §A4/§A10.10)"
        );
    }

    #[test]
    fn nats_fp_of_nkey_matches_fingerprint_of_the_raw_public_key() {
        let kp = nkeys::KeyPair::new_user();
        let fp = nats_fp_of_nkey(&kp.public_key()).expect("valid nkey decodes");
        let (_prefix, raw) = nkeys::from_public_key(&kp.public_key()).unwrap();
        assert_eq!(fp, Fingerprint::of_parts(&[&raw]));
    }
}
