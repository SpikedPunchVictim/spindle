//! Test-fixture identities/capabilities + the CONNECT `auth_token` wire envelope (DESIGN.md §A4:
//! "caps travel in the CONNECT `auth_token` as compact CBOR ... base64url").
//!
//! # The `auth_token` envelope (this spike's own addition — not a `spindle_proto` artifact type)
//! DESIGN.md/ADR-002 describe WHAT travels in `auth_token` (device certificate, session-nkey
//! attestation, capabilities — or, for a host, its operating-key certificate + admission token)
//! but not a concrete wire *shape* bundling them into one CBOR value. `spindle_proto::artifacts`
//! has no such envelope type (task constraint: do not add one there in this task). This module
//! defines a minimal one, gap flagged here rather than silently invented:
//!
//! ```text
//! device connection: { "kind": "device", "root_pk": bytes32, "device_cert": bytes, "caps": [bytes, ...] }
//! host connection:   { "kind": "host", "host_root_pk": bytes32, "host_op_cert": bytes,
//!                       "admission_token": bytes (present only if a token accompanies this connect) }
//! ```
//! `device_cert`/`host_op_cert`/`caps[i]`/`admission_token` are each the artifact's own
//! `to_canonical_bytes()` output re-embedded as a CBOR byte string — this only needs to be
//! symmetric with itself (encoder and decoder live in this same crate), not compatible with any
//! other wire format. The whole envelope is canonical-CBOR-encoded, then base64url (no padding)
//! for the CONNECT `auth_token` string, matching DESIGN.md's presentation rule.
//!
//! There is no separate "session-nkey attestation" artifact in this envelope: see
//! `src/bin/responder.rs`'s module docs for why `verify_nkey_sig` is satisfied by the real NATS
//! CONNECT-level nkey signature (the callout request's `connect_opts.sig`/`nats.user_nkey`)
//! rather than a bespoke `sig_device(nats_fp, ts)` artifact spindle-proto doesn't define.

use base64::Engine;
use nkeys::KeyPair;
use spindle_core::artifacts::{issue_capability, issue_device_certificate, issue_host_op_key_cert};
use spindle_core::identity::{DeviceKey, RootKey};
use spindle_core::{root_fp_of, Fingerprint};
use spindle_proto::artifacts::{
    AdmissionToken, CapKind, Capability, DeviceCertificate, HostOpKeyCert,
};
use spindle_proto::canonical::CborValue;

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?)
}

/// An nkey `KeyPair`'s raw 32-byte Ed25519 public key (nkeys encodes prefix+checksum around the
/// same raw key `ed25519_dalek::VerifyingKey` uses) — needed to compute `nats_fp = hash(nats_pk)`
/// (DESIGN.md §A4) from the NATS-level `user_nkey` the callout request carries.
pub fn nkey_public_raw(pubkey_str: &str) -> anyhow::Result<[u8; 32]> {
    let (_prefix, raw) = nkeys::from_public_key(pubkey_str)
        .map_err(|e| anyhow::anyhow!("bad nkey public key: {e}"))?;
    Ok(raw)
}

pub fn nats_fp_of_nkey(pubkey_str: &str) -> anyhow::Result<Fingerprint> {
    let raw = nkey_public_raw(pubkey_str)?;
    Ok(Fingerprint::of_parts(&[&raw]))
}

/// A test device identity: root key + device key + the device certificate binding it to a given
/// NATS session fingerprint.
pub struct DeviceIdentity {
    pub root: RootKey,
    pub device: DeviceKey,
    pub root_fp: Fingerprint,
    pub device_fp: Fingerprint,
}

pub fn new_device_identity(
    root_seed: [u8; 32],
    device_sign_seed: [u8; 32],
    device_agree_seed: [u8; 32],
) -> DeviceIdentity {
    let root = RootKey::from_seed(root_seed);
    let device = DeviceKey::from_seeds(device_sign_seed, device_agree_seed);
    let root_fp = root.root_fp();
    let device_fp = device.device_fp();
    DeviceIdentity {
        root,
        device,
        root_fp,
        device_fp,
    }
}

/// Issues a device certificate for `identity` binding it to `nats_fp`, `ts`, `exp`.
pub fn device_certificate(
    identity: &DeviceIdentity,
    nats_fp: Fingerprint,
    ts: u64,
    exp: u64,
) -> DeviceCertificate {
    issue_device_certificate(&identity.root, identity.device_fp, nats_fp, ts, exp)
}

/// A test host identity: host root key + operating key.
pub struct HostIdentity {
    pub root: RootKey,
    pub op_signing: ed25519_dalek::SigningKey,
    pub host_fp: Fingerprint,
}

pub fn new_host_identity(root_seed: [u8; 32], op_seed: [u8; 32]) -> HostIdentity {
    let root = RootKey::from_seed(root_seed);
    let op_signing = ed25519_dalek::SigningKey::from_bytes(&op_seed);
    let host_fp = root.root_fp();
    HostIdentity {
        root,
        op_signing,
        host_fp,
    }
}

pub fn host_op_key_cert(
    identity: &HostIdentity,
    nats_fp: Fingerprint,
    ts: u64,
    exp: u64,
) -> HostOpKeyCert {
    issue_host_op_key_cert(
        &identity.root,
        &identity.op_signing.verifying_key(),
        nats_fp,
        ts,
        exp,
    )
}

/// Issues a `member` capability for `subject` (a device's `root_fp`), signed by the host's
/// operating key.
pub fn member_capability(
    host: &HostIdentity,
    subject: Fingerprint,
    cap_epoch: u64,
    exp: u64,
    nonce: Vec<u8>,
) -> Capability {
    issue_capability(
        &host.op_signing,
        CapKind::Member,
        subject,
        cap_epoch,
        exp,
        nonce,
    )
}

pub fn invite_capability(
    host: &HostIdentity,
    subject: Fingerprint,
    exp: u64,
    nonce: Vec<u8>,
) -> Capability {
    issue_capability(&host.op_signing, CapKind::Invite, subject, 0, exp, nonce)
}

/// Builds the base64url canonical-CBOR `auth_token` for a device CONNECT (see module docs for
/// the envelope shape). `caps` may be empty (the fresh-key/no-cap negative test).
pub fn device_auth_token(
    root_pk_bytes: &[u8; 32],
    device_cert: &DeviceCertificate,
    caps: &[Capability],
) -> String {
    let cap_bytes: Vec<CborValue> = caps
        .iter()
        .map(|c| CborValue::bytes(c.to_canonical_bytes()))
        .collect();
    let env = CborValue::map(vec![
        ("kind", CborValue::text("device")),
        ("root_pk", CborValue::bytes(root_pk_bytes.to_vec())),
        (
            "device_cert",
            CborValue::bytes(device_cert.to_canonical_bytes()),
        ),
        ("caps", CborValue::array(cap_bytes)),
    ]);
    b64url(&spindle_proto::canonical_encode(&env))
}

/// Builds the base64url canonical-CBOR `auth_token` for a host CONNECT.
pub fn host_auth_token(
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
    let env = CborValue::map(entries);
    b64url(&spindle_proto::canonical_encode(&env))
}

/// A fresh key presenting a syntactically-empty device auth_token (no capabilities at all) —
/// the "fresh key with no cap" negative test (DESIGN.md §A13/§A5: "A connection presenting no
/// valid cap is refused").
pub fn no_cap_auth_token(root_pk_bytes: &[u8; 32], device_cert: &DeviceCertificate) -> String {
    device_auth_token(root_pk_bytes, device_cert, &[])
}

/// Decoded device auth_token payload, for the responder side.
pub struct DecodedDevicePayload {
    pub root_pk_bytes: [u8; 32],
    pub device_cert: DeviceCertificate,
    pub caps: Vec<Capability>,
}

pub struct DecodedHostPayload {
    pub host_root_pk_bytes: [u8; 32],
    pub host_op_cert: HostOpKeyCert,
    pub admission_token: Option<AdmissionToken>,
}

pub enum DecodedPayload {
    Device(DecodedDevicePayload),
    Host(DecodedHostPayload),
}

/// Decodes a base64url canonical-CBOR `auth_token` string (as produced by
/// [`device_auth_token`]/[`host_auth_token`]) back into its typed payload.
pub fn decode_auth_token(token: &str) -> anyhow::Result<DecodedPayload> {
    let bytes = b64url_decode(token)?;
    let val = spindle_proto::canonical_decode(&bytes)
        .map_err(|e| anyhow::anyhow!("bad auth_token CBOR: {e}"))?;
    let map = val
        .as_map()
        .ok_or_else(|| anyhow::anyhow!("auth_token is not a CBOR map"))?;
    let get = |key: &str| -> Option<&CborValue> {
        map.iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    };
    let kind = get("kind")
        .and_then(|v| v.as_text())
        .ok_or_else(|| anyhow::anyhow!("missing kind"))?;
    match kind {
        "device" => {
            let root_pk_bytes: [u8; 32] = get("root_pk")
                .and_then(|v| v.as_bytes())
                .ok_or_else(|| anyhow::anyhow!("missing root_pk"))?
                .try_into()
                .map_err(|_| anyhow::anyhow!("root_pk wrong length"))?;
            let device_cert_bytes = get("device_cert")
                .and_then(|v| v.as_bytes())
                .ok_or_else(|| anyhow::anyhow!("missing device_cert"))?;
            let device_cert = DeviceCertificate::from_canonical_bytes(device_cert_bytes)
                .map_err(|e| anyhow::anyhow!("bad device_cert: {e}"))?;
            let caps_arr = get("caps")
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow::anyhow!("missing caps"))?;
            let mut caps = Vec::with_capacity(caps_arr.len());
            for c in caps_arr {
                let bytes = c
                    .as_bytes()
                    .ok_or_else(|| anyhow::anyhow!("cap entry not bytes"))?;
                caps.push(
                    Capability::from_canonical_bytes(bytes)
                        .map_err(|e| anyhow::anyhow!("bad cap: {e}"))?,
                );
            }
            Ok(DecodedPayload::Device(DecodedDevicePayload {
                root_pk_bytes,
                device_cert,
                caps,
            }))
        }
        "host" => {
            let host_root_pk_bytes: [u8; 32] = get("host_root_pk")
                .and_then(|v| v.as_bytes())
                .ok_or_else(|| anyhow::anyhow!("missing host_root_pk"))?
                .try_into()
                .map_err(|_| anyhow::anyhow!("host_root_pk wrong length"))?;
            let host_op_cert_bytes = get("host_op_cert")
                .and_then(|v| v.as_bytes())
                .ok_or_else(|| anyhow::anyhow!("missing host_op_cert"))?;
            let host_op_cert = HostOpKeyCert::from_canonical_bytes(host_op_cert_bytes)
                .map_err(|e| anyhow::anyhow!("bad host_op_cert: {e}"))?;
            let admission_token = match get("admission_token") {
                Some(v) => {
                    let bytes = v
                        .as_bytes()
                        .ok_or_else(|| anyhow::anyhow!("admission_token not bytes"))?;
                    Some(
                        AdmissionToken::from_canonical_bytes(bytes)
                            .map_err(|e| anyhow::anyhow!("bad admission_token: {e}"))?,
                    )
                }
                None => None,
            };
            Ok(DecodedPayload::Host(DecodedHostPayload {
                host_root_pk_bytes,
                host_op_cert,
                admission_token,
            }))
        }
        other => Err(anyhow::anyhow!("unknown auth_token kind {other}")),
    }
}

/// Convenience: derive an `ed25519_dalek::VerifyingKey` from raw bytes (for handing
/// `root_pk`/`host_root_pk` to `spindle_helper::authz`'s `DeviceConnectPresented`/
/// `HostConnectPresented`).
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> anyhow::Result<ed25519_dalek::VerifyingKey> {
    Ok(ed25519_dalek::VerifyingKey::from_bytes(bytes)?)
}

/// Generates a fresh nkey `KeyPair` for a device/host CONNECT session, returning it alongside
/// its `nats_fp`.
pub fn new_session_nkey() -> anyhow::Result<(KeyPair, Fingerprint)> {
    let kp = KeyPair::new_user();
    let fp = nats_fp_of_nkey(&kp.public_key())?;
    Ok((kp, fp))
}

/// `root_fp_of` re-exported at fixture-call sites without importing `spindle_core` directly.
pub fn root_fp(pk: &ed25519_dalek::VerifyingKey) -> Fingerprint {
    root_fp_of(pk)
}
