//! `gen-crypto-vectors` — writes `vectors/signed/`: real Ed25519 signatures (and, for the
//! envelope, a real AES-256-GCM seal) over the exact canonical bytes `spindle-proto`'s
//! `gen-vectors` already exercises. This is Stage 3's counterpart to
//! `crates/spindle-proto/src/bin/gen_vectors.rs`, which could only emit opaque dummy signature
//! bytes because `spindle-proto` has no crypto dependency (see that bin's module docs and
//! `vectors/README.md`'s "Signature validity" section).
//!
//! Every keypair here is derived from a **fixed, hardcoded 32-byte seed — TEST-ONLY**, never from
//! `OsRng`, so reruns are byte-identical (verified via `git diff` in `just vectors` / CI). None of
//! these seeds must ever be reused for anything but reproducing or validating this vector file.
//!
//! Mirrors `spindle-proto`'s `gen-vectors` bin's hand-rolled JSON writer rather than pulling in
//! `serde_json` — consistent with that bin's approach, and it keeps this bin's only dependency
//! surface being `spindle-core` itself (no additional crate needed just to write JSON).

use ed25519_dalek::{SigningKey, VerifyingKey};
use spindle_core::artifacts::{
    issue_admin_command, issue_admission_token, issue_capability, issue_device_certificate,
    issue_host_device_cert, issue_host_op_key_cert, issue_revocation_record, verify_admin_command,
    verify_admission_token, verify_capability, verify_device_certificate, verify_host_device_cert,
    verify_host_op_key_cert, verify_revocation_record,
};
use spindle_core::envelope::{
    derive_bootstrap_key, derive_session_key, open, seal, OpenParams, SealParams,
};
use spindle_core::{DeviceKey, Fingerprint, RootKey};
use spindle_proto::artifacts::CapKind;
use spindle_proto::canonical::CborValue;
use spindle_proto::signaling::KIND_OFFER;
use std::fs;
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

// ================================================================================================
// Minimal JSON writer — mirrors crates/spindle-proto/src/bin/gen_vectors.rs's hand-rolled writer
// (see that file's module docs for why: keeping vector-generator bins dependency-free rather than
// pulling in `serde_json`).
// ================================================================================================

enum Json {
    Str(String),
    UInt(u64),
    Bool(bool),
    Arr(Vec<Json>),
    Obj(Vec<(&'static str, Json)>),
}

impl Json {
    fn hex(bytes: &[u8]) -> Json {
        Json::Str(to_hex(bytes))
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_json(value: &Json, out: &mut String, indent: usize) {
    let pad = "  ".repeat(indent);
    let pad_in = "  ".repeat(indent + 1);
    match value {
        Json::Str(s) => write_json_string(s, out),
        Json::UInt(v) => out.push_str(&v.to_string()),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                out.push_str(&pad_in);
                write_json(item, out, indent + 1);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push(']');
        }
        Json::Obj(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (i, (k, v)) in entries.iter().enumerate() {
                out.push_str(&pad_in);
                write_json_string(k, out);
                out.push_str(": ");
                write_json(v, out, indent + 1);
                if i + 1 < entries.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push('}');
        }
    }
}

fn write_vector_file(dir: &Path, filename: &str, top: Json) {
    let mut s = String::new();
    write_json(&top, &mut s, 0);
    s.push('\n');
    let path = dir.join(filename);
    fs::write(&path, s).unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
    println!("wrote {}", path.display());
}

/// Mirrors `spindle-proto`'s `gen-vectors` bin's `cbor_to_json` exactly (same field names/shape)
/// so a reader cross-referencing `vectors/admin-command.json` (proto's opaque-signature vector)
/// against `vectors/signed/admin-command.json` (this bin's real-signature vector) sees the same
/// `args` representation in both.
fn cbor_to_json(v: &CborValue) -> Json {
    match v {
        CborValue::Uint(n) => Json::Obj(vec![
            ("type", Json::Str("uint".into())),
            ("value", Json::UInt(*n)),
        ]),
        CborValue::NegInt(n) => {
            let logical = -1i64 - (*n as i64);
            Json::Obj(vec![
                ("type", Json::Str("negint".into())),
                ("magnitude", Json::UInt(*n)),
                ("value", Json::Str(logical.to_string())),
            ])
        }
        CborValue::Bytes(b) => Json::Obj(vec![
            ("type", Json::Str("bytes".into())),
            ("value", Json::hex(b)),
        ]),
        CborValue::Text(s) => Json::Obj(vec![
            ("type", Json::Str("text".into())),
            ("value", Json::Str(s.clone())),
        ]),
        CborValue::Array(items) => Json::Obj(vec![
            ("type", Json::Str("array".into())),
            ("value", Json::Arr(items.iter().map(cbor_to_json).collect())),
        ]),
        CborValue::Map(entries) => Json::Obj(vec![
            ("type", Json::Str("map".into())),
            (
                "value",
                Json::Arr(
                    entries
                        .iter()
                        .map(|(k, v)| {
                            Json::Obj(vec![("key", cbor_to_json(k)), ("value", cbor_to_json(v))])
                        })
                        .collect(),
                ),
            ),
        ]),
        CborValue::Bool(b) => Json::Obj(vec![
            ("type", Json::Str("bool".into())),
            ("value", Json::Bool(*b)),
        ]),
        CborValue::Null => Json::Obj(vec![("type", Json::Str("null".into()))]),
    }
}

fn signed_vectors_dir() -> PathBuf {
    // crates/spindle-core -> repo root -> vectors/signed
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vectors")
        .join("signed")
}

// ================================================================================================
// TEST-ONLY fixed seeds. Never derived from OsRng; never reused outside this generator.
// ================================================================================================

const PERSON_ROOT_SEED: [u8; 32] = [0x01; 32]; // TEST-ONLY
const HOST_ROOT_SEED: [u8; 32] = [0x05; 32]; // TEST-ONLY
const HOST_OP_SEED: [u8; 32] = [0x06; 32]; // TEST-ONLY
const OPERATOR_SEED: [u8; 32] = [0x07; 32]; // TEST-ONLY

const DEVICE_A_SIGN_SEED: [u8; 32] = [0x10; 32]; // TEST-ONLY (client device, "from_fp" role)
const DEVICE_A_AGREE_SEED: [u8; 32] = [0x11; 32]; // TEST-ONLY
const DEVICE_A_EPH_SEED: [u8; 32] = [0x12; 32]; // TEST-ONLY

const DEVICE_B_SIGN_SEED: [u8; 32] = [0x20; 32]; // TEST-ONLY (host device, "to_fp" role)
const DEVICE_B_AGREE_SEED: [u8; 32] = [0x21; 32]; // TEST-ONLY
const DEVICE_B_EPH_SEED: [u8; 32] = [0x22; 32]; // TEST-ONLY

fn seed_field(label: &'static str, seed: &[u8; 32]) -> Json {
    Json::Obj(vec![
        ("label", Json::Str(label.to_string())),
        ("seed_hex", Json::hex(seed)),
    ])
}

fn main() {
    let dir = signed_vectors_dir();
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("failed to create {}: {e}", dir.display()));

    write_vector_file(
        &dir,
        "device-certificate.json",
        device_certificate_vectors(),
    );
    write_vector_file(&dir, "capability.json", capability_vectors());
    write_vector_file(&dir, "host-op-key-cert.json", host_op_key_cert_vectors());
    write_vector_file(&dir, "host-device-cert.json", host_device_cert_vectors());
    write_vector_file(&dir, "revocation-record.json", revocation_record_vectors());
    write_vector_file(&dir, "admission-token.json", admission_token_vectors());
    write_vector_file(&dir, "admin-command.json", admin_command_vectors());
    write_vector_file(&dir, "envelope.json", envelope_vectors());
}

fn case(
    name: &'static str,
    description: &'static str,
    decoded: Json,
    canonical_cbor: &[u8],
    signing_input: &[u8],
    sig: &[u8],
    signature_valid: bool,
) -> Json {
    Json::Obj(vec![
        ("name", Json::Str(name.into())),
        ("description", Json::Str(description.into())),
        ("decoded", decoded),
        ("canonical_cbor_hex", Json::hex(canonical_cbor)),
        ("signing_input_hex", Json::hex(signing_input)),
        ("signature_hex", Json::hex(sig)),
        ("signature_valid", Json::Bool(signature_valid)),
    ])
}

fn artifact_file(
    artifact: &'static str,
    tag: &'static [u8],
    signer: Json,
    cases: Vec<Json>,
) -> Json {
    Json::Obj(vec![
        ("artifact", Json::Str(artifact.into())),
        (
            "domain_tag",
            Json::Str(String::from_utf8(tag.to_vec()).unwrap()),
        ),
        ("signer", signer),
        ("cases", Json::Arr(cases)),
    ])
}

fn flip_last_byte(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    if let Some(last) = v.last_mut() {
        *last ^= 0xff;
    }
    v
}

// ---- DeviceCertificate ----

fn device_certificate_vectors() -> Json {
    let root = RootKey::from_seed(PERSON_ROOT_SEED);
    // A10.34: the certificate's device_fp is now derived from a real device identity's
    // (alg_id, sign_pk, agree_pk) rather than fabricated directly — an inconsistent certificate is
    // unconstructible through `issue_device_certificate` at all. Reuses `DEVICE_A_*` (the same
    // device identity `envelope_vectors` already uses) so the vector files describe one
    // consistent device.
    let device = DeviceKey::from_seeds(DEVICE_A_SIGN_SEED, DEVICE_A_AGREE_SEED);
    let nats_fp = Fingerprint::of_parts(&[b"gen-crypto-vectors:device-certificate:nats"]);
    let ts = 1_755_907_200;
    let exp = 1_787_443_200; // ts + 1 year

    let cert = issue_device_certificate(
        &root,
        device.alg_id(),
        &device.sign_public_key(),
        &device.agree_public_key(),
        nats_fp,
        ts,
        exp,
    );
    assert!(verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), ts).is_ok());

    fn decoded(c: &spindle_proto::artifacts::DeviceCertificate) -> Json {
        Json::Obj(vec![
            ("device_fp", Json::hex(&c.device_fp)),
            ("alg_id", Json::UInt(c.alg_id as u64)),
            ("sign_pk", Json::hex(&c.sign_pk)),
            ("agree_pk", Json::hex(&c.agree_pk)),
            ("nats_fp", Json::hex(&c.nats_fp)),
            ("ts", Json::UInt(c.ts)),
            ("exp", Json::UInt(c.exp)),
            ("sig_root", Json::hex(&c.sig_root)),
        ])
    }

    let mut tampered = cert.clone();
    tampered.sig_root = flip_last_byte(&cert.sig_root);
    assert!(verify_device_certificate(&tampered, &root.public_key(), &root.root_fp(), ts).is_err());

    let cases = vec![
        case(
            "valid",
            "Device certificate signed by the identity root; verifies under root_pk at now=ts.",
            decoded(&cert),
            &cert.to_canonical_bytes(),
            &cert.signing_input(),
            &cert.sig_root,
            true,
        ),
        case(
            "tampered_signature_last_byte",
            "sig_root's last byte flipped; verify_device_certificate must reject with BadSignature.",
            decoded(&tampered),
            &tampered.to_canonical_bytes(),
            &tampered.signing_input(),
            &tampered.sig_root,
            false,
        ),
    ];

    artifact_file(
        "DeviceCertificate",
        spindle_proto::tags::DEVICE_CERT_V1,
        Json::Obj(vec![
            ("role", Json::Str("identity_root".into())),
            ("seed", seed_field("TEST-ONLY", &PERSON_ROOT_SEED)),
            ("public_key_hex", Json::hex(root.public_key().as_bytes())),
            ("root_fp_hex", Json::hex(&root.root_fp().to_vec())),
        ]),
        cases,
    )
}

// ---- Capability ----

/// A10.30: `Capability` now carries the host root/op-key cert chain — `host_fp` is derived from
/// the host **root** key, and the capability embeds the same [`HostOpKeyCert`] artifact that
/// certifies the operating key which actually signs the capability. This vector's host reuses
/// `HOST_ROOT_SEED`/`HOST_OP_SEED` (the same identity as `host_op_key_cert_vectors`' host) so the
/// two vector files describe one consistent host across the whole chain.
fn capability_vectors() -> Json {
    use spindle_core::artifacts::issue_host_op_key_cert;

    let host_root = RootKey::from_seed(HOST_ROOT_SEED);
    let host_op = SigningKey::from_bytes(&HOST_OP_SEED);
    let op_cert_ts = 1_755_907_200;
    let op_cert_exp = 1_763_683_200; // ts + 90 days
    let op_cert = issue_host_op_key_cert(
        &host_root,
        &host_op.verifying_key(),
        Fingerprint::of_parts(&[b"gen-crypto-vectors:capability:op-cert-nats"]),
        op_cert_ts,
        op_cert_exp,
    );
    let subject = Fingerprint::of_parts(&[b"gen-crypto-vectors:capability:subject"]);
    let exp = 1_756_000_000;

    let cap = issue_capability(
        &host_root.public_key(),
        &op_cert,
        &host_op,
        CapKind::Member,
        subject,
        3,
        exp,
        vec![0x77; 16],
    );
    assert!(verify_capability(&cap, exp).is_ok());

    fn decoded(c: &spindle_proto::artifacts::Capability) -> Json {
        Json::Obj(vec![
            ("v", Json::UInt(c.v as u64)),
            ("host_fp", Json::hex(&c.host_fp)),
            ("host_root_pk", Json::hex(&c.host_root_pk)),
            ("op_cert", Json::hex(&c.op_cert)),
            ("kind", Json::UInt(c.kind as u64)),
            ("subject", Json::hex(&c.subject)),
            ("cap_epoch", Json::UInt(c.cap_epoch)),
            ("exp", Json::UInt(c.exp)),
            ("nonce", Json::hex(&c.nonce)),
            ("sig", Json::hex(&c.sig)),
        ])
    }

    let mut tampered = cap.clone();
    tampered.sig = flip_last_byte(&cap.sig);
    assert!(verify_capability(&tampered, exp).is_err());

    let cases = vec![
        case(
            "valid_member_cap",
            "Member capability chained root -> op cert -> capability sig (A10.30): host_fp = \
             SHA-256(host_root_pk), op_cert is the embedded real HostOpKeyCert, sig is by the \
             op key op_cert certifies.",
            decoded(&cap),
            &cap.to_canonical_bytes(),
            &cap.signing_input(),
            &cap.sig,
            true,
        ),
        case(
            "tampered_signature_last_byte",
            "sig's last byte flipped; verify_capability must reject with BadSignature.",
            decoded(&tampered),
            &tampered.to_canonical_bytes(),
            &tampered.signing_input(),
            &tampered.sig,
            false,
        ),
    ];

    artifact_file(
        "Capability",
        spindle_proto::tags::CAPABILITY_V1,
        Json::Obj(vec![
            (
                "role",
                Json::Str("host_root_and_operating_key_chain".into()),
            ),
            ("root_seed", seed_field("TEST-ONLY", &HOST_ROOT_SEED)),
            (
                "host_root_pk_hex",
                Json::hex(host_root.public_key().as_bytes()),
            ),
            ("host_fp_hex", Json::hex(&host_root.root_fp().to_vec())),
            ("op_seed", seed_field("TEST-ONLY", &HOST_OP_SEED)),
            (
                "op_public_key_hex",
                Json::hex(host_op.verifying_key().as_bytes()),
            ),
            (
                "op_cert_canonical_cbor_hex",
                Json::hex(&op_cert.to_canonical_bytes()),
            ),
        ]),
        cases,
    )
}

// ---- HostOpKeyCert ----

fn host_op_key_cert_vectors() -> Json {
    let host_root = RootKey::from_seed(HOST_ROOT_SEED);
    let host_op_pk = SigningKey::from_bytes(&HOST_OP_SEED).verifying_key();
    let nats_fp = Fingerprint::of_parts(&[b"gen-crypto-vectors:host-op-key-cert:nats"]);
    let ts = 1_755_907_200;
    let exp = 1_763_683_200; // ts + 90 days

    let cert = issue_host_op_key_cert(&host_root, &host_op_pk, nats_fp, ts, exp);
    assert!(
        verify_host_op_key_cert(&cert, &host_root.public_key(), &host_root.root_fp(), ts).is_ok()
    );

    fn decoded(c: &spindle_proto::artifacts::HostOpKeyCert) -> Json {
        Json::Obj(vec![
            ("host_op_pk", Json::hex(&c.host_op_pk)),
            ("nats_fp", Json::hex(&c.nats_fp)),
            ("ts", Json::UInt(c.ts)),
            ("exp", Json::UInt(c.exp)),
            ("sig_host_root", Json::hex(&c.sig_host_root)),
        ])
    }

    let mut tampered = cert.clone();
    tampered.sig_host_root = flip_last_byte(&cert.sig_host_root);
    assert!(
        verify_host_op_key_cert(&tampered, &host_root.public_key(), &host_root.root_fp(), ts)
            .is_err()
    );

    let cases = vec![
        case(
            "valid",
            "Host operating-key certificate signed by the host root.",
            decoded(&cert),
            &cert.to_canonical_bytes(),
            &cert.signing_input(),
            &cert.sig_host_root,
            true,
        ),
        case(
            "tampered_signature_last_byte",
            "sig_host_root's last byte flipped; verify_host_op_key_cert must reject with BadSignature.",
            decoded(&tampered),
            &tampered.to_canonical_bytes(),
            &tampered.signing_input(),
            &tampered.sig_host_root,
            false,
        ),
    ];

    artifact_file(
        "HostOpKeyCert",
        spindle_proto::tags::HOST_OP_KEY_CERT_V1,
        Json::Obj(vec![
            ("role", Json::Str("host_root".into())),
            ("seed", seed_field("TEST-ONLY", &HOST_ROOT_SEED)),
            (
                "public_key_hex",
                Json::hex(host_root.public_key().as_bytes()),
            ),
            ("root_fp_hex", Json::hex(&host_root.root_fp().to_vec())),
        ]),
        cases,
    )
}

// ---- HostDeviceCert ----

/// A10.35: `HostDeviceCert` chains root -> op key -> a dedicated host device key, the host's own
/// §A7 envelope identity. Reuses `HOST_ROOT_SEED`/`HOST_OP_SEED` (the same host identity
/// `host_op_key_cert_vectors`/`capability_vectors` already use) and `DEVICE_B_SIGN_SEED`/
/// `DEVICE_B_AGREE_SEED` (already labeled "host device" — the same identity `envelope_vectors`
/// uses in the `to_fp` role) so all four vector files describe one consistent host end to end.
fn host_device_cert_vectors() -> Json {
    let host_root = RootKey::from_seed(HOST_ROOT_SEED);
    let host_op = SigningKey::from_bytes(&HOST_OP_SEED);
    let op_cert_ts = 1_755_907_200;
    let op_cert_exp = 1_763_683_200; // ts + 90 days
    let op_cert = issue_host_op_key_cert(
        &host_root,
        &host_op.verifying_key(),
        Fingerprint::of_parts(&[b"gen-crypto-vectors:host-device-cert:op-cert-nats"]),
        op_cert_ts,
        op_cert_exp,
    );

    let host_device = DeviceKey::from_seeds(DEVICE_B_SIGN_SEED, DEVICE_B_AGREE_SEED);
    let ts = 1_755_907_200;
    let exp = 1_763_683_200; // ts + 90 days, rotation-scale like the op cert

    let cert = issue_host_device_cert(
        &host_op,
        host_root.root_fp(),
        &host_root.public_key(),
        &op_cert,
        host_device.alg_id(),
        &host_device.sign_public_key(),
        &host_device.agree_public_key(),
        ts,
        exp,
    );
    assert!(verify_host_device_cert(&cert, &host_root.root_fp(), ts).is_ok());

    fn decoded(c: &spindle_proto::artifacts::HostDeviceCert) -> Json {
        Json::Obj(vec![
            ("host_fp", Json::hex(&c.host_fp)),
            ("host_root_pk", Json::hex(&c.host_root_pk)),
            ("op_cert", Json::hex(&c.op_cert)),
            ("host_device_fp", Json::hex(&c.host_device_fp)),
            ("alg_id", Json::UInt(c.alg_id as u64)),
            ("sign_pk", Json::hex(&c.sign_pk)),
            ("agree_pk", Json::hex(&c.agree_pk)),
            ("ts", Json::UInt(c.ts)),
            ("exp", Json::UInt(c.exp)),
            ("sig_host_op", Json::hex(&c.sig_host_op)),
        ])
    }

    let mut tampered = cert.clone();
    tampered.sig_host_op = flip_last_byte(&cert.sig_host_op);
    assert!(verify_host_device_cert(&tampered, &host_root.root_fp(), ts).is_err());

    let cases = vec![
        case(
            "valid",
            "Host device certificate chained root -> op cert -> device sig (A10.35): host_fp = \
             SHA-256(host_root_pk), op_cert is the embedded real HostOpKeyCert, host_device_fp is \
             the host's dedicated A7 envelope identity, sig_host_op is by the op key op_cert \
             certifies.",
            decoded(&cert),
            &cert.to_canonical_bytes(),
            &cert.signing_input(),
            &cert.sig_host_op,
            true,
        ),
        case(
            "tampered_signature_last_byte",
            "sig_host_op's last byte flipped; verify_host_device_cert must reject with BadSignature.",
            decoded(&tampered),
            &tampered.to_canonical_bytes(),
            &tampered.signing_input(),
            &tampered.sig_host_op,
            false,
        ),
    ];

    artifact_file(
        "HostDeviceCert",
        spindle_proto::tags::HOST_DEVICE_CERT_V1,
        Json::Obj(vec![
            (
                "role",
                Json::Str("host_root_and_operating_key_chain".into()),
            ),
            ("root_seed", seed_field("TEST-ONLY", &HOST_ROOT_SEED)),
            (
                "host_root_pk_hex",
                Json::hex(host_root.public_key().as_bytes()),
            ),
            ("host_fp_hex", Json::hex(&host_root.root_fp().to_vec())),
            ("op_seed", seed_field("TEST-ONLY", &HOST_OP_SEED)),
            (
                "op_public_key_hex",
                Json::hex(host_op.verifying_key().as_bytes()),
            ),
            (
                "op_cert_canonical_cbor_hex",
                Json::hex(&op_cert.to_canonical_bytes()),
            ),
            (
                "host_device_sign_seed",
                seed_field("TEST-ONLY", &DEVICE_B_SIGN_SEED),
            ),
            (
                "host_device_agree_seed",
                seed_field("TEST-ONLY", &DEVICE_B_AGREE_SEED),
            ),
        ]),
        cases,
    )
}

// ---- RevocationRecord ----

fn revocation_record_vectors() -> Json {
    let host_op = SigningKey::from_bytes(&HOST_OP_SEED);
    let host_fp = Fingerprint::of_parts(&[b"gen-crypto-vectors:revocation-record:host"]);
    let revoked_device = Fingerprint::of_parts(&[b"gen-crypto-vectors:revocation-record:device"]);
    let ts = 1_755_907_200;

    let rec = issue_revocation_record(&host_op, host_fp, 1, vec![revoked_device], ts);
    assert!(verify_revocation_record(&rec, &host_op.verifying_key()).is_ok());

    fn decoded(r: &spindle_proto::artifacts::RevocationRecord) -> Json {
        Json::Obj(vec![
            ("host_fp", Json::hex(&r.host_fp)),
            ("epoch", Json::UInt(r.epoch)),
            (
                "revoked",
                Json::Arr(r.revoked.iter().map(|fp| Json::hex(fp)).collect()),
            ),
            ("ts", Json::UInt(r.ts)),
            ("sig", Json::hex(&r.sig)),
        ])
    }

    let mut tampered = rec.clone();
    tampered.sig = flip_last_byte(&rec.sig);
    assert!(verify_revocation_record(&tampered, &host_op.verifying_key()).is_err());

    let cases = vec![
        case(
            "valid",
            "Revocation record signed by the host operating key (one device revoked at epoch 1).",
            decoded(&rec),
            &rec.to_canonical_bytes(),
            &rec.signing_input(),
            &rec.sig,
            true,
        ),
        case(
            "tampered_signature_last_byte",
            "sig's last byte flipped; verify_revocation_record must reject with BadSignature.",
            decoded(&tampered),
            &tampered.to_canonical_bytes(),
            &tampered.signing_input(),
            &tampered.sig,
            false,
        ),
    ];

    artifact_file(
        "RevocationRecord",
        spindle_proto::tags::REVOCATION_V1,
        Json::Obj(vec![
            ("role", Json::Str("host_operating_key".into())),
            ("seed", seed_field("TEST-ONLY", &HOST_OP_SEED)),
            (
                "public_key_hex",
                Json::hex(host_op.verifying_key().as_bytes()),
            ),
        ]),
        cases,
    )
}

// ---- AdmissionToken ----

fn admission_token_vectors() -> Json {
    let operator = SigningKey::from_bytes(&OPERATOR_SEED);
    let exp = 1_756_512_000;

    let tok = issue_admission_token(
        &operator,
        vec![0x61; 16],
        exp,
        "workshop-nas".to_string(),
        "default".to_string(),
    );
    assert!(verify_admission_token(&tok, &operator.verifying_key(), exp).is_ok());

    fn decoded(t: &spindle_proto::artifacts::AdmissionToken) -> Json {
        Json::Obj(vec![
            ("nonce", Json::hex(&t.nonce)),
            ("exp", Json::UInt(t.exp)),
            ("label", Json::Str(t.label.clone())),
            ("quota_profile", Json::Str(t.quota_profile.clone())),
            ("sig_operator", Json::hex(&t.sig_operator)),
        ])
    }

    let mut tampered = tok.clone();
    tampered.sig_operator = flip_last_byte(&tok.sig_operator);
    assert!(verify_admission_token(&tampered, &operator.verifying_key(), exp).is_err());

    let cases = vec![
        case(
            "valid",
            "Admission token signed by the operator admission key.",
            decoded(&tok),
            &tok.to_canonical_bytes(),
            &tok.signing_input(),
            &tok.sig_operator,
            true,
        ),
        case(
            "tampered_signature_last_byte",
            "sig_operator's last byte flipped; verify_admission_token must reject with BadSignature.",
            decoded(&tampered),
            &tampered.to_canonical_bytes(),
            &tampered.signing_input(),
            &tampered.sig_operator,
            false,
        ),
    ];

    artifact_file(
        "AdmissionToken",
        spindle_proto::tags::ADMISSION_TOKEN_V1,
        Json::Obj(vec![
            ("role", Json::Str("operator_admission_key".into())),
            ("seed", seed_field("TEST-ONLY", &OPERATOR_SEED)),
            (
                "public_key_hex",
                Json::hex(operator.verifying_key().as_bytes()),
            ),
        ]),
        cases,
    )
}

// ---- AdminCommand ----

fn admin_command_vectors() -> Json {
    let operator = SigningKey::from_bytes(&OPERATOR_SEED);
    let signer_fp = Fingerprint::of_parts(&[b"gen-crypto-vectors:admin-command:signer"]);
    let ts = 1_755_907_200;

    let cmd = issue_admin_command(
        &operator,
        1,
        "evict_host".to_string(),
        CborValue::map(vec![(
            "host_fp",
            CborValue::bytes(Fingerprint::of_parts(&[b"evicted-host"]).to_vec()),
        )]),
        signer_fp.to_vec(),
        12,
        vec![0x93; 16],
        ts,
    );
    assert!(verify_admin_command(&cmd, &operator.verifying_key(), ts).is_ok());

    fn decoded(c: &spindle_proto::artifacts::AdminCommand) -> Json {
        Json::Obj(vec![
            ("v", Json::UInt(c.v as u64)),
            ("cmd", Json::Str(c.cmd.clone())),
            ("args", cbor_to_json(&c.args)),
            ("signer_fp", Json::hex(&c.signer_fp)),
            ("seq", Json::UInt(c.seq)),
            ("nonce", Json::hex(&c.nonce)),
            ("ts", Json::UInt(c.ts)),
            ("sig", Json::hex(&c.sig)),
        ])
    }

    let mut tampered = cmd.clone();
    tampered.sig = flip_last_byte(&cmd.sig);
    assert!(verify_admin_command(&tampered, &operator.verifying_key(), ts).is_err());

    let cases = vec![
        case(
            "valid",
            "Admin command signed by the operator admission key.",
            decoded(&cmd),
            &cmd.to_canonical_bytes(),
            &cmd.signing_input(),
            &cmd.sig,
            true,
        ),
        case(
            "tampered_signature_last_byte",
            "sig's last byte flipped; verify_admin_command must reject with BadSignature.",
            decoded(&tampered),
            &tampered.to_canonical_bytes(),
            &tampered.signing_input(),
            &tampered.sig,
            false,
        ),
    ];

    artifact_file(
        "AdminCommand",
        spindle_proto::tags::ADMIN_COMMAND_V1,
        Json::Obj(vec![
            ("role", Json::Str("operator_admission_key".into())),
            ("seed", seed_field("TEST-ONLY", &OPERATOR_SEED)),
            (
                "public_key_hex",
                Json::hex(operator.verifying_key().as_bytes()),
            ),
        ]),
        cases,
    )
}

// ---- Envelope ----

struct DeviceFixture {
    label: &'static str,
    sign_seed: [u8; 32],
    agree_seed: [u8; 32],
    eph_seed: [u8; 32],
    device: DeviceKey,
    sign_pk: VerifyingKey,
    agree_pk: X25519PublicKey,
    eph_secret: StaticSecret,
    eph_pk: X25519PublicKey,
    fp: Fingerprint,
}

fn build_device_fixture(
    label: &'static str,
    sign_seed: [u8; 32],
    agree_seed: [u8; 32],
    eph_seed: [u8; 32],
) -> DeviceFixture {
    let device = DeviceKey::from_seeds(sign_seed, agree_seed);
    let sign_pk = device.sign_public_key();
    let agree_pk = device.agree_public_key();
    let eph_secret = StaticSecret::from(eph_seed);
    let eph_pk = X25519PublicKey::from(&eph_secret);
    let fp = device.device_fp();
    DeviceFixture {
        label,
        sign_seed,
        agree_seed,
        eph_seed,
        device,
        sign_pk,
        agree_pk,
        eph_secret,
        eph_pk,
        fp,
    }
}

fn device_fixture_json(fx: &DeviceFixture) -> Json {
    Json::Obj(vec![
        ("role", Json::Str(fx.label.to_string())),
        ("sign_seed", seed_field("TEST-ONLY", &fx.sign_seed)),
        ("sign_pk_hex", Json::hex(fx.sign_pk.as_bytes())),
        ("agree_seed", seed_field("TEST-ONLY", &fx.agree_seed)),
        ("agree_pk_hex", Json::hex(fx.agree_pk.as_bytes())),
        ("eph_seed", seed_field("TEST-ONLY", &fx.eph_seed)),
        ("eph_pk_hex", Json::hex(fx.eph_pk.as_bytes())),
        ("device_fp_hex", Json::hex(&fx.fp.to_vec())),
    ])
}

#[allow(clippy::too_many_arguments)]
fn envelope_case(
    name: &'static str,
    description: &'static str,
    direction: u8,
    seq: u64,
    ts: u64,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &[u8],
    envelope_bytes: &[u8],
    signing_input: &[u8],
    sig: &[u8],
    signature_valid: bool,
    decrypts_ok: bool,
) -> Json {
    Json::Obj(vec![
        ("name", Json::Str(name.into())),
        ("description", Json::Str(description.into())),
        ("direction_byte", Json::UInt(direction as u64)),
        ("seq", Json::UInt(seq)),
        ("ts", Json::UInt(ts)),
        ("nonce_hex", Json::hex(nonce)),
        ("aad_hex", Json::hex(aad)),
        ("plaintext_hex", Json::hex(plaintext)),
        ("ciphertext_hex", Json::hex(ciphertext)),
        ("envelope_canonical_cbor_hex", Json::hex(envelope_bytes)),
        ("signing_input_hex", Json::hex(signing_input)),
        ("signature_hex", Json::hex(sig)),
        ("signature_valid", Json::Bool(signature_valid)),
        ("decrypts_ok", Json::Bool(decrypts_ok)),
    ])
}

fn envelope_vectors() -> Json {
    let a = build_device_fixture(
        "device_a (client; from_fp role in session-key info)",
        DEVICE_A_SIGN_SEED,
        DEVICE_A_AGREE_SEED,
        DEVICE_A_EPH_SEED,
    );
    let b = build_device_fixture(
        "device_b (host; to_fp role in session-key info)",
        DEVICE_B_SIGN_SEED,
        DEVICE_B_AGREE_SEED,
        DEVICE_B_EPH_SEED,
    );

    let eph_dh = *a.eph_secret.diffie_hellman(&b.eph_pk).as_bytes();
    let dev_dh = a.device.diffie_hellman(&b.agree_pk);
    let sid = vec![0xAB; 16];
    let session_key = derive_session_key(&eph_dh, &dev_dh, &sid, &a.fp, &b.fp);

    // DESIGN.md §A7 (amended v0.9.14): `bootstrap_key` (k0) is derived from the *exact same*
    // (eph_dh, dev_dh, sid, from_fp, to_fp) inputs as `session_key` (k1) above, purely to make the
    // domain-separation property visible in this vector file: identical inputs, two different info
    // domains, two different keys. A real offer's k0 uses a different `eph_dh` (ephemeral-static, not
    // ephemeral-ephemeral — see envelope.rs's `derive_bootstrap_key` doc comment) but reusing the
    // already-computed DH terms here keeps this vector focused on the one property it needs to prove.
    let bootstrap_key = derive_bootstrap_key(&eph_dh, &dev_dh, &sid, &a.fp, &b.fp);
    assert_ne!(
        session_key.as_bytes(),
        bootstrap_key.as_bytes(),
        "k0 and k1 must differ for identical inputs"
    );

    let ts = 1_755_907_200;
    let plaintext = b"spindle envelope vector plaintext".to_vec();

    let env = seal(SealParams {
        session_key: &session_key,
        signer: &a.device,
        v: 1,
        alg_id: 1,
        from_fp: a.fp,
        to_fp: b.fp,
        sid: sid.clone(),
        kind: 1,
        seq: 0,
        ts,
        eph_pk: Some(a.eph_pk.as_bytes().to_vec()),
        plaintext: &plaintext,
    });

    // Recompute the AAD/nonce independently (not reading them back off `env`) so the vector
    // demonstrates the receiver-side derivation a TS twin must reproduce, not just an echo.
    let direction = spindle_core::direction_byte(&a.fp, &b.fp);
    let mut nonce = [0u8; 12];
    nonce[0] = direction;
    nonce[4..12].copy_from_slice(&0u64.to_be_bytes());
    let aad = env.header_canonical_bytes();

    let opened = open(
        OpenParams {
            session_key: &session_key,
            pinned_sender_key: &a.sign_pk,
            self_fp: &b.fp,
            expected_sid: &sid,
            bound_from_fp: None,
            min_seq_exclusive: None,
            now: ts,
            min_v: 1,
            min_alg_id: 1,
            expected_kind: 1,
            sender_revoked: false,
        },
        &env,
    )
    .expect("valid envelope opens");
    assert_eq!(opened, plaintext);

    let valid_case = envelope_case(
        "a_to_b_first_message",
        "First envelope of the session, A (client) -> B (host): eph_pk present, seq=0.",
        direction,
        0,
        ts,
        &nonce,
        &aad,
        &plaintext,
        &env.ciphertext,
        &env.to_canonical_bytes(),
        &env.signing_input(),
        &env.sig,
        true,
        true,
    );

    // Negative case: tamper the signature; open() must reject with BadSignature (not attempted
    // here since `open` needs `spindle_core::EnvelopeError` — this vector records the byte-level
    // fact for a TS twin's own negative test).
    let mut tampered = env.clone();
    tampered.sig = flip_last_byte(&env.sig);
    let tampered_open = open(
        OpenParams {
            session_key: &session_key,
            pinned_sender_key: &a.sign_pk,
            self_fp: &b.fp,
            expected_sid: &sid,
            bound_from_fp: None,
            min_seq_exclusive: None,
            now: ts,
            min_v: 1,
            min_alg_id: 1,
            expected_kind: 1,
            sender_revoked: false,
        },
        &tampered,
    );
    assert!(tampered_open.is_err());

    let tampered_case = envelope_case(
        "tampered_signature_last_byte",
        "sig's last byte flipped; open() must reject with BadSignature.",
        direction,
        0,
        ts,
        &nonce,
        &aad,
        &plaintext,
        &tampered.ciphertext,
        &tampered.to_canonical_bytes(),
        &tampered.signing_input(),
        &tampered.sig,
        false,
        false,
    );

    // Offer-shaped case (DESIGN.md §A7 v0.9.14): demonstrates an envelope sealed under k0 instead of
    // k1. Uses `kind: KIND_OFFER` (spindle_proto::signaling), the named wire constant for an offer
    // payload's envelope kind — not a bare marker literal. Kept as its own top-level `offer_case`
    // field, NOT appended to the `cases` array:
    // `crates/spindle-core/tests/vectors.rs`'s generic per-case loop assumes every entry in `cases`
    // opens under the single k1 `session_key` with kind=1 in the A->B direction, so mixing a
    // k0-sealed case into that array would break that loop's generic assumption rather than exercise
    // anything new — this vector's k0/k1 conformance is instead consumed directly by
    // `packages/crypto`'s TS tests, which read `offer_case` explicitly.
    let offer_plaintext = b"spindle connect offer vector plaintext".to_vec();
    let offer_env = seal(SealParams {
        session_key: &bootstrap_key,
        signer: &a.device,
        v: 1,
        alg_id: 1,
        from_fp: a.fp,
        to_fp: b.fp,
        sid: sid.clone(),
        kind: KIND_OFFER,
        seq: 0,
        ts,
        eph_pk: Some(a.eph_pk.as_bytes().to_vec()),
        plaintext: &offer_plaintext,
    });

    let offer_opened = open(
        OpenParams {
            session_key: &bootstrap_key,
            pinned_sender_key: &a.sign_pk,
            self_fp: &b.fp,
            expected_sid: &sid,
            bound_from_fp: None,
            min_seq_exclusive: None,
            now: ts,
            min_v: 1,
            min_alg_id: 1,
            expected_kind: KIND_OFFER,
            sender_revoked: false,
        },
        &offer_env,
    )
    .expect("offer envelope opens under k0");
    assert_eq!(offer_opened, offer_plaintext);

    let offer_direction = spindle_core::direction_byte(&a.fp, &b.fp);
    let mut offer_nonce = [0u8; 12];
    offer_nonce[0] = offer_direction;
    offer_nonce[4..12].copy_from_slice(&0u64.to_be_bytes());
    let offer_aad = offer_env.header_canonical_bytes();

    let offer_case = envelope_case(
        "offer_sealed_under_k0",
        "Offer-shaped envelope sealed under k0 (derive_bootstrap_key), not k1; carries \
         kind = KIND_OFFER. Opens only under k0 — see bootstrap_key_hex.",
        offer_direction,
        0,
        ts,
        &offer_nonce,
        &offer_aad,
        &offer_plaintext,
        &offer_env.ciphertext,
        &offer_env.to_canonical_bytes(),
        &offer_env.signing_input(),
        &offer_env.sig,
        true,
        true,
    );

    Json::Obj(vec![
        ("artifact", Json::Str("Envelope".into())),
        (
            "domain_tag",
            Json::Str(String::from_utf8(spindle_proto::tags::ENVELOPE_V1.to_vec()).unwrap()),
        ),
        ("device_a", device_fixture_json(&a)),
        ("device_b", device_fixture_json(&b)),
        ("sid_hex", Json::hex(&sid)),
        ("session_key_hex", Json::hex(session_key.as_bytes())),
        ("bootstrap_key_hex", Json::hex(bootstrap_key.as_bytes())),
        ("cases", Json::Arr(vec![valid_case, tampered_case])),
        ("offer_case", offer_case),
    ])
}
