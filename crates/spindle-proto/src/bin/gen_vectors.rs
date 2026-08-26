//! `gen-vectors` — writes the golden CBOR test vectors in `vectors/` (DESIGN.md §A9b) consumed
//! by both this crate's own tests and `@spindle/proto`'s TypeScript canonical-encoder tests.
//!
//! Every input here is fixed and deterministic (fixed timestamps, fixed dummy fingerprints/keys/
//! signatures of representative lengths). `spindle-proto` has no crypto dependency, so `sig*`
//! fields below are opaque byte patterns, **not** valid signatures — signature-*validity*
//! vectors are Stage 3's job, once `spindle-core` exists to produce and check real Ed25519
//! signatures over these exact same canonical bytes (see `vectors/README.md`).
//!
//! This bin has zero dependencies (see `crates/spindle-proto/Cargo.toml`): the tiny JSON writer
//! below is hand-rolled rather than pulling in `serde_json`, consistent with `spindle-proto`
//! staying dependency-free end to end (library and bin alike).

use spindle_proto::artifacts::{
    AdminCommand, AdmissionToken, CapKind, Capability, DeviceCertificate, Envelope, HostOpKeyCert,
    RevocationRecord,
};
use spindle_proto::canonical::{canonical_encode, CborValue};
use spindle_proto::tags;
use spindle_proto::vfs_rpc::{
    DirEntry, EntryKind, VfsErrorCode, VfsPerms, VfsReply, VfsRequest, VfsRequestEnvelope,
};
use std::fs;
use std::path::{Path, PathBuf};

// ================================================================================================
// Minimal JSON writer (Vec/Obj/Str/UInt/SInt/Bool/Null) — see module docs for why this is
// hand-rolled instead of using `serde_json`.
// ================================================================================================

enum Json {
    Str(String),
    UInt(u64),
    SInt(i64),
    Bool(bool),
    Arr(Vec<Json>),
    Obj(Vec<(&'static str, Json)>),
}

impl Json {
    fn hex(bytes: &[u8]) -> Json {
        Json::Str(to_hex(bytes))
    }

    fn hex_array(items: &[Vec<u8>]) -> Json {
        Json::Arr(items.iter().map(|b| Json::hex(b)).collect())
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
        Json::SInt(v) => out.push_str(&v.to_string()),
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

/// Mirrors a `CborValue` into the generic JSON shape used for `AdminCommand.args` and the
/// canonical-cbor primitive vectors: `{"type": "...", "value": ...}` so a reader (Rust or TS)
/// can reconstruct the exact typed `CborValue` tree without guessing from JSON's looser type
/// system (JSON has no byte-string/text-string distinction, no map-key-type distinction).
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
                ("value", Json::SInt(logical)),
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

fn case(
    name: &'static str,
    description: &'static str,
    decoded: Json,
    canonical_cbor: &[u8],
    signing_input: &[u8],
) -> Json {
    Json::Obj(vec![
        ("name", Json::Str(name.into())),
        ("description", Json::Str(description.into())),
        ("decoded", decoded),
        ("canonical_cbor_hex", Json::hex(canonical_cbor)),
        ("signing_input_hex", Json::hex(signing_input)),
    ])
}

fn artifact_file(artifact: &'static str, tag: &'static [u8], cases: Vec<Json>) -> Json {
    Json::Obj(vec![
        ("artifact", Json::Str(artifact.into())),
        (
            "domain_tag",
            Json::Str(String::from_utf8(tag.to_vec()).unwrap()),
        ),
        ("cases", Json::Arr(cases)),
    ])
}

// ================================================================================================
// Fixed dummy byte patterns. None of these are real keys/signatures — spindle-proto has no
// crypto dependency (A9c boundary rule 3) and cannot produce any. Repeated-byte patterns are
// used deliberately so a vector reader can immediately recognize which dummy value populates
// each field without decoding hex by hand.
// ================================================================================================

fn rep(byte: u8, len: usize) -> Vec<u8> {
    vec![byte; len]
}

fn main() {
    let vectors_dir = vectors_dir();

    write_vector_file(&vectors_dir, "envelope.json", envelope_vectors());
    write_vector_file(&vectors_dir, "capability.json", capability_vectors());
    write_vector_file(
        &vectors_dir,
        "admission-token.json",
        admission_token_vectors(),
    );
    write_vector_file(
        &vectors_dir,
        "device-certificate.json",
        device_certificate_vectors(),
    );
    write_vector_file(
        &vectors_dir,
        "revocation-record.json",
        revocation_record_vectors(),
    );
    write_vector_file(&vectors_dir, "admin-command.json", admin_command_vectors());
    write_vector_file(
        &vectors_dir,
        "host-op-key-cert.json",
        host_op_key_cert_vectors(),
    );
    write_vector_file(
        &vectors_dir,
        "canonical-cbor.json",
        canonical_cbor_vectors(),
    );
    write_vector_file(&vectors_dir, "vfs-rpc.json", vfs_rpc_vectors());
}

fn vectors_dir() -> PathBuf {
    // crates/spindle-proto -> repo root -> vectors/
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vectors")
}

// ---- Envelope ----

fn envelope_vectors() -> Json {
    let e1 = Envelope {
        v: 1,
        alg_id: 1,
        from_fp: rep(0x11, 32),
        to_fp: rep(0x22, 32),
        sid: rep(0xaa, 16),
        kind: 1,
        seq: 0,
        ts: 1_755_907_200,
        eph_pk: Some(rep(0xbb, 32)),
        ciphertext: vec![0xc0, 0xff, 0xee, 0x01, 0x02, 0x03],
        sig: rep(0x99, 64),
    };
    let e2 = Envelope {
        v: 1,
        alg_id: 1,
        from_fp: rep(0x22, 32),
        to_fp: rep(0x11, 32),
        sid: rep(0xaa, 16),
        kind: 3,
        seq: 7,
        ts: 1_755_907_260,
        eph_pk: None,
        ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
        sig: rep(0x88, 64),
    };
    let e3 = Envelope {
        v: 1,
        alg_id: 1,
        from_fp: rep(0x33, 32),
        to_fp: rep(0x44, 32),
        sid: rep(0xcd, 16),
        kind: 0,
        seq: 4_294_967_296, // exercises the 8-byte uint form for seq
        ts: 1_756_000_000,
        eph_pk: Some(rep(0xee, 32)),
        ciphertext: vec![],
        sig: rep(0x77, 64),
    };

    fn decoded(e: &Envelope) -> Json {
        let mut fields = vec![
            ("v", Json::UInt(e.v as u64)),
            ("alg_id", Json::UInt(e.alg_id as u64)),
            ("from_fp", Json::hex(&e.from_fp)),
            ("to_fp", Json::hex(&e.to_fp)),
            ("sid", Json::hex(&e.sid)),
            ("kind", Json::UInt(e.kind as u64)),
            ("seq", Json::UInt(e.seq)),
            ("ts", Json::UInt(e.ts)),
        ];
        if let Some(eph_pk) = &e.eph_pk {
            fields.push(("eph_pk", Json::hex(eph_pk)));
        }
        fields.push(("ciphertext", Json::hex(&e.ciphertext)));
        fields.push(("sig", Json::hex(&e.sig)));
        Json::Obj(fields)
    }

    let cases = vec![
        case(
            "first_message_with_eph_pk",
            "First envelope of a session: eph_pk present, seq=0.",
            decoded(&e1),
            &e1.to_canonical_bytes(),
            &e1.signing_input(),
        ),
        case(
            "subsequent_message_no_eph_pk",
            "A later envelope in the same session: eph_pk omitted entirely (key omission, not null).",
            decoded(&e2),
            &e2.to_canonical_bytes(),
            &e2.signing_input(),
        ),
        case(
            "large_seq_empty_ciphertext",
            "seq beyond u32 range (exercises the 8-byte canonical uint form) and a zero-length ciphertext.",
            decoded(&e3),
            &e3.to_canonical_bytes(),
            &e3.signing_input(),
        ),
    ];
    artifact_file("Envelope", tags::ENVELOPE_V1, cases)
}

// ---- Capability ----

fn capability_vectors() -> Json {
    // The embedded `op_cert` is itself an opaque `HostOpKeyCert` canonical encoding (A10.30) —
    // `spindle-proto` has no crypto dependency, so its `sig_host_root` here is the same kind of
    // dummy byte pattern every other `sig*` field in this file uses, not a valid signature (see
    // module docs). Fixed once and reused across both cap cases, matching how one host presents
    // the same current op cert for every capability it issues.
    let dummy_op_cert = HostOpKeyCert {
        host_op_pk: rep(0x21, 32),
        nats_fp: rep(0x22, 32),
        ts: 1_755_907_200,
        exp: 1_763_683_200, // ts + 90 days
        sig_host_root: rep(0x23, 64),
    };
    let op_cert_bytes = dummy_op_cert.to_canonical_bytes();

    fn build(kind: CapKind, cap_epoch: u64, exp: u64, op_cert_bytes: Vec<u8>) -> Capability {
        Capability {
            v: 1,
            host_fp: rep(0x10, 32),
            host_root_pk: rep(0x20, 32),
            op_cert: op_cert_bytes,
            kind,
            subject: rep(0x30, 32),
            cap_epoch,
            exp,
            nonce: rep(0x40, 16),
            sig: rep(0x50, 64),
        }
    }
    let invite = build(CapKind::Invite, 0, 1_755_993_600, op_cert_bytes.clone()); // +24h from ts base
    let member = build(CapKind::Member, 3, 1_759_017_600, op_cert_bytes); // +6 weeks-ish

    fn decoded(c: &Capability) -> Json {
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

    let cases = vec![
        case(
            "invite_cap",
            "Bearer invite capability: kind=invite(0), cap_epoch=0, 24h exp. host_fp = SHA-256(host_root_pk) \
             (A10.30 — root-derived, not operating-key-derived); op_cert is an opaque embedded HostOpKeyCert \
             canonical encoding.",
            decoded(&invite),
            &invite.to_canonical_bytes(),
            &invite.signing_input(),
        ),
        case(
            "member_cap",
            "Member capability issued post-redemption: kind=member(1), nonzero cap_epoch, weeks-scale exp. \
             Same host_fp/host_root_pk/op_cert chain shape as invite_cap (A10.30).",
            decoded(&member),
            &member.to_canonical_bytes(),
            &member.signing_input(),
        ),
    ];
    artifact_file("Capability", tags::CAPABILITY_V1, cases)
}

// ---- AdmissionToken ----

fn admission_token_vectors() -> Json {
    let t1 = AdmissionToken {
        nonce: rep(0x61, 16),
        exp: 1_756_512_000, // default-duration-derived absolute timestamp, not a day count (see lib.rs schema table)
        label: "workshop-nas".to_string(),
        quota_profile: "default".to_string(),
        sig_operator: rep(0x62, 64),
    };
    let t2 = AdmissionToken {
        nonce: rep(0x63, 16),
        exp: 1_758_326_400,
        label: "backoffice-archive".to_string(),
        quota_profile: "high-bandwidth".to_string(),
        sig_operator: rep(0x64, 64),
    };

    fn decoded(t: &AdmissionToken) -> Json {
        Json::Obj(vec![
            ("nonce", Json::hex(&t.nonce)),
            ("exp", Json::UInt(t.exp)),
            ("label", Json::Str(t.label.clone())),
            ("quota_profile", Json::Str(t.quota_profile.clone())),
            ("sig_operator", Json::hex(&t.sig_operator)),
        ])
    }

    let cases = vec![
        case(
            "default_quota",
            "Admission invite with the default quota profile.",
            decoded(&t1),
            &t1.to_canonical_bytes(),
            &t1.signing_input(),
        ),
        case(
            "custom_quota",
            "Admission invite with a named non-default quota profile and a longer label.",
            decoded(&t2),
            &t2.to_canonical_bytes(),
            &t2.signing_input(),
        ),
    ];
    artifact_file("AdmissionToken", tags::ADMISSION_TOKEN_V1, cases)
}

// ---- DeviceCertificate ----

fn device_certificate_vectors() -> Json {
    let c1 = DeviceCertificate {
        device_fp: rep(0x71, 32),
        nats_fp: rep(0x72, 32),
        ts: 1_755_907_200,
        exp: 1_787_443_200, // ts + 1 year
        sig_root: rep(0x73, 64),
    };
    let c2 = DeviceCertificate {
        device_fp: rep(0x74, 32),
        nats_fp: rep(0x75, 32),
        ts: 1_756_000_000, // re-signed on contact, per A4
        exp: 1_787_536_000,
        sig_root: rep(0x76, 64),
    };

    fn decoded(c: &DeviceCertificate) -> Json {
        Json::Obj(vec![
            ("device_fp", Json::hex(&c.device_fp)),
            ("nats_fp", Json::hex(&c.nats_fp)),
            ("ts", Json::UInt(c.ts)),
            ("exp", Json::UInt(c.exp)),
            ("sig_root", Json::hex(&c.sig_root)),
        ])
    }

    let cases = vec![
        case(
            "freshly_issued",
            "Device certificate at enrollment time; exp = ts + 1 year. No `label` field — see the \
             discrepancy note on `DeviceCertificate` in artifacts.rs.",
            decoded(&c1),
            &c1.to_canonical_bytes(),
            &c1.signing_input(),
        ),
        case(
            "re_signed_on_contact",
            "Device certificate re-signed on contact (A4): same device_fp identity, refreshed ts/exp.",
            decoded(&c2),
            &c2.to_canonical_bytes(),
            &c2.signing_input(),
        ),
    ];
    artifact_file("DeviceCertificate", tags::DEVICE_CERT_V1, cases)
}

// ---- RevocationRecord ----

fn revocation_record_vectors() -> Json {
    let r1 = RevocationRecord {
        host_fp: rep(0x81, 32),
        epoch: 1,
        revoked: vec![rep(0x82, 32)],
        ts: 1_755_907_200,
        sig: rep(0x83, 64),
    };
    let r2 = RevocationRecord {
        host_fp: rep(0x84, 32),
        epoch: 5,
        revoked: vec![rep(0x85, 32), rep(0x86, 32), rep(0x87, 32)],
        ts: 1_756_000_000,
        sig: rep(0x88, 64),
    };
    let r3 = RevocationRecord {
        host_fp: rep(0x89, 32),
        epoch: 0,
        revoked: vec![],
        ts: 1_755_800_000,
        sig: rep(0x8a, 64),
    };

    fn decoded(r: &RevocationRecord) -> Json {
        Json::Obj(vec![
            ("host_fp", Json::hex(&r.host_fp)),
            ("epoch", Json::UInt(r.epoch)),
            ("revoked", Json::hex_array(&r.revoked)),
            ("ts", Json::UInt(r.ts)),
            ("sig", Json::hex(&r.sig)),
        ])
    }

    let cases = vec![
        case(
            "single_device_revoked",
            "One device fingerprint revoked at epoch 1.",
            decoded(&r1),
            &r1.to_canonical_bytes(),
            &r1.signing_input(),
        ),
        case(
            "multiple_fingerprints_revoked",
            "Three fingerprints revoked in one record at a higher epoch (max-wins semantics per A7b).",
            decoded(&r2),
            &r2.to_canonical_bytes(),
            &r2.signing_input(),
        ),
        case(
            "empty_revoked_array",
            "Edge case: zero-length `revoked` array — exercises the empty-array canonical encoding.",
            decoded(&r3),
            &r3.to_canonical_bytes(),
            &r3.signing_input(),
        ),
    ];
    artifact_file("RevocationRecord", tags::REVOCATION_V1, cases)
}

// ---- AdminCommand ----

fn admin_command_vectors() -> Json {
    let c1 = AdminCommand {
        v: 1,
        cmd: "evict_host".to_string(),
        args: CborValue::map(vec![("host_fp", CborValue::bytes(rep(0x91, 32)))]),
        signer_fp: rep(0x92, 32),
        seq: 12,
        nonce: rep(0x93, 16),
        ts: 1_755_907_200,
        sig: rep(0x94, 64),
    };
    let c2 = AdminCommand {
        v: 1,
        cmd: "set_mode".to_string(),
        args: CborValue::map(vec![("mode", CborValue::text("open"))]),
        signer_fp: rep(0x95, 32),
        seq: 13,
        nonce: rep(0x96, 16),
        ts: 1_755_907_260,
        sig: rep(0x97, 64),
    };
    let c3 = AdminCommand {
        v: 1,
        cmd: "rotate_admission_key".to_string(),
        args: CborValue::Null,
        signer_fp: rep(0x98, 32),
        seq: 14,
        nonce: rep(0x99, 16),
        ts: 1_755_907_320,
        sig: rep(0x9a, 64),
    };

    fn decoded(c: &AdminCommand) -> Json {
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

    let cases = vec![
        case(
            "evict_host_with_map_args",
            "`args` is a one-entry canonical map naming the host to evict.",
            decoded(&c1),
            &c1.to_canonical_bytes(),
            &c1.signing_input(),
        ),
        case(
            "set_mode_with_text_arg",
            "`args` carries a single text-valued field.",
            decoded(&c2),
            &c2.to_canonical_bytes(),
            &c2.signing_input(),
        ),
        case(
            "rotate_key_with_null_args",
            "A command with no arguments: `args` is CBOR null, not an omitted field.",
            decoded(&c3),
            &c3.to_canonical_bytes(),
            &c3.signing_input(),
        ),
    ];
    artifact_file("AdminCommand", tags::ADMIN_COMMAND_V1, cases)
}

// ---- HostOpKeyCert ----

fn host_op_key_cert_vectors() -> Json {
    let c1 = HostOpKeyCert {
        host_op_pk: rep(0xa1, 32),
        nats_fp: rep(0xa2, 32),
        ts: 1_755_907_200,
        exp: 1_763_683_200, // ts + 90 days
        sig_host_root: rep(0xa3, 64),
    };
    let c2 = HostOpKeyCert {
        host_op_pk: rep(0xa4, 32), // rotated operating key
        nats_fp: rep(0xa2, 32),    // same nats_fp across rotation
        ts: 1_763_683_200,
        exp: 1_771_459_200,
        sig_host_root: rep(0xa5, 64),
    };

    fn decoded(c: &HostOpKeyCert) -> Json {
        Json::Obj(vec![
            ("host_op_pk", Json::hex(&c.host_op_pk)),
            ("nats_fp", Json::hex(&c.nats_fp)),
            ("ts", Json::UInt(c.ts)),
            ("exp", Json::UInt(c.exp)),
            ("sig_host_root", Json::hex(&c.sig_host_root)),
        ])
    }

    let cases = vec![
        case(
            "freshly_issued",
            "Host operating-key certificate at issuance; exp = ts + 90 days.",
            decoded(&c1),
            &c1.to_canonical_bytes(),
            &c1.signing_input(),
        ),
        case(
            "rotated",
            "Operating-key rotation: new host_op_pk, same nats_fp, exp window rolled forward.",
            decoded(&c2),
            &c2.to_canonical_bytes(),
            &c2.signing_input(),
        ),
    ];
    artifact_file("HostOpKeyCert", tags::HOST_OP_KEY_CERT_V1, cases)
}

// ---- canonical-cbor.json: primitive canonicalization cases ----

fn canonical_cbor_vectors() -> Json {
    fn prim_case(name: &'static str, description: &'static str, v: CborValue) -> Json {
        let bytes = canonical_encode(&v);
        Json::Obj(vec![
            ("name", Json::Str(name.into())),
            ("description", Json::Str(description.into())),
            ("value", cbor_to_json(&v)),
            ("canonical_cbor_hex", Json::hex(&bytes)),
        ])
    }

    let cases = vec![
        prim_case("uint_0", "Smallest uint; fits in the initial byte.", CborValue::uint(0)),
        prim_case(
            "uint_23",
            "Largest uint that fits in the initial byte (additional info 0-23).",
            CborValue::uint(23),
        ),
        prim_case(
            "uint_24",
            "Smallest uint requiring the 1-byte-argument form (additional info 24).",
            CborValue::uint(24),
        ),
        prim_case(
            "uint_255",
            "Largest uint fitting the 1-byte-argument form.",
            CborValue::uint(255),
        ),
        prim_case(
            "uint_256",
            "Smallest uint requiring the 2-byte-argument form (additional info 25).",
            CborValue::uint(256),
        ),
        prim_case(
            "uint_65535",
            "Largest uint fitting the 2-byte-argument form.",
            CborValue::uint(65535),
        ),
        prim_case(
            "uint_65536",
            "Smallest uint requiring the 4-byte-argument form (additional info 26).",
            CborValue::uint(65536),
        ),
        prim_case(
            "uint_4294967295",
            "Largest uint fitting the 4-byte-argument form.",
            CborValue::uint(4_294_967_295),
        ),
        prim_case(
            "uint_4294967296",
            "Smallest uint requiring the 8-byte-argument form (additional info 27).",
            CborValue::uint(4_294_967_296),
        ),
        prim_case(
            "negint_minus_1",
            "Smallest-magnitude negative integer: CBOR major type 1, argument 0, logical value -1.",
            CborValue::NegInt(0),
        ),
        prim_case(
            "negint_minus_100",
            "A negative integer requiring the 1-byte-argument form (magnitude 99, logical value -100).",
            CborValue::NegInt(99),
        ),
        prim_case(
            "byte_string_empty",
            "Zero-length byte string.",
            CborValue::bytes(Vec::new()),
        ),
        prim_case(
            "byte_string_short",
            "A short byte string.",
            CborValue::bytes(vec![0xde, 0xad, 0xbe, 0xef]),
        ),
        prim_case(
            "text_string",
            "A short UTF-8 text string.",
            CborValue::text("spindle"),
        ),
        prim_case(
            "array_of_uints",
            "A definite-length array of three small unsigned integers.",
            CborValue::array(vec![CborValue::uint(1), CborValue::uint(2), CborValue::uint(3)]),
        ),
        prim_case(
            "array_empty",
            "Zero-length array.",
            CborValue::array(Vec::new()),
        ),
        prim_case(
            "map_key_ordering_by_length",
            "Map with keys \"aa\" and \"z\", constructed in that insertion order. Canonical order \
             sorts by each key's own encoded bytes, so the shorter key \"z\" (1-byte header) is \
             emitted before the longer key \"aa\" (2-byte header) even though \"aa\" < \"z\" \
             lexicographically — this is the encoder reordering entries, not an input error.",
            CborValue::map(vec![("aa", CborValue::uint(1)), ("z", CborValue::uint(2))]),
        ),
        prim_case(
            "map_key_ordering_same_length",
            "Map with same-length keys \"bb\" and \"ac\", constructed out of canonical order; \
             canonical order falls back to byte-lexicographic comparison of the key content, so \
             \"ac\" sorts before \"bb\".",
            CborValue::map(vec![("bb", CborValue::uint(1)), ("ac", CborValue::uint(2))]),
        ),
        prim_case(
            "map_nested",
            "A map whose value is itself an array and whose value is itself a map, exercising \
             recursive canonical encoding.",
            CborValue::map(vec![(
                "items",
                CborValue::array(vec![
                    CborValue::map(vec![("id", CborValue::uint(1))]),
                    CborValue::map(vec![("id", CborValue::uint(2))]),
                ]),
            )]),
        ),
        prim_case("bool_true", "The simple value `true`.", CborValue::Bool(true)),
        prim_case("bool_false", "The simple value `false`.", CborValue::Bool(false)),
        prim_case("null", "The simple value `null`.", CborValue::Null),
    ];

    Json::Obj(vec![
        (
            "description",
            Json::Str(
                "Primitive canonical-CBOR encoding cases (RFC 8949 §4.2.1), independent of any \
                 Spindle artifact type — for validating a canonical CBOR encoder at the byte level."
                    .to_string(),
            ),
        ),
        ("cases", Json::Arr(cases)),
    ])
}

// ---- VFS RPC (DESIGN.md §A8, Stage 6 slice 3) ----
//
// Not A7b signed artifacts (see `spindle_proto::vfs_rpc`'s module doc comment) — no domain tag,
// no signing input, so each case here is `{name, description, decoded, canonical_cbor_hex}`
// rather than the artifact-vector shape's extra `signing_input_hex` field. `decoded` reuses
// `cbor_to_json` (the same generic CBOR-to-JSON mirror `admin-command.json`'s open-ended `args`
// field already relies on) rather than a bespoke per-op JSON shape, since the six ops carry
// different field sets.

fn vfs_rpc_case(name: &'static str, description: &'static str, cbor: CborValue) -> Json {
    let bytes = canonical_encode(&cbor);
    Json::Obj(vec![
        ("name", Json::Str(name.into())),
        ("description", Json::Str(description.into())),
        ("decoded", cbor_to_json(&cbor)),
        ("canonical_cbor_hex", Json::hex(&bytes)),
    ])
}

fn vfs_rpc_vectors() -> Json {
    let requests = vec![
        vfs_rpc_case(
            "list_root_no_cursor",
            "`list` at the share-root-relative virtual path \"Photos\", first page (no cursor, \
             server-default limit).",
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::List {
                    path: "Photos".to_string(),
                    cursor: None,
                    limit: None,
                },
            }
            .to_cbor(),
        ),
        vfs_rpc_case(
            "list_with_cursor_and_limit",
            "`list` continuing from an opaque cursor, with an explicit page-size limit.",
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::List {
                    path: "Photos".to_string(),
                    cursor: Some(rep(0x01, 4)),
                    limit: Some(50),
                },
            }
            .to_cbor(),
        ),
        vfs_rpc_case(
            "stat",
            "`stat` a single virtual path.",
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::Stat {
                    path: "Photos/Vacation/img.jpg".to_string(),
                },
            }
            .to_cbor(),
        ),
        vfs_rpc_case(
            "read_one_chunk",
            "`read` one 64 KiB chunk starting at offset 65536 (DESIGN.md §A8 max chunk size).",
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::Read {
                    path: "Photos/Vacation/img.jpg".to_string(),
                    offset: 65536,
                    len: 65536,
                },
            }
            .to_cbor(),
        ),
        vfs_rpc_case(
            "mkdir",
            "`mkdir` a new virtual directory.",
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::Mkdir {
                    path: "Photos/NewAlbum".to_string(),
                },
            }
            .to_cbor(),
        ),
        vfs_rpc_case(
            "delete",
            "`delete` a virtual path.",
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::Delete {
                    path: "Photos/old.jpg".to_string(),
                },
            }
            .to_cbor(),
        ),
        vfs_rpc_case(
            "whoami",
            "`whoami` — no fields beyond the shared `v`/`op` envelope.",
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::Whoami,
            }
            .to_cbor(),
        ),
    ];

    let mut replies = vec![
        vfs_rpc_case(
            "list_reply_one_entry_more_pages",
            "`list` reply with one directory entry and a continuation cursor.",
            VfsReply::List {
                entries: vec![DirEntry {
                    name: "Vacation".to_string(),
                    kind: EntryKind::Dir,
                    size: 0,
                    mtime: 1_755_907_200,
                    perms_here: VfsPerms::BROWSE,
                }],
                next_cursor: Some(rep(0x02, 4)),
            }
            .to_cbor(),
        ),
        vfs_rpc_case(
            "list_reply_empty_last_page",
            "`list` reply with zero entries and no continuation cursor (end of listing) — also \
             exercises the empty-array canonical encoding edge case for this schema.",
            VfsReply::List {
                entries: vec![],
                next_cursor: None,
            }
            .to_cbor(),
        ),
        vfs_rpc_case(
            "stat_reply_file",
            "`stat` reply for a regular file with browse+download granted here.",
            VfsReply::Stat {
                kind: EntryKind::File,
                size: 4_194_304,
                mtime: 1_755_907_200,
                perms_here: VfsPerms::BROWSE.union(VfsPerms::DOWNLOAD),
            }
            .to_cbor(),
        ),
        vfs_rpc_case(
            "read_reply_partial_chunk",
            "`read` reply carrying one chunk of file data, more remaining (`eof: false`).",
            VfsReply::Read {
                data: rep(0xab, 128),
                eof: false,
            }
            .to_cbor(),
        ),
        vfs_rpc_case(
            "read_reply_final_chunk",
            "`read` reply carrying the last chunk of a file (`eof: true`), including the \
             zero-length-at-exact-boundary case.",
            VfsReply::Read {
                data: vec![],
                eof: true,
            }
            .to_cbor(),
        ),
        vfs_rpc_case(
            "mkdir_reply",
            "`mkdir` success acknowledgement.",
            VfsReply::Mkdir.to_cbor(),
        ),
        vfs_rpc_case(
            "delete_reply",
            "`delete` success acknowledgement.",
            VfsReply::Delete.to_cbor(),
        ),
        vfs_rpc_case(
            "whoami_reply",
            "`whoami` reply — trimmed per DESIGN.md §A4b/A12 #32: display name and effective \
             paths only, no group names.",
            VfsReply::Whoami {
                member_display: "Alex".to_string(),
                effective_paths: vec!["Photos/Vacation".to_string(), "Drop".to_string()],
            }
            .to_cbor(),
        ),
    ];

    for code in [
        VfsErrorCode::NotFound,
        VfsErrorCode::QuotaExceeded,
        VfsErrorCode::GrantsChanged,
        VfsErrorCode::ResumeExpired,
        VfsErrorCode::UploadRejected,
        VfsErrorCode::StorageFull,
        VfsErrorCode::Throttled,
        VfsErrorCode::UnsupportedVersion,
    ] {
        replies.push(vfs_rpc_case(
            "error_reply",
            "One of the eight typed VFS error codes (DESIGN.md §A8's seven, plus this crate's \
             UnsupportedVersion addition — see `spindle_proto::vfs_rpc`'s schema-choices table).",
            VfsReply::Error { code }.to_cbor(),
        ));
    }

    Json::Obj(vec![
        (
            "description",
            Json::Str(
                "VFS RPC wire types (DESIGN.md §A8), Stage 6 slice 3: request/reply CBOR shapes \
                 for list/stat/read/mkdir/delete/whoami and the typed error-code model. Not A7b \
                 signed artifacts — no domain tag, no signing input."
                    .to_string(),
            ),
        ),
        ("requests", Json::Arr(requests)),
        ("replies", Json::Arr(replies)),
    ])
}
