//! Loads `vectors/signed/*.json` (written by `src/bin/gen_crypto_vectors.rs`) back and re-verifies
//! every signature and the envelope's decrypt independently of the generator's own in-process
//! `assert!`s — this is the check that would catch a generator bug that happened to write a
//! self-consistent-but-wrong file (e.g. hex encoding of the wrong buffer).
//!
//! Deliberately hand-rolls a minimal JSON reader rather than depending on `serde_json`, matching
//! the zero-dependency approach `spindle-proto`'s vector generator and this crate's own
//! `gen-crypto-vectors` bin already take for *writing* these files (see that bin's module docs).
//! This parser only needs to support the shapes `gen-crypto-vectors` actually emits: objects,
//! arrays, strings, unsigned integers, and booleans — no floats, no escapes beyond `\"`/`\\`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use spindle_core::artifacts::{
    verify_admin_command, verify_admission_token, verify_capability, verify_device_certificate,
    verify_host_device_cert, verify_host_op_key_cert, verify_revocation_record,
    verify_session_attestation,
};
use spindle_core::envelope::{open, OpenParams};
use spindle_core::{root_fp_of, Fingerprint};
use spindle_proto::artifacts::{
    AdminCommand, AdmissionToken, Capability, DeviceCertificate, Envelope, HostDeviceCert,
    HostOpKeyCert, RevocationRecord, SessionAttestation,
};
use std::fs;
use std::path::{Path, PathBuf};

// ================================================================================================
// Minimal JSON reader
// ================================================================================================

#[derive(Debug, Clone)]
enum Json {
    Str(String),
    Num(u64),
    Bool(bool),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> &Json {
        match self {
            Json::Obj(entries) => {
                &entries
                    .iter()
                    .find(|(k, _)| k == key)
                    .unwrap_or_else(|| panic!("missing JSON key `{key}`"))
                    .1
            }
            other => panic!("expected object looking up `{key}`, got {other:?}"),
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Json::Str(s) => s,
            other => panic!("expected string, got {other:?}"),
        }
    }

    fn as_u64(&self) -> u64 {
        match self {
            Json::Num(n) => *n,
            other => panic!("expected number, got {other:?}"),
        }
    }

    fn as_bool(&self) -> bool {
        match self {
            Json::Bool(b) => *b,
            other => panic!("expected bool, got {other:?}"),
        }
    }

    fn as_arr(&self) -> &[Json] {
        match self {
            Json::Arr(items) => items,
            other => panic!("expected array, got {other:?}"),
        }
    }

    /// Decodes a lowercase-hex string field into raw bytes.
    fn hex(&self) -> Vec<u8> {
        decode_hex(self.as_str())
    }
}

fn decode_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex string: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|e| panic!("bad hex `{s}`: {e}"))
        })
        .collect()
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Parser {
            bytes: s.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> u8 {
        self.bytes[self.pos]
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.peek().is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn expect(&mut self, b: u8) {
        assert_eq!(
            self.peek(),
            b,
            "expected `{}` at byte {}",
            b as char,
            self.pos
        );
        self.pos += 1;
    }

    fn parse_value(&mut self) -> Json {
        self.skip_ws();
        match self.peek() {
            b'{' => self.parse_obj(),
            b'[' => self.parse_arr(),
            b'"' => Json::Str(self.parse_str()),
            b't' | b'f' => self.parse_bool(),
            _ => Json::Num(self.parse_num()),
        }
    }

    fn parse_obj(&mut self) -> Json {
        self.expect(b'{');
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek() == b'}' {
            self.pos += 1;
            return Json::Obj(entries);
        }
        loop {
            self.skip_ws();
            let key = self.parse_str();
            self.skip_ws();
            self.expect(b':');
            let value = self.parse_value();
            entries.push((key, value));
            self.skip_ws();
            match self.peek() {
                b',' => {
                    self.pos += 1;
                }
                b'}' => {
                    self.pos += 1;
                    break;
                }
                other => panic!("unexpected byte `{}` in object", other as char),
            }
        }
        Json::Obj(entries)
    }

    fn parse_arr(&mut self) -> Json {
        self.expect(b'[');
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == b']' {
            self.pos += 1;
            return Json::Arr(items);
        }
        loop {
            let value = self.parse_value();
            items.push(value);
            self.skip_ws();
            match self.peek() {
                b',' => {
                    self.pos += 1;
                }
                b']' => {
                    self.pos += 1;
                    break;
                }
                other => panic!("unexpected byte `{}` in array", other as char),
            }
        }
        Json::Arr(items)
    }

    fn parse_str(&mut self) -> String {
        self.expect(b'"');
        let mut out = String::new();
        loop {
            let b = self.peek();
            self.pos += 1;
            match b {
                b'"' => break,
                b'\\' => {
                    let esc = self.peek();
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex =
                                std::str::from_utf8(&self.bytes[self.pos..self.pos + 4]).unwrap();
                            let cp = u32::from_str_radix(hex, 16).unwrap();
                            out.push(char::from_u32(cp).unwrap());
                            self.pos += 4;
                        }
                        other => panic!("unsupported escape `\\{}`", other as char),
                    }
                }
                _ => out.push(b as char),
            }
        }
        out
    }

    fn parse_bool(&mut self) -> Json {
        if self.bytes[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Json::Bool(true)
        } else if self.bytes[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Json::Bool(false)
        } else {
            panic!("invalid literal at byte {}", self.pos);
        }
    }

    fn parse_num(&mut self) -> u64 {
        let start = self.pos;
        while self.pos < self.bytes.len() && (self.peek().is_ascii_digit() || self.peek() == b'-') {
            self.pos += 1;
        }
        std::str::from_utf8(&self.bytes[start..self.pos])
            .unwrap()
            .parse()
            .unwrap_or_else(|e| panic!("bad number at byte {start}: {e}"))
    }
}

fn parse_json(s: &str) -> Json {
    Parser::new(s).parse_value()
}

fn load(filename: &str) -> Json {
    let path = signed_vectors_dir().join(filename);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    parse_json(&text)
}

fn signed_vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vectors")
        .join("signed")
}

/// The repo-root `vectors/` directory itself (parent of [`signed_vectors_dir`]) — where
/// `key-validity.json` lives; see `gen_crypto_vectors.rs`'s `vectors_dir()` doc comment for why
/// that file is not under `vectors/signed/`.
fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vectors")
}

fn load_top(filename: &str) -> Json {
    let path = vectors_dir().join(filename);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    parse_json(&text)
}

fn verifying_key_from_hex(j: &Json) -> VerifyingKey {
    let bytes: [u8; 32] = j.hex().try_into().expect("32-byte public key");
    spindle_core::checked_verifying_key(&bytes)
        .expect("valid, canonically-encoded Ed25519 public key")
}

fn fingerprint_from_hex(j: &Json) -> Fingerprint {
    Fingerprint::from_slice(&j.hex()).expect("32-byte fingerprint")
}

// ================================================================================================
// DeviceCertificate / HostOpKeyCert: pinned root fp + signature + exp
// ================================================================================================

#[test]
fn device_certificate_vectors_verify() {
    let doc = load("device-certificate.json");
    let root_pk = verifying_key_from_hex(doc.get("signer").get("public_key_hex"));
    let root_fp = fingerprint_from_hex(doc.get("signer").get("root_fp_hex"));
    assert_eq!(
        root_fp_of(&root_pk),
        root_fp,
        "root_fp_hex must match SHA-256(root_pk)"
    );

    for case in doc.get("cases").as_arr() {
        let cert = DeviceCertificate {
            device_fp: case.get("decoded").get("device_fp").hex(),
            alg_id: case.get("decoded").get("alg_id").as_u64() as u8,
            sign_pk: case.get("decoded").get("sign_pk").hex(),
            agree_pk: case.get("decoded").get("agree_pk").hex(),
            ts: case.get("decoded").get("ts").as_u64(),
            exp: case.get("decoded").get("exp").as_u64(),
            sig_root: case.get("decoded").get("sig_root").hex(),
        };
        assert_eq!(
            cert.to_canonical_bytes(),
            case.get("canonical_cbor_hex").hex()
        );
        assert_eq!(cert.signing_input(), case.get("signing_input_hex").hex());

        let now = case.get("decoded").get("ts").as_u64();
        let result = verify_device_certificate(&cert, &root_pk, &root_fp, now);
        assert_eq!(
            result.is_ok(),
            case.get("signature_valid").as_bool(),
            "case `{}`",
            case.get("name").as_str()
        );
    }
}

// ================================================================================================
// SessionAttestation: signer key supplied out of band (device identity key here); expected_nats_fp
// is read per-case from the case's own `decoded.nats_fp` — this artifact's `nats_fp` field IS the
// value `verify_session_attestation` requires the caller to already expect, so there is no separate
// top-level field for it (unlike `signer`, which is the same key across every case).
// ================================================================================================

#[test]
fn session_attestation_vectors_verify() {
    let doc = load("session-attestation.json");
    let device_sign_pk = verifying_key_from_hex(doc.get("signer").get("public_key_hex"));

    for case in doc.get("cases").as_arr() {
        let att = SessionAttestation {
            nats_fp: case.get("decoded").get("nats_fp").hex(),
            ts: case.get("decoded").get("ts").as_u64(),
            sig_device: case.get("decoded").get("sig_device").hex(),
        };
        assert_eq!(
            att.to_canonical_bytes(),
            case.get("canonical_cbor_hex").hex()
        );
        assert_eq!(att.signing_input(), case.get("signing_input_hex").hex());

        let expected_nats_fp = fingerprint_from_hex(case.get("decoded").get("nats_fp"));
        let now = case.get("decoded").get("ts").as_u64();
        let result = verify_session_attestation(&att, &device_sign_pk, &expected_nats_fp, now);
        assert_eq!(
            result.is_ok(),
            case.get("signature_valid").as_bool(),
            "case `{}`",
            case.get("name").as_str()
        );
    }
}

#[test]
fn host_op_key_cert_vectors_verify() {
    let doc = load("host-op-key-cert.json");
    let root_pk = verifying_key_from_hex(doc.get("signer").get("public_key_hex"));
    let root_fp = fingerprint_from_hex(doc.get("signer").get("root_fp_hex"));
    assert_eq!(root_fp_of(&root_pk), root_fp);

    for case in doc.get("cases").as_arr() {
        let cert = HostOpKeyCert {
            host_op_pk: case.get("decoded").get("host_op_pk").hex(),
            nats_fp: case.get("decoded").get("nats_fp").hex(),
            ts: case.get("decoded").get("ts").as_u64(),
            exp: case.get("decoded").get("exp").as_u64(),
            sig_host_root: case.get("decoded").get("sig_host_root").hex(),
        };
        assert_eq!(
            cert.to_canonical_bytes(),
            case.get("canonical_cbor_hex").hex()
        );
        assert_eq!(cert.signing_input(), case.get("signing_input_hex").hex());

        let now = case.get("decoded").get("ts").as_u64();
        let result = verify_host_op_key_cert(&cert, &root_pk, &root_fp, now);
        assert_eq!(result.is_ok(), case.get("signature_valid").as_bool());
    }
}

// ================================================================================================
// Capability: self-verifying, no external key needed
// ================================================================================================

#[test]
fn capability_vectors_verify() {
    let doc = load("capability.json");
    for case in doc.get("cases").as_arr() {
        let kind = match case.get("decoded").get("kind").as_u64() {
            0 => spindle_proto::artifacts::CapKind::Invite,
            1 => spindle_proto::artifacts::CapKind::Member,
            other => panic!("unknown CapKind {other}"),
        };
        let cap = Capability {
            v: case.get("decoded").get("v").as_u64() as u8,
            host_fp: case.get("decoded").get("host_fp").hex(),
            host_root_pk: case.get("decoded").get("host_root_pk").hex(),
            op_cert: case.get("decoded").get("op_cert").hex(),
            kind,
            subject: case.get("decoded").get("subject").hex(),
            cap_epoch: case.get("decoded").get("cap_epoch").as_u64(),
            exp: case.get("decoded").get("exp").as_u64(),
            nonce: case.get("decoded").get("nonce").hex(),
            sig: case.get("decoded").get("sig").hex(),
        };
        assert_eq!(
            cap.to_canonical_bytes(),
            case.get("canonical_cbor_hex").hex()
        );
        assert_eq!(cap.signing_input(), case.get("signing_input_hex").hex());

        let now = case.get("decoded").get("exp").as_u64(); // at exactly exp: still valid (now > exp fails)
        let result = verify_capability(&cap, now);
        assert_eq!(result.is_ok(), case.get("signature_valid").as_bool());
    }
}

// ================================================================================================
// HostDeviceCert: self-verifying like Capability, but verify_host_device_cert additionally
// requires the caller's pinned host_fp (decision A10.35) — this vector's cases all pin the
// certificate's own declared host_fp, since that's the "client already pinned this host" case the
// signature-validity cases are exercising.
// ================================================================================================

#[test]
fn host_device_cert_vectors_verify() {
    let doc = load("host-device-cert.json");
    let expected_host_fp = fingerprint_from_hex(doc.get("signer").get("host_fp_hex"));

    for case in doc.get("cases").as_arr() {
        let cert = HostDeviceCert {
            host_fp: case.get("decoded").get("host_fp").hex(),
            host_root_pk: case.get("decoded").get("host_root_pk").hex(),
            op_cert: case.get("decoded").get("op_cert").hex(),
            host_device_fp: case.get("decoded").get("host_device_fp").hex(),
            alg_id: case.get("decoded").get("alg_id").as_u64() as u8,
            sign_pk: case.get("decoded").get("sign_pk").hex(),
            agree_pk: case.get("decoded").get("agree_pk").hex(),
            ts: case.get("decoded").get("ts").as_u64(),
            exp: case.get("decoded").get("exp").as_u64(),
            sig_host_op: case.get("decoded").get("sig_host_op").hex(),
        };
        assert_eq!(
            cert.to_canonical_bytes(),
            case.get("canonical_cbor_hex").hex()
        );
        assert_eq!(cert.signing_input(), case.get("signing_input_hex").hex());

        let now = case.get("decoded").get("exp").as_u64(); // at exactly exp: still valid (now > exp fails)
        let result = verify_host_device_cert(&cert, &expected_host_fp, now);
        assert_eq!(
            result.is_ok(),
            case.get("signature_valid").as_bool(),
            "case `{}`",
            case.get("name").as_str()
        );
    }
}

// ================================================================================================
// RevocationRecord: signer key supplied out of band (host op key here)
// ================================================================================================

#[test]
fn revocation_record_vectors_verify() {
    let doc = load("revocation-record.json");
    let signer_pk = verifying_key_from_hex(doc.get("signer").get("public_key_hex"));

    for case in doc.get("cases").as_arr() {
        let revoked: Vec<Vec<u8>> = case
            .get("decoded")
            .get("revoked")
            .as_arr()
            .iter()
            .map(|j| j.hex())
            .collect();
        let rec = RevocationRecord {
            host_fp: case.get("decoded").get("host_fp").hex(),
            epoch: case.get("decoded").get("epoch").as_u64(),
            revoked,
            ts: case.get("decoded").get("ts").as_u64(),
            sig: case.get("decoded").get("sig").hex(),
        };
        assert_eq!(
            rec.to_canonical_bytes(),
            case.get("canonical_cbor_hex").hex()
        );
        assert_eq!(rec.signing_input(), case.get("signing_input_hex").hex());

        let result = verify_revocation_record(&rec, &signer_pk);
        assert_eq!(result.is_ok(), case.get("signature_valid").as_bool());
    }
}

// ================================================================================================
// AdmissionToken
// ================================================================================================

#[test]
fn admission_token_vectors_verify() {
    let doc = load("admission-token.json");
    let operator_pk = verifying_key_from_hex(doc.get("signer").get("public_key_hex"));

    for case in doc.get("cases").as_arr() {
        let tok = AdmissionToken {
            nonce: case.get("decoded").get("nonce").hex(),
            exp: case.get("decoded").get("exp").as_u64(),
            label: case.get("decoded").get("label").as_str().to_string(),
            quota_profile: case
                .get("decoded")
                .get("quota_profile")
                .as_str()
                .to_string(),
            sig_operator: case.get("decoded").get("sig_operator").hex(),
        };
        assert_eq!(
            tok.to_canonical_bytes(),
            case.get("canonical_cbor_hex").hex()
        );
        assert_eq!(tok.signing_input(), case.get("signing_input_hex").hex());

        let now = case.get("decoded").get("exp").as_u64();
        let result = verify_admission_token(&tok, &operator_pk, now);
        assert_eq!(result.is_ok(), case.get("signature_valid").as_bool());
    }
}

// ================================================================================================
// AdminCommand
// ================================================================================================

#[test]
fn admin_command_vectors_verify() {
    let doc = load("admin-command.json");
    let operator_pk = verifying_key_from_hex(doc.get("signer").get("public_key_hex"));

    for case in doc.get("cases").as_arr() {
        // `args` is carried opaquely by spindle-proto; reconstruct it well enough for
        // `to_canonical_bytes`/`signing_input` to match by round-tripping the one shape this
        // generator emits (a single-entry map, bytes value) rather than a general JSON->CborValue
        // decoder — good enough to exercise the real signature-verification path this test cares
        // about.
        let args_json = case.get("decoded").get("args");
        let entries = args_json.get("value").as_arr();
        let mut cbor_entries = Vec::new();
        for entry in entries {
            let key = entry.get("key").get("value").as_str().to_string();
            let val_bytes = entry.get("value").get("value").hex();
            cbor_entries.push((key, spindle_proto::canonical::CborValue::bytes(val_bytes)));
        }
        let args = spindle_proto::canonical::CborValue::map(
            cbor_entries
                .iter()
                .map(|(k, v)| (k.as_str(), v.clone()))
                .collect(),
        );

        let cmd = AdminCommand {
            v: case.get("decoded").get("v").as_u64() as u8,
            cmd: case.get("decoded").get("cmd").as_str().to_string(),
            args,
            signer_fp: case.get("decoded").get("signer_fp").hex(),
            seq: case.get("decoded").get("seq").as_u64(),
            nonce: case.get("decoded").get("nonce").hex(),
            ts: case.get("decoded").get("ts").as_u64(),
            sig: case.get("decoded").get("sig").hex(),
        };
        assert_eq!(
            cmd.to_canonical_bytes(),
            case.get("canonical_cbor_hex").hex()
        );
        assert_eq!(cmd.signing_input(), case.get("signing_input_hex").hex());

        let now = case.get("decoded").get("ts").as_u64();
        let result = verify_admin_command(&cmd, &operator_pk, now);
        assert_eq!(result.is_ok(), case.get("signature_valid").as_bool());
    }
}

// ================================================================================================
// Envelope: full seal/open round trip against the vector's own derived session key
// ================================================================================================

#[test]
fn envelope_vector_verifies_and_decrypts() {
    let doc = load("envelope.json");
    let device_a = doc.get("device_a");
    let device_b = doc.get("device_b");

    let a_sign_pk = verifying_key_from_hex(device_a.get("sign_pk_hex"));
    let b_fp = fingerprint_from_hex(device_b.get("device_fp_hex"));
    let sid = doc.get("sid_hex").hex();
    let session_key_bytes: [u8; 32] = doc
        .get("session_key_hex")
        .hex()
        .try_into()
        .expect("32-byte session key");

    // `SessionKey` has no public constructor from raw bytes (by design — every real caller
    // derives it via `derive_session_key`); reconstruct it here by re-deriving from the vector's
    // own seeds/eph keys instead of poking at private fields, since that's the only route this
    // test needs and it exercises the same derivation the generator used.
    let dev_a = spindle_core::DeviceKey::from_seeds(
        seed32(device_a.get("sign_seed").get("seed_hex")),
        seed32(device_a.get("agree_seed").get("seed_hex")),
    );
    let dev_b = spindle_core::DeviceKey::from_seeds(
        seed32(device_b.get("sign_seed").get("seed_hex")),
        seed32(device_b.get("agree_seed").get("seed_hex")),
    );
    // Ephemeral X25519 keys are re-derived from the vector's *seeds*, not its `eph_pk_hex`
    // fields, so this also cross-checks that the recorded public keys match those seeds.
    let eph_a = x25519_dalek::StaticSecret::from(seed32(device_a.get("eph_seed").get("seed_hex")));
    let eph_b_secret =
        x25519_dalek::StaticSecret::from(seed32(device_b.get("eph_seed").get("seed_hex")));
    let eph_b_pk = x25519_dalek::PublicKey::from(&eph_b_secret);
    assert_eq!(eph_b_pk.as_bytes(), &seed32_pk(device_b.get("eph_pk_hex")));
    let eph_dh = *eph_a.diffie_hellman(&eph_b_pk).as_bytes();
    let dev_dh = dev_a.diffie_hellman(&dev_b.agree_public_key());
    let a_fp = dev_a.device_fp();
    assert_eq!(
        a_fp.to_vec(),
        fingerprint_from_hex(device_a.get("device_fp_hex")).to_vec()
    );
    let session_key = spindle_core::derive_session_key(&eph_dh, &dev_dh, &sid, &a_fp, &b_fp);
    assert_eq!(
        session_key.as_bytes(),
        &session_key_bytes,
        "re-derived session key must match the vector's recorded session_key_hex"
    );

    for case in doc.get("cases").as_arr() {
        let env = Envelope {
            v: 1,
            alg_id: 1,
            from_fp: a_fp.to_vec(),
            to_fp: b_fp.to_vec(),
            sid: sid.clone(),
            kind: 1,
            seq: case.get("seq").as_u64(),
            ts: case.get("ts").as_u64(),
            eph_pk: Some(device_a.get("eph_pk_hex").hex()),
            ciphertext: case.get("ciphertext_hex").hex(),
            sig: case.get("signature_hex").hex(),
        };
        assert_eq!(
            env.to_canonical_bytes(),
            case.get("envelope_canonical_cbor_hex").hex()
        );
        assert_eq!(env.signing_input(), case.get("signing_input_hex").hex());

        // Independently verify the signature under the sender's pinned key (mirrors what `open`
        // does internally, checked here explicitly so a generator bug in `sig` is caught even if
        // `open`'s own signature check has a latent bug).
        let sig_bytes: [u8; 64] = env.sig.as_slice().try_into().expect("64-byte signature");
        let sig_ok = a_sign_pk
            .verify(&env.signing_input(), &Signature::from_bytes(&sig_bytes))
            .is_ok();
        assert_eq!(
            sig_ok,
            case.get("signature_valid").as_bool(),
            "case `{}`",
            case.get("name").as_str()
        );

        if case.get("signature_valid").as_bool() {
            let plaintext = open(
                OpenParams {
                    session_key: &session_key,
                    pinned_sender_key: &a_sign_pk,
                    self_fp: &b_fp,
                    expected_sid: &sid,
                    bound_from_fp: None,
                    min_seq_exclusive: None,
                    now: case.get("ts").as_u64(),
                    min_v: 1,
                    min_alg_id: 1,
                    expected_kind: 1,
                    sender_revoked: false,
                },
                &env,
            )
            .expect("valid envelope opens");
            assert_eq!(plaintext, case.get("plaintext_hex").hex());
        }
    }
}

fn seed32(j: &Json) -> [u8; 32] {
    j.hex().try_into().expect("32-byte seed")
}

fn seed32_pk(j: &Json) -> [u8; 32] {
    j.hex().try_into().expect("32-byte public key")
}

// ================================================================================================
// key-validity.json: Ed25519 canonicality / X25519 non-validation cross-language parity (td-b8c68a)
// ================================================================================================

/// Loads `vectors/key-validity.json` (written by `gen_crypto_vectors.rs`'s `key_validity_vectors`)
/// and re-checks every case against `spindle_core::checked_verifying_key` (curve `"ed25519"`) or
/// `x25519_dalek::PublicKey::from` (curve `"x25519"`), independently of the generator's own
/// in-process `assert!`s — same "don't just trust the writer" discipline as every other test in
/// this file. `@spindle/crypto`'s `test/vectors.test.ts` reads this same file and must reach the
/// same verdicts, since this file's whole purpose is being the cross-language contract (DESIGN.md
/// :1117) for td-b8c68a's Rust/TS Ed25519 canonicality fix.
#[test]
fn key_validity_vectors_agree_with_checked_verifying_key() {
    let doc = load_top("key-validity.json");
    for case in doc.get("cases").as_arr() {
        let name = case.get("name").as_str();
        let curve = case.get("curve").as_str();
        let key_bytes: [u8; 32] = case.get("key_hex").hex().try_into().expect("32-byte key");
        let expect_accept = match case.get("expected").as_str() {
            "accept" => true,
            "reject" => false,
            other => panic!("case `{name}`: unknown expected verdict `{other}`"),
        };

        match curve {
            "ed25519" => {
                let accepted = spindle_core::checked_verifying_key(&key_bytes).is_some();
                assert_eq!(
                    accepted, expect_accept,
                    "case `{name}`: checked_verifying_key accepted={accepted}, expected \
                     accept={expect_accept}"
                );
            }
            "x25519" => {
                // x25519_dalek::PublicKey::from is infallible (any 32 bytes are a valid
                // Montgomery u-coordinate candidate), so this branch only exists to fail loudly
                // if a future case's `expected` is ever "reject" for an X25519 key — which would
                // mean this vector file has drifted from the deliberate agreement it exists to
                // pin (see key_validity_vectors' doc comment in gen_crypto_vectors.rs).
                let _ = spindle_core::X25519PublicKey::from(key_bytes);
                assert!(
                    expect_accept,
                    "case `{name}`: an X25519 case expecting `reject` contradicts \
                     x25519_dalek::PublicKey::from's documented infallibility -- fix the vector, \
                     not this test"
                );
            }
            other => panic!("case `{name}`: unknown curve `{other}`"),
        }
    }
}
