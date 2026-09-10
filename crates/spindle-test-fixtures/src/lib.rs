//! **DEV-ONLY.** This crate exists solely to be a `[dev-dependencies]` entry of other crates'
//! integration tests. It must never appear in any crate's `[dependencies]`, and it ships no
//! production code — only the NATS Auth Callout bootstrap fixtures and live-stack connection
//! helpers that [`crate::fixtures`] and this crate's top-level connection helpers below provide.
//!
//! # Why this crate exists
//!
//! `crates/spindle-net/tests/live_signaling.rs`'s fixtures were originally a private `mod
//! fixtures` inside that integration test, so no other crate could reach them. `spindle-hostd`
//! needs the same callout bootstrap for its own live test. The alternative — copying ~190 lines of
//! callout/certificate bootstrap into a second test file — was rejected: divergence between a
//! fixture copy and the helper's real wire schema is precisely what caused the 2026-08-31 incident
//! `live_signaling.rs`'s own module doc comment documents in full (every live test began failing
//! at NATS CONNECT with `authorization violation`, and the root cause was a fixture/helper
//! wire-schema mismatch that looked like an unrelated auth failure). One definition, two
//! consumers. See `live_signaling.rs`'s module doc comment for the full narrative: the callout
//! bootstrap recipe, the incident writeup, and the "rebuild the helper image after any A7b
//! wire-schema change" warning — all of that still applies verbatim to the fixtures now living
//! here.

// =================================================================================================
// Fixtures — the proven callout bootstrap recipe, rebuilt on `spindle-core`/`spindle-proto`
// (`spikes/s1-callout::fixtures` is spike-local and not a dependency of this crate).
// =================================================================================================

pub mod fixtures {
    use base64::Engine as _;
    use spindle_core::artifacts::{
        issue_capability, issue_device_certificate, issue_host_op_key_cert,
        issue_host_session_attestation, issue_session_attestation,
    };
    use spindle_core::identity::{DeviceKey, RootKey};
    use spindle_core::{Fingerprint, SigningKey};
    use spindle_proto::artifacts::{
        CapKind, Capability, DeviceCertificate, HostOpKeyCert, HostSessionAttestation,
        SessionAttestation,
    };
    use spindle_proto::canonical::CborValue;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the unix epoch")
            .as_secs()
    }

    /// `nats_fp = hash(nats_pk)` (DESIGN.md §A4) for an nkey-encoded Ed25519 public key. `nkeys`
    /// wraps prefix+checksum around the same raw 32 bytes `ed25519_dalek` uses.
    pub fn nats_fp_of_nkey(pubkey_str: &str) -> Fingerprint {
        let (_prefix, raw) =
            nkeys::from_public_key(pubkey_str).expect("nkey public key is well-formed");
        Fingerprint::of_parts(&[&raw])
    }

    /// A device's root key + device key seeds, plus the fingerprint derived from them.
    /// `spindle_core::identity::DeviceKey` is deliberately not `Clone` (it holds secret halves),
    /// and both `SignalingClient::new` and `SignalingHost::new` take one by value, so this fixture
    /// keeps the seeds and mints a fresh equal key on demand rather than trying to share one.
    pub struct DeviceIdentity {
        pub root: RootKey,
        sign_seed: [u8; 32],
        agree_seed: [u8; 32],
        pub device_fp: Fingerprint,
    }

    impl DeviceIdentity {
        pub fn new(
            root_seed: [u8; 32],
            device_sign_seed: [u8; 32],
            device_agree_seed: [u8; 32],
        ) -> Self {
            let root = RootKey::from_seed(root_seed);
            let device_fp = DeviceKey::from_seeds(device_sign_seed, device_agree_seed).device_fp();
            Self {
                root,
                sign_seed: device_sign_seed,
                agree_seed: device_agree_seed,
                device_fp,
            }
        }

        pub fn device_key(&self) -> DeviceKey {
            DeviceKey::from_seeds(self.sign_seed, self.agree_seed)
        }

        pub fn root_fp(&self) -> Fingerprint {
            self.root.root_fp()
        }

        /// [amended v0.9.29, td-0bcab4 §A4 step 2]: no longer takes a `nats_fp` — the certificate
        /// itself no longer binds to a session key at all (that field is gone from
        /// `DeviceCertificate`). Session binding now happens per-connection, via
        /// [`Self::session_attestation`].
        pub fn certificate(&self, ts: u64, exp: u64) -> DeviceCertificate {
            let device = self.device_key();
            issue_device_certificate(
                &self.root,
                device.alg_id(),
                &device.sign_public_key(),
                &device.agree_public_key(),
                ts,
                exp,
            )
        }

        /// The §A4-step-2 artifact (td-0bcab4, added v0.9.29) that binds this device's
        /// **identity** key to one connecting session nkey's `nats_fp`. This is the fix for the
        /// bearer-token defect: previously `{root_pk, device_cert, caps}` alone authorized a
        /// connection from *any* nkey, because nothing at CONNECT ever exercised the device's own
        /// identity key. A caller mints one of these per session, over that session's own
        /// `nats_fp`, and presents it alongside the (now session-agnostic) certificate.
        pub fn session_attestation(&self, nats_fp: Fingerprint, ts: u64) -> SessionAttestation {
            issue_session_attestation(&self.device_key(), nats_fp, ts)
        }
    }

    /// A host's NATS-authenticating identity: root key + operating key. `host_fp` is the root
    /// fingerprint — the token every §A5 subject is scoped by. Deliberately separate from the
    /// host's envelope [`DeviceKey`]; see `crates/spindle-net/tests/live_signaling.rs`'s module
    /// doc comment (the "two fingerprints collapsed into one" defect it documents).
    pub struct HostRootIdentity {
        pub root: RootKey,
        pub op_signing: SigningKey,
        pub host_fp: Fingerprint,
    }

    impl HostRootIdentity {
        pub fn new(root_seed: [u8; 32], op_seed: [u8; 32]) -> Self {
            let root = RootKey::from_seed(root_seed);
            let op_signing = SigningKey::from_bytes(&op_seed);
            let host_fp = root.root_fp();
            Self {
                root,
                op_signing,
                host_fp,
            }
        }

        pub fn op_key_cert(&self, ts: u64, exp: u64) -> HostOpKeyCert {
            issue_host_op_key_cert(&self.root, &self.op_signing.verifying_key(), ts, exp)
        }

        /// The §A4-step-3 artifact (v0.9.31, td-583db5) that binds this host's **operating** key
        /// to one connecting session nkey's `nats_fp`. This is the host-side mirror of
        /// [`DeviceIdentity::session_attestation`]: `HostOpKeyCert` is the issuance chain only
        /// (no session binding at all), and a caller mints one of these per session, over that
        /// session's own `nats_fp`, and presents it alongside the op-key cert.
        pub fn session_attestation(&self, nats_fp: Fingerprint, ts: u64) -> HostSessionAttestation {
            issue_host_session_attestation(&self.op_signing, nats_fp, ts)
        }

        /// The `op_cert` a capability embeds (decision A10.30 — a capability chains root ->
        /// operating key -> capability). Built fresh per call with a never-expiring `exp`: this is
        /// an issuance-time cert, not the one the host presents on its own CONNECT.
        ///
        /// `pub` (rather than private, as this started) so a live test can build a real
        /// `spindle_host_core::RootKeyCapIssuer` from this same fixture (td-c74122 slice D):
        /// `RootKeyCapIssuer::new` needs exactly this op cert, this struct's own `root.public_key()`,
        /// and its already-`pub` `op_signing` field. `HostOpKeyCert` no longer carries a `nats_fp`
        /// at all (td-583db5 moved the per-connect NATS binding to `HostSessionAttestation`), so
        /// there is no dummy session-binding value to explain here any more: the issuance chain and
        /// the session a host actually presents on are two different artifacts now, not one cert
        /// pressed into both roles.
        pub fn capability_op_cert(&self) -> HostOpKeyCert {
            issue_host_op_key_cert(&self.root, &self.op_signing.verifying_key(), 0, u64::MAX)
        }

        /// A `member` capability for `subject` (a device's `root_fp`) — what earns a client
        /// connection `pub host.<h>.connect`, `pub host.<h>.sess.<own>.*.c2h` and
        /// `sub host.<h>.sess.<own>.*.h2c` from the callout.
        pub fn member_capability(
            &self,
            subject: Fingerprint,
            exp: u64,
            nonce: Vec<u8>,
        ) -> Capability {
            issue_capability(
                &self.root.public_key(),
                &self.capability_op_cert(),
                &self.op_signing,
                CapKind::Member,
                subject,
                0,
                exp,
                nonce,
            )
        }
    }

    fn b64url(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// The device CONNECT `auth_token`, byte-compatible with
    /// `spindle_helper::auth_token::decode_auth_token`'s `kind: "device"` arm.
    ///
    /// `session_attest` (added v0.9.29, td-0bcab4 §A4 step 2) is required — see
    /// `spindle_helper::auth_token`'s module doc for why this field, unlike the host arm's
    /// `admission_token`, has no "absent" case.
    pub fn device_auth_token(
        root_pk_bytes: &[u8; 32],
        device_cert: &DeviceCertificate,
        session_attest: &SessionAttestation,
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
            (
                "session_attest",
                CborValue::bytes(session_attest.to_canonical_bytes()),
            ),
            ("caps", CborValue::array(cap_bytes)),
        ]);
        b64url(&spindle_proto::canonical_encode(&env))
    }

    /// The host CONNECT `auth_token`, byte-compatible with
    /// `spindle_helper::auth_token::decode_auth_token`'s `kind: "host"` arm. No admission token:
    /// the composed stack runs `ADMISSION_MODE=open`.
    ///
    /// `session_attest` (added v0.9.31, td-583db5 §A4 step 3) is required — see
    /// `spindle_helper::auth_token`'s module doc for why this field, unlike `admission_token`, has
    /// no "absent" case.
    pub fn host_auth_token(
        host_root_pk_bytes: &[u8; 32],
        host_op_cert: &HostOpKeyCert,
        session_attest: &HostSessionAttestation,
    ) -> String {
        let env = CborValue::map(vec![
            ("kind", CborValue::text("host")),
            (
                "host_root_pk",
                CborValue::bytes(host_root_pk_bytes.to_vec()),
            ),
            (
                "host_op_cert",
                CborValue::bytes(host_op_cert.to_canonical_bytes()),
            ),
            (
                "session_attest",
                CborValue::bytes(session_attest.to_canonical_bytes()),
            ),
        ]);
        b64url(&spindle_proto::canonical_encode(&env))
    }
}

// =================================================================================================
// NATS connection bootstrap
// =================================================================================================

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fixtures::{DeviceIdentity, HostRootIdentity};

pub fn nats_url() -> String {
    std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string())
}

/// Every `async_nats::Event` this connection reported, as a string. Permission violations and
/// authorization errors surface here and nowhere else (`publish`/`subscribe` are fire-and-forget
/// at the client API level), so this is the only way a test can observe callout-issued scoping
/// actually biting. Same mechanism `spikes/s2-signaling`'s `s2-tests.rs` uses.
pub type EventLog = Arc<Mutex<Vec<String>>>;

pub fn base_opts() -> (async_nats::ConnectOptions, EventLog) {
    let events: EventLog = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let opts = async_nats::ConnectOptions::new()
        .connection_timeout(Duration::from_secs(5))
        .event_callback(move |event| {
            let sink = sink.clone();
            async move {
                sink.lock()
                    .expect("event log mutex")
                    .push(event.to_string());
            }
        });
    (opts, events)
}

/// Connects a device to the live stack through the real Auth Callout: fresh session nkey,
/// root-signed device certificate (no longer session-bound — see
/// [`fixtures::DeviceIdentity::certificate`]), a [`spindle_proto::artifacts::SessionAttestation`]
/// binding that key's `nats_fp` to the device's own identity key (§A4 step 2, td-0bcab4),
/// `auth_token` carrying `caps`, and the `_INBOX_<device_fp>` prefix §A5 grants. Also returns the
/// session nkey's own public-key string (`session.public_key()`) — the same value nats-server's own
/// `$SYS.ACCOUNT.*.CONNECT`/`.DISCONNECT` advisories carry at `client.user`
/// (`spindle_helper::presence`'s module doc names this field), so a caller can later recognize
/// *this exact connection* in a live advisory stream (the S9 revocation test needs this; neither
/// existing live test does, hence the leading underscore at most of their call sites).
pub async fn connect_device(
    url: &str,
    device: &DeviceIdentity,
    caps: &[spindle_proto::artifacts::Capability],
    exp: u64,
) -> (async_nats::Client, EventLog, String) {
    let session = nkeys::KeyPair::new_user();
    let user_pk = session.public_key();
    let nats_fp = fixtures::nats_fp_of_nkey(&user_pk);
    let ts = fixtures::now();
    let cert = device.certificate(ts, exp);
    let session_attest = device.session_attestation(nats_fp, ts);
    let token = fixtures::device_auth_token(
        &device.root.public_key().to_bytes(),
        &cert,
        &session_attest,
        caps,
    );
    let (opts, events) = base_opts();
    let client = opts
        .nkey(session.seed().expect("session nkey seed"))
        .token(token)
        .custom_inbox_prefix(format!("_INBOX_{}", device.device_fp))
        .connect(url)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "device CONNECT to the live stack at {url} failed: {e}\n\
                 This test requires `docker compose -f deploy/docker-compose.yml up -d` \
                 (nats + postgres + helper). It never skips.\n\
                 If the error above is an authorization violation rather than an unreachable-stack \
                 error, the stack may be perfectly healthy: this device's root_fp may already be \
                 durably revoked in the helper's own store from a PREVIOUS run (Postgres's \
                 `revoked_subjects` table, keyed by root_fp under a host_fp) — check that table for \
                 this identity before assuming the stack is broken."
            )
        });
    (client, events, user_pk)
}

/// Connects a host to the live stack through the real Auth Callout (operating-key certificate,
/// a [`spindle_proto::artifacts::HostSessionAttestation`] binding that key's `nats_fp` to the
/// host's own operating key (§A4 step 3, td-583db5), `ADMISSION_MODE=open`, so no admission
/// token).
pub async fn connect_host(
    url: &str,
    host: &HostRootIdentity,
    exp: u64,
) -> (async_nats::Client, EventLog) {
    let session = nkeys::KeyPair::new_user();
    let nats_fp = fixtures::nats_fp_of_nkey(&session.public_key());
    let ts = fixtures::now();
    let cert = host.op_key_cert(ts, exp);
    let session_attest = host.session_attestation(nats_fp, ts);
    let token =
        fixtures::host_auth_token(&host.root.public_key().to_bytes(), &cert, &session_attest);
    let (opts, events) = base_opts();
    let client = opts
        .nkey(session.seed().expect("session nkey seed"))
        .token(token)
        .connect(url)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "host CONNECT to the live stack at {url} failed: {e}\n\
                 This test requires `docker compose -f deploy/docker-compose.yml up -d` \
                 (nats + postgres + helper). It never skips.\n\
                 If the error above is an authorization violation rather than an unreachable-stack \
                 error, the stack may be perfectly healthy: this host's root_fp may already be \
                 durably revoked in the helper's own store from a PREVIOUS run (Postgres's \
                 `revoked_subjects` table, keyed by root_fp under a host_fp) — check that table for \
                 this identity before assuming the stack is broken."
            )
        });
    (client, events)
}

/// Proves the stack is not accepting anonymous connections. If it were, every permission-scoping
/// claim this test makes would be vacuous — a connection that authenticated as nobody would carry
/// no callout-issued subject grants to violate in the first place.
pub async fn assert_stack_rejects_anonymous(url: &str) {
    let (opts, _events) = base_opts();
    match opts.connect(url).await {
        Ok(_) => panic!(
            "the stack at {url} accepted a connection with no nkey and no auth_token. \
             This test's permission-scoping evidence would be meaningless against such a stack — \
             check that deploy/docker-compose.yml's helper is running and nats-server.conf still \
             requires Auth Callout."
        ),
        Err(e) => println!("[auth] anonymous CONNECT correctly rejected: {e}"),
    }
}

/// Fails if this connection ever reported a NATS permissions violation. A violation here would
/// mean `spindle_net::signaling::subject`'s subject strings have drifted from
/// `spindle_helper::permissions`' grants — silently, since `async_nats`' publish/subscribe are
/// fire-and-forget and only surface the server's `-ERR` through the event callback. This is
/// precisely the check that caught defect 1 in `crates/spindle-net/tests/live_signaling.rs`'s
/// module doc comment.
pub fn assert_no_permission_violation(events: &EventLog, who: &str) {
    let log = events.lock().expect("event log mutex");
    if let Some(hit) = log.iter().find(|e| e.contains("Permissions Violation")) {
        panic!(
            "{who} connection hit a NATS permissions violation: {hit}\n\
             full event log: {log:#?}"
        );
    }
}

// =================================================================================================
// Minimal JSON — just enough to read a nats-server $SYS advisory
// =================================================================================================

/// This crate's own `[dependencies]` carry only `nkeys`/`base64` (see this crate's `Cargo.toml`) —
/// no `serde_json`, and this task is explicitly not to add one. The only JSON this
/// test ever needs to read is nats-server's own `$SYS.ACCOUNT.*.DISCONNECT` advisory payload
/// (`spikes/s9-revoke-kick/RESULTS.md` documents its exact shape), and the only two fields that
/// matter are a top-level string (`reason`) and one nested string (`client.user`). This is a
/// deliberately small recursive-descent parser covering just enough of RFC 8259 to read
/// nats-server's own advisories — not a general-purpose JSON library.
pub mod tinyjson {
    #[derive(Debug, Clone)]
    // This test only ever reads `String`/`Object` values back out (via `get`/`as_str`) — the
    // other variants exist so `parse_value` can walk past whatever shape of JSON a real
    // nats-server advisory contains (numbers, bools, nested arrays) without failing, even though
    // nothing in this test currently reads their payloads back out.
    #[allow(dead_code)]
    pub enum Json {
        Null,
        Bool(bool),
        Number(f64),
        String(String),
        Array(Vec<Json>),
        Object(Vec<(String, Json)>),
    }

    impl Json {
        /// Looks up `key` if `self` is an object; `None` for every other shape or a missing key.
        pub fn get(&self, key: &str) -> Option<&Json> {
            match self {
                Json::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }

        pub fn as_str(&self) -> Option<&str> {
            match self {
                Json::String(s) => Some(s.as_str()),
                _ => None,
            }
        }
    }

    pub fn parse(input: &str) -> Option<Json> {
        let bytes = input.as_bytes();
        let mut pos = 0usize;
        parse_value(bytes, &mut pos)
    }

    fn skip_ws(bytes: &[u8], pos: &mut usize) {
        while matches!(bytes.get(*pos), Some(b) if b.is_ascii_whitespace()) {
            *pos += 1;
        }
    }

    fn parse_value(bytes: &[u8], pos: &mut usize) -> Option<Json> {
        skip_ws(bytes, pos);
        match bytes.get(*pos)? {
            b'{' => parse_object(bytes, pos),
            b'[' => parse_array(bytes, pos),
            b'"' => parse_string(bytes, pos).map(Json::String),
            b't' => parse_literal(bytes, pos, "true", Json::Bool(true)),
            b'f' => parse_literal(bytes, pos, "false", Json::Bool(false)),
            b'n' => parse_literal(bytes, pos, "null", Json::Null),
            _ => parse_number(bytes, pos),
        }
    }

    fn parse_literal(bytes: &[u8], pos: &mut usize, literal: &str, value: Json) -> Option<Json> {
        let end = *pos + literal.len();
        if bytes.get(*pos..end)? == literal.as_bytes() {
            *pos = end;
            Some(value)
        } else {
            None
        }
    }

    fn parse_number(bytes: &[u8], pos: &mut usize) -> Option<Json> {
        let start = *pos;
        if bytes.get(*pos) == Some(&b'-') {
            *pos += 1;
        }
        while matches!(
            bytes.get(*pos),
            Some(b'0'..=b'9') | Some(b'.') | Some(b'e') | Some(b'E') | Some(b'+') | Some(b'-')
        ) {
            *pos += 1;
        }
        let s = std::str::from_utf8(&bytes[start..*pos]).ok()?;
        s.parse::<f64>().ok().map(Json::Number)
    }

    fn parse_string(bytes: &[u8], pos: &mut usize) -> Option<String> {
        if bytes.get(*pos) != Some(&b'"') {
            return None;
        }
        *pos += 1;
        let mut s = String::new();
        loop {
            match *bytes.get(*pos)? {
                b'"' => {
                    *pos += 1;
                    return Some(s);
                }
                b'\\' => {
                    *pos += 1;
                    match *bytes.get(*pos)? {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'n' => s.push('\n'),
                        b't' => s.push('\t'),
                        b'r' => s.push('\r'),
                        b'b' => s.push('\u{8}'),
                        b'f' => s.push('\u{c}'),
                        b'u' => {
                            let hex = std::str::from_utf8(bytes.get(*pos + 1..*pos + 5)?).ok()?;
                            let code_point = u32::from_str_radix(hex, 16).ok()?;
                            s.push(char::from_u32(code_point)?);
                            *pos += 4;
                        }
                        _ => return None,
                    }
                    *pos += 1;
                }
                _ => {
                    // Copy one UTF-8 scalar verbatim (advisories may carry non-ASCII in, e.g.,
                    // hostnames — never assumed ASCII-only).
                    let rest = std::str::from_utf8(&bytes[*pos..]).ok()?;
                    let ch = rest.chars().next()?;
                    s.push(ch);
                    *pos += ch.len_utf8();
                }
            }
        }
    }

    fn parse_object(bytes: &[u8], pos: &mut usize) -> Option<Json> {
        *pos += 1; // consume '{'
        let mut entries = Vec::new();
        skip_ws(bytes, pos);
        if bytes.get(*pos) == Some(&b'}') {
            *pos += 1;
            return Some(Json::Object(entries));
        }
        loop {
            skip_ws(bytes, pos);
            let key = parse_string(bytes, pos)?;
            skip_ws(bytes, pos);
            if bytes.get(*pos) != Some(&b':') {
                return None;
            }
            *pos += 1;
            let value = parse_value(bytes, pos)?;
            entries.push((key, value));
            skip_ws(bytes, pos);
            match bytes.get(*pos)? {
                b',' => *pos += 1,
                b'}' => {
                    *pos += 1;
                    return Some(Json::Object(entries));
                }
                _ => return None,
            }
        }
    }

    fn parse_array(bytes: &[u8], pos: &mut usize) -> Option<Json> {
        *pos += 1; // consume '['
        let mut items = Vec::new();
        skip_ws(bytes, pos);
        if bytes.get(*pos) == Some(&b']') {
            *pos += 1;
            return Some(Json::Array(items));
        }
        loop {
            items.push(parse_value(bytes, pos)?);
            skip_ws(bytes, pos);
            match bytes.get(*pos)? {
                b',' => *pos += 1,
                b']' => {
                    *pos += 1;
                    return Some(Json::Array(items));
                }
                _ => return None,
            }
        }
    }
}
