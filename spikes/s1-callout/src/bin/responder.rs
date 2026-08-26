//! S1's real Auth Callout responder (docs/SPIKES.md §S1): subscribes to
//! `$SYS.REQ.USER.AUTH`, decodes the authorization-request JWT (`src/natsjwt.rs`), decodes
//! Spindle's presented `auth_token` payload (`src/fixtures.rs`'s envelope), calls
//! `spindle_helper::authz::{decide_device_connect, decide_host_connect}` — the pure decision
//! core this spike exists to wire up, not reimplement — and answers with a signed
//! AuthorizationResponse JWT carrying the §A5 permission set from `spindle_helper::permissions`.
//!
//! # `verify_nkey_sig` (DESIGN.md §A4 step 1: "signing the server nonce with its session nkey")
//! The pure decision core takes this as an `impl FnOnce() -> bool` parameter rather than
//! performing it itself (see `spindle-helper/src/authz.rs`'s module docs: nkey-signature
//! verification against the server nonce is explicitly a "NATS-library/wiring-layer concern for
//! a later slice"). This responder satisfies it with the REAL mechanism NATS already gives a
//! callout responder for free: the authorization request's `connect_opts.sig` is the client's
//! session nkey signing the server-issued nonce (`client_info.nonce`) — exactly DESIGN.md §A4
//! step 1's "signing the server nonce with its session nkey". This is verified here via
//! `nkeys::KeyPair::from_public_key(connect_nkey)?.verify(nonce.as_bytes(), &sig)`, where
//! `connect_nkey = nats.connect_opts.nkey` (the client's actual presented nkey, equal to
//! `nats.client_info.user`) — **not** `nats.user_nkey`, a distinct, server-generated
//! per-request correlation key used only to address the response back to the right pending
//! connection (confirmed empirically: `probe.rs`'s captured request shows the two differ; using
//! the wrong one made every signature check fail with `BadNkeySignature` while surfacing on the
//! wire only as a bare `AuthorizationViolation` — see RESULTS.md). There is no separate
//! `sig_device(nats_fp, ts)` artifact in `spindle_proto` (see `fixtures.rs`'s module docs) —
//! this spike treats the NATS-level nkey proof-of-possession as satisfying that DESIGN.md
//! sentence, since both express the same fact (this session's nkey is genuinely held by whoever
//! is connecting), and no wire type exists for a distinct second signature.
//!
//! # HelperView
//! This spike uses an in-memory, all-permissive `HelperView` (no revocations, `open` admission
//! for hosts unless an admission token was presented, since S1's negative tests don't exercise
//! §A3b's admission-mode matrix — that's S16's job). See `InMemoryHelperView` below.

use futures_util::StreamExt;
use nkeys::KeyPair;
use spike_s1_callout::{fixtures, natsjwt};
use spindle_core::Fingerprint;
use spindle_helper::authz::{
    self, AdmissionMode, AdmissionRecord, AuthzDecision, DeviceConnectPresented, HelperView,
    HostConnectPresented,
};
use spindle_helper::permissions::SubjectPermissions;
use spindle_helper::session::SessionRecord;
use std::collections::HashMap;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

/// Bucket width for this store's TURN-usage counter — mirrors
/// `spindle_helper::memory_store::InMemoryHelperView`'s fixed 30-day rolling window (see that
/// module's `record_turn_issuance` doc comment); S1 doesn't exercise TURN at all, so this constant
/// only needs to exist to make the trait method's arithmetic well-defined.
const TURN_PERIOD_SECS: u64 = 30 * 86_400;

/// All-permissive test double: no revocations, `open` admission (a host with no prior admission
/// record is admitted on cert alone), one fixed operator key for admission-token verification.
/// Good enough for S1 — the admission-mode state machine itself is S16's negative-test suite, not
/// this one (docs/SPIKES.md §S1's pass criteria don't mention admission modes).
///
/// `sessions`/`turn_usage` (DESIGN.md §A5/§A9b, Stage 4 slice 3) were added after S1 originally
/// PASSed 19/19 — `HelperView` grew `put_session_record`/`session_record`/
/// `record_turn_issuance`/`record_revocation` for the graduated store
/// (`spindle_helper::memory_store::InMemoryHelperView`) without this spike's own copy being
/// updated to match, which left this binary failing to compile (E0046). Implemented here at
/// spike-appropriate fidelity — plain `HashMap`s, same semantics as the graduated store — purely
/// so the workspace builds again; S1's actual pass criteria (docs/SPIKES.md §S1) never exercised
/// sessions, TURN quota, or revocation, so none of this is expected to see real traffic.
struct InMemoryHelperView {
    operator_pk: ed25519_dalek::VerifyingKey,
    revoked: HashMap<(Fingerprint, Fingerprint), bool>,
    epochs: HashMap<Fingerprint, u64>,
    admitted: HashMap<Fingerprint, AdmissionRecord>,
    burned_nonces: HashMap<(Fingerprint, Vec<u8>), AdmissionRecord>,
    sessions: HashMap<Fingerprint, SessionRecord>,
    turn_usage: HashMap<(Fingerprint, u64), u64>,
}

impl HelperView for InMemoryHelperView {
    fn revocation_epoch(&mut self, host_fp: &Fingerprint) -> u64 {
        self.epochs.get(host_fp).copied().unwrap_or(0)
    }
    fn is_revoked(&mut self, host_fp: &Fingerprint, subject: &Fingerprint) -> bool {
        self.revoked
            .get(&(*host_fp, *subject))
            .copied()
            .unwrap_or(false)
    }
    fn admission_mode(&mut self) -> AdmissionMode {
        AdmissionMode::Open
    }
    fn admission_record(&mut self, host_fp: &Fingerprint) -> Option<AdmissionRecord> {
        self.admitted.get(host_fp).cloned()
    }
    fn operator_pk(&mut self) -> ed25519_dalek::VerifyingKey {
        self.operator_pk
    }
    fn burn_admission_token(
        &mut self,
        host_fp: Fingerprint,
        nonce: Vec<u8>,
        label: String,
        quota_profile: String,
        admitted_at: u64,
    ) -> Option<AdmissionRecord> {
        let key = (host_fp, nonce.clone());
        if let Some(existing) = self.burned_nonces.get(&key) {
            return if existing.host_fp == host_fp {
                Some(existing.clone())
            } else {
                None
            };
        }
        let record = AdmissionRecord {
            host_fp,
            label,
            admitted_at,
            quota_profile,
        };
        self.burned_nonces.insert(key, record.clone());
        self.admitted.insert(host_fp, record.clone());
        Some(record)
    }

    fn put_session_record(&mut self, record: SessionRecord) {
        self.sessions.insert(record.nats_fp, record);
    }

    fn session_record(&mut self, nats_fp: &Fingerprint, now: u64) -> Option<SessionRecord> {
        self.sessions.get(nats_fp).filter(|r| r.exp > now).cloned()
    }

    fn record_turn_issuance(
        &mut self,
        root_fp: &Fingerprint,
        now: u64,
        monthly_quota: u64,
    ) -> Result<u64, u64> {
        let period = now / TURN_PERIOD_SECS;
        let count = self.turn_usage.entry((*root_fp, period)).or_insert(0);
        if *count >= monthly_quota {
            Err(*count)
        } else {
            *count += 1;
            Ok(*count)
        }
    }

    fn record_revocation(
        &mut self,
        host_fp: Fingerprint,
        epoch: u64,
        revoked_subjects: &[Fingerprint],
    ) {
        let entry = self.epochs.entry(host_fp).or_insert(0);
        *entry = (*entry).max(epoch);
        for subject in revoked_subjects {
            self.revoked.insert((host_fp, *subject), true);
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Translates `spindle_helper::permissions::SubjectPermissions` into the NATS v2 User-JWT `nats`
/// claims object (`src/natsjwt.rs::user_nats_claims`).
fn permissions_to_nats_claims(
    perms: &SubjectPermissions,
    payload_bytes: u32,
    max_subs: u32,
    allowed_connection_types: &[&str],
) -> serde_json::Value {
    // TTL travels as nanoseconds (a plain JSON number) -- see natsjwt::user_nats_claims's doc
    // comment for why a Go duration *string* like "120s" is wrong here.
    let resp = perms
        .allow_responses
        .map(|ar| (ar.max, ar.expires_secs as i64 * 1_000_000_000));
    natsjwt::user_nats_claims(
        &perms.publish_allow,
        &perms.subscribe_allow,
        &perms.deny,
        resp,
        max_subs as i64,
        payload_bytes as i64,
        allowed_connection_types,
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let callout_seed = env::var("CALLOUT_USER_SEED").expect("CALLOUT_USER_SEED");
    let app_account_seed = env::var("APP_ACCOUNT_SEED").expect("APP_ACCOUNT_SEED");
    let operator_seed = env::var("OPERATOR_SEED").ok();
    let url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());

    let app_kp = KeyPair::from_seed(&app_account_seed)?;
    let operator_pk = match operator_seed {
        Some(seed) => {
            let (_, raw) =
                nkeys::decode_seed(&seed).map_err(|e| anyhow::anyhow!("bad OPERATOR_SEED: {e}"))?;
            ed25519_dalek::SigningKey::from_bytes(&raw).verifying_key()
        }
        None => ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]).verifying_key(),
    };

    let mut view = InMemoryHelperView {
        operator_pk,
        revoked: HashMap::new(),
        epochs: HashMap::new(),
        admitted: HashMap::new(),
        burned_nonces: HashMap::new(),
        sessions: HashMap::new(),
        turn_usage: HashMap::new(),
    };

    let client = async_nats::ConnectOptions::with_nkey(callout_seed)
        .connect(&url)
        .await?;
    let mut sub = client.subscribe("$SYS.REQ.USER.AUTH").await?;
    eprintln!("responder: listening on $SYS.REQ.USER.AUTH");

    while let Some(msg) = sub.next().await {
        let Some(reply) = msg.reply.clone() else {
            continue;
        };
        let result = handle_one(&msg.payload, &app_kp, &mut view);
        let resp_jwt = match result {
            Ok(jwt) => jwt,
            Err(e) => {
                eprintln!("responder: internal error building response: {e:#}");
                // Uniform refusal even for an internal decode error — never leak detail on the
                // wire (spindle_helper::authz module docs: "uniform silent drops").
                encode_refusal(&msg.payload, &app_kp)
            }
        };
        if let Some(resp) = resp_jwt {
            let _ = client.publish(reply, resp.into()).await;
            let _ = client.flush().await;
        }
    }
    Ok(())
}

fn encode_refusal(request_payload: &[u8], app_kp: &KeyPair) -> Option<String> {
    let req_str = String::from_utf8(request_payload.to_vec()).ok()?;
    let claims = natsjwt::decode_claims_unverified(&req_str).ok()?;
    let user_nkey = claims["nats"]["user_nkey"].as_str()?.to_string();
    let server_id = claims["nats"]["server_id"]["id"].as_str()?.to_string();
    let inner = natsjwt::response_err(authz::UNIFORM_REFUSAL_MESSAGE);
    let resp_claims =
        natsjwt::authorization_response(&app_kp.public_key(), &server_id, &user_nkey, inner);
    Some(natsjwt::encode(resp_claims, app_kp))
}

fn handle_one(
    request_payload: &[u8],
    app_kp: &KeyPair,
    view: &mut InMemoryHelperView,
) -> anyhow::Result<Option<String>> {
    let req_str = String::from_utf8(request_payload.to_vec())?;
    let claims = natsjwt::decode_claims_unverified(&req_str)?;
    // `nats.user_nkey` is a server-generated per-request correlation key -- NOT the client's
    // actual presented nkey. It exists so the callout protocol works uniformly for clients that
    // never present an nkey at all (password/TLS-cert auth); the *response*'s `sub` must echo
    // this value back (empirically confirmed: `probe.rs` against a live server, and nats-server's
    // `auth_callout.go` `decodeResponse`, matches the response against the request it correlates
    // to by this field, not by `connect_opts.nkey`). It must NOT be used as the public key for
    // nkey-signature verification.
    let user_nkey = claims["nats"]["user_nkey"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing user_nkey"))?
        .to_string();
    let server_id = claims["nats"]["server_id"]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing server_id"))?
        .to_string();
    let nonce = claims["nats"]["client_info"]["nonce"]
        .as_str()
        .unwrap_or("")
        .to_string();
    // The client's *actual* presented nkey -- `connect_opts.nkey` (equal to `client_info.user`)
    // -- is what `connect_opts.sig` is a signature over `nonce` with. This is distinct from
    // `nats.user_nkey` above (see its comment): using the wrong one here makes every real
    // signature fail verification while looking, from the wire, like a generic
    // AuthorizationViolation with no further detail -- root-caused empirically via `probe.rs`'s
    // captured request (RESULTS.md).
    let connect_nkey = claims["nats"]["connect_opts"]["nkey"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let sig_b64 = claims["nats"]["connect_opts"]["sig"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let auth_token = claims["nats"]["connect_opts"]["auth_token"]
        .as_str()
        .map(|s| s.to_string());

    let now = now_secs();
    let jitter_source: u64 = rand::random();

    let respond_ok = |perms: SubjectPermissions,
                      limits: spindle_helper::permissions::Limits,
                      max_hosts: u32|
     -> String {
        let nats_claims = permissions_to_nats_claims(
            &perms,
            limits.payload_bytes,
            limits.max_subscriptions.max(4 * max_hosts + 8),
            &["STANDARD", "WEBSOCKET"],
        );
        let user_claims_val = natsjwt::user_claims(
            &app_kp.public_key(),
            "APP",
            &user_nkey,
            limits.exp,
            nats_claims,
        );
        let user_jwt = natsjwt::encode(user_claims_val, app_kp);
        let inner = natsjwt::response_ok(user_jwt);
        let resp_claims =
            natsjwt::authorization_response(&app_kp.public_key(), &server_id, &user_nkey, inner);
        natsjwt::encode(resp_claims, app_kp)
    };

    let respond_err = |msg: &str| -> String {
        let inner = natsjwt::response_err(msg);
        let resp_claims =
            natsjwt::authorization_response(&app_kp.public_key(), &server_id, &user_nkey, inner);
        natsjwt::encode(resp_claims, app_kp)
    };

    let verify_nkey_sig = || -> bool {
        if nonce.is_empty() || sig_b64.is_empty() || connect_nkey.is_empty() {
            return false;
        }
        let Ok(kp) = KeyPair::from_public_key(&connect_nkey) else {
            return false;
        };
        let Ok(sig) = base64_url_decode(&sig_b64) else {
            return false;
        };
        kp.verify(nonce.as_bytes(), &sig).is_ok()
    };

    let Some(auth_token) = auth_token else {
        // No auth_token at all presented: treat identically to "no capabilities presented" —
        // uniform refusal (DESIGN.md §A5 Sybil/flood defense).
        return Ok(Some(respond_err(authz::UNIFORM_REFUSAL_MESSAGE)));
    };

    let decoded = match fixtures::decode_auth_token(&auth_token) {
        Ok(d) => d,
        Err(_) => return Ok(Some(respond_err(authz::UNIFORM_REFUSAL_MESSAGE))),
    };

    match decoded {
        fixtures::DecodedPayload::Device(d) => {
            let root_pk = fixtures::verifying_key_from_bytes(&d.root_pk_bytes)?;
            let nats_fp = fixtures::nats_fp_of_nkey(&connect_nkey)?;
            let presented = DeviceConnectPresented {
                root_pk,
                device_cert: d.device_cert,
                caps: d.caps,
                nats_fp,
            };
            let decision =
                authz::decide_device_connect(&presented, verify_nkey_sig, now, view, jitter_source);
            match decision {
                AuthzDecision::Authorized(auth) => {
                    let host_count = auth.session_record.host_fps.len() as u32;
                    Ok(Some(respond_ok(auth.permissions, auth.limits, host_count)))
                }
                AuthzDecision::Refused(_reason) => {
                    // `_reason` (spindle_helper::authz::RefusalReason) is deliberately not put on
                    // the wire or logged here -- the uniform-refusal contract
                    // (authz::UNIFORM_REFUSAL_MESSAGE's doc: "never leak detail on the wire")
                    // extends to this spike's own stderr too, so nothing about this binary's
                    // default behavior depends on which refusal reason fired.
                    Ok(Some(respond_err(authz::UNIFORM_REFUSAL_MESSAGE)))
                }
            }
        }
        fixtures::DecodedPayload::Host(h) => {
            let host_root_pk = fixtures::verifying_key_from_bytes(&h.host_root_pk_bytes)?;
            let nats_fp = fixtures::nats_fp_of_nkey(&connect_nkey)?;
            let presented = HostConnectPresented {
                host_root_pk,
                host_op_cert: h.host_op_cert,
                admission_token: h.admission_token,
                nats_fp,
            };
            let decision =
                authz::decide_host_connect(&presented, verify_nkey_sig, now, view, jitter_source);
            match decision {
                AuthzDecision::Authorized(auth) => {
                    Ok(Some(respond_ok(auth.permissions, auth.limits, 1)))
                }
                AuthzDecision::Refused(_reason) => {
                    Ok(Some(respond_err(authz::UNIFORM_REFUSAL_MESSAGE)))
                }
            }
        }
    }
}

fn base64_url_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?)
}
