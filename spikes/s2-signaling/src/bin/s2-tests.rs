//! S2 leg A step A live validation harness (docs/SPIKES.md §S2; docs/DESIGN.md §A6/§A7) — the
//! first empirical test of the §A6 signaling flow against the live composed stack
//! (`deploy/docker-compose.yml`'s `nats` + `postgres` + `helper`), over the same NATS Auth
//! Callout scoping `spike-s1-callout`/`spike-s5-presence` already exercised. Deliberately does
//! NOT do ICE (the real libwebrtc/webrtc-rs kind) or QUIC — see this crate's `RESULTS.md` for
//! exactly what this step answers and what it defers to step B.
//!
//! # Architecture of this harness
//! A single OS process. The "host" side runs as an in-process `tokio::spawn`ed task holding its
//! own real `async-nats` connection (authenticated via `spike_s1_callout::fixtures`' host
//! `auth_token`, exactly like `spike-s5-presence`'s `fake_host`), so it is a genuine NATS peer
//! subject to the composed helper's real Auth Callout scoping — not a stand-in. Unlike S5's
//! `fake_host`, this host needs to run real application-level protocol logic (open/verify
//! envelopes, reply, track per-session replay state), so it lives in-process rather than as a
//! separate OS binary; nothing in this step needs to freeze/kill it as a separate process the
//! way S5's dead-socket scenario did.
//!
//! # The host's own "device" identity
//! DESIGN.md never says how a host's per-session E2E envelope identity (the `to_fp` the envelope
//! module's own doc calls "the host's device_fp") relates to the host's NATS-authenticating
//! `host_fp` (root-derived, used only for subject scoping / capability chains). This harness
//! mints the host a plain `spindle_core::identity::DeviceKey` for that purpose, kept entirely
//! separate from its `HostIdentity` (root + operating key, used only for the NATS CONNECT and
//! for signing member capabilities). See `spike_s2_signaling`'s crate doc and `RESULTS.md` for
//! why, and for the related key-distribution gap this harness works around by pre-sharing public
//! keys directly in test setup rather than through any registry/enrollment flow (out of scope
//! for this step).
//!
//! # Env vars
//! - `NATS_URL` — default `nats://127.0.0.1:4222` (the compose stack's published TCP listener).

use futures_util::StreamExt;
use nkeys::KeyPair;
use rand::Rng;
use spike_s1_callout::fixtures;
use spike_s2_signaling::{
    open_payload, seal_payload, x25519_public_from_bytes, AnswerPayload, EphemeralKey, IcePayload,
    OfferPayload, SealPayloadParams, ALG_ID_V1, KIND_ANSWER, KIND_ICE, KIND_OFFER, V1,
};
use spindle_core::identity::DeviceKey;
use spindle_core::{derive_session_key, Fingerprint, OpenParams, SessionKey, VerifyingKey};
use spindle_proto::artifacts::{Capability, Envelope};
use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
use x25519_dalek::PublicKey as X25519PublicKey;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sid_token(sid: &[u8]) -> String {
    sid.iter().map(|b| format!("{b:02x}")).collect()
}

fn fresh_sid() -> Vec<u8> {
    let mut sid = [0u8; 16];
    rand::thread_rng().fill(&mut sid);
    sid.to_vec()
}

// ================================================================================================
// Checks bookkeeping — mirrors spike-s1-callout/spike-s5-presence's `Checks`.
// ================================================================================================

struct Checks {
    results: Vec<(String, bool, String)>,
}

impl Checks {
    fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    fn record(&mut self, name: &str, passed: bool, detail: impl Into<String>) {
        let detail = detail.into();
        println!(
            "[{}] {name}{}",
            if passed { "PASS" } else { "FAIL" },
            if detail.is_empty() {
                String::new()
            } else {
                format!(" -- {detail}")
            }
        );
        self.results.push((name.to_string(), passed, detail));
    }

    fn all_passed(&self) -> bool {
        self.results.iter().all(|(_, p, _)| *p)
    }
}

fn print_summary(checks: &Checks) {
    let total = checks.results.len();
    let passed = checks.results.iter().filter(|(_, p, _)| *p).count();
    println!("\n==== S2 leg A step A suite summary: {passed}/{total} checks passed ====");
    for (name, ok, detail) in &checks.results {
        println!(
            "  [{}] {name}{}",
            if *ok { "PASS" } else { "FAIL" },
            if detail.is_empty() {
                String::new()
            } else {
                format!(" -- {detail}")
            }
        );
    }
}

// ================================================================================================
// EventLog (NATS-permission-violation observation) — copied from spike-s5-presence's
// `src/bin/s5-tests.rs` (not shared via lib.rs there either — see that crate's own note).
// ================================================================================================

type EventLog = Arc<Mutex<Vec<String>>>;

fn base_opts() -> (async_nats::ConnectOptions, EventLog) {
    let events: EventLog = Arc::new(Mutex::new(Vec::new()));
    let events2 = events.clone();
    let opts = async_nats::ConnectOptions::new()
        .connection_timeout(Duration::from_secs(5))
        .event_callback(move |event| {
            let events = events2.clone();
            async move {
                events.lock().unwrap().push(event.to_string());
            }
        });
    (opts, events)
}

async fn wait_for_violation(events: &EventLog, needles: &[&str], timeout_ms: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        {
            let log = events.lock().unwrap();
            if log.iter().any(|e| needles.iter().all(|n| e.contains(n))) {
                return true;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn connect_device(
    url: &str,
    device: &fixtures::DeviceIdentity,
    caps: Vec<Capability>,
    exp: u64,
) -> anyhow::Result<(async_nats::Client, EventLog, Fingerprint)> {
    let session = KeyPair::new_user();
    let nats_fp = fixtures::nats_fp_of_nkey(&session.public_key())?;
    let cert = fixtures::device_certificate(device, nats_fp, now(), exp);
    let root_pk_bytes = device.root.public_key().to_bytes();
    let token = fixtures::device_auth_token(&root_pk_bytes, &cert, &caps);
    let inbox_prefix = format!("_INBOX_{}", device.device_fp);
    let (opts, events) = base_opts();
    let client = opts
        .nkey(session.seed()?)
        .token(token)
        .custom_inbox_prefix(inbox_prefix)
        .connect(url)
        .await?;
    Ok((client, events, nats_fp))
}

// ================================================================================================
// Host side
// ================================================================================================

/// Per-session state the host tracks once a connect handshake has been accepted (DESIGN.md §A7:
/// `seq` strictly increasing per `(sid, direction)`). Keyed by the client's `device_fp` in
/// [`HostState`] below — this harness never needs more than one live session per client fp at a
/// time, so a fresh connect simply overwrites any prior entry (a real host would need to decide
/// whether that's a reconnect or a stale replay; out of scope here).
struct HostSessionState {
    sid: Vec<u8>,
    session_key: SessionKey,
    min_seq_c2h: Option<u64>,
    next_seq_h2c: u64,
}

/// One event the host's handler logs for every inbound message it processes (accepted or
/// dropped), so the harness — which cannot otherwise observe a "silent drop" (that's the whole
/// point of DESIGN.md §A5's uniform-refusal rule) — can assert on what actually happened.
///
/// Every variant's fields are read via the derived `Debug` (printed in check-result detail
/// strings) rather than by direct field access, which rustc's dead-code analysis doesn't credit
/// as a "read" — hence the blanket allow rather than one per unused field.
#[allow(dead_code)]
#[derive(Debug, Clone)]
enum HostEvent {
    ConnectAccepted { from_fp: String },
    ConnectDroppedBadReplyPrefix { reply: Option<String> },
    ConnectDroppedUnknownSender { from_fp: String },
    ConnectDroppedEnvelopeError { detail: String },
    IceAccepted { seq: u64 },
    IceDroppedUnknownSession,
    IceDroppedEnvelopeError { seq: u64, detail: String },
}

type HostEvents = Arc<Mutex<Vec<HostEvent>>>;
type HostSessions = Arc<Mutex<HashMap<Fingerprint, HostSessionState>>>;

struct HostState {
    nats_client: async_nats::Client,
    host_fp: Fingerprint,   // NATS subject namespace (root-derived)
    host_device: DeviceKey, // E2E crypto identity for this host
    host_device_fp: Fingerprint,
    known_device_fp: Fingerprint, // the one device this spike's host recognizes as a member
    known_device_sign_pk: VerifyingKey,
    known_device_agree_pk: X25519PublicKey,
    sessions: HostSessions,
    events: HostEvents,
}

async fn wait_for_host_event(
    events: &HostEvents,
    pred: impl Fn(&HostEvent) -> bool,
    timeout_ms: u64,
) -> Option<HostEvent> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        {
            let log = events.lock().unwrap();
            if let Some(e) = log.iter().find(|e| pred(e)) {
                return Some(e.clone());
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Handles one `host.<h>.connect` request (DESIGN.md §A6/§A7's full receiver checklist).
async fn handle_connect(state: &HostState, msg: async_nats::Message) {
    let env = match Envelope::from_canonical_bytes(&msg.payload) {
        Ok(e) => e,
        Err(e) => {
            state
                .events
                .lock()
                .unwrap()
                .push(HostEvent::ConnectDroppedEnvelopeError {
                    detail: format!("envelope decode failed: {e}"),
                });
            return;
        }
    };
    let from_fp = match Fingerprint::from_slice(&env.from_fp) {
        Ok(fp) => fp,
        Err(e) => {
            state
                .events
                .lock()
                .unwrap()
                .push(HostEvent::ConnectDroppedEnvelopeError {
                    detail: format!("bad from_fp: {e}"),
                });
            return;
        }
    };

    // MUST (§A6, cheap, before crypto): reply subject starts with `_INBOX_<from_fp>.`.
    let expected_prefix = format!("_INBOX_{from_fp}.");
    let reply_ok = msg
        .reply
        .as_deref()
        .map(|r| r.starts_with(&expected_prefix))
        .unwrap_or(false);
    if !reply_ok {
        state
            .events
            .lock()
            .unwrap()
            .push(HostEvent::ConnectDroppedBadReplyPrefix {
                reply: msg.reply.as_ref().map(|s| s.to_string()),
            });
        return; // uniform silent drop -- no response, no distinguishable error (DESIGN.md §A5)
    }

    // MUST (§A5, cheap, before crypto): sender is an active member device.
    if from_fp != state.known_device_fp {
        state
            .events
            .lock()
            .unwrap()
            .push(HostEvent::ConnectDroppedUnknownSender {
                from_fp: from_fp.to_string(),
            });
        return;
    }

    let Some(eph_pk_c_bytes) = env.eph_pk.as_ref() else {
        state
            .events
            .lock()
            .unwrap()
            .push(HostEvent::ConnectDroppedEnvelopeError {
                detail: "offer envelope missing eph_pk".to_string(),
            });
        return;
    };
    let eph_pk_c = match x25519_public_from_bytes(eph_pk_c_bytes) {
        Ok(k) => k,
        Err(e) => {
            state
                .events
                .lock()
                .unwrap()
                .push(HostEvent::ConnectDroppedEnvelopeError {
                    detail: format!("bad eph_pk: {e:#}"),
                });
            return;
        }
    };

    // Bootstrap (message-1) session key -- see spike_s2_signaling's crate doc for why this
    // differs from the answer-onward key: eph_dh here is ephemeral(client)-static(host).
    let dev_dh = state
        .host_device
        .diffie_hellman(&state.known_device_agree_pk);
    let eph_dh_offer = state.host_device.diffie_hellman(&eph_pk_c);
    let session_key_offer = derive_session_key(
        &eph_dh_offer,
        &dev_dh,
        &env.sid,
        &from_fp,
        &state.host_device_fp,
    );

    let open_params = OpenParams {
        session_key: &session_key_offer,
        pinned_sender_key: &state.known_device_sign_pk,
        self_fp: &state.host_device_fp,
        expected_sid: &env.sid,
        bound_from_fp: None,
        min_seq_exclusive: None,
        now: now(),
        min_v: V1,
        min_alg_id: ALG_ID_V1,
        expected_kind: KIND_OFFER,
        sender_revoked: false,
    };
    let offer: OfferPayload = match open_payload(open_params, &env) {
        Ok(p) => p,
        Err(e) => {
            state
                .events
                .lock()
                .unwrap()
                .push(HostEvent::ConnectDroppedEnvelopeError {
                    detail: format!("{e}"),
                });
            return;
        }
    };

    // Accepted: derive the final (answer-onward) session key, store per-session state, reply.
    let eph_h = EphemeralKey::generate();
    let eph_dh_final = eph_h.diffie_hellman(&eph_pk_c);
    let session_key_final = derive_session_key(
        &eph_dh_final,
        &dev_dh,
        &env.sid,
        &from_fp,
        &state.host_device_fp,
    );

    state.sessions.lock().unwrap().insert(
        from_fp,
        HostSessionState {
            sid: env.sid.clone(),
            session_key: session_key_final.clone(),
            min_seq_c2h: Some(0),
            next_seq_h2c: 1,
        },
    );
    state
        .events
        .lock()
        .unwrap()
        .push(HostEvent::ConnectAccepted {
            from_fp: from_fp.to_string(),
        });

    let answer_payload = AnswerPayload {
        answer: format!("answer-for-{}", offer.offer),
    };
    let answer_env = seal_payload(
        SealPayloadParams {
            session_key: &session_key_final,
            signer: &state.host_device,
            v: V1,
            alg_id: ALG_ID_V1,
            from_fp: state.host_device_fp,
            to_fp: from_fp,
            sid: env.sid.clone(),
            kind: KIND_ANSWER,
            seq: 0,
            ts: now(),
            eph_pk: Some(eph_h.public_bytes()),
        },
        &answer_payload,
    );

    let reply_subject = msg.reply.clone().expect("checked Some above");
    let _ = state
        .nats_client
        .publish(reply_subject, answer_env.to_canonical_bytes().into())
        .await;
}

/// Handles one trickled ICE envelope on `host.<h>.sess.*.*.c2h`.
async fn handle_ice_c2h(state: &HostState, msg: async_nats::Message) {
    let env = match Envelope::from_canonical_bytes(&msg.payload) {
        Ok(e) => e,
        Err(e) => {
            state
                .events
                .lock()
                .unwrap()
                .push(HostEvent::IceDroppedEnvelopeError {
                    seq: 0,
                    detail: format!("envelope decode failed: {e}"),
                });
            return;
        }
    };
    let from_fp = match Fingerprint::from_slice(&env.from_fp) {
        Ok(fp) => fp,
        Err(e) => {
            state
                .events
                .lock()
                .unwrap()
                .push(HostEvent::IceDroppedEnvelopeError {
                    seq: env.seq,
                    detail: format!("bad from_fp: {e}"),
                });
            return;
        }
    };

    let echo_out;
    {
        let mut sessions = state.sessions.lock().unwrap();
        let Some(sess) = sessions.get_mut(&from_fp) else {
            drop(sessions);
            state
                .events
                .lock()
                .unwrap()
                .push(HostEvent::IceDroppedUnknownSession);
            return;
        };

        let open_params = OpenParams {
            session_key: &sess.session_key,
            pinned_sender_key: &state.known_device_sign_pk,
            self_fp: &state.host_device_fp,
            expected_sid: &sess.sid,
            bound_from_fp: Some(&from_fp),
            min_seq_exclusive: sess.min_seq_c2h,
            now: now(),
            min_v: V1,
            min_alg_id: ALG_ID_V1,
            expected_kind: KIND_ICE,
            sender_revoked: false,
        };
        let ice: IcePayload = match open_payload(open_params, &env) {
            Ok(p) => p,
            Err(e) => {
                let seq = env.seq;
                drop(sessions);
                state
                    .events
                    .lock()
                    .unwrap()
                    .push(HostEvent::IceDroppedEnvelopeError {
                        seq,
                        detail: format!("{e}"),
                    });
                return;
            }
        };

        sess.min_seq_c2h = Some(env.seq);
        let seq_out = sess.next_seq_h2c;
        sess.next_seq_h2c += 1;
        let echo = IcePayload {
            candidate: format!("host-echo-of:{}", ice.candidate),
        };
        let echo_env = seal_payload(
            SealPayloadParams {
                session_key: &sess.session_key,
                signer: &state.host_device,
                v: V1,
                alg_id: ALG_ID_V1,
                from_fp: state.host_device_fp,
                to_fp: from_fp,
                sid: sess.sid.clone(),
                kind: KIND_ICE,
                seq: seq_out,
                ts: now(),
                eph_pk: None,
            },
            &echo,
        );
        let h2c_subject = format!(
            "host.{}.sess.{}.{}.h2c",
            state.host_fp,
            from_fp,
            sid_token(&sess.sid)
        );
        echo_out = (h2c_subject, echo_env);
        state
            .events
            .lock()
            .unwrap()
            .push(HostEvent::IceAccepted { seq: env.seq });
    }

    let (h2c_subject, echo_env) = echo_out;
    let _ = state
        .nats_client
        .publish(h2c_subject, echo_env.to_canonical_bytes().into())
        .await;
}

async fn run_host(state: Arc<HostState>) {
    let connect_sub = state
        .nats_client
        .subscribe(format!("host.{}.connect", state.host_fp))
        .await;
    let c2h_sub = state
        .nats_client
        .subscribe(format!("host.{}.sess.*.*.c2h", state.host_fp))
        .await;
    let (mut connect_sub, mut c2h_sub) = match (connect_sub, c2h_sub) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            eprintln!("host failed to subscribe: connect={a:?} c2h={b:?}");
            return;
        }
    };
    loop {
        tokio::select! {
            msg = connect_sub.next() => {
                match msg {
                    Some(msg) => handle_connect(&state, msg).await,
                    None => break,
                }
            }
            msg = c2h_sub.next() => {
                match msg {
                    Some(msg) => handle_ice_c2h(&state, msg).await,
                    None => break,
                }
            }
        }
    }
}

// ================================================================================================
// Client side
// ================================================================================================

struct ClientSessionState {
    sid: Vec<u8>,
    session_key: SessionKey,
    own_fp: Fingerprint,  // client device fp
    peer_fp: Fingerprint, // host device fp
    next_seq_c2h: u64,
    min_seq_h2c: Option<u64>,
}

/// Runs one full connect handshake (offer -> answer) and returns the established session state,
/// the round-trip elapsed time (issuing the request to having verified the answer), and the
/// decrypted answer payload.
#[allow(clippy::too_many_arguments)]
async fn do_handshake(
    nats_client: &async_nats::Client,
    host_nats_fp: Fingerprint,
    host_device_fp: Fingerprint,
    host_device_sign_pk: VerifyingKey,
    host_device_agree_pk: X25519PublicKey,
    device: &fixtures::DeviceIdentity,
    offer_text: String,
) -> anyhow::Result<(ClientSessionState, Duration, AnswerPayload)> {
    let sid = fresh_sid();
    let eph_c = EphemeralKey::generate();
    let dev_dh = device.device.diffie_hellman(&host_device_agree_pk);
    let eph_dh_offer = eph_c.diffie_hellman(&host_device_agree_pk);
    let session_key_offer = derive_session_key(
        &eph_dh_offer,
        &dev_dh,
        &sid,
        &device.device_fp,
        &host_device_fp,
    );

    let offer_payload = OfferPayload {
        offer: offer_text.clone(),
        inbox: format!("_INBOX_{}", device.device_fp),
    };
    let offer_env = seal_payload(
        SealPayloadParams {
            session_key: &session_key_offer,
            signer: &device.device,
            v: V1,
            alg_id: ALG_ID_V1,
            from_fp: device.device_fp,
            to_fp: host_device_fp,
            sid: sid.clone(),
            kind: KIND_OFFER,
            seq: 0,
            ts: now(),
            eph_pk: Some(eph_c.public_bytes()),
        },
        &offer_payload,
    );

    let t0 = Instant::now();
    let reply = nats_client
        .request(
            format!("host.{host_nats_fp}.connect"),
            offer_env.to_canonical_bytes().into(),
        )
        .await?;
    let answer_env = Envelope::from_canonical_bytes(&reply.payload)
        .map_err(|e| anyhow::anyhow!("answer envelope decode failed: {e}"))?;
    let eph_pk_h_bytes = answer_env
        .eph_pk
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("answer envelope missing eph_pk"))?;
    let eph_pk_h = x25519_public_from_bytes(eph_pk_h_bytes)?;
    let eph_dh_final = eph_c.diffie_hellman(&eph_pk_h);
    let session_key_final = derive_session_key(
        &eph_dh_final,
        &dev_dh,
        &sid,
        &device.device_fp,
        &host_device_fp,
    );

    let open_params = OpenParams {
        session_key: &session_key_final,
        pinned_sender_key: &host_device_sign_pk,
        self_fp: &device.device_fp,
        expected_sid: &sid,
        bound_from_fp: None,
        min_seq_exclusive: None,
        now: now(),
        min_v: V1,
        min_alg_id: ALG_ID_V1,
        expected_kind: KIND_ANSWER,
        sender_revoked: false,
    };
    let answer_payload: AnswerPayload = open_payload(open_params, &answer_env)
        .map_err(|e| anyhow::anyhow!("answer open/verify failed: {e}"))?;
    let elapsed = t0.elapsed();

    let state = ClientSessionState {
        sid,
        session_key: session_key_final,
        own_fp: device.device_fp,
        peer_fp: host_device_fp,
        next_seq_c2h: 1,
        min_seq_h2c: Some(0),
    };
    Ok((state, elapsed, answer_payload))
}

// ================================================================================================
// main
// ================================================================================================

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let exp = now() + 3600;
    let mut checks = Checks::new();

    // ---- identities ----
    let host_seed = [0x52u8; 32]; // root_seed == op_seed workaround (spike-s1-callout/RESULTS.md)
    let host_identity = fixtures::new_host_identity(host_seed, host_seed);
    let host_fp = host_identity.host_fp;
    let host_device = DeviceKey::from_seeds([0x53; 32], [0x54; 32]);
    let host_device_fp = host_device.device_fp();
    let host_device_sign_pk = host_device.sign_public_key();
    let host_device_agree_pk = host_device.agree_public_key();

    let device_a = fixtures::new_device_identity([0x61; 32], [0x62; 32], [0x63; 32]);
    let device_a_sign_pk = device_a.device.sign_public_key();
    let device_a_agree_pk = device_a.device.agree_public_key();

    // A second, never-connected host — exists only to mint a member cap for check 4
    // (no-responders): `decide_device_connect` only verifies capability crypto, not host
    // liveness, so this cap is fully valid even though nothing ever subscribes under its
    // `host.<h2>.>` namespace.
    let host2_seed = [0x72u8; 32];
    let host2_identity = fixtures::new_host_identity(host2_seed, host2_seed);
    let host2_fp = host2_identity.host_fp;

    let cap_a_host1 =
        fixtures::member_capability(&host_identity, device_a.root_fp, 0, exp, vec![0xA1]);
    let cap_a_host2 =
        fixtures::member_capability(&host2_identity, device_a.root_fp, 0, exp, vec![0xA2]);

    // ---- connect host to the composed stack's real NATS/helper ----
    let host_nats_client = {
        let session = KeyPair::new_user();
        let nats_fp = fixtures::nats_fp_of_nkey(&session.public_key())?;
        let cert = fixtures::host_op_key_cert(&host_identity, nats_fp, now(), exp);
        let root_pk_bytes = host_identity.root.public_key().to_bytes();
        let token = fixtures::host_auth_token(&root_pk_bytes, &cert, None);
        async_nats::ConnectOptions::new()
            .nkey(session.seed()?)
            .token(token)
            .connection_timeout(Duration::from_secs(5))
            .connect(&url)
            .await?
    };
    checks.record("setup_host_connects", true, format!("host_fp={host_fp}"));

    let host_state = Arc::new(HostState {
        nats_client: host_nats_client,
        host_fp,
        host_device,
        host_device_fp,
        known_device_fp: device_a.device_fp,
        known_device_sign_pk: device_a_sign_pk,
        known_device_agree_pk: device_a_agree_pk,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        events: Arc::new(Mutex::new(Vec::new())),
    });
    {
        let state = host_state.clone();
        tokio::spawn(async move {
            run_host(state).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(300)).await; // let host subs land server-side

    // ---- connect device_a (member of host + host2) ----
    let (client_a, events_a, _nats_fp_a) =
        connect_device(&url, &device_a, vec![cap_a_host1, cap_a_host2], exp).await?;
    checks.record(
        "setup_device_a_connects",
        true,
        "member cap for host + host2",
    );

    // ============================================================================================
    // Check 1: connect handshake round trip (x20 — also the latency sample).
    // ============================================================================================
    let mut latencies: Vec<Duration> = Vec::with_capacity(20);
    let mut last_state: Option<ClientSessionState> = None;
    let mut round_trip_ok = true;
    let mut round_trip_detail = String::new();
    for i in 0..20u32 {
        let offer_text = format!("offer-{i}");
        match do_handshake(
            &client_a,
            host_fp,
            host_device_fp,
            host_device_sign_pk,
            host_device_agree_pk,
            &device_a,
            offer_text.clone(),
        )
        .await
        {
            Ok((state, elapsed, answer)) => {
                let expected = format!("answer-for-{offer_text}");
                if answer.answer != expected {
                    round_trip_ok = false;
                    round_trip_detail = format!(
                        "iteration {i}: got answer {:?} want {:?}",
                        answer.answer, expected
                    );
                }
                latencies.push(elapsed);
                last_state = Some(state);
            }
            Err(e) => {
                round_trip_ok = false;
                round_trip_detail = format!("iteration {i} errored: {e:#}");
                break;
            }
        }
    }
    checks.record(
        "a_connect_handshake_round_trip",
        round_trip_ok,
        if round_trip_ok {
            format!(
                "{} handshakes, every decrypted answer matched the host's expected value",
                latencies.len()
            )
        } else {
            round_trip_detail
        },
    );

    latencies.sort();
    if !latencies.is_empty() {
        let n = latencies.len();
        let median = if n.is_multiple_of(2) {
            (latencies[n / 2 - 1] + latencies[n / 2]) / 2
        } else {
            latencies[n / 2]
        };
        let max = *latencies.last().unwrap();
        println!(
            "\n== SIGNALING-HALF LATENCY (loopback, no ICE, no QUIC -- NOT the S2 bar) ==\n  n={n} median={:.2}ms max={:.2}ms\n",
            median.as_secs_f64() * 1000.0,
            max.as_secs_f64() * 1000.0
        );
    }

    // ============================================================================================
    // Check 2: `_INBOX` reply-prefix validation (negative case; the positive case is already
    // proven by every one of check 1's 20 successful round trips).
    // ============================================================================================
    {
        let sid = fresh_sid();
        let eph_c = EphemeralKey::generate();
        let dev_dh = device_a.device.diffie_hellman(&host_device_agree_pk);
        let eph_dh_offer = eph_c.diffie_hellman(&host_device_agree_pk);
        let session_key_offer = derive_session_key(
            &eph_dh_offer,
            &dev_dh,
            &sid,
            &device_a.device_fp,
            &host_device_fp,
        );
        let offer_payload = OfferPayload {
            offer: "offer-bad-reply".to_string(),
            inbox: format!("_INBOX_{}", device_a.device_fp),
        };
        let offer_env = seal_payload(
            SealPayloadParams {
                session_key: &session_key_offer,
                signer: &device_a.device,
                v: V1,
                alg_id: ALG_ID_V1,
                from_fp: device_a.device_fp,
                to_fp: host_device_fp,
                sid: sid.clone(),
                kind: KIND_OFFER,
                seq: 0,
                ts: now(),
                eph_pk: Some(eph_c.public_bytes()),
            },
            &offer_payload,
        );

        let bogus_reply = "_INBOX_not-the-real-device-fp.deadbeef".to_string();
        client_a
            .publish_with_reply(
                format!("host.{host_fp}.connect"),
                bogus_reply.clone(),
                offer_env.to_canonical_bytes().into(),
            )
            .await?;
        client_a.flush().await?;

        let dropped = wait_for_host_event(
            &host_state.events,
            |e| matches!(e, HostEvent::ConnectDroppedBadReplyPrefix { .. }),
            1500,
        )
        .await;
        checks.record(
            "b_inbox_reply_prefix_validation",
            dropped.is_some(),
            format!(
                "bogus reply={bogus_reply:?} host event={dropped:?} (positive case already \
                 proven by all 20 check-1 round trips)"
            ),
        );
    }

    // ============================================================================================
    // Check 3: trickle-ICE subject round trip, using the last established session.
    // ============================================================================================
    let mut session = last_state.expect("at least one check-1 handshake must have succeeded");
    {
        let sid_tok = sid_token(&session.sid);
        let c2h_subject = format!("host.{host_fp}.sess.{}.{sid_tok}.c2h", session.own_fp);
        let h2c_subject = format!("host.{host_fp}.sess.{}.{sid_tok}.h2c", session.own_fp);
        let mut h2c_sub = client_a.subscribe(h2c_subject.clone()).await?;
        client_a.flush().await?;
        tokio::time::sleep(Duration::from_millis(150)).await;

        let seq = session.next_seq_c2h;
        session.next_seq_c2h += 1;
        let candidate = "candidate:1 1 UDP 2130706431 203.0.113.1 54321 typ host".to_string();
        let ice_env = seal_payload(
            SealPayloadParams {
                session_key: &session.session_key,
                signer: &device_a.device,
                v: V1,
                alg_id: ALG_ID_V1,
                from_fp: session.own_fp,
                to_fp: session.peer_fp,
                sid: session.sid.clone(),
                kind: KIND_ICE,
                seq,
                ts: now(),
                eph_pk: None,
            },
            &IcePayload {
                candidate: candidate.clone(),
            },
        );
        client_a
            .publish(c2h_subject.clone(), ice_env.to_canonical_bytes().into())
            .await?;
        client_a.flush().await?;

        let host_accepted = wait_for_host_event(
            &host_state.events,
            |e| matches!(e, HostEvent::IceAccepted { seq: s } if *s == seq),
            2000,
        )
        .await;

        let h2c_msg = timeout(Duration::from_secs(2), h2c_sub.next())
            .await
            .ok()
            .flatten();
        let h2c_ok = match &h2c_msg {
            Some(msg) => match Envelope::from_canonical_bytes(&msg.payload) {
                Ok(env) => {
                    let open_params = OpenParams {
                        session_key: &session.session_key,
                        pinned_sender_key: &host_device_sign_pk,
                        self_fp: &session.own_fp,
                        expected_sid: &session.sid,
                        bound_from_fp: Some(&session.peer_fp),
                        min_seq_exclusive: session.min_seq_h2c,
                        now: now(),
                        min_v: V1,
                        min_alg_id: ALG_ID_V1,
                        expected_kind: KIND_ICE,
                        sender_revoked: false,
                    };
                    match open_payload::<IcePayload>(open_params, &env) {
                        Ok(p) => {
                            session.min_seq_h2c = Some(env.seq);
                            p.candidate == format!("host-echo-of:{candidate}")
                        }
                        Err(_) => false,
                    }
                }
                Err(_) => false,
            },
            None => false,
        };

        checks.record(
            "c_trickle_ice_subject_round_trip",
            host_accepted.is_some() && h2c_ok,
            format!("c2h seq={seq} host_event={host_accepted:?} h2c_verified={h2c_ok}"),
        );
    }

    // ============================================================================================
    // Check 4: no-responders is instant (connect to host2, which has no live subscriber).
    // ============================================================================================
    {
        let sid = fresh_sid();
        let eph_c = EphemeralKey::generate();
        let dev_dh = device_a.device.diffie_hellman(&host_device_agree_pk);
        let eph_dh = eph_c.diffie_hellman(&host_device_agree_pk);
        let session_key =
            derive_session_key(&eph_dh, &dev_dh, &sid, &device_a.device_fp, &host_device_fp);
        let offer_env = seal_payload(
            SealPayloadParams {
                session_key: &session_key,
                signer: &device_a.device,
                v: V1,
                alg_id: ALG_ID_V1,
                from_fp: device_a.device_fp,
                to_fp: host_device_fp,
                sid,
                kind: KIND_OFFER,
                seq: 0,
                ts: now(),
                eph_pk: Some(eph_c.public_bytes()),
            },
            &OfferPayload {
                offer: "unreachable".to_string(),
                inbox: format!("_INBOX_{}", device_a.device_fp),
            },
        );

        let t0 = Instant::now();
        let result = client_a
            .request(
                format!("host.{host2_fp}.connect"),
                offer_env.to_canonical_bytes().into(),
            )
            .await;
        let elapsed = t0.elapsed();
        let is_no_responders =
            matches!(&result, Err(e) if e.kind() == async_nats::RequestErrorKind::NoResponders);
        checks.record(
            "d_no_responders_is_instant",
            is_no_responders && elapsed < Duration::from_secs(1),
            format!(
                "elapsed={:.1}ms is_no_responders={is_no_responders} result={result:?}",
                elapsed.as_secs_f64() * 1000.0
            ),
        );
    }

    // ============================================================================================
    // Check 5: scoping refusal -- device_a cannot reach another session's c2h subject.
    // ============================================================================================
    {
        let foreign_device_fp = Fingerprint::of_parts(&[b"spike-s2-signaling:foreign-device"]);
        let foreign_sid = sid_token(&fresh_sid());
        let foreign_subject = format!("host.{host_fp}.sess.{foreign_device_fp}.{foreign_sid}.c2h");
        client_a
            .publish(foreign_subject.clone(), b"not mine".to_vec().into())
            .await?;
        client_a.flush().await?;
        let violated = wait_for_violation(
            &events_a,
            &["Permissions Violation for Publish", &foreign_subject],
            1500,
        )
        .await;
        checks.record(
            "e_scoping_refusal_cross_session_publish_denied",
            violated,
            format!("subject={foreign_subject} violation_seen={violated}"),
        );
    }

    // ============================================================================================
    // Check 6 (OBSERVATION, not a pass/fail against a spec bar): seq reordering vs. retry.
    // ============================================================================================
    {
        let sid_tok = sid_token(&session.sid);
        let c2h_subject = format!("host.{host_fp}.sess.{}.{sid_tok}.c2h", session.own_fp);

        let base = session.next_seq_c2h; // continues after check 3's seq
        let seq_ahead = base + 1; // deliberately skips `base`
        let seq_reordered = base; // arrives "late": lower than seq_ahead, never seen before
        let seq_retry = seq_ahead; // exact duplicate of the first send

        let send = |seq: u64, candidate: &str| {
            seal_payload(
                SealPayloadParams {
                    session_key: &session.session_key,
                    signer: &device_a.device,
                    v: V1,
                    alg_id: ALG_ID_V1,
                    from_fp: session.own_fp,
                    to_fp: session.peer_fp,
                    sid: session.sid.clone(),
                    kind: KIND_ICE,
                    seq,
                    ts: now(),
                    eph_pk: None,
                },
                &IcePayload {
                    candidate: candidate.to_string(),
                },
            )
        };

        let env1 = send(seq_ahead, "candidate:2 skip-ahead");
        client_a
            .publish(c2h_subject.clone(), env1.to_canonical_bytes().into())
            .await?;
        client_a.flush().await?;
        let ev1 = wait_for_host_event(
            &host_state.events,
            |e| {
                matches!(e, HostEvent::IceAccepted { seq } if *seq == seq_ahead)
                    || matches!(e, HostEvent::IceDroppedEnvelopeError { seq, .. } if *seq == seq_ahead)
            },
            1500,
        )
        .await;

        let env2 = send(seq_reordered, "candidate:1 reordered-late-arrival");
        client_a
            .publish(c2h_subject.clone(), env2.to_canonical_bytes().into())
            .await?;
        client_a.flush().await?;
        let ev2 = wait_for_host_event(
            &host_state.events,
            |e| {
                matches!(e, HostEvent::IceAccepted { seq } if *seq == seq_reordered)
                    || matches!(e, HostEvent::IceDroppedEnvelopeError { seq, .. } if *seq == seq_reordered)
            },
            1500,
        )
        .await;

        let env3 = send(seq_retry, "candidate:2 skip-ahead");
        client_a
            .publish(c2h_subject.clone(), env3.to_canonical_bytes().into())
            .await?;
        client_a.flush().await?;
        // seq_retry == seq_ahead, so both sends share a predicate; poll long enough for a NEW
        // event (index-based would be neater, but the log is append-only and small -- distinguish
        // by re-checking the log length grew past `ev1`'s position instead).
        let ev3 = {
            let before_len = host_state.events.lock().unwrap().len();
            let deadline = Instant::now() + Duration::from_millis(1500);
            loop {
                {
                    let log = host_state.events.lock().unwrap();
                    if let Some(e) = log.iter().skip(before_len).find(|e| {
                        matches!(e, HostEvent::IceAccepted { seq } if *seq == seq_retry)
                            || matches!(e, HostEvent::IceDroppedEnvelopeError { seq, .. } if *seq == seq_retry)
                    }) {
                        break Some(e.clone());
                    }
                }
                if Instant::now() >= deadline {
                    break None;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        session.next_seq_c2h = seq_retry + 1;

        println!("\n== CHECK 6 OBSERVATION: seq reordering vs. retry (DESIGN.md §A7 vs. §A6) ==");
        println!("  seq={seq_ahead} (sent first, skips ahead)              -> {ev1:?}");
        println!("  seq={seq_reordered} (sent second, arrives \"late\")       -> {ev2:?}");
        println!("  seq={seq_retry} (sent third, exact retry of the first) -> {ev3:?}");

        let captured = ev1.is_some() && ev2.is_some() && ev3.is_some();
        checks.record(
            "f_seq_reordering_observation",
            captured,
            if captured {
                format!(
                    "ahead={ev1:?} reordered={ev2:?} retry={ev3:?} -- see RESULTS.md for the finding"
                )
            } else {
                "could not capture a clean host-side event for every send -- observation \
                 inconclusive"
                    .to_string()
            },
        );
    }

    print_summary(&checks);
    if checks.all_passed() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}
