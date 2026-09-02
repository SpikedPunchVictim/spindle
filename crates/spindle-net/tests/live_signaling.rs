//! Live end-to-end integration test for [`spindle_net::signaling`], and for DESIGN.md §A4's
//! revoke -> kick -> reject chain, against the composed stack (`deploy/docker-compose.yml`'s
//! `nats` + `postgres` + `helper` + `coturn`).
//!
//! # Why this file exists
//!
//! `spikes/s2-signaling` proved the DESIGN.md §A6/§A7 *flow* works against a real NATS Auth
//! Callout deployment. It did not prove the **graduated** `spindle-net::signaling` code works:
//! every unit test in `crates/spindle-net/src/signaling/**` runs in-process with no NATS server,
//! no ICE punch, and no QUIC handshake. Subject strings, permission scoping, envelope field
//! wiring and the ICE/QUIC handoff can all drift silently during graduation, and none of the
//! existing tests would notice. This test drives the real public API —
//! [`spindle_net::signaling::SignalingHost`] and [`spindle_net::signaling::SignalingClient`] —
//! over two genuinely callout-authenticated NATS connections, and round-trips real bytes over the
//! resulting QUIC control stream.
//!
//! # Gating
//!
//! Both live tests are `#[ignore]`d, so `cargo test --workspace` reports them as `ignored` rather
//! than running them. They are **not** the "silently no-op when an env var is unset" shape: when
//! run, an unreachable stack is a hard failure with a message naming what to start, never a skip.
//! A test that passes without running is the exact false-green this repo has already been bitten
//! by.
//!
//! Run with:
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml up -d
//! cargo test -p spindle-net --test live_signaling -- --ignored --nocapture
//! ```
//!
//! `NATS_URL` overrides the stack's TCP listener (default `nats://127.0.0.1:4222`).
//!
//! # Rebuild the helper image after any A7b wire-schema change
//!
//! The helper runs as a prebuilt container image, not as source the test stack recompiles on
//! each run. Any change to an A7b artifact's wire schema — a `DeviceCertificate`, a `Capability`,
//! a `HostOpKeyCert`, anything `spindle_proto::canonical` serializes — or to `spindle-helper`
//! itself requires rebuilding that image. Skip the rebuild and these tests fail as an
//! authentication error that looks entirely unrelated to the change that caused it:
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml build helper
//! docker compose -f deploy/docker-compose.yml up -d --no-deps helper
//! ```
//!
//! **The 2026-08-31 incident.** Every live test began failing at device CONNECT
//! (`connect_device`, the panic at the `.unwrap_or_else` on `.connect(url)`), before any
//! signaling code ran, with `authorization violation: nats: authorization violation`. The NATS
//! server log gave the real reason: `[WRN] Auth callout service returned an error: authentication
//! refused` — the helper was actively refusing the callout, not timing out or unreachable. Root
//! cause: the helper container image was still running a binary built before commit `03fc885`
//! (A10.34), which changed `DeviceCertificate`'s canonical-CBOR wire map from 5 to 8 fields
//! (signing input a4->a7, adding `alg_id`/`sign_pk`/`agree_pk`).
//! [`spindle_test_fixtures::fixtures`] builds the new 8-field certificate; the old helper binary
//! rejected it. Rebuilding the image (the two commands above) fixed both live tests. A red herring
//! worth naming so the next person skips it:
//! postgres was simultaneously degraded (a `DELETE FROM session_records` taking 17s, pool acquire
//! >16s). Restarting postgres and helper did **not** fix it — only rebuilding the image did.
//!
//! When device CONNECT fails, check which side of the callout the failure is on before touching
//! the fixtures:
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml logs nats | grep -i callout
//! ```
//!
//! That line distinguishes "helper refused the credentials" from "helper never answered" — which
//! is what tells you whether to suspect the fixtures or the stack.
//!
//! # The callout bootstrap recipe
//!
//! [`spindle_test_fixtures::fixtures`] rebuilds `spikes/s1-callout`'s `fixtures` module against
//! this workspace's real `spindle-core`/`spindle-proto` artifact types (that spike module is
//! spike-local and not a dependency of this crate). It — along with the live-stack connection
//! helpers (`connect_device`/`connect_host`/etc.) this file used to define locally — now lives in
//! the shared `spindle-test-fixtures` dev-only crate, graduated out of this file so
//! `spindle-hostd`'s own live test can reuse the identical bootstrap rather than carrying a
//! second, driftable copy; see that crate's docs for the full rationale. Per connection: a fresh
//! nkey session keypair, a root-signed device certificate binding `device_fp` to that session
//! key's `nats_fp`, a base64url canonical-CBOR `auth_token` carrying the root public key +
//! certificate + capabilities, and — for devices — a `custom_inbox_prefix` of `_INBOX_<device_fp>`
//! so the connection's request inboxes fall inside the `sub _INBOX_<own>.>` grant the callout
//! issues (and so the host's `_INBOX_<from_fp>.` reply-prefix check can pass).
//!
//! # What its first live run found
//!
//! Two defects, both invisible to every existing unit test and both fatal to the connect path:
//!
//! 1. **The host's two fingerprints had been collapsed into one.** A host has two identities that
//!    can never be equal: `host_fp` (`SHA-256(host_root_pk)`, an Ed25519-only root key) is what
//!    every §A5 NATS subject is scoped by and what `spindle_helper::permissions` grants on, while
//!    the host's envelope `device_fp` belongs to a [`DeviceKey`] whose X25519 half §A7's `k0`/`k1`
//!    derivation requires — a root key has no such half, so the split is structurally forced.
//!    `SignalingHost` had been subscribing on `host.<device_fp>.connect` and
//!    `client::HostIdentity` carried a single fingerprint used as both the subject token and the
//!    envelope `to_fp`. Live, that is `Permissions Violation for Subscription to
//!    "host.<device_fp>.connect"` on the host and `Permissions Violation for Publish` on the
//!    client — no offer ever reaches the host. `spikes/s2-signaling` had kept the two apart
//!    (`HostState { host_fp, host_device_fp, .. }`); graduation merged them.
//! 2. **`Agent::start_connectivity_checks` was never called.** Both peers read the other side's
//!    `ufrag`/`pwd` out of the offer/answer and then discarded them, so neither agent ever sent a
//!    single binding request. Every connect ended in `SignalingError::Timeout("ICE trickle")`.
//!
//! Both are fixed; this test is what keeps them fixed.
//!
//! # S9: the revoke -> kick -> reject chain
//!
//! `live_revocation_kicks_and_then_refuses_the_devices_reconnect_within_the_five_second_bar`
//! measures the whole of DESIGN.md §A4's chain against this same live stack: a host publishes a
//! `RevocationRecord` on `registry.revoke.<host_fp>` (t0), the composed helper ingests it
//! (`spindle_helper::revoke::ingest_revocation`), computes and issues a
//! `$SYS.REQ.SERVER.<id>.KICK` for the live session (`spindle_helper::kick`), and the revoked
//! device's own NATS connection is dropped with a `$SYS.ACCOUNT.*.DISCONNECT` advisory whose
//! `reason` is exactly `"Kicked"` (t_kick — anything else, notably `"Client Closed"`, is NOT a
//! kick; `spikes/s9-revoke-kick/RESULTS.md` was bitten by exactly that false green). Because a
//! kicked NATS client auto-reconnects on its own, a kick alone cuts nobody off: the test's real
//! assertion is that a brand-new connect attempt presenting the same now-revoked identity is
//! refused by the callout (t1), and that `t1 - t0 < 5s`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::StreamExt;
use spindle_core::artifacts::issue_revocation_record;
use spindle_core::identity::DeviceKey;
use spindle_core::{Fingerprint, SigningKey, VerifyingKey};
use spindle_net::framing::{read_frame, write_frame};
use spindle_net::quic::ControlStream;
use spindle_net::signaling::{
    ConnectAuthorizer, ConnectDecision, ConnectOptions, HostIdentity, HostOptions, SessionHandler,
    SignalingClient, SignalingHost,
};
use x25519_dalek::PublicKey as X25519PublicKey;

// The callout bootstrap fixtures (`fixtures::*`), the live-stack connection helpers
// (`connect_device`/`connect_host`/`base_opts`/`nats_url`/`assert_stack_rejects_anonymous`/
// `assert_no_permission_violation`), and the small `$SYS`-advisory JSON parser (`tinyjson`) that
// used to live in this file were graduated into `spindle-test-fixtures`, a shared dev-only crate,
// so `spindle-hostd`'s own live test can reuse them verbatim instead of carrying a second,
// driftable copy. See that crate's docs for the full rationale (the 2026-08-31 incident this
// file's own module doc comment documents).
use spindle_test_fixtures::fixtures::{self, DeviceIdentity, HostRootIdentity};
use spindle_test_fixtures::tinyjson;
use spindle_test_fixtures::{
    assert_no_permission_violation, assert_stack_rejects_anonymous, base_opts, connect_device,
    connect_host, nats_url,
};

// =================================================================================================
// Injected traits under test
// =================================================================================================

/// The decision the authorizer made for one `from_fp`, recorded so the test can prove the
/// authorizer was consulted **on the live path** (and with which fingerprint), rather than
/// inferring it from a connect that merely failed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorizeCall {
    from_fp: Fingerprint,
    allowed: bool,
}

/// A `ConnectAuthorizer` backed by a fixed device registry — the shape a real
/// `spindle-host-core` member-registry lookup takes, minus the registry. Records every call.
struct RegistryAuthorizer {
    registry: HashMap<Fingerprint, (VerifyingKey, X25519PublicKey)>,
    calls: Arc<Mutex<Vec<AuthorizeCall>>>,
}

impl RegistryAuthorizer {
    fn new(devices: &[&DeviceIdentity]) -> (Self, Arc<Mutex<Vec<AuthorizeCall>>>) {
        let registry = devices
            .iter()
            .map(|d| {
                let key = d.device_key();
                (d.device_fp, (key.sign_public_key(), key.agree_public_key()))
            })
            .collect();
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                registry,
                calls: calls.clone(),
            },
            calls,
        )
    }
}

impl ConnectAuthorizer for RegistryAuthorizer {
    async fn authorize(&self, from_fp: &Fingerprint) -> ConnectDecision {
        let hit = self.registry.get(from_fp).copied();
        self.calls
            .lock()
            .expect("authorize call log mutex")
            .push(AuthorizeCall {
                from_fp: *from_fp,
                allowed: hit.is_some(),
            });
        match hit {
            Some((sign_pk, agree_pk)) => ConnectDecision::Allow { sign_pk, agree_pk },
            None => ConnectDecision::Deny,
        }
    }
}

/// A `SessionHandler` that echoes one length-prefixed frame back over the established control
/// stream, and counts how many sessions it ever handled. The count is the host-side proof that a
/// denied connect never reaches a session at all.
struct EchoHandler {
    sessions: Arc<AtomicUsize>,
    /// Every `peer_device_fp` this handler was handed, in order. The host-side proof that
    /// `spindle-net` passes the *authenticated* client identity through to the session layer —
    /// without this, a handler could only assume who it is serving.
    peers: Arc<Mutex<Vec<Fingerprint>>>,
}

impl SessionHandler for EchoHandler {
    async fn handle_session(
        &self,
        peer_device_fp: Fingerprint,
        mut control: ControlStream,
    ) -> ControlStream {
        self.sessions.fetch_add(1, Ordering::SeqCst);
        self.peers
            .lock()
            .expect("session peer log mutex")
            .push(peer_device_fp);
        match read_frame(&mut control.recv).await {
            Ok(Some(frame)) => {
                if let Err(error) = write_frame(&mut control.send, &frame).await {
                    eprintln!("[host] echo write failed: {error}");
                }
            }
            Ok(None) => eprintln!("[host] client closed the control stream before sending a frame"),
            Err(error) => eprintln!("[host] echo read failed: {error}"),
        }
        control
    }
}

// =================================================================================================
// Latency bookkeeping — the same four phases `spikes/s2-signaling`'s `s2-connect.rs` reported.
// =================================================================================================

struct RunLatencies {
    offer_to_answer_ms: f64,
    answer_to_selected_ms: f64,
    selected_to_quic_ms: f64,
    offer_to_stream_ms: f64,
}

fn median(values: &[f64]) -> f64 {
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN latencies"));
    let n = v.len();
    if n == 0 {
        return f64::NAN;
    }
    if n.is_multiple_of(2) {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    } else {
        v[n / 2]
    }
}

const N_RUNS: usize = 5;
const ICE_BIND_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

fn client_opts() -> ConnectOptions {
    ConnectOptions {
        // `ConnectOptions::default()` binds `0.0.0.0`, which makes the gathered host candidate
        // literally `0.0.0.0` — unusable. Loopback, matching the spike's own choice.
        bind_ip: ICE_BIND_IP,
        ice_timeout: Duration::from_secs(10),
        answer_timeout: Duration::from_secs(5),
    }
}

fn host_opts() -> HostOptions {
    HostOptions {
        bind_ip: ICE_BIND_IP,
        ice_timeout: Duration::from_secs(10),
        session_close_timeout: Duration::from_secs(5),
    }
}

// =================================================================================================
// The live tests
// =================================================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d` first, \
            then `cargo test -p spindle-net --test live_signaling -- --ignored --nocapture`. \
            When run, an unreachable stack fails loudly — this test never skips."]
async fn live_connect_round_trips_bytes_and_reports_latency() {
    let url = nats_url();
    assert_stack_rejects_anonymous(&url).await;

    let exp = fixtures::now() + 3600;

    // ---- identities ------------------------------------------------------------------------
    let host_root = HostRootIdentity::new([0xB1; 32], [0xB2; 32]);
    let host_device_seeds = ([0xB3u8; 32], [0xB4u8; 32]);
    let host_device = DeviceKey::from_seeds(host_device_seeds.0, host_device_seeds.1);
    let host_device_fp = host_device.device_fp();
    let host_device_sign_pk = host_device.sign_public_key();
    let host_device_agree_pk = host_device.agree_public_key();
    let client = DeviceIdentity::new([0xC1; 32], [0xC2; 32], [0xC3; 32]);
    let cap = host_root.member_capability(client.root_fp(), exp, vec![0xA1]);

    println!("[ids] host_fp={} (NATS subject scope)", host_root.host_fp);
    println!("[ids] host envelope device_fp={host_device_fp}");
    println!("[ids] client device_fp={}", client.device_fp);

    // ---- live, callout-authenticated NATS connections ----------------------------------------
    let (host_nats, host_events) = connect_host(&url, &host_root, exp).await;
    let (client_nats, client_events, _client_user_pk) =
        connect_device(&url, &client, &[cap], exp).await;

    // ---- the real SignalingHost --------------------------------------------------------------
    let (authorizer, authorize_calls) = RegistryAuthorizer::new(&[&client]);
    let sessions = Arc::new(AtomicUsize::new(0));
    let session_peers = Arc::new(Mutex::new(Vec::new()));
    let host = Arc::new(SignalingHost::new(
        host_nats,
        host_device,
        host_root.host_fp,
        authorizer,
        EchoHandler {
            sessions: sessions.clone(),
            peers: session_peers.clone(),
        },
    ));
    let host_task = tokio::spawn({
        let host = host.clone();
        async move { host.run(host_opts()).await }
    });
    // Let the host's connect subscription land server-side before the first offer.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_no_permission_violation(&host_events, "host");

    // ---- the real SignalingClient ------------------------------------------------------------
    let signaling_client = SignalingClient::new(client_nats, client.device_key());
    let host_identity = HostIdentity {
        host_fp: host_root.host_fp,
        device_fp: host_device_fp,
        sign_pk: host_device_sign_pk,
        agree_pk: host_device_agree_pk,
    };

    let mut runs: Vec<RunLatencies> = Vec::with_capacity(N_RUNS);
    println!("\n==== CONNECT RUNS (n={N_RUNS}) ====");
    for i in 0..N_RUNS {
        let (mut control, timings) = signaling_client
            .connect_timed(&host_identity, client_opts())
            .await
            .unwrap_or_else(|e| panic!("run {i}: SignalingClient::connect failed: {e}"));
        // `timings` starts at the offer publish, matching the spike's t0 (which deliberately
        // excludes this side's own ICE gathering and certificate generation); the first byte
        // round trip is measured on top of it, so (d) below is the spike's (d) exactly.
        let after_connect = Instant::now();

        // An established connection that never carried data proves less than one that did.
        let payload = format!("live-signaling-run-{i}").into_bytes();
        write_frame(&mut control.send, &payload)
            .await
            .unwrap_or_else(|e| panic!("run {i}: writing the control-stream frame failed: {e}"));
        let echoed = read_frame(&mut control.recv)
            .await
            .unwrap_or_else(|e| panic!("run {i}: reading the echoed frame failed: {e}"))
            .unwrap_or_else(|| panic!("run {i}: host closed the control stream without echoing"));
        assert_eq!(
            echoed, payload,
            "run {i}: the host echoed different bytes than the client wrote"
        );
        let offer_to_stream_ms =
            (timings.offer_to_quic_complete + after_connect.elapsed()).as_secs_f64() * 1000.0;

        control.connection.close(0u32.into(), b"done");
        drop(control);

        let r = RunLatencies {
            offer_to_answer_ms: timings.offer_to_answer.as_secs_f64() * 1000.0,
            answer_to_selected_ms: timings.answer_to_ice_selected.as_secs_f64() * 1000.0,
            selected_to_quic_ms: timings.ice_selected_to_quic.as_secs_f64() * 1000.0,
            offer_to_stream_ms,
        };
        println!(
            "run {i}: offer->answer={:.2}ms answer->selected={:.2}ms selected->quic={:.2}ms \
             offer->usable-stream={:.2}ms",
            r.offer_to_answer_ms,
            r.answer_to_selected_ms,
            r.selected_to_quic_ms,
            r.offer_to_stream_ms
        );
        runs.push(r);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let a: Vec<f64> = runs.iter().map(|r| r.offer_to_answer_ms).collect();
    let b: Vec<f64> = runs.iter().map(|r| r.answer_to_selected_ms).collect();
    let c: Vec<f64> = runs.iter().map(|r| r.selected_to_quic_ms).collect();
    let d: Vec<f64> = runs.iter().map(|r| r.offer_to_stream_ms).collect();
    println!("\n==== LATENCY SUMMARY (n={}) ====", runs.len());
    println!(
        "(a) offer publish -> answer received+verified: values={a:.2?} median={:.2}ms",
        median(&a)
    );
    println!(
        "(b) answer received -> ICE selected pair:      values={b:.2?} median={:.2}ms",
        median(&b)
    );
    println!(
        "(c) selected pair -> QUIC handshake complete:  values={c:.2?} median={:.2}ms",
        median(&c)
    );
    println!(
        "(d) TOTAL offer -> usable stream (bytes back): values={d:.2?} median={:.2}ms",
        median(&d)
    );

    // ---- evidence the live path really went through the code under test ----------------------
    assert_eq!(
        sessions.load(Ordering::SeqCst),
        N_RUNS,
        "the injected SessionHandler must have handled exactly one session per run"
    );
    let handled_peers = session_peers
        .lock()
        .expect("session peer log mutex")
        .clone();
    assert_eq!(
        handled_peers,
        vec![client.device_fp; N_RUNS],
        "every session must have been handed the real client device_fp as its authenticated peer \
         identity, got {handled_peers:?}"
    );
    let calls = authorize_calls
        .lock()
        .expect("authorize call log mutex")
        .clone();
    assert_eq!(
        calls.len(),
        N_RUNS,
        "the injected ConnectAuthorizer must have been consulted exactly once per connect offer, \
         got {calls:?}"
    );
    assert!(
        calls
            .iter()
            .all(|c| c.from_fp == client.device_fp && c.allowed),
        "every authorize call must name the real client device_fp and be allowed, got {calls:?}"
    );

    assert_no_permission_violation(&host_events, "host");
    assert_no_permission_violation(&client_events, "client");

    host_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d` first, \
            then `cargo test -p spindle-net --test live_signaling -- --ignored --nocapture`. \
            When run, an unreachable stack fails loudly — this test never skips."]
async fn live_connect_denied_by_the_authorizer_never_reaches_a_session() {
    let url = nats_url();
    let exp = fixtures::now() + 3600;

    // A *different* host identity from the happy-path test, so the two can run concurrently
    // without sharing `host.<hfp>.connect`.
    let host_root = HostRootIdentity::new([0xD1; 32], [0xD2; 32]);
    let host_device = DeviceKey::from_seeds([0xD3; 32], [0xD4; 32]);
    let host_device_fp = host_device.device_fp();
    let host_device_sign_pk = host_device.sign_public_key();
    let host_device_agree_pk = host_device.agree_public_key();

    // Two real member devices. Both hold a member capability for this host (so both are
    // NATS-permitted to publish on `host.<h>.connect`); only `allowed` is in the host's registry.
    let allowed = DeviceIdentity::new([0xE1; 32], [0xE2; 32], [0xE3; 32]);
    let denied = DeviceIdentity::new([0xF1; 32], [0xF2; 32], [0xF3; 32]);
    let cap_allowed = host_root.member_capability(allowed.root_fp(), exp, vec![0xB1]);
    let cap_denied = host_root.member_capability(denied.root_fp(), exp, vec![0xB2]);

    let (host_nats, host_events) = connect_host(&url, &host_root, exp).await;
    let (allowed_nats, _allowed_events, _allowed_user_pk) =
        connect_device(&url, &allowed, &[cap_allowed], exp).await;
    let (denied_nats, denied_events, _denied_user_pk) =
        connect_device(&url, &denied, &[cap_denied], exp).await;

    let (authorizer, authorize_calls) = RegistryAuthorizer::new(&[&allowed]);
    let sessions = Arc::new(AtomicUsize::new(0));
    let session_peers = Arc::new(Mutex::new(Vec::new()));
    let host = Arc::new(SignalingHost::new(
        host_nats,
        host_device,
        host_root.host_fp,
        authorizer,
        EchoHandler {
            sessions: sessions.clone(),
            peers: session_peers.clone(),
        },
    ));
    let host_task = tokio::spawn({
        let host = host.clone();
        async move { host.run(host_opts()).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let host_identity = HostIdentity {
        host_fp: host_root.host_fp,
        device_fp: host_device_fp,
        sign_pk: host_device_sign_pk,
        agree_pk: host_device_agree_pk,
    };

    // ---- control: the allowed device connects, proving the host is live and reachable ---------
    let allowed_client = SignalingClient::new(allowed_nats, allowed.device_key());
    let (mut control, _) = allowed_client
        .connect_timed(&host_identity, client_opts())
        .await
        .expect("the registered device must connect (control for the negative case below)");
    write_frame(&mut control.send, b"control")
        .await
        .expect("control frame write");
    assert_eq!(
        read_frame(&mut control.recv)
            .await
            .expect("control frame read")
            .expect("control frame present"),
        b"control".to_vec(),
        "control run must round-trip bytes"
    );
    control.connection.close(0u32.into(), b"done");
    drop(control);
    assert_eq!(
        sessions.load(Ordering::SeqCst),
        1,
        "control run established one session"
    );

    // ---- the negative case --------------------------------------------------------------------
    let denied_client = SignalingClient::new(denied_nats, denied.device_key());
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        denied_client.connect_timed(&host_identity, client_opts()),
    )
    .await;

    match result {
        Ok(Ok(_)) => panic!(
            "a device the ConnectAuthorizer denies established a session — false green. \
             The authorizer is not being consulted on the live path."
        ),
        Ok(Err(e)) => println!(
            "[denied] SignalingClient::connect failed after {:.0}ms: {e}",
            started.elapsed().as_secs_f64() * 1000.0
        ),
        Err(_) => println!(
            "[denied] SignalingClient::connect did not complete within 15s (the client-visible \
             shape of DESIGN.md §A5's uniform silent drop)"
        ),
    }

    // The client cannot distinguish "denied" from "host offline" by design (§A5 uniform silent
    // drop: the host sends no reply at all). The denial itself is therefore proved host-side:
    // the authorizer was consulted with the denied device's real `device_fp` and answered Deny,
    // and no second session was ever handed to the SessionHandler.
    let calls = authorize_calls
        .lock()
        .expect("authorize call log mutex")
        .clone();
    println!("[denied] authorizer call log: {calls:?}");
    assert!(
        calls
            .iter()
            .any(|c| c.from_fp == denied.device_fp && !c.allowed),
        "the ConnectAuthorizer must have been consulted with the denied device's device_fp ({}) \
         and returned Deny — got {calls:?}. Without this the connect failure could be a timeout \
         from any cause, which would prove nothing.",
        denied.device_fp
    );
    assert!(
        calls
            .iter()
            .any(|c| c.from_fp == allowed.device_fp && c.allowed),
        "sanity: the control run's allow decision must also be in the log, got {calls:?}"
    );

    assert_eq!(
        sessions.load(Ordering::SeqCst),
        1,
        "the denied connect must not have reached the SessionHandler — only the control run's \
         session may be counted"
    );

    let handled_peers = session_peers
        .lock()
        .expect("session peer log mutex")
        .clone();
    assert_eq!(
        handled_peers,
        vec![allowed.device_fp],
        "the session layer must have been handed exactly one peer identity — the control run's \
         allowed device — and never the denied device's ({}), got {handled_peers:?}",
        denied.device_fp
    );

    assert_no_permission_violation(&host_events, "host");
    assert_no_permission_violation(&denied_events, "denied client");

    host_task.abort();
}

/// Dev-only throwaway SYS-account nkey seed, copied verbatim from
/// `spikes/s9-revoke-kick/src/main.rs`'s `SYS_CONN_SEED` (itself lifted from
/// `deploy/docker-compose.yml`'s `helper.environment.SYS_CONN_SEED` — the same seed the composed
/// helper container uses for its own `sys_client`). Genuine SYS-account membership is required to
/// receive `$SYS.ACCOUNT.*.DISCONNECT` advisories at all (`spikes/s5-presence`'s finding, repeated
/// in `spikes/s9-revoke-kick/RESULTS.md`'s header comment) — the `AUTH`-account `CALLOUT_USER`
/// this file's other fixtures bootstrap through is not sufficient. Never used outside this local
/// stack.
const SYS_CONN_SEED: &str = "SUAJNND3A4EBPOPMXASJCSIAPEFJROE7JFVDDZMLN2WEP3OPTNQSLMBO6A";

/// Extra fresh-reconnect attempts made *after* the first observed refusal, before trusting that
/// refusal as durable rather than a one-off blip. See
/// [`assert_revoked_device_cannot_reconnect`]'s doc comment.
const RECONNECT_CONFIRMATION_ATTEMPTS: usize = 4;
const RECONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(150);

/// Attempts a brand-new device CONNECT presenting the SAME (now revoked) identity — a fresh
/// session nkey each try, exactly the wire-level shape of `async-nats`'s own automatic reconnect,
/// made explicit and observable rather than left to run in the background — until either a
/// refusal is confirmed durable (1 initial refusal + `RECONNECT_CONFIRMATION_ATTEMPTS` more), or
/// `deadline` passes.
///
/// Only `ConnectErrorKind::AuthorizationViolation` counts as a refusal. Any other connect error
/// (`TimedOut`, `Io`, `Dns`, ...) is an immediate, loud panic: it means the NATS stack itself is
/// unreachable or misconfigured, which proves NOTHING about whether the revoked device is
/// refused, and must be reported as an inconclusive run rather than silently counted as a pass.
///
/// Returns the [`Instant`] the refusal was **first** observed (t1) — not the instant the last
/// confirmation attempt finished, so extra confirmation attempts add confidence without inflating
/// the measured timing. The only way this function returns normally is reaching
/// `RECONNECT_CONFIRMATION_ATTEMPTS` confirmations before `deadline`; hitting `deadline` first —
/// whether zero or only some confirmations were observed — is always a loud panic, never a quiet
/// pass.
///
/// **Any attempt that connects successfully is an immediate, loud panic — never a retry.** The
/// entire point of this helper is to prove the revoked identity genuinely cannot get back onto
/// NATS; a single success anywhere in this loop falsifies that outright, regardless of how many
/// earlier attempts were refused (DESIGN.md §A4's actual security property is "revoked stays
/// revoked", not "revoked is refused most of the time").
async fn assert_revoked_device_cannot_reconnect(
    url: &str,
    device: &DeviceIdentity,
    caps: &[spindle_proto::artifacts::Capability],
    exp: u64,
    deadline: Instant,
) -> Instant {
    let mut first_refusal: Option<Instant> = None;
    let mut confirmations = 0usize;
    let mut attempt = 0usize;
    loop {
        if let Some(t1) = first_refusal {
            if confirmations >= RECONNECT_CONFIRMATION_ATTEMPTS {
                return t1;
            }
        }
        if Instant::now() >= deadline {
            match first_refusal {
                None => panic!(
                    "the revoked device's fresh reconnect attempts (all {attempt} of them) never \
                     received a single authorization refusal before the bound expired — the \
                     revoked device was never conclusively cut off from NATS. FAILURE, not a \
                     pass."
                ),
                Some(_) => panic!(
                    "the revoked device was refused at least once, but only {confirmations} of \
                     the required {RECONNECT_CONFIRMATION_ATTEMPTS} confirmation attempts \
                     completed before the bound expired — the refusal was never conclusively \
                     confirmed as durable/repeatable. FAILURE, not a pass."
                ),
            }
        }
        attempt += 1;

        // Deliberately NOT `connect_device`: that helper panics on a connect error, which is
        // exactly the outcome this loop expects and must NOT treat as fatal. A fresh session nkey
        // every attempt matches what a real auto-reconnect does (a new TCP connection, same
        // credentials) and sidesteps any server-side nkey-reuse throttling that isn't the concern
        // under test here.
        let session = nkeys::KeyPair::new_user();
        let nats_fp = fixtures::nats_fp_of_nkey(&session.public_key());
        let cert = device.certificate(nats_fp, fixtures::now(), exp);
        let token = fixtures::device_auth_token(&device.root.public_key().to_bytes(), &cert, caps);
        let (opts, _events) = base_opts();
        let result = opts
            .nkey(session.seed().expect("session nkey seed"))
            .token(token)
            .custom_inbox_prefix(format!("_INBOX_{}", device.device_fp))
            .connect(url)
            .await;

        match result {
            Ok(client) => {
                drop(client);
                panic!(
                    "attempt #{attempt}: a FRESH connection using the revoked device's identity \
                     SUCCEEDED. The device was NOT cut off — this is the security property under \
                     test failing, and must be reported as a genuine finding, not papered over by \
                     weakening this assertion."
                );
            }
            Err(e) => match e.kind() {
                async_nats::ConnectErrorKind::AuthorizationViolation => {
                    println!(
                        "[reconnect] attempt #{attempt}: fresh connect correctly refused: {e}"
                    );
                    match first_refusal {
                        None => first_refusal = Some(Instant::now()),
                        Some(_) => confirmations += 1,
                    }
                    tokio::time::sleep(RECONNECT_RETRY_INTERVAL).await;
                }
                kind => {
                    panic!(
                        "attempt #{attempt}: fresh connect failed with a non-authorization error \
                         (kind={kind}, full error: {e}) — a timeout, IO, or DNS failure means the \
                         NATS stack itself is unreachable or misconfigured, which proves NOTHING \
                         about whether the revoked device is actually refused. This must be \
                         reported as an inconclusive run, not counted as a pass."
                    );
                }
            },
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d` first, \
            then `cargo test -p spindle-net --test live_signaling -- --ignored --nocapture`. \
            When run, an unreachable stack fails loudly — this test never skips."]
async fn live_revocation_kicks_and_then_refuses_the_devices_reconnect_within_the_five_second_bar() {
    let url = nats_url();

    // ---- SYS-account connection: subscribe to DISCONNECT advisories BEFORE anything else, so no
    // kick evidence can possibly be missed (the same ordering discipline
    // `spikes/s9-revoke-kick/src/main.rs` uses). ------------------------------------------------
    let sys_client = async_nats::ConnectOptions::new()
        .nkey(SYS_CONN_SEED.to_string())
        .connect(&url)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "SYS-account CONNECT to the live stack at {url} failed: {e}\n\
                 This test requires `docker compose -f deploy/docker-compose.yml up -d` \
                 (nats + postgres + helper) — the helper container is configured with the \
                 identical SYS_CONN_SEED. It never skips."
            )
        });
    let mut disconnect_sub = sys_client
        .subscribe("$SYS.ACCOUNT.*.DISCONNECT")
        .await
        .expect("subscribing to $SYS.ACCOUNT.*.DISCONNECT");

    let exp = fixtures::now() + 3600;

    // ---- per-run identity material --------------------------------------------------------------
    // Unlike this file's other two live tests, this one PUBLISHES A REVOCATION, and
    // `spindle_helper::revoke::ingest_revocation` persists it DURABLY in Postgres (`revoked_subjects`,
    // plus a bumped `revocation_epochs` row), keyed by the device's `root_fp` under the host's
    // `host_fp`. A fixed seed here — as the other two live tests correctly use, since they never
    // revoke anything — would make THIS test single-use: its first run revokes that `root_fp`
    // forever, and every later run's very first `connect_device(...)` call fails at that
    // permanently-revoked identity's *initial* CONNECT, with a generic "stack unreachable" panic
    // that looks nothing like what actually happened. Deriving both the host's and the device's
    // identities fresh each run — from one throwaway nkey keypair, domain-separated per seed so the
    // five derived 32-byte seeds are independent — keeps this test repeatable against the same live
    // database. `nkeys` is already a dev-dependency used elsewhere in this file; no new dependency.
    let identity_entropy = nkeys::KeyPair::new_user().public_key().into_bytes();
    let seed_for = |domain: &[u8]| -> [u8; 32] {
        *Fingerprint::of_parts(&[domain, &identity_entropy]).as_bytes()
    };

    // ---- host + device identities, and a member capability binding the device to the host ------
    let host_root = HostRootIdentity::new(
        seed_for(b"spindle-net:live_signaling:revocation-test:host-root-seed"),
        seed_for(b"spindle-net:live_signaling:revocation-test:host-op-seed"),
    );
    let device = DeviceIdentity::new(
        seed_for(b"spindle-net:live_signaling:revocation-test:device-root-seed"),
        seed_for(b"spindle-net:live_signaling:revocation-test:device-sign-seed"),
        seed_for(b"spindle-net:live_signaling:revocation-test:device-agree-seed"),
    );
    let cap = host_root.member_capability(device.root_fp(), exp, vec![0xC1]);
    let caps = vec![cap];

    println!(
        "[ids] host_fp={} (revocation subject scope)",
        host_root.host_fp
    );
    println!(
        "[ids] device root_fp={} (revocation target)",
        device.root_fp()
    );

    // ---- live, callout-authenticated NATS connections --------------------------------------------
    let (host_nats, host_events) = connect_host(&url, &host_root, exp).await;
    let (device_nats, device_events, device_user_pk) =
        connect_device(&url, &device, &caps, exp).await;
    assert_no_permission_violation(&host_events, "host");
    assert_no_permission_violation(&device_events, "device");

    // ---- sanity: the device connection is genuinely live, not just "connect() returned Ok" -----
    // A round-tripped request on a subject the device's own callout-issued permissions grant
    // (`client_member_permissions`'s `pub helper.presence.get.<own_nats_fp>`) proves the
    // connection can both publish and receive a reply through its own inbox grant right now. A
    // device that was never actually live cannot prove anything about being cut off later.
    let device_nats_fp = fixtures::nats_fp_of_nkey(&device_user_pk);
    let presence_subject = format!("helper.presence.get.{device_nats_fp}");
    match tokio::time::timeout(
        Duration::from_secs(5),
        device_nats.request(presence_subject.clone(), Bytes::new()),
    )
    .await
    {
        Ok(Ok(reply)) => println!(
            "[sanity] device connection is live: {presence_subject} replied with {} bytes",
            reply.payload.len()
        ),
        Ok(Err(e)) => panic!(
            "sanity check failed: request on {presence_subject} errored: {e} — the device \
             connection does not appear to be genuinely live, so nothing this test observes \
             later about it being 'cut off' would mean anything."
        ),
        Err(_) => panic!(
            "sanity check failed: request on {presence_subject} timed out — the device \
             connection does not appear to be genuinely live, so nothing this test observes \
             later about it being 'cut off' would mean anything."
        ),
    }

    // ---- mint + publish the revocation record, naming the device's root_fp ----------------------
    // The signer is a throwaway key: `spindle_helper::revoke::ingest_revocation` never verifies
    // this signature (see that module's doc comment's "Identity check" section) — trust here comes
    // entirely from NATS subject scoping (`host_permissions` grants `pub
    // registry.revoke.<own_host_fp>` to the host connection alone), matching that module's own
    // test fixtures.
    let revocation_signer = SigningKey::from_bytes(&[0x16; 32]);
    let record = issue_revocation_record(
        &revocation_signer,
        host_root.host_fp,
        1, // epoch — irrelevant to whether the connect-time check refuses (see decide_device_connect)
        vec![device.root_fp()],
        fixtures::now(),
    );
    let record_bytes = record.to_canonical_bytes();
    let subject = format!("registry.revoke.{}", host_root.host_fp);

    let t0 = Instant::now();
    host_nats
        .publish(subject.clone(), record_bytes.into())
        .await
        .unwrap_or_else(|e| {
            panic!(
                "publishing the revocation record on {subject} failed: {e} — host_permissions \
                 grants `pub registry.revoke.<own_host_fp>`; a failure here means that grant has \
                 drifted from `permissions::host_permissions`."
            )
        });
    host_nats
        .flush()
        .await
        .expect("flush after publishing the revocation record");

    // ---- wait for the confirmed KICK: a DISCONNECT advisory for THIS device's connection whose
    // top-level `reason` is exactly "Kicked". Nothing else counts (see this file's module doc
    // comment's S9 section and spikes/s9-revoke-kick/RESULTS.md's false-green correction). --------
    let kick_deadline = t0 + Duration::from_secs(15);
    let mut seen_disconnects: Vec<String> = Vec::new();
    let t_kick = loop {
        let remaining = kick_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!(
                "no $SYS.ACCOUNT.*.DISCONNECT advisory with reason==\"Kicked\" for the device's \
                 connection (client.user={device_user_pk}) arrived within {:?} of the revocation \
                 publish. Advisories observed while waiting:\n{}",
                kick_deadline.saturating_duration_since(t0),
                if seen_disconnects.is_empty() {
                    "  (none)".to_string()
                } else {
                    seen_disconnects.join("\n")
                }
            );
        }
        let msg = match tokio::time::timeout(remaining, disconnect_sub.next()).await {
            Ok(Some(m)) => m,
            Ok(None) => panic!(
                "$SYS.ACCOUNT.*.DISCONNECT subscription ended unexpectedly while waiting for the \
                 kick"
            ),
            Err(_) => continue, // deadline re-checked at the top of the loop
        };
        let raw = String::from_utf8_lossy(&msg.payload).to_string();
        let Some(json) = tinyjson::parse(&raw) else {
            seen_disconnects.push(format!("[unparsable JSON, subject={}] {raw}", msg.subject));
            continue;
        };
        let user = json
            .get("client")
            .and_then(|c| c.get("user"))
            .and_then(|v| v.as_str());
        let reason = json.get("reason").and_then(|v| v.as_str());
        seen_disconnects.push(format!(
            "subject={} client.user={user:?} reason={reason:?} raw={raw}",
            msg.subject
        ));
        if user == Some(device_user_pk.as_str()) {
            if reason == Some("Kicked") {
                break Instant::now();
            }
            println!(
                "[kick-watch] a DISCONNECT for the device's OWN connection arrived but its \
                 reason was {reason:?}, not \"Kicked\" — per \
                 spikes/s9-revoke-kick/RESULTS.md this is NOT evidence of a kick; still waiting."
            );
        }
    };
    let t_kick_minus_t0_ms = t_kick.duration_since(t0).as_secs_f64() * 1000.0;
    println!("[timing] t_kick - t0 (revoke publish -> confirmed KICK) = {t_kick_minus_t0_ms:.1}ms");

    // ---- the real assertion: a brand-new connect for the same identity must be refused ---------
    // A kicked NATS client auto-reconnects on its own (spikes/s9-revoke-kick/RESULTS.md's own
    // "curiosity" section) — a kick alone cuts nobody off. This is the client's own reconnect,
    // made explicit and bounded rather than left to race in the background on `device_nats`.
    drop(device_nats); // stop the original connection's own background auto-reconnect from racing
                       // this explicit, observable stand-in for it.
    let reconnect_deadline = t0 + Duration::from_secs(15);
    let t1 =
        assert_revoked_device_cannot_reconnect(&url, &device, &caps, exp, reconnect_deadline).await;

    let t1_minus_t0_ms = t1.duration_since(t0).as_secs_f64() * 1000.0;
    println!("\n==== S9 REVOKE -> KICK -> REJECT TIMING ====");
    println!("t_kick - t0 (revoke publish -> confirmed KICK disconnect):        {t_kick_minus_t0_ms:.1}ms");
    println!(
        "t1     - t0 (revoke publish -> reconnect conclusively refused):   {t1_minus_t0_ms:.1}ms"
    );

    assert_no_permission_violation(&host_events, "host");

    assert!(
        t1.duration_since(t0) < Duration::from_secs(5),
        "DESIGN.md §A4's revoke -> kick -> reject bar (< 5s) was NOT met: t1 - t0 = \
         {t1_minus_t0_ms:.1}ms (t_kick - t0 was {t_kick_minus_t0_ms:.1}ms). This is a genuine \
         timing finding, not a test bug — do not weaken this assertion to make it pass."
    );
}
