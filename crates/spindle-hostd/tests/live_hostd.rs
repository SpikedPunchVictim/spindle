//! Live end-to-end integration test for [`spindle_hostd::HostDaemon`] against the composed stack
//! (`deploy/docker-compose.yml`'s `nats` + `postgres` + `helper` + `coturn`) — td-539ffa's
//! acceptance criterion: "A host binary constructs `HostConnectAuthorizer` over
//! `SqliteDeviceLookup` and serves the connect path with it; the live signaling test exercises the
//! production authorizer rather than `RegistryAuthorizer`."
//!
//! # What this proves that `crates/spindle-net/tests/live_signaling.rs` does not
//!
//! That file's two connect tests drive `spindle_net::signaling::{SignalingHost, SignalingClient}`
//! directly, injected with a test-local `RegistryAuthorizer` — a `HashMap` standing in for a real
//! device registry. That proves `spindle-net`'s signaling code itself works against a live NATS
//! Auth Callout deployment, but it proves nothing about `spindle-host-core`'s own
//! `HostConnectAuthorizer<SqliteDeviceLookup>` — the type that actually ships inside a real host
//! process (see `spindle_hostd::HostDaemon::run`'s assembly). A `HashMap` lookup and a
//! `rusqlite`-backed lookup through `spindle_vfs::store::Store::member_for_device_fp` are entirely
//! different code paths; a defect in the latter (a wrong query, a status check dropped, a key
//! rehash that never runs) would be invisible to every existing live test. This file drives
//! [`spindle_hostd::HostDaemon`] — the exact assembly `HostDaemon::run` builds: `HostConnectAuthorizer`
//! wrapping a `SqliteDeviceLookup` over a real, on-disk SQLite store, and `VfsSessionHandler`
//! wrapping a second `SqliteDeviceLookup` plus a `SqliteStoreFactory` over the same store file —
//! and proves both the allow and the deny path through that real store.
//!
//! Unlike `live_signaling.rs`, this file never drives a raw echo `SessionHandler`: the happy-path
//! test's core assertion is that a real VFS RPC `whoami` request, sent over the resulting QUIC
//! control stream, comes back naming the exact member row this test seeded — proof that
//! `HostConnectAuthorizer` allowed the connect, `VfsSessionHandler::session_context` resolved the
//! same device back to that member, and `serve_control_stream` served the request under that
//! `SessionContext`. A weaker assertion (bytes came back, no error) would pass even if the host
//! had silently served the wrong member.
//!
//! # Gating
//!
//! Both live tests are `#[ignore]`d, so `cargo test --workspace` reports them as `ignored` rather
//! than running them. They are **not** the "silently no-op when an env var is unset" shape: when
//! run, an unreachable stack is a hard failure with a message naming what to start, never a skip.
//! A test that passes without running is the exact false-green this repo has already been bitten
//! by (see `live_signaling.rs`'s own module doc comment for the incident that established this
//! rule).
//!
//! Run with:
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml up -d
//! cargo test -p spindle-hostd --test live_hostd -- --ignored --nocapture
//! ```
//!
//! `NATS_URL` overrides the stack's TCP listener (default `nats://127.0.0.1:4222`).
//!
//! # Rebuild the helper image after any A7b wire-schema change
//!
//! This warning applies here exactly as it does to `live_signaling.rs`, verbatim, because both
//! files bootstrap the identical NATS Auth Callout connections through the same
//! `spindle-test-fixtures` crate. The helper runs as a prebuilt container image, not as source the
//! test stack recompiles on each run. Any change to an A7b artifact's wire schema — a
//! `DeviceCertificate`, a `Capability`, a `HostOpKeyCert`, anything `spindle_proto::canonical`
//! serializes — or to `spindle-helper` itself requires rebuilding that image. Skip the rebuild and
//! these tests fail as an authentication error that looks entirely unrelated to the change that
//! caused it:
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml build helper
//! docker compose -f deploy/docker-compose.yml up -d --no-deps helper
//! ```
//!
//! **The 2026-08-31 incident** (recorded in full in `live_signaling.rs`'s module doc comment):
//! every live test began failing at device CONNECT with `authorization violation`, before any
//! signaling code ran, because the helper container was still running a binary built before
//! `DeviceCertificate`'s wire schema changed. Rebuilding the image fixed it; restarting containers
//! did not. When device CONNECT fails here, check
//! `docker compose -f deploy/docker-compose.yml logs nats | grep -i callout` before touching this
//! file's fixtures — that line distinguishes "helper refused the credentials" from "helper never
//! answered."

use std::net::IpAddr;
use std::time::{Duration, Instant};

use spindle_core::identity::DeviceKey;
use spindle_hostd::{HostDaemon, HostOptions};
use spindle_net::framing::{read_frame, write_frame};
use spindle_net::signaling::{ConnectOptions, HostIdentity, SignalingClient};
use spindle_proto::{VfsReply, VfsRequest, VfsRequestEnvelope};
use spindle_vfs::model::DevicePublicKeys;
use spindle_vfs::store::Store;

use spindle_test_fixtures::fixtures::{self, DeviceIdentity, HostRootIdentity};
use spindle_test_fixtures::{
    assert_no_permission_violation, connect_device, connect_host, nats_url,
};

const ICE_BIND_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

fn client_opts() -> ConnectOptions {
    ConnectOptions {
        // `ConnectOptions::default()` binds `0.0.0.0`, which makes the gathered host candidate
        // literally `0.0.0.0` — unusable. Loopback, matching `live_signaling.rs`'s own choice.
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

/// Sends a `whoami` request over `control` and returns the reply's `(member_display,
/// effective_paths)`, panicking with a descriptive message on any framing/decode failure or a
/// reply that is not `VfsReply::Whoami`. Shared by both this file's tests so the control run in
/// the second test and the sole request in the first go through byte-for-byte identical code.
async fn whoami(
    control: &mut spindle_net::quic::ControlStream,
    who: &str,
) -> (String, Vec<String>) {
    let request = VfsRequestEnvelope {
        v: spindle_proto::CURRENT_PROTOCOL_VERSION,
        request: VfsRequest::Whoami,
    };
    write_frame(&mut control.send, &request.to_canonical_bytes())
        .await
        .unwrap_or_else(|e| panic!("{who}: writing the whoami request frame failed: {e}"));
    let frame = read_frame(&mut control.recv)
        .await
        .unwrap_or_else(|e| panic!("{who}: reading the whoami reply frame failed: {e}"))
        .unwrap_or_else(|| panic!("{who}: host closed the control stream without replying"));
    match VfsReply::from_canonical_bytes(&frame)
        .unwrap_or_else(|e| panic!("{who}: decoding the whoami reply failed: {e}"))
    {
        VfsReply::Whoami {
            member_display,
            effective_paths,
        } => (member_display, effective_paths),
        other => panic!("{who}: expected VfsReply::Whoami, got {other:?}"),
    }
}

/// Seeds `store_path` with one active member and one enrolled, non-revoked device — real
/// `sign_pk`/`agree_pk` on file, exactly as `crate::authorize`'s own `enroll_device` test helper
/// does, so `HostConnectAuthorizer`'s check 8 (the `device_fp_of` binding rehash) holds. Returns
/// nothing: the caller already has every identity it needs (`device`'s fingerprint, the display
/// name it chose).
///
/// Runs entirely synchronously (no `.await` inside) and the `Store` handle is dropped when this
/// function returns, before `HostDaemon` ever opens its own connection to the same file. This is a
/// deliberate sequencing choice, not a correctness requirement this workspace enforces elsewhere:
/// `spindle_vfs::store::Store` wraps a plain `rusqlite::Connection` with no exclusive lock of its
/// own, and SQLite supports multiple connections to one database file — the same fact
/// `SqliteDeviceLookup`'s and `SqliteStoreFactory`'s own doc comments already lean on to justify
/// opening independent connections to a host's live store. Closing this one first simply avoids
/// any possibility of lock contention during the daemon's own startup, for free.
fn seed_active_member_with_device(
    store_path: &std::path::Path,
    device: &DeviceIdentity,
    display_name: &str,
) {
    let store = Store::open(store_path).expect("open a fresh SQLite store to seed");
    let member_id = store
        .add_member(device.root_fp(), display_name, fixtures::now())
        .expect("add_member");
    store.activate_member(member_id).expect("activate_member");
    let keys = device.device_key();
    store
        .add_device(
            member_id,
            device.device_fp,
            "test-device",
            fixtures::now(),
            Some(&DevicePublicKeys {
                sign_pk: keys.sign_public_key().as_bytes().to_vec(),
                agree_pk: keys.agree_public_key().as_bytes().to_vec(),
            }),
        )
        .expect("add_device");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d` first, \
            then `cargo test -p spindle-hostd --test live_hostd -- --ignored --nocapture`. \
            When run, an unreachable stack fails loudly — this test never skips."]
async fn live_connect_resolves_the_real_member_through_hostconnectauthorizer_and_sqlitedevicelookup(
) {
    let url = nats_url();
    let exp = fixtures::now() + 3600;

    const MEMBER_DISPLAY_NAME: &str = "Live HostDaemon Member";

    // ---- identities ---------------------------------------------------------------------------
    let host_root = HostRootIdentity::new([0x51; 32], [0x52; 32]);
    let host_device = DeviceKey::from_seeds([0x53; 32], [0x54; 32]);
    let host_device_fp = host_device.device_fp();
    let host_device_sign_pk = host_device.sign_public_key();
    let host_device_agree_pk = host_device.agree_public_key();
    let client = DeviceIdentity::new([0x55; 32], [0x56; 32], [0x57; 32]);
    let cap = host_root.member_capability(client.root_fp(), exp, vec![0xC1]);

    println!("[ids] host_fp={} (NATS subject scope)", host_root.host_fp);
    println!("[ids] host envelope device_fp={host_device_fp}");
    println!("[ids] client device_fp={}", client.device_fp);

    // ---- seed the real SQLite store the production authorizer will read -----------------------
    let store_dir = tempfile::tempdir().expect("tempdir for the host's SQLite store");
    let store_path = store_dir.path().join("host.db");
    seed_active_member_with_device(&store_path, &client, MEMBER_DISPLAY_NAME);

    // ---- live, callout-authenticated NATS connections ------------------------------------------
    let (host_nats, host_events) = connect_host(&url, &host_root, exp).await;
    let (client_nats, client_events, _client_user_pk) =
        connect_device(&url, &client, &[cap], exp).await;

    // ---- the real HostDaemon: HostConnectAuthorizer<SqliteDeviceLookup> over the seeded store,
    // wired to a real SignalingHost and driven with `run` — exactly `HostDaemon::run`'s own
    // assembly, not a hand-rolled stand-in for it. --------------------------------------------
    let daemon = HostDaemon::new(host_nats, host_device, host_root.host_fp, store_path);
    let host_task = tokio::spawn(daemon.run(host_opts()));
    // Let the host's connect subscription land server-side before the first offer.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_no_permission_violation(&host_events, "host");

    // ---- the real SignalingClient ---------------------------------------------------------------
    let signaling_client = SignalingClient::new(client_nats, client.device_key());
    let host_identity = HostIdentity {
        host_fp: host_root.host_fp,
        device_fp: host_device_fp,
        sign_pk: host_device_sign_pk,
        agree_pk: host_device_agree_pk,
    };
    let mut control = signaling_client
        .connect(&host_identity, client_opts())
        .await
        .unwrap_or_else(|e| panic!("SignalingClient::connect failed: {e}"));

    // ---- the real assertion: a real VFS RPC whoami request over the resulting QUIC control
    // stream must resolve to the exact member this test seeded. This can only be correct if
    // HostConnectAuthorizer allowed the connect, VfsSessionHandler::session_context resolved the
    // same peer device_fp to that member, and serve_control_stream served the request under that
    // SessionContext — see this file's module doc comment for why a weaker "bytes came back"
    // assertion would not prove any of that. --------------------------------------------------
    let (member_display, _effective_paths) = whoami(&mut control, "happy path").await;
    assert_eq!(
        member_display, MEMBER_DISPLAY_NAME,
        "the host must have resolved the connecting device's device_fp all the way to the seeded \
         member row via HostConnectAuthorizer -> SqliteDeviceLookup -> VfsSessionHandler -> \
         serve_control_stream; got a different member_display, which means the host served the \
         wrong identity (or an authorizer/lookup defect let the connect through without correctly \
         resolving it)"
    );

    control.connection.close(0u32.into(), b"done");
    drop(control);

    assert_no_permission_violation(&host_events, "host");
    assert_no_permission_violation(&client_events, "client");

    host_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d` first, \
            then `cargo test -p spindle-hostd --test live_hostd -- --ignored --nocapture`. \
            When run, an unreachable stack fails loudly — this test never skips."]
async fn live_connect_denied_when_the_production_authorizer_finds_the_device_revoked_in_sqlite() {
    let url = nats_url();
    let exp = fixtures::now() + 3600;

    const ALLOWED_DISPLAY_NAME: &str = "Allowed HostDaemon Member";
    const REVOKED_DISPLAY_NAME: &str = "Revoked HostDaemon Member";

    // A different host identity from the happy-path test, so the two can run concurrently without
    // sharing `host.<hfp>.connect`.
    let host_root = HostRootIdentity::new([0x61; 32], [0x62; 32]);
    let host_device = DeviceKey::from_seeds([0x63; 32], [0x64; 32]);
    let host_device_fp = host_device.device_fp();
    let host_device_sign_pk = host_device.sign_public_key();
    let host_device_agree_pk = host_device.agree_public_key();

    // Two real member devices, each its own member row. Both hold a valid member capability for
    // this host (so both are NATS-permitted to publish on `host.<h>.connect` — a NATS-level
    // permission violation on the revoked device would prove nothing about
    // HostConnectAuthorizer); only `allowed`'s device is left un-revoked in the store.
    let allowed = DeviceIdentity::new([0x65; 32], [0x66; 32], [0x67; 32]);
    let revoked = DeviceIdentity::new([0x68; 32], [0x69; 32], [0x6a; 32]);
    let cap_allowed = host_root.member_capability(allowed.root_fp(), exp, vec![0xD1]);
    let cap_revoked = host_root.member_capability(revoked.root_fp(), exp, vec![0xD2]);

    // ---- seed the real SQLite store: an active member with a live device, and a second active
    // member whose sole device is revoked (HostConnectAuthorizer's check 5 — a still-Active
    // member can have one revoked device, independent of its own status check). ----------------
    let store_dir = tempfile::tempdir().expect("tempdir for the host's SQLite store");
    let store_path = store_dir.path().join("host.db");
    seed_active_member_with_device(&store_path, &allowed, ALLOWED_DISPLAY_NAME);
    seed_active_member_with_device(&store_path, &revoked, REVOKED_DISPLAY_NAME);
    {
        let store = Store::open(&store_path).expect("re-open the seeded store to revoke a device");
        store
            .revoke_device(revoked.device_fp)
            .expect("revoke_device");
    }

    // ---- live, callout-authenticated NATS connections ------------------------------------------
    let (host_nats, host_events) = connect_host(&url, &host_root, exp).await;
    let (allowed_nats, _allowed_events, _allowed_user_pk) =
        connect_device(&url, &allowed, &[cap_allowed], exp).await;
    let (revoked_nats, revoked_events, _revoked_user_pk) =
        connect_device(&url, &revoked, &[cap_revoked], exp).await;

    let daemon = HostDaemon::new(host_nats, host_device, host_root.host_fp, store_path);
    let host_task = tokio::spawn(daemon.run(host_opts()));
    tokio::time::sleep(Duration::from_millis(300)).await;

    let host_identity = HostIdentity {
        host_fp: host_root.host_fp,
        device_fp: host_device_fp,
        sign_pk: host_device_sign_pk,
        agree_pk: host_device_agree_pk,
    };

    // ---- control: the allowed device connects and completes a real whoami round trip FIRST,
    // proving this exact host process, over this exact NATS connection, using this exact
    // ConnectOptions, is genuinely up and correctly authorizing right now. Without this, a stack
    // that is simply down (or a host that silently drops every connect) would make the denial
    // assertion below pass for entirely the wrong reason — this exact false-green shape ("no
    // session happened" passing vacuously) has already occurred once in this task's history. ----
    let allowed_client = SignalingClient::new(allowed_nats, allowed.device_key());
    let mut control = allowed_client
        .connect(&host_identity, client_opts())
        .await
        .expect(
            "the allowed device must connect (control for the negative case below) — if this \
             fails, the stack itself is broken and the denial assertion below would be meaningless",
        );
    let (member_display, _) = whoami(&mut control, "control run").await;
    assert_eq!(
        member_display, ALLOWED_DISPLAY_NAME,
        "control run: the allowed device must resolve to its own seeded, non-revoked member"
    );
    control.connection.close(0u32.into(), b"done");
    drop(control);

    // ---- the negative case: the store says this device is revoked -----------------------------
    let denied_client = SignalingClient::new(revoked_nats, revoked.device_key());
    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        denied_client.connect(&host_identity, client_opts()),
    )
    .await;

    // What this proves, and what it honestly does not: DESIGN.md §A5's uniform silent drop means
    // a denied connect is, from the client's own vantage point, indistinguishable from "host
    // offline" — the client observes only a timeout or a connect-flow error, never a typed
    // "denied" signal, so this match arm alone cannot attribute the failure to
    // HostConnectAuthorizer specifically. What makes the attribution meaningful is the control run
    // immediately above: it already proved this exact host process answers a legitimate connect,
    // within the same timeout window, over a connection with the same NATS-level permission shape
    // (a valid member capability) as this one. The only material difference between the two
    // connect attempts is that `revoked.device_fp`'s row was marked `revoked = 1` in the store
    // HostConnectAuthorizer reads from. That is strong circumstantial evidence, not a
    // host-internal hook proving `HostConnectAuthorizer::authorize` itself returned `Deny` — this
    // test has no such hook available over the live stack, and does not claim to.
    match result {
        Ok(Ok(_)) => panic!(
            "a device the store marked revoked established a session — false green. \
             HostConnectAuthorizer<SqliteDeviceLookup> is not being consulted on the live path, \
             or is not reading the revoked flag."
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

    assert_no_permission_violation(&host_events, "host");
    assert_no_permission_violation(&revoked_events, "revoked client");

    host_task.abort();
}
