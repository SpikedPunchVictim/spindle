#![cfg(unix)]
//! Live end-to-end test for td-65884b's host half: a running host mints and publishes its
//! `HostDeviceCert` on every connect (A10.37), the broker helper caches it, and a member fetches
//! exactly that certificate back over `helper.devcert.get.<nfp>`.
//!
//! # What this proves
//!
//! The helper half's unit tests prove the store and handler logic against an in-memory view. This
//! file proves the wire path with **production** code on the host side: [`mint_host_identity`] and
//! [`spindle_hostd::connect::connect_host`] build a real host identity, callout-authenticated
//! connection, mint and publish. The publish cadence lives inside `connect_host` (initial connect
//! plus cached-byte republishes on `Event::Connected`), so the test never calls a publish helper
//! itself. A real device then connects through the callout with a member capability and requests
//! the certificate from the subject it is granted. The assertion that matters is identity binding:
//! the certificate the helper serves contains **exactly this process's envelope keys**, so the
//! bytes a client would use to seal its first A7 offer name the running host, not a stale process.
//!
//! The negative half proves the fetch cannot enumerate hosts: a **second** host also publishes its
//! certificate through the production connect path, so the helper's cache holds it, but the device
//! holds no capability for that host. The fetch must still return the uniform refusal, byte for
//! byte. Because the second certificate genuinely is cached, this exercises the membership guard
//! (`session.host_fps.contains`) rather than an uncached-host lookup that would answer the same way
//! even if the guard were deleted.
//!
//! # Gating
//!
//! This test is `#[ignore]`d, so `cargo test --workspace` reports it as `ignored` rather than
//! running it. It is **not** the "silently no-op when an env var is unset" shape: when run, an
//! unreachable stack is a hard failure with a message naming what to start, never a skip. A test
//! that passes without running is the exact false-green this repo has already been bitten by (see
//! `live_hostd.rs`'s own module doc comment).
//!
//! Run with:
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml up -d --build
//! cargo test -p spindle-hostd --test live_devcert -- --ignored --nocapture
//! ```
//!
//! `NATS_URL` overrides the stack's TCP listener (default `nats://127.0.0.1:4222`).
//!
//! # Rebuild the helper image after any spindle-helper change
//!
//! The helper runs as a prebuilt container image, not as source the test stack recompiles. This
//! test exercises subscriptions added to `spindle-helper` by td-65884b
//! (`registry.devcert.*` and `helper.devcert.get.*`), so a stale image has no subscription at all
//! and the fetch request simply times out. Rebuild it with
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml build helper
//! docker compose -f deploy/docker-compose.yml up -d --no-deps helper
//! ```
//!
//! The same instruction appears in `live_hostd.rs`/`live_host_binary.rs` for wire-schema changes;
//! here it is the subscriptions themselves that must be present.
//!
//! # Why the positive fetch retries
//!
//! `connect_host` flushes after publishing, so the host's write has been accepted by the server
//! before the call returns — but the flush does not order that write against the helper's ingest
//! on a *different* connection. The positive fetch therefore retries only the exact "no
//! certificate yet" reply, for a bounded window, and fails loudly on timeout. The negative fetch
//! does not retry: its reply must be the refusal on the first try.

use std::time::{Duration, Instant};

use base64::Engine as _;
use spindle_core::artifacts::{issue_capability, verify_host_device_cert};
use spindle_hostd::connect::connect_host;
use spindle_hostd::{mint_host_identity, wall_clock_now_secs};
use spindle_proto::artifacts::{CapKind, HostDeviceCert};
use spindle_test_fixtures::fixtures::{self, DeviceIdentity};
use spindle_test_fixtures::{connect_device, nats_url};

/// The uniform refusal, byte for byte, as the helper publishes it (see
/// `spindle_helper::devcert`'s wire schema). Asserting against the literal rather than a parsed
/// field is what makes "the two cases are indistinguishable" a statement about the wire.
const NO_CERT_REPLY: &[u8] = br#"{"error":"no device certificate available"}"#;

/// How long the positive fetch waits for the helper's ingest to catch up with the already-flushed
/// host publish.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
const FETCH_RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// Requests a certificate from the helper, retrying only while the reply is the uniform
/// "no certificate available" answer. Any other reply (including an unexpected error) is returned
/// immediately for the caller to assert on.
async fn fetch_certificate(
    client: &async_nats::Client,
    subject: &str,
    request: &str,
) -> async_nats::Message {
    let deadline = Instant::now() + FETCH_TIMEOUT;
    loop {
        let reply = client
            .request(subject.to_owned(), request.to_owned().into())
            .await
            .expect("helper.devcert.get request/reply failed; is the helper image rebuilt?");
        if reply.payload.as_ref() != NO_CERT_REPLY {
            return reply;
        }
        assert!(
            Instant::now() < deadline,
            "the helper never served {} within {}s; its `registry.devcert.<hfp>` ingest did not \
             catch up with the host's flushed publish (stale helper image?)",
            subject,
            FETCH_TIMEOUT.as_secs()
        );
        tokio::time::sleep(FETCH_RETRY_INTERVAL).await;
    }
}

/// Reads the `cert` field out of a helper reply, panicking with the raw payload when absent.
fn cert_field(reply: &async_nats::Message) -> String {
    let parsed = spindle_test_fixtures::tinyjson::parse(
        std::str::from_utf8(&reply.payload).expect("helper reply is UTF-8 JSON"),
    )
    .unwrap_or_else(|| {
        panic!(
            "helper.devcert.get reply did not parse as JSON: {:?}",
            String::from_utf8_lossy(&reply.payload)
        )
    });
    parsed
        .get("cert")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| {
            panic!(
                "expected a certificate from the helper, got: {:?}",
                String::from_utf8_lossy(&reply.payload)
            )
        })
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d --build` \
            first, then `cargo test -p spindle-hostd --test live_devcert -- --ignored --nocapture`. \
            When run, an unreachable stack fails loudly — this test never skips."]
async fn host_publishes_its_device_cert_and_a_member_fetches_the_running_envelope_identity() {
    let url = nats_url();
    // One clock read for the whole test: the certificate's ts/exp, the op cert, the capability,
    // and the fetch verification must all agree on "now" to the second.
    let now = wall_clock_now_secs();

    // ---- the running host: production identity mint + production connect ----------------------
    // `connect_host` mints the device certificate, publishes it on `registry.devcert.<hfp>`, and
    // flushes before returning (A10.37); there is no separate publish step here.
    let identity = mint_host_identity([0x6a; 32], now);
    // The second tuple element is the guard that keeps the reconnect-republish pump alive; hold
    // it for the connection's lifetime (dropping the client alone would leave the pump's clone).
    let (host_client, _host_publisher) = connect_host(&identity, &url, None, now)
        .await
        .expect("host CONNECT to the live stack failed; is the stack up and the helper rebuilt?");
    println!(
        "[host] connect_host published registry.devcert.{}",
        identity.host_fp
    );

    // A second, independent host also publishes through the production path. The device below
    // holds no capability for it, so fetching it exercises the helper's membership guard against a
    // certificate that genuinely is in the cache.
    let other_host = mint_host_identity([0x6b; 32], now);
    let (other_host_client, _other_host_publisher) = connect_host(&other_host, &url, None, now)
        .await
        .unwrap_or_else(|error| {
            panic!("second host CONNECT/publish to the live stack failed: {error}")
        });
    println!(
        "[other-host] connect_host published registry.devcert.{}",
        other_host.host_fp
    );

    // ---- a member device with a capability for exactly the first host ------------------------
    let device = DeviceIdentity::new([0x7b; 32], [0x7c; 32], [0x7d; 32]);
    let cap = issue_capability(
        &identity.root.public_key(),
        &identity.op_cert,
        &identity.op_signing,
        CapKind::Member,
        device.root_fp(),
        0,
        now + 3600,
        vec![0u8; 32],
    );
    let (device_client, _device_events, user_pk) =
        connect_device(&url, &device, &[cap], now + 3600).await;

    // The callout proves this connection owns `nats_fp`; the helper's handler parses exactly this
    // token out of the request subject, so it is the `<nfp>` the fetch must be addressed to.
    let nats_fp = fixtures::nats_fp_of_nkey(&user_pk);
    let fetch_subject = format!("helper.devcert.get.{nats_fp}");

    // ---- fetch: the helper must serve this process's certificate -----------------------------
    let request = format!(r#"{{"host_fp":"{}"}}"#, identity.host_fp);
    let reply = fetch_certificate(&device_client, &fetch_subject, &request).await;

    let cert_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cert_field(&reply))
        .expect("the served certificate is unpadded base64url");
    let cert = HostDeviceCert::from_canonical_bytes(&cert_bytes)
        .expect("the served bytes decode as a canonical HostDeviceCert");

    // The identity-binding proof: the certificate verifies to this host's pinned root, and the
    // envelope keys in it are the *running process's* keys — the ones a client would seal its
    // first offer to.
    verify_host_device_cert(&cert, &identity.host_fp, now)
        .expect("the fetched certificate must verify against the host's own pinned fingerprint");
    assert_eq!(
        cert.sign_pk,
        identity.device.sign_public_key().as_bytes().to_vec(),
        "the served sign_pk must be this process's envelope signing key"
    );
    assert_eq!(
        cert.agree_pk,
        identity.device.agree_public_key().as_bytes().to_vec(),
        "the served agree_pk must be this process's envelope agreement key"
    );
    assert_eq!(
        cert.host_device_fp,
        identity.device_fp.to_vec(),
        "the served host_device_fp must be this process's envelope fingerprint"
    );
    println!(
        "[device] fetched and verified host device cert for host_fp={} device_fp={}",
        identity.host_fp, identity.device_fp
    );

    // ---- negative: a cached certificate for a host outside the caller's session ---------------
    // The second host's certificate really is in the helper's cache, so only the session-record
    // membership check can produce this refusal. Do not retry: the answer must be immediate.
    let negative_request = format!(r#"{{"host_fp":"{}"}}"#, other_host.host_fp);
    let negative_reply = device_client
        .request(fetch_subject, negative_request.into())
        .await
        .expect("the negative helper.devcert.get request/reply itself must still succeed");

    assert_eq!(
        negative_reply.payload.as_ref(),
        NO_CERT_REPLY,
        "a host with a cached certificate but outside the caller's session must get the uniform \
         absent reply, byte for byte; any other shape is an enumeration oracle"
    );
    let negative_parsed = spindle_test_fixtures::tinyjson::parse(
        std::str::from_utf8(&negative_reply.payload).expect("negative reply is UTF-8 JSON"),
    )
    .expect("negative reply parses as JSON");
    assert!(
        negative_parsed.get("cert").is_none(),
        "the refusal must carry no certificate field"
    );
    println!("[device] cached certificate for an out-of-session host correctly refused");

    // async-nats 0.35 has no `close`/`drain` on `Client`. The publisher guards are dropped first to
    // abort the pumps (releasing their client clones), then the clients — at which point the last
    // handle really is gone. There is no reference cycle left to keep a connection alive.
    drop(_other_host_publisher);
    drop(_host_publisher);
    drop(device_client);
    drop(other_host_client);
    drop(host_client);
}
