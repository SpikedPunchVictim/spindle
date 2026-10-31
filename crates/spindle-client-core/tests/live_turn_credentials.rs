#![cfg(unix)]
//! Live end-to-end proof for td-870b25's client half: [`fetch_turn_credentials`] in
//! `spindle-client-core`, driven over a real callout-authenticated member connection against the
//! real helper's `helper.turn.get.<nfp>` handler.
//!
//! # What this proves
//!
//! `turn_credentials.rs`'s unit tests stop at the [`TurnCredentialTransport`] seam: a fake answers
//! with canned helper JSON. This file supplies a test-local adapter over a real
//! `async_nats::Client` (the production adapter is deliberately not in this crate — it lands with
//! the app, which is out of this ticket's scope), so the whole wire path runs for real: a random
//! member connects through the real Auth Callout, publishes `{}` to
//! `helper.turn.get.<its own session nfp>` with a real request/reply, and reads the helper's real
//! credential reply. The helper looks the session record up by the **subject's** `nfp`, charges the
//! per-`root_fp` quota in its durable store, and mints `username = "<expiry>:<root_fp>"` with the
//! stack's configured `TURN_TTL_SECS`. This test asserts exactly that: the username's
//! `<expiry>:<root_fp>` shape with the root the session belongs to, the configured TTL, non-empty
//! coturn-shaped `uris`, and a non-empty credential.
//!
//! # A random identity on every run [load-bearing]
//!
//! The helper's TURN issuance counter lives in durable Postgres, keyed by `root_fp`, and the
//! configured quota is monthly. A fixed root would share that counter across runs until it ran
//! out, and a failure would then look like a helper defect. Every seed here therefore comes from
//! [`OsRng`] — the root and the member device's keys — so each run starts against a fresh
//! `root_fp` and the quota is never a factor. Running this test twice in a row must behave
//! identically; that repeat is the practical check on this choice.
//!
//! # Gating
//!
//! `#[ignore]`d, so `cargo test --workspace` reports it as `ignored` rather than running it. It is
//! **not** the "silently no-op when an env var is unset" shape: when run, an unreachable stack is a
//! hard failure naming what to start, never a skip.
//!
//! Run with:
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml up -d
//! cargo test -p spindle-client-core --test live_turn_credentials -- --ignored --nocapture
//! ```
//!
//! `NATS_URL` overrides the stack's TCP listener (default `nats://127.0.0.1:4222`). The helper must
//! have `TURN_SECRET`/`TURN_URIS`/`TURN_TTL_SECS` configured — `deploy/docker-compose.yml` sets
//! all three; without them the helper answers `{"error": "TURN not configured"}` and this test
//! fails loudly instead of skipping.

use rand::rngs::OsRng;
use rand::RngCore;
use spindle_client_core::turn_credentials::{
    fetch_turn_credentials, TransportError, TurnCredentialError, TurnCredentialTransport,
};
use spindle_test_fixtures::fixtures::{self, DeviceIdentity, HostRootIdentity};
use spindle_test_fixtures::{assert_no_permission_violation, connect_device, nats_url};

/// `TURN_TTL_SECS` in `deploy/docker-compose.yml` — the stack this test runs against. Asserted as
/// a literal (not read from the environment) because the point is that the helper's configured
/// value, not a test-local one, reached the client.
const STACK_TURN_TTL_SECS: u64 = 3_600;

/// Test-local implementation of the production transport seam, over the already-authenticated
/// member connection. It does exactly what `TurnCredentialTransport`'s contract requires: publish
/// the given payload on the given subject as a request and return the raw reply bytes. It is
/// deliberately here, not in the library — the app/engine adapter is a later slice.
struct NatsTurnCredentialTransport {
    client: async_nats::Client,
}

impl TurnCredentialTransport for NatsTurnCredentialTransport {
    async fn request(&self, subject: &str, payload: Vec<u8>) -> Result<Vec<u8>, TransportError> {
        let reply = self
            .client
            .request(subject.to_owned(), payload.into())
            .await
            .map_err(|error| -> TransportError { Box::new(error) })?;
        Ok(reply.payload.to_vec())
    }
}

/// A fresh 32-byte seed from the OS CSPRNG. See the module doc's random-identity section: reusing a
/// seed would share the helper's durable per-`root_fp` quota across runs.
fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d` first, \
            then `cargo test -p spindle-client-core --test live_turn_credentials -- --ignored \
            --nocapture`. When run, an unreachable stack fails loudly — this test never skips."]
async fn a_member_session_fetches_live_turn_credentials_from_the_helper() {
    let url = nats_url();
    let now = fixtures::now();

    // ---- a fresh identity root per run (see the module doc) ----------------------------------
    let member = DeviceIdentity::new(random_seed(), random_seed(), random_seed());
    // A host fixture only mints the member capability; the host itself never connects. The
    // callout verifies the capability's issuance chain from the keys embedded in it.
    let host = HostRootIdentity::new(random_seed(), random_seed());
    let exp = now + 3_600;
    let cap = host.member_capability(member.root_fp(), exp, vec![0u8; 32]);

    // ---- connect through the real Auth Callout ------------------------------------------------
    let (client, events, user_pk) =
        connect_device(&url, &member, std::slice::from_ref(&cap), exp).await;
    // The subject token the helper parses is the *session* nkey's fingerprint, never a payload
    // field. The callout has just proven this connection owns it.
    let nats_fp = fixtures::nats_fp_of_nkey(&user_pk);
    let transport = NatsTurnCredentialTransport {
        client: client.clone(),
    };
    println!(
        "[member] connected through the callout as root_fp={} device_fp={} nfp={}",
        member.root_fp(),
        member.device_fp,
        nats_fp
    );

    // ---- fetch the credential over the real helper --------------------------------------------
    let reply = match fetch_turn_credentials(&transport, &nats_fp.to_string()).await {
        Ok(reply) => reply,
        Err(TurnCredentialError::Rejected(reason)) => panic!(
            "the helper refused a TURN credential request from a live member session: {reason}\n\
             Check that the running helper image has TURN_SECRET/TURN_URIS/TURN_TTL_SECS set \
             (deploy/docker-compose.yml does) and that this fresh random identity's root has \
             quota left. This is a real refusal, not a flaky reply."
        ),
        Err(other) => panic!(
            "fetching TURN credentials from the live helper failed: {other:?}. A transport error \
             here means the stack is unreachable or the helper image predates the \
             helper.turn.get.<nfp> subscription; a malformed-reply error means the helper's wire \
             shape changed."
        ),
    };
    let now_after = fixtures::now();
    assert_no_permission_violation(&events, "turn-credential member");

    // ---- the username is "<expiry>:<root_fp>" for this session's own root ----------------------
    let (expiry, root_fp) = reply.username.split_once(':').unwrap_or_else(|| {
        panic!(
            "username {:?} is not the documented \"<expiry>:<root_fp>\" shape",
            reply.username
        )
    });
    assert_eq!(
        root_fp,
        member.root_fp().to_string(),
        "the credential must be minted for the session record's root_fp, not any other identity"
    );
    let expiry: u64 = expiry.parse().unwrap_or_else(|_| {
        panic!(
            "username's expiry segment {:?} is not a Unix-seconds integer",
            expiry
        )
    });
    assert!(
        expiry > now && expiry <= now_after + STACK_TURN_TTL_SECS + 60,
        "username expiry {expiry} is not roughly now + ttl ({now} + {STACK_TURN_TTL_SECS})"
    );

    // ---- TTL and URIs come from the stack's TURN configuration ---------------------------------
    assert_eq!(
        reply.ttl_secs, STACK_TURN_TTL_SECS,
        "the helper must report its configured TURN_TTL_SECS (deploy/docker-compose.yml)"
    );
    assert!(
        !reply.uris.is_empty(),
        "the helper must return at least one ICE server URI"
    );
    for uri in &reply.uris {
        assert!(
            uri.starts_with("turn:") || uri.starts_with("turns:"),
            "URI {uri:?} is not a TURN/TURNS ICE server URI"
        );
        let after_scheme = uri
            .split_once(':')
            .map(|(_, rest)| rest)
            .expect("a TURN URI always has a scheme separator");
        let host_port = after_scheme
            .split_once('?')
            .map_or(after_scheme, |(host_port, _)| host_port);
        assert!(
            host_port.contains(':') && !host_port.starts_with(':'),
            "URI {uri:?} is not coturn-shaped (expected scheme:host:port)"
        );
    }

    // ---- the credential itself -----------------------------------------------------------------
    assert!(
        !reply.credential.is_empty(),
        "the helper must return a non-empty coturn credential"
    );

    println!(
        "[member] helper minted a TURN credential: username={} ttl_secs={} uris={:?} \
         credential_len={}",
        reply.username,
        reply.ttl_secs,
        reply.uris,
        reply.credential.len()
    );

    // async-nats 0.35 has no `close`/`drain` on `Client`; dropping the last handles is how the
    // connection is released.
    drop(transport);
    drop(client);
}
