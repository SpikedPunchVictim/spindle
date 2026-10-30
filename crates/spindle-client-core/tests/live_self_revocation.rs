#![cfg(unix)]
//! Live end-to-end proof for td-a06afc's client half: [`mint_self_revocation`] and
//! [`deposit_self_revocation`] in `spindle-client-core`, driven over a real callout-authenticated
//! member connection, and a later CONNECT by the revoked device refused by the real helper.
//!
//! # What this proves
//!
//! `self_revocation.rs`'s unit tests stop at the [`RevokeTransport`] seam: a fake answers with
//! canned helper JSON. This file supplies a test-local adapter over a real
//! `async_nats::Client` (the production adapter is deliberately not in this crate — it lands with
//! the app, which is still out of this ticket's scope), so the whole wire path runs for real: the
//! primary device mints a `spindle-self-rev-v1` record under the identity root, publishes it to
//! `helper.revoke.<its own nfp>` with a real request/reply, and reads the helper's real
//! `{"ok": true, "root_fp": ..., "epoch": ...}` reply. The helper writes the accepted revoked set
//! to its durable Postgres store before replying, so the reply's epoch is evidence the deposit
//! was applied. The lost device's **exact bundle** is then connected once *before* the deposit
//! and must succeed — the positive control that rules out every unrelated refusal cause — before
//! a later connection presenting that same bundle is refused by the real Auth Callout; the client
//! observes [`async_nats::ConnectErrorKind::AuthorizationViolation`], not a timeout. The host that
//! issued the member capability never runs: this is S14's "revoke while the host is offline" shape.
//!
//! The negative leg deposits a perfectly signed record under a **different** root from the same
//! live session. The helper refuses it at its cheap root-binding check (its signer is not the
//! session record's `root_fp`), which is exactly the subject-session binding DESIGN.md §A4/§A5
//! relies on to stop one member depositing revocations under somebody else's root.
//!
//! # The deposit that revokes the depositing session [td-b49943]
//!
//! The first two legs follow S14's normal shape: the primary deposits a record revoking a *lost*
//! device, so the helper's kick relay (DESIGN.md §A3/§A4 leg 3) has no live session to target and
//! the depositing session is undisturbed. The final leg exercises the other shape: the primary
//! revokes its **own** `device_fp`, so the kick relay targets the very connection that sent the
//! deposit. The helper publishes the reply before it plans or executes kicks, so this deposit
//! still observes its typed `Ok(epoch)` reply. With the old ordering the reply was destroyed:
//! measured live, the helper logged `self-revocation accepted ... epoch=1`, then
//! `newly revoked devices — planning kicks`, then `kicked a revoked connection cid=<the depositing
//! session>`, and the client's request/reply timed out on a deposit that had been durably
//! applied. The helper then plans and executes the kick for this session, which is the expected
//! consequence; the test deliberately does not assert on that disconnect (the client may drop its
//! connection first as the test ends — only the typed reply is asserted). The leg runs last so
//! nothing reuses the connection afterwards.
//!
//! # A random identity on every run [load-bearing]
//!
//! The helper's accepted revoked set lives in **durable Postgres** (`revoked_subjects`, keyed by
//! the root's `root_fp`). A record revoking a fixed `device_fp` is permanent — S14's own
//! "none (permanent)" lifetime — so a second run with a fixed seed would connect and deposit
//! against an identity the first run already revoked, and its first CONNECT would be refused
//! before the test could prove anything. Every seed here therefore comes from [`OsRng`]: the
//! root, both devices' keys, and the other-root fixture in the negative leg. Running this test
//! twice in a row must behave identically; that repeat is the practical check on this choice.
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
//! cargo test -p spindle-client-core --test live_self_revocation -- --ignored --nocapture
//! ```
//!
//! `NATS_URL` overrides the stack's TCP listener (default `nats://127.0.0.1:4222`).
//!
//! The helper runs as a prebuilt container image, not as source this test recompiles. The
//! `helper.revoke.<nfp>` subscription itself shipped in td-b5d50c, so a stale image has no
//! subscription and every deposit request times out. Rebuild it after any `spindle-helper`
//! change:
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml build helper
//! docker compose -f deploy/docker-compose.yml up -d --no-deps helper
//! ```

use async_nats::ConnectErrorKind;
use rand::rngs::OsRng;
use rand::RngCore;
use spindle_client_core::self_revocation::{
    deposit_self_revocation, mint_self_revocation, DepositError, RevokeTransport, TransportError,
};
use spindle_core::root_fp_of;
use spindle_core::SigningKey;
use spindle_proto::artifacts::Capability;
use spindle_test_fixtures::fixtures::{self, DeviceIdentity, HostRootIdentity};
use spindle_test_fixtures::{assert_no_permission_violation, base_opts, connect_device, nats_url};

/// The helper's fixed refusal for a record whose signer is not the session's own root. Asserted
/// as a literal (not a locally re-derived constant) because it is the helper's wire text, and the
/// point of this leg is that the real handler, not a fixture, produced it.
const ROOT_MISMATCH_REFUSAL: &str = "record root_fp does not match the session's root";

/// Test-local implementation of the production transport seam, over the already-authenticated
/// member connection. It does exactly what `RevokeTransport`'s contract requires: publish the
/// given payload on the given subject as a request and return the raw reply bytes. It is
/// deliberately here, not in the library — the app/engine adapter is a later slice.
struct NatsRevokeTransport {
    client: async_nats::Client,
}

impl RevokeTransport for NatsRevokeTransport {
    async fn request(&self, subject: &str, payload: Vec<u8>) -> Result<Vec<u8>, TransportError> {
        let reply = self
            .client
            .request(subject.to_owned(), payload.into())
            .await
            .map_err(|error| -> TransportError { Box::new(error) })?;
        Ok(reply.payload.to_vec())
    }
}

/// A fresh 32-byte seed from the OS CSPRNG. See the module doc's random-identity section: reusing
/// any seed would collide with the helper's durable revoked set on a later run.
fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

/// The same CONNECT construction [`connect_device`] performs, but returning the connect error
/// instead of panicking on it — this test expects a refusal and must inspect its
/// [`ConnectErrorKind`]. Duplicated rather than added to `spindle-test-fixtures` because
/// `connect_device`'s panic-on-error is the right default for every other live test; this is the
/// one caller for which a refused CONNECT is the asserted outcome (the same reason
/// `spindle-net/tests/live_signaling.rs`'s revoked-reconnect probe builds its own connection).
async fn try_connect_device(
    url: &str,
    device: &DeviceIdentity,
    caps: &[Capability],
    exp: u64,
) -> Result<async_nats::Client, async_nats::ConnectError> {
    let session = nkeys::KeyPair::new_user();
    let nats_fp = fixtures::nats_fp_of_nkey(&session.public_key());
    let ts = fixtures::now();
    let cert = device.certificate(ts, exp);
    let session_attest = device.session_attestation(nats_fp, ts);
    let token = fixtures::device_auth_token(
        &device.root.public_key().to_bytes(),
        &cert,
        &session_attest,
        caps,
    );
    let (opts, _events) = base_opts();
    opts.nkey(session.seed().expect("session nkey seed"))
        .token(token)
        .custom_inbox_prefix(format!("_INBOX_{}", device.device_fp))
        .connect(url)
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d` first, \
            then `cargo test -p spindle-client-core --test live_self_revocation -- --ignored \
            --nocapture`. When run, an unreachable stack fails loudly — this test never skips."]
async fn a_deposited_self_revocation_is_accepted_and_the_revoked_device_cannot_reconnect() {
    let url = nats_url();
    let now = fixtures::now();

    // ---- a fresh identity root with two devices per run (see the module doc) -----------------
    // `DeviceIdentity` keeps its root as a `RootKey`, which deliberately exposes no signing-key
    // accessor (it holds the secret half). `RootKey::from_seed` wraps exactly
    // `SigningKey::from_bytes(seed)` — the helper's own end-to-end test asserts that identity — so
    // keeping the root seed here is how the same root both enrolls both devices and signs the
    // self-revocation.
    let root_seed = random_seed();
    let primary = DeviceIdentity::new(root_seed, random_seed(), random_seed());
    let lost_device = DeviceIdentity::new(root_seed, random_seed(), random_seed());
    let root_signing = SigningKey::from_bytes(&root_seed);
    assert_eq!(
        root_fp_of(&root_signing.verifying_key()),
        primary.root_fp(),
        "the seed used to sign the self-revocation must be the session device's own identity root"
    );
    assert_eq!(
        primary.root_fp(),
        lost_device.root_fp(),
        "both devices are enrolled under the same identity root"
    );
    assert_ne!(
        primary.device_fp, lost_device.device_fp,
        "the revoked device must be a distinct device key pair"
    );

    // A host fixture only mints the member capability. The host is never connected: the callout
    // verifies the capability's issuance chain from the keys embedded in it. One capability for
    // the shared root covers both devices — the subject is the root, not a device.
    let host = HostRootIdentity::new(random_seed(), random_seed());
    let exp = now + 3_600;
    let cap = host.member_capability(primary.root_fp(), exp, vec![0u8; 32]);

    // ---- connect the primary through the real Auth Callout ------------------------------------
    let (client, events, user_pk) =
        connect_device(&url, &primary, std::slice::from_ref(&cap), exp).await;
    // The subject token the helper parses is the *session* nkey's fingerprint, never a payload
    // field. The callout has just proven this connection owns it.
    let nats_fp = fixtures::nats_fp_of_nkey(&user_pk);
    let transport = NatsRevokeTransport {
        client: client.clone(),
    };
    println!(
        "[primary] connected through the callout as root_fp={} device_fp={} nfp={}",
        primary.root_fp(),
        primary.device_fp,
        nats_fp
    );

    // ---- positive control: the lost device's exact bundle is accepted before the revocation ----
    // Without this, the post-deposit `AuthorizationViolation` below could be caused by anything —
    // a malformed capability, a mistyped session attestation, a fixture the callout never accepts —
    // and the test would still pass. This connects the *same* bundle that will later be refused
    // (same root, same device key pair, same capability; a fresh session nkey, exactly what the
    // device's own next reconnect mints) and requires success. The only state transition between
    // this acceptance and the refusal is the deposit, so the refusal is attributable to it.
    // Dropping the connection before the deposit also leaves the revoked device with no live
    // session for the helper's kick relay to target (see the module doc).
    match try_connect_device(&url, &lost_device, std::slice::from_ref(&cap), exp).await {
        Ok(control) => drop(control),
        Err(error) => panic!(
            "the lost device's bundle was refused BEFORE any self-revocation (kind={}, error: \
             {error}) — the post-deposit refusal below would prove nothing. Check the fixture and \
             capability before reading that assertion as evidence.",
            error.kind()
        ),
    }
    println!("[lost-device] pre-deposit control CONNECT accepted");

    // ---- deposit: revoke the lost device under this session's root ----------------------------
    // Signed by the primary's identity root, naming the lost device's `device_fp`. The helper's
    // binding check accepts it because the signer is the session's `root_fp`; the lost device's
    // control connection is already dropped, so nothing live is kicked and the reply reaches this
    // connection.
    let record = mint_self_revocation(&root_signing, 1, &[lost_device.device_fp], now);
    let epoch = deposit_self_revocation(&transport, nats_fp, &record)
        .await
        .expect(
            "the helper must accept a record signed by this session's own root; a transport \
             error here means the stack is unreachable or the helper image predates the \
             helper.revoke.<nfp> subscription",
        );
    assert_eq!(
        epoch, 1,
        "the reply's epoch is the helper's stored high-water mark for this root"
    );
    assert_no_permission_violation(&events, "depositing device");
    println!("[primary] helper accepted the self-revocation at epoch {epoch}");

    // ---- the lost device's bundle must now be refused at CONNECT -------------------------------
    // Same identity root and the same member capability as the primary's accepted connection;
    // different device key pair and a fresh session nkey (exactly what the lost device's own next
    // reconnect would mint). Any successful connect here falsifies S14, so it is a loud panic —
    // never a retry.
    match try_connect_device(&url, &lost_device, std::slice::from_ref(&cap), exp).await {
        Ok(second) => {
            drop(second);
            panic!(
                "a CONNECT presenting the revoked device's bundle SUCCEEDED. The callout did not \
                 refuse a self-revoked device — S14's security property is failing."
            );
        }
        Err(error) => match error.kind() {
            ConnectErrorKind::AuthorizationViolation => {
                println!("[second-connect] revoked device correctly refused: {error}");
            }
            kind => panic!(
                "the revoked device's CONNECT failed with a non-authorization error \
                 (kind={kind}, full error: {error}) — a timeout/IO/DNS failure means the NATS \
                 stack itself is unreachable and proves NOTHING about the refusal. Report this \
                 as an inconclusive run, not a pass."
            ),
        },
    }

    // ---- negative leg: a different root cannot deposit on this session ------------------------
    // Runs after the deposit, from the same still-live session, which also proves the primary's
    // own connection was not disturbed. A different root signs a record for a device under that
    // root. The record is valid on its own terms; only the helper's session binding can refuse
    // it. The reply's exact text is the cheap `root_fp` comparison in
    // `spindle_helper::self_revoke`, i.e. the wire proof that a member may deposit only under the
    // root its session record carries.
    let foreign_root_seed = random_seed();
    let foreign_root = SigningKey::from_bytes(&foreign_root_seed);
    // Enrolled under `foreign_root`, so the record's signer and the device it names belong to the
    // same (third, unrelated) root — exactly what the comment above describes.
    let foreign_device = DeviceIdentity::new(foreign_root_seed, random_seed(), random_seed());
    assert_eq!(
        foreign_device.root_fp(),
        root_fp_of(&foreign_root.verifying_key()),
        "the foreign device must belong to the foreign root that signs its revocation"
    );
    let foreign_record = mint_self_revocation(&foreign_root, 1, &[foreign_device.device_fp], now);
    let refusal = deposit_self_revocation(&transport, nats_fp, &foreign_record)
        .await
        .expect_err("a record signed by a different root must not be accepted");
    match refusal {
        DepositError::Rejected(reason) => assert_eq!(
            reason, ROOT_MISMATCH_REFUSAL,
            "the helper must refuse by the session's root binding"
        ),
        other => panic!(
            "expected the helper's typed Rejected(root mismatch), got {other:?} — this is a \
             wire-behavior change, not a flaky reply"
        ),
    }
    println!(
        "[primary] deposit under a different root correctly rejected: {ROOT_MISMATCH_REFUSAL}"
    );

    // ---- third leg: the primary revokes its own device and still gets the typed reply --------
    // td-b49943. Unlike the first deposit, this record names the depositing session's own
    // `device_fp`, so the helper's kick relay plans a kick for this very connection. The helper
    // must publish the reply first — it goes to the caller's own inbox, which still exists at
    // that instant — or the kick destroys the connection and the request times out on a deposit
    // that was durably applied (the pre-fix behavior measured live; see the module doc). The
    // helper then kicks this session, as expected, but that disconnect is deliberately not
    // asserted (the client may drop first as the test ends); this leg runs last, and nothing
    // below reuses the connection.
    let self_revoke_record = mint_self_revocation(&root_signing, 2, &[primary.device_fp], now);
    match deposit_self_revocation(&transport, nats_fp, &self_revoke_record).await {
        Ok(epoch) => {
            assert_eq!(
                epoch, 2,
                "the reply's epoch is the helper's stored high-water mark after the \
                 self-revocation"
            );
            println!(
                "[self-revoke] the helper accepted the deposit revoking this session's own \
                 device_fp={} and replied Ok(epoch={epoch}) BEFORE kicking; the helper then \
                 kicks this session, as expected (the disconnect is not asserted)",
                primary.device_fp
            );
        }
        Err(error) => panic!(
            "a deposit revoking the depositing session's own device_fp must still receive the \
             typed Ok(epoch) reply before the kick runs (td-b49943); got {error:?}. A Transport \
             timeout here means the reply was destroyed by the kick — the helper image likely \
             predates the reply-before-kick fix or is stale."
        ),
    }

    // async-nats 0.35 has no `close`/`drain` on `Client`; dropping the last handles is how the
    // connection is released.
    drop(transport);
    drop(client);
}
