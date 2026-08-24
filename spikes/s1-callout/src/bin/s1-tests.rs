//! S1 negative-test suite (docs/SPIKES.md §S1; DESIGN.md §A4/§A5) — the client harness that
//! drives a live `nats-server` (server.conf) with `responder` already running and answering
//! `$SYS.REQ.USER.AUTH`. Generates fresh identities/capabilities via `spike_s1_callout::fixtures`
//! and asserts the full negative-test checklist from the task brief. `run.sh` is what actually
//! wires up the server + responder + this binary end to end; this binary assumes `NATS_URL`
//! (default `nats://127.0.0.1:4222`) already has both.
//!
//! # Detection method for permission denials (documented once here; see RESULTS.md for the
//! transcribed summary)
//! `nats-server` (confirmed against `server/client.go` in v2.10.29) reports a denied
//! publish/subscribe as an **async protocol `-ERR`** on the offending connection itself, not as a
//! synchronous error from the client call that attempted it — `client.publish`/`client.subscribe`
//! return `Ok` regardless of whether the server will honor the action. The exact wire text is:
//! - `Permissions Violation for Publish to "<subject>"`
//! - `Permissions Violation for Publish with Reply of "<reply>"`
//! - `Permissions Violation for Subscription to "<subject>"` (or `... using queue "<queue>"`)
//!
//! `async-nats` surfaces these via `ConnectOptions::event_callback` as
//! `Event::ServerError(ServeError::Other(text))` (the crate's fixed `ServerError` enum has no
//! dedicated `PermissionsViolation` variant — every unrecognized `-ERR` text lands in `Other`, so
//! this suite matches on substrings of `text`, not a variant). Every check here that asserts a
//! *denial* polls the connection's captured event log for a violation event naming the subject in
//! question, AND — wherever a legitimately-permitted publisher exists to send a canary at that
//! exact subject — asserts the canary never actually arrives at the denied subscriber (or, for a
//! denied *publish*, that a companion listener never receives it). Where no legitimately-permitted
//! publisher exists for a given subject (only `host.<h>.presence`, see the note on
//! `device_a_can_sub_own_presence` below — a pre-existing gap in
//! `spindle_helper::permissions::host_permissions`, not introduced by this spike), the check is
//! necessarily weaker (absence-of-violation only) and is labeled as such in its detail string.
//! Every check that asserts an *allow* is paired with an actual, content-verified delivery through
//! a companion connection wherever one exists — never "no violation observed" alone — so a
//! silently-misrouted or silently-dropped message cannot be mistaken for a granted permission.

use futures_util::StreamExt;
use nkeys::KeyPair;
use spike_s1_callout::fixtures;
use spindle_proto::artifacts::Capability;
use std::env;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

type EventLog = Arc<Mutex<Vec<String>>>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Builds a `ConnectOptions` wired with an `event_callback` that appends every observed `Event`'s
/// `Display` text to a shared, lock-guarded log this suite can poll — see module docs' "Detection
/// method" section.
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

/// Polls `events` (every 20ms, up to `timeout_ms`) for an entry containing every one of `needles`
/// as a substring — the deterministic way this suite detects an async permission-violation `-ERR`
/// (see module docs).
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

// ================================================================================================
// Connection builders
// ================================================================================================

async fn connect_device(
    url: &str,
    device: &fixtures::DeviceIdentity,
    caps: Vec<Capability>,
    exp: u64,
) -> anyhow::Result<(async_nats::Client, EventLog)> {
    let session = KeyPair::new_user();
    let nats_fp = fixtures::nats_fp_of_nkey(&session.public_key())?;
    let cert = fixtures::device_certificate(device, nats_fp, now(), exp);
    let root_pk_bytes = device.root.public_key().to_bytes();
    let token = fixtures::device_auth_token(&root_pk_bytes, &cert, &caps);
    // Real devices use a session-scoped custom inbox prefix (`_INBOX_<device_fp>`), matching the
    // subject table's `sub _INBOX_<own>.>` grant — the library's own default `_INBOX.<nuid>`
    // prefix would never match that allow pattern.
    let inbox_prefix = format!("_INBOX_{}", device.device_fp);
    let (opts, events) = base_opts();
    let client = opts
        .nkey(session.seed()?)
        .token(token)
        .custom_inbox_prefix(inbox_prefix)
        .connect(url)
        .await?;
    Ok((client, events))
}

async fn connect_host(
    url: &str,
    host: &fixtures::HostIdentity,
    exp: u64,
) -> anyhow::Result<(async_nats::Client, EventLog)> {
    let session = KeyPair::new_user();
    let nats_fp = fixtures::nats_fp_of_nkey(&session.public_key())?;
    let cert = fixtures::host_op_key_cert(host, nats_fp, now(), exp);
    let root_pk_bytes = host.root.public_key().to_bytes();
    let token = fixtures::host_auth_token(&root_pk_bytes, &cert, None);
    let (opts, events) = base_opts();
    let client = opts.nkey(session.seed()?).token(token).connect(url).await?;
    Ok((client, events))
}

// ================================================================================================
// Assertion helpers — every one pairs a permission-model expectation with an observable proof.
// ================================================================================================

/// Asserts `publisher` CAN deliver to `subject`: `listener` (already holding a matching
/// subscription right) must receive a fresh canary payload, and no publish-violation event may be
/// observed on `publisher`.
async fn assert_pub_allowed(
    publisher: &async_nats::Client,
    publisher_events: &EventLog,
    listener: &async_nats::Client,
    subject: String,
) -> anyhow::Result<(bool, String)> {
    let mut sub = listener.subscribe(subject.clone()).await?;
    listener.flush().await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let marker = format!("s1-canary-{}", rand::random::<u64>());
    publisher
        .publish(subject.clone(), marker.clone().into())
        .await?;
    publisher.flush().await?;
    let received = timeout(Duration::from_millis(1000), sub.next()).await;
    let violated = wait_for_violation(
        publisher_events,
        &["Permissions Violation for Publish", &subject],
        200,
    )
    .await;
    match received {
        Ok(Some(msg)) if msg.payload.as_ref() == marker.as_bytes() => Ok((
            !violated,
            format!("listener received canary on {subject}; violation_seen={violated}"),
        )),
        _ => Ok((
            false,
            format!("listener did NOT receive canary on {subject}; violation_seen={violated}"),
        )),
    }
}

/// Asserts `publisher` CANNOT deliver to `subject`: if `listener` is `Some`, it must never
/// receive the canary; a matching publish-violation event should also appear (best-effort — see
/// `require_violation`).
async fn assert_pub_denied(
    publisher: &async_nats::Client,
    publisher_events: &EventLog,
    listener: Option<&async_nats::Client>,
    subject: String,
) -> anyhow::Result<(bool, String)> {
    let mut sub_opt = match listener {
        Some(l) => {
            let s = l.subscribe(subject.clone()).await?;
            l.flush().await?;
            Some(s)
        }
        None => None,
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    let marker = format!("s1-canary-{}", rand::random::<u64>());
    // publish() itself returns Ok even when the server will refuse it server-side (async denial,
    // see module docs) — the interesting signal is what happens next, not this call's Result.
    let _ = publisher
        .publish(subject.clone(), marker.clone().into())
        .await;
    let _ = publisher.flush().await;
    let violated = wait_for_violation(
        publisher_events,
        &["Permissions Violation for Publish", &subject],
        800,
    )
    .await;
    let not_delivered = match sub_opt.as_mut() {
        Some(sub) => !matches!(
            timeout(Duration::from_millis(300), sub.next()).await,
            Ok(Some(ref m)) if m.payload.as_ref() == marker.as_bytes()
        ),
        None => true,
    };
    let passed = if sub_opt.is_some() {
        violated && not_delivered
    } else {
        violated
    };
    Ok((
        passed,
        format!(
            "violation_seen={violated} not_delivered={not_delivered} (companion_listener={})",
            sub_opt.is_some()
        ),
    ))
}

/// Asserts `subscriber` CAN receive `subject`: `(pub_client, pub_subject)` (already holding a
/// matching publish right) sends a canary; `subscriber` must receive it and no
/// subscription-violation event may be observed.
async fn assert_sub_allowed(
    subscriber: &async_nats::Client,
    subscriber_events: &EventLog,
    subject: String,
    pub_client: &async_nats::Client,
    pub_subject: String,
) -> anyhow::Result<(bool, String)> {
    let mut sub = subscriber.subscribe(subject.clone()).await?;
    subscriber.flush().await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let marker = format!("s1-canary-{}", rand::random::<u64>());
    pub_client
        .publish(pub_subject.clone(), marker.clone().into())
        .await?;
    pub_client.flush().await?;
    let received = timeout(Duration::from_millis(1000), sub.next()).await;
    let violated = wait_for_violation(
        subscriber_events,
        &["Permissions Violation for Subscription", &subject],
        200,
    )
    .await;
    match received {
        Ok(Some(msg)) if msg.payload.as_ref() == marker.as_bytes() => Ok((
            !violated,
            format!("subscriber received canary; violation_seen={violated}"),
        )),
        _ => Ok((
            false,
            format!("subscriber did NOT receive canary on {subject}; violation_seen={violated}"),
        )),
    }
}

/// Asserts `subscriber` CANNOT receive `subject`. If `canary` is `Some((pub_client,
/// pub_subject))`, that publisher (which must itself be authorized to publish there) sends a
/// canary and the check additionally requires it never arrives; otherwise the check relies solely
/// on the violation event (documented explicitly in the caller — e.g. no connection in this suite
/// has publish rights to `$SYS.>`/`$JS.>` at all, so there is nothing to use as a canary source).
async fn assert_sub_denied(
    subscriber: &async_nats::Client,
    subscriber_events: &EventLog,
    subject: String,
    canary: Option<(&async_nats::Client, String)>,
) -> anyhow::Result<(bool, String)> {
    let mut sub = subscriber.subscribe(subject.clone()).await?;
    subscriber.flush().await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let marker = format!("s1-canary-{}", rand::random::<u64>());
    if let Some((pub_client, pub_subject)) = &canary {
        let _ = pub_client
            .publish(pub_subject.clone(), marker.clone().into())
            .await;
        let _ = pub_client.flush().await;
    }
    let violated = wait_for_violation(
        subscriber_events,
        &["Permissions Violation for Subscription", &subject],
        800,
    )
    .await;
    let not_delivered = !matches!(
        timeout(Duration::from_millis(300), sub.next()).await,
        Ok(Some(ref m)) if m.payload.as_ref() == marker.as_bytes()
    );
    let passed = if canary.is_some() {
        violated && not_delivered
    } else {
        violated
    };
    Ok((
        passed,
        format!(
            "violation_seen={violated} not_delivered={not_delivered} (canary={})",
            canary.is_some()
        ),
    ))
}

// ================================================================================================
// Report collector
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

    /// Runs an async check body, converting any `Err` into a recorded `FAIL` (so one broken
    /// check's setup failure never aborts the rest of the suite).
    async fn run<Fut>(&mut self, name: &str, fut: Fut)
    where
        Fut: std::future::Future<Output = anyhow::Result<(bool, String)>>,
    {
        match fut.await {
            Ok((passed, detail)) => self.record(name, passed, detail),
            Err(e) => self.record(name, false, format!("check errored: {e:#}")),
        }
    }

    fn all_passed(&self) -> bool {
        self.results.iter().all(|(_, p, _)| *p)
    }
}

// ================================================================================================
// main
// ================================================================================================

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let exp = now() + 3600;
    let mut checks = Checks::new();

    // ---- Shared fixture identities ----
    // IMPORTANT (see RESULTS.md's "host_fp inconsistency" finding -- the single most important
    // thing S1 found): `decide_host_connect` (spindle-helper/src/authz.rs) derives the `host_fp`
    // it uses for `permissions::host_permissions(host_fp)` -- i.e. what a host itself subscribes
    // to, `host.<host_fp>.>` -- from the host's ROOT key (`root_fp_of(presented.host_root_pk)`).
    // But `issue_capability` (spindle-core/src/artifacts/capability.rs) derives the `host_fp` it
    // embeds in every capability from the signer it's given, which callers always pass as the
    // host's OPERATING key (`fixtures::member_capability`/`invite_capability` -> `host.op_signing`
    // -- matching DESIGN.md §A4's "the host signs with its operating key"). Since a capability's
    // `host_fp` is exactly what a member device's own granted subjects
    // (`client_member_permissions`) are scoped under, these two `host_fp`s are, by construction,
    // computed from TWO DIFFERENT KEYS -- and so, for any host whose root and operating keys
    // actually differ (which DESIGN.md §A4 requires: "signs its operating key", implying a
    // distinct key), a device's capability-granted subjects can never land in the same namespace
    // the host itself subscribes to. This is a real, blocking bug in the reused decision core,
    // not something this spike introduces -- see RESULTS.md for the full analysis and why it was
    // NOT patched in spindle-helper/spindle-core (out of this spike's authority/scope; a call for
    // ADR-002/DESIGN.md to resolve which of the two `host_fp` definitions is canonical).
    //
    // Workaround, confined entirely to this spike's own fixtures, so the REST of the negative
    // suite can still exercise real ALLOW-path NATS permission mechanics end-to-end: construct
    // each test host with root_seed == op_seed, so its root and operating keys are the identical
    // Ed25519 keypair and both `host_fp` computations coincidentally converge on the same value.
    // This does not fix, hide, or paper over the underlying bug (flagged loudly above and in
    // RESULTS.md) -- it only keeps this suite able to prove something beyond "connections get
    // authorized" while that bug remains open.
    let host_h = fixtures::new_host_identity([0x10; 32], [0x10; 32]);
    let host_h2 = fixtures::new_host_identity([0x20; 32], [0x20; 32]); // device A holds NO cap for this one
    let device_a = fixtures::new_device_identity([0x30; 32], [0x31; 32], [0x32; 32]);
    let device_b = fixtures::new_device_identity([0x40; 32], [0x41; 32], [0x42; 32]); // "another device"
    let device_c = fixtures::new_device_identity([0x50; 32], [0x51; 32], [0x52; 32]); // invite-only

    // ---- Foundational connection: a real host H, used throughout as companion/observer. Its
    // own `host.<H>.>` subscription is broad enough to observe every host-side message this
    // suite needs to check for (host.<H>.connect, host.<H>.sess.<A>.*.c2h, and — for the
    // bridging check — host.<H>.presence), so it is created once and reused rather than
    // re-subscribed per check. ----
    let (host_conn, host_events) = match connect_host(&url, &host_h, exp).await {
        Ok(pair) => {
            checks.record(
                "host_h_connects",
                true,
                "host H connected with a valid host_op_cert",
            );
            pair
        }
        Err(e) => {
            checks.record("host_h_connects", false, format!("{e:#}"));
            checks.record(
                "suite_aborted",
                false,
                "host H failed to connect -- every subsequent check depends on it as a companion/observer; aborting",
            );
            print_summary(&checks);
            return Ok(ExitCode::FAILURE);
        }
    };
    let mut host_sub = host_conn
        .subscribe(format!("host.{}.>", host_h.host_fp))
        .await?;
    host_conn.flush().await?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    // ============================================================================================
    // (a) fresh key, no cap -> refused
    // ============================================================================================
    checks
        .run("fresh_key_no_cap_refused", async {
            let session = KeyPair::new_user();
            let nats_fp = fixtures::nats_fp_of_nkey(&session.public_key())?;
            let cert = fixtures::device_certificate(&device_a, nats_fp, now(), exp);
            let root_pk_bytes = device_a.root.public_key().to_bytes();
            let token = fixtures::no_cap_auth_token(&root_pk_bytes, &cert);
            let (opts, _events) = base_opts();
            let result = opts.nkey(session.seed()?).token(token).connect(&url).await;
            Ok((
                result.is_err(),
                match &result {
                    Err(e) => format!("connect() refused as expected: {e:#}"),
                    Ok(_) => {
                        "connect() unexpectedly SUCCEEDED for a no-cap presentation".to_string()
                    }
                },
            ))
        })
        .await;

    // ============================================================================================
    // (b)/(c) device A: member cap for host H only
    // ============================================================================================
    let cap_a_h = fixtures::member_capability(&host_h, device_a.root_fp, 0, exp, vec![0xA1]);
    let device_a_conn = connect_device(&url, &device_a, vec![cap_a_h], exp).await;

    match device_a_conn {
        Ok((client_a, events_a)) => {
            checks.record(
                "device_a_connects_with_member_cap_for_host_h",
                true,
                "device A connected presenting one member cap for host H",
            );

            // ---- ALLOW: pub host.<H>.connect (host H observes it via a fresh subscription --
            // deliberately not host_sub, so this check's proof doesn't depend on host_sub's
            // pre-existing subscription state). ----
            checks
                .run(
                    "device_a_can_pub_host_h_connect",
                    assert_pub_allowed(
                        &client_a,
                        &events_a,
                        &host_conn,
                        format!("host.{}.connect", host_h.host_fp),
                    ),
                )
                .await;

            // ---- ALLOW: sub own session h2c subject (host H publishes into it) ----
            let session_h2c = format!(
                "host.{}.sess.{}.ping.h2c",
                host_h.host_fp, device_a.device_fp
            );
            checks
                .run(
                    "device_a_can_sub_own_session_h2c",
                    assert_sub_allowed(
                        &client_a,
                        &events_a,
                        session_h2c.clone(),
                        &host_conn,
                        format!(
                            "host.{}.sess.{}.ping.h2c",
                            host_h.host_fp, device_a.device_fp
                        ),
                    ),
                )
                .await;

            // ---- ALLOW (weak -- see module docs): sub own presence subject. No connection in
            // this permission model (host_permissions grants no pub for host.<h>.presence -- a
            // pre-existing gap, see RESULTS.md) can publish a canary here, so this check can only
            // assert absence of a subscription-violation event. ----
            checks
                .run("device_a_can_sub_own_presence_weak", async {
                    let presence_subject = format!("host.{}.presence", host_h.host_fp);
                    let _sub = client_a.subscribe(presence_subject.clone()).await?;
                    client_a.flush().await?;
                    let violated = wait_for_violation(
                        &events_a,
                        &["Permissions Violation for Subscription", &presence_subject],
                        300,
                    )
                    .await;
                    Ok((
                        !violated,
                        "weak proof only: no canary publisher exists for host.<h>.presence in this permission model (see module docs); asserts absence of a violation event only".to_string(),
                    ))
                })
                .await;

            // ---- DENY: sub another device's inbox ----
            checks
                .run(
                    "device_a_cannot_sub_other_devices_inbox",
                    assert_sub_denied(
                        &client_a,
                        &events_a,
                        format!("_INBOX_{}.reply1", device_b.device_fp),
                        None, // nothing in this model has publish rights into another device's inbox
                    ),
                )
                .await;

            // ---- DENY: pub host.<H2>.connect (no cap for H2) ----
            checks
                .run(
                    "device_a_cannot_pub_host_h2_connect",
                    assert_pub_denied(
                        &client_a,
                        &events_a,
                        None,
                        format!("host.{}.connect", host_h2.host_fp),
                    ),
                )
                .await;

            // ---- DENY: sub host.<H2>.> (no cap for H2) ----
            checks
                .run(
                    "device_a_cannot_sub_host_h2_wildcard",
                    assert_sub_denied(
                        &client_a,
                        &events_a,
                        format!("host.{}.>", host_h2.host_fp),
                        None,
                    ),
                )
                .await;

            // ---- DENY: sub another client's session subject under the SAME host H ----
            checks
                .run(
                    "device_a_cannot_sub_other_clients_session",
                    assert_sub_denied(
                        &client_a,
                        &events_a,
                        format!(
                            "host.{}.sess.{}.ping.h2c",
                            host_h.host_fp, device_b.device_fp
                        ),
                        Some((
                            &host_conn,
                            format!(
                                "host.{}.sess.{}.ping.h2c",
                                host_h.host_fp, device_b.device_fp
                            ),
                        )),
                    ),
                )
                .await;

            // ---- DENY: pub $SYS.> ----
            checks
                .run(
                    "device_a_cannot_pub_sys",
                    assert_pub_denied(
                        &client_a,
                        &events_a,
                        None,
                        "$SYS.REQ.SERVER.PING".to_string(),
                    ),
                )
                .await;

            // ---- DENY: sub $JS.> ----
            checks
                .run(
                    "device_a_cannot_sub_js",
                    assert_sub_denied(&client_a, &events_a, "$JS.API.INFO".to_string(), None),
                )
                .await;

            // ========================================================================================
            // (d) reply-prefix bypass: host can only reply into a validated `_INBOX_<from_fp>.`
            // reply subject it actually received, `allow_responses{max:1}` -- a second reply (same
            // subject) or a reply to a different, never-granted subject must fail.
            // ========================================================================================
            // `host_sub` (subscribed way up front to the whole `host.<H>.>` wildcard, and still
            // needed later for the bridging check at the bottom of `main`) ALSO matches
            // `host.<H>.connect`. If it stays subscribed during this check, the server delivers
            // device A's request to host H TWICE -- once per matching subscription -- and each
            // delivery's "is this reply subject already allowed" bookkeeping call
            // (`pubAllowedFullCheck`, called with `fullCheck=true` as a side effect of deciding
            // whether to start tracking the reply) increments the SAME per-connection
            // `client.replies[reply].n` counter, since `allow_responses` budget is tracked once
            // per CONNECTION, not per subscription. That silently burns the `max:1` budget before
            // this check's own `host_conn.publish(reply_subject, "first")` ever runs, so the
            // first real reply is denied deterministically -- not a race, reproduces every run.
            // Root-caused by re-running the suite against a `-DV` (trace) nats-server and reading
            // the raw protocol log: two `MSG host.<H>.connect <sid> <reply> ...` frames (sid 1 and
            // sid 3) were delivered to host H's connection for the SAME publish (RESULTS.md).
            // Fix: temporarily unsubscribe `host_sub` for the duration of this check, then
            // re-subscribe a fresh one afterward for the later check that still needs it.
            host_sub.unsubscribe().await?;
            host_conn.flush().await?;
            tokio::time::sleep(Duration::from_millis(150)).await;

            checks
                .run("reply_prefix_bypass_suite", async {
                    let reply_subject = client_a.new_inbox();
                    if !reply_subject.starts_with(&format!("_INBOX_{}", device_a.device_fp)) {
                        anyhow::bail!(
                            "device A's custom inbox prefix did not take effect: got {reply_subject}"
                        );
                    }
                    let mut reply_sub = client_a.subscribe(reply_subject.clone()).await?;
                    client_a.flush().await?;
                    tokio::time::sleep(Duration::from_millis(150)).await;

                    // A fresh, dedicated subscription for this check -- deliberately NOT the
                    // long-lived `host_sub` (subscribed once, up front, to the whole `host.<H>.>`
                    // wildcard): earlier checks published several canary messages that also match
                    // that wildcard and were never drained from it (each of those checks used its
                    // own short-lived subscription instead), so reusing `host_sub` here risked
                    // picking up a stale canary (with `reply == None`) instead of this check's own
                    // request. A brand-new subscription only ever sees messages published after it
                    // is created, sidestepping that entirely.
                    let mut host_req_sub = host_conn
                        .subscribe(format!("host.{}.connect", host_h.host_fp))
                        .await?;
                    host_conn.flush().await?;
                    tokio::time::sleep(Duration::from_millis(150)).await;

                    // Device A sends a request-shaped message (explicit publish-with-reply, not
                    // client.request(), so this suite fully controls the reply subject and can
                    // reuse it for the second/denied attempt below).
                    client_a
                        .publish_with_reply(
                            format!("host.{}.connect", host_h.host_fp),
                            reply_subject.clone(),
                            "req".into(),
                        )
                        .await?;
                    client_a.flush().await?;

                    // Host H must have received it, with reply == reply_subject.
                    let Some(req_msg) = timeout(Duration::from_millis(1000), host_req_sub.next())
                        .await
                        .ok()
                        .flatten()
                    else {
                        anyhow::bail!("host H never received device A's request on host.<H>.connect");
                    };
                    if req_msg.reply.as_deref() != Some(reply_subject.as_str()) {
                        anyhow::bail!(
                            "host H's received reply-to ({:?}) did not match device A's custom-prefixed inbox ({reply_subject})",
                            req_msg.reply
                        );
                    }

                    // First reply: allow_responses should grant this one-off publish into
                    // reply_subject even though host H has no static pub-allow entry matching
                    // `_INBOX_*` (universal_denies' `_INBOX.>` deny does NOT match
                    // `_INBOX_<fp>.>` -- different first subject token -- but there is also no
                    // explicit ALLOW for it; allow_responses is the only path).
                    host_conn.publish(reply_subject.clone(), "first".into()).await?;
                    host_conn.flush().await?;
                    let first_delivery = timeout(Duration::from_millis(1000), reply_sub.next()).await;
                    let first_ok = matches!(
                        &first_delivery,
                        Ok(Some(m)) if m.payload.as_ref() == b"first"
                    );

                    // Second reply to the SAME subject: max:1 already consumed -> must fail.
                    let _ = host_conn.publish(reply_subject.clone(), "second".into()).await;
                    let _ = host_conn.flush().await;
                    let second_violated = wait_for_violation(
                        &host_events,
                        &["Permissions Violation for Publish", &reply_subject],
                        800,
                    )
                    .await;
                    let second_delivered = matches!(
                        timeout(Duration::from_millis(300), reply_sub.next()).await,
                        Ok(Some(ref m)) if m.payload.as_ref() == b"second"
                    );

                    // Reply to a DIFFERENT subject that was never granted via allow_responses at
                    // all -- must also fail.
                    let bogus_subject = format!("_INBOX_{}.never-granted", device_a.device_fp);
                    let mut bogus_sub = client_a.subscribe(bogus_subject.clone()).await?;
                    client_a.flush().await?;
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    let _ = host_conn.publish(bogus_subject.clone(), "bogus".into()).await;
                    let _ = host_conn.flush().await;
                    let bogus_violated = wait_for_violation(
                        &host_events,
                        &["Permissions Violation for Publish", &bogus_subject],
                        800,
                    )
                    .await;
                    let bogus_delivered = matches!(
                        timeout(Duration::from_millis(300), bogus_sub.next()).await,
                        Ok(Some(ref m)) if m.payload.as_ref() == b"bogus"
                    );

                    let passed = first_ok
                        && second_violated
                        && !second_delivered
                        && bogus_violated
                        && !bogus_delivered;
                    Ok((
                        passed,
                        format!(
                            "first_ok={first_ok} second_violated={second_violated} second_delivered={second_delivered} bogus_violated={bogus_violated} bogus_delivered={bogus_delivered}"
                        ),
                    ))
                })
                .await;

            // Re-subscribe `host_sub` (unsubscribed above for the duration of
            // `reply_prefix_bypass_suite`) as a fresh subscription for the bridging check near the
            // end of `main`, which still needs an active `host.<H>.>` listener.
            host_sub = host_conn
                .subscribe(format!("host.{}.>", host_h.host_fp))
                .await?;
            host_conn.flush().await?;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        Err(e) => {
            checks.record(
                "device_a_connects_with_member_cap_for_host_h",
                false,
                format!("{e:#}"),
            );
            checks.record(
                "device_a_dependent_checks",
                false,
                "skipped: device A failed to connect",
            );
        }
    }

    // ============================================================================================
    // (e) invite-only connection: connect-only permissions (connect works, everything else denied)
    // ============================================================================================
    let cap_c_invite = fixtures::invite_capability(&host_h, device_c.root_fp, exp, vec![0xC1]);
    match connect_device(&url, &device_c, vec![cap_c_invite], exp).await {
        Ok((client_c, events_c)) => {
            checks.record(
                "invite_only_device_c_connects",
                true,
                "device C connected presenting a single invite cap for host H",
            );

            checks
                .run(
                    "invite_only_can_pub_host_h_connect",
                    assert_pub_allowed(
                        &client_c,
                        &events_c,
                        &host_conn,
                        format!("host.{}.connect", host_h.host_fp),
                    ),
                )
                .await;

            checks
                .run(
                    "invite_only_cannot_pub_helper_presence_get",
                    assert_pub_denied(
                        &client_c,
                        &events_c,
                        None,
                        "helper.presence.get".to_string(),
                    ),
                )
                .await;

            checks
                .run(
                    "invite_only_cannot_sub_host_presence",
                    assert_sub_denied(
                        &client_c,
                        &events_c,
                        format!("host.{}.presence", host_h.host_fp),
                        None,
                    ),
                )
                .await;

            checks
                .run(
                    "invite_only_cannot_pub_session_c2h",
                    assert_pub_denied(
                        &client_c,
                        &events_c,
                        None,
                        format!(
                            "host.{}.sess.{}.ping.c2h",
                            host_h.host_fp, device_c.device_fp
                        ),
                    ),
                )
                .await;
        }
        Err(e) => {
            checks.record("invite_only_device_c_connects", false, format!("{e:#}"));
            checks.record(
                "invite_only_dependent_checks",
                false,
                "skipped: device C failed to connect",
            );
        }
    }

    // ============================================================================================
    // Helper two-connection bridging finding (DESIGN.md §A5 [DEFAULT], ADR-002 "finalize in S1"):
    // can the callout responder's own AUTH-account connection reach an APP-account subject
    // (host.<h>.presence) at all? If CALLOUT_USER_SEED is provided (run.sh always sets it), this
    // opens a second connection as that same identity and checks whether it can publish into an
    // APP-account subject that host H (a real APP-account connection) is listening on.
    // ============================================================================================
    match env::var("CALLOUT_USER_SEED") {
        Ok(callout_seed) => {
            checks
                .run("bridging_callout_account_cannot_reach_app_subjects", async {
                    let (opts, _events) = base_opts();
                    let callout_client = opts.nkey(callout_seed).connect(&url).await?;
                    let subject = format!("host.{}.presence", host_h.host_fp);
                    let marker = format!("s1-bridge-canary-{}", rand::random::<u64>());
                    // This publish is expected to be entirely INVISIBLE to host_sub: AUTH and APP
                    // are separate accounts in server.conf with no import/export configured, so
                    // account-level isolation -- not a permission-list deny -- is what should stop
                    // this, if it is stopped at all.
                    let pub_result = callout_client.publish(subject.clone(), marker.clone().into()).await;
                    let _ = callout_client.flush().await;
                    let received = timeout(Duration::from_millis(500), host_sub.next()).await;
                    let reached = matches!(
                        &received,
                        Ok(Some(m)) if m.payload.as_ref() == marker.as_bytes()
                    );
                    Ok((
                        !reached,
                        format!(
                            "publish_from_auth_account_result={:?} reached_app_account_subscriber={reached} -- see RESULTS.md 'bridging finding'",
                            pub_result.is_ok()
                        ),
                    ))
                })
                .await;
        }
        Err(_) => {
            // Not recorded as a checks-list entry at all (so it can never fail the suite by
            // itself): run.sh always exports CALLOUT_USER_SEED for this binary, so reaching here
            // only happens when s1-tests is invoked directly without it.
            println!("[SKIP] bridging_callout_account_cannot_reach_app_subjects -- CALLOUT_USER_SEED not set");
        }
    }

    print_summary(&checks);
    if checks.all_passed() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}

fn print_summary(checks: &Checks) {
    let total = checks.results.len();
    let passed = checks.results.iter().filter(|(_, p, _)| *p).count();
    println!("\n==== S1 suite summary: {passed}/{total} checks passed ====");
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
