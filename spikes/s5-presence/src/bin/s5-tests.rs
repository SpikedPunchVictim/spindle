//! S5 live validation harness (docs/SPIKES.md §S5; docs/DESIGN.md §A3/§A6) — drives the *actual*
//! `spindle-helper` binary running inside the composed reference deployment
//! (`deploy/docker-compose.yml`), over the same NATS port a real host daemon or client app would
//! use. Unlike S1 (which stood up its own throwaway `nats-server` + in-process responder), this
//! spike treats the compose stack as a black box: every check here is something an unmodified
//! host/client could observe for itself (a `helper.presence.get.<nfp>` reply, a
//! `host.<hfp>.presence` delta, a NATS permission violation) — see RESULTS.md for the full
//! writeup and measured numbers.
//!
//! # Why a fake host is a separate OS process
//! Scenario (d) (dead socket) needs a connection whose TCP socket stays open with **no FIN**
//! while the application behind it cannot respond to NATS `PING`s — the exact failure
//! `ping_interval`/`ping_max` server-side timeout detection exists for (DESIGN.md §A6). The only
//! way to produce that condition without root/network-namespace tricks is to freeze a real OS
//! process with `SIGSTOP`: the kernel suspends its scheduling entirely but does not (and cannot)
//! touch its already-open file descriptors. That requires the host connection to live in its own
//! process — `src/bin/fake_host.rs` — which this harness spawns, waits for a `READY <host_fp>`
//! line from, and controls via `kill -SIG<n>`.
//!
//! # `host_fp` root/operating-key convergence workaround
//! Inherited verbatim from `spike_s1_callout::fixtures`' own flagged workaround (see that
//! module's doc comment and `spikes/s1-callout/RESULTS.md`'s "host_fp inconsistency" finding):
//! `decide_host_connect` derives `host_fp` from the host's ROOT key, but `issue_capability`
//! derives the `host_fp` it embeds from the host's OPERATING key. Every test host below is
//! constructed with `root_seed == op_seed` so both computations converge on the same value —
//! this is a pre-existing, out-of-scope bug (not something S5 patches), carried forward exactly
//! as S1 left it.
//!
//! # Env vars
//! - `NATS_URL` — default `nats://127.0.0.1:4222` (the compose stack's published TCP listener).
//! - `DEPLOY_COMPOSE_FILE` — default `<repo>/deploy/docker-compose.yml`, used only for the
//!   scenario (f) `docker compose restart helper` call.

use futures_util::StreamExt;
use nkeys::KeyPair;
use spike_s1_callout::fixtures;
use spindle_core::Fingerprint;
use spindle_proto::artifacts::Capability;
use std::process::{ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

type EventLog = Arc<Mutex<Vec<String>>>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Mirrors `spike_s1_callout::src/bin/s1-tests.rs`'s `base_opts` — an `event_callback`-wired
/// `ConnectOptions` whose observed `Event`s (including async permission-violation `-ERR`s) land
/// in a shared, lock-guarded log this suite can poll.
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

/// Connects a device holding `caps`, using a fresh session nkey — mirrors
/// `spike_s1_callout::src/bin/s1-tests.rs`'s private `connect_device` (copied, not imported: that
/// binary's helpers aren't part of the spike's `lib.rs`, only `fixtures`/`natsjwt` are — see this
/// crate's `Cargo.toml` header comment).
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

/// Sends one `helper.presence.get.<nfp>` request and parses the JSON reply.
async fn presence_get(
    client: &async_nats::Client,
    nats_fp: Fingerprint,
) -> anyhow::Result<serde_json::Value> {
    let subject = format!("helper.presence.get.{nats_fp}");
    let reply = timeout(
        Duration::from_secs(3),
        client.request(subject, Vec::new().into()),
    )
    .await??;
    Ok(serde_json::from_slice(&reply.payload)?)
}

/// Retries [`presence_get`] until it succeeds and passes `want`, or `budget` elapses — used after
/// restarting the `helper` container (scenario f), where requests simply time out until it's back
/// up and its `helper.presence.get.*` subscription is re-established.
async fn presence_get_until(
    client: &async_nats::Client,
    nats_fp: Fingerprint,
    want: impl Fn(&serde_json::Value) -> bool,
    budget: Duration,
) -> anyhow::Result<serde_json::Value> {
    let deadline = Instant::now() + budget;
    let mut last_err = None;
    loop {
        if Instant::now() >= deadline {
            return Err(match last_err {
                Some(e) => anyhow::anyhow!("presence_get_until timed out; last error: {e:#}"),
                None => anyhow::anyhow!("presence_get_until timed out with no successful reply"),
            });
        }
        match presence_get(client, nats_fp).await {
            Ok(v) if want(&v) => return Ok(v),
            Ok(v) => last_err = Some(anyhow::anyhow!("reply did not match: {v}")),
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Polls `sub` (up to `budget`) for a `host.<hfp>.presence` delta whose `state` equals
/// `want_state`, returning `(elapsed_since_call, parsed_delta)`. `elapsed` is measured from this
/// function's own entry, so callers should invoke it immediately after triggering the state
/// change they're timing (matching S5's "time until the device sees the ... delta" bar).
async fn wait_for_delta_state(
    sub: &mut async_nats::Subscriber,
    want_state: &str,
    budget: Duration,
) -> Option<(Duration, serde_json::Value)> {
    let t0 = Instant::now();
    let deadline = t0 + budget;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match timeout(remaining, sub.next()).await {
            Ok(Some(msg)) => {
                let Ok(v) = serde_json::from_slice::<serde_json::Value>(&msg.payload) else {
                    continue;
                };
                if v.get("state").and_then(|s| s.as_str()) == Some(want_state) {
                    return Some((t0.elapsed(), v));
                }
                // A delta for a different state (e.g. a stray "online" while we're waiting for
                // "offline") is not what we're waiting for — keep polling within budget.
            }
            _ => return None,
        }
    }
}

/// Asserts no `host.<hfp>.presence` delta of ANY state arrives within `budget` — the "no flip"
/// half of the overlap checks (scenario e).
async fn assert_no_delta(
    sub: &mut async_nats::Subscriber,
    budget: Duration,
) -> Option<serde_json::Value> {
    match timeout(budget, sub.next()).await {
        Ok(Some(msg)) => serde_json::from_slice::<serde_json::Value>(&msg.payload).ok(),
        _ => None,
    }
}

// ================================================================================================
// Fake-host process control
// ================================================================================================

fn fake_host_bin_path() -> anyhow::Result<std::path::PathBuf> {
    let mut p = std::env::current_exe()?;
    p.pop(); // drop the "s5-tests" file name, keep the containing target/{debug,release} dir
    p.push("fake_host");
    anyhow::ensure!(
        p.exists(),
        "fake_host binary not found at {p:?} — build it alongside s5-tests"
    );
    Ok(p)
}

struct FakeHost {
    #[allow(dead_code)] // kept alive so the process isn't reaped; lifecycle is signal-driven
    child: Child,
    pid: u32,
}

/// Spawns `fake_host` with the given host identity seeds, waits (bounded) for its `READY
/// <host_fp>` line, and returns the child handle (still running) plus the `host_fp` it reported.
async fn spawn_fake_host(
    url: &str,
    root_seed: &[u8; 32],
    op_seed: &[u8; 32],
) -> anyhow::Result<(FakeHost, String)> {
    let bin = fake_host_bin_path()?;
    let mut child = Command::new(bin)
        .env("NATS_URL", url)
        .env("ROOT_SEED_HEX", hex32(root_seed))
        .env("OP_SEED_HEX", hex32(op_seed))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(false) // we control its lifecycle explicitly via signals, not Drop
        .spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow::anyhow!("fake_host exited before reporting a pid"))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let mut lines = BufReader::new(stdout).lines();
    let line = timeout(Duration::from_secs(10), lines.next_line())
        .await
        .map_err(|_| anyhow::anyhow!("fake_host did not print READY within 10s"))??
        .ok_or_else(|| anyhow::anyhow!("fake_host closed stdout without printing READY"))?;
    let host_fp = line
        .strip_prefix("READY ")
        .ok_or_else(|| {
            anyhow::anyhow!("fake_host's first line was not 'READY <host_fp>': {line:?}")
        })?
        .to_string();
    Ok((FakeHost { child, pid }, host_fp))
}

fn signal(pid: u32, sig: &str) -> anyhow::Result<()> {
    let status = std::process::Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status()?;
    anyhow::ensure!(status.success(), "kill -{sig} {pid} exited non-zero");
    Ok(())
}

// ================================================================================================
// Checks bookkeeping — mirrors spike-s1-callout's src/bin/s1-tests.rs `Checks`.
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

fn print_summary(checks: &Checks) {
    let total = checks.results.len();
    let passed = checks.results.iter().filter(|(_, p, _)| *p).count();
    println!("\n==== S5 suite summary: {passed}/{total} checks passed ====");
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
// main
// ================================================================================================

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let compose_file = std::env::var("DEPLOY_COMPOSE_FILE").unwrap_or_else(|_| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/docker-compose.yml")
            .to_string_lossy()
            .into_owned()
    });
    let exp = now() + 3600;
    let mut checks = Checks::new();
    let mut all_pids: Vec<u32> = Vec::new(); // best-effort cleanup at the very end

    let host_seed = [0xA5u8; 32]; // root_seed == op_seed, see module doc's convergence workaround
    let device_a = fixtures::new_device_identity([0xB0; 32], [0xB1; 32], [0xB2; 32]);
    let device_b = fixtures::new_device_identity([0xC0; 32], [0xC1; 32], [0xC2; 32]);
    let host_identity = fixtures::new_host_identity(host_seed, host_seed);
    let host_fp_str = host_identity.host_fp.to_string();

    // ============================================================================================
    // (a) fake host connects through the callout
    // ============================================================================================
    let fh1 = match spawn_fake_host(&url, &host_seed, &host_seed).await {
        Ok((fh, reported_fp)) => {
            checks.record(
                "a_fake_host_connects",
                reported_fp == host_fp_str,
                format!("reported host_fp={reported_fp} expected={host_fp_str}"),
            );
            fh
        }
        Err(e) => {
            checks.record("a_fake_host_connects", false, format!("{e:#}"));
            checks.record(
                "suite_aborted",
                false,
                "fake host failed to connect at all -- aborting",
            );
            print_summary(&checks);
            return Ok(ExitCode::FAILURE);
        }
    };
    all_pids.push(fh1.pid);
    let fh1_pid = fh1.pid;

    // ============================================================================================
    // (b) device connects with a member cap, subscribes host.<hfp>.presence, requests
    // helper.presence.get.<own_nfp> -- expect {ok:true, hosts:[{host_fp, state:"online", ...}]}.
    // Also the A12 #46 negative test: device A cannot publish on device B's own
    // helper.presence.get.<nfp> subject.
    // ============================================================================================
    let cap_a = fixtures::member_capability(&host_identity, device_a.root_fp, 0, exp, vec![0xA1]);
    let (client_a, events_a, nats_fp_a) = connect_device(&url, &device_a, vec![cap_a], exp).await?;
    checks.record(
        "b_device_a_connects_with_member_cap",
        true,
        format!("nats_fp={nats_fp_a}"),
    );

    let mut presence_sub = client_a
        .subscribe(format!("host.{}.presence", host_identity.host_fp))
        .await?;
    client_a.flush().await?;
    tokio::time::sleep(Duration::from_millis(200)).await; // let the sub land server-side

    checks
        .run("b_presence_get_reports_online", async {
            let reply = presence_get(&client_a, nats_fp_a).await?;
            let ok = reply.get("ok").and_then(|v| v.as_bool()) == Some(true);
            let hosts = reply
                .get("hosts")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let entry = hosts
                .iter()
                .find(|h| h.get("host_fp").and_then(|v| v.as_str()) == Some(host_fp_str.as_str()));
            let online =
                entry.and_then(|e| e.get("state")).and_then(|v| v.as_str()) == Some("online");
            Ok((ok && online, format!("reply={reply}")))
        })
        .await;

    // A second device, so there's a real, distinct nats_fp to attempt the cross-session publish
    // against. It needs no cap at all for this check (only its *nats_fp*, hence its granted
    // subject name, matters) but giving it a real member cap keeps this a realistic full
    // connection rather than a connect-only stub.
    let cap_b = fixtures::member_capability(&host_identity, device_b.root_fp, 0, exp, vec![0xB1]);
    let (client_b, _events_b, nats_fp_b) =
        connect_device(&url, &device_b, vec![cap_b], exp).await?;
    checks.record(
        "b_device_b_connects_for_negative_test",
        true,
        format!("nats_fp={nats_fp_b}"),
    );

    checks
        .run("b_cross_session_presence_get_publish_denied", async {
            // Device A attempts to publish on Device B's own granted presence.get subject --
            // A12 #46's scoping property, the presence.get analog of the helper.turn.get.<nfp>
            // scoping the unit suite (permissions.rs) already covers in-process. `publish()`
            // itself returns Ok even when the server will refuse it server-side (nats-server
            // reports denials as an async protocol -ERR on the offending connection, not a
            // synchronous error from the call that attempted it -- see
            // spike-s1-callout/src/bin/s1-tests.rs's module doc for the empirical basis).
            let foreign_subject = format!("helper.presence.get.{nats_fp_b}");
            let _ = client_a
                .publish(foreign_subject.clone(), Vec::new().into())
                .await;
            let _ = client_a.flush().await;
            let violated = wait_for_violation(
                &events_a,
                &["Permissions Violation for Publish", &foreign_subject],
                800,
            )
            .await;
            Ok((
                violated,
                format!("violation_seen={violated} subject={foreign_subject}"),
            ))
        })
        .await;

    // ============================================================================================
    // (c) clean disconnect: measure time to the offline delta and re-query presence.get.
    // ============================================================================================
    let clean_t0 = Instant::now();
    signal(fh1_pid, "TERM")?;
    match wait_for_delta_state(&mut presence_sub, "offline", Duration::from_secs(15)).await {
        Some((elapsed, delta)) => {
            checks.record(
                "c_clean_disconnect_delta_within_5s",
                elapsed <= Duration::from_secs(5),
                format!("elapsed={:.2}s delta={delta}", elapsed.as_secs_f64()),
            );
        }
        None => {
            checks.record(
                "c_clean_disconnect_delta_within_5s",
                false,
                "no offline delta observed within 15s",
            );
        }
    }
    let _ = clean_t0; // elapsed is measured inside wait_for_delta_state; kept for RESULTS.md math

    checks
        .run("c_clean_disconnect_requery_reports_offline", async {
            let reply = presence_get(&client_a, nats_fp_a).await?;
            let hosts = reply
                .get("hosts")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let entry = hosts
                .iter()
                .find(|h| h.get("host_fp").and_then(|v| v.as_str()) == Some(host_fp_str.as_str()));
            let offline =
                entry.and_then(|e| e.get("state")).and_then(|v| v.as_str()) == Some("offline");
            let has_last_seen = entry
                .and_then(|e| e.get("last_seen"))
                .map(|v| !v.is_null())
                .unwrap_or(false);
            Ok((offline && has_last_seen, format!("reply={reply}")))
        })
        .await;

    // ============================================================================================
    // (d) dead socket: reconnect the host, SIGSTOP it, measure time to the offline delta.
    // ============================================================================================
    let (fh2, fh2_fp) = spawn_fake_host(&url, &host_seed, &host_seed).await?;
    all_pids.push(fh2.pid);
    checks.record(
        "d_host_reconnects",
        fh2_fp == host_fp_str,
        format!("reported host_fp={fh2_fp}"),
    );
    match wait_for_delta_state(&mut presence_sub, "online", Duration::from_secs(10)).await {
        Some((elapsed, _)) => checks.record(
            "d_reconnect_delta_reports_online",
            true,
            format!("elapsed={:.2}s", elapsed.as_secs_f64()),
        ),
        None => checks.record(
            "d_reconnect_delta_reports_online",
            false,
            "no online delta observed within 10s",
        ),
    }

    let dead_t0 = Instant::now();
    signal(fh2.pid, "STOP")?;
    let dead_result =
        wait_for_delta_state(&mut presence_sub, "offline", Duration::from_secs(90)).await;
    let _ = dead_t0;
    match dead_result {
        Some((elapsed, delta)) => {
            checks.record(
                "d_dead_socket_delta_within_60s",
                elapsed <= Duration::from_secs(60),
                format!("elapsed={:.2}s delta={delta}", elapsed.as_secs_f64()),
            );
        }
        None => {
            checks.record(
                "d_dead_socket_delta_within_60s",
                false,
                "no offline delta observed within 90s",
            );
        }
    }
    // SIGCONT before SIGKILL: a SIGKILL delivered to a stopped process is itself queued but not
    // guaranteed to act identically across platforms until the process is resumable; thawing
    // first keeps cleanup deterministic (task instruction: "SIGCONT/kill the child after").
    let _ = signal(fh2.pid, "CONT");
    let _ = signal(fh2.pid, "KILL");

    // ============================================================================================
    // (e) overlap semantics: two live connections for the same host_fp; dropping one must never
    // flip presence offline; a fresh connect-before-the-old-one's-disconnect ordering likewise
    // never flips offline.
    // ============================================================================================
    let (fh3, _) = spawn_fake_host(&url, &host_seed, &host_seed).await?;
    all_pids.push(fh3.pid);
    let _ = wait_for_delta_state(&mut presence_sub, "online", Duration::from_secs(10)).await; // baseline reconnect

    let (fh4, _) = spawn_fake_host(&url, &host_seed, &host_seed).await?;
    all_pids.push(fh4.pid);
    // fh3 and fh4 are now two independent, live connections for the same host_fp (connection
    // count == 2, DESIGN.md §A6's "presence is by connection count, not a boolean").
    let no_flip_on_second_connect =
        assert_no_delta(&mut presence_sub, Duration::from_secs(2)).await;
    checks.record(
        "e_second_concurrent_connect_does_not_re_flip_online",
        no_flip_on_second_connect.is_none(),
        format!("unexpected delta on 2nd connect: {no_flip_on_second_connect:?}"),
    );

    signal(fh3.pid, "TERM")?;
    let flip_after_dropping_one_of_two =
        assert_no_delta(&mut presence_sub, Duration::from_secs(3)).await;
    checks
        .run("e_drop_one_of_two_connections_keeps_online", async {
            let reply = presence_get(&client_a, nats_fp_a).await?;
            let hosts = reply
                .get("hosts")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let entry = hosts
                .iter()
                .find(|h| h.get("host_fp").and_then(|v| v.as_str()) == Some(host_fp_str.as_str()));
            let still_online =
                entry.and_then(|e| e.get("state")).and_then(|v| v.as_str()) == Some("online");
            Ok((
                still_online && flip_after_dropping_one_of_two.is_none(),
                format!("reply={reply} unexpected_delta={flip_after_dropping_one_of_two:?}"),
            ))
        })
        .await;

    // Reconnect-before-stale-disconnect, by explicit construction: fh5 CONNECTs (count 1 -> 2)
    // strictly before fh4 (the "stale" connection) is torn down (count 2 -> 1) -- at no point
    // does the live count reach zero, so no offline flip should ever be observable in between.
    let (fh5, _) = spawn_fake_host(&url, &host_seed, &host_seed).await?;
    all_pids.push(fh5.pid);
    let no_flip_on_reconnect = assert_no_delta(&mut presence_sub, Duration::from_secs(2)).await;
    signal(fh4.pid, "TERM")?;
    let no_flip_after_stale_disconnect =
        assert_no_delta(&mut presence_sub, Duration::from_secs(3)).await;
    checks.record(
        "e_reconnect_before_stale_disconnect_never_flips_offline",
        no_flip_on_reconnect.is_none() && no_flip_after_stale_disconnect.is_none(),
        format!(
            "delta_on_reconnect={no_flip_on_reconnect:?} delta_after_stale_disconnect={no_flip_after_stale_disconnect:?}"
        ),
    );

    // Clean up fh5 (the sole remaining live connection) before moving on, and confirm presence
    // settles back to offline -- a sanity check, not a scored one, that also gives scenario (f) a
    // clean "was online, now let's make it online again via a fresh connection" starting point.
    signal(fh5.pid, "TERM")?;
    let _ = wait_for_delta_state(&mut presence_sub, "offline", Duration::from_secs(15)).await;

    // ============================================================================================
    // (f) CONNZ seeding across a helper restart: bring the host online, restart the `helper`
    // container, and confirm presence.get still reports it online once the helper is back --
    // validating the CONNZ-fold + durable-session-record host_fp resolution heuristic
    // (bin/helper.rs's `seed_presence_map`) against a REAL restart, not a unit-test double.
    // ============================================================================================
    let (fh6, _) = spawn_fake_host(&url, &host_seed, &host_seed).await?;
    all_pids.push(fh6.pid);
    let _ = wait_for_delta_state(&mut presence_sub, "online", Duration::from_secs(10)).await;

    checks
        .run("f_restart_helper_container", async {
            let status = tokio::process::Command::new("docker")
                .args(["compose", "-f", &compose_file, "restart", "helper"])
                .status()
                .await?;
            Ok((
                status.success(),
                format!("docker compose restart helper exit={status}"),
            ))
        })
        .await;

    checks
        .run("f_connz_reseed_reports_online_after_restart", async {
            let reply = presence_get_until(
                &client_a,
                nats_fp_a,
                |v| {
                    v.get("hosts")
                        .and_then(|h| h.as_array())
                        .map(|hosts| {
                            hosts.iter().any(|h| {
                                h.get("host_fp").and_then(|v| v.as_str())
                                    == Some(host_fp_str.as_str())
                                    && h.get("state").and_then(|v| v.as_str()) == Some("online")
                            })
                        })
                        .unwrap_or(false)
                },
                Duration::from_secs(30),
            )
            .await?;
            Ok((true, format!("reply={reply}")))
        })
        .await;

    // ============================================================================================
    // Cleanup: kill every fake_host we ever spawned (best-effort; several are already dead).
    // ============================================================================================
    let _ = client_b; // keep alive until here so its NATS session doesn't churn the CONNECT/DISCONNECT log mid-suite
    for pid in all_pids {
        let _ = signal(pid, "CONT"); // harmless if already running; required if still stopped
        let _ = signal(pid, "KILL");
    }

    print_summary(&checks);
    if checks.all_passed() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::FAILURE)
    }
}
