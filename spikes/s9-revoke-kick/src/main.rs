//! S9 (docs/DESIGN.md §A4, "kicks live connections via `$SYS.REQ.SERVER.<id>.KICK {id: cid}`") —
//! throwaway empirical probe, narrow scope: settle the mechanics of the nats-server KICK admin
//! request against the LIVE composed stack (`deploy/docker-compose.yml`). This is NOT the full S9
//! revoke->kick->reject timing run (that is later work) and it is NOT production code — every
//! answer below comes from a captured live response, printed verbatim, never from general
//! knowledge or documentation recollection.
//!
//! Two facts this probe exists to settle empirically (see spikes/s9-revoke-kick/RESULTS.md for
//! the full method and captured evidence):
//!   1. Where the server id actually lives (spikes/s5-presence/RESULTS.md elided the CONNECT
//!      advisory's `server` object as `{"...": "..."}` — genuinely unknown before this spike).
//!   2. The KICK request's exact subject form(s), payload field name, and reply shape — including
//!      whether the broadcast form `$SYS.REQ.SERVER.PING.KICK` works, and proof (a real
//!      `$SYS.ACCOUNT.*.DISCONNECT` advisory or an observed connection-state flip) that a
//!      non-error reply actually corresponds to the target connection dropping. A reply saying OK
//!      while the connection stays up is exactly the false-green this project treats as a
//!      severity-zero bug class (see docs root CLAUDE-adjacent process notes / this spike's own
//!      RESULTS.md).
//!
//! Credentials are the dev-only throwaway seeds already embedded in `deploy/docker-compose.yml`
//! (SYS_CONN_SEED / APP_CONN_SEED) — same pattern `crates/spindle-helper/src/bin/helper.rs` uses
//! for its own `sys_client`/`app_client` (`async_nats::ConnectOptions::with_nkey`).

use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use serde_json::{json, Value};

const NATS_URL: &str = "nats://localhost:4222";

// Dev-only throwaway seeds from deploy/docker-compose.yml — never used outside this local stack.
const SYS_CONN_SEED: &str = "SUAJNND3A4EBPOPMXASJCSIAPEFJROE7JFVDDZMLN2WEP3OPTNQSLMBO6A";
const APP_CONN_SEED: &str = "SUAFWWQRCTGQTS6DKVAJKMMFMIJKFZ3MRFGFQ4WCRZ5RVZ5WFRB4CXPYBY";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const DISCONNECT_WATCH_TIMEOUT: Duration = Duration::from_secs(5);

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

fn hr(title: &str) {
    println!("\n============================================================");
    println!("{title}");
    println!("============================================================");
}

/// A captured application connection: the live `async_nats::Client` plus the `cid` and `server`
/// object taken from its own real `$SYS.ACCOUNT.*.CONNECT` advisory.
struct CapturedConn {
    client: async_nats::Client,
    cid: i64,
}

/// Opens a new APP-seed connection and waits for the matching `$SYS.ACCOUNT.*.CONNECT` advisory
/// on `connect_sub`, printing the full raw JSON verbatim (server object fully expanded, nothing
/// elided — closing the gap left by spikes/s5-presence's `{ "...": "..." }` capture).
async fn open_app_conn_and_capture(
    connect_sub: &mut async_nats::Subscriber,
    label: &str,
) -> Result<(CapturedConn, Value)> {
    let client = async_nats::ConnectOptions::with_nkey(APP_CONN_SEED.to_string())
        .event_callback(|event| async move {
            println!("[nats client event] {event}");
        })
        .connect(NATS_URL)
        .await
        .context("connecting APP-seed client")?;
    println!("[{label}] APP connection opened");

    let msg = tokio::time::timeout(REQUEST_TIMEOUT, connect_sub.next())
        .await
        .context("timed out waiting for $SYS.ACCOUNT.*.CONNECT advisory")?
        .context("connect_sub stream ended unexpectedly")?;

    println!(
        "[{label}] captured CONNECT advisory on subject '{}'",
        msg.subject
    );
    let value: Value = serde_json::from_slice(&msg.payload)
        .context("CONNECT advisory payload was not valid JSON")?;
    println!("[{label}] FULL CONNECT EVENT (verbatim, server object fully expanded):");
    println!("{}", pretty(&value));

    let cid = value
        .get("client")
        .and_then(|c| c.get("id"))
        .and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow::anyhow!("CONNECT advisory had no client.id"))?;
    println!("[{label}] resolved cid = {cid}");

    Ok((CapturedConn { client, cid }, value))
}

/// Sends a JSON request on `client` and returns the raw reply bytes plus (if parseable) the
/// parsed JSON value. Never panics on a non-JSON or error reply — those are evidence, not
/// failures of the probe.
async fn send_request(
    client: &async_nats::Client,
    subject: &str,
    payload: &Value,
) -> Result<(Vec<u8>, Option<Value>), String> {
    let bytes = serde_json::to_vec(payload).expect("json! value always serializes");
    match tokio::time::timeout(
        REQUEST_TIMEOUT,
        client.request(subject.to_string(), bytes.into()),
    )
    .await
    {
        Ok(Ok(reply)) => {
            let parsed = serde_json::from_slice::<Value>(&reply.payload).ok();
            Ok((reply.payload.to_vec(), parsed))
        }
        Ok(Err(e)) => Err(format!("request error: {e}")),
        Err(_) => Err("request TIMED OUT — no reply received".to_string()),
    }
}

/// Best-effort extraction of a server id from a CONNZ-shaped reply, trying every plausible JSON
/// path and reporting which one actually matched (never guessed — only reported if observed).
fn extract_server_id(v: &Value) -> Option<(&'static str, String)> {
    if let Some(id) = v
        .get("server")
        .and_then(|s| s.get("id"))
        .and_then(|x| x.as_str())
    {
        return Some(("server.id", id.to_string()));
    }
    if let Some(id) = v
        .get("data")
        .and_then(|d| d.get("server_id"))
        .and_then(|x| x.as_str())
    {
        return Some(("data.server_id", id.to_string()));
    }
    if let Some(id) = v.get("server_id").and_then(|x| x.as_str()) {
        return Some(("server_id", id.to_string()));
    }
    None
}

/// Watches `disconnect_sub` for up to `timeout` for a `$SYS.ACCOUNT.*.DISCONNECT` advisory whose
/// `client.id` matches `target_cid`. Any non-matching advisory observed along the way is printed
/// too (it's real evidence, not noise) but does not satisfy the wait.
async fn wait_for_disconnect(
    disconnect_sub: &mut async_nats::Subscriber,
    target_cid: i64,
    timeout: Duration,
) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let msg = match tokio::time::timeout(remaining, disconnect_sub.next()).await {
            Ok(Some(m)) => m,
            Ok(None) | Err(_) => return None,
        };
        let Ok(value) = serde_json::from_slice::<Value>(&msg.payload) else {
            continue;
        };
        let cid = value
            .get("client")
            .and_then(|c| c.get("id"))
            .and_then(|v| v.as_i64());
        println!(
            "[disconnect-watch] observed DISCONNECT advisory (client.id={:?}) on '{}':",
            cid, msg.subject
        );
        println!("{}", pretty(&value));
        if cid == Some(target_cid) {
            return Some(value);
        }
    }
}

struct KickAttempt {
    label: &'static str,
    subject: String,
    payload: Value,
    /// Guard-against-regression expectation: does this (subject, payload) combination land an
    /// actual server-side KICK on the target connection? Compared against the observed outcome
    /// (a DISCONNECT advisory whose top-level `reason` is exactly `"Kicked"`) at the end of the
    /// run, and drives that attempt's PASS/FAIL line plus the process exit code.
    expected_kicked: bool,
}

struct KickOutcome {
    label: &'static str,
    subject: String,
    payload: Value,
    reply_raw: Option<String>,
    reply_parsed: Option<Value>,
    request_error: Option<String>,
    disconnect_evidence: Option<Value>,
    /// The captured DISCONNECT advisory's top-level `reason` field, if any advisory for this cid
    /// was observed. This is the ONLY thing that may set `kicked` — see RESULTS.md's "false
    /// green" section for why a DISCONNECT advisory alone (regardless of reason) is not evidence
    /// of a kick: the probe's own connection teardown between attempts also generates one, with
    /// `reason: "Client Closed"`.
    disconnect_reason: Option<String>,
    connection_state_after: String,
    /// Whether the connection is gone for ANY reason (matched DISCONNECT advisory and/or an
    /// observed `Disconnected` client state). Used only for probe bookkeeping (deciding whether
    /// the next attempt needs a fresh target connection) — NOT used to decide `kicked`.
    connection_gone: bool,
    /// The actual verdict: true iff a DISCONNECT advisory was captured for this cid AND its
    /// `reason` is exactly `"Kicked"`. Nothing else counts — see RESULTS.md.
    kicked: bool,
    expected_kicked: bool,
}

async fn run_kick_attempt(
    sys_client: &async_nats::Client,
    disconnect_sub: &mut async_nats::Subscriber,
    attempt: KickAttempt,
    target: &CapturedConn,
) -> KickOutcome {
    hr(&format!("KICK ATTEMPT: {}", attempt.label));
    println!("subject: {}", attempt.subject);
    println!("payload: {}", attempt.payload);
    println!("target cid: {}", target.cid);

    let (reply_raw, reply_parsed, request_error) =
        match send_request(sys_client, &attempt.subject, &attempt.payload).await {
            Ok((raw, parsed)) => {
                println!("reply (raw utf8): {}", String::from_utf8_lossy(&raw));
                if let Some(p) = &parsed {
                    println!("reply (parsed, pretty):\n{}", pretty(p));
                }
                (
                    Some(String::from_utf8_lossy(&raw).to_string()),
                    parsed,
                    None,
                )
            }
            Err(e) => {
                println!("reply: ERROR — {e}");
                (None, None, Some(e))
            }
        };

    println!(
        "\nnow watching for a $SYS.ACCOUNT.*.DISCONNECT advisory for cid={} (up to {:?})...",
        target.cid, DISCONNECT_WATCH_TIMEOUT
    );
    let disconnect_evidence =
        wait_for_disconnect(disconnect_sub, target.cid, DISCONNECT_WATCH_TIMEOUT).await;

    let state = target.client.connection_state();
    let connection_state_after = format!("{state:?}");
    println!("target client's own connection_state() after this attempt: {connection_state_after}");

    let state_disconnected = matches!(state, async_nats::connection::State::Disconnected);
    // Bookkeeping only (does the NEXT attempt need a fresh target connection?) — never used to
    // decide `kicked`. A DISCONNECT advisory or a Disconnected state can both be caused by things
    // that are not a kick (e.g. the probe's own teardown of the previous attempt's connection).
    let connection_gone = disconnect_evidence.is_some() || state_disconnected;

    let disconnect_reason = disconnect_evidence
        .as_ref()
        .and_then(|v| v.get("reason"))
        .and_then(|r| r.as_str())
        .map(|s| s.to_string());
    // The ONLY thing that proves a kick: a captured DISCONNECT advisory for this cid whose
    // top-level `reason` is exactly "Kicked" — the server's own word for it (RESULTS.md). Neither
    // "some advisory arrived" nor "connection_state() == Disconnected" is sufficient on its own;
    // both are printed above as corroborating detail only.
    let kicked = disconnect_reason.as_deref() == Some("Kicked");

    let verdict_line = match (&disconnect_evidence, disconnect_reason.as_deref()) {
        (Some(_), Some("Kicked")) => {
            "KICKED (confirmed: DISCONNECT advisory reason == \"Kicked\")".to_string()
        }
        (Some(_), Some(other)) => format!(
            "NOT KICKED — a DISCONNECT advisory for this cid WAS observed, but its reason was \
             \"{other}\", not \"Kicked\". This is the probe's OWN connection teardown (or some \
             other cause), NOT evidence of a kick."
        ),
        (Some(_), None) => "NOT KICKED — a DISCONNECT advisory for this cid was observed but it \
             carried no 'reason' field."
            .to_string(),
        (None, _) => "NOT KICKED — no DISCONNECT advisory for this cid was observed within the \
             watch window."
            .to_string(),
    };

    println!("\n>>> VERDICT for '{}': {verdict_line} <<<", attempt.label);
    println!(
        "    (connection_state() after: {connection_state_after} — corroborating detail only, \
         NEVER sufficient alone to declare a kick)"
    );

    KickOutcome {
        label: attempt.label,
        subject: attempt.subject,
        payload: attempt.payload,
        reply_raw,
        reply_parsed,
        request_error,
        disconnect_evidence,
        disconnect_reason,
        connection_state_after,
        connection_gone,
        kicked,
        expected_kicked: attempt.expected_kicked,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    hr("S9 KICK MECHANICS PROBE — spikes/s9-revoke-kick");
    println!("Partial spike: settles KICK mechanics only against the live composed stack.");
    println!("NATS URL: {NATS_URL}");

    // --- SYS connection (genuine SYS-account membership, matching helper.rs's sys_client) ---
    let sys_client = async_nats::ConnectOptions::with_nkey(SYS_CONN_SEED.to_string())
        .event_callback(|event| async move {
            println!("[nats client event: sys_client] {event}");
        })
        .connect(NATS_URL)
        .await
        .context("connecting SYS-seed client")?;
    println!("[setup] SYS client connected");

    // Subscribe to CONNECT/DISCONNECT advisories up front, before opening ANY app connection, so
    // nothing is missed.
    let mut connect_sub = sys_client
        .subscribe("$SYS.ACCOUNT.*.CONNECT")
        .await
        .context("subscribing to $SYS.ACCOUNT.*.CONNECT")?;
    let mut disconnect_sub = sys_client
        .subscribe("$SYS.ACCOUNT.*.DISCONNECT")
        .await
        .context("subscribing to $SYS.ACCOUNT.*.DISCONNECT")?;
    println!("[setup] subscribed to $SYS.ACCOUNT.*.CONNECT and $SYS.ACCOUNT.*.DISCONNECT");

    // ---------------- STEP 1: full CONNECT event, server object expanded ----------------
    hr("STEP 1 — open APP connection, capture full CONNECT advisory");
    let (conn1, _connect1_json) = open_app_conn_and_capture(&mut connect_sub, "step1").await?;

    // ---------------- STEP 2: $SYS.REQ.SERVER.PING.CONNZ ----------------
    hr("STEP 2 — $SYS.REQ.SERVER.PING.CONNZ");
    let connz_payload = json!({ "auth": true });
    println!("request payload: {connz_payload}");
    let connz_reply =
        match send_request(&sys_client, "$SYS.REQ.SERVER.PING.CONNZ", &connz_payload).await {
            Ok((raw, parsed)) => {
                println!("FULL CONNZ REPLY (verbatim, raw utf8):");
                println!("{}", String::from_utf8_lossy(&raw));
                if let Some(p) = &parsed {
                    println!("\nFULL CONNZ REPLY (pretty-printed):");
                    println!("{}", pretty(p));
                }
                parsed
            }
            Err(e) => {
                println!("CONNZ request FAILED: {e}");
                None
            }
        };

    let server_id = connz_reply.as_ref().and_then(extract_server_id);
    match &server_id {
        Some((path, id)) => println!("\n[analysis] server id found at JSON path '{path}' = {id}"),
        None => println!(
            "\n[analysis] no server id found at any of the tried JSON paths (server.id, \
             data.server_id, server_id) — see full reply above for manual inspection"
        ),
    }

    // ---------------- STEP 3: KICK attempts ----------------
    hr("STEP 3 — KICK attempts (both subject forms x both payload field names)");

    let server_id_str = server_id
        .as_ref()
        .map(|(_, id)| id.clone())
        .unwrap_or_else(|| "UNKNOWN_SERVER_ID".to_string());
    if server_id.is_none() {
        println!(
            "[warning] no server id was recovered from CONNZ; the per-server KICK subject form \
             will use the literal placeholder 'UNKNOWN_SERVER_ID' and is expected to fail — this \
             failure is itself evidence."
        );
    }

    let mut current = conn1;
    let mut outcomes: Vec<KickOutcome> = Vec::new();

    let planned: Vec<(&'static str, bool, &'static str, bool)> = vec![
        // (label, use_server_id_subject, payload_field, expected_kicked)
        (
            "A: server-id subject + {id: cid} (DESIGN.md's exact claim)",
            true,
            "id",
            false,
        ),
        ("B: server-id subject + {cid: cid}", true, "cid", true),
        (
            "C: broadcast PING.KICK subject + {id: cid}",
            false,
            "id",
            false,
        ),
        (
            "D: broadcast PING.KICK subject + {cid: cid}",
            false,
            "cid",
            false,
        ),
    ];

    for (i, (label, use_server_id, field, expected_kicked)) in planned.into_iter().enumerate() {
        // If the previous target connection is gone (for any reason — kicked or otherwise), open
        // a fresh one so every combination is tested against a live, known-good connection. This
        // is bookkeeping only; it does NOT feed the kicked/not-kicked verdict.
        if i > 0 && outcomes.last().map(|o| o.connection_gone).unwrap_or(false) {
            println!(
                "\n[setup] previous target connection was kicked; opening a fresh APP connection \
                 for the next attempt"
            );
            let (new_conn, _) =
                open_app_conn_and_capture(&mut connect_sub, &format!("step3-refresh-{i}")).await?;
            current = new_conn;
        }

        let subject = if use_server_id {
            format!("$SYS.REQ.SERVER.{server_id_str}.KICK")
        } else {
            "$SYS.REQ.SERVER.PING.KICK".to_string()
        };
        let payload = match field {
            "id" => json!({ "id": current.cid }),
            "cid" => json!({ "cid": current.cid }),
            _ => unreachable!(),
        };

        let outcome = run_kick_attempt(
            &sys_client,
            &mut disconnect_sub,
            KickAttempt {
                label,
                subject,
                payload,
                expected_kicked,
            },
            &current,
        )
        .await;
        outcomes.push(outcome);
    }

    // ---------------- FINAL SUMMARY ----------------
    hr("FINAL SUMMARY — ANSWERS");

    println!("\nQ1: Where does the server id live?");
    match &server_id {
        Some((path, id)) => {
            println!("  ANSWER: JSON path '{path}' in the CONNZ reply, observed value = {id}")
        }
        None => {
            println!("  ANSWER: NOT FOUND at any tried path — see full CONNZ reply printed above.")
        }
    }

    println!("\nQ2/Q3: Which KICK subject form(s) work, and which payload field name is correct?");
    for o in &outcomes {
        println!("  - {}", o.label);
        println!("      subject: {}", o.subject);
        println!("      payload: {}", o.payload);
        if let Some(err) = &o.request_error {
            println!("      request outcome: ERROR — {err}");
        } else if let Some(p) = &o.reply_parsed {
            println!("      request outcome: reply received — {}", pretty(p));
        } else if let Some(raw) = &o.reply_raw {
            println!("      request outcome: reply received (non-JSON) — {raw}");
        }
        println!(
            "      connection_state() after: {} (corroborating detail only, not the verdict)",
            o.connection_state_after
        );
        match (&o.disconnect_evidence, o.disconnect_reason.as_deref()) {
            (Some(_), Some("Kicked")) => {
                println!("      DISCONNECT advisory reason: \"Kicked\"");
            }
            (Some(_), Some(other)) => {
                println!(
                    "      DISCONNECT advisory reason: \"{other}\" — this is NOT a kick (the \
                     probe's own connection teardown, or some other cause)"
                );
            }
            (Some(_), None) => {
                println!("      DISCONNECT advisory captured but had no 'reason' field");
            }
            (None, _) => {
                println!("      no DISCONNECT advisory observed for this cid");
            }
        }
        println!(
            "      KICKED: {}",
            if o.kicked {
                "YES (confirmed — reason == \"Kicked\")"
            } else {
                "NO"
            }
        );
        if let Some(ev) = &o.disconnect_evidence {
            println!("      DISCONNECT advisory (verbatim): {}", pretty(ev));
        }
        println!(
            "      EXPECTED: {}",
            if o.expected_kicked {
                "KICKED"
            } else {
                "NOT KICKED"
            }
        );
        println!(
            "      {}",
            if o.kicked == o.expected_kicked {
                "PASS (actual matches expected)"
            } else {
                "FAIL (actual does NOT match expected)"
            }
        );
    }

    let any_kicked = outcomes.iter().any(|o| o.kicked);
    println!(
        "\nOVERALL: {}",
        if any_kicked {
            "at least one KICK form/payload combination ACTUALLY kicked the target connection \
             (confirmed solely via a DISCONNECT advisory with reason == \"Kicked\")."
        } else {
            "NO combination tried actually kicked the target connection. Any 'success'-looking \
             reply above without a confirmed reason == \"Kicked\" is a false green and must be \
             reported as such, not as a working KICK."
        }
    );

    let all_passed = outcomes.iter().all(|o| o.kicked == o.expected_kicked);
    println!(
        "\nREGRESSION CHECK: {}",
        if all_passed {
            "ALL 4 ATTEMPTS MATCHED THEIR EXPECTED OUTCOME — PASS"
        } else {
            "ONE OR MORE ATTEMPTS DID NOT MATCH THEIR EXPECTED OUTCOME — FAIL (nats-server's \
             behavior has changed since this probe's findings were recorded — see RESULTS.md)"
        }
    );

    if !all_passed {
        anyhow::bail!(
            "S9 KICK mechanics regression: at least one attempt's actual outcome differed from \
             its expected outcome (see REGRESSION CHECK above for detail per attempt)."
        );
    }

    Ok(())
}
