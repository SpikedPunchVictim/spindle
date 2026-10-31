//! Host side of the across-NAT S2 harness. Runs the production `SignalingHost` on the host
//! peer's private IP and reports the events it can observe: offer receipts (via a second NATS
//! subscription on `host.<hfp>.connect`) and QUIC-control-stream usability (via the
//! `SessionHandler`). The production host exposes no per-phase hooks for answer-published or
//! ICE-selected; the client's `ConnectTimings` are the authoritative phases.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::StreamExt;
use spike_s2_nat_lab::{
    client_device, host_device, host_fp, ice_config_from_env, init_tracing, EchoHandler,
    RegistryAuthorizer,
};
use spindle_net::signaling::{HostOptions, SignalingHost};

#[tokio::main]
async fn main() -> Result<()> {
    // `transport selected` (with the session id) is a debug event on the production host; the JSON
    // subscriber makes it observable per attempt, including failed handshakes (td-870b25).
    init_tracing();
    let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://172.28.0.15:4222".into());
    let bind_ip: IpAddr = std::env::var("BIND_IP")
        .context("BIND_IP (this peer's private IP) is required")?
        .parse()
        .context("BIND_IP")?;
    let ice_ms: u64 = std::env::var("ICE_TIMEOUT_MS")
        .unwrap_or_else(|_| "5000".into())
        .parse()
        .context("ICE_TIMEOUT_MS")?;

    let nats = async_nats::connect(&url)
        .await
        .with_context(|| format!("NATS connect to {url}"))?;
    let start = Instant::now();

    // A second subscription on the connect subject, only to timestamp offer arrivals. The host's
    // own `run` subscription also receives every offer (no queue group), so this does not steal
    // the message the signaling host must process.
    let mut offers = nats
        .subscribe(format!("host.{}.connect", host_fp()))
        .await
        .context("subscribe offer timestamps")?;
    tokio::spawn(async move {
        while offers.next().await.is_some() {
            println!(
                "{}",
                serde_json::json!({
                    "event": "offer_received",
                    "t_ms": start.elapsed().as_secs_f64() * 1000.0,
                })
            );
        }
    });

    let client = client_device();
    let client_fp = client.device_fp();
    let authorizer = RegistryAuthorizer::new(&[&client]);

    // The answer is published to the client's fixed `_INBOX_<client_fp>.<nonce>` reply subject.
    // The production host exposes no answer-published hook, but that subject is observable, so a
    // second subscription records when the host actually published it. This is host-side timing;
    // the client's receipt is one NATS hop later.
    let mut answers = nats
        .subscribe(format!("_INBOX_{client_fp}.>"))
        .await
        .context("subscribe answer timestamps")?;
    tokio::spawn(async move {
        while answers.next().await.is_some() {
            println!(
                "{}",
                serde_json::json!({
                    "event": "answer_published",
                    "t_ms": start.elapsed().as_secs_f64() * 1000.0,
                })
            );
        }
    });
    let host = Arc::new(SignalingHost::new(
        nats,
        host_device(),
        host_fp(),
        authorizer,
        EchoHandler::new(start),
    ));
    println!(
        "{}",
        serde_json::json!({
            "event": "host_ready",
            "bind_ip": bind_ip.to_string(),
            "nats": url,
        })
    );
    host.run(HostOptions {
        bind_ip,
        ice_timeout: Duration::from_millis(ice_ms),
        session_close_timeout: Duration::from_secs(5),
        max_concurrent_connects: 64,
        ice: ice_config_from_env()?,
    })
    .await
    .context("SignalingHost::run")?;
    Ok(())
}
