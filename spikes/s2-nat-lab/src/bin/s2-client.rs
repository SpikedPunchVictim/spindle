//! Client side of the across-NAT S2 harness. Runs `SignalingClient::connect_timed` against the
//! host, writes and reads one control-stream frame, and prints one JSON line per attempt plus a
//! summary. Attempts continue until `RUNS` successes or `MAX_ATTEMPTS`, so a probabilistic ICE
//! punch still yields `RUNS` successful samples without hiding the failure rate.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use spike_s2_nat_lab::{client_device, host_identity, ice_config_from_env, init_tracing, median};
use spindle_net::framing::{read_frame, write_frame};
use spindle_net::signaling::{ConnectOptions, SelectedTransport, SignalingClient};

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://172.28.0.15:4222".into());
    let bind_ip: IpAddr = std::env::var("BIND_IP")
        .context("BIND_IP (this peer's private IP) is required")?
        .parse()
        .context("BIND_IP")?;
    let runs = env_usize("RUNS", 5);
    let max_attempts = env_usize("MAX_ATTEMPTS", runs);
    let ice_ms = env_u64("ICE_TIMEOUT_MS", 5000);
    let answer_ms = env_u64("ANSWER_TIMEOUT_MS", 5000);
    // td-870b25 long-hold: keep ONE connected session open for HOLD_SECS, exchanging a frame every
    // KEEP_ALIVE_SECS, and report a heartbeat each time. No reconnection: the point is to outlive
    // coturn's 300 s permission and 600 s allocation lifetimes and prove data still flows.
    let hold_secs = env_u64("HOLD_SECS", 0);
    let keep_alive_secs = env_u64("KEEP_ALIVE_SECS", 10).max(1);
    let hold_read_timeout_secs = env_u64("HOLD_READ_TIMEOUT_SECS", 30).max(1);
    let label = std::env::var("LABEL").unwrap_or_else(|_| "unlabeled".into());

    let device = client_device();
    let device_fp = device.device_fp();
    // The host's reply-prefix check requires this exact `_INBOX_<device_fp>` shape; without it the
    // offer is rejected before the answer is ever sealed (production behavior, not a lab tweak).
    let nats = async_nats::ConnectOptions::new()
        .connection_timeout(Duration::from_secs(5))
        .custom_inbox_prefix(format!("_INBOX_{device_fp}"))
        .connect(&url)
        .await
        .with_context(|| format!("NATS connect to {url}"))?;
    let client = SignalingClient::new(nats, device);
    let host = host_identity();
    let opts = ConnectOptions {
        bind_ip,
        ice_timeout: Duration::from_millis(ice_ms),
        answer_timeout: Duration::from_millis(answer_ms),
        ice: ice_config_from_env()?,
    };

    let mut attempts = 0usize;
    let mut failures = 0usize;
    let mut punch_successes = 0usize;
    let mut relay_successes = 0usize;
    let mut rows: Vec<(f64, f64, f64, f64)> = Vec::new();
    while rows.len() < runs && attempts < max_attempts {
        attempts += 1;
        let started = Instant::now();
        match client.connect_timed(&host, opts.clone()).await {
            Ok((mut control, timings)) => {
                if hold_secs > 0 {
                    let hold = Duration::from_secs(hold_secs);
                    let hold_started = Instant::now();
                    let mut seq = 0u64;
                    let mut heartbeats = 0u64;
                    let mut first_t: Option<f64> = None;
                    let mut last_t = 0.0f64;
                    let mut failure: Option<(f64, String)> = None;
                    loop {
                        if hold_started.elapsed() >= hold {
                            break;
                        }
                        seq += 1;
                        let payload =
                            format!("hold-{seq}-{:.3}", hold_started.elapsed().as_secs_f64())
                                .into_bytes();
                        let sent = Instant::now();
                        let exchange = async {
                            write_frame(&mut control.send, &payload).await?;
                            let echoed = read_frame(&mut control.recv).await?.ok_or_else(|| {
                                anyhow::anyhow!("host closed the control stream during the hold")
                            })?;
                            if echoed != payload {
                                bail!("host echoed different bytes during the hold");
                            }
                            Ok::<(), anyhow::Error>(())
                        };
                        match tokio::time::timeout(
                            Duration::from_secs(hold_read_timeout_secs),
                            exchange,
                        )
                        .await
                        {
                            Ok(Ok(())) => {
                                let t = hold_started.elapsed().as_secs_f64();
                                if first_t.is_none() {
                                    first_t = Some(t);
                                }
                                last_t = t;
                                heartbeats += 1;
                                println!(
                                    "{}",
                                    serde_json::json!({
                                        "label": label,
                                        "event": "hold",
                                        "seq": seq,
                                        "t_s": t,
                                        "rtt_ms": sent.elapsed().as_secs_f64() * 1000.0,
                                        "transport": timings.transport.as_str(),
                                    })
                                );
                            }
                            Ok(Err(error)) => {
                                failure =
                                    Some((hold_started.elapsed().as_secs_f64(), error.to_string()));
                                break;
                            }
                            Err(_) => {
                                failure = Some((
                                    hold_started.elapsed().as_secs_f64(),
                                    format!("no echo within {hold_read_timeout_secs}s"),
                                ));
                                break;
                            }
                        }
                        let remaining = hold.saturating_sub(hold_started.elapsed());
                        if remaining.is_zero() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_secs(keep_alive_secs).min(remaining))
                            .await;
                    }
                    println!(
                        "{}",
                        serde_json::json!({
                            "label": label,
                            "event": "hold_summary",
                            "hold_secs": hold_secs,
                            "heartbeats_attempted": seq,
                            "heartbeats_ok": heartbeats,
                            "first_t_s": first_t,
                            "last_t_s": last_t,
                            "transport": timings.transport.as_str(),
                            "failed_at_s": failure.as_ref().map(|(t, _)| *t),
                            "failure": failure.as_ref().map(|(_, e)| e.clone()),
                        })
                    );
                    control.connection.close(0u32.into(), b"done");
                    return Ok(());
                }
                let after_connect = Instant::now();
                let payload = format!("s2-nat-run-{attempts}").into_bytes();
                write_frame(&mut control.send, &payload)
                    .await
                    .context("writing the control-stream frame")?;
                let echoed = read_frame(&mut control.recv)
                    .await
                    .context("reading the echoed frame")?
                    .context("host closed the control stream without echoing")?;
                if echoed != payload {
                    bail!("host echoed different bytes than the client wrote");
                }
                let offer_to_stream = (timings.offer_to_quic_complete + after_connect.elapsed())
                    .as_secs_f64()
                    * 1000.0;
                let row = (
                    ms(timings.offer_to_answer),
                    ms(timings.answer_to_ice_selected),
                    ms(timings.ice_selected_to_quic),
                    offer_to_stream,
                );
                match timings.transport {
                    SelectedTransport::Punch => punch_successes += 1,
                    SelectedTransport::Relay => relay_successes += 1,
                }
                println!(
                    "{}",
                    serde_json::json!({
                        "label": label,
                        "attempt": attempts,
                        "status": "ok",
                        "transport": timings.transport.as_str(),
                        "offer_to_answer_ms": row.0,
                        "answer_to_selected_ms": row.1,
                        "selected_to_quic_ms": row.2,
                        "offer_to_stream_ms": row.3,
                    })
                );
                rows.push(row);
                control.connection.close(0u32.into(), b"done");
            }
            Err(error) => {
                failures += 1;
                println!(
                    "{}",
                    serde_json::json!({
                        "label": label,
                        "attempt": attempts,
                        "status": "failed",
                        "elapsed_ms": started.elapsed().as_secs_f64() * 1000.0,
                        "error": error.to_string(),
                    })
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let a: Vec<f64> = rows.iter().map(|r| r.0).collect();
    let b: Vec<f64> = rows.iter().map(|r| r.1).collect();
    let c: Vec<f64> = rows.iter().map(|r| r.2).collect();
    let d: Vec<f64> = rows.iter().map(|r| r.3).collect();
    println!(
        "{}",
        serde_json::json!({
            "label": label,
            "attempts": attempts,
            "successes": rows.len(),
            "failures": failures,
            "punch_successes": punch_successes,
            "relay_successes": relay_successes,
            "offer_to_answer_ms_median": median(&a),
            "answer_to_selected_ms_median": median(&b),
            "selected_to_quic_ms_median": median(&c),
            "offer_to_stream_ms_median": median(&d),
            "offer_to_stream_ms_values": d,
        })
    );
    Ok(())
}
