//! Throwaway probe: connect as the callout responder, subscribe to `$SYS.REQ.USER.AUTH`, dump
//! the first N authorization-request payloads it receives (raw bytes + best-effort JWT-part
//! decode) so the JWT claim shapes documented in RESULTS.md are read off the real server, not
//! assumed. Delete-or-keep is not important; not part of the S1 deliverable itself.

use base64::Engine;
use futures_util::StreamExt;
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let seed = env::var("CALLOUT_USER_SEED").expect("CALLOUT_USER_SEED");
    let url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:14222".to_string());
    let client = async_nats::ConnectOptions::with_nkey(seed)
        .connect(&url)
        .await?;
    let mut sub = client.subscribe("$SYS.REQ.USER.AUTH").await?;
    println!("subscribed; waiting for a connection attempt on the client port...");
    if let Some(msg) = sub.next().await {
        println!("reply subject: {:?}", msg.reply);
        println!("raw payload len: {}", msg.payload.len());
        let s = String::from_utf8_lossy(&msg.payload);
        println!("raw payload: {s}");
        // The payload itself may be a bare JWT (header.payload.sig); try to decode each part.
        for (i, part) in s.split('.').enumerate() {
            if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part) {
                if let Ok(text) = String::from_utf8(bytes) {
                    println!("part[{i}] decoded: {text}");
                }
            }
        }
    }
    Ok(())
}
