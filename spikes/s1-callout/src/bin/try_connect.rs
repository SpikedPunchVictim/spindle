//! Throwaway: attempt an nkey-authenticated connection so the probe can capture what
//! `connect_opts` looks like when a real nkey signature is presented (nonce/sig/nkey field
//! names). Not part of the S1 deliverable.
use nkeys::KeyPair;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let kp = KeyPair::new_user();
    println!("user pub: {}", kp.public_key());
    let seed = kp.seed().unwrap();
    let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:14222".to_string());
    let res = async_nats::ConnectOptions::with_nkey(seed)
        .connection_timeout(std::time::Duration::from_secs(3))
        .connect(&url)
        .await;
    println!("connect result: {res:?}");
    Ok(())
}
