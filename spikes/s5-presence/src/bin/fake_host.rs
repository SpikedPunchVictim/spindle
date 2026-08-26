//! A minimal standalone "fake host" daemon for S5 (docs/SPIKES.md §S5): connects to the composed
//! stack's `nats-server` exactly the way a real host daemon would (host `auth_token`, `open`
//! admission — see `spike_s1_callout::fixtures::host_auth_token`/`new_host_identity`), prints a
//! single `READY <host_fp>` line once connected, then blocks forever.
//!
//! This has to be a **separate OS process**, not a task inside the harness binary
//! (`src/bin/s5-tests.rs`): the harness needs to `kill -STOP` it mid-run to simulate a frozen/
//! dead application while its TCP socket stays fully open (no FIN) — the exact scenario
//! `ping_interval`/`ping_max` server-side ping timeout detection exists for (DESIGN.md §A6).
//! `kill -STOP` suspends process scheduling at the kernel level; it does not (and cannot) touch
//! already-open file descriptors, so this is the one dead-socket-without-network-partition
//! technique that needs no OS-level firewall/netem access, root, or network namespace tricks —
//! see RESULTS.md for the negative results from anything cheaper this spike tried.
//!
//! No graceful shutdown handling is intentional: for the "clean disconnect" scenario, the
//! harness just `kill`s (`SIGTERM`) this process outright. A process death (whether by default
//! `SIGTERM` disposition or `SIGKILL`) closes every fd the kernel holds for it — including this
//! socket — sending a normal TCP `FIN`, which is exactly the "host client closes cleanly" case
//! S5 needs, and needs no cooperation from this binary's own code path at all.
//!
//! Env vars (all required except `EXP_SECS`):
//! - `NATS_URL` — e.g. `nats://127.0.0.1:4222`
//! - `ROOT_SEED_HEX` / `OP_SEED_HEX` — 64 hex chars each (32 raw bytes), the host's root/operating
//!   key seeds. Per `spike_s1_callout::fixtures`' own workaround note (this spike inherits it
//!   verbatim — see `s5-tests.rs`'s module doc for why): pass the **same** 32 bytes for both, so
//!   the root-key-derived and operating-key-derived `host_fp` computations converge (a
//!   pre-existing, out-of-scope bug flagged by S1, not something this spike patches).
//! - `EXP_SECS` — optional, default 3600 (seconds from now the host's operating-key cert and
//!   session are valid for).

use spike_s1_callout::fixtures;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn seed_from_hex(env_var: &str) -> anyhow::Result<[u8; 32]> {
    let hex = std::env::var(env_var).map_err(|_| anyhow::anyhow!("{env_var} not set"))?;
    let bytes = hex_decode(&hex)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("{env_var} decoded to {} bytes, want 32", v.len()))
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(s.len().is_multiple_of(2), "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow::anyhow!("{e}")))
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let root_seed = seed_from_hex("ROOT_SEED_HEX")?;
    let op_seed = seed_from_hex("OP_SEED_HEX")?;
    let exp_secs: u64 = std::env::var("EXP_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);

    let host = fixtures::new_host_identity(root_seed, op_seed);
    let exp = now() + exp_secs;

    let session = nkeys::KeyPair::new_user();
    let nats_fp = fixtures::nats_fp_of_nkey(&session.public_key())?;
    let cert = fixtures::host_op_key_cert(&host, nats_fp, now(), exp);
    let root_pk_bytes = host.root.public_key().to_bytes();
    let token = fixtures::host_auth_token(&root_pk_bytes, &cert, None);

    let client = async_nats::ConnectOptions::new()
        .nkey(session.seed()?)
        .token(token)
        .connection_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await?;
    // Keep the connection alive for the process's lifetime — dropping `client` would close it.
    std::mem::forget(client);

    println!("READY {}", host.host_fp);
    std::io::stdout().flush()?;

    // Block forever. See module doc: shutdown is entirely external (SIGTERM = clean close,
    // SIGSTOP/SIGCONT = freeze/thaw for the dead-socket scenario, SIGKILL = final cleanup).
    std::future::pending::<()>().await;
    Ok(())
}
