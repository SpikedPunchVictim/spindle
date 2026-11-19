//! Live admin-plane proof (td-efea19): a command signed with the operator key is accepted over
//! real NATS, verified, audit-committed, and answered with the pinned reply envelope.
//!
//! Gated like the other live suites. Requires the compose stack (nats + postgres + helper) with
//! the dev `OPERATOR_SEED`/`ADMIN_ALLOW_PLAINTEXT` values from `deploy/docker-compose.yml`:
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml up -d --build nats postgres helper
//! cargo test -p spindle-helper --test live_admin -- --ignored --nocapture
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use spindle_core::artifacts::issue_admin_command;
use spindle_core::SigningKey;
use spindle_proto::canonical::{canonical_decode, CborValue};

const DEV_OPERATOR_SEED: &str = "SUAOLFPBPF7WNOWHBE7ZLHCWSLTT7I5DHRA4VXCH2E44Q7XQX7A3E46STA";
static LIVE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Dev-only: clears the durable replay guard so each ignored live run can start at a known seq.
/// Uses the compose stack's published Postgres port; never point this at a real registry.
async fn reset_admin_replay() {
    let url = std::env::var("ADMIN_TEST_DATABASE_URL").unwrap_or_else(|_| {
        "postgres://spindle:spindle-dev-only@127.0.0.1:12019/spindle".to_string()
    });
    let pool = sqlx::PgPool::connect(&url)
        .await
        .expect("connect the dev admin database for replay reset");
    sqlx::query("TRUNCATE admin_replay")
        .execute(&pool)
        .await
        .expect("truncate admin_replay");
}

const DEV_APP_CONN_SEED: &str = "SUAFWWQRCTGQTS6DKVAJKMMFMIJKFZ3MRFGFQ4WCRZ5RVZ5WFRB4CXPYBY";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d --build nats postgres helper` first"]
async fn a_signed_admin_command_is_verified_and_answered() {
    let _guard = LIVE_LOCK.lock().await;
    reset_admin_replay().await;
    let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let (_, raw) = nkeys::decode_seed(DEV_OPERATOR_SEED).expect("operator seed");
    let operator = SigningKey::from_bytes(&raw);
    let signer_fp = spindle_core::identity::root_fp_of(&operator.verifying_key());

    let nats = async_nats::ConnectOptions::with_nkey(DEV_APP_CONN_SEED.to_string())
        .connect(&url)
        .await
        .expect("operator NATS connection");
    let mut inbox = nats
        .subscribe("_INBOX_admin_live".to_string())
        .await
        .expect("inbox");
    // Let the helper's admin subscription land.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let send = |cmd: &str, args: CborValue, seq: u64, nonce: [u8; 16]| {
        let command = issue_admin_command(
            &operator,
            1,
            cmd.to_string(),
            args,
            signer_fp.to_vec(),
            seq,
            nonce.to_vec(),
            now(),
        );
        let subject = format!("registry.admin.{cmd}");
        let reply = "_INBOX_admin_live".to_string();
        let payload = command.to_canonical_bytes();
        let nats = nats.clone();
        async move {
            nats.publish_with_reply(subject, reply, payload.into())
                .await
                .expect("publish admin command");
        }
    };

    let base = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos() as u64;
    // A high, monotonically increasing base: nanos/1000 keeps every serialized run above the
    // previous one's durable last_seq without approaching u64 overflow.
    let seq = (1u64 << 62) + base / 1_000;
    let nonce = |salt: u8| {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&base.to_be_bytes());
        nonce[8..].copy_from_slice(&base.to_le_bytes());
        nonce[15] ^= salt;
        nonce
    };

    send(
        "set_mode",
        CborValue::map(vec![("mode", CborValue::text("closed"))]),
        seq,
        nonce(0x61),
    )
    .await;
    let reply = tokio::time::timeout(std::time::Duration::from_secs(5), inbox.next())
        .await
        .expect("admin reply")
        .expect("message");
    assert_reply_ok(&reply.payload, true);

    send("list_hosts", CborValue::Null, seq + 1, nonce(0x62)).await;
    let reply = tokio::time::timeout(std::time::Duration::from_secs(5), inbox.next())
        .await
        .expect("admin reply")
        .expect("message");
    assert_reply_ok(&reply.payload, true);

    // Restore the mode other live tests expect.
    send(
        "set_mode",
        CborValue::map(vec![("mode", CborValue::text("open"))]),
        seq + 2,
        nonce(0x63),
    )
    .await;
    let reply = tokio::time::timeout(std::time::Duration::from_secs(5), inbox.next())
        .await
        .expect("admin reply")
        .expect("message");
    assert_reply_ok(&reply.payload, true);
}

fn assert_reply_ok(bytes: &[u8], expected: bool) {
    let value = canonical_decode(bytes).expect("reply is canonical CBOR");
    let map = value.as_map().expect("reply is a map");
    let ok = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("ok"))
        .and_then(|(_, v)| match v {
            CborValue::Bool(ok) => Some(*ok),
            _ => None,
        })
        .expect("ok field");
    assert_eq!(ok, expected, "reply: {map:?}");
}

// `futures_util::StreamExt` is needed for `Subscriber::next`.
use futures_util::StreamExt;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d --build nats postgres helper` first"]
async fn suspending_a_host_kicks_its_live_connection() {
    use spindle_test_fixtures::connect_host;
    use spindle_test_fixtures::fixtures::HostRootIdentity;

    let url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let (_, raw) = nkeys::decode_seed(DEV_OPERATOR_SEED).expect("operator seed");
    let operator = SigningKey::from_bytes(&raw);
    let signer_fp = spindle_core::identity::root_fp_of(&operator.verifying_key());

    // A random host identity so reruns do not collide with durable admission/state rows.
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos()
        .to_le_bytes();
    let mut root_seed = [0u8; 32];
    root_seed[..16].copy_from_slice(&stamp[..16]);
    let mut op_seed = [0u8; 32];
    op_seed[..16].copy_from_slice(&stamp);
    op_seed[16..].copy_from_slice(&stamp);
    op_seed[0] ^= 0x5A;
    let host_root = HostRootIdentity::new(root_seed, op_seed);
    let host_fp = host_root.host_fp;
    let now = now();
    let (host_client, host_events) = connect_host(&url, &host_root, now + 3_600).await;

    let nats = async_nats::ConnectOptions::with_nkey(DEV_APP_CONN_SEED.to_string())
        .connect(&url)
        .await
        .expect("operator NATS connection");
    let mut inbox = nats
        .subscribe("_INBOX_admin_kick".to_string())
        .await
        .expect("inbox");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let seq = (1u64 << 62)
        + SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos() as u64
            / 1_000;
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&stamp);
    let command = issue_admin_command(
        &operator,
        1,
        "suspend_host".to_string(),
        CborValue::map(vec![(
            "host_fp",
            CborValue::bytes(host_fp.as_bytes().to_vec()),
        )]),
        signer_fp.to_vec(),
        seq,
        nonce.to_vec(),
        now,
    );
    nats.publish_with_reply(
        "registry.admin.suspend_host".to_string(),
        "_INBOX_admin_kick".to_string(),
        command.to_canonical_bytes().into(),
    )
    .await
    .expect("publish suspend");
    let reply = tokio::time::timeout(std::time::Duration::from_secs(5), inbox.next())
        .await
        .expect("admin reply")
        .expect("message");
    assert_reply_ok(&reply.payload, true);

    // The kick is issued after the command transaction; wait for the host's connection event.
    let mut kicked = false;
    for _ in 0..100 {
        if host_events
            .lock()
            .expect("event log")
            .iter()
            .any(|event| event.contains("disconnected"))
        {
            kicked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        kicked,
        "host session was not kicked; events: {:?}",
        host_events.lock().expect("log")
    );
    drop(host_client);
}
