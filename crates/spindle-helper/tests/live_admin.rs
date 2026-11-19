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

    let send = |cmd: &str, args: CborValue, seq: u64, nonce: u8| {
        let command = issue_admin_command(
            &operator,
            1,
            cmd.to_string(),
            args,
            signer_fp.to_vec(),
            seq,
            vec![nonce; 16],
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
        .as_millis() as u64;
    // Use a fresh high seq so reruns never collide with the durable replay table.
    let seq = base * 10;

    send(
        "set_mode",
        CborValue::map(vec![("mode", CborValue::text("closed"))]),
        seq,
        0x61,
    )
    .await;
    let reply = tokio::time::timeout(std::time::Duration::from_secs(5), inbox.next())
        .await
        .expect("admin reply")
        .expect("message");
    assert_reply_ok(&reply.payload, true);

    send("list_hosts", CborValue::Null, seq + 1, 0x62).await;
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
        0x63,
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
