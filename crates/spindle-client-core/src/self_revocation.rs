//! Minting and depositing a root-signed `spindle-self-rev-v1` record (DESIGN.md §A4/§A7b, S14).
//!
//! The helper half of S14 lives in `spindle-helper`'s `self_revoke` module: a live member
//! session's `helper.revoke.<nfp>` request is answered by checking the record against the
//! `root_pk` retained on that session. This module is the producing half. The primary device —
//! the only device that holds the identity root — mints a record with
//! [`mint_self_revocation`] and deposits it with [`deposit_self_revocation`].
//!
//! # The transport seam
//!
//! [`RevokeTransport`] exists so this crate does not depend on `async-nats`: the app (and later
//! the client engine) implements it over its already-authenticated member connection. An
//! implementation must publish **exactly** the `subject` and `payload` it is given as a NATS
//! request and return the raw reply payload bytes; it must not substitute its own subject,
//! re-encode the record, or retry with different arguments. The reply bytes are the helper's
//! `{"ok": ...}` JSON described on [`deposit_self_revocation`]. Keeping the seam this narrow
//! means every behaviour below is testable with a fake, with no broker in the loop.
//!
//! # No production caller yet
//!
//! **Nothing in this workspace calls these functions yet.** The Tauri client shell, the primary
//! device's key-custody flow, and the actual NATS adapter are later slices; this module is the
//! library-level half of td-a06afc, not an app integration.

use serde::Deserialize;
use spindle_core::artifacts::issue_self_revocation;
use spindle_core::{Fingerprint, SigningKey};
use spindle_proto::artifacts::SelfRevocationRecord;

/// A boxed transport failure: anything the app's NATS client reports as a failed request/reply
/// exchange (connection loss, timeout, no responders, a publish error).
pub type TransportError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// One request/reply exchange on the caller's authenticated app connection.
///
/// This is the seam the app's NATS client implements; see the module docs for the contract.
/// Implementors publish `payload` on `subject` as a NATS request and return the reply bytes. The
/// library never inspects the transport, so a fake implementation is enough to test every
/// reply-handling branch in this module.
//
// The app supplies a concrete adapter; this crate uses the trait only as a bound on
// `deposit_self_revocation`, never as a `dyn RevokeTransport` — the case the lint's own note says
// may be suppressed. It is deliberately not desugared to `-> impl Future + Send` yet: that is a
// breaking signature change, and no caller that needs the bound exists. If a Tauri command later
// spawns `deposit_self_revocation`, desugar it then.
#[allow(async_fn_in_trait)]
pub trait RevokeTransport {
    /// Publishes `payload` on `subject` and returns the raw reply payload.
    async fn request(&self, subject: &str, payload: Vec<u8>) -> Result<Vec<u8>, TransportError>;
}

/// Mints a root-signed `spindle-self-rev-v1` record naming `revoked` under the person's root.
///
/// Only the **primary** device holds the identity root, so this is the only place a
/// self-revocation can originate. The call is a thin wrapper over
/// [`spindle_core::artifacts::issue_self_revocation`]: `root_fp` is derived from `root` by the
/// issuer and is never accepted from the caller, so a record whose `root_fp` disagrees with its
/// own signer cannot be minted through this API.
///
/// `epoch` is the per-root monotonic counter the primary device maintains. `ts` is
/// informational: self-revocation records are permanent (DESIGN.md §A7b, "none (permanent)"), so
/// an old record is still valid and `ts` is not a freshness gate.
pub fn mint_self_revocation(
    root: &SigningKey,
    epoch: u64,
    revoked: &[Fingerprint],
    ts: u64,
) -> SelfRevocationRecord {
    issue_self_revocation(root, epoch, revoked.to_vec(), ts)
}

/// Errors from [`deposit_self_revocation`]. Each variant names the one thing that went wrong;
/// no variant tries to interpret a helper rejection beyond passing along its own reason.
#[derive(Debug, thiserror::Error)]
pub enum DepositError {
    /// The request/reply exchange itself failed (no reply, connection loss, timeout, ...).
    #[error("transport failure: {0}")]
    Transport(#[source] TransportError),
    /// The reply was not the helper's `{"ok", "root_fp"?, "epoch"?, "error"?}` JSON shape, or an
    /// acceptance was missing the fields this module requires. The deposit may or may not have
    /// been applied — see the advisory-reply note on [`deposit_self_revocation`].
    #[error("helper reply was not a well-formed helper.revoke reply")]
    MalformedReply,
    /// The helper answered `ok: false`; carries the helper's own human-readable reason.
    #[error("helper refused the deposit: {0}")]
    Rejected(String),
}

/// The subset of the helper's `self_revoke::SelfRevokeReply` wire shape this module reads.
///
/// Defined locally rather than depended on from `spindle-helper`: the client crate must not link
/// the helper, and only these four fields are part of the contract. Unknown fields are ignored
/// by serde, so a helper that adds a field does not break older clients.
#[derive(Deserialize)]
struct SelfRevokeReplyWire {
    ok: bool,
    root_fp: Option<String>,
    epoch: Option<u64>,
    error: Option<String>,
}

/// Deposits a minted self-revocation on `helper.revoke.<own nats fp>` and returns the epoch the
/// helper reports as stored.
///
/// The subject is built from `own_nats_fp` — the caller's **session NKey** fingerprint, not the
/// `device_fp` of any revoked device. The helper authorizes the request against the callout
/// grant for the connection's own session `pub helper.revoke.<nfp>` (DESIGN.md §A5), and the
/// record's `revoked` list is what names the lost devices.
///
/// # Reply handling
///
/// - `ok: true` with `epoch` → `Ok(epoch)`, the helper's stored high-water mark.
/// - `ok: true` without `epoch` → [`DepositError::MalformedReply`].
/// - `ok: false` → [`DepositError::Rejected`] with the helper's `error`, or
///   `"rejected without a reason"` if it sent none.
/// - Unparseable JSON, or any other malformed shape → [`DepositError::MalformedReply`].
/// - A transport failure → [`DepositError::Transport`].
///
/// If the reply carries `root_fp`, it must equal the record's own `root_fp` in the same Display
/// encoding (lowercase, unpadded RFC 4648 base32). This is a **sanity check, not a security
/// boundary**: the record's signature already authorizes it under the root it names, so a helper
/// claiming a different root has simply returned an inconsistent reply, and the client refuses
/// to report success against it. Nothing here trusts the helper to confirm which root signed.
///
/// # The reply is advisory
///
/// An `Ok(epoch)` means the helper stored the record; it is not the revocation's durable effect.
/// Enforcement still lives at the host, which consults the helper's accepted revoked set per
/// CONNECT request. A lost or malformed reply therefore says nothing about whether the deposit
/// landed — callers may re-publish the same record, since the accepted revoked set is a monotone
/// union and the epoch counter is max-wins.
pub async fn deposit_self_revocation<T: RevokeTransport>(
    transport: &T,
    own_nats_fp: Fingerprint,
    record: &SelfRevocationRecord,
) -> Result<u64, DepositError> {
    let subject = format!("helper.revoke.{own_nats_fp}");
    let payload = record.to_canonical_bytes();
    let reply_bytes = transport
        .request(&subject, payload)
        .await
        .map_err(DepositError::Transport)?;

    let reply: SelfRevokeReplyWire =
        serde_json::from_slice(&reply_bytes).map_err(|_| DepositError::MalformedReply)?;

    if !reply.ok {
        return Err(DepositError::Rejected(
            reply
                .error
                .unwrap_or_else(|| "rejected without a reason".to_owned()),
        ));
    }

    if let Some(reply_root_fp) = reply.root_fp {
        let expected =
            Fingerprint::from_slice(&record.root_fp).map_err(|_| DepositError::MalformedReply)?;
        if reply_root_fp != expected.to_string() {
            return Err(DepositError::MalformedReply);
        }
    }

    reply.epoch.ok_or(DepositError::MalformedReply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::artifacts::verify_self_revocation;
    use spindle_core::root_fp_of;
    use std::sync::Mutex;

    /// Records every request and answers it with one canned result.
    struct FakeTransport {
        reply: Mutex<Option<Result<Vec<u8>, TransportError>>>,
        calls: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl FakeTransport {
        fn replying(reply: Vec<u8>) -> Self {
            Self {
                reply: Mutex::new(Some(Ok(reply))),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn failing(error: impl Into<TransportError>) -> Self {
            Self {
                reply: Mutex::new(Some(Err(error.into()))),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(String, Vec<u8>)> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    impl RevokeTransport for FakeTransport {
        async fn request(
            &self,
            subject: &str,
            payload: Vec<u8>,
        ) -> Result<Vec<u8>, TransportError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push((subject.to_owned(), payload));
            self.reply
                .lock()
                .expect("reply lock")
                .take()
                .expect("FakeTransport answers exactly one request")
        }
    }

    fn root() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }

    fn own_nats_fp() -> Fingerprint {
        Fingerprint::of_parts(&[b"own-nats-session"])
    }

    fn record() -> SelfRevocationRecord {
        mint_self_revocation(
            &root(),
            7,
            &[Fingerprint::of_parts(&[b"lost-device"])],
            1_755_907_200,
        )
    }

    #[test]
    fn mint_derives_root_fp_from_the_root_and_verifies() {
        let root = root();
        let revoked = [
            Fingerprint::of_parts(&[b"device-a"]),
            Fingerprint::of_parts(&[b"device-b"]),
        ];
        let rec = mint_self_revocation(&root, 3, &revoked, 123);

        assert_eq!(rec.root_fp, root_fp_of(&root.verifying_key()).to_vec());
        assert_eq!(rec.epoch, 3);
        assert_eq!(rec.revoked, vec![revoked[0].to_vec(), revoked[1].to_vec()]);
        assert_eq!(rec.ts, 123);
        verify_self_revocation(&rec, &root.verifying_key()).expect("valid signature");
    }

    #[tokio::test]
    async fn accepted_reply_returns_the_stored_epoch_and_deposits_the_record() {
        let rec = record();
        let reply = serde_json::json!({
            "ok": true,
            "root_fp": Fingerprint::from_slice(&rec.root_fp).unwrap().to_string(),
            "epoch": 7,
        });
        let transport = FakeTransport::replying(reply.to_string().into_bytes());

        let epoch = deposit_self_revocation(&transport, own_nats_fp(), &rec)
            .await
            .expect("accepted deposit");

        assert_eq!(epoch, 7);
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, format!("helper.revoke.{}", own_nats_fp()));
        assert_eq!(
            SelfRevocationRecord::from_canonical_bytes(&calls[0].1)
                .expect("payload is a canonical SelfRevocationRecord"),
            rec
        );
    }

    #[tokio::test]
    async fn rejected_reply_surfaces_the_helpers_reason() {
        let transport = FakeTransport::replying(br#"{"ok":false,"error":"rate limited"}"#.to_vec());

        let err = deposit_self_revocation(&transport, own_nats_fp(), &record())
            .await
            .unwrap_err();

        assert!(
            matches!(&err, DepositError::Rejected(reason) if reason == "rate limited"),
            "expected Rejected(rate limited), got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejection_without_a_reason_gets_a_placeholder() {
        let transport = FakeTransport::replying(br#"{"ok":false}"#.to_vec());

        let err = deposit_self_revocation(&transport, own_nats_fp(), &record())
            .await
            .unwrap_err();

        assert!(
            matches!(&err, DepositError::Rejected(reason) if reason == "rejected without a reason"),
            "expected the placeholder reason, got {err:?}"
        );
    }

    #[tokio::test]
    async fn acceptance_without_an_epoch_is_a_malformed_reply() {
        let transport = FakeTransport::replying(br#"{"ok":true}"#.to_vec());

        let err = deposit_self_revocation(&transport, own_nats_fp(), &record())
            .await
            .unwrap_err();

        assert!(matches!(err, DepositError::MalformedReply), "got {err:?}");
    }

    #[tokio::test]
    async fn unparseable_json_is_a_malformed_reply() {
        let transport = FakeTransport::replying(b"not json".to_vec());

        let err = deposit_self_revocation(&transport, own_nats_fp(), &record())
            .await
            .unwrap_err();

        assert!(matches!(err, DepositError::MalformedReply), "got {err:?}");
    }

    #[tokio::test]
    async fn a_reply_naming_a_different_root_is_a_malformed_reply() {
        let other_root = Fingerprint::of_parts(&[b"some-other-root"]).to_string();
        let reply = serde_json::json!({ "ok": true, "root_fp": other_root, "epoch": 7 });
        let transport = FakeTransport::replying(reply.to_string().into_bytes());

        let err = deposit_self_revocation(&transport, own_nats_fp(), &record())
            .await
            .unwrap_err();

        assert!(matches!(err, DepositError::MalformedReply), "got {err:?}");
    }

    #[tokio::test]
    async fn a_transport_failure_is_reported_as_such() {
        let transport = FakeTransport::failing(std::io::Error::other("no responders"));

        let err = deposit_self_revocation(&transport, own_nats_fp(), &record())
            .await
            .unwrap_err();

        match err {
            DepositError::Transport(source) => assert_eq!(source.to_string(), "no responders"),
            other => panic!("expected Transport, got {other:?}"),
        }
    }
}
