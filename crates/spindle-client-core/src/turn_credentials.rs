//! Fetching TURN credentials from the helper (`helper.turn.get.<nfp>`, DESIGN.md §A8).
//!
//! The helper half lives in `spindle-helper`'s `turn` module: a live member session's
//! `helper.turn.get.<nfp>` request is answered by checking the session record for `<nfp>`,
//! enforcing the helper's per-`root_fp` monthly quota, and minting a coturn REST credential
//! (`username = "<expiry>:<root_fp>"`, `credential = base64_standard(HMAC-SHA1(secret,
//! username))`). This module is the client half: [`fetch_turn_credentials`] performs one
//! request/reply on the caller's already-authenticated member connection and returns the
//! helper's answer as neutral Rust types — no `spindle-net` (or any ICE/coturn) dependency.
//!
//! # Identity comes from the subject, never the payload
//!
//! The request body is the empty JSON object `{}` and carries no identity field. The `<nfp>` in
//! `helper.turn.get.<nfp>` is the caller's **own session-nkey fingerprint** — the identity the
//! NATS Auth Callout proved this connection owns. The helper mints against the `root_fp` on that
//! session record and charges the issuance to the per-`root_fp` quota; a device cannot ask for
//! another root's credential, and cannot burn another root's quota, by writing a field into the
//! body (DESIGN.md §A5/§A12 #45). Callers therefore pass the fingerprint of their own session
//! nkey, not a device fingerprint.
//!
//! # The returned URIs are ICE server URIs
//!
//! `uris` is the operator-configured ICE server list, e.g.
//! `turn:host:3478?transport=udp` / `turns:host:5349?transport=tcp`. This module hands them back
//! verbatim, together with the coturn username/credential and the minted TTL; converting them
//! into a transport config (an ICE server / TURN relay configuration) is the caller's job.
//!
//! # The transport seam
//!
//! [`TurnCredentialTransport`] exists so this crate does not depend on `async-nats`: the app (and
//! later the client engine) implements it over its already-authenticated member connection. An
//! implementation must publish **exactly** the `subject` and `payload` it is given as a NATS
//! request and return the raw reply payload bytes; it must not substitute its own subject,
//! re-encode the body, or retry with different arguments. The reply bytes are the helper's
//! `{"username", "credential", "ttl", "uris"}` / `{"error"}` JSON described on
//! [`fetch_turn_credentials`]. Keeping the seam this narrow means every behaviour below is
//! testable with a fake, with no broker in the loop.
//!
//! # No production caller yet
//!
//! **Nothing in this workspace calls [`fetch_turn_credentials`] in production.** The app's NATS
//! adapter and the engine wiring that turns the returned URIs into a transport configuration are
//! later slices; this module is the library-level client half, not an app integration.
//! `tests/live_turn_credentials.rs` drives it over a real callout-authenticated connection against
//! the helper, but that adapter is test-local.

use serde::Deserialize;

pub use crate::self_revocation::TransportError;

/// One request/reply exchange on the caller's authenticated app connection.
///
/// This is the seam the app's NATS client implements; see the module docs for the contract.
/// Implementors publish `payload` on `subject` as a NATS request and return the reply bytes. The
/// library never inspects the transport, so a fake implementation is enough to test every
/// reply-handling branch in this module.
//
// The app supplies a concrete adapter; this crate uses the trait only as a bound on
// `fetch_turn_credentials`, never as a `dyn TurnCredentialTransport` — the case the lint's own
// note says may be suppressed. It is deliberately not desugared to `-> impl Future + Send` yet:
// that is a breaking signature change, and no caller that needs the bound exists. If a Tauri
// command later spawns `fetch_turn_credentials`, desugar it then.
#[allow(async_fn_in_trait)]
pub trait TurnCredentialTransport {
    /// Publishes `payload` on `subject` and returns the raw reply payload.
    async fn request(&self, subject: &str, payload: Vec<u8>) -> Result<Vec<u8>, TransportError>;
}

/// A successfully minted TURN credential, as returned by [`fetch_turn_credentials`].
///
/// The fields mirror the helper's reply one-for-one; nothing here is interpreted beyond the
/// presence/emptiness checks documented on the fetch function.
#[derive(Clone, PartialEq, Eq)]
pub struct TurnCredentialsReply {
    /// ICE server URIs, e.g. `turn:host:3478?transport=udp`. Handed back verbatim.
    pub uris: Vec<String>,
    /// The coturn REST username, `"<expiry>:<root_fp>"`. coturn treats it as opaque HMAC input.
    pub username: String,
    /// `base64_standard(HMAC-SHA1(secret, username))`, the coturn credential.
    pub credential: String,
    /// How long the minted credential is valid for, in seconds (the helper's configured TTL).
    pub ttl_secs: u64,
}

impl std::fmt::Debug for TurnCredentialsReply {
    /// The credential is a live coturn secret and the username embeds the caller's
    /// `root_fp`; neither is rendered, matching `spindle_net::signaling::TurnCredentials`'s
    /// redaction. `uris` and `ttl_secs` are not secrets and stay visible for debugging.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnCredentialsReply")
            .field("uris", &self.uris)
            .field("username", &"<redacted>")
            .field("credential", &"<redacted>")
            .field("ttl_secs", &self.ttl_secs)
            .finish()
    }
}

/// Errors from [`fetch_turn_credentials`]. Each variant names the one thing that went wrong; no
/// variant tries to interpret a helper rejection beyond passing along its own reason.
#[derive(Debug, thiserror::Error)]
pub enum TurnCredentialError {
    /// The request/reply exchange itself failed (no reply, connection loss, timeout, ...).
    #[error("transport failure: {0}")]
    Transport(#[source] TransportError),
    /// The reply was not the helper's `{"username", "credential", "ttl", "uris"}` /
    /// `{"error"}` JSON shape, or a success was missing a field this module requires.
    #[error("helper reply was not a well-formed helper.turn.get reply")]
    MalformedReply,
    /// The helper answered `{"error": "..."}`; carries the helper's own human-readable reason
    /// (e.g. `"no active session"`, `"TURN quota exceeded"`, `"TURN not configured"`).
    #[error("helper refused the TURN credential request: {0}")]
    Rejected(String),
}

/// The subset of the helper's `turn::TurnGetReply` wire shape this module reads.
///
/// Defined locally rather than depended on from `spindle-helper`: the client crate must not link
/// the helper, and only these five fields are part of the contract. Unknown fields are ignored
/// by serde, so a helper that adds a field does not break older clients.
#[derive(Deserialize)]
struct TurnCredentialsReplyWire {
    username: Option<String>,
    credential: Option<String>,
    ttl: Option<u64>,
    uris: Option<Vec<String>>,
    error: Option<String>,
}

/// Requests a TURN credential on `helper.turn.get.<nats_fp>` and decodes the helper's reply.
///
/// `nats_fp` is the caller's own **session-nkey fingerprint** (its Display form — lowercase,
/// unpadded RFC 4648 base32), the token the callout granted this connection `pub
/// helper.turn.get.<nfp>` for. The helper authorizes against the session record for that token and
/// mints per its `root_fp`; the body (`{}`) carries no identity.
///
/// # Reply handling
///
/// - A well-formed success (non-empty `uris`, non-empty `username` and `credential`, and
///   `ttl_secs > 0`) → [`TurnCredentialsReply`].
/// - `{"error": "..."}` → [`TurnCredentialError::Rejected`] with the helper's reason.
/// - Unparseable JSON, a missing/empty required field, or `ttl == 0` →
///   [`TurnCredentialError::MalformedReply`].
/// - A transport failure → [`TurnCredentialError::Transport`].
///
/// The error field is checked first: a refusal is a refusal even if it happens to carry other
/// fields. The success checks are deliberately strict — a helper that says "ok" but hands back
/// nothing usable is indistinguishable from a corrupt reply, and treating it as success would
/// push the failure into the ICE layer with far less context.
pub async fn fetch_turn_credentials(
    transport: &impl TurnCredentialTransport,
    nats_fp: &str,
) -> Result<TurnCredentialsReply, TurnCredentialError> {
    let subject = format!("helper.turn.get.{nats_fp}");
    // `{}` is the documented request body (`turn.rs` also accepts a truly empty body); the helper
    // reads no fields from it. This is not where the caller's identity comes from.
    let reply_bytes = transport
        .request(&subject, b"{}".to_vec())
        .await
        .map_err(TurnCredentialError::Transport)?;

    let reply: TurnCredentialsReplyWire =
        serde_json::from_slice(&reply_bytes).map_err(|_| TurnCredentialError::MalformedReply)?;

    if let Some(reason) = reply.error {
        return Err(TurnCredentialError::Rejected(reason));
    }

    let username = reply
        .username
        .filter(|s| !s.is_empty())
        .ok_or(TurnCredentialError::MalformedReply)?;
    let credential = reply
        .credential
        .filter(|s| !s.is_empty())
        .ok_or(TurnCredentialError::MalformedReply)?;
    let uris = reply
        .uris
        .filter(|u| !u.is_empty())
        .ok_or(TurnCredentialError::MalformedReply)?;
    let ttl_secs = reply
        .ttl
        .filter(|ttl| *ttl > 0)
        .ok_or(TurnCredentialError::MalformedReply)?;

    Ok(TurnCredentialsReply {
        uris,
        username,
        credential,
        ttl_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records every request and answers it with one canned result.
    struct FakeTransport {
        reply: Mutex<Option<Result<Vec<u8>, TransportError>>>,
        calls: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl FakeTransport {
        fn replying(reply: impl Into<Vec<u8>>) -> Self {
            Self {
                reply: Mutex::new(Some(Ok(reply.into()))),
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

    impl TurnCredentialTransport for FakeTransport {
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

    const NATS_FP: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx";

    fn ok_reply() -> Vec<u8> {
        serde_json::json!({
            "username": "1700003600:some-root-fp",
            "credential": "IIsOngJ7WKPm5PufqLTehcGxqtU=",
            "ttl": 3600,
            "uris": [
                "turn:example.org:3478?transport=udp",
                "turns:example.org:5349?transport=tcp",
            ],
        })
        .to_string()
        .into_bytes()
    }

    #[tokio::test]
    async fn ok_reply_round_trips() {
        let transport = FakeTransport::replying(ok_reply());

        let reply = fetch_turn_credentials(&transport, NATS_FP)
            .await
            .expect("a complete success reply is accepted");

        assert_eq!(
            reply,
            TurnCredentialsReply {
                uris: vec![
                    "turn:example.org:3478?transport=udp".to_string(),
                    "turns:example.org:5349?transport=tcp".to_string(),
                ],
                username: "1700003600:some-root-fp".to_string(),
                credential: "IIsOngJ7WKPm5PufqLTehcGxqtU=".to_string(),
                ttl_secs: 3600,
            }
        );
    }

    #[test]
    fn debug_redacts_the_username_and_credential() {
        let reply = TurnCredentialsReply {
            uris: vec!["turn:example.org:3478?transport=udp".to_string()],
            username: "1700003600:some-root-fp".to_string(),
            credential: "IIsOngJ7WKPm5PufqLTehcGxqtU=".to_string(),
            ttl_secs: 3600,
        };

        let rendered = format!("{reply:?}");

        assert!(
            !rendered.contains(&reply.username),
            "Debug must not render the username (it embeds the caller's root_fp): {rendered}"
        );
        assert!(
            !rendered.contains(&reply.credential),
            "Debug must not render the live coturn credential: {rendered}"
        );
        // The non-secret fields stay inspectable, so the redaction is not achieved by rendering
        // nothing at all.
        assert!(
            rendered.contains("turn:example.org:3478?transport=udp"),
            "{rendered}"
        );
        assert!(rendered.contains("ttl_secs: 3600"), "{rendered}");
    }

    #[tokio::test]
    async fn error_reply_carries_the_helpers_reason() {
        let transport = FakeTransport::replying(br#"{"error":"TURN quota exceeded"}"#.to_vec());

        let err = fetch_turn_credentials(&transport, NATS_FP)
            .await
            .unwrap_err();

        assert!(
            matches!(&err, TurnCredentialError::Rejected(reason) if reason == "TURN quota exceeded"),
            "expected Rejected(TURN quota exceeded), got {err:?}"
        );
    }

    #[tokio::test]
    async fn unparseable_json_is_a_malformed_reply() {
        let transport = FakeTransport::replying(b"not json".to_vec());

        let err = fetch_turn_credentials(&transport, NATS_FP)
            .await
            .unwrap_err();

        assert!(
            matches!(err, TurnCredentialError::MalformedReply),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn missing_or_empty_required_fields_are_malformed_replies() {
        // One case per required field, each removing it entirely and then emptying it. The
        // success path is otherwise fully valid, so each case isolates exactly one defect.
        let cases = [
            serde_json::json!({
                "credential": "c", "ttl": 60,
                "uris": ["turn:example.org:3478?transport=udp"],
            }),
            serde_json::json!({
                "username": "", "credential": "c", "ttl": 60,
                "uris": ["turn:example.org:3478?transport=udp"],
            }),
            serde_json::json!({
                "username": "1700000060:root", "ttl": 60,
                "uris": ["turn:example.org:3478?transport=udp"],
            }),
            serde_json::json!({
                "username": "1700000060:root", "credential": "", "ttl": 60,
                "uris": ["turn:example.org:3478?transport=udp"],
            }),
            serde_json::json!({
                "username": "1700000060:root", "credential": "c", "ttl": 60,
            }),
            serde_json::json!({
                "username": "1700000060:root", "credential": "c", "ttl": 60,
                "uris": [],
            }),
        ];

        for case in cases {
            let transport = FakeTransport::replying(case.to_string().into_bytes());
            let err = fetch_turn_credentials(&transport, NATS_FP)
                .await
                .unwrap_err();
            assert!(
                matches!(err, TurnCredentialError::MalformedReply),
                "case {case} should be malformed, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn zero_ttl_is_a_malformed_reply() {
        let transport = FakeTransport::replying(
            serde_json::json!({
                "username": "1700000000:root", "credential": "c", "ttl": 0,
                "uris": ["turn:example.org:3478?transport=udp"],
            })
            .to_string()
            .into_bytes(),
        );

        let err = fetch_turn_credentials(&transport, NATS_FP)
            .await
            .unwrap_err();

        assert!(
            matches!(err, TurnCredentialError::MalformedReply),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn transport_failure_is_reported_as_such() {
        let transport = FakeTransport::failing(std::io::Error::other("no responders"));

        let err = fetch_turn_credentials(&transport, NATS_FP)
            .await
            .unwrap_err();

        match err {
            TurnCredentialError::Transport(source) => {
                assert_eq!(source.to_string(), "no responders")
            }
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subject_is_built_from_the_session_nfp_and_the_body_is_empty_object() {
        let transport = FakeTransport::replying(ok_reply());

        fetch_turn_credentials(&transport, NATS_FP)
            .await
            .expect("ok reply");

        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, format!("helper.turn.get.{NATS_FP}"));
        assert_eq!(
            calls[0].1, b"{}",
            "the body must carry no identity or other fields"
        );
    }

    #[tokio::test]
    async fn extra_unknown_fields_are_accepted_for_forward_compatibility() {
        let transport = FakeTransport::replying(
            serde_json::json!({
                "username": "1700003600:root",
                "credential": "c",
                "ttl": 3600,
                "uris": ["turn:example.org:3478?transport=udp"],
                "realm": "spindle",
                "issued_at": 1700000000,
            })
            .to_string()
            .into_bytes(),
        );

        let reply = fetch_turn_credentials(&transport, NATS_FP)
            .await
            .expect("unknown fields must be ignored, not rejected");

        assert_eq!(reply.ttl_secs, 3600);
    }
}
