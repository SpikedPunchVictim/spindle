//! TURN credential minting (`helper.turn.get.<nfp>`, DESIGN.md §A5 subject table + "Permissions
//! issued by callout", v0.9.7/A12 #45).
//!
//! # Identity source: the subject token, not the payload [v0.9.7]
//! Prior to v0.9.7, this subject was the bare `helper.turn.get`, and the caller declared its own
//! `nats_fp` inside the JSON request body — a quota-griefing gap (DESIGN.md §A12 #45): core NATS
//! pub/sub gives a subscriber no notion of which authenticated connection published a message, so
//! nothing stopped an authenticated device from asserting someone *else's* `nats_fp` and burning
//! that victim's TURN quota. DESIGN.md §A5 closes this the same way it already scopes
//! `registry.revoke.<hfp>`: parametrize the subject itself as `helper.turn.get.<nfp>`, where
//! `<nfp>` is the caller's session-nkey fingerprint. The callout only ever grants a connection
//! `pub helper.turn.get.<own_nats_fp>` for its *own* `nats_fp` (see
//! `permissions::client_member_permissions`), so NATS's own permission system — not this
//! payload — proves the caller's identity: by the time a message reaches this handler, the
//! subject it arrived on is the one fact about the caller's identity that cannot have been
//! forged. [`handle_turn_get`] therefore takes the subject as a parameter and parses `<nfp>` out
//! of it; the request body carries no identity field at all.
//!
//! Wire schema (v0.9.7):
//! ```text
//! subject:   helper.turn.get.<nfp>            (nfp = base32(session nkey fingerprint), same
//!                                               Display encoding as every other <...fp> subject
//!                                               token — see permissions.rs's module doc)
//! request:   {}  (or an empty body — no fields are read; unknown fields are ignored)
//! reply ok:  { "username": "<exp>:<root_fp base32>", "credential": "<base64>", "ttl": <secs>,
//!              "uris": ["turn:host:3478?transport=udp", ...] }
//! reply err: { "error": "<human-readable reason>" }
//! ```
//! `src/bin/helper.rs` subscribes `helper.turn.get.*` and passes both the received `msg.subject`
//! and `msg.payload` into [`handle_turn_get`]; this module stays NATS-free (no `async-nats` type
//! appears in its signature) so it can be unit-tested without a broker.
//!
//! **`username = expiry:root_fp` [amended v0.9.7]**: [`crate::session::SessionRecord`] (as
//! `authz.rs`/`session.rs` define it) carries `root_fp`, not `device_fp`, for client connections
//! (see that module's own doc comment on why). DESIGN.md §A8 now states the username as
//! `expiry:root_fp` directly — this is no longer a divergence this module has to paper over, it
//! is the session record's caller identity, and it matches the per-`root_fp` quota model DESIGN.md
//! §A8 itself uses ("device keys are free to mint" — the quota that matters is per-root, not
//! per-device). coturn treats the whole username as an opaque HMAC input and never decodes it, so
//! this was always harmless; it is now also spec-correct.

use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use spindle_core::Fingerprint;

use crate::authz::HelperView;

/// Static TURN configuration (DESIGN.md §A8/§A9b), read from env by `src/bin/helper.rs` and
/// passed in here as plain data — this module has no env/CLI parsing of its own.
#[derive(Debug, Clone)]
pub struct TurnConfig {
    /// coturn's `static-auth-secret` (DESIGN.md §A8 "coturn `use-auth-secret`").
    pub secret: String,
    /// ICE server URIs handed back verbatim to the caller (e.g. `turn:host:3478?transport=udp`).
    pub uris: Vec<String>,
    /// How far in the future a minted credential's embedded expiry is set.
    pub ttl_secs: u64,
    /// The per-`root_fp` quota enforced by [`HelperView::record_turn_issuance`] — see that
    /// method's doc comment for the (30-day-rolling, not calendar-month) period definition.
    pub monthly_quota: u64,
}

/// The `helper.turn.get.` subject prefix; `<nfp>` follows it as the final subject token.
const SUBJECT_PREFIX: &str = "helper.turn.get.";

/// The (now-empty) request body. No fields are read — caller identity comes from the subject
/// (see the module doc) — but the type still exists so `{}` / unknown-fields tolerance is a
/// documented, tested contract rather than an accident of `serde_json::from_slice::<Value>`.
/// Deliberately *not* `#[serde(deny_unknown_fields)]`: an unrecognized field (e.g. a lingering
/// client still sending the old `nats_fp`) must be ignored, not rejected — this is serde's
/// default struct behavior, stated here explicitly rather than left implicit.
#[derive(Debug, Deserialize)]
struct TurnGetRequest {}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnGetReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uris: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl TurnGetReply {
    fn err(message: impl Into<String>) -> Self {
        Self {
            username: None,
            credential: None,
            ttl: None,
            uris: None,
            error: Some(message.into()),
        }
    }

    fn ok(username: String, credential: String, ttl: u64, uris: Vec<String>) -> Self {
        Self {
            username: Some(username),
            credential: Some(credential),
            ttl: Some(ttl),
            uris: Some(uris),
            error: None,
        }
    }
}

/// Mints a coturn REST-style credential (DESIGN.md §A8): `username = "<expiry>:<label>"`,
/// `credential = base64_standard(HMAC-SHA1(secret, username))`. Mirrors
/// `spikes/s19-quic-transport/src/bin/quic-peer.rs`'s `mint_turn_credentials` exactly (same
/// crates, same encoding), generalized to take an already-computed `expiry` and `label` rather
/// than deriving them inline, so it is independently unit-testable against known vectors.
pub fn mint_credentials(secret: &str, label: &str, expiry: u64) -> (String, String) {
    let username = format!("{expiry}:{label}");
    let mut mac =
        Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("HMAC-SHA1 accepts any key length");
    mac.update(username.as_bytes());
    let credential = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    (username, credential)
}

/// Parses the caller's `nats_fp` out of a `helper.turn.get.<nfp>` subject. Rejects anything that
/// doesn't start with the exact `helper.turn.get.` prefix, has an empty token after it, or whose
/// token doesn't decode as a [`Fingerprint`] under the same base32 `Display` encoding every other
/// `<...fp>` subject token uses (DESIGN.md §A5; see `permissions.rs`'s module doc).
fn parse_subject_nats_fp(subject: &str) -> Option<Fingerprint> {
    crate::parse_fp_after_prefix(subject, SUBJECT_PREFIX)
}

/// Decodes and authorizes one `helper.turn.get.<nfp>` request, enforcing the per-`root_fp` quota
/// and minting credentials on success. Pure with respect to NATS — takes the subject the request
/// arrived on and the raw request payload bytes, and returns the JSON reply payload bytes to
/// publish back; `src/bin/helper.rs` is the only caller that touches an actual NATS connection.
///
/// Caller identity comes from `subject` alone (the callout-granted permission already proved this
/// connection owns that `nats_fp` — see the module doc); `payload` carries no identity field.
pub fn handle_turn_get(
    subject: &str,
    payload: &[u8],
    config: Option<&TurnConfig>,
    view: &mut impl HelperView,
    now: u64,
) -> Vec<u8> {
    let reply = handle_turn_get_inner(subject, payload, config, view, now);
    serde_json::to_vec(&reply).expect("TurnGetReply always serializes")
}

fn handle_turn_get_inner(
    subject: &str,
    payload: &[u8],
    config: Option<&TurnConfig>,
    view: &mut impl HelperView,
    now: u64,
) -> TurnGetReply {
    let Some(config) = config else {
        return TurnGetReply::err("TURN not configured");
    };

    let Some(nats_fp) = parse_subject_nats_fp(subject) else {
        return TurnGetReply::err("malformed subject");
    };

    // The body carries no identity and (as of v0.9.7) no other required field either — empty and
    // `{}` are both valid. An unparseable *non-empty* body is still rejected, though: a caller
    // sending garbage there is a bug worth surfacing loudly rather than silently ignoring.
    if !payload.is_empty() && serde_json::from_slice::<TurnGetRequest>(payload).is_err() {
        return TurnGetReply::err("malformed request");
    }

    let Some(session) = view.session_record(&nats_fp, now) else {
        return TurnGetReply::err("no active session");
    };

    if view
        .record_turn_issuance(&session.root_fp, now, config.monthly_quota)
        .is_err()
    {
        return TurnGetReply::err("TURN quota exceeded");
    }

    let expiry = now + config.ttl_secs;
    let (username, credential) =
        mint_credentials(&config.secret, &session.root_fp.to_string(), expiry);
    TurnGetReply::ok(username, credential, config.ttl_secs, config.uris.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_store::InMemoryHelperView;
    use crate::session::SessionRecord;
    use spindle_core::SigningKey;

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_parts(&[seed])
    }

    fn store() -> InMemoryHelperView {
        InMemoryHelperView::new(
            crate::authz::AdmissionMode::Open,
            SigningKey::from_bytes(&[0x77; 32]).verifying_key(),
        )
    }

    fn subject_for(nats_fp: &Fingerprint) -> String {
        format!("helper.turn.get.{nats_fp}")
    }

    // ---- mint_credentials: known vectors (independent oracle: `openssl dgst -sha1 -hmac`) -------

    #[test]
    fn mint_credentials_matches_rfc2202_hmac_sha1_vector() {
        // RFC 2202 test case 2: HMAC-SHA1(key="Jefe", data="what do ya want for nothing?")
        // = effcdf6ae5eb2fa2d27416d5f184df9c259a7c79 (hex), base64 "7/zfauXrL6LSdBbV8YTfnCWafHk=".
        // mint_credentials builds username = "<expiry>:<label>" before MACing it, so this test
        // calls the HMAC machinery directly (not through mint_credentials's username formatting)
        // to check this crate's exact HMAC-SHA1 + base64(STANDARD) pipeline against a vector with
        // no relation to this module's own code.
        let mut mac = Hmac::<Sha1>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        let digest = mac.finalize().into_bytes();
        let expected_digest: [u8; 20] = [
            0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
            0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
        ];
        assert_eq!(digest.as_slice(), &expected_digest);
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        assert_eq!(b64, "7/zfauXrL6LSdBbV8YTfnCWafHk=");
    }

    #[test]
    fn mint_credentials_matches_independently_computed_vector() {
        // Independently verified via `openssl dgst -sha1 -hmac 's3cr3t-dev-only' -binary | base64`
        // over the literal bytes "9999999999:device-fp-test-label" -> "IIsOngJ7WKPm5PufqLTehcGxqtU=".
        let (username, credential) =
            mint_credentials("s3cr3t-dev-only", "device-fp-test-label", 9_999_999_999);
        assert_eq!(username, "9999999999:device-fp-test-label");
        assert_eq!(credential, "IIsOngJ7WKPm5PufqLTehcGxqtU=");
    }

    #[test]
    fn mint_credentials_username_shape_is_expiry_colon_label() {
        let (username, _) = mint_credentials("secret", "some-label", 1_700_000_000);
        assert_eq!(username, "1700000000:some-label");
    }

    // ---- parse_subject_nats_fp -------------------------------------------------------------------

    #[test]
    fn parse_subject_round_trips_a_fingerprint() {
        let nats_fp = fp(b"nats-subject-parse");
        assert_eq!(parse_subject_nats_fp(&subject_for(&nats_fp)), Some(nats_fp));
    }

    #[test]
    fn parse_subject_rejects_wrong_prefix() {
        let nats_fp = fp(b"nats-wrong-prefix");
        assert_eq!(
            parse_subject_nats_fp(&format!("helper.turn.gett.{nats_fp}")),
            None
        );
        assert_eq!(parse_subject_nats_fp("helper.turn.get"), None);
        assert_eq!(
            parse_subject_nats_fp(&format!("registry.revoke.{nats_fp}")),
            None
        );
    }

    #[test]
    fn parse_subject_rejects_empty_token() {
        assert_eq!(parse_subject_nats_fp("helper.turn.get."), None);
    }

    #[test]
    fn parse_subject_rejects_a_token_that_does_not_decode_as_a_fingerprint() {
        assert_eq!(
            parse_subject_nats_fp("helper.turn.get.not-a-fingerprint!!"),
            None
        );
        // Valid base32 alphabet, but the wrong decoded length.
        assert_eq!(parse_subject_nats_fp("helper.turn.get.my"), None);
    }

    // ---- handle_turn_get: authorization / quota / config paths -----------------------------------

    #[test]
    fn unconfigured_turn_replies_with_a_clear_error() {
        let mut s = store();
        let nats_fp = fp(b"nats-a");
        let reply_bytes = handle_turn_get(&subject_for(&nats_fp), b"", None, &mut s, 1_000);
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("TURN not configured"));
        assert!(reply.username.is_none());
    }

    #[test]
    fn malformed_subject_is_refused_before_config_is_even_consulted() {
        // Config is present (Some) here specifically to prove the subject check happens first
        // and independently of TURN configuration state.
        let mut s = store();
        let config = TurnConfig {
            secret: "s".to_string(),
            uris: vec![],
            ttl_secs: 60,
            monthly_quota: 10,
        };
        let reply_bytes = handle_turn_get("helper.turn.get", b"", Some(&config), &mut s, 1_000);
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("malformed subject"));
    }

    #[test]
    fn wrong_prefix_subject_is_refused_as_malformed() {
        let mut s = store();
        let config = TurnConfig {
            secret: "s".to_string(),
            uris: vec![],
            ttl_secs: 60,
            monthly_quota: 10,
        };
        let nats_fp = fp(b"nats-wrong-prefix-2");
        let reply_bytes = handle_turn_get(
            &format!("registry.revoke.{nats_fp}"),
            b"",
            Some(&config),
            &mut s,
            1_000,
        );
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("malformed subject"));
    }

    #[test]
    fn bad_fingerprint_token_in_subject_is_refused_as_malformed() {
        let mut s = store();
        let config = TurnConfig {
            secret: "s".to_string(),
            uris: vec![],
            ttl_secs: 60,
            monthly_quota: 10,
        };
        let reply_bytes = handle_turn_get(
            "helper.turn.get.not-a-real-fingerprint",
            b"",
            Some(&config),
            &mut s,
            1_000,
        );
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("malformed subject"));
    }

    #[test]
    fn no_session_record_is_refused() {
        let mut s = store();
        let config = TurnConfig {
            secret: "s".to_string(),
            uris: vec!["turn:example:3478".to_string()],
            ttl_secs: 3600,
            monthly_quota: 10,
        };
        let nats_fp = fp(b"nats-no-session");
        let reply_bytes =
            handle_turn_get(&subject_for(&nats_fp), b"", Some(&config), &mut s, 1_000);
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("no active session"));
    }

    #[test]
    fn a_subject_fp_with_no_matching_session_record_is_refused_even_if_other_sessions_exist() {
        // Proves lookup is keyed by the *subject's* fp, not merely "some session exists somewhere".
        let mut s = store();
        let unrelated_nats_fp = fp(b"nats-unrelated-session");
        s.put_session_record(SessionRecord::new(
            unrelated_nats_fp,
            fp(b"root-unrelated"),
            vec![],
            "member".to_string(),
            10_000,
        ));
        let config = TurnConfig {
            secret: "s".to_string(),
            uris: vec![],
            ttl_secs: 60,
            monthly_quota: 10,
        };
        let caller_nats_fp = fp(b"nats-caller-with-no-session");
        let reply_bytes = handle_turn_get(
            &subject_for(&caller_nats_fp),
            b"",
            Some(&config),
            &mut s,
            1_000,
        );
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("no active session"));
    }

    #[test]
    fn authorized_session_mints_credentials_with_configured_ttl_and_uris() {
        let mut s = store();
        let nats_fp = fp(b"nats-b");
        let root_fp = fp(b"root-b");
        s.put_session_record(SessionRecord::new(
            nats_fp,
            root_fp,
            vec![fp(b"host-b")],
            "member".to_string(),
            10_000,
        ));
        let config = TurnConfig {
            secret: "topsecret".to_string(),
            uris: vec![
                "turn:example.org:3478?transport=udp".to_string(),
                "turns:example.org:5349?transport=tcp".to_string(),
            ],
            ttl_secs: 1_800,
            monthly_quota: 10,
        };
        let now = 1_000;
        let reply_bytes = handle_turn_get(&subject_for(&nats_fp), b"", Some(&config), &mut s, now);
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert!(reply.error.is_none());
        assert_eq!(reply.ttl, Some(1_800));
        assert_eq!(reply.uris, Some(config.uris.clone()));
        let username = reply.username.expect("username present");
        assert_eq!(username, format!("{}:{}", now + 1_800, root_fp));
        let expected_credential =
            mint_credentials(&config.secret, &root_fp.to_string(), now + 1_800).1;
        assert_eq!(reply.credential, Some(expected_credential));
    }

    #[test]
    fn empty_body_is_accepted() {
        let mut s = store();
        let nats_fp = fp(b"nats-empty-body");
        let root_fp = fp(b"root-empty-body");
        s.put_session_record(SessionRecord::new(
            nats_fp,
            root_fp,
            vec![],
            "member".to_string(),
            10_000,
        ));
        let config = TurnConfig {
            secret: "s".to_string(),
            uris: vec![],
            ttl_secs: 60,
            monthly_quota: 10,
        };
        let reply_bytes =
            handle_turn_get(&subject_for(&nats_fp), b"", Some(&config), &mut s, 1_000);
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert!(
            reply.error.is_none(),
            "empty body must be accepted: {reply:?}"
        );
    }

    #[test]
    fn empty_json_object_body_is_accepted() {
        let mut s = store();
        let nats_fp = fp(b"nats-empty-object-body");
        let root_fp = fp(b"root-empty-object-body");
        s.put_session_record(SessionRecord::new(
            nats_fp,
            root_fp,
            vec![],
            "member".to_string(),
            10_000,
        ));
        let config = TurnConfig {
            secret: "s".to_string(),
            uris: vec![],
            ttl_secs: 60,
            monthly_quota: 10,
        };
        let reply_bytes =
            handle_turn_get(&subject_for(&nats_fp), b"{}", Some(&config), &mut s, 1_000);
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert!(
            reply.error.is_none(),
            "`{{}}` body must be accepted: {reply:?}"
        );
    }

    #[test]
    fn unknown_fields_in_body_are_ignored() {
        let mut s = store();
        let nats_fp = fp(b"nats-unknown-fields");
        let root_fp = fp(b"root-unknown-fields");
        s.put_session_record(SessionRecord::new(
            nats_fp,
            root_fp,
            vec![],
            "member".to_string(),
            10_000,
        ));
        let config = TurnConfig {
            secret: "s".to_string(),
            uris: vec![],
            ttl_secs: 60,
            monthly_quota: 10,
        };
        // Also proves the payload's own (now-vestigial) "nats_fp" field, even naming a *different*
        // fingerprint than the subject, is fully ignored: identity comes from the subject alone.
        let attacker_claimed_fp = fp(b"attacker-claims-this-fp-in-body");
        let body = serde_json::to_vec(&serde_json::json!({
            "nats_fp": attacker_claimed_fp.to_string(),
            "something_else": 42,
        }))
        .unwrap();
        let reply_bytes =
            handle_turn_get(&subject_for(&nats_fp), &body, Some(&config), &mut s, 1_000);
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert!(
            reply.error.is_none(),
            "unknown fields must be ignored: {reply:?}"
        );
        let username = reply.username.expect("username present");
        assert_eq!(
            username,
            format!("{}:{}", 1_000 + config.ttl_secs, root_fp),
            "credential must be minted for the subject's session, never the body's claimed fp"
        );
    }

    #[test]
    fn quota_exceeded_refuses_further_mints_for_the_same_root_fp() {
        let mut s = store();
        let nats_fp = fp(b"nats-c");
        let root_fp = fp(b"root-c");
        s.put_session_record(SessionRecord::new(
            nats_fp,
            root_fp,
            vec![],
            "member".to_string(),
            10_000,
        ));
        let config = TurnConfig {
            secret: "s".to_string(),
            uris: vec![],
            ttl_secs: 60,
            monthly_quota: 1,
        };
        let subject = subject_for(&nats_fp);
        let first = handle_turn_get(&subject, b"", Some(&config), &mut s, 1_000);
        let first_reply: TurnGetReply = serde_json::from_slice(&first).unwrap();
        assert!(first_reply.error.is_none(), "first mint must be admitted");

        let second = handle_turn_get(&subject, b"", Some(&config), &mut s, 1_000);
        let second_reply: TurnGetReply = serde_json::from_slice(&second).unwrap();
        assert_eq!(second_reply.error.as_deref(), Some("TURN quota exceeded"));
    }

    #[test]
    fn expired_session_record_is_treated_as_no_session() {
        let mut s = store();
        let nats_fp = fp(b"nats-d");
        s.put_session_record(SessionRecord::new(
            nats_fp,
            fp(b"root-d"),
            vec![],
            "member".to_string(),
            500, // already expired at now=1_000
        ));
        let config = TurnConfig {
            secret: "s".to_string(),
            uris: vec![],
            ttl_secs: 60,
            monthly_quota: 10,
        };
        let reply_bytes =
            handle_turn_get(&subject_for(&nats_fp), b"", Some(&config), &mut s, 1_000);
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("no active session"));
    }

    #[test]
    fn malformed_non_empty_request_payload_is_still_refused() {
        // Empty / `{}` bodies are valid (identity lives in the subject now), but a non-empty body
        // that isn't even parseable JSON is kept strict rather than silently ignored.
        let mut s = store();
        let config = TurnConfig {
            secret: "s".to_string(),
            uris: vec![],
            ttl_secs: 60,
            monthly_quota: 10,
        };
        let nats_fp = fp(b"nats-malformed-body");
        let reply_bytes = handle_turn_get(
            &subject_for(&nats_fp),
            b"not json",
            Some(&config),
            &mut s,
            1_000,
        );
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("malformed request"));
    }
}
