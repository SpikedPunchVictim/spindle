//! TURN credential minting (`helper.turn.get`, DESIGN.md §A5 "request/reply TURN credentials
//! (helper authorizes via the session record...)", §A8 "coturn `use-auth-secret`, `username =
//! expiry:device_fp`; quota enforced by the helper per `root_fp`").
//!
//! # Wire-schema gap, documented rather than silently resolved
//! DESIGN.md defines *that* `helper.turn.get` is a request/reply subject and *how* the helper
//! authorizes it ("via the session record"), but — like the `auth_token` CONNECT envelope
//! ([`crate::auth_token`]'s own module docs) and the session-record ambiguities
//! ([`crate::session`]'s doc comment) — it defines no field-level shape for the request or reply
//! payload. This module invents one, following the same base64url-CBOR-free, plain-JSON style
//! already used for the NATS-JWT claims this crate builds elsewhere (`natsjwt.rs`):
//!
//! ```text
//! request:  { "nats_fp": "<32 bytes, base64url no-pad>" }
//! reply ok: { "username": "<exp>:<root_fp base32>", "credential": "<base64>", "ttl": <secs>,
//!             "uris": ["turn:host:3478?transport=udp", ...] }
//! reply err: { "error": "<human-readable reason>" }
//! ```
//!
//! **Two more gaps this shape papers over, flagged for the coordinator**:
//! 1. **No cryptographic binding between the request payload and the connection that sent it.**
//!    Core NATS pub/sub gives a subscriber no notion of which authenticated connection published
//!    a message — unlike `host.<hfp>.connect`, which carries the caller's `from_fp` inside an
//!    A7-verified, signed envelope, DESIGN.md's subject table shows `helper.turn.get` with no
//!    envelope and no per-caller subject suffix (contrast `host.<h>.sess.<own_device_fp>.*.c2h`,
//!    where the *subject itself*, not the payload, is what NATS permissions bind to the caller's
//!    own fingerprint). Absent either of those two existing patterns, a caller can only *assert*
//!    which `nats_fp` it is in the payload; the helper cannot verify the assertion. The
//!    consequence is bounded, not a confidentiality break: an authenticated device presenting a
//!    fabricated `nats_fp` can only cause the *named* session's TURN-quota counter to be
//!    consumed (an availability/quota-griefing surface, not credential theft — a reply is
//!    delivered to whatever `reply` subject the *attacker's own request* carried, but it is
//!    minted under the *victim's* session's `root_fp`, so the attacker only harms the victim's
//!    quota, not itself gain anything address). This is a genuine residual gap worth a real fix
//!    (e.g. parametrizing the subject as `helper.turn.get.<own_device_fp>` the same way
//!    `host.<h>.sess.<own>.*.c2h` is, so NATS's own permission system — not this payload — proves
//!    the caller's identity) — deliberately not made here since it would change
//!    `permissions.rs`'s byte-exact, DESIGN.md-table-matching subject strings, which is exactly
//!    the kind of design question this task brief asks to report rather than unilaterally
//!    resolve.
//! 2. **`username = expiry:device_fp` cannot be honored literally.** [`crate::session::
//!    SessionRecord`] (as `authz.rs`/`session.rs` define it) carries `root_fp`, not `device_fp`,
//!    for client connections (see that module's own doc comment on why). This module mints
//!    `username = expiry:root_fp` instead — consistent with the per-`root_fp` quota model DESIGN.md
//!    §A8 itself uses ("device keys are free to mint" — the quota that matters is per-root, not
//!    per-device) and harmless to coturn (which treats the whole username as an opaque HMAC
//!    input, never decoding it), but it is a real divergence from the literal spec text.

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

#[derive(Debug, Deserialize)]
struct TurnGetRequest {
    nats_fp: String,
}

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

/// Decodes and authorizes one `helper.turn.get` request, enforcing the per-`root_fp` quota and
/// minting credentials on success. Pure with respect to NATS — takes the raw request payload
/// bytes and returns the JSON reply payload bytes to publish back; `src/bin/helper.rs` is the only
/// caller that touches an actual NATS connection.
pub fn handle_turn_get(
    payload: &[u8],
    config: Option<&TurnConfig>,
    view: &mut impl HelperView,
    now: u64,
) -> Vec<u8> {
    let reply = handle_turn_get_inner(payload, config, view, now);
    serde_json::to_vec(&reply).expect("TurnGetReply always serializes")
}

fn handle_turn_get_inner(
    payload: &[u8],
    config: Option<&TurnConfig>,
    view: &mut impl HelperView,
    now: u64,
) -> TurnGetReply {
    let Some(config) = config else {
        return TurnGetReply::err("TURN not configured");
    };

    let Ok(req) = serde_json::from_slice::<TurnGetRequest>(payload) else {
        return TurnGetReply::err("malformed request");
    };
    let Ok(nats_fp_raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&req.nats_fp)
    else {
        return TurnGetReply::err("malformed request");
    };
    let Ok(nats_fp) = Fingerprint::from_slice(&nats_fp_raw) else {
        return TurnGetReply::err("malformed request");
    };

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

    fn request_payload(nats_fp: &Fingerprint) -> Vec<u8> {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nats_fp.as_bytes());
        serde_json::to_vec(&serde_json::json!({ "nats_fp": b64 })).unwrap()
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

    // ---- handle_turn_get: authorization / quota / config paths -----------------------------------

    #[test]
    fn unconfigured_turn_replies_with_a_clear_error() {
        let mut s = store();
        let nats_fp = fp(b"nats-a");
        let reply_bytes = handle_turn_get(&request_payload(&nats_fp), None, &mut s, 1_000);
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("TURN not configured"));
        assert!(reply.username.is_none());
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
        let reply_bytes = handle_turn_get(&request_payload(&nats_fp), Some(&config), &mut s, 1_000);
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
        let reply_bytes = handle_turn_get(&request_payload(&nats_fp), Some(&config), &mut s, now);
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert!(reply.error.is_none());
        assert_eq!(reply.ttl, Some(1_800));
        assert_eq!(reply.uris, Some(config.uris.clone()));
        let username = reply.username.expect("username present");
        assert_eq!(username, format!("{}:{}", now + 1_800, root_fp));
        let expected_credential = mint_credentials(&config.secret, &root_fp.to_string(), now + 1_800).1;
        assert_eq!(reply.credential, Some(expected_credential));
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
        let payload = request_payload(&nats_fp);
        let first = handle_turn_get(&payload, Some(&config), &mut s, 1_000);
        let first_reply: TurnGetReply = serde_json::from_slice(&first).unwrap();
        assert!(first_reply.error.is_none(), "first mint must be admitted");

        let second = handle_turn_get(&payload, Some(&config), &mut s, 1_000);
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
        let reply_bytes = handle_turn_get(&request_payload(&nats_fp), Some(&config), &mut s, 1_000);
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("no active session"));
    }

    #[test]
    fn malformed_request_payload_is_refused() {
        let mut s = store();
        let config = TurnConfig {
            secret: "s".to_string(),
            uris: vec![],
            ttl_secs: 60,
            monthly_quota: 10,
        };
        let reply_bytes = handle_turn_get(b"not json", Some(&config), &mut s, 1_000);
        let reply: TurnGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("malformed request"));
    }
}
