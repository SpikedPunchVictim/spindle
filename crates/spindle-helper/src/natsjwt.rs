//! NATS v2 JWT claim encoding/decoding for the Auth Callout responder (DESIGN.md §A4 step 1–3,
//! §A5).
//!
//! **Graduated from `spikes/s1-callout/src/natsjwt.rs`** (docs/SPIKES.md §S1 — **PASS, 19/19**
//! automated checks against a live `nats-server:2.10-alpine` v2.10.29, 2026-08-24; full record in
//! `spikes/s1-callout/RESULTS.md`). Every empirically-verified field-shape decision the spike
//! discovered is preserved verbatim here — nothing in the wire shape below is a fresh guess:
//!
//! - **`resp.ttl` is a plain JSON number of nanoseconds, never a Go duration string** (e.g. NOT
//!   `"120s"`). `time.Duration` has no custom `UnmarshalJSON`, so `encoding/json` decodes it as
//!   whatever `int64` alias it is — a bare number of nanoseconds. A string here fails deep inside
//!   server-side JSON unmarshaling (`Json: cannot unmarshal string into Go struct field
//!   ResponsePermission.nats.UserPermissionLimits.Permissions.resp.ttl of type time.Duration`),
//!   surfacing to the connecting client only as an undifferentiated `authorization violation`.
//!   Root-caused empirically against a live server (RESULTS.md).
//! - **`user_nkey` (the request's server-generated per-request correlation key) is distinct from
//!   `connect_opts.nkey` (the client's actual presented nkey, == `client_info.user`)** —
//!   `connect_opts.sig` is a signature over `client_info.nonce` made with `connect_opts.nkey`,
//!   never with `user_nkey`. Conflating the two makes every real nkey-signature check fail with
//!   no useful error (a bare `AuthorizationViolation`). This module only encodes/decodes JWT
//!   claims — the responder (see `src/bin/helper.rs`) is what reads these two fields apart from
//!   the raw `AuthorizationRequest` claims and must not confuse them.
//! - **`deny` is applied to both `pub.deny` and `sub.deny`** in [`user_nats_claims`], matching
//!   [`crate::permissions::SubjectPermissions::deny`]'s documented contract ("applied to both
//!   publish and subscribe"). An earlier spike version hard-coded `pub.deny` to `[]`, silently
//!   dropping the deny list on the publish side — inert under every caller's restrictive
//!   `pub_allow` at the time, but a real bug for any future blanket-allow caller.
//! - **`aud` on a User JWT is the target account's NAME** (e.g. `"APP"`), not its public key: in
//!   non-operator/config-based-accounts mode, nats-server's `auth_callout.go`
//!   (`assignAccountAndPermissions`) does `placement = arc.Audience;
//!   s.LookupAccount(placement)`. Not documented anywhere DESIGN.md/ADR-002 could have cited;
//!   found only by reading server source after the naive omit-`aud` version failed with an opaque
//!   `"Unable to validate expected prefixes - [account]"` error.
//! - **`iss` on an `AuthorizationResponse` MUST be an ACCOUNT-prefixed nkey ("A...")** — never the
//!   callout responder's own connection identity (a "U"-prefixed user nkey). Easy to get backwards
//!   (the responder is who *answers*, and reads naturally as "issuer"); nats-server's error gives
//!   almost no hint (`"Unable to validate expected prefixes - [account]"`).
//!   `AuthorizationResponseClaims.ExpectedPrefixes()` hard-codes `PrefixByteAccount`
//!   (`nats-io/jwt` v2 `authorization_claims.go`).
//!
//! # Why hand-rolled
//! A NATS v2 JWT is a compact JWS: `base64url(header) + "." + base64url(claims) + "." +
//! base64url(sig)`, where `sig = Ed25519(header_b64 + "." + claims_b64)` signed by the relevant
//! nkey. No mature Rust crate understands NATS's specific v2 claim JSON shape (the `nats` nested
//! object, `aud`-as-account-name, `AuthorizationResponseClaims`'s prefix requirement) — this
//! module hand-builds that JSON via `serde_json::Value` and uses [`nkeys`] only for the
//! underlying key material and Ed25519 signature primitive. `header` is always the constant
//! `{"typ":"JWT","alg":"ed25519-nkey"}`.

use base64::Engine;
use nkeys::KeyPair;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors from building or reading a NATS v2 JWT claim. Distinct from
/// [`crate::authz::RefusalReason`] — these are *encoding-layer* failures (malformed input, a
/// signing primitive erroring), never a policy decision; callers translate any of these into the
/// same uniform wire-facing refusal ([`crate::authz::UNIFORM_REFUSAL_MESSAGE`]) rather than
/// exposing this error's `Display` text to a connecting client.
#[derive(Debug, thiserror::Error)]
pub enum NatsJwtError {
    #[error("not a 3-part compact JWT (got {0} part(s))")]
    MalformedJwt(usize),
    #[error("invalid base64url in JWT part: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid JSON in JWT claims: {0}")]
    Json(#[from] serde_json::Error),
    #[error("nkey signing failed: {0}")]
    Sign(String),
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, NatsJwtError> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?)
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
}

/// A process-local counter mixed into the generated `jti` to keep it unique even when two claims
/// are encoded within the same clock tick. `jti` is a convenience/debugging aid only — nats-server
/// never validates its shape or uniqueness (confirmed empirically by S1's probe against a live
/// server) — so this is deliberately a boring, dependency-free scheme (wall-clock nanoseconds +
/// a monotonic counter) rather than pulling in an RNG crate for a non-cryptographic id.
static JTI_COUNTER: AtomicU64 = AtomicU64::new(0);

fn generate_jti() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = JTI_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}-{n:x}")
}

/// Signs `claims` (the full JWT body, including `iss`/`sub`/`exp`/the nested `nats` object) with
/// `signer`, producing the compact three-part JWT string. Inserts a `jti` if `claims` doesn't
/// already carry one (see [`generate_jti`]).
pub fn encode(mut claims: Value, signer: &KeyPair) -> Result<String, NatsJwtError> {
    let header = json!({"typ": "JWT", "alg": "ed25519-nkey"});
    let header_b64 = b64url(header.to_string().as_bytes());

    if claims.get("jti").is_none() {
        claims["jti"] = json!(generate_jti());
    }
    let claims_b64 = b64url(claims.to_string().as_bytes());

    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig = signer
        .sign(signing_input.as_bytes())
        .map_err(|e| NatsJwtError::Sign(e.to_string()))?;
    let sig_b64 = b64url(&sig);
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Decodes (WITHOUT signature verification — the caller trusts the transport this JWT arrived
/// over; see `src/bin/helper.rs`'s module docs for why the responder's own `$SYS.REQ.USER.AUTH`
/// request doesn't need a second signature check here) the middle (claims) part of a compact JWT
/// into a [`serde_json::Value`].
pub fn decode_claims_unverified(jwt: &str) -> Result<Value, NatsJwtError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(NatsJwtError::MalformedJwt(parts.len()));
    }
    let bytes = b64url_decode(parts[1])?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Builds the `nats` object for a User JWT (nats-io/jwt v2 `jwt.User`/`UserPermissionLimits`
/// shape, confirmed empirically — see this module's doc comment): permission allow/deny lists, an
/// optional `resp` (allow_responses) block, `subs`/`data`/`payload` limits (`-1` = unlimited,
/// matching the Go jwt library's `jwt.NoLimit`), and `allowed_connection_types`.
///
/// `resp`'s second tuple element is the TTL as nanoseconds — see this module's doc comment for
/// why that must be a plain JSON number, never a duration string.
#[allow(clippy::too_many_arguments)]
pub fn user_nats_claims(
    pub_allow: &[String],
    sub_allow: &[String],
    deny: &[String],
    resp: Option<(u32, i64)>,
    max_subs: i64,
    payload_bytes: i64,
    allowed_connection_types: &[&str],
) -> Value {
    let mut nats = json!({
        "pub": { "allow": pub_allow, "deny": deny },
        "sub": { "allow": sub_allow, "deny": deny },
        "subs": max_subs,
        "data": -1,
        "payload": payload_bytes,
        "type": "user",
        "version": 2,
        "allowed_connection_types": allowed_connection_types,
    });
    if let Some((max, ttl_ns)) = resp {
        nats["resp"] = json!({ "max": max, "ttl": ttl_ns });
    }
    nats
}

/// Full User JWT claims (top-level `ClaimsData` + nested `nats`): `iss` = the account signing
/// key, `sub` = the presented connection's `user_nkey` (from the authorization request), `exp` =
/// absolute unix seconds, `aud` = the target account's NAME (see this module's doc comment).
pub fn user_claims(
    issuer_account_pub: &str,
    target_account_name: &str,
    user_nkey_sub: &str,
    exp: u64,
    nats: Value,
) -> Value {
    json!({
        "iat": now_unix(),
        "iss": issuer_account_pub,
        "aud": target_account_name,
        "sub": user_nkey_sub,
        "exp": exp,
        "nats": nats,
    })
}

/// The `AuthorizationResponse` claims (nats-io/jwt v2 `jwt.AuthorizationResponseClaims`): `aud` =
/// the request's `server_id.id`; `sub` = the same `user_nkey` the request asked about.
///
/// **`account_pub` MUST be an account-prefixed nkey ("A...")** — see this module's doc comment.
pub fn authorization_response(
    account_pub: &str,
    server_id: &str,
    user_nkey_sub: &str,
    inner: Value,
) -> Value {
    json!({
        "iat": now_unix(),
        "iss": account_pub,
        "aud": server_id,
        "sub": user_nkey_sub,
        "nats": inner,
    })
}

pub fn response_ok(user_jwt: String) -> Value {
    json!({ "jwt": user_jwt, "type": "authorization_response", "version": 2 })
}

pub fn response_err(message: &str) -> Value {
    json!({ "error": message, "type": "authorization_response", "version": 2 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_kp() -> KeyPair {
        KeyPair::new_account()
    }

    #[test]
    fn encode_then_decode_roundtrips_claims_and_fills_in_a_jti() {
        let kp = account_kp();
        let claims = json!({"iss": kp.public_key(), "sub": "U123", "exp": 1_000});
        let jwt = encode(claims, &kp).expect("encode succeeds");
        let decoded = decode_claims_unverified(&jwt).expect("decode succeeds");
        assert_eq!(decoded["iss"], kp.public_key());
        assert_eq!(decoded["sub"], "U123");
        assert_eq!(decoded["exp"], 1_000);
        assert!(
            decoded["jti"].is_string() && !decoded["jti"].as_str().unwrap().is_empty(),
            "encode() must fill in a non-empty jti when the caller didn't supply one"
        );
    }

    #[test]
    fn encode_preserves_a_caller_supplied_jti() {
        let kp = account_kp();
        let claims = json!({"sub": "U1", "jti": "caller-chosen"});
        let jwt = encode(claims, &kp).unwrap();
        let decoded = decode_claims_unverified(&jwt).unwrap();
        assert_eq!(decoded["jti"], "caller-chosen");
    }

    #[test]
    fn two_encodes_of_the_same_claims_get_distinct_jtis() {
        let kp = account_kp();
        let jwt_a = encode(json!({"sub": "U1"}), &kp).unwrap();
        let jwt_b = encode(json!({"sub": "U1"}), &kp).unwrap();
        let a = decode_claims_unverified(&jwt_a).unwrap();
        let b = decode_claims_unverified(&jwt_b).unwrap();
        assert_ne!(a["jti"], b["jti"]);
    }

    #[test]
    fn signature_verifies_against_the_signer_public_key() {
        let kp = account_kp();
        let jwt = encode(json!({"sub": "U1"}), &kp).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .unwrap();
        let verifier = KeyPair::from_public_key(&kp.public_key()).unwrap();
        verifier
            .verify(signing_input.as_bytes(), &sig)
            .expect("signature must verify against the signer's own public key");
    }

    #[test]
    fn signature_does_not_verify_against_a_different_key() {
        let kp = account_kp();
        let other = account_kp();
        let jwt = encode(json!({"sub": "U1"}), &kp).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .unwrap();
        let verifier = KeyPair::from_public_key(&other.public_key()).unwrap();
        assert!(
            verifier.verify(signing_input.as_bytes(), &sig).is_err(),
            "a signature made by one account key must not verify against a different key"
        );
    }

    #[test]
    fn decode_rejects_a_jwt_with_the_wrong_number_of_parts() {
        let err = decode_claims_unverified("only.two").unwrap_err();
        assert!(matches!(err, NatsJwtError::MalformedJwt(2)));

        let err = decode_claims_unverified("no-dots-at-all").unwrap_err();
        assert!(matches!(err, NatsJwtError::MalformedJwt(1)));
    }

    #[test]
    fn decode_rejects_invalid_base64_in_the_claims_part() {
        let err = decode_claims_unverified("header.not!valid!base64.sig").unwrap_err();
        assert!(matches!(err, NatsJwtError::Base64(_)));
    }

    #[test]
    fn decode_rejects_valid_base64_that_is_not_json() {
        let not_json_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not a json object");
        let jwt = format!("header.{not_json_b64}.sig");
        let err = decode_claims_unverified(&jwt).unwrap_err();
        assert!(matches!(err, NatsJwtError::Json(_)));
    }

    #[test]
    fn user_nats_claims_ttl_is_a_plain_nanoseconds_number_not_a_duration_string() {
        let nats = user_nats_claims(
            &[],
            &[],
            &[],
            Some((1, 120_000_000_000)), // 120s in nanoseconds
            8,
            65536,
            &["STANDARD"],
        );
        assert_eq!(nats["resp"]["ttl"], json!(120_000_000_000i64));
        assert!(
            nats["resp"]["ttl"].is_number(),
            "resp.ttl must be a JSON number, never a Go-duration string like \"120s\""
        );
        assert_eq!(nats["resp"]["max"], json!(1));
    }

    #[test]
    fn user_nats_claims_omits_resp_when_not_requested() {
        let nats = user_nats_claims(&[], &[], &[], None, 8, 65536, &["STANDARD"]);
        assert!(nats.get("resp").is_none());
    }

    #[test]
    fn user_nats_claims_deny_applies_to_both_pub_and_sub() {
        let deny = vec!["_INBOX.>".to_string(), "$SYS.>".to_string()];
        let nats = user_nats_claims(&[], &[], &deny, None, 8, 65536, &["STANDARD"]);
        assert_eq!(nats["pub"]["deny"], json!(deny));
        assert_eq!(
            nats["sub"]["deny"],
            json!(deny),
            "deny must be mirrored onto sub.deny too, not just pub.deny"
        );
    }

    #[test]
    fn user_claims_aud_is_the_account_name_not_a_public_key() {
        let claims = user_claims("ACCTPUBKEY", "APP", "USUB", 1_000, json!({}));
        assert_eq!(
            claims["aud"], "APP",
            "aud must be the target account's NAME, not its nkey public key"
        );
    }

    #[test]
    fn authorization_response_shape_and_response_ok_err() {
        let ok = response_ok("some.jwt.string".to_string());
        assert_eq!(ok["jwt"], "some.jwt.string");
        assert_eq!(ok["type"], "authorization_response");
        assert_eq!(ok["version"], 2);
        assert!(ok.get("error").is_none());

        let err = response_err("authentication refused");
        assert_eq!(err["error"], "authentication refused");
        assert!(err.get("jwt").is_none());

        let resp = authorization_response("ACCTPUB", "server-1", "USUB", ok.clone());
        assert_eq!(resp["iss"], "ACCTPUB");
        assert_eq!(resp["aud"], "server-1");
        assert_eq!(resp["sub"], "USUB");
        assert_eq!(resp["nats"], ok);
    }
}
