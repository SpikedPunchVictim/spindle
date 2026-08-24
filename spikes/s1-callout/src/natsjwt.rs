//! Hand-rolled NATS v2 JWT claim encoding (task brief: "there is no mature Rust nats-jwt crate —
//! document the claim structures you had to construct, field by field, in RESULTS.md"). See
//! RESULTS.md's "JWT claim structures" section for the field-by-field provenance of every shape
//! below — each was either read directly off a real `$SYS.REQ.USER.AUTH` request captured from
//! the live server (`src/bin/probe.rs`), or empirically verified by round-tripping a generated
//! User JWT through a real `nats-server` connection and observing accept/reject.
//!
//! A NATS v2 JWT is a compact JWS: `base64url(header) + "." + base64url(claims) + "." +
//! base64url(sig)`, where `sig = Ed25519(header_b64 + "." + claims_b64)` signed by the relevant
//! nkey `KeyPair`. `header` is always `{"typ":"JWT","alg":"ed25519-nkey"}` — this crate hand-rolls
//! that constant rather than depending on a general JWT crate (none understand nkey signing or
//! the NATS-specific `nats` claim envelope).

use base64::Engine;
use nkeys::KeyPair;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
}

/// Signs `claims` (the full JWT body, including `iss`/`sub`/`exp`/the nested `nats` object) with
/// `signer`, producing the compact three-part JWT string. `claims` must NOT include a `jti` —
/// this function computes and inserts one, matching the real server's convention observed in
/// `probe.rs`'s captured request: `jti` is a base32-ish uppercase hash-looking token. This spike
/// uses a simple hex digest of the header+claims bytes prefixed nothing fancy required — the
/// server never validates `jti`'s *shape*, only that user JWTs round-trip through its own
/// generation, which this spike's own responses do not need to prove; `jti` is set as a
/// convenience/debugging aid, not a checked field for the responses this spike issues.
pub fn encode(mut claims: Value, signer: &KeyPair) -> String {
    let header = json!({"typ": "JWT", "alg": "ed25519-nkey"});
    let header_b64 = b64url(header.to_string().as_bytes());

    if claims.get("jti").is_none() {
        // Cheap non-cryptographic placeholder unique id — good enough for a spike; a real
        // implementation would use the base32-encoded SHA-256 of the claims per nats-io/jwt.
        let nonce: u64 = rand::random();
        claims["jti"] = json!(format!("{nonce:x}"));
    }
    let claims_b64 = b64url(claims.to_string().as_bytes());

    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig = signer
        .sign(signing_input.as_bytes())
        .expect("nkey signing never fails for a valid seed keypair");
    let sig_b64 = b64url(&sig);
    format!("{signing_input}.{sig_b64}")
}

/// Decodes (WITHOUT signature verification — this spike's responder trusts the server's own
/// transport; the request arrives over the responder's own authenticated `$SYS` connection) the
/// middle (claims) part of a compact JWT into a [`serde_json::Value`].
pub fn decode_claims_unverified(jwt: &str) -> anyhow::Result<Value> {
    let parts: Vec<&str> = jwt.split('.').collect();
    anyhow::ensure!(parts.len() == 3, "not a 3-part JWT");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Builds the `nats` object for a User JWT (nats-io/jwt v2 `jwt.User`/`UserPermissionLimits`
/// shape, confirmed empirically — see RESULTS.md): permission allow/deny lists, an optional
/// `resp` (allow_responses) block, `subs`/`data`/`payload` limits (`-1` = unlimited, matching the
/// Go jwt library's `jwt.NoLimit`), and `allowed_connection_types`.
///
/// `deny` is applied to **both** `pub.deny` and `sub.deny`, matching
/// `spindle_helper::permissions::SubjectPermissions::deny`'s documented contract ("applied to
/// both publish and subscribe"). An earlier version of this function hard-coded `pub.deny` to an
/// empty array, silently dropping the deny list on the publish side; every current caller happens
/// to also pass a restrictive (non-blanket) `pub_allow`, under which NATS's allow-list semantics
/// make the omission inert in practice, but it diverged from the documented contract and would
/// have mattered for any future blanket/no-allow-list caller. Caught during S1 by re-reading the
/// `SubjectPermissions` doc comment while root-causing an unrelated failure (RESULTS.md).
///
/// `resp`'s second tuple element is the TTL as **nanoseconds, encoded as a plain JSON number** —
/// NOT a Go duration string like `"120s"`. That was the natural first guess (Go's
/// `time.Duration` has a human-readable `String()` form) and it is wrong: plain `time.Duration`
/// has no custom `UnmarshalJSON`, so `encoding/json` decodes it as whatever `int64` type alias it
/// is — a bare number of nanoseconds. Presenting a string here doesn't fail politely either: the
/// server rejects the whole User JWT deep inside JSON unmarshaling with `Json: cannot unmarshal
/// string into Go struct field ResponsePermission.nats.UserPermissionLimits.Permissions.resp.ttl
/// of type time.Duration`, surfacing to the connecting client as a bare `authorization
/// violation`, no more specific than any other rejection. Root-caused empirically against a live
/// nats-server v2.10.29 (RESULTS.md).
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
/// key (the APP account's own nkey in this spike's non-operator config — see RESULTS.md),
/// `sub` = the presented connection's `user_nkey` (from the authorization request), `exp` =
/// absolute unix seconds.
///
/// **`aud` = the target account's NAME (e.g. `"APP"`), not its public key.** Confirmed by reading
/// nats-server v2.10.29's `server/auth_callout.go` (`assignAccountAndPermissions`): in
/// non-operator/config-based-accounts mode, `placement = arc.Audience` and
/// `s.LookupAccount(placement)` — the generated user is placed into whichever account NAME this
/// JWT's `aud` names. This is *not* documented anywhere DESIGN.md/ADR-002 could have cited; it
/// was found only by reading the server source after the naive omit-`aud` version failed with an
/// opaque "Unable to validate expected prefixes - [account]" error (see RESULTS.md).
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

/// The `AuthorizationResponse` claims (nats-io/jwt v2 `jwt.AuthorizationResponseClaims`):
/// `aud` = the request's `server_id.id` (empirically required — `decodeResponse` in
/// nats-server's `auth_callout.go` rejects a response whose `aud` doesn't match its own server
/// id); `sub` = the same `user_nkey` the request asked about.
///
/// **`iss` MUST be an ACCOUNT-prefixed nkey ("A...")** — NOT the callout responder's own
/// connection identity (a "U"-prefixed user nkey, `auth_callout.auth_users` in server.conf).
/// This is easy to get backwards (the responder user is who *answers* the request, so it reads
/// naturally as the "issuer") and nats-server's error message gives almost no hint: an `iss` of
/// the wrong prefix produces the opaque `"Unable to validate expected prefixes - [account]"`,
/// surfacing as a plain `AuthorizationViolation` on the connecting client with no further detail
/// in default logging. Root-caused by reading `nats-io/jwt` v2's `decoder.go::Decode()`, which
/// (after verifying the signature) separately checks `claim.ExpectedPrefixes()` against the
/// claim's own `iss` — and `AuthorizationResponseClaims.ExpectedPrefixes()` hard-codes
/// `[]nkeys.PrefixByte{nkeys.PrefixByteAccount}` (`nats-io/jwt` v2
/// `authorization_claims.go`). This spike signs the response with the same APP-account keypair
/// that signs the inner User JWT — the callout user's own nkey is used only for the responder's
/// own NATS-level connection permissions (subscribing to `$SYS.REQ.USER.AUTH`), never for
/// signing any JWT.
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
