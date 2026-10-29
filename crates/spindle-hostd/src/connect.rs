//! The headless host's NATS connection: a fresh session nkey, a fresh per-connect
//! [`spindle_proto::artifacts::HostSessionAttestation`], and the CONNECT `auth_token` envelope
//! that carries the host's root -> operating-key certificate chain.
//!
//! This is the production counterpart of `spindle_test_fixtures::connect_host` (the fixture a
//! live test uses) and of `crates/spindle-helper/src/bin/helper.rs`'s responder-side wiring: the
//! same sequence DESIGN.md §A4 specifies, with a real [`HostIdentity`] instead of fixture seeds.
//!
//! # The token is minted once per `connect_host` call, not per reconnect
//!
//! DESIGN.md §A4 step 3 and A10.40 make the host's NATS nkey **per-session**: [`KeyPair::new_user`]
//! creates a new one on every [`connect_host`] call, the operating key signs a fresh
//! `HostSessionAttestation` over that session's `nats_fp`, and the resulting `auth_token` is
//! handed to [`async_nats::ConnectOptions::token`] once. async-nats 0.35 does not re-run this
//! function on an automatic reconnect: its reconnect path calls the same connector
//! (`async-nats-0.35.1/src/lib.rs`, `handle_reconnect`), which re-sends the static
//! `auth_token` from the saved options (`connector.rs:193`). The attestation inside that token is
//! valid only within its ±2 minute window, so a reconnect later than that is refused by the
//! callout.
//!
//! [`connect_host`] therefore sets `.max_reconnects(1)` — the initial attempt is attempt one;
//! every later attempt fails immediately and closes the client. The headless binary treats that
//! close as terminal and relies on process restart to re-authenticate (a fresh process mints a
//! fresh nkey, attestation, and token, per A10.43/A10.44). Without the bound, an unlimited
//! reconnect loop would retry a credential that can never verify again, hiding a permanently
//! dead host behind a client that still looks alive; with it, the loss is a visible close.
//!
//! The auth-callback escape hatch does not help here: async-nats 0.35 encodes whatever an auth
//! callback returns into a `String` (`connector.rs`, `URL_SAFE_NO_PAD.encode(auth.signature)`), so
//! it cannot carry this envelope's raw bytes. The callback would need raw 64-byte signature bytes,
//! which `Option<String>` cannot represent.
//!
//! # `now` is the moment of connect, never process start
//!
//! Both the `HostSessionAttestation` and the `HostOpKeyCert` it accompanies are checked against a
//! ±2 minute server-time window (A7b; see `HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS` in
//! `spindle_core::artifacts`). The certificate is minted once per process at startup, but the
//! attestation is not a process-start value: the caller must pass the wall clock read at the
//! moment it calls [`connect_host`]. Passing a startup timestamp would make every reconnect more
//! than two minutes into the process fail authentication while looking, from this function's
//! signature, like a perfectly ordinary connect.
//!
//! # The admission token is optional
//!
//! `admission_token_bytes: None` omits the `admission_token` key from the envelope entirely, not
//! just its value. That is the legitimate shape for a host's second and later connections
//! (DESIGN.md §A3b: an already-admitted host connects on its certificate alone), and it is why
//! the field is optional here while `session_attest` is not.
//!
//! # Connection events are logged, credentials are not
//!
//! [`async_nats::ConnectOptions::event_callback`] is installed so an authentication failure — the
//! callout's refusal reaches the client as an event/`-ERR`, not as a typed `connect` error — is
//! visible at `debug` instead of being swallowed by the fire-and-forget client API. The callback
//! logs [`async_nats::Event`]'s own `Display` only. It must never log the `auth_token` or the
//! session nkey seed: both are credentials, and this crate's redaction policy exempts no
//! credential.

use base64::Engine as _;
use nkeys::KeyPair;
use spindle_core::artifacts::issue_host_session_attestation;
use spindle_core::Fingerprint;
use spindle_proto::auth_token::encode_host_auth_token;

use crate::HostIdentity;

/// Everything [`connect_host`] can fail with before a client exists. A failure returns no
/// partially-authenticated connection: the session nkey, attestation, and token are all local
/// values until the single `connect` call succeeds.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// Creating the per-session user nkey or reading its seed failed. `nkeys`' error text carries a
    /// length, position, or checksum — never the seed itself.
    #[error("host session nkey error: {0}")]
    Nkey(#[from] nkeys::error::Error),

    /// `async_nats` refused or could not complete the connection. Its `Display` may name the
    /// operator's own NATS endpoint (permitted configuration under this crate's redaction
    /// policy); it never carries the `auth_token` or the nkey seed.
    #[error("host NATS connect failed: {0}")]
    Nats(#[from] async_nats::ConnectError),
}

/// Connects the headless host to `nats_url` with a fresh per-session nkey and a freshly-minted
/// host CONNECT `auth_token`.
///
/// `now` must be the wall-clock second at the moment of this call (see the module docs' "`now` is
/// the moment of connect" section). `admission_token_bytes`, when present, is the raw bytes of the
/// admission-token file; this function embeds them verbatim and does not validate them — the
/// Auth Callout (the helper) is the verifier.
pub async fn connect_host(
    identity: &HostIdentity,
    nats_url: &str,
    admission_token_bytes: Option<Vec<u8>>,
    now: u64,
) -> Result<async_nats::Client, ConnectError> {
    let session = KeyPair::new_user();
    let nats_fp = nats_fp_for_session(&session)?;
    let token = mint_auth_token(identity, nats_fp, admission_token_bytes.as_deref(), now);

    let client = async_nats::ConnectOptions::new()
        .event_callback(|event| async move {
            // `Event`'s Display is a fixed description of the event kind. Deliberately not
            // `{event:?}` or anything that could grow to include connect options.
            tracing::debug!(event = %event, "host NATS connection event");
        })
        // The initial attempt only. A reconnect replays the static `token` below
        // (`async-nats-0.35.1/src/connector.rs:193`), whose attestation is stale after ±2
        // minutes, so a retry is guaranteed to fail and would hide the lost connection forever.
        // See this module's "minted once per `connect_host` call" section.
        .max_reconnects(1)
        .nkey(session.seed()?)
        .token(token)
        .connect(nats_url)
        .await?;
    Ok(client)
}

/// `nats_fp = SHA-256(raw session public key)` — the same derivation the Auth Callout uses for
/// `client_info.user` / the attestation's `nats_fp` (DESIGN.md §A4 step 3).
fn nats_fp_for_session(session: &KeyPair) -> Result<Fingerprint, nkeys::error::Error> {
    let (_prefix, raw) = nkeys::from_public_key(&session.public_key())?;
    Ok(Fingerprint::of_parts(&[&raw]))
}

/// Builds the base64url CONNECT `auth_token` for one session. Split out of [`connect_host`] so the
/// envelope can be exercised without a broker (this crate's unit tests) while the live path still
/// has exactly one construction site.
fn mint_auth_token(
    identity: &HostIdentity,
    nats_fp: Fingerprint,
    admission_token_bytes: Option<&[u8]>,
    now: u64,
) -> String {
    let attestation = issue_host_session_attestation(&identity.op_signing, nats_fp, now);
    let envelope = encode_host_auth_token(
        &identity.root.public_key().to_bytes(),
        &identity.op_cert.to_canonical_bytes(),
        &attestation.to_canonical_bytes(),
        admission_token_bytes,
    );
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mint_host_identity, ROOT_SEED_LEN};

    const NOW: u64 = 1_700_000_000;

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    /// The derivation [`connect_host`] feeds into the attestation is the one the callout checks:
    /// fingerprint over the *raw* 32-byte public key, not the encoded nkey string.
    #[test]
    fn session_nkey_maps_to_the_fingerprint_of_its_raw_public_key() {
        let session = KeyPair::new_user();
        let (_prefix, raw) = nkeys::from_public_key(&session.public_key()).expect("valid nkey");

        assert_eq!(
            nats_fp_for_session(&session).expect("valid nkey"),
            Fingerprint::of_parts(&[&raw])
        );
    }

    /// Without a broker, at least assert the *contents* of what would be presented: the token is
    /// valid base64url and carries this identity's root public key, its operating-key certificate,
    /// the session attestation over the requested `ts`, and the admission token, each as its own
    /// `to_canonical_bytes()` byte string.
    #[test]
    fn token_decodes_to_the_expected_artifact_bytes() {
        let identity = mint_host_identity([0x5a; ROOT_SEED_LEN], NOW);
        let session = KeyPair::new_user();
        let nats_fp = nats_fp_for_session(&session).expect("valid nkey");
        let admission_token = [0xA5u8; 11];
        let connect_at = NOW + 7;

        let token = mint_auth_token(&identity, nats_fp, Some(&admission_token), connect_at);
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.as_bytes())
            .expect("token is unpadded base64url");

        assert!(contains_subslice(
            &decoded,
            &identity.root.public_key().to_bytes()
        ));
        assert!(contains_subslice(
            &decoded,
            &identity.op_cert.to_canonical_bytes()
        ));
        let attestation = issue_host_session_attestation(&identity.op_signing, nats_fp, connect_at);
        assert!(contains_subslice(
            &decoded,
            &attestation.to_canonical_bytes()
        ));
        assert!(contains_subslice(&decoded, &admission_token));
    }

    /// The `None` case must be key *omission* in the envelope, so a second connection's token is
    /// strictly shorter than a first connection's rather than carrying an empty byte string.
    #[test]
    fn no_admission_token_means_no_admission_token_bytes_in_the_envelope() {
        let identity = mint_host_identity([0x5b; ROOT_SEED_LEN], NOW);
        let session = KeyPair::new_user();
        let nats_fp = nats_fp_for_session(&session).expect("valid nkey");

        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(mint_auth_token(&identity, nats_fp, None, NOW).as_bytes())
            .expect("token is unpadded base64url");

        assert!(
            !decoded
                .windows(b"admission_token".len())
                .any(|window| window == b"admission_token"),
            "a host with no admission token must not carry the key at all"
        );
    }
}
