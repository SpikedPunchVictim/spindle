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
//! [`connect_host`] therefore sets `.max_reconnects(1)`. async-nats resets its attempt counter
//! after every successful connect (`connector.rs:286`, `self.attempts = 0`), so the bound means
//! **one reconnect attempt per disconnect**: if that attempt fails, the client closes instead of
//! retrying forever. A reconnect that lands inside the attestation's ±2 minute window can still
//! verify — an already-admitted host presents no admission token, and the server checks only the
//! skew — but one after the window never will. The headless binary treats any loop exit as
//! terminal and relies on process restart to re-authenticate (a fresh process mints a fresh nkey,
//! attestation, and token, per A10.43/A10.44). Without the bound, an unlimited reconnect loop
//! would retry a credential that can never verify again, hiding a permanently dead host behind a
//! client that still looks alive; with it, the loss is a visible close.
//!
//! The auth-callback escape hatch does not solve this either. async-nats 0.35 copies
//! `auth.token` verbatim (`connector.rs`, `connect_info.auth_token = auth.token`), so the
//! envelope itself could be carried, but it base64-encodes `auth.signature` again —
//! `connect_info.signature = auth.signature.map(|signature| URL_SAFE_NO_PAD.encode(signature))`
//! — and `auth.signature` is an `Option<String>`. A callback therefore cannot hand the client
//! the raw 64-byte signature a fresh nkey handshake needs; any value it supplies is encoded a
//! second time. Re-minting the session credential inside a callback is not available, which is
//! why bounding the retry is the honest option.
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
//!
//! # The `HostDeviceCert` publish cadence rides on the same callback [A10.37]
//!
//! DESIGN.md A10.37 requires the host to publish its `HostDeviceCert` on **every** registry
//! connect. This function owns that cadence so a library consumer gets it for free: it mints the
//! certificate before connecting (from this process's identity, A10.35), keeps its canonical bytes
//! in an [`Arc`], publishes once after the connect returns, flushes, and republishes the **same
//! cached bytes** whenever a background pump learns — through the event callback's channel — that
//! [`async_nats::Event::Connected`] fired again.
//!
//! async-nats 0.35 has no separate "reconnected" event variant — `Connected` is emitted on the
//! initial connect and again after every successful reconnect (`connector.rs` sends it in the same
//! success branch `handle_reconnect` reaches). The pump discards the first signal it receives
//! (the initial connect, already covered by the explicit publish below) and publishes on every
//! later one; signals arrive in the order the callback emitted them, so the first one really is
//! the initial connect. The bytes are reused rather than re-minted because the certificate chains
//! to this process's operating key and embeds this process's envelope keys, and neither changes
//! across a reconnect — re-minting would produce the same bytes again. A restart mints a fresh
//! identity (A10.43/A10.44), and its fresh bytes replace the helper's cached copy (A10.37).
//!
//! A publish-only subject has no broker ack (§A5). The explicit publish's local error is
//! propagated, and the follow-up [`async_nats::Client::flush`] confirms the server accepted what
//! was written on this connection; a republish failure is only logged, because a background pump
//! has no caller to return to. A server-side refusal still surfaces only as a connection
//! event/close.
//!
//! # The reconnect publisher is not allowed to own the client [reference-cycle note]
//!
//! [`async_nats::Client`] owns the `ConnectOptions` that own the `event_callback` closure. If that
//! closure captured a client (or an `Arc<Mutex<Option<Client>>>` holding one), the client would
//! own itself: dropping every external handle would leave the connection alive forever, and a
//! long-lived library consumer (the planned Tauri shell, reconnecting in-process) would leak one
//! live NATS connection per `connect_host` call. The callback therefore holds only an
//! [`tokio::sync::mpsc::UnboundedSender`] signal; a small pump task spawned after `connect()` owns
//! the one client clone it needs, and [`DevCertPublisher`]'s `Drop` aborts that task. The caller
//! holds the guard for the connection's lifetime, so the pump's clone is bounded by the guard and
//! dropping the guard plus the last client handle really does close the connection.

use std::sync::Arc;

use base64::Engine as _;
use nkeys::KeyPair;
use spindle_core::artifacts::issue_host_session_attestation;
use spindle_core::Fingerprint;
use spindle_proto::auth_token::encode_host_auth_token;
use tokio::sync::mpsc;

use crate::devcert::{device_cert_subject, mint_device_cert};
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

    /// The host device certificate could not be handed to the NATS client (a local queue/payload
    /// error). Carries the same harmless `Display` an [`async_nats::PublishError`] does.
    #[error("publishing the host device certificate failed: {0}")]
    Publish(#[from] async_nats::PublishError),

    /// The follow-up flush failed, so the certificate's delivery to the server could not be
    /// confirmed. async-nats 0.35 does not re-export its flush error type, so its `Display` is
    /// kept as text; it is static kind text, never payload bytes.
    #[error("flushing the host device certificate publish failed: {0}")]
    Flush(String),
}

/// Keeps the reconnect-republish task alive, and aborts it when dropped.
///
/// [`connect_host`] returns one of these alongside the client. Hold it for as long as the
/// connection should be republished on reconnect; dropping it stops the pump (and aborts its
/// in-flight publish). It is a separate value rather than something hidden in a wrapper because
/// the binary needs to bind it before moving the client into [`crate::HostDaemon`], keeping the
/// guard alive until the process's select returns.
///
/// See this module's "reference-cycle note": the guard is what bounds the pump's client clone, so
/// dropping every client handle *and* this guard closes the connection.
pub struct DevCertPublisher {
    handle: tokio::task::JoinHandle<()>,
}

impl DevCertPublisher {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self { handle }
    }
}

impl Drop for DevCertPublisher {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Connects the headless host to `nats_url` with a fresh per-session nkey and a freshly-minted
/// host CONNECT `auth_token`, and returns the client together with the
/// [`DevCertPublisher`] guard that keeps its reconnect-republish task alive.
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
) -> Result<(async_nats::Client, DevCertPublisher), ConnectError> {
    let session = KeyPair::new_user();
    let nats_fp = nats_fp_for_session(&session)?;
    let token = mint_auth_token(identity, nats_fp, admission_token_bytes.as_deref(), now);

    // A10.37: mint this process's device certificate **before** connecting, so the bytes are ready
    // to publish both on the explicit connect below and on every later reconnect. See this
    // module's "The `HostDeviceCert` publish cadence" section.
    let cert_subject = device_cert_subject(identity);
    let cert_bytes = Arc::new(mint_device_cert(identity, now).to_canonical_bytes());

    // The callback holds a bare signal channel, never a client — see this module's
    // "reference-cycle note". It fires for the initial connect too; the pump discards that first
    // signal because the explicit publish below covers connection one.
    let (connected_tx, mut connected_rx) = mpsc::unbounded_channel::<()>();

    let client = async_nats::ConnectOptions::new()
        .event_callback(move |event| {
            let connected_tx = connected_tx.clone();
            async move {
                // `Connected` is emitted for the initial connect and for every successful
                // reconnect; async-nats 0.35 has no distinct reconnected variant.
                if matches!(event, async_nats::Event::Connected) {
                    // A closed receiver means the guard was dropped; nothing to signal.
                    let _ = connected_tx.send(());
                }
                // `Event`'s Display is a fixed description of the event kind. Deliberately not
                // `{event:?}` or anything that could grow to include connect options.
                tracing::debug!(event = %event, "host NATS connection event");
            }
        })
        // One reconnect attempt per disconnect. A reconnect replays the static `token` below
        // (`async-nats-0.35.1/src/connector.rs:193`); the attempt counter resets after every
        // successful connect (`connector.rs:286`), so this admits one retry before the client
        // closes. That retry verifies only inside the attestation's ±2 minute window — after it,
        // never. See this module's "minted once per `connect_host` call" section.
        .max_reconnects(1)
        .nkey(session.seed()?)
        .token(token)
        .connect(nats_url)
        .await?;

    // The pump owns the one client clone needed to republish; the returned guard aborts it, which
    // is what keeps that clone from outliving the caller's client.
    let pump_client = client.clone();
    let pump_subject = cert_subject.clone();
    let pump_bytes = Arc::clone(&cert_bytes);
    let handle = tokio::spawn(async move {
        // First signal = the initial connect (events are delivered in order); the explicit publish
        // below already covers it, so drop it rather than publishing a duplicate.
        if connected_rx.recv().await.is_none() {
            return;
        }
        while connected_rx.recv().await.is_some() {
            // Same cached bytes as the first publish: the op key and envelope keys do not change
            // across a reconnect (see the module docs).
            let bytes: Vec<u8> = pump_bytes.as_ref().clone();
            if let Err(error) = pump_client
                .publish(pump_subject.clone(), bytes.into())
                .await
            {
                tracing::warn!(
                    error = %error, // redaction-ok: async_nats::PublishError Display is fixed kind text plus a length/closed-queue source; never the certificate bytes
                    "failed to republish the host device certificate after reconnect"
                );
            }
        }
    });
    let publisher = DevCertPublisher::new(handle);

    // The initial publish, then a flush: `publish` only queues, and the flush completes once the
    // server has accepted everything written on this connection. Both failures are returned so the
    // caller can refuse to serve with an unpublished certificate. See the module docs for why this
    // still does not order the publish against the helper's ingest on another connection.
    let initial_bytes: Vec<u8> = cert_bytes.as_ref().clone();
    client.publish(cert_subject, initial_bytes.into()).await?;
    client
        .flush()
        .await
        .map_err(|error| ConnectError::Flush(error.to_string()))?;

    Ok((client, publisher))
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
