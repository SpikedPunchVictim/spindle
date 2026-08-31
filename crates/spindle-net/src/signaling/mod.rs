//! NATS-mediated signaling (DESIGN.md §A6/§A7), graduated from `spikes/s2-signaling`'s
//! `s2-connect.rs` (see that spike's module doc comment and `RESULTS.md` for the empirical
//! groundwork this module rests on — a real connect/answer/trickle-ICE exchange run end-to-end
//! against the live composed stack). Both peer roles live here:
//!
//! - [`client::SignalingClient`] — sends the offer, receives the answer, trickles ICE, ends with
//!   [`crate::quic::QuicClient::from_socket`].
//! - [`host::SignalingHost`] — subscribes for offers, authorizes+verifies+answers, trickles ICE,
//!   ends with [`crate::quic::QuicServer::from_socket`].
//!
//! # The NATS client is passed in, not owned
//!
//! Both roles take an already-connected `async_nats::Client` as a constructor parameter. This
//! module never calls `async_nats::connect` itself and holds no global/static client — connection
//! lifecycle (URLs, credentials, reconnect policy) is entirely the caller's concern.
//!
//! # Layering (DESIGN.md §A9c boundary rule 3)
//!
//! `spindle-net` must never depend on `spindle-host-core`/`spindle-client-core`/`spindle-vfs`. Two
//! decisions in this module exist specifically because of that rule, both via an injected trait
//! rather than an inline lookup:
//! - [`authorize::ConnectAuthorizer`] — the host's "is this sender an active, non-revoked member
//!   device?" decision (DESIGN.md §A5); the member registry lives in `spindle-host-core`.
//! - [`host::SessionHandler`] — what a host actually *does* with a QUIC control stream once a
//!   session is established (the VFS RPC serve loop); that loop lives in `spindle-host-core::serve`
//!   too. See [`host`]'s module doc comment for why this second trait exists — the task brief for
//!   this slice only specified [`authorize::ConnectAuthorizer`], but "ending in
//!   `QuicServer::from_socket`" still leaves the question of who drives the resulting
//!   [`crate::quic::ControlStream`] to a serve loop, and that loop cannot live in this crate either.
//!
//! # Submodules
//!
//! - [`wire`] — pure offer/answer/ICE envelope construction and verification (no NATS/ICE/QUIC
//!   I/O) — the richest unit-testable surface for every §A7 receiver MUST-check.
//! - [`subject`] — NATS subject construction/parsing, matching `spindle-helper::permissions`'
//!   scoping exactly, plus the `_INBOX` reply-prefix check DESIGN.md §A6 requires.
//! - [`seq`] — [`seq::SeqFloor`], the per-`(sid, direction)` replay-window bookkeeping `seq`'s
//!   MUST-check needs a caller to maintain.
//! - [`ice`] — standalone sans-I/O ICE punching (`rtc-ice`), graduated unchanged from the spike.
//! - [`authorize`] — [`authorize::ConnectAuthorizer`] (see above).
//! - [`error`] — [`error::SignalingError`], every failure this module's functions can produce.
//! - [`client`] / [`host`] — the two peer roles' actual NATS/ICE/QUIC I/O.

pub mod authorize;
pub mod client;
pub mod error;
pub mod host;
pub mod ice;
pub mod seq;
pub mod subject;
pub mod wire;

pub use authorize::{ConnectAuthorizer, ConnectDecision};
pub use client::{ConnectOptions, HostIdentity, SignalingClient};
pub use error::SignalingError;
pub use host::{HostOptions, SessionHandler, SignalingHost};

use futures_util::StreamExt;
use spindle_core::envelope::SessionKey;
use spindle_core::{Fingerprint, VerifyingKey};
use spindle_proto::artifacts::Envelope;
use tokio::sync::mpsc;

use ice::TrickleEvent;
use seq::SeqFloor;
use subject::IceDirection;

/// Drains `sub` for the lifetime of this task, decoding+verifying each message as a trickled ICE
/// envelope (`k1`, DESIGN.md §A7) bound to exactly the expected `(host_fp, client_fp, sid,
/// direction)`, and forwards each accepted candidate/end-of-candidates marker to `tx`. Shared by
/// both [`client`] and [`host`] — the bridging logic (decode -> verify -> advance the seq floor ->
/// forward) does not differ between the two roles, only which side of the session they are.
///
/// `expected_host_fp`/`expected_client_fp` are the **NATS subject** tokens (the host's root
/// fingerprint and the client's device fingerprint — the two `<...>` slots in
/// `host.<h>.sess.<c>.<sid>.<dir>`), while `self_fp`/`peer_fp` are the **envelope** `to_fp`/
/// `from_fp` this side expects. For the client those two roles coincide (`expected_client_fp ==
/// self_fp`); for the host they never do, because a host's subject-scoping fingerprint and its
/// envelope device fingerprint are different keys entirely — see [`client::HostIdentity`]'s doc
/// comment.
///
/// Every rejected envelope is a soft failure (`tracing::warn!` + continue, never a fatal error
/// propagated up): DESIGN.md §A5's uniform-silent-drop philosophy applies here exactly as it does
/// to the connect offer itself — a single malformed or replayed trickled candidate must not abort
/// a session that may still complete via other, already-gathered candidates.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn bridge_incoming_ice(
    mut sub: async_nats::Subscriber,
    expected_host_fp: Fingerprint,
    expected_client_fp: Fingerprint,
    expected_sid: Vec<u8>,
    expected_direction: IceDirection,
    session_key: SessionKey,
    pinned_sender_key: VerifyingKey,
    self_fp: Fingerprint,
    peer_fp: Fingerprint,
    tx: mpsc::UnboundedSender<TrickleEvent>,
) {
    let mut seq_floor = SeqFloor::new();
    while let Some(msg) = sub.next().await {
        let env = match Envelope::from_canonical_bytes(&msg.payload) {
            Ok(env) => env,
            Err(error) => {
                tracing::warn!(%error, "malformed trickled ICE envelope; dropping");
                continue;
            }
        };
        let opened = match wire::open_ice(
            &env,
            msg.subject.as_str(),
            &expected_host_fp,
            &expected_client_fp,
            &expected_sid,
            expected_direction,
            &session_key,
            &pinned_sender_key,
            &self_fp,
            &peer_fp,
            &seq_floor,
        ) {
            Ok(opened) => opened,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "rejected trickled ICE envelope; dropping (uniform silent drop, DESIGN.md §A5)"
                );
                continue;
            }
        };
        seq_floor.advance(opened.seq);

        let event = if opened.payload.end_of_candidates {
            TrickleEvent::EndOfCandidates
        } else if let Some(candidate) = opened.payload.candidate {
            TrickleEvent::Candidate(candidate)
        } else {
            // Neither field meaningfully set -- the schema allows this combination (see
            // `IcePayload`'s doc comment) but there is nothing to forward.
            continue;
        };
        if tx.send(event).is_err() {
            // The receiver dropped -- `drive_ice_agent_trickle` already selected a pair and
            // stopped listening. Nothing left for this task to do.
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this module is the assertion */
    }
}
