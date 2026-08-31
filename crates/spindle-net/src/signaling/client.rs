//! Client role: NATS-mediated connect (DESIGN.md §A6) — send the offer, receive the answer,
//! trickle ICE (both directions), end with [`crate::quic::QuicClient::from_socket`]. Graduated
//! from `spikes/s2-signaling/src/bin/s2-connect.rs`'s client leg (`run_client`).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use spindle_core::identity::DeviceKey;
use spindle_core::{Fingerprint, VerifyingKey};
use spindle_proto::signaling::{IcePayload, OfferPayload, Transport};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::quic::{ControlStream, QuicClient, SessionCert};

use super::bridge_incoming_ice;
use super::error::SignalingError;
use super::ice::{drive_ice_agent_trickle, start_local_ice};
use super::subject::{connect_subject, session_subject, IceDirection};
use super::wire::{new_offer_context, open_answer, seal_ice, seal_offer};

/// The host's identity, resolved by the caller before dialing (DESIGN.md §A5's directory/admission
/// flow is out of scope for this crate — by the time [`SignalingClient::connect`] is called, the
/// caller already knows who it means to reach and has pinned that host's keys).
///
/// # Two fingerprints, not one
///
/// A host has two distinct fingerprints and they can never be equal — collapsing them was a real
/// defect this struct's first shape carried, caught by `tests/live_signaling.rs` against the live
/// composed stack (the callout scopes subjects by `host_fp`, so a client publishing to
/// `host.<host_device_fp>.connect` gets `Permissions Violation for Publish`, and the host is
/// equally unable to subscribe there):
///
/// - [`Self::host_fp`] — `SHA-256(host_root_pk)`, the host's **Ed25519-only** root identity. Every
///   NATS subject in DESIGN.md §A5's table is scoped by this token (`host.<hfp>.connect`,
///   `host.<hfp>.sess.<cfp>.<sid>.<c2h|h2c>`), and it is exactly what
///   `spindle_helper::permissions::host_permissions` / `client_member_permissions` grant on.
/// - [`Self::device_fp`] — the host's envelope [`DeviceKey`] fingerprint. §A7's `k0`/`k1` schedule
///   needs an X25519 agreement half, which a root key does not have, so the host's envelope
///   identity is structurally forced to be a separate keypair. This is the `to_fp` an offer is
///   sealed to and the `from_fp` its answer arrives under.
///
/// `spikes/s2-signaling` kept the two apart from the start (`HostState { host_fp, host_device_fp,
/// .. }`); DESIGN.md never spells the relationship out, which is how the two came to be merged
/// during graduation.
pub struct HostIdentity {
    /// The host's root fingerprint — the NATS subject-scoping token only. Never an envelope field.
    pub host_fp: Fingerprint,
    /// The host's envelope device fingerprint — the offer's `to_fp` and the answer's `from_fp`.
    /// Never appears in a NATS subject.
    pub device_fp: Fingerprint,
    pub sign_pk: VerifyingKey,
    pub agree_pk: X25519PublicKey,
}

/// Wall-clock breakdown of one [`SignalingClient::connect_timed`] attempt, in the same four phases
/// `spikes/s2-signaling`'s `s2-connect.rs` reported, so a graduated run's numbers are directly
/// comparable to that spike's recorded ones.
///
/// Every phase is measured from the moment the offer is actually published — deliberately *not*
/// from entry into `connect`, which would fold this side's own ICE gathering and per-session
/// certificate generation (work that happens before a single byte is on the wire) into the
/// offer→answer figure. Same t0 the spike chose, for the same reason.
#[derive(Debug, Clone, Copy)]
pub struct ConnectTimings {
    /// Offer published -> answer received *and* fully verified/decrypted (§A7 receiver checks
    /// included).
    pub offer_to_answer: Duration,
    /// Answer verified -> ICE connectivity checks selected a candidate pair.
    pub answer_to_ice_selected: Duration,
    /// Candidate pair selected -> QUIC handshake complete on the punched socket, mutually
    /// fingerprint-pinned (A10.32).
    pub ice_selected_to_quic: Duration,
    /// Offer published -> QUIC handshake complete. The sum of the three phases above; a caller
    /// measuring "offer -> usable stream" adds its own first round trip on top.
    pub offer_to_quic_complete: Duration,
}

/// Tunable knobs for one connect attempt.
#[derive(Debug, Clone, Copy)]
pub struct ConnectOptions {
    /// Local address to bind the ICE UDP socket on (loopback/LAN gathering only this slice — see
    /// [`super::ice`]'s module doc comment).
    pub bind_ip: IpAddr,
    /// How long to wait for ICE connectivity checks to select a candidate pair.
    pub ice_timeout: Duration,
    /// How long to wait for the host's answer after publishing the offer (DESIGN.md §A6: "connect
    /// timeout covers the answer only"). This used to be implicit in
    /// `async_nats::Client::request`'s own default; §A10.36's switch to an explicitly-controlled
    /// reply inbox makes it this crate's to set.
    pub answer_timeout: Duration,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            bind_ip: IpAddr::from([0, 0, 0, 0]),
            ice_timeout: Duration::from_secs(10),
            answer_timeout: Duration::from_secs(5),
        }
    }
}

/// DESIGN.md §A6: NATS reports "nobody is subscribed to `host.<hfp>.connect`" as a 503
/// no-responders status message on the reply subject, not as silence -- that is what makes "host
/// is offline" instant rather than a timeout. `async_nats::Client::request` checked this
/// internally; a free function (rather than inlining the check at its one call site) so it can be
/// exercised without a live NATS server, since `async_nats::Message` is plain data.
fn reject_no_responders(reply: &async_nats::Message) -> Result<(), SignalingError> {
    if reply.status == Some(async_nats::StatusCode::NO_RESPONDERS) {
        return Err(SignalingError::HostOffline);
    }
    Ok(())
}

/// The client role's connect flow. Holds the caller-owned NATS client (never connects one itself —
/// see this module's parent's doc comment) and this device's own identity.
pub struct SignalingClient {
    nats: async_nats::Client,
    device: DeviceKey,
    device_fp: Fingerprint,
}

impl SignalingClient {
    pub fn new(nats: async_nats::Client, device: DeviceKey) -> Self {
        let device_fp = device.device_fp();
        Self {
            nats,
            device,
            device_fp,
        }
    }

    pub fn device_fp(&self) -> Fingerprint {
        self.device_fp
    }

    /// Runs one full connect attempt against `host`: seals and sends the offer, verifies and opens
    /// the answer, trickles ICE in both directions, and returns a QUIC control stream mutually
    /// fingerprint-pinned per DESIGN.md §A10.32.
    pub async fn connect(
        &self,
        host: &HostIdentity,
        opts: ConnectOptions,
    ) -> Result<ControlStream, SignalingError> {
        self.connect_timed(host, opts).await.map(|(c, _)| c)
    }

    /// [`Self::connect`], plus the phase-by-phase [`ConnectTimings`] for the attempt. Separate
    /// entry point rather than a changed return type so the common case stays a one-value
    /// `Result`; the connect flow itself is identical (`connect` is a thin wrapper over this).
    pub async fn connect_timed(
        &self,
        host: &HostIdentity,
        opts: ConnectOptions,
    ) -> Result<(ControlStream, ConnectTimings), SignalingError> {
        use futures_util::StreamExt;

        let cert = SessionCert::generate()?;
        // The client is always the ICE-controlling side (matches `s2-connect.rs`'s convention:
        // the offerer controls).
        let mut local_ice = start_local_ice(true, opts.bind_ip).await?;

        let ctx = new_offer_context();

        // Subscribe to the host's trickled ICE *before* sending the offer, so a host->client
        // candidate published immediately after the answer can never race ahead of this
        // subscription existing.
        let h2c_subject = session_subject(
            &host.host_fp,
            &self.device_fp,
            &ctx.sid,
            IceDirection::HostToClient,
        );
        let h2c_sub = self
            .nats
            .subscribe(h2c_subject)
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;

        // DESIGN.md §A10.36: the offer's `inbox` is a *binding* of the reply subject into signed
        // material, so this client must own that subject rather than let `Client::request` mint one
        // internally -- doing the latter is exactly the drift this decision found and fixed (the
        // signed value and the real reply subject were two independent `new_inbox()` results that
        // never matched, and nothing read the field, so nothing noticed). Subscribing before
        // publishing also removes the race where the answer arrives first.
        let inbox = self.nats.new_inbox();
        let mut answer_sub = self
            .nats
            .subscribe(inbox.clone())
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;

        let offer_payload = OfferPayload {
            inbox: inbox.clone(),
            transport: Transport::Quic,
            ufrag: local_ice.ufrag.clone(),
            pwd: local_ice.pwd.clone(),
            cert_fp: cert.fingerprint(),
        };
        // `host.device_fp` seals the envelope, `host.host_fp` scopes the subject -- see
        // `HostIdentity`'s doc comment for why these are two different values.
        let offer_env = seal_offer(
            &ctx,
            &self.device,
            self.device_fp,
            host.device_fp,
            &host.agree_pk,
            &offer_payload,
        );

        let offer_sent = Instant::now();
        self.nats
            .publish_with_reply(
                connect_subject(&host.host_fp),
                inbox,
                offer_env.to_canonical_bytes().into(),
            )
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;
        // Flush so the offer is actually on the wire before `answer_timeout` starts counting --
        // otherwise the timeout would partly measure our own send buffer draining rather than the
        // host's response. This is a deliberate addition, not a reproduction of what
        // `Client::request` did: async-nats' own explicit-inbox request path does not flush.
        // Ordering does not depend on this -- `subscribe` and `publish_with_reply` share one
        // ordered command channel on the same connection, so the SUB always precedes the PUB.
        self.nats
            .flush()
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;

        let reply = tokio::time::timeout(opts.answer_timeout, answer_sub.next())
            .await
            .map_err(|_| SignalingError::Timeout("connect offer/answer"))?
            .ok_or_else(|| {
                SignalingError::Nats("answer subscription closed before the answer arrived".into())
            })?;

        // DESIGN.md §A6: "no-responders on connect -> instant 'host is offline'". `Client::request`
        // used to check this for us; owning our own reply inbox (§A10.36) means we must check the
        // 503 status NATS delivers on that inbox ourselves, before treating the message as an
        // answer envelope.
        reject_no_responders(&reply)?;

        let answer_env = spindle_proto::artifacts::Envelope::from_canonical_bytes(&reply.payload)?;
        let (session_key, answer) = open_answer(
            &answer_env,
            &ctx,
            &self.device,
            self.device_fp,
            host.device_fp,
            &host.sign_pk,
            &host.agree_pk,
        )?;
        if answer.transport != Transport::Quic {
            return Err(SignalingError::UnsupportedTransport(answer.transport));
        }
        let answer_opened = Instant::now();

        // Trickle this side's own (single, loopback/LAN) candidate to the host, then mark
        // end-of-candidates -- both as their own separately-signed/sealed KIND_ICE envelopes
        // (DESIGN.md §A6: never batched).
        let c2h_subject = session_subject(
            &host.host_fp,
            &self.device_fp,
            &ctx.sid,
            IceDirection::ClientToHost,
        );
        let mut seq: u64 = 1;
        let candidate_env = seal_ice(
            &session_key,
            &self.device,
            self.device_fp,
            host.device_fp,
            &ctx.sid,
            seq,
            &IcePayload {
                candidate: Some(local_ice.candidate_line.clone()),
                end_of_candidates: false,
            },
        );
        self.nats
            .publish(
                c2h_subject.clone(),
                candidate_env.to_canonical_bytes().into(),
            )
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;
        seq += 1;
        let eoc_env = seal_ice(
            &session_key,
            &self.device,
            self.device_fp,
            host.device_fp,
            &ctx.sid,
            seq,
            &IcePayload {
                candidate: None,
                end_of_candidates: true,
            },
        );
        self.nats
            .publish(c2h_subject, eoc_env.to_canonical_bytes().into())
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;

        // Bridge the host's trickled ICE (received over NATS) into the sans-I/O agent's trickle
        // channel, then drive the agent to a selected candidate pair.
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let bridge = tokio::spawn(bridge_incoming_ice(
            h2c_sub,
            // Subject tokens (host root fp, client device fp) ...
            host.host_fp,
            self.device_fp,
            ctx.sid.clone(),
            IceDirection::HostToClient,
            session_key,
            host.sign_pk,
            // ... and envelope fingerprints (this device, the host's *envelope* identity).
            self.device_fp,
            host.device_fp,
            tx,
        ));

        let (remote_addr, _stats) = drive_ice_agent_trickle(
            &mut local_ice.agent,
            &local_ice.socket,
            // The offerer is the ICE-controlling side; the peer's credentials come from the
            // answer this side just verified.
            true,
            &answer.ufrag,
            &answer.pwd,
            rx,
            opts.ice_timeout,
        )
        .await?;
        bridge.abort();
        let ice_selected = Instant::now();

        let std_socket = local_ice.socket.into_std()?;
        let control =
            QuicClient::from_socket(std_socket, remote_addr, answer.cert_fp, &cert).await?;
        let quic_complete = Instant::now();

        let timings = ConnectTimings {
            offer_to_answer: answer_opened.duration_since(offer_sent),
            answer_to_ice_selected: ice_selected.duration_since(answer_opened),
            ice_selected_to_quic: quic_complete.duration_since(ice_selected),
            offer_to_quic_complete: quic_complete.duration_since(offer_sent),
        };
        Ok((control, timings))
    }
}

#[cfg(test)]
mod tests {
    use async_nats::StatusCode;

    use super::*;

    /// A minimal `async_nats::Message` for exercising [`reject_no_responders`] without a live NATS
    /// server -- every field is plain public data, so this is real `Message` handling, not a fake.
    fn message_with_status(status: Option<StatusCode>) -> async_nats::Message {
        async_nats::Message {
            subject: "_INBOX_test.abc123".into(),
            reply: None,
            payload: bytes::Bytes::new(),
            headers: None,
            status,
            description: None,
            length: 0,
        }
    }

    #[test]
    fn reject_no_responders_rejects_the_503_status() {
        let reply = message_with_status(Some(StatusCode::NO_RESPONDERS));
        let err = reject_no_responders(&reply).unwrap_err();
        assert!(
            matches!(err, SignalingError::HostOffline),
            "expected SignalingError::HostOffline, got {err:?}"
        );
    }

    #[test]
    fn reject_no_responders_accepts_a_message_with_no_status() {
        reject_no_responders(&message_with_status(None))
            .expect("a message with no status must not be treated as no-responders");
    }

    #[test]
    fn reject_no_responders_accepts_an_unrelated_status() {
        // Any other status (e.g. a real answer never carries one, but this proves the check is
        // specifically for 503, not "any status at all") must not be misread as no-responders.
        reject_no_responders(&message_with_status(Some(StatusCode::OK)))
            .expect("a non-503 status must not be treated as no-responders");
    }
}
