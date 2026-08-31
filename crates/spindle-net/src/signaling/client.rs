//! Client role: NATS-mediated connect (DESIGN.md §A6) — send the offer, receive the answer,
//! trickle ICE (both directions), end with [`crate::quic::QuicClient::from_socket`]. Graduated
//! from `spikes/s2-signaling/src/bin/s2-connect.rs`'s client leg (`run_client`).

use std::net::IpAddr;
use std::time::Duration;

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
pub struct HostIdentity {
    pub host_fp: Fingerprint,
    pub sign_pk: VerifyingKey,
    pub agree_pk: X25519PublicKey,
}

/// Tunable knobs for one connect attempt.
#[derive(Debug, Clone, Copy)]
pub struct ConnectOptions {
    /// Local address to bind the ICE UDP socket on (loopback/LAN gathering only this slice — see
    /// [`super::ice`]'s module doc comment).
    pub bind_ip: IpAddr,
    /// How long to wait for ICE connectivity checks to select a candidate pair.
    pub ice_timeout: Duration,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            bind_ip: IpAddr::from([0, 0, 0, 0]),
            ice_timeout: Duration::from_secs(10),
        }
    }
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

        let offer_payload = OfferPayload {
            // This offer's own reply is delivered as the NATS request's reply (see
            // `AnswerPayload`'s doc comment) -- `inbox` here is the same value so the offer's
            // *signed* envelope also asserts which subject the client will treat as authoritative,
            // rather than relying solely on whatever `msg.reply` the transport reports (matching
            // DESIGN.md §A6's `env{eph_pk_c, offer, inbox, ...}` shape).
            inbox: self.nats.new_inbox(),
            transport: Transport::Quic,
            ufrag: local_ice.ufrag.clone(),
            pwd: local_ice.pwd.clone(),
            cert_fp: cert.fingerprint(),
        };
        let offer_env = seal_offer(
            &ctx,
            &self.device,
            self.device_fp,
            host.host_fp,
            &host.agree_pk,
            &offer_payload,
        );

        let reply = self
            .nats
            .request(
                connect_subject(&host.host_fp),
                offer_env.to_canonical_bytes().into(),
            )
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;

        let answer_env = spindle_proto::artifacts::Envelope::from_canonical_bytes(&reply.payload)?;
        let (session_key, answer) = open_answer(
            &answer_env,
            &ctx,
            &self.device,
            self.device_fp,
            host.host_fp,
            &host.sign_pk,
            &host.agree_pk,
        )?;
        if answer.transport != Transport::Quic {
            return Err(SignalingError::UnsupportedTransport(answer.transport));
        }

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
            host.host_fp,
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
            host.host_fp,
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
            host.host_fp,
            self.device_fp,
            ctx.sid.clone(),
            IceDirection::HostToClient,
            session_key,
            host.sign_pk,
            self.device_fp,
            host.host_fp,
            tx,
        ));

        let (remote_addr, _stats) = drive_ice_agent_trickle(
            &mut local_ice.agent,
            &local_ice.socket,
            rx,
            opts.ice_timeout,
        )
        .await?;
        bridge.abort();

        let std_socket = local_ice.socket.into_std()?;
        let control =
            QuicClient::from_socket(std_socket, remote_addr, answer.cert_fp, &cert).await?;
        Ok(control)
    }
}
