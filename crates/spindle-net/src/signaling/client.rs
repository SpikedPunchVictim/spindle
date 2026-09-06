//! Client role: NATS-mediated connect (DESIGN.md §A6) — send the offer, receive the answer,
//! trickle ICE (both directions), end with [`crate::quic::QuicClient::from_socket`]. Graduated
//! from `spikes/s2-signaling/src/bin/s2-connect.rs`'s client leg (`run_client`).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use spindle_core::identity::DeviceKey;
use spindle_core::{Fingerprint, SessionKey, VerifyingKey};
use spindle_proto::artifacts::Capability;
use spindle_proto::signaling::{AnswerPayload, IcePayload, OfferPayload, Transport, CERT_FP_LEN};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::quic::{ControlStream, QuicClient, SessionCert};

use super::bridge_incoming_ice;
use super::error::SignalingError;
use super::ice::{drive_ice_agent_trickle, start_local_ice};
use super::subject::{connect_subject, session_subject, IceDirection};
use super::wire::{new_offer_context, open_answer, seal_ice, seal_offer, OfferContext};

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

/// The result of [`SignalingClient::send_offer_and_await_answer`] -- the offer/answer exchange
/// shared by [`SignalingClient::connect_timed`] and [`SignalingClient::refresh_capability`]. Does
/// not carry the [`super::wire::OfferContext`] the exchange was run under: the caller already
/// owns it (it must exist before the exchange starts, since `connect_timed` needs `ctx.sid` to
/// subscribe the host's trickled ICE *before* the offer is sent -- see that method's doc comment),
/// so returning it back would only be handing the caller its own value.
struct OfferAnswerExchange {
    /// The derived session key (`k1`) -- needed again by a caller that goes on to trickle ICE
    /// (`connect_timed`); unused and simply dropped by one that does not (`refresh_capability`).
    session_key: SessionKey,
    answer: AnswerPayload,
    /// The instant the offer was actually published -- `connect_timed`'s [`ConnectTimings`]
    /// t0 (see that type's doc comment for why it is measured from here, not from entry into
    /// `connect`).
    offer_sent: Instant,
    /// The instant the answer was received *and* fully verified/decrypted.
    answer_opened: Instant,
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
    ///
    /// # `member_cap` is not surfaced here (td-c74122 / S18)
    ///
    /// The host puts its current member capability in every successful answer unconditionally
    /// (DESIGN.md:286/:289-290 -- see [`super::authorize::ConnectDecision::Allow::member_cap`]'s
    /// doc comment), but neither `connect` nor `connect_timed` returns it: no consumer exists to
    /// receive it until `spindle-client-core` is built (Stage 7), and inventing a return-type
    /// shape now with no consumer would be guessing rather than building to evidence. This is a
    /// deliberate scope cut, not an oversight -- S18's bar is the no-lockout path, which
    /// [`Self::refresh_capability`] serves for the one case that actually needs the cap before a
    /// full session exists.
    pub async fn connect_timed(
        &self,
        host: &HostIdentity,
        opts: ConnectOptions,
    ) -> Result<(ControlStream, ConnectTimings), SignalingError> {
        let cert = SessionCert::generate()?;
        // The client is always the ICE-controlling side (matches `s2-connect.rs`'s convention:
        // the offerer controls).
        let mut local_ice = start_local_ice(true, opts.bind_ip).await?;

        let ctx = new_offer_context();

        // Subscribe to the host's trickled ICE *before* sending the offer, so a host->client
        // candidate published immediately after the answer can never race ahead of this
        // subscription existing. This is exactly the permission a connect-only device (expired or
        // stale-epoch cap) does NOT hold -- see `refresh_capability`'s doc comment -- which is why
        // that method cannot simply call `connect_timed` and ignore the error: it would already
        // have failed here, before the offer carrying the answer it needs is even sent.
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

        let exchange = self
            .send_offer_and_await_answer(
                host,
                &ctx,
                local_ice.ufrag.clone(),
                local_ice.pwd.clone(),
                cert.fingerprint(),
                opts.answer_timeout,
            )
            .await?;
        let answer = exchange.answer;

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
            &exchange.session_key,
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
            &exchange.session_key,
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
            exchange.session_key,
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
            offer_to_answer: exchange.answer_opened.duration_since(exchange.offer_sent),
            answer_to_ice_selected: ice_selected.duration_since(exchange.answer_opened),
            ice_selected_to_quic: quic_complete.duration_since(ice_selected),
            offer_to_quic_complete: quic_complete.duration_since(exchange.offer_sent),
        };
        Ok((control, timings))
    }

    /// The offer/answer exchange shared by [`Self::connect_timed`] and [`Self::refresh_capability`]:
    /// mint a fresh reply inbox, seal and publish the offer, await the answer (honoring
    /// [`ConnectOptions::answer_timeout`] and DESIGN.md §A6's no-responders-is-offline rule), then
    /// verify and open it.
    ///
    /// Factored out rather than duplicated so the two callers cannot drift apart -- in particular,
    /// so `refresh_capability` can never accidentally grow the `h2c` subscribe or ICE trickle it
    /// must never perform (see that method's doc comment for why: a connect-only device does not
    /// hold the NATS permissions for either).
    ///
    /// Does NOT subscribe the host's trickled ICE subject. A caller that needs it
    /// (`connect_timed`, and only `connect_timed`) must subscribe *before* calling this, using
    /// `ctx.sid` -- the same before-the-offer ordering `connect_timed`'s own comment on that
    /// subscribe explains, which is why `ctx` is a parameter here rather than something this
    /// method mints for itself.
    async fn send_offer_and_await_answer(
        &self,
        host: &HostIdentity,
        ctx: &OfferContext,
        ufrag: String,
        pwd: String,
        cert_fp: [u8; CERT_FP_LEN],
        answer_timeout: Duration,
    ) -> Result<OfferAnswerExchange, SignalingError> {
        use futures_util::StreamExt;

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
            ufrag,
            pwd,
            cert_fp,
        };
        // `host.device_fp` seals the envelope, `host.host_fp` scopes the subject -- see
        // `HostIdentity`'s doc comment for why these are two different values.
        let offer_env = seal_offer(
            ctx,
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

        let reply = tokio::time::timeout(answer_timeout, answer_sub.next())
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
            ctx,
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

        Ok(OfferAnswerExchange {
            session_key,
            answer,
            offer_sent,
            answer_opened,
        })
    }

    /// Refreshes this device's member capability against `host`, for a device whose cap has
    /// expired or gone stale-epoch (DESIGN.md:288-290's connect-only renewal path) -- and can
    /// therefore do *exactly* this and nothing more.
    ///
    /// # Why this exists as a second entry point rather than a `connect` fallback
    ///
    /// A connect-only device holds precisely `pub host.<h>.connect` and
    /// `sub _INBOX_<own_device_fp>.>` (`spindle-helper::permissions::client_connect_only_permissions`)
    /// -- enough to publish an offer and open the sealed answer on its own inbox, and nothing
    /// else. It cannot subscribe `host.<h>.sess.<c>.<sid>.h2c` and cannot trickle ICE on
    /// `host.<h>.sess.<c>.<sid>.c2h`, so [`Self::connect`]/[`Self::connect_timed`] fail partway
    /// through for it -- *after* the answer carrying the freshly re-issued cap is already in hand,
    /// which those methods would then discard along with the error. This method performs exactly
    /// the prefix of `connect_timed` a connect-only device is permitted to perform: publish the
    /// offer, open the sealed answer, return the cap, stop. It deliberately does NOT subscribe the
    /// `h2c` session subject, and does NOT trickle ICE or start a QUIC handshake -- doing either
    /// would be a permissions violation for the very device this method exists to serve, defeating
    /// its purpose. `opts.bind_ip`/`opts.ice_timeout` are therefore unused; only
    /// `opts.answer_timeout` applies.
    ///
    /// The offer's `ufrag`/`pwd`/`cert_fp` are placeholder values, never a real gathered ICE
    /// credential or session certificate: this call never reaches ICE or QUIC, so there is nothing
    /// for real ones to be used for, and generating them (a UDP bind, a self-signed cert) would be
    /// pure waste for a refresh. The host cannot tell a refresh-only offer apart from an ordinary
    /// one at this stage -- see the resource note below.
    ///
    /// # The returned cap is not verified here
    ///
    /// `Ok(Some(cap))`'s bytes are opaque as far as this crate is concerned -- `spindle-net` has no
    /// host/member registry to check them against (per this crate's own layering doc comments).
    /// The caller is expected to present the returned cap to the same callout/registry that
    /// verifies every other cap, on its next connect attempt; that verification, not this method,
    /// is what actually admits the device as a full member again. `Ok(None)` means the host had no
    /// cap-signing key to mint with (every host today) -- not "denied" and not "no cap exists".
    ///
    /// # Resource note
    ///
    /// The host cannot distinguish a refresh-only offer from an ordinary one, so it still runs its
    /// full answer path for this call -- including local ICE gathering and a per-session
    /// certificate -- work it will discard once its own `ice_timeout` elapses without this method
    /// ever trickling a single candidate. That is acceptable at DESIGN.md:286's ~6-week cap
    /// lifetime (a rare event per device), but is the thing to optimise first if refreshes ever
    /// become frequent -- e.g. a marker in `OfferPayload` letting the host skip ICE setup entirely
    /// for a refresh-only offer. Not built here: no evidence yet that refreshes are frequent enough
    /// to need it.
    pub async fn refresh_capability(
        &self,
        host: &HostIdentity,
        opts: ConnectOptions,
    ) -> Result<Option<Capability>, SignalingError> {
        let ctx = new_offer_context();
        let exchange = self
            .send_offer_and_await_answer(
                host,
                &ctx,
                REFRESH_ONLY_UFRAG.to_string(),
                REFRESH_ONLY_PWD.to_string(),
                [0u8; CERT_FP_LEN],
                opts.answer_timeout,
            )
            .await?;
        Ok(exchange.answer.member_cap)
    }
}

/// Placeholder ICE credentials for [`SignalingClient::refresh_capability`]'s offer. Never used for
/// any real ICE negotiation -- that path never gathers a local candidate, never trickles, and
/// never starts a QUIC handshake (see that method's doc comment) -- so any well-formed strings
/// satisfy the wire schema equally well. Named constants rather than inline literals so a reader
/// of the offer-building code does not mistake them for real gathered values.
const REFRESH_ONLY_UFRAG: &str = "refresh-only-ufrag";
const REFRESH_ONLY_PWD: &str = "refresh-only-password-placeholder";

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
