//! Client role: NATS-mediated connect (DESIGN.md §A6) — send the offer, receive the answer,
//! trickle ICE (both directions), end with [`crate::quic::QuicClient::from_socket`]. Graduated
//! from `spikes/s2-signaling/src/bin/s2-connect.rs`'s client leg (`run_client`).

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use spindle_core::identity::DeviceKey;
use spindle_core::{Fingerprint, SessionKey, VerifyingKey};
use spindle_proto::artifacts::Capability;
use spindle_proto::signaling::{AnswerPayload, IcePayload, OfferPayload, Transport, CERT_FP_LEN};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::quic::{ControlStream, QuicClient, SessionCert};

use super::error::SignalingError;
use super::ice::{
    await_peer_relay_candidate, decide_after_window, drive_ice_agent_trickle, punch_deadline,
    relay_candidate_line, split_relay_candidates, start_local_ice, AbortOnDrop, IceConfig,
    LocalTrickleEvent, SelectedTransport, StunGather, WindowDecision, DEADLINE_SETTLE,
};
use super::subject::{connect_subject, session_subject, IceDirection};
use super::turn;
use super::wire::{new_offer_context, open_answer, seal_ice, seal_offer, OfferContext};
use super::{bridge_incoming_ice, sid_hex, QUIC_HANDSHAKE_TIMEOUT};

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
/// The distinction is normative, not incidental: `HostDeviceCert` (A4/A10.35) is signed by the
/// host **operating** key (`sig_host_op(host_device_fp, alg_id, sign_pk, agree_pk, ts)`), chaining
/// root→op→device, and its `device_fp` *is* the host's A7 envelope identity. `host_fp` and
/// `device_fp` are therefore not interchangeable.
///
/// `spikes/s2-signaling` kept the two apart from the start (`HostState { host_fp, host_device_fp,
/// .. }`); graduation merged them before A10.35 named the rule, which is what the live
/// `tests/live_signaling.rs` run caught.
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
    /// The data path this attempt actually used. On [`SelectedTransport::Relay`],
    /// [`Self::answer_to_ice_selected`] measures "answer verified -> TURN allocation and
    /// CreatePermission complete" instead of an ICE selection, because the punch window expired
    /// without a pair (punch-first, td-870b25). On [`SelectedTransport::Punch`] it is the genuine
    /// ICE selection; STUN gathering runs concurrently with it and does not gate it.
    pub transport: SelectedTransport,
}

/// Tunable knobs for one connect attempt.
///
/// `Clone` rather than `Copy`: [`Self::ice`] carries a server list and credentials.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// Local address to bind the ICE UDP socket on. Use a concrete interface address, not the
    /// wildcard: the wildcard is what gets advertised as this side's host candidate, and a peer
    /// cannot route to `0.0.0.0` (empirically `No route to host` in the S19 harness).
    pub bind_ip: IpAddr,
    /// How long to wait for ICE connectivity checks to select a candidate pair.
    pub ice_timeout: Duration,
    /// How long to wait for the host's answer after publishing the offer (DESIGN.md §A6: "connect
    /// timeout covers the answer only"). This used to be implicit in
    /// `async_nats::Client::request`'s own default; §A10.36's switch to an explicitly-controlled
    /// reply inbox makes it this crate's to set.
    pub answer_timeout: Duration,
    /// Candidate gathering (td-c3badf). The default is empty — host candidate only, exactly the
    /// pre-td-c3badf behaviour. Add STUN servers for server-reflexive candidates across a NAT; add
    /// a TURN server to run punch-first with a relay fallback (see [`IceConfig`]).
    pub ice: IceConfig,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            bind_ip: IpAddr::from([0, 0, 0, 0]),
            ice_timeout: Duration::from_secs(10),
            answer_timeout: Duration::from_secs(5),
            ice: IceConfig::default(),
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

    /// Seals and publishes one trickled ICE payload, advancing `seq` on success. Factored out so
    /// the punch-only, punch-first and fallback paths share one wire shape and one sequencing rule
    /// (DESIGN.md §A6: each candidate is its own signed/sealed `KIND_ICE` envelope, never batched).
    async fn publish_ice(
        &self,
        subject: String,
        session_key: &SessionKey,
        to_fp: Fingerprint,
        sid: &[u8],
        seq: &mut u64,
        payload: IcePayload,
    ) -> Result<(), SignalingError> {
        let env = seal_ice(
            session_key,
            &self.device,
            self.device_fp,
            to_fp,
            sid,
            *seq,
            &payload,
        );
        self.nats
            .publish(subject, env.to_canonical_bytes().into())
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;
        *seq += 1;
        Ok(())
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

    /// [`Self::connect`], plus the phase-by-phase [`ConnectTimings`] for the attempt.
    pub async fn connect_timed(
        &self,
        host: &HostIdentity,
        opts: ConnectOptions,
    ) -> Result<(ControlStream, ConnectTimings), SignalingError> {
        self.connect_core(host, opts)
            .await
            .map(|(control, _, timings)| (control, timings))
    }

    /// [`Self::connect`], plus the member capability the host put in its answer (Stage 7's
    /// client session is the consumer). `None` when the answer carried none; a host that admits
    /// the capability bundle always includes its current member cap.
    pub async fn connect_with_cap(
        &self,
        host: &HostIdentity,
        opts: ConnectOptions,
    ) -> Result<(ControlStream, Option<Capability>), SignalingError> {
        self.connect_core(host, opts)
            .await
            .map(|(control, member_cap, _)| (control, member_cap))
    }

    /// The one connect flow behind [`Self::connect`], [`Self::connect_timed`] and
    /// [`Self::connect_with_cap`]; it always carries the answer's `member_cap` internally.
    ///
    /// # `member_cap`
    ///
    /// The host puts its current member capability in every successful answer unconditionally
    /// (DESIGN.md:286/:289-290 -- see [`super::authorize::ConnectDecision::Allow::member_cap`]'s
    /// doc comment). The callers above choose whether to surface it; `spindle-client-core`'s
    /// device session does, and persists it.
    async fn connect_core(
        &self,
        host: &HostIdentity,
        opts: ConnectOptions,
    ) -> Result<(ControlStream, Option<Capability>, ConnectTimings), SignalingError> {
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

        // Publish the host candidate *now*. Every slow step (STUN inside the ICE drive, TURN
        // allocation below) happens after the answer is on the wire, so a blackholed STUN server
        // cannot turn a working host-only connect into an answer timeout (td-c3badf review fix 1).
        // Each candidate is its own signed/sealed KIND_ICE envelope (DESIGN.md §A6: never batched).
        let c2h_subject = session_subject(
            &host.host_fp,
            &self.device_fp,
            &ctx.sid,
            IceDirection::ClientToHost,
        );
        let mut seq: u64 = 1;
        self.publish_ice(
            c2h_subject.clone(),
            &exchange.session_key,
            host.device_fp,
            &ctx.sid,
            &mut seq,
            IcePayload {
                candidate: Some(local_ice.host_candidate_line.clone()),
                end_of_candidates: false,
            },
        )
        .await?;

        // Bridge the host's trickled candidates (received over NATS) into the sans-I/O agent's
        // trickle channel. The punch path then drives the agent to a selected pair; on the
        // punch-first path a tee splits the peer's `relay` candidate out for the fallback. The
        // guard aborts the task on every error path, not just the success path.
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let bridge = AbortOnDrop::new(tokio::spawn(bridge_incoming_ice(
            h2c_sub,
            // Subject tokens (host root fp, client device fp) ...
            host.host_fp,
            self.device_fp,
            ctx.sid.clone(),
            IceDirection::HostToClient,
            // Cloned because the candidate-publishing paths below still need the key; both copies
            // zeroize on drop.
            exchange.session_key.clone(),
            host.sign_pk,
            // ... and envelope fingerprints (this device, the host's *envelope* identity).
            self.device_fp,
            host.device_fp,
            tx,
        )));

        // ── Punch-first with a shared local window (td-870b25) ──────────────────────────────
        //
        // With TURN configured, the allocation runs in parallel with an ICE attempt bounded by
        // `punch_window`. The window starts **here**, at the first poll of the ICE drive: after the
        // answer has been verified and this side's host candidate published. The host starts its
        // own window after publishing the answer *and* its host candidate, so the two deadlines
        // differ by the answer's one-way NATS leg plus this side's verification/decryption — less
        // than one RTT, not a full round trip. A pair present at the deadline check wins (the
        // window bounds the wait, not the outcome) and the allocation is released; otherwise the
        // ICE agent is torn down and the session uses the relay. With no TURN this branch is not
        // taken and behaviour is exactly the old punch-only path.
        let (transport, ice_selected, control) = if let Some(turn_config) = opts.ice.turn.as_ref() {
            // Validated before any network work: out-of-range (or clock-overflowing) positive
            // values are a configuration error, never a panic at `Instant + Duration`
            // (td-870b25 review). Zero is the explicit relay-only mode.
            let window_deadline = punch_deadline(opts.ice.punch_window, Instant::now())?;
            let relay_only = opts.ice.punch_window.is_zero();
            if relay_only {
                tracing::debug!("punch_window is zero: relay-only mode, skipping the ICE attempt");
            }

            // Allocation is a background task: it must not sit on the punched path's critical
            // section, and a guard it returns is released by whoever drops it (including a
            // detached task below when the punch wins while the allocation is still in flight).
            let allocation_config = turn_config.clone();
            let bind_ip = opts.bind_ip;
            let mut allocation_task = tokio::spawn(async move {
                turn::allocate(&allocation_config, bind_ip, turn::TURN_SETUP_TIMEOUT).await
            });

            // The tee outlives the ICE drive so a peer `relay` candidate arriving after the window
            // is not lost when the agent is torn down.
            let (ice_tx, ice_rx) = tokio::sync::mpsc::unbounded_channel();
            // Bounded (capacity 1): the fallback needs only the first valid relay candidate, and a
            // peer streaming `typ relay` lines must not be able to grow a buffer during the
            // window. The tee uses `try_send` and drops anything beyond the first (td-870b25 review).
            let (relay_tx, relay_rx) = tokio::sync::mpsc::channel(1);
            let tee = AbortOnDrop::new(tokio::spawn(split_relay_candidates(rx, ice_tx, relay_tx)));

            let (local_tx, mut local_rx) = tokio::sync::mpsc::unbounded_channel();
            let gather = StunGather::new(&opts.ice.stun_servers, Instant::now());
            let mut drive = Box::pin(drive_ice_agent_trickle(
                &mut local_ice.agent,
                &local_ice.socket,
                // The offerer is the ICE-controlling side; the peer's credentials come from the
                // answer this side just verified.
                true,
                &answer.ufrag,
                &answer.pwd,
                ice_rx,
                gather,
                local_tx,
                opts.ice_timeout,
            ));

            let mut allocation: Option<turn::AllocationGuard> = None;
            let mut allocation_settled = false;
            let mut drive_finished = false;
            let mut drive_error: Option<SignalingError> = None;
            let mut selected_at: Option<Instant> = None;
            let mut remote_addr: Option<SocketAddr> = None;

            loop {
                tokio::select! {
                    // `biased` polls branches in source order and stops at the first ready one, so
                    // the drive branch (below) is always polled — and its result consumed — before
                    // the deadline branch. Without this, a `select!` that finds both ready can
                    // discard the drive's selected-pair result and then the deadline branch would
                    // poll a completed future (a resume-after-completion panic) (td-870b25 review
                    // fix 1). Source order is therefore load-bearing: drive before deadline.
                    biased;
                    Some(event) = local_rx.recv() => {
                        let payload = match event {
                            LocalTrickleEvent::Candidate(line) => IcePayload {
                                candidate: Some(line),
                                end_of_candidates: false,
                            },
                            LocalTrickleEvent::EndOfCandidates => IcePayload {
                                candidate: None,
                                end_of_candidates: true,
                            },
                        };
                        self.publish_ice(
                            c2h_subject.clone(),
                            &exchange.session_key,
                            host.device_fp,
                            &ctx.sid,
                            &mut seq,
                            payload,
                        )
                        .await?;
                    }
                    joined = &mut allocation_task, if !allocation_settled => {
                        allocation_settled = true;
                        match joined {
                            Ok(Ok(guard)) => {
                                // Advertise the relay candidate immediately. The peer may need it
                                // for its own fallback even while this side is still punching.
                                let relayed = guard.relayed_addr()?;
                                let relay_line = relay_candidate_line(
                                    relayed,
                                    guard.local_addr()?,
                                    turn_config.server,
                                )?;
                                self.publish_ice(
                                    c2h_subject.clone(),
                                    &exchange.session_key,
                                    host.device_fp,
                                    &ctx.sid,
                                    &mut seq,
                                    IcePayload {
                                        candidate: Some(relay_line),
                                        end_of_candidates: false,
                                    },
                                )
                                .await?;
                                allocation = Some(guard);
                                tracing::debug!(
                                    relayed = %relayed,
                                    "TURN allocation ready; relay candidate trickled"
                                );
                            }
                            Ok(Err(error)) => {
                                // Required semantics: a failed allocation is soft. Keep punching.
                                tracing::warn!(
                                    error = %error.redacted(),
                                    "TURN allocation failed; continuing punch-only"
                                );
                            }
                            Err(error) => {
                                tracing::warn!(
                                    error = %error, // redaction-ok: tokio::task::JoinError Display is "task <id> panicked/cancelled" text; no peer bytes, paths, or full ids
                                    "TURN allocation task failed; continuing punch-only"
                                );
                            }
                        }
                    }
                    result = &mut drive, if !drive_finished && !relay_only => {
                        drive_finished = true;
                        match result {
                            Ok((addr, _stats)) => {
                                // A pair selected at/after the deadline can only be observed
                                // here because this branch won a `select!` against the deadline;
                                // record it at the deadline so `decide_after_window` applies the
                                // same "present at the deadline check wins" rule as its final
                                // poll (td-870b25 review).
                                selected_at = Some(Instant::now().min(window_deadline));
                                remote_addr = Some(addr);
                                break;
                            }
                            Err(error) => {
                                // The window, not an early ICE failure, is the coordination point:
                                // the peer may still select, and switching early would guarantee a
                                // split. Keep waiting for the deadline unless no relay can exist.
                                drive_error = Some(error);
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(window_deadline.into()) => {
                        // A publish body in flight when the deadline fired suspends this loop, so
                        // the drive may already hold a selected pair this `select!` never observed.
                        // Give it one bounded final poll; a pair found here is recorded at the
                        // deadline and wins (td-870b25 review fix 1). A drive that already
                        // finished (with an error) must not be polled again.
                        if !drive_finished && !relay_only {
                            if let Ok(result) =
                                tokio::time::timeout(DEADLINE_SETTLE, &mut drive).await
                            {
                                match result {
                                    Ok((addr, _stats)) => {
                                        selected_at = Some(window_deadline);
                                        remote_addr = Some(addr);
                                    }
                                    Err(error) => drive_error = Some(error),
                                }
                            }
                        }
                        break;
                    }
                }

                // With the ICE attempt failed and no relay possible there is nothing left to
                // coordinate with the peer: fail now rather than sleeping out the window.
                if drive_finished
                    && drive_error.is_some()
                    && allocation_settled
                    && allocation.is_none()
                {
                    break;
                }
            }

            // Settle a pending allocation before a decision that may choose the relay. A selected
            // pair does not wait on it: a pair present at the deadline check is a punch win
            // regardless of whether the allocation finished.
            if selected_at.is_none() && !allocation_settled {
                allocation_settled = true;
                match (&mut allocation_task).await {
                    Ok(Ok(guard)) => {
                        let relayed = guard.relayed_addr()?;
                        let relay_line =
                            relay_candidate_line(relayed, guard.local_addr()?, turn_config.server)?;
                        self.publish_ice(
                            c2h_subject.clone(),
                            &exchange.session_key,
                            host.device_fp,
                            &ctx.sid,
                            &mut seq,
                            IcePayload {
                                candidate: Some(relay_line),
                                end_of_candidates: false,
                            },
                        )
                        .await?;
                        allocation = Some(guard);
                        tracing::debug!(
                            relayed = %relayed,
                            "TURN allocation ready; relay candidate trickled"
                        );
                    }
                    Ok(Err(error)) => tracing::warn!(
                        error = %error.redacted(),
                        "TURN allocation failed; continuing punch-only"
                    ),
                    Err(error) => tracing::warn!(
                        error = %error, // redaction-ok: tokio::task::JoinError Display is "task <id> panicked/cancelled" text; no peer bytes, paths, or full ids
                        "TURN allocation task failed; continuing punch-only"
                    ),
                }
            }

            // The unit-tested policy, applied once at the one place it matters.
            match decide_after_window(true, allocation.is_some(), selected_at, window_deadline) {
                WindowDecision::Punch => {
                    if let Some(remote_addr) = remote_addr {
                        // Release the relay allocation. If it is still in flight, let it finish and
                        // release in the background rather than delaying the punched handshake — or
                        // aborting mid-Allocate, which would leave coturn holding the port until its
                        // lifetime ends.
                        if allocation_settled {
                            drop(allocation.take());
                        } else {
                            tokio::spawn(async move {
                                if let Ok(Ok(guard)) = allocation_task.await {
                                    drop(guard);
                                }
                            });
                        }
                        tee.abort();
                        bridge.abort();
                        tracing::debug!(
                            sid = %sid_hex(&ctx.sid),
                            transport = SelectedTransport::Punch.as_str(),
                            %remote_addr,
                            "transport selected"
                        );
                        let ice_selected = Instant::now();
                        drop(drive);
                        let std_socket = local_ice.socket.into_std()?;
                        let control = tokio::time::timeout(
                            QUIC_HANDSHAKE_TIMEOUT,
                            QuicClient::from_socket(std_socket, remote_addr, answer.cert_fp, &cert),
                        )
                        .await
                        .map_err(|_| SignalingError::Timeout("QUIC handshake"))??;
                        (SelectedTransport::Punch, ice_selected, control)
                    } else {
                        // No pair and no relay. In relay-only mode there is no punch attempt to
                        // continue: the attempt cannot complete without the allocation it asked
                        // for. Otherwise the required semantics for a failed allocation are to
                        // continue punch-only, bounded by the drive's own `ice_timeout`.
                        if relay_only {
                            return Err(SignalingError::Turn(
                                "relay-only punch window: no relay allocation is available"
                                    .to_string(),
                            ));
                        }
                        if let Some(error) = drive_error {
                            return Err(error);
                        }
                        let remote_addr = loop {
                            tokio::select! {
                                result = &mut drive => break result?.0,
                                Some(event) = local_rx.recv() => {
                                    let payload = match event {
                                        LocalTrickleEvent::Candidate(line) => IcePayload {
                                            candidate: Some(line),
                                            end_of_candidates: false,
                                        },
                                        LocalTrickleEvent::EndOfCandidates => IcePayload {
                                            candidate: None,
                                            end_of_candidates: true,
                                        },
                                    };
                                    self.publish_ice(
                                        c2h_subject.clone(),
                                        &exchange.session_key,
                                        host.device_fp,
                                        &ctx.sid,
                                        &mut seq,
                                        payload,
                                    )
                                    .await?;
                                }
                            }
                        };
                        drop(drive);
                        tee.abort();
                        bridge.abort();
                        tracing::debug!(
                            sid = %sid_hex(&ctx.sid),
                            transport = SelectedTransport::Punch.as_str(),
                            %remote_addr,
                            "transport selected"
                        );
                        let ice_selected = Instant::now();
                        let std_socket = local_ice.socket.into_std()?;
                        let control = tokio::time::timeout(
                            QUIC_HANDSHAKE_TIMEOUT,
                            QuicClient::from_socket(std_socket, remote_addr, answer.cert_fp, &cert),
                        )
                        .await
                        .map_err(|_| SignalingError::Timeout("QUIC handshake"))??;
                        (SelectedTransport::Punch, ice_selected, control)
                    }
                }
                WindowDecision::Relay => {
                    let mut allocation = allocation
                        .take()
                        .expect("a Relay decision requires a live allocation");
                    // Stop/tear down the ICE agent: its socket is not the data path.
                    drop(drive);
                    let peer_relayed =
                        await_peer_relay_candidate(relay_rx, turn::TURN_SETUP_TIMEOUT).await?;
                    tee.abort();
                    bridge.abort();
                    turn::create_permission(
                        allocation.allocation_mut()?,
                        peer_relayed,
                        turn::TURN_SETUP_TIMEOUT,
                    )
                    .await?;
                    tracing::debug!(
                        sid = %sid_hex(&ctx.sid),
                        transport = SelectedTransport::Relay.as_str(),
                        %peer_relayed,
                        "transport selected"
                    );
                    let relay_ready = Instant::now();
                    let relay_socket =
                        allocation.into_relay_socket(turn_config.server, peer_relayed)?;
                    turn::spawn_driver(relay_socket.clone());
                    let control = tokio::time::timeout(
                        QUIC_HANDSHAKE_TIMEOUT,
                        QuicClient::from_abstract_socket(
                            relay_socket,
                            peer_relayed,
                            answer.cert_fp,
                            &cert,
                        ),
                    )
                    .await
                    .map_err(|_| SignalingError::Timeout("QUIC handshake"))??;
                    (SelectedTransport::Relay, relay_ready, control)
                }
            }
        } else {
            // Punch-only (no TURN configured): exactly the pre-td-870b25 behaviour.
            let (local_tx, mut local_rx) = tokio::sync::mpsc::unbounded_channel();
            let gather = StunGather::new(&opts.ice.stun_servers, Instant::now());
            let mut drive = Box::pin(drive_ice_agent_trickle(
                &mut local_ice.agent,
                &local_ice.socket,
                // The offerer is the ICE-controlling side; the peer's credentials come from the
                // answer this side just verified.
                true,
                &answer.ufrag,
                &answer.pwd,
                rx,
                gather,
                local_tx,
                opts.ice_timeout,
            ));
            // Publish each candidate the drive gathers while it also runs connectivity checks.
            let remote_addr = loop {
                tokio::select! {
                    result = &mut drive => break result?.0,
                    Some(event) = local_rx.recv() => {
                        let payload = match event {
                            LocalTrickleEvent::Candidate(line) => IcePayload {
                                candidate: Some(line),
                                end_of_candidates: false,
                            },
                            LocalTrickleEvent::EndOfCandidates => IcePayload {
                                candidate: None,
                                end_of_candidates: true,
                            },
                        };
                        self.publish_ice(
                            c2h_subject.clone(),
                            &exchange.session_key,
                            host.device_fp,
                            &ctx.sid,
                            &mut seq,
                            payload,
                        )
                        .await?;
                    }
                }
            };
            drop(drive);
            bridge.abort();
            tracing::debug!(
                sid = %sid_hex(&ctx.sid),
                transport = SelectedTransport::Punch.as_str(),
                %remote_addr,
                "transport selected"
            );
            let ice_selected = Instant::now();

            let std_socket = local_ice.socket.into_std()?;
            let control = tokio::time::timeout(
                QUIC_HANDSHAKE_TIMEOUT,
                QuicClient::from_socket(std_socket, remote_addr, answer.cert_fp, &cert),
            )
            .await
            .map_err(|_| SignalingError::Timeout("QUIC handshake"))??;
            (SelectedTransport::Punch, ice_selected, control)
        };
        let quic_complete = Instant::now();

        let timings = ConnectTimings {
            offer_to_answer: exchange.answer_opened.duration_since(exchange.offer_sent),
            answer_to_ice_selected: ice_selected.duration_since(exchange.answer_opened),
            ice_selected_to_quic: quic_complete.duration_since(ice_selected),
            offer_to_quic_complete: quic_complete.duration_since(exchange.offer_sent),
            transport,
        };
        Ok((control, answer.member_cap, timings))
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
