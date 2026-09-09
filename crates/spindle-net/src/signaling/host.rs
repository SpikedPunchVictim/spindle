//! Host role: NATS-mediated connect (DESIGN.md §A6) — subscribe for offers, authorize+verify,
//! answer, trickle ICE (both directions), end with [`crate::quic::QuicServer::from_socket`].
//! Graduated from `spikes/s2-signaling/src/bin/s2-connect.rs`'s host leg (`run_host`).
//!
//! # A second injected trait: [`SessionHandler`]
//!
//! This slice's brief specified one injected trait ([`super::authorize::ConnectAuthorizer`], for
//! the membership/authorization decision). Finishing "ending in `QuicServer::from_socket`" surfaces
//! a second layering question the brief didn't spell out: once a session's QUIC control stream is
//! established, *something* has to drive the actual VFS RPC serve loop over it — and that loop
//! lives in `spindle-host-core::serve`, a crate this one must never depend on (DESIGN.md §A9c
//! boundary rule 3, same rule that motivated `ConnectAuthorizer`). [`SessionHandler`] is the same
//! injection pattern applied a second time: a real host wires it to `spindle-host-core`'s serve
//! loop at the call site; this crate only owns getting to a verified, pinned
//! [`crate::quic::ControlStream`] in the first place.
//!
//! # The `connection.closed()` lifecycle bug (`spikes/s2-signaling`'s `RESULTS.md`)
//!
//! quinn implicitly sends `CONNECTION_CLOSE` when the last [`quinn::Connection`] handle is
//! dropped. If a per-session task returned (dropping its `ControlStream`, and with it the
//! `Connection`) immediately after [`SessionHandler::handle_session`] finishes, that implicit close
//! can race the peer's read of whatever the handler just finished writing — the spike hit this
//! empirically. [`SignalingHost::handle_connect`] awaits `connection.closed()`, bounded by
//! [`HostOptions::session_close_timeout`], before letting the `ControlStream` (and so the
//! `Connection`) actually drop.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use spindle_core::identity::DeviceKey;
use spindle_core::Fingerprint;
use spindle_proto::artifacts::{Capability, Envelope};
use spindle_proto::signaling::{AnswerPayload, IcePayload, Transport};

use crate::quic::{ControlStream, QuicServer, SessionCert};

use super::authorize::{ConnectAuthorizer, ConnectDecision, VerifiedDecision};
use super::bridge_incoming_ice;
use super::error::SignalingError;
use super::ice::{drive_ice_agent_trickle, start_local_ice};
use super::subject::{connect_subject, reply_prefix_ok, session_subject, IceDirection};
use super::wire::{seal_ice, OpenedOffer};

/// What a host does with a session once its QUIC control stream is established — see this
/// module's doc comment for why this is an injected trait rather than a direct call into
/// `spindle-host-core`. Takes ownership of `control` and hands it back once the session is over
/// (still holding its `Connection`), so [`SignalingHost::handle_connect`] can perform the
/// `connection.closed()` wait described in this module's doc comment.
///
/// `peer_device_fp` is the **authenticated** envelope device fingerprint of the peer this session
/// belongs to — not merely the `from_fp` the offer claimed. By the time this method is called,
/// [`process_offer`] has resolved that fingerprint through the injected [`ConnectAuthorizer`] and
/// then verified the offer's signature against the `sign_pk` the authorizer returned for it (see
/// [`super::wire::open_offer`]), so a peer cannot reach here under a fingerprint whose signing key
/// it does not hold.
///
/// Passing it is not a convenience. A host's session layer is required to bind one VFS RPC session
/// to one `{member_id, device_fp}` pair for the session's whole duration, resolved once before the
/// request loop starts rather than re-derived per request (see
/// `spindle_host_core::serve::serve_control_stream`'s `ctx` parameter, whose doc comment names
/// establishing those two values as this crate's responsibility). This crate can supply only the
/// device half: it does not and must not own the member registry, per A9c boundary rule 3 — the
/// same rule that makes [`ConnectAuthorizer`] an injected trait — so resolving `member_id` from
/// this fingerprint is left to the implementer.
pub trait SessionHandler: Send + Sync {
    fn handle_session(
        &self,
        peer_device_fp: Fingerprint,
        control: ControlStream,
    ) -> impl std::future::Future<Output = ControlStream> + Send;
}

/// Tunable knobs for the host's connect/session lifecycle.
#[derive(Debug, Clone, Copy)]
pub struct HostOptions {
    /// Local address to bind each session's ICE UDP socket on (loopback/LAN gathering only this
    /// slice — see [`super::ice`]'s module doc comment).
    pub bind_ip: IpAddr,
    /// How long to wait for ICE connectivity checks to select a candidate pair.
    pub ice_timeout: Duration,
    /// How long to wait for `connection.closed()` after a session ends, before giving up and
    /// letting the `ControlStream` drop anyway (see this module's doc comment).
    pub session_close_timeout: Duration,
    /// The maximum number of connect offers being handled concurrently. `SignalingHost::run`'s
    /// subscription is `host.<hfp>.connect` (DESIGN.md §A5's subject table), a subject any
    /// authenticated NATS client can publish to — the Auth Callout grants `pub` on it to anyone
    /// holding a valid device identity, and nothing about §A5/§A6 checks a Spindle-level signature
    /// before that message reaches this host. Before this field existed, `run` spawned one
    /// unbounded `tokio::spawn` task per inbound message on that subject, so an attacker with
    /// nothing more than a NATS connection could set this host's task count and, through it, its
    /// memory. DESIGN.md:481-483 requires a "max-concurrent-sessions" cap on every connect, and
    /// DESIGN.md:930 threat #14 pairs "token bucket, concurrency cap" as the mitigation for
    /// exactly this — this field is the concurrency-cap half.
    ///
    /// `64` is a retunable placeholder, not a derived constant: DESIGN.md:481 mandates the cap but
    /// specifies no number for it, and this crate has no basis yet (no live load data) to pick one
    /// more precisely. Treat this default as something to revisit once a real deployment's
    /// concurrent-session profile is known, not as a value load-bearing in its own right.
    ///
    /// When the cap is reached, `run` drops the offer with no reply at all — it does not queue or
    /// block. That is DESIGN.md §A5's uniform silent drop, the same observable outcome a peer sees
    /// from a `ConnectDecision::Deny` or a malformed envelope: no signal distinguishes "the host is
    /// at capacity" from "the offer was rejected" from "the offer was malformed". Queuing instead
    /// (e.g. waiting for a permit before spawning) was considered and rejected: a blocked
    /// subscription loop cannot pull the next message off the NATS subscription until a permit
    /// frees up, so the unbounded growth this field exists to bound would simply move from the
    /// task count into the NATS subscription's own internal buffer — strictly worse, since the
    /// memory is still consumed and *every* legitimate offer behind the flood is delayed instead of
    /// only the hostile one(s) being dropped.
    pub max_concurrent_connects: usize,
}

impl Default for HostOptions {
    fn default() -> Self {
        Self {
            bind_ip: IpAddr::from([0, 0, 0, 0]),
            ice_timeout: Duration::from_secs(10),
            session_close_timeout: Duration::from_secs(5),
            max_concurrent_connects: 64,
        }
    }
}

/// The host role's connect flow. Holds the caller-owned NATS client (never connects one itself —
/// see [`super`]'s module doc comment), this host's two identities, the injected
/// [`ConnectAuthorizer`], and the injected [`SessionHandler`].
///
/// # Two fingerprints, not one
///
/// `host_fp` (`SHA-256(host_root_pk)`) and `device_fp` (this host's envelope [`DeviceKey`]) are
/// different values and are used for different things — see [`super::client::HostIdentity`]'s doc
/// comment for the full statement of why they cannot be collapsed, and what happens live when they
/// are (`tests/live_signaling.rs` caught exactly that: `Permissions Violation for Subscription to
/// "host.<device_fp>.connect"`, because the Auth Callout grants `sub host.<host_fp>.>`).
pub struct SignalingHost<A, H> {
    nats: async_nats::Client,
    device: DeviceKey,
    device_fp: Fingerprint,
    /// The host's root fingerprint — the NATS subject-scoping token only, never an envelope field.
    host_fp: Fingerprint,
    authorizer: A,
    handler: H,
}

/// Builds the [`AnswerPayload`] `handle_connect` seals and returns to the client.
///
/// Extracted so the unit tests construct the answer through the *same* code the production path
/// does. This is not ceremony: when the `member_cap` relay was first written, the tests hand-rolled
/// their own `AnswerPayload` mirroring this one, so setting `member_cap: None` on the production
/// construction passed the entire suite. A test that builds its own copy of the value under test
/// can never notice the real one dropping a field.
///
/// `transport` is fixed to [`Transport::Quic`]: this crate answers native<->native connects only
/// (DESIGN.md A10.31 scopes WebRTC to browser peers, which arrive in Stage 8).
fn build_answer_payload(
    ufrag: String,
    pwd: String,
    cert_fp: [u8; spindle_proto::signaling::CERT_FP_LEN],
    member_cap: Option<Capability>,
) -> AnswerPayload {
    AnswerPayload {
        transport: Transport::Quic,
        ufrag,
        pwd,
        cert_fp,
        member_cap,
    }
}

/// Verifies every §A7/§A5/§A6 receiver-side check on one raw connect-offer message and returns the
/// opened offer plus the authorizer's `member_cap` decision (td-c74122: the cap `handle_connect`
/// puts in the answer, per DESIGN.md:286/:289-290 — see `ConnectDecision::Allow::member_cap`'s doc
/// comment), without touching NATS/ICE/QUIC — the richest unit-testable surface for this half of
/// the host flow (see this crate's report for what a live run still needs to prove beyond this).
///
/// The reply-prefix check runs first — it is cheap and needs no crypto. The §A10.36 `inbox`
/// equality check is the third and last routing check, and is structurally forced to run after
/// decryption for the reason given at this function's tail: `inbox` lives inside the ciphertext,
/// so there is no key to read it with until `open_offer` has returned. The authorizer call runs
/// next, but not for a performance reason: it runs before [`super::wire::open_offer`]'s signature
/// verification and AEAD decryption because it is *structurally forced to*. `open_offer` needs the
/// sender's `sign_pk`/`agree_pk` before it can verify anything, and the authorizer's
/// `ConnectDecision::Allow { sign_pk, agree_pk }` is the only source of those keys this crate has
/// (DESIGN.md §A9c boundary rule 3: `spindle-net` does not own the member registry). There is no
/// way to check the signature first, because until the authorizer answers, there is no key to
/// check it against.
///
/// That ordering has a security-relevant consequence worth stating plainly: the authorizer is
/// necessarily consulted with an unverified, attacker-controlled `from_fp` — before any signature
/// has been checked. An unauthenticated peer can therefore trigger one membership lookup per
/// connect offer it sends, just by naming any `from_fp` it likes. This is a constraint on
/// implementers of [`ConnectAuthorizer`], not something `spindle-net` can solve itself (it does not
/// and must not own the membership registry): an implementation must rate-limit these lookups (an
/// unauthenticated lookup is an amplification surface), and it must make `Allow` and `Deny`
/// indistinguishable to the caller in timing and observable behavior, per §A5's uniform-silent-drop
/// philosophy — otherwise the connect endpoint becomes a membership oracle.
///
/// # Why the decision is split in two (td-fc5a30)
///
/// "Attacker-controlled `from_fp`" is not a theoretical caveat, and the mitigation above
/// ("rate-limit these lookups") is not, on its own, sufficient — it was in fact the vulnerability.
/// A device holding `pub host.<h>.connect` can publish to that subject naming a **different**
/// device's inbox as the NATS reply subject: measured against nats-server 2.10, publish permissions
/// are evaluated against the publish *subject* only, never the reply, so nothing at the broker
/// refuses it. An attacker with any valid device credential can therefore send this host an offer
/// claiming a **victim's** `from_fp` with `reply = _INBOX_<victim_fp>.…`, which sails through
/// [`reply_prefix_ok`] and reaches [`ConnectAuthorizer::authorize`]. Every cost the authorizer
/// charges against the *named* identity at that point is charged to the victim by someone who
/// cannot produce the victim's signature: a per-`from_fp` token bucket becomes a targeted lockout,
/// a bounded per-`from_fp` map becomes exhaustible with fabricated names, and a per-`Allow`
/// capability mint becomes a free Ed25519 signature per attacker packet (and, since only `Allow`
/// signs, a timing oracle for membership).
///
/// The structural constraint on `authorize` cannot be removed — the signature genuinely cannot be
/// checked before the key that checks it has been resolved. So the *work* moves instead of the
/// ordering: [`ConnectAuthorizer::on_verified`] is a second callback this function makes only after
/// [`super::wire::open_offer`] has verified the offer's signature under the resolved `sign_pk` and
/// after every routing check has passed. A forged offer never reaches it. `authorize` is left
/// holding only costs that are bounded globally rather than per-identity; per-identity charges —
/// the per-`from_fp` bucket, the mint — live in `on_verified`, where `from_fp` is authenticated.
/// See [`ConnectAuthorizer`]'s own doc comment for the rule an implementer must follow, and why
/// moving a per-identity charge back into `authorize` reintroduces the targeted denial-of-service.
///
/// `on_verified` is called last, after the `inbox` equality check, so that every routing check has
/// already passed: an offer that is going to be rejected for *any* reason this function can see is
/// rejected before the host does per-identity work for it. A [`VerifiedDecision::Drop`] produces
/// [`SignalingError::Denied`] — the same uniform silent drop as every other rejection here, with no
/// distinguishable reply (DESIGN.md §A5).
pub async fn process_offer<A: ConnectAuthorizer>(
    payload: &[u8],
    reply: Option<&str>,
    host_device: &DeviceKey,
    host_device_fp: Fingerprint,
    authorizer: &A,
) -> Result<(OpenedOffer, Option<Capability>), SignalingError> {
    let env = Envelope::from_canonical_bytes(payload)?;
    let from_fp = Fingerprint::from_slice(&env.from_fp)?;

    if !reply_prefix_ok(reply, &from_fp) {
        return Err(SignalingError::BadReplyPrefix);
    }

    let (sign_pk, agree_pk) = match authorizer.authorize(&from_fp).await {
        ConnectDecision::Allow { sign_pk, agree_pk } => (sign_pk, agree_pk),
        ConnectDecision::Deny => return Err(SignalingError::Denied),
    };

    let opened = super::wire::open_offer(&env, host_device, host_device_fp, &sign_pk, &agree_pk)?;

    // DESIGN.md §A6/§A10.36: `inbox` is a *binding* of the reply subject into signed material, not
    // a redundant copy. `reply_prefix_ok` above proved the reply subject is shaped like this
    // sender's own inbox; this proves it is the *exact* subject the sender signed. It necessarily
    // runs last: `inbox` lives inside the ciphertext, so there is no key to read it with until
    // `open_offer` has returned.
    if reply != Some(opened.offer.inbox.as_str()) {
        return Err(SignalingError::ReplyInboxMismatch);
    }

    // The post-verification half of the authorization decision (td-fc5a30) — see this function's
    // "Why the decision is split in two" section. `from_fp` is authenticated from here on: the
    // envelope signature verified under the `sign_pk` `authorize` resolved for this exact
    // fingerprint, so only the holder of that device's signing key can have got this far. This is
    // therefore the first point at which it is safe for the host to charge anything against the
    // identity `from_fp` names.
    //
    // Deliberately placed after the `inbox` check rather than immediately after `open_offer`: an
    // offer this function is going to reject for a routing reason must cost the host no
    // per-identity work at all.
    let member_cap = match authorizer.on_verified(&from_fp).await {
        VerifiedDecision::Proceed { member_cap } => member_cap,
        // Uniform silent drop, identical in every observable way to a `ConnectDecision::Deny` or a
        // malformed envelope (DESIGN.md §A5) — the caller replies to none of them.
        VerifiedDecision::Drop => return Err(SignalingError::Denied),
    };

    Ok((opened, member_cap))
}

impl<A, H> SignalingHost<A, H>
where
    A: ConnectAuthorizer + Send + Sync + 'static,
    H: SessionHandler + Send + Sync + 'static,
{
    /// `device` is this host's **envelope** identity (§A7 `to_fp`/`from_fp`, and the X25519 half
    /// `k0`/`k1` are derived from); `host_fp` is its **root** fingerprint, the token every §A5 NATS
    /// subject is scoped by. See this type's doc comment for why both are required.
    pub fn new(
        nats: async_nats::Client,
        device: DeviceKey,
        host_fp: Fingerprint,
        authorizer: A,
        handler: H,
    ) -> Self {
        let device_fp = device.device_fp();
        Self {
            nats,
            device,
            device_fp,
            host_fp,
            authorizer,
            handler,
        }
    }

    /// This host's envelope device fingerprint — what a client seals its offer's `to_fp` to.
    pub fn device_fp(&self) -> Fingerprint {
        self.device_fp
    }

    /// This host's root fingerprint — the `<hfp>` token in every `host.<hfp>.*` subject.
    pub fn host_fp(&self) -> Fingerprint {
        self.host_fp
    }

    /// Subscribes on `host.<self>.connect` and handles connect offers for as long as the
    /// subscription stays open (i.e. until the NATS connection is dropped/closed by the caller —
    /// this method has no separate shutdown signal of its own). Each accepted offer is handled in
    /// its own spawned task so one slow or hostile connect attempt cannot block the next, bounded
    /// by `opts.max_concurrent_connects` in-flight tasks at a time — see that field's doc comment
    /// for why the cap exists and why exceeding it drops the offer rather than queuing it.
    pub async fn run(self: Arc<Self>, opts: HostOptions) -> Result<(), SignalingError> {
        use futures_util::StreamExt;
        use tokio::sync::Semaphore;

        let mut sub = self
            .nats
            .subscribe(connect_subject(&self.host_fp))
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;

        let connect_slots = Arc::new(Semaphore::new(opts.max_concurrent_connects));

        while let Some(msg) = sub.next().await {
            // `try_acquire_owned`, never the blocking `acquire`: this loop must never wait for a
            // permit. Waiting here would stall the NATS subscription itself — see
            // `HostOptions::max_concurrent_connects`'s doc comment for why that is strictly worse
            // than the uniform silent drop below.
            let Ok(permit) = Arc::clone(&connect_slots).try_acquire_owned() else {
                // Uniform silent drop (DESIGN.md §A5): the offer gets no reply at all, the same
                // observable outcome as a `ConnectDecision::Deny` or a malformed envelope. Log only
                // the cap value, never anything derived from `msg` — its payload, reply subject,
                // and headers are all attacker-supplied and unverified at this point (no signature
                // has been checked yet).
                tracing::warn!(
                    max_concurrent_connects = opts.max_concurrent_connects,
                    "connect offer dropped: at max-concurrent-connects cap"
                );
                continue;
            };
            let this = self.clone();
            tokio::spawn(async move {
                // Held for the whole handler; the slot is released when this task ends, whether
                // `handle_connect` succeeds, errors, or panics.
                let _permit = permit;
                if let Err(error) = this.handle_connect(msg, opts).await {
                    // `error.redacted()`, not `%error`: `handle_connect` can fail with any
                    // `SignalingError`, including the four variants that carry peer-supplied
                    // CBOR keys or an untruncated-fingerprint NATS subject — see
                    // `SignalingError::redacted`.
                    tracing::warn!(error = %error.redacted(), "connect attempt failed");
                }
            });
        }
        Ok(())
    }

    async fn handle_connect(
        &self,
        msg: async_nats::Message,
        opts: HostOptions,
    ) -> Result<(), SignalingError> {
        let reply_subject = msg.reply.clone().ok_or(SignalingError::BadReplyPrefix)?;
        let (opened, member_cap) = process_offer(
            &msg.payload,
            Some(reply_subject.as_str()),
            &self.device,
            self.device_fp,
            &self.authorizer,
        )
        .await?;

        if opened.offer.transport != Transport::Quic {
            return Err(SignalingError::UnsupportedTransport(opened.offer.transport));
        }

        let cert = SessionCert::generate()?;
        // The host is never the ICE-controlling side (the offerer, i.e. the client, controls —
        // matches `s2-connect.rs`'s convention).
        let mut local_ice = start_local_ice(false, opts.bind_ip).await?;

        // `member_cap` is the authorizer's own per-connect decision (td-c74122 slice B) — see
        // `ConnectDecision::Allow::member_cap`'s doc comment for what `None` means and why. This
        // crate never mints, inspects, or validates the cap; it only relays whatever the injected
        // `ConnectAuthorizer` supplied, unconditionally, on every successful connect
        // (DESIGN.md:286's "refreshed opportunistically on every successful session" and
        // :289-290's renewal-in-the-reply path — one mechanism satisfies both).
        let answer_payload = build_answer_payload(
            local_ice.ufrag.clone(),
            local_ice.pwd.clone(),
            cert.fingerprint(),
            member_cap,
        );
        let (session_key, answer_env) =
            opened.seal_answer(&self.device, self.device_fp, &answer_payload);

        // Subjects are scoped by the host's *root* fingerprint (§A5's subject table), never by its
        // envelope device fingerprint -- see this type's doc comment.
        let h2c_subject = session_subject(
            &self.host_fp,
            &opened.from_fp,
            &opened.sid,
            IceDirection::HostToClient,
        );
        let c2h_subject = session_subject(
            &self.host_fp,
            &opened.from_fp,
            &opened.sid,
            IceDirection::ClientToHost,
        );
        // Subscribe to the client's trickled ICE *before* publishing the answer, for the same
        // reason `client::SignalingClient::connect` subscribes before publishing its offer: the
        // client starts trickling the instant the answer lands, and a subscription created after
        // that point can silently miss the candidate that would have completed the punch.
        let c2h_sub = self
            .nats
            .subscribe(c2h_subject)
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;

        self.nats
            .publish(reply_subject, answer_env.to_canonical_bytes().into())
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;

        let mut seq: u64 = 1;
        let candidate_env = seal_ice(
            &session_key,
            &self.device,
            self.device_fp,
            opened.from_fp,
            &opened.sid,
            seq,
            &IcePayload {
                candidate: Some(local_ice.candidate_line.clone()),
                end_of_candidates: false,
            },
        );
        self.nats
            .publish(
                h2c_subject.clone(),
                candidate_env.to_canonical_bytes().into(),
            )
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;
        seq += 1;
        let eoc_env = seal_ice(
            &session_key,
            &self.device,
            self.device_fp,
            opened.from_fp,
            &opened.sid,
            seq,
            &IcePayload {
                candidate: None,
                end_of_candidates: true,
            },
        );
        self.nats
            .publish(h2c_subject, eoc_env.to_canonical_bytes().into())
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let bridge = tokio::spawn(bridge_incoming_ice(
            c2h_sub,
            // Subject tokens (host root fp, client device fp) ...
            self.host_fp,
            opened.from_fp,
            opened.sid.clone(),
            IceDirection::ClientToHost,
            session_key,
            opened.sender_sign_pk,
            // ... and envelope fingerprints (this host's envelope identity, the client's).
            self.device_fp,
            opened.from_fp,
            tx,
        ));

        let (remote_addr, _stats) = drive_ice_agent_trickle(
            &mut local_ice.agent,
            &local_ice.socket,
            // The host is never the controlling side; the peer's credentials come from the offer
            // this side just opened.
            false,
            &opened.offer.ufrag,
            &opened.offer.pwd,
            rx,
            opts.ice_timeout,
        )
        .await?;
        bridge.abort();
        tracing::debug!(%remote_addr, "ICE selected a candidate pair; accepting QUIC on the punched socket");

        let std_socket = local_ice.socket.into_std()?;
        let server = QuicServer::from_socket(std_socket, &cert, opened.offer.cert_fp)?;
        let control = server.accept().await?;

        // `opened.from_fp` is authenticated at this point, not merely claimed: `process_offer`
        // resolved it through the authorizer and `open_offer` verified the offer signature against
        // the `sign_pk` that lookup returned. See `SessionHandler`'s doc comment.
        let control = self.handler.handle_session(opened.from_fp, control).await;
        let _ = tokio::time::timeout(opts.session_close_timeout, control.connection.closed()).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use spindle_core::VerifyingKey;
    use spindle_proto::signaling::OfferPayload;
    use x25519_dalek::PublicKey as X25519PublicKey;

    use super::super::wire;
    use super::*;

    struct Peer {
        device: DeviceKey,
        fp: Fingerprint,
    }

    fn peer(sign_seed: u8, agree_seed: u8) -> Peer {
        let device = DeviceKey::from_seeds([sign_seed; 32], [agree_seed; 32]);
        let fp = device.device_fp();
        Peer { device, fp }
    }

    /// The reply subject a well-behaved client of fingerprint `fp` would both listen on and sign
    /// into its offer's `inbox` (DESIGN.md §A10.36 -- the two are the same string by construction).
    fn client_inbox(fp: &Fingerprint) -> String {
        format!("_INBOX_{fp}.abc123")
    }

    fn sample_offer_payload(inbox: &str) -> OfferPayload {
        OfferPayload {
            inbox: inbox.to_string(),
            transport: Transport::Quic,
            ufrag: "clientufrag".to_string(),
            pwd: "clientpassword1234567890ab".to_string(),
            cert_fp: [0x11; 32],
        }
    }

    /// An authorizer that always `Allow`s with a fixed, caller-supplied key pair — used to model
    /// "the registry resolved `from_fp` to these keys", independent of whether those keys actually
    /// belong to the envelope's real signer (see `process_offer_rejects_bad_signature_...` below,
    /// which deliberately hands back the wrong `sign_pk`).
    struct KeyAuthorizer {
        sign_pk: VerifyingKey,
        agree_pk: X25519PublicKey,
        /// td-c74122 slice B: the `member_cap` this fixture hands back from `on_verified`. `None`
        /// in every existing test (mirroring every host today, which has no cap-signing key);
        /// `Some(cap)` only in the tests that specifically pin the cap-relay behavior below.
        ///
        /// td-fc5a30 moved this from `authorize`'s `Allow` to `on_verified`'s `Proceed`: the
        /// production authorizer's mint moved across the signature-verification boundary, and a
        /// fixture that still handed the cap back from `authorize` could not model that.
        member_cap: Option<Capability>,
        /// Counts `on_verified` calls, so a test can prove the post-verification half is reached
        /// exactly once on the happy path and *not at all* when an earlier check rejects.
        on_verified_calls: AtomicUsize,
    }

    impl KeyAuthorizer {
        fn new(sign_pk: VerifyingKey, agree_pk: X25519PublicKey) -> Self {
            KeyAuthorizer {
                sign_pk,
                agree_pk,
                member_cap: None,
                on_verified_calls: AtomicUsize::new(0),
            }
        }

        fn with_member_cap(mut self, cap: Capability) -> Self {
            self.member_cap = Some(cap);
            self
        }

        fn on_verified_calls(&self) -> usize {
            self.on_verified_calls.load(Ordering::SeqCst)
        }
    }

    impl ConnectAuthorizer for KeyAuthorizer {
        async fn authorize(&self, _from_fp: &Fingerprint) -> ConnectDecision {
            ConnectDecision::Allow {
                sign_pk: self.sign_pk,
                agree_pk: self.agree_pk,
            }
        }

        async fn on_verified(&self, _from_fp: &Fingerprint) -> VerifiedDecision {
            self.on_verified_calls.fetch_add(1, Ordering::SeqCst);
            VerifiedDecision::Proceed {
                member_cap: self.member_cap.clone(),
            }
        }
    }

    /// An authorizer that always `Deny`s.
    struct DenyAuthorizer;

    impl ConnectAuthorizer for DenyAuthorizer {
        async fn authorize(&self, _from_fp: &Fingerprint) -> ConnectDecision {
            ConnectDecision::Deny
        }

        async fn on_verified(&self, _from_fp: &Fingerprint) -> VerifiedDecision {
            panic!("on_verified must be unreachable when authorize denies")
        }
    }

    /// An authorizer that `Allow`s with real keys (so the signature genuinely verifies) but then
    /// drops the connect in its post-verification half — the `VerifiedDecision::Drop` path.
    struct DropOnVerifiedAuthorizer {
        sign_pk: VerifyingKey,
        agree_pk: X25519PublicKey,
    }

    impl ConnectAuthorizer for DropOnVerifiedAuthorizer {
        async fn authorize(&self, _from_fp: &Fingerprint) -> ConnectDecision {
            ConnectDecision::Allow {
                sign_pk: self.sign_pk,
                agree_pk: self.agree_pk,
            }
        }

        async fn on_verified(&self, _from_fp: &Fingerprint) -> VerifiedDecision {
            VerifiedDecision::Drop
        }
    }

    /// A spy: records whether it was ever consulted, independent of what it decides. Used to prove
    /// (not just assert-by-comment) that `process_offer` rejects a bad reply prefix without ever
    /// calling the injected [`ConnectAuthorizer`] — see this module's doc comment above
    /// [`process_offer`] for why that ordering matters beyond performance.
    #[derive(Default)]
    struct SpyAuthorizer {
        called: AtomicBool,
    }

    impl SpyAuthorizer {
        fn was_called(&self) -> bool {
            self.called.load(Ordering::SeqCst)
        }
    }

    impl ConnectAuthorizer for SpyAuthorizer {
        async fn authorize(&self, _from_fp: &Fingerprint) -> ConnectDecision {
            self.called.store(true, Ordering::SeqCst);
            ConnectDecision::Deny
        }

        async fn on_verified(&self, _from_fp: &Fingerprint) -> VerifiedDecision {
            panic!("on_verified must be unreachable when authorize denies")
        }
    }

    #[tokio::test]
    async fn process_offer_happy_path_opens_for_an_authorized_sender() {
        let client = peer(0x10, 0x11);
        let host = peer(0x20, 0x21);
        let ctx = wire::new_offer_context();
        let payload = sample_offer_payload(&client_inbox(&client.fp));
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &payload,
        );
        let authorizer = KeyAuthorizer::new(
            client.device.sign_public_key(),
            client.device.agree_public_key(),
        );
        let reply = client_inbox(&client.fp);

        let (opened, member_cap) = process_offer(
            &offer_env.to_canonical_bytes(),
            Some(reply.as_str()),
            &host.device,
            host.fp,
            &authorizer,
        )
        .await
        .expect("a well-formed offer from an authorized sender must open");

        assert_eq!(opened.offer, payload);
        assert_eq!(opened.from_fp, client.fp);
        assert_eq!(member_cap, None);
    }

    #[tokio::test]
    async fn process_offer_denied_by_authorizer_yields_denied() {
        let client = peer(0x30, 0x31);
        let host = peer(0x40, 0x41);
        let ctx = wire::new_offer_context();
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(&client_inbox(&client.fp)),
        );
        let reply = client_inbox(&client.fp);

        let err = process_offer(
            &offer_env.to_canonical_bytes(),
            Some(reply.as_str()),
            &host.device,
            host.fp,
            &DenyAuthorizer,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, SignalingError::Denied),
            "expected SignalingError::Denied, got {err:?}"
        );
    }

    #[tokio::test]
    async fn process_offer_rejects_a_reply_with_the_wrong_inbox_prefix() {
        let client = peer(0x32, 0x33);
        let host = peer(0x42, 0x43);
        let ctx = wire::new_offer_context();
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(&client_inbox(&client.fp)),
        );
        let authorizer = KeyAuthorizer::new(
            client.device.sign_public_key(),
            client.device.agree_public_key(),
        );
        // Well-formed _INBOX subject, but scoped to a different device than the offer's own
        // from_fp -- the exact NATS-level spoof `reply_prefix_ok` exists to catch.
        let bad_reply = format!("_INBOX_{}.abc123", host.fp);

        let err = process_offer(
            &offer_env.to_canonical_bytes(),
            Some(bad_reply.as_str()),
            &host.device,
            host.fp,
            &authorizer,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, SignalingError::BadReplyPrefix),
            "expected SignalingError::BadReplyPrefix, got {err:?}"
        );
    }

    /// DESIGN.md §A10.36's *isolating* test. Everything about this offer is correct -- valid
    /// signature, authorized sender, and an `inbox` that is a perfectly well-formed
    /// `_INBOX_<from_fp>.` subject, so `reply_prefix_ok` passes -- except that the reply subject
    /// the transport reports is a *different* inbox of the same sender's. That is precisely what a
    /// substituting broker produces. Delete the `inbox` equality check and this offer is accepted:
    /// this test then fails by *succeeding*, not by returning some other error.
    #[tokio::test]
    async fn process_offer_rejects_a_reply_subject_the_client_did_not_sign() {
        let client = peer(0x3a, 0x3b);
        let host = peer(0x4a, 0x4b);
        let ctx = wire::new_offer_context();
        let signed_inbox = client_inbox(&client.fp);
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(&signed_inbox),
        );
        let authorizer = KeyAuthorizer::new(
            client.device.sign_public_key(),
            client.device.agree_public_key(),
        );
        // A different, but still validly-prefixed, inbox of the same client's -- what a
        // substituting broker would report as `msg.reply` instead of the signed `inbox`.
        let reported_reply = format!("_INBOX_{}.zzz999", client.fp);
        assert_ne!(signed_inbox, reported_reply);

        let err = process_offer(
            &offer_env.to_canonical_bytes(),
            Some(reported_reply.as_str()),
            &host.device,
            host.fp,
            &authorizer,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, SignalingError::ReplyInboxMismatch),
            "expected SignalingError::ReplyInboxMismatch, got {err:?}"
        );
    }

    /// The positive twin: reply subject and signed `inbox` agree, so the binding check passes.
    #[tokio::test]
    async fn process_offer_accepts_a_reply_subject_matching_the_signed_inbox() {
        let client = peer(0x3c, 0x3d);
        let host = peer(0x4c, 0x4d);
        let ctx = wire::new_offer_context();
        let signed_inbox = client_inbox(&client.fp);
        let payload = sample_offer_payload(&signed_inbox);
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &payload,
        );
        let authorizer = KeyAuthorizer::new(
            client.device.sign_public_key(),
            client.device.agree_public_key(),
        );

        let (opened, _member_cap) = process_offer(
            &offer_env.to_canonical_bytes(),
            Some(signed_inbox.as_str()),
            &host.device,
            host.fp,
            &authorizer,
        )
        .await
        .expect("a reply subject matching the signed inbox must be accepted");

        assert_eq!(opened.offer, payload);
    }

    #[tokio::test]
    async fn process_offer_rejects_a_missing_reply() {
        let client = peer(0x34, 0x35);
        let host = peer(0x44, 0x45);
        let ctx = wire::new_offer_context();
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(&client_inbox(&client.fp)),
        );
        let authorizer = KeyAuthorizer::new(
            client.device.sign_public_key(),
            client.device.agree_public_key(),
        );

        // `reply_prefix_ok(None, _)` is unconditionally false (`Option::is_some_and`) -- a missing
        // reply is rejected the same way a wrong-prefix one is, not treated as some other case.
        let err = process_offer(
            &offer_env.to_canonical_bytes(),
            None,
            &host.device,
            host.fp,
            &authorizer,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, SignalingError::BadReplyPrefix),
            "expected SignalingError::BadReplyPrefix for a None reply, got {err:?}"
        );
    }

    #[tokio::test]
    async fn process_offer_rejects_bad_signature_from_the_authorizer_resolved_key() {
        // The authorizer resolves from_fp to the WRONG signing key (an impostor's, not the real
        // sender's) -- e.g. a stale/incorrect registry entry. The envelope itself is genuine and
        // untampered; only the key process_offer is told to verify it against is wrong. Mirrors
        // `wire::tests::open_offer_rejects_wrong_signing_key` but goes through `process_offer`.
        let client = peer(0x36, 0x37);
        let host = peer(0x46, 0x47);
        let impostor = peer(0x56, 0x57);
        let ctx = wire::new_offer_context();
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(&client_inbox(&client.fp)),
        );
        // The authorizer resolves `from_fp` to the WRONG signing key (an impostor's).
        let authorizer = KeyAuthorizer::new(
            impostor.device.sign_public_key(),
            client.device.agree_public_key(),
        );
        let reply = client_inbox(&client.fp);

        let err = process_offer(
            &offer_env.to_canonical_bytes(),
            Some(reply.as_str()),
            &host.device,
            host.fp,
            &authorizer,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                SignalingError::Envelope(spindle_core::envelope::EnvelopeError::BadSignature)
            ),
            "expected Envelope(BadSignature), got {err:?}"
        );
    }

    #[tokio::test]
    async fn process_offer_rejects_bad_reply_prefix_without_consulting_the_authorizer() {
        let client = peer(0x38, 0x39);
        let host = peer(0x48, 0x49);
        let ctx = wire::new_offer_context();
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(&client_inbox(&client.fp)),
        );
        let spy = SpyAuthorizer::default();

        let err = process_offer(
            &offer_env.to_canonical_bytes(),
            None, // bad reply -- missing entirely
            &host.device,
            host.fp,
            &spy,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, SignalingError::BadReplyPrefix),
            "expected SignalingError::BadReplyPrefix, got {err:?}"
        );
        assert!(
            !spy.was_called(),
            "the authorizer must not be consulted before the reply-prefix check passes, but it was called"
        );
    }

    // ---- td-fc5a30: the authorization decision is split across the signature-verification
    // boundary, so a forged offer never reaches the per-identity half ------------------------

    /// The crate-level regression test for td-fc5a30. An attacker publishes an offer that *names*
    /// the victim's `from_fp` and carries a reply subject shaped like the victim's own inbox —
    /// which is exactly what nats-server permits, since it evaluates publish permissions against
    /// the publish subject only. `reply_prefix_ok` therefore passes, `authorize` is consulted for
    /// the victim's fingerprint, and only `open_offer`'s signature check can tell the difference:
    /// the attacker cannot sign as the victim.
    ///
    /// What this pins is that `on_verified` is **never called** for such an offer. Everything the
    /// host charges to the named identity — its per-`from_fp` token bucket, its slot in the bounded
    /// tracking map, an Ed25519 capability mint — now lives behind that call, so "never called"
    /// is exactly "the victim was charged nothing". Move any of it back into `authorize` and this
    /// test still passes, which is why `spindle-host-core`'s
    /// `a_forged_offer_naming_a_victim_does_not_consume_the_victims_per_fp_bucket` exists too: this
    /// one pins the control flow, that one pins the consequence.
    #[tokio::test]
    async fn a_forged_offer_naming_another_device_never_reaches_on_verified() {
        let victim = peer(0x80, 0x81);
        let attacker = peer(0x82, 0x83);
        let host = peer(0x84, 0x85);
        let ctx = wire::new_offer_context();

        // The attacker seals an offer with its OWN key material but stamps the victim's
        // fingerprint on the envelope, and uses the victim's inbox as the reply subject.
        let victim_reply = client_inbox(&victim.fp);
        let offer_env = wire::seal_offer(
            &ctx,
            &attacker.device,
            victim.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(&victim_reply),
        );

        // The host's registry resolves the victim's fingerprint to the VICTIM's real keys — the
        // honest lookup a real authorizer performs, and the reason the forgery is detectable at
        // all.
        let authorizer = KeyAuthorizer::new(
            victim.device.sign_public_key(),
            victim.device.agree_public_key(),
        );

        let err = process_offer(
            &offer_env.to_canonical_bytes(),
            Some(victim_reply.as_str()),
            &host.device,
            host.fp,
            &authorizer,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                SignalingError::Envelope(spindle_core::envelope::EnvelopeError::BadSignature)
            ),
            "expected Envelope(BadSignature): the attacker cannot sign as the victim, got {err:?}"
        );
        assert_eq!(
            authorizer.on_verified_calls(),
            0,
            "on_verified must never run for an offer whose signature did not verify. Every \
             per-identity cost the host charges (the per-from_fp token bucket, the bounded \
             tracking map, the capability mint) lives behind this call precisely so a forged \
             offer naming a victim charges that victim nothing -- a nonzero count here means the \
             post-verification boundary has been moved or bypassed, reopening td-fc5a30's \
             targeted denial-of-service."
        );
    }

    /// The routing-check twin: an offer whose signature is genuine but whose reply subject is not
    /// the one the sender signed (§A10.36's substituting-broker case) must also stop short of
    /// `on_verified`. This is why the call is placed after the `inbox` equality check rather than
    /// immediately after `open_offer`.
    #[tokio::test]
    async fn a_reply_subject_the_client_did_not_sign_never_reaches_on_verified() {
        let client = peer(0x86, 0x87);
        let host = peer(0x88, 0x89);
        let ctx = wire::new_offer_context();
        let signed_inbox = client_inbox(&client.fp);
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(&signed_inbox),
        );
        let authorizer = KeyAuthorizer::new(
            client.device.sign_public_key(),
            client.device.agree_public_key(),
        );
        let reported_reply = format!("_INBOX_{}.zzz999", client.fp);
        assert_ne!(signed_inbox, reported_reply);

        let err = process_offer(
            &offer_env.to_canonical_bytes(),
            Some(reported_reply.as_str()),
            &host.device,
            host.fp,
            &authorizer,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SignalingError::ReplyInboxMismatch));
        assert_eq!(
            authorizer.on_verified_calls(),
            0,
            "on_verified must run only after EVERY routing check has passed, so an offer rejected \
             for a routing reason costs the host no per-identity work at all"
        );
    }

    /// The positive half: a fully valid offer reaches `on_verified` exactly once.
    #[tokio::test]
    async fn a_valid_offer_reaches_on_verified_exactly_once() {
        let client = peer(0x8a, 0x8b);
        let host = peer(0x8c, 0x8d);
        let ctx = wire::new_offer_context();
        let reply = client_inbox(&client.fp);
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(&reply),
        );
        let authorizer = KeyAuthorizer::new(
            client.device.sign_public_key(),
            client.device.agree_public_key(),
        );

        process_offer(
            &offer_env.to_canonical_bytes(),
            Some(reply.as_str()),
            &host.device,
            host.fp,
            &authorizer,
        )
        .await
        .expect("a well-formed offer from an authorized sender must open");
        assert_eq!(
            authorizer.on_verified_calls(),
            1,
            "a verified offer must consult the post-verification half exactly once -- not zero \
             times (the per-identity charge and the mint would never happen) and not twice (the \
             peer would be charged twice for one connect)"
        );
    }

    /// `VerifiedDecision::Drop` rejects the connect with the same uniform silent drop every other
    /// rejection uses: `SignalingError::Denied`, indistinguishable from a `ConnectDecision::Deny`.
    #[tokio::test]
    async fn on_verified_drop_yields_denied() {
        let client = peer(0x8e, 0x8f);
        let host = peer(0x90, 0x91);
        let ctx = wire::new_offer_context();
        let reply = client_inbox(&client.fp);
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(&reply),
        );
        let authorizer = DropOnVerifiedAuthorizer {
            sign_pk: client.device.sign_public_key(),
            agree_pk: client.device.agree_public_key(),
        };

        let err = process_offer(
            &offer_env.to_canonical_bytes(),
            Some(reply.as_str()),
            &host.device,
            host.fp,
            &authorizer,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, SignalingError::Denied),
            "a VerifiedDecision::Drop must produce the same SignalingError::Denied a \
             ConnectDecision::Deny does -- no reply, and nothing that distinguishes the two to \
             the peer. Got {err:?}"
        );
    }

    // ---- td-c74122 slice B: the authorizer's `member_cap` decision flows into the answer ----

    /// A dummy `Capability` — never verified by anything in this test, only carried as opaque
    /// bytes (see `ConnectDecision::Allow::member_cap`'s doc comment: `spindle-net` never mints,
    /// inspects, or validates this value). Field values follow the same "distinct repeated byte
    /// per field" convention `spindle-proto`'s own `gen_vectors.rs` uses for its dummy caps.
    fn sample_capability() -> Capability {
        Capability {
            v: 1,
            host_fp: vec![0x91; 32],
            host_root_pk: vec![0x92; 32],
            op_cert: vec![0x93; 16],
            kind: spindle_proto::artifacts::CapKind::Member,
            subject: vec![0x94; 32],
            cap_epoch: 3,
            exp: 1_759_017_600,
            nonce: vec![0x95; 16],
            sig: vec![0x96; 64],
        }
    }

    /// DESIGN.md:286/:289-290, end to end through this crate's own plumbing (not just the wire
    /// type slice A already pinned): an authorizer that `Allow`s with `member_cap: Some(cap)`
    /// must produce a sealed answer that decodes back to that exact cap. Goes all the way through
    /// `opened.seal_answer`/`wire::open_answer` -- the real E2E sealing path, not a bare CBOR
    /// round trip -- so this is also evidence the cap survives the k1 envelope, not merely
    /// `AnswerPayload`'s own encoder/decoder.
    #[tokio::test]
    async fn allow_with_a_member_cap_flows_into_the_sealed_answer() {
        let client = peer(0x60, 0x61);
        let host = peer(0x62, 0x63);
        let ctx = wire::new_offer_context();
        let reply = client_inbox(&client.fp);
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(&reply),
        );
        let cap = sample_capability();
        let authorizer = KeyAuthorizer::new(
            client.device.sign_public_key(),
            client.device.agree_public_key(),
        )
        .with_member_cap(cap.clone());

        let (opened, member_cap) = process_offer(
            &offer_env.to_canonical_bytes(),
            Some(reply.as_str()),
            &host.device,
            host.fp,
            &authorizer,
        )
        .await
        .expect("a well-formed offer from an authorized sender must open");
        assert_eq!(
            member_cap,
            Some(cap.clone()),
            "process_offer must hand back the exact member_cap the authorizer returned"
        );

        let answer_payload = build_answer_payload(
            "hostufrag".to_string(),
            "hostpassword1234567890abcd".to_string(),
            [0x22; 32],
            member_cap,
        );
        let (_session_key, answer_env) = opened.seal_answer(&host.device, host.fp, &answer_payload);

        let (_client_k1, decoded_answer) = wire::open_answer(
            &answer_env,
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.sign_public_key(),
            &host.device.agree_public_key(),
        )
        .expect("answer opens");

        assert_eq!(
            decoded_answer.member_cap,
            Some(cap),
            "the client must see the exact cap the host's authorizer supplied, through the real \
             seal/open path"
        );
    }

    /// The negative twin: an authorizer that `Allow`s with `member_cap: None` (every host today,
    /// per that field's doc comment) must produce an answer that both decodes to `None` and
    /// genuinely omits the `member_cap` key on the wire -- not a `null`-emitting encoder that
    /// would also decode back to `None` (see `spindle-proto`'s own
    /// `answer_round_trips_with_member_cap_absent_and_omits_the_key`, which this test's assertion
    /// on the raw CBOR mirrors at this crate's own construction site).
    #[tokio::test]
    async fn allow_with_no_member_cap_produces_an_answer_that_omits_the_key() {
        let client = peer(0x64, 0x65);
        let host = peer(0x66, 0x67);
        let ctx = wire::new_offer_context();
        let reply = client_inbox(&client.fp);
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &sample_offer_payload(&reply),
        );
        let authorizer = KeyAuthorizer::new(
            client.device.sign_public_key(),
            client.device.agree_public_key(),
        );

        let (opened, member_cap) = process_offer(
            &offer_env.to_canonical_bytes(),
            Some(reply.as_str()),
            &host.device,
            host.fp,
            &authorizer,
        )
        .await
        .expect("a well-formed offer from an authorized sender must open");
        assert_eq!(member_cap, None);

        let answer_payload = build_answer_payload(
            "hostufrag".to_string(),
            "hostpassword1234567890abcd".to_string(),
            [0x22; 32],
            member_cap,
        );
        let (_session_key, answer_env) = opened.seal_answer(&host.device, host.fp, &answer_payload);

        let (_client_k1, decoded_answer) = wire::open_answer(
            &answer_env,
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.sign_public_key(),
            &host.device.agree_public_key(),
        )
        .expect("answer opens");
        assert_eq!(decoded_answer.member_cap, None);

        let decoded_cbor = spindle_proto::canonical_decode(&answer_payload.to_canonical_bytes())
            .expect("decode cbor");
        if let spindle_proto::CborValue::Map(entries) = decoded_cbor {
            assert!(
                !entries
                    .iter()
                    .any(|(k, _)| k.as_text() == Some("member_cap")),
                "member_cap key must be omitted when the authorizer supplies None, not present \
                 with any value"
            );
        } else {
            panic!("expected a map");
        }
    }

    // ---- td-4bcf24: max_concurrent_connects is a load-bearing cap, not a decorative default ----

    /// Pins the documented default so `HostOptions::default()`'s `64` cannot silently drift out of
    /// sync with `max_concurrent_connects`'s doc comment (which cites this exact number).
    #[test]
    fn host_options_default_max_concurrent_connects_is_64() {
        assert_eq!(HostOptions::default().max_concurrent_connects, 64);
    }

    /// A pure-semaphore proof that the cap actually bounds concurrency, without standing up NATS:
    /// a `Semaphore` sized from `HostOptions::default().max_concurrent_connects` yields exactly
    /// that many non-blocking permits and then refuses the next `try_acquire_owned` -- mirroring
    /// `SignalingHost::run`'s own use of `try_acquire_owned` (never the blocking `acquire`) against
    /// the exact same `Semaphore` API this test exercises directly.
    #[test]
    fn semaphore_sized_from_the_default_cap_admits_exactly_that_many_permits_then_refuses() {
        let cap = HostOptions::default().max_concurrent_connects;
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(cap));

        let permits: Vec<_> = (0..cap)
            .map(|_| {
                std::sync::Arc::clone(&slots)
                    .try_acquire_owned()
                    .expect("permit within the cap must be granted")
            })
            .collect();
        assert_eq!(permits.len(), cap);

        assert!(
            std::sync::Arc::clone(&slots).try_acquire_owned().is_err(),
            "a permit beyond the cap must be refused, not granted or blocked on"
        );
    }

    /// The release half of the same proof: dropping one held permit frees exactly one slot -- the
    /// next `try_acquire_owned` succeeds, and the one after that (with no further drop) fails
    /// again. This is the behavior `SignalingHost::run` relies on to admit the next legitimate
    /// offer once an in-flight `handle_connect` task ends and drops its `_permit`.
    #[test]
    fn dropping_one_permit_admits_exactly_one_more() {
        let cap = HostOptions::default().max_concurrent_connects;
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(cap));

        let mut permits: Vec<_> = (0..cap)
            .map(|_| {
                std::sync::Arc::clone(&slots)
                    .try_acquire_owned()
                    .expect("permit within the cap must be granted")
            })
            .collect();
        assert!(std::sync::Arc::clone(&slots).try_acquire_owned().is_err());

        drop(permits.pop().expect("cap is non-zero"));

        let _reacquired = std::sync::Arc::clone(&slots)
            .try_acquire_owned()
            .expect("dropping one permit must admit exactly one more");
        assert!(
            std::sync::Arc::clone(&slots).try_acquire_owned().is_err(),
            "only one additional permit should be admitted after exactly one drop"
        );
    }
}
