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
use spindle_proto::artifacts::Envelope;
use spindle_proto::signaling::{AnswerPayload, IcePayload, Transport};

use crate::quic::{ControlStream, QuicServer, SessionCert};

use super::authorize::{ConnectAuthorizer, ConnectDecision};
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
pub trait SessionHandler: Send + Sync {
    fn handle_session(
        &self,
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
}

impl Default for HostOptions {
    fn default() -> Self {
        Self {
            bind_ip: IpAddr::from([0, 0, 0, 0]),
            ice_timeout: Duration::from_secs(10),
            session_close_timeout: Duration::from_secs(5),
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

/// Verifies every §A7/§A5/§A6 receiver-side check on one raw connect-offer message and returns the
/// opened offer, without touching NATS/ICE/QUIC — the richest unit-testable surface for this half
/// of the host flow (see this crate's report for what a live run still needs to prove beyond this).
///
/// The reply-prefix check runs first — it is cheap and needs no crypto. The authorizer call runs
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
pub async fn process_offer<A: ConnectAuthorizer>(
    payload: &[u8],
    reply: Option<&str>,
    host_device: &DeviceKey,
    host_device_fp: Fingerprint,
    authorizer: &A,
) -> Result<OpenedOffer, SignalingError> {
    let env = Envelope::from_canonical_bytes(payload)?;
    let from_fp = Fingerprint::from_slice(&env.from_fp)?;

    if !reply_prefix_ok(reply, &from_fp) {
        return Err(SignalingError::BadReplyPrefix);
    }

    let (sign_pk, agree_pk) = match authorizer.authorize(&from_fp).await {
        ConnectDecision::Allow { sign_pk, agree_pk } => (sign_pk, agree_pk),
        ConnectDecision::Deny => return Err(SignalingError::Denied),
    };

    super::wire::open_offer(&env, host_device, host_device_fp, &sign_pk, &agree_pk)
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
    /// its own spawned task so one slow or hostile connect attempt cannot block the next.
    pub async fn run(self: Arc<Self>, opts: HostOptions) -> Result<(), SignalingError> {
        use futures_util::StreamExt;

        let mut sub = self
            .nats
            .subscribe(connect_subject(&self.host_fp))
            .await
            .map_err(|e| SignalingError::Nats(e.to_string()))?;

        while let Some(msg) = sub.next().await {
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(error) = this.handle_connect(msg, opts).await {
                    tracing::warn!(%error, "connect attempt failed");
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
        let opened = process_offer(
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

        let answer_payload = AnswerPayload {
            transport: Transport::Quic,
            ufrag: local_ice.ufrag.clone(),
            pwd: local_ice.pwd.clone(),
            cert_fp: cert.fingerprint(),
        };
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

        let control = self.handler.handle_session(control).await;
        let _ = tokio::time::timeout(opts.session_close_timeout, control.connection.closed()).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

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

    fn sample_offer_payload() -> OfferPayload {
        OfferPayload {
            inbox: "_INBOX_client.x".to_string(),
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
    }

    impl ConnectAuthorizer for KeyAuthorizer {
        async fn authorize(&self, _from_fp: &Fingerprint) -> ConnectDecision {
            ConnectDecision::Allow {
                sign_pk: self.sign_pk,
                agree_pk: self.agree_pk,
            }
        }
    }

    /// An authorizer that always `Deny`s.
    struct DenyAuthorizer;

    impl ConnectAuthorizer for DenyAuthorizer {
        async fn authorize(&self, _from_fp: &Fingerprint) -> ConnectDecision {
            ConnectDecision::Deny
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
    }

    #[tokio::test]
    async fn process_offer_happy_path_opens_for_an_authorized_sender() {
        let client = peer(0x10, 0x11);
        let host = peer(0x20, 0x21);
        let ctx = wire::new_offer_context();
        let payload = sample_offer_payload();
        let offer_env = wire::seal_offer(
            &ctx,
            &client.device,
            client.fp,
            host.fp,
            &host.device.agree_public_key(),
            &payload,
        );
        let authorizer = KeyAuthorizer {
            sign_pk: client.device.sign_public_key(),
            agree_pk: client.device.agree_public_key(),
        };
        let reply = format!("_INBOX_{}.abc123", client.fp);

        let opened = process_offer(
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
            &sample_offer_payload(),
        );
        let reply = format!("_INBOX_{}.abc123", client.fp);

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
            &sample_offer_payload(),
        );
        let authorizer = KeyAuthorizer {
            sign_pk: client.device.sign_public_key(),
            agree_pk: client.device.agree_public_key(),
        };
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
            &sample_offer_payload(),
        );
        let authorizer = KeyAuthorizer {
            sign_pk: client.device.sign_public_key(),
            agree_pk: client.device.agree_public_key(),
        };

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
            &sample_offer_payload(),
        );
        let authorizer = KeyAuthorizer {
            sign_pk: impostor.device.sign_public_key(), // wrong pinned key
            agree_pk: client.device.agree_public_key(),
        };
        let reply = format!("_INBOX_{}.abc123", client.fp);

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
            &sample_offer_payload(),
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
}
