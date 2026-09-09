//! [`ConnectAuthorizer`] — the host-side "is this connect offer's sender an active, non-revoked
//! member device permitted to connect to this host?" decision (DESIGN.md §A5). Injected rather
//! than implemented here: per A9c boundary rule 3 (`proto ← core ← {net, vfs} ← {host-core,
//! client-core}`), `spindle-net` must never depend on `spindle-host-core`, which is where the
//! member registry and revocation state actually live. `spikes/s2-signaling`'s `s2-connect.rs`
//! did this lookup inline against a hand-built test fixture (`HostState::known_device_fp`); that
//! inline shape does not graduate — a real host wires this trait to its registry at the call site.

use spindle_core::Fingerprint;
use x25519_dalek::PublicKey as X25519PublicKey;

/// The outcome of a connect-authorization decision.
// `Allow`'s two public keys make it substantially larger than `Deny` (clippy's
// `large_enum_variant`) — not boxed, deliberately: this decision is returned exactly once per
// connect attempt (never stored in a hot-path collection), so the extra ~200 bytes on the stack is
// immaterial, and boxing would only add an indirection for every caller to unwrap for no benefit.
#[allow(clippy::large_enum_variant)]
pub enum ConnectDecision {
    /// `from_fp` is an active, non-revoked member device permitted to connect. Carries the
    /// sender's pinned public keys — both needed before a single byte of the offer's signature or
    /// ciphertext can be verified (DESIGN.md §A7): `sign_pk` verifies the envelope signature,
    /// `agree_pk` is the X25519 half `k0`/`k1` are derived from. Resolving these from `from_fp`
    /// needs a device registry, which is exactly the state `spindle-net` must not own — see this
    /// module's doc comment. As of DESIGN.md v0.9.16 (§A10.34),
    /// `spindle_proto::artifacts::DeviceCertificate` does carry `alg_id`/`sign_pk`/`agree_pk`
    /// directly, and a verifier recomputes `device_fp` from them to check the binding — but
    /// mapping `from_fp` to the right certificate in the first place is still the registry lookup
    /// this trait exists to inject rather than perform.
    Allow {
        sign_pk: spindle_core::VerifyingKey,
        agree_pk: X25519PublicKey,
    },
    /// `from_fp` is unknown, not (yet) a member, or revoked. The caller must drop the offer with
    /// no distinguishable reply (DESIGN.md §A5's uniform-silent-drop philosophy) — see
    /// [`super::error::SignalingError::Denied`].
    Deny,
}

/// The outcome of [`ConnectAuthorizer::on_verified`] — the *post*-signature-verification half of a
/// connect decision. See that method's doc comment for the boundary this type sits on.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifiedDecision {
    /// The connect may proceed. Carries the host's current member capability for this device's
    /// root, to be returned in the connect answer (DESIGN.md:286 — member caps are "refreshed
    /// opportunistically on every successful session" — and :289-290's renewal path, which
    /// re-issues "the current cap in the reply").
    ///
    /// `member_cap: None` is a normal, non-exceptional answer, not a placeholder for
    /// "unimplemented": it is what a host with no cap-signing key online supplies (which is every
    /// host today — `spindle-hostd` installs a `CapIssuer` only if one is handed to it), and it is
    /// also what a host supplies when minting was attempted and failed. An issuance failure must
    /// never become a [`Self::Drop`]: it costs the peer a fresh capability, never the connect.
    ///
    /// `spindle-net` never mints, inspects, or validates this value: it is opaque bytes the
    /// injected authorizer supplies, and this crate only relays it into the answer envelope.
    /// Minting requires host key material (the root public key, the capability op cert, the op
    /// signing key) that A9c boundary rule 3 keeps out of this crate — see this module's doc
    /// comment.
    Proceed {
        member_cap: Option<spindle_proto::artifacts::Capability>,
    },
    /// The connect must be dropped, even though its signature verified. The caller drops the offer
    /// with no distinguishable reply, exactly as it does for [`ConnectDecision::Deny`] — see
    /// [`super::error::SignalingError::Denied`].
    Drop,
}

/// Host-injected membership/authorization decision (DESIGN.md §A5). A real host implements this
/// against its own member registry / revocation store; nothing in `spindle-net` may resolve it
/// directly (see the module doc comment).
///
/// # Two methods, one signature-verification boundary
///
/// This trait deliberately splits one logical decision across two calls, because the two halves
/// are reached with fundamentally different amounts of trust in `from_fp`:
///
/// - [`Self::authorize`] runs **before** any signature has been checked. Its `from_fp` is an
///   unverified, attacker-chosen string of bytes lifted straight out of an unauthenticated NATS
///   message. It is called precisely so the caller can obtain the `sign_pk` it will *then* verify
///   the offer against — there is no earlier point at which the identity could have been proven.
/// - [`Self::on_verified`] runs **only after** [`super::wire::open_offer`] has verified the
///   offer's Ed25519 signature under the `sign_pk` that [`Self::authorize`] returned, and after
///   every routing check has passed. Its `from_fp` is authenticated: only the holder of that
///   device's signing key can cause this method to be called with it.
///
/// **The rule this split exists to enforce**: [`Self::authorize`] may charge only costs an
/// attacker is allowed to impose on *everyone* — a global bound, a shared budget, work whose
/// exhaustion degrades the host uniformly. It must never charge a cost against the **named
/// identity**: not a per-`from_fp` token bucket, not an entry in a per-`from_fp` map, not a
/// signature minted for that identity, not a counter, not a lockout. Any such charge is an
/// attacker-directed weapon, because the attacker picks the name.
///
/// Stated plainly, because it is the defect this design was written to close: **moving a
/// per-identity charge back into [`Self::authorize`] reintroduces a targeted denial-of-service
/// against an arbitrary victim.** An attacker holding any valid device credential can publish to
/// `host.<h>.connect` naming a victim's `from_fp`; nats-server evaluates publish permissions
/// against the publish subject only, never the reply subject, so the offer reaches the host and
/// passes [`super::subject::reply_prefix_ok`]. Every per-identity cost [`Self::authorize`] charges
/// is therefore charged to the victim, by someone who could never produce the victim's signature.
/// A per-fp token bucket becomes a remote "lock this specific device out" primitive; a bounded
/// per-fp map becomes exhaustible with fabricated names; a mint becomes a free Ed25519 signature
/// per attacker packet. None of that is reachable from [`Self::on_verified`], where the identity
/// has been proven.
///
/// Per-identity costs are legitimate in [`Self::on_verified`] and belong there: a peer that can
/// sign as `from_fp` **is** `from_fp`, so throttling it, tracking it, or minting for it charges
/// exactly the party responsible for the work.
pub trait ConnectAuthorizer: Send + Sync {
    /// Resolves a connect decision for `from_fp` (the offer's claimed sender, already extracted
    /// from the envelope but not yet cryptographically verified — the caller uses the returned
    /// `sign_pk`/`agree_pk` to perform that verification next, so an authorizer must not treat
    /// being asked as proof of anything about the envelope itself).
    ///
    /// Called with an **unverified, attacker-chosen** `from_fp`. Read this trait's own doc comment
    /// before adding any work here: an implementation may charge only globally-bounded costs, and
    /// must never charge anything against the identity `from_fp` names. A membership lookup (which
    /// is what this method exists to perform) is fine; a per-`from_fp` bucket, map insert, counter,
    /// or signature is not.
    fn authorize(
        &self,
        from_fp: &Fingerprint,
    ) -> impl std::future::Future<Output = ConnectDecision> + Send;

    /// The post-verification half of the decision, called by [`super::host::process_offer`] once —
    /// and only once — the offer's signature has verified under the `sign_pk` [`Self::authorize`]
    /// returned for this same `from_fp`, and every routing check (reply prefix, `to_fp`, the
    /// §A10.36 signed-`inbox` binding) has passed.
    ///
    /// `from_fp` is **authenticated** here. That is the entire point of the split: this method is
    /// unreachable for a forged offer, so per-identity costs charged here are charged to the party
    /// that actually incurred them. Put the per-`from_fp` token bucket, any per-identity bookkeeping,
    /// and the member-capability mint here — never in [`Self::authorize`].
    ///
    /// Returning [`VerifiedDecision::Drop`] rejects the connect exactly as [`ConnectDecision::Deny`]
    /// does: the caller produces `SignalingError::Denied` and drops the offer with no reply.
    /// Returning [`VerifiedDecision::Proceed`] supplies the `member_cap` (possibly `None`) the host
    /// relays into the connect answer.
    fn on_verified(
        &self,
        from_fp: &Fingerprint,
    ) -> impl std::future::Future<Output = VerifiedDecision> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::identity::DeviceKey;

    fn fp(seed: u8) -> Fingerprint {
        DeviceKey::from_seeds([seed; 32], [seed.wrapping_add(1); 32]).device_fp()
    }

    /// A fixed allow/deny-list authorizer — the shape a real host-core registry lookup would take,
    /// minus the registry itself.
    struct FixedAuthorizer {
        allowed: Fingerprint,
        device: DeviceKey,
    }

    impl ConnectAuthorizer for FixedAuthorizer {
        async fn authorize(&self, from_fp: &Fingerprint) -> ConnectDecision {
            if *from_fp == self.allowed {
                ConnectDecision::Allow {
                    sign_pk: self.device.sign_public_key(),
                    agree_pk: self.device.agree_public_key(),
                }
            } else {
                ConnectDecision::Deny
            }
        }

        async fn on_verified(&self, _from_fp: &Fingerprint) -> VerifiedDecision {
            // This fixture models a bare registry lookup, not cap issuance -- see
            // `VerifiedDecision::Proceed::member_cap`'s doc comment for why `None` is the honest
            // answer whenever no cap-signing key is wired in.
            VerifiedDecision::Proceed { member_cap: None }
        }
    }

    #[tokio::test]
    async fn allows_the_known_sender() {
        let device = DeviceKey::from_seeds([0x70; 32], [0x71; 32]);
        let allowed = device.device_fp();
        let authorizer = FixedAuthorizer { allowed, device };

        match authorizer.authorize(&allowed).await {
            ConnectDecision::Allow { sign_pk, agree_pk } => {
                assert_eq!(sign_pk, authorizer.device.sign_public_key());
                assert_eq!(agree_pk, authorizer.device.agree_public_key());
            }
            ConnectDecision::Deny => panic!("expected Allow for the registered device_fp"),
        }
        assert_eq!(
            authorizer.on_verified(&allowed).await,
            VerifiedDecision::Proceed { member_cap: None },
            "this fixture mints nothing, so the post-verification half proceeds with no cap"
        );
    }

    #[tokio::test]
    async fn denies_an_unknown_sender() {
        let device = DeviceKey::from_seeds([0x72; 32], [0x73; 32]);
        let allowed = device.device_fp();
        let authorizer = FixedAuthorizer { allowed, device };

        let stranger = fp(0x99);
        assert!(stranger != allowed, "test fixture sanity: must differ");
        match authorizer.authorize(&stranger).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!("expected Deny for an unregistered device_fp"),
        }
    }
}
