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
    /// module's doc comment, and `spikes/s2-signaling`'s RESULTS.md finding #2 ("no wire artifact
    /// carries a device's raw public keys": `spindle_proto::artifacts::DeviceCertificate` carries
    /// only a `device_fp`, a hash, never the keys behind it).
    Allow {
        sign_pk: spindle_core::VerifyingKey,
        agree_pk: X25519PublicKey,
    },
    /// `from_fp` is unknown, not (yet) a member, or revoked. The caller must drop the offer with
    /// no distinguishable reply (DESIGN.md §A5's uniform-silent-drop philosophy) — see
    /// [`super::error::SignalingError::Denied`].
    Deny,
}

/// Host-injected membership/authorization decision (DESIGN.md §A5). A real host implements this
/// against its own member registry / revocation store; nothing in `spindle-net` may resolve it
/// directly (see the module doc comment).
pub trait ConnectAuthorizer: Send + Sync {
    /// Resolves a connect decision for `from_fp` (the offer's claimed sender, already extracted
    /// from the envelope but not yet cryptographically verified — the caller uses the returned
    /// `sign_pk`/`agree_pk` to perform that verification next, so an authorizer must not treat
    /// being asked as proof of anything about the envelope itself).
    fn authorize(
        &self,
        from_fp: &Fingerprint,
    ) -> impl std::future::Future<Output = ConnectDecision> + Send;
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
