//! A [`CapIssuer`] wrapper that can be switched off while the daemon keeps serving.
//!
//! DESIGN.md A10.45's failure rule is deliberately not "shut down": on a failed mid-process
//! certificate renewal the host **keeps existing sessions alive, refuses to issue new
//! capabilities, logs the reason, and retries**, and stops serving only when the certificate
//! actually expires. The refusal half needs to reach the `CapIssuer` the already-running
//! [`crate::HostDaemon`] was built with, so it cannot be decided once when the daemon is
//! constructed. [`GateableCapIssuer`] holds a shared [`AtomicBool`] gate: the binary's renewal
//! arm flips it off on a failed renewal and back on after a successful one, while the running
//! daemon's issuer observes the same flag.
//!
//! Returning `None` while disabled is the trait's own fail-closed shape
//! (`CapIssuer::issue_member_cap`'s doc comment): the authorizer treats that exactly like "no
//! issuer installed" — the connect still proceeds, just without a fresh member capability. A
//! device keeps whatever capability it already holds, which is why existing sessions survive.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use spindle_core::Fingerprint;
use spindle_host_core::{CapIssuer, RootKeyCapIssuer};
use spindle_proto::artifacts::Capability;

/// `RootKeyCapIssuer` behind a shared on/off gate.
///
/// The gate is `Acquire`/`Release`: a renewal failure sets it before the next connect decision
/// reads it, and a successful renewal sets it back after the new credentials are in hand.
pub struct GateableCapIssuer {
    inner: RootKeyCapIssuer,
    enabled: Arc<AtomicBool>,
}

impl GateableCapIssuer {
    /// Wraps `inner` and observes `enabled`. The caller keeps a clone of the same `Arc` to flip
    /// the gate from outside the daemon.
    pub fn new(inner: RootKeyCapIssuer, enabled: Arc<AtomicBool>) -> Self {
        Self { inner, enabled }
    }
}

impl CapIssuer for GateableCapIssuer {
    fn issue_member_cap(&self, subject: Fingerprint, cap_epoch: u64) -> Option<Capability> {
        if !self.enabled.load(Ordering::Acquire) {
            return None;
        }
        self.inner.issue_member_cap(subject, cap_epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{mint_host_identity, ROOT_SEED_LEN};

    const NOW: u64 = 1_700_000_000;

    fn issuer() -> RootKeyCapIssuer {
        let identity = mint_host_identity([0x5a; ROOT_SEED_LEN], NOW);
        RootKeyCapIssuer::new(
            identity.root.public_key(),
            identity.op_cert.clone(),
            identity.op_signing.clone(),
        )
        .with_now_fn(|| NOW)
    }

    /// Disabling the gate must not take the daemon down: it returns `None`, the authorizer's
    /// "no capability this time" answer, and delegates again once re-enabled.
    #[test]
    fn disabled_refuses_new_capabilities_and_enabled_delegates() {
        let gate = Arc::new(AtomicBool::new(true));
        let wrapped = GateableCapIssuer::new(issuer(), Arc::clone(&gate));
        let subject = Fingerprint::of_parts(&[b"member root"]);

        assert!(
            wrapped.issue_member_cap(subject, 7).is_some(),
            "an enabled gate must delegate to the wrapped issuer"
        );

        gate.store(false, Ordering::Release);
        assert!(
            wrapped.issue_member_cap(subject, 7).is_none(),
            "a disabled gate must refuse to mint, not fail the connect"
        );

        gate.store(true, Ordering::Release);
        assert!(
            wrapped.issue_member_cap(subject, 7).is_some(),
            "re-enabling after a successful renewal must restore issuance"
        );
    }
}
