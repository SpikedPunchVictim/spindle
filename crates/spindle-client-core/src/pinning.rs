//! Host pinning and the key-change wall (DESIGN.md §A4, A10.3, td-4559af).
//!
//! An invite is trusted **on first use, as one blob**; that is where the host identity is pinned.
//! Afterwards the client compares every observation against the pin:
//!
//! - the same root-derived `host_fp` is [`HostObservation::Pinned`], including across operating-key
//!   and envelope-key rotation — A10.43/A10.44 keep `host_fp = hash(host_root_pk)` stable, so a
//!   rotation must not re-wall a member;
//! - a different root presented for an already-pinned identity is a **key-change wall**: no API
//!   here auto-accepts it or overwrites the pin, and the caller must make the user decide. It is
//!   observable only through [`Pinning::verify_pinned`], which takes the expected fingerprint
//!   from the caller's own store; [`Pinning::observe`] keys on the root's *derived* `host_fp`, so
//!   a substituted root looks like a never-seen host there. Every connect path must call
//!   `verify_pinned` against the fp it already holds; `observe` is first-use only.
//! - an unknown `host_fp` is simply not pinned yet; it is not silently trusted.
//!
//! Storage is a narrow trait so the Tauri/keychain implementation lands later; the in-memory
//! implementation here backs it and the tests. A corrupt or unreadable record is a typed error,
//! never a default-accept.

use std::collections::HashMap;

use spindle_core::artifacts::{checked_verifying_key, verify_capability, ArtifactError};
use spindle_core::identity::root_fp_of;
use spindle_core::Fingerprint;
use spindle_proto::artifacts::{CapKind, Capability};
use spindle_proto::invite::InvitePayload;

/// One pinned host identity, as first learned from a verified invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPin {
    pub host_fp: Fingerprint,
    /// The host identity root public key the fingerprint was derived from.
    pub host_root_pk: Vec<u8>,
    pub pinned_at: u64,
    /// Digest of the invite container that established the pin, for audit/display.
    pub invite_digest: Fingerprint,
}

/// What the client knows about an observed host identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostObservation {
    Pinned(HostPin),
    Unknown,
}

/// Storage failures. Deliberately coarse: a backend error and a corrupt record are the only two
/// cases a caller can act on, and neither may be treated as "no pin".
#[derive(Debug, thiserror::Error)]
pub enum PinStoreError {
    #[error("the pinning store failed")]
    Backend,
    #[error("the stored host pin is corrupt")]
    Corrupt,
}

/// The storage seam. Implementations must return [`PinStoreError::Corrupt`] rather than dropping
/// or repairing a record they cannot validate.
pub trait PinStore {
    fn get(&self, host_fp: &Fingerprint) -> Result<Option<HostPin>, PinStoreError>;
    /// Inserts a pin. Implementations must refuse to replace an existing pin for the same
    /// `host_fp` with different key material ([`PinStoreError::Corrupt`] or `Backend`).
    fn put(&mut self, pin: HostPin) -> Result<(), PinStoreError>;
}

/// In-memory pinning store. Process-lifetime only; the app supplies a durable implementation.
#[derive(Debug, Default)]
pub struct MemoryPinStore {
    pins: HashMap<[u8; 32], HostPin>,
}

impl MemoryPinStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PinStore for MemoryPinStore {
    fn get(&self, host_fp: &Fingerprint) -> Result<Option<HostPin>, PinStoreError> {
        Ok(self.pins.get(host_fp.as_bytes()).cloned())
    }

    fn put(&mut self, pin: HostPin) -> Result<(), PinStoreError> {
        match self.pins.get(pin.host_fp.as_bytes()) {
            Some(existing) if existing.host_root_pk != pin.host_root_pk => {
                Err(PinStoreError::Corrupt)
            }
            _ => {
                self.pins.insert(*pin.host_fp.as_bytes(), pin);
                Ok(())
            }
        }
    }
}

/// Pinning failures. `Display` omits fingerprints and key bytes: callers that log a refusal must
/// not turn it into an identifier disclosure.
#[derive(Debug, thiserror::Error)]
pub enum PinningError {
    #[error("invite capability failed verification")]
    Verify(#[source] ArtifactError),
    #[error("capability is not an invite")]
    NotAnInvite,
    #[error("host root public key is not a canonical Ed25519 encoding")]
    BadHostKey,
    #[error("host fingerprint does not match its root public key")]
    HostFingerprintMismatch,
    #[error("this host is not pinned; no trust decision has been made")]
    NotPinned,
    #[error("host key changed for an already-pinned identity; user confirmation is required")]
    KeyChangeWall,
    #[error("pinning store failure")]
    Store(#[from] PinStoreError),
}

/// The pinning decision layer over a [`PinStore`].
pub struct Pinning<S: PinStore> {
    store: S,
}

impl<S: PinStore> Pinning<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Observes a host identity root and returns its pin if this exact root was previously
    /// pinned, else `Unknown`. **First-use only:** because the lookup key is derived from the
    /// presented root, a substituted root is indistinguishable here from a new host. A connect
    /// path that already knows which host it intends to reach must use [`Self::verify_pinned`]
    /// with that expected fingerprint, which is what surfaces a key change as a wall.
    ///
    /// A stored record that does not rehash to its own key is treated as corruption, never as a
    /// missing pin.
    pub fn observe(&self, host_root_pk: &[u8; 32]) -> Result<HostObservation, PinningError> {
        let host_fp = fingerprint_of(host_root_pk)?;
        match self.store.get(&host_fp)? {
            None => Ok(HostObservation::Unknown),
            Some(pin) => {
                self.validate_pin(&pin, &host_fp)?;
                Ok(HostObservation::Pinned(pin))
            }
        }
    }

    /// Verifies a pinned host against an observation. A different root for the expected identity
    /// is the key-change wall; there is deliberately no "accept and re-pin" method.
    pub fn verify_pinned(
        &self,
        expected_host_fp: &Fingerprint,
        presented_root_pk: &[u8; 32],
    ) -> Result<HostPin, PinningError> {
        let presented_fp = fingerprint_of(presented_root_pk)?;
        if presented_fp != *expected_host_fp {
            return Err(PinningError::KeyChangeWall);
        }
        let pin = self
            .store
            .get(expected_host_fp)?
            .ok_or(PinningError::NotPinned)?;
        self.validate_pin(&pin, expected_host_fp)?;
        Ok(pin)
    }

    /// Pins the host carried by a verified invite container. The capability's own chain and
    /// expiry are checked first, then `host_fp` is required to be the hash of the embedded
    /// `host_root_pk`. Re-pinning the same identity with the same root is idempotent and returns
    /// the original pin; different key material for the same `host_fp` is refused.
    pub fn pin_from_invite(
        &mut self,
        invite: &InvitePayload,
        now: u64,
    ) -> Result<HostPin, PinningError> {
        self.pin_from_capability(&invite.cap, invite.to_canonical_bytes(), now)
    }

    fn pin_from_capability(
        &mut self,
        cap: &Capability,
        invite_bytes: Vec<u8>,
        now: u64,
    ) -> Result<HostPin, PinningError> {
        verify_capability(cap, now).map_err(PinningError::Verify)?;
        if cap.kind != CapKind::Invite {
            return Err(PinningError::NotAnInvite);
        }
        let root: [u8; 32] = cap
            .host_root_pk
            .as_slice()
            .try_into()
            .map_err(|_| PinningError::BadHostKey)?;
        let host_fp = fingerprint_of(&root)?;
        if host_fp.as_bytes() != cap.host_fp.as_slice() {
            return Err(PinningError::HostFingerprintMismatch);
        }

        if let Some(existing) = self.store.get(&host_fp)? {
            self.validate_pin(&existing, &host_fp)?;
            if existing.host_root_pk.as_slice() != root.as_slice() {
                return Err(PinningError::KeyChangeWall);
            }
            return Ok(existing);
        }

        let pin = HostPin {
            host_fp,
            host_root_pk: root.to_vec(),
            pinned_at: now,
            invite_digest: Fingerprint::of_parts(&[&invite_bytes]),
        };
        self.store.put(pin.clone())?;
        Ok(pin)
    }

    fn validate_pin(&self, pin: &HostPin, expected_fp: &Fingerprint) -> Result<(), PinningError> {
        let root: [u8; 32] = pin
            .host_root_pk
            .as_slice()
            .try_into()
            .map_err(|_| PinningError::Store(PinStoreError::Corrupt))?;
        let actual =
            fingerprint_of(&root).map_err(|_| PinningError::Store(PinStoreError::Corrupt))?;
        if actual != *expected_fp || actual != pin.host_fp {
            return Err(PinningError::Store(PinStoreError::Corrupt));
        }
        Ok(())
    }
}

fn fingerprint_of(root_pk: &[u8; 32]) -> Result<Fingerprint, PinningError> {
    let key = checked_verifying_key(root_pk).ok_or(PinningError::BadHostKey)?;
    Ok(root_fp_of(&key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::artifacts::issue_host_op_key_cert;
    use spindle_core::identity::RootKey;
    use spindle_core::SigningKey;
    use spindle_host_core::invite::InviteIssuer;
    use spindle_proto::invite::TlsPin;

    const NOW: u64 = 1_755_907_200;

    /// The host whose key is pinned, plus a valid invite for it.
    struct Fixture {
        host_root: RootKey,
        invite: InvitePayload,
    }

    fn fixture() -> Fixture {
        let host_root = RootKey::from_seed([0x90; 32]);
        let op_signing = SigningKey::from_bytes(&[0x91; 32]);
        let op_cert = issue_host_op_key_cert(
            &host_root,
            &op_signing.verifying_key(),
            NOW,
            NOW + 90 * 86_400,
        );
        let issuer =
            InviteIssuer::new(host_root.public_key(), op_cert, op_signing).with_now_fn(|| NOW);
        let invitee = RootKey::from_seed([0xA0; 32]);
        let invite = issuer
            .issue_invite(
                invitee.root_fp(),
                0,
                vec!["wss://registry.example:443".to_string()],
                TlsPin::WebPki,
            )
            .expect("issue invite");
        Fixture { host_root, invite }
    }

    fn pin(f: &Fixture) -> (Pinning<MemoryPinStore>, HostPin) {
        let mut pinning = Pinning::new(MemoryPinStore::new());
        let pinned = pinning
            .pin_from_invite(&f.invite, NOW)
            .expect("first-use pin");
        (pinning, pinned)
    }

    #[test]
    fn first_use_pins_the_invite_carried_host_key() {
        let f = fixture();
        let (pinning, pinned) = pin(&f);
        assert_eq!(pinned.host_fp, f.host_root.root_fp());
        assert_eq!(pinned.host_root_pk, f.host_root.public_key().to_bytes());
        assert_eq!(pinned.pinned_at, NOW);

        let observed = pinning
            .observe(&f.host_root.public_key().to_bytes())
            .expect("observe");
        assert_eq!(observed, HostObservation::Pinned(pinned));
    }

    #[test]
    fn repinning_the_same_invite_is_idempotent() {
        let f = fixture();
        let (mut pinning, first) = pin(&f);
        let again = pinning
            .pin_from_invite(&f.invite, NOW + 60)
            .expect("re-pin");
        assert_eq!(again, first, "an existing pin must not be overwritten");
    }

    /// A10.43/A10.44: operating-key and envelope-key rotation keep `host_fp` root-derived, so the
    /// same root observed later is the same pin — no wall.
    #[test]
    fn a_rotated_operating_key_does_not_wall() {
        let f = fixture();
        let (pinning, pinned) = pin(&f);
        let rotated = pinning
            .verify_pinned(&pinned.host_fp, &f.host_root.public_key().to_bytes())
            .expect("rotation keeps the same root");
        assert_eq!(rotated, pinned);
    }

    #[test]
    fn a_different_root_for_a_pinned_identity_is_a_wall() {
        let f = fixture();
        let (pinning, pinned) = pin(&f);
        let replacement = RootKey::from_seed([0xE0; 32]);
        let error = pinning
            .verify_pinned(&pinned.host_fp, &replacement.public_key().to_bytes())
            .expect_err("replacement must wall");
        assert!(matches!(error, PinningError::KeyChangeWall));

        // The original pin is untouched: there is no auto-re-pin path.
        let observed = pinning
            .observe(&f.host_root.public_key().to_bytes())
            .expect("observe");
        assert_eq!(observed, HostObservation::Pinned(pinned));
    }

    #[test]
    fn an_unknown_host_is_not_silently_trusted() {
        let f = fixture();
        let pinning = Pinning::new(MemoryPinStore::new());
        let stranger = RootKey::from_seed([0xB0; 32]);
        assert_eq!(
            pinning
                .observe(&stranger.public_key().to_bytes())
                .expect("observe"),
            HostObservation::Unknown
        );
        assert!(matches!(
            pinning
                .verify_pinned(&f.host_root.root_fp(), &f.host_root.public_key().to_bytes())
                .expect_err("not pinned"),
            PinningError::NotPinned
        ));
    }

    #[test]
    fn an_expired_invite_does_not_create_a_pin() {
        let f = fixture();
        let mut pinning = Pinning::new(MemoryPinStore::new());
        let error = pinning
            .pin_from_invite(&f.invite, f.invite.cap.exp + 1)
            .expect_err("expired invite");
        assert!(matches!(error, PinningError::Verify(_)));
        assert_eq!(
            pinning
                .observe(&f.host_root.public_key().to_bytes())
                .expect("observe"),
            HostObservation::Unknown
        );
    }

    #[test]
    fn a_non_canonical_root_key_is_refused() {
        let pinning = Pinning::new(MemoryPinStore::new());
        let error = pinning.observe(&[0xFF; 32]).expect_err("non-canonical key");
        assert!(matches!(error, PinningError::BadHostKey));
    }

    /// A store record that does not rehash to the key it is filed under is corruption, never a
    /// missing pin and never a valid pin.
    #[test]
    fn a_corrupt_pin_is_a_typed_error() {
        struct CorruptStore {
            host_fp: Fingerprint,
            pin: HostPin,
        }
        impl PinStore for CorruptStore {
            fn get(&self, host_fp: &Fingerprint) -> Result<Option<HostPin>, PinStoreError> {
                Ok((host_fp == &self.host_fp).then(|| self.pin.clone()))
            }
            fn put(&mut self, _pin: HostPin) -> Result<(), PinStoreError> {
                Ok(())
            }
        }

        let f = fixture();
        let good = RootKey::from_seed([0xC0; 32]);
        let host_fp = f.host_root.root_fp();
        let store = CorruptStore {
            host_fp,
            pin: HostPin {
                host_fp,
                host_root_pk: good.public_key().to_bytes().to_vec(),
                pinned_at: NOW,
                invite_digest: Fingerprint::of_parts(&[b"invite"]),
            },
        };
        let pinning = Pinning::new(store);
        let error = pinning
            .observe(&f.host_root.public_key().to_bytes())
            .expect_err("corrupt pin");
        assert!(matches!(error, PinningError::Store(PinStoreError::Corrupt)));
    }

    #[test]
    fn the_store_refuses_to_replace_a_pin_with_different_key_material() {
        let mut store = MemoryPinStore::new();
        let host_fp = Fingerprint::of_parts(&[b"host"]);
        store
            .put(HostPin {
                host_fp,
                host_root_pk: vec![0x01; 32],
                pinned_at: NOW,
                invite_digest: Fingerprint::of_parts(&[b"a"]),
            })
            .expect("first put");
        let error = store
            .put(HostPin {
                host_fp,
                host_root_pk: vec![0x02; 32],
                pinned_at: NOW,
                invite_digest: Fingerprint::of_parts(&[b"b"]),
            })
            .expect_err("must not overwrite");
        assert!(matches!(error, PinStoreError::Corrupt));
    }
}
