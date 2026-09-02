//! [`HostConnectAuthorizer`] — the production
//! `spindle_net::signaling::authorize::ConnectAuthorizer` implementation, wired to this host's own
//! member/device registry. `spindle-net`'s module doc comment for `signaling::authorize` is
//! explicit about why this lives here rather than there: per A9c boundary rule 3 (`proto ← core ←
//! {net, vfs} ← {host-core, client-core}`), `spindle-net` must never depend on `spindle-host-core`,
//! so the trait is injected and the real member-registry lookup belongs on this side of the
//! boundary.
//!
//! This is the connect-time twin of [`crate::server::VfsRpcServer::handle`]'s per-request
//! `denied:device_revoked` gate (see the comment block above that gate, ~line 250 of
//! `server.rs`): both enforce DESIGN.md §A4's rule that member liveness and device revocation are
//! independently, freshly checked — one of them once per connect offer, the other once per VFS RPC
//! request.
//!
//! # The `DeviceLookup` seam
//!
//! `ConnectAuthorizer` requires `Send + Sync`, but `spindle_vfs::store::Store` wraps a
//! `rusqlite::Connection`, which is `Send` but **not** `Sync`. `crate::serve`'s module doc comment
//! is explicit that this crate must not introduce an `Arc<Mutex<_>>` or an `unsafe impl Sync` — a
//! rule that exists for `VfsRpcServer`, whose `RefCell` caches make it deliberately
//! single-threaded per session. Rather than override that rule crate-wide, [`DeviceLookup`]
//! confines the `!Sync -> Sync` bridge to one small adapter ([`SqliteDeviceLookup`]) whose entire
//! purpose is that bridge, so [`HostConnectAuthorizer`] itself never names a lock, and a host
//! backed by a connection pool or an already-`Sync` store can implement `DeviceLookup` directly
//! and skip the lock entirely.

use spindle_core::identity::device_fp_of;
use spindle_core::{Fingerprint, VerifyingKey, X25519PublicKey, ALG_ID_V1};
use spindle_net::signaling::authorize::{ConnectAuthorizer, ConnectDecision};
use spindle_vfs::model::{Member, MemberStatus};
use spindle_vfs::store::{Store, StoreError};
use std::sync::Mutex;
use thiserror::Error;

/// A device registry lookup, abstracted away from `spindle_vfs::store::Store`'s concrete
/// `!Sync`-ness — see the module doc comment for why this trait exists rather than
/// [`HostConnectAuthorizer`] naming `Store` (or a lock around one) directly.
pub trait DeviceLookup: Send + Sync {
    /// Resolves the member that owns `device_fp`, if any — the same lookup
    /// `spindle_vfs::store::Store::member_for_device_fp` performs.
    fn member_for_device_fp(&self, device_fp: Fingerprint) -> Result<Option<Member>, LookupError>;
}

/// A [`DeviceLookup`] failure. Every caller of [`DeviceLookup::member_for_device_fp`] in this
/// module treats this the same way it treats `Ok(None)`: fail closed, [`ConnectDecision::Deny`].
#[derive(Debug, Error)]
pub enum LookupError {
    /// The underlying `spindle_vfs::store::Store` read failed.
    #[error("device lookup store error: {0}")]
    Store(#[from] StoreError),
    /// [`SqliteDeviceLookup`]'s `Mutex<Store>` was poisoned (a prior holder panicked while the
    /// lock was held). A poisoned lock must never become an `Allow` — see that type's doc comment.
    #[error("device lookup mutex poisoned")]
    LockPoisoned,
}

/// A [`DeviceLookup`] adapter owning a [`Store`] behind a [`std::sync::Mutex`] — the one place in
/// this module the `!Sync -> Sync` bridge described in the module doc comment actually happens.
///
/// Takes an **owned** `Store` rather than borrowing the one `VfsRpcServer` uses: a host should
/// give this its own `Store` handle (SQLite supports multiple connections to one database file),
/// keeping the connect path off the RPC path's connection entirely.
///
/// The lock is honestly documented, not hand-waved: the guard is held across a synchronous SQLite
/// read inside an `async fn` (`HostConnectAuthorizer::authorize` below), which would not be
/// acceptable on the VFS RPC hot path but is acceptable here — this lookup runs once per connect
/// *offer* (not once per request), and is a single primary-key-indexed read on `devices` plus
/// `get_member`. If the mutex is poisoned, [`Self::member_for_device_fp`] returns
/// [`LookupError::LockPoisoned`] rather than panicking — a poisoned lock must never silently
/// become an `Allow`.
pub struct SqliteDeviceLookup {
    store: Mutex<Store>,
}

impl SqliteDeviceLookup {
    pub fn new(store: Store) -> Self {
        SqliteDeviceLookup {
            store: Mutex::new(store),
        }
    }
}

impl DeviceLookup for SqliteDeviceLookup {
    fn member_for_device_fp(&self, device_fp: Fingerprint) -> Result<Option<Member>, LookupError> {
        let store = self.store.lock().map_err(|_| LookupError::LockPoisoned)?;
        Ok(store.member_for_device_fp(device_fp)?)
    }
}

/// Resolves `device_fp` to its owning member, but only if every one of DESIGN.md §A4's liveness
/// checks holds: the device is enrolled, its member is `Active`, and neither the member nor this
/// specific device has been revoked. Returns `None` on any failure — including a [`LookupError`]
/// — never propagating an error, because every caller of this function treats "I could not prove
/// this device is live" as "treat it as not live" (fail closed).
///
/// This is [`HostConnectAuthorizer::authorize`]'s checks 1–5, extracted rather than duplicated:
/// [`crate::session::VfsSessionHandler`]'s session-time gate (building a
/// `crate::server::SessionContext` — see that module's doc comment) needs exactly this same "is
/// this device's member still live, right now" answer, at a different moment in a session's
/// lifecycle. Duplicating a fail-closed security rule across two files is worse than sharing it: a
/// future change to §A4's liveness definition (a new revocation state, an added precondition)
/// would otherwise have to be found and re-applied in both places by hand.
///
/// 1. Lookup error (including a poisoned lock): fail closed, never propagate.
/// 2. No such device: fail closed.
/// 3. Member status is not `Active` (§A4b: unauthorized is indistinguishable from not-found): fail
///    closed.
/// 4. The device row for `device_fp` is not in `member.devices`. Should be impossible given
///    `member_for_device_fp` resolved through that device, but handled explicitly rather than
///    unwrapped — mirroring how `server.rs`'s gate handles its own `None` arm.
/// 5. This device is revoked — the independently-enforced half of §A4: a still-Active member can
///    have one revoked device among several (see `server.rs`'s `denied:device_revoked` gate, the
///    per-request twin of this check).
///
/// Only reaching past all five returns `Some(member)`.
pub(crate) fn active_member_for_device<L: DeviceLookup + ?Sized>(
    lookup: &L,
    device_fp: Fingerprint,
) -> Option<Member> {
    // 1 & 2.
    let member = match lookup.member_for_device_fp(device_fp) {
        Ok(Some(member)) => member,
        Ok(None) => return None,
        Err(_) => return None,
    };

    // 3.
    if member.status != MemberStatus::Active {
        return None;
    }

    // 4.
    let device = member.devices.iter().find(|d| d.device_fp == device_fp)?;

    // 5.
    if device.revoked {
        return None;
    }

    Some(member)
}

/// The production `ConnectAuthorizer`: DESIGN.md §A5's "is this connect offer's sender an active,
/// non-revoked member device permitted to connect to this host?" decision, resolved against a
/// real member registry via [`DeviceLookup`].
///
/// Deliberately does **not**:
/// - verify the envelope signature — the caller does that next, using the `sign_pk`/`agree_pk`
///   this returns (see `ConnectAuthorizer::authorize`'s own doc comment: "an authorizer must not
///   treat being asked as proof of anything about the envelope itself");
/// - consult `cap_epoch` — a connect decision is membership, not capability freshness.
pub struct HostConnectAuthorizer<L: DeviceLookup> {
    lookup: L,
}

impl<L: DeviceLookup> HostConnectAuthorizer<L> {
    pub fn new(lookup: L) -> Self {
        HostConnectAuthorizer { lookup }
    }
}

impl<L: DeviceLookup> ConnectAuthorizer for HostConnectAuthorizer<L> {
    /// Every failure mode below returns `Deny`; only reaching the final line returns `Allow`. See
    /// the module doc comment and this crate's task brief for why each check exists; in
    /// particular, checks 3 and 5 (folded into [`active_member_for_device`] below — see its own
    /// doc comment for the full per-check narrative, including why checks 3 and 5 are
    /// independently enforced: a still-`Active` member can have one revoked device among several,
    /// the same split `server.rs`'s `denied:device_revoked` gate makes per request) are shared
    /// with [`crate::session::VfsSessionHandler`]'s session-time gate rather than duplicated here.
    async fn authorize(&self, from_fp: &Fingerprint) -> ConnectDecision {
        // 1-5: is `from_fp` an active, non-revoked member's non-revoked device? See
        // `active_member_for_device`'s doc comment for the full five-check narrative this folds
        // together.
        let Some(member) = active_member_for_device(&self.lookup, *from_fp) else {
            return ConnectDecision::Deny;
        };
        // Re-finding the device row is redundant with what `active_member_for_device` already
        // confirmed, but this module's house style never unwraps an invariant instead of failing
        // closed (see check 4's own comment for the same call) — an `expect` here would be the
        // one panic-shaped seam in an otherwise all-`Deny` function.
        let Some(device) = member.devices.iter().find(|d| d.device_fp == *from_fp) else {
            return ConnectDecision::Deny;
        };

        // 6. Either key is missing on file. Fail closed; a missing key is never "skip the check".
        let (Some(sign_pk_bytes), Some(agree_pk_bytes)) = (&device.sign_pk, &device.agree_pk)
        else {
            return ConnectDecision::Deny;
        };

        // 7. Either key fails to parse (wrong length, or — for the Ed25519 sign key — not a valid
        // curve point).
        let Ok(sign_pk_arr): Result<[u8; 32], _> = sign_pk_bytes.as_slice().try_into() else {
            return ConnectDecision::Deny;
        };
        let Ok(sign_pk) = VerifyingKey::from_bytes(&sign_pk_arr) else {
            return ConnectDecision::Deny;
        };
        let Ok(agree_pk_arr): Result<[u8; 32], _> = agree_pk_bytes.as_slice().try_into() else {
            return ConnectDecision::Deny;
        };
        let agree_pk = X25519PublicKey::from(agree_pk_arr);

        // 8. The binding does not hold (DESIGN.md §A7b clarification-6 — the same check
        // `verify_device_certificate` performs). This is what makes the stored key pair
        // *self-verifying*: `device_fp` is the hash of exactly `(DEVICE_FP_DOMAIN, alg_id,
        // sign_pk, agree_pk)`, so a row whose keys were corrupted, transposed, or swapped for
        // another device's cannot silently authorize — it simply fails to rehash to `from_fp`.
        if device_fp_of(ALG_ID_V1, &sign_pk, &agree_pk) != *from_fp {
            return ConnectDecision::Deny;
        }

        ConnectDecision::Allow { sign_pk, agree_pk }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::identity::DeviceKey;
    use spindle_vfs::model::DevicePublicKeys;

    fn store_with_active_member(display_name: &str) -> (Store, spindle_vfs::model::MemberId) {
        let store = Store::open_in_memory().expect("open in-memory store");
        let member_id = store
            .add_member(
                Fingerprint::of_parts(&[display_name.as_bytes()]),
                display_name,
                0,
            )
            .expect("add_member");
        store.activate_member(member_id).expect("activate_member");
        (store, member_id)
    }

    fn enroll_device(
        store: &Store,
        member_id: spindle_vfs::model::MemberId,
        label: &str,
        device: &DeviceKey,
    ) -> Fingerprint {
        let device_fp = device.device_fp();
        let keys = DevicePublicKeys {
            sign_pk: device.sign_public_key().as_bytes().to_vec(),
            agree_pk: device.agree_public_key().as_bytes().to_vec(),
        };
        store
            .add_device(member_id, device_fp, label, 0, Some(&keys))
            .expect("add_device");
        device_fp
    }

    #[tokio::test]
    async fn allows_an_active_members_enrolled_device_and_returns_its_pinned_sign_pk_and_agree_pk()
    {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x01; 32], [0x02; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store));

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { sign_pk, agree_pk } => {
                assert_eq!(sign_pk, device.sign_public_key());
                assert_eq!(agree_pk, device.agree_public_key());
            }
            ConnectDecision::Deny => panic!("expected Allow for an active member's own device"),
        }
    }

    #[tokio::test]
    async fn denies_a_device_fp_that_was_never_enrolled() {
        let (store, _member_id) = store_with_active_member("alex");
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store));

        let stranger = DeviceKey::from_seeds([0x03; 32], [0x04; 32]).device_fp();
        match authorizer.authorize(&stranger).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!("expected Deny for an unenrolled device_fp"),
        }
    }

    #[tokio::test]
    async fn denies_when_the_owning_member_is_invited_not_yet_active() {
        let store = Store::open_in_memory().expect("open in-memory store");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"pending"]), "pending", 0)
            .expect("add_member");
        // deliberately not activated: stays MemberStatus::Invited
        let device = DeviceKey::from_seeds([0x05; 32], [0x06; 32]);
        let device_fp = enroll_device(&store, member_id, "phone", &device);
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store));

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => {
                panic!("expected Deny for a still-Invited member's device")
            }
        }
    }

    #[tokio::test]
    async fn denies_when_the_owning_member_is_revoked() {
        let (store, member_id) = store_with_active_member("bad-actor");
        let device = DeviceKey::from_seeds([0x07; 32], [0x08; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        store.revoke_member(member_id).expect("revoke_member");
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store));

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!("expected Deny for a Revoked member's device"),
        }
    }

    #[tokio::test]
    async fn denies_a_revoked_device_whose_member_is_still_active() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x09; 32], [0x0a; 32]);
        let device_fp = enroll_device(&store, member_id, "old-laptop", &device);
        store.revoke_device(device_fp).expect("revoke_device");
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store));

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!(
                "expected Deny: this device is revoked even though its member is still Active"
            ),
        }
    }

    #[tokio::test]
    async fn denies_a_device_enrolled_with_no_keys_on_file() {
        let (store, member_id) = store_with_active_member("alex");
        let device_fp = Fingerprint::of_parts(&[b"keyless-device"]);
        store
            .add_device(member_id, device_fp, "keyless", 0, None)
            .expect("add_device with no keys");
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store));

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => {
                panic!("expected Deny for a device with no keys on file")
            }
        }
    }

    #[tokio::test]
    async fn denies_when_the_stored_keys_do_not_rehash_to_the_devices_own_device_fp() {
        let (store, member_id) = store_with_active_member("alex");
        // Device A's device_fp, but device B's key pair — constructed directly (add_device does
        // not validate the binding), simulating corrupted/transposed/swapped stored keys.
        let device_a = DeviceKey::from_seeds([0x0b; 32], [0x0c; 32]);
        let device_b = DeviceKey::from_seeds([0x0d; 32], [0x0e; 32]);
        let mismatched_keys = DevicePublicKeys {
            sign_pk: device_b.sign_public_key().as_bytes().to_vec(),
            agree_pk: device_b.agree_public_key().as_bytes().to_vec(),
        };
        store
            .add_device(
                member_id,
                device_a.device_fp(),
                "corrupted",
                0,
                Some(&mismatched_keys),
            )
            .expect("add_device");
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store));

        match authorizer.authorize(&device_a.device_fp()).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => {
                panic!("expected Deny: stored keys do not rehash to this device's own device_fp")
            }
        }
    }

    #[tokio::test]
    async fn denies_when_a_lookup_returns_an_error() {
        struct AlwaysFails;
        impl DeviceLookup for AlwaysFails {
            fn member_for_device_fp(
                &self,
                _device_fp: Fingerprint,
            ) -> Result<Option<Member>, LookupError> {
                Err(LookupError::LockPoisoned)
            }
        }

        let authorizer = HostConnectAuthorizer::new(AlwaysFails);
        let some_fp = DeviceKey::from_seeds([0x0f; 32], [0x10; 32]).device_fp();
        match authorizer.authorize(&some_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!("expected Deny when the lookup itself fails"),
        }
    }
}
