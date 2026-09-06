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

use spindle_core::artifacts::issue_capability;
use spindle_core::identity::device_fp_of;
use spindle_core::{Fingerprint, SigningKey, VerifyingKey, X25519PublicKey, ALG_ID_V1};
use spindle_net::signaling::authorize::{ConnectAuthorizer, ConnectDecision};
use spindle_proto::artifacts::{CapKind, Capability, HostOpKeyCert};
use spindle_vfs::model::{Member, MemberStatus};
use spindle_vfs::store::{Store, StoreError};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// A device registry lookup, abstracted away from `spindle_vfs::store::Store`'s concrete
/// `!Sync`-ness — see the module doc comment for why this trait exists rather than
/// [`HostConnectAuthorizer`] naming `Store` (or a lock around one) directly.
pub trait DeviceLookup: Send + Sync {
    /// Resolves the member that owns `device_fp`, if any — the same lookup
    /// `spindle_vfs::store::Store::member_for_device_fp` performs.
    fn member_for_device_fp(&self, device_fp: Fingerprint) -> Result<Option<Member>, LookupError>;

    /// The host's current `cap_epoch` (`spindle_vfs::store::Store::cap_epoch`) — the value a
    /// freshly-minted member capability must be stamped with.
    ///
    /// Deliberately read through this same [`DeviceLookup`] rather than a second `Store` handle:
    /// `Store::bump_cap_epoch` (the *only* path that increments the epoch — see its own doc
    /// comment) and the epoch a minted cap carries must never be able to disagree. Routing both
    /// through one source of truth makes that a structural guarantee rather than a "the two
    /// handles happened to stay in sync" hope; a second, independently-opened `Store` reading the
    /// same SQLite file would still be *correct* (SQLite serializes commits), but it would be a
    /// second thing that could theoretically read a stale epoch under some future refactor, for
    /// no benefit over reusing the lookup already in hand.
    fn cap_epoch(&self) -> Result<u64, LookupError>;
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

    fn cap_epoch(&self) -> Result<u64, LookupError> {
        let store = self.store.lock().map_err(|_| LookupError::LockPoisoned)?;
        Ok(store.cap_epoch()?)
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

/// Mints [`HostConnectAuthorizer`]'s optional member capability (DESIGN.md:286: member caps are
/// "refreshed opportunistically on every successful session"). Separated from
/// [`HostConnectAuthorizer`] itself for the same crate-layering reason [`DeviceLookup`] is
/// separated from `Store`: the concrete signing material (a host's root public key, its current
/// operating-key certificate, the operating signing key itself) is a deployment concern, not
/// something this module's connect-decision logic should hold or construct.
///
/// Returns `Option<Capability>`, not `Result<Capability, _>`, and that is deliberate: an issuer
/// that cannot sign right now (no key online, keystore locked, clock unavailable) yields `None`,
/// and [`HostConnectAuthorizer::authorize`] treats that exactly like "no issuer installed" —
/// `member_cap: None` in an otherwise-`Allow` decision. A cap-issuance failure must **never**
/// turn an otherwise-valid connect into a `Deny`: the device simply gets an answer with no fresh
/// cap and falls back to whatever cap it already holds. Denying here would be strictly worse than
/// the status quo, because it would take a working connect path and break it over a problem
/// (signing) that has nothing to do with whether this device is still a live member.
pub trait CapIssuer: Send + Sync {
    /// Issues a `member`-kind capability for `subject` (see [`RootKeyCapIssuer`]'s doc comment
    /// for why `subject` must be the member's `root_fp`, never a device fp), stamped with
    /// `cap_epoch` — the caller (`HostConnectAuthorizer::authorize`) is responsible for reading
    /// that epoch live via [`DeviceLookup::cap_epoch`] rather than caching it, so a cap minted
    /// moments after a revocation bump always carries the new epoch.
    fn issue_member_cap(&self, subject: Fingerprint, cap_epoch: u64) -> Option<Capability>;
}

/// A member capability's default lifetime: DESIGN.md:286 — "`exp` ... in weeks (default 6)".
/// `6 * 7 * 24 * 60 * 60 == 3_628_800` seconds.
pub const MEMBER_CAP_DEFAULT_TTL_SECS: u64 = 6 * 7 * 24 * 60 * 60;

/// The real wall-clock `now_fn` [`RootKeyCapIssuer::new`] defaults to: `SystemTime::now()`
/// truncated to whole seconds since the Unix epoch. Saturates to `0` rather than panicking if the
/// system clock reads before the epoch — a misconfigured clock should degrade a minted cap's
/// `exp` (making it trivially expired, which is the fail-closed direction), not crash the connect
/// path outright. Mirrors `spindle-hostd`'s own `wall_clock_now_secs`
/// (`crates/spindle-hostd/src/lib.rs:119`) exactly; duplicated rather than imported because
/// `spindle-hostd` depends on this crate, not the other way around.
fn wall_clock_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The default `nonce_fn` [`RootKeyCapIssuer::new`] installs. DESIGN.md:563's signed-artifact
/// replay table reads "invite: nonce burn (idempotent replay of result); **member: n/a**" — a
/// member cap's nonce carries no replay/burn semantics, unlike an invite cap's. Since nothing
/// downstream ever checks this value for unpredictability, pulling in a CSPRNG dependency to fill
/// it would be pure cost for no security benefit; instead this derives a nonce deterministically
/// from data already in hand — a domain-separating literal, the subject, and the issue
/// timestamp — via the same `Fingerprint::of_parts` construction every other fingerprint in this
/// workspace uses. Two caps for different subjects, or for the same subject in different seconds,
/// get different nonces; two caps for the same subject issued within the same wall-clock second
/// do not, which is fine precisely because this nonce is not load-bearing for `kind: member`.
///
/// **This is not a security-bearing random value.** An issuer for `CapKind::Invite` (DESIGN.md:563:
/// "invite: nonce burn") *does* need a real CSPRNG-sourced nonce and must not reuse this function —
/// its nonce is checked for burn/replay, and a predictable one would defeat that check entirely.
fn default_member_cap_nonce(subject: Fingerprint, now: u64) -> Vec<u8> {
    Fingerprint::of_parts(&[
        b"spindle-host-core:member-cap-nonce:v1",
        subject.as_bytes(),
        &now.to_le_bytes(),
    ])
    .to_vec()
}

type BoxedNowFn = Box<dyn Fn() -> u64 + Send + Sync + 'static>;
type BoxedNonceFn = Box<dyn Fn(Fingerprint, u64) -> Vec<u8> + Send + Sync + 'static>;

/// The production [`CapIssuer`]: mints `member`-kind capabilities chained to this host's root
/// identity, per DESIGN.md §A4 / decision A10.30 (see [`issue_capability`]'s own doc comment for
/// the root-vs-operating-key rule this leans on).
///
/// **`subject` is always the member's `root_fp`, never a device fp** — DESIGN.md:286: "`subject =
/// root_fp` so every root-certified device of the person may use it". Getting this backwards
/// would scope a member cap to one enrolled device instead of the whole person, silently breaking
/// every other device that person owns. Callers (`HostConnectAuthorizer::authorize`) are
/// responsible for passing `member.root_fp`, not `from_fp`/`device_fp`.
pub struct RootKeyCapIssuer {
    host_root_pk: VerifyingKey,
    op_cert: HostOpKeyCert,
    op_signing: SigningKey,
    now_fn: BoxedNowFn,
    nonce_fn: BoxedNonceFn,
    ttl_secs: u64,
}

impl RootKeyCapIssuer {
    /// Builds an issuer using the real wall clock ([`wall_clock_now_secs`]), the deterministic
    /// non-security-bearing nonce ([`default_member_cap_nonce`]), and
    /// [`MEMBER_CAP_DEFAULT_TTL_SECS`]. Chain [`Self::with_now_fn`], [`Self::with_nonce_fn`], and/or
    /// [`Self::with_ttl_secs`] onto the result to inject a deterministic clock/nonce or a
    /// non-default TTL (a test's fixed clock, for instance) — the same boxed-injectable-clock shape
    /// `spindle_hostd::HostDaemon::new`/`with_now_fn` uses (`crates/spindle-hostd/src/lib.rs:187,
    /// 198`), applied here rather than inventing a new pattern. Unlike `HostDaemon`, which exposes
    /// only one such knob, this issuer has three, and they are independent of one another; an
    /// earlier version mirrored `HostDaemon`'s single alternative-constructor shape per knob, which
    /// made the three mutually exclusive — a caller needing, say, an injected clock and a
    /// non-default TTL together had no way to express it. Chainable consuming-self setters let any
    /// subset be combined.
    pub fn new(host_root_pk: VerifyingKey, op_cert: HostOpKeyCert, op_signing: SigningKey) -> Self {
        RootKeyCapIssuer {
            host_root_pk,
            op_cert,
            op_signing,
            now_fn: Box::new(wall_clock_now_secs),
            nonce_fn: Box::new(default_member_cap_nonce),
            ttl_secs: MEMBER_CAP_DEFAULT_TTL_SECS,
        }
    }

    /// As [`Self::new`] built it, but with an explicit `now_fn` — a deterministic clock for tests.
    /// Chainable with [`Self::with_nonce_fn`] and [`Self::with_ttl_secs`].
    pub fn with_now_fn(self, now_fn: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        RootKeyCapIssuer {
            now_fn: Box::new(now_fn),
            ..self
        }
    }

    /// As [`Self::new`] built it, but with an explicit `nonce_fn` — see
    /// [`default_member_cap_nonce`]'s doc comment before reaching for this: a replacement nonce
    /// source for `kind: member` still does not need to be a CSPRNG (DESIGN.md:563: "member: n/a"),
    /// but a test asserting nonces differ under a fixed clock is one legitimate reason to inject
    /// one. Chainable with [`Self::with_now_fn`] and [`Self::with_ttl_secs`].
    pub fn with_nonce_fn(
        self,
        nonce_fn: impl Fn(Fingerprint, u64) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        RootKeyCapIssuer {
            nonce_fn: Box::new(nonce_fn),
            ..self
        }
    }

    /// As [`Self::new`] built it, but with an explicit `ttl_secs` instead of
    /// [`MEMBER_CAP_DEFAULT_TTL_SECS`]. Chainable with [`Self::with_now_fn`] and
    /// [`Self::with_nonce_fn`].
    pub fn with_ttl_secs(self, ttl_secs: u64) -> Self {
        RootKeyCapIssuer { ttl_secs, ..self }
    }
}

impl CapIssuer for RootKeyCapIssuer {
    fn issue_member_cap(&self, subject: Fingerprint, cap_epoch: u64) -> Option<Capability> {
        let now = (self.now_fn)();
        let nonce = (self.nonce_fn)(subject, now);
        Some(issue_capability(
            &self.host_root_pk,
            &self.op_cert,
            &self.op_signing,
            CapKind::Member,
            subject,
            cap_epoch,
            now + self.ttl_secs,
            nonce,
        ))
    }
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
    /// The optional cap-issuing seam (td-c74122 slice C). Boxed as a trait object rather than a
    /// second generic parameter on `HostConnectAuthorizer<L, I>` deliberately:
    /// `crates/spindle-hostd/src/lib.rs:150` names the concrete type
    /// `HostConnectAuthorizer<SqliteDeviceLookup>` in a type alias, and every caller downstream of
    /// it matches that one-generic-parameter shape. Adding a second generic parameter would be a
    /// breaking API change this slice has no reason to force; a `Box<dyn CapIssuer>` keeps the
    /// struct's public shape exactly as every existing caller already names it.
    issuer: Option<Box<dyn CapIssuer>>,
}

impl<L: DeviceLookup> HostConnectAuthorizer<L> {
    /// Installs no cap-issuing seam: `authorize` always answers `member_cap: None`. Correct for a
    /// host with no cap-signing key online yet — see [`CapIssuer`]'s doc comment — not merely a
    /// placeholder for "unimplemented".
    pub fn new(lookup: L) -> Self {
        HostConnectAuthorizer {
            lookup,
            issuer: None,
        }
    }

    /// As [`Self::new`], but with a real [`CapIssuer`] installed so `authorize` mints a fresh
    /// member capability for every `Allow`.
    pub fn with_issuer(lookup: L, issuer: Box<dyn CapIssuer>) -> Self {
        HostConnectAuthorizer {
            lookup,
            issuer: Some(issuer),
        }
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

        // 9. Mint the opportunistic member capability (DESIGN.md:286), if we can. This never
        // downgrades an `Allow` into a `Deny` — see `CapIssuer`'s doc comment for why an
        // issuance failure must be strictly no worse than the status quo (no fresh cap, not a
        // broken connect).
        //
        // `subject` is `member.root_fp`, not `from_fp`/`device_fp` — DESIGN.md:286: "`subject =
        // root_fp` so every root-certified device of the person may use it". This is the central
        // hazard of this slice: scoping the cap to the device fp instead would silently restrict
        // it to the one device that happened to connect, breaking every other device the same
        // person owns.
        let member_cap = match &self.issuer {
            None => None,
            Some(issuer) => match self.lookup.cap_epoch() {
                // A store read failure on the epoch is not a membership failure: every check
                // above already proved `from_fp` is a live member device, so this connect stays
                // an `Allow` — just one with no fresh cap, exactly like "no issuer installed".
                Err(_) => None,
                Ok(cap_epoch) => issuer.issue_member_cap(member.root_fp, cap_epoch),
            },
        };

        ConnectDecision::Allow {
            sign_pk,
            agree_pk,
            member_cap,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::artifacts::{issue_host_op_key_cert, verify_capability};
    use spindle_core::identity::{DeviceKey, RootKey};
    use spindle_vfs::model::DevicePublicKeys;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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

    /// A [`RootKeyCapIssuer`] with a fixed clock, for tests that need to assert something about
    /// `exp` or the signed chain without racing the real wall clock. `op_cert_exp` is set far in
    /// the future so it never interferes with a test's own `now`.
    fn test_cap_issuer(root_seed: [u8; 32], op_seed: [u8; 32], now: u64) -> RootKeyCapIssuer {
        let root = RootKey::from_seed(root_seed);
        let op_signing = SigningKey::from_bytes(&op_seed);
        let op_cert = issue_host_op_key_cert(
            &root,
            &op_signing.verifying_key(),
            Fingerprint::of_parts(&[b"authorize-test:nats"]),
            0,
            u64::MAX / 2,
        );
        RootKeyCapIssuer::new(root.public_key(), op_cert, op_signing).with_now_fn(move || now)
    }

    #[tokio::test]
    async fn allows_an_active_members_enrolled_device_and_returns_its_pinned_sign_pk_and_agree_pk()
    {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x01; 32], [0x02; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store));

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow {
                sign_pk,
                agree_pk,
                member_cap,
            } => {
                assert_eq!(sign_pk, device.sign_public_key());
                assert_eq!(agree_pk, device.agree_public_key());
                assert_eq!(
                    member_cap, None,
                    "HostConnectAuthorizer::new deliberately installs no cap-issuing seam -- it \
                     must supply None, never fabricate a cap"
                );
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

            fn cap_epoch(&self) -> Result<u64, LookupError> {
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

    #[tokio::test]
    async fn with_issuer_mints_a_cap_that_verifies() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x11; 32], [0x12; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let issuer = test_cap_issuer([0x21; 32], [0x22; 32], 1_000);
        let authorizer =
            HostConnectAuthorizer::with_issuer(SqliteDeviceLookup::new(store), Box::new(issuer));

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { member_cap, .. } => {
                let cap = member_cap.expect("with_issuer must mint a cap for an Allow decision");
                verify_capability(&cap, 1_000)
                    .expect("the minted cap must verify its own root -> op-key -> sig chain");
            }
            ConnectDecision::Deny => panic!("expected Allow for an active member's own device"),
        }
    }

    #[tokio::test]
    async fn minted_caps_subject_is_the_members_root_fp_not_the_device_fp() {
        let (store, member_id) = store_with_active_member("alex");
        let root_fp = Fingerprint::of_parts(&[b"alex"]); // matches store_with_active_member
        let device = DeviceKey::from_seeds([0x13; 32], [0x14; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        assert_ne!(
            root_fp, device_fp,
            "test fixture bug: root_fp and device_fp must differ for this assertion to mean anything"
        );
        let issuer = test_cap_issuer([0x23; 32], [0x24; 32], 1_000);
        let authorizer =
            HostConnectAuthorizer::with_issuer(SqliteDeviceLookup::new(store), Box::new(issuer));

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { member_cap, .. } => {
                let cap = member_cap.expect("with_issuer must mint a cap");
                assert!(
                    root_fp.matches(&cap.subject),
                    "DESIGN.md:286: subject must be the member's root_fp"
                );
                assert!(
                    !device_fp.matches(&cap.subject),
                    "DESIGN.md:286: subject must NOT be the connecting device's device_fp"
                );
            }
            ConnectDecision::Deny => panic!("expected Allow for an active member's own device"),
        }
    }

    #[tokio::test]
    async fn minted_caps_kind_and_exp_match_member_and_the_injected_clock_plus_default_ttl() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x15; 32], [0x16; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let now = 5_000;
        let issuer = test_cap_issuer([0x25; 32], [0x26; 32], now);
        let authorizer =
            HostConnectAuthorizer::with_issuer(SqliteDeviceLookup::new(store), Box::new(issuer));

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { member_cap, .. } => {
                let cap = member_cap.expect("with_issuer must mint a cap");
                assert_eq!(cap.kind, CapKind::Member);
                assert_eq!(cap.exp, now + MEMBER_CAP_DEFAULT_TTL_SECS);
            }
            ConnectDecision::Deny => panic!("expected Allow for an active member's own device"),
        }
    }

    #[tokio::test]
    async fn cap_epoch_is_read_live_not_cached() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("host.sqlite3");

        // Independent connection #1: what HostConnectAuthorizer's lookup owns.
        let lookup_store = Store::open(&path).expect("open lookup store");
        let member_id = lookup_store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "alex", 0)
            .expect("add_member");
        lookup_store
            .activate_member(member_id)
            .expect("activate_member");
        let device = DeviceKey::from_seeds([0x17; 32], [0x18; 32]);
        let device_fp = enroll_device(&lookup_store, member_id, "laptop", &device);
        let issuer = test_cap_issuer([0x27; 32], [0x28; 32], 1_000);
        let authorizer = HostConnectAuthorizer::with_issuer(
            SqliteDeviceLookup::new(lookup_store),
            Box::new(issuer),
        );

        let first_epoch = match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { member_cap, .. } => {
                member_cap.expect("with_issuer must mint a cap").cap_epoch
            }
            ConnectDecision::Deny => panic!("expected Allow"),
        };

        // Independent connection #2, to the same file: bumps the epoch out from under the
        // authorizer's own connection. SQLite serializes commits across connections to one file,
        // so the authorizer's next `cap_epoch()` read must observe this.
        let bumping_store = Store::open(&path).expect("open second store handle");
        let bumped_epoch = bumping_store.bump_cap_epoch().expect("bump_cap_epoch");
        assert_eq!(bumped_epoch, first_epoch + 1);

        let second_epoch = match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { member_cap, .. } => {
                member_cap.expect("with_issuer must mint a cap").cap_epoch
            }
            ConnectDecision::Deny => panic!("expected Allow"),
        };
        assert_eq!(
            second_epoch, bumped_epoch,
            "cap_epoch must be read live via DeviceLookup, not cached from the first authorize call"
        );
    }

    #[tokio::test]
    async fn an_issuer_returning_none_still_yields_allow_with_no_cap() {
        struct NeverIssues;
        impl CapIssuer for NeverIssues {
            fn issue_member_cap(
                &self,
                _subject: Fingerprint,
                _cap_epoch: u64,
            ) -> Option<Capability> {
                None
            }
        }

        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x19; 32], [0x1a; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let authorizer = HostConnectAuthorizer::with_issuer(
            SqliteDeviceLookup::new(store),
            Box::new(NeverIssues),
        );

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { member_cap, .. } => {
                assert_eq!(
                    member_cap, None,
                    "issuance failure must never turn an otherwise-valid connect into a Deny, \
                     but it also must not fabricate a cap"
                );
            }
            ConnectDecision::Deny => {
                panic!("issuance failure must never turn an otherwise-valid connect into a Deny")
            }
        }
    }

    #[tokio::test]
    async fn a_denied_device_never_reaches_the_issuer() {
        struct CountingIssuer {
            calls: Arc<AtomicUsize>,
        }
        impl CapIssuer for CountingIssuer {
            fn issue_member_cap(&self, subject: Fingerprint, cap_epoch: u64) -> Option<Capability> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                test_cap_issuer([0x29; 32], [0x2a; 32], 1_000).issue_member_cap(subject, cap_epoch)
            }
        }

        let (store, _member_id) = store_with_active_member("alex");
        let calls = Arc::new(AtomicUsize::new(0));
        let authorizer = HostConnectAuthorizer::with_issuer(
            SqliteDeviceLookup::new(store),
            Box::new(CountingIssuer {
                calls: Arc::clone(&calls),
            }),
        );

        let stranger = DeviceKey::from_seeds([0x1b; 32], [0x1c; 32]).device_fp();
        match authorizer.authorize(&stranger).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!("expected Deny for an unenrolled device_fp"),
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a denied device must never reach the cap issuer"
        );
    }
}
