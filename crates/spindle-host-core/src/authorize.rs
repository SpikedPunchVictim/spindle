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

use crate::device_keys::{checked_device_keys, DeviceKeyError};
use crate::ratelimit::{ConnectRateLimitConfig, ConnectRateLimiter};
use spindle_core::artifacts::issue_capability;
use spindle_core::identity::device_fp_of;
use spindle_core::{Fingerprint, SigningKey, VerifyingKey, X25519PublicKey, ALG_ID_V1};
use spindle_net::signaling::authorize::{ConnectAuthorizer, ConnectDecision, VerifiedDecision};
use spindle_proto::artifacts::{CapKind, Capability, HostOpKeyCert};
use spindle_vfs::model::{Member, MemberStatus};
use spindle_vfs::store::{Store, StoreError};
use std::sync::{LazyLock, Mutex, Once};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// A device registry lookup, abstracted away from `spindle_vfs::store::Store`'s concrete
/// `!Sync`-ness — see the module doc comment for why this trait exists rather than
/// [`HostConnectAuthorizer`] naming `Store` (or a lock around one) directly.
pub trait DeviceLookup: Send + Sync {
    /// Resolves the member that owns `device_fp`, if any — the same lookup
    /// `spindle_vfs::store::Store::member_for_device_fp` performs.
    fn member_for_device_fp(&self, device_fp: Fingerprint) -> Result<Option<Member>, LookupError>;

    /// The host's current `cap_epoch` (`spindle_vfs::store::Store::cap_epoch`), read on its own,
    /// independent of any membership read.
    ///
    /// **Must NOT be used to source the epoch a freshly-minted member capability is stamped
    /// with.** That was this method's original purpose, but it is exactly the split-read shape
    /// [`Self::member_and_cap_epoch`]'s doc comment warns against: calling this method and
    /// [`Self::member_for_device_fp`] as two independent reads reopens the TOCTOU a revoke can
    /// land inside of, pairing a pre-revoke member with a post-bump epoch. Any caller about to
    /// mint a capability **must** use [`Self::member_and_cap_epoch`] instead, which reads both
    /// values from one atomic snapshot. As of this writing this method has no caller left at all,
    /// production or test: `HostConnectAuthorizer::authorize` reads the epoch exclusively via
    /// `self.lookup.member_and_cap_epoch(..)`, and [`SqliteDeviceLookup::member_and_cap_epoch`]'s
    /// own implementation delegates straight to `Store::member_and_cap_epoch` rather than calling
    /// this method. It is still implemented — by [`SqliteDeviceLookup`] and by several test
    /// doubles in this crate's `#[cfg(test)]` modules — only because implementing [`DeviceLookup`]
    /// requires it; nothing anywhere invokes it. (td-fc5a30 moved the minting caller from
    /// `HostConnectAuthorizer::authorize` to `HostConnectAuthorizer::on_verified`; the rule is
    /// unchanged — that method reads both values via [`Self::member_and_cap_epoch`].)
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

    /// Resolves `device_fp`'s owning member **and** reads `cap_epoch`, both from one snapshot of
    /// the store — the atomic counterpart to calling [`Self::member_for_device_fp`] and
    /// [`Self::cap_epoch`] separately.
    ///
    /// The outer `Result` and the inner `Option<u64>` mean two very different things, and they
    /// must not be collapsed into each other:
    ///
    /// - The outer `Result`'s `Err` means "membership is unprovable" — the same fail-closed
    ///   signal [`Self::member_for_device_fp`] gives, and every caller treats it the same way:
    ///   [`ConnectDecision::Deny`].
    /// - The inner `Option<u64>` being `None` means "the connect is fine, there is just no fresh
    ///   cap this time" — [`CapIssuer`]'s own doc comment states the invariant this preserves: a
    ///   cap-issuance failure must never turn an otherwise-valid connect into a `Deny`. A single,
    ///   shared `LookupError` cannot distinguish "I could not read membership" from "I read
    ///   membership fine but the `cap_epoch` read failed", so folding the epoch read into the
    ///   outer `Result` would silently deny every connect on the second failure too.
    ///
    /// That second failure is reachable, not hypothetical: `Store::cap_epoch` runs `SELECT
    /// cap_epoch FROM meta WHERE id = 0`, and `spindle-hostd` deliberately opens multiple
    /// independent connections to the same database file (see `crates/spindle-hostd/src/lib.rs`'s
    /// module doc comment) — a transient `SQLITE_BUSY` on that read is possible while another
    /// connection holds a write lock. If that busy error denied the connect, a host would refuse
    /// every device until the busy window passed, which is precisely the lockout DESIGN.md:288-290's
    /// renewal path exists to prevent. Losing the epoch on such a read must cost the connect
    /// nothing worse than "no fresh cap this time" — [`Self::member_for_device_fp`] failing,
    /// by contrast, means membership itself could not be proven, so `Deny` is correct there.
    ///
    /// This exists to close a TOCTOU race that a two-call sequence leaves open. `Store`'s two
    /// revocation entry points — `revoke_member_and_bump_epoch` and
    /// `revoke_device_and_bump_epoch` (`crates/spindle-vfs/src/store/mod.rs`) — each flip a
    /// member's status (or a device's `revoked` flag) *and* bump `cap_epoch` inside one
    /// transaction; nothing else in this codebase bumps `cap_epoch` at all (see this trait's
    /// [`Self::cap_epoch`] doc comment). If a caller resolves the member via
    /// [`Self::member_for_device_fp`], and only afterward reads [`Self::cap_epoch`] as a second,
    /// independent lock acquisition, one of those revoke transactions can commit in the window
    /// between the two reads. The caller then holds a `member` snapshot from *before* the revoke
    /// paired with a `cap_epoch` from *after* it — and if it mints a capability from that pair,
    /// the result is a capability for a subject the store has already revoked, stamped with the
    /// post-bump epoch. That makes it indistinguishable from a legitimately fresh capability to
    /// any consumer that only checks `cap.cap_epoch` against the host's current `cap_epoch` —
    /// exactly the check `cap_epoch` exists to make revocation defeat. See
    /// [`HostConnectAuthorizer::on_verified`]'s own comment at its call site for the concrete
    /// exploit shape this closes (td-fc5a30 moved that call site out of `authorize`, which no
    /// longer mints; the race, and this method's role in closing it, are unchanged).
    ///
    /// An implementation must take one **database-level transaction** covering both reads, not
    /// merely one in-process lock: an in-process `Mutex`/lock only ever excludes other threads
    /// holding the *same* handle, and `spindle-hostd` deliberately opens multiple independent
    /// connections to the same database file (see its module doc comment), so a lock held around
    /// two separate autocommit reads is not a snapshot — another connection's
    /// `revoke_member_and_bump_epoch` / `revoke_device_and_bump_epoch` can still commit in the gap
    /// between them regardless of how long the lock is held. `SqliteDeviceLookup` cannot build
    /// that transaction itself (`Store::connection()` is `pub(crate)` to `spindle-vfs`), so the
    /// real snapshot has to be constructed inside `spindle-vfs` and exposed as one call —
    /// `Store::member_and_cap_epoch` — that this method's implementation must delegate to under
    /// its lock. See [`SqliteDeviceLookup::member_and_cap_epoch`] for that shape.
    ///
    /// Any caller that is about to mint a capability from the result **must** use this method
    /// rather than [`Self::member_for_device_fp`] plus [`Self::cap_epoch`]. Callers that only need
    /// the membership decision and never touch `cap_epoch` — [`active_member_for_device`], and
    /// through it both [`crate::session::VfsSessionHandler`] and
    /// [`HostConnectAuthorizer::authorize`] — have no epoch to race against and keep using
    /// [`Self::member_for_device_fp`] alone.
    fn member_and_cap_epoch(
        &self,
        device_fp: Fingerprint,
    ) -> Result<(Option<Member>, Option<u64>), LookupError>;
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

    fn member_and_cap_epoch(
        &self,
        device_fp: Fingerprint,
    ) -> Result<(Option<Member>, Option<u64>), LookupError> {
        // The `Mutex` here only excludes other threads holding *this* `Store` handle — it says
        // nothing about `spindle-hostd`'s other, independent connections to the same database
        // file, so it cannot by itself be the snapshot this method promises. The actual snapshot
        // is `Store::member_and_cap_epoch`'s database-level transaction; the lock's only job is to
        // make `!Sync` `Store` safe to call from here at all (see the module doc comment's
        // `DeviceLookup` seam section).
        let store = self.store.lock().map_err(|_| LookupError::LockPoisoned)?;
        match store.member_and_cap_epoch(device_fp) {
            Ok((member, cap_epoch)) => Ok((member, Some(cap_epoch))),
            Err(e) => {
                // `Store::member_and_cap_epoch` failed as a whole — most plausibly a transient
                // `SQLITE_BUSY` opening the transaction while another of `spindle-hostd`'s
                // connections holds a write lock. Preserve the deliberate asymmetry this trait's
                // doc comment describes: a failed *membership* read must deny the connect, but a
                // failed *epoch* read must cost only the capability. A whole-call error conflates
                // the two, so fall back to the plain, single-statement `member_for_device_fp` —
                // if membership can be read on its own, the connect proceeds with no fresh cap
                // (`None`); if it can't, `?` propagates and denies, exactly as it would have if
                // the fused read had never been attempted.
                //
                // This single occurrence may well be exactly that transient blip — this call site
                // cannot tell transient from persistent apart, so this reports what happened, not
                // what caused it. What makes a *persistent* failure here worth a human's attention:
                // every connect keeps succeeding (via the fallback below, or via the plain
                // membership-only path when no issuer is installed), but this host quietly stops
                // minting fresh member capabilities — a fleet-wide lock-out that only surfaces once
                // existing caps expire (`MEMBER_CAP_DEFAULT_TTL_SECS`: six weeks), degrees removed
                // in both time and symptom from this call site.
                // Audited 2026-09-07: `%e` is a `LookupError`, whose only reachable content
                // here is a `rusqlite` message from this host's own store (its path is operator
                // configuration, exempt — see this crate's `lib.rs` `tracing` section) or a
                // fingerprint *length* complaint. `LookupError::Store` is typed over all of
                // `StoreError` though, and that enum's `Confine`/`Model`/`MountPathCollision`/
                // `DeviceNotFound` variants do carry real paths, virtual paths, and untruncated
                // fingerprints — so anything that widens what these lookups call must re-check
                // this line rather than trusting the redaction guard, which only reads binding
                // names.
                tracing::warn!(
                    device_fp = %device_fp.redacted(),
                    error = %e,
                    "member_and_cap_epoch: fused member+cap_epoch read failed; falling back to a \
                     membership-only read for this connect. A persistent recurrence silently \
                     degrades this host to never minting fresh member capabilities"
                );
                let member = store.member_for_device_fp(device_fp)?;
                Ok((member, None))
            }
        }
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
        Ok(member) => member,
        Err(e) => {
            // Reachable from two independent pipelines: `HostConnectAuthorizer::authorize`, and
            // every session's own liveness re-check
            // (`crate::session::VfsSessionHandler::session_context`) — so this fires far more
            // often than just at connect time. Fails closed either way (per this function's own
            // doc comment), which is correct regardless of why the lookup failed; this line exists
            // only so a human can tell "denied, store unreadable" apart from "denied, not a
            // member" after the fact, the same distinction `HostConnectAuthorizer::authorize`
            // makes explicit for its own `Err` arm below.
            // Audited 2026-09-07: `%e` is a `LookupError`, whose only reachable content
            // here is a `rusqlite` message from this host's own store (its path is operator
            // configuration, exempt — see this crate's `lib.rs` `tracing` section) or a
            // fingerprint *length* complaint. `LookupError::Store` is typed over all of
            // `StoreError` though, and that enum's `Confine`/`Model`/`MountPathCollision`/
            // `DeviceNotFound` variants do carry real paths, virtual paths, and untruncated
            // fingerprints — so anything that widens what these lookups call must re-check
            // this line rather than trusting the redaction guard, which only reads binding
            // names.
            tracing::warn!(
                device_fp = %device_fp.redacted(),
                error = %e,
                "active_member_for_device: membership lookup failed; failing closed (treated as \
                 not live)"
            );
            return None;
        }
    };
    liveness_checks(member, device_fp)
}

/// Checks 3–5 of [`active_member_for_device`]'s narrative — applied to an already-fetched
/// `Option<Member>` rather than performing the fetch itself. Factored out so DESIGN.md §A4's
/// liveness rule is defined in exactly one place while still having two entry points: the plain,
/// membership-only fetch ([`active_member_for_device`], used by [`crate::session::VfsSessionHandler`]
/// and by [`HostConnectAuthorizer::authorize`], neither of which mints) and the atomic snapshot
/// fetch ([`DeviceLookup::member_and_cap_epoch`], used by
/// [`HostConnectAuthorizer::on_verified`], which does). Checks 1 and
/// 2 — the fetch itself, and its `None`/`Err` handling — are each entry point's own job, since
/// they differ in how the member is obtained; this function starts from whatever `Option<Member>`
/// the caller already has in hand.
fn liveness_checks(member: Option<Member>, device_fp: Fingerprint) -> Option<Member> {
    let member = member?;

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
/// and [`HostConnectAuthorizer::on_verified`] treats that exactly like "no issuer installed" —
/// `member_cap: None` in an otherwise-`Proceed` decision. A cap-issuance failure must **never**
/// turn an otherwise-valid connect into a `Drop`: the device simply gets an answer with no fresh
/// cap and falls back to whatever cap it already holds. Dropping here would be strictly worse than
/// the status quo, because it would take a working connect path and break it over a problem
/// (signing) that has nothing to do with whether this device is still a live member.
pub trait CapIssuer: Send + Sync {
    /// Issues a `member`-kind capability for `subject` (see [`RootKeyCapIssuer`]'s doc comment
    /// for why `subject` must be the member's `root_fp`, never a device fp), stamped with
    /// `cap_epoch` — the caller (`HostConnectAuthorizer::on_verified`) reads that epoch live via
    /// [`DeviceLookup::member_and_cap_epoch`], in the same snapshot as the membership check that
    /// gated this call, rather than caching it. Reading it via [`DeviceLookup::cap_epoch`] as a
    /// second, independent call — alongside a separate membership read — is precisely the TOCTOU
    /// this method's caller was rewritten to close: a revoke committing between the two reads
    /// would let this method mint a validly-signed capability for a subject the store has already
    /// revoked, stamped with an epoch that makes it indistinguishable from a legitimately fresh
    /// one. See [`DeviceLookup::member_and_cap_epoch`]'s own doc comment for the full shape of
    /// that race.
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
/// Closes both of `spindle-net`'s `signaling::host` module doc comment's MUSTs for a
/// `ConnectAuthorizer` implementation (`crates/spindle-net/src/signaling/host.rs`'s
/// `process_offer` doc comment): "must rate-limit these lookups" is [`Self::limiter`], a
/// [`ConnectRateLimiter`] consulted before any store access (see `authorize`'s check 0); "must
/// make `Allow` and `Deny` indistinguishable to the caller in timing and observable behavior" is
/// [`equalize_denial_work`], run on every pre-crypto `Deny` so an unenrolled `from_fp` costs
/// roughly the same crypto work as an enrolled one. Neither is complete:
///
/// - the rate limiter's global bucket state (whether it is exhausted right now) is itself
///   observable via timing/behavior differences between callers — see [`ConnectRateLimiter`]'s own
///   doc comment for the accepted "shared fate" cost this implies. Since td-fc5a30 the *per-fp*
///   bucket is no longer part of that surface at all: it is charged only in [`Self::on_verified`],
///   behind the signature check, so an unauthenticated peer cannot observe or influence any
///   fingerprint's own bucket;
/// - the timing equalization closes the crypto-work asymmetry (check 9's own comment explains why
///   it stops exactly there) but leaves the store-side cost difference between a registry hit and
///   a miss, plus SQLite page-cache and allocator jitter, unequalized — see
///   [`equalize_denial_work`]'s doc comment for the honest accounting of what remains open. That
///   residual gap is bounded by the rate limiter and by §A5's uniform silent drop
///   (`SignalingError::Denied` produces no reply at all), not eliminated.
///
/// [`Self::authorize`] deliberately does **not**:
/// - verify the envelope signature — the caller does that next, using the `sign_pk`/`agree_pk`
///   this returns (see `ConnectAuthorizer::authorize`'s own doc comment: "an authorizer must not
///   treat being asked as proof of anything about the envelope itself");
/// - consult `cap_epoch` — a connect decision is membership, not capability freshness;
/// - charge anything to the identity `from_fp` names, or mint anything for it. Both moved to
///   [`Self::on_verified`] in td-fc5a30, which runs only after the caller has verified that
///   signature. See that method, `authorize`'s check 0, and
///   [`spindle_net::signaling::authorize::ConnectAuthorizer`]'s own doc comment for the rule and
///   the attack it exists to close.
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
    /// `spindle-net`'s `signaling::host` module doc comment's first MUST (see this struct's own
    /// doc comment above): the pre-authentication token bucket over the connect endpoint DESIGN.md
    /// §A5/v0.9.24 mandates. Installed by both [`Self::new`] and [`Self::with_issuer`] with
    /// [`ConnectRateLimitConfig::default`] — **never opt-in**. This is a security control, not a
    /// convenience knob: a host built via either constructor and never touching
    /// [`Self::with_connect_rate_limit`] must still be rate-limited, not silently unlimited. See
    /// this module's `tests::the_rate_limiter_is_on_by_default_and_is_not_opt_in` for the test
    /// that pins this.
    limiter: ConnectRateLimiter,
    /// The clock the rate limiter reads (separate from [`CapIssuer`]'s own `now_fn`, which stamps
    /// a minted capability's `exp` — the two clocks answer different questions and a test may need
    /// to control them independently). Defaults to [`wall_clock_now_secs`]; [`Self::with_now_fn`]
    /// injects a deterministic one for tests, mirroring [`RootKeyCapIssuer::with_now_fn`]'s own
    /// chainable-setter shape (see that method's doc comment for why chainable consuming-self
    /// setters are used here rather than alternative constructors).
    now_fn: BoxedNowFn,
}

impl<L: DeviceLookup> HostConnectAuthorizer<L> {
    /// Installs no cap-issuing seam: `authorize` always answers `member_cap: None`. Correct for a
    /// host with no cap-signing key online yet — see [`CapIssuer`]'s doc comment — not merely a
    /// placeholder for "unimplemented".
    ///
    /// Also installs the connect-rate limiter ([`ConnectRateLimiter`], via
    /// [`ConnectRateLimitConfig::default`]) and the real wall clock for it. Unlike the cap issuer,
    /// the limiter is **not** an opt-in seam: DESIGN.md §A5/v0.9.24 mandates it unconditionally,
    /// so there is no "no limiter installed" state to construct, the way `issuer: None` is a valid
    /// choice. Use [`Self::with_connect_rate_limit`] to retune it, not to turn it on.
    pub fn new(lookup: L) -> Self {
        HostConnectAuthorizer {
            lookup,
            issuer: None,
            limiter: ConnectRateLimiter::new(ConnectRateLimitConfig::default()),
            now_fn: Box::new(wall_clock_now_secs),
        }
    }

    /// As [`Self::new`], but with a real [`CapIssuer`] installed so `authorize` mints a fresh
    /// member capability for every `Allow`. Installs the same default-on connect-rate limiter
    /// [`Self::new`] does — see that constructor's doc comment; the cap issuer and the rate
    /// limiter are independent seams, and neither constructor may skip the limiter.
    pub fn with_issuer(lookup: L, issuer: Box<dyn CapIssuer>) -> Self {
        HostConnectAuthorizer {
            lookup,
            issuer: Some(issuer),
            limiter: ConnectRateLimiter::new(ConnectRateLimitConfig::default()),
            now_fn: Box::new(wall_clock_now_secs),
        }
    }

    /// As either constructor built it, but with an explicit clock for the connect-rate limiter —
    /// a deterministic clock for tests. Follows [`RootKeyCapIssuer::with_now_fn`]'s established
    /// chainable-consuming-self-setter shape (see that method's doc comment for why this is a
    /// setter rather than a third alternative constructor: it must compose with
    /// [`Self::with_connect_rate_limit`], and a per-knob alternative constructor would make the
    /// two mutually exclusive).
    pub fn with_now_fn(self, now_fn: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        HostConnectAuthorizer {
            now_fn: Box::new(now_fn),
            ..self
        }
    }

    /// As either constructor built it, but with the connect-rate limiter rebuilt from an explicit
    /// `config` instead of [`ConnectRateLimitConfig::default`]. Rebuilding (rather than mutating
    /// the existing limiter in place) is correct here: [`ConnectRateLimiter`] has no in-place
    /// reconfiguration method, and a fresh limiter with empty bucket state is exactly what
    /// switching configs should produce — there is no meaningful "carry the old buckets forward
    /// under new parameters" behavior to preserve.
    pub fn with_connect_rate_limit(self, config: ConnectRateLimitConfig) -> Self {
        HostConnectAuthorizer {
            limiter: ConnectRateLimiter::new(config),
            ..self
        }
    }

    /// Test-only view of how many per-`from_fp` buckets the limiter is tracking. Exists so
    /// td-fc5a30's regression tests can assert that the *pre*-verification path inserts nothing
    /// into that bounded map, which is not observable through `ConnectDecision` alone.
    #[cfg(test)]
    fn tracked_fps(&self) -> usize {
        self.limiter.tracked_fps()
    }
}

/// A fixed, valid Ed25519 verifying key / X25519 public key pair, computed once, that
/// [`equalize_denial_work`] recomputes a `device_fp` against on every pre-crypto `Deny`.
///
/// Only the sign half needs to be a genuinely valid curve point: `checked_verifying_key` (td-b8c68a;
/// `VerifyingKey::from_bytes` plus the RFC 8032 §5.1.3 canonicality pre-check) is a point
/// decompression that can fail for a byte string that does not encode a canonical, valid Ed25519
/// point, and it is exactly that check — not a scalar multiplication, which the real `Allow` path
/// never performs either — that [`equalize_denial_work`] must redo per call to match the real
/// path's cost. Deriving `sign_bytes` here, once, via `SigningKey::from_bytes(&[0xA5; 32])
/// .verifying_key().to_bytes()` guarantees a point `checked_verifying_key` can always
/// successfully decompress, without paying that derivation cost on every denied connect.
///
/// `agree_bytes` has no such constraint: X25519 public keys are unvalidated (any 32 bytes decode),
/// so `[0x5A; 32]` — an arbitrary fixed constant, chosen only to be visibly not all-zero — is fine
/// as-is; there is no equivalent "valid point" cost for `X25519PublicKey::from` to redo, since the
/// real `Allow` path's own `X25519PublicKey::from` call (check 7, above) does not validate either.
static EQUALIZATION_DUMMY_KEYS: LazyLock<([u8; 32], [u8; 32])> = LazyLock::new(|| {
    let sign_bytes = SigningKey::from_bytes(&[0xA5; 32])
        .verifying_key()
        .to_bytes();
    let agree_bytes = [0x5A; 32];
    (sign_bytes, agree_bytes)
});

/// Guards the `tracing::error!` in [`equalize_denial_work`]'s failure branch so it fires at most
/// once per process. That branch runs on the pre-authentication connect path, reachable by any
/// unauthenticated peer naming any `from_fp` it likes — every denied connect that isn't a plain
/// rate-limit or already-signature-verified `Deny` re-enters `equalize_denial_work`, and a bad
/// `EQUALIZATION_DUMMY_KEYS` constant would make ALL of them take this branch. Without a guard,
/// that is an attacker-driven, unbounded log flood: one `tracing::error!` per denied connect,
/// forever, for as long as the attacker keeps connecting. `Once` still gets the operator the
/// signal — this is a real programmer error worth surfacing loudly — just exactly once per
/// process lifetime rather than once per attacker request.
static EQUALIZATION_DUMMY_KEY_INVALID_LOGGED: Once = Once::new();

#[cfg(test)]
thread_local! {
    /// Test-only count of [`equalize_denial_work`] invocations on the current thread. Thread-local,
    /// **not** a global `AtomicUsize`: this module's tests run concurrently in one process and
    /// several of them call `authorize`, so a shared global counter would be raced by unrelated
    /// tests incrementing it out from under each other. `#[tokio::test]` uses a current-thread
    /// runtime, so each test's `authorize` calls all happen on that one test's own thread — a
    /// thread-local is race-free here with no lock needed, at the cost of the test harness
    /// potentially reusing that OS thread for a later test, which is exactly why every test using
    /// this resets it first via [`reset_equalization_calls`] rather than trusting it to start at
    /// `0`.
    ///
    /// What this proves, and what it does not: an increment proves the denial path *called*
    /// [`equalize_denial_work`], which is what makes the routing of all eight
    /// `deny_with_equalized_work()` call sites in `HostConnectAuthorizer::authorize` load-bearing —
    /// see `tests::a_denial_for_an_unenrolled_from_fp_runs_the_timing_equalization`, which fails if
    /// a future edit quietly reverts one of those call sites back to a plain
    /// `ConnectDecision::Deny`. It says nothing about whether the resulting timings are actually
    /// indistinguishable: this crate deliberately does not assert wall-clock timing anywhere (see
    /// the comment at the end of this module's `tests` module for why such an assertion would be
    /// flaky and prove nothing), and `equalize_denial_work`'s own doc comment's "What this does NOT
    /// close" section already scopes that honestly — the store-side cost difference and ordinary
    /// allocator/cache jitter stay unequalized no matter how many times this counter increments.
    static EQUALIZATION_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test-only reader for [`EQUALIZATION_CALLS`] on the current thread. Exists so tests read the
/// count through a named function rather than reaching into the `Cell` directly at each call site.
#[cfg(test)]
fn equalization_calls() -> usize {
    EQUALIZATION_CALLS.with(|calls| calls.get())
}

/// Test-only reset of [`EQUALIZATION_CALLS`] on the current thread to `0`. Every test that reads
/// this counter must call this first — see [`EQUALIZATION_CALLS`]'s own doc comment: the test
/// harness may reuse the same OS thread for an earlier, unrelated test, so a fresh `#[tokio::test]`
/// cannot assume the counter already reads `0`.
#[cfg(test)]
fn reset_equalization_calls() {
    EQUALIZATION_CALLS.with(|calls| calls.set(0));
}

/// Performs the same Ed25519/X25519 key parse and `device_fp_of` recompute an `Allow` path
/// performs (checks 7 and 9 of [`HostConnectAuthorizer::authorize`]), against the fixed dummy key
/// pair in [`EQUALIZATION_DUMMY_KEYS`], and discards the result — the crypto half of closing
/// `spindle-net`'s `signaling::host` module doc comment's second MUST for a `ConnectAuthorizer`:
/// making `Allow` and `Deny` "indistinguishable to the caller in timing and observable behavior".
///
/// Without this, an unenrolled `from_fp` returns after one indexed store lookup (`liveness_checks`
/// finding no member/device), while an enrolled, live one continues through `get_member`'s row
/// assembly, two key parses, and a `device_fp_of` rehash — a real, measurable amount of extra
/// crypto work an `Allow` pays that a fast pre-crypto `Deny` does not. Doing that same parse-and-
/// rehash work on the `Deny` path too, against a value nobody's response depends on, closes that
/// gap: every pre-crypto `Deny` (see [`deny_with_equalized_work`]) now pays roughly the same
/// crypto cost an `Allow` does, so an attacker timing responses cannot use the crypto-work
/// difference to distinguish "not a member" from "is a member, but denied for some other reason
/// upstream of crypto" — or, combined with the rate limiter, to efficiently enumerate valid
/// `from_fp` values by timing alone.
///
/// **What this does NOT close** — read before assuming the timing channel is shut: the store-side
/// cost difference between a registry hit (`get_member` assembling a `Member` plus its device
/// rows) and a miss (one indexed lookup returning nothing) remains unequalized here, along with
/// ordinary SQLite page-cache and allocator jitter between runs. This function only redoes the
/// *crypto* work an `Allow` performs; it does not — and, running entirely in-process with no store
/// handle in scope, cannot — redo the store-side asymmetry too. That residual gap is bounded by
/// [`ConnectRateLimiter`] (an attacker gets only so many timed samples per unit time) and by
/// DESIGN.md §A5's uniform silent drop (`SignalingError::Denied` produces no reply at all, so
/// there is no reply latency to time from the wire in the first place), not eliminated by it.
/// DESIGN.md:481-483's v0.9.24 amendment records this same caveat; do not describe this function,
/// in a future doc update, as closing the channel entirely — it does not.
///
/// **A second, larger gap in the same direction — CLOSED by td-fc5a30, recorded here because the
/// shape of the fix is the point.** While the capability mint lived in
/// [`HostConnectAuthorizer::authorize`] (its old "check 10"), an `Allow` that successfully minted a
/// member cap performed an Ed25519 SIGNATURE — `issue_member_cap`'s whole reason for existing —
/// that this function's crypto recompute never matched; it only redoes the parse/rehash work of
/// checks 7 and 9, never a signature. Measured on one release-build machine:
/// `equalize_denial_work` ≈ 3.3 µs/call, `issue_member_cap` ≈ 16.7 µs/call — an asymmetry roughly
/// 5x LARGER than the parse/rehash gap this function closes, pointing the same direction (`Allow`
/// slower than `Deny`).
///
/// Equalizing it was never the fix: performing an Ed25519 signature on every denial, to match,
/// would hand an attacker exactly the CPU-cost amplification [`ConnectRateLimiter`] exists to deny
/// them — trading a timing side-channel for a cheap denial-of-service amplifier is a strictly worse
/// trade. The actual fix was to move the signature out of the pre-authentication path entirely:
/// the mint now runs in [`HostConnectAuthorizer::on_verified`], reached only after the offer's
/// signature has verified, so no `Deny` this function equalizes can be compared against an `Allow`
/// that signed. Every `ConnectDecision::Allow` now does the same parse-and-rehash work and nothing
/// more, which makes this function's ≈3.3 µs an imitation of the WHOLE of an `Allow`'s crypto cost
/// rather than a fraction of it. Do not move a mint, or any other signature, back onto the
/// `authorize` path — it would reopen this gap and, worse, hand every unauthenticated peer a free
/// signature per packet.
///
/// Wrapped in [`std::hint::black_box`] so the compiler cannot prove the result is unused and
/// optimize the recompute away — an elided recompute would silently stop equalizing anything while
/// looking, to a reader of this source, exactly like it still was.
fn equalize_denial_work() {
    // Test-only instrumentation, load-bearing for the coverage gap td-4bcf24 closes: see
    // EQUALIZATION_CALLS's doc comment for what an increment here does and does not prove.
    #[cfg(test)]
    EQUALIZATION_CALLS.with(|calls| calls.set(calls.get() + 1));

    let (sign_bytes, agree_bytes) = *EQUALIZATION_DUMMY_KEYS;
    // If this ever failed, `equalize_denial_work` would silently do LESS work than the real
    // `Allow` path (which always has a key that parsed, by construction) — quietly reopening the
    // exact timing gap this function exists to close, with no compile-time or test signal short of
    // `the_equalization_dummy_key_parses_as_a_valid_ed25519_point` (below) catching a bad constant.
    // Returning early here costs only that equalization, never the security decision itself: this
    // function's only caller, `deny_with_equalized_work`, returns `ConnectDecision::Deny` either
    // way, with or without the equalization work actually running. This module's house style never
    // `unwrap`s an invariant in a security path (see e.g. check 4 and check 8's own comments for
    // the same rule), and here that rule is sharper than usual — `equalize_denial_work` runs on
    // the pre-authentication connect path, reachable by any unauthenticated peer naming any
    // `from_fp` it likes, so panicking on a malformed *constant* would convert a programmer error
    // into the one crash-shaped seam in an otherwise all-`Deny` path. Logging loudly and returning
    // is strictly better: the connect is still denied, just without this call's timing
    // equalization.
    let Some(sign_pk) = spindle_core::checked_verifying_key(&sign_bytes) else {
        // See EQUALIZATION_DUMMY_KEY_INVALID_LOGGED's doc comment: any peer can reach this branch
        // at will simply by causing a pre-crypto denial, so this must log at most once per
        // process, not once per request.
        EQUALIZATION_DUMMY_KEY_INVALID_LOGGED.call_once(|| {
            tracing::error!(
                "equalize_denial_work: the fixed dummy Ed25519 key failed to decompress, so \
                 connect denials are no longer timing-equalized against the Allow path's crypto \
                 work. This is a programmer error in EQUALIZATION_DUMMY_KEYS, not \
                 attacker-controlled input"
            );
        });
        return;
    };
    let agree_pk = X25519PublicKey::from(agree_bytes);
    let recomputed = device_fp_of(ALG_ID_V1, &sign_pk, &agree_pk);
    std::hint::black_box(recomputed);
}

/// A pre-crypto `Deny` (checks 1-8 of [`HostConnectAuthorizer::authorize`] — every check that
/// denies before performing the real `device_fp_of` rehash) routed through
/// [`equalize_denial_work`] first. See that function's doc comment for exactly what this does, and
/// does not, close. Check 9's own `Deny` (the `device_fp_of` mismatch) deliberately does NOT use
/// this helper — see the comment at that call site for why.
fn deny_with_equalized_work() -> ConnectDecision {
    equalize_denial_work();
    ConnectDecision::Deny
}

impl<L: DeviceLookup> ConnectAuthorizer for HostConnectAuthorizer<L> {
    /// Every failure mode below returns `Deny`; only reaching the final line returns `Allow`. See
    /// the module doc comment and this crate's task brief for why each check exists; in
    /// particular, checks 3 and 5 (the shared `liveness_checks` helper reached via either
    /// [`active_member_for_device`] or [`DeviceLookup::member_and_cap_epoch`] below — see
    /// `active_member_for_device`'s doc comment for the full per-check narrative, including why
    /// checks 3 and 5 are independently enforced: a still-`Active` member can have one revoked
    /// device among several, the same split `server.rs`'s `denied:device_revoked` gate makes per
    /// request) are shared with [`crate::session::VfsSessionHandler`]'s session-time gate rather
    /// than duplicated here.
    async fn authorize(&self, from_fp: &Fingerprint) -> ConnectDecision {
        // 0. Rate limit, before any store access at all (`spindle-net`'s `signaling::host` module
        // doc comment: an implementation "must rate-limit these lookups", since the authorizer is
        // reached with an unverified, attacker-chosen `from_fp` before any signature is checked).
        //
        // **GLOBAL bucket only** (td-fc5a30). `from_fp` is not authenticated here and never can
        // be at this point — this method exists to resolve the key the signature will later be
        // checked against — so nothing this method does may be charged to the identity `from_fp`
        // names. The per-fp bucket, and the bounded map insert that comes with it, moved to
        // `on_verified`. Note that `try_acquire_global` does not even take a `Fingerprint`: there
        // is deliberately no name here for a future edit to accidentally charge.
        //
        // Restoring `try_acquire_fp` to this line reintroduces a remote, targeted lockout of an
        // arbitrary victim device: an attacker with any valid device credential can publish to
        // `host.<h>.connect` naming a victim's `from_fp` with `reply = _INBOX_<victim_fp>.…`
        // (nats-server 2.10 checks publish permissions against the publish subject only, never the
        // reply), so every per-identity token spent here is spent out of the victim's budget by
        // someone who cannot produce the victim's signature. See `ConnectRateLimiter`'s doc
        // comment for the measured numbers, and
        // `tests::a_forged_offer_naming_a_victim_does_not_consume_the_victims_per_fp_bucket` for
        // the regression that fails if this line is changed back.
        //
        // This returns a PLAIN `Deny`, not `deny_with_equalized_work()`'s equalized one, and that
        // is deliberate, not an oversight:
        // - a rate-limited rejection reveals only rate-limiter state (the shared global bucket is
        //   out of tokens right now), never membership — it leaks nothing about whether `from_fp`
        //   is enrolled, so there is no membership-oracle signal here to hide behind equalized
        //   crypto work. Since td-fc5a30 this is stronger still: the bucket consulted here is not
        //   keyed on `from_fp` at all, so its state cannot be about `from_fp` even in principle;
        // - spending crypto work on a request the limiter has already refused would hand a
        //   flooder exactly the amplification the limiter exists to deny: the whole point of
        //   checking the limiter first is to make a throttled request cheap, not merely
        //   indistinguishable-looking. Being measurably faster on this path is the correct
        //   trade-off, not a timing leak that needs closing.
        if !self.limiter.try_acquire_global((self.now_fn)()) {
            return ConnectDecision::Deny;
        }

        // 1-5. Membership and DESIGN.md §A4's liveness rule, via the plain, membership-only
        // `active_member_for_device` — one lookup, no `cap_epoch` read at all, keeping this
        // struct's own doc comment true ("a connect decision is membership, not capability
        // freshness").
        //
        // td-fc5a30 note on what this block used to do. Until the mint moved to `on_verified`,
        // this branched on whether a `CapIssuer` was installed: with one, it called
        // `DeviceLookup::member_and_cap_epoch` so that the member and the `cap_epoch` a freshly
        // minted cap would carry came from ONE atomic snapshot. That fused read exists solely to
        // close a mint-time TOCTOU (a revoke committing between a member read and a separate epoch
        // read lets a caller mint a validly-signed capability for an already-revoked subject,
        // stamped with the post-bump epoch — see `DeviceLookup::member_and_cap_epoch`'s own doc
        // comment for the full shape). With no mint on this path there is no epoch here to pair
        // with anything, so there is nothing left to race: the fused read moved, intact and with
        // its reasoning, to `on_verified`, which is now the only place a capability is minted.
        // **Do not reintroduce a mint here**, and if one ever does come back, it must come back
        // together with `member_and_cap_epoch` — never with a separate `cap_epoch()` call.
        let Some(member) = active_member_for_device(&self.lookup, *from_fp) else {
            return deny_with_equalized_work();
        };
        // Re-finding the device row is redundant with what `active_member_for_device` already
        // confirmed, but this module's house style never unwraps an invariant instead of failing
        // closed (see check 4's own comment for the same call) — an `expect` here would be the
        // one panic-shaped seam in an otherwise all-`Deny` function.
        let Some(device) = member.devices.iter().find(|d| d.device_fp == *from_fp) else {
            return deny_with_equalized_work();
        };

        // 6-9. Parse this device's stored keys and prove they are the exact preimage of its own
        // `device_fp` (missing key, unparseable key, missing/non-v1 `alg_id`, and the binding
        // rehash itself) — see `crate::device_keys::checked_device_keys`'s doc comment for the
        // check-by-check reasoning. That helper lives in its own module, not here, because
        // `crate::server`'s per-request upload-manifest path (`VfsRpcServer::verify_manifest_signature`)
        // needs the identical check, and the two paths used to disagree about it (td-ad318f): the
        // connect path rehashed before trusting the stored keys, the request path did not. The
        // helper knows nothing about connect-path denial policy, so that policy is spelled out
        // here at the call site instead.
        //
        // td-4bcf24 review note: routing `DeviceKeyError::Unverifiable` through
        // `deny_with_equalized_work()` was flagged as "over-equalized" (a failed decompression is
        // already cheaper than a real `Allow`, so equalizing it further supposedly widens rather
        // than closes the gap). That finding is wrong; recorded here so a future reviewer does not
        // re-raise it. Let D = the cost of `checked_verifying_key`'s point decompression (td-b8c68a:
        // the RFC 8032 canonicality pre-check plus `VerifyingKey::from_bytes`), H = the cost of the
        // `device_fp_of` rehash (combined with an `Allow`'s later work), and Df = the (smaller)
        // cost of a decompression that fails fast. A real `Allow` pays D+H. Without
        // equalization, a failed-decompression `Deny` pays only Df — off from `Allow` by the full
        // D+H, a large gap. WITH equalization (`deny_with_equalized_work` redoes a successful
        // decompression + rehash against the fixed dummy key), this `Deny` pays Df+D+H — off from
        // `Allow` by only Df, a tiny gap. Df+D+H is strictly closer to D+H than Df alone is:
        // equalizing here is strictly closer to indistinguishable, not further from it.
        //
        // `DeviceKeyError::BindingMismatch`'s `Deny` stays PLAIN — never routed through
        // `deny_with_equalized_work()` — and that is deliberate, not a missed spot: every
        // `Unverifiable` case above denies *before* performing the real
        // `checked_verifying_key`/`X25519PublicKey::from`/`device_fp_of` work an `Allow` also
        // does, so equalizing them against a dummy recompute closes a real faster-than-`Allow`
        // gap. A binding mismatch has already paid that exact cost for real (both key parses, the
        // rehash itself) before reaching here — there is no gap left to close. Adding a second,
        // redundant `equalize_denial_work()` call here would not equalize anything; it would make
        // this specific `Deny` measurably *slower* than an `Allow` reaches the same point,
        // manufacturing a new timing asymmetry pointing the other way.
        let (sign_pk, agree_pk) = match checked_device_keys(device, from_fp) {
            Ok(keys) => (keys.sign_pk, keys.agree_pk),
            Err(DeviceKeyError::BindingMismatch) => return ConnectDecision::Deny,
            Err(DeviceKeyError::Unverifiable) => return deny_with_equalized_work(),
        };

        // There is deliberately no check 10 here any more. Minting the opportunistic member
        // capability (DESIGN.md:286) moved to `on_verified`, below — td-fc5a30: an Ed25519
        // signature is a per-identity cost, and charging one for an unverified, attacker-chosen
        // `from_fp` hands any peer a free signature per packet it sends.
        //
        // Removing it makes `equalize_denial_work` STRICTLY STRONGER, and that is worth stating
        // because it reverses a caveat that function's own doc comment carried for as long as the
        // mint lived here. With a `CapIssuer` installed, an `Allow` used to perform an Ed25519
        // signature (measured ≈16.7 µs/call) that no `Deny` path could match — an asymmetry
        // roughly 5x LARGER than the parse/rehash gap the equalization closes (≈3.3 µs/call), and
        // one the equalization could not close without handing a flooder exactly the CPU-cost
        // amplification the rate limiter exists to deny. That asymmetry is now gone from this
        // method entirely: every `Allow` returned here does the same parse-and-rehash work and
        // nothing more, so `equalize_denial_work`'s ≈3.3 µs now imitates the whole of what an
        // `Allow` actually does rather than a fraction of it. Nothing about the equalization
        // machinery changed — it simply now has a smaller thing to imitate.
        ConnectDecision::Allow { sign_pk, agree_pk }
    }

    /// The post-verification half (td-fc5a30). Reached only after
    /// `spindle_net::signaling::host::process_offer` has verified the offer's Ed25519 signature
    /// under the `sign_pk` [`Self::authorize`] returned for this same `from_fp`, and after every
    /// routing check has passed — so `from_fp` is **authenticated** here, not merely claimed.
    ///
    /// Both things this method does are per-identity costs, which is exactly why they live here
    /// and not in [`Self::authorize`]: the per-`from_fp` token bucket (plus the bounded-map slot
    /// that comes with it) and the member-capability mint. A peer that can sign as `from_fp` *is*
    /// `from_fp`, so charging it is charging the party responsible for the work. Moving either
    /// back into [`Self::authorize`] reintroduces td-fc5a30's targeted denial-of-service — see
    /// that method's check 0 comment and [`ConnectRateLimiter`]'s doc comment.
    async fn on_verified(&self, from_fp: &Fingerprint) -> VerifiedDecision {
        // The per-`from_fp` token bucket DESIGN.md §A5 calls for, charged at the first moment
        // `from_fp` means anything. A refusal is a PLAIN `Drop` with no equalization work of any
        // kind, for two reasons that both differ from check 0's:
        // - this peer is authenticated, so revealing that its own bucket is empty is not a
        //   membership oracle. It already knows it is a member; it just proved it. There is
        //   nothing here for equalized timing to hide;
        // - `equalize_denial_work` exists to make a `Deny` look like an `Allow` to an *unknown*
        //   caller. This caller is known, and the connect is being throttled precisely to make it
        //   cheap. Spending crypto work to disguise a throttle would defeat the throttle.
        if !self.limiter.try_acquire_fp(*from_fp, (self.now_fn)()) {
            return VerifiedDecision::Drop;
        }

        // No issuer installed: nothing to mint, and — importantly — no second store read at all.
        // A host with no cap-signing key online pays exactly one lookup per connect, the same as
        // before this split.
        let Some(issuer) = &self.issuer else {
            return VerifiedDecision::Proceed { member_cap: None };
        };

        // Minting needs two things `authorize` did not carry across: the member's `root_fp` (the
        // cap's `subject`) and the host's current `cap_epoch`. So the lookup is redone here rather
        // than plumbed through the `ConnectDecision`. That is one extra store read, and it is
        // deliberately acceptable:
        // - it happens on the SUCCESS path only. Every denial — unknown fp, revoked member,
        //   revoked device, unverifiable keys, a failed signature, a mismatched inbox — returns
        //   before this method is ever called, so an attacker cannot provoke it at all;
        // - it is FRESHER. `authorize` ran before the signature check, the AEAD decryption, and
        //   the routing checks; this read reflects the store as of now. A revoke that committed in
        //   between is observed here, and (via `liveness_checks` below) results in no cap being
        //   minted — the correct outcome.
        //
        // `member_and_cap_epoch`, never `member_for_device_fp` + `cap_epoch()`: the member and the
        // epoch stamped onto the cap must come from ONE database-level snapshot. Two independent
        // reads let `Store::revoke_member_and_bump_epoch` / `revoke_device_and_bump_epoch` commit
        // in the window between them, pairing a pre-revoke member with a post-bump epoch and
        // minting a validly-signed capability for an already-revoked subject that is
        // indistinguishable from a legitimately fresh one — defeating `cap_epoch`'s entire purpose
        // as the revocation-invalidation mechanism (DESIGN.md §A4). See
        // `DeviceLookup::member_and_cap_epoch`'s own doc comment for the full statement of that
        // race; this call site is the one that carries the hazard.
        let (member, cap_epoch) = match self.lookup.member_and_cap_epoch(*from_fp) {
            Ok(pair) => pair,
            Err(e) => {
                // Carried over verbatim in substance from the old check 10's rule (`CapIssuer`'s
                // doc comment): a cap-issuance failure must NEVER be worse than the status quo.
                // The peer has already proven it is who it says it is and every membership check
                // has already passed in `authorize` — a store read failing *now* means only that
                // this host cannot mint a fresh cap this time, so the connect proceeds with
                // `member_cap: None` and the peer falls back to whatever cap it already holds.
                // Returning `Drop` here would take a working, fully-verified connect and break it
                // over a problem (a transient `SQLITE_BUSY`, say — reachable because
                // `spindle-hostd` holds multiple independent connections to the same database
                // file) that has nothing to do with whether this device may connect. That would be
                // the fleet-wide lockout DESIGN.md:288-290's renewal path exists to prevent.
                //
                // Audited 2026-09-08: `%e` is a `LookupError`, whose only reachable content here
                // is a `rusqlite` message from this host's own store (its path is operator
                // configuration, exempt — see this crate's `lib.rs` `tracing` section) or a
                // fingerprint *length* complaint. `LookupError::Store` is typed over all of
                // `StoreError` though, and that enum's `Confine`/`Model`/`MountPathCollision`/
                // `DeviceNotFound` variants do carry real paths, virtual paths, and untruncated
                // fingerprints — so anything that widens what these lookups call must re-check
                // this line rather than trusting the redaction guard, which only reads binding
                // names.
                tracing::warn!(
                    device_fp = %from_fp.redacted(),
                    error = %e,
                    "on_verified: member_and_cap_epoch failed after the offer's signature \
                     verified; proceeding with no freshly-minted member capability. The connect \
                     is NOT denied — an issuance failure must never break an otherwise-valid \
                     connect — but a persistent recurrence silently degrades this host to never \
                     minting fresh member capabilities"
                );
                return VerifiedDecision::Proceed { member_cap: None };
            }
        };

        // Re-apply §A4's liveness rule to this fresher snapshot. A member (or this device) revoked
        // since `authorize` ran must not be minted a fresh capability — but, per the rule above,
        // that still is not a `Drop`: `authorize` is the authority on whether this connect is
        // permitted, and it already answered. This only decides whether a cap is issued.
        //
        // `subject` is `member.root_fp`, not `from_fp`/`device_fp` — DESIGN.md:286: "`subject =
        // root_fp` so every root-certified device of the person may use it". Scoping the cap to
        // the device fp instead would silently restrict it to the one device that happened to
        // connect, breaking every other device the same person owns.
        //
        // `cap_epoch` can legitimately be `None` even here — see `DeviceLookup::
        // member_and_cap_epoch`'s doc comment: a tolerated `cap_epoch` read failure (e.g.
        // `SQLITE_BUSY` on `meta`) reaches this point as `Ok((member, None))`, not as the `Err`
        // arm above. The `match` spells out every combination rather than `unwrap`ping an epoch
        // that might not be there: "member is live" and "epoch available" are independent facts,
        // and this module's house style never unwraps an invariant instead of failing closed.
        let member_cap = match (liveness_checks(member, *from_fp), cap_epoch) {
            (Some(member), Some(cap_epoch)) => issuer.issue_member_cap(member.root_fp, cap_epoch),
            _ => None,
        };
        VerifiedDecision::Proceed { member_cap }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratelimit::RateLimitConfig;
    use spindle_core::artifacts::{issue_host_op_key_cert, verify_capability};
    use spindle_core::identity::{DeviceKey, RootKey};
    use spindle_vfs::model::{Device, DevicePublicKeys, MemberId};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
            alg_id: ALG_ID_V1,
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
            ConnectDecision::Allow { sign_pk, agree_pk } => {
                assert_eq!(sign_pk, device.sign_public_key());
                assert_eq!(agree_pk, device.agree_public_key());
            }
            ConnectDecision::Deny => panic!("expected Allow for an active member's own device"),
        }
        assert_eq!(
            authorizer.on_verified(&device_fp).await,
            VerifiedDecision::Proceed { member_cap: None },
            "HostConnectAuthorizer::new deliberately installs no cap-issuing seam -- it must \
             supply None, never fabricate a cap"
        );
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
            alg_id: ALG_ID_V1,
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
    async fn denies_a_device_whose_stored_alg_id_is_null_despite_both_keys_being_present() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x0f; 32], [0x10; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);

        // `add_device` always writes `alg_id` from the very `Option` that supplies the keys (see
        // `Store::add_device`'s doc comment), so no legitimate caller can leave `alg_id` `NULL`
        // next to present keys. `set_device_alg_id_for_test` (a `spindle-vfs` `test-support`-
        // feature-gated method, enabled only via this crate's dev-dependency edge on `spindle-vfs`
        // — see that crate's `Cargo.toml`) is the honest way to test a fail-closed guard against a
        // row nothing else can create, not a workaround for a missing API.
        store
            .set_device_alg_id_for_test(device_fp, None)
            .expect("set_device_alg_id_for_test");

        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store));
        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!(
                "expected Deny: alg_id is NULL even though both keys are present — impossible \
                 after the SCHEMA_V9 backfill via any real write path, but this module's house \
                 style never unwraps an invariant instead of failing closed"
            ),
        }
    }

    #[tokio::test]
    async fn denies_a_device_whose_stored_alg_id_names_an_unsupported_algorithm() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x11; 32], [0x12; 32]);

        // This row must be *self-consistent* under alg_id = 2, not merely have its alg_id column
        // flipped after enrolling under alg 1 (that was this test's original, broken shape — see
        // below). A device_fp genuinely committed to alg 2 is
        // `device_fp_of(2, sign_pk, agree_pk)`, so that is what gets stored as `device_fp` here —
        // deliberately NOT `device.device_fp()`, which is `device_fp_of(ALG_ID_V1, ..)` and would
        // leave the row internally inconsistent (a fingerprint computed under alg 1, sitting next
        // to an alg_id column claiming 2).
        //
        // Why the self-consistent row matters: check 9, a few lines below check 8 in
        // `authorize()`, recomputes `device_fp_of(alg_id, sign_pk, agree_pk)` from the row's OWN
        // `alg_id` field and compares it against `from_fp`. If the row is inconsistent (fp under
        // alg 1, column says 2), check 9's recompute uses alg_id = 2 and produces a hash that does
        // NOT match the stored (alg-1) `device_fp` — so check 9 denies on its own, and check 8
        // never gets exercised at all. That was this test's original defect: it asserted `Deny`
        // for the right verdict but the wrong reason, and proved nothing about check 8. Emptying
        // check 8 (deleting its `if alg_id != ALG_ID_V1 { return Deny }`) left the whole
        // `spindle-host-core` suite green, because check 9 covered the inconsistent-row case check
        // 8 was never actually exercised on.
        //
        // With the row self-consistent (fp genuinely derived under alg 2, column says 2), check
        // 9's recompute matches `from_fp` and check 9 ALLOWS. Check 8 is then the only thing
        // standing between this row and an `Allow` — exactly the case check 8 exists to guard:
        // `sign_pk`/`agree_pk` are parsed as Ed25519/X25519 unconditionally regardless of what
        // `alg_id` claims, so this code path cannot actually verify an alg-2 device even though
        // its fingerprint checks out.
        //
        // A future reader tempted to "simplify" this back to `enroll_device` +
        // `set_device_alg_id_for_test` should not — that simpler-looking shape is precisely the
        // broken version this comment describes.
        let alg2_fp = device_fp_of(2, &device.sign_public_key(), &device.agree_public_key());
        let keys = DevicePublicKeys {
            // `Store::add_device` rejects any `keys.alg_id != ALG_ID_V1` (see its doc comment and
            // implementation), so the row must be written as alg 1 first and flipped to 2
            // afterward via `set_device_alg_id_for_test` — `add_device` does not otherwise
            // validate the `device_fp`/keys binding (see its own doc comment; `store/mod.rs`'s
            // tests rely on the same non-validation to store deliberately mismatched keys), so
            // storing `alg2_fp` next to `ALG_ID_V1` keys here is legal.
            alg_id: ALG_ID_V1,
            sign_pk: device.sign_public_key().as_bytes().to_vec(),
            agree_pk: device.agree_public_key().as_bytes().to_vec(),
        };
        // `enroll_device` hardcodes `device.device_fp()` (alg-1) as the stored fingerprint, so it
        // cannot produce this row — call `Store::add_device` directly with `alg2_fp` instead.
        store
            .add_device(member_id, alg2_fp, "laptop", 0, Some(&keys))
            .expect("add_device");
        store
            .set_device_alg_id_for_test(alg2_fp, Some(2))
            .expect("set_device_alg_id_for_test");

        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store));
        match authorizer.authorize(&alg2_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!(
                "expected Deny: alg_id = 2 names an algorithm this code path parses sign_pk/\
                 agree_pk as neither of — sign_pk/agree_pk are parsed as Ed25519/X25519 \
                 unconditionally, so a row claiming another algorithm cannot be verified here, \
                 even though this row's device_fp genuinely commits to alg 2 and so passes check \
                 9's recompute"
            ),
        }
    }

    #[tokio::test]
    async fn denies_a_device_whose_stored_alg_id_is_out_of_range_rather_than_truncating_to_v1() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x13; 32], [0x14; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);

        // `devices.alg_id` is a SQLite `INTEGER` column (i64-domain), so a corrupted or tampered
        // row can hold a raw value no real `u8`-typed writer would ever produce — 257, in
        // particular. Before the `Store::devices_for_member` fix this test proves, that value was
        // read with `alg_id.map(|a| a as u8)`, and `257 as u8` truncates (modulo 256) to `1`,
        // which is `ALG_ID_V1` — so this exact row would have been silently treated as "verified
        // v1" and ALLOWED, defeating check 8 entirely. `u8::try_from` makes the conversion total
        // instead: an out-of-range value becomes `None`, which is denied fail-closed exactly like
        // any other unverifiable row. `set_device_alg_id_for_test` takes `Option<i64>` (not
        // `Option<u8>`) precisely so a test can reach this otherwise-unwritable value.
        store
            .set_device_alg_id_for_test(device_fp, Some(257))
            .expect("set_device_alg_id_for_test");

        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store));
        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!(
                "expected Deny: alg_id = 257 is out of u8 range and must not truncate to a \
                 valid-looking ALG_ID_V1 (1) — before the fix, `257 as u8 == 1` and this row \
                 would have been ALLOWED"
            ),
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

            fn member_and_cap_epoch(
                &self,
                _device_fp: Fingerprint,
            ) -> Result<(Option<Member>, Option<u64>), LookupError> {
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
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Deny => panic!("expected Allow for an active member's own device"),
        }
        // The mint lives behind the signature-verification boundary (td-fc5a30), so the cap comes
        // from `on_verified`, not from `authorize`'s `Allow`.
        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Proceed { member_cap } => {
                let cap = member_cap.expect("with_issuer must mint a cap for a verified connect");
                verify_capability(&cap, 1_000)
                    .expect("the minted cap must verify its own root -> op-key -> sig chain");
            }
            VerifiedDecision::Drop => panic!("expected Proceed for an active member's own device"),
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

        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Proceed { member_cap } => {
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
            VerifiedDecision::Drop => panic!("expected Proceed for an active member's own device"),
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

        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Proceed { member_cap } => {
                let cap = member_cap.expect("with_issuer must mint a cap");
                assert_eq!(cap.kind, CapKind::Member);
                assert_eq!(cap.exp, now + MEMBER_CAP_DEFAULT_TTL_SECS);
            }
            VerifiedDecision::Drop => panic!("expected Proceed for an active member's own device"),
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

        let first_epoch = match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Proceed { member_cap } => {
                member_cap.expect("with_issuer must mint a cap").cap_epoch
            }
            VerifiedDecision::Drop => panic!("expected Proceed"),
        };

        // Independent connection #2, to the same file: bumps the epoch out from under the
        // authorizer's own connection. SQLite serializes commits across connections to one file,
        // so the authorizer's next `cap_epoch()` read must observe this.
        let bumping_store = Store::open(&path).expect("open second store handle");
        let bumped_epoch = bumping_store.bump_cap_epoch().expect("bump_cap_epoch");
        assert_eq!(bumped_epoch, first_epoch + 1);

        let second_epoch = match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Proceed { member_cap } => {
                member_cap.expect("with_issuer must mint a cap").cap_epoch
            }
            VerifiedDecision::Drop => panic!("expected Proceed"),
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

        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Proceed { member_cap } => {
                assert_eq!(
                    member_cap, None,
                    "issuance failure must never turn an otherwise-valid connect into a Drop, \
                     but it also must not fabricate a cap"
                );
            }
            VerifiedDecision::Drop => {
                panic!("issuance failure must never turn an otherwise-valid connect into a Drop")
            }
        }
    }

    /// A [`DeviceLookup`] wrapping a real [`SqliteDeviceLookup`] but discarding the epoch half of
    /// [`DeviceLookup::member_and_cap_epoch`]'s result — simulating the tolerated failure
    /// `SqliteDeviceLookup::member_and_cap_epoch`'s own doc comment describes (a `cap_epoch` read
    /// hitting `SQLITE_BUSY` on `meta` while membership itself was read fine). Delegates
    /// `member_for_device_fp` and `cap_epoch` unchanged so any path that doesn't go through
    /// `member_and_cap_epoch` behaves exactly like the plain `SqliteDeviceLookup`.
    struct EpochUnavailableDeviceLookup {
        inner: SqliteDeviceLookup,
    }

    impl DeviceLookup for EpochUnavailableDeviceLookup {
        fn member_for_device_fp(
            &self,
            device_fp: Fingerprint,
        ) -> Result<Option<Member>, LookupError> {
            self.inner.member_for_device_fp(device_fp)
        }

        fn cap_epoch(&self) -> Result<u64, LookupError> {
            self.inner.cap_epoch()
        }

        fn member_and_cap_epoch(
            &self,
            device_fp: Fingerprint,
        ) -> Result<(Option<Member>, Option<u64>), LookupError> {
            let (member, _epoch) = self.inner.member_and_cap_epoch(device_fp)?;
            Ok((member, None))
        }
    }

    /// The regression this whole slice exists to fix: a `DeviceLookup::member_and_cap_epoch` that
    /// reads membership fine but cannot read `cap_epoch` (`Ok((Some(live_member), None))`) must
    /// still `Allow` — with no minted cap, since there is no epoch to mint from — even though a
    /// `CapIssuer` is installed. Conflating this with a genuine `Err` (see
    /// `denies_when_the_lookup_returns_a_genuine_error_and_an_issuer_is_installed` below) would
    /// deny every connect on a transient `SQLITE_BUSY` reading `meta`, exactly the lockout
    /// DESIGN.md:288-290's renewal path exists to prevent.
    #[tokio::test]
    async fn ok_member_with_no_cap_epoch_still_allows_with_no_minted_cap_when_issuer_is_installed()
    {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x33; 32], [0x34; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let lookup = EpochUnavailableDeviceLookup {
            inner: SqliteDeviceLookup::new(store),
        };
        let issuer = test_cap_issuer([0x35; 32], [0x36; 32], 1_000);
        let authorizer = HostConnectAuthorizer::with_issuer(lookup, Box::new(issuer));

        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Proceed { member_cap } => {
                assert_eq!(
                    member_cap, None,
                    "Ok((Some(live_member), None)) from member_and_cap_epoch means membership is \
                     fine but there is no fresh cap_epoch to mint from this time -- Proceed with \
                     no cap is correct, the same 'issuance failure is never worse than the status \
                     quo' rule CapIssuer's doc comment states for a failing issuer"
                );
            }
            VerifiedDecision::Drop => panic!(
                "regression: an active, non-revoked member's connect must not be denied just \
                 because member_and_cap_epoch could not read cap_epoch -- that conflates 'no fresh \
                 cap this time' with 'membership is unprovable', which would turn a transient \
                 SQLITE_BUSY on Store::cap_epoch (reachable because spindle-hostd holds multiple \
                 independent connections to the same database file) into a host that refuses every \
                 connect"
            ),
        }
    }

    /// The other half of the same discrimination: a genuine [`LookupError`] from
    /// `member_and_cap_epoch` — membership itself unprovable — must still `Deny`, with an issuer
    /// installed and never reached. This is [`denies_when_a_lookup_returns_an_error`]'s twin on
    /// the `with_issuer` path: that test's `AlwaysFails` lookup goes through
    /// `active_member_for_device` because it uses `HostConnectAuthorizer::new` (no issuer), never
    /// exercising `member_and_cap_epoch`'s own `Err` arm at all.
    #[tokio::test]
    async fn denies_when_the_lookup_returns_a_genuine_error_and_an_issuer_is_installed() {
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

            fn member_and_cap_epoch(
                &self,
                _device_fp: Fingerprint,
            ) -> Result<(Option<Member>, Option<u64>), LookupError> {
                Err(LookupError::LockPoisoned)
            }
        }

        let issuer = test_cap_issuer([0x37; 32], [0x38; 32], 1_000);
        let authorizer = HostConnectAuthorizer::with_issuer(AlwaysFails, Box::new(issuer));
        let some_fp = DeviceKey::from_seeds([0x39; 32], [0x3a; 32]).device_fp();

        match authorizer.authorize(&some_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!(
                "a genuine Err from member_and_cap_epoch means membership is unprovable -- must \
                 fail closed even with an issuer installed"
            ),
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

        // td-fc5a30: the issuer is now unreachable from `authorize` for ANY fingerprint, denied or
        // not -- `process_offer` never calls `on_verified` for an offer whose signature did not
        // verify, so a denied device could not reach it even if it tried. Asserting the count is
        // still 0 after the `on_verified` half runs for this same unenrolled fp pins the other
        // half of the rule: a lookup that finds no live member mints nothing (and, per
        // `CapIssuer`'s doc comment, still Proceeds rather than Dropping).
        assert_eq!(
            authorizer.on_verified(&stranger).await,
            VerifiedDecision::Proceed { member_cap: None },
            "on_verified for a fp with no live member must Proceed with no cap, never Drop -- an \
             issuance failure must not break an otherwise-valid connect"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no live member means nothing to mint for, so the issuer is still never reached"
        );
    }

    // ---- TOCTOU: member_and_cap_epoch must read member + cap_epoch as one snapshot (td brief) --

    /// Which half of DESIGN.md §A4's liveness rule [`RacingDeviceLookup`] revokes when its
    /// simulated race lands — the two axes the task brief asks this suite to cover.
    #[derive(Clone, Copy)]
    enum RaceKind {
        /// The member itself is revoked mid-window (its device stays enrolled and non-revoked).
        Member,
        /// Only the one device is revoked mid-window; its member stays `Active`.
        Device,
    }

    struct RaceState {
        member: Member,
        device_fp: Fingerprint,
        epoch: u64,
        kind: RaceKind,
        /// Set the first time any call lands the simulated race, so a second call doesn't
        /// revoke/bump twice. The race lands as a side effect of [`RacingDeviceLookup::
        /// member_for_device_fp`] specifically -- see that method and the struct doc comment.
        landed: bool,
    }

    /// A [`DeviceLookup`] test double reproducing the exact TOCTOU window a two-read `authorize`
    /// left open, to prove [`DeviceLookup::member_and_cap_epoch`] actually closes it.
    ///
    /// [`Self::member_for_device_fp`] returns a snapshot of the member *before* any revoke, then —
    /// as a side effect of that call returning, simulating a concurrent
    /// `Store::revoke_member_and_bump_epoch` / `revoke_device_and_bump_epoch` transaction
    /// committing in the window right after this read released its lock — flips its internal
    /// state: the member or its device becomes revoked, and `cap_epoch` is bumped, exactly as
    /// `Store` does both atomically in one transaction. A later, *separate* [`Self::cap_epoch`]
    /// call then observes that post-revoke epoch. This is precisely the shape the two-read version
    /// of `authorize` used to have: a member read, then, after other checks ran, an independent
    /// epoch read.
    ///
    /// [`Self::member_and_cap_epoch`] never goes through that side effect: it reads the member and
    /// the epoch from the current state in one step, under one lock — the entire guarantee that
    /// method exists to provide. Called exactly once, the way the fixed `authorize` calls it, it
    /// therefore always returns a self-consistent pair reflecting one instant, never a
    /// pre-revoke member paired with a post-revoke epoch.
    ///
    /// That alone only discriminates against the *old shape* of the bug (a `member_for_device_fp`
    /// call followed by a separate `cap_epoch` call): `member_and_cap_epoch` here is idempotent
    /// and never lands the race, so a regression to calling `member_and_cap_epoch` *twice* (taking
    /// the member from the first call and the epoch from the second) would sail through unnoticed.
    /// `calls` closes that gap: every [`DeviceLookup`] method on this double increments it, and
    /// the tests assert it is exactly 1 after `authorize` returns -- proving `authorize` performs
    /// exactly one lookup call of any kind, not merely "not the old two-call shape".
    struct RacingDeviceLookup {
        state: Mutex<RaceState>,
        calls: AtomicUsize,
    }

    impl RacingDeviceLookup {
        fn new(member: Member, device_fp: Fingerprint, epoch: u64, kind: RaceKind) -> Self {
            RacingDeviceLookup {
                state: Mutex::new(RaceState {
                    member,
                    device_fp,
                    epoch,
                    kind,
                    landed: false,
                }),
                calls: AtomicUsize::new(0),
            }
        }

        /// Total number of [`DeviceLookup`] calls (of any of the three methods) made on this
        /// double. The minting path (`on_verified` since td-fc5a30) must leave this at exactly 1:
        /// any second call, even a second `member_and_cap_epoch`, is a second read of what would
        /// be a racing store.
        fn lookup_calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl DeviceLookup for RacingDeviceLookup {
        fn member_for_device_fp(
            &self,
            _device_fp: Fingerprint,
        ) -> Result<Option<Member>, LookupError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut state = self.state.lock().map_err(|_| LookupError::LockPoisoned)?;
            let snapshot = state.member.clone();
            if !state.landed {
                state.landed = true;
                match state.kind {
                    RaceKind::Member => state.member.status = MemberStatus::Revoked,
                    RaceKind::Device => {
                        let device_fp = state.device_fp;
                        if let Some(d) = state
                            .member
                            .devices
                            .iter_mut()
                            .find(|d| d.device_fp == device_fp)
                        {
                            d.revoked = true;
                        }
                    }
                }
                state.epoch += 1;
            }
            Ok(Some(snapshot))
        }

        fn cap_epoch(&self) -> Result<u64, LookupError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let state = self.state.lock().map_err(|_| LookupError::LockPoisoned)?;
            Ok(state.epoch)
        }

        fn member_and_cap_epoch(
            &self,
            _device_fp: Fingerprint,
        ) -> Result<(Option<Member>, Option<u64>), LookupError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // One lock, one read of both fields -- the race never gets a chance to land "between"
            // them, because there is no between: this whole method is the atomic snapshot.
            let state = self.state.lock().map_err(|_| LookupError::LockPoisoned)?;
            Ok((Some(state.member.clone()), Some(state.epoch)))
        }
    }

    /// Forwards through an `Arc` so the tests can hold onto the double (to read `lookup_calls`
    /// after `with_issuer` consumes its lookup by value) while still handing it an owned
    /// `L: DeviceLookup`.
    impl DeviceLookup for std::sync::Arc<RacingDeviceLookup> {
        fn member_for_device_fp(
            &self,
            device_fp: Fingerprint,
        ) -> Result<Option<Member>, LookupError> {
            (**self).member_for_device_fp(device_fp)
        }

        fn cap_epoch(&self) -> Result<u64, LookupError> {
            (**self).cap_epoch()
        }

        fn member_and_cap_epoch(
            &self,
            device_fp: Fingerprint,
        ) -> Result<(Option<Member>, Option<u64>), LookupError> {
            (**self).member_and_cap_epoch(device_fp)
        }
    }

    fn racing_member_and_device(device: &DeviceKey, device_fp: Fingerprint) -> Member {
        Member {
            member_id: MemberId(1),
            root_fp: Fingerprint::of_parts(&[b"racing-member"]),
            display_name: "racer".to_string(),
            status: MemberStatus::Active,
            devices: vec![Device {
                device_fp,
                label: "laptop".to_string(),
                added: 0,
                revoked: false,
                sign_pk: Some(device.sign_public_key().as_bytes().to_vec()),
                agree_pk: Some(device.agree_public_key().as_bytes().to_vec()),
                alg_id: Some(ALG_ID_V1),
            }],
            groups: vec![],
            created: 0,
        }
    }

    #[tokio::test]
    async fn atomic_snapshot_survives_a_member_revoked_in_the_window_between_the_old_two_reads() {
        let device = DeviceKey::from_seeds([0x2b; 32], [0x2c; 32]);
        let device_fp = device.device_fp();
        let member = racing_member_and_device(&device, device_fp);
        let epoch_before_race = 41;
        let lookup = Arc::new(RacingDeviceLookup::new(
            member,
            device_fp,
            epoch_before_race,
            RaceKind::Member,
        ));
        let issuer = test_cap_issuer([0x2d; 32], [0x2e; 32], 1_000);
        let authorizer = HostConnectAuthorizer::with_issuer(Arc::clone(&lookup), Box::new(issuer));

        // td-fc5a30 moved the mint from `authorize` to `on_verified`, so the minting path this
        // test exercises is `on_verified`. The property is unchanged: whichever method mints must
        // read the member and the epoch through exactly ONE `DeviceLookup` call.
        let decision = authorizer.on_verified(&device_fp).await;
        assert_eq!(
            lookup.lookup_calls(),
            1,
            "`on_verified` must make exactly ONE DeviceLookup call on the minting path. A second \
             call -- even another `member_and_cap_epoch` -- is a second read of a store a \
             concurrent revoke can commit into between them, which is exactly the TOCTOU \
             `member_and_cap_epoch` exists to close."
        );
        match decision {
            VerifiedDecision::Proceed { member_cap } => {
                let cap = member_cap.expect(
                    "the member was Active in the atomic snapshot this call took -- must mint",
                );
                assert_eq!(
                    cap.cap_epoch, epoch_before_race,
                    "the minted cap's cap_epoch must come from the SAME atomic snapshot that \
                     showed the member Active, not a later, separately-read epoch bumped by a \
                     member revoke landing in the window between two reads. A cap combining a \
                     member snapshot from before such a revoke with the post-bump epoch would be \
                     indistinguishable from a legitimately fresh cap to any consumer that only \
                     checks cap.cap_epoch against the host's current cap_epoch -- defeating \
                     cap_epoch's entire purpose as the revocation-invalidation mechanism."
                );
            }
            VerifiedDecision::Drop => panic!(
                "expected Proceed: the atomic snapshot must see the member Active -- the simulated \
                 race only lands after a call returns, and `on_verified` must make exactly one \
                 DeviceLookup call on this path, never a second one for it to land before"
            ),
        }
    }

    #[tokio::test]
    async fn atomic_snapshot_survives_a_device_revoked_in_the_window_between_the_old_two_reads() {
        let device = DeviceKey::from_seeds([0x2f; 32], [0x30; 32]);
        let device_fp = device.device_fp();
        let member = racing_member_and_device(&device, device_fp);
        let epoch_before_race = 7;
        let lookup = Arc::new(RacingDeviceLookup::new(
            member,
            device_fp,
            epoch_before_race,
            RaceKind::Device,
        ));
        let issuer = test_cap_issuer([0x31; 32], [0x32; 32], 1_000);
        let authorizer = HostConnectAuthorizer::with_issuer(Arc::clone(&lookup), Box::new(issuer));

        // See the member-revoked twin above for why this drives `on_verified` (td-fc5a30).
        let decision = authorizer.on_verified(&device_fp).await;
        assert_eq!(
            lookup.lookup_calls(),
            1,
            "`on_verified` must make exactly ONE DeviceLookup call on the minting path. A second \
             call -- even another `member_and_cap_epoch` -- is a second read of a store a \
             concurrent revoke can commit into between them, which is exactly the TOCTOU \
             `member_and_cap_epoch` exists to close."
        );
        match decision {
            VerifiedDecision::Proceed { member_cap } => {
                let cap = member_cap.expect(
                    "the device was non-revoked in the atomic snapshot this call took -- must mint",
                );
                assert_eq!(
                    cap.cap_epoch, epoch_before_race,
                    "the minted cap's cap_epoch must come from the SAME atomic snapshot that \
                     showed this device non-revoked, not a later, separately-read epoch bumped by \
                     a device revoke landing in the window between two reads -- the member-revoked \
                     axis's twin: a still-Active member can have one revoked device among several, \
                     and that device's cap must not come out looking fresh either."
                );
            }
            VerifiedDecision::Drop => panic!(
                "expected Proceed: the atomic snapshot must see the device non-revoked -- the \
                 simulated race only lands after a call returns, and `on_verified` must make \
                 exactly one DeviceLookup call on this path, never a second one for it to land \
                 before"
            ),
        }
    }

    // ---- connect-rate limiting (td-4bcf24): DESIGN.md §A5/v0.9.24's per-`from_fp` + global token
    // bucket over the connect endpoint, and its timing/observable-behavior equalization -------

    /// The load-bearing test for `HostConnectAuthorizer`'s rate limiter being a security control,
    /// not an opt-in convenience: a plain `HostConnectAuthorizer::new(..)` -- never touching
    /// `with_connect_rate_limit` -- must still throttle. Covers the PER-FP half, which since
    /// td-fc5a30 is charged in `on_verified`, not `authorize`. If this regresses to `Proceed` on
    /// the 11th connect, `new`/`with_issuer` have silently stopped installing a real
    /// `ConnectRateLimiter`.
    #[tokio::test]
    async fn the_per_fp_rate_limiter_is_on_by_default_and_is_not_opt_in() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x40; 32], [0x41; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        // A frozen clock, so refill never masks the burst boundary -- `with_now_fn` is the only
        // knob touched here; `with_connect_rate_limit` deliberately is not, since this test exists
        // to prove the *default* config (installed by `new` with no further configuration) is
        // what's actually enforced.
        let authorizer =
            HostConnectAuthorizer::new(SqliteDeviceLookup::new(store)).with_now_fn(|| 0);

        // Each iteration is one whole connect: the pre-verification half, then the
        // post-verification half `spindle_net::signaling::host::process_offer` reaches once the
        // offer's signature has verified.
        for i in 0..10 {
            match authorizer.authorize(&device_fp).await {
                ConnectDecision::Allow { .. } => {}
                ConnectDecision::Deny => panic!(
                    "connect {i} must pass the pre-verification half: the default global burst \
                     (200) is nowhere near spent by 10 connects"
                ),
            }
            match authorizer.on_verified(&device_fp).await {
                VerifiedDecision::Proceed { .. } => {}
                VerifiedDecision::Drop => panic!(
                    "connect {i} of the documented default per-fp burst (10) must Proceed -- a \
                     live, active member device must not be throttled before its own burst is \
                     spent"
                ),
            }
        }
        assert!(
            matches!(
                authorizer.authorize(&device_fp).await,
                ConnectDecision::Allow { .. }
            ),
            "the 11th connect must still pass the pre-verification half -- the per-fp bucket is \
             not consulted there any more (td-fc5a30)"
        );
        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Drop => {}
            VerifiedDecision::Proceed { .. } => panic!(
                "the rate limiter is on by default and is NOT opt-in: HostConnectAuthorizer::new \
                 must install ConnectRateLimiter::new(ConnectRateLimitConfig::default()) even \
                 though this test never called with_connect_rate_limit. A Proceed on the 11th \
                 connect (one past the documented default per-fp burst of 10) would mean a host \
                 built via HostConnectAuthorizer::new silently ran with no per-fp rate limiting at \
                 all -- exactly the security regression this test exists to catch."
            ),
        }
    }

    /// The other half of the same default-on claim, and the one that matters most since
    /// td-fc5a30: the PRE-verification path -- the only one an unauthenticated peer can reach --
    /// must still be bounded, by the default global bucket, with no configuration. The documented
    /// default global burst is 200, so exactly 200 pre-verification calls are admitted at a frozen
    /// clock and the 201st is refused.
    ///
    /// This is the test that fails if a future edit removes the limiter from `authorize`
    /// altogether under the mistaken impression that td-fc5a30 moved *all* limiting to
    /// `on_verified`. It moved the per-identity half; the global half must stay exactly where it
    /// is, because nothing else bounds an offer whose signature will never verify.
    #[tokio::test]
    async fn the_global_rate_limiter_is_on_by_default_and_bounds_the_pre_verification_path() {
        let (store, _member_id) = store_with_active_member("alex");
        let authorizer =
            HostConnectAuthorizer::new(SqliteDeviceLookup::new(store)).with_now_fn(|| 0);

        // Fabricated, never-enrolled fingerprints -- exactly what a flood consists of. Each is
        // denied on membership, but check 0 runs first, so each still spends a global token.
        let fabricated =
            |i: usize| Fingerprint::of_parts(&[b"global-default-flood", &i.to_le_bytes()]);
        let default_global_burst = ConnectRateLimitConfig::default().global.burst as usize;
        assert_eq!(
            default_global_burst, 200,
            "this test's arithmetic tracks the documented default global burst"
        );

        for i in 0..default_global_burst {
            // Every one of these is a `Deny` on membership, which is fine: what is being counted
            // is whether check 0 let the request reach the membership lookup at all. The
            // distinction is made by the 201st call below, which must be denied *before* the
            // lookup -- proven by the equalization counter, which a membership denial increments
            // and a rate-limit denial does not.
            let _ = authorizer.authorize(&fabricated(i)).await;
        }

        reset_equalization_calls();
        match authorizer
            .authorize(&fabricated(default_global_burst))
            .await
        {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => unreachable!("a fabricated fp is never a member"),
        }
        assert_eq!(
            equalization_calls(),
            0,
            "the 201st pre-verification call must be refused by the DEFAULT global bucket at \
             check 0 -- before the membership lookup, and so without the equalized crypto work a \
             membership denial performs. A count of 1 here means check 0 admitted the request and \
             it was denied downstream on membership instead, i.e. the global bucket is not \
             actually bounding the pre-verification path at its documented default of 200."
        );
    }

    #[tokio::test]
    async fn denies_a_live_member_device_once_its_per_fp_burst_is_exhausted() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x42; 32], [0x43; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store))
            .with_now_fn(|| 0)
            .with_connect_rate_limit(ConnectRateLimitConfig {
                per_fp: RateLimitConfig {
                    burst: 2.0,
                    refill_per_sec: 0.0,
                },
                global: ConnectRateLimitConfig::default().global,
                max_tracked_fps: ConnectRateLimitConfig::default().max_tracked_fps,
            });

        // The per-fp bucket is charged in `on_verified` (td-fc5a30), so that is what this test
        // drives. `authorize` would never observe it.
        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Proceed { .. } => {}
            VerifiedDecision::Drop => panic!("first connect must Proceed: per-fp burst is 2"),
        }
        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Proceed { .. } => {}
            VerifiedDecision::Drop => panic!("second connect must Proceed: per-fp burst is 2"),
        }
        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Drop => {}
            VerifiedDecision::Proceed { .. } => panic!(
                "third connect must Drop: the per-fp burst of 2 is exhausted, refill_per_sec is \
                 0, and the clock is frozen at the same instant -- even a genuinely live, active \
                 member device that has just proven its signature is throttled once its own \
                 bucket is empty"
            ),
        }
    }

    #[tokio::test]
    async fn a_throttled_device_is_allowed_again_once_its_bucket_refills() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x44; 32], [0x45; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let clock = Arc::new(AtomicU64::new(0));
        let clock_for_fn = Arc::clone(&clock);
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store))
            .with_now_fn(move || clock_for_fn.load(Ordering::SeqCst))
            .with_connect_rate_limit(ConnectRateLimitConfig {
                per_fp: RateLimitConfig {
                    burst: 1.0,
                    refill_per_sec: 1.0,
                },
                global: ConnectRateLimitConfig::default().global,
                max_tracked_fps: ConnectRateLimitConfig::default().max_tracked_fps,
            });

        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Proceed { .. } => {}
            VerifiedDecision::Drop => {
                panic!("first connect must Proceed: burst is 1 and the bucket starts full")
            }
        }
        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Drop => {}
            VerifiedDecision::Proceed { .. } => panic!(
                "second connect at the same instant must Drop: burst of 1 is exhausted and the \
                 clock has not advanced"
            ),
        }
        clock.store(1, Ordering::SeqCst);
        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Proceed { .. } => {}
            VerifiedDecision::Drop => panic!(
                "one second later, at refill_per_sec = 1.0, exactly one token has refilled -- \
                 this connect must Proceed"
            ),
        }
    }

    /// Proves DESIGN.md v0.9.24's accepted "shared fate" cost is real and intentional, not a bug:
    /// a flood that rotates its claimed `from_fp` on every attempt cannot be stopped by the per-fp
    /// bucket alone (each fabricated fp starts with a fresh, full bucket), so the global bucket is
    /// the only thing that can bound it -- and spending it costs *every* caller, including a
    /// genuinely live member device, not just the flooder. The alternative (no global bound) lets
    /// identity rotation defeat throttling entirely, which DESIGN.md judges strictly worse than
    /// this shared cost.
    #[tokio::test]
    async fn a_flood_that_rotates_from_fp_is_stopped_by_the_global_bucket() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x46; 32], [0x47; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store))
            .with_now_fn(|| 0)
            .with_connect_rate_limit(ConnectRateLimitConfig {
                per_fp: RateLimitConfig {
                    burst: 1000.0,
                    refill_per_sec: 1000.0,
                },
                global: RateLimitConfig {
                    burst: 3.0,
                    refill_per_sec: 0.0,
                },
                max_tracked_fps: ConnectRateLimitConfig::default().max_tracked_fps,
            });

        // Three fabricated, never-enrolled fingerprints. Each is denied on membership (checks
        // 1-2), but check 0 -- the rate limiter -- runs before any membership lookup, so each
        // still spends one of the global bucket's three tokens regardless of the Deny reason.
        for seed in [0x50u8, 0x51, 0x52] {
            let stranger =
                DeviceKey::from_seeds([seed; 32], [seed.wrapping_add(1); 32]).device_fp();
            match authorizer.authorize(&stranger).await {
                ConnectDecision::Deny => {}
                ConnectDecision::Allow { .. } => {
                    panic!("an unenrolled, fabricated fingerprint must be denied on membership")
                }
            }
        }

        // The global bucket (burst 3, refill 0) is now empty. This is the accepted trade-off,
        // not a bug: a rotating flood of fabricated fingerprints, none of which is ever a real
        // member, still exhausts the SAME shared budget a legitimate device's connect draws from.
        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!(
                "expected Deny: the global bucket was exhausted by the preceding rotating flood, \
                 so even this genuinely live member device must be denied at check 0 -- before \
                 its membership is ever consulted. This is DESIGN.md v0.9.24's accepted \
                 shared-fate cost, not a bug: the alternative (no global bucket) would let \
                 identity rotation defeat throttling entirely."
            ),
        }
    }

    /// Without this, a bad `EQUALIZATION_DUMMY_KEYS` constant would make `equalize_denial_work`
    /// silently do LESS work than the real `Allow` path (a failed `checked_verifying_key` short-
    /// circuits before the `device_fp_of` rehash it exists to redo), quietly reopening the timing
    /// gap it exists to close -- and nothing else in this suite would catch that, since every other
    /// test here observes only `ConnectDecision`, never the equalization's internal cost.
    ///
    /// td-b8c68a: asserts against `checked_verifying_key` specifically, not bare
    /// `VerifyingKey::from_bytes` -- the real `Allow` path (via `checked_device_keys`) and
    /// `equalize_denial_work` both now call `checked_verifying_key`, so this constant must pass
    /// the RFC 8032 canonicality pre-check too, not merely decompress. It is a real derived key
    /// (`SigningKey::from_bytes(&[0xA5; 32]).verifying_key()`), so it should -- this test proves
    /// that rather than assuming it.
    #[test]
    fn the_equalization_dummy_key_parses_as_a_valid_ed25519_point() {
        let (sign_bytes, _agree_bytes) = *EQUALIZATION_DUMMY_KEYS;
        assert!(
            spindle_core::checked_verifying_key(&sign_bytes).is_some(),
            "EQUALIZATION_DUMMY_KEYS's sign half must pass checked_verifying_key (decompress as a \
             canonically-encoded, valid Ed25519 point)"
        );
    }

    /// The load-bearing test for the coverage gap td-4bcf24 exists to close: a neuter that replaced
    /// every one of `HostConnectAuthorizer::authorize`'s eight `deny_with_equalized_work()` return
    /// sites with a plain `Deny` left this whole suite green -- nothing asserted
    /// that a pre-crypto denial actually ran the timing equalization, only that it returned `Deny`.
    /// This test closes that: it asserts both the verdict AND that `equalize_denial_work` ran
    /// exactly once, so reverting any of those eight call sites back to a plain `Deny` fails it.
    #[tokio::test]
    async fn a_denial_for_an_unenrolled_from_fp_runs_the_timing_equalization() {
        reset_equalization_calls();
        let (store, _member_id) = store_with_active_member("alex");
        let authorizer =
            HostConnectAuthorizer::new(SqliteDeviceLookup::new(store)).with_now_fn(|| 0);

        let stranger = DeviceKey::from_seeds([0x60; 32], [0x61; 32]).device_fp();
        match authorizer.authorize(&stranger).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!("expected Deny for an unenrolled device_fp"),
        }
        assert_eq!(
            equalization_calls(),
            1,
            "an unenrolled from_fp is denied by checks 1-2, before any crypto -- that denial must \
             go through deny_with_equalized_work(), which calls equalize_denial_work() exactly \
             once. A count of 0 here means the call site that denied this request has been \
             reverted to a plain ConnectDecision::Deny, silently reopening the timing gap between \
             an unenrolled from_fp and a live member's device -- exactly the regression a neuter \
             of all 8 deny_with_equalized_work() call sites proved this suite could not otherwise \
             catch."
        );
    }

    /// The `Allow` side of the same coverage: the real path already pays the parse-and-rehash cost
    /// `equalize_denial_work` exists to imitate, so it must never run the dummy work too -- doing
    /// so would waste cycles and would make `Allow` slower than the denials it is supposed to be
    /// indistinguishable from, the opposite of what the equalization is for.
    #[tokio::test]
    async fn an_allow_does_not_run_the_timing_equalization() {
        reset_equalization_calls();
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x62; 32], [0x63; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let authorizer =
            HostConnectAuthorizer::new(SqliteDeviceLookup::new(store)).with_now_fn(|| 0);

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Deny => panic!("expected Allow for an active member's own device"),
        }
        assert_eq!(
            equalization_calls(),
            0,
            "an Allow must never call equalize_denial_work() -- the Allow path already performs \
             the real checked_verifying_key/X25519PublicKey::from/device_fp_of work that \
             function exists to imitate for a Deny, so running the dummy work on top of the real \
             work would be pure waste and would make Allow measurably slower than the denials it \
             is supposed to be indistinguishable from."
        );
    }

    /// Pins the deliberate exception documented at check 0 in `authorize`: a rate-limited
    /// rejection stays a PLAIN `ConnectDecision::Deny`, never routed through
    /// `deny_with_equalized_work()`. Without a test observing the equalization call count
    /// directly, a future reader could "fix" what looks like a missed spot by wiring check 0
    /// through the equalizer too -- which check 0's own comment explains would hand a flooder
    /// exactly the crypto-work amplification the rate limiter exists to deny, since a rejection
    /// here reveals only limiter state, never membership.
    ///
    /// Since td-fc5a30 the bucket check 0 consults is the GLOBAL one, so that is what this test
    /// exhausts (burst 1). That strengthens the property rather than weakening it: the bucket is
    /// not keyed on `from_fp` at all any more, so a rejection here cannot be about `from_fp` even
    /// in principle.
    #[tokio::test]
    async fn a_rate_limited_denial_does_not_run_the_timing_equalization() {
        reset_equalization_calls();
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x64; 32], [0x65; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store))
            .with_now_fn(|| 0)
            .with_connect_rate_limit(ConnectRateLimitConfig {
                per_fp: ConnectRateLimitConfig::default().per_fp,
                global: RateLimitConfig {
                    burst: 1.0,
                    refill_per_sec: 0.0,
                },
                max_tracked_fps: ConnectRateLimitConfig::default().max_tracked_fps,
            });

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Deny => panic!("first call must Allow: global burst is 1"),
        }
        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!(
                "second call must Deny: the global burst of 1 is exhausted, refill_per_sec is 0, \
                 and the clock is frozen at the same instant -- even this genuinely live, enrolled \
                 device is denied once the shared budget is empty (DESIGN.md v0.9.24's accepted \
                 shared-fate cost)"
            ),
        }
        assert_eq!(
            equalization_calls(),
            0,
            "a rate-limited denial (check 0) must never call equalize_denial_work() -- if this \
             counter is nonzero, check 0 has been rewired to route through \
             deny_with_equalized_work(), reversing the deliberate exception documented at that \
             check: a rate-limited rejection reveals only limiter state, not membership, so \
             spending crypto work equalizing it would hand a flooder exactly the amplification \
             the rate limiter exists to deny."
        );
    }

    /// The `on_verified` twin: a per-fp throttle drops the connect with no equalization work
    /// either. The reasoning differs from check 0's and is spelled out at that call site -- this
    /// peer is authenticated, so revealing its own bucket's state is not a membership oracle, and
    /// spending crypto work to disguise a throttle would defeat the throttle.
    #[tokio::test]
    async fn an_on_verified_throttle_drops_without_running_the_timing_equalization() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x66; 32], [0x67; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store))
            .with_now_fn(|| 0)
            .with_connect_rate_limit(ConnectRateLimitConfig {
                per_fp: RateLimitConfig {
                    burst: 1.0,
                    refill_per_sec: 0.0,
                },
                global: ConnectRateLimitConfig::default().global,
                max_tracked_fps: ConnectRateLimitConfig::default().max_tracked_fps,
            });

        assert!(matches!(
            authorizer.on_verified(&device_fp).await,
            VerifiedDecision::Proceed { .. }
        ));
        reset_equalization_calls();
        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Drop => {}
            VerifiedDecision::Proceed { .. } => panic!(
                "the per-fp burst of 1 is exhausted at a frozen clock -- the second connect must \
                 Drop"
            ),
        }
        assert_eq!(
            equalization_calls(),
            0,
            "on_verified's throttle path must never call equalize_denial_work()"
        );
    }

    /// td-ad318f: a neuter that changed the `Err(DeviceKeyError::BindingMismatch)` arm of
    /// `authorize`'s check 6-9 `match` (the `checked_device_keys` call site) from a plain `Deny`
    /// to `return deny_with_equalized_work();` left this whole suite green -- nothing here
    /// distinguished the two `DeviceKeyError` arms' routing, only that both ended in `Deny`. This
    /// test closes that half of the gap: it stores device B's own `sign_pk`/`agree_pk` (both
    /// genuinely valid Ed25519/X25519 keys) under device A's `device_fp`, with `alg_id:
    /// ALG_ID_V1`. Both keys parse cleanly and the alg_id is valid, so `checked_device_keys`
    /// reaches its rehash, finds `device_fp_of(ALG_ID_V1, B.sign_pk, B.agree_pk) != A.device_fp`,
    /// and returns `BindingMismatch` -- not `Unverifiable`.
    #[tokio::test]
    async fn a_binding_mismatch_denial_does_not_run_the_timing_equalization() {
        reset_equalization_calls();
        let (store, member_id) = store_with_active_member("alex");
        let device_a = DeviceKey::from_seeds([0x70; 32], [0x71; 32]);
        let device_b = DeviceKey::from_seeds([0x72; 32], [0x73; 32]);
        let a_fp = device_a.device_fp();

        // Store B's own (self-consistent, validly parsing) keys under A's device_fp -- `Store::
        // add_device` does not validate the device_fp/keys binding (see its own doc comment), so
        // this row is legal to write even though it can never rehash back to `a_fp`.
        let mismatched_keys = DevicePublicKeys {
            alg_id: ALG_ID_V1,
            sign_pk: device_b.sign_public_key().as_bytes().to_vec(),
            agree_pk: device_b.agree_public_key().as_bytes().to_vec(),
        };
        store
            .add_device(member_id, a_fp, "laptop", 0, Some(&mismatched_keys))
            .expect("add_device");

        let authorizer =
            HostConnectAuthorizer::new(SqliteDeviceLookup::new(store)).with_now_fn(|| 0);
        match authorizer.authorize(&a_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => {
                panic!("expected Deny: the stored keys do not rehash to this row's device_fp")
            }
        }
        assert_eq!(
            equalization_calls(),
            0,
            "a BindingMismatch denial must never call equalize_denial_work() -- a binding \
             mismatch is only reached after checked_device_keys has already paid the real \
             checked_verifying_key/X25519PublicKey::from/device_fp_of cost that \
             equalize_denial_work exists to imitate, so equalizing it too would not close any \
             gap: it would make this Deny measurably SLOWER than an Allow reaches the same point, \
             manufacturing a new timing asymmetry pointing the other way. A nonzero count here \
             means the DeviceKeyError::BindingMismatch arm in authorize() has been rewired \
             through deny_with_equalized_work(), reversing the deliberate exception documented at \
             that call site (td-ad318f, td-4bcf24's review note)."
        );
    }

    /// td-ad318f: the other half of the same coverage gap. A device row with no keys at all fails
    /// `checked_device_keys`'s very first check (`Unverifiable`, before any parse or rehash is
    /// even attempted), so a neuter that reverted the `Err(DeviceKeyError::Unverifiable)` arm back
    /// to a plain `Deny` would reopen the pre-crypto timing gap `deny_with_equalized_work` exists
    /// to close -- and, symmetrically with the test above, nothing in this suite asserted that
    /// this specific arm still runs the equalization.
    ///
    /// This keyless row is denied specifically at checked_device_keys's key check, not earlier at
    /// checks 1-5 (membership/status/revocation): `store_with_active_member` + a fresh
    /// `add_device(.., None)` produce an active member with a non-revoked device row, so
    /// liveness_checks passes and authorize() reaches the key check before denying. A row denied
    /// by an earlier check would still read equalization_calls() == 1 (those checks' own denials
    /// are equalized too), for the wrong reason -- see
    /// `denies_a_device_whose_stored_alg_id_names_an_unsupported_algorithm`'s comment for the same
    /// "right number, wrong reason" trap.
    #[tokio::test]
    async fn an_unverifiable_denial_runs_the_timing_equalization() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x74; 32], [0x75; 32]);
        let device_fp = device.device_fp();
        store
            .add_device(member_id, device_fp, "laptop", 0, None)
            .expect("add_device");

        reset_equalization_calls();
        let authorizer =
            HostConnectAuthorizer::new(SqliteDeviceLookup::new(store)).with_now_fn(|| 0);
        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => {
                panic!("expected Deny: a device with no stored keys can never be verified")
            }
        }
        assert_eq!(
            equalization_calls(),
            1,
            "an Unverifiable denial must call equalize_denial_work() exactly once -- this denial \
             fires at checked_device_keys's very first check, before any of the real \
             checked_verifying_key/X25519PublicKey::from/device_fp_of work an Allow performs, \
             so without equalize_denial_work it would be measurably FASTER than a live member's \
             device reaches the same point -- exactly the pre-crypto timing gap \
             deny_with_equalized_work exists to close. A count of 0 here means the \
             DeviceKeyError::Unverifiable arm in authorize() has been reverted to a plain \
             ConnectDecision::Deny."
        );
    }

    // ---- td-fc5a30: the per-identity half of the decision lives behind the signature-
    // verification boundary, so a forged offer naming a victim charges that victim nothing ----

    /// **The regression test for the whole ticket.**
    ///
    /// The attack, measured: a device holding `pub host.<h>.connect` can publish to that subject
    /// naming a *different* device's inbox as the NATS reply subject -- nats-server 2.10 evaluates
    /// publish permissions against the publish subject only, never the reply -- so an attacker
    /// with any valid device credential can send a host a connect offer claiming a VICTIM's
    /// `from_fp` with `reply = _INBOX_<victim_fp>.…`, and it passes `reply_prefix_ok`. What it
    /// cannot do is produce the victim's signature, so `spindle_net::signaling::wire::open_offer`
    /// rejects it -- but only *after* the authorizer has already been consulted.
    ///
    /// Everything such an offer can reach is therefore exactly `HostConnectAuthorizer::authorize`,
    /// which this test calls directly: the forged offer's entire footprint on this host, before it
    /// is thrown away, is that one call. `on_verified` is deliberately NOT called here, because
    /// `process_offer` would never call it for an offer whose signature failed -- pinned
    /// separately by `spindle-net`'s
    /// `a_forged_offer_naming_another_device_never_reaches_on_verified`.
    ///
    /// The assertion is that the victim's own per-fp budget is completely intact afterwards: the
    /// victim can still make its full documented burst of successful connects. Before td-fc5a30,
    /// `authorize` charged the victim's per-fp bucket, so 10 forged offers left the victim locked
    /// out (measured by the td-4bcf24 review: a victim succeeded 0/60 during a sustained flood
    /// while a bystander fp was allowed 10/10 at the same instant).
    #[tokio::test]
    async fn a_forged_offer_naming_a_victim_does_not_consume_the_victims_per_fp_bucket() {
        let (store, member_id) = store_with_active_member("victim");
        let victim_device = DeviceKey::from_seeds([0xa0; 32], [0xa1; 32]);
        let victim_fp = enroll_device(&store, member_id, "laptop", &victim_device);
        let per_fp_burst = 10.0;
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store))
            .with_now_fn(|| 0)
            .with_connect_rate_limit(ConnectRateLimitConfig {
                per_fp: RateLimitConfig {
                    burst: per_fp_burst,
                    // No refill at all, and the clock is frozen: if the flood spends even ONE of
                    // the victim's tokens, nothing can give it back and the assertion below fails.
                    refill_per_sec: 0.0,
                },
                // Generous enough that the flood cannot deny the victim via the shared global
                // bucket instead -- this test is about the per-fp bucket specifically, and a
                // global-bucket denial would be a right-answer-for-the-wrong-reason pass.
                global: RateLimitConfig {
                    burst: 100_000.0,
                    refill_per_sec: 0.0,
                },
                max_tracked_fps: ConnectRateLimitConfig::default().max_tracked_fps,
            });

        // 50 forged offers, all naming the victim. Each reaches `authorize` and nothing else.
        for _ in 0..50 {
            match authorizer.authorize(&victim_fp).await {
                // The lookup succeeds -- the victim IS a live member, which is the whole point of
                // naming them -- so `authorize` answers Allow with the victim's real keys. The
                // signature check downstream is what actually kills the offer.
                ConnectDecision::Allow { .. } => {}
                ConnectDecision::Deny => panic!(
                    "fixture check: the victim is a live member, so authorize must Allow -- if \
                     this Denies, the flood is being stopped for some unrelated reason and the \
                     assertion below would pass vacuously"
                ),
            }
        }

        // The victim now connects for real: signature verifies, so `process_offer` reaches
        // `on_verified`. Its full burst must be available, untouched.
        for i in 0..(per_fp_burst as usize) {
            assert!(
                matches!(
                    authorizer.authorize(&victim_fp).await,
                    ConnectDecision::Allow { .. }
                ),
                "victim connect {i}: the pre-verification half must still allow"
            );
            match authorizer.on_verified(&victim_fp).await {
                VerifiedDecision::Proceed { .. } => {}
                VerifiedDecision::Drop => panic!(
                    "victim connect {i} of {per_fp_burst} was throttled -- the 50 forged offers \
                     above consumed the victim's own per-fp token bucket. This is td-fc5a30's \
                     targeted denial-of-service: an attacker who cannot produce the victim's \
                     signature locked the victim out anyway, by naming them. The per-fp charge \
                     has been moved back into `authorize`, where `from_fp` is unverified and \
                     attacker-chosen."
                ),
            }
        }
    }

    /// The bounded-map half of the same attack. `ConnectRateLimiter`'s per-fp map is capped at
    /// `max_tracked_fps` and, when full of still-throttled buckets, refuses every not-yet-tracked
    /// fingerprint outright -- a hard denial, not a slowdown (the td-4bcf24 review measured 0/20
    /// legitimate new devices admitted while the map sat at capacity with the global bucket full).
    /// While the map insert happened in `authorize`, filling it cost an attacker nothing but
    /// fabricated names.
    ///
    /// After the split, a fabricated `from_fp` reaches only `try_acquire_global`, which takes no
    /// fingerprint at all, so the map cannot grow from unauthenticated traffic.
    #[tokio::test]
    async fn forged_offers_with_fabricated_from_fps_do_not_grow_the_bounded_tracking_map() {
        let (store, _member_id) = store_with_active_member("alex");
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(store))
            .with_now_fn(|| 0)
            .with_connect_rate_limit(ConnectRateLimitConfig {
                per_fp: RateLimitConfig {
                    burst: 1.0,
                    refill_per_sec: 0.0,
                },
                global: RateLimitConfig {
                    burst: 100_000.0,
                    refill_per_sec: 0.0,
                },
                // Deliberately tiny: under the old shape, 4 fabricated fingerprints would fill
                // this map and the 5th legitimate device would be refused outright.
                max_tracked_fps: 4,
            });

        for i in 0..1_000u32 {
            let fabricated = Fingerprint::of_parts(&[b"td-fc5a30-fabricated", &i.to_le_bytes()]);
            match authorizer.authorize(&fabricated).await {
                ConnectDecision::Deny => {}
                ConnectDecision::Allow { .. } => {
                    unreachable!("a fabricated fingerprint is never an enrolled device")
                }
            }
        }

        assert_eq!(
            authorizer.tracked_fps(),
            0,
            "1000 forged offers with 1000 distinct fabricated from_fps must leave the bounded \
             per-fp map completely empty. Any nonzero count means the pre-verification path is \
             inserting attacker-chosen names into a capacity-limited map again -- which, once \
             full of throttled buckets, refuses every legitimate device the map does not already \
             track (td-fc5a30 / td-4bcf24 mode 2)."
        );
    }

    /// The positive end-to-end of the split, with a real issuer: a connect that passes both halves
    /// still gets its member capability, minted from its new home in `on_verified`, and it
    /// verifies its full root -> op-key -> signature chain. Without this, a fix that simply
    /// deleted the mint would look correct to every negative test above.
    #[tokio::test]
    async fn a_successful_staged_connect_still_receives_a_verifiable_member_cap() {
        let (store, member_id) = store_with_active_member("alex");
        let root_fp = Fingerprint::of_parts(&[b"alex"]); // matches store_with_active_member
        let device = DeviceKey::from_seeds([0xa2; 32], [0xa3; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let now = 1_000;
        let issuer = test_cap_issuer([0xa4; 32], [0xa5; 32], now);
        let authorizer =
            HostConnectAuthorizer::with_issuer(SqliteDeviceLookup::new(store), Box::new(issuer))
                .with_now_fn(|| 0);

        // Half one: the pre-verification decision, which resolves the keys and mints nothing.
        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { sign_pk, agree_pk } => {
                assert_eq!(sign_pk, device.sign_public_key());
                assert_eq!(agree_pk, device.agree_public_key());
            }
            ConnectDecision::Deny => panic!("expected Allow for an active member's own device"),
        }

        // Half two: the post-verification decision, which is where the cap now comes from.
        match authorizer.on_verified(&device_fp).await {
            VerifiedDecision::Proceed { member_cap } => {
                let cap = member_cap.expect(
                    "a verified connect from a live member, with an issuer installed, must \
                     receive a freshly-minted member capability -- the mint still works from its \
                     new home in on_verified",
                );
                verify_capability(&cap, now)
                    .expect("the minted cap must verify its own root -> op-key -> sig chain");
                assert_eq!(cap.kind, CapKind::Member);
                assert!(
                    root_fp.matches(&cap.subject),
                    "DESIGN.md:286: subject must still be the member's root_fp after the move"
                );
            }
            VerifiedDecision::Drop => panic!("expected Proceed for an active member's own device"),
        }
    }

    /// `authorize` must never mint, for anyone. A live member's pre-verification decision performs
    /// no issuance at all -- which is what makes the Ed25519 signature unreachable to an
    /// unauthenticated peer, and what lets `equalize_denial_work` imitate the whole of an `Allow`'s
    /// crypto cost rather than a fraction of it (see that function's doc comment).
    #[tokio::test]
    async fn authorize_never_reaches_the_issuer_even_for_a_live_member() {
        struct CountingIssuer {
            calls: Arc<AtomicUsize>,
        }
        impl CapIssuer for CountingIssuer {
            fn issue_member_cap(&self, subject: Fingerprint, cap_epoch: u64) -> Option<Capability> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                test_cap_issuer([0xa6; 32], [0xa7; 32], 1_000).issue_member_cap(subject, cap_epoch)
            }
        }

        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0xa8; 32], [0xa9; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let calls = Arc::new(AtomicUsize::new(0));
        let authorizer = HostConnectAuthorizer::with_issuer(
            SqliteDeviceLookup::new(store),
            Box::new(CountingIssuer {
                calls: Arc::clone(&calls),
            }),
        )
        .with_now_fn(|| 0);

        for _ in 0..5 {
            assert!(matches!(
                authorizer.authorize(&device_fp).await,
                ConnectDecision::Allow { .. }
            ));
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "authorize must never mint. Five pre-verification decisions for a genuinely live \
             member produced five Allows and zero signatures -- a nonzero count here means the \
             mint has been moved back onto the pre-authentication path, handing every \
             unauthenticated peer a free Ed25519 signature per packet it sends and reopening the \
             Allow-signs/Deny-doesn't timing oracle."
        );

        // ... and one post-verification call does mint, exactly once.
        assert!(matches!(
            authorizer.on_verified(&device_fp).await,
            VerifiedDecision::Proceed {
                member_cap: Some(_)
            }
        ));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the mint happens exactly once, in on_verified"
        );
    }

    /// A lookup that fails outright inside `on_verified` must degrade to `Proceed { member_cap:
    /// None }`, never to `Drop`. The peer has already proven its signature and every membership
    /// check already passed in `authorize`; a store read failing *now* means only that this host
    /// cannot mint a fresh cap this time. Dropping instead would turn a transient `SQLITE_BUSY`
    /// (reachable because `spindle-hostd` holds multiple independent connections to one database
    /// file) into a host that refuses every connect -- the fleet-wide lockout DESIGN.md:288-290's
    /// renewal path exists to prevent. This is check 10's original rule, carried over to its new
    /// home.
    #[tokio::test]
    async fn on_verified_with_a_failing_lookup_proceeds_without_a_cap_rather_than_dropping() {
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

            fn member_and_cap_epoch(
                &self,
                _device_fp: Fingerprint,
            ) -> Result<(Option<Member>, Option<u64>), LookupError> {
                Err(LookupError::LockPoisoned)
            }
        }

        let issuer = test_cap_issuer([0xaa; 32], [0xab; 32], 1_000);
        let authorizer =
            HostConnectAuthorizer::with_issuer(AlwaysFails, Box::new(issuer)).with_now_fn(|| 0);
        let some_fp = DeviceKey::from_seeds([0xac; 32], [0xad; 32]).device_fp();

        assert_eq!(
            authorizer.on_verified(&some_fp).await,
            VerifiedDecision::Proceed { member_cap: None },
            "a LookupError inside on_verified must cost the connect only its fresh capability, \
             never the connect itself. A Drop here breaks an already-verified connect over a \
             problem that has nothing to do with whether this device may connect."
        );
    }

    // Deliberately no wall-clock timing assertion anywhere in this section (e.g. asserting a
    // Deny and an Allow complete within some close elapsed-time tolerance of each other): such an
    // assertion would be flaky under ordinary scheduling/allocator/CPU-frequency jitter, and
    // passing it would not actually prove the equalization works -- only that this run, on this
    // machine, happened to produce two close-enough numbers. `the_equalization_dummy_key_parses_
    // as_a_valid_ed25519_point` above is the meaningful thing to test instead: that the dummy
    // constant is valid, so `equalize_denial_work` always performs the same SHAPE of work an
    // `Allow` does, which is what this module can actually guarantee deterministically.
}
