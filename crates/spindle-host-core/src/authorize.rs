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

use crate::ratelimit::{ConnectRateLimitConfig, ConnectRateLimiter};
use spindle_core::artifacts::issue_capability;
use spindle_core::identity::device_fp_of;
use spindle_core::{Fingerprint, SigningKey, VerifyingKey, X25519PublicKey, ALG_ID_V1};
use spindle_net::signaling::authorize::{ConnectAuthorizer, ConnectDecision};
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
    /// requires it; nothing anywhere invokes it.
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
    /// [`HostConnectAuthorizer::authorize`]'s own comment at its call site for the concrete
    /// exploit shape this closes.
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
    /// through it [`crate::session::VfsSessionHandler`] — have no epoch to race against and keep
    /// using [`Self::member_for_device_fp`] alone.
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
            // Reachable from two independent pipelines: `HostConnectAuthorizer::authorize` when
            // no `CapIssuer` is installed, and every session's own liveness re-check
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
/// and by [`HostConnectAuthorizer::authorize`] when no cap will be minted) and the atomic
/// snapshot fetch ([`DeviceLookup::member_and_cap_epoch`], used by
/// [`HostConnectAuthorizer::authorize`] when a cap might be minted from the result). Checks 1 and
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
/// and [`HostConnectAuthorizer::authorize`] treats that exactly like "no issuer installed" —
/// `member_cap: None` in an otherwise-`Allow` decision. A cap-issuance failure must **never**
/// turn an otherwise-valid connect into a `Deny`: the device simply gets an answer with no fresh
/// cap and falls back to whatever cap it already holds. Denying here would be strictly worse than
/// the status quo, because it would take a working connect path and break it over a problem
/// (signing) that has nothing to do with whether this device is still a live member.
pub trait CapIssuer: Send + Sync {
    /// Issues a `member`-kind capability for `subject` (see [`RootKeyCapIssuer`]'s doc comment
    /// for why `subject` must be the member's `root_fp`, never a device fp), stamped with
    /// `cap_epoch` — the caller (`HostConnectAuthorizer::authorize`) reads that epoch live via
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
/// `process_offer` doc comment, ~line 194-197 as of this writing): "must rate-limit these lookups"
/// is [`Self::limiter`], a [`ConnectRateLimiter`] consulted before any store access (see
/// `authorize`'s check 0); "must make `Allow` and `Deny` indistinguishable to the caller in timing
/// and observable behavior" is [`equalize_denial_work`], run on every pre-crypto `Deny` so an
/// unenrolled `from_fp` costs roughly the same crypto work as an enrolled one. Neither is complete:
///
/// - the rate limiter's own state (which bucket a given `from_fp` lands in, whether the global
///   bucket is exhausted) is itself observable via timing/behavior differences between callers —
///   see [`ConnectRateLimiter`]'s own doc comment for the accepted "shared fate" cost this implies;
/// - the timing equalization closes the crypto-work asymmetry (check 9's own comment explains why
///   it stops exactly there) but leaves the store-side cost difference between a registry hit and
///   a miss, plus SQLite page-cache and allocator jitter, unequalized — see
///   [`equalize_denial_work`]'s doc comment for the honest accounting of what remains open. That
///   residual gap is bounded by the rate limiter and by §A5's uniform silent drop
///   (`SignalingError::Denied` produces no reply at all), not eliminated.
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
}

/// A fixed, valid Ed25519 verifying key / X25519 public key pair, computed once, that
/// [`equalize_denial_work`] recomputes a `device_fp` against on every pre-crypto `Deny`.
///
/// Only the sign half needs to be a genuinely valid curve point: `VerifyingKey::from_bytes` is a
/// point decompression that can fail for a byte string that does not encode a valid Ed25519 point,
/// and it is exactly that decompression — not a scalar multiplication, which the real `Allow` path
/// never performs either — that [`equalize_denial_work`] must redo per call to match the real
/// path's cost. Deriving `sign_bytes` here, once, via `SigningKey::from_bytes(&[0xA5; 32])
/// .verifying_key().to_bytes()` guarantees a point `VerifyingKey::from_bytes` can always
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
/// A second, larger gap in the same direction: once a [`CapIssuer`] is installed (see check 10 in
/// [`HostConnectAuthorizer::authorize`]), an `Allow` that successfully mints a member cap performs
/// an Ed25519 SIGNATURE — `issue_member_cap`'s whole reason for existing — that this function's
/// crypto recompute never matches; it only redoes the parse/rehash work of checks 7 and 9, never a
/// signature. Measured on one release-build machine: `equalize_denial_work` ≈ 3.3 µs/call,
/// `issue_member_cap` ≈ 16.7 µs/call — an asymmetry roughly 5x LARGER than the parse/rehash gap
/// this function closes, pointing the same direction (`Allow` slower than `Deny`). Nothing
/// installs a `CapIssuer` today — only `spindle-hostd`'s `HostDaemon::with_cap_issuer`'s
/// definition exists, nothing calls it yet — so this is latent, not live, but it goes live
/// silently the moment Stage 7 wires the operating key in, with no change to this function
/// required to trigger it. Equalizing it is NOT the fix: performing an Ed25519 signature on every
/// denial, to match, would hand an attacker exactly the CPU-cost amplification
/// [`ConnectRateLimiter`] exists to deny them — trading a timing side-channel for a cheap
/// denial-of-service amplifier is a strictly worse trade. The right fix, whenever this goes live,
/// is scoped to Stage 7, not to this function.
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
    let Ok(sign_pk) = VerifyingKey::from_bytes(&sign_bytes) else {
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
        // This returns a PLAIN `Deny`, not `deny_with_equalized_work()`'s equalized one, and that
        // is deliberate, not an oversight:
        // - a rate-limited rejection reveals only rate-limiter state (this bucket, or the shared
        //   global one, is out of tokens right now), never membership — it leaks nothing about
        //   whether `from_fp` is enrolled, so there is no membership-oracle signal here to hide
        //   behind equalized crypto work;
        // - spending crypto work on a request the limiter has already refused would hand a
        //   flooder exactly the amplification the limiter exists to deny: the whole point of
        //   checking the limiter first is to make a throttled request cheap, not merely
        //   indistinguishable-looking. Being measurably faster on this path is the correct
        //   trade-off, not a timing leak that needs closing.
        if !self.limiter.try_acquire(*from_fp, (self.now_fn)()) {
            return ConnectDecision::Deny;
        }

        // 1-5, plus — when a `CapIssuer` is installed — the `cap_epoch` a freshly minted cap must
        // carry, both resolved from ONE atomic snapshot via `DeviceLookup::member_and_cap_epoch`.
        //
        // This used to be two independent reads: `active_member_for_device` (itself one
        // `store.lock()`) for the member, then, after checks 6-8 below, a *separate*
        // `self.lookup.cap_epoch()` call for the epoch. That shape has a TOCTOU race:
        // `Store::revoke_member_and_bump_epoch` and `revoke_device_and_bump_epoch` each flip a
        // member's status (or a device's `revoked` flag) *and* bump `cap_epoch` inside one
        // transaction, and nothing stops such a transaction committing in the window between the
        // two reads. When it does, the member snapshot already in hand is from *before* the
        // revoke, but the `cap_epoch` read moments later is from *after* it — and minting from
        // that pair produces a capability for a subject the store has already revoked, stamped
        // with the post-bump epoch. Since the only thing most consumers check is `cap.cap_epoch`
        // against the host's current `cap_epoch`, that capability is indistinguishable from a
        // legitimately fresh one — which defeats `cap_epoch`'s entire purpose as the
        // revocation-invalidation mechanism (DESIGN.md §A4). Do not "simplify" this back into two
        // reads — see `DeviceLookup::member_and_cap_epoch`'s own doc comment for the same warning.
        //
        // When no issuer is installed, no capability will ever be minted from this call, so there
        // is no epoch to race against: the plain, membership-only `active_member_for_device` is
        // used instead, keeping this struct's own doc comment true ("a connect decision is
        // membership, not capability freshness") — `cap_epoch` is never even read on this path.
        //
        // In the branch below, a `cap_epoch` read failure is likewise never a `Deny` — see
        // `DeviceLookup::member_and_cap_epoch`'s doc comment: only a failure to read *membership*
        // (an outer `Err`) denies; a missing epoch (`Ok((member, None))`) just means check 9
        // mints no cap. The two failure modes share one `LookupError` type at the call site but
        // must never share its fail-closed treatment.
        let (member, cap_epoch_for_mint): (Option<Member>, Option<u64>) = match &self.issuer {
            None => (active_member_for_device(&self.lookup, *from_fp), None),
            Some(_) => match self.lookup.member_and_cap_epoch(*from_fp) {
                // `cap_epoch` may legitimately be `None` here (see `DeviceLookup::
                // member_and_cap_epoch`'s doc comment: a transient `cap_epoch` read failure,
                // e.g. `SQLITE_BUSY` on `meta`, costs only the freshly-minted cap). That must
                // NOT be conflated with the `Err` arm below: membership was read successfully,
                // so an otherwise-live member still gets `Allow`, just with `member_cap: None`
                // once check 9 finds no epoch to mint from.
                Ok((member, cap_epoch)) => (liveness_checks(member, *from_fp), cap_epoch),
                // Only a genuine `Err` — membership itself unprovable, or a poisoned lock — is a
                // fail-closed `Deny`. Worth a line of its own: without it, this `Deny` is
                // indistinguishable from "the device is not a member", when it is operationally a
                // very different fact — the store could not be read at all.
                Err(e) => {
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
                        device_fp = %from_fp.redacted(),
                        error = %e,
                        "authorize: member_and_cap_epoch failed; denying connect due to a store \
                         failure, not because the device is not a member"
                    );
                    (None, None)
                }
            },
        };
        let Some(member) = member else {
            return deny_with_equalized_work();
        };
        // Re-finding the device row is redundant with what `active_member_for_device` already
        // confirmed, but this module's house style never unwraps an invariant instead of failing
        // closed (see check 4's own comment for the same call) — an `expect` here would be the
        // one panic-shaped seam in an otherwise all-`Deny` function.
        let Some(device) = member.devices.iter().find(|d| d.device_fp == *from_fp) else {
            return deny_with_equalized_work();
        };

        // 6. Either key is missing on file. Fail closed; a missing key is never "skip the check".
        let (Some(sign_pk_bytes), Some(agree_pk_bytes)) = (&device.sign_pk, &device.agree_pk)
        else {
            return deny_with_equalized_work();
        };

        // 7. Either key fails to parse (wrong length, or — for the Ed25519 sign key — not a valid
        // curve point).
        let Ok(sign_pk_arr): Result<[u8; 32], _> = sign_pk_bytes.as_slice().try_into() else {
            return deny_with_equalized_work();
        };
        // td-4bcf24 review note: this `Deny` routing through `deny_with_equalized_work()` was
        // flagged as "over-equalized" (a failed decompression is already cheaper than a real
        // `Allow`, so equalizing it further supposedly widens rather than closes the gap). That
        // finding is wrong; recorded here so a future reviewer does not re-raise it. Let D = the
        // cost of `VerifyingKey::from_bytes`'s point decompression, H = the cost of the
        // `device_fp_of` rehash (checks 7/9 combined with an `Allow`'s later work), and Df = the
        // (smaller) cost of a decompression that fails fast. A real `Allow` pays D+H. Without
        // equalization, this failed-decompression `Deny` pays only Df — off from `Allow` by the
        // full D+H, a large gap. WITH equalization (`deny_with_equalized_work` redoes a successful
        // decompression + rehash against the fixed dummy key), this `Deny` pays Df+D+H — off from
        // `Allow` by only Df, a tiny gap. Df+D+H is strictly closer to D+H than Df alone is:
        // equalizing here is strictly closer to indistinguishable, not further from it.
        let Ok(sign_pk) = VerifyingKey::from_bytes(&sign_pk_arr) else {
            return deny_with_equalized_work();
        };
        let Ok(agree_pk_arr): Result<[u8; 32], _> = agree_pk_bytes.as_slice().try_into() else {
            return deny_with_equalized_work();
        };
        let agree_pk = X25519PublicKey::from(agree_pk_arr);

        // 8. The stored `alg_id` is missing, or names anything other than `ALG_ID_V1` (td-6c01e3:
        // `devices.alg_id`, DESIGN.md:225-227's `device_fp = H(DEVICE_FP_DOMAIN, alg_id, sign_pk,
        // agree_pk)`). `sign_pk`/`agree_pk` were just parsed above as Ed25519/X25519
        // unconditionally — that parsing is what pins the algorithm, not this integer — so a row
        // whose `alg_id` is `None` (a row with keys but no algorithm — impossible after the
        // SCHEMA_V9 backfill, but this module's house style never unwraps an invariant instead of
        // failing closed) or names something other than v1 cannot be verified by this code path
        // at all. Hashing that `alg_id` into `device_fp_of` anyway would manufacture a hash that
        // matches for a row nobody can actually verify; denying is the only sound answer.
        //
        // Written as an explicit bind-then-compare rather than `let Some(ALG_ID_V1) = device.alg_id
        // else { ... }`. That form type-checks today only because `ALG_ID_V1` happens to resolve to
        // an in-scope `const` in SCREAMING_SNAKE_CASE, which is a lexical convention Rust's pattern
        // matching leans on but does not enforce — nothing about the type system requires it. A
        // future rename away from that convention, or a local shadowing binding named `ALG_ID_V1`,
        // would silently turn `Some(ALG_ID_V1)` from a refutable constant pattern into an
        // irrefutable *binding* pattern that accepts every `Some(_)` — and it would still compile,
        // because the name is used again on the next lines (as the now-shadowed binding, not the
        // constant). That failure mode is silent and would not show up as a type or lint error, only
        // as this check quietly accepting every alg_id. Binding the value under its own name and
        // comparing with `!=` cannot be reinterpreted that way: renaming or shadowing `ALG_ID_V1`
        // would break the `!=` comparison at compile time (or, at worst, compare against the wrong
        // but still-explicit value), never silently widen this into a no-op check.
        let Some(alg_id) = device.alg_id else {
            return deny_with_equalized_work();
        };
        if alg_id != ALG_ID_V1 {
            return deny_with_equalized_work();
        }

        // 9. The binding does not hold (DESIGN.md §A7b clarification-6 — the same check
        // `verify_device_certificate` performs). This is what makes the stored key pair
        // *self-verifying*: `device_fp` is the hash of exactly `(DEVICE_FP_DOMAIN, alg_id,
        // sign_pk, agree_pk)`, so a row whose keys were corrupted, transposed, or swapped for
        // another device's cannot silently authorize — it simply fails to rehash to `from_fp`.
        // Uses `alg_id` (the value just read from and validated against this row), not a
        // hardcoded `ALG_ID_V1` constant — check 8 above already proved they're equal for this
        // row, but recomputing the hash from the row's own field, rather than a compile-time
        // constant, is what makes this the actual device_fp recompute td-6c01e3 requires: a
        // future second algorithm added as another `Some(alg_id) if alg_id != ALG_ID_V1` arm
        // above would still rehash correctly here without this line needing to change at all.
        //
        // This `Deny` stays PLAIN — never routed through `deny_with_equalized_work()` — and that
        // is deliberate, not a missed spot: every check above this one denies *before* performing
        // the real `VerifyingKey::from_bytes`/`X25519PublicKey::from`/`device_fp_of` work an
        // `Allow` also does, so equalizing them against a dummy recompute closes a real
        // faster-than-`Allow` gap. This check has already paid that exact cost for real (the parse
        // at checks 6-7, the rehash right above) before reaching here — there is no gap left to
        // close. Adding a second, redundant `equalize_denial_work()` call here would not equalize
        // anything; it would make this specific `Deny` measurably *slower* than an `Allow` reaches
        // the same point, manufacturing a new timing asymmetry pointing the other way.
        if device_fp_of(alg_id, &sign_pk, &agree_pk) != *from_fp {
            return ConnectDecision::Deny;
        }

        // 10. Mint the opportunistic member capability (DESIGN.md:286), if we can. This never
        // downgrades an `Allow` into a `Deny` — see `CapIssuer`'s doc comment for why an
        // issuance failure must be strictly no worse than the status quo (no fresh cap, not a
        // broken connect).
        //
        // `cap_epoch_for_mint` can legitimately be `None` even when `self.issuer` is `Some` — see
        // `DeviceLookup::member_and_cap_epoch`'s doc comment: a tolerated `cap_epoch` read
        // failure (e.g. `SQLITE_BUSY` on `meta`) reaches here as `None`, not as a `Deny` a few
        // lines up. The `match` spells out every combination explicitly rather than `unwrap`ping
        // an epoch that might not be there — this module's house style never unwraps an
        // invariant instead of failing closed, and here there simply is no invariant to unwrap:
        // "issuer installed" and "epoch available" are independent facts.
        //
        // `subject` is `member.root_fp`, not `from_fp`/`device_fp` — DESIGN.md:286: "`subject =
        // root_fp` so every root-certified device of the person may use it". This is the central
        // hazard of this slice: scoping the cap to the device fp instead would silently restrict
        // it to the one device that happened to connect, breaking every other device the same
        // person owns.
        let member_cap = match (&self.issuer, cap_epoch_for_mint) {
            (Some(issuer), Some(cap_epoch)) => issuer.issue_member_cap(member.root_fp, cap_epoch),
            _ => None,
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

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { member_cap, .. } => {
                assert_eq!(
                    member_cap, None,
                    "Ok((Some(live_member), None)) from member_and_cap_epoch means membership is \
                     fine but there is no fresh cap_epoch to mint from this time -- Allow with no \
                     cap is correct, the same 'issuance failure is never worse than the status \
                     quo' rule CapIssuer's doc comment states for a failing issuer"
                );
            }
            ConnectDecision::Deny => panic!(
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
        /// double. `authorize` must leave this at exactly 1: any second call, even a second
        /// `member_and_cap_epoch`, is a second read of what would be a racing store.
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
    /// after `authorize` consumes its lookup by value) while still handing `with_issuer` an owned
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

        let decision = authorizer.authorize(&device_fp).await;
        assert_eq!(
            lookup.lookup_calls(),
            1,
            "`authorize` must make exactly ONE DeviceLookup call on this path. A second call -- \
             even another `member_and_cap_epoch` -- is a second read of a store a concurrent \
             revoke can commit into between them, which is exactly the TOCTOU this method exists \
             to close."
        );
        match decision {
            ConnectDecision::Allow { member_cap, .. } => {
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
            ConnectDecision::Deny => panic!(
                "expected Allow: the atomic snapshot must see the member Active -- the simulated \
                 race only lands after a call returns, and `authorize` must make exactly one \
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

        let decision = authorizer.authorize(&device_fp).await;
        assert_eq!(
            lookup.lookup_calls(),
            1,
            "`authorize` must make exactly ONE DeviceLookup call on this path. A second call -- \
             even another `member_and_cap_epoch` -- is a second read of a store a concurrent \
             revoke can commit into between them, which is exactly the TOCTOU this method exists \
             to close."
        );
        match decision {
            ConnectDecision::Allow { member_cap, .. } => {
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
            ConnectDecision::Deny => panic!(
                "expected Allow: the atomic snapshot must see the device non-revoked -- the \
                 simulated race only lands after a call returns, and `authorize` must make \
                 exactly one DeviceLookup call on this path, never a second one for it to land \
                 before"
            ),
        }
    }

    // ---- connect-rate limiting (td-4bcf24): DESIGN.md §A5/v0.9.24's per-`from_fp` + global token
    // bucket over the connect endpoint, and its timing/observable-behavior equalization -------

    /// The load-bearing test for `HostConnectAuthorizer`'s rate limiter being a security control,
    /// not an opt-in convenience: a plain `HostConnectAuthorizer::new(..)` -- never touching
    /// `with_connect_rate_limit` -- must still throttle. If this regresses to `Allow` on the 11th
    /// call, `new`/`with_issuer` have silently stopped installing a real `ConnectRateLimiter`.
    #[tokio::test]
    async fn the_rate_limiter_is_on_by_default_and_is_not_opt_in() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x40; 32], [0x41; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        // A frozen clock, so refill never masks the burst boundary -- `with_now_fn` is the only
        // knob touched here; `with_connect_rate_limit` deliberately is not, since this test exists
        // to prove the *default* config (installed by `new` with no further configuration) is
        // what's actually enforced.
        let authorizer =
            HostConnectAuthorizer::new(SqliteDeviceLookup::new(store)).with_now_fn(|| 0);

        for i in 0..10 {
            match authorizer.authorize(&device_fp).await {
                ConnectDecision::Allow { .. } => {}
                ConnectDecision::Deny => panic!(
                    "call {i} of the documented default per-fp burst (10) must Allow -- a live, \
                     active member device must not be throttled before its own burst is spent"
                ),
            }
        }
        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!(
                "the rate limiter is on by default and is NOT opt-in: HostConnectAuthorizer::new \
                 must install ConnectRateLimiter::new(ConnectRateLimitConfig::default()) even \
                 though this test never called with_connect_rate_limit. An Allow on the 11th call \
                 (one past the documented default per-fp burst of 10) would mean a host built via \
                 HostConnectAuthorizer::new silently ran with no rate limiting at all -- exactly \
                 the security regression this test exists to catch."
            ),
        }
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

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Deny => panic!("first call must Allow: per-fp burst is 2"),
        }
        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Deny => panic!("second call must Allow: per-fp burst is 2"),
        }
        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!(
                "third call must Deny: the per-fp burst of 2 is exhausted, refill_per_sec is 0, \
                 and the clock is frozen at the same instant -- even a genuinely live, active \
                 member device is throttled once its own bucket is empty"
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

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Deny => {
                panic!("first call must Allow: burst is 1 and the bucket starts full")
            }
        }
        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!(
                "second call at the same instant must Deny: burst of 1 is exhausted and the \
                 clock has not advanced"
            ),
        }
        clock.store(1, Ordering::SeqCst);
        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Deny => panic!(
                "one second later, at refill_per_sec = 1.0, exactly one token has refilled -- \
                 this call must Allow"
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
    /// silently do LESS work than the real `Allow` path (a failed `VerifyingKey::from_bytes` short-
    /// circuits before the `device_fp_of` rehash it exists to redo), quietly reopening the timing
    /// gap it exists to close -- and nothing else in this suite would catch that, since every other
    /// test here observes only `ConnectDecision`, never the equalization's internal cost.
    #[test]
    fn the_equalization_dummy_key_parses_as_a_valid_ed25519_point() {
        let (sign_bytes, _agree_bytes) = *EQUALIZATION_DUMMY_KEYS;
        assert!(
            VerifyingKey::from_bytes(&sign_bytes).is_ok(),
            "EQUALIZATION_DUMMY_KEYS's sign half must decompress as a valid Ed25519 point"
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
             the real VerifyingKey::from_bytes/X25519PublicKey::from/device_fp_of work that \
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
    #[tokio::test]
    async fn a_rate_limited_denial_does_not_run_the_timing_equalization() {
        reset_equalization_calls();
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x64; 32], [0x65; 32]);
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

        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Allow { .. } => {}
            ConnectDecision::Deny => panic!("first call must Allow: per-fp burst is 1"),
        }
        match authorizer.authorize(&device_fp).await {
            ConnectDecision::Deny => {}
            ConnectDecision::Allow { .. } => panic!(
                "second call must Deny: the per-fp burst of 1 is exhausted, refill_per_sec is 0, \
                 and the clock is frozen at the same instant -- even this genuinely live, enrolled \
                 device is throttled once its own bucket is empty"
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

    // Deliberately no wall-clock timing assertion anywhere in this section (e.g. asserting a
    // Deny and an Allow complete within some close elapsed-time tolerance of each other): such an
    // assertion would be flaky under ordinary scheduling/allocator/CPU-frequency jitter, and
    // passing it would not actually prove the equalization works -- only that this run, on this
    // machine, happened to produce two close-enough numbers. `the_equalization_dummy_key_parses_
    // as_a_valid_ed25519_point` above is the meaningful thing to test instead: that the dummy
    // constant is valid, so `equalize_denial_work` always performs the same SHAPE of work an
    // `Allow` does, which is what this module can actually guarantee deterministically.
}
