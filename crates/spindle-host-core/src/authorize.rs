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
    /// particular, checks 3 and 5 (the shared `liveness_checks` helper reached via either
    /// [`active_member_for_device`] or [`DeviceLookup::member_and_cap_epoch`] below — see
    /// `active_member_for_device`'s doc comment for the full per-check narrative, including why
    /// checks 3 and 5 are independently enforced: a still-`Active` member can have one revoked
    /// device among several, the same split `server.rs`'s `denied:device_revoked` gate makes per
    /// request) are shared with [`crate::session::VfsSessionHandler`]'s session-time gate rather
    /// than duplicated here.
    async fn authorize(&self, from_fp: &Fingerprint) -> ConnectDecision {
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
    use spindle_core::artifacts::{issue_host_op_key_cert, verify_capability};
    use spindle_core::identity::{DeviceKey, RootKey};
    use spindle_vfs::model::{Device, DevicePublicKeys, MemberId};
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
}
