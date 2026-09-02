//! [`VfsSessionHandler`] — the production `spindle_net::signaling::host::SessionHandler`
//! implementation, the third injected-trait implementation this crate supplies (after
//! [`crate::authorize::HostConnectAuthorizer`] and its [`crate::authorize::DeviceLookup`] seam).
//! It drives a host's already-established QUIC control stream through
//! [`crate::serve::serve_control_stream`]'s binding loop over a fresh [`crate::server::VfsRpcServer`].
//!
//! # Why this is injected rather than a direct call
//!
//! The same rule that makes `authorize`'s `ConnectAuthorizer` an injected trait applies here: per
//! DESIGN.md §A9c's crate layering law (boundary rule 3, `proto ← core ← {net, vfs} ← host-core`),
//! `spindle-net` must never depend on `spindle-host-core`. `spindle-net`'s `SignalingHost` gets a
//! session all the way to a verified, mutually-pinned `spindle_net::quic::ControlStream`, but
//! *driving the actual VFS RPC serve loop over it* is this crate's job, on this crate's own
//! `VfsRpcServer` — `signaling/host.rs`'s module doc comment names this exact gap and introduces
//! `SessionHandler` to close it, the same injection pattern applied a second time. This module is
//! where that trait finally meets a real implementation.
//!
//! # One owned `Store` per session, and the `Send` chain that forces it
//!
//! `serve_control_stream` takes its `VfsRpcServer` **by value** (see that function's own doc
//! comment for why: its `RefCell`-based caches make it deliberately `!Sync`, so the loop must own
//! it outright rather than share a reference across an await point). A `VfsRpcServer<Store>`
//! therefore needs one **owned** `Store` per session — not a borrowed `&Store` shared across every
//! session a host is serving. [`StoreFactory`] exists to produce that owned `Store` on demand,
//! because a shared reference would break more than `VfsRpcServer`'s own `!Sync` requirement: it
//! would make the *session future itself* `!Send`. `spindle_vfs::store::Store` wraps a
//! `rusqlite::Connection`, which is `Send` but **not** `Sync` — a `&Store` held across an await
//! point is only `Send` if `Store` is `Sync`, which it is not. `SessionHandler::handle_session` is
//! declared to return `impl Future<Output = ControlStream> + Send` precisely because
//! `SignalingHost::run` `tokio::spawn`s the future it returns, and `tokio::spawn` requires `Send`.
//! An **owned** `Store`, by contrast, closes over nothing but `Send` values, so the future built
//! around it is `Send` with no extra work.
//!
//! SQLite raises no objection to this: it supports multiple connections to one database file.
//! `crate::authorize::SqliteDeviceLookup`'s doc comment already sets this precedent for the
//! connect path ("a host should give this its own `Store` handle ... keeping the connect path off
//! the RPC path's connection entirely"); this module applies the identical pattern one hop later,
//! keeping each session's RPC path off every *other* session's connection too — a real host opens
//! one fresh [`StoreFactory::open`] handle per accepted session, exactly mirroring
//! `spindle_net::quic::QuicServer::accept`'s per-session `ControlStream`.
//!
//! The seam is a trait — not, say, a `PathBuf` field this handler opens directly — for the same
//! reason [`crate::authorize::DeviceLookup`] is a trait rather than a concrete `Store`: see
//! `authorize.rs`'s module doc comment. A host backed by a connection pool, or a store type this
//! crate has never heard of, can implement [`StoreFactory`] directly and skip
//! [`SqliteStoreFactory`] entirely.
//!
//! # The impl compiling is the `Send` proof
//!
//! There is deliberately no runtime test in this module asserting that
//! `VfsSessionHandler::handle_session`'s future is `Send` — none is needed, and none could prove
//! more than the compiler already has. `SessionHandler::handle_session` is declared
//! `-> impl std::future::Future<Output = ControlStream> + Send`; the `impl SessionHandler for
//! VfsSessionHandler<..>` block below only compiles if every value the generated future closes
//! over, across every await point inside it, is itself `Send`. That bound is checked once, at
//! compile time, across every possible execution path through this function — a unit test could
//! only ever exercise the handful of paths it happens to call. The compiler's check subsumes it.

use crate::authorize::{active_member_for_device, DeviceLookup};
use crate::limits::{FreeSpaceProbe, OsFreeSpace, UploadLimits};
use crate::ratelimit::RateLimitConfig;
use crate::serve::serve_control_stream;
use crate::server::{SessionContext, VfsRpcServer};
use spindle_core::Fingerprint;
use spindle_net::quic::ControlStream;
use spindle_net::signaling::host::SessionHandler;
use spindle_vfs::store::{Store, StoreError};
use std::path::PathBuf;

/// Sent when [`VfsSessionHandler::session_context`] refuses a session (the peer's device is
/// unenrolled, revoked, or its member is not `Active`) — see that method's doc comment. This close
/// is **terminal**: the member or device is no longer authorized to connect to this host, and
/// retrying will not change that outcome. See [`CLOSE_SESSION_UNAVAILABLE`] for the distinct,
/// transient code sent when the session gate passes but the store cannot be opened.
pub const CLOSE_SESSION_REFUSED: u32 = 1;

/// Sent when [`StoreFactory::open`] fails to produce a `Store` to serve the session with — after
/// [`VfsSessionHandler::session_context`]'s gate has already passed. Unlike
/// [`CLOSE_SESSION_REFUSED`], this close is **transient**: it says nothing about the peer's
/// authorization, only that the host could not open its own store just now, so retrying later is
/// reasonable.
///
/// This is a distinct numeric value and a distinct reason string from `CLOSE_SESSION_REFUSED`, not
/// a merge of the two. An earlier draft of this module merged them, reasoning that a peer able to
/// trigger both outcomes on demand could otherwise use *which* close code comes back as an oracle
/// for exactly the fact DESIGN.md §A4b says must never leak — whether a given `device_fp` belongs
/// to a currently-active, non-revoked member. That oracle is not reachable here. `handle_session`
/// is unreachable except after three gates have all already passed: `process_offer` resolved the
/// peer through the injected `ConnectAuthorizer` (i.e. `HostConnectAuthorizer` already returned
/// `Allow`), `open_offer` verified the offer's signature against the `sign_pk` that lookup
/// returned, and the QUIC handshake completed under mutual certificate pinning (see
/// `spindle_net::signaling::host::SignalingHost::handle_connect`). A party that cannot produce a
/// signature under an enrolled, active, non-revoked device's signing key never reaches this code
/// at all, so it cannot probe these two codes to enumerate anything. The only way
/// `session_context` still fails here is a revocation that landed during the ICE-plus-handshake
/// window — a peer that *did* legitimately hold the key moments earlier. Telling that peer "you
/// were refused" rather than "the host is broken" leaks nothing it could not already determine.
///
/// Keeping the codes distinct instead buys real client behaviour: a client that sees
/// `CLOSE_SESSION_REFUSED` knows not to retry (the member or device is no longer authorized),
/// while one that sees `CLOSE_SESSION_UNAVAILABLE` knows retrying later is reasonable. A merged
/// code would make a client unable to tell a permanent revocation from a temporary host fault,
/// which is a worse outcome than the unreachable oracle the merge was meant to avoid.
///
/// Note that §A4b's "unauthorized is indistinguishable from not-found" posture still governs the
/// *pre-auth* surfaces — `HostConnectAuthorizer`'s uniform `Deny`, and §A5's uniform silent drops.
/// This is post-auth, which is the same distinction `serve.rs`'s module doc comment already draws
/// when it explains why typed `VfsErrorCode` replies are allowed inside an authenticated session
/// but not before one.
pub const CLOSE_SESSION_UNAVAILABLE: u32 = 2;

/// Sent when [`crate::serve::serve_control_stream`] returns `Err(ServeError)` — a framing or
/// decode violation from a peer already past the session gate above. Deliberately a distinct value
/// from [`CLOSE_SESSION_REFUSED`]/[`CLOSE_SESSION_UNAVAILABLE`]: by the time this fires, the peer
/// has already been let into a live, authorized session, so this code carries no information about
/// authorization status — there is nothing left to protect by making it indistinguishable from the
/// others.
pub const CLOSE_PROTOCOL_VIOLATION: u32 = 3;

/// Produces one **owned** [`Store`] per call — see the module doc comment for why
/// [`VfsSessionHandler`] needs a fresh one per session rather than a shared `&Store`.
pub trait StoreFactory: Send + Sync {
    fn open(&self) -> Result<Store, StoreError>;
}

/// The production [`StoreFactory`]: opens a fresh SQLite connection to the same database file on
/// every call. See the module doc comment for why repeatedly opening the same path is exactly
/// right (SQLite supports multiple connections to one file) rather than a workaround.
pub struct SqliteStoreFactory {
    path: PathBuf,
}

impl SqliteStoreFactory {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        SqliteStoreFactory { path: path.into() }
    }
}

impl StoreFactory for SqliteStoreFactory {
    fn open(&self) -> Result<Store, StoreError> {
        Store::open(&self.path)
    }
}

/// The production `SessionHandler`: for every session a host's `SignalingHost` establishes, opens
/// a fresh `Store` via `store_factory`, re-checks that the peer's device is still live (see
/// [`Self::session_context`]), and drives [`crate::serve::serve_control_stream`] over the session's
/// `ControlStream` on a per-session [`VfsRpcServer`].
///
/// `probe_factory` produces a fresh [`FreeSpaceProbe`] per session, rather than this struct holding
/// one shared probe value, because each session gets its own `VfsRpcServer` (see
/// `VfsRpcServer::with_limits`) and `Box<dyn FreeSpaceProbe + Send>` is not `Clone` — there is no
/// single boxed value that could be handed to more than one session anyway.
pub struct VfsSessionHandler<F, L, N> {
    store_factory: F,
    lookup: L,
    now_fn: N,
    limits: UploadLimits,
    probe_factory: Box<dyn Fn() -> Box<dyn FreeSpaceProbe + Send> + Send + Sync>,
}

impl<F, L, N> VfsSessionHandler<F, L, N>
where
    F: StoreFactory,
    L: DeviceLookup,
    N: Fn() -> u64 + Send + Sync,
{
    /// Builds a handler with `UploadLimits::default()` and, notably, `OsFreeSpace` (not
    /// `VfsRpcServer::new`'s `UnlimitedFreeSpace`) as the default free-space probe.
    ///
    /// This is a deliberate departure from `VfsRpcServer::new`'s own default. `UnlimitedFreeSpace`
    /// is the right default there because `VfsRpcServer::new` exists chiefly to keep unit tests
    /// from depending on host-machine free space (see `crate::limits`'s module doc comment); it is
    /// the wrong default for a real host, where it silently disables DESIGN.md §A8's free-space
    /// floor entirely. [`VfsSessionHandler`], unlike `VfsRpcServer`, only ever exists inside a real
    /// host process — nothing in a test suite constructs one to drive a serve loop directly, the
    /// way `crate::server`'s tests construct a bare `VfsRpcServer`. A daemon that never explicitly
    /// opted into a real probe would ship §A8's protection missing and not notice, so this
    /// constructor flips the polarity of the default: the safe, real-OS probe is what you get for
    /// free, and the unlimited, test-only probe is the thing you must ask for via
    /// [`Self::with_limits`].
    ///
    /// Rate-limit configuration is deliberately **not** plumbed through this constructor (or
    /// [`Self::with_limits`]): out of scope by user decision 2026-09-02 (td-4bcf24).
    /// [`VfsRpcServer::with_limits`] is always called with `RateLimitConfig::default()` — see
    /// [`SessionHandler::handle_session`]'s implementation below.
    pub fn new(store_factory: F, lookup: L, now_fn: N) -> Self {
        Self::with_limits(
            store_factory,
            lookup,
            now_fn,
            UploadLimits::default(),
            Box::new(|| Box::new(OsFreeSpace) as Box<dyn FreeSpaceProbe + Send>),
        )
    }

    /// As [`Self::new`], but with explicit `limits` and `probe_factory` — production wiring that
    /// wants non-default quotas, or a test exercising this handler end to end with a fake probe.
    pub fn with_limits(
        store_factory: F,
        lookup: L,
        now_fn: N,
        limits: UploadLimits,
        probe_factory: Box<dyn Fn() -> Box<dyn FreeSpaceProbe + Send> + Send + Sync>,
    ) -> Self {
        VfsSessionHandler {
            store_factory,
            lookup,
            now_fn,
            limits,
            probe_factory,
        }
    }
}

impl<F, L, N> VfsSessionHandler<F, L, N>
where
    L: DeviceLookup,
{
    /// Re-runs DESIGN.md §A4's member-active-and-device-not-revoked rule at the moment the
    /// session's QUIC control stream comes up, via [`crate::authorize::active_member_for_device`]
    /// (the same helper `HostConnectAuthorizer::authorize` uses for its own checks 1–5).
    ///
    /// This gate is **not** what makes revocation safe. §A4's Revocation paragraph is explicit
    /// that the per-request check is the authoritative one — "the host rejects envelopes/VFS
    /// requests from revoked keys per request (authoritative)" — and `server.rs`'s
    /// `denied:device_revoked` gate runs that check on every request inside every session,
    /// including this one. Delete this method entirely and a revoked device is still denied, on
    /// its very first VFS request, by that gate. §A4 names exactly one authoritative checkpoint
    /// for revocation, and this is not it; it draws no three-point line.
    ///
    /// What this gate is actually for is two other things.
    ///
    /// First, structurally: [`crate::serve::serve_control_stream`] requires a [`SessionContext`],
    /// and its `member_id` has to come from somewhere. Resolving it through
    /// [`crate::authorize::active_member_for_device`] makes that resolution fail-closed by
    /// construction — there is no separate, weaker `member_id` lookup anywhere in this crate that
    /// could hand back an identifier for a revoked device — rather than leaving a future caller to
    /// remember to re-derive the same liveness check by hand.
    ///
    /// Second, as a cheap early-out: admitting a session whose every request is guaranteed to be
    /// denied wastes a QUIC connection and a `Store` handle for no benefit. Refusing at the door,
    /// before a single `VfsRpcServer` is even constructed, is both clearer to the peer (it learns
    /// immediately that it has no path in, rather than only after successfully opening a session)
    /// and cheaper for the host.
    ///
    /// It remains true that this method must not assume `HostConnectAuthorizer`'s earlier verdict
    /// still holds: `HostConnectAuthorizer::authorize` ran once, when the connect *offer* arrived,
    /// over NATS, and real wall-clock time passes between that moment and this one — DESIGN.md
    /// §A6's ICE gathering, ICE connectivity checks, and the QUIC handshake itself all have to
    /// complete, time enough for an owner to revoke the member, or this one device, before the
    /// session this offer led to ever comes up. That gap is why this check is re-run here rather
    /// than cached from the connect-time decision — not because DESIGN.md mandates a distinct
    /// checkpoint, but because caching a verdict across that gap would be wrong regardless of what
    /// DESIGN.md says about it. It fails closed exactly like the connect-time authorizer and the
    /// per-request gate do.
    fn session_context(&self, peer_device_fp: Fingerprint) -> Option<SessionContext> {
        let member = active_member_for_device(&self.lookup, peer_device_fp)?;
        Some(SessionContext {
            member_id: member.member_id,
            device_fp: Some(peer_device_fp),
        })
    }
}

impl<F, L, N> SessionHandler for VfsSessionHandler<F, L, N>
where
    F: StoreFactory,
    L: DeviceLookup,
    N: Fn() -> u64 + Send + Sync,
{
    /// Refuse (session gate fails, or the store can't be opened), serve (drive
    /// `serve_control_stream` to completion), or fail mid-session (a protocol violation) — see the
    /// module doc comment's `Send` discussion for why this can be `async fn` here at all.
    ///
    /// The clean-EOF and protocol-violation outcomes are handled asymmetrically on purpose: a
    /// clean EOF means the peer closed its own send side, so this method leaves the `ControlStream`
    /// (and its `Connection`) alone and returns it as-is, letting
    /// `SignalingHost::handle_connect`'s bounded `connection.closed()` wait (see
    /// `spindle_net::signaling::host`'s module doc comment) observe the peer's *own* close.
    /// Calling [`ControlStream::close`] here too would risk exactly the race that module doc
    /// comment documents finding empirically in `spikes/s2-signaling`: an explicit close can
    /// discard a reply the peer has not read yet. On the refusal and protocol-violation paths,
    /// by contrast, there is nothing left to deliver — either nothing was ever sent, or the peer
    /// has already broken the protocol this stream speaks — so calling `close` costs nothing and
    /// ends the session promptly instead of leaving it to the bounded wait's full timeout.
    async fn handle_session(
        &self,
        peer_device_fp: Fingerprint,
        control: ControlStream,
    ) -> ControlStream {
        let Some(ctx) = self.session_context(peer_device_fp) else {
            control.close(CLOSE_SESSION_REFUSED, b"session refused");
            return control;
        };

        let store = match self.store_factory.open() {
            Ok(store) => store,
            Err(_) => {
                control.close(CLOSE_SESSION_UNAVAILABLE, b"host store unavailable");
                return control;
            }
        };

        let server = VfsRpcServer::with_limits(
            store,
            self.limits,
            (self.probe_factory)(),
            RateLimitConfig::default(),
        );

        let ControlStream {
            connection,
            mut send,
            mut recv,
        } = control;
        let result =
            serve_control_stream(server, &ctx, || (self.now_fn)(), &mut recv, &mut send).await;
        let control = ControlStream {
            connection,
            send,
            recv,
        };

        match result {
            Ok(()) => control,
            Err(_) => {
                control.close(CLOSE_PROTOCOL_VIOLATION, b"protocol violation");
                control
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorize::{LookupError, SqliteDeviceLookup};
    use spindle_core::identity::DeviceKey;
    use spindle_vfs::model::{DevicePublicKeys, Member, MemberId};

    fn store_with_active_member(display_name: &str) -> (Store, MemberId) {
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
        member_id: MemberId,
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

    /// A [`StoreFactory`] never actually reached by any `session_context`-only test below —
    /// present only so `VfsSessionHandler::new` type-checks.
    struct NeverOpenedStoreFactory;
    impl StoreFactory for NeverOpenedStoreFactory {
        fn open(&self) -> Result<Store, StoreError> {
            panic!("session_context tests never open a store")
        }
    }

    fn handler_for<L: DeviceLookup>(
        lookup: L,
    ) -> VfsSessionHandler<NeverOpenedStoreFactory, L, fn() -> u64> {
        VfsSessionHandler::new(NeverOpenedStoreFactory, lookup, || 0)
    }

    #[test]
    fn resolves_an_active_members_enrolled_device_to_its_member_id_and_device_fp() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x01; 32], [0x02; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        let handler = handler_for(SqliteDeviceLookup::new(store));

        let ctx = handler
            .session_context(device_fp)
            .expect("expected Some for an active member's enrolled device");
        assert_eq!(ctx.member_id, member_id);
        assert_eq!(ctx.device_fp, Some(device_fp));
    }

    #[test]
    fn refuses_a_device_fp_that_was_never_enrolled() {
        let (store, _member_id) = store_with_active_member("alex");
        let handler = handler_for(SqliteDeviceLookup::new(store));

        let stranger = DeviceKey::from_seeds([0x03; 32], [0x04; 32]).device_fp();
        assert!(handler.session_context(stranger).is_none());
    }

    #[test]
    fn refuses_a_still_invited_members_device() {
        let store = Store::open_in_memory().expect("open in-memory store");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"pending"]), "pending", 0)
            .expect("add_member");
        // deliberately not activated: stays MemberStatus::Invited
        let device = DeviceKey::from_seeds([0x05; 32], [0x06; 32]);
        let device_fp = enroll_device(&store, member_id, "phone", &device);
        let handler = handler_for(SqliteDeviceLookup::new(store));

        assert!(handler.session_context(device_fp).is_none());
    }

    #[test]
    fn refuses_a_revoked_members_device() {
        let (store, member_id) = store_with_active_member("bad-actor");
        let device = DeviceKey::from_seeds([0x07; 32], [0x08; 32]);
        let device_fp = enroll_device(&store, member_id, "laptop", &device);
        store.revoke_member(member_id).expect("revoke_member");
        let handler = handler_for(SqliteDeviceLookup::new(store));

        assert!(handler.session_context(device_fp).is_none());
    }

    #[test]
    fn refuses_a_revoked_device_whose_member_is_still_active() {
        let (store, member_id) = store_with_active_member("alex");
        let device = DeviceKey::from_seeds([0x09; 32], [0x0a; 32]);
        let device_fp = enroll_device(&store, member_id, "old-laptop", &device);
        store.revoke_device(device_fp).expect("revoke_device");
        let handler = handler_for(SqliteDeviceLookup::new(store));

        assert!(handler.session_context(device_fp).is_none());
    }

    #[test]
    fn refuses_a_session_when_the_lookup_itself_fails() {
        struct AlwaysFails;
        impl DeviceLookup for AlwaysFails {
            fn member_for_device_fp(
                &self,
                _device_fp: Fingerprint,
            ) -> Result<Option<Member>, LookupError> {
                Err(LookupError::LockPoisoned)
            }
        }

        let handler = handler_for(AlwaysFails);
        let some_fp = DeviceKey::from_seeds([0x0f; 32], [0x10; 32]).device_fp();
        assert!(handler.session_context(some_fp).is_none());
    }

    #[test]
    fn sqlite_store_factory_open_yields_a_working_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("host.sqlite3");
        let factory = SqliteStoreFactory::new(&path);

        let store = factory
            .open()
            .expect("open should succeed against a fresh path");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "alex", 0)
            .expect("add_member on the opened store should work");
        store
            .activate_member(member_id)
            .expect("activate_member on the opened store should work");
    }

    #[test]
    fn sqlite_store_factory_open_called_twice_yields_two_independent_handles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("host.sqlite3");
        let factory = SqliteStoreFactory::new(&path);

        let store_a = factory.open().expect("first open");
        let member_id = store_a
            .add_member(Fingerprint::of_parts(&[b"alex"]), "alex", 0)
            .expect("add_member via the first handle");

        // A second, independent connection to the same file sees what the first wrote.
        let store_b = factory.open().expect("second open");
        let member = store_b
            .get_member(member_id)
            .expect("get_member via the second handle")
            .expect("member written via the first handle should be visible via the second");
        assert_eq!(member.display_name, "alex");
    }
}
