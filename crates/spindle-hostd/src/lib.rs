//! [`HostDaemon`] — the assembled host process: the injected-trait implementations
//! `spindle-host-core` supplies (`HostConnectAuthorizer`, `VfsSessionHandler`) wired to a real
//! `spindle_net::signaling::host::SignalingHost` and driven to completion. This crate exists so
//! that assembly is written exactly once, in a place both `src/main.rs` (this crate's dev-only
//! binary) and, eventually, `apps/host`'s Tauri shell (Stage 7) can call — see this crate's
//! `Cargo.toml` header comment for why the wiring could not simply live as a `[[bin]]` inside
//! `spindle-host-core` itself (in short: that would drag `async-nats` and a Tokio runtime into a
//! library the Tauri shell links in-process, per DESIGN.md §A10.26).
//!
//! The library, not the binary, is the deliverable. `apps/host` is a user decision away
//! (2026-09-02) from calling directly into [`HostDaemon`] rather than re-deriving this wiring on
//! its own side of the boundary — every piece of assembly below is therefore written to be called
//! from a non-`main` caller, not just from this crate's own `src/main.rs`.
//!
//! # The caller-owned NATS client rule
//!
//! [`HostDaemon::new`] takes an **already-connected** `async_nats::Client`. This crate never
//! connects one itself, for the same reason `spindle_net::signaling::host::SignalingHost`'s own
//! doc comment states it: "holds the caller-owned NATS client (never connects one itself)". The
//! connection has to be callout-authenticated (DESIGN.md §A4/§A5) by whatever code holds the
//! credentials — this crate's `src/main.rs` in dev, the Tauri shell's own connection setup in
//! Stage 7 — and a live test needs to be able to inject a connection of its own (a fake or
//! sandboxed `nats-server`) rather than have one materialize from environment state this crate
//! reached into on its own.
//!
//! # Two fingerprints, not one
//!
//! [`HostDaemon::new`] takes **two** distinct identifiers, and they are not interchangeable:
//!
//! - `device`: this host's **envelope** identity (DESIGN.md §A7's `to_fp`/`from_fp`, and the
//!   X25519 half `k0`/`k1` are derived from it). A connect offer's `to_fp` is this device's
//!   `device_fp`.
//! - `host_fp`: this host's **root** fingerprint (`hash(host_root_pk)`) — the `<hfp>` token every
//!   DESIGN.md §A5 NATS subject is scoped by (`host.<hfp>.connect`, `host.<hfp>.presence`, ...).
//!
//! `spindle_net::signaling::host::SignalingHost`'s own doc comment ("Two fingerprints, not one")
//! and `spindle_net::signaling::client::HostIdentity`'s doc comment both draw this same line, and
//! both name the same live failure this crate must not repeat: a run that collapsed the two into
//! one fingerprint failed with `Permissions Violation for Subscription to
//! "host.<device_fp>.connect"`, because the Auth Callout grants `sub host.<host_fp>.>` — the
//! *root* fingerprint, not the envelope device fingerprint — to a host's connection. Passing
//! `device.device_fp()` where `host_fp` belongs (or vice versa) compiles cleanly and fails only at
//! runtime, against a live NATS server, in exactly that shape. Keep the two straight.
//!
//! # Store handles: one per seam, never shared
//!
//! [`HostDaemon::run`] opens **three** independent SQLite connections to the same store file
//! rather than passing one `Store` handle around: one for the connect-time
//! [`spindle_host_core::SqliteDeviceLookup`] behind [`spindle_host_core::HostConnectAuthorizer`],
//! one for the session-time `SqliteDeviceLookup` behind [`spindle_host_core::VfsSessionHandler`],
//! and — via [`spindle_host_core::SqliteStoreFactory`] — a fresh one per accepted RPC session.
//! `SqliteDeviceLookup`'s own doc comment sets the precedent this follows: "a host should give
//! this its own `Store` handle ... keeping the connect path off the RPC path's connection
//! entirely". `VfsSessionHandler` needs a `DeviceLookup` of its own for exactly the same
//! `!Sync`-vs-`Send` reason `HostConnectAuthorizer` does (see that struct's own module doc
//! comment) — it cannot reuse the connect authorizer's lookup, because `HostConnectAuthorizer`
//! consumes the one it is given by value. Rather than introduce sharing (an `Arc<Mutex<Store>>`
//! neither type asks for, and a lock two independent call sites would then contend over for no
//! reason — connect-time authorization and per-session liveness re-checks never need to observe
//! each other's in-flight reads), this crate opens a second, independent connection instead.
//! SQLite supports multiple connections to one database file, which is the same fact
//! `SqliteStoreFactory`'s own doc comment already leans on to justify opening a fresh connection
//! per RPC session; three independent connections in one process is the same pattern applied one
//! more time, not a new one.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use spindle_core::identity::DeviceKey;
use spindle_core::Fingerprint;
use spindle_host_core::{
    HostConnectAuthorizer, SqliteDeviceLookup, SqliteStoreFactory, StoreFactory, VfsSessionHandler,
};
use spindle_net::signaling::host::SignalingHost;
use spindle_net::signaling::SignalingError;
use spindle_vfs::store::StoreError;

/// Re-exported so a caller — this crate's own `src/main.rs`, `apps/host`'s Tauri shell (Stage 7),
/// or a test — can configure [`HostDaemon::run`]'s connect/session lifecycle knobs without also
/// depending on `spindle-net` directly for this one type.
pub use spindle_net::signaling::host::HostOptions;

/// The real wall-clock `now_fn`: `SystemTime::now()` truncated to whole seconds since the Unix
/// epoch. Never called directly by [`HostDaemon::run`] — see [`HostDaemon::new`]'s doc comment for
/// why the clock is instead threaded through as an injectable closure.
///
/// Saturates to `0` rather than panicking if the system clock reads before the epoch — a
/// misconfigured clock should degrade the daemon's timestamps, not crash it outright. This mirrors
/// `spindle_host_core::serve::serve_control_stream`'s own `now_fn` seam and
/// `spindle_host_core::server::VfsRpcServer::handle_bytes`'s `ts` parameter: every timestamp seam
/// in this workspace is injectable so a test can supply a deterministic clock instead of racing the
/// real one.
pub fn wall_clock_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Everything [`HostDaemon::run`] can fail with. Construction itself
/// ([`HostDaemon::new`]) cannot fail — it only stores the values the caller already produced (an
/// already-connected NATS client, this host's two identities, and a store path) — so this enum
/// only covers what can go wrong once `run` actually starts opening store connections and driving
/// the signaling host.
#[derive(Debug, thiserror::Error)]
pub enum HostDaemonError {
    /// One of the three independent SQLite connections `run` opens (see this crate's module doc
    /// comment's "Store handles" section) failed to open.
    #[error("failed to open host store: {0}")]
    Store(#[from] StoreError),

    /// `SignalingHost::run` failed — most commonly, subscribing on `host.<host_fp>.connect`
    /// itself, since that is the one fallible step between a successfully-assembled
    /// `SignalingHost` and an unboundedly-running connect loop.
    #[error("signaling host failed: {0}")]
    Signaling(#[from] SignalingError),
}

/// The concrete `SignalingHost` type [`HostDaemon::run`] assembles and drives: this crate's own
/// `HostConnectAuthorizer<SqliteDeviceLookup>` for the connect-time membership decision, and its
/// own `VfsSessionHandler<SqliteStoreFactory, SqliteDeviceLookup, N>` for the per-session VFS RPC
/// serve loop, where `N` is whatever `now_fn` closure type [`HostDaemon::new`] was given.
type AssembledSignalingHost<N> = SignalingHost<
    HostConnectAuthorizer<SqliteDeviceLookup>,
    VfsSessionHandler<SqliteStoreFactory, SqliteDeviceLookup, N>,
>;

/// A `now_fn` closure boxed to a single concrete type, so [`HostDaemon`] itself does not need to be
/// generic over every caller's choice of clock. [`HostDaemon::new`] takes any `Fn() -> u64 + Send +
/// Sync + 'static` and boxes it here once; [`wall_clock_now_secs`] is the production default a
/// caller reaches for when it has no reason to inject anything else, and a test supplies its own
/// deterministic closure instead — the same seam `serve_control_stream`'s `now_fn` and
/// `VfsRpcServer::handle_bytes`'s `ts` establish elsewhere in this workspace.
type BoxedNowFn = Box<dyn Fn() -> u64 + Send + Sync + 'static>;

/// The assembled host process for one host identity: an already-connected NATS client, this host's
/// two fingerprints (see this module's doc comment's "Two fingerprints, not one" section), the
/// path to this host's SQLite store, and an injectable wall-clock closure. [`HostDaemon::run`]
/// turns these five values into a running `SignalingHost` and drives it to completion (i.e. until
/// the NATS connection is dropped or closed — `SignalingHost::run`'s own doc comment is explicit
/// that it has no separate shutdown signal of its own, and this crate does not add one).
///
/// See the module doc comment for the caller-owned-NATS-client rule this constructor follows, and
/// for why `device` and `host_fp` are two distinct values rather than one.
pub struct HostDaemon {
    nats: async_nats::Client,
    device: DeviceKey,
    host_fp: Fingerprint,
    store_path: PathBuf,
    now_fn: BoxedNowFn,
}

impl HostDaemon {
    /// Builds a daemon from an **already-connected** `async_nats::Client`, this host's envelope
    /// [`DeviceKey`], its root [`Fingerprint`], and the path to its SQLite store. Uses
    /// [`wall_clock_now_secs`] as the clock — call [`Self::with_now_fn`] instead to inject a
    /// deterministic one (a live test's fixed clock, for instance).
    ///
    /// This constructor cannot fail: it only stores the values above. Every fallible step (opening
    /// the store connections, subscribing on NATS) happens in [`Self::run`].
    pub fn new(
        nats: async_nats::Client,
        device: DeviceKey,
        host_fp: Fingerprint,
        store_path: impl Into<PathBuf>,
    ) -> Self {
        Self::with_now_fn(nats, device, host_fp, store_path, wall_clock_now_secs)
    }

    /// As [`Self::new`], but with an explicit `now_fn` — the injectable-clock seam this module's
    /// doc comment on [`wall_clock_now_secs`] describes.
    pub fn with_now_fn(
        nats: async_nats::Client,
        device: DeviceKey,
        host_fp: Fingerprint,
        store_path: impl Into<PathBuf>,
        now_fn: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Self {
        HostDaemon {
            nats,
            device,
            host_fp,
            store_path: store_path.into(),
            now_fn: Box::new(now_fn),
        }
    }

    /// Assembles and drives the whole connect path, per this module's doc comment's "Store
    /// handles" section:
    ///
    /// 1. Opens three independent SQLite connections to `store_path` — one for the connect-time
    ///    `SqliteDeviceLookup`, one for the session-time `SqliteDeviceLookup`, and a
    ///    [`SqliteStoreFactory`] that opens a fourth (and every subsequent) connection lazily, one
    ///    per accepted RPC session.
    /// 2. Wraps the connect-time lookup in [`HostConnectAuthorizer`] and the session-time lookup
    ///    (plus the factory) in [`VfsSessionHandler`].
    /// 3. Builds a [`SignalingHost`] from the caller-owned NATS client, this host's two
    ///    fingerprints, and those two injected implementations, then runs it.
    ///
    /// Consumes `self`: a `HostDaemon` is a one-shot recipe for one running host process, not a
    /// value a caller re-runs after this returns.
    pub async fn run(self, opts: HostOptions) -> Result<(), HostDaemonError> {
        let HostDaemon {
            nats,
            device,
            host_fp,
            store_path,
            now_fn,
        } = self;

        let factory = SqliteStoreFactory::new(&store_path);

        // Independent connection #1: the connect path's own lookup (never the RPC path's) — see
        // `SqliteDeviceLookup`'s doc comment and this module's doc comment.
        let connect_store = factory.open()?;
        let authorizer = HostConnectAuthorizer::new(SqliteDeviceLookup::new(connect_store));

        // Independent connection #2: the session handler's own lookup. `HostConnectAuthorizer`
        // consumed the first `SqliteDeviceLookup` by value above, so `VfsSessionHandler` needs a
        // second one of its own rather than a reference to the first.
        let session_lookup_store = factory.open()?;
        let session_lookup = SqliteDeviceLookup::new(session_lookup_store);

        // `factory` itself is moved in here; every RPC session gets its own connection (#3, #4,
        // ...) opened on demand by `VfsSessionHandler::handle_session` via `StoreFactory::open`.
        let handler = VfsSessionHandler::new(factory, session_lookup, now_fn);

        let host: AssembledSignalingHost<_> =
            SignalingHost::new(nats, device, host_fp, authorizer, handler);
        Arc::new(host).run(opts).await?;
        Ok(())
    }
}
