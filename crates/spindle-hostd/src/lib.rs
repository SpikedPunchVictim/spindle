//! [`HostDaemon`] — the assembled host process: the injected-trait implementations
//! `spindle-host-core` supplies (`HostConnectAuthorizer`, `VfsSessionHandler`) wired to a real
//! `spindle_net::signaling::host::SignalingHost` and driven to completion. This crate exists so
//! that assembly is written exactly once, in a place both this crate's own live integration test
//! (`tests/live_hostd.rs`) and, eventually, `apps/host`'s Tauri shell (Stage 7) can call — see
//! this crate's `Cargo.toml` header comment for why the wiring could not simply live as a
//! `[[bin]]` inside `spindle-host-core` itself (in short: that would drag `async-nats` and a
//! Tokio runtime into a library the Tauri shell links in-process, per DESIGN.md §A10.26).
//!
//! The library, not the binary, is the deliverable. `apps/host` is a user decision away
//! (2026-09-02) from calling directly into [`HostDaemon`] rather than re-deriving this wiring on
//! its own side of the boundary — every piece of assembly below is therefore written to be called
//! from a non-`main` caller, not just from this crate's own live integration test
//! (`tests/live_hostd.rs`).
//!
//! # Why this crate ships no binary (yet)
//!
//! This crate is library-only today: no `src/main.rs`, no `[[bin]]` target. [`HostDaemon::new`]
//! needs this host's envelope [`DeviceKey`] and root [`Fingerprint`] (`host_fp`) — see this
//! module's "Two fingerprints, not one" section below — and DESIGN.md §A4 puts custody of a
//! host's root key in the OS keystore, the same custody model §A4 states for a person's identity
//! root key. That keystore integration is Stage 7 work and does not exist anywhere in this
//! workspace yet, confirmed against `crates/spindle-vfs/src/store/schema.rs`, which has no table
//! for a host root key, an operating key, or a device key of any kind.
//!
//! The only public way this workspace can produce a [`DeviceKey`] today is
//! [`DeviceKey::generate`] (a fresh, unpersisted random keypair — useless here, since a real host
//! needs the *same* identity across restarts) or [`DeviceKey::from_seeds`], whose own doc comment
//! reads "Deterministic construction from two 32-byte seeds — TEST-ONLY / crypto-vector use."
//! Wiring seeds in from the environment would satisfy the type signature while being a dishonest
//! implementation of key custody, not a real one. A binary that cannot possibly work is worse
//! than no binary at all — someone runs it, it fails, and they conclude the daemon itself is
//! broken — so no binary ships until there is something real for it to do.
//!
//! Stage 7, when OS-keystore-backed host identity lands, is when a real entry point appears —
//! either a binary here, or, per this module's own opening paragraphs, `apps/host`'s Tauri shell
//! calling [`HostDaemon`] directly instead.
//!
//! # The caller-owned NATS client rule
//!
//! [`HostDaemon::new`] takes an **already-connected** `async_nats::Client`. This crate never
//! connects one itself, for the same reason `spindle_net::signaling::host::SignalingHost`'s own
//! doc comment states it: "holds the caller-owned NATS client (never connects one itself)". The
//! connection has to be callout-authenticated (DESIGN.md §A4/§A5) by whatever code holds the
//! credentials — this crate's own live integration test (`tests/live_hostd.rs`) in dev, the
//! Tauri shell's own connection setup in Stage 7 — and a live test needs to be able to inject a
//! connection of its own (a fake or sandboxed `nats-server`) rather than have one materialize
//! from environment state this crate reached into on its own.
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
//! [`HostDaemon::run`] opens **two** independent SQLite connections eagerly, rather than passing
//! one `Store` handle around: one for the connect-time
//! [`spindle_host_core::SqliteDeviceLookup`] behind [`spindle_host_core::HostConnectAuthorizer`],
//! and one for the session-time `SqliteDeviceLookup` behind
//! [`spindle_host_core::VfsSessionHandler`]. It also constructs a
//! [`spindle_host_core::SqliteStoreFactory`] — which is not itself a connection — and that
//! factory opens one further connection per accepted RPC session, lazily.
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
//! per RPC session; opening this second, independent connection here applies that same pattern
//! once more, not a new one.
//!
//! # `tracing` (td-6c9d95 step 4): library only, no subscriber
//!
//! This crate emits `tracing` events at a handful of lifecycle call sites in [`HostDaemon::run`] —
//! startup, the cap-issuer seam, and how the signaling run loop exits — following the house style
//! `crates/spindle-vfs`'s instrumentation (step 2) set. No call site here carries a filesystem or
//! virtual path (the store path is a path and is never logged), a file or group name, capability
//! bytes, key material, or a payload; identifiers that do appear are truncated via
//! `spindle_core::Fingerprint::redacted()`. This crate also does not duplicate the tamper-evident
//! audit log `spindle-host-core` already writes (DESIGN.md:413) — tracing here is lifecycle
//! visibility for an operator, not an audit trail.
//!
//! **This crate must never call `tracing_subscriber` or install a global subscriber**, even though
//! it is daemon-shaped. It is a library with no runtime of its own — see this module's own "Why
//! this crate ships no binary (yet)" section above — and installing a subscriber here would apply
//! workspace-wide to whatever binary eventually links this crate, including `apps/host`'s Tauri
//! shell, which must own that decision itself. Only a binary initializes one (see
//! `crates/spindle-helper/src/bin/helper.rs:349-351`'s `tracing_subscriber::fmt()...init()` for the
//! precedent this crate's future binary, or `apps/host`, should follow). If output from this crate
//! ever seems to vanish, the fix is to init a subscriber in the consuming binary, not to add one
//! here.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use spindle_core::identity::DeviceKey;
use spindle_core::Fingerprint;
use spindle_host_core::{
    CapIssuer, HostConnectAuthorizer, SqliteDeviceLookup, SqliteStoreFactory, StoreFactory,
    VfsSessionHandler,
};
use spindle_net::signaling::host::SignalingHost;
use spindle_net::signaling::SignalingError;
use spindle_vfs::store::StoreError;

/// Re-exported so a caller — this crate's own live integration test (`tests/live_hostd.rs`)
/// today, or `apps/host`'s Tauri shell in Stage 7 — can configure [`HostDaemon::run`]'s
/// connect/session lifecycle knobs without also depending on `spindle-net` directly for this one
/// type.
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
    /// One of the two SQLite connections `run` opens eagerly (see this crate's module doc
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
    /// The optional cap-issuing seam (td-c74122 slice D). `None` by default — see
    /// [`Self::with_cap_issuer`]'s doc comment for why this crate never builds a
    /// [`spindle_host_core::RootKeyCapIssuer`] on its own.
    issuer: Option<Box<dyn CapIssuer>>,
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
            issuer: None,
        }
    }

    /// Installs a [`spindle_host_core::CapIssuer`] so [`Self::run`] wires
    /// [`HostConnectAuthorizer::with_issuer`] instead of [`HostConnectAuthorizer::new`] — every
    /// successful connect this daemon serves then carries a freshly-minted member capability in
    /// its answer (DESIGN.md:286's "refreshed opportunistically on every successful session").
    /// Without this call, [`Self::run`] falls back to no issuer at all and every answer's
    /// `member_cap` is `None`, exactly as [`HostConnectAuthorizer::new`]'s own doc comment
    /// describes.
    ///
    /// # Why the daemon takes an issuer rather than building one from key material
    ///
    /// Constructing a real [`spindle_host_core::RootKeyCapIssuer`] needs three pieces of this
    /// host's own signing material: its root public key, its current operating-key certificate,
    /// and — the sensitive one — the operating **signing** key itself. Per DESIGN.md §A4, custody
    /// of that key belongs in an OS keystore, and (per this module's own doc comment's "Why this
    /// crate ships no binary (yet)" section) that keystore integration is unresolved Stage 7
    /// work — the same blocker recorded against td-539ffa and S13. If `HostDaemon` reached into
    /// key material to build its own issuer, this crate would need to either grow that keystore
    /// dependency itself or fall back to a dishonest stand-in (seeds from the environment, say),
    /// neither of which this crate should do on its caller's behalf. Taking `Box<dyn CapIssuer>`
    /// instead keeps key custody entirely on the caller's side of the boundary: today, this
    /// crate's own live integration test builds a [`spindle_host_core::RootKeyCapIssuer`] from
    /// test-fixture key material and installs it here; once Stage 7's keystore lands, the real
    /// caller (a binary here, or `apps/host`'s Tauri shell per this module's doc comment) does the
    /// same with real key material, and this crate's own code does not change at all.
    ///
    /// Chainable, matching [`spindle_host_core::RootKeyCapIssuer::new`]'s own builder shape
    /// (`new(...).with_now_fn(...)`), not this struct's own alternative-constructor shape
    /// (`HostDaemon::new` / `HostDaemon::with_now_fn`) — this is a single optional knob added onto
    /// an already-built `HostDaemon`, not a second way to construct one from scratch.
    pub fn with_cap_issuer(self, issuer: Box<dyn CapIssuer>) -> Self {
        HostDaemon {
            issuer: Some(issuer),
            ..self
        }
    }

    /// Assembles and drives the whole connect path, per this module's doc comment's "Store
    /// handles" section:
    ///
    /// 1. Opens two independent SQLite connections to `store_path` eagerly — one for the
    ///    connect-time `SqliteDeviceLookup`, one for the session-time `SqliteDeviceLookup` — and
    ///    constructs a [`SqliteStoreFactory`] (not itself a connection) that opens one further
    ///    connection lazily per accepted RPC session: the third, the fourth, and so on.
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
            issuer,
        } = self;

        // Bound to a plain local first (rather than interpolating `device.device_fp().redacted()`
        // directly) so `crates/spindle-core/tests/redaction_guard.rs`'s text scan can see the
        // `.redacted()` call immediately after the flagged `_fp` binding — its heuristic does not
        // look past an intermediate method call's parentheses. Truncated per this crate's
        // redaction policy (see this module's `tracing` doc section) — enough for an operator to
        // tell which host this log came from, never enough to identify it on its own.
        let device_fp = device.device_fp();
        tracing::info!(
            device_fp = %device_fp.redacted(),
            host_fp = %host_fp.redacted(),
            "host daemon starting"
        );

        let factory = SqliteStoreFactory::new(&store_path);

        // Independent connection #1: the connect path's own lookup (never the RPC path's) — see
        // `SqliteDeviceLookup`'s doc comment and this module's doc comment.
        let connect_store = match factory.open() {
            Ok(store) => store,
            Err(error) => {
                tracing::error!(%error, "host daemon failed to open connect-path store connection");
                return Err(error.into());
            }
        };
        let connect_lookup = SqliteDeviceLookup::new(connect_store);
        let authorizer = match issuer {
            // `with_cap_issuer`'s doc comment explains why this crate never builds this seam
            // itself: a real `RootKeyCapIssuer` needs this host's operating signing key, and that
            // key's custody (an OS keystore) is unresolved Stage 7 work. Whether one is installed
            // changes behavior materially (with none, connect answers never carry a member
            // capability), so it is worth its own `info!` line rather than folding into the
            // startup line above.
            Some(issuer) => {
                tracing::info!(
                    "cap issuer installed; successful connects will carry a freshly-minted \
                     member capability"
                );
                HostConnectAuthorizer::with_issuer(connect_lookup, issuer)
            }
            None => {
                tracing::info!(
                    "no cap issuer installed (HostDaemon::with_cap_issuer was not called); \
                     connect answers will never carry a member capability"
                );
                HostConnectAuthorizer::new(connect_lookup)
            }
        };

        // Independent connection #2: the session handler's own lookup. `HostConnectAuthorizer`
        // consumed the first `SqliteDeviceLookup` by value above, so `VfsSessionHandler` needs a
        // second one of its own rather than a reference to the first.
        let session_lookup_store = match factory.open() {
            Ok(store) => store,
            Err(error) => {
                tracing::error!(%error, "host daemon failed to open session-path store connection");
                return Err(error.into());
            }
        };
        let session_lookup = SqliteDeviceLookup::new(session_lookup_store);

        // `factory` itself is moved in here; every RPC session gets its own connection (#3, #4,
        // ...) opened on demand by `VfsSessionHandler::handle_session` via `StoreFactory::open`.
        let handler = VfsSessionHandler::new(factory, session_lookup, now_fn);

        tracing::info!(
            connections_opened = 2u32,
            "host daemon store connections opened at startup; entering signaling run loop"
        );

        let host: AssembledSignalingHost<_> =
            SignalingHost::new(nats, device, host_fp, authorizer, handler);
        match Arc::new(host).run(opts).await {
            Ok(()) => {
                tracing::info!(
                    "host daemon signaling run loop exited (nats connection closed or dropped)"
                );
                Ok(())
            }
            Err(error) => {
                tracing::error!(%error, "host daemon signaling run loop failed");
                Err(error.into())
            }
        }
    }
}
