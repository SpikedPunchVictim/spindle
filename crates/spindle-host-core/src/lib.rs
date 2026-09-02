//! `spindle-host-core` — the host library: the VFS RPC server (DESIGN.md §A8, §A4b), this crate's
//! whole deliverable across Stage 6 slices 3-5. Crate layering law (A9c boundary rule 3 /
//! DESIGN.md §A9c: `proto ← core ← {net, vfs} ← host-core`): this crate depends on `spindle-vfs`
//! (and transitively `spindle-core`) plus `spindle-proto` directly (for the wire types
//! [`server::VfsRpcServer`] decodes/encodes). **As of Stage 6 slice 5**, this crate also depends on
//! `spindle-net` — the layering law explicitly permits `host-core -> net` — for [`serve`]'s binding
//! loop, which reads/writes `spindle_net::framing` frames off a real QUIC control stream
//! (`spindle_net::quic`) and calls straight into [`server::VfsRpcServer::handle_bytes`]. Streaming
//! a `read`/`upload_chunk` reply's bytes across multiple frames rather than one shot, and binding
//! the browser-peer WebRTC data-channel transport, remain out of scope (Stage 5, unscheduled as of
//! this slice — see [`serve`]'s module doc comment).
//!
//! Per A9c boundary rule 3, nothing below `apps/*/src-tauri` depends on `tauri` — the `apps/host`
//! Tauri shell (Stage 7) will embed this crate in-process and expose only a minimal, typed IPC
//! command surface over it.
//!
//! # Module map
//!
//! - [`authorize`] — [`authorize::HostConnectAuthorizer`], the production
//!   `spindle_net::signaling::authorize::ConnectAuthorizer` implementation, wired to this crate's
//!   own member/device registry via the [`authorize::DeviceLookup`] seam (see that module's doc
//!   comment for why the seam exists rather than naming `spindle_vfs::store::Store` directly) and
//!   its `Store`-backed adapter [`authorize::SqliteDeviceLookup`]. This is the connect-time twin of
//!   [`server::VfsRpcServer::handle`]'s per-request `denied:device_revoked` gate — both enforce
//!   DESIGN.md §A4's member-active-and-device-not-revoked rule, one at connect time (once per
//!   session) and one per request.
//! - [`server`] — [`server::VfsRpcServer`], the per-request enforcement pipeline, and
//!   [`server::SessionContext`] (the trusted, already-authenticated `{member_id, device_fp}}` a
//!   transport layer hands in per call). This is the crate's whole public surface.
//! - [`mount`] (crate-private) — resolves an incoming RPC's virtual path (spanning every share's
//!   `mount_path` in one per-host tree) down to `(share, subpath)` via longest-prefix match.
//! - [`cache`] (crate-private) — [`cache::GrantsCache`], the host-wide shares/entitlements
//!   snapshot cache, invalidated by `grants_version`/`cap_epoch`. Deliberately does **not** cache
//!   a member's own status/groups — see that module's doc comment for why (the revocation
//!   liveness rule this crate's pipeline order exists to preserve).
//! - [`identity_cache`] (crate-private) — [`identity_cache::IdentityCache`], the per-member
//!   last-observed file-identity cache that carries DESIGN.md §A4b's stat→read TOCTOU rule across
//!   separate RPC calls (there is no wire-level identity token — see
//!   `spindle_proto::vfs_rpc`'s module doc comment).
//! - [`upload`] (crate-private, Stage 6 slice 4) — [`upload::UploadSessions`], the in-memory
//!   upload-session table (DESIGN.md §A8 "transfer manager"): open/resume, per-chunk offset
//!   tracking, and TTL GC.
//! - [`limits`] (Stage 6 slice 4) — [`limits::UploadLimits`] (per-member/per-share quotas, the
//!   free-space floor), the [`limits::FreeSpaceProbe`] seam, and [`limits::OsFreeSpace`], the real
//!   OS probe (`rustix`/`windows-sys`, user decision 2026-08-26 — see that module's doc comment).
//! - [`ratelimit`] (crate-private, Stage 6 slice 4) — [`ratelimit::RateLimiter`], the per-caller
//!   token-bucket limiter DESIGN.md §A5 describes for pre-auth connects, adapted here to the
//!   post-auth VFS RPC entry point.
//! - [`revoke`] — [`revoke::revoke_member_and_mint`]/[`revoke::revoke_device_and_mint`]: applies a
//!   revocation to the store, bumps `cap_epoch` (DESIGN.md §A4: only on security events), and
//!   mints the signed `RevocationRecord` `spindle_helper::revoke::ingest_revocation` admits on
//!   `registry.revoke.<host_fp>` — everything except the actual NATS publish. See that module's
//!   doc comment for the store-first ordering rationale and why `cap_epoch` is bumped here rather
//!   than inside `spindle_vfs::store::Store::revoke_member`/`revoke_device`.
//! - [`serve`] (Stage 6 slice 5) — [`serve::serve_control_stream`], the binding loop: reads
//!   [`spindle_net::framing`] frames off a real duplex stream (production: a
//!   `spindle_net::quic::ControlStream`'s QUIC control stream), calls
//!   [`server::VfsRpcServer::handle_bytes`], and writes the reply frame back. Framing/decode
//!   violations close the connection rather than producing a typed [`spindle_proto::VfsErrorCode`]
//!   — see that module's doc comment for the §A5 uniform-drop rationale.
//! - [`session`] (Stage 5 slice 4) — [`session::VfsSessionHandler`], the production
//!   `spindle_net::signaling::host::SessionHandler` implementation: opens a per-session
//!   [`session::StoreFactory`]-produced `Store`, re-checks DESIGN.md §A4's member-active-and-
//!   device-not-revoked rule at the moment the session's QUIC control stream comes up, and drives
//!   [`serve::serve_control_stream`] over it. This re-check is not what makes revocation safe —
//!   `server.rs`'s per-request gate is §A4's one authoritative checkpoint, and it runs on every
//!   request inside every session — see [`session::VfsSessionHandler::session_context`]'s doc
//!   comment for what this gate is actually for (a fail-closed source for `SessionContext`'s
//!   `member_id`, and a cheap early-out) and why it must still be re-run rather than cached from
//!   `authorize`'s connect-time decision.
//!
//! # Pipeline order (task brief; see [`server::VfsRpcServer::handle`]'s doc comment for the
//! authoritative, code-adjacent version of this list)
//!
//! Per request, cheapest checks first: per-caller rate limit (see [`ratelimit`]) → decode +
//! protocol-version check → member active? (§A4b: unauthorized == `not_found`) → resolve the
//! virtual path via the mount table → effective perms from the algebra (cached; see [`cache`]) →
//! confine/ for the actual I/O (fresh `Dir` every request; TOCTOU identity checks; see
//! [`identity_cache`]) → audit append, for every outcome, including every denial.
//!
//! # Scope
//!
//! **In**: `list` (cursor-paged, max page), `stat`, `read` (chunked, offset/len), `mkdir`,
//! `delete`, `whoami`, `upload_open`/`upload_chunk`/`upload_commit`/`upload_abort` (DESIGN.md §A8
//! transfer manager: resumable sessions, hidden staging names, 48h TTL GC, manifest-signature
//! verification before move-into-place, entitlement-change-mid-transfer abort), per-member/
//! per-share upload quotas, a free-space floor seam, and a per-caller rate limit — all
//! transport-agnostic and pure/testable (bytes-in/bytes-out, or typed request/typed reply —
//! [`server::VfsRpcServer`] offers both).
//!
//! **In (Stage 6 slice 5 addition)**: [`serve::serve_control_stream`] — binding
//! [`server::VfsRpcServer::handle_bytes`] to a real QUIC control stream (`spindle-net`).
//!
//! **Out**: streaming a `read`/`upload_chunk` reply's bytes across multiple frames instead of one
//! shot; the browser-peer WebRTC data-channel transport (needs signaling — Stage 5, unscheduled).

pub mod authorize;
pub mod serve;
pub mod server;
pub mod session;

mod cache;
mod identity_cache;
pub mod limits;
mod mount;
mod ratelimit;
pub mod revoke;
mod upload;

pub use authorize::{DeviceLookup, HostConnectAuthorizer, LookupError, SqliteDeviceLookup};
pub use revoke::{
    revoke_device_and_mint, revoke_member_and_mint, RevocationPublication, RevokeError,
};
pub use serve::{serve_control_stream, ServeError};
pub use server::{SessionContext, VfsRpcServer};
pub use session::{
    SqliteStoreFactory, StoreFactory, VfsSessionHandler, CLOSE_PROTOCOL_VIOLATION,
    CLOSE_SESSION_REFUSED, CLOSE_SESSION_UNAVAILABLE,
};

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
