//! `spindle-host-core` — the host library: the VFS RPC server (DESIGN.md §A8, §A4b), this crate's
//! whole deliverable across Stage 6 slices 3-4. Crate layering law (A9c boundary rule 3 /
//! DESIGN.md §A9c: `proto ← core ← {net, vfs} ← host-core`): this crate depends on `spindle-vfs`
//! (and transitively `spindle-core`) plus `spindle-proto` directly (for the wire types
//! [`server::VfsRpcServer`] decodes/encodes) — **not** on `spindle-net`. Binding to a real
//! transport (accepting connections, framing, backpressure, streaming a `read`/`upload_chunk`
//! reply's bytes rather than returning them in one shot) remains out of scope for this crate
//! (`spindle-net`'s job, still unscheduled as of this slice).
//!
//! Per A9c boundary rule 3, nothing below `apps/*/src-tauri` depends on `tauri` — the `apps/host`
//! Tauri shell (Stage 7) will embed this crate in-process and expose only a minimal, typed IPC
//! command surface over it.
//!
//! # Module map
//!
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
//! **Out**: binding to any real transport (`spindle-net`).

pub mod server;

mod cache;
mod identity_cache;
pub mod limits;
mod mount;
mod ratelimit;
mod upload;

pub use server::{SessionContext, VfsRpcServer};

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
