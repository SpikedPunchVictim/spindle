//! `spindle-host-core` — the host library: the VFS RPC server (DESIGN.md §A8, §A4b), this slice's
//! whole deliverable. Crate layering law (A9c boundary rule 3 / DESIGN.md §A9c:
//! `proto ← core ← {net, vfs} ← host-core`): this crate depends on `spindle-vfs` (and
//! transitively `spindle-core`) plus `spindle-proto` directly (for the wire types
//! [`server::VfsRpcServer`] decodes/encodes) — **not** on `spindle-net` for this slice. The
//! slice-1 stub this module doc comment replaces claimed a `spindle-net` dependency prematurely;
//! that was a forward-looking placeholder, not something Stage 6 slice 1 actually wired up, and is
//! corrected here per this slice's task brief ("host-core depends on vfs, NOT on net for this
//! slice"). Binding to a real transport (accepting connections, framing, backpressure, streaming a
//! `read` reply's bytes rather than returning them in one shot, `upload`'s resumable sessions,
//! rate limiting/quotas) is Stage 6 slice 4 territory — see the Scope section below and
//! `IMPLEMENTATION_PLAN.md`'s Stage 6 Note.
//!
//! Per A9c boundary rule 3, nothing below `apps/*/src-tauri` depends on `tauri` — the `apps/host`
//! Tauri shell (Stage 7) will embed this crate in-process and expose only a minimal, typed IPC
//! command surface over it.
//!
//! # Module map
//!
//! - [`server`] — [`server::VfsRpcServer`], the per-request enforcement pipeline, and
//!   [`server::SessionContext`] (the trusted, already-authenticated `{member_id, device_fp}}` a
//!   transport layer hands in per call). This is the crate's whole public surface for this slice.
//! - [`mount`] (crate-private) — resolves an incoming RPC's virtual path (spanning every share's
//!   `mount_path` in one per-host tree) down to `(share, subpath)` via longest-prefix match —
//!   the mount-path-to-share virtual-tree resolution step flagged as a gap at the end of Stage 6
//!   slice 1, closed here.
//! - [`cache`] (crate-private) — [`cache::GrantsCache`], the host-wide shares/entitlements
//!   snapshot cache, invalidated by `grants_version`/`cap_epoch`. Deliberately does **not** cache
//!   a member's own status/groups — see that module's doc comment for why (the revocation
//!   liveness rule this crate's pipeline order exists to preserve).
//! - [`identity_cache`] (crate-private) — [`identity_cache::IdentityCache`], the per-member
//!   last-observed file-identity cache that carries DESIGN.md §A4b's stat→read TOCTOU rule across
//!   separate RPC calls (there is no wire-level identity token — see
//!   `spindle_proto::vfs_rpc`'s module doc comment).
//!
//! # Pipeline order (task brief; see [`server::VfsRpcServer::handle`]'s doc comment for the
//! authoritative, code-adjacent version of this list)
//!
//! Per request, cheapest checks first: decode + protocol-version check → member active? (§A4b:
//! unauthorized == `not_found`) → resolve the virtual path via the mount table → effective perms
//! from the algebra (cached; see [`cache`]) → confine/ for the actual I/O (fresh `Dir` every
//! request; TOCTOU identity checks; see [`identity_cache`]) → audit append, for every outcome,
//! including every denial.
//!
//! # Scope (deliberately bounded — task brief)
//!
//! **In** (this slice): `list` (cursor-paged, max page), `stat`, `read` (chunked, offset/len),
//! `mkdir`, `delete`, `whoami`, and the enforcement pipeline above, all transport-agnostic and
//! pure/testable (bytes-in/bytes-out, or typed request/typed reply — [`server::VfsRpcServer`]
//! offers both).
//!
//! **Out** (Stage 6 slice 4, not this crate yet): `upload`'s resumable-session machinery (staging
//! names, TTL GC, manifest verification — DESIGN.md §A8's transfer manager), rate
//! limiting/quotas, and binding to any real transport (`spindle-net`, Stage 5).

pub mod server;

mod cache;
mod identity_cache;
mod mount;

pub use server::{SessionContext, VfsRpcServer};

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
