//! `spindle-vfs` — the shares/groups/entitlements engine and `cap-std` path confinement for host
//! authorization (DESIGN.md §A4b, ADR-006). Depends on `spindle-core` (and transitively
//! `spindle-proto`); per A9c boundary rule 3 nothing below `apps/*/src-tauri` depends on `tauri`,
//! and this crate sits below `spindle-host-core` and `spindle-client-core` in the dependency
//! chain (`proto ← core ← {net, vfs} ← {host-core, client-core}`).
//!
//! # This slice's scope (IMPLEMENTATION_PLAN Stage 6, slice 1)
//!
//! Two foundation modules only, both pure/in-memory:
//! - [`confine`] — path confinement graduated from spike S11 (`spikes/s11-vfs-confinement`):
//!   `cap-std`-backed share-root capabilities, identity checks, the hardlink-bypass guard,
//!   overlapping-root rejection, case/Unicode fold-key comparison, and upload-path scoping +
//!   overwrite gating.
//! - [`algebra`] — the pure entitlement algebra: positive-only union of a member's grants, the
//!   browse-implies-traversal / upload-implies-resolve / delete-does-not-imply-download /
//!   overwrite-requires-delete edge rules, and not-found semantics that make an unauthorized
//!   path indistinguishable from a nonexistent one.
//!
//! [`model`] holds the plain data structs (`Share`, `Group`, `Member`, `Entitlement`) both of the
//! above operate on, and [`glob`] is the minimal exclude-glob matcher `model::Share` uses.
//!
//! **Not in this slice** (later Stage 6 work, tracked in `IMPLEMENTATION_PLAN.md`): SQLite
//! persistence, the VFS RPC server, the tamper-evident audit log, and `spindle-host-core`
//! wiring. See [`algebra`]'s module doc comment for the specific mount-path/virtual-tree
//! resolution gap this slice leaves to that later work.

pub mod algebra;
pub mod confine;
pub mod glob;
pub mod model;

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
