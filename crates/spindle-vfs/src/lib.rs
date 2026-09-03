//! `spindle-vfs` — the shares/groups/entitlements engine, `cap-std` path confinement, SQLite
//! persistence, and the tamper-evident audit chain for host authorization (DESIGN.md §A4b,
//! ADR-006). Depends on `spindle-core` (and transitively `spindle-proto`) plus `rusqlite`
//! (bundled); per A9c boundary rule 3 nothing below `apps/*/src-tauri` depends on `tauri`, and
//! this crate sits below `spindle-host-core` and `spindle-client-core` in the dependency chain
//! (`proto ← core ← {net, vfs} ← {host-core, client-core}`). No `tokio`, no async runtime — every
//! module here is synchronous.
//!
//! # Module map
//! - [`model`] — plain in-memory data structs (`Share`, `Group`, `Member`, `Entitlement`,
//!   `VirtualPath`, `Perms`) with the construction-time invariants DESIGN.md §A4b states plainly
//!   (e.g. upload/delete grantable only on `allow_upload` shares).
//! - [`glob`] — the minimal hand-rolled exclude-glob matcher `model::Share` uses.
//! - [`confine`] — path confinement graduated from spike S11 (`spikes/s11-vfs-confinement`):
//!   `cap-std`-backed share-root capabilities, identity checks, the hardlink-bypass guard,
//!   overlapping-root rejection, case/Unicode fold-key comparison, and upload-path scoping +
//!   overwrite gating.
//! - [`algebra`] — the pure entitlement algebra: positive-only union of a member's grants, the
//!   browse-implies-traversal / upload-implies-resolve / delete-does-not-imply-download /
//!   overwrite-requires-delete edge rules, and not-found semantics that make an unauthorized
//!   path indistinguishable from a nonexistent one.
//! - [`store`] — SQLite-backed durable host state (DESIGN.md §A4b: "Everything here lives only on
//!   the host (SQLite)"): members, devices, groups, shares, entitlements, the idempotent
//!   invite-nonce CAS, and the `cap_epoch`/`grants_version` counters, all mapped to/from the
//!   `model` structs above — see [`store::Store`]'s doc comment for the invariants it enforces.
//! - [`audit`] — the tamper-evident, hash-chained audit log (DESIGN.md §A4b "Audit log"), backed
//!   by the same connection as [`store::Store`] — see [`audit::Audit`]'s doc comment for the hash
//!   chain, signed-head, and transaction-discipline design.
//! - [`reconcile`] — heals DB-vs-filesystem skew in the upload ledger (td-2db67d): a composing
//!   function over `store` and `confine` (not a `Store` method — `Store` stays pure DB) that walks
//!   `uploaded_files` and repairs drift from a crash between a filesystem op and its ledger write,
//!   or an owner editing an uploaded file out of band. See [`reconcile`]'s module doc comment for
//!   why this is not the rejected directory-walk design and why owner-placed content is left
//!   alone.
//!
//! # Stage 6 slice history
//!
//! **Slice 1** (`model`/`algebra`/`confine`/`glob`): pure/in-memory only — no SQLite, no VFS RPC,
//! no `spindle-host-core`. 36 tests (40 including 4 Windows-only compile-gated cases).
//!
//! **Slice 2** (this slice — `store`/`audit`): SQLite persistence and the tamper-evident audit
//! chain, both wired to the existing slice-1 `model`/`algebra`/`confine`/`glob` modules
//! unmodified (two small *additive* extensions were made to `model` to support round-tripping
//! through storage — [`model::VirtualPath::to_path_string`] and [`model::Perms::bits`]/
//! [`model::Perms::from_bits`] — neither changes any existing behavior or test). `store::Store`
//! persists every entity via embedded, numbered `PRAGMA user_version` migrations
//! (`store::schema`); `audit::Audit` hash-chains every entry and supports periodic signed heads
//! via a `HeadSigner` trait so key custody stays out of this crate. Still not in this slice: the
//! VFS RPC server and `spindle-host-core` wiring (tracked in `IMPLEMENTATION_PLAN.md`).
//! 73 tests (77 including the 4 Windows-only cases).
//!
//! **Slice 3** (`spindle-host-core`'s VFS RPC server, implemented in that crate — not this one):
//! this crate gained exactly two additions to support it, both additive/non-breaking to slices
//! 1-2: [`confine::listing`] (directory listing, `mkdir`, and `delete` primitives through the same
//! `cap-std` `Dir` capability — slice 1/2 never needed to enumerate or mutate a directory's real
//! entries, only stat/read/write single files) and a `mount_path` collision check in
//! [`store::Store::add_share`] (`StoreError::MountPathCollision` — the store already rejected
//! overlapping *real* roots but had no equivalent check for overlapping *virtual* `mount_path`s,
//! flagged and closed per that slice's task brief). The RPC server, the mount-path-to-share
//! virtual-tree resolution step, and the effective-perms/identity caches all live in
//! `spindle-host-core`, per the crate layering law — see that crate's `lib.rs` module doc comment.
//! 76 tests (79 including the 4 Windows-only cases, and 3 new `MountPathCollision` tests in
//! `store`).

pub mod algebra;
pub mod audit;
pub mod confine;
pub mod glob;
pub mod model;
pub mod reconcile;
pub mod store;

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
