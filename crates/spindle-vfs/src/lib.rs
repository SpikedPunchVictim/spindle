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

pub mod algebra;
pub mod audit;
pub mod confine;
pub mod glob;
pub mod model;
pub mod store;

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
