//! `spindle-helper` — the broker-helper service: callout responder, presence, TURN credential
//! minting, the durable revocation store, and the admin-command verifier (A3, A3b, A9b). Depends
//! only on `spindle-proto` and `spindle-core` — per A9c boundary rule 3 this crate MUST NEVER
//! grow host or client logic (it holds no membership data; see docs/DESIGN.md A2's
//! zero-knowledge definition).
//!
//! # Stage 4 slice 1: the pure callout-verification core
//!
//! This slice implements only the **decision logic** behind the NATS Auth Callout (DESIGN.md
//! §A4, §A5) — the part that is pure, deterministic, and exhaustively unit-testable without a
//! running NATS server or a Postgres database:
//! - [`authz`] — [`authz::decide_device_connect`]/[`authz::decide_host_connect`]: given a
//!   presented auth payload, a caller-verified nkey-signature result, the current time, and a
//!   [`authz::HelperView`] (the store lookups the callout needs), decide
//!   [`authz::AuthzDecision::Authorized`] (with permissions/limits/session record) or
//!   [`authz::AuthzDecision::Refused`] (with an internal-only [`authz::RefusalReason`]).
//! - [`permissions`] — builds the exact §A5 permission sets (subject-pattern lists, limits,
//!   jittered `exp`) as plain data.
//! - [`session`] — [`session::SessionRecord`], the `nats_fp → {root_fp, host_fps, quota_profile,
//!   exp}` record DESIGN.md §A5 describes.
//!
//! **Deliberately out of scope here** (arriving in the NATS/Postgres wiring slice, per ADR-009 —
//! this crate *may* use `tokio`/`sqlx`/`async-nats` eventually, just not in this pure module):
//! decoding raw NATS CONNECT bytes into `spindle_proto::artifacts` types, the actual nkey
//! signature check against the server nonce (NATS-library territory), the durable Postgres-backed
//! `HelperView` implementation, presence, TURN credential minting, and the admin-command
//! verifier.
//!
//! # Design notes and ambiguities (reported, not silently resolved)
//!
//! See the doc comments on [`permissions::host_permissions`] (the `pub registry.revoke` vs.
//! `pub registry.revoke.<hfp>` inconsistency between DESIGN.md §A5's permission-list bullet and
//! its own subject table) and on [`session::SessionRecord`] (reusing the client-oriented session
//! record shape for host connections; the undefined source of a client session's
//! `quota_profile`) for the specific wire-schema ambiguities this slice had to resolve one way
//! without a spec to point to.

pub mod authz;
pub mod permissions;
pub mod session;

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
