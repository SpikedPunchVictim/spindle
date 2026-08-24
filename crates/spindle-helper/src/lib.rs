//! `spindle-helper` — the broker-helper service: callout responder, presence, TURN credential
//! minting, the durable revocation store, and the admin-command verifier (A3, A3b, A9b). Depends
//! only on `spindle-proto` and `spindle-core` — per A9c boundary rule 3 this crate MUST NEVER
//! grow host or client logic (it holds no membership data; see docs/DESIGN.md A2's
//! zero-knowledge definition).
//!
//! # Layering within this crate
//!
//! - [`authz`], [`permissions`], [`session`] — **the pure callout-verification core** (Stage 4
//!   slice 1). Deliberately free of `tokio`/`async-nats`/`sqlx` — no async, no I/O. Every
//!   external fact (current time, a caller-verified nkey signature, a store lookup) is a
//!   parameter, never read implicitly. This is what makes [`authz::decide_device_connect`]/
//!   [`authz::decide_host_connect`] exhaustively unit-testable without a running NATS server.
//! - [`natsjwt`], [`memory_store`], and `src/bin/helper.rs` — **the NATS/runtime wiring layer**
//!   (Stage 4 slice 2, graduated from `spikes/s1-callout` — S1 **PASS**, 19/19 automated checks
//!   against a live `nats-server`, 2026-08-24; `spikes/s1-callout/RESULTS.md`). This is where
//!   ADR-009's runtime-dependency allowance for this crate (`tokio`, `async-nats`, `nkeys`,
//!   `tracing`, `serde`/`serde_json`) applies — the pure core above never gains any of these.
//!
//! - [`authz`] — [`authz::decide_device_connect`]/[`authz::decide_host_connect`]: given a
//!   presented auth payload, a caller-verified nkey-signature result, the current time, and a
//!   [`authz::HelperView`] (the store lookups the callout needs), decide
//!   [`authz::AuthzDecision::Authorized`] (with permissions/limits/session record) or
//!   [`authz::AuthzDecision::Refused`] (with an internal-only [`authz::RefusalReason`]).
//! - [`permissions`] — builds the exact §A5 permission sets (subject-pattern lists, limits,
//!   jittered `exp`) as plain data.
//! - [`session`] — [`session::SessionRecord`], the `nats_fp → {root_fp, host_fps, quota_profile,
//!   exp}` record DESIGN.md §A5 describes.
//! - [`natsjwt`] — hand-rolled NATS v2 JWT claim encode/decode, graduated from the S1 spike with
//!   every empirically-verified field-shape decision preserved (see its own module docs).
//! - [`auth_token`] — decodes the CONNECT `auth_token` envelope (device cert + caps, or host op
//!   cert + admission token), graduated (decode side only) from the S1 spike's `fixtures.rs`. See
//!   its own module docs for the still-open wire-schema gap this envelope shape papers over.
//! - [`memory_store`] — [`memory_store::InMemoryHelperView`], the dev-mode default
//!   [`authz::HelperView`] implementation `src/bin/helper.rs` runs with. **Not durable** — every
//!   revocation/admission/session fact it holds is lost on restart. Exists so the store is
//!   swappable behind the same trait: a Postgres-backed `HelperView` (Stage 4 slice 3, `sqlx`)
//!   drops in wherever `InMemoryHelperView` is constructed today, with no change to `authz.rs`,
//!   `natsjwt.rs`, or the callout-handling logic in `src/bin/helper.rs`.
//!
//! **Still out of scope** (later slices): the durable Postgres-backed `HelperView`, presence
//! (`$SYS` event bridging into `host.<hfp>.presence`), TURN credential minting, and the
//! admin-command verifier (`registry.admin.>`).
//!
//! # Design notes and ambiguities (reported, not silently resolved)
//!
//! See the doc comments on [`permissions::host_permissions`] (the `pub registry.revoke` vs.
//! `pub registry.revoke.<hfp>` inconsistency between DESIGN.md §A5's permission-list bullet and
//! its own subject table) and on [`session::SessionRecord`] (reusing the client-oriented session
//! record shape for host connections; the undefined source of a client session's
//! `quota_profile`) for the specific wire-schema ambiguities this slice had to resolve one way
//! without a spec to point to. `spikes/s1-callout/RESULTS.md` additionally flagged a
//! `host_fp`-derivation inconsistency between `decide_device_connect` and `decide_host_connect`;
//! that has since been resolved by decision A10.30 (capabilities now chain through a host's root
//! key via an embedded `HostOpKeyCert`, so both functions derive the same root-based `host_fp` —
//! see `authz.rs`'s `TestHost` doc comment).

pub mod auth_token;
pub mod authz;
pub mod memory_store;
pub mod natsjwt;
pub mod permissions;
pub mod session;

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
