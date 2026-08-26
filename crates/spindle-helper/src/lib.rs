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
//! - [`natsjwt`], [`memory_store`], [`pg_store`], [`turn`], and `src/bin/helper.rs` — **the
//!   NATS/runtime wiring layer** (Stage 4 slices 2 and 3, graduated from `spikes/s1-callout` — S1
//!   **PASS**, 19/19 automated checks against a live `nats-server`, 2026-08-24;
//!   `spikes/s1-callout/RESULTS.md`). This is where ADR-009's runtime-dependency allowance for
//!   this crate (`tokio`, `async-nats`, `nkeys`, `tracing`, `serde`/`serde_json`, and — as of
//!   slice 3 — `sqlx`/`hmac`/`sha1` per A9c's "sqlx/Postgres helper-side" line) applies — the pure
//!   core above never gains any of these.
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
//!   [`authz::HelperView`] implementation `src/bin/helper.rs` runs with when `DATABASE_URL` is
//!   unset. **Not durable** — every revocation/admission/session/TURN-counter fact it holds is
//!   lost on restart.
//! - [`pg_store`] — [`pg_store::PgStore`] (Stage 4 slice 3): the durable, `sqlx`/Postgres-backed
//!   [`authz::HelperView`], embedding its own migrations (`migrations/`). Drops in wherever
//!   `InMemoryHelperView` is constructed, with no change to `authz.rs`, `natsjwt.rs`, or the
//!   callout-handling logic — `src/bin/helper.rs` picks one or the other at startup based on
//!   whether `DATABASE_URL` is set. See that module's own doc comment for the SQL semantics and
//!   for why its `HelperView` methods bridge to async I/O via `block_in_place` rather than making
//!   the trait itself async.
//! - [`turn`] — [`turn::handle_turn_get`] (Stage 4 slice 3, subject parametrized in v0.9.7 —
//!   DESIGN.md §A5, A12 #45): TURN credential minting for `helper.turn.get.<nfp>`, where identity
//!   comes from the subject token, not the payload. Authorized via the session record a
//!   successful callout now persists (see [`authz::HelperView::put_session_record`]) and
//!   quota-limited per `root_fp` via [`authz::HelperView::record_turn_issuance`]. See that
//!   module's own doc comment for the wire-schema detail.
//! - [`presence`] — [`presence::ConnectionMap`] + [`presence::handle_presence_get`] (DESIGN.md
//!   §A3/§A5/§A6, subject parametrized the same way as `helper.turn.get.<nfp>`): the live
//!   connection map `src/bin/helper.rs` feeds from `$SYS.REQ.SERVER.PING.CONNZ` at startup and
//!   `$SYS.ACCOUNT.*.CONNECT|DISCONNECT` deltas thereafter, answering
//!   `helper.presence.get.<nfp>` snapshots and computing `host.<hfp>.presence` push deltas. See
//!   that module's own doc comment for the wire-schema detail and for why `unresponsive` (§A6/§A9)
//!   isn't tracked here.
//!
//! **Still out of scope** (later slices): the admin-command verifier (`registry.admin.>`), the
//! kick relay, split-brain newest-wins policy, multi-server `CONNZ` aggregation, and leader-only
//! delta publishing (A10.23) — see `presence.rs`'s module doc for the presence-specific subset of
//! this list.
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
pub mod pg_store;
pub mod presence;
pub mod session;
pub mod turn;

use spindle_core::Fingerprint;

/// Parses the final `.`-delimited token of `subject` as a [`Fingerprint`], requiring `subject` to
/// start with `prefix` exactly. Shared by `turn.rs`'s `helper.turn.get.<nfp>` and `presence.rs`'s
/// `helper.presence.get.<nfp>` subject parsers — both need byte-identical "strip this literal
/// prefix, reject an empty or non-fingerprint remainder" logic, since both scope caller identity
/// to the subject token a NATS permission already gated (never a request-payload field).
pub(crate) fn parse_fp_after_prefix(subject: &str, prefix: &str) -> Option<Fingerprint> {
    let token = subject.strip_prefix(prefix)?;
    if token.is_empty() {
        return None;
    }
    token.parse::<Fingerprint>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }

    #[test]
    fn parse_fp_after_prefix_round_trips() {
        let fp = Fingerprint::of_parts(&[b"lib-rs-shared-helper-test"]);
        let subject = format!("helper.presence.get.{fp}");
        assert_eq!(parse_fp_after_prefix(&subject, "helper.presence.get."), Some(fp));
    }

    #[test]
    fn parse_fp_after_prefix_rejects_wrong_prefix_or_empty_token() {
        assert_eq!(parse_fp_after_prefix("helper.presence.get", "helper.presence.get."), None);
        assert_eq!(parse_fp_after_prefix("helper.presence.get.", "helper.presence.get."), None);
    }
}
