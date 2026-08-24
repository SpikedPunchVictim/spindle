# S1 — Callout verifying self-signed caps; scoped perms; no-cap refusal — results

Pass criterion (verbatim, `docs/DESIGN.md` §A13, repeated in `docs/SPIKES.md` §S1): *"Automated
negative tests: other inbox unreadable; un-capped host unreachable; other client's session
unreachable; reply-prefix bypass rejected; fresh key with no cap refused."*

**Status: PASS — 19/19 automated checks green against a live `nats-server:2.10-alpine`
(v2.10.29), 2026-08-24.** All five pass-criterion attacks are covered (with margin — see the
checklist below); the run is deterministic (reproduced clean on three independent
container+responder restarts, including one under `-DV` trace logging).

**Environment**: macOS (Darwin 25.3.0, arm64) host; `nats:2.10-alpine` (server v2.10.29) in
Docker, ports 14222 (client)/18080 (websocket)/18222 (monitor) mapped to avoid clashing with any
other local NATS instance; `responder` and `s1-tests` built with the pinned workspace toolchain
(`mise` shims). No TLS (see `server.conf`'s dev-only note — orthogonal to what this spike proves).

## What this proves, concretely

`spikes/s1-callout/` wires `spindle-helper`'s pure decision core
(`crates/spindle-helper/src/{authz.rs,permissions.rs,session.rs}`) — completely unmodified, no
core-crate changes — to a real NATS Auth Callout loop:

1. `server.conf` configures `nats-server` for non-operator/config-based-accounts Auth Callout
   (`authorization.auth_callout`), with a fixed `AUTH` account (the responder connects here) and
   an `APP` account (where authorized users land).
2. `src/bin/responder.rs` subscribes to `$SYS.REQ.USER.AUTH`, decodes each `AuthorizationRequest`
   JWT, decodes Spindle's presented capability/cert bundle (`src/fixtures.rs`'s envelope), calls
   **`spindle_helper::authz::{decide_device_connect, decide_host_connect}`** — the real decision
   functions, not a stand-in — and signs a real `AuthorizationResponse` User JWT carrying the
   exact §A5 permission set from **`spindle_helper::permissions`**.
3. `src/bin/s1-tests.rs` drives 19 checks against this live loop from real `async-nats` client
   connections (real nkeys, real signatures, real wire traffic), covering the full negative-test
   checklist below plus two extra checks (deny-inbox `$SYS`/`$JS`, and the ADR-002 bridging
   question).

## Checklist against the pass criterion

| A13 attack | Check(s) | Result |
|---|---|---|
| fresh key, no cap → refused | `fresh_key_no_cap_refused` | **PASS** |
| other device's `_INBOX_<dfp>.>` unreadable | `device_a_cannot_sub_other_devices_inbox` | **PASS** |
| un-capped host unreachable | `device_a_cannot_pub_host_h2_connect`, `device_a_cannot_sub_host_h2_wildcard` | **PASS** |
| other client's session unreachable | `device_a_cannot_sub_other_clients_session` | **PASS** |
| reply-prefix bypass rejected | `reply_prefix_bypass_suite` (3 sub-assertions: legitimate first reply allowed via `allow_responses`; second reply to the same subject denied once `max:1` is spent; reply to a never-granted subject denied) | **PASS** |

Plus, beyond the literal criterion: positive proof that a valid member cap grants exactly the
intended subjects (`device_a_can_pub_host_h_connect`, `device_a_can_sub_own_session_h2c`,
`device_a_can_sub_own_presence_weak`), explicit `$SYS.>`/`$JS.>` denial
(`device_a_cannot_pub_sys`, `device_a_cannot_sub_js`), the full invite-only/connect-only
permission shape (`invite_only_*`, 5 checks), and the ADR-002 bridging question (next section).
Full 19/19 transcript:

```
[PASS] host_h_connects
[PASS] fresh_key_no_cap_refused
[PASS] device_a_connects_with_member_cap_for_host_h
[PASS] device_a_can_pub_host_h_connect
[PASS] device_a_can_sub_own_session_h2c
[PASS] device_a_can_sub_own_presence_weak
[PASS] device_a_cannot_sub_other_devices_inbox
[PASS] device_a_cannot_pub_host_h2_connect
[PASS] device_a_cannot_sub_host_h2_wildcard
[PASS] device_a_cannot_sub_other_clients_session
[PASS] device_a_cannot_pub_sys
[PASS] device_a_cannot_sub_js
[PASS] reply_prefix_bypass_suite
[PASS] invite_only_device_c_connects
[PASS] invite_only_can_pub_host_h_connect
[PASS] invite_only_cannot_pub_helper_presence_get
[PASS] invite_only_cannot_sub_host_presence
[PASS] invite_only_cannot_pub_session_c2h
[PASS] bridging_callout_account_cannot_reach_app_subjects
==== S1 suite summary: 19/19 checks passed ====
```

Detection method for every denial: nats-server reports a permissions violation as an **async
protocol `-ERR`** on the offending connection (`client.publish`/`client.subscribe` return `Ok`
regardless of server-side outcome), surfaced by `async-nats`'s `event_callback` as
`Event::ServerError(ServerError::Other(text))` with exact text `Permissions Violation for Publish
to "<subject>"` / `... for Subscription to "<subject>"` / `... for Publish with Reply of
"<reply>"`. Every "denied" check polls the event log for this text AND (wherever a legitimate
publisher exists) confirms the payload never actually arrives at the target subscriber — never
"no violation observed" alone. Full rationale in `src/bin/s1-tests.rs`'s module doc comment.

## ADR-002's open topology question — answered

ADR-002 §"NATS account topology" leaves one row **"To be finalized in S1"**: *"whether the helper
holds one dual-privileged connection (SYS + APP) or two separate connections (one per account)
bridging `$SYS` events into APP-account publishes."*

`bridging_callout_account_cannot_reach_app_subjects` (gated on `CALLOUT_USER_SEED` being set —
skipped, not failed, if absent) empirically confirms: **two separate connections are required.**
The callout responder's own AUTH-account connection publishes into an APP-account subject
(`host.<hfp>.presence`); an APP-account subscriber never sees it
(`publish_from_auth_account_result=true reached_app_account_subscriber=false`). This is
**account-level isolation** (NATS accounts are hard subject-space boundaries, not just permission
lists) — no `pub`/`sub` permission list on the AUTH-account connection could change this outcome,
because the message never crosses into APP's subject space at all. A single dual-privileged
connection cannot exist in NATS's account model the way DESIGN.md's diagram might suggest;
whatever wiring the helper eventually uses, it needs at least one connection per account it
touches (SYS, AUTH-if-distinct-from-SYS, and APP), consistent with the `auth_callout.account`
config's own AUTH/APP split already forced this spike to use two.

## The host_fp inconsistency — the most significant finding (not fixed here, flagged for ADR-002/DESIGN.md)

`decide_device_connect` (`crates/spindle-helper/src/authz.rs`) scopes a device's granted host
subjects by `host_fp = Fingerprint::of_parts(&[host_pk.as_bytes()])`, where `host_pk` is the
signer's public key embedded in the capability by
`spindle_core::artifacts::issue_capability` — and every caller of `issue_capability` passes the
host's **operating (op) key**, per that function's own doc comment ("host_pk/host_fp are derived
from signer").

`decide_host_connect` scopes the host's *own* connection permissions
(`permissions::host_permissions(host_fp)`, i.e. what `host.<host_fp>.>` it may subscribe to) by
`root_fp_of(&presented.host_root_pk)` — the host's **root** key.

These are two different keys. Unless a host's root key and op key happen to be identical, a
device's capability grants it `pub host.<op-key-fp>.connect`, while the host itself only ever
subscribes to `host.<root-key-fp>.>` — **the subjects never coincide**, and no member device
could ever reach its own host. `docs/DESIGN.md` itself carries two hard-to-reconcile statements
about this: line 199 ("`host_fp = hash(host_root_pk)` ... members pin `host_fp`") implies
root-key-derived, stable-across-op-key-rotation semantics; line 220 ("Self-verifying: `host_fp ==
hash(host_pk)`") implies the cap's own embedded, op-key-derived `host_pk`. Both are true of
*something* in the current code — just not the same `host_fp`.

This spike does **not** patch `spindle-helper`/`spindle-core` (out of scope/authority — see task
constraints) and instead works around it locally in `src/fixtures.rs`'s `new_host_identity`,
which is called with `root_seed == op_seed` for every test host (`host_h`, `host_h2`), making the
two derivations coincide by construction. **This is a real, pre-existing ambiguity in the
decision core that blocks any real deployment where a host's root and op keys differ (i.e. any
deployment that ever rotates or separates them, which is the entire point of having two keys per
DESIGN.md's key hierarchy) — it needs a DESIGN.md/ADR-002 decision, not a spike workaround, before
Stage 4 can wire this up for real.**

## JWT claim structures (hand-rolled — no mature Rust "nats-jwt" crate exists)

Full field-by-field provenance lives in `src/natsjwt.rs`'s doc comments; summarized here.

- **AuthorizationRequestClaims** (read from the server, not built): `nats.user_nkey` is a
  server-generated **per-request correlation key** — distinct from `nats.connect_opts.nkey` (==
  `nats.client_info.user`), the client's **actual presented nkey**, which is what
  `nats.connect_opts.sig` is a signature over `nats.client_info.nonce` with. Conflating the two
  (using `user_nkey` for signature verification) breaks every real nkey-signature check with no
  useful error — surfaces only as a bare `AuthorizationViolation`. Root-caused via
  `src/bin/probe.rs`'s captured live request JSON.
- **User JWT `nats` object** (`nats-io/jwt` v2 `UserPermissionLimits`, flattened, no wrapper):
  `pub`/`sub` each `{allow, deny}`; `resp: {max, ttl}` (`ResponsePermission`, only present when
  `allow_responses` is set); `subs`/`data`/`payload` limits (`-1` = unlimited); `type: "user"`,
  `version: 2`; `allowed_connection_types`.
  - **`resp.ttl` must be a plain JSON number of nanoseconds, not a Go-duration string** like
    `"120s"`. `time.Duration` has no custom `UnmarshalJSON`; presenting a string fails deep inside
    JSON unmarshaling server-side (`Json: cannot unmarshal string into Go struct field
    ResponsePermission.nats.UserPermissionLimits.Permissions.resp.ttl of type time.Duration`),
    surfacing to the client as an undifferentiated `authorization violation`. Root-caused
    empirically against the live server; fixed in `natsjwt.rs`/`responder.rs`.
  - **`deny` must apply to both `pub.deny` and `sub.deny`.** An earlier version of
    `user_nats_claims` hard-coded `pub.deny` to `[]`, silently dropping
    `spindle_helper::permissions::SubjectPermissions::deny` on the publish side — that field's own
    doc comment says "applied to both publish and subscribe". Every current caller also passes a
    restrictive (non-blanket) `pub_allow`, under which NATS's allow-list semantics make the
    omission inert in the checks this suite runs (allow-list already the binding restriction), but
    it diverged from the documented contract and would matter for any future
    blanket/no-allow-list caller. Caught and fixed while root-causing the bug below; would not
    have been caught by any of this suite's current assertions on its own.
  - **`aud` = the target account's NAME** (e.g. `"APP"`), not its public key — in non-operator
    mode, nats-server's `auth_callout.go` (`assignAccountAndPermissions`) does
    `placement = arc.Audience; s.LookupAccount(placement)`. Not documented anywhere DESIGN.md
    could have cited; found only by reading server source after the naive omit-`aud` version
    failed with an opaque "Unable to validate expected prefixes - [account]" error.
- **AuthorizationResponseClaims**: `iss` **must be an account-prefixed nkey ("A...")**, never the
  callout responder's own user nkey — `AuthorizationResponseClaims.ExpectedPrefixes()` hard-codes
  `PrefixByteAccount`. Easy to get backwards (the responder is who *answers*, reads naturally as
  "issuer"); the server's error gives almost no hint (`"Unable to validate expected prefixes -
  [account]"`). This spike signs responses with the same APP-account keypair that signs the inner
  User JWT — the callout user's own nkey is used only for the responder's own NATS-level
  connection (subscribing to `$SYS.REQ.USER.AUTH`), never for signing a JWT.

## A test-harness bug found and fixed: double-delivery burns the `allow_responses` budget

`reply_prefix_bypass_suite`'s first, legitimately-earned reply was denied on every run —
deterministic, not a race. Root-caused by re-running the whole suite against `nats-server -DV`
(trace logging) and reading the raw protocol log: the server delivered device A's
`host.<H>.connect` request **twice** to host H's connection — once for the long-lived `host_sub`
(subscribed once, up front, to the whole `host.<H>.>` wildcard, and still needed later for the
bridging check) and once for this check's own fresh, narrowly-scoped subscription, both of which
match the same published subject:

```
[TRC] cid:9 - ->> [MSG host.<H>.connect 1 _INBOX_<dfp>.<reply> 3]
[TRC] cid:9 - ->> [MSG host.<H>.connect 3 _INBOX_<dfp>.<reply> 3]
```

nats-server's per-connection `allow_responses` bookkeeping (`server/client.go`:
`deliverMsg`/`pubAllowedFullCheck`) tracks the reply-subject budget once **per connection**, not
per subscription: each matching delivery calls `pubAllowedFullCheck(reply, fullCheck=true, ...)`
as a side effect of deciding whether to start tracking the reply, and that call itself increments
the shared `client.replies[reply].n` counter once the entry exists. With two matching
subscriptions, the second delivery's bookkeeping call silently consumes one unit of the `max:1`
budget before this check's own `host_conn.publish(reply_subject, "first")` ever runs — so the
first *real* reply already sees `n == 1` incoming, pushes it to 2, exceeds `max:1`, and is denied.
This is entirely a test-harness artifact (an unrelated live subscription overlapping the subject
under test), not a `nats-server` or `spindle-helper` bug. Fixed in `s1-tests.rs` by temporarily
unsubscribing `host_sub` for the duration of `reply_prefix_bypass_suite` and re-subscribing a
fresh one immediately after, for the later bridging check that still needs it.

## Dependencies added (spike crate only — none added to `spindle-helper`/`spindle-core`)

All in `spikes/s1-callout/Cargo.toml`, already present before this session's work resumed (no new
crate-level dependencies were added in this segment; documented here per the task's "list what's
added + why" instruction):

- `nkeys` — nkey/Ed25519 key material and the raw signature primitive. No mature Rust "nats-jwt"
  crate exists that understands NATS's v2 claim JSON shape, so this spike hand-rolls that JSON
  (`natsjwt.rs`) and uses `nkeys` only for keys + signing/verification.
- `serde`/`serde_json`/`base64` — building/parsing the hand-rolled JWT claim JSON
  (`base64` is `URL_SAFE_NO_PAD` throughout, matching both the JWT convention and DESIGN.md §A4's
  capability-presentation encoding).
- `async-nats` — the real client library used by both the responder's own callout connection and
  every simulated device/host connection in `s1-tests.rs`.
- `rand`, `ed25519-dalek`, `futures-util`, `tracing`/`tracing-subscriber` (declared, not currently
  used by any `eprintln!`-only binary — see below), `thiserror` — supporting glue.

## Files

**Deliverable** (part of the S1 result):
- `spikes/s1-callout/server.conf` — dev/local Auth Callout config (non-operator/config-based
  accounts mode), fresh nkeys, documented TLS-omission note.
- `spikes/s1-callout/src/bin/responder.rs` — the real callout responder wiring
  `spindle_helper::authz` to the wire.
- `spikes/s1-callout/src/bin/s1-tests.rs` — the 19-check automated negative-test suite.
- `spikes/s1-callout/src/natsjwt.rs` — hand-rolled NATS v2 JWT claim encode/decode.
- `spikes/s1-callout/src/fixtures.rs` — test identity/capability/cert builders (pre-existing,
  read but not modified this session except as noted above).
- `spikes/s1-callout/RESULTS.md` — this file.
- `docs/SPIKES.md` (§S1 Status line) and `IMPLEMENTATION_PLAN.md` (Stage 4 Note) — updated
  alongside this file.

**Throwaway / exploratory** (kept, each already carries a `//! Throwaway: ...` doc comment
explaining its purpose and disclaiming deliverable status — kept rather than deleted because they
document the empirical discovery process this crate's own doc comments repeatedly cite as the
source of a claim, e.g. "confirmed via `probe.rs`'s captured request"):
- `src/bin/genkeys.rs` — one-shot key generator used to produce `server.conf`'s nkeys (legitimate
  provenance record, not purely throwaway, but not needed again after config authoring).
- `src/bin/probe.rs` — dumps raw `$SYS.REQ.USER.AUTH` request payloads from a live server.
- `src/bin/try_connect.rs` — captures what a real nkey-signed `connect_opts` looks like on the
  wire.
- `src/bin/test_responder.rs` — an always-allow responder used to nail the JWT round trip before
  wiring in the real decision core.

## Toolchain / build status

- `cargo build --workspace`: clean, zero warnings.
- `cargo test --workspace`: green (`responder`/`s1-tests`/`probe`/`try_connect`/`test_responder`
  are plain `#[tokio::main]` binaries, not `#[test]`s — `cargo test --workspace` never touches
  them or requires Docker; the live-server suite is deliberately gated behind a real server on
  `NATS_URL`, invoked only via `run.sh` or manually).
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- Live-server run (`run.sh`, or the manual sequence it automates): **19/19**, reproduced on three
  independent container+responder restarts.
