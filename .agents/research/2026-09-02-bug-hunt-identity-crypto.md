# Bug Hunt — Identity + Crypto Paths (2026-09-02)

- **Scope**: identity + crypto paths — spindle-proto canonical CBOR, spindle-core fingerprints, spindle-host-core authorize/session/server, spindle-vfs store + schema, spindle-helper auth callout
- **Lenses**: all 9
- **Runtime context**: Server (helper service), Desktop (Tauri host/client), Browser (pure-TS engine), Windows specifically
- **Method**: /bug-hunt skill — every BUG/FRAGILE survived Step 5 adversarial refutation; Confidence labels are Confirmed (empirical) / Traced / Suspected
- **All 11 surviving findings are filed on the td board with the `bug-hunt` label** (ids in the rating table)

## Guard Map (Step 2 file list)

- `crates/spindle-vfs/src/store/schema.rs` — DDL, UNIQUE indexes, REFERENCES clauses, user_version migrations
- `crates/spindle-host-core/src/authorize.rs` — the 8 connect-time checks (`ConnectDecision`)
- `crates/spindle-host-core/src/server.rs` — per-request member/device gates
- `crates/spindle-host-core/src/session.rs` — `VfsSessionHandler`, sole production `SessionContext` constructor
- `crates/spindle-proto/src/canonical.rs` — canonical CBOR decoder, `read_arg` shortest-form rule
- `crates/spindle-core/src/fingerprint.rs` + `base32.rs` — `Fingerprint::of_parts`, `from_str`, domain tags
- `crates/spindle-helper/src/auth_token.rs` — NATS Auth Callout decode path
- `docs/DESIGN.md` — §A5 uniform silent drop, line 330 (per-request revocation authoritative), line 1022 (helper epoch check demoted *because* of line 330)
- existing `#[cfg(test)]` suites in server.rs / rpc_negative.rs — asserted-intended behavior

## Summary Counts

BUG 7 · FRAGILE 2 · REVIEW 2 · Refuted-and-killed 3

## Issue Rating Table

| # | td | Finding | Lens | Confidence | Urgency | Risk: Fix | Risk: No Fix | ROI | Blast Radius | Fix Effort |
|---|----|---------|------|------------|---------|-----------|---------------|-----|---------------|------------|
| 1 | td-13c7dc | Canonical CBOR decoder: 9-byte unauthenticated message panics via unvalidated `Vec::with_capacity` | 3 | **Confirmed (empirical)** | Now | Low | **Critical** — unauthenticated remote DoS on host *and* on the helper's auth callout | Highest | 1 file (`canonical.rs`), no data, no coordination | S |
| 2 | td-2454b3 | `Store::add_share` check-then-act race persists overlapping shares; 3-statement insert is non-atomic | 6 | **Confirmed (empirical)** | Soon | Low | High — overlapping shares bypass overlap guard; share can commit without its exclusion globs | High | 1 file, no migration, single service | S–M |
| 3 | td-c057a1 | No `PRAGMA foreign_keys = ON` — every `REFERENCES` clause is decoration | 4 | **Confirmed** (search receipt) | Soon | **Medium** — enabling FKs can surface pre-existing orphan rows | Medium (latent; live the moment any delete API ships) | High | 1 file + possible data audit | S |
| 4 | td-f65637 | No `busy_timeout` — concurrent access returns SQLITE_BUSY immediately | 6/7 | **Confirmed** (search receipt) | Soon | Low | Medium — spurious runtime failures under normal multi-connection load | High | 1 file, no data | S |
| 5 | td-de94c5 | Per-request device-revocation gate skipped when `SessionContext.device_fp` is `None` | 8 | **Traced** | Soon | Medium — touches ~59 test call sites | Medium now, High at Stage 7 (in-process Tauri caller) | Medium | 1–2 files + broad test churn | M |
| 6 | td-93cee6 | `invite_nonces.member_id` lacks `REFERENCES`; `burn_invite_nonce` can't distinguish burn from no-op | 4 | **Traced** | Later | Low | Low–Medium — silent replay window | Medium | 1–2 files | S |
| 7 | td-b940b1 | Quota counters bumped via `let _ =` outside any transaction with the file move | 4/5 | **Traced** | Later | Low | Low–Medium — silent quota drift, always low | Medium | 1 file | S |
| 8 | td-f19bc4 | Member revocation leaves `devices.revoked = 0` | 4 | **Traced** | Later | Low | Low — consistency only; member check already denies | Medium | 1 file | S |
| 9 | td-04e225 | No production device-enrollment path (`add_device`: 0 non-test callers) | — | **Confirmed** (search receipt) | Later | — | — (design gap, not a defect) | — | design decision | — |
| 10 | td-70c90b | `Capability`/`AdminCommand` carry a signed `v` never checked — no `min_v` floor | 8 | **Traced** | Later | Low | Low now, High later — a version floor is only worth shipping *before* the version you want to reject | High | 1–2 files | S |
| 11 | td-e6f19f | `root_fp` preimage rebuilt inline at 3 sites instead of calling `root_fp_of` | 8 | **Traced** | Later | Low | Low — drift hazard only | Medium | 1–2 files, behavior-preserving | S |

**Note**: rows 9 and 11 are REVIEW/chore rather than BUG; rows 5 and 10 are FRAGILE (correct today, break under a named foreseeable change).

## Fix Plan & Interactions

- **#1 ships alone and first.** It is the only unauthenticated-remote finding and touches one file with no data or coordination cost. Nothing blocks it.
- **#2 and #4 must ship together.** Adding a transaction to `add_share` (#2) makes correctness right but makes `SQLITE_BUSY` *more* likely, because a transaction holds its lock longer. Shipping #2 without #4 trades a rare race for a common spurious failure. Use `TransactionBehavior::Immediate`.
- **#3 ships behind an existing-data audit.** Enabling FK enforcement can fail at startup on orphan rows that were legal to write while enforcement was off. Audit before enabling. #6's `REFERENCES` addition ships *after* #3, since it is inert until enforcement is on.
- **#5 is a test-surface change, not a one-liner.** The `ctx()` helper (12 call sites in `rpc_negative.rs`, 47 in `server.rs`) defaults `device_fp` to `None`. Either supply a real fingerprint in the helper, or make the field non-optional so the type system deletes the branch. Prefer the latter.
- **#9 gates the severity of several other tasks.** Device-related findings cap at FRAGILE *because* enrollment is unreachable. When enrollment ships, re-triage td-de94c5, td-ad318f and td-6c01e3 against the new reachability facts.
- Deferred to design work: none. Every fix above passed the Step 6 checklist or is explicitly scoped as a design decision (#9).

## Detailed Findings

### #1 — canonical CBOR `Vec::with_capacity` (td-13c7dc), Confirmed (empirical)

**Lens**: 3 (boundaries)

`crates/spindle-proto/src/canonical.rs:414-443`. Major-type 4 (array) and 5 (map) branches:

```rust
4 => {
    let (count, mut off) = read_arg(bytes, offset, info, head_offset)?;
    let mut items = Vec::with_capacity(count as usize);   // line 416
    ...
5 => {
    let (count, mut off) = read_arg(bytes, offset, info, head_offset)?;
    let mut entries = Vec::with_capacity(count as usize); // line 426
```

**Assumption**: the decoder assumed the count field is a reasonable, boundable size before it is used to allocate.

**Violation scenario**: the count is attacker-controlled and allocated against before a single element is read. The byte-string and text-string branches **in the same file** do bounds-check first (`bytes.get(off..end).ok_or(UnexpectedEof)?`) — this is Lens 8 inside one file: two branches, one guards.

**Consequence**: unauthenticated remote panic / DoS on both production entry points.

**Current code**: as quoted above, `canonical.rs:414-443`.

**Confidence + evidence**: Empirical, 9-byte payload `[9b, ff, ff, ff, ff, ff, ff, ff, ff]`, run in a scratch probe crate, both production entry points:

```
[1] signaling/mod.rs:101 path -> Envelope::from_canonical_bytes(&msg.payload)
    panicked at raw_vec/mod.rs:28:5: capacity overflow
    *** PANICKED ***
[2] spindle-helper auth_token.rs:102 path -> DeviceCertificate::from_canonical_bytes(cert_bytes)
    panicked at raw_vec/mod.rs:28:5: capacity overflow
    *** PANICKED ***
```

Reachability: `signaling/mod.rs:101` and `host.rs:150` decode **pre-auth**; `auth_token.rs:102` decodes inside the NATS auth callout that runs to *decide* authentication. Both are reachable by an unauthenticated remote.

**Honest limit, do not soften**: `read_arg`'s shortest-form rule forces counts ≥ 2^32 into the 8-byte head, so the implied allocation is ≥ 137 GB and panics as `capacity overflow`. Intermediate counts (large but allocatable-looking) are expected on Linux/containers to abort via `handle_alloc_error`, which is **uncatchable** — that path was **NOT measured here** and should be measured before fixing. My first probe on macOS did **not** reproduce, because lazy VM satisfied a 1e10 count and the decode returned `UnexpectedEof` cleanly; only `u64::MAX` panics there.

**Fix direction**: bound the count against remaining input length before allocating (each element costs ≥ 1 byte, so `count > bytes.len() - off` is unsatisfiable), or drop `with_capacity` for a growing `Vec`. Prefer the bound — it also rejects the input earlier.

### #2 — `add_share` race (td-2454b3), Confirmed (empirical)

**Lens**: 6 (time & concurrency)

`crates/spindle-vfs/src/store/mod.rs:843-913`. Four read-based checks (share-count limit, exclude-count limit, `real_root` overlap via a full `list_shares()` scan, `mount_path` collision via the same scan), then `INSERT INTO shares`. Grep for `transaction|BEGIN` across 843-913 returns nothing — every statement autocommits, no lock is held across the gap.

**Assumption**: the check phase and act phase were assumed to be effectively atomic under normal (single-caller) usage.

**Violation scenario**: two concurrent callers both scan, both see no conflict, both insert.

**Consequence**: overlapping shares bypass the overlap guard; a share can commit without its exclusion globs.

**Current code**: `store/mod.rs:843-913`, as described above.

**Confidence + evidence**: Empirical (python3 sqlite3, mirroring `Store::open` exactly — rollback journal, autocommit, `timeout=0`):

```
A scan sees []; B scan sees []  -> both find no conflict
A insert -> OK
B insert -> OK  *** BOTH COMMITTED ***
final rows: [(1,'/pub','/srv/data'), (2,'/pub/sub','/srv/data/inner')]
```

The `UNIQUE` index on `mount_path` does not catch this: `mount_paths_collide` is a prefix/overlap test, not equality, and `/pub` ≠ `/pub/sub`. `real_root` overlap has no constraint at all. `check_persisted_share_overlaps` only notices at the *next* `Store::open`.

Second defect, same function: the insert is three independent autocommits — `INSERT INTO shares`, then a loop of `INSERT INTO share_excludes`, then `bump_grants_version()`. A crash between them commits a share **without its exclusion globs**. Those globs hide files, so this half is a security consequence, not a consistency one.

**Fix direction**: wrap check + insert(s) in a single transaction, `TransactionBehavior::Immediate` (see Fix Plan interaction with #4).

### #3 — no `PRAGMA foreign_keys` (td-c057a1), Confirmed

**Lens**: 4 (data lifecycle)

`crates/spindle-vfs/src/store/mod.rs:240-267`. `Store::open` / `open_with_limits` / `open_in_memory` / `open_in_memory_with_limits` all call `Connection::open(...)` then `schema::migrate(...)` and nothing else. No pragma is set anywhere.

**Assumption**: `REFERENCES` clauses in `schema.rs` were assumed to be enforced.

**Violation scenario**: any write that would violate a foreign-key relationship succeeds silently, because SQLite disables FK enforcement by default, per connection.

**Consequence**: `devices.member_id`, `member_groups.member_id/group_id`, `share_excludes.share_id`, `entitlements.group_id/share_id`, `member_upload_bytes.member_id`, `share_upload_bytes.share_id` are all decorative-only.

**Current code**: `store/mod.rs:240-267`.

**Confidence + evidence**: Search receipt: `grep -rn "foreign_keys" --include='*.rs'` across the repo → **zero matches**. `grep -n "pragma|PRAGMA"` across `crates/spindle-vfs/src/store/` → only `user_version` (the migration mechanism).

Latent today: no `delete_member`/`delete_share`/`delete_group` exists anywhere in the crate (searched), so nothing orphans a row yet. It goes live the moment any admin removal API is written — by an author who will reasonably assume the `REFERENCES` clauses already protect them.

**Fix direction**: enable `PRAGMA foreign_keys = ON` on every connection, after an existing-data audit for orphan rows (see Fix Plan).

### #4 — no `busy_timeout` (td-f65637), Confirmed

**Lens**: 6/7 (time & concurrency / environment divergence)

Same four constructors as #3, same absence.

**Assumption**: the daemon's multi-connection access pattern was assumed to tolerate SQLite's default locking behavior.

**Violation scenario**: a writer finds the database locked and returns `SQLITE_BUSY` on the *first* attempt, because rusqlite's default busy timeout is effectively zero.

**Consequence**: `spindle-hostd` opens its own `Store`, `SqliteDeviceLookup` opens one, `VfsSessionHandler` opens one, plus one per session — contention is normal operation. Under the default rollback journal a single writer also blocks **readers**, so an ordinary VFS list during an admin write can fail outright.

**Current code**: same four constructors as #3 (`store/mod.rs:240-267`).

**Confidence + evidence**: Search receipt: `grep -rn "busy_timeout|busy_handler|journal_mode|WAL" --include='*.rs'` → **zero matches**.

**Fix direction**: set a `busy_timeout` on every connection (see Fix Plan interaction with #2).

### #5 — optional revocation gate (td-de94c5), Traced. FRAGILE

**Lens**: 8 (write/read asymmetry — one guarded implementation, one unguarded caller path)

`crates/spindle-host-core/src/server.rs:261-307`. Member-status check is unconditional; the device-revocation check is not:

```rust
if let Some(device_fp) = ctx.device_fp {
    match member.devices.iter().find(|d| d.device_fp == device_fp) {
        Some(d) if d.revoked => { ...audit "denied:device_revoked"... }
```

**Assumption**: every `SessionContext` reaching this gate was assumed to carry a populated `device_fp`.

**Violation scenario**: a `SessionContext` is constructed with `device_fp: None`, and the device-revocation check is skipped entirely — only the unconditional member-status check still runs.

**Consequence**: `DESIGN.md:330` states the host rejects VFS requests from revoked keys **per request** and calls that check **authoritative**. `DESIGN.md:1022` records that the helper's callout epoch check was *deliberately demoted* to best-effort **because** the host check is authoritative. This gate is therefore the compensating control for a check that was intentionally weakened elsewhere — and it is conditional.

**Current code**: `server.rs:261-307`, as quoted above.

**Confidence + evidence**: Not exploitable end-to-end today: `VfsSessionHandler` is the sole production constructor of `SessionContext` and does populate `device_fp` (verified) — hence Traced, not Confirmed, and latent rather than an active bypass. But `SessionContext` is `pub` (`server.rs:41`) with `pub device_fp: Option<Fingerprint>`, re-exported at `lib.rs:115`, so any future in-process caller — notably `apps/host`'s Tauri shell at Stage 7, which per DESIGN §A10.26 runs the daemon in-process — can construct one with `None` and silently lose the gate. Fail-open by omission.

The in-code justification is half stale: it says wiring per-session device identity is "`spindle-net`'s job, a later slice" — that slice has landed. The other half stands (see Refutation Log entry 3).

**Fix direction**: tighten `None` to a denial, or make `device_fp` non-optional (preferred; see Needs Human Review — public-API change to a `pub` re-exported type).

### #6 — invite nonces (td-93cee6), Traced

**Lens**: 4 (data lifecycle)

Two weaknesses: `invite_nonces.member_id` declares no `REFERENCES`, unlike every other member-scoped table in `schema.rs` (`devices`, `member_groups`, `member_upload_bytes` all do) — a divergence from the crate's own convention, though inert until #3 lands. And `burn_invite_nonce` issues its UPDATE/DELETE without first asserting the nonce exists and is unburned, so "burned a live nonce" and "burned nothing" are indistinguishable to the caller — a single-use nonce whose burn silently no-ops is a replay window with no signal to reject on.

**Fix direction**: add the `REFERENCES` clause (after #3 ships); make `burn_invite_nonce` assert existence/unburned state and surface a distinct result for no-op vs. burn.

### #7 — quota counters (td-b940b1), Traced

**Lens**: 4/5 (data lifecycle / error paths)

`member_upload_bytes` / `share_upload_bytes` are bumped with the result discarded via `let _ = ...`, outside any transaction covering the file move. A failed update is swallowed entirely (Lens 5): the upload succeeds, the quota does not move, and accounting drifts **low** — the direction that matters for a limit. Separate autocommits also mean a crash between them leaves bytes on disk no counter accounts for, or a counter charged for bytes never persisted. Same root cause as #2 (multi-step mutation, no spanning transaction), distinct code path and fix.

**Fix direction**: stop discarding the update result; wrap the file move and counter bump in one transaction.

### #8 — member revocation vs `devices.revoked` (td-f19bc4), Traced. Consistency, not auth

**Lens**: 4 (data lifecycle)

Revoking a member leaves that member's device rows at `revoked = 0`. **Not an auth bypass** — `server.rs` checks member status unconditionally before it looks at the device, so a revoked member is denied regardless. The cost is that any future query, audit export, or admin UI treating `devices.revoked` as ground truth gets a wrong answer.

**Fix direction**: cascade-revoke device rows when a member is revoked.

### #9 — no production enrollment path (td-04e225), Confirmed. REVIEW

**Lens**: — (design gap)

Search receipt: `grep -rn "add_device" --include='*.rs'` → 13 call sites, **all 13** inside `#[cfg(test)]` modules or `tests/` files. No production path enrolls a device. This is a design gap surfaced by the hunt, and it is *why* several device-related findings cap at FRAGILE: a bug in enrollment cannot be triggered by a real user when enrollment cannot be triggered at all. Recorded so the cap is revisited rather than silently assumed permanent.

**Fix direction**: not a fix — a design decision. Re-triage td-de94c5, td-ad318f and td-6c01e3 once an enrollment path ships.

### #10 — unchecked `v` field (td-70c90b), Traced. FRAGILE

**Lens**: 8 (write/read asymmetry)

`Envelope` validates its version against a minimum-version floor before acting. `Capability` and `AdminCommand` carry the same signed `v` and nothing ever reads it — no `min_v` equivalent on either. Lens 8 exactly: one implementation guards, its siblings do not, and the guarded one is the specification.

**Consequence**: a future format revision can never be made mandatory, because no code exists that could reject an old version. The field is signed, so it is trustworthy input — it is simply unused. No live exploit (one version exists), which is why it is P3; the value of a version floor is entirely in shipping it *before* the version you want to reject.

**Fix direction**: add a `min_v` floor check to `Capability` and `AdminCommand`, mirroring `Envelope`.

### #11 — duplicated `root_fp` preimage (td-e6f19f), Traced. Chore

**Lens**: 8 (write/read asymmetry)

`root_fp_of` is the single named constructor, but the preimage is rebuilt inline at `capability.rs:34`, `capability.rs:76`, and `host_device_cert.rs:108`. Three hand-rolled copies of a domain-separated hash preimage is a drift hazard fingerprint construction cannot tolerate: a future preimage change that updates `root_fp_of` and misses a copy produces two fingerprints that are each "correct" by their own code and never match. Compare `device_fp_of`, whose four-input preimage already has a known documentation/schema mismatch elsewhere on the board.

**Confidence + evidence**: All three copies are currently byte-identical to `root_fp_of`'s output (verified by reading all three) — pure refactor, no behavior change.

**Fix direction**: replace all three inline copies with calls to `root_fp_of`.

## Already Guarded (verification cleared these)

- **Connect-time `device_fp` binding is hardcoded and fail-closed** — `crates/spindle-host-core/src/authorize.rs:209`: `if device_fp_of(ALG_ID_V1, &sign_pk, &agree_pk) != *from_fp { return ConnectDecision::Deny; }`.
- **Member-status check is unconditional** on the per-request path (`server.rs`), which is what keeps #8 a consistency issue rather than an auth bypass.
- **Byte-string and text-string CBOR branches bounds-check before allocating** (`canonical.rs`) — the guarded sibling that makes #1 a divergence rather than a design choice.
- **§A5 uniform silent drop is intentional**: a denied connect produces no typed denial on the wire; the client sees only its own timeout. Positive-control runs are what rule out false greens here.

## Refutation Log (killed in Step 5)

1. **"Revoke double-bumps `cap_epoch` under concurrency" — REFUTED.** A python sqlite3 probe showed SQLite's RESERVED lock blocks the second writer; the observed `cap_epoch` was **1, not 2**. The revoke path *does* wrap its work in a transaction, which is precisely why it is protected and `add_share` (#2, no transaction at all) is not. This contrast is the reason #2 is credible.
2. **"base32 padding aliases distinct fingerprints" — REFUTED.** `base32` is a **private** module, and `Fingerprint::from_str` rejects every padded variant with `WrongLength(33/34/35)`. No aliasing path exists.
3. **My own sub-claim "the `device_fp: None` comment inflates its test count ~4×" — REFUTED by me.** Only 5 literal `device_fp: None` sites exist, but the comment counts callers of the `ctx()` helper: 12 in `rpc_negative.rs`, 47 in `server.rs`. The comment's count is accurate; my correction was wrong. This is why #5's fix is scoped as a test-surface change rather than a one-line flip.
4. **"Manifest `sign_pk` rehash is escalatable to session hijack" — REFUTED.** `sign_pk`/`agree_pk` are never written after insert: the sole `INSERT INTO devices` is `store/mod.rs:583`, and the only other writes touching that table are `UPDATE devices SET revoked = 1`. So connect-time check 8 covers the whole session — the keys it validated cannot change underneath it. (The rehash concern on td-ad318f stands on its own terms; the escalation does not. Logged there too.)
5. **My first CBOR probe did not reproduce the DoS.** Count `1e10` returned `UnexpectedEof` cleanly on macOS because lazy VM satisfied the allocation. Reported as a non-reproduction rather than claimed as confirmation; refined to `u64::MAX`, which does panic. Recorded because the negative result is what makes the positive one trustworthy.

## Needs Human Review

- **#1's intermediate-count abort path on Linux/containers was NOT measured.** Measure `handle_alloc_error` behavior (uncatchable abort) before fixing, so the fix is verified against the real failure mode and not only against the macOS `capacity overflow` panic.
- **#9 — device enrollment** is a scope/design decision, not a defect. It also gates the severity of td-de94c5, td-ad318f and td-6c01e3.
- **#3's existing-data audit**: whether orphan rows already exist that would make enabling FK enforcement fail at startup.
- **#5's fix shape**: tighten `None` to a denial, or make `device_fp` non-optional. The latter is preferred here but is a public-API change to a `pub` re-exported type.

## Footer

Note that no duplicates were filed: td-684764 (revocation no audit), td-ad318f (manifest rehash), td-6c01e3 (alg_id), td-b2c16b (agree_pk backfill) and td-4bcf24 (rate-limit) were already on the board and cover ground this hunt re-touched.
