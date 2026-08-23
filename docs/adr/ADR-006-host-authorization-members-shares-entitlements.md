# ADR-006: Host Authorization — Members, Shares, and Entitlements

## Status

Accepted

## Context

Spindle has no registry-held accounts: identity is cryptographic and is *recognized* per host (ADR-003). Once a
device has a valid session with a host (ADR-002, ADR-004), the host still must decide, per request, exactly what
that member is allowed to see, browse, download, upload, or delete — and it must do so without the registry's help,
since the registry is explicitly barred from ever learning what a host shares, its member names, groups, or
entitlements (ADR-001 §A2, zero-knowledge definition clause (d)). Everything in this ADR therefore lives **only on
the host** (SQLite) and is enforced **only by the host**.

This is also where the filesystem-confinement asset from the threat model is defended in depth: adversary A1
("malicious authenticated device/member") starts with a valid device key and membership on some hosts, and wants to
reach hosts/paths it wasn't granted, escape the VFS, or plant hostile files (ADR-001 §A2). A large fraction of the
red-team traceability table (ADR-001 §A12, rows #19–23 and #29–32) is closed specifically by the mechanisms
described here: VFS escape, exclusion bypass via case/Unicode variants, existence leaks, stale grants after
revocation, upload scoping/overwrite, overlapping-root/hardlink exclusion bypass, TOCTOU rename races, and
case/NFD upload-collision overwrites.

## Decision

### Members

`{member_id, root_fp, display_name, status: invited|active|revoked, devices[{device_fp, label, added, revoked?}],
groups[], created}`

"Creating an account" *is* issuing an invite; redemption creates the member record. The owner is an implicit
member with all rights. **Owner-only administration in v1** (decided) is performed **only in the host's local UI**
(tray/desktop) — there is no remote admin surface in v1 (open item A10.11, below).

### Shares (the VFS)

The owner adds a file or directory, producing:

`{share_id, name, mount_path, real_root, flags: {read_only, allow_upload, show_hidden}, excludes: [glob…]}`

Shares are mounted into **one virtual tree per host**; clients only ever see or speak virtual paths. Exclusions are
share-level — they apply to every member — and are how "Photos except Photos/Private" is expressed, which keeps the
permission algebra monotonic (no denies needed at the entitlement layer). Rules:
- **no overlapping roots** — rejected at add-time by resolved real path *and* by device+inode/file-id, and
  re-checked at host start;
- warn when rooting a share at a home directory or a volume root;
- caps apply on shares per host and on globs per share;
- when a share has exclusions, files with link count > 1 are **not served** (hardlink bypass prevention);
- **archives are never auto-expanded**.

### Groups

Built-in `Owner` (implicit, all rights, not editable) and `Members` (default, empty grants); plus custom groups.
Members and groups are many-to-many. Invites may name an initial group (e.g. "Invite Alex to *Family*").

### Entitlements

`{group_id, share_id, subpath, perms ⊆ {browse, download, upload, delete}}`

**Algebra (decided)**: positive-only; a member's effective permissions on virtual path P are the **union** of every
grant from every group they belong to whose `(share, subpath)` is a prefix of P, inherited downward. There are no
deny rules in v1 — exclusions live on shares, not in the entitlement algebra. This is explainable in one sentence:
"you can do whatever any of your groups can do, anywhere under the folder it was granted on." `upload` and `delete`
are grantable only on shares flagged `allow_upload` (decided: uploads are v1, opt-in per share).

**Edge rules** (decided):
- `browse` on P implies *traversal* of P's ancestors — the ancestor listing shows only the path toward P, not
  siblings;
- `upload` on P implies resolution of P without listing it (drop-box behavior);
- `delete` does **not** imply `download`;
- overwriting an existing entry requires `delete`;
- creating a name that collides case-insensitively, or under Unicode normalization, with an existing directory
  entry **is** an overwrite.

**Secure by default**: a new share starts with no grants; a new member starts in the `Members` group with no
grants. Nothing is visible until it is explicitly granted.

### Enforcement

Every VFS request (ADR-005) is checked against a cached effective-grant table for the member, invalidated by the
host's `epoch` counter, **per request** — revoking a group takes effect immediately, not at reconnect
(ADR-001 §A12 #22, stale grants in live sessions after revocation). Listings show only entries the member can
`browse`; non-browsable paths return **not found**, never a distinguishable "exists but forbidden" response
(ADR-001 §A12 #21, existence leak of non-browsable paths). Client UI hiding of unpermitted actions is a courtesy,
not a security boundary — enforcement is host-side and per-request.

### Path confinement

Share roots are opened as `cap-std` `Dir`s, **pinned ≥ 3.4.1 / 4.x** — RUSTSEC-2024-0445 and the Windows
DOS/UNC device-path cases are covered by spike S11. All I/O goes through the capability, so `..`, symlink escape,
and absolute-path tricks are excluded **by construction** (ADR-001 §A12 #19, VFS escape); symlinks that point out
of the share root are not followed, and no device files are exposed.

`cap-std` does **not** canonicalize, case-fold, or normalize paths — Spindle does this itself: exclusion and
permission matching is performed against the resolved real path plus case/Unicode folding on case-insensitive
filesystems, and identity checks (dev+ino / file-id) are used wherever names are ambiguous (ADR-001 §A12 #20,
exclusion/permission bypass via case or Unicode variants). Every request re-resolves from the share `Dir` — there
are no long-lived subdirectory handles — and file identity is re-checked between `stat` and `read`/`upload`, and at
every chunk boundary, aborting on any change (ADR-001 §A12 #30, TOCTOU/rename races).

Uploads land only under the granted subpath, obey ADR-005's received-file policy, are subject to per-member and
per-share quotas, and never overwrite without `delete` (ADR-001 §A12 #23, upload outside granted subpath /
overwrite). Overlapping-root rejection by path *and* identity, plus the hardlink `nlink` rule above, close
ADR-001 §A12 #29 (overlapping share roots / hardlinks defeat exclusions). The case/Unicode collision-is-overwrite
rule closes ADR-001 §A12 #31 (case/NFD upload collision overwrites without `delete`).

### Audit log

`{ts, member, device, action, virtual_path, bytes, outcome}` recorded for every VFS operation and every admin
change; the log is **hash-chained, append-only**, with a periodically signed head, making tampering evident.
`list` is cursor-paged with a maximum page size; exclusion globs are precompiled; `whoami` returns only the
caller's own effective paths and never group names (ADR-001 §A12 #32, member enumeration via presence / `whoami` /
timing).

### Owner live operations

A *Sessions* view shows who is connected now, per device, with current transfer and byte counts. The owner has a
**soft disconnect** for a live session (distinct from a revocation), a host-level **free-space floor** that pauses
uploads before the disk fills, and an optional per-host **egress cap** — an owner-controlled bandwidth throttle,
distinct from the security-motivated rate limits elsewhere in the system.

### Operator UX

*Shares* (add folder → name → appears in tree); *People* (members, their devices, groups; revoke a device or the
whole person); *Groups* (a grid of Groups × Shares with permission chips, click to refine a subpath); **"Preview as
…"** (see the tree exactly as a given member sees it); plain-language explanations — e.g. "Alex can download from
Photos because they're in Family" — derived directly from the union model above, not a separate explanation engine.

### Decision A10.4b

DESIGN.md §A10 row 4b records this whole model as **DECIDED 2026-08-23**: positive-only union algebra plus share
exclusions; uploads on opt-in shares; owner-only administration.

## Consequences

### Positive

- Positive-only union algebra with share-level exclusions keeps the permission model explainable in one sentence
  and monotonic, satisfying the design goal that "permissions are predictable and explainable" (DESIGN.md A1
  goal 3).
- Per-request enforcement, gated by the host's `epoch`, makes revocation of a group or member take effect
  immediately rather than at next reconnect, closing ADR-001 §A12 #22.
- `cap-std` capability confinement plus Spindle-side canonicalization closes VFS escape (ADR-001 §A12 #19) and
  case/Unicode bypass (ADR-001 §A12 #20) as two independently defended layers rather than one.
- Not-found semantics for both unauthorized calls and unbrowsable listing entries close the existence-leak class of
  attack uniformly (ADR-001 §A12 #21).
- Overlap rejection by path *and* identity, plus the hardlink `nlink` rule, close a bypass class (ADR-001 §A12 #29)
  that path-string checks alone cannot catch.
- The hash-chained, append-only audit log gives tamper-evidence for both file operations and administrative
  changes, supporting the owner-only administration model without needing a separate trusted admin channel.

### Negative

- No deny rules in v1 means an owner who wants to grant broad access to a group but exclude one member's ability to
  reach a specific subpath cannot express that directly — they must model it via share exclusions or restructure
  groups, which is less flexible than a full ACL model.
- Path confinement relies on a pinned `cap-std` version and manual Windows-path handling (DOS/UNC/8.3/ADS device
  names); this is a nontrivial, platform-divergent surface that spike S11 must exhaustively cover, and any gap
  there directly threatens the confinement guarantee this ADR relies on.
- Every VFS request re-resolving from the share `Dir` (no long-lived subdirectory handles) trades some performance
  for TOCTOU safety; on very deep directory trees or slow filesystems this could add latency to every operation.
- Owner-only administration (no delegated admin in v1) means a host owner who is unavailable is a single point of
  failure for any membership/entitlement change, including emergency revocation via the host UI (root-signed
  self-revocation and helper-side revocation deposit mitigate the offline-host case specifically, per ADR-003).

### Neutral

- The audit log's cursor-paged `list` and precompiled exclusion globs are implementation details in service of the
  security properties above; they do not themselves close any specific red-team row but keep enforcement
  performant enough to remain per-request.
- The "Preview as …" operator UX feature is a usability mechanism built directly on the union algebra; it has no
  independent security property beyond making the enforced model auditable by the owner.

## Alternatives Considered

From DESIGN.md §A11:
- **Deny rules in entitlements** — Deferred; predictability was prioritized, and share-level exclusions were
  judged to cover the common case ("everything except this subfolder") without breaking the positive-only union's
  simplicity.
- **Host-local passwords for members** — Rejected; this would break the E2E key model (ADR-003, ADR-004) and the
  one-identity-many-hosts UX that root-key-based membership provides.
- **String-sanitization path confinement** — Rejected in favor of `cap-std` capability confinement by construction,
  supplemented by Spindle-side case/Unicode folding and identity checks; string sanitization alone has historically
  been a recurring source of path-traversal bugs.
- **Host-wide single epoch** — Rejected (v0.8); this conflated security invalidation with cache invalidation. The
  design instead splits `cap_epoch` (bumps only on security events; invalidates capabilities) from
  `grants_version` (host-internal entitlement-edit/cache invalidation; never leaves the host) — see ADR-003 for the
  capability side of this split.

## Open items

DESIGN.md marks the following as unresolved; they are recorded here, not decided by this ADR:

- **A10.11 — Admin surface [DEFAULT]**: local host UI only in v1; remote admin is deferred. This is a default
  choice, not an explicit user decision, and is not reopened by this ADR.

## References

- ../DESIGN.md §A2 (threat model, asset 5, adversary A1, zero-knowledge definition), §A4 (identity, capabilities,
  enrollment — capability lifecycle that gates membership), §A4b (host authorization: members, shares,
  entitlements), §A9 (UX requirements — Share a folder, Browse, Received files rows), §A10 rows 4b and 11, §A11
  (alternatives), §A12 (red-team traceability, rows #19–23, #29–32)
- [ADR-001: Threat Model](./ADR-001-threat-model.md) — adversary A1, §A12 rows #19, #20, #21, #22, #23, #29, #30,
  #31, #32
- [ADR-003: Identity, Capabilities, Enrollment](./ADR-003-identity-capabilities-enrollment.md) — `cap_epoch` vs.
  `grants_version` split; capability revocation that this ADR's per-request enforcement treats as authoritative
- [ADR-005: Transport, VFS RPC, and File Safety](./ADR-005-transport-vfs-rpc-file-safety.md) — every VFS RPC call
  this ADR's enforcement layer gates; received-file policy for uploads
- ../SPIKES.md S11 (VFS confinement negative-test suite), S10 ("Preview as" / permission-grid usability test)
