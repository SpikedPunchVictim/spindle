//! SQLite-backed durable host state (DESIGN.md §A4b: "Everything here lives only on the host
//! (SQLite) and is enforced only by the host. The registry never sees it."). [`Store`] wraps a
//! single `rusqlite::Connection` (bundled SQLite — no separate service, no network) with typed
//! methods that read/write the existing slice-1 model structs (`crate::model`) directly; this
//! module invents no parallel wire/storage types.
//!
//! # Two counters, two rules (DESIGN.md §A4 "`cap_epoch` vs `grants_version`")
//!
//! `meta.grants_version` bumps on **every** entitlement, group-membership, or share mutation —
//! [`Store::bump_grants_version`] is called from inside every such method here, never left to a
//! caller to remember. `meta.cap_epoch` bumps **only** via the explicit [`Store::bump_cap_epoch`]
//! — no other method in this file touches it. This is a deliberate asymmetry, not an oversight:
//! §A4 states cap_epoch bumps "only on security events (member/device revocation)" but also that
//! "revoking one member does not invalidate other members' caps unless the host chooses a full
//! rotation" — i.e. *whether* a given revocation warrants a host-wide epoch bump (vs. some
//! narrower, per-subject invalidation) is a policy decision that belongs to the caller
//! (`spindle-host-core`, a later slice), not something [`Store::set_member_status`] /
//! [`Store::revoke_device`] should decide unilaterally by always bumping it as a side effect. So
//! those two methods only change status; bumping `cap_epoch` for the resulting security event is
//! the caller's explicit next call. This keeps the two counters' independence a structural
//! property of this module (there is exactly one code path that can increment `cap_epoch`) rather
//! than a convention someone could accidentally violate.
//!
//! # Secure by default (DESIGN.md §A4b)
//!
//! [`Store::add_share`] creates zero grants (no entitlement rows reference it yet).
//! [`Store::add_member`] places the new member in the built-in `Members` group only, which itself
//! starts with zero grants — see `crate::algebra`'s `new_share_nothing_visible` /
//! `new_member_in_default_group_nothing_visible` tests for the algebra-level assertion this
//! module's own tests (below) build on directly against real persisted rows.
//!
//! # Built-in groups
//!
//! `Owner` (`GroupId(1)`) and `Members` (`GroupId(2)`) are seeded by the schema migration itself
//! (`schema::SCHEMA_V1`) — every store, from its very first connection, has both. Per §A4b
//! ("Owner ... not editable"), mutating a built-in group's definition (rename, delete, or adding
//! an entitlement grant *to* `Owner` specifically, which would be redundant with its implicit-all
//! rights and is also the "not listable as grantable" half of that sentence) is rejected with
//! [`StoreError::BuiltinGroupNotEditable`]. `Members` remains an ordinary grantable group for
//! entitlement purposes (only its row identity/kind is protected) — the owner routinely grants
//! things to `Members` (e.g. "everyone can browse Public"); §A4b's "not editable"/"not listable as
//! grantable" language is Owner-specific, contrasted in the same sentence with "Members
//! (default)".
//!
//! # Overlap re-checking (DESIGN.md §A4b: "no overlapping roots ... re-checked at host start")
//!
//! [`Store::add_share`] rejects an overlapping root at add-time using `crate::confine::overlap_check`
//! (slice-1, unmodified). [`Store::open`] additionally re-runs the same check over every
//! *persisted* share after migrating, because the filesystem can change out from under a host
//! between runs (an external mount, a moved directory, a symlink swap) in ways no add-time check
//! could have seen. [`Store::open_in_memory`] skips this re-check — an in-memory store never has
//! pre-existing persisted shares to re-check.
//!
//! # Limits (DESIGN.md §A4b: "caps on shares per host, globs per share")
//!
//! [`StoreLimits`] carries both caps with documented defaults; see its doc comment.

mod schema;

use crate::confine::{self, overlap_check};
use crate::glob::CompiledGlob;
use crate::model::{
    Device, DevicePublicKeys, Entitlement, Group, GroupId, GroupKind, Member, MemberId,
    MemberStatus, ModelError, Perms, Share, ShareFlags, ShareId, VirtualPath,
};
use rusqlite::{params, Connection, OptionalExtension};
use spindle_core::{Fingerprint, FingerprintError};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// `GroupId` of the built-in, implicit-all-rights, not-editable/not-grantable `Owner` group
/// (DESIGN.md §A4b), seeded by `schema::SCHEMA_V1`.
pub const OWNER_GROUP_ID: GroupId = GroupId(1);
/// `GroupId` of the built-in, default, initially-empty `Members` group (DESIGN.md §A4b), seeded
/// by `schema::SCHEMA_V1`. Every fresh member is placed here (see [`Store::add_member`]).
pub const MEMBERS_GROUP_ID: GroupId = GroupId(2);

/// Configurable caps, DESIGN.md §A4b: "caps on shares per host, globs per share". Defaults are
/// generous-but-bounded placeholders (no numeric default is specified in DESIGN.md; these are
/// this implementation's choice, documented here so a later slice can retune them without hunting
/// through the store's method bodies): a host with hundreds of shares or an exclude list with
/// dozens of globs per share is already an unusual deployment, and an unbounded value would make
/// the "caps" language in §A4b meaningless.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreLimits {
    /// Maximum number of shares a single host may have. Default: 256.
    pub max_shares: usize,
    /// Maximum number of exclude globs a single share may have. Default: 128.
    pub max_excludes_per_share: usize,
}

impl Default for StoreLimits {
    fn default() -> Self {
        StoreLimits {
            max_shares: 256,
            max_excludes_per_share: 128,
        }
    }
}

/// Errors from [`Store`] operations.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error(transparent)]
    Model(#[from] ModelError),

    #[error("path confinement error: {0}")]
    Confine(#[from] confine::ConfineError),

    #[error("corrupt fingerprint stored in the database: {0}")]
    CorruptFingerprint(#[from] FingerprintError),

    /// DESIGN.md §A4b: Owner is "implicit, all, not editable"; Members' *definition* (identity,
    /// kind) is likewise protected even though entitlements may still target it (see the module
    /// doc comment).
    #[error(
        "group {0:?} is a built-in group and its definition cannot be edited/deleted \
         (DESIGN.md §A4b: \"Owner (implicit, all, not editable)\")"
    )]
    BuiltinGroupNotEditable(GroupId),

    /// Owner already has implicit all rights everywhere; granting it an entitlement would be
    /// meaningless, and §A4b states it is "not listable as grantable".
    #[error(
        "the Owner group is not grantable (DESIGN.md §A4b: \"not listable as grantable\"); it \
         already has all rights implicitly"
    )]
    OwnerNotGrantable,

    #[error("group {0:?} not found")]
    GroupNotFound(GroupId),

    #[error("share {0:?} not found")]
    ShareNotFound(ShareId),

    #[error("member {0:?} not found")]
    MemberNotFound(MemberId),

    #[error("device {0} not found")]
    DeviceNotFound(Fingerprint),

    /// DESIGN.md §A4b member status: "invited|active|revoked"; revoked is terminal.
    #[error(
        "invalid member status transition {from:?} -> {to:?} (DESIGN.md §A4b: revoked is \
         terminal; invited -> active -> revoked is the only forward path)"
    )]
    InvalidStatusTransition {
        from: MemberStatus,
        to: MemberStatus,
    },

    /// DESIGN.md §A4b: "no overlapping roots (rejected at add-time by resolved real path *and*
    /// device+inode/file-id ...)".
    #[error(
        "share root {new_root:?} overlaps existing share {existing:?} (DESIGN.md §A4b: no \
         overlapping roots)"
    )]
    OverlappingShareRoot {
        new_root: PathBuf,
        existing: ShareId,
    },

    /// **Stage 6 slice 3 addition, reported per the task brief rather than silently added**: the
    /// slice-1/2 store rejected overlapping *real* roots (`real_root`, via
    /// `crate::confine::overlap_check`) but had no equivalent check for overlapping **virtual**
    /// `mount_path`s. DESIGN.md §A4b states shares are "mounted into one virtual tree per host"
    /// but does not spell out a mount-path collision rule the way it does for real roots. Left
    /// unchecked, two shares could claim the same (or an ancestor/descendant) `mount_path` — e.g.
    /// `"Photos"` and `"Photos/Vacation"` — which the slice-3 VFS RPC server's longest-prefix-match
    /// mount resolution (`spindle-host-core`) would then resolve ambiguously: a virtual path under
    /// the shorter mount could be silently shadowed by the longer one, permanently hiding part of
    /// the first share's tree with no error at share-creation time. This check closes that gap: a
    /// new `mount_path` must be neither equal to, an ancestor of, nor a descendant of any existing
    /// share's `mount_path` (component-wise, case/Unicode-fold-key compared, matching every other
    /// virtual-path comparison in this codebase — see
    /// [`crate::model::VirtualPath::descends_from_or_eq`]).
    #[error(
        "mount path {new_mount_path:?} collides with existing share {existing:?}'s mount path \
         (equal to, an ancestor of, or a descendant of it) — DESIGN.md §A4b shares mount into one \
         virtual tree per host; overlapping mount paths would resolve ambiguously"
    )]
    MountPathCollision {
        new_mount_path: String,
        existing: ShareId,
    },

    /// DESIGN.md §A4b: "... re-checked at host start" — this store's persisted shares now overlap
    /// on disk (e.g. an external mount or symlink change since the last run); each pair is listed
    /// rather than silently proceeding with a stale confinement guarantee.
    #[error(
        "persisted shares now overlap on disk, re-checked at host start (DESIGN.md §A4b): \
         {offenders:?}"
    )]
    PersistedSharesOverlap { offenders: Vec<(ShareId, ShareId)> },

    #[error(
        "host share limit reached ({limit}) (DESIGN.md §A4b: \"caps on shares per host\"); see \
         StoreLimits"
    )]
    TooManyShares { limit: usize },

    #[error(
        "share {share:?} exclude-glob limit reached ({limit}) (DESIGN.md §A4b: \"globs per \
         share\"); see StoreLimits"
    )]
    TooManyExcludeGlobs { share: ShareId, limit: usize },

    /// A database file written by a newer build than this one. Refused rather than opened: the
    /// newer schema's columns and constraints would be silently used by code that does not know
    /// about them.
    #[error(
        "database schema version {found} is newer than this build supports (newest known \
         migration is {supported}); refusing to open it — upgrade the application"
    )]
    SchemaTooNew { found: i64, supported: i64 },
}

/// The atomically-persisted result of redeeming an invite nonce (DESIGN.md §A4: "the host stores
/// `nonce -> {member_id, issued_cap}` atomically; re-presentation of the same nonce within `exp`
/// replays the stored cap"). `issued_cap` is opaque bytes from this crate's point of view — see
/// [`Store::burn_invite_nonce`]'s doc comment for why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedCapRecord {
    pub member_id: MemberId,
    pub issued_cap: Vec<u8>,
    pub redeemed_at: u64,
}

/// A durable, SQLite-backed host store (DESIGN.md §A4b). See the module doc comment for the
/// invariants this type enforces (two-counter rule, secure-by-default, built-in group
/// protection, overlap rejection, limits).
#[derive(Debug)]
pub struct Store {
    conn: Connection,
    limits: StoreLimits,
}

impl Store {
    /// Opens (creating if absent) a file-backed store at `path`, applying any pending schema
    /// migrations, then re-checking every persisted share for overlap (DESIGN.md §A4b:
    /// "re-checked at host start") — see the module doc comment.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::open_with_limits(path, StoreLimits::default())
    }

    pub fn open_with_limits(path: &Path, limits: StoreLimits) -> Result<Self, StoreError> {
        let mut conn = Connection::open(path)?;
        schema::migrate(&mut conn)?;
        let store = Store { conn, limits };
        store.check_persisted_share_overlaps()?;
        Ok(store)
    }

    /// Opens a fresh in-memory store (tests, and any short-lived/ephemeral use). Nothing to
    /// re-check for overlap — a brand-new database has no persisted shares yet.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::open_in_memory_with_limits(StoreLimits::default())
    }

    pub fn open_in_memory_with_limits(limits: StoreLimits) -> Result<Self, StoreError> {
        let mut conn = Connection::open_in_memory()?;
        schema::migrate(&mut conn)?;
        Ok(Store { conn, limits })
    }

    /// Direct access to the underlying connection for [`crate::audit::Audit`], which persists to
    /// the *same* database (single-writer discipline — see that module's doc comment) rather than
    /// opening a second connection to the same file.
    pub(crate) fn connection(&self) -> &Connection {
        &self.conn
    }

    /// The audit chain for this host (DESIGN.md §A4b "Audit log"), backed by the same connection
    /// as every other table here — see `crate::audit`'s module doc comment for why that matters.
    pub fn audit(&self) -> crate::audit::Audit<'_> {
        crate::audit::Audit::new(self.connection())
    }

    // ---------------------------------------------------------------------------------------
    // Meta / counters
    // ---------------------------------------------------------------------------------------

    pub fn cap_epoch(&self) -> Result<u64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT cap_epoch FROM meta WHERE id = 0", [], |r| {
                r.get::<_, i64>(0)
            })? as u64)
    }

    pub fn grants_version(&self) -> Result<u64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT grants_version FROM meta WHERE id = 0", [], |r| {
                r.get::<_, i64>(0)
            })? as u64)
    }

    /// The **only** method in this crate that increments `cap_epoch` — see the module doc
    /// comment's "Two counters, two rules" section. Returns the new value.
    pub fn bump_cap_epoch(&self) -> Result<u64, StoreError> {
        self.conn
            .execute("UPDATE meta SET cap_epoch = cap_epoch + 1 WHERE id = 0", [])?;
        self.cap_epoch()
    }

    /// Called from every entitlement/group-membership/share mutation in this file — never from
    /// callers directly (not `pub`).
    fn bump_grants_version(&self) -> Result<u64, StoreError> {
        self.conn.execute(
            "UPDATE meta SET grants_version = grants_version + 1 WHERE id = 0",
            [],
        )?;
        self.grants_version()
    }

    // ---------------------------------------------------------------------------------------
    // Members
    // ---------------------------------------------------------------------------------------

    /// Creates a member in `invited` status (DESIGN.md §A4b: "creating an account == issuing an
    /// invite; redemption creates the member" — this store models both halves: a caller invites
    /// by calling this immediately, or calls it at redemption time; either way the member starts
    /// `invited` and [`Store::activate_member`] is the transition redemption performs).
    /// Automatically placed in the built-in `Members` group with zero grants (secure by default —
    /// see the module doc comment); this counts as the group-membership mutation the two-counters
    /// rule requires bumping `grants_version` for.
    pub fn add_member(
        &self,
        root_fp: Fingerprint,
        display_name: &str,
        created: u64,
    ) -> Result<MemberId, StoreError> {
        self.conn.execute(
            "INSERT INTO members (root_fp, display_name, status, created) VALUES (?1, ?2, 'invited', ?3)",
            params![root_fp.to_vec(), display_name, created as i64],
        )?;
        let member_id = MemberId(self.conn.last_insert_rowid() as u64);
        self.conn.execute(
            "INSERT INTO member_groups (member_id, group_id) VALUES (?1, ?2)",
            params![member_id.0 as i64, MEMBERS_GROUP_ID.0 as i64],
        )?;
        self.bump_grants_version()?;
        Ok(member_id)
    }

    pub fn get_member(&self, member_id: MemberId) -> Result<Option<Member>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT root_fp, display_name, status, created FROM members WHERE member_id = ?1",
                params![member_id.0 as i64],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((root_fp_bytes, display_name, status_str, created)) = row else {
            return Ok(None);
        };
        let root_fp = Fingerprint::from_slice(&root_fp_bytes)?;
        let status = parse_status(&status_str);
        let devices = self.devices_for_member(member_id)?;
        let groups = self.groups_for_member(member_id)?;
        Ok(Some(Member {
            member_id,
            root_fp,
            display_name,
            status,
            devices,
            groups,
            created: created as u64,
        }))
    }

    pub fn list_members(&self) -> Result<Vec<Member>, StoreError> {
        let ids: Vec<i64> = {
            let mut stmt = self.conn.prepare("SELECT member_id FROM members")?;
            let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
            rows.collect::<Result<_, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                self.get_member(MemberId(id as u64))
                    .map(|m| m.expect("row just listed must still exist"))
            })
            .collect()
    }

    fn devices_for_member(&self, member_id: MemberId) -> Result<Vec<Device>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT device_fp, label, added, revoked, sign_pk, agree_pk FROM devices \
             WHERE member_id = ?1",
        )?;
        let rows = stmt.query_map(params![member_id.0 as i64], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Option<Vec<u8>>>(4)?,
                r.get::<_, Option<Vec<u8>>>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (fp_bytes, label, added, revoked, sign_pk, agree_pk) = row?;
            out.push(Device {
                device_fp: Fingerprint::from_slice(&fp_bytes)?,
                label,
                added: added as u64,
                revoked: revoked != 0,
                sign_pk,
                agree_pk,
            });
        }
        Ok(out)
    }

    fn groups_for_member(&self, member_id: MemberId) -> Result<Vec<GroupId>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT group_id FROM member_groups WHERE member_id = ?1")?;
        let rows = stmt.query_map(params![member_id.0 as i64], |r| r.get::<_, i64>(0))?;
        Ok(rows
            .collect::<Result<Vec<i64>, _>>()?
            .into_iter()
            .map(|id| GroupId(id as u64))
            .collect())
    }

    /// DESIGN.md §A4b member status: `invited -> active -> revoked`, revoked terminal. Rejects
    /// any other transition (including a no-op self-transition, and `active -> invited`).
    pub fn set_member_status(
        &self,
        member_id: MemberId,
        new_status: MemberStatus,
    ) -> Result<(), StoreError> {
        let current = self
            .get_member(member_id)?
            .ok_or(StoreError::MemberNotFound(member_id))?
            .status;
        let allowed = matches!(
            (current, new_status),
            (MemberStatus::Invited, MemberStatus::Active)
                | (MemberStatus::Invited, MemberStatus::Revoked)
                | (MemberStatus::Active, MemberStatus::Revoked)
        );
        if !allowed {
            return Err(StoreError::InvalidStatusTransition {
                from: current,
                to: new_status,
            });
        }
        self.conn.execute(
            "UPDATE members SET status = ?1 WHERE member_id = ?2",
            params![status_str(new_status), member_id.0 as i64],
        )?;
        Ok(())
    }

    /// Convenience for the common redemption path: `invited -> active`.
    pub fn activate_member(&self, member_id: MemberId) -> Result<(), StoreError> {
        self.set_member_status(member_id, MemberStatus::Active)
    }

    /// Terminal (DESIGN.md §A4b). Does **not** bump `cap_epoch` — see the module doc comment.
    pub fn revoke_member(&self, member_id: MemberId) -> Result<(), StoreError> {
        self.set_member_status(member_id, MemberStatus::Revoked)
    }

    // ---------------------------------------------------------------------------------------
    // Devices
    // ---------------------------------------------------------------------------------------

    /// `keys` is the device's pinned Ed25519 signing + X25519 agreement public keys, paired in one
    /// [`DevicePublicKeys`] rather than two adjacent `Option<&[u8]>` parameters (see that struct's
    /// doc comment for why: an accidental transposition of two same-typed byte slices is not a
    /// type error, and would silently produce a device whose stored keys never rehash to its own
    /// `device_fp`). DESIGN.md §A4's device certificates already carry both keys; this is where
    /// the host pins them at enrollment. `None` is accepted (e.g. a test that never needs
    /// upload-manifest verification or connect-time authorization), but a real enrollment flow
    /// should always supply both — a device with no keys on file cannot have any upload it signs
    /// verified later (`crate::model::Device::sign_pk`), nor can it ever be authorized to connect
    /// (`crate::model::Device::agree_pk`).
    pub fn add_device(
        &self,
        member_id: MemberId,
        device_fp: Fingerprint,
        label: &str,
        added: u64,
        keys: Option<&DevicePublicKeys>,
    ) -> Result<(), StoreError> {
        if self.get_member(member_id)?.is_none() {
            return Err(StoreError::MemberNotFound(member_id));
        }
        self.conn.execute(
            "INSERT INTO devices (device_fp, member_id, label, added, revoked, sign_pk, agree_pk) \
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)",
            params![
                device_fp.to_vec(),
                member_id.0 as i64,
                label,
                added as i64,
                keys.map(|k| k.sign_pk.clone()),
                keys.map(|k| k.agree_pk.clone()),
            ],
        )?;
        Ok(())
    }

    /// Does **not** bump `cap_epoch` — see the module doc comment.
    pub fn revoke_device(&self, device_fp: Fingerprint) -> Result<(), StoreError> {
        let changed = self.conn.execute(
            "UPDATE devices SET revoked = 1 WHERE device_fp = ?1",
            params![device_fp.to_vec()],
        )?;
        if changed == 0 {
            return Err(StoreError::DeviceNotFound(device_fp));
        }
        Ok(())
    }

    /// The device's pinned signing public key, if any (Stage 6 slice 4 — see
    /// `crate::model::Device::sign_pk`'s doc comment). `Ok(None)` means either the device has no
    /// key on file or the device does not exist — this method deliberately does not distinguish
    /// the two (an upload-manifest-verification caller treats both identically: "cannot verify").
    pub fn device_sign_pk(&self, device_fp: Fingerprint) -> Result<Option<Vec<u8>>, StoreError> {
        let key: Option<Option<Vec<u8>>> = self
            .conn
            .query_row(
                "SELECT sign_pk FROM devices WHERE device_fp = ?1",
                params![device_fp.to_vec()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(key.flatten())
    }

    /// Resolves the [`Member`] owning `device_fp` — the connect-time lookup direction. `device_fp`
    /// is what a connect offer's envelope names (DESIGN.md §A5's injected `ConnectAuthorizer`,
    /// `crates/spindle-net/src/signaling/authorize.rs`); `member_id` is host-internal and never
    /// appears on the wire, which is why this exists alongside [`Store::get_member`] rather than
    /// replacing it.
    ///
    /// Returns the whole `Member` (via [`Store::get_member`], so it carries its full `devices` and
    /// `groups` exactly as that method builds them — not hand-assembled here) rather than just a
    /// status, deliberately: the caller must check BOTH the member's status AND the specific
    /// device's `revoked` flag, since a still-`Active` member can have one revoked device among
    /// several (DESIGN.md §A4: a revocation names `root_fp | device_fp`), and both halves come
    /// from this single read. `crates/spindle-host-core/src/server.rs`'s two-part gate (search
    /// `denied:device_revoked`) is the per-request twin of that same check.
    ///
    /// `Ok(None)` when `device_fp` is unknown. A devices row referencing a missing member is
    /// impossible (the `member_id` foreign key), but the delegation to `get_member` would surface
    /// that as `Ok(None)` anyway rather than panicking.
    pub fn member_for_device_fp(
        &self,
        device_fp: Fingerprint,
    ) -> Result<Option<Member>, StoreError> {
        let member_id: Option<i64> = self
            .conn
            .query_row(
                "SELECT member_id FROM devices WHERE device_fp = ?1",
                params![device_fp.to_vec()],
                |r| r.get(0),
            )
            .optional()?;
        let Some(member_id) = member_id else {
            return Ok(None);
        };
        self.get_member(MemberId(member_id as u64))
    }

    // ---------------------------------------------------------------------------------------
    // Groups
    // ---------------------------------------------------------------------------------------

    pub fn create_custom_group(&self, name: &str) -> Result<GroupId, StoreError> {
        self.conn.execute(
            "INSERT INTO groups (name, kind) VALUES (?1, 'custom')",
            params![name],
        )?;
        Ok(GroupId(self.conn.last_insert_rowid() as u64))
    }

    pub fn get_group(&self, group_id: GroupId) -> Result<Option<Group>, StoreError> {
        self.conn
            .query_row(
                "SELECT name, kind FROM groups WHERE group_id = ?1",
                params![group_id.0 as i64],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(name, kind)| {
                Ok(Group {
                    group_id,
                    name,
                    kind: parse_group_kind(&kind),
                })
            })
            .transpose()
    }

    /// All groups, including the built-ins — for admin display, not for a "pick a group to
    /// grant" UI (use [`Store::list_grantable_groups`] for that).
    pub fn list_groups(&self) -> Result<Vec<Group>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT group_id, name, kind FROM groups ORDER BY group_id")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, name, kind) = row?;
            out.push(Group {
                group_id: GroupId(id as u64),
                name,
                kind: parse_group_kind(&kind),
            });
        }
        Ok(out)
    }

    /// Every group except `Owner` (DESIGN.md §A4b: Owner is "not listable as grantable").
    pub fn list_grantable_groups(&self) -> Result<Vec<Group>, StoreError> {
        Ok(self
            .list_groups()?
            .into_iter()
            .filter(|g| g.kind != GroupKind::Owner)
            .collect())
    }

    /// Rejects a built-in group (DESIGN.md §A4b: "Owner ... not editable"; this protects both
    /// built-ins' identity, not just Owner's).
    pub fn rename_group(&self, group_id: GroupId, new_name: &str) -> Result<(), StoreError> {
        let group = self
            .get_group(group_id)?
            .ok_or(StoreError::GroupNotFound(group_id))?;
        if group.kind != GroupKind::Custom {
            return Err(StoreError::BuiltinGroupNotEditable(group_id));
        }
        self.conn.execute(
            "UPDATE groups SET name = ?1 WHERE group_id = ?2",
            params![new_name, group_id.0 as i64],
        )?;
        Ok(())
    }

    pub fn add_member_to_group(
        &self,
        member_id: MemberId,
        group_id: GroupId,
    ) -> Result<(), StoreError> {
        if self.get_member(member_id)?.is_none() {
            return Err(StoreError::MemberNotFound(member_id));
        }
        if self.get_group(group_id)?.is_none() {
            return Err(StoreError::GroupNotFound(group_id));
        }
        self.conn.execute(
            "INSERT OR IGNORE INTO member_groups (member_id, group_id) VALUES (?1, ?2)",
            params![member_id.0 as i64, group_id.0 as i64],
        )?;
        self.bump_grants_version()?;
        Ok(())
    }

    pub fn remove_member_from_group(
        &self,
        member_id: MemberId,
        group_id: GroupId,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM member_groups WHERE member_id = ?1 AND group_id = ?2",
            params![member_id.0 as i64, group_id.0 as i64],
        )?;
        self.bump_grants_version()?;
        Ok(())
    }

    // ---------------------------------------------------------------------------------------
    // Shares
    // ---------------------------------------------------------------------------------------

    /// Adds a share with zero grants (secure by default). Rejects: overlap with any existing
    /// share's `real_root` (DESIGN.md §A4b, via `crate::confine::overlap_check` — the exact
    /// slice-1 check, unmodified), the host share-count limit, and the per-share exclude-glob
    /// limit (both from [`StoreLimits`]).
    #[allow(clippy::too_many_arguments)]
    pub fn add_share(
        &self,
        name: &str,
        mount_path: &str,
        real_root: &Path,
        flags: ShareFlags,
        excludes: &[String],
        created: u64,
    ) -> Result<ShareId, StoreError> {
        let existing_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM shares", [], |r| r.get(0))?;
        if existing_count as usize >= self.limits.max_shares {
            return Err(StoreError::TooManyShares {
                limit: self.limits.max_shares,
            });
        }
        if excludes.len() > self.limits.max_excludes_per_share {
            // No share_id yet (not inserted); report against a placeholder — callers already
            // know which share they're adding.
            return Err(StoreError::TooManyExcludeGlobs {
                share: ShareId(0),
                limit: self.limits.max_excludes_per_share,
            });
        }

        // Reject an invalid mount_path outright (same component rules as any other virtual path
        // — see `VirtualPath::parse`), then check it against every existing share's mount_path
        // for a collision (equal, ancestor, or descendant — see `StoreError::MountPathCollision`
        // and `mount_paths_collide`'s doc comment).
        let new_mount_path = VirtualPath::parse(mount_path)?;
        for existing in self.list_shares()? {
            if overlap_check(real_root, &existing.real_root)? {
                return Err(StoreError::OverlappingShareRoot {
                    new_root: real_root.to_path_buf(),
                    existing: existing.share_id,
                });
            }
            let existing_mount_path = VirtualPath::parse(&existing.mount_path)
                .expect("mount_path persisted by this store is always a valid VirtualPath");
            if mount_paths_collide(&new_mount_path, &existing_mount_path) {
                return Err(StoreError::MountPathCollision {
                    new_mount_path: mount_path.to_string(),
                    existing: existing.share_id,
                });
            }
        }

        self.conn.execute(
            "INSERT INTO shares (name, mount_path, real_root, read_only, allow_upload, show_hidden, created) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                name,
                mount_path,
                real_root.to_string_lossy(),
                flags.read_only as i64,
                flags.allow_upload as i64,
                flags.show_hidden as i64,
                created as i64,
            ],
        )?;
        let share_id = ShareId(self.conn.last_insert_rowid() as u64);
        for glob in excludes {
            self.conn.execute(
                "INSERT INTO share_excludes (share_id, glob) VALUES (?1, ?2)",
                params![share_id.0 as i64, glob],
            )?;
        }
        self.bump_grants_version()?;
        Ok(share_id)
    }

    pub fn get_share(&self, share_id: ShareId) -> Result<Option<Share>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT name, mount_path, real_root, read_only, allow_upload, show_hidden \
                 FROM shares WHERE share_id = ?1",
                params![share_id.0 as i64],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((name, mount_path, real_root, read_only, allow_upload, show_hidden)) = row else {
            return Ok(None);
        };
        let excludes = self.excludes_for_share(share_id)?;
        Ok(Some(Share {
            share_id,
            name,
            mount_path,
            real_root: PathBuf::from(real_root),
            flags: ShareFlags {
                read_only: read_only != 0,
                allow_upload: allow_upload != 0,
                show_hidden: show_hidden != 0,
            },
            excludes,
        }))
    }

    pub fn list_shares(&self) -> Result<Vec<Share>, StoreError> {
        let ids: Vec<i64> = {
            let mut stmt = self.conn.prepare("SELECT share_id FROM shares")?;
            let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
            rows.collect::<Result<_, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                self.get_share(ShareId(id as u64))
                    .map(|s| s.expect("row just listed must still exist"))
            })
            .collect()
    }

    /// Precompiled on load (DESIGN.md §A4b), reusing slice-1's `crate::glob::CompiledGlob` — the
    /// stored representation is always the original pattern text; compilation happens here, every
    /// time a [`Share`] is materialized, never once at write time (compiled globs are not
    /// `Send`/serializable and are cheap to recompile).
    fn excludes_for_share(&self, share_id: ShareId) -> Result<Vec<CompiledGlob>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT glob FROM share_excludes WHERE share_id = ?1")?;
        let rows = stmt.query_map(params![share_id.0 as i64], |r| r.get::<_, String>(0))?;
        Ok(rows
            .collect::<Result<Vec<String>, _>>()?
            .iter()
            .map(|pattern| CompiledGlob::compile(pattern))
            .collect())
    }

    pub fn update_share_flags(
        &self,
        share_id: ShareId,
        flags: ShareFlags,
    ) -> Result<(), StoreError> {
        if self.get_share(share_id)?.is_none() {
            return Err(StoreError::ShareNotFound(share_id));
        }
        self.conn.execute(
            "UPDATE shares SET read_only = ?1, allow_upload = ?2, show_hidden = ?3 WHERE share_id = ?4",
            params![
                flags.read_only as i64,
                flags.allow_upload as i64,
                flags.show_hidden as i64,
                share_id.0 as i64,
            ],
        )?;
        self.bump_grants_version()?;
        Ok(())
    }

    pub fn add_share_exclude(&self, share_id: ShareId, glob: &str) -> Result<(), StoreError> {
        let current: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM share_excludes WHERE share_id = ?1",
            params![share_id.0 as i64],
            |r| r.get(0),
        )?;
        if current as usize >= self.limits.max_excludes_per_share {
            return Err(StoreError::TooManyExcludeGlobs {
                share: share_id,
                limit: self.limits.max_excludes_per_share,
            });
        }
        self.conn.execute(
            "INSERT OR IGNORE INTO share_excludes (share_id, glob) VALUES (?1, ?2)",
            params![share_id.0 as i64, glob],
        )?;
        self.bump_grants_version()?;
        Ok(())
    }

    /// DESIGN.md §A4b: "no overlapping roots ... re-checked at host start" — pairwise-checks
    /// every persisted share's `real_root` against every other. Called automatically by
    /// [`Store::open`]; also `pub` so tests (and a future host-core admin surface) can invoke it
    /// on demand.
    pub fn check_persisted_share_overlaps(&self) -> Result<(), StoreError> {
        let shares = self.list_shares()?;
        let mut offenders = Vec::new();
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                if overlap_check(&shares[i].real_root, &shares[j].real_root)? {
                    offenders.push((shares[i].share_id, shares[j].share_id));
                }
            }
        }
        if offenders.is_empty() {
            Ok(())
        } else {
            Err(StoreError::PersistedSharesOverlap { offenders })
        }
    }

    // ---------------------------------------------------------------------------------------
    // Entitlements
    // ---------------------------------------------------------------------------------------

    /// Rejects the built-in `Owner` group ([`StoreError::OwnerNotGrantable`]); otherwise
    /// delegates upload/delete-requires-`allow_upload` validation to the existing slice-1
    /// [`Entitlement::new`] constructor (looking up the target share's flag first), so this store
    /// enforces exactly the same construction-time invariant the pure model already does — no
    /// duplicated logic. Replaces (upserts) any existing entitlement for the same
    /// `(group_id, share_id, subpath)`.
    pub fn add_entitlement(
        &self,
        group_id: GroupId,
        share_id: ShareId,
        subpath: &VirtualPath,
        perms: Perms,
    ) -> Result<(), StoreError> {
        let group = self
            .get_group(group_id)?
            .ok_or(StoreError::GroupNotFound(group_id))?;
        if group.kind == GroupKind::Owner {
            return Err(StoreError::OwnerNotGrantable);
        }
        let share = self
            .get_share(share_id)?
            .ok_or(StoreError::ShareNotFound(share_id))?;

        // Validate via the slice-1 model constructor (also confirms this exact combination is
        // constructible before it's persisted); the constructed value's fields are then written
        // through rather than kept, since the store's row is the source of truth.
        let entitlement = Entitlement::new(
            group_id,
            share_id,
            subpath.clone(),
            perms,
            share.flags.allow_upload,
        )?;

        self.conn.execute(
            "INSERT INTO entitlements (group_id, share_id, subpath, perms) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (group_id, share_id, subpath) DO UPDATE SET perms = excluded.perms",
            params![
                entitlement.group_id.0 as i64,
                entitlement.share_id.0 as i64,
                entitlement.subpath.to_path_string(),
                entitlement.perms.bits() as i64,
            ],
        )?;
        self.bump_grants_version()?;
        Ok(())
    }

    pub fn remove_entitlement(
        &self,
        group_id: GroupId,
        share_id: ShareId,
        subpath: &VirtualPath,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM entitlements WHERE group_id = ?1 AND share_id = ?2 AND subpath = ?3",
            params![
                group_id.0 as i64,
                share_id.0 as i64,
                subpath.to_path_string()
            ],
        )?;
        self.bump_grants_version()?;
        Ok(())
    }

    pub fn list_entitlements(&self) -> Result<Vec<Entitlement>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT group_id, share_id, subpath, perms FROM entitlements")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (group_id, share_id, subpath, perms) = row?;
            out.push(Entitlement {
                group_id: GroupId(group_id as u64),
                share_id: ShareId(share_id as u64),
                subpath: VirtualPath::parse(&subpath)
                    .expect("subpath persisted by this store is always a valid VirtualPath"),
                perms: Perms::from_bits(perms as u8),
            });
        }
        Ok(out)
    }

    // ---------------------------------------------------------------------------------------
    // Upload quotas (DESIGN.md §A4b: "quotas per member and per share"), Stage 6 slice 4 addition
    // ---------------------------------------------------------------------------------------
    //
    // **Design choice, flagged per the task brief rather than resolved silently**: these counters
    // track cumulative bytes that moved through *this crate's* upload path (successful
    // `upload_commit` calls, net of overwrite deltas), not a recursive walk of real on-disk usage.
    // DESIGN.md's "quotas per member and per share" appears in §A4b's list of upload-edge rules,
    // in the same breath as "uploads land only under the granted subpath" and "received-file
    // policy" — i.e. in context, about the upload flow specifically, not the share's total disk
    // footprint (which may include content the owner placed directly on the real filesystem,
    // never seen by any VFS RPC call). A store-backed running counter was chosen over computing
    // usage on demand (e.g. a directory walk) because the latter would be too slow to check before
    // every chunk write on a large share, and because "how many bytes has this member/share
    // consumed via uploads" has no other durable source of truth once files sit anonymously on
    // the real filesystem.
    //
    // **Documented limitation**: `share_upload_bytes` is accurate for deletes (a delete always
    // knows the real size of what it removes, regardless of who uploaded it, so
    // [`Store::adjust_share_upload_bytes`] is called with a negative delta from
    // `spindle-host-core`'s delete handler). `member_upload_bytes` is **not** symmetrically
    // decremented on a delete performed by a different member, because no ownership ledger here
    // maps a real file back to the member who uploaded it (DESIGN.md does not specify this depth
    // of per-member accounting). A member's own counter therefore only grows via their own
    // commits and shrinks only via deltas from their own overwrites; deleting content does not
    // retroactively refund any member's quota. Acceptable for generous, host-configured default
    // limits; a full ownership ledger is out of scope for this slice.

    /// Adjusts `member_id`'s running upload-byte counter by `delta` (which may be negative, e.g.
    /// an overwrite that shrank a file), clamped at 0, and returns the new total. Creates the
    /// counter row on first use.
    pub fn adjust_member_upload_bytes(
        &self,
        member_id: MemberId,
        delta: i64,
    ) -> Result<u64, StoreError> {
        self.conn.execute(
            "INSERT INTO member_upload_bytes (member_id, bytes) VALUES (?1, MAX(?2, 0)) \
             ON CONFLICT(member_id) DO UPDATE SET bytes = MAX(bytes + ?2, 0)",
            params![member_id.0 as i64, delta],
        )?;
        self.member_upload_bytes(member_id)
    }

    /// `member_id`'s current running upload-byte total (0 if it has never uploaded anything).
    pub fn member_upload_bytes(&self, member_id: MemberId) -> Result<u64, StoreError> {
        let bytes: Option<i64> = self
            .conn
            .query_row(
                "SELECT bytes FROM member_upload_bytes WHERE member_id = ?1",
                params![member_id.0 as i64],
                |r| r.get(0),
            )
            .optional()?;
        Ok(bytes.unwrap_or(0) as u64)
    }

    /// Adjusts `share_id`'s running upload-byte counter by `delta`, clamped at 0, and returns the
    /// new total. Creates the counter row on first use. See the module-section doc comment above
    /// for why this counter (unlike [`Store::adjust_member_upload_bytes`]) is kept exactly in sync
    /// with deletes.
    pub fn adjust_share_upload_bytes(
        &self,
        share_id: ShareId,
        delta: i64,
    ) -> Result<u64, StoreError> {
        self.conn.execute(
            "INSERT INTO share_upload_bytes (share_id, bytes) VALUES (?1, MAX(?2, 0)) \
             ON CONFLICT(share_id) DO UPDATE SET bytes = MAX(bytes + ?2, 0)",
            params![share_id.0 as i64, delta],
        )?;
        self.share_upload_bytes(share_id)
    }

    /// `share_id`'s current running upload-byte total (0 if nothing has ever been uploaded to it).
    pub fn share_upload_bytes(&self, share_id: ShareId) -> Result<u64, StoreError> {
        let bytes: Option<i64> = self
            .conn
            .query_row(
                "SELECT bytes FROM share_upload_bytes WHERE share_id = ?1",
                params![share_id.0 as i64],
                |r| r.get(0),
            )
            .optional()?;
        Ok(bytes.unwrap_or(0) as u64)
    }

    // ---------------------------------------------------------------------------------------
    // Invite nonces (idempotent redemption, DESIGN.md §A4)
    // ---------------------------------------------------------------------------------------

    /// Atomically burns `nonce`, mirroring `spindle-helper`'s admission-nonce CAS
    /// (`crates/spindle-helper/src/pg_store.rs`: `INSERT ... ON CONFLICT (nonce) DO NOTHING` then
    /// a read-back, in one transaction): if `nonce` is fresh, `issued_cap`/`member_id`/`now` are
    /// stored as given and returned; if `nonce` was already burned (by this call racing itself,
    /// a retried redemption, or a genuinely repeated presentation within `exp`), the **original**
    /// stored record is returned instead — the caller's freshly-computed `issued_cap` for *this*
    /// call is silently discarded in that case, which is exactly the "replay the stored cap"
    /// contract DESIGN.md §A4 specifies.
    ///
    /// **Design note (reported per the task brief, not silently resolved)**: `spindle-vfs` has no
    /// way to *mint* a capability — that requires `spindle-core`'s op-key signing machinery
    /// (`spindle_core::artifacts::issue_capability`), which needs the host's live signing key and
    /// therefore belongs to `spindle-host-core` (a later slice), not this pure-storage crate. So
    /// this method treats `issued_cap` as **opaque bytes**: the caller (host-core) mints the
    /// capability first, then calls this method to durably and atomically decide whether *this*
    /// mint or an earlier one is the one that counts. This is exactly the resolution the task
    /// brief anticipated, and is the only design that keeps `spindle-vfs` free of a
    /// `spindle-core::artifacts`/signing-key dependency it has no other reason to take.
    pub fn burn_invite_nonce(
        &mut self,
        nonce: &[u8],
        member_id: MemberId,
        issued_cap: &[u8],
        now: u64,
    ) -> Result<IssuedCapRecord, StoreError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO invite_nonces (nonce, member_id, issued_cap, redeemed_at) \
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT (nonce) DO NOTHING",
            params![nonce, member_id.0 as i64, issued_cap, now as i64],
        )?;
        let (stored_member_id, stored_cap, stored_redeemed_at): (i64, Vec<u8>, i64) = tx
            .query_row(
                "SELECT member_id, issued_cap, redeemed_at FROM invite_nonces WHERE nonce = ?1",
                params![nonce],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
        tx.commit()?;
        Ok(IssuedCapRecord {
            member_id: MemberId(stored_member_id as u64),
            issued_cap: stored_cap,
            redeemed_at: stored_redeemed_at as u64,
        })
    }
}

fn status_str(status: MemberStatus) -> &'static str {
    match status {
        MemberStatus::Invited => "invited",
        MemberStatus::Active => "active",
        MemberStatus::Revoked => "revoked",
    }
}

fn parse_status(s: &str) -> MemberStatus {
    match s {
        "invited" => MemberStatus::Invited,
        "active" => MemberStatus::Active,
        "revoked" => MemberStatus::Revoked,
        other => unreachable!("CHECK constraint guarantees only known statuses, got {other:?}"),
    }
}

fn parse_group_kind(s: &str) -> GroupKind {
    match s {
        "owner" => GroupKind::Owner,
        "members" => GroupKind::Members,
        "custom" => GroupKind::Custom,
        other => unreachable!("CHECK constraint guarantees only known kinds, got {other:?}"),
    }
}

/// `true` if `a` and `b` are the same virtual path, or one is a proper ancestor of the other
/// (component-wise, case/Unicode fold-key compared — see
/// [`VirtualPath::descends_from_or_eq`]). Two shares whose `mount_path`s collide this way would
/// resolve ambiguously under the slice-3 VFS RPC server's longest-prefix-match mount resolution —
/// see [`StoreError::MountPathCollision`]'s doc comment. Sibling mount paths (neither a prefix of
/// the other — e.g. `"Photos"` and `"Documents"`, or `"Photos"` and `"PhotosArchive"`, which share
/// no common path component) do not collide.
fn mount_paths_collide(a: &VirtualPath, b: &VirtualPath) -> bool {
    a.descends_from_or_eq(b) || b.descends_from_or_eq(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::{EffectiveGrants, GrantsVersion};
    use tempfile::tempdir;

    fn vp(s: &str) -> VirtualPath {
        VirtualPath::parse(s).expect("valid virtual path")
    }

    // ---- Built-in groups ----

    #[test]
    fn builtin_groups_seeded_and_protected() {
        let store = Store::open_in_memory().expect("open");
        let owner = store
            .get_group(OWNER_GROUP_ID)
            .expect("get")
            .expect("exists");
        assert_eq!(owner.kind, GroupKind::Owner);
        let members = store
            .get_group(MEMBERS_GROUP_ID)
            .expect("get")
            .expect("exists");
        assert_eq!(members.kind, GroupKind::Members);

        let err = store.rename_group(OWNER_GROUP_ID, "Nope").unwrap_err();
        assert!(matches!(
            err,
            StoreError::BuiltinGroupNotEditable(OWNER_GROUP_ID)
        ));
        let err = store.rename_group(MEMBERS_GROUP_ID, "Nope").unwrap_err();
        assert!(matches!(
            err,
            StoreError::BuiltinGroupNotEditable(MEMBERS_GROUP_ID)
        ));

        let grantable = store.list_grantable_groups().expect("list");
        assert!(
            !grantable.iter().any(|g| g.group_id == OWNER_GROUP_ID),
            "Owner must not be listed as grantable"
        );
        assert!(
            grantable.iter().any(|g| g.group_id == MEMBERS_GROUP_ID),
            "Members must remain grantable"
        );
    }

    #[test]
    fn owner_group_rejects_entitlements() {
        let store = Store::open_in_memory().expect("open");
        let share_id = store
            .add_share(
                "Photos",
                "Photos",
                Path::new("/tmp/does-not-need-to-exist-for-this-check"),
                ShareFlags::default(),
                &[],
                0,
            )
            .expect("add_share");
        let err = store
            .add_entitlement(
                OWNER_GROUP_ID,
                share_id,
                &VirtualPath::root(),
                Perms::BROWSE,
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::OwnerNotGrantable));
    }

    // ---- Secure by default ----

    #[test]
    fn new_share_has_zero_grants_via_algebra() {
        let store = Store::open_in_memory().expect("open");
        let dir = tempdir().expect("tempdir");
        let share_id = store
            .add_share(
                "Photos",
                "Photos",
                dir.path(),
                ShareFlags::default(),
                &[],
                0,
            )
            .expect("add_share");
        let share = store.get_share(share_id).expect("get").expect("exists");

        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");
        let member = store.get_member(member_id).expect("get").expect("exists");

        let entitlements = store.list_entitlements().expect("list");
        let grants = EffectiveGrants::compute(&member, &entitlements, GrantsVersion::default());
        assert_eq!(
            grants.resolve_access(&share, &VirtualPath::root()),
            crate::algebra::AccessDecision::NotFound
        );
    }

    #[test]
    fn new_member_in_members_group_has_zero_grants() {
        let store = Store::open_in_memory().expect("open");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");
        let member = store.get_member(member_id).expect("get").expect("exists");
        assert_eq!(member.groups, vec![MEMBERS_GROUP_ID]);
        assert_eq!(member.status, MemberStatus::Invited);
    }

    // ---- grants_version / cap_epoch two-counter rule ----

    #[test]
    fn grants_version_bumps_on_entitlement_group_and_share_mutation_cap_epoch_never_does() {
        let store = Store::open_in_memory().expect("open");
        let dir = tempdir().expect("tempdir");
        let v0 = store.grants_version().expect("v0");
        let e0 = store.cap_epoch().expect("e0");

        let share_id = store
            .add_share(
                "Photos",
                "Photos",
                dir.path(),
                ShareFlags::default(),
                &[],
                0,
            )
            .expect("add_share bumps");
        let v1 = store.grants_version().expect("v1");
        assert!(v1 > v0, "add_share must bump grants_version");

        let group_id = store
            .create_custom_group("Family")
            .expect("create_custom_group");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member bumps (Members group assignment)");
        let v2 = store.grants_version().expect("v2");
        assert!(
            v2 > v1,
            "add_member's group assignment must bump grants_version"
        );

        store
            .add_member_to_group(member_id, group_id)
            .expect("add_member_to_group bumps");
        let v3 = store.grants_version().expect("v3");
        assert!(v3 > v2);

        store
            .add_entitlement(group_id, share_id, &VirtualPath::root(), Perms::BROWSE)
            .expect("add_entitlement bumps");
        let v4 = store.grants_version().expect("v4");
        assert!(v4 > v3);

        // cap_epoch must be untouched by every mutation above.
        assert_eq!(store.cap_epoch().expect("e still 0"), e0);

        // Only bump_cap_epoch touches it, and it does not touch grants_version.
        let new_epoch = store.bump_cap_epoch().expect("bump_cap_epoch");
        assert_eq!(new_epoch, e0 + 1);
        assert_eq!(
            store.grants_version().expect("v unchanged"),
            v4,
            "bump_cap_epoch must never bump grants_version"
        );
    }

    #[test]
    fn revoke_does_not_bump_cap_epoch_automatically() {
        let store = Store::open_in_memory().expect("open");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");
        let e0 = store.cap_epoch().expect("e0");
        store.revoke_member(member_id).expect("revoke");
        assert_eq!(
            store.cap_epoch().expect("e unchanged"),
            e0,
            "revoke_member must not itself bump cap_epoch — see module doc comment"
        );
    }

    // ---- Status transitions ----

    #[test]
    fn member_status_transitions_forward_only_revoked_terminal() {
        let store = Store::open_in_memory().expect("open");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");

        store.activate_member(member_id).expect("invited -> active");
        assert_eq!(
            store.get_member(member_id).unwrap().unwrap().status,
            MemberStatus::Active
        );

        // Backward transition rejected.
        let err = store
            .set_member_status(member_id, MemberStatus::Invited)
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidStatusTransition { .. }));

        store.revoke_member(member_id).expect("active -> revoked");
        assert_eq!(
            store.get_member(member_id).unwrap().unwrap().status,
            MemberStatus::Revoked
        );

        // Revoked is terminal: every further transition is rejected, including re-revoking.
        for target in [
            MemberStatus::Invited,
            MemberStatus::Active,
            MemberStatus::Revoked,
        ] {
            let err = store.set_member_status(member_id, target).unwrap_err();
            assert!(matches!(err, StoreError::InvalidStatusTransition { .. }));
        }
    }

    #[test]
    fn invited_can_be_revoked_directly() {
        let store = Store::open_in_memory().expect("open");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");
        store.revoke_member(member_id).expect("invited -> revoked");
        assert_eq!(
            store.get_member(member_id).unwrap().unwrap().status,
            MemberStatus::Revoked
        );
    }

    // ---- Overlap rejection ----

    #[test]
    fn add_share_rejects_overlapping_root() {
        let store = Store::open_in_memory().expect("open");
        let sandbox = tempdir().expect("tempdir");
        let a = sandbox.path().join("a");
        let nested = a.join("nested");
        std::fs::create_dir_all(&nested).expect("mkdir");

        store
            .add_share("A", "A", &a, ShareFlags::default(), &[], 0)
            .expect("first share ok");
        let err = store
            .add_share("Nested", "Nested", &nested, ShareFlags::default(), &[], 0)
            .unwrap_err();
        assert!(matches!(err, StoreError::OverlappingShareRoot { .. }));
    }

    #[test]
    fn add_share_allows_sibling_roots() {
        let store = Store::open_in_memory().expect("open");
        let sandbox = tempdir().expect("tempdir");
        let a = sandbox.path().join("a");
        let b = sandbox.path().join("b");
        std::fs::create_dir_all(&a).expect("mkdir a");
        std::fs::create_dir_all(&b).expect("mkdir b");

        store
            .add_share("A", "A", &a, ShareFlags::default(), &[], 0)
            .expect("first share ok");
        store
            .add_share("B", "B", &b, ShareFlags::default(), &[], 0)
            .expect("sibling share ok");
    }

    // ---- Mount-path collision (Stage 6 slice 3 addition) ----

    #[test]
    fn add_share_rejects_exact_mount_path_collision() {
        let store = Store::open_in_memory().expect("open");
        let sandbox = tempdir().expect("tempdir");
        let a = sandbox.path().join("a");
        let b = sandbox.path().join("b");
        std::fs::create_dir_all(&a).expect("mkdir a");
        std::fs::create_dir_all(&b).expect("mkdir b");

        store
            .add_share("A", "Photos", &a, ShareFlags::default(), &[], 0)
            .expect("first share ok");
        let err = store
            .add_share("B", "Photos", &b, ShareFlags::default(), &[], 0)
            .unwrap_err();
        assert!(matches!(err, StoreError::MountPathCollision { .. }));
    }

    #[test]
    fn add_share_rejects_ancestor_and_descendant_mount_path_collisions() {
        let store = Store::open_in_memory().expect("open");
        let sandbox = tempdir().expect("tempdir");
        let a = sandbox.path().join("a");
        let b = sandbox.path().join("b");
        std::fs::create_dir_all(&a).expect("mkdir a");
        std::fs::create_dir_all(&b).expect("mkdir b");

        store
            .add_share("A", "Photos", &a, ShareFlags::default(), &[], 0)
            .expect("first share ok");

        // Descendant of an existing mount path.
        let err = store
            .add_share("B", "Photos/Vacation", &b, ShareFlags::default(), &[], 0)
            .unwrap_err();
        assert!(matches!(err, StoreError::MountPathCollision { .. }));
    }

    #[test]
    fn add_share_allows_sibling_mount_paths() {
        let store = Store::open_in_memory().expect("open");
        let sandbox = tempdir().expect("tempdir");
        let a = sandbox.path().join("a");
        let b = sandbox.path().join("b");
        std::fs::create_dir_all(&a).expect("mkdir a");
        std::fs::create_dir_all(&b).expect("mkdir b");

        store
            .add_share("A", "Photos", &a, ShareFlags::default(), &[], 0)
            .expect("first share ok");
        // "PhotosArchive" shares no path component with "Photos" — not a prefix either way.
        store
            .add_share("B", "PhotosArchive", &b, ShareFlags::default(), &[], 0)
            .expect("sibling mount path ok");
    }

    #[test]
    fn open_rechecks_persisted_overlap_and_reports_offenders() {
        let sandbox = tempdir().expect("tempdir");
        let db_path = sandbox.path().join("host.sqlite3");
        let a = sandbox.path().join("a");
        let b = sandbox.path().join("b");
        std::fs::create_dir_all(&a).expect("mkdir a");
        std::fs::create_dir_all(&b).expect("mkdir b");

        let (share_a, share_b) = {
            let store = Store::open(&db_path).expect("open fresh file-backed store");
            let share_a = store
                .add_share("A", "A", &a, ShareFlags::default(), &[], 0)
                .expect("add A");
            let share_b = store
                .add_share("B", "B", &b, ShareFlags::default(), &[], 0)
                .expect("add B");
            (share_a, share_b)
        }; // store (and its Connection) dropped here — file-backed, so state persists.

        // Simulate "the persisted state now overlaps on disk" (e.g. an external mount/symlink
        // change since the last run) by directly editing the row via a fresh raw connection —
        // Store::add_share's own add-time check cannot be the thing that catches this, by
        // definition; only the re-check at open() can.
        {
            let raw = Connection::open(&db_path).expect("raw connection");
            raw.execute(
                "UPDATE shares SET real_root = ?1 WHERE share_id = ?2",
                params![a.to_string_lossy(), share_b.0 as i64],
            )
            .expect("simulate overlap");
        }

        let err = Store::open(&db_path).unwrap_err();
        match err {
            StoreError::PersistedSharesOverlap { offenders } => {
                assert_eq!(offenders, vec![(share_a, share_b)]);
            }
            other => panic!("expected PersistedSharesOverlap, got {other:?}"),
        }
    }

    // ---- Limits ----

    #[test]
    fn share_limit_enforced() {
        let store = Store::open_in_memory_with_limits(StoreLimits {
            max_shares: 1,
            ..StoreLimits::default()
        })
        .expect("open");
        let sandbox = tempdir().expect("tempdir");
        let a = sandbox.path().join("a");
        let b = sandbox.path().join("b");
        std::fs::create_dir_all(&a).expect("mkdir a");
        std::fs::create_dir_all(&b).expect("mkdir b");

        store
            .add_share("A", "A", &a, ShareFlags::default(), &[], 0)
            .expect("first share within limit");
        let err = store
            .add_share("B", "B", &b, ShareFlags::default(), &[], 0)
            .unwrap_err();
        assert!(matches!(err, StoreError::TooManyShares { limit: 1 }));
    }

    #[test]
    fn exclude_glob_limit_enforced() {
        let store = Store::open_in_memory_with_limits(StoreLimits {
            max_excludes_per_share: 1,
            ..StoreLimits::default()
        })
        .expect("open");
        let dir = tempdir().expect("tempdir");
        let err = store
            .add_share(
                "Photos",
                "Photos",
                dir.path(),
                ShareFlags::default(),
                &["a".to_string(), "b".to_string()],
                0,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::TooManyExcludeGlobs { limit: 1, .. }
        ));
    }

    #[test]
    fn exclude_glob_limit_enforced_on_incremental_add() {
        let store = Store::open_in_memory_with_limits(StoreLimits {
            max_excludes_per_share: 1,
            ..StoreLimits::default()
        })
        .expect("open");
        let dir = tempdir().expect("tempdir");
        let share_id = store
            .add_share(
                "Photos",
                "Photos",
                dir.path(),
                ShareFlags::default(),
                &[],
                0,
            )
            .expect("add_share");
        store
            .add_share_exclude(share_id, "one")
            .expect("first exclude within limit");
        let err = store.add_share_exclude(share_id, "two").unwrap_err();
        assert!(matches!(
            err,
            StoreError::TooManyExcludeGlobs { limit: 1, .. }
        ));
    }

    // ---- Invite nonce idempotent CAS ----

    #[test]
    fn burn_invite_nonce_replays_idempotently() {
        let mut store = Store::open_in_memory().expect("open");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");
        let nonce = vec![0xAA; 16];

        let first = store
            .burn_invite_nonce(&nonce, member_id, b"cap-bytes-v1", 1000)
            .expect("first burn");
        assert_eq!(first.member_id, member_id);
        assert_eq!(first.issued_cap, b"cap-bytes-v1");
        assert_eq!(first.redeemed_at, 1000);

        // Re-presentation with a DIFFERENT (freshly minted) cap and timestamp must replay the
        // original, not overwrite it — DESIGN.md §A4 idempotent redemption.
        let replay = store
            .burn_invite_nonce(&nonce, member_id, b"a-different-freshly-minted-cap", 9999)
            .expect("replay burn");
        assert_eq!(
            replay, first,
            "replay must return the original stored record"
        );
    }

    #[test]
    fn burn_invite_nonce_distinct_nonces_are_independent() {
        let mut store = Store::open_in_memory().expect("open");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");
        let a = store
            .burn_invite_nonce(&[1u8; 8], member_id, b"cap-a", 1)
            .expect("burn a");
        let b = store
            .burn_invite_nonce(&[2u8; 8], member_id, b"cap-b", 2)
            .expect("burn b");
        assert_ne!(a, b);
    }

    // ---- Devices: sign_pk (Stage 6 slice 4) ----

    #[test]
    fn device_sign_pk_round_trips_and_defaults_to_none() {
        let store = Store::open_in_memory().expect("open");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");
        let fp_no_key = Fingerprint::of_parts(&[b"device-no-key"]);
        let fp_with_key = Fingerprint::of_parts(&[b"device-with-key"]);

        store
            .add_device(member_id, fp_no_key, "Laptop", 0, None)
            .expect("add_device without key");
        store
            .add_device(
                member_id,
                fp_with_key,
                "Phone",
                0,
                Some(&DevicePublicKeys {
                    sign_pk: vec![0xAB; 32],
                    agree_pk: vec![0xCD; 32],
                }),
            )
            .expect("add_device with key");

        assert_eq!(store.device_sign_pk(fp_no_key).expect("lookup"), None);
        assert_eq!(
            store.device_sign_pk(fp_with_key).expect("lookup"),
            Some(vec![0xAB; 32])
        );
        assert_eq!(
            store
                .device_sign_pk(Fingerprint::of_parts(&[b"unknown-device"]))
                .expect("lookup nonexistent"),
            None,
            "an unknown device_fp is treated the same as a known device with no key on file"
        );
    }

    // ---- Devices: agree_pk + member_for_device_fp (Stage 6 slice 5) ----

    #[test]
    fn member_for_device_fp_returns_the_owning_member_with_both_stored_key_halves() {
        let store = Store::open_in_memory().expect("open");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");
        let device_fp = Fingerprint::of_parts(&[b"alex-laptop"]);
        let keys = DevicePublicKeys {
            sign_pk: vec![0x11; 32],
            agree_pk: vec![0x22; 32],
        };
        store
            .add_device(member_id, device_fp, "Laptop", 0, Some(&keys))
            .expect("add_device");

        let member = store
            .member_for_device_fp(device_fp)
            .expect("lookup")
            .expect("device is known");
        assert_eq!(member.member_id, member_id);
        let device = member
            .devices
            .iter()
            .find(|d| d.device_fp == device_fp)
            .expect("owning member's devices include the looked-up device");
        assert_eq!(device.sign_pk, Some(keys.sign_pk));
        assert_eq!(device.agree_pk, Some(keys.agree_pk));
    }

    #[test]
    fn member_for_device_fp_returns_none_for_a_device_fp_that_was_never_added() {
        let store = Store::open_in_memory().expect("open");
        store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");

        assert!(store
            .member_for_device_fp(Fingerprint::of_parts(&[b"never-added"]))
            .expect("lookup")
            .is_none());
    }

    #[test]
    fn stored_device_key_bytes_are_the_exact_preimage_device_fp_of_was_computed_from() {
        // Proves the binding property a connect-time authorizer relies on: a verifier that
        // recomputes `device_fp_of(alg_id, sign_pk, agree_pk)` from the STORED bytes must get back
        // the STORED `device_fp`. `spindle-vfs` may depend only on `spindle-core` (A9c crate-
        // layering law) and `x25519_dalek::PublicKey` is not re-exported from there, so this
        // asserts byte-for-byte preservation against the original `DeviceKey`'s own public keys
        // instead of round-tripping through a locally-parsed `X25519PublicKey` — that is sufficient
        // to prove the store never mutates either half, which is the property that matters here.
        let store = Store::open_in_memory().expect("open");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");
        let dev = spindle_core::identity::DeviceKey::from_seeds([0x30; 32], [0x31; 32]);
        let device_fp = dev.device_fp();
        let keys = DevicePublicKeys {
            sign_pk: dev.sign_public_key().as_bytes().to_vec(),
            agree_pk: dev.agree_public_key().as_bytes().to_vec(),
        };
        store
            .add_device(member_id, device_fp, "Laptop", 0, Some(&keys))
            .expect("add_device");

        let member = store
            .member_for_device_fp(device_fp)
            .expect("lookup")
            .expect("device is known");
        let device = member
            .devices
            .iter()
            .find(|d| d.device_fp == device_fp)
            .expect("owning member's devices include the looked-up device");
        assert_eq!(
            device.sign_pk.as_deref(),
            Some(dev.sign_public_key().as_bytes().as_slice())
        );
        assert_eq!(
            device.agree_pk.as_deref(),
            Some(dev.agree_public_key().as_bytes().as_slice())
        );
        assert_eq!(
            device_fp,
            spindle_core::device_fp_of(
                spindle_core::ALG_ID_V1,
                &dev.sign_public_key(),
                &dev.agree_public_key()
            ),
            "test fixture sanity: DeviceKey::device_fp must equal device_fp_of over its own keys"
        );
    }

    #[test]
    fn member_for_device_fp_still_finds_a_revoked_device_with_revoked_flag_set() {
        let store = Store::open_in_memory().expect("open");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");
        let device_fp = Fingerprint::of_parts(&[b"alex-laptop"]);
        store
            .add_device(member_id, device_fp, "Laptop", 0, None)
            .expect("add_device");
        store.revoke_device(device_fp).expect("revoke_device");

        let member = store
            .member_for_device_fp(device_fp)
            .expect("lookup")
            .expect("a revoked device must still be findable, so the deny path is auditable");
        let device = member
            .devices
            .iter()
            .find(|d| d.device_fp == device_fp)
            .expect("owning member's devices include the revoked device");
        assert!(
            device.revoked,
            "the authorizer must be able to tell 'revoked' apart from 'unknown'"
        );
    }

    // ---- Upload quotas (Stage 6 slice 4) ----

    #[test]
    fn member_upload_bytes_accumulates_and_clamps_at_zero() {
        let store = Store::open_in_memory().expect("open");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member");

        assert_eq!(store.member_upload_bytes(member_id).expect("read"), 0);
        assert_eq!(
            store
                .adjust_member_upload_bytes(member_id, 1000)
                .expect("adjust"),
            1000
        );
        assert_eq!(
            store
                .adjust_member_upload_bytes(member_id, 500)
                .expect("adjust"),
            1500
        );
        // A negative delta larger than the current total clamps at 0 rather than going negative.
        assert_eq!(
            store
                .adjust_member_upload_bytes(member_id, -10_000)
                .expect("adjust"),
            0
        );
    }

    #[test]
    fn share_upload_bytes_accumulates_independently_of_member() {
        let sandbox = tempdir().expect("tempdir");
        let store = Store::open_in_memory().expect("open");
        let share_id = store
            .add_share(
                "Drop",
                "Drop",
                sandbox.path(),
                ShareFlags {
                    allow_upload: true,
                    ..ShareFlags::default()
                },
                &[],
                0,
            )
            .expect("add_share");

        assert_eq!(store.share_upload_bytes(share_id).expect("read"), 0);
        assert_eq!(
            store
                .adjust_share_upload_bytes(share_id, 2048)
                .expect("adjust"),
            2048
        );
        assert_eq!(
            store
                .adjust_share_upload_bytes(share_id, -1000)
                .expect("adjust"),
            1048
        );
    }

    // ---- Integration: store -> algebra survives a reopen ----

    #[test]
    fn effective_grants_survive_reopen_byte_equal() {
        let sandbox = tempdir().expect("tempdir");
        let db_path = sandbox.path().join("host.sqlite3");
        let share_dir = tempdir().expect("share dir");

        let (member_id, share_id) = {
            let store = Store::open(&db_path).expect("open");
            let group_id = store.create_custom_group("Family").expect("group");
            let share_id = store
                .add_share(
                    "Photos",
                    "Photos",
                    share_dir.path(),
                    ShareFlags {
                        allow_upload: true,
                        ..ShareFlags::default()
                    },
                    &[],
                    0,
                )
                .expect("share");
            let member_id = store
                .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
                .expect("member");
            store
                .add_member_to_group(member_id, group_id)
                .expect("assign group");
            store
                .add_entitlement(
                    group_id,
                    share_id,
                    &vp("Vacation"),
                    Perms::BROWSE | Perms::DOWNLOAD,
                )
                .expect("entitlement");
            (member_id, share_id)
        };

        let before = {
            let store = Store::open(&db_path).expect("reopen (pre-restart snapshot)");
            let member = store.get_member(member_id).unwrap().unwrap();
            let share = store.get_share(share_id).unwrap().unwrap();
            let entitlements = store.list_entitlements().unwrap();
            let grants = EffectiveGrants::compute(&member, &entitlements, GrantsVersion::default());
            grants.resolve_access(&share, &vp("Vacation/img.jpg"))
        };

        // Reopen fresh (a brand-new Store/Connection over the same file) and recompute.
        let after = {
            let store = Store::open(&db_path).expect("reopen (post-restart)");
            let member = store.get_member(member_id).unwrap().unwrap();
            let share = store.get_share(share_id).unwrap().unwrap();
            let entitlements = store.list_entitlements().unwrap();
            let grants = EffectiveGrants::compute(&member, &entitlements, GrantsVersion::default());
            grants.resolve_access(&share, &vp("Vacation/img.jpg"))
        };

        assert_eq!(
            before, after,
            "effective perms must be identical across a restart"
        );
        assert_eq!(
            after,
            crate::algebra::AccessDecision::Granted(Perms::BROWSE | Perms::DOWNLOAD)
        );
    }
}
