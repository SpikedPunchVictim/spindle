//! `VfsRpcServer` — the per-request enforcement pipeline (DESIGN.md §A8 "VFS RPC", §A4b
//! "Enforcement", "Path confinement", "Audit log"). See this crate's `lib.rs` module doc comment
//! for the full pipeline order and scope; this module is the pipeline's implementation.
//!
//! `VfsRpcServer` is transport-agnostic and synchronous by design (task brief: "pure and testable
//! without any I/O framework"): [`VfsRpcServer::handle`] takes a typed request and returns a typed
//! reply; [`VfsRpcServer::handle_bytes`] is the thin bytes-in/bytes-out wrapper around it.
//! Wiring a real transport (accepting connections, framing, backpressure, streaming a `read`
//! reply's bytes over a QUIC/WebRTC data channel rather than returning them all at once) is
//! `spindle-net`'s job, out of scope here (task brief SCOPE/OUT).

use crate::cache::GrantsCache;
use crate::identity_cache::IdentityCache;
use crate::mount::{MountLookup, MountNode, MountTable};
use spindle_core::Fingerprint;
use spindle_proto::{
    DirEntry, EntryKind, ProtoError, VfsErrorCode, VfsPerms, VfsReply, VfsRequest,
    VfsRequestEnvelope, MAX_LIST_PAGE, MAX_READ_CHUNK, MIN_PROTOCOL_VERSION,
};
use spindle_vfs::algebra::{AccessDecision, EffectiveGrants, GrantsVersion};
use spindle_vfs::audit::AuditEntry;
use spindle_vfs::confine::{self, identity as confine_identity};
use spindle_vfs::model::{Member, MemberStatus, Perms, Share, VirtualPath};
use spindle_vfs::store::Store;
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

/// Identifies the calling session for pipeline purposes: which member is acting, and (optionally)
/// which of their devices, for the audit trail. Authenticating a transport-level session down to
/// these two values, and keeping them stable for the lifetime of that session, is `spindle-net`'s
/// responsibility (a later slice) — `VfsRpcServer` trusts them completely, exactly as scoped
/// (`spindle_proto::vfs_rpc`'s module doc comment: "VFS RPC messages travel inside an
/// already-authenticated ... session").
#[derive(Debug, Clone, Copy)]
pub struct SessionContext {
    pub member_id: spindle_vfs::model::MemberId,
    pub device_fp: Option<Fingerprint>,
}

/// One real-filesystem-or-synthetic listing/stat candidate, before permission filtering has
/// decided whether it is visible and before pagination has decided whether it is on this page.
/// Unifies two sources this crate's `list`/`stat` handling draws from: real dirents
/// (`spindle_vfs::confine::list_dir`) and synthetic mount-tree directories (`crate::mount`'s
/// `Intermediate` nodes, and mount-root entries at the virtual root/an intermediate directory) —
/// see the module doc comment on why both need to funnel through the same pagination logic.
struct Candidate {
    name: String,
    kind: EntryKind,
    size: u64,
    mtime: u64,
    perms: Perms,
}

/// The host-side VFS RPC enforcement pipeline. Holds a borrow of the `Store` it enforces against
/// (never owns it — a real host process owns exactly one `Store` per running host and constructs
/// this server around a reference to it) plus this slice's two caches (`crate::cache::GrantsCache`
/// for the host-wide shares/entitlements snapshot, `crate::identity_cache::IdentityCache` for the
/// stat→read TOCTOU baseline) — see each module's doc comment for what is and is not cached and
/// why.
pub struct VfsRpcServer<'s> {
    store: &'s Store,
    grants_cache: GrantsCache,
    identity_cache: IdentityCache,
}

impl<'s> VfsRpcServer<'s> {
    pub fn new(store: &'s Store) -> Self {
        VfsRpcServer {
            store,
            grants_cache: GrantsCache::new(),
            identity_cache: IdentityCache::new(),
        }
    }

    /// Bytes-in/bytes-out wrapper around [`Self::handle`]. `ts` is the audit timestamp for this
    /// request — threaded in explicitly rather than read from a wall clock inside this crate, so
    /// the whole pipeline (including its audit trail) stays deterministic and testable without
    /// any I/O framework (task brief), exactly like every other input here.
    ///
    /// Returns `Err` only when `bytes` does not even decode as a [`VfsRequestEnvelope`] —
    /// deliberately distinct from every [`VfsErrorCode`]: DESIGN.md §A8's error model defines
    /// typed codes for well-formed-but-rejected requests, not for bytes that are not a request at
    /// all (a transport bug or a corrupt/hostile peer *inside* an already-authenticated session).
    /// No existing code honestly describes "this wasn't a request"; flagged in this slice's report
    /// as a documented gap rather than silently mapped onto e.g. `NotFound`. The transport layer
    /// (`spindle-net`, later) decides what to do with this `Err` — e.g. closing the session.
    pub fn handle_bytes(
        &self,
        ctx: &SessionContext,
        ts: u64,
        bytes: &[u8],
    ) -> Result<Vec<u8>, ProtoError> {
        let env = VfsRequestEnvelope::from_canonical_bytes(bytes)?;
        Ok(self.handle(ctx, ts, env).to_canonical_bytes())
    }

    /// The pipeline, in the order the task brief specifies (cheapest checks first):
    /// 1. version check (no store access at all)
    /// 2. member active? (§A4b: unauthorized == `not_found`)
    /// 3. resolve the virtual path via the mount table (longest-prefix match)
    /// 4. effective perms from the algebra (host-wide shares/entitlements cached; a member's own
    ///    row is always fetched fresh — see `crate::cache` module doc comment)
    /// 5. confine/ for the actual I/O (fresh `Dir` every request; TOCTOU identity checks)
    /// 6. audit append — for every outcome, including every denial, at every step above.
    pub fn handle(&self, ctx: &SessionContext, ts: u64, env: VfsRequestEnvelope) -> VfsReply {
        // Step 1: version check. Zero store access — the cheapest possible rejection, and (by
        // construction) the one whose audit entry cannot carry a resolved member fingerprint yet
        // (see this crate's `lib.rs` module doc comment: doing a store lookup purely to enrich
        // this audit row would defeat the point of checking the version first).
        if env.v < MIN_PROTOCOL_VERSION {
            self.audit(
                ts,
                None,
                ctx.device_fp,
                op_name(&env.request),
                request_path(&env.request),
                None,
                "denied:unsupported_version",
            );
            return VfsReply::Error {
                code: VfsErrorCode::UnsupportedVersion,
            };
        }

        // Step 2: member active? Always a fresh store read — see `crate::cache` module doc
        // comment for why this is never served from a grants_version/cap_epoch-keyed cache.
        let member = match self.store.get_member(ctx.member_id) {
            Ok(Some(m)) => m,
            Ok(None) => {
                self.audit(
                    ts,
                    None,
                    ctx.device_fp,
                    op_name(&env.request),
                    request_path(&env.request),
                    None,
                    "denied:unknown_member",
                );
                return VfsReply::Error {
                    code: VfsErrorCode::NotFound,
                };
            }
            Err(_) => {
                // A store failure is not a VFS-semantic outcome any of the eight codes describe;
                // fail closed rather than leak internal error detail over the wire.
                self.audit(
                    ts,
                    None,
                    ctx.device_fp,
                    op_name(&env.request),
                    request_path(&env.request),
                    None,
                    "error:store_read_failed",
                );
                return VfsReply::Error {
                    code: VfsErrorCode::NotFound,
                };
            }
        };
        if member.status != MemberStatus::Active {
            self.audit(
                ts,
                Some(member.root_fp),
                ctx.device_fp,
                op_name(&env.request),
                request_path(&env.request),
                None,
                "denied:member_not_active",
            );
            return VfsReply::Error {
                code: VfsErrorCode::NotFound,
            };
        }

        match &env.request {
            VfsRequest::Whoami => self.handle_whoami(ts, ctx, &member),
            VfsRequest::List {
                path,
                cursor,
                limit,
            } => self.handle_list(ts, ctx, &member, path, cursor.as_deref(), *limit),
            VfsRequest::Stat { path } => self.handle_stat(ts, ctx, &member, path),
            VfsRequest::Read { path, offset, len } => {
                self.handle_read(ts, ctx, &member, path, *offset, *len)
            }
            VfsRequest::Mkdir { path } => self.handle_mkdir(ts, ctx, &member, path),
            VfsRequest::Delete { path } => self.handle_delete(ts, ctx, &member, path),
        }
    }

    // -------------------------------------------------------------------------------------
    // whoami
    // -------------------------------------------------------------------------------------

    fn handle_whoami(&self, ts: u64, ctx: &SessionContext, member: &Member) -> VfsReply {
        let (shares, entitlements) = self.grants_cache.get(self.store).unwrap_or_default();
        // DESIGN.md's literal `{member_display, effective_paths}` tuple, trimmed per §A4b/A12
        // #32 (no group names, no internal ids): the full virtual path (mount_path + subpath) of
        // every entitlement, belonging to a group this member is in, that grants `browse`
        // directly — i.e. the paths a client would show as top-level browsable roots. This is a
        // documented interpretation: DESIGN.md names the field but not its exact contents:
        // ancestor-traversal steps toward a grant are not themselves "effective paths" (they are
        // not independently useful destinations), so they are not listed here even though
        // `list`/`stat` do treat them as visible directories.
        let mut effective_paths: Vec<String> = entitlements
            .iter()
            .filter(|e| member.groups.contains(&e.group_id) && e.perms.contains(Perms::BROWSE))
            .filter_map(|e| {
                shares
                    .iter()
                    .find(|s| s.share_id == e.share_id)
                    .map(|s| combine_mount_and_subpath(s, &e.subpath).to_path_string())
            })
            .collect();
        effective_paths.sort();
        effective_paths.dedup();

        self.audit(
            ts,
            Some(member.root_fp),
            ctx.device_fp,
            "whoami",
            None,
            None,
            "ok",
        );
        VfsReply::Whoami {
            member_display: member.display_name.clone(),
            effective_paths,
        }
    }

    // -------------------------------------------------------------------------------------
    // list
    // -------------------------------------------------------------------------------------

    fn handle_list(
        &self,
        ts: u64,
        ctx: &SessionContext,
        member: &Member,
        path: &str,
        cursor: Option<&[u8]>,
        limit: Option<u32>,
    ) -> VfsReply {
        let (shares, entitlements) = match self.grants_cache.get(self.store) {
            Ok(v) => v,
            Err(_) => {
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "list",
                    Some(path),
                    "error:store_read_failed",
                )
            }
        };
        let version = GrantsVersion(self.store.grants_version().unwrap_or(0));
        let effective = EffectiveGrants::compute(member, &entitlements, version);
        let mount_table = MountTable::build(shares);

        let Ok(vp) = VirtualPath::parse(path) else {
            return self.deny(ts, member, ctx, "list", Some(path), "denied:not_found");
        };

        let candidates = match mount_table.resolve(&vp) {
            MountLookup::NotFound => {
                return self.deny(ts, member, ctx, "list", Some(path), "denied:not_found")
            }
            MountLookup::Intermediate(children) => {
                visible_intermediate_entries(children, &effective)
            }
            MountLookup::Share { share, subpath } => {
                let decision = effective.resolve_access(share, &subpath);
                let listable = matches!(decision, AccessDecision::Traversal)
                    || matches!(decision, AccessDecision::Granted(p) if p.contains(Perms::BROWSE));
                if !listable {
                    return self.deny(ts, member, ctx, "list", Some(path), "denied:not_found");
                }
                match self.list_share_directory(share, &subpath, &effective) {
                    Some(c) => c,
                    None => {
                        return self.deny(ts, member, ctx, "list", Some(path), "denied:not_found")
                    }
                }
            }
        };

        let (entries, next_cursor) = paginate(candidates, cursor, limit);
        self.audit(
            ts,
            Some(member.root_fp),
            ctx.device_fp,
            "list",
            Some(path),
            None,
            "ok",
        );
        VfsReply::List {
            entries,
            next_cursor,
        }
    }

    /// Lists `subpath` inside `share` through a freshly opened `Dir` (DESIGN.md §A4b: "every
    /// request re-resolves from the share `Dir`"), applies the entitlement algebra's listing
    /// filter, and — for files, when the share has exclusions — the hardlink-bypass `nlink` guard
    /// (§A4b; `spindle_vfs::confine::identity::nlink_guard`'s doc comment: the rule targets files,
    /// not directories, which routinely have `nlink > 1` from their own subdirectories' `..`
    /// entries with no bearing on the hardlink-bypass attack it exists to close).
    fn list_share_directory(
        &self,
        share: &Share,
        subpath: &VirtualPath,
        effective: &EffectiveGrants<'_>,
    ) -> Option<Vec<Candidate>> {
        let dir = confine::open_share_root(&share.real_root).ok()?;
        let relative = subpath.to_path_string();
        let real_entries = confine::list_dir(&dir, &relative).ok()?;
        let names: Vec<&str> = real_entries.iter().map(|e| e.name.as_str()).collect();
        let filtered = effective.filter_listing(share, subpath, names.iter().copied());

        let mut out = Vec::new();
        for (name, decision) in filtered {
            let real = real_entries
                .iter()
                .find(|e| e.name == name)
                .expect("filtered name came from the same real_entries list");
            if share.has_exclusions() && real.kind == confine::RealEntryKind::File {
                let Ok(file) = dir.open(name) else { continue };
                let file = file.into_std();
                match confine_identity::nlink_guard(&file, true) {
                    Ok(true) => {}
                    _ => continue, // hardlink-bypass guard failed, or metadata errored: skip, don't leak.
                }
            }
            let kind = match real.kind {
                confine::RealEntryKind::File => EntryKind::File,
                confine::RealEntryKind::Dir => EntryKind::Dir,
            };
            out.push(Candidate {
                name: name.to_string(),
                kind,
                size: real.size,
                mtime: real.mtime,
                perms: decision.perms(),
            });
        }
        Some(out)
    }

    // -------------------------------------------------------------------------------------
    // stat
    // -------------------------------------------------------------------------------------

    fn handle_stat(&self, ts: u64, ctx: &SessionContext, member: &Member, path: &str) -> VfsReply {
        let (shares, entitlements) = match self.grants_cache.get(self.store) {
            Ok(v) => v,
            Err(_) => {
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "stat",
                    Some(path),
                    "error:store_read_failed",
                )
            }
        };
        let version = GrantsVersion(self.store.grants_version().unwrap_or(0));
        let effective = EffectiveGrants::compute(member, &entitlements, version);
        let mount_table = MountTable::build(shares);

        let Ok(vp) = VirtualPath::parse(path) else {
            return self.deny(ts, member, ctx, "stat", Some(path), "denied:not_found");
        };

        let reply = match mount_table.resolve(&vp) {
            MountLookup::NotFound => None,
            MountLookup::Intermediate(children) => {
                if intermediate_is_visible(children, &effective) {
                    Some(VfsReply::Stat {
                        kind: EntryKind::Dir,
                        size: 0,
                        mtime: 0,
                        perms_here: VfsPerms::NONE,
                    })
                } else {
                    None
                }
            }
            MountLookup::Share { share, subpath } => {
                let decision = effective.resolve_access(share, &subpath);
                if matches!(decision, AccessDecision::NotFound) {
                    None
                } else {
                    self.stat_in_share(member, share, &subpath, decision)
                }
            }
        };

        match reply {
            Some(reply) => {
                self.audit(
                    ts,
                    Some(member.root_fp),
                    ctx.device_fp,
                    "stat",
                    Some(path),
                    None,
                    "ok",
                );
                reply
            }
            None => self.deny(ts, member, ctx, "stat", Some(path), "denied:not_found"),
        }
    }

    fn stat_in_share(
        &self,
        member: &Member,
        share: &Share,
        subpath: &VirtualPath,
        decision: AccessDecision,
    ) -> Option<VfsReply> {
        let dir = confine::open_share_root(&share.real_root).ok()?;
        let relative = confine_relative(subpath);
        let meta = confine_identity::stat_through_dir(&dir, &relative).ok()?;
        if let Ok(identity) = confine_identity::resolve_identity(&dir, &relative) {
            self.identity_cache
                .record(member.member_id, share.share_id, subpath, identity);
        }
        let kind = if meta.is_dir() {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        let perms_here =
            VfsPerms::from_bits_truncate_checked(decision.perms().bits()).unwrap_or(VfsPerms::NONE);
        Some(VfsReply::Stat {
            kind,
            size: meta.len(),
            mtime: unix_seconds(&meta),
            perms_here,
        })
    }

    // -------------------------------------------------------------------------------------
    // read
    // -------------------------------------------------------------------------------------

    fn handle_read(
        &self,
        ts: u64,
        ctx: &SessionContext,
        member: &Member,
        path: &str,
        offset: u64,
        len: u32,
    ) -> VfsReply {
        let (shares, entitlements) = match self.grants_cache.get(self.store) {
            Ok(v) => v,
            Err(_) => {
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "read",
                    Some(path),
                    "error:store_read_failed",
                )
            }
        };
        let version = GrantsVersion(self.store.grants_version().unwrap_or(0));
        let effective = EffectiveGrants::compute(member, &entitlements, version);
        let mount_table = MountTable::build(shares);

        let Ok(vp) = VirtualPath::parse(path) else {
            return self.deny(ts, member, ctx, "read", Some(path), "denied:not_found");
        };

        let (share, subpath) = match mount_table.resolve(&vp) {
            MountLookup::Share { share, subpath } => (share, subpath),
            MountLookup::Intermediate(_) | MountLookup::NotFound => {
                return self.deny(ts, member, ctx, "read", Some(path), "denied:not_found")
            }
        };
        let decision = effective.resolve_access(share, &subpath);
        if !decision.perms().contains(Perms::DOWNLOAD) {
            return self.deny(ts, member, ctx, "read", Some(path), "denied:not_found");
        }

        match self.read_chunk(member, share, &subpath, offset, len) {
            Ok((data, eof)) => {
                self.audit(
                    ts,
                    Some(member.root_fp),
                    ctx.device_fp,
                    "read",
                    Some(path),
                    Some(data.len() as u64),
                    "ok",
                );
                VfsReply::Read { data, eof }
            }
            Err(outcome) => self.deny(ts, member, ctx, "read", Some(path), outcome),
        }
    }

    /// Reads one bounded chunk (≤ [`MAX_READ_CHUNK`]) at `offset`, through a freshly opened `Dir`,
    /// enforcing DESIGN.md §A4b's stat→read TOCTOU rule via `crate::identity_cache::IdentityCache`
    /// both *before* the read (compare against the last observation for this member/path, if any)
    /// and *after* it (compare against the identity captured immediately before this read — the
    /// per-chunk-boundary half of the same rule, applied at this RPC call's own boundary since
    /// transport-level chunk streaming is out of scope here).
    fn read_chunk(
        &self,
        member: &Member,
        share: &Share,
        subpath: &VirtualPath,
        offset: u64,
        len: u32,
    ) -> Result<(Vec<u8>, bool), &'static str> {
        let dir = confine::open_share_root(&share.real_root).map_err(|_| "denied:not_found")?;
        let relative = confine_relative(subpath);
        let meta =
            confine_identity::stat_through_dir(&dir, &relative).map_err(|_| "denied:not_found")?;
        if !meta.is_file() {
            return Err("denied:not_found");
        }
        let pre_identity =
            confine_identity::resolve_identity(&dir, &relative).map_err(|_| "denied:not_found")?;
        if self
            .identity_cache
            .mismatches(member.member_id, share.share_id, subpath, pre_identity)
        {
            self.identity_cache
                .forget(member.member_id, share.share_id, subpath);
            return Err("denied:identity_changed");
        }

        let clamped_len = len.min(MAX_READ_CHUNK) as usize;
        let mut file = dir.open(&relative).map_err(|_| "denied:not_found")?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| "denied:not_found")?;
        let mut buf = vec![0u8; clamped_len];
        let n = file.read(&mut buf).map_err(|_| "denied:not_found")?;
        buf.truncate(n);
        let eof = offset.saturating_add(n as u64) >= meta.len();

        let post_identity =
            confine_identity::resolve_identity(&dir, &relative).map_err(|_| "denied:not_found")?;
        if post_identity != pre_identity {
            self.identity_cache
                .forget(member.member_id, share.share_id, subpath);
            return Err("denied:identity_changed");
        }
        self.identity_cache
            .record(member.member_id, share.share_id, subpath, post_identity);
        Ok((buf, eof))
    }

    // -------------------------------------------------------------------------------------
    // mkdir
    // -------------------------------------------------------------------------------------

    fn handle_mkdir(&self, ts: u64, ctx: &SessionContext, member: &Member, path: &str) -> VfsReply {
        let (shares, entitlements) = match self.grants_cache.get(self.store) {
            Ok(v) => v,
            Err(_) => {
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "mkdir",
                    Some(path),
                    "error:store_read_failed",
                )
            }
        };
        let version = GrantsVersion(self.store.grants_version().unwrap_or(0));
        let effective = EffectiveGrants::compute(member, &entitlements, version);
        let mount_table = MountTable::build(shares);

        let Ok(vp) = VirtualPath::parse(path) else {
            return self.deny(ts, member, ctx, "mkdir", Some(path), "denied:not_found");
        };
        let (share, subpath) = match mount_table.resolve(&vp) {
            MountLookup::Share { share, subpath } => (share, subpath),
            MountLookup::Intermediate(_) | MountLookup::NotFound => {
                return self.deny(ts, member, ctx, "mkdir", Some(path), "denied:not_found")
            }
        };
        let decision = effective.resolve_access(share, &subpath);
        if !decision.perms().contains(Perms::UPLOAD)
            || !share.flags.allow_upload
            || share.flags.read_only
        {
            return self.deny(ts, member, ctx, "mkdir", Some(path), "denied:not_found");
        }

        let dir = match confine::open_share_root(&share.real_root) {
            Ok(d) => d,
            Err(_) => return self.deny(ts, member, ctx, "mkdir", Some(path), "denied:not_found"),
        };
        let can_delete = decision.perms().contains(Perms::DELETE);
        match confine::create_dir_confined(&dir, &subpath.to_path_string(), true, can_delete) {
            Ok(true) => {
                self.audit(
                    ts,
                    Some(member.root_fp),
                    ctx.device_fp,
                    "mkdir",
                    Some(path),
                    None,
                    "ok",
                );
                VfsReply::Mkdir
            }
            Ok(false) => self.deny_with_code(
                ts,
                member,
                ctx,
                "mkdir",
                Some(path),
                "denied:exists_needs_delete",
                VfsErrorCode::UploadRejected,
            ),
            Err(_) => self.deny(ts, member, ctx, "mkdir", Some(path), "denied:not_found"),
        }
    }

    // -------------------------------------------------------------------------------------
    // delete
    // -------------------------------------------------------------------------------------

    fn handle_delete(
        &self,
        ts: u64,
        ctx: &SessionContext,
        member: &Member,
        path: &str,
    ) -> VfsReply {
        let (shares, entitlements) = match self.grants_cache.get(self.store) {
            Ok(v) => v,
            Err(_) => {
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "delete",
                    Some(path),
                    "error:store_read_failed",
                )
            }
        };
        let version = GrantsVersion(self.store.grants_version().unwrap_or(0));
        let effective = EffectiveGrants::compute(member, &entitlements, version);
        let mount_table = MountTable::build(shares);

        let Ok(vp) = VirtualPath::parse(path) else {
            return self.deny(ts, member, ctx, "delete", Some(path), "denied:not_found");
        };
        let (share, subpath) = match mount_table.resolve(&vp) {
            MountLookup::Share { share, subpath } => (share, subpath),
            MountLookup::Intermediate(_) | MountLookup::NotFound => {
                return self.deny(ts, member, ctx, "delete", Some(path), "denied:not_found")
            }
        };
        // `delete` does not imply `download` (DESIGN.md §A4b) — checked here only for `DELETE`.
        let decision = effective.resolve_access(share, &subpath);
        if !decision.perms().contains(Perms::DELETE)
            || !share.flags.allow_upload
            || share.flags.read_only
        {
            return self.deny(ts, member, ctx, "delete", Some(path), "denied:not_found");
        }

        let dir = match confine::open_share_root(&share.real_root) {
            Ok(d) => d,
            Err(_) => return self.deny(ts, member, ctx, "delete", Some(path), "denied:not_found"),
        };
        match confine::remove_confined(&dir, &subpath.to_path_string()) {
            Ok(()) => {
                self.identity_cache
                    .forget(member.member_id, share.share_id, &subpath);
                self.audit(
                    ts,
                    Some(member.root_fp),
                    ctx.device_fp,
                    "delete",
                    Some(path),
                    None,
                    "ok",
                );
                VfsReply::Delete
            }
            Err(_) => self.deny(ts, member, ctx, "delete", Some(path), "denied:not_found"),
        }
    }

    // -------------------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------------------

    fn deny(
        &self,
        ts: u64,
        member: &Member,
        ctx: &SessionContext,
        action: &str,
        path: Option<&str>,
        outcome: &str,
    ) -> VfsReply {
        self.deny_with_code(
            ts,
            member,
            ctx,
            action,
            path,
            outcome,
            VfsErrorCode::NotFound,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn deny_with_code(
        &self,
        ts: u64,
        member: &Member,
        ctx: &SessionContext,
        action: &str,
        path: Option<&str>,
        outcome: &str,
        code: VfsErrorCode,
    ) -> VfsReply {
        self.audit(
            ts,
            Some(member.root_fp),
            ctx.device_fp,
            action,
            path,
            None,
            outcome,
        );
        VfsReply::Error { code }
    }

    #[allow(clippy::too_many_arguments)]
    fn audit(
        &self,
        ts: u64,
        member_fp: Option<Fingerprint>,
        device_fp: Option<Fingerprint>,
        action: &str,
        virtual_path: Option<&str>,
        bytes: Option<u64>,
        outcome: &str,
    ) {
        // Best-effort (task brief deliverable #2: "audit append for EVERY op including denials"
        // — but an audit *write* failure, e.g. a transient SQLite error, is treated here as a
        // logging fault, not grounds to also fail the VFS op that already succeeded/was denied on
        // its own merits; DESIGN.md does not specify fail-open vs. fail-closed on audit-append
        // failure specifically, so this is a documented choice, flagged in this slice's report).
        let entry = AuditEntry {
            ts,
            member: member_fp,
            device: device_fp,
            action: action.to_string(),
            virtual_path: virtual_path.map(str::to_string),
            bytes,
            outcome: outcome.to_string(),
        };
        let _ = self.store.audit().append(entry);
    }
}

// ===========================================================================================
// Free functions
// ===========================================================================================

fn op_name(req: &VfsRequest) -> &'static str {
    match req {
        VfsRequest::List { .. } => "list",
        VfsRequest::Stat { .. } => "stat",
        VfsRequest::Read { .. } => "read",
        VfsRequest::Mkdir { .. } => "mkdir",
        VfsRequest::Delete { .. } => "delete",
        VfsRequest::Whoami => "whoami",
    }
}

fn request_path(req: &VfsRequest) -> Option<&str> {
    match req {
        VfsRequest::List { path, .. }
        | VfsRequest::Stat { path }
        | VfsRequest::Read { path, .. }
        | VfsRequest::Mkdir { path }
        | VfsRequest::Delete { path } => Some(path.as_str()),
        VfsRequest::Whoami => None,
    }
}

/// `cap_std::fs::Dir::open`/`read_dir` treat an empty relative path as invalid, unlike
/// `spindle_vfs::confine::listing::list_dir` (which special-cases it internally); `"."` (a plain,
/// ordinary relative-path component every OS accepts as "this directory") is this crate's own
/// stand-in for "the share root itself" wherever this module calls into `stat_through_dir`/
/// `resolve_identity`/`Dir::open` directly rather than through `list_dir`.
fn confine_relative(subpath: &VirtualPath) -> String {
    if subpath.is_root() {
        ".".to_string()
    } else {
        subpath.to_path_string()
    }
}

fn combine_mount_and_subpath(share: &Share, subpath: &VirtualPath) -> VirtualPath {
    let mount = VirtualPath::parse(&share.mount_path)
        .expect("share.mount_path is validated at Store::add_share time");
    subpath
        .components()
        .iter()
        .fold(mount, |acc, c| acc.join(c))
}

fn unix_seconds(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Visible entries at a virtual-root/intermediate mount-tree directory (task brief: "listings at
/// the virtual root and intermediate virtual directories show only entries the member can browse
/// — browse implies ancestor traversal, listing only the path toward the grant"). A mount-root
/// child is visible exactly when the member's access to that share's own root is `Traversal` or
/// `Granted` with `browse`; an `Intermediate` child (another synthetic directory, not itself a
/// mount) is visible when *any* mount reachable underneath it is.
fn visible_intermediate_entries(
    children: &BTreeMap<String, MountNode>,
    effective: &EffectiveGrants<'_>,
) -> Vec<Candidate> {
    children
        .iter()
        .filter_map(|(name, node)| match node {
            MountNode::Share(share) => {
                let decision = effective.resolve_access(share, &VirtualPath::root());
                match decision {
                    AccessDecision::Granted(p) if p.contains(Perms::BROWSE) => Some(Candidate {
                        name: name.clone(),
                        kind: EntryKind::Dir,
                        size: 0,
                        mtime: 0,
                        perms: p,
                    }),
                    AccessDecision::Traversal => Some(Candidate {
                        name: name.clone(),
                        kind: EntryKind::Dir,
                        size: 0,
                        mtime: 0,
                        perms: Perms::NONE,
                    }),
                    _ => None,
                }
            }
            MountNode::Intermediate(sub) => {
                intermediate_is_visible(sub, effective).then(|| Candidate {
                    name: name.clone(),
                    kind: EntryKind::Dir,
                    size: 0,
                    mtime: 0,
                    perms: Perms::NONE,
                })
            }
        })
        .collect()
}

fn intermediate_is_visible(
    children: &BTreeMap<String, MountNode>,
    effective: &EffectiveGrants<'_>,
) -> bool {
    children.values().any(|node| match node {
        MountNode::Share(share) => {
            let decision = effective.resolve_access(share, &VirtualPath::root());
            matches!(decision, AccessDecision::Traversal)
                || matches!(decision, AccessDecision::Granted(p) if p.contains(Perms::BROWSE))
        }
        MountNode::Intermediate(sub) => intermediate_is_visible(sub, effective),
    })
}

/// Sorts `candidates` by name (deterministic, keyset-paginable order), applies `cursor`/`limit`,
/// and converts the page to wire [`DirEntry`] values. `cursor` is this crate's own opaque-bytes
/// convention (`spindle_proto::vfs_rpc`'s module doc comment: "the host-core paging implementation
/// owns the cursor's internal shape"): the UTF-8 bytes of the last name returned on the previous
/// page. Keyset (not offset) pagination is used specifically so a page boundary survives
/// insertions/deletions elsewhere in the directory between calls without skipping or repeating
/// entries around the edit — resuming means "every name greater than the cursor," not "skip N
/// entries." An unparseable cursor (not valid UTF-8, or naming an entry no longer relevant) is
/// treated as "start from the beginning" rather than an error — a client that mishandles its own
/// opaque cursor gets a correct-but-restarted listing, not a hard failure.
fn paginate(
    mut candidates: Vec<Candidate>,
    cursor: Option<&[u8]>,
    limit: Option<u32>,
) -> (Vec<DirEntry>, Option<Vec<u8>>) {
    candidates.sort_by(|a, b| a.name.cmp(&b.name));
    let start = match cursor.and_then(|c| std::str::from_utf8(c).ok()) {
        Some(after_name) => candidates.partition_point(|c| c.name.as_str() <= after_name),
        None => 0,
    };
    let page_limit = limit.map(|l| l.min(MAX_LIST_PAGE)).unwrap_or(MAX_LIST_PAGE) as usize;
    let end = candidates.len().min(start.saturating_add(page_limit));
    let page = &candidates[start..end];

    let entries = page
        .iter()
        .map(|c| DirEntry {
            name: c.name.clone(),
            kind: c.kind,
            size: c.size,
            mtime: c.mtime,
            perms_here: VfsPerms::from_bits_truncate_checked(c.perms.bits())
                .unwrap_or(VfsPerms::NONE),
        })
        .collect();
    let next_cursor = if end < candidates.len() {
        Some(
            page.last()
                .expect("end > start when truncated")
                .name
                .clone()
                .into_bytes(),
        )
    } else {
        None
    };
    (entries, next_cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_vfs::model::{MemberId, ShareFlags, ShareId};
    use spindle_vfs::store::Store;
    use tempfile::TempDir;

    /// Shared test scaffolding: an in-memory `Store` plus a disposable real directory tree for
    /// share roots, both dropped together at the end of each test.
    struct Harness {
        sandbox: TempDir,
        store: Store,
    }

    impl Harness {
        fn new() -> Self {
            Harness {
                sandbox: tempfile::tempdir().expect("tempdir"),
                store: Store::open_in_memory().expect("open in-memory store"),
            }
        }

        fn server(&self) -> VfsRpcServer<'_> {
            VfsRpcServer::new(&self.store)
        }

        fn real_root(&self, name: &str) -> std::path::PathBuf {
            let p = self.sandbox.path().join(name);
            std::fs::create_dir_all(&p).expect("mkdir real root");
            p
        }

        fn add_active_member(&self, display_name: &str) -> (MemberId, Fingerprint) {
            let fp = Fingerprint::of_parts(&[display_name.as_bytes()]);
            let id = self
                .store
                .add_member(fp, display_name, 0)
                .expect("add member");
            self.store.activate_member(id).expect("activate member");
            (id, fp)
        }

        fn add_share(&self, name: &str, mount_path: &str, flags: ShareFlags) -> ShareId {
            let root = self.real_root(name);
            self.store
                .add_share(name, mount_path, &root, flags, &[], 0)
                .expect("add share")
        }

        fn share_real_root(&self, share_id: ShareId) -> std::path::PathBuf {
            self.store
                .get_share(share_id)
                .expect("get_share")
                .expect("share exists")
                .real_root
        }

        /// Creates a fresh custom group, puts `member_id` in it, and grants `perms` on
        /// `share_id` at `subpath` — the common "one member, one grant" test setup.
        fn grant(&self, member_id: MemberId, share_id: ShareId, subpath: &str, perms: Perms) {
            let group_name = format!("g-{}-{}-{}", member_id.0, share_id.0, subpath);
            let group_id = self
                .store
                .create_custom_group(&group_name)
                .expect("create group");
            self.store
                .add_member_to_group(member_id, group_id)
                .expect("join group");
            self.store
                .add_entitlement(
                    group_id,
                    share_id,
                    &VirtualPath::parse(subpath).expect("valid subpath"),
                    perms,
                )
                .expect("grant entitlement");
        }

        fn ctx(&self, member_id: MemberId) -> SessionContext {
            SessionContext {
                member_id,
                device_fp: None,
            }
        }
    }

    fn req(v: u8, request: VfsRequest) -> VfsRequestEnvelope {
        VfsRequestEnvelope { v, request }
    }

    #[test]
    fn whoami_returns_trimmed_display_and_browse_paths() {
        let h = Harness::new();
        let (member_id, _) = h.add_active_member("Alex");
        let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
        h.grant(member_id, share_id, "Vacation", Perms::BROWSE);

        let server = h.server();
        let reply = server.handle(&h.ctx(member_id), 1, req(1, VfsRequest::Whoami));
        match reply {
            VfsReply::Whoami {
                member_display,
                effective_paths,
            } => {
                assert_eq!(member_display, "Alex");
                assert_eq!(effective_paths, vec!["Photos/Vacation".to_string()]);
            }
            other => panic!("expected Whoami, got {other:?}"),
        }
    }

    #[test]
    fn list_shows_only_browsable_entries_and_descends_into_them() {
        let h = Harness::new();
        let (member_id, _) = h.add_active_member("Alex");
        let share_id = h.add_share(
            "Photos",
            "Photos",
            ShareFlags {
                read_only: false,
                allow_upload: false,
                show_hidden: false,
            },
        );
        let root = h.share_real_root(share_id);
        std::fs::write(root.join("a.jpg"), b"x").expect("write a.jpg");
        std::fs::create_dir(root.join("Vacation")).expect("mkdir Vacation");
        std::fs::write(root.join("Vacation/img.jpg"), b"y").expect("write img.jpg");
        std::fs::create_dir(root.join("Private")).expect("mkdir Private");

        h.grant(
            member_id,
            share_id,
            "Vacation",
            Perms::BROWSE | Perms::DOWNLOAD,
        );

        let server = h.server();
        let reply = server.handle(
            &h.ctx(member_id),
            1,
            req(
                1,
                VfsRequest::List {
                    path: "Photos".to_string(),
                    cursor: None,
                    limit: None,
                },
            ),
        );
        match reply {
            VfsReply::List {
                entries,
                next_cursor,
            } => {
                assert_eq!(entries.len(), 1, "a.jpg and Private must not be visible");
                assert_eq!(entries[0].name, "Vacation");
                assert!(next_cursor.is_none());
            }
            other => panic!("expected List, got {other:?}"),
        }

        let reply = server.handle(
            &h.ctx(member_id),
            2,
            req(
                1,
                VfsRequest::List {
                    path: "Photos/Vacation".to_string(),
                    cursor: None,
                    limit: None,
                },
            ),
        );
        match reply {
            VfsReply::List { entries, .. } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "img.jpg");
            }
            other => panic!("expected List, got {other:?}"),
        }
    }

    #[test]
    fn stat_reports_kind_size_and_perms() {
        let h = Harness::new();
        let (member_id, _) = h.add_active_member("Alex");
        let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
        let root = h.share_real_root(share_id);
        std::fs::write(root.join("a.jpg"), b"hello").expect("write a.jpg");
        h.grant(member_id, share_id, "", Perms::BROWSE | Perms::DOWNLOAD);

        let server = h.server();
        let reply = server.handle(
            &h.ctx(member_id),
            1,
            req(
                1,
                VfsRequest::Stat {
                    path: "Photos/a.jpg".to_string(),
                },
            ),
        );
        match reply {
            VfsReply::Stat {
                kind,
                size,
                perms_here,
                ..
            } => {
                assert_eq!(kind, EntryKind::File);
                assert_eq!(size, 5);
                assert!(perms_here.contains(VfsPerms::DOWNLOAD));
            }
            other => panic!("expected Stat, got {other:?}"),
        }
    }

    #[test]
    fn read_returns_requested_chunk_and_reports_eof() {
        let h = Harness::new();
        let (member_id, _) = h.add_active_member("Alex");
        let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
        let root = h.share_real_root(share_id);
        std::fs::write(root.join("a.bin"), vec![7u8; 10]).expect("write a.bin");
        h.grant(member_id, share_id, "", Perms::BROWSE | Perms::DOWNLOAD);

        let server = h.server();
        let reply = server.handle(
            &h.ctx(member_id),
            1,
            req(
                1,
                VfsRequest::Read {
                    path: "Photos/a.bin".to_string(),
                    offset: 0,
                    len: 5,
                },
            ),
        );
        match reply {
            VfsReply::Read { data, eof } => {
                assert_eq!(data, vec![7u8; 5]);
                assert!(!eof);
            }
            other => panic!("expected Read, got {other:?}"),
        }

        let reply = server.handle(
            &h.ctx(member_id),
            2,
            req(
                1,
                VfsRequest::Read {
                    path: "Photos/a.bin".to_string(),
                    offset: 5,
                    len: 100,
                },
            ),
        );
        match reply {
            VfsReply::Read { data, eof } => {
                assert_eq!(data.len(), 5);
                assert!(eof);
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    #[test]
    fn read_without_download_perm_is_denied() {
        let h = Harness::new();
        let (member_id, _) = h.add_active_member("Alex");
        let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
        let root = h.share_real_root(share_id);
        std::fs::write(root.join("a.bin"), vec![7u8; 10]).expect("write a.bin");
        h.grant(member_id, share_id, "", Perms::BROWSE); // no download

        let server = h.server();
        let reply = server.handle(
            &h.ctx(member_id),
            1,
            req(
                1,
                VfsRequest::Read {
                    path: "Photos/a.bin".to_string(),
                    offset: 0,
                    len: 5,
                },
            ),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::NotFound
            }
        );
    }

    #[test]
    fn mkdir_creates_directory_with_upload_perm() {
        let h = Harness::new();
        let (member_id, _) = h.add_active_member("Alex");
        let share_id = h.add_share(
            "Drop",
            "Drop",
            ShareFlags {
                read_only: false,
                allow_upload: true,
                show_hidden: false,
            },
        );
        h.grant(member_id, share_id, "", Perms::UPLOAD);

        let server = h.server();
        let reply = server.handle(
            &h.ctx(member_id),
            1,
            req(
                1,
                VfsRequest::Mkdir {
                    path: "Drop/NewAlbum".to_string(),
                },
            ),
        );
        assert_eq!(reply, VfsReply::Mkdir);
        assert!(h.share_real_root(share_id).join("NewAlbum").is_dir());
    }

    #[test]
    fn delete_removes_file_with_delete_perm() {
        let h = Harness::new();
        let (member_id, _) = h.add_active_member("Alex");
        let share_id = h.add_share(
            "Drop",
            "Drop",
            ShareFlags {
                read_only: false,
                allow_upload: true,
                show_hidden: false,
            },
        );
        let root = h.share_real_root(share_id);
        std::fs::write(root.join("old.txt"), b"x").expect("write old.txt");
        h.grant(member_id, share_id, "", Perms::DELETE);

        let server = h.server();
        let reply = server.handle(
            &h.ctx(member_id),
            1,
            req(
                1,
                VfsRequest::Delete {
                    path: "Drop/old.txt".to_string(),
                },
            ),
        );
        assert_eq!(reply, VfsReply::Delete);
        assert!(!root.join("old.txt").exists());
    }

    #[test]
    fn delete_without_delete_perm_is_denied_and_file_survives() {
        let h = Harness::new();
        let (member_id, _) = h.add_active_member("Alex");
        let share_id = h.add_share(
            "Drop",
            "Drop",
            ShareFlags {
                read_only: false,
                allow_upload: true,
                show_hidden: false,
            },
        );
        let root = h.share_real_root(share_id);
        std::fs::write(root.join("old.txt"), b"x").expect("write old.txt");
        h.grant(member_id, share_id, "", Perms::BROWSE | Perms::DOWNLOAD); // no delete

        let server = h.server();
        let reply = server.handle(
            &h.ctx(member_id),
            1,
            req(
                1,
                VfsRequest::Delete {
                    path: "Drop/old.txt".to_string(),
                },
            ),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::NotFound
            }
        );
        assert!(root.join("old.txt").exists());
    }
}
