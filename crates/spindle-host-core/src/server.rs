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
use crate::limits::{FreeSpaceProbe, UnlimitedFreeSpace, UploadLimits};
use crate::mount::{MountLookup, MountNode, MountTable};
use crate::ratelimit::{RateLimitConfig, RateLimiter};
use crate::upload::{manifest_signing_bytes, UploadSession, UploadSessions};
use cap_std::fs::OpenOptions;
use spindle_core::{verify_bytes, Fingerprint, VerifyingKey};
use spindle_proto::{
    DirEntry, EntryKind, ProtoError, VfsErrorCode, VfsPerms, VfsReply, VfsRequest,
    VfsRequestEnvelope, MAX_LIST_PAGE, MAX_READ_CHUNK, MAX_UPLOAD_CHUNK, MIN_PROTOCOL_VERSION,
    UPLOAD_SESSION_TTL_SECS,
};
use spindle_vfs::algebra::{AccessDecision, EffectiveGrants, GrantsVersion};
use spindle_vfs::audit::AuditEntry;
use spindle_vfs::confine::{self, identity as confine_identity, UploadOutcome};
use spindle_vfs::model::{Member, MemberStatus, Perms, Share, VirtualPath};
use spindle_vfs::store::Store;
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write as _};

/// Identifies the calling session for pipeline purposes: which member is acting, and which of
/// their devices, for the audit trail and for the per-request device-revocation check (Step 2b of
/// [`VfsRpcServer::handle`]). Authenticating a transport-level session down to these two values,
/// and keeping them stable for the lifetime of that session, happens in `crate::session`'s
/// `VfsSessionHandler::session_context` — the production `SessionHandler`, which builds this from
/// the QUIC peer's device fingerprint and which `spindle-hostd` wires up as the real host's
/// handler — `VfsRpcServer` trusts them completely, exactly as scoped
/// (`spindle_proto::vfs_rpc`'s module doc comment: "VFS RPC messages travel inside an
/// already-authenticated ... session"). `device_fp` is not optional: there is no legitimate
/// device-less session (see Step 2b's comment for why), and making one unrepresentable in this
/// type is what closes the fail-open gap a `None` used to leave.
#[derive(Debug, Clone, Copy)]
pub struct SessionContext {
    pub member_id: spindle_vfs::model::MemberId,
    pub device_fp: Fingerprint,
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

/// The host-side VFS RPC enforcement pipeline. The store holder is a type parameter so the same
/// server serves both shapes: `VfsRpcServer<&Store>` for a caller that already owns a `Store` and
/// only lends it (tests, single-threaded callers), and `VfsRpcServer<Store>` for a per-session
/// server that must live in a `Send` future — SQLite supports several connections to one database
/// file, the same reasoning `SqliteDeviceLookup`'s doc comment already gives for keeping the
/// connect path off the RPC path's connection. Plus this crate's caches/state
/// (`crate::cache::GrantsCache` for the host-wide shares/entitlements snapshot,
/// `crate::identity_cache::IdentityCache` for the stat→read TOCTOU baseline,
/// `crate::upload::UploadSessions` for in-flight upload sessions, `crate::ratelimit::RateLimiter`
/// for the per-caller VFS-RPC-entry-point throttle) plus this slice's configuration
/// (`crate::limits::UploadLimits`, a `crate::limits::FreeSpaceProbe`) — see each module's doc
/// comment for what is and is not cached/configurable and why.
pub struct VfsRpcServer<S> {
    store: S,
    grants_cache: GrantsCache,
    identity_cache: IdentityCache,
    upload_sessions: UploadSessions,
    limits: UploadLimits,
    free_space_probe: Box<dyn FreeSpaceProbe + Send>,
    rate_limiter: RateLimiter,
}

impl<S: Borrow<Store>> VfsRpcServer<S> {
    /// The `Store` this server enforces against, whether it was given a borrow or handed an owned
    /// one. Every read below goes through here rather than touching the field, so the same body
    /// serves `VfsRpcServer<&Store>` and `VfsRpcServer<Store>` — see this type's doc comment for
    /// why both exist.
    fn store(&self) -> &Store {
        self.store.borrow()
    }

    /// Generous defaults throughout: unlimited free-space reporting (see
    /// `crate::limits`'s module doc comment for why a real OS probe is not wired in here), default
    /// `UploadLimits`, default `RateLimitConfig`. Use [`Self::with_limits`] to override any of
    /// these (production wiring, or a test exercising `quota_exceeded`/`storage_full`/`throttled`
    /// with small numbers).
    pub fn new(store: S) -> Self {
        Self::with_limits(
            store,
            UploadLimits::default(),
            Box::new(UnlimitedFreeSpace),
            RateLimitConfig::default(),
        )
    }

    pub fn with_limits(
        store: S,
        limits: UploadLimits,
        free_space_probe: Box<dyn FreeSpaceProbe + Send>,
        rate_limit_config: RateLimitConfig,
    ) -> Self {
        VfsRpcServer {
            store,
            grants_cache: GrantsCache::new(),
            identity_cache: IdentityCache::new(),
            upload_sessions: UploadSessions::new(),
            limits,
            free_space_probe,
            rate_limiter: RateLimiter::new(rate_limit_config),
        }
    }

    /// Removes every upload session whose TTL has passed as of `now` (DESIGN.md §A8: 48h),
    /// deleting each one's staged bytes best-effort. A plain callable method, not a background
    /// timer — see `crate::upload`'s module doc comment: wiring this to a periodic scheduler tick
    /// is application territory, out of scope for this transport-agnostic, pure server.
    pub fn gc_expired_upload_sessions(&self, now: u64) {
        for session in self.upload_sessions.gc_expired(now) {
            self.discard_staging_bytes(&session);
        }
    }

    fn discard_staging_bytes(&self, session: &UploadSession) {
        if let Ok(Some(share)) = self.store().get_share(session.share_id) {
            if let Ok(dir) = confine::open_share_root(&share.real_root) {
                let _ = dir.remove_file(confine::staging_name(&session.id));
            }
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
        // Step 0: per-caller rate limit (DESIGN.md §A5's token-bucket mechanism, adapted to this
        // post-auth layer — see `crate::ratelimit`'s module doc comment). Checked before even the
        // version gate: a throttled caller should not learn anything else about why a request
        // failed, and this is the cheapest possible check (no store access, no decoding of
        // `env.request`'s payload beyond what's needed for the audit row).
        let rl_key = rate_limit_key(ctx);
        if !self.rate_limiter.try_acquire(&rl_key, ts) {
            self.audit(
                ts,
                None,
                Some(ctx.device_fp),
                op_name(&env.request),
                request_path(&env.request),
                None,
                "denied:throttled",
            );
            return VfsReply::Error {
                code: VfsErrorCode::Throttled,
            };
        }

        // Step 1: version check. Zero store access — the cheapest possible rejection, and (by
        // construction) the one whose audit entry cannot carry a resolved member fingerprint yet
        // (see this crate's `lib.rs` module doc comment: doing a store lookup purely to enrich
        // this audit row would defeat the point of checking the version first).
        if env.v < MIN_PROTOCOL_VERSION {
            self.audit(
                ts,
                None,
                Some(ctx.device_fp),
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
        let member = match self.store().get_member(ctx.member_id) {
            Ok(Some(m)) => m,
            Ok(None) => {
                self.audit(
                    ts,
                    None,
                    Some(ctx.device_fp),
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
                    Some(ctx.device_fp),
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
                Some(ctx.device_fp),
                op_name(&env.request),
                request_path(&env.request),
                None,
                "denied:member_not_active",
            );
            return VfsReply::Error {
                code: VfsErrorCode::NotFound,
            };
        }

        // Step 2b: device active? DESIGN.md §A4: "the host rejects envelopes/VFS requests from
        // revoked keys per request (authoritative)", where a revocation names `root_fp |
        // device_fp` — i.e. device-level revocation is a distinct, independently-enforced half of
        // §A4, not implied by the member-active check above (a still-Active member can have one
        // revoked device among several). `member.devices` is part of the same fresh
        // `store.get_member` read as the status check just above, so this costs no extra store
        // round-trip and is checked fresh every request for the same reason member liveness is
        // (never served from the grants_version/cap_epoch-keyed cache; see `crate::cache`'s module
        // doc comment). This check is unconditional: `SessionContext::device_fp` is a plain
        // `Fingerprint`, not an `Option`, so there is no "no device supplied" case left to fall
        // through on — DESIGN.md :1022 records that the helper's callout epoch check was demoted
        // to best-effort precisely because this per-request check is the authoritative one, so
        // this gate cannot itself have a silent bypass. That type is sound because there is no
        // legitimate device-less session in production: the sole production constructor,
        // `VfsSessionHandler::session_context`, only ever runs with a peer-supplied device
        // fingerprint, and it resolves the member *through* `active_member_for_device`, which
        // itself requires the device to exist and be unrevoked before a `SessionContext` is ever
        // built.
        match member.devices.iter().find(|d| d.device_fp == ctx.device_fp) {
            Some(d) if d.revoked => {
                self.audit(
                    ts,
                    Some(member.root_fp),
                    Some(ctx.device_fp),
                    op_name(&env.request),
                    request_path(&env.request),
                    None,
                    "denied:device_revoked",
                );
                return VfsReply::Error {
                    code: VfsErrorCode::NotFound,
                };
            }
            Some(_) => {}
            None => {
                self.audit(
                    ts,
                    Some(member.root_fp),
                    Some(ctx.device_fp),
                    op_name(&env.request),
                    request_path(&env.request),
                    None,
                    "denied:unknown_device",
                );
                return VfsReply::Error {
                    code: VfsErrorCode::NotFound,
                };
            }
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
            VfsRequest::UploadOpen {
                path,
                size,
                hash,
                manifest_sig,
            } => self.handle_upload_open(ts, ctx, &member, path, *size, hash, manifest_sig),
            VfsRequest::UploadChunk {
                session_id,
                offset,
                data,
            } => self.handle_upload_chunk(ts, ctx, &member, session_id, *offset, data),
            VfsRequest::UploadCommit { session_id } => {
                self.handle_upload_commit(ts, ctx, &member, session_id)
            }
            VfsRequest::UploadAbort { session_id } => {
                self.handle_upload_abort(ts, ctx, &member, session_id)
            }
        }
    }

    // -------------------------------------------------------------------------------------
    // whoami
    // -------------------------------------------------------------------------------------

    fn handle_whoami(&self, ts: u64, ctx: &SessionContext, member: &Member) -> VfsReply {
        let (shares, entitlements) = self.grants_cache.get(self.store()).unwrap_or_default();
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
            Some(ctx.device_fp),
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
        let (shares, entitlements) = match self.grants_cache.get(self.store()) {
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
        let version = GrantsVersion(self.store().grants_version().unwrap_or(0));
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
            Some(ctx.device_fp),
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
        let (shares, entitlements) = match self.grants_cache.get(self.store()) {
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
        let version = GrantsVersion(self.store().grants_version().unwrap_or(0));
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
                    Some(ctx.device_fp),
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
        let (shares, entitlements) = match self.grants_cache.get(self.store()) {
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
        let version = GrantsVersion(self.store().grants_version().unwrap_or(0));
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
                    Some(ctx.device_fp),
                    "read",
                    Some(path),
                    Some(data.len() as u64),
                    "ok",
                );
                VfsReply::Read { data, eof }
            }
            Err((outcome, code)) => {
                self.deny_with_code(ts, member, ctx, "read", Some(path), outcome, code)
            }
        }
    }

    /// Reads one bounded chunk (≤ [`MAX_READ_CHUNK`]) at `offset`, through a freshly opened `Dir`,
    /// enforcing DESIGN.md §A4b's stat→read TOCTOU rule via `crate::identity_cache::IdentityCache`
    /// both *before* the read (compare against the last observation for this member/path, if any)
    /// and *after* it (compare against the identity captured immediately before this read — the
    /// per-chunk-boundary half of the same rule, applied at this RPC call's own boundary since
    /// transport-level chunk streaming is out of scope here).
    ///
    /// Returns `(outcome, code)` on failure rather than a bare outcome string — v0.9.10 remap
    /// (was always `VfsErrorCode::NotFound` via the generic [`Self::deny`] helper, before
    /// `file_changed` existed on the wire — see `spindle_proto::vfs_rpc`'s module doc comment
    /// "Remapped from slice 3"): a TOCTOU identity mismatch is DESIGN.md §A4b's stat→read
    /// identity-check abort, which now has its own dedicated code distinct from a genuine
    /// not-found.
    fn read_chunk(
        &self,
        member: &Member,
        share: &Share,
        subpath: &VirtualPath,
        offset: u64,
        len: u32,
    ) -> Result<(Vec<u8>, bool), (&'static str, VfsErrorCode)> {
        fn not_found<E>(_: E) -> (&'static str, VfsErrorCode) {
            ("denied:not_found", VfsErrorCode::NotFound)
        }
        let dir = confine::open_share_root(&share.real_root).map_err(not_found)?;
        let relative = confine_relative(subpath);
        let meta = confine_identity::stat_through_dir(&dir, &relative).map_err(not_found)?;
        if !meta.is_file() {
            return Err(("denied:not_found", VfsErrorCode::NotFound));
        }
        let pre_identity =
            confine_identity::resolve_identity(&dir, &relative).map_err(not_found)?;
        if self
            .identity_cache
            .mismatches(member.member_id, share.share_id, subpath, &pre_identity)
        {
            self.identity_cache
                .forget(member.member_id, share.share_id, subpath);
            return Err(("denied:identity_changed", VfsErrorCode::FileChanged));
        }

        let clamped_len = len.min(MAX_READ_CHUNK) as usize;
        let mut file = dir.open(&relative).map_err(not_found)?;
        file.seek(SeekFrom::Start(offset)).map_err(not_found)?;
        let mut buf = vec![0u8; clamped_len];
        let n = file.read(&mut buf).map_err(not_found)?;
        buf.truncate(n);
        let eof = offset.saturating_add(n as u64) >= meta.len();

        let post_identity =
            confine_identity::resolve_identity(&dir, &relative).map_err(not_found)?;
        if post_identity != pre_identity {
            self.identity_cache
                .forget(member.member_id, share.share_id, subpath);
            return Err(("denied:identity_changed", VfsErrorCode::FileChanged));
        }
        self.identity_cache
            .record(member.member_id, share.share_id, subpath, post_identity);
        Ok((buf, eof))
    }

    // -------------------------------------------------------------------------------------
    // mkdir
    // -------------------------------------------------------------------------------------

    fn handle_mkdir(&self, ts: u64, ctx: &SessionContext, member: &Member, path: &str) -> VfsReply {
        let (shares, entitlements) = match self.grants_cache.get(self.store()) {
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
        let version = GrantsVersion(self.store().grants_version().unwrap_or(0));
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
                    Some(ctx.device_fp),
                    "mkdir",
                    Some(path),
                    None,
                    "ok",
                );
                VfsReply::Mkdir
            }
            // v0.9.10 remap (was `VfsErrorCode::UploadRejected` as a slice-3 stopgap, before
            // `already_exists` existed on the wire — see `spindle_proto::vfs_rpc`'s module doc
            // comment "Remapped from slice 3"): a name collision without `delete` is exactly
            // DESIGN.md §A4b's "collision == overwrite; overwrite requires delete" rule, which now
            // has its own dedicated code.
            Ok(false) => self.deny_with_code(
                ts,
                member,
                ctx,
                "mkdir",
                Some(path),
                "denied:exists_needs_delete",
                VfsErrorCode::AlreadyExists,
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
        let (shares, entitlements) = match self.grants_cache.get(self.store()) {
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
        let version = GrantsVersion(self.store().grants_version().unwrap_or(0));
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
        // Stage 6 slice 5 (uploaded_files ledger, `spindle_vfs::store::schema::SCHEMA_V6`): the
        // counter decrement below now comes from `Store::remove_uploads_under` after the
        // filesystem removal succeeds, not from a stat of the file(s) being removed. An earlier
        // revision of this comment snapshotted real bytes-on-disk here because computing a
        // directory's recursive size would be a full directory walk on this crate's hot path —
        // that rationale no longer applies to the counter: `uploaded_files` gives the exact
        // recursive total for any subtree via one indexed `DELETE`, with no filesystem walk at
        // all, and (unlike a stat of the real file) it only ever counts bytes that were actually
        // counted *up* by the upload path in the first place — see the `Ok(())` arm below.
        match confine::remove_confined(&dir, &subpath.to_path_string()) {
            Ok(()) => {
                self.identity_cache
                    .forget(member.member_id, share.share_id, &subpath);
                // Drive the decrement from the ledger, not the filesystem: `remove_uploads_under`
                // removes every `uploaded_files` row at or beneath `subpath` (matching
                // `remove_confined`'s own `remove_dir_all` on a directory target) and refunds each
                // row's own uploader. This is the actual bug fix over the old stat-based approach,
                // which decremented `share_upload_bytes` by the on-disk size even for content the
                // owner placed directly on the real filesystem — never counted *up* into the
                // counter, so counting it down was an overcount (see `spindle_vfs::store`'s
                // upload-quota module comment). It also refunds `member_upload_bytes` for the
                // first time, previously out of scope because nothing recorded who the uploader
                // was — closed by `uploaded_files`.
                //
                // The filesystem delete already succeeded by this point, so a ledger failure here
                // must not fail the RPC (fail-open) — but per this ticket it must not be silently
                // discarded either, so it is folded into this call's own audit outcome instead of
                // a bare `let _ = ...`. Same reasoning this file's own `fn audit` gives, in the
                // inline comment on its `AuditEntry` append, for audit-append failures themselves
                // (deliberately unversioned by line number: this comment has already gone stale once).
                let ledger_outcome = match self
                    .store()
                    .remove_uploads_under(share.share_id, &subpath.to_path_string())
                {
                    Ok(_) => "ok",
                    Err(_) => "ok:counter_drift",
                };
                self.audit(
                    ts,
                    Some(member.root_fp),
                    Some(ctx.device_fp),
                    "delete",
                    Some(path),
                    None,
                    ledger_outcome,
                );
                VfsReply::Delete
            }
            Err(_) => self.deny(ts, member, ctx, "delete", Some(path), "denied:not_found"),
        }
    }

    // -------------------------------------------------------------------------------------
    // upload_open / upload_chunk / upload_commit / upload_abort (Stage 6 slice 4, DESIGN.md §A8
    // "Transfer manager" / "Upload sessions", §A4b upload edge rules)
    // -------------------------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn handle_upload_open(
        &self,
        ts: u64,
        ctx: &SessionContext,
        member: &Member,
        path: &str,
        size: u64,
        hash: &[u8],
        manifest_sig: &[u8],
    ) -> VfsReply {
        let (shares, entitlements) = match self.grants_cache.get(self.store()) {
            Ok(v) => v,
            Err(_) => {
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "upload_open",
                    Some(path),
                    "error:store_read_failed",
                )
            }
        };
        let grants_version = self.store().grants_version().unwrap_or(0);
        let cap_epoch = self.store().cap_epoch().unwrap_or(0);
        let version = GrantsVersion(grants_version);
        let effective = EffectiveGrants::compute(member, &entitlements, version);
        let mount_table = MountTable::build(shares);

        let Ok(vp) = VirtualPath::parse(path) else {
            return self.deny(
                ts,
                member,
                ctx,
                "upload_open",
                Some(path),
                "denied:not_found",
            );
        };
        let (share, subpath) = match mount_table.resolve(&vp) {
            MountLookup::Share { share, subpath } => (share, subpath),
            MountLookup::Intermediate(_) | MountLookup::NotFound => {
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "upload_open",
                    Some(path),
                    "denied:not_found",
                )
            }
        };

        // Upload implies resolve-without-listing (drop-box, DESIGN.md §A4b): only `upload` (not
        // `browse`) is required here.
        let decision = effective.resolve_access(share, &subpath);
        if !decision.perms().contains(Perms::UPLOAD)
            || !share.flags.allow_upload
            || share.flags.read_only
        {
            return self.deny(
                ts,
                member,
                ctx,
                "upload_open",
                Some(path),
                "denied:not_found",
            );
        }

        let member_bytes = self
            .store()
            .member_upload_bytes(member.member_id)
            .unwrap_or(0);
        if member_bytes.saturating_add(size) > self.limits.max_member_upload_bytes {
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_open",
                Some(path),
                "denied:quota_exceeded_member",
                VfsErrorCode::QuotaExceeded,
            );
        }
        let share_bytes = self.store().share_upload_bytes(share.share_id).unwrap_or(0);
        if share_bytes.saturating_add(size) > self.limits.max_share_upload_bytes {
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_open",
                Some(path),
                "denied:quota_exceeded_share",
                VfsErrorCode::QuotaExceeded,
            );
        }

        if !self.verify_manifest_signature(Some(ctx.device_fp), path, size, hash, manifest_sig) {
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_open",
                Some(path),
                "denied:bad_manifest_signature",
                VfsErrorCode::UploadRejected,
            );
        }

        let session = self.upload_sessions.open_or_resume(
            member.member_id,
            share.share_id,
            &subpath,
            size,
            hash,
            manifest_sig,
            Some(ctx.device_fp),
            ts,
            UPLOAD_SESSION_TTL_SECS,
            grants_version,
            cap_epoch,
        );

        let dir = match confine::open_share_root(&share.real_root) {
            Ok(d) => d,
            Err(_) => {
                self.upload_sessions.remove(&session.id);
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "upload_open",
                    Some(path),
                    "denied:not_found",
                );
            }
        };
        if session.offset == 0 && dir.create(confine::staging_name(&session.id)).is_err() {
            self.upload_sessions.remove(&session.id);
            return self.deny(
                ts,
                member,
                ctx,
                "upload_open",
                Some(path),
                "denied:not_found",
            );
        }

        self.audit(
            ts,
            Some(member.root_fp),
            Some(ctx.device_fp),
            "upload_open",
            Some(path),
            None,
            "ok",
        );
        VfsReply::UploadOpen {
            session_id: session.id,
            offset: session.offset,
        }
    }

    /// DESIGN.md §A8: the upload manifest (`path`+`size`+`hash`) is "signed ... by the sending
    /// device's key" — checked against that device's `sign_pk` (Stage 6 slice 4's addition to
    /// `spindle_vfs::model::Device`; see this slice's report for the schema-gap finding). A
    /// session with no signer device (e.g. a test `SessionContext` carrying no `device_fp`) can
    /// never pass this check, by construction — DESIGN.md gives no alternative identity to verify
    /// an upload manifest against, so "no device" is treated as "cannot be authorized" rather than
    /// silently skipping the check.
    fn verify_manifest_signature(
        &self,
        device_fp: Option<Fingerprint>,
        path: &str,
        size: u64,
        hash: &[u8],
        sig: &[u8],
    ) -> bool {
        let Some(fp) = device_fp else {
            return false;
        };
        let Ok(Some(sign_pk)) = self.store().device_sign_pk(fp) else {
            return false;
        };
        let Ok(arr): Result<[u8; 32], _> = sign_pk.as_slice().try_into() else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&arr) else {
            return false;
        };
        let msg = manifest_signing_bytes(path, size, hash);
        verify_bytes(&vk, &msg, sig).is_ok()
    }

    /// True if neither `grants_version` nor `cap_epoch` has moved since `session` was opened (or
    /// last resumed) — DESIGN.md §A8: "an entitlement change mid-transfer aborts the session".
    fn entitlement_unchanged(&self, session: &UploadSession) -> bool {
        let grants_version = self.store().grants_version().unwrap_or(0);
        let cap_epoch = self.store().cap_epoch().unwrap_or(0);
        session.grants_version_at_open == grants_version && session.cap_epoch_at_open == cap_epoch
    }

    /// Removes `session` and best-effort discards its staged bytes — the shared "abort and GC"
    /// action DESIGN.md §A8 requires on an entitlement change mid-transfer, factored out since
    /// both `upload_chunk` and `upload_commit` need it.
    fn abort_and_gc(&self, session: &UploadSession) {
        self.upload_sessions.remove(&session.id);
        self.discard_staging_bytes(session);
    }

    fn handle_upload_chunk(
        &self,
        ts: u64,
        ctx: &SessionContext,
        member: &Member,
        session_id: &[u8],
        offset: u64,
        data: &[u8],
    ) -> VfsReply {
        let Some(session) = self.upload_sessions.get_owned(session_id, member.member_id) else {
            return self.deny(ts, member, ctx, "upload_chunk", None, "denied:not_found");
        };
        let path_str = session.subpath.to_path_string();

        if !self.entitlement_unchanged(&session) {
            self.abort_and_gc(&session);
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_chunk",
                Some(&path_str),
                "denied:grants_changed",
                VfsErrorCode::GrantsChanged,
            );
        }

        if offset != session.offset {
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_chunk",
                Some(&path_str),
                "denied:offset_mismatch",
                VfsErrorCode::FileChanged,
            );
        }
        if data.len() as u64 > MAX_UPLOAD_CHUNK as u64 {
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_chunk",
                Some(&path_str),
                "denied:chunk_too_large",
                VfsErrorCode::UploadRejected,
            );
        }
        let new_offset = offset.saturating_add(data.len() as u64);
        if new_offset > session.size {
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_chunk",
                Some(&path_str),
                "denied:oversize",
                VfsErrorCode::UploadRejected,
            );
        }

        let Ok(Some(share)) = self.store().get_share(session.share_id) else {
            return self.deny(
                ts,
                member,
                ctx,
                "upload_chunk",
                Some(&path_str),
                "denied:not_found",
            );
        };

        // Free-space floor, checked BEFORE accepting these chunk bytes (task brief wording).
        if self.free_space_probe.available_bytes(&share.real_root) < self.limits.min_free_bytes {
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_chunk",
                Some(&path_str),
                "denied:storage_full",
                VfsErrorCode::StorageFull,
            );
        }

        let dir = match confine::open_share_root(&share.real_root) {
            Ok(d) => d,
            Err(_) => {
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "upload_chunk",
                    Some(&path_str),
                    "denied:not_found",
                )
            }
        };
        let staging = confine::staging_name(&session.id);
        let mut opts = OpenOptions::new();
        opts.write(true);
        let mut file = match dir.open_with(&staging, &opts) {
            Ok(f) => f,
            Err(_) => {
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "upload_chunk",
                    Some(&path_str),
                    "denied:not_found",
                )
            }
        };
        if file.seek(SeekFrom::Start(offset)).is_err() || file.write_all(data).is_err() {
            return self.deny(
                ts,
                member,
                ctx,
                "upload_chunk",
                Some(&path_str),
                "error:staging_write_failed",
            );
        }

        self.upload_sessions.set_offset(&session.id, new_offset);
        self.audit(
            ts,
            Some(member.root_fp),
            Some(ctx.device_fp),
            "upload_chunk",
            Some(&path_str),
            Some(data.len() as u64),
            "ok",
        );
        VfsReply::UploadChunk { offset: new_offset }
    }

    fn handle_upload_commit(
        &self,
        ts: u64,
        ctx: &SessionContext,
        member: &Member,
        session_id: &[u8],
    ) -> VfsReply {
        let Some(session) = self.upload_sessions.get_owned(session_id, member.member_id) else {
            return self.deny(ts, member, ctx, "upload_commit", None, "denied:not_found");
        };
        // The *full* virtual path (mount + subpath) — must match exactly what `upload_open`
        // signed the manifest over (DESIGN.md §A8 "path"), not `session.subpath` alone (which is
        // share-relative and omits the share's own mount prefix).
        let path_str = match self.store().get_share(session.share_id) {
            Ok(Some(share)) => combine_mount_and_subpath(&share, &session.subpath).to_path_string(),
            _ => session.subpath.to_path_string(),
        };

        if !self.entitlement_unchanged(&session) {
            self.abort_and_gc(&session);
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_commit",
                Some(&path_str),
                "denied:grants_changed",
                VfsErrorCode::GrantsChanged,
            );
        }

        if session.offset != session.size {
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_commit",
                Some(&path_str),
                "denied:incomplete",
                VfsErrorCode::FileChanged,
            );
        }

        let Ok(Some(share)) = self.store().get_share(session.share_id) else {
            return self.deny(
                ts,
                member,
                ctx,
                "upload_commit",
                Some(&path_str),
                "denied:not_found",
            );
        };

        let (shares, entitlements) = match self.grants_cache.get(self.store()) {
            Ok(v) => v,
            Err(_) => {
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "upload_commit",
                    Some(&path_str),
                    "error:store_read_failed",
                )
            }
        };
        let _ = shares;
        let version = GrantsVersion(self.store().grants_version().unwrap_or(0));
        let effective = EffectiveGrants::compute(member, &entitlements, version);
        let decision = effective.resolve_access(&share, &session.subpath);
        let can_delete = decision.perms().contains(Perms::DELETE);
        if !decision.perms().contains(Perms::UPLOAD)
            || !share.flags.allow_upload
            || share.flags.read_only
        {
            self.abort_and_gc(&session);
            return self.deny(
                ts,
                member,
                ctx,
                "upload_commit",
                Some(&path_str),
                "denied:not_found",
            );
        }

        let dir = match confine::open_share_root(&share.real_root) {
            Ok(d) => d,
            Err(_) => {
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "upload_commit",
                    Some(&path_str),
                    "denied:not_found",
                )
            }
        };
        let staging = confine::staging_name(&session.id);

        // Whole-file hash check — this crate's chosen algorithm is SHA-256, computed via
        // `spindle_core::Fingerprint::of_parts`'s existing hasher (not a new dependency: this
        // crate already depends on `spindle-core`, and `Fingerprint` itself IS a SHA-256 digest —
        // see `spindle_core::fingerprint`'s module doc comment). DESIGN.md's `hash` field is
        // opaque bytes with no algorithm specified; documented here as this slice's choice.
        let staged_bytes = match dir.read(&staging) {
            Ok(b) => b,
            Err(_) => {
                return self.deny(
                    ts,
                    member,
                    ctx,
                    "upload_commit",
                    Some(&path_str),
                    "denied:not_found",
                )
            }
        };
        let actual_hash = Fingerprint::of_parts(&[&staged_bytes]).to_vec();
        if actual_hash != session.hash {
            self.abort_and_gc(&session);
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_commit",
                Some(&path_str),
                "denied:hash_mismatch",
                VfsErrorCode::UploadRejected,
            );
        }

        // DESIGN.md §A8: "signed manifest verified BEFORE move-into-place" — re-verified here (not
        // only at `upload_open`), so a mid-transfer device-key change/revocation is caught before
        // the bytes ever land.
        if !self.verify_manifest_signature(
            Some(ctx.device_fp),
            &path_str,
            session.size,
            &session.hash,
            &session.manifest_sig,
        ) {
            self.abort_and_gc(&session);
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_commit",
                Some(&path_str),
                "denied:bad_manifest_signature",
                VfsErrorCode::UploadRejected,
            );
        }

        // Quota re-check: usage may have grown since `upload_open` (other sessions committing
        // concurrently).
        let member_bytes = self
            .store()
            .member_upload_bytes(member.member_id)
            .unwrap_or(0);
        if member_bytes.saturating_add(session.size) > self.limits.max_member_upload_bytes {
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_commit",
                Some(&path_str),
                "denied:quota_exceeded_member",
                VfsErrorCode::QuotaExceeded,
            );
        }
        let share_bytes = self.store().share_upload_bytes(share.share_id).unwrap_or(0);
        if share_bytes.saturating_add(session.size) > self.limits.max_share_upload_bytes {
            return self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_commit",
                Some(&path_str),
                "denied:quota_exceeded_share",
                VfsErrorCode::QuotaExceeded,
            );
        }

        match confine::finalize_upload(
            &dir,
            &staging,
            &session.subpath.to_path_string(),
            can_delete,
        ) {
            Ok(UploadOutcome::Landed(landed_name)) => {
                self.upload_sessions.remove(&session.id);
                self.identity_cache
                    .forget(member.member_id, share.share_id, &session.subpath);
                // The ledger must record the name the file actually landed under, not the name
                // the member requested: on a fold-collision overwrite, `finalize_upload` renames
                // onto the *existing* dirent's spelling (see its doc comment), so recording the
                // requested spelling would store a `uploaded_files.subpath` that does not exist on
                // a case-sensitive filesystem. Rebuild the full virtual path with the last
                // component replaced by the landed name, keeping the parent components as-is.
                let landed_subpath = match landed_name.to_str() {
                    Some(landed_str) => session
                        .subpath
                        .parent()
                        .unwrap_or_else(VirtualPath::root)
                        .join(landed_str),
                    // A non-UTF-8 landed name can only occur in the `Fresh` case (equal to the
                    // requested name): `existing_entry_colliding` skips entries that fail
                    // `to_str`, so a fold-collision `Overwrites` name is always valid UTF-8. Best
                    // effort: fall back to the requested spelling, which is correct here anyway.
                    None => session.subpath.clone(),
                };
                // `record_upload` upserts the `uploaded_files` ledger row and applies both
                // counter deltas in one transaction, including the subtle different-uploader
                // overwrite case (see its doc comment in `spindle_vfs::store`). The staged file
                // has already been moved into place by this point, so a ledger failure here must
                // not fail the RPC (fail-open) — but per this ticket it must not be silently
                // discarded either, so it is folded into this call's own audit outcome instead of
                // a bare `let _ = ...`. Same reasoning this file's own `fn audit` gives, in the
                // inline comment on its `AuditEntry` append, for audit-append failures themselves
                // (deliberately unversioned by line number: this comment has already gone stale once).
                let ledger_outcome = match self.store().record_upload(
                    share.share_id,
                    member.member_id,
                    &landed_subpath.to_path_string(),
                    session.size,
                ) {
                    Ok(()) => "ok",
                    Err(_) => "ok:counter_drift",
                };
                self.audit(
                    ts,
                    Some(member.root_fp),
                    Some(ctx.device_fp),
                    "upload_commit",
                    Some(&path_str),
                    Some(session.size),
                    ledger_outcome,
                );
                VfsReply::UploadCommit
            }
            // Collision without `delete` (DESIGN.md §A4b "collision == overwrite; overwrite
            // requires delete"): the session survives so the caller can delete the conflicting
            // entry and retry `upload_commit` without re-uploading any bytes.
            Ok(UploadOutcome::Refused) => self.deny_with_code(
                ts,
                member,
                ctx,
                "upload_commit",
                Some(&path_str),
                "denied:exists_needs_delete",
                VfsErrorCode::AlreadyExists,
            ),
            Err(_) => {
                self.abort_and_gc(&session);
                self.deny(
                    ts,
                    member,
                    ctx,
                    "upload_commit",
                    Some(&path_str),
                    "denied:not_found",
                )
            }
        }
    }

    fn handle_upload_abort(
        &self,
        ts: u64,
        ctx: &SessionContext,
        member: &Member,
        session_id: &[u8],
    ) -> VfsReply {
        let Some(session) = self.upload_sessions.get_owned(session_id, member.member_id) else {
            return self.deny(ts, member, ctx, "upload_abort", None, "denied:not_found");
        };
        let path_str = session.subpath.to_path_string();
        self.abort_and_gc(&session);
        self.audit(
            ts,
            Some(member.root_fp),
            Some(ctx.device_fp),
            "upload_abort",
            Some(&path_str),
            None,
            "ok",
        );
        VfsReply::UploadAbort
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
            Some(ctx.device_fp),
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
        let _ = self.store().audit().append(entry);
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
        VfsRequest::UploadOpen { .. } => "upload_open",
        VfsRequest::UploadChunk { .. } => "upload_chunk",
        VfsRequest::UploadCommit { .. } => "upload_commit",
        VfsRequest::UploadAbort { .. } => "upload_abort",
    }
}

fn request_path(req: &VfsRequest) -> Option<&str> {
    match req {
        VfsRequest::List { path, .. }
        | VfsRequest::Stat { path }
        | VfsRequest::Read { path, .. }
        | VfsRequest::Mkdir { path }
        | VfsRequest::Delete { path }
        | VfsRequest::UploadOpen { path, .. } => Some(path.as_str()),
        VfsRequest::Whoami
        | VfsRequest::UploadChunk { .. }
        | VfsRequest::UploadCommit { .. }
        | VfsRequest::UploadAbort { .. } => None,
    }
}

/// The per-caller key [`RateLimiter`] buckets on (`crate::ratelimit`'s module doc comment): the
/// caller's device fingerprint, so distinct devices of the same member each get their own
/// independent bucket rather than colliding.
fn rate_limit_key(ctx: &SessionContext) -> Vec<u8> {
    ctx.device_fp.to_vec()
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
    use spindle_core::identity::DeviceKey;
    use spindle_core::SigningKey;
    use spindle_vfs::model::{DevicePublicKeys, MemberId, ShareFlags, ShareId};
    use spindle_vfs::store::Store;
    use std::cell::RefCell;
    use tempfile::TempDir;

    /// Shared test scaffolding: an in-memory `Store` plus a disposable real directory tree for
    /// share roots, both dropped together at the end of each test.
    struct Harness {
        sandbox: TempDir,
        store: Store,
        /// Lazily populated by [`Self::ctx`]: each member gets exactly one enrolled "default"
        /// device the first time a context is requested for it, then the same fingerprint on
        /// every later call — see `ctx`'s doc comment for why `SessionContext::device_fp` can no
        /// longer be `None`.
        default_devices: RefCell<BTreeMap<MemberId, Fingerprint>>,
    }

    impl Harness {
        fn new() -> Self {
            Harness {
                sandbox: tempfile::tempdir().expect("tempdir"),
                store: Store::open_in_memory().expect("open in-memory store"),
                default_devices: RefCell::new(BTreeMap::new()),
            }
        }

        fn server(&self) -> VfsRpcServer<&Store> {
            VfsRpcServer::new(&self.store)
        }

        fn server_with_limits(
            &self,
            limits: UploadLimits,
            probe: Box<dyn FreeSpaceProbe + Send>,
            rate_limit_config: RateLimitConfig,
        ) -> VfsRpcServer<&Store> {
            VfsRpcServer::with_limits(&self.store, limits, probe, rate_limit_config)
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

        /// The device fingerprint [`Self::ctx`] uses for `member_id`: enrolled (with no pinned
        /// keys — plain pipeline tests never verify an upload-manifest signature) the first time
        /// it's asked for, and memoized after that so repeated `ctx(member_id)` calls within one
        /// test keep returning the same device rather than silently enrolling a new one each
        /// time. `add_device` only requires that the member row exist, not that it be `Active`, so
        /// this also works for the not-yet-active/invited-member tests that call `ctx` directly.
        fn default_device(&self, member_id: MemberId) -> Fingerprint {
            if let Some(fp) = self.default_devices.borrow().get(&member_id) {
                return *fp;
            }
            let fp = Fingerprint::of_parts(&[b"default-device", &member_id.0.to_be_bytes()]);
            self.store
                .add_device(member_id, fp, "default", 0, None)
                .expect("enroll default device for ctx()");
            self.default_devices.borrow_mut().insert(member_id, fp);
            fp
        }

        /// A session context for `member_id`, carrying that member's default enrolled device
        /// (see [`Self::default_device`]) — `SessionContext::device_fp` is no longer optional, so
        /// every test context needs a real, enrolled device or it would hit
        /// `denied:unknown_device` in Step 2b regardless of what the test is actually asserting.
        fn ctx(&self, member_id: MemberId) -> SessionContext {
            SessionContext {
                member_id,
                device_fp: self.default_device(member_id),
            }
        }

        fn ctx_with_device(&self, member_id: MemberId, device_fp: Fingerprint) -> SessionContext {
            SessionContext {
                member_id,
                device_fp,
            }
        }

        /// Enrolls a device with a real Ed25519 signing keypair pinned as its `sign_pk` — the
        /// upload-manifest-signature tests' way of getting a `(device_fp, SigningKey)` pair the
        /// server can actually verify against (see `crate::server`'s
        /// `verify_manifest_signature`). Also pins a real, matching `agree_pk`: `device_fp` is
        /// `spindle_core::identity::DeviceKey`'s own binding hash over both keys (rather than the
        /// pre-Stage-6-slice-5 arbitrary hash of just the label), so `sign_pk`/`agree_pk`/
        /// `device_fp` genuinely rehash together the way `Store::member_for_device_fp`'s doc
        /// comment says a connect-time authorizer relies on.
        fn add_signing_device(
            &self,
            member_id: MemberId,
            label: &str,
        ) -> (Fingerprint, SigningKey) {
            let sign_seed = {
                let mut seed = [0u8; 32];
                let digest = Fingerprint::of_parts(&[b"signing-key-seed", label.as_bytes()]);
                seed.copy_from_slice(digest.as_bytes());
                seed
            };
            let agree_seed = {
                let mut seed = [0u8; 32];
                let digest = Fingerprint::of_parts(&[b"agree-key-seed", label.as_bytes()]);
                seed.copy_from_slice(digest.as_bytes());
                seed
            };
            let dev = DeviceKey::from_seeds(sign_seed, agree_seed);
            let device_fp = dev.device_fp();
            let signing_key = SigningKey::from_bytes(&sign_seed);
            self.store
                .add_device(
                    member_id,
                    device_fp,
                    label,
                    0,
                    Some(&DevicePublicKeys {
                        sign_pk: dev.sign_public_key().as_bytes().to_vec(),
                        agree_pk: dev.agree_public_key().as_bytes().to_vec(),
                    }),
                )
                .expect("add signing device");
            (device_fp, signing_key)
        }
    }

    fn req(v: u8, request: VfsRequest) -> VfsRequestEnvelope {
        VfsRequestEnvelope { v, request }
    }

    /// Signs `(path, size, hash)` the same way a real client would build an upload manifest's
    /// signature — used by every upload test that needs `upload_open`/`upload_commit` to actually
    /// pass signature verification.
    fn sign_manifest(signing_key: &SigningKey, path: &str, size: u64, hash: &[u8]) -> Vec<u8> {
        spindle_core::sign_bytes(signing_key, &manifest_signing_bytes(path, size, hash))
    }

    fn sha256(data: &[u8]) -> Vec<u8> {
        Fingerprint::of_parts(&[data]).to_vec()
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
    fn stat_reports_kind_dir_for_a_real_directory() {
        // Regression test: `stat_in_share` gets its metadata from
        // `confine_identity::stat_through_dir`, which opens `subpath` through the share's `Dir`
        // capability with plain `read(true)` before the `maybe_dir(true)` fix. On Windows, opening
        // a *directory* that way fails (needs `FILE_FLAG_BACKUP_SEMANTICS`), so `stat_in_share`'s
        // `.ok()?` would turn a stat of a real, browsable directory into `denied:not_found` —
        // exactly the failure mode `list_shows_only_browsable_entries_and_descends_into_them`
        // (this module) hit for listings. This test pins the RPC-level contract for `stat`.
        let h = Harness::new();
        let (member_id, _) = h.add_active_member("Alex");
        let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
        let root = h.share_real_root(share_id);
        std::fs::create_dir(root.join("Vacation")).expect("mkdir Vacation");
        h.grant(member_id, share_id, "", Perms::BROWSE | Perms::DOWNLOAD);

        let server = h.server();
        let reply = server.handle(
            &h.ctx(member_id),
            1,
            req(
                1,
                VfsRequest::Stat {
                    path: "Photos/Vacation".to_string(),
                },
            ),
        );
        match reply {
            VfsReply::Stat { kind, .. } => {
                assert_eq!(kind, EntryKind::Dir);
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

    // ===========================================================================================
    // Upload sessions + rate limits (Stage 6 slice 4, DESIGN.md §A4b/§A8)
    // ===========================================================================================

    struct AlwaysFull;
    impl FreeSpaceProbe for AlwaysFull {
        fn available_bytes(&self, _real_root: &std::path::Path) -> u64 {
            0
        }
    }

    /// A `Drop`-mounted, upload-enabled share plus a member with `upload`+`delete`, plus that
    /// member's signing device — the common scaffold every upload test starts from.
    struct UploadFixture {
        h: Harness,
        member_id: MemberId,
        device_fp: Fingerprint,
        signing_key: SigningKey,
        share_id: ShareId,
    }

    impl UploadFixture {
        fn new(perms: Perms) -> Self {
            let h = Harness::new();
            let (member_id, _) = h.add_active_member("Alex");
            let (device_fp, signing_key) = h.add_signing_device(member_id, "alex-phone");
            let share_id = h.add_share(
                "Drop",
                "Drop",
                ShareFlags {
                    read_only: false,
                    allow_upload: true,
                    show_hidden: false,
                },
            );
            h.grant(member_id, share_id, "", perms);
            UploadFixture {
                h,
                member_id,
                device_fp,
                signing_key,
                share_id,
            }
        }

        fn ctx(&self) -> SessionContext {
            self.h.ctx_with_device(self.member_id, self.device_fp)
        }

        fn server(&self) -> VfsRpcServer<&Store> {
            self.h.server()
        }

        fn real_root(&self) -> std::path::PathBuf {
            self.h.share_real_root(self.share_id)
        }

        fn open(
            &self,
            server: &VfsRpcServer<&Store>,
            ts: u64,
            virtual_path: &str,
            data: &[u8],
        ) -> Vec<u8> {
            let hash = sha256(data);
            let sig = sign_manifest(&self.signing_key, virtual_path, data.len() as u64, &hash);
            let reply = server.handle(
                &self.ctx(),
                ts,
                req(
                    1,
                    VfsRequest::UploadOpen {
                        path: virtual_path.to_string(),
                        size: data.len() as u64,
                        hash,
                        manifest_sig: sig,
                    },
                ),
            );
            match reply {
                VfsReply::UploadOpen { session_id, .. } => session_id,
                other => panic!("expected UploadOpen, got {other:?}"),
            }
        }
    }

    #[test]
    fn upload_open_stages_hidden_file_never_listed() {
        let fx = UploadFixture::new(Perms::UPLOAD | Perms::BROWSE);
        let server = fx.server();
        let data = b"hello upload".to_vec();
        let _session_id = fx.open(&server, 1, "Drop/incoming.bin", &data);

        // Exactly one hidden staging file exists in the real share root ...
        let real_entries: Vec<_> = std::fs::read_dir(fx.real_root())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(real_entries.len(), 1);
        assert!(spindle_vfs::confine::is_staging_name(&real_entries[0]));

        // ... but a `list` never shows it (DESIGN.md §A8: "never listed").
        let listing = server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::List {
                    path: "Drop".to_string(),
                    cursor: None,
                    limit: None,
                },
            ),
        );
        match listing {
            VfsReply::List { entries, .. } => assert!(entries.is_empty()),
            other => panic!("expected List, got {other:?}"),
        }
    }

    #[test]
    fn upload_full_flow_commits_bytes_and_updates_quota_counters() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.server();
        let data = b"the quick brown fox".to_vec();
        let session_id = fx.open(&server, 1, "Drop/fox.txt", &data);

        let chunk_reply = server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id: session_id.clone(),
                    offset: 0,
                    data: data.clone(),
                },
            ),
        );
        assert_eq!(
            chunk_reply,
            VfsReply::UploadChunk {
                offset: data.len() as u64
            }
        );

        let commit_reply = server.handle(
            &fx.ctx(),
            3,
            req(1, VfsRequest::UploadCommit { session_id }),
        );
        assert_eq!(commit_reply, VfsReply::UploadCommit);
        assert_eq!(
            std::fs::read(fx.real_root().join("fox.txt")).expect("read committed file"),
            data
        );
        assert_eq!(
            fx.h.store
                .member_upload_bytes(fx.member_id)
                .expect("member_upload_bytes"),
            data.len() as u64
        );
        assert_eq!(
            fx.h.store
                .share_upload_bytes(fx.share_id)
                .expect("share_upload_bytes"),
            data.len() as u64
        );
    }

    /// Stage 6 slice 5 (uploaded_files ledger): an upload-commit followed by a `Delete` of the
    /// same path must return both quota counters to exactly 0, now that the delete path refunds
    /// via `Store::remove_uploads_under` (the ledger) instead of decrementing by a filesystem
    /// stat.
    #[test]
    fn upload_then_delete_round_trip_returns_both_counters_to_zero() {
        let fx = UploadFixture::new(Perms::UPLOAD | Perms::DELETE);
        let server = fx.server();
        let data = b"round trip".to_vec();
        let session_id = fx.open(&server, 1, "Drop/trip.txt", &data);

        server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id: session_id.clone(),
                    offset: 0,
                    data: data.clone(),
                },
            ),
        );
        let commit_reply = server.handle(
            &fx.ctx(),
            3,
            req(1, VfsRequest::UploadCommit { session_id }),
        );
        assert_eq!(commit_reply, VfsReply::UploadCommit);
        assert_eq!(
            fx.h.store.member_upload_bytes(fx.member_id).unwrap(),
            data.len() as u64
        );
        assert_eq!(
            fx.h.store.share_upload_bytes(fx.share_id).unwrap(),
            data.len() as u64
        );

        let delete_reply = server.handle(
            &fx.ctx(),
            4,
            req(
                1,
                VfsRequest::Delete {
                    path: "Drop/trip.txt".to_string(),
                },
            ),
        );
        assert_eq!(delete_reply, VfsReply::Delete);
        assert_eq!(fx.h.store.member_upload_bytes(fx.member_id).unwrap(), 0);
        assert_eq!(fx.h.store.share_upload_bytes(fx.share_id).unwrap(), 0);
    }

    /// The bug fix this ticket exists to land: content the owner placed directly on the real
    /// filesystem (bypassing the upload flow entirely, so `uploaded_files` has no row for it) has
    /// never been counted *up* into `share_upload_bytes` — see `spindle_vfs::store`'s upload-quota
    /// module comment. Deleting that file through the VFS must therefore leave the counter
    /// exactly as it was. Under the old stat-based code, this decremented `share_upload_bytes` by
    /// the raw file's on-disk size regardless of the ledger, which is the overcount this ticket
    /// fixes — with a nonzero starting balance (from a real, separate upload) that overcount
    /// would have been directly observable rather than masked by the zero-clamp.
    #[test]
    fn deleting_owner_placed_content_never_counted_up_leaves_share_upload_bytes_unchanged() {
        let fx = UploadFixture::new(Perms::UPLOAD | Perms::DELETE);
        let server = fx.server();

        // A real upload gives the share a nonzero counter baseline, so an erroneous decrement
        // from the unrelated raw-file delete below would be visible rather than clamped at 0.
        let data = b"legitimate upload".to_vec();
        let session_id = fx.open(&server, 1, "Drop/legit.txt", &data);
        server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id: session_id.clone(),
                    offset: 0,
                    data: data.clone(),
                },
            ),
        );
        server.handle(
            &fx.ctx(),
            3,
            req(1, VfsRequest::UploadCommit { session_id }),
        );
        let baseline = fx.h.store.share_upload_bytes(fx.share_id).unwrap();
        assert_eq!(baseline, data.len() as u64);

        // Content placed directly on the real filesystem, never seen by any upload RPC call —
        // no `uploaded_files` row exists for it.
        std::fs::write(fx.real_root().join("owner_placed.bin"), vec![0u8; 999])
            .expect("write owner-placed file directly to the real filesystem");

        let delete_reply = server.handle(
            &fx.ctx(),
            4,
            req(
                1,
                VfsRequest::Delete {
                    path: "Drop/owner_placed.bin".to_string(),
                },
            ),
        );
        assert_eq!(delete_reply, VfsReply::Delete);
        assert_eq!(
            fx.h.store.share_upload_bytes(fx.share_id).unwrap(),
            baseline,
            "deleting content the ledger never counted up must not move the counter at all"
        );
    }

    /// A directory delete must remove the ledger rows of every file uploaded beneath it (not
    /// just files at the deleted path itself), returning both counters to 0 in one VFS delete —
    /// exercising `Store::remove_uploads_under`'s recursive contract through the real RPC path
    /// (`confine::remove_confined`'s `remove_dir_all` on a directory target).
    #[test]
    fn deleting_a_directory_removes_every_uploaded_files_row_beneath_it() {
        let fx = UploadFixture::new(Perms::UPLOAD | Perms::DELETE);
        let server = fx.server();

        // `finalize_upload` opens the target's parent directory rather than creating it, so the
        // nested real directories must already exist before uploading into them.
        std::fs::create_dir_all(fx.real_root().join("sub/nested"))
            .expect("create nested real directories");

        let a = b"aaa".to_vec();
        let session_a = fx.open(&server, 1, "Drop/sub/a.txt", &a);
        server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id: session_a.clone(),
                    offset: 0,
                    data: a.clone(),
                },
            ),
        );
        server.handle(
            &fx.ctx(),
            3,
            req(
                1,
                VfsRequest::UploadCommit {
                    session_id: session_a,
                },
            ),
        );

        let b = b"bbbbb".to_vec();
        let session_b = fx.open(&server, 4, "Drop/sub/nested/b.txt", &b);
        server.handle(
            &fx.ctx(),
            5,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id: session_b.clone(),
                    offset: 0,
                    data: b.clone(),
                },
            ),
        );
        server.handle(
            &fx.ctx(),
            6,
            req(
                1,
                VfsRequest::UploadCommit {
                    session_id: session_b,
                },
            ),
        );

        assert_eq!(
            fx.h.store.share_upload_bytes(fx.share_id).unwrap(),
            (a.len() + b.len()) as u64
        );

        let delete_reply = server.handle(
            &fx.ctx(),
            7,
            req(
                1,
                VfsRequest::Delete {
                    path: "Drop/sub".to_string(),
                },
            ),
        );
        assert_eq!(delete_reply, VfsReply::Delete);
        assert_eq!(fx.h.store.member_upload_bytes(fx.member_id).unwrap(), 0);
        assert_eq!(fx.h.store.share_upload_bytes(fx.share_id).unwrap(), 0);
    }

    #[test]
    fn upload_open_resumes_a_live_session_at_its_current_offset() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.server();
        let data = b"resumable payload".to_vec();
        let session_id = fx.open(&server, 1, "Drop/resume.bin", &data);

        let first_chunk = &data[..8];
        server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id: session_id.clone(),
                    offset: 0,
                    data: first_chunk.to_vec(),
                },
            ),
        );

        // Same server instance, `upload_open` called again for the identical manifest — DESIGN.md
        // §A8 "resume via next-expected-offset".
        let resumed_id = fx.open(&server, 3, "Drop/resume.bin", &data);
        assert_eq!(resumed_id, session_id, "must resume the same session");

        let reopened = server.handle(
            &fx.ctx(),
            4,
            req(
                1,
                VfsRequest::UploadOpen {
                    path: "Drop/resume.bin".to_string(),
                    size: data.len() as u64,
                    hash: sha256(&data),
                    manifest_sig: sign_manifest(
                        &fx.signing_key,
                        "Drop/resume.bin",
                        data.len() as u64,
                        &sha256(&data),
                    ),
                },
            ),
        );
        match reopened {
            VfsReply::UploadOpen { offset, .. } => {
                assert_eq!(
                    offset,
                    first_chunk.len() as u64,
                    "resumes at next-expected-offset"
                )
            }
            other => panic!("expected UploadOpen, got {other:?}"),
        }
    }

    #[test]
    fn upload_chunk_wrong_offset_is_file_changed() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.server();
        let data = b"0123456789".to_vec();
        let session_id = fx.open(&server, 1, "Drop/a.bin", &data);

        let reply = server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id,
                    offset: 5, // wrong: session's next-expected-offset is 0
                    data: data[5..].to_vec(),
                },
            ),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::FileChanged
            }
        );
    }

    #[test]
    fn upload_chunk_beyond_declared_size_is_upload_rejected() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.server();
        let data = b"short".to_vec();
        let session_id = fx.open(&server, 1, "Drop/a.bin", &data);

        let reply = server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id,
                    offset: 0,
                    data: b"this chunk is way longer than the declared size".to_vec(),
                },
            ),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::UploadRejected
            }
        );
    }

    #[test]
    fn upload_commit_incomplete_transfer_is_file_changed() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.server();
        let data = b"0123456789".to_vec();
        let session_id = fx.open(&server, 1, "Drop/a.bin", &data);
        // Only send half the declared bytes, then try to commit early.
        server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id: session_id.clone(),
                    offset: 0,
                    data: data[..5].to_vec(),
                },
            ),
        );
        let reply = server.handle(
            &fx.ctx(),
            3,
            req(1, VfsRequest::UploadCommit { session_id }),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::FileChanged
            }
        );
    }

    #[test]
    fn upload_commit_hash_mismatch_is_upload_rejected() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.server();
        let data = b"genuine bytes".to_vec();
        // Sign a manifest for `data`, but then have the session's staging bytes turn out
        // different by writing content of the same length but different bytes.
        let session_id = fx.open(&server, 1, "Drop/a.bin", &data);
        let tampered = b"not-the-same!".to_vec();
        assert_eq!(tampered.len(), data.len());
        server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id: session_id.clone(),
                    offset: 0,
                    data: tampered,
                },
            ),
        );
        let reply = server.handle(
            &fx.ctx(),
            3,
            req(1, VfsRequest::UploadCommit { session_id }),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::UploadRejected
            }
        );
    }

    #[test]
    fn upload_open_without_upload_perm_is_denied() {
        let fx = UploadFixture::new(Perms::BROWSE | Perms::DOWNLOAD); // no upload
        let server = fx.server();
        let data = b"x".to_vec();
        let hash = sha256(&data);
        let sig = sign_manifest(&fx.signing_key, "Drop/a.bin", data.len() as u64, &hash);
        let reply = server.handle(
            &fx.ctx(),
            1,
            req(
                1,
                VfsRequest::UploadOpen {
                    path: "Drop/a.bin".to_string(),
                    size: data.len() as u64,
                    hash,
                    manifest_sig: sig,
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
    fn upload_open_with_unsigned_manifest_is_upload_rejected() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.server();
        let data = b"x".to_vec();
        let hash = sha256(&data);
        // No device on the session context at all -> can never verify (documented in
        // `verify_manifest_signature`'s doc comment).
        let reply = server.handle(
            &fx.h.ctx(fx.member_id),
            1,
            req(
                1,
                VfsRequest::UploadOpen {
                    path: "Drop/a.bin".to_string(),
                    size: data.len() as u64,
                    hash,
                    manifest_sig: vec![0u8; 64],
                },
            ),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::UploadRejected
            }
        );
    }

    #[test]
    fn upload_commit_over_existing_file_without_delete_is_already_exists_and_session_survives() {
        let fx = UploadFixture::new(Perms::UPLOAD); // no delete
        let root = fx.real_root();
        std::fs::write(root.join("existing.txt"), b"old content").expect("seed existing file");
        let server = fx.server();
        let data = b"new content!".to_vec();
        let session_id = fx.open(&server, 1, "Drop/existing.txt", &data);
        server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id: session_id.clone(),
                    offset: 0,
                    data: data.clone(),
                },
            ),
        );
        let reply = server.handle(
            &fx.ctx(),
            3,
            req(
                1,
                VfsRequest::UploadCommit {
                    session_id: session_id.clone(),
                },
            ),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::AlreadyExists
            }
        );
        assert_eq!(
            std::fs::read(root.join("existing.txt")).expect("read"),
            b"old content"
        );

        // The session survives an `already_exists` refusal — a client can grant itself `delete`
        // out of band and retry `upload_commit` without re-uploading anything (asserted here by
        // just retrying the commit after this test's fixture is rebuilt with `delete` below).
        let reply_again = server.handle(
            &fx.ctx(),
            4,
            req(1, VfsRequest::UploadCommit { session_id }),
        );
        assert_eq!(
            reply_again,
            VfsReply::Error {
                code: VfsErrorCode::AlreadyExists
            },
            "retrying without delete must still refuse the same way"
        );
    }

    #[test]
    fn upload_commit_over_existing_file_with_delete_overwrites() {
        let fx = UploadFixture::new(Perms::UPLOAD | Perms::DELETE);
        let root = fx.real_root();
        std::fs::write(root.join("existing.txt"), b"old content").expect("seed existing file");
        let server = fx.server();
        let data = b"new content!".to_vec();
        let session_id = fx.open(&server, 1, "Drop/existing.txt", &data);
        server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id: session_id.clone(),
                    offset: 0,
                    data: data.clone(),
                },
            ),
        );
        let reply = server.handle(
            &fx.ctx(),
            3,
            req(1, VfsRequest::UploadCommit { session_id }),
        );
        assert_eq!(reply, VfsReply::UploadCommit);
        assert_eq!(
            std::fs::read(root.join("existing.txt")).expect("read"),
            data
        );
    }

    #[test]
    fn upload_commit_fold_key_collision_counts_as_overwrite() {
        let fx = UploadFixture::new(Perms::UPLOAD); // no delete
        let root = fx.real_root();
        std::fs::write(root.join("Existing.TXT"), b"old").expect("seed existing file");
        let server = fx.server();
        let data = b"new".to_vec();
        // Case-different target name — a fold-key collision, DESIGN.md §A4b "collision ==
        // overwrite" — must be refused exactly like an exact-name collision.
        let session_id = fx.open(&server, 1, "Drop/existing.txt", &data);
        server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id: session_id.clone(),
                    offset: 0,
                    data: data.clone(),
                },
            ),
        );
        let reply = server.handle(
            &fx.ctx(),
            3,
            req(1, VfsRequest::UploadCommit { session_id }),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::AlreadyExists
            }
        );
    }

    #[test]
    fn upload_abort_discards_session_and_staging_bytes() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.server();
        let data = b"never committed".to_vec();
        let session_id = fx.open(&server, 1, "Drop/a.bin", &data);
        assert_eq!(
            std::fs::read_dir(fx.real_root()).expect("read_dir").count(),
            1
        );

        let reply = server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadAbort {
                    session_id: session_id.clone(),
                },
            ),
        );
        assert_eq!(reply, VfsReply::UploadAbort);
        assert_eq!(
            std::fs::read_dir(fx.real_root()).expect("read_dir").count(),
            0,
            "staging file must be gone after abort"
        );

        // The session is really gone: a chunk against it is a fresh not_found, not resumable.
        let reply = server.handle(
            &fx.ctx(),
            3,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id,
                    offset: 0,
                    data: vec![1],
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
    fn gc_expired_upload_sessions_removes_stale_staging_file() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.server();
        let data = b"stale".to_vec();
        let _session_id = fx.open(&server, 1_000, "Drop/a.bin", &data);
        assert_eq!(
            std::fs::read_dir(fx.real_root()).expect("read_dir").count(),
            1
        );

        // Not yet expired: TTL is 48h.
        server.gc_expired_upload_sessions(1_000 + 60);
        assert_eq!(
            std::fs::read_dir(fx.real_root()).expect("read_dir").count(),
            1,
            "must not GC a session before its TTL"
        );

        server.gc_expired_upload_sessions(1_000 + UPLOAD_SESSION_TTL_SECS + 1);
        assert_eq!(
            std::fs::read_dir(fx.real_root()).expect("read_dir").count(),
            0,
            "must GC the staging file once the session's TTL has passed"
        );
    }

    #[test]
    fn entitlement_change_mid_upload_aborts_session_and_gcs_it() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.server();
        let data = b"0123456789".to_vec();
        let session_id = fx.open(&server, 1, "Drop/a.bin", &data);

        // DESIGN.md §A8: "an entitlement change mid-transfer aborts the session" — simulated here
        // via `bump_cap_epoch` directly (any grants/cap_epoch movement is treated conservatively,
        // regardless of whether this member's own perms actually changed).
        fx.h.store.bump_cap_epoch().expect("bump_cap_epoch");

        let reply = server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id: session_id.clone(),
                    offset: 0,
                    data: data[..5].to_vec(),
                },
            ),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::GrantsChanged
            }
        );
        assert_eq!(
            std::fs::read_dir(fx.real_root()).expect("read_dir").count(),
            0,
            "the aborted session's staging file must be GC'd immediately"
        );

        // The session is really gone, not just "still enforcing the old grants".
        let reply = server.handle(
            &fx.ctx(),
            3,
            req(1, VfsRequest::UploadCommit { session_id }),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::NotFound
            }
        );
    }

    #[test]
    fn upload_open_quota_exceeded_for_member() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.h.server_with_limits(
            UploadLimits {
                max_member_upload_bytes: 5,
                ..UploadLimits::default()
            },
            Box::new(UnlimitedFreeSpace),
            RateLimitConfig::default(),
        );
        let data = b"this is way more than five bytes".to_vec();
        let hash = sha256(&data);
        let sig = sign_manifest(&fx.signing_key, "Drop/a.bin", data.len() as u64, &hash);
        let reply = server.handle(
            &fx.ctx(),
            1,
            req(
                1,
                VfsRequest::UploadOpen {
                    path: "Drop/a.bin".to_string(),
                    size: data.len() as u64,
                    hash,
                    manifest_sig: sig,
                },
            ),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::QuotaExceeded
            }
        );
    }

    #[test]
    fn upload_open_quota_exceeded_for_share() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.h.server_with_limits(
            UploadLimits {
                max_share_upload_bytes: 5,
                ..UploadLimits::default()
            },
            Box::new(UnlimitedFreeSpace),
            RateLimitConfig::default(),
        );
        let data = b"this is way more than five bytes".to_vec();
        let hash = sha256(&data);
        let sig = sign_manifest(&fx.signing_key, "Drop/a.bin", data.len() as u64, &hash);
        let reply = server.handle(
            &fx.ctx(),
            1,
            req(
                1,
                VfsRequest::UploadOpen {
                    path: "Drop/a.bin".to_string(),
                    size: data.len() as u64,
                    hash,
                    manifest_sig: sig,
                },
            ),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::QuotaExceeded
            }
        );
    }

    #[test]
    fn upload_chunk_storage_full_via_fake_probe() {
        let fx = UploadFixture::new(Perms::UPLOAD);
        let server = fx.h.server_with_limits(
            UploadLimits::default(),
            Box::new(AlwaysFull),
            RateLimitConfig::default(),
        );
        let data = b"anything".to_vec();
        let session_id = fx.open(&server, 1, "Drop/a.bin", &data);
        let reply = server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::UploadChunk {
                    session_id,
                    offset: 0,
                    data,
                },
            ),
        );
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::StorageFull
            }
        );
    }

    #[test]
    fn rate_limiter_throttles_after_burst_and_recovers_after_refill() {
        let fx = UploadFixture::new(Perms::BROWSE);
        let server = fx.h.server_with_limits(
            UploadLimits::default(),
            Box::new(UnlimitedFreeSpace),
            RateLimitConfig {
                burst: 2.0,
                refill_per_sec: 1.0,
            },
        );
        let whoami = || req(1, VfsRequest::Whoami);

        assert!(matches!(
            server.handle(&fx.ctx(), 0, whoami()),
            VfsReply::Whoami { .. }
        ));
        assert!(matches!(
            server.handle(&fx.ctx(), 0, whoami()),
            VfsReply::Whoami { .. }
        ));
        assert_eq!(
            server.handle(&fx.ctx(), 0, whoami()),
            VfsReply::Error {
                code: VfsErrorCode::Throttled
            },
            "third request at the same instant must be throttled"
        );

        // One second later, a token has refilled.
        assert!(matches!(
            server.handle(&fx.ctx(), 1, whoami()),
            VfsReply::Whoami { .. }
        ));
    }

    #[test]
    fn upload_implies_resolve_without_listing_drop_box() {
        // `upload`-only (no `browse`) can still open a session against a path it cannot list —
        // DESIGN.md §A4b "upload implies resolve-without-listing (drop-box)".
        let fx = UploadFixture::new(Perms::UPLOAD); // no browse
        let server = fx.server();
        let data = b"drop box payload".to_vec();
        let session_id = fx.open(&server, 1, "Drop/secret.bin", &data);
        assert!(!session_id.is_empty());

        let listing = server.handle(
            &fx.ctx(),
            2,
            req(
                1,
                VfsRequest::List {
                    path: "Drop".to_string(),
                    cursor: None,
                    limit: None,
                },
            ),
        );
        assert_eq!(
            listing,
            VfsReply::Error {
                code: VfsErrorCode::NotFound
            },
            "no browse perm: listing the drop-box share must still be refused"
        );
    }

    #[test]
    fn mkdir_over_existing_without_delete_is_already_exists() {
        // v0.9.10 remap regression test: byte-level assertion that the wire error is
        // `already_exists`, not the slice-3 `upload_rejected` stopgap.
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
        std::fs::create_dir(root.join("NewAlbum")).expect("seed existing dir");
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
        assert_eq!(
            reply,
            VfsReply::Error {
                code: VfsErrorCode::AlreadyExists
            }
        );
    }

    #[test]
    fn read_toctou_identity_change_is_file_changed() {
        // v0.9.10 remap regression test: byte-level assertion that a stat->read identity mismatch
        // reports `file_changed`, not the slice-3 `not_found` stopgap.
        let h = Harness::new();
        let (member_id, _) = h.add_active_member("Alex");
        let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
        let root = h.share_real_root(share_id);
        std::fs::write(root.join("a.bin"), vec![1u8; 10]).expect("write a.bin");
        h.grant(member_id, share_id, "", Perms::BROWSE | Perms::DOWNLOAD);

        let server = h.server();
        // Prime the identity cache with a baseline observation.
        let first = server.handle(
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
        assert!(matches!(first, VfsReply::Read { .. }));

        // Replace the file's real content out from under the cached identity by writing the new
        // content to a sibling path and renaming it over `a.bin` — this is DESIGN.md §A4b's
        // actual threat model ("rename races"), and it guarantees a fresh inode/identity on every
        // filesystem. (An earlier version of this test used remove_file + write to force a new
        // inode; that was flaky on Linux (ext4/tmpfs), where a freed inode number is commonly
        // reused immediately by the very next file created, so the old `(dev, ino)` and the new
        // one could compare equal and the identity mismatch would never fire. macOS/APFS
        // allocates inodes monotonically, so the old pattern happened to pass there, but it
        // relied on filesystem-specific behavior instead of a real distinct-identity guarantee.
        // Writing under a different name first — while `a.bin` still exists — means the replacement
        // is always a distinct inode before the rename ever touches `a.bin`.)
        let replacement = root.join("a.bin.tmp");
        std::fs::write(&replacement, vec![2u8; 10]).expect("write replacement");
        std::fs::rename(&replacement, root.join("a.bin")).expect("rename over a.bin");

        let second = server.handle(
            &h.ctx(member_id),
            2,
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
            second,
            VfsReply::Error {
                code: VfsErrorCode::FileChanged
            }
        );
    }
}
