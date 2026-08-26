//! VFS RPC wire types (DESIGN.md §A8 "VFS RPC" + "VFS error model"), Stage 6 slice 3.
//!
//! These types carry the six read-side/metadata VFS operations across the control
//! channel/stream once a session is authenticated (post-DTLS/QUIC handshake) — they are **not**
//! one of A7b's seven signed-artifact kinds (no domain-separation tag, no `sig` field, no
//! [`crate::tags`] involvement): §A8 places VFS RPC *inside* the already-authenticated,
//! already-encrypted session, so per-message signing would be redundant with the transport's own
//! integrity guarantee. Like every other wire type in this crate, encoding is this crate's
//! canonical CBOR ([`crate::canonical`]) with the same closed-schema/strict-type discipline
//! `artifacts.rs` uses (unknown fields rejected, missing required fields rejected) — see
//! [`crate::artifacts`]'s `MapReader`, reused here as `pub(crate)`.
//!
//! # Scope (Stage 6 slice 3 — deliberately bounded, see `IMPLEMENTATION_PLAN.md`)
//!
//! **In**: `list`, `stat`, `read` (chunked, offset/len), `mkdir`, `delete`, `whoami`, and the
//! [`VfsErrorCode`] typed error model.
//!
//! **Out** (slice 4): `upload`'s resumable-session wire types (staging names, manifests, TTL) —
//! DESIGN.md §A8's "transfer manager" / "upload sessions" paragraphs. `resume_expired` and
//! `upload_rejected` below are defined now (per the task brief: "define all codes now even though
//! some fire only in slice 4") but nothing in this slice ever produces them.
//!
//! # Schema choices (this crate's established practice — see `lib.rs`'s schema-choices table for
//! the A7b-artifact precedent this follows)
//!
//! | Choice | Decision |
//! |---|---|
//! | Wire shape | One CBOR map per message, request and reply alike: `{"op": <uint>, ...op-specific fields}`, with the request side additionally carrying `"v"` (protocol version). This mirrors `Envelope`'s single-flat-map-with-a-small-int-discriminant style rather than introducing a CBOR tag or a nested `{"kind": ..., "payload": {...}}` envelope. |
//! | `v` (protocol version) | Present on every **request**, absent from every **reply** — DESIGN.md's negotiation language ("peers negotiate the highest common version with no downgrade below each side's minimum") is about the client asserting a version per call and the server accepting-or-rejecting it, not a per-message bidirectional handshake; a reply is already scoped to the request it answers. See [`VfsRequestEnvelope`]. |
//! | `op` discriminant | A small unsigned integer (0–5 for requests, 0–6 for replies — `Error` is reply-only, value 6), exactly like `Capability.kind`'s precedent: a fixed, closed discriminant set that doesn't need self-description on the wire. |
//! | Virtual paths | Plain UTF-8 text (`/`-separated), never a dedicated wire type — `spindle-proto` sits below `spindle-vfs` in the crate graph (`proto ← core ← {net, vfs} ← host-core`) and must not depend on `spindle_vfs::model::VirtualPath`; callers (`spindle-host-core`) parse/render via that type. |
//! | `list`'s `cursor` | Opaque bytes (`Option<Vec<u8>>`, key omission when absent — same optional-field convention as `Envelope.eph_pk`), not a decoded integer/string — the host-core paging implementation owns the cursor's internal shape (currently an audit/entry sequence-adjacent encoding; see `spindle-host-core`), and an opaque wire type means that internal shape can change without a wire-schema break. |
//! | `list`'s `limit` | Optional `u32`; omitted means "use the server's default/max page" ([`MAX_LIST_PAGE`]). A client-supplied value above the server max is clamped server-side, not rejected — same posture as `spindle-vfs::audit::Audit::list`'s existing `page_size` clamp (precedent inside this same codebase). |
//! | `read`'s `len` | `u32`, capped at [`MAX_READ_CHUNK`] (64 KiB, DESIGN.md §A8) — enforced by the server (`spindle-host-core`), not by this crate's decoder (a `len` field over the cap decodes fine; it is a request the server is entitled to refuse/clamp, not a malformed wire item). |
//! | `read`'s reply | `{data: bytes, eof: bool}` — DESIGN.md's RPC line (`read(path, offset, len) → chunk stream on the data channel/stream`) does not spell out the reply shape precisely (it also punts the actual bytes to "the data channel/stream", a transport-layer concern out of scope here per the task brief: "transport streaming/backpressure belongs to spindle-net later"). This crate's choice: the reply carries the chunk's bytes directly (so a pure, transport-agnostic `VfsRpcServer` — bytes/typed-request in, bytes/typed-reply out — is fully testable with no channel abstraction at all) plus an explicit `eof` bool rather than making the caller infer end-of-file from `data.len() < len` (that inference breaks when the file's remaining length happens to be an exact multiple of the request size). |
//! | `stat`'s reply | Mirrors one [`DirEntry`] minus `name` (the caller already knows the path it stat'd) — `{kind, size, mtime, perms_here}`. No file-identity token on the wire: DESIGN.md's stat-then-read TOCTOU check (§A4b: "file identity is checked between `stat` and `read`") is enforced **server-side** (`spindle-host-core` keeps a per-session last-observed-identity cache — see that crate's module docs), so the client never needs to see or round-trip an identity value. |
//! | `whoami`'s reply | `{member_display, effective_paths}` exactly per DESIGN.md's literal tuple and the A4b/A12 #32 trimming rule ("no group names") — `effective_paths` is a flat list of virtual-path strings the caller can currently browse to, not a tree and not group-attributed. |
//! | `VfsErrorCode::UnsupportedVersion` | **Not** one of DESIGN.md §A8's seven named codes (`not_found, quota_exceeded, grants_changed, resume_expired, upload_rejected, storage_full, throttled`) — added because the task brief explicitly requires "server rejects below its minimum with a typed error" for protocol-version negotiation, and none of the seven named codes fits a version mismatch (`not_found` would misleadingly imply a permission/existence problem; `grants_changed` implies an entitlement edit). Flagged here as a documented, deliberate schema extension beyond DESIGN.md's literal list, exactly as this crate's convention requires (see the `lib.rs` schema-choices table for the general practice of recording such decisions in one place). |

use crate::artifacts::{MapReader, ProtoError};
use crate::canonical::{canonical_decode, canonical_encode, CborValue};

/// Minimum protocol version this schema's server-side implementations accept (DESIGN.md §A8:
/// "peers negotiate the highest common version with no downgrade below each side's minimum").
/// `spindle-host-core` checks incoming [`VfsRequestEnvelope::v`] against this constant.
pub const MIN_PROTOCOL_VERSION: u8 = 1;
/// The protocol version this schema currently implements/produces.
pub const CURRENT_PROTOCOL_VERSION: u8 = 1;

/// Server-enforced maximum number of entries in one `list` reply page. DESIGN.md §A4b/§A8 state
/// "cursor-paged with a max page" without a number; this default follows the same order of
/// magnitude as `spindle_vfs::audit::MAX_AUDIT_PAGE_SIZE` (500) — both are "generous but bounded"
/// placeholders, documented here so a later slice can retune without hunting through server code.
pub const MAX_LIST_PAGE: u32 = 500;

/// Maximum bytes in one `read` reply chunk (DESIGN.md §A8, verbatim: "64 KiB chunks").
pub const MAX_READ_CHUNK: u32 = 64 * 1024;

// ================================================================================================
// Small closed-set enums (wire: small unsigned integers, per this crate's established convention)
// ================================================================================================

/// A `list`/`stat` entry's kind. DESIGN.md's VFS RPC line does not enumerate a closed kind set
/// explicitly; `file`/`dir` is the minimum this crate needs for a browsable virtual tree (no
/// symlinks are ever exposed as their own kind — §A4b/`spindle-vfs::confine` never follows a
/// symlink whose target resolves outside the share root, and one that resolves inside it is
/// indistinguishable from a plain file/dir at this layer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File = 0,
    Dir = 1,
}

impl EntryKind {
    fn to_cbor(self) -> CborValue {
        CborValue::uint(self as u64)
    }

    fn from_u64(v: u64) -> Result<Self, ProtoError> {
        match v {
            0 => Ok(EntryKind::File),
            1 => Ok(EntryKind::Dir),
            other => Err(ProtoError::InvalidEnumValue("kind", other)),
        }
    }
}

/// The four grantable permissions, as they cross the wire — a small bitset mirroring (but
/// independent from, per this crate's no-dependency-on-`spindle-vfs` layering rule)
/// `spindle_vfs::model::Perms`. Bit assignment intentionally matches that type's
/// (`browse=1, download=2, upload=4, delete=8`) so `spindle-host-core`'s conversion is a trivial,
/// explicit, unit-tested mapping rather than a coincidence relied upon silently.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VfsPerms(u8);

impl VfsPerms {
    pub const NONE: VfsPerms = VfsPerms(0);
    pub const BROWSE: VfsPerms = VfsPerms(1 << 0);
    pub const DOWNLOAD: VfsPerms = VfsPerms(1 << 1);
    pub const UPLOAD: VfsPerms = VfsPerms(1 << 2);
    pub const DELETE: VfsPerms = VfsPerms(1 << 3);

    /// All four bits set — the only values accepted on decode (closed schema: an out-of-range
    /// bitset is rejected, not silently masked).
    const MAX_VALID: u8 = 0b1111;

    pub fn from_bits_truncate_checked(bits: u8) -> Option<Self> {
        (bits <= Self::MAX_VALID).then_some(VfsPerms(bits))
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn union(self, other: VfsPerms) -> VfsPerms {
        VfsPerms(self.0 | other.0)
    }

    pub fn contains(self, other: VfsPerms) -> bool {
        self.0 & other.0 == other.0
    }
}

fn perms_from_reader(m: &MapReader<'_>, key: &'static str) -> Result<VfsPerms, ProtoError> {
    let bits = m.u8(key)?;
    VfsPerms::from_bits_truncate_checked(bits).ok_or(ProtoError::IntOutOfRange(key))
}

/// DESIGN.md §A8 "VFS error model": the typed error codes returned *inside* the authenticated
/// session (§A5's uniform-silent-drop rule applies only pre-auth — see the module doc comment on
/// [`crate::vfs_rpc`] and DESIGN.md §A8's error-model paragraph, quoted there verbatim). All seven
/// named codes are defined now even though `resume_expired`/`upload_rejected`/`storage_full` fire
/// only once the slice-4 upload/transfer-manager/quota work lands — see the module doc comment's
/// scope section. [`VfsErrorCode::UnsupportedVersion`] is this crate's own addition beyond
/// DESIGN.md's literal list — see the schema-choices table above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsErrorCode {
    /// The requested path does not exist, OR the caller is not authorized to see it — DESIGN.md
    /// §A4b: "unauthorized == not found", deliberately the *same* wire value for both causes.
    NotFound = 0,
    /// A per-member/per-share/per-transfer quota was exceeded (slice 4: upload/transfer quotas).
    QuotaExceeded = 1,
    /// The member's effective grants changed since an in-flight operation began (e.g. a
    /// resumable upload's entitlement was revoked mid-transfer — DESIGN.md §A8 "an entitlement
    /// change mid-transfer aborts the session").
    GrantsChanged = 2,
    /// A resumable upload session's TTL (DESIGN.md §A8: 48 h) expired.
    ResumeExpired = 3,
    /// An uploaded file was rejected (manifest verification failure, unsafe name, size cap, etc.
    /// — DESIGN.md §A8 "received-file policy").
    UploadRejected = 4,
    /// The host's free-space floor was reached (DESIGN.md §A8 "owner live operations": "host-level
    /// free-space floor that pauses uploads before the disk fills").
    StorageFull = 5,
    /// A rate limit was hit (distinct from the pre-auth callout rate limits of §A3/§A5 — this is
    /// the post-auth, per-session/per-member VFS-op rate limit the task brief defers to slice 4).
    Throttled = 6,
    /// This crate's addition (not one of DESIGN.md's seven) — see the schema-choices table above.
    /// The request's [`VfsRequestEnvelope::v`] was below the server's [`MIN_PROTOCOL_VERSION`].
    UnsupportedVersion = 7,
}

impl VfsErrorCode {
    fn to_cbor(self) -> CborValue {
        CborValue::uint(self as u64)
    }

    fn from_u64(v: u64) -> Result<Self, ProtoError> {
        match v {
            0 => Ok(VfsErrorCode::NotFound),
            1 => Ok(VfsErrorCode::QuotaExceeded),
            2 => Ok(VfsErrorCode::GrantsChanged),
            3 => Ok(VfsErrorCode::ResumeExpired),
            4 => Ok(VfsErrorCode::UploadRejected),
            5 => Ok(VfsErrorCode::StorageFull),
            6 => Ok(VfsErrorCode::Throttled),
            7 => Ok(VfsErrorCode::UnsupportedVersion),
            other => Err(ProtoError::InvalidEnumValue("code", other)),
        }
    }
}

// ================================================================================================
// list/stat entry shape
// ================================================================================================

/// One `list` reply entry — DESIGN.md §A8: `entries[{name, kind, size, mtime, perms_here}]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    pub mtime: u64,
    pub perms_here: VfsPerms,
}

const DIR_ENTRY_FIELDS: &[&str] = &["name", "kind", "size", "mtime", "perms_here"];

impl DirEntry {
    fn to_cbor(&self) -> CborValue {
        CborValue::map(vec![
            ("name", CborValue::text(self.name.clone())),
            ("kind", self.kind.to_cbor()),
            ("size", CborValue::uint(self.size)),
            ("mtime", CborValue::uint(self.mtime)),
            ("perms_here", CborValue::uint(self.perms_here.bits() as u64)),
        ])
    }

    fn from_cbor(v: &CborValue) -> Result<Self, ProtoError> {
        let m = MapReader::new(v)?;
        m.deny_unknown_fields(DIR_ENTRY_FIELDS)?;
        Ok(DirEntry {
            name: m.text("name")?,
            kind: EntryKind::from_u64(m.u64("kind")?)?,
            size: m.u64("size")?,
            mtime: m.u64("mtime")?,
            perms_here: perms_from_reader(&m, "perms_here")?,
        })
    }
}

// ================================================================================================
// Op discriminants
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReqOp {
    List = 0,
    Stat = 1,
    Read = 2,
    Mkdir = 3,
    Delete = 4,
    Whoami = 5,
}

impl ReqOp {
    fn to_cbor(self) -> CborValue {
        CborValue::uint(self as u64)
    }

    fn from_u64(v: u64) -> Result<Self, ProtoError> {
        match v {
            0 => Ok(ReqOp::List),
            1 => Ok(ReqOp::Stat),
            2 => Ok(ReqOp::Read),
            3 => Ok(ReqOp::Mkdir),
            4 => Ok(ReqOp::Delete),
            5 => Ok(ReqOp::Whoami),
            other => Err(ProtoError::InvalidEnumValue("op", other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyOp {
    List = 0,
    Stat = 1,
    Read = 2,
    Mkdir = 3,
    Delete = 4,
    Whoami = 5,
    Error = 6,
}

impl ReplyOp {
    fn to_cbor(self) -> CborValue {
        CborValue::uint(self as u64)
    }

    fn from_u64(v: u64) -> Result<Self, ProtoError> {
        match v {
            0 => Ok(ReplyOp::List),
            1 => Ok(ReplyOp::Stat),
            2 => Ok(ReplyOp::Read),
            3 => Ok(ReplyOp::Mkdir),
            4 => Ok(ReplyOp::Delete),
            5 => Ok(ReplyOp::Whoami),
            6 => Ok(ReplyOp::Error),
            other => Err(ProtoError::InvalidEnumValue("op", other)),
        }
    }
}

// ================================================================================================
// Requests
// ================================================================================================

/// One of the six in-scope VFS RPC requests (DESIGN.md §A8). All paths are virtual, `/`-separated
/// UTF-8 text — see the schema-choices table above for why this crate carries them as plain
/// `String` rather than a dedicated path type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VfsRequest {
    /// `list(path, cursor) → entries[...]`. `limit` is this crate's addition (see schema-choices
    /// table); omitted means "server default/max".
    List {
        path: String,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    },
    /// `stat(path)`.
    Stat { path: String },
    /// `read(path, offset, len) → chunk`. `len` is capped server-side at [`MAX_READ_CHUNK`].
    Read { path: String, offset: u64, len: u32 },
    /// `mkdir(path)`.
    Mkdir { path: String },
    /// `delete(path)`.
    Delete { path: String },
    /// `whoami → {member_display, effective_paths}`. No fields of its own.
    Whoami,
}

const LIST_REQ_FIELDS: &[&str] = &["v", "op", "path", "cursor", "limit"];
const STAT_REQ_FIELDS: &[&str] = &["v", "op", "path"];
const READ_REQ_FIELDS: &[&str] = &["v", "op", "path", "offset", "len"];
const MKDIR_REQ_FIELDS: &[&str] = &["v", "op", "path"];
const DELETE_REQ_FIELDS: &[&str] = &["v", "op", "path"];
const WHOAMI_REQ_FIELDS: &[&str] = &["v", "op"];

/// A [`VfsRequest`] plus the protocol-version field every request carries (DESIGN.md §A8: "RPC
/// carries a protocol version"). Encoded as a single flat CBOR map — see the schema-choices table
/// above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfsRequestEnvelope {
    pub v: u8,
    pub request: VfsRequest,
}

impl VfsRequestEnvelope {
    pub fn to_cbor(&self) -> CborValue {
        let v_entry = ("v", CborValue::uint(self.v as u64));
        let entries = match &self.request {
            VfsRequest::List {
                path,
                cursor,
                limit,
            } => {
                let mut e = vec![
                    v_entry,
                    ("op", ReqOp::List.to_cbor()),
                    ("path", CborValue::text(path.clone())),
                ];
                if let Some(c) = cursor {
                    e.push(("cursor", CborValue::bytes(c.clone())));
                }
                if let Some(l) = limit {
                    e.push(("limit", CborValue::uint(*l as u64)));
                }
                e
            }
            VfsRequest::Stat { path } => vec![
                v_entry,
                ("op", ReqOp::Stat.to_cbor()),
                ("path", CborValue::text(path.clone())),
            ],
            VfsRequest::Read { path, offset, len } => vec![
                v_entry,
                ("op", ReqOp::Read.to_cbor()),
                ("path", CborValue::text(path.clone())),
                ("offset", CborValue::uint(*offset)),
                ("len", CborValue::uint(*len as u64)),
            ],
            VfsRequest::Mkdir { path } => vec![
                v_entry,
                ("op", ReqOp::Mkdir.to_cbor()),
                ("path", CborValue::text(path.clone())),
            ],
            VfsRequest::Delete { path } => vec![
                v_entry,
                ("op", ReqOp::Delete.to_cbor()),
                ("path", CborValue::text(path.clone())),
            ],
            VfsRequest::Whoami => vec![v_entry, ("op", ReqOp::Whoami.to_cbor())],
        };
        CborValue::map(entries)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, ProtoError> {
        let m = MapReader::new(v)?;
        let ver = m.u8("v")?;
        let op = ReqOp::from_u64(m.u64("op")?)?;
        let request = match op {
            ReqOp::List => {
                m.deny_unknown_fields(LIST_REQ_FIELDS)?;
                VfsRequest::List {
                    path: m.text("path")?,
                    cursor: m.optional_bytes("cursor")?,
                    limit: m.optional_u32("limit")?,
                }
            }
            ReqOp::Stat => {
                m.deny_unknown_fields(STAT_REQ_FIELDS)?;
                VfsRequest::Stat {
                    path: m.text("path")?,
                }
            }
            ReqOp::Read => {
                m.deny_unknown_fields(READ_REQ_FIELDS)?;
                VfsRequest::Read {
                    path: m.text("path")?,
                    offset: m.u64("offset")?,
                    len: m.u32("len")?,
                }
            }
            ReqOp::Mkdir => {
                m.deny_unknown_fields(MKDIR_REQ_FIELDS)?;
                VfsRequest::Mkdir {
                    path: m.text("path")?,
                }
            }
            ReqOp::Delete => {
                m.deny_unknown_fields(DELETE_REQ_FIELDS)?;
                VfsRequest::Delete {
                    path: m.text("path")?,
                }
            }
            ReqOp::Whoami => {
                m.deny_unknown_fields(WHOAMI_REQ_FIELDS)?;
                VfsRequest::Whoami
            }
        };
        Ok(VfsRequestEnvelope { v: ver, request })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }
}

// ================================================================================================
// Replies
// ================================================================================================

/// One of the six in-scope VFS RPC replies, or [`VfsReply::Error`] (DESIGN.md §A8's error model).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VfsReply {
    List {
        entries: Vec<DirEntry>,
        next_cursor: Option<Vec<u8>>,
    },
    Stat {
        kind: EntryKind,
        size: u64,
        mtime: u64,
        perms_here: VfsPerms,
    },
    Read {
        data: Vec<u8>,
        eof: bool,
    },
    Mkdir,
    Delete,
    Whoami {
        member_display: String,
        effective_paths: Vec<String>,
    },
    Error {
        code: VfsErrorCode,
    },
}

const LIST_REPLY_FIELDS: &[&str] = &["op", "entries", "next_cursor"];
const STAT_REPLY_FIELDS: &[&str] = &["op", "kind", "size", "mtime", "perms_here"];
const READ_REPLY_FIELDS: &[&str] = &["op", "data", "eof"];
const MKDIR_REPLY_FIELDS: &[&str] = &["op"];
const DELETE_REPLY_FIELDS: &[&str] = &["op"];
const WHOAMI_REPLY_FIELDS: &[&str] = &["op", "member_display", "effective_paths"];
const ERROR_REPLY_FIELDS: &[&str] = &["op", "code"];

impl VfsReply {
    pub fn to_cbor(&self) -> CborValue {
        let entries = match self {
            VfsReply::List {
                entries,
                next_cursor,
            } => {
                let mut e = vec![
                    ("op", ReplyOp::List.to_cbor()),
                    (
                        "entries",
                        CborValue::array(entries.iter().map(DirEntry::to_cbor).collect()),
                    ),
                ];
                if let Some(c) = next_cursor {
                    e.push(("next_cursor", CborValue::bytes(c.clone())));
                }
                e
            }
            VfsReply::Stat {
                kind,
                size,
                mtime,
                perms_here,
            } => vec![
                ("op", ReplyOp::Stat.to_cbor()),
                ("kind", kind.to_cbor()),
                ("size", CborValue::uint(*size)),
                ("mtime", CborValue::uint(*mtime)),
                ("perms_here", CborValue::uint(perms_here.bits() as u64)),
            ],
            VfsReply::Read { data, eof } => vec![
                ("op", ReplyOp::Read.to_cbor()),
                ("data", CborValue::bytes(data.clone())),
                ("eof", CborValue::Bool(*eof)),
            ],
            VfsReply::Mkdir => vec![("op", ReplyOp::Mkdir.to_cbor())],
            VfsReply::Delete => vec![("op", ReplyOp::Delete.to_cbor())],
            VfsReply::Whoami {
                member_display,
                effective_paths,
            } => vec![
                ("op", ReplyOp::Whoami.to_cbor()),
                ("member_display", CborValue::text(member_display.clone())),
                (
                    "effective_paths",
                    CborValue::array(
                        effective_paths
                            .iter()
                            .cloned()
                            .map(CborValue::text)
                            .collect(),
                    ),
                ),
            ],
            VfsReply::Error { code } => {
                vec![("op", ReplyOp::Error.to_cbor()), ("code", code.to_cbor())]
            }
        };
        CborValue::map(entries)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }

    pub fn from_cbor(v: &CborValue) -> Result<Self, ProtoError> {
        let m = MapReader::new(v)?;
        let op = ReplyOp::from_u64(m.u64("op")?)?;
        Ok(match op {
            ReplyOp::List => {
                m.deny_unknown_fields(LIST_REPLY_FIELDS)?;
                let raw_entries = m
                    .require("entries")?
                    .as_array()
                    .ok_or(ProtoError::WrongType("entries"))?;
                let entries = raw_entries
                    .iter()
                    .map(DirEntry::from_cbor)
                    .collect::<Result<Vec<_>, _>>()?;
                VfsReply::List {
                    entries,
                    next_cursor: m.optional_bytes("next_cursor")?,
                }
            }
            ReplyOp::Stat => {
                m.deny_unknown_fields(STAT_REPLY_FIELDS)?;
                VfsReply::Stat {
                    kind: EntryKind::from_u64(m.u64("kind")?)?,
                    size: m.u64("size")?,
                    mtime: m.u64("mtime")?,
                    perms_here: perms_from_reader(&m, "perms_here")?,
                }
            }
            ReplyOp::Read => {
                m.deny_unknown_fields(READ_REPLY_FIELDS)?;
                VfsReply::Read {
                    data: m.bytes("data")?,
                    eof: m.bool("eof")?,
                }
            }
            ReplyOp::Mkdir => {
                m.deny_unknown_fields(MKDIR_REPLY_FIELDS)?;
                VfsReply::Mkdir
            }
            ReplyOp::Delete => {
                m.deny_unknown_fields(DELETE_REPLY_FIELDS)?;
                VfsReply::Delete
            }
            ReplyOp::Whoami => {
                m.deny_unknown_fields(WHOAMI_REPLY_FIELDS)?;
                let raw_paths = m
                    .require("effective_paths")?
                    .as_array()
                    .ok_or(ProtoError::WrongType("effective_paths"))?;
                let effective_paths = raw_paths
                    .iter()
                    .map(|v| v.as_text().map(str::to_string))
                    .collect::<Option<Vec<_>>>()
                    .ok_or(ProtoError::WrongType("effective_paths"))?;
                VfsReply::Whoami {
                    member_display: m.text("member_display")?,
                    effective_paths,
                }
            }
            ReplyOp::Error => {
                m.deny_unknown_fields(ERROR_REPLY_FIELDS)?;
                VfsReply::Error {
                    code: VfsErrorCode::from_u64(m.u64("code")?)?,
                }
            }
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_cbor(&canonical_decode(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt_req(env: &VfsRequestEnvelope) {
        let bytes = env.to_canonical_bytes();
        let decoded = VfsRequestEnvelope::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(&decoded, env);
    }

    fn rt_reply(reply: &VfsReply) {
        let bytes = reply.to_canonical_bytes();
        let decoded = VfsReply::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(&decoded, reply);
    }

    #[test]
    fn round_trips_every_request_variant() {
        rt_req(&VfsRequestEnvelope {
            v: 1,
            request: VfsRequest::List {
                path: "Photos/Vacation".to_string(),
                cursor: None,
                limit: None,
            },
        });
        rt_req(&VfsRequestEnvelope {
            v: 1,
            request: VfsRequest::List {
                path: "Photos".to_string(),
                cursor: Some(vec![1, 2, 3]),
                limit: Some(50),
            },
        });
        rt_req(&VfsRequestEnvelope {
            v: 1,
            request: VfsRequest::Stat {
                path: "Photos/img.jpg".to_string(),
            },
        });
        rt_req(&VfsRequestEnvelope {
            v: 1,
            request: VfsRequest::Read {
                path: "Photos/img.jpg".to_string(),
                offset: 65536,
                len: 65536,
            },
        });
        rt_req(&VfsRequestEnvelope {
            v: 1,
            request: VfsRequest::Mkdir {
                path: "Photos/NewAlbum".to_string(),
            },
        });
        rt_req(&VfsRequestEnvelope {
            v: 1,
            request: VfsRequest::Delete {
                path: "Photos/old.jpg".to_string(),
            },
        });
        rt_req(&VfsRequestEnvelope {
            v: 1,
            request: VfsRequest::Whoami,
        });
    }

    #[test]
    fn round_trips_every_reply_variant() {
        rt_reply(&VfsReply::List {
            entries: vec![DirEntry {
                name: "Vacation".to_string(),
                kind: EntryKind::Dir,
                size: 0,
                mtime: 1000,
                perms_here: VfsPerms::BROWSE,
            }],
            next_cursor: Some(vec![9, 9]),
        });
        rt_reply(&VfsReply::List {
            entries: vec![],
            next_cursor: None,
        });
        rt_reply(&VfsReply::Stat {
            kind: EntryKind::File,
            size: 4096,
            mtime: 2000,
            perms_here: VfsPerms::BROWSE.union(VfsPerms::DOWNLOAD),
        });
        rt_reply(&VfsReply::Read {
            data: vec![0xAB; 128],
            eof: true,
        });
        rt_reply(&VfsReply::Mkdir);
        rt_reply(&VfsReply::Delete);
        rt_reply(&VfsReply::Whoami {
            member_display: "Alex".to_string(),
            effective_paths: vec!["Photos/Vacation".to_string(), "Drop".to_string()],
        });
        for code in [
            VfsErrorCode::NotFound,
            VfsErrorCode::QuotaExceeded,
            VfsErrorCode::GrantsChanged,
            VfsErrorCode::ResumeExpired,
            VfsErrorCode::UploadRejected,
            VfsErrorCode::StorageFull,
            VfsErrorCode::Throttled,
            VfsErrorCode::UnsupportedVersion,
        ] {
            rt_reply(&VfsReply::Error { code });
        }
    }

    #[test]
    fn rejects_unknown_field() {
        let mut cbor = VfsRequestEnvelope {
            v: 1,
            request: VfsRequest::Whoami,
        }
        .to_cbor();
        if let CborValue::Map(entries) = &mut cbor {
            entries.push((CborValue::text("bogus"), CborValue::uint(1)));
        }
        let bytes = canonical_encode(&cbor);
        let err = VfsRequestEnvelope::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(err, ProtoError::UnknownField("bogus".to_string()));
    }

    #[test]
    fn rejects_missing_required_field() {
        let mut cbor = VfsRequestEnvelope {
            v: 1,
            request: VfsRequest::Stat {
                path: "x".to_string(),
            },
        }
        .to_cbor();
        if let CborValue::Map(entries) = &mut cbor {
            entries.retain(|(k, _)| k.as_text() != Some("path"));
        }
        let bytes = canonical_encode(&cbor);
        let err = VfsRequestEnvelope::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(err, ProtoError::MissingField("path"));
    }

    #[test]
    fn rejects_invalid_op_and_error_code() {
        let bad_op = CborValue::map(vec![("v", CborValue::uint(1)), ("op", CborValue::uint(99))]);
        let bytes = canonical_encode(&bad_op);
        let err = VfsRequestEnvelope::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(err, ProtoError::InvalidEnumValue("op", 99));

        let bad_code = CborValue::map(vec![
            ("op", CborValue::uint(6)),
            ("code", CborValue::uint(99)),
        ]);
        let bytes = canonical_encode(&bad_code);
        let err = VfsReply::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(err, ProtoError::InvalidEnumValue("code", 99));
    }

    #[test]
    fn rejects_out_of_range_perms_bitset() {
        let cbor = CborValue::map(vec![
            ("op", CborValue::uint(1)),
            ("kind", CborValue::uint(0)),
            ("size", CborValue::uint(0)),
            ("mtime", CborValue::uint(0)),
            ("perms_here", CborValue::uint(0xff)),
        ]);
        let bytes = canonical_encode(&cbor);
        let err = VfsReply::from_canonical_bytes(&bytes).unwrap_err();
        assert_eq!(err, ProtoError::IntOutOfRange("perms_here"));
    }

    #[test]
    fn all_error_codes_distinct_and_round_trip_u64() {
        let codes = [
            VfsErrorCode::NotFound,
            VfsErrorCode::QuotaExceeded,
            VfsErrorCode::GrantsChanged,
            VfsErrorCode::ResumeExpired,
            VfsErrorCode::UploadRejected,
            VfsErrorCode::StorageFull,
            VfsErrorCode::Throttled,
            VfsErrorCode::UnsupportedVersion,
        ];
        for (i, c) in codes.iter().enumerate() {
            assert_eq!(*c as u64, i as u64);
        }
    }

    #[test]
    fn max_read_chunk_is_64_kib() {
        assert_eq!(MAX_READ_CHUNK, 65536);
    }
}
