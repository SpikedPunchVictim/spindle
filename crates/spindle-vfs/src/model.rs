//! Plain in-memory model structs for host authorization (DESIGN.md §A4b, ADR-006): `Member`,
//! `Share`, `Group`, `Entitlement`. No persistence and no RPC live here — see the crate root doc
//! comment for this slice's scope. Invariants that are cheap to check at construction (e.g.
//! "`upload`/`delete` are grantable only on shares flagged `allow_upload`") are enforced here via
//! fallible constructors rather than left to callers to remember.

use crate::confine::fold_key;
use spindle_core::Fingerprint;
use std::path::PathBuf;
use thiserror::Error;

/// Errors from constructing model values that violate a §A4b invariant.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ModelError {
    /// §A4b: "`upload`/`delete` [are] grantable only on shares flagged `allow_upload`."
    #[error(
        "entitlement grants upload and/or delete on share {share_id:?}, which is not flagged \
         allow_upload (DESIGN.md §A4b: upload/delete grantable only on allow_upload shares)"
    )]
    UploadNotAllowedOnShare { share_id: ShareId },

    /// A virtual path component was empty, `.`, or `..` — never valid in a stored subpath or
    /// mount path (the confinement layer, `crate::confine`, independently refuses these at the
    /// real-filesystem level for uploads; this is the model-level analogue for virtual paths).
    #[error("virtual path component {0:?} is invalid (empty, \".\", or \"..\")")]
    InvalidPathComponent(String),
}

/// Declares a small `Copy` newtype wrapping a `u64` host-local row id. Kept distinct per entity
/// (rather than passing bare `u64`s around) so a `ShareId` can never be silently passed where a
/// `GroupId` was expected.
macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u64);
    };
}

id_type!(
    /// A share's host-local row id.
    ShareId
);
id_type!(
    /// A group's host-local row id.
    GroupId
);
id_type!(
    /// A member's host-local row id.
    MemberId
);

/// A normalized virtual path: a sequence of non-empty, non-`.`/`..` path components. The empty
/// sequence is the share root (or host virtual-tree root, depending on context — see the crate
/// root doc comment's note on the mount-path resolution gap).
///
/// Component comparisons (`descends_from_or_eq`) use [`fold_key`] (§A4b case/Unicode folding),
/// exactly as `crate::confine` folds real dirent names — so a grant expressed with one
/// case/Unicode spelling still applies to a path reached with a different, colliding spelling of
/// the same name.
///
/// **`Eq`/`Hash` are deliberately literal, not folded** — this is an asymmetry with
/// `descends_from_or_eq`, and that asymmetry is a trap this codebase has fallen into repeatedly
/// (td-9bf38d is the fifth/sixth instance: `spindle-host-core`'s identity cache and its upload
/// session table both keyed/compared on the literal `VirtualPath` and so treated two
/// fold-colliding spellings — e.g. `"Photo.JPG"` and `"photo.jpg"` — of what is, since `b0c2f3f`,
/// the *same on-disk dirent* as two unrelated paths). The literal `Eq` is kept anyway: a folded
/// `Eq` would make every `assert_eq!` comparing two `VirtualPath`s blind to a spelling change,
/// silently weakening tests — this repo has already shipped that failure mode twice (a byte-vs-
/// character regression test that stopped discriminating, and a fold-scan technique that died the
/// same way). **Anything that keys or matches on a path's identity — a map/set key, an `==`
/// comparison meant to mean "same dirent", `contains`/`find`/`retain`/`position` — must go through
/// [`VirtualPath::folded`] instead of comparing `VirtualPath` directly.**
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct VirtualPath(Vec<String>);

/// A case/Unicode-folded virtual path, for use as a map/set key or in an identity comparison —
/// see the warning on [`VirtualPath`]'s doc comment. Built via [`VirtualPath::folded`].
///
/// Folding the whole `/`-joined string (rather than folding each component and rejoining) is
/// equivalent here: `/` is neither cased nor case-ignorable, so it is as hard a boundary for
/// Rust's context-dependent final-sigma lowercasing rule as a string edge is, and NFD's canonical
/// reordering only acts within contiguous combining-mark runs, which a `/` always breaks. So
/// whole-string folding cannot fold marks or casing *across* a component boundary that
/// per-component folding would have kept separate. (Verified empirically during td-ea075e's
/// review.)
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FoldedPath(String);

impl VirtualPath {
    /// The root path (zero components).
    pub fn root() -> Self {
        VirtualPath(Vec::new())
    }

    /// Parses a `/`-separated virtual path. Leading/trailing/repeated slashes collapse to
    /// nothing (so `"/Photos//Vacation/"` and `"Photos/Vacation"` parse identically); a `.` or
    /// `..` component is rejected outright — a virtual path is never subject to `..`-style
    /// resolution, unlike the real filesystem paths `crate::confine` guards.
    pub fn parse(s: &str) -> Result<Self, ModelError> {
        let mut components = Vec::new();
        for part in s.split('/') {
            if part.is_empty() {
                continue;
            }
            if part == "." || part == ".." {
                return Err(ModelError::InvalidPathComponent(part.to_string()));
            }
            components.push(part.to_string());
        }
        Ok(VirtualPath(components))
    }

    pub fn components(&self) -> &[String] {
        &self.0
    }

    /// The inverse of [`VirtualPath::parse`]: renders back to a `/`-joined string (the root path
    /// renders as `""`). Additive helper for Stage 6 slice 2 (`crate::store`), which persists
    /// `subpath` as `TEXT` and must round-trip it losslessly; does not change any slice-1
    /// behavior — [`VirtualPath::parse`] of this output is guaranteed to reconstruct an equal
    /// value since components are already validated non-empty/non-`.`/non-`..`.
    pub fn to_path_string(&self) -> String {
        self.0.join("/")
    }

    /// The folded key for this path — see [`FoldedPath`] and the warning on this type's doc
    /// comment. Two `VirtualPath`s that are `descends_from_or_eq` each other at equal depth (i.e.
    /// component-wise fold-equal) produce equal `FoldedPath`s; anything that needs to know "is
    /// this the same dirent" rather than "is this the same spelling" should compare `folded()`
    /// values instead of the `VirtualPath`s themselves.
    pub fn folded(&self) -> FoldedPath {
        FoldedPath(fold_key(&self.to_path_string()))
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn depth(&self) -> usize {
        self.0.len()
    }

    /// Appends one path component, without any validation beyond non-emptiness (callers that
    /// need `.`/`..` rejection should route the raw name through [`VirtualPath::parse`] first).
    pub fn join(&self, name: &str) -> Self {
        let mut v = self.0.clone();
        v.push(name.to_string());
        VirtualPath(v)
    }

    /// The parent path, or `None` at the root.
    pub fn parent(&self) -> Option<Self> {
        if self.0.is_empty() {
            None
        } else {
            Some(VirtualPath(self.0[..self.0.len() - 1].to_vec()))
        }
    }

    /// `true` when `self` is `other`, or a descendant of `other` — i.e. `other` is a
    /// component-wise, fold-key-equal prefix of `self`. This is the "`(share, subpath)` is a
    /// prefix of P" relation DESIGN.md §A4b's union algebra is built on.
    pub fn descends_from_or_eq(&self, other: &VirtualPath) -> bool {
        if other.0.len() > self.0.len() {
            return false;
        }
        other
            .0
            .iter()
            .zip(self.0.iter())
            .all(|(a, b)| fold_key(a) == fold_key(b))
    }
}

/// Share flags (§A4b): `{read_only, allow_upload, show_hidden}`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareFlags {
    pub read_only: bool,
    pub allow_upload: bool,
    pub show_hidden: bool,
}

/// A share: `{share_id, name, mount_path, real_root, flags, excludes}` (§A4b). Exclusions are
/// share-level — they apply to every member, regardless of grant — which is what keeps the
/// entitlement algebra positive-only/monotonic (no deny rules needed).
#[derive(Clone, Debug)]
pub struct Share {
    pub share_id: ShareId,
    pub name: String,
    pub mount_path: String,
    pub real_root: PathBuf,
    pub flags: ShareFlags,
    pub excludes: Vec<crate::glob::CompiledGlob>,
}

impl Share {
    pub fn has_exclusions(&self) -> bool {
        !self.excludes.is_empty()
    }

    /// `true` if `path` (or any ancestor of `path`) matches one of this share's exclude globs —
    /// see [`crate::glob::CompiledGlob`] for the ancestor-cascading semantics and the
    /// case/Unicode folding applied to every path component. Excluded paths are invisible to
    /// **every** member regardless of how broad their grant is (§A4b: "exclusions live on
    /// shares, not the entitlement algebra"); `crate::algebra` checks this before consulting any
    /// entitlement.
    pub fn is_excluded(&self, path: &VirtualPath) -> bool {
        self.excludes
            .iter()
            .any(|glob| glob.matches_path_or_ancestor(path.components()))
    }
}

/// A group: built-in `Owner` (implicit, all rights, not editable) and `Members` (default, empty
/// grants), or a custom group (§A4b).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupKind {
    Owner,
    Members,
    Custom,
}

#[derive(Clone, Debug)]
pub struct Group {
    pub group_id: GroupId,
    pub name: String,
    pub kind: GroupKind,
}

/// A member's device: `{device_fp, label, added, revoked?}` (§A4b).
///
/// **Stage 6 slice 4 addition, flagged per the task brief rather than resolved silently**:
/// `sign_pk` — the device's Ed25519 signing public key — is new as of slice 4. DESIGN.md §A4's
/// device certificates already carry this key (`spindle_proto::artifacts::DeviceCertificate`),
/// and the host pins it at enrollment, but no slice before this one had a reason to persist it
/// here: slices 1-2 only needed `device_fp` (a fingerprint) to identify a device for grants/
/// revocation bookkeeping. Slice 4 needs the actual public key because DESIGN.md §A8's transfer
/// manager requires verifying an upload's manifest signature — signed by the *sending device's*
/// key — before the staged file is moved into place, and there is nowhere else in this crate's
/// durable state that key is recorded. `None` for a device added before this field existed, or in
/// a test that never supplied one; an upload manifest signed by such a device fails closed
/// (`spindle-host-core` cannot verify without a key, and does not treat a missing key as "skip
/// verification").
///
/// **Stage 6 slice 5 addition**: `agree_pk` — the device's X25519 key-agreement public key —
/// arrives later than `sign_pk` for the same reason `sign_pk` arrived later than `device_fp`: each
/// slice persists only the key material its own consumer needs. Slice 4's upload-manifest
/// verification only ever checks an Ed25519 signature, so only `sign_pk` was needed. Connect-time
/// authorization (DESIGN.md §A5's injected `ConnectAuthorizer`, `crates/spindle-net/src/signaling/
/// authorize.rs`) needs the X25519 half too: `ConnectDecision::Allow` must hand the caller *both*
/// pinned public keys before a single byte of a connect offer's signature or ciphertext can be
/// verified — `sign_pk` verifies the envelope signature, `agree_pk` is the key `k0`/`k1` are
/// derived from (DESIGN.md §A7). `None` means "cannot authorize this device" — fail closed, the
/// same as a missing `sign_pk`, never "skip the check".
///
/// **td-6c01e3 addition**: `alg_id` — the algorithm identifier that is the second element of
/// `device_fp`'s preimage, `H(DEVICE_FP_DOMAIN, alg_id, sign_pk, agree_pk)` (DESIGN.md:225-227,
/// `spindle_core::identity::device_fp_of`). Before this, every verifier recomputed that hash with
/// `alg_id` hardcoded to `ALG_ID_V1` rather than reading it from the row it names — this field is
/// what the row was missing to verify itself. The invariant is **`alg_id` is `None` if and only if
/// `sign_pk`/`agree_pk` are `None`** — a row with no keys has no algorithm to name. A verifier that
/// finds `None` here MUST treat it as "cannot verify this device", never as "skip the alg_id
/// check" — the identical fail-closed treatment this doc comment already prescribes for a missing
/// `sign_pk`/`agree_pk`. The same applies to `Some(a)` where `a != ALG_ID_V1`: `sign_pk`/`agree_pk`
/// are parsed as Ed25519/X25519 unconditionally (that is the only parse this codebase knows how to
/// do), so a row naming a different algorithm cannot actually be verified by that parse — hashing
/// its `alg_id` into `device_fp_of` anyway would manufacture a hash that matches for a row nobody
/// can verify, which is strictly worse than the old hardcoded assumption. Reject, do not hash.
#[derive(Clone, Debug)]
pub struct Device {
    pub device_fp: Fingerprint,
    pub label: String,
    pub added: u64,
    pub revoked: bool,
    pub sign_pk: Option<Vec<u8>>,
    pub agree_pk: Option<Vec<u8>>,
    pub alg_id: Option<u8>,
}

/// The write-path pairing of a device's two public key halves, for [`crate::store::Store::add_device`].
/// Exists so that method takes ONE optional argument instead of two adjacent `Option<&[u8]>`
/// parameters a caller could silently transpose — a transposition would not be caught by the type
/// system (both are just byte slices) and would produce a device whose stored keys do not rehash
/// to its own `device_fp` (see [`Device::agree_pk`]'s doc comment on the binding
/// `spindle_core::identity::device_fp_of` checks), i.e. a device that can never authenticate,
/// discovered only at connect time. It also encodes "both halves or neither" — the only
/// combination a `device_fp` binding check can use — as a single `Option` rather than letting two
/// independent `Option`s disagree.
///
/// **td-6c01e3 addition**: `alg_id` lives here, not as a separate parameter threaded alongside
/// this struct into [`crate::store::Store::add_device`] (28 call sites at the time of writing).
/// `alg_id` describes this key pair — it is the algorithm the pair was generated under, and the
/// second element of the `device_fp` preimage that binds them together (DESIGN.md:225-227) — so it
/// belongs with the pieces it describes, in the struct that exists precisely to keep them together
/// and untransposable, per this doc comment's own opening sentence. A bolted-on extra argument next
/// to two same-typed byte vectors would reintroduce exactly the transposition hazard this struct
/// was created to prevent, just with a third value instead of two.
#[derive(Clone, Debug)]
pub struct DevicePublicKeys {
    pub alg_id: u8,
    pub sign_pk: Vec<u8>,
    pub agree_pk: Vec<u8>,
}

/// `invited | active | revoked` (§A4b).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberStatus {
    Invited,
    Active,
    Revoked,
}

/// A member: `{member_id, root_fp, display_name, status, devices, groups, created}` (§A4b). A
/// freshly created member (redeemed invite, no group edits yet) starts in the `Members` group
/// with `groups` containing only that group's id and therefore has **no** grants anywhere —
/// "secure by default" (§A4b) is a property of there being no entitlements naming that group's
/// id yet, not of anything special in this struct.
#[derive(Clone, Debug)]
pub struct Member {
    pub member_id: MemberId,
    pub root_fp: Fingerprint,
    pub display_name: String,
    pub status: MemberStatus,
    pub devices: Vec<Device>,
    pub groups: Vec<GroupId>,
    pub created: u64,
}

/// The four grantable permissions, as a small hand-rolled bitset (no `bitflags` dependency — the
/// set is fixed at four bits and never needs to grow generically). DESIGN.md §A4b: "`perms ⊆
/// {browse, download, upload, delete}`".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Perms(u8);

impl Perms {
    pub const NONE: Perms = Perms(0);
    pub const BROWSE: Perms = Perms(1 << 0);
    pub const DOWNLOAD: Perms = Perms(1 << 1);
    pub const UPLOAD: Perms = Perms(1 << 2);
    pub const DELETE: Perms = Perms(1 << 3);

    pub fn union(self, other: Perms) -> Perms {
        Perms(self.0 | other.0)
    }

    pub fn contains(self, other: Perms) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The raw bitset byte. Additive helper for Stage 6 slice 2 (`crate::store`), which persists
    /// perms as a SQLite `INTEGER` column; does not change any slice-1 behavior.
    pub fn bits(self) -> u8 {
        self.0
    }

    /// Inverse of [`Perms::bits`] — wraps any byte value as-is (the bitset has no invalid bit
    /// patterns to reject: every combination of the four defined bits, and even unused high bits,
    /// is representable and simply behaves as "no permission" for any bit not one of the four
    /// named constants).
    pub fn from_bits(bits: u8) -> Self {
        Perms(bits)
    }
}

impl std::ops::BitOr for Perms {
    type Output = Perms;
    fn bitor(self, rhs: Perms) -> Perms {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for Perms {
    fn bitor_assign(&mut self, rhs: Perms) {
        *self = self.union(rhs);
    }
}

/// `{group_id, share_id, subpath, perms}` (§A4b). Constructed only via [`Entitlement::new`],
/// which enforces the one construction-time invariant DESIGN.md §A4b states plainly: `upload`
/// and `delete` are grantable only on shares flagged `allow_upload`.
#[derive(Clone, Debug)]
pub struct Entitlement {
    pub group_id: GroupId,
    pub share_id: ShareId,
    pub subpath: VirtualPath,
    pub perms: Perms,
}

impl Entitlement {
    /// `share_allows_upload` is the target share's `flags.allow_upload` — the caller (host-core,
    /// later) looks up the `Share` by `share_id` and passes its flag through; `Entitlement`
    /// itself holds no reference to `Share` to keep this a plain, storable data model.
    pub fn new(
        group_id: GroupId,
        share_id: ShareId,
        subpath: VirtualPath,
        perms: Perms,
        share_allows_upload: bool,
    ) -> Result<Self, ModelError> {
        if (perms.contains(Perms::UPLOAD) || perms.contains(Perms::DELETE)) && !share_allows_upload
        {
            return Err(ModelError::UploadNotAllowedOnShare { share_id });
        }
        Ok(Entitlement {
            group_id,
            share_id,
            subpath,
            perms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vp(s: &str) -> VirtualPath {
        VirtualPath::parse(s).expect("valid virtual path")
    }

    #[test]
    fn virtual_path_parse_collapses_slashes() {
        assert_eq!(vp("/Photos//Vacation/"), vp("Photos/Vacation"));
        assert_eq!(vp(""), VirtualPath::root());
        assert_eq!(vp("/"), VirtualPath::root());
    }

    #[test]
    fn virtual_path_parse_rejects_dot_and_dotdot() {
        assert_eq!(
            VirtualPath::parse("Photos/../etc").unwrap_err(),
            ModelError::InvalidPathComponent("..".to_string())
        );
        assert_eq!(
            VirtualPath::parse("./Photos").unwrap_err(),
            ModelError::InvalidPathComponent(".".to_string())
        );
    }

    #[test]
    fn descends_from_or_eq_is_prefix_relation() {
        let root = VirtualPath::root();
        let photos = vp("Photos");
        let vacation = vp("Photos/Vacation");
        let vacation_img = vp("Photos/Vacation/img.jpg");
        let other = vp("Other");

        assert!(root.descends_from_or_eq(&root));
        assert!(photos.descends_from_or_eq(&root));
        assert!(vacation.descends_from_or_eq(&photos));
        assert!(vacation_img.descends_from_or_eq(&photos));
        assert!(vacation.descends_from_or_eq(&vacation));
        assert!(
            !photos.descends_from_or_eq(&vacation),
            "ancestor does not descend from its child"
        );
        assert!(
            !other.descends_from_or_eq(&photos),
            "sibling does not descend from Photos"
        );
    }

    #[test]
    fn descends_from_or_eq_folds_case_and_unicode() {
        let a = vp("Photos/Café");
        let b = vp("photos/cafe\u{0301}"); // NFD spelling, lowercase
        assert!(a.descends_from_or_eq(&b));
        assert!(b.descends_from_or_eq(&a));
    }

    #[test]
    fn entitlement_rejects_upload_or_delete_on_non_upload_share() {
        let share_id = ShareId(1);
        let err = Entitlement::new(
            GroupId(1),
            share_id,
            VirtualPath::root(),
            Perms::UPLOAD,
            false,
        )
        .unwrap_err();
        assert_eq!(err, ModelError::UploadNotAllowedOnShare { share_id });

        let err = Entitlement::new(
            GroupId(1),
            share_id,
            VirtualPath::root(),
            Perms::DELETE,
            false,
        )
        .unwrap_err();
        assert_eq!(err, ModelError::UploadNotAllowedOnShare { share_id });

        // browse/download alone never require allow_upload.
        assert!(Entitlement::new(
            GroupId(1),
            share_id,
            VirtualPath::root(),
            Perms::BROWSE | Perms::DOWNLOAD,
            false,
        )
        .is_ok());

        // upload/delete are fine when the share does allow uploads.
        assert!(Entitlement::new(
            GroupId(1),
            share_id,
            VirtualPath::root(),
            Perms::UPLOAD | Perms::DELETE,
            true,
        )
        .is_ok());
    }

    #[test]
    fn perms_bitset_union_and_contains() {
        let p = Perms::BROWSE | Perms::DOWNLOAD;
        assert!(p.contains(Perms::BROWSE));
        assert!(p.contains(Perms::DOWNLOAD));
        assert!(!p.contains(Perms::UPLOAD));
        assert!(!p.contains(Perms::DELETE));
        assert!(!p.is_empty());
        assert!(Perms::NONE.is_empty());
    }
}
