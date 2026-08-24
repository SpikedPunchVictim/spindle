//! The pure entitlement algebra (DESIGN.md §A4b, ADR-006 "Entitlements"): given a member, the
//! entitlement table, and a share, compute what that member may do at any virtual path. No I/O,
//! no persistence — every function here is a pure computation over in-memory `crate::model`
//! values. See the crate root doc comment for a note on what is deliberately *not* modeled yet
//! (host-wide virtual-tree mount-path resolution).
//!
//! # The algebra (verbatim, §A4b)
//!
//! "Effective perms of a member on virtual path P = **union** of all grants from all their
//! groups whose `(share, subpath)` is a prefix of P; inherited down. No denies in v1."
//!
//! # Edge rules and where each one lives
//!
//! - **`browse` implies ancestor traversal** — [`AccessDecision::Traversal`], computed by
//!   [`EffectiveGrants::resolve_access`]: an ancestor of a browse-granted subtree is listable,
//!   but [`EffectiveGrants::filter_listing`] shows only the single child that continues the chain
//!   toward the grant, never siblings.
//! - **`upload` implies resolution without listing** — an emergent property of returning the raw
//!   [`Perms`] bitset in [`AccessDecision::Granted`] rather than requiring `browse` to also be
//!   set: a path with only `upload` granted resolves to `Granted(Perms::UPLOAD)`, which a caller
//!   gates listing on (`.contains(Perms::BROWSE)`) but gates "may write here" on
//!   (`.contains(Perms::UPLOAD)`) independently. See
//!   [`tests::upload_only_grant_resolves_without_browse`].
//! - **`delete` does not imply `download`** — perms are independent bits; see
//!   [`tests::delete_does_not_imply_download`].
//! - **Overwrite requires `delete`; fold-collision counts as overwrite** — enforced at the
//!   confinement layer (`crate::confine::upload::write_is_authorized`), which already treats a
//!   case/Unicode fold collision as an overwrite (`crate::confine::fold::existing_entry_colliding`).
//!   This module does not duplicate that check; it only supplies the `can_delete`/`can_upload`
//!   bits `write_is_authorized` needs, via [`AccessDecision::Granted`].
//! - **Exclusions apply to everyone, including broad grants** — checked first, before any
//!   entitlement lookup, in [`EffectiveGrants::resolve_access`] (`Share::is_excluded`).
//! - **Not-found for non-browsable paths** — [`AccessDecision::NotFound`] is the *only* variant
//!   this module returns for "no access"; there is no second variant a caller could use to
//!   distinguish "exists but forbidden" from "genuinely absent" (this layer does no filesystem
//!   I/O at all, so it structurally cannot know the difference — see
//!   [`tests::denied_paths_are_indistinguishable_from_nonexistent`]).
//!
//! # Integration point this layer does not own
//!
//! §A4b's hardlink `nlink` rule ("when a share has exclusions, files with link count > 1 are not
//! served") is filesystem metadata this pure algebra never sees. A caller must additionally run
//! `crate::confine::identity::nlink_guard` on every entry of a share with `Share::has_exclusions()
//! == true` before actually serving it, even after `resolve_access` returns `Granted`.

use crate::model::{Entitlement, GroupId, Member, MemberId, Perms, Share, ShareId, VirtualPath};
use std::collections::HashSet;

/// Host-internal cache-invalidation token (ADR-006 "Host-wide single epoch" alternative,
/// rejected in favor of splitting `cap_epoch` — capability revocation, `spindle-core`/ADR-003 —
/// from `grants_version` — entitlement-edit/cache invalidation, host-internal only). This slice
/// defines the type as an **API-shape placeholder only**: no caching is implemented here. A
/// future host-core cache would key stored [`EffectiveGrants`] computations by
/// `(MemberId, GrantsVersion)` and recompute whenever the version bumps (any entitlement, group
/// membership, or share edit).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantsVersion(pub u64);

impl GrantsVersion {
    pub fn next(self) -> Self {
        GrantsVersion(self.0 + 1)
    }
}

/// The result of resolving a member's access to one virtual path. **This is the only type this
/// module returns for a permission decision** — deliberately shaped so a caller cannot
/// accidentally leak the existence of a path the member is not authorized to see: `NotFound` is
/// used uniformly for "no grant reaches here" (see the module doc comment's not-found-semantics
/// bullet, DESIGN.md §A4b / ADR-006 A12 #21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessDecision {
    /// No grant reaches this path, or it is excluded. Must be treated identically to "this path
    /// does not exist" by every caller — never surfaced differently.
    NotFound,
    /// This path is not itself granted, but it lies on the traversal chain toward at least one of
    /// the member's `browse`-granted subtrees (§A4b: "`browse` on P implies traversal of P's
    /// ancestors — the ancestor listing shows only the path toward P, not siblings"). Carries no
    /// permissions of its own; a listing of a `Traversal` path must be filtered accordingly (see
    /// [`EffectiveGrants::filter_listing`]).
    Traversal,
    /// The union of every entitlement whose `(share, subpath)` prefixes this path, from every
    /// group the member belongs to.
    Granted(Perms),
}

impl AccessDecision {
    pub fn perms(self) -> Perms {
        match self {
            AccessDecision::Granted(perms) => perms,
            AccessDecision::Traversal | AccessDecision::NotFound => Perms::NONE,
        }
    }
}

/// A member's applicable entitlements (already filtered to the groups they belong to), tagged
/// with the [`GrantsVersion`] they were computed against. This slice does not cache these across
/// calls — see [`GrantsVersion`]'s doc comment.
pub struct EffectiveGrants<'a> {
    pub member_id: MemberId,
    pub version: GrantsVersion,
    entitlements: Vec<&'a Entitlement>,
}

impl<'a> EffectiveGrants<'a> {
    /// Filters `all_entitlements` down to the ones naming a group `member` belongs to. This is
    /// the "union of all grants from all their groups" half of the algebra; the "(share,
    /// subpath) is a prefix of P" half happens per-query in [`resolve_access`].
    pub fn compute(
        member: &Member,
        all_entitlements: &'a [Entitlement],
        version: GrantsVersion,
    ) -> Self {
        let member_groups: HashSet<GroupId> = member.groups.iter().copied().collect();
        let entitlements = all_entitlements
            .iter()
            .filter(|e| member_groups.contains(&e.group_id))
            .collect();
        EffectiveGrants {
            member_id: member.member_id,
            version,
            entitlements,
        }
    }

    /// Resolves this member's access to `path` within `share`. Checks exclusions first (they
    /// apply to every member regardless of grant breadth), then the direct/inherited union, then
    /// falls back to ancestor-traversal detection.
    pub fn resolve_access(&self, share: &Share, path: &VirtualPath) -> AccessDecision {
        if share.is_excluded(path) {
            return AccessDecision::NotFound;
        }

        let direct = self.direct_perms(share.share_id, path);
        if !direct.is_empty() {
            return AccessDecision::Granted(direct);
        }

        if self.is_traversal_ancestor(share.share_id, path) {
            return AccessDecision::Traversal;
        }

        AccessDecision::NotFound
    }

    /// Union of every applicable entitlement's perms whose `subpath` is a prefix of (or equal
    /// to) `path`, within `share_id`. This is the algebra's core union, with no traversal or
    /// exclusion logic layered in.
    fn direct_perms(&self, share_id: ShareId, path: &VirtualPath) -> Perms {
        self.entitlements
            .iter()
            .filter(|e| e.share_id == share_id && path.descends_from_or_eq(&e.subpath))
            .fold(Perms::NONE, |acc, e| acc.union(e.perms))
    }

    /// `true` if `path` is a proper ancestor of some `browse`-granted entitlement's `subpath`
    /// within `share_id` — the "browse implies ancestor traversal" edge rule. Only `browse`
    /// grants imply traversal (§A4b names `browse` specifically); an `upload`-only grant on a
    /// nested subpath does not make its ancestors traversable (consistent with "drop-box"
    /// behavior: a member with only an upload grant must be told the exact virtual path
    /// out-of-band, since nothing reveals a traversal chain to it).
    fn is_traversal_ancestor(&self, share_id: ShareId, path: &VirtualPath) -> bool {
        self.entitlements.iter().any(|e| {
            e.share_id == share_id
                && e.perms.contains(Perms::BROWSE)
                && e.subpath.descends_from_or_eq(path)
                && e.subpath != *path
        })
    }

    /// Given `dir_path`'s child entry names (as already listed from the real filesystem — this
    /// function does no I/O), returns the subset visible to this member: for each child, whether
    /// its full path is `Granted` with `browse`, or a `Traversal` step toward a deeper grant.
    /// Everything else (including anything share-excluded) is silently dropped — never returned
    /// with a "hidden" marker, so a caller cannot leak the excluded/unauthorized child's name.
    ///
    /// **Caller responsibility this function does not cover**: §A4b's hardlink `nlink` rule (see
    /// the module doc comment's "Integration point" section) — filter the real dirents through
    /// `crate::confine::identity::nlink_guard` too when `share.has_exclusions()`.
    pub fn filter_listing<'b>(
        &self,
        share: &Share,
        dir_path: &VirtualPath,
        entry_names: impl IntoIterator<Item = &'b str>,
    ) -> Vec<(&'b str, AccessDecision)> {
        entry_names
            .into_iter()
            .filter_map(|name| {
                let child_path = dir_path.join(name);
                let decision = self.resolve_access(share, &child_path);
                let visible = match decision {
                    AccessDecision::Granted(perms) => perms.contains(Perms::BROWSE),
                    AccessDecision::Traversal => true,
                    AccessDecision::NotFound => false,
                };
                visible.then_some((name, decision))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MemberStatus, ShareFlags};
    use spindle_core::Fingerprint;

    fn share(share_id: ShareId, excludes: &[&str]) -> Share {
        Share {
            share_id,
            name: "Photos".to_string(),
            mount_path: "Photos".to_string(),
            real_root: "/tmp/does-not-matter".into(),
            flags: ShareFlags {
                read_only: false,
                allow_upload: true,
                show_hidden: false,
            },
            excludes: excludes
                .iter()
                .map(|p| crate::glob::CompiledGlob::compile(p))
                .collect(),
        }
    }

    fn member(member_id: MemberId, groups: &[GroupId]) -> Member {
        Member {
            member_id,
            root_fp: Fingerprint::of_parts(&[b"member"]),
            display_name: "Alex".to_string(),
            status: MemberStatus::Active,
            devices: vec![],
            groups: groups.to_vec(),
            created: 0,
        }
    }

    fn vp(s: &str) -> VirtualPath {
        VirtualPath::parse(s).expect("valid virtual path")
    }

    fn entitlement(group: GroupId, share_id: ShareId, subpath: &str, perms: Perms) -> Entitlement {
        Entitlement::new(group, share_id, vp(subpath), perms, true).expect("valid entitlement")
    }

    // ---- Secure by default ----

    #[test]
    fn new_share_nothing_visible() {
        let share_id = ShareId(1);
        let s = share(share_id, &[]);
        let group_id = GroupId(1);
        let m = member(MemberId(1), &[group_id]);
        // An entitlement exists, but on a *different* share.
        let entitlements = vec![entitlement(group_id, ShareId(99), "", Perms::BROWSE)];
        let grants = EffectiveGrants::compute(&m, &entitlements, GrantsVersion::default());

        assert_eq!(
            grants.resolve_access(&s, &VirtualPath::root()),
            AccessDecision::NotFound
        );
        assert_eq!(
            grants.resolve_access(&s, &vp("anything.txt")),
            AccessDecision::NotFound
        );
    }

    #[test]
    fn new_member_in_default_group_nothing_visible() {
        let share_id = ShareId(1);
        let s = share(share_id, &[]);
        let members_group = GroupId(2); // built-in "Members" group, no grants configured
        let m = member(MemberId(1), &[members_group]);
        let entitlements: Vec<Entitlement> = vec![]; // nothing granted to Members yet
        let grants = EffectiveGrants::compute(&m, &entitlements, GrantsVersion::default());

        assert_eq!(
            grants.resolve_access(&s, &VirtualPath::root()),
            AccessDecision::NotFound
        );
    }

    // ---- Union / prefix / no leak to siblings ----

    #[test]
    fn browse_grant_does_not_leak_siblings() {
        let share_id = ShareId(1);
        let s = share(share_id, &[]);
        let group_id = GroupId(1);
        let m = member(MemberId(1), &[group_id]);
        let entitlements = vec![entitlement(
            group_id,
            share_id,
            "Photos/Vacation",
            Perms::BROWSE | Perms::DOWNLOAD,
        )];
        let grants = EffectiveGrants::compute(&m, &entitlements, GrantsVersion::default());

        // Descendant: inherited grant.
        assert_eq!(
            grants.resolve_access(&s, &vp("Photos/Vacation/img.jpg")),
            AccessDecision::Granted(Perms::BROWSE | Perms::DOWNLOAD)
        );
        // Exact node: direct grant.
        assert_eq!(
            grants.resolve_access(&s, &vp("Photos/Vacation")),
            AccessDecision::Granted(Perms::BROWSE | Perms::DOWNLOAD)
        );
        // Sibling: no leak.
        assert_eq!(
            grants.resolve_access(&s, &vp("Photos/Other")),
            AccessDecision::NotFound
        );
        // Ancestor: traversal only, not a full grant.
        assert_eq!(
            grants.resolve_access(&s, &vp("Photos")),
            AccessDecision::Traversal
        );
        assert_eq!(
            grants.resolve_access(&s, &VirtualPath::root()),
            AccessDecision::Traversal
        );
    }

    #[test]
    fn ancestor_traversal_listing_shows_only_the_chain_toward_the_grant() {
        let share_id = ShareId(1);
        let s = share(share_id, &[]);
        let group_id = GroupId(1);
        let m = member(MemberId(1), &[group_id]);
        let entitlements = vec![entitlement(
            group_id,
            share_id,
            "Photos/Vacation",
            Perms::BROWSE,
        )];
        let grants = EffectiveGrants::compute(&m, &entitlements, GrantsVersion::default());

        let photos = vp("Photos");
        let listing = grants.filter_listing(&s, &photos, ["Vacation", "Other", "Random"]);
        let names: Vec<&str> = listing.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec!["Vacation"],
            "only the path toward the granted subtree is listable, never siblings"
        );
        assert_eq!(listing[0].1, AccessDecision::Granted(Perms::BROWSE));
    }

    // ---- upload implies resolve-not-list ----

    #[test]
    fn upload_only_grant_resolves_without_browse() {
        let share_id = ShareId(1);
        let s = share(share_id, &[]);
        let group_id = GroupId(1);
        let m = member(MemberId(1), &[group_id]);
        let entitlements = vec![entitlement(group_id, share_id, "Drop", Perms::UPLOAD)];
        let grants = EffectiveGrants::compute(&m, &entitlements, GrantsVersion::default());

        let decision = grants.resolve_access(&s, &vp("Drop"));
        assert_eq!(decision, AccessDecision::Granted(Perms::UPLOAD));
        assert!(decision.perms().contains(Perms::UPLOAD));
        assert!(
            !decision.perms().contains(Perms::BROWSE),
            "upload-only grant must not imply browse (drop-box: resolvable, not listable)"
        );

        // Nested target under the drop-box also resolves (upload targets can be nested paths).
        let nested = grants.resolve_access(&s, &vp("Drop/newfile.txt"));
        assert_eq!(nested, AccessDecision::Granted(Perms::UPLOAD));

        // And an upload-only grant does NOT make its own ancestor traversable (no browse to
        // imply the traversal edge rule) — the member must already know "Drop" out-of-band.
        assert_eq!(
            grants.resolve_access(&s, &VirtualPath::root()),
            AccessDecision::NotFound
        );
    }

    // ---- delete does not imply download ----

    #[test]
    fn delete_does_not_imply_download() {
        let share_id = ShareId(1);
        let s = share(share_id, &[]);
        let group_id = GroupId(1);
        let m = member(MemberId(1), &[group_id]);
        let entitlements = vec![entitlement(group_id, share_id, "Files", Perms::DELETE)];
        let grants = EffectiveGrants::compute(&m, &entitlements, GrantsVersion::default());

        let decision = grants.resolve_access(&s, &vp("Files/doc.txt"));
        assert!(decision.perms().contains(Perms::DELETE));
        assert!(!decision.perms().contains(Perms::DOWNLOAD));
    }

    // ---- upload outside granted subpath ----

    #[test]
    fn upload_outside_granted_subpath_refused_at_algebra_level() {
        let share_id = ShareId(1);
        let s = share(share_id, &[]);
        let group_id = GroupId(1);
        let m = member(MemberId(1), &[group_id]);
        let entitlements = vec![entitlement(group_id, share_id, "Drop", Perms::UPLOAD)];
        let grants = EffectiveGrants::compute(&m, &entitlements, GrantsVersion::default());

        assert_eq!(
            grants.resolve_access(&s, &vp("Other/evil.txt")),
            AccessDecision::NotFound,
            "a path outside the granted subpath must never resolve to a Granted upload target"
        );
    }

    // ---- exclusions override even broad grants ----

    #[test]
    fn excluded_paths_invisible_even_to_broad_grants() {
        let share_id = ShareId(1);
        let s = share(share_id, &["Photos/Private"]);
        let owner_group = GroupId(0);
        let owner = member(MemberId(1), &[owner_group]);
        // Owner-equivalent: full perms at the share root, inherited everywhere.
        let entitlements = vec![entitlement(
            owner_group,
            share_id,
            "",
            Perms::BROWSE | Perms::DOWNLOAD | Perms::UPLOAD | Perms::DELETE,
        )];
        let grants = EffectiveGrants::compute(&owner, &entitlements, GrantsVersion::default());

        assert_eq!(
            grants.resolve_access(&s, &vp("Photos/Public/img.jpg")),
            AccessDecision::Granted(
                Perms::BROWSE | Perms::DOWNLOAD | Perms::UPLOAD | Perms::DELETE
            )
        );
        assert_eq!(
            grants.resolve_access(&s, &vp("Photos/Private/secret.txt")),
            AccessDecision::NotFound,
            "an exclusion must hide a path even from a member with a full grant at the share root"
        );
        assert_eq!(
            grants.resolve_access(&s, &vp("Photos/Private")),
            AccessDecision::NotFound
        );

        // And it must not even show up in a listing.
        let listing = grants.filter_listing(&s, &vp("Photos"), ["Public", "Private"]);
        let names: Vec<&str> = listing.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["Public"]);
    }

    // ---- not-found is indistinguishable regardless of cause ----

    #[test]
    fn denied_paths_are_indistinguishable_from_nonexistent() {
        let share_id = ShareId(1);
        let s = share(share_id, &["Photos/Private"]);
        let group_id = GroupId(1);
        let m = member(MemberId(1), &[group_id]);
        let entitlements = vec![entitlement(
            group_id,
            share_id,
            "Photos/Vacation",
            Perms::BROWSE,
        )];
        let grants = EffectiveGrants::compute(&m, &entitlements, GrantsVersion::default());

        // Case 1: a path with zero entitlement coverage at all (this algebra layer has no idea
        // whether "Photos/DoesNotExist" is a real directory or not — it never touches disk).
        let no_grant_path = grants.resolve_access(&s, &vp("Photos/DoesNotExist"));
        // Case 2: a path that IS excluded (the real directory may well exist on disk).
        let excluded_path = grants.resolve_access(&s, &vp("Photos/Private"));
        // Case 3: a path outside any grant entirely, on an unrelated branch.
        let unrelated_path = grants.resolve_access(&s, &vp("Unrelated/Branch"));

        assert_eq!(no_grant_path, AccessDecision::NotFound);
        assert_eq!(excluded_path, AccessDecision::NotFound);
        assert_eq!(unrelated_path, AccessDecision::NotFound);
        assert_eq!(
            no_grant_path, excluded_path,
            "unauthorized-but-possibly-real and excluded-and-real must produce the identical \
             AccessDecision value — no distinguishing information crosses this API"
        );
        assert_eq!(excluded_path, unrelated_path);
    }

    #[test]
    fn grants_version_is_carried_but_not_used_for_caching() {
        let share_id = ShareId(1);
        let group_id = GroupId(1);
        let m = member(MemberId(7), &[group_id]);
        let entitlements: Vec<Entitlement> =
            vec![entitlement(group_id, share_id, "", Perms::BROWSE)];
        let v = GrantsVersion(5);
        let grants = EffectiveGrants::compute(&m, &entitlements, v);
        assert_eq!(grants.version, v);
        assert_eq!(grants.member_id, MemberId(7));
        assert_eq!(GrantsVersion(5).next(), GrantsVersion(6));
    }
}
