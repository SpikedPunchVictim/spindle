//! Mount-path virtual-tree resolution — the gap flagged at the end of Stage 6 slice 1 and closed
//! here: `spindle-vfs::algebra` computes access *within* one already-identified share (DESIGN.md
//! §A4b's union algebra takes a `&Share` parameter), but nothing below this crate resolves an
//! incoming RPC's virtual path (spanning the whole per-host tree of every share's `mount_path`)
//! down to "which share, and what's left of the path inside it." That is this module's only job.
//!
//! # Shape
//!
//! Every [`spindle_vfs::model::Share::mount_path`] is parsed into components and inserted into a
//! small trie ([`MountNode`]): a leaf `Share` node where a mount lands, or an `Intermediate` node
//! for every path segment that exists only because some share's `mount_path` has more than one
//! component (e.g. a share mounted at `"Family/Photos"` with no share mounted at `"Family"`
//! itself — `"Family"` is a real, listable virtual directory even though it is not itself a
//! mount). [`Store::add_share`] already rejects a `mount_path` that is equal to, an ancestor of,
//! or a descendant of another share's `mount_path` (see `spindle_vfs::store::StoreError::
//! MountPathCollision`, added alongside this crate in the same slice) — so this trie is always
//! well-formed: a `Share` node is always a leaf, and no two mounts ever compete for the same
//! subtree.
//!
//! A share mounted at the virtual root itself (`mount_path == ""`) is a legitimate, if unusual,
//! single-share-fills-the-whole-tree configuration — DESIGN.md's mount-collision rule (any two
//! mount paths in a prefix relation collide) means at most one share can ever have this
//! `mount_path` at a time, and no other share can coexist with it. It cannot be keyed into the
//! trie's `BTreeMap<String, MountNode>` (there is no name to key it under), so it is tracked
//! separately as [`MountTable::root_share`].
//!
//! # Fold-key aware lookup
//!
//! Mount-path components are compared via [`spindle_vfs::confine::fold_key`] — the same
//! case/Unicode folding [`spindle_vfs::model::VirtualPath::descends_from_or_eq`] uses internally
//! — so a client that reaches a mount through a different Unicode normalization or case spelling
//! of the same name still resolves to the same share, exactly as entitlement subpaths already
//! fold within a share.

use spindle_vfs::confine::fold_key;
use spindle_vfs::model::{Share, VirtualPath};
use std::collections::BTreeMap;

/// One node of the mount-path trie. `Share` is always a leaf (see the module doc comment on why
/// the store's collision check guarantees this).
#[derive(Debug, Clone)]
pub(crate) enum MountNode {
    Share(Share),
    Intermediate(BTreeMap<String, MountNode>),
}

/// The result of resolving one virtual path against a [`MountTable`].
#[derive(Debug)]
pub(crate) enum MountLookup<'a> {
    /// `path` landed inside `share`; `subpath` is what remains of `path` once `share`'s
    /// `mount_path` prefix is consumed (the coordinate `spindle_vfs::algebra` and
    /// `spindle_vfs::confine` operate in).
    Share {
        share: &'a Share,
        subpath: VirtualPath,
    },
    /// `path` is not itself a mount, but is a real (if synthetic) virtual directory on the way to
    /// one or more mounts — the virtual root, or an intermediate directory like `"Family"` in the
    /// module doc comment's example. Carries that node's children for listing.
    Intermediate(&'a BTreeMap<String, MountNode>),
    /// `path` matches no mount and is not an ancestor of one either — genuinely off the tree.
    NotFound,
}

/// The per-host virtual tree of every configured share's `mount_path`, built fresh from
/// `Store::list_shares()` on every request (see `crate::cache::GrantsCache` — the shares list
/// itself is cached there; rebuilding this trie from an already-fetched `Vec<Share>` is cheap
/// relative to the SQLite round trip it replaces, well within the `StoreLimits::max_shares`
/// default of 256).
pub(crate) struct MountTable {
    root_share: Option<Share>,
    children: BTreeMap<String, MountNode>,
}

impl MountTable {
    pub(crate) fn build(shares: Vec<Share>) -> Self {
        let mut root_share = None;
        let mut children: BTreeMap<String, MountNode> = BTreeMap::new();
        for share in shares {
            let mount_path = VirtualPath::parse(&share.mount_path)
                .expect("share.mount_path is validated at Store::add_share time");
            if mount_path.is_root() {
                root_share = Some(share);
            } else {
                insert(&mut children, mount_path.components(), share);
            }
        }
        MountTable {
            root_share,
            children,
        }
    }

    pub(crate) fn resolve(&self, path: &VirtualPath) -> MountLookup<'_> {
        if let Some(share) = &self.root_share {
            return MountLookup::Share {
                share,
                subpath: path.clone(),
            };
        }
        resolve_in(&self.children, path.components())
    }
}

fn insert(map: &mut BTreeMap<String, MountNode>, components: &[String], share: Share) {
    let (head, rest) = components
        .split_first()
        .expect("mount_path is non-root here, so it has at least one component");
    if rest.is_empty() {
        map.insert(head.clone(), MountNode::Share(share));
        return;
    }
    let entry = map
        .entry(head.clone())
        .or_insert_with(|| MountNode::Intermediate(BTreeMap::new()));
    match entry {
        MountNode::Intermediate(sub) => insert(sub, rest, share),
        MountNode::Share(_) => unreachable!(
            "a mount_path collision (this component already a Share leaf) must have been \
             rejected by Store::add_share's MountPathCollision check before reaching this trie"
        ),
    }
}

fn resolve_in<'a>(map: &'a BTreeMap<String, MountNode>, components: &[String]) -> MountLookup<'a> {
    match components.split_first() {
        None => MountLookup::Intermediate(map),
        Some((head, rest)) => match find_fold(map, head) {
            Some(MountNode::Share(share)) => MountLookup::Share {
                share,
                subpath: components_to_virtual_path(rest),
            },
            Some(MountNode::Intermediate(sub)) => resolve_in(sub, rest),
            None => MountLookup::NotFound,
        },
    }
}

fn find_fold<'a>(map: &'a BTreeMap<String, MountNode>, name: &str) -> Option<&'a MountNode> {
    let key = fold_key(name);
    map.iter()
        .find(|(k, _)| fold_key(k) == key)
        .map(|(_, node)| node)
}

fn components_to_virtual_path(components: &[String]) -> VirtualPath {
    components
        .iter()
        .fold(VirtualPath::root(), |acc, c| acc.join(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_vfs::model::{ShareFlags, ShareId};

    fn share(id: u64, mount_path: &str) -> Share {
        Share {
            share_id: ShareId(id),
            name: format!("share-{id}"),
            mount_path: mount_path.to_string(),
            real_root: "/tmp/does-not-matter".into(),
            flags: ShareFlags::default(),
            excludes: vec![],
        }
    }

    fn vp(s: &str) -> VirtualPath {
        VirtualPath::parse(s).expect("valid virtual path")
    }

    #[test]
    fn resolves_a_single_component_mount_and_its_subpath() {
        let table = MountTable::build(vec![share(1, "Photos")]);
        match table.resolve(&vp("Photos/Vacation/img.jpg")) {
            MountLookup::Share { share, subpath } => {
                assert_eq!(share.share_id, ShareId(1));
                assert_eq!(subpath, vp("Vacation/img.jpg"));
            }
            other => panic!("expected Share, got {other:?}"),
        }
        match table.resolve(&vp("Photos")) {
            MountLookup::Share { share, subpath } => {
                assert_eq!(share.share_id, ShareId(1));
                assert_eq!(subpath, VirtualPath::root());
            }
            other => panic!("expected Share, got {other:?}"),
        }
    }

    #[test]
    fn intermediate_directory_synthesized_for_multi_component_mount_path() {
        let table = MountTable::build(vec![share(1, "Family/Photos"), share(2, "Family/Docs")]);
        match table.resolve(&vp("Family")) {
            MountLookup::Intermediate(children) => {
                assert_eq!(children.len(), 2);
                assert!(children.contains_key("Photos"));
                assert!(children.contains_key("Docs"));
            }
            other => panic!("expected Intermediate, got {other:?}"),
        }
        match table.resolve(&VirtualPath::root()) {
            MountLookup::Intermediate(children) => {
                assert_eq!(children.len(), 1);
                assert!(children.contains_key("Family"));
            }
            other => panic!("expected Intermediate, got {other:?}"),
        }
        match table.resolve(&vp("Family/Photos/img.jpg")) {
            MountLookup::Share { share, subpath } => {
                assert_eq!(share.share_id, ShareId(1));
                assert_eq!(subpath, vp("img.jpg"));
            }
            other => panic!("expected Share, got {other:?}"),
        }
    }

    #[test]
    fn unrelated_path_is_not_found() {
        let table = MountTable::build(vec![share(1, "Photos")]);
        assert!(matches!(
            table.resolve(&vp("Music/song.mp3")),
            MountLookup::NotFound
        ));
    }

    #[test]
    fn root_mounted_share_captures_the_entire_tree() {
        let table = MountTable::build(vec![share(1, "")]);
        match table.resolve(&vp("anything/at/all")) {
            MountLookup::Share { share, subpath } => {
                assert_eq!(share.share_id, ShareId(1));
                assert_eq!(subpath, vp("anything/at/all"));
            }
            other => panic!("expected Share, got {other:?}"),
        }
    }

    #[test]
    fn mount_lookup_is_fold_key_aware() {
        let table = MountTable::build(vec![share(1, "Café")]);
        match table.resolve(&vp("cafe\u{0301}/img.jpg")) {
            MountLookup::Share { share, .. } => assert_eq!(share.share_id, ShareId(1)),
            other => panic!("expected Share, got {other:?}"),
        }
    }
}
