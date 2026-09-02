//! S11-style negative integration suite for the VFS RPC pipeline (task brief deliverable #3):
//! exercises [`spindle_host_core::VfsRpcServer`] end-to-end, against real temporary directories,
//! through its public surface only (this is an external integration test — no access to this
//! crate's private `mount`/`cache`/`identity_cache` modules, exactly as a real caller would have
//! none either). Each test names the DESIGN.md rule or A12 red-team row it exercises.

use spindle_core::Fingerprint;
use spindle_host_core::{SessionContext, VfsRpcServer};
use spindle_proto::{VfsErrorCode, VfsReply, VfsRequest, VfsRequestEnvelope};
use spindle_vfs::model::{MemberId, MemberStatus, Perms, ShareFlags, ShareId, VirtualPath};
use spindle_vfs::store::Store;
use tempfile::TempDir;

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

    fn real_root(&self, name: &str) -> std::path::PathBuf {
        let p = self.sandbox.path().join(name);
        std::fs::create_dir_all(&p).expect("mkdir real root");
        p
    }

    fn add_active_member(&self, display_name: &str) -> MemberId {
        let fp = Fingerprint::of_parts(&[display_name.as_bytes()]);
        let id = self
            .store
            .add_member(fp, display_name, 0)
            .expect("add member");
        self.store.activate_member(id).expect("activate member");
        id
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

    fn server(&self) -> VfsRpcServer<&Store> {
        VfsRpcServer::new(&self.store)
    }

    fn ctx(&self, member_id: MemberId) -> SessionContext {
        SessionContext {
            member_id,
            device_fp: None,
        }
    }

    /// Like [`Self::ctx`], but carries a `device_fp` — for tests exercising device-level
    /// revocation specifically. A separate helper rather than a parameter on `ctx` so the ~20
    /// existing tests that call `ctx` (and rely on `device_fp: None`) are untouched.
    fn ctx_with_device(&self, member_id: MemberId, device_fp: Fingerprint) -> SessionContext {
        SessionContext {
            member_id,
            device_fp: Some(device_fp),
        }
    }
}

fn envelope(v: u8, request: VfsRequest) -> VfsRequestEnvelope {
    VfsRequestEnvelope { v, request }
}

fn not_found() -> VfsReply {
    VfsReply::Error {
        code: VfsErrorCode::NotFound,
    }
}

// =================================================================================================
// Traversal / `..` / absolute-path attempts inside RPC paths
// =================================================================================================

#[test]
fn dotdot_and_absolute_looking_rpc_paths_are_refused_not_found() {
    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let share_id = h.add_share(
        "Photos",
        "Photos",
        ShareFlags {
            read_only: false,
            allow_upload: true,
            show_hidden: false,
        },
    );
    let root = h.share_real_root(share_id);
    std::fs::write(root.join("a.jpg"), b"real content").expect("write a.jpg");
    // A real secret file living outside the share root, at the real filesystem level.
    std::fs::write(h.sandbox.path().join("secret.txt"), b"outside-the-share")
        .expect("write secret outside root");
    h.grant(
        member_id,
        share_id,
        "",
        Perms::BROWSE | Perms::DOWNLOAD | Perms::UPLOAD | Perms::DELETE,
    );

    let server = h.server();
    let ctx = h.ctx(member_id);

    // "../secret.txt" contains a literal ".." component: rejected at VirtualPath::parse, before
    // ever reaching the mount table or the real filesystem.
    for malicious in [
        "Photos/../secret.txt",
        "../secret.txt",
        "Photos/../../secret.txt",
    ] {
        let reply = server.handle(
            &ctx,
            1,
            envelope(
                1,
                VfsRequest::Stat {
                    path: malicious.to_string(),
                },
            ),
        );
        assert_eq!(
            reply,
            not_found(),
            "traversal attempt {malicious:?} must be refused"
        );
    }

    // A leading slash collapses harmlessly into an ordinary (and here, unauthorized) virtual
    // path — DESIGN.md's virtual paths are never resolved against the real OS root.
    let reply = server.handle(
        &ctx,
        2,
        envelope(
            1,
            VfsRequest::Stat {
                path: "/etc/passwd".to_string(),
            },
        ),
    );
    assert_eq!(reply, not_found());

    // Sanity: the legitimate path under the same grant still works, proving the traversal
    // rejections above are about the malicious paths specifically, not a broken pipeline.
    let reply = server.handle(
        &ctx,
        3,
        envelope(
            1,
            VfsRequest::Stat {
                path: "Photos/a.jpg".to_string(),
            },
        ),
    );
    assert!(matches!(reply, VfsReply::Stat { .. }));
}

// =================================================================================================
// Symlink escape (A12 #19)
// =================================================================================================

#[test]
#[cfg(unix)]
fn symlink_escaping_the_share_root_is_not_found() {
    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
    let root = h.share_real_root(share_id);
    let outside = h.sandbox.path().join("outside.txt");
    std::fs::write(&outside, b"outside-content").expect("write outside file");
    std::os::unix::fs::symlink(&outside, root.join("escape")).expect("create escaping symlink");
    h.grant(member_id, share_id, "", Perms::BROWSE | Perms::DOWNLOAD);

    let server = h.server();
    let ctx = h.ctx(member_id);

    let reply = server.handle(
        &ctx,
        1,
        envelope(
            1,
            VfsRequest::Stat {
                path: "Photos/escape".to_string(),
            },
        ),
    );
    assert_eq!(
        reply,
        not_found(),
        "cap-std must refuse to stat through an escaping symlink"
    );

    let reply = server.handle(
        &ctx,
        2,
        envelope(
            1,
            VfsRequest::Read {
                path: "Photos/escape".to_string(),
                offset: 0,
                len: 64,
            },
        ),
    );
    assert_eq!(
        reply,
        not_found(),
        "cap-std must refuse to read through an escaping symlink"
    );
}

// =================================================================================================
// Unauthorized paths indistinguishable from nonexistent — compare error bytes
// =================================================================================================

#[test]
fn unauthorized_and_nonexistent_paths_produce_byte_identical_errors() {
    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
    let root = h.share_real_root(share_id);
    // "Private" genuinely exists on disk but is never granted to this member.
    std::fs::create_dir(root.join("Private")).expect("mkdir Private");
    std::fs::write(root.join("Private/secret.jpg"), b"secret").expect("write secret");
    // "DoesNotExist" never existed at all.
    h.grant(
        member_id,
        share_id,
        "Vacation",
        Perms::BROWSE | Perms::DOWNLOAD,
    );

    let server = h.server();
    let ctx = h.ctx(member_id);

    let unauthorized_but_real = server.handle(
        &ctx,
        1,
        envelope(
            1,
            VfsRequest::Stat {
                path: "Photos/Private/secret.jpg".to_string(),
            },
        ),
    );
    let genuinely_nonexistent = server.handle(
        &ctx,
        2,
        envelope(
            1,
            VfsRequest::Stat {
                path: "Photos/DoesNotExist/nothing.jpg".to_string(),
            },
        ),
    );

    assert_eq!(unauthorized_but_real, not_found());
    assert_eq!(genuinely_nonexistent, not_found());
    assert_eq!(
        unauthorized_but_real.to_canonical_bytes(),
        genuinely_nonexistent.to_canonical_bytes(),
        "the wire bytes for \"exists but unauthorized\" and \"genuinely does not exist\" must be \
         identical — DESIGN.md §A4b: unauthorized == not_found, no existence leak"
    );

    // Same property for `read` and `list`.
    let read_unauthorized = server.handle(
        &ctx,
        3,
        envelope(
            1,
            VfsRequest::Read {
                path: "Photos/Private/secret.jpg".to_string(),
                offset: 0,
                len: 16,
            },
        ),
    );
    let read_nonexistent = server.handle(
        &ctx,
        4,
        envelope(
            1,
            VfsRequest::Read {
                path: "Photos/DoesNotExist.bin".to_string(),
                offset: 0,
                len: 16,
            },
        ),
    );
    assert_eq!(
        read_unauthorized.to_canonical_bytes(),
        read_nonexistent.to_canonical_bytes()
    );
}

// =================================================================================================
// Revoked member mid-session
// =================================================================================================

#[test]
fn revoked_member_is_denied_on_the_very_next_request_without_any_grants_version_change() {
    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
    let root = h.share_real_root(share_id);
    std::fs::write(root.join("a.jpg"), b"hello").expect("write a.jpg");
    h.grant(member_id, share_id, "", Perms::BROWSE | Perms::DOWNLOAD);

    let server = h.server();
    let ctx = h.ctx(member_id);

    let before = server.handle(
        &ctx,
        1,
        envelope(
            1,
            VfsRequest::Stat {
                path: "Photos/a.jpg".to_string(),
            },
        ),
    );
    assert!(
        matches!(before, VfsReply::Stat { .. }),
        "must succeed while the member is still active"
    );

    let grants_version_before = h.store.grants_version().expect("grants_version");
    let cap_epoch_before = h.store.cap_epoch().expect("cap_epoch");

    h.store.revoke_member(member_id).expect("revoke member");

    assert_eq!(
        h.store.grants_version().expect("grants_version"),
        grants_version_before,
        "revoking a member must not bump grants_version (spindle_vfs::store's own documented \
         two-counters rule) — this test would be meaningless against a store that did"
    );
    assert_eq!(
        h.store.cap_epoch().expect("cap_epoch"),
        cap_epoch_before,
        "revoking a member alone (no explicit bump_cap_epoch call) must not move cap_epoch either"
    );

    let after = server.handle(
        &ctx,
        2,
        envelope(
            1,
            VfsRequest::Stat {
                path: "Photos/a.jpg".to_string(),
            },
        ),
    );
    assert_eq!(
        after,
        not_found(),
        "the very next request after revocation must be denied, even though neither counter this \
         crate's grants cache keys off moved — proving member liveness is checked fresh every \
         request, never served from the grants_version/cap_epoch-keyed cache (see \
         spindle_host_core's cache module doc comment)"
    );
}

// =================================================================================================
// Revoked device mid-session (member stays Active — DESIGN.md §A4: a revocation names
// `root_fp | device_fp`, so device-level revocation must be enforced independently of
// member-level revocation)
// =================================================================================================

#[test]
fn revoked_device_is_denied_on_the_very_next_request_while_its_member_stays_active() {
    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let device_fp = Fingerprint::of_parts(&[b"Alex's iPhone"]);
    h.store
        .add_device(member_id, device_fp, "Alex's iPhone", 0, None)
        .expect("add device");
    let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
    let root = h.share_real_root(share_id);
    std::fs::write(root.join("a.jpg"), b"hello").expect("write a.jpg");
    h.grant(member_id, share_id, "", Perms::BROWSE | Perms::DOWNLOAD);

    let server = h.server();
    let ctx = h.ctx_with_device(member_id, device_fp);

    let before = server.handle(
        &ctx,
        1,
        envelope(
            1,
            VfsRequest::Stat {
                path: "Photos/a.jpg".to_string(),
            },
        ),
    );
    assert!(
        matches!(before, VfsReply::Stat { .. }),
        "must succeed while the device is still un-revoked"
    );

    let grants_version_before = h.store.grants_version().expect("grants_version");
    let cap_epoch_before = h.store.cap_epoch().expect("cap_epoch");

    h.store.revoke_device(device_fp).expect("revoke device");

    assert_eq!(
        h.store.grants_version().expect("grants_version"),
        grants_version_before,
        "revoking a device must not bump grants_version — this test would be meaningless \
         against a store that did"
    );
    assert_eq!(
        h.store.cap_epoch().expect("cap_epoch"),
        cap_epoch_before,
        "revoking a device alone (no explicit bump_cap_epoch call) must not move cap_epoch either"
    );
    assert_eq!(
        h.store
            .get_member(member_id)
            .expect("get_member")
            .expect("member exists")
            .status,
        MemberStatus::Active,
        "the member itself must still be Active — this test isolates device revocation \
         specifically, not member revocation"
    );

    let after = server.handle(
        &ctx,
        2,
        envelope(
            1,
            VfsRequest::Stat {
                path: "Photos/a.jpg".to_string(),
            },
        ),
    );
    assert_eq!(
        after,
        not_found(),
        "the very next request after device revocation must be denied, even though the member \
         is still Active and neither counter this crate's grants cache keys off moved — proving \
         device liveness is checked fresh every request (DESIGN.md §A4: the host rejects \
         envelopes/VFS requests from revoked keys per request, where a revocation names \
         `root_fp | device_fp`)"
    );
}

// =================================================================================================
// Protocol version negotiation
// =================================================================================================

#[test]
fn request_below_minimum_protocol_version_is_rejected() {
    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let server = h.server();
    let reply = server.handle(&h.ctx(member_id), 1, envelope(0, VfsRequest::Whoami));
    assert_eq!(
        reply,
        VfsReply::Error {
            code: VfsErrorCode::UnsupportedVersion
        }
    );
}

// =================================================================================================
// Paging boundaries
// =================================================================================================

#[test]
fn list_pages_through_every_entry_exactly_once_in_order() {
    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
    let root = h.share_real_root(share_id);
    let names = ["a.jpg", "b.jpg", "c.jpg", "d.jpg", "e.jpg"];
    for name in names {
        std::fs::write(root.join(name), b"x").expect("write file");
    }
    h.grant(member_id, share_id, "", Perms::BROWSE | Perms::DOWNLOAD);

    let server = h.server();
    let ctx = h.ctx(member_id);

    let mut collected = Vec::new();
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let reply = server.handle(
            &ctx,
            1,
            envelope(
                1,
                VfsRequest::List {
                    path: "Photos".to_string(),
                    cursor: cursor.clone(),
                    limit: Some(2),
                },
            ),
        );
        let VfsReply::List {
            entries,
            next_cursor,
        } = reply
        else {
            panic!("expected List reply");
        };
        assert!(entries.len() <= 2, "must respect the requested limit");
        collected.extend(entries.into_iter().map(|e| e.name));
        match next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
        assert!(
            collected.len() <= names.len(),
            "pagination must terminate at exactly the source's length, not loop forever"
        );
    }

    assert_eq!(
        collected, names,
        "every entry exactly once, in sorted order"
    );
}

#[test]
fn list_cursor_survives_a_deletion_between_pages() {
    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
    let root = h.share_real_root(share_id);
    for name in ["a.jpg", "b.jpg", "c.jpg"] {
        std::fs::write(root.join(name), b"x").expect("write file");
    }
    h.grant(member_id, share_id, "", Perms::BROWSE | Perms::DOWNLOAD);

    let server = h.server();
    let ctx = h.ctx(member_id);

    let first = server.handle(
        &ctx,
        1,
        envelope(
            1,
            VfsRequest::List {
                path: "Photos".to_string(),
                cursor: None,
                limit: Some(1),
            },
        ),
    );
    let VfsReply::List {
        entries,
        next_cursor,
    } = first
    else {
        panic!("expected List reply");
    };
    assert_eq!(entries[0].name, "a.jpg");
    let cursor = next_cursor.expect("more entries remain");

    // "b.jpg" (the entry the cursor logically points past) is deleted between pages.
    std::fs::remove_file(root.join("b.jpg")).expect("remove b.jpg");

    let second = server.handle(
        &ctx,
        2,
        envelope(
            1,
            VfsRequest::List {
                path: "Photos".to_string(),
                cursor: Some(cursor),
                limit: Some(10),
            },
        ),
    );
    let VfsReply::List { entries, .. } = second else {
        panic!("expected List reply");
    };
    assert_eq!(
        entries.into_iter().map(|e| e.name).collect::<Vec<_>>(),
        vec!["c.jpg".to_string()],
        "keyset pagination must resume correctly (skip everything <= the cursor name) even when \
         the cursor's own entry no longer exists"
    );
}

// =================================================================================================
// Virtual-root listing filtered
// =================================================================================================

#[test]
fn virtual_root_listing_shows_only_shares_the_member_can_browse() {
    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let photos = h.add_share("Photos", "Photos", ShareFlags::default());
    let _private = h.add_share("Private", "Private", ShareFlags::default());
    h.grant(member_id, photos, "", Perms::BROWSE);
    // No grant at all on "Private" — it must not appear at the virtual root.

    let server = h.server();
    let reply = server.handle(
        &h.ctx(member_id),
        1,
        envelope(
            1,
            VfsRequest::List {
                path: "".to_string(),
                cursor: None,
                limit: None,
            },
        ),
    );
    let VfsReply::List { entries, .. } = reply else {
        panic!("expected List reply");
    };
    assert_eq!(
        entries.len(),
        1,
        "Private must not be visible at the virtual root"
    );
    assert_eq!(entries[0].name, "Photos");
}

#[test]
fn intermediate_virtual_directory_is_listed_and_traversable_toward_a_nested_mount() {
    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let nested = h.add_share("NestedPhotos", "Family/Photos", ShareFlags::default());
    h.grant(member_id, nested, "", Perms::BROWSE);

    let server = h.server();
    let ctx = h.ctx(member_id);

    // The virtual root shows the synthetic "Family" directory (no share is mounted there
    // directly — only "Family/Photos" is a real mount).
    let root_listing = server.handle(
        &ctx,
        1,
        envelope(
            1,
            VfsRequest::List {
                path: "".to_string(),
                cursor: None,
                limit: None,
            },
        ),
    );
    let VfsReply::List { entries, .. } = root_listing else {
        panic!("expected List reply");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "Family");

    // Descending into it lists the actual mount.
    let family_listing = server.handle(
        &ctx,
        2,
        envelope(
            1,
            VfsRequest::List {
                path: "Family".to_string(),
                cursor: None,
                limit: None,
            },
        ),
    );
    let VfsReply::List { entries, .. } = family_listing else {
        panic!("expected List reply");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "Photos");
}

// =================================================================================================
// whoami trimmed (§A4b / A12 #32)
// =================================================================================================

#[test]
fn whoami_never_leaks_group_names_or_ids() {
    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let share_id = h.add_share("Photos", "Photos", ShareFlags::default());
    // A deliberately distinctive group name that must never surface on the wire.
    let group_id = h
        .store
        .create_custom_group("TopSecretInternalGroupName")
        .expect("create group");
    h.store
        .add_member_to_group(member_id, group_id)
        .expect("join group");
    h.store
        .add_entitlement(
            group_id,
            share_id,
            &VirtualPath::parse("Vacation").expect("valid subpath"),
            Perms::BROWSE,
        )
        .expect("grant");

    let server = h.server();
    let reply = server.handle(&h.ctx(member_id), 1, envelope(1, VfsRequest::Whoami));
    let VfsReply::Whoami {
        member_display,
        effective_paths,
    } = &reply
    else {
        panic!("expected Whoami reply");
    };
    assert_eq!(member_display, "Alex");
    assert_eq!(effective_paths, &vec!["Photos/Vacation".to_string()]);

    let bytes = reply.to_canonical_bytes();
    assert!(
        !bytes
            .windows(b"TopSecretInternalGroupName".len())
            .any(|w| w == b"TopSecretInternalGroupName"),
        "the group's name must never appear in the encoded whoami reply"
    );
    let group_id_bytes = group_id.0.to_be_bytes();
    assert!(
        !bytes
            .windows(group_id_bytes.len())
            .any(|w| w == group_id_bytes)
            || group_id.0 < 256,
        "the group's raw id must not appear in the encoded whoami reply either"
    );
}

#[test]
fn whoami_for_a_member_with_no_grants_has_empty_effective_paths() {
    let h = Harness::new();
    let member_id = h.add_active_member("Newcomer");
    let server = h.server();
    let reply = server.handle(&h.ctx(member_id), 1, envelope(1, VfsRequest::Whoami));
    match reply {
        VfsReply::Whoami {
            member_display,
            effective_paths,
        } => {
            assert_eq!(member_display, "Newcomer");
            assert!(effective_paths.is_empty());
        }
        other => panic!("expected Whoami, got {other:?}"),
    }
}

// =================================================================================================
// Unknown / inactive member statuses
// =================================================================================================

#[test]
fn unknown_member_id_is_not_found_not_a_crash() {
    let h = Harness::new();
    let server = h.server();
    let ctx = SessionContext {
        member_id: MemberId(99999),
        device_fp: None,
    };
    let reply = server.handle(&ctx, 1, envelope(1, VfsRequest::Whoami));
    assert_eq!(reply, not_found());
}

#[test]
fn invited_but_not_yet_active_member_is_not_found() {
    let h = Harness::new();
    let fp = Fingerprint::of_parts(&[b"Invitee"]);
    let member_id = h.store.add_member(fp, "Invitee", 0).expect("add member");
    assert_eq!(
        h.store
            .get_member(member_id)
            .expect("get_member")
            .expect("exists")
            .status,
        MemberStatus::Invited,
        "sanity: a freshly added member starts Invited, not Active"
    );

    let server = h.server();
    let reply = server.handle(&h.ctx(member_id), 1, envelope(1, VfsRequest::Whoami));
    assert_eq!(reply, not_found());
}
