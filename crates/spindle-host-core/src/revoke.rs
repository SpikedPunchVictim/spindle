//! Host-side revoke-and-publish (DESIGN.md §A4): turns a `spindle_vfs::store::Store` revocation
//! mutation (`Store::revoke_member` / `Store::revoke_device`) into the signed, publishable
//! `RevocationRecord` that `spindle_helper::revoke::ingest_revocation` already knows how to admit
//! on `registry.revoke.<host_fp>`. Everything except the actual NATS publish — a later slice wires
//! [`RevocationPublication::subject`]/[`RevocationPublication::record`] onto a real connection;
//! this module's whole job is minting a record the wire-side consumer will accept.
//!
//! # Ordering: store first, mint second [deliberate]
//!
//! DESIGN.md §A4 makes the **host's own** per-request enforcement authoritative and the helper's
//! ingestion of a published record explicitly "best-effort" (`spindle_helper::revoke`'s module doc
//! comment: "the authoritative check is the host's per-request enforcement"). So
//! [`revoke_member_and_mint`]/[`revoke_device_and_mint`] apply the revocation to the store
//! (`Store::revoke_member`/`Store::revoke_device`) and bump `cap_epoch`
//! (`Store::bump_cap_epoch`) *before* minting anything. If the mint step were first, or if this
//! function crashed/returned early between minting and applying, a signed record could exist
//! claiming a revocation the host's own durable state does not yet enforce — and if the
//! subsequent publish then failed, or the helper never received it, nothing would be left to
//! catch that gap. With store-first ordering, the host's own next request against that subject is
//! refused regardless of what happens to the publish: `crate::server`'s per-request
//! `denied:member_not_active`/`denied:device_revoked` gates and `crate::authorize`'s connect-time
//! twin both read straight from the store, not from anything this module mints.
//!
//! # `cap_epoch` is bumped here, explicitly — not inside `Store::revoke_*` [deliberate]
//!
//! `Store::revoke_member`/`Store::revoke_device` do **not** touch `cap_epoch` — see
//! `spindle_vfs::store`'s module doc comment ("Two counters, two rules") and the store's own
//! `revoke_does_not_bump_cap_epoch_automatically` test. That split is mechanism vs. policy: the
//! store primitive records the membership/device fact; deciding that a given revocation is *also*
//! the kind of security event that must invalidate every outstanding capability (§A4: "cap_epoch
//! bumps ... only on security events (member/device revocation)") is this module's job, not the
//! store's. A caller that wants to revoke without invalidating any outstanding cap — not a
//! scenario this module needs, but one the store's split deliberately still allows — calls
//! `Store::revoke_member`/`Store::revoke_device` directly instead of going through here.
//!
//! # What goes in `revoked`
//!
//! §A4's record shape is `revoked: [root_fp | device_fp, ...]` — a list that may hold either kind
//! of fingerprint, opaque to `spindle_proto::artifacts::RevocationRecord` itself.
//! [`revoke_member_and_mint`] names the member's **`root_fp` alone**, never its individual device
//! fingerprints: the helper's connect check is `view.is_revoked(&host_fp, &root_fp) ||
//! view.is_revoked(&host_fp, &device_fp)` (`crates/spindle-helper/src/authz.rs`'s
//! `decide_device_connect`, ~line 388) — an OR, so naming the root already refuses every one of
//! that member's devices; enumerating them individually would add nothing but bloat to a record
//! that gets replicated and durably stored. [`revoke_device_and_mint`] names the **`device_fp`
//! alone** — the entire point of a device revocation, as opposed to a member revocation, is that
//! the member and their other devices keep working.
//!
//! # Subject encoding
//!
//! `registry.revoke.<host_fp>`, where `<host_fp>` is `host_fp`'s `Display` rendering (lowercase,
//! unpadded RFC 4648 base32 — `spindle_core::Fingerprint`'s `Display` impl,
//! `crates/spindle-core/src/fingerprint.rs`). This is not a guess: it is the exact inverse of how
//! `spindle_helper::revoke::ingest_revocation` recovers the subject's host_fp
//! (`crates/spindle-helper/src/revoke.rs`'s `parse_subject_host_fp`, which delegates to
//! `crate::parse_fp_after_prefix`, whose final step is `token.parse::<Fingerprint>()` —
//! `FromStr for Fingerprint`'s doc comment names itself "the exact inverse of Display"), and it
//! matches that module's own test fixture `subject_for` (`format!("registry.revoke.{host_fp}")`
//! at `crates/spindle-helper/src/revoke.rs:198-200`) byte for byte.

use spindle_core::artifacts::issue_revocation_record;
use spindle_core::{Fingerprint, SigningKey};
use spindle_proto::artifacts::RevocationRecord;
use spindle_vfs::model::MemberId;
use spindle_vfs::store::{Store, StoreError};
use thiserror::Error;

/// The `registry.revoke.` subject prefix, mirroring
/// `crates/spindle-helper/src/revoke.rs`'s own `SUBJECT_PREFIX` constant — kept as a literal here
/// rather than a shared crate (this crate must not depend on `spindle-helper`; see the module doc
/// comment's "Subject encoding" section) but pinned to the identical string.
const SUBJECT_PREFIX: &str = "registry.revoke.";

/// Errors from [`revoke_member_and_mint`]/[`revoke_device_and_mint`]. Both functions only ever
/// call into `spindle_vfs::store::Store`, so every failure mode is a [`StoreError`] — there is no
/// "member has no resolvable `root_fp`" variant here because `Store::get_member` always returns
/// the `root_fp` alongside everything else about a member (`crates/spindle-vfs/src/model.rs`'s
/// `Member` struct); if a member row vanished between this call's own `revoke_member` and its
/// follow-up `get_member`, that already surfaces as `StoreError::MemberNotFound`.
#[derive(Debug, Error)]
pub enum RevokeError {
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The signed, publishable output of [`revoke_member_and_mint`]/[`revoke_device_and_mint`] — a
/// `RevocationRecord` (DESIGN.md §A4/§A7b) plus the subject to publish it on. Publishing itself
/// (`async-nats`) is out of scope for this module — see the module doc comment.
pub struct RevocationPublication {
    /// `registry.revoke.<host_fp>` — see the module doc comment's "Subject encoding" section for
    /// exactly how `<host_fp>` is rendered and why that encoding is the one
    /// `spindle_helper::revoke::ingest_revocation` expects.
    pub subject: String,
    pub record: RevocationRecord,
    /// The host's `cap_epoch` after the bump this call performed — identical to `record.epoch`,
    /// exposed separately so a caller doesn't need to re-decode the record to log/act on it.
    pub cap_epoch: u64,
}

fn subject_for(host_fp: Fingerprint) -> String {
    format!("{SUBJECT_PREFIX}{host_fp}")
}

/// Revokes `member_id` and mints the record for it: applies `store.revoke_member`, bumps
/// `cap_epoch`, then signs a `RevocationRecord` naming the member's `root_fp` alone (see the
/// module doc comment's "What goes in `revoked`" section for why not its individual devices).
/// `op_key` is the host operating key (or identity root — `issue_revocation_record` does not
/// distinguish, per its own doc comment); key custody is deliberately out of scope here (see
/// `crates/spindle-vfs/src/audit/mod.rs`'s doc comment on the same deferral).
pub fn revoke_member_and_mint(
    store: &Store,
    op_key: &SigningKey,
    host_fp: Fingerprint,
    member_id: MemberId,
    ts: u64,
) -> Result<RevocationPublication, RevokeError> {
    store.revoke_member(member_id)?;
    let epoch = store.bump_cap_epoch()?;

    let root_fp = store
        .get_member(member_id)?
        .ok_or(StoreError::MemberNotFound(member_id))?
        .root_fp;

    let record = issue_revocation_record(op_key, host_fp, epoch, vec![root_fp], ts);
    Ok(RevocationPublication {
        subject: subject_for(host_fp),
        record,
        cap_epoch: epoch,
    })
}

/// Revokes `device_fp` and mints the record for it: applies `store.revoke_device`, bumps
/// `cap_epoch`, then signs a `RevocationRecord` naming `device_fp` alone — the member and their
/// other devices are unaffected (see the module doc comment's "What goes in `revoked`" section).
pub fn revoke_device_and_mint(
    store: &Store,
    op_key: &SigningKey,
    host_fp: Fingerprint,
    device_fp: Fingerprint,
    ts: u64,
) -> Result<RevocationPublication, RevokeError> {
    store.revoke_device(device_fp)?;
    let epoch = store.bump_cap_epoch()?;

    let record = issue_revocation_record(op_key, host_fp, epoch, vec![device_fp], ts);
    Ok(RevocationPublication {
        subject: subject_for(host_fp),
        record,
        cap_epoch: epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::artifacts::{is_newer_epoch, verify_revocation_record};
    use spindle_core::identity::DeviceKey;
    use spindle_vfs::model::{DevicePublicKeys, MemberStatus};

    fn op_key() -> SigningKey {
        SigningKey::from_bytes(&[0x21; 32])
    }

    fn other_key() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    fn host_fp() -> Fingerprint {
        Fingerprint::of_parts(&[b"revoke-and-mint-host"])
    }

    fn store_with_member(display_name: &str) -> (Store, MemberId, Fingerprint) {
        let store = Store::open_in_memory().expect("open in-memory store");
        let root_fp = Fingerprint::of_parts(&[display_name.as_bytes()]);
        let member_id = store
            .add_member(root_fp, display_name, 0)
            .expect("add_member");
        store.activate_member(member_id).expect("activate_member");
        (store, member_id, root_fp)
    }

    fn enroll_device(store: &Store, member_id: MemberId, seed: u8) -> Fingerprint {
        let device = DeviceKey::from_seeds([seed; 32], [seed.wrapping_add(1); 32]);
        let device_fp = device.device_fp();
        let keys = DevicePublicKeys {
            sign_pk: device.sign_public_key().as_bytes().to_vec(),
            agree_pk: device.agree_public_key().as_bytes().to_vec(),
        };
        store
            .add_device(member_id, device_fp, "device", 0, Some(&keys))
            .expect("add_device");
        device_fp
    }

    // ---- revoke_member_and_mint -------------------------------------------------------------

    #[test]
    fn revoking_a_member_sets_that_members_status_to_revoked_in_the_store() {
        let (store, member_id, _root_fp) = store_with_member("alex");

        revoke_member_and_mint(&store, &op_key(), host_fp(), member_id, 1_000)
            .expect("revoke_member_and_mint");

        let member = store
            .get_member(member_id)
            .expect("get_member")
            .expect("exists");
        assert_eq!(member.status, MemberStatus::Revoked);
    }

    #[test]
    fn revoking_a_member_bumps_cap_epoch_by_exactly_one_and_the_record_carries_the_new_epoch() {
        let (store, member_id, _root_fp) = store_with_member("alex");
        let e0 = store.cap_epoch().expect("e0");

        let publication = revoke_member_and_mint(&store, &op_key(), host_fp(), member_id, 1_000)
            .expect("revoke_member_and_mint");

        let e1 = store.cap_epoch().expect("e1");
        assert_eq!(e1, e0 + 1, "exactly one bump");
        assert_eq!(publication.record.epoch, e1);
        assert_eq!(publication.cap_epoch, e1);
    }

    #[test]
    fn a_member_revocations_minted_record_verifies_under_the_op_key_and_not_under_another_key() {
        let (store, member_id, _root_fp) = store_with_member("alex");

        let publication = revoke_member_and_mint(&store, &op_key(), host_fp(), member_id, 1_000)
            .expect("revoke_member_and_mint");

        verify_revocation_record(&publication.record, &op_key().verifying_key())
            .expect("must verify under the signing op key");
        verify_revocation_record(&publication.record, &other_key().verifying_key())
            .expect_err("must not verify under a different key");
    }

    #[test]
    fn a_member_revocations_revoked_list_names_only_the_root_fp_not_either_of_its_devices() {
        let (store, member_id, root_fp) = store_with_member("alex");
        let device_a = enroll_device(&store, member_id, 0x01);
        let device_b = enroll_device(&store, member_id, 0x03);

        let publication = revoke_member_and_mint(&store, &op_key(), host_fp(), member_id, 1_000)
            .expect("revoke_member_and_mint");

        assert_eq!(publication.record.revoked, vec![root_fp.to_vec()]);
        assert!(!publication.record.revoked.contains(&device_a.to_vec()));
        assert!(!publication.record.revoked.contains(&device_b.to_vec()));
    }

    // ---- revoke_device_and_mint -------------------------------------------------------------

    #[test]
    fn revoking_a_device_sets_only_that_devices_revoked_flag_and_leaves_its_member_active() {
        let (store, member_id, _root_fp) = store_with_member("alex");
        let device_a = enroll_device(&store, member_id, 0x05);
        let device_b = enroll_device(&store, member_id, 0x07);

        revoke_device_and_mint(&store, &op_key(), host_fp(), device_a, 1_000)
            .expect("revoke_device_and_mint");

        let member = store
            .get_member(member_id)
            .expect("get_member")
            .expect("exists");
        assert_eq!(
            member.status,
            MemberStatus::Active,
            "member must stay Active"
        );
        let dev_a = member
            .devices
            .iter()
            .find(|d| d.device_fp == device_a)
            .expect("device_a present");
        assert!(dev_a.revoked, "device_a must be revoked");
        let dev_b = member
            .devices
            .iter()
            .find(|d| d.device_fp == device_b)
            .expect("device_b present");
        assert!(!dev_b.revoked, "device_b must remain unrevoked");
    }

    #[test]
    fn a_device_revocations_revoked_list_names_exactly_that_one_device_fp() {
        let (store, member_id, _root_fp) = store_with_member("alex");
        let device_a = enroll_device(&store, member_id, 0x09);

        let publication = revoke_device_and_mint(&store, &op_key(), host_fp(), device_a, 1_000)
            .expect("revoke_device_and_mint");

        assert_eq!(publication.record.revoked, vec![device_a.to_vec()]);
    }

    // ---- subject encoding (pinned literal — see the module doc's "Subject encoding" section) -

    #[test]
    fn the_published_subject_is_registry_revoke_dot_host_fp_display_rendering() {
        let (store, member_id, _root_fp) = store_with_member("alex");
        let hfp = host_fp();

        let publication = revoke_member_and_mint(&store, &op_key(), hfp, member_id, 1_000)
            .expect("revoke_member_and_mint");

        assert_eq!(publication.subject, format!("registry.revoke.{hfp}"));
    }

    // ---- epoch monotonicity across successive revocations ------------------------------------

    #[test]
    fn two_successive_revocations_produce_strictly_increasing_epochs() {
        let (store, member_id, _root_fp) = store_with_member("alex");
        let device_a = enroll_device(&store, member_id, 0x0b);

        let first = revoke_device_and_mint(&store, &op_key(), host_fp(), device_a, 1_000)
            .expect("first revocation");

        let second = revoke_member_and_mint(&store, &op_key(), host_fp(), member_id, 2_000)
            .expect("second revocation");

        assert!(
            is_newer_epoch(second.record.epoch, first.record.epoch),
            "the second revocation's epoch must be strictly newer than the first's"
        );
    }
}
