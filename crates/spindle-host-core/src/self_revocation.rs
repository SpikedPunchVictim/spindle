//! Host-side ingestion of a root-signed self-revocation (`spindle-self-rev-v1`, DESIGN.md
//! §A4/§A7b). [`apply_self_revocation`] takes a [`SelfRevocationRecord`] that a member's identity
//! root signed for one of its own devices, verifies it against that member's stored `root_pk`, and
//! applies the resulting device revocations to this host's `Store`.
//!
//! This is the host-side counterpart of `spindle_helper::self_revoke`'s `helper.revoke.<nfp>`
//! handler, but it is **not** that handler moved: a host has no NATS session to recover the
//! caller's identity from, so the caller passes the already-authenticated `member_id` explicitly
//! and this module re-derives authority from durable state instead. Supplying a `member_id` buys
//! the caller nothing: the record is verified under *that member's* `root_pk`, and the member's
//! `root_fp` must equal the record's `root_fp` (steps 4-5 below), so a record can only ever revoke
//! devices under the root that actually signed it. A wrong `member_id` fails verification rather
//! than selecting a different victim.
//!
//! # Verification before mutation [deliberate]
//!
//! Every cheap or cryptographic check runs before the first store write, in this order:
//!
//! 1. the member exists ([`StoreError::MemberNotFound`]);
//! 2. the member has a `root_pk` on file — `None` is [`SelfRevocationError::MemberRootPkMissing`],
//!    never "skip the check" (a pre-V10 row has no key to verify against);
//! 3. that key is exactly 32 bytes and canonically encoded per RFC 8032 §5.1.3, via
//!    [`spindle_core::artifacts::checked_verifying_key`]
//!    ([`SelfRevocationError::InvalidRootPk`]);
//! 4. [`verify_self_revocation`] checks `root_fp_of(key) == record.root_fp` and then the
//!    signature, both surfaced transparently as [`SelfRevocationError::Artifact`] (so a tampered
//!    signature is `Artifact(BadSignature)` and a record signed by another root is
//!    `Artifact(RootFingerprintMismatch)`);
//! 5. the record's `root_fp` is required to equal the member's stored `root_fp` byte-for-byte
//!    ([`SelfRevocationError::RootFingerprintMismatch`]). This is implied by the write-time binding
//!    in [`spindle_vfs::store::Store::set_member_root_pk`] together with step 4, and is unreachable
//!    through the public store API today — it is stated anyway so a corrupted store row or a
//!    future second key path cannot bypass the binding;
//! 6. **every** `revoked` entry is decoded as a 32-byte [`Fingerprint`]; one malformed entry rejects
//!    the whole record before anything is written
//!    ([`SelfRevocationError::MalformedRevokedEntry`]). The signature covers those bytes, so
//!    silently dropping an entry would mean accepting a signed artifact while ignoring part of
//!    what was signed. Entries are deduplicated preserving first-seen order, so a duplicate is
//!    neither revoked twice nor audited twice.
//!
//! Only then does step 8 mutate anything.
//!
//! # A root revokes only its own devices; everything else is ignored
//!
//! Step 7 partitions the deduplicated entries against **this member's** `devices` list. Names that
//! match one of the member's devices are revocation candidates. Names that do not match — an
//! unknown fingerprint, or a device belonging to a different member — go to
//! [`SelfRevocationOutcome::ignored`] and are never passed to the store. A record naming a foreign
//! `device_fp` therefore cannot touch that other member's row, even before the signature is
//! considered.
//!
//! # Per-device atomicity, crash semantics, and replay
//!
//! Each candidate is applied with [`Store::revoke_device_and_bump_epoch`], which writes the
//! `revoked` flag and bumps `cap_epoch` in one transaction. There is deliberately no larger
//! transaction spanning the whole record: a crash partway through a multi-device record can leave
//! a **prefix** of the record applied, and replaying the same record is safe because every step is
//! keyed by an already-observed `revoked` flag. A device whose row is already revoked is reported
//! in [`SelfRevocationOutcome::already_revoked`] and does not bump the epoch again, so the replay
//! converges on the same durable state rather than re-invalidating every outstanding capability.
//!
//! That convergence covers durable revocation state, **not** the audit trail. Each device's audit
//! row is appended after that device's transaction commits; a crash between the commit and the
//! append loses that row permanently, and a replay will not reconstruct it because the device is
//! already revoked (and therefore not re-audited). This is the accepted best-effort gap described
//! below, stated here so the crash-prefix guarantee is not read as stronger than it is.
//!
//! # No epoch gate [deliberate]
//!
//! Every signature-valid record is applied regardless of its `epoch`. A self-revocation is a
//! one-way lattice: the accepted set is the **monotone union** of every accepted record's entries
//! (DESIGN.md §A7b, *[amended v0.9.48]*), so a replayed record can only re-add devices that were
//! genuinely revoked at some point and can never un-revoke one. Rejecting a stale-epoch record
//! would silently lose real revocations (a redelivered message, an operator re-publishing during
//! recovery) for no security benefit. `epoch` is never compared here — it stays in the record,
//! which the caller already holds; this function reports no epoch of its own.
//!
//! # The audit append is best-effort, after the revocation has already committed
//!
//! This matches `crate::revoke` exactly: for each **newly** revoked device an
//! [`AuditEntry`] with action `"revoke_device_self"` is appended immediately after that device's
//! commit — inside the candidate loop, before the next candidate — and an append failure is
//! logged with `tracing::error!` rather than turned into an `Err`. Appending after the whole loop
//! would lose the committed prefix's rows whenever a later `?` returned early, so the append is
//! per-device for the same reason the mutation is. By that point
//! [`Store::revoke_device_and_bump_epoch`] has committed and `crate::server`'s per-request
//! `denied:device_revoked` gate (and `crate::authorize`'s connect-time twin) already enforce the
//! revocation; reporting a completed security action as failed would be worse than leaving it
//! unaudited. Ignored and already-revoked devices are not audited — no state changed for them.
//!
//! The residual is a crash (or a `tracing` failure) between a commit and its immediately following
//! append: that one row is gone, and replay will not reconstruct it because the device is already
//! revoked. A missing row is a gap in the tamper-evident chain, not a forged one;
//! `Audit::verify_chain` still verifies every row that was written.
//!
//! # No production caller yet
//!
//! Nothing in this workspace calls [`apply_self_revocation`] today. The delivery route that will
//! invoke it — receiving a member's self-revocation and handing it to the host — is td-bdab3a,
//! and this function is the seam that route will call. Until then it is exercised only by this
//! module's in-crate tests, the same honest note `crate::revoke` records for its own missing
//! publish step.

use spindle_core::artifacts::{checked_verifying_key, verify_self_revocation, ArtifactError};
use spindle_core::{Fingerprint, FINGERPRINT_LEN};
use spindle_proto::artifacts::SelfRevocationRecord;
use spindle_vfs::audit::AuditEntry;
use spindle_vfs::model::MemberId;
use spindle_vfs::store::{Store, StoreError};
use std::collections::HashSet;
use thiserror::Error;

/// Errors from [`apply_self_revocation`].
///
/// Store and artifact failures are transparent so their kinds survive (callers can distinguish
/// `Artifact(BadSignature)` from `Artifact(RootFingerprintMismatch)`, for example). This module's
/// remaining variants name only the member id or an entry index; none echoes key bytes or record
/// contents in `Display`. The transparent `Store` variant is the exception: e.g.
/// `StoreError::DeviceNotFound(Fingerprint)` prints the full fingerprint. That is unreachable
/// today because nothing deletes device rows (the same reachability argument `crate::revoke`
/// documents), and it matters only once a caller logs the error.
#[derive(Debug, Error)]
pub enum SelfRevocationError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    /// The member has no `root_pk` on file, so there is no key under which the record could be
    /// verified. Fail closed: a missing key is never permission to skip verification.
    #[error("member {member_id:?} has no root_pk on file; cannot verify a self-revocation")]
    MemberRootPkMissing { member_id: MemberId },
    /// The stored `root_pk` is not exactly 32 bytes, or is not a canonically encoded Ed25519
    /// public key per RFC 8032 §5.1.3. Defense in depth: the write path
    /// ([`spindle_vfs::store::Store::set_member_root_pk`]) already rejects both cases, so this is
    /// reachable only through direct database corruption — the same status as
    /// [`SelfRevocationError::RootFingerprintMismatch`] below.
    #[error(
        "member {member_id:?} has a malformed root_pk (expected a canonical 32-byte Ed25519 key)"
    )]
    InvalidRootPk { member_id: MemberId },
    /// The record's `root_fp` does not equal the member's stored `root_fp`. See the module doc
    /// comment's step 5 for why this is checked explicitly even though the write-time binding makes
    /// it unreachable through the public store API today.
    #[error("self-revocation for member {member_id:?} does not name that member's root_fp")]
    RootFingerprintMismatch { member_id: MemberId },
    /// `revoked[index]` is not a 32-byte fingerprint. The whole record is rejected; no entry is
    /// dropped and nothing is mutated.
    #[error("revoked entry {index} is not a 32-byte fingerprint")]
    MalformedRevokedEntry { index: usize },
}

/// What [`apply_self_revocation`] did, per deduplicated entry of the record.
///
/// The three fingerprint lists partition the record's entries: an entry appears in exactly one of
/// them, in first-seen order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfRevocationOutcome {
    /// Entries naming one of this member's devices that were not yet revoked, and were revoked by
    /// this call (each with a `cap_epoch` bump and an audit entry).
    pub newly_revoked: Vec<Fingerprint>,
    /// Entries naming one of this member's devices that was already revoked. These did not bump
    /// the epoch and were not audited.
    pub already_revoked: Vec<Fingerprint>,
    /// Entries naming neither one of this member's devices: an unknown fingerprint, or a device
    /// belonging to another member. They are reported and never passed to the store.
    pub ignored: Vec<Fingerprint>,
    /// `store.cap_epoch()` after the applies above.
    pub cap_epoch: u64,
}

/// Verifies `record` against `member_id`'s stored identity root and applies its device
/// revocations. See the module doc comment for the ordering, the epoch/replay rule, and the
/// per-device atomicity guarantee.
pub fn apply_self_revocation(
    store: &Store,
    member_id: MemberId,
    record: &SelfRevocationRecord,
    ts: u64,
) -> Result<SelfRevocationOutcome, SelfRevocationError> {
    // Steps 1-2: the member and its identity-root key, both before any crypto or mutation.
    let member = store
        .get_member(member_id)?
        .ok_or(StoreError::MemberNotFound(member_id))?;
    let root_pk_bytes = member
        .root_pk
        .as_deref()
        .ok_or(SelfRevocationError::MemberRootPkMissing { member_id })?;

    // Step 3: exactly 32 bytes, canonically encoded.
    let root_pk_arr: [u8; FINGERPRINT_LEN] = root_pk_bytes
        .try_into()
        .map_err(|_| SelfRevocationError::InvalidRootPk { member_id })?;
    let root_pk = checked_verifying_key(&root_pk_arr)
        .ok_or(SelfRevocationError::InvalidRootPk { member_id })?;

    // Step 4: root_fp_of(key) == record.root_fp, then the signature.
    verify_self_revocation(record, &root_pk)?;

    // Step 5: the explicit binding to *this* member's root_fp. See the module doc comment.
    if !member.root_fp.matches(&record.root_fp) {
        return Err(SelfRevocationError::RootFingerprintMismatch { member_id });
    }

    // Step 6: decode every entry, rejecting the whole record on the first malformed one. The
    // signature covered the raw bytes, so an entry cannot be skipped. Dedup preserves first-seen
    // order (HashSet only answers membership) so a duplicate is reported once.
    let mut seen = HashSet::new();
    let mut entries: Vec<Fingerprint> = Vec::with_capacity(record.revoked.len());
    for (index, raw) in record.revoked.iter().enumerate() {
        let device_fp = Fingerprint::from_slice(raw)
            .map_err(|_| SelfRevocationError::MalformedRevokedEntry { index })?;
        if seen.insert(device_fp) {
            entries.push(device_fp);
        }
    }

    // Step 7: only this member's own devices are candidates. The `revoked` flag is snapshotted
    // here, before any write, which is also what makes the per-entry replay check below cheap.
    let mut candidates: Vec<(Fingerprint, bool)> = Vec::new();
    let mut ignored: Vec<Fingerprint> = Vec::new();
    for device_fp in entries {
        match member
            .devices
            .iter()
            .find(|device| device.device_fp == device_fp)
        {
            Some(device) => candidates.push((device_fp, device.revoked)),
            None => ignored.push(device_fp),
        }
    }

    // Steps 8-9: apply each candidate atomically, then append its audit entry immediately —
    // before the next candidate, so a `?` on a later store failure cannot strand the committed
    // prefix without audit rows. `None` is the store's idempotent "already revoked" answer (a race
    // with another writer since step 1's snapshot), so it joins `already_revoked` without an epoch
    // bump and is not audited.
    //
    // A crash between one candidate's commit and its append still loses that row, and replay will
    // not reconstruct it because the device is already revoked — see the module doc comment's
    // residual.
    let mut newly_revoked: Vec<Fingerprint> = Vec::new();
    let mut already_revoked: Vec<Fingerprint> = Vec::new();
    for (device_fp, was_revoked) in candidates {
        if was_revoked {
            already_revoked.push(device_fp);
            continue;
        }
        match store.revoke_device_and_bump_epoch(device_fp)? {
            Some(_) => {
                newly_revoked.push(device_fp);
                // Best-effort per-device audit. `%e` is an `spindle_vfs::audit::AuditError`,
                // redaction-safe by construction (see `crate::revoke`'s identical comment).
                if let Err(e) = store.audit().append(AuditEntry {
                    ts,
                    member: Some(member.root_fp),
                    device: Some(device_fp),
                    action: "revoke_device_self".to_string(),
                    virtual_path: None,
                    bytes: None,
                    outcome: "ok".to_string(),
                }) {
                    tracing::error!(
                        member_root_fp = %member.root_fp.redacted(),
                        device_fp = %device_fp.redacted(),
                        error = %e,
                        "apply_self_revocation: audit append failed; the device revocation itself \
                         already committed and is already being enforced, proceeding without an \
                         audit record"
                    );
                }
            }
            None => already_revoked.push(device_fp),
        }
    }

    // Step 10.
    Ok(SelfRevocationOutcome {
        newly_revoked,
        already_revoked,
        ignored,
        cap_epoch: store.cap_epoch()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::artifacts::issue_self_revocation;
    use spindle_core::identity::{root_fp_of, DeviceKey};
    use spindle_core::SigningKey;
    use spindle_vfs::model::DevicePublicKeys;

    fn root_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A store with one active member whose `root_fp` is derived from `root` and whose `root_pk`
    /// is bound to it by the real write path.
    fn member_with_root(store: &Store, name: &str, root: &SigningKey) -> MemberId {
        let member_id = store
            .add_member(root_fp_of(&root.verifying_key()), name, 0)
            .expect("add_member");
        store.activate_member(member_id).expect("activate_member");
        store
            .set_member_root_pk(member_id, root.verifying_key().as_bytes())
            .expect("set_member_root_pk");
        member_id
    }

    fn enroll_device(store: &Store, member_id: MemberId, seed: u8) -> Fingerprint {
        let device = DeviceKey::from_seeds([seed; 32], [seed.wrapping_add(1); 32]);
        let device_fp = device.device_fp();
        let keys = DevicePublicKeys {
            alg_id: spindle_core::ALG_ID_V1,
            sign_pk: device.sign_public_key().as_bytes().to_vec(),
            agree_pk: device.agree_public_key().as_bytes().to_vec(),
        };
        store
            .add_device(member_id, device_fp, "device", 0, Some(&keys))
            .expect("add_device");
        device_fp
    }

    fn is_revoked(store: &Store, member_id: MemberId, device_fp: Fingerprint) -> bool {
        store
            .get_member(member_id)
            .expect("get_member")
            .expect("member exists")
            .devices
            .iter()
            .find(|device| device.device_fp == device_fp)
            .is_some_and(|device| device.revoked)
    }

    #[test]
    fn valid_record_revokes_the_owned_device_bumps_epoch_and_audits_once() {
        let store = Store::open_in_memory().expect("open_in_memory");
        let root = root_key(0x61);
        let member_id = member_with_root(&store, "alex", &root);
        let device_fp = enroll_device(&store, member_id, 0x01);
        let e0 = store.cap_epoch().expect("e0");
        let record = issue_self_revocation(&root, 3, vec![device_fp], 1_000);

        let outcome = apply_self_revocation(&store, member_id, &record, 4_242)
            .expect("apply_self_revocation");

        assert_eq!(outcome.newly_revoked, vec![device_fp]);
        assert!(outcome.already_revoked.is_empty());
        assert!(outcome.ignored.is_empty());
        assert_eq!(outcome.cap_epoch, e0 + 1, "one bump");
        assert_eq!(store.cap_epoch().expect("after"), e0 + 1);
        assert!(is_revoked(&store, member_id, device_fp));

        let page = store.audit().list(None, 10).expect("audit list");
        assert_eq!(page.records.len(), 1, "exactly one audit entry");
        let entry = &page.records[0].entry;
        assert_eq!(entry.action, "revoke_device_self");
        assert_eq!(entry.outcome, "ok");
        assert_eq!(entry.member, Some(root_fp_of(&root.verifying_key())));
        assert_eq!(entry.device, Some(device_fp));
        assert_eq!(entry.ts, 4_242);
        assert_eq!(entry.virtual_path, None);
        assert_eq!(entry.bytes, None);
    }

    #[test]
    fn two_newly_revoked_devices_are_applied_and_audited_in_first_seen_order() {
        let store = Store::open_in_memory().expect("open_in_memory");
        let root = root_key(0x6d);
        let member_id = member_with_root(&store, "alex", &root);
        let device_1 = enroll_device(&store, member_id, 0x15);
        let device_2 = enroll_device(&store, member_id, 0x17);
        let e0 = store.cap_epoch().expect("e0");
        let record = issue_self_revocation(&root, 1, vec![device_1, device_2], 1_000);

        let outcome = apply_self_revocation(&store, member_id, &record, 1_000).expect("apply");

        assert_eq!(
            outcome.newly_revoked,
            vec![device_1, device_2],
            "first-seen order"
        );
        assert!(outcome.already_revoked.is_empty());
        assert!(outcome.ignored.is_empty());
        assert_eq!(outcome.cap_epoch, e0 + 2, "one bump per device");
        assert_eq!(store.cap_epoch().expect("after"), e0 + 2);
        assert!(is_revoked(&store, member_id, device_1));
        assert!(is_revoked(&store, member_id, device_2));

        let page = store.audit().list(None, 10).expect("audit list");
        assert_eq!(
            page.records.len(),
            2,
            "one audit row per newly revoked device"
        );
        assert!(page
            .records
            .iter()
            .all(|record| record.entry.action == "revoke_device_self"));
        assert_eq!(page.records[0].entry.device, Some(device_1));
        assert_eq!(page.records[1].entry.device, Some(device_2));
    }

    #[test]
    fn replay_reports_already_revoked_and_does_not_bump_the_epoch_again() {
        let store = Store::open_in_memory().expect("open_in_memory");
        let root = root_key(0x62);
        let member_id = member_with_root(&store, "alex", &root);
        let device_fp = enroll_device(&store, member_id, 0x03);
        let record = issue_self_revocation(&root, 1, vec![device_fp], 1_000);

        apply_self_revocation(&store, member_id, &record, 1_000).expect("first apply");
        let e1 = store.cap_epoch().expect("e1");

        let outcome = apply_self_revocation(&store, member_id, &record, 2_000)
            .expect("replay must be a success");

        assert!(outcome.newly_revoked.is_empty());
        assert_eq!(outcome.already_revoked, vec![device_fp]);
        assert!(outcome.ignored.is_empty());
        assert_eq!(outcome.cap_epoch, e1, "replay must not bump");
        assert_eq!(store.cap_epoch().expect("after replay"), e1);
        assert_eq!(
            store
                .audit()
                .list(None, 10)
                .expect("audit list")
                .records
                .len(),
            1,
            "an already-revoked device is not audited again"
        );
    }

    #[test]
    fn duplicate_entry_is_reported_once() {
        let store = Store::open_in_memory().expect("open_in_memory");
        let root = root_key(0x63);
        let member_id = member_with_root(&store, "alex", &root);
        let device_fp = enroll_device(&store, member_id, 0x05);
        let e0 = store.cap_epoch().expect("e0");
        let record = issue_self_revocation(&root, 1, vec![device_fp, device_fp], 1_000);

        let outcome = apply_self_revocation(&store, member_id, &record, 1_000).expect("apply");

        assert_eq!(
            outcome.newly_revoked,
            vec![device_fp],
            "reported exactly once"
        );
        assert!(outcome.already_revoked.is_empty());
        assert!(outcome.ignored.is_empty());
        assert_eq!(store.cap_epoch().expect("after"), e0 + 1, "one bump");
        assert_eq!(
            store
                .audit()
                .list(None, 10)
                .expect("audit list")
                .records
                .len(),
            1,
            "one audit entry for the deduplicated device"
        );
    }

    #[test]
    fn a_device_belonging_to_another_member_is_ignored_and_stays_unrevoked() {
        let store = Store::open_in_memory().expect("open_in_memory");
        let root_a = root_key(0x64);
        let root_b = root_key(0x65);
        let member_a = member_with_root(&store, "alex", &root_a);
        let member_b = member_with_root(&store, "blair", &root_b);
        let device_a = enroll_device(&store, member_a, 0x07);
        let device_b = enroll_device(&store, member_b, 0x09);
        let e0 = store.cap_epoch().expect("e0");
        let record = issue_self_revocation(&root_a, 1, vec![device_a, device_b], 1_000);

        let outcome = apply_self_revocation(&store, member_a, &record, 1_000).expect("apply");

        assert_eq!(outcome.newly_revoked, vec![device_a]);
        assert!(outcome.already_revoked.is_empty());
        assert_eq!(outcome.ignored, vec![device_b]);
        assert!(
            !is_revoked(&store, member_b, device_b),
            "a root may not revoke another member's device"
        );
        assert!(is_revoked(&store, member_a, device_a));
        assert_eq!(
            store.cap_epoch().expect("after"),
            e0 + 1,
            "only the legitimate device's revocation bumps the epoch"
        );
        assert_eq!(
            store
                .audit()
                .list(None, 10)
                .expect("audit list")
                .records
                .len(),
            1,
            "the ignored entry is not audited"
        );
    }

    #[test]
    fn unknown_device_fingerprint_is_ignored() {
        let store = Store::open_in_memory().expect("open_in_memory");
        let root = root_key(0x66);
        let member_id = member_with_root(&store, "alex", &root);
        let e0 = store.cap_epoch().expect("e0");
        let unknown = Fingerprint::of_parts(&[b"never-enrolled"]);
        let record = issue_self_revocation(&root, 1, vec![unknown], 1_000);

        let outcome = apply_self_revocation(&store, member_id, &record, 1_000).expect("apply");

        assert!(outcome.newly_revoked.is_empty());
        assert!(outcome.already_revoked.is_empty());
        assert_eq!(outcome.ignored, vec![unknown]);
        assert_eq!(outcome.cap_epoch, e0);
        assert_eq!(store.cap_epoch().expect("after"), e0);
        assert!(store
            .audit()
            .list(None, 10)
            .expect("audit list")
            .records
            .is_empty());
    }

    #[test]
    fn empty_revoked_list_verifies_changes_nothing_and_returns_the_current_epoch() {
        let store = Store::open_in_memory().expect("open_in_memory");
        let root = root_key(0x67);
        let member_id = member_with_root(&store, "alex", &root);
        let device_fp = enroll_device(&store, member_id, 0x0b);
        let e0 = store.cap_epoch().expect("e0");
        let record = issue_self_revocation(&root, 7, vec![], 1_000);

        let outcome = apply_self_revocation(&store, member_id, &record, 1_000).expect("apply");

        assert!(outcome.newly_revoked.is_empty());
        assert!(outcome.already_revoked.is_empty());
        assert!(outcome.ignored.is_empty());
        assert_eq!(outcome.cap_epoch, e0);
        assert_eq!(store.cap_epoch().expect("after"), e0);
        assert!(!is_revoked(&store, member_id, device_fp));
        assert!(store
            .audit()
            .list(None, 10)
            .expect("audit list")
            .records
            .is_empty());
    }

    #[test]
    fn missing_root_pk_is_refused_without_mutation() {
        let store = Store::open_in_memory().expect("open_in_memory");
        let root = root_key(0x68);
        // Deliberately never call `set_member_root_pk`: this models a pre-V10 row.
        let member_id = store
            .add_member(root_fp_of(&root.verifying_key()), "alex", 0)
            .expect("add_member");
        store.activate_member(member_id).expect("activate_member");
        let device_fp = enroll_device(&store, member_id, 0x0d);
        let e0 = store.cap_epoch().expect("e0");
        let record = issue_self_revocation(&root, 1, vec![device_fp], 1_000);

        let err = apply_self_revocation(&store, member_id, &record, 1_000)
            .expect_err("a member with no root_pk cannot verify a self-revocation");

        assert!(
            matches!(
                err,
                SelfRevocationError::MemberRootPkMissing { member_id: m } if m == member_id
            ),
            "unexpected error: {err:?}"
        );
        assert!(!is_revoked(&store, member_id, device_fp));
        assert_eq!(store.cap_epoch().expect("after"), e0);
        assert!(store
            .audit()
            .list(None, 10)
            .expect("audit list")
            .records
            .is_empty());
    }

    #[test]
    fn record_signed_by_a_different_root_is_refused() {
        let store = Store::open_in_memory().expect("open_in_memory");
        let root_a = root_key(0x69);
        let root_b = root_key(0x6a);
        let member_a = member_with_root(&store, "alex", &root_a);
        let device_a = enroll_device(&store, member_a, 0x0f);
        let e0 = store.cap_epoch().expect("e0");
        // Signed by root B, naming a device that belongs to root A's member.
        let record = issue_self_revocation(&root_b, 1, vec![device_a], 1_000);

        let err = apply_self_revocation(&store, member_a, &record, 1_000)
            .expect_err("a record under another root must not verify");

        // This module verifies before comparing the member's stored root_fp, so the artifact
        // layer fires first (`root_fp_of(root_pk_A) != record.root_fp == root_fp_B`). The explicit
        // step-5 `RootFingerprintMismatch { member_id }` would only be reachable through a
        // corrupted store row and is unreachable via the public store API today.
        assert!(
            matches!(
                err,
                SelfRevocationError::Artifact(ArtifactError::RootFingerprintMismatch)
            ),
            "unexpected error: {err:?}"
        );
        assert!(!is_revoked(&store, member_a, device_a));
        assert_eq!(store.cap_epoch().expect("after"), e0);
        assert!(store
            .audit()
            .list(None, 10)
            .expect("audit list")
            .records
            .is_empty());
    }

    #[test]
    fn tampered_signature_is_refused_without_mutation() {
        let store = Store::open_in_memory().expect("open_in_memory");
        let root = root_key(0x6b);
        let member_id = member_with_root(&store, "alex", &root);
        let device_fp = enroll_device(&store, member_id, 0x11);
        let e0 = store.cap_epoch().expect("e0");
        let mut record = issue_self_revocation(&root, 1, vec![device_fp], 1_000);
        record.sig_root[0] ^= 0xff;

        let err = apply_self_revocation(&store, member_id, &record, 1_000)
            .expect_err("a tampered signature must not verify");

        assert!(
            matches!(
                err,
                SelfRevocationError::Artifact(ArtifactError::BadSignature)
            ),
            "unexpected error: {err:?}"
        );
        assert!(!is_revoked(&store, member_id, device_fp));
        assert_eq!(store.cap_epoch().expect("after"), e0);
        assert!(store
            .audit()
            .list(None, 10)
            .expect("audit list")
            .records
            .is_empty());
    }

    #[test]
    fn one_malformed_entry_rejects_the_whole_record_before_any_mutation() {
        let store = Store::open_in_memory().expect("open_in_memory");
        let root = root_key(0x6c);
        let member_id = member_with_root(&store, "alex", &root);
        let device_fp = enroll_device(&store, member_id, 0x13);
        let e0 = store.cap_epoch().expect("e0");

        // Start from a validly signed record, then add a 31-byte entry and re-sign so the
        // signature genuinely covers the malformed bytes (mutating without re-signing would fail
        // at step 4 with BadSignature instead of reaching step 6).
        let mut record = issue_self_revocation(&root, 1, vec![device_fp], 1_000);
        record.revoked.push(vec![0u8; 31]);
        record.sig_root = spindle_core::sign_bytes(&root, &record.signing_input());

        let err = apply_self_revocation(&store, member_id, &record, 1_000)
            .expect_err("a malformed entry must reject the whole record");

        assert!(
            matches!(err, SelfRevocationError::MalformedRevokedEntry { index: 1 }),
            "unexpected error: {err:?}"
        );
        assert!(
            !is_revoked(&store, member_id, device_fp),
            "the valid device must not be revoked when the record is rejected as a whole"
        );
        assert_eq!(store.cap_epoch().expect("after"), e0);
        assert!(store
            .audit()
            .list(None, 10)
            .expect("audit list")
            .records
            .is_empty());
    }
}
