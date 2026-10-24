//! S14 helper-side end to end: a real root-signed `spindle-self-rev-v1` record deposited through
//! [`handle_self_revoke`] makes [`decide_device_connect`] refuse the *same* device bundle that it
//! authorized immediately before the deposit.
//!
//! Built only from public APIs and the real [`InMemoryHelperView`] store — no `MockView`, no
//! copied private test helpers. The negative control (authorized before the deposit) is what
//! makes the later refusal meaningful; without it, any unrelated broken fixture would also
//! produce a `Refused`.

use spindle_core::artifacts::{
    issue_capability, issue_device_certificate, issue_host_op_key_cert, issue_self_revocation,
    issue_session_attestation,
};
use spindle_core::identity::{DeviceKey, RootKey};
use spindle_core::{root_fp_of, Fingerprint, SigningKey};
use spindle_helper::authz::{
    decide_device_connect, AdmissionMode, AuthzDecision, DeviceConnectPresented, HelperView,
    RefusalReason,
};
use spindle_helper::memory_store::InMemoryHelperView;
use spindle_helper::self_revoke::{handle_self_revoke, SelfRevokeLimits};
use spindle_helper::session::SessionRecord;
use spindle_proto::artifacts::CapKind;

#[test]
fn a_deposited_root_signed_self_revocation_refuses_that_device() {
    let now: u64 = 1_700_000_000;
    let cert_exp = now + 3_600;

    // `RootKey::from_seed` wraps exactly `SigningKey::from_bytes(seed)` (identity.rs). Confirm
    // that before relying on the same seed producing both the session's `root_fp` and the
    // self-revocation record's signer.
    let root = RootKey::from_seed([0x01; 32]);
    let signing = SigningKey::from_bytes(&[0x01; 32]);
    assert_eq!(
        root.public_key().as_bytes(),
        signing.verifying_key().as_bytes(),
        "RootKey::from_seed must wrap SigningKey::from_bytes for the same seed"
    );
    let root_fp = root_fp_of(&root.public_key());

    let device = DeviceKey::from_seeds([0x02; 32], [0x03; 32]);
    let device_fp = device.device_fp();
    let device_cert = issue_device_certificate(
        &root,
        device.alg_id(),
        &device.sign_public_key(),
        &device.agree_public_key(),
        now,
        cert_exp,
    );

    let session_fp = Fingerprint::of_parts(&[b"self-revoke-e2e-session"]);
    let session_attest = issue_session_attestation(&device, session_fp, now);

    // A host identity (root -> operating key -> member capability) whose chain verifies inside
    // `decide_device_connect`.
    let host_root = RootKey::from_seed([0x04; 32]);
    let host_op = SigningKey::from_bytes(&[0x05; 32]);
    let host_op_cert =
        issue_host_op_key_cert(&host_root, &host_op.verifying_key(), now, now + 86_400);
    let cap = issue_capability(
        &host_root.public_key(),
        &host_op_cert,
        &host_op,
        CapKind::Member,
        root_fp,
        0,
        now + 3_600,
        b"self-revoke-e2e-nonce".to_vec(),
    );

    let operator_pk = SigningKey::from_bytes(&[0x06; 32]).verifying_key();
    let mut view = InMemoryHelperView::new(AdmissionMode::Open, operator_pk);
    // The same shape `decide_device_connect` writes on success (DESIGN.md §A5, amended
    // v0.9.47): `root_pk` is retained so the deposit can verify a signature under this session's
    // root, and `device_fp` is what the per-device attempt budget keys on.
    view.put_session_record(SessionRecord::new(
        session_fp,
        root_fp,
        Some(root.public_key().to_bytes()),
        Some(device_fp),
        vec![],
        "member".to_string(),
        cert_exp,
    ));

    let presented = DeviceConnectPresented {
        root_pk: root.public_key(),
        device_cert,
        caps: vec![cap],
        nats_fp: session_fp,
        session_attest,
    };

    // 1. Negative control, deliberately first: the exact bundle that will later be refused is
    //    authorized while no self-revocation exists. Keeping this assertion ahead of the deposit
    //    is what makes the refusal below attributable to the deposit rather than to a fixture
    //    that could never have authorized in the first place.
    let before = decide_device_connect(&presented, || true, now, &mut view, 0);
    assert!(
        matches!(&before, AuthzDecision::Authorized(_)),
        "fixture must authorize before the deposit, got {before:?}"
    );

    // 2. A record whose signature no longer covers its fields must be rejected and must revoke
    //    nobody. This is the sensitivity probe for "record verification is not skipped": a
    //    handler that applied any decodable record would revoke the device here and fail the
    //    `Authorized` assertion, even though the genuine deposit below would still look correct.
    let record = issue_self_revocation(&signing, 1, vec![device_fp], now);
    let mut tampered = record.clone();
    tampered.epoch = 2; // fields changed, `sig_root` retained from the genuine record
    let tampered_result = handle_self_revoke(
        &format!("helper.revoke.{session_fp}"),
        &tampered.to_canonical_bytes(),
        &mut view,
        &mut SelfRevokeLimits::new(),
        now,
    );
    let tampered_reply: serde_json::Value =
        serde_json::from_slice(&tampered_result.reply).expect("reply is JSON");
    assert_eq!(
        tampered_reply["ok"], false,
        "a record whose signature does not cover its fields must be refused"
    );
    assert!(
        tampered_result.newly_revoked.is_empty(),
        "a rejected record must report nothing to kick"
    );
    assert!(
        matches!(
            decide_device_connect(&presented, || true, now, &mut view, 0),
            AuthzDecision::Authorized(_)
        ),
        "a rejected record must not revoke the device"
    );

    // 3. Deposit the genuine root-signed record through the real handler.
    let result = handle_self_revoke(
        &format!("helper.revoke.{session_fp}"),
        &record.to_canonical_bytes(),
        &mut view,
        &mut SelfRevokeLimits::new(),
        now,
    );
    let reply: serde_json::Value = serde_json::from_slice(&result.reply).expect("reply is JSON");
    assert_eq!(reply["ok"], true, "genuine deposit must be accepted");
    assert_eq!(
        result.newly_revoked,
        vec![device_fp],
        "the accepted deposit must report exactly the device it newly revoked — that is what \
         the kick relay acts on"
    );
    let expected_root_fp = root_fp.to_string();
    assert_eq!(
        reply["root_fp"].as_str(),
        Some(expected_root_fp.as_str()),
        "the accepted record must be attributed to the session's root"
    );

    // 4. The identical bundle against the same store is now refused at the pre-crypto
    //    self-revocation check.
    let after = decide_device_connect(&presented, || true, now, &mut view, 0);
    assert_eq!(after, AuthzDecision::Refused(RefusalReason::SubjectRevoked));

    // 5. Re-checking the stored control value documents that the bundle was unchanged between
    //    the two decisions — the only state transition in this test is the deposit in step 3.
    assert!(
        matches!(&before, AuthzDecision::Authorized(_)),
        "the negative control must have been Authorized for step 4 to prove anything"
    );
}
