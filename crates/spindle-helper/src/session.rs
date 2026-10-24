//! The callout's session record (DESIGN.md §A5, amended v0.9.18): `nats_fp → {root_fp, device_fp,
//! host_fps, quota_profile, exp}`, written on every successful auth so the helper can authorize
//! the non-callout requests
//! (`helper.presence.get`, `helper.turn.get.<nfp>`) that a live connection makes later. This module
//! defines only the plain data type and its constructor — durable storage (the keyed `nats_fp →
//! ...` map itself) is a [`crate::authz::HelperView`] concern, wired to Postgres in a later
//! slice.

use spindle_core::Fingerprint;

use crate::authz::HelperView;

/// One connection's session record (DESIGN.md §A5), keyed externally by `nats_fp` (this struct
/// carries `nats_fp` as a field rather than being wrapped in a map itself, so callers choose
/// their own storage shape).
///
/// **Ambiguity flagged, not resolved**: DESIGN.md §A5 introduces this record in the context of
/// *client* connections ("on each successful auth the callout writes `nats_fp → {root_fp,
/// device_fp, host_fps, quota_profile, exp}`"), and `quota_profile` elsewhere (§A3b) is populated
/// only from a **host's** admission record. Two interpretive choices this slice makes, neither
/// spelled out in DESIGN.md:
/// 1. **Host connections also get a session record**, reusing this same shape, since the helper
///    needs *some* record to authorize a host's later `helper.*` calls too. `root_fp` holds the
///    host's own `host_fp` and `host_fps` holds `[own_host_fp]` for a host connection — a stretch
///    of the field's client-oriented name, kept because introducing a second, near-identical
///    struct for hosts seemed like needless duplication for a single-field semantic difference.
/// 2. **A client/device session's `quota_profile`** has no described source at all (only hosts
///    have admission-record quota profiles). [`crate::authz`] fills it with the fixed placeholder
///    `"member"` for client connections. A later slice should replace this once — if ever — a
///    real per-member quota concept exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub nats_fp: Fingerprint,
    pub root_fp: Fingerprint,
    /// The identity root public key the caller presented in its auth bundle (DESIGN.md §A5,
    /// **[amended v0.9.47]**). Retained so `helper.revoke.<nfp>` can verify a self-revocation
    /// under the root this session presented — that handler accepts a record only if its signer is
    /// the session's `root_fp`, and a fingerprint cannot verify a signature. `None` for host
    /// connections, which have no member root: the same honest-`None` rationale as `device_fp`
    /// below.
    pub root_pk: Option<[u8; 32]>,
    /// The presenting device's fingerprint (DESIGN.md §A5, **[amended v0.9.18]**), so a
    /// device-scoped revocation (§A4: "a revocation names `root_fp | device_fp`") can be resolved
    /// to this live session (§A3's kick relay, keyed `device_fp -> (server_id, cid)` — a later
    /// slice) via [`crate::authz::HelperView::sessions_for_subject`].
    ///
    /// **Ambiguity flagged, not resolved** (same shape as this struct's own note above): a host
    /// connection's session record (interpretive choice 1 above) has no client device fingerprint
    /// in the client sense at all — there is no device standing between a host's own identity
    /// root and its operating key. `None` is the honest representation for that case, not a
    /// placeholder standing in for a value that simply doesn't exist yet.
    pub device_fp: Option<Fingerprint>,
    pub host_fps: Vec<Fingerprint>,
    pub quota_profile: String,
    pub exp: u64,
}

impl SessionRecord {
    pub fn new(
        nats_fp: Fingerprint,
        root_fp: Fingerprint,
        root_pk: Option<[u8; 32]>,
        device_fp: Option<Fingerprint>,
        host_fps: Vec<Fingerprint>,
        quota_profile: String,
        exp: u64,
    ) -> Self {
        Self {
            nats_fp,
            root_fp,
            root_pk,
            device_fp,
            host_fps,
            quota_profile,
            exp,
        }
    }
}

/// True only when `reply` is inside the inbox the caller was granted.
///
/// `permissions::client_member_permissions` grants each member connection `sub
/// _INBOX_<own_device_fp>.>` — note the grant is by **`device_fp`**, not the session's
/// `nats_fp`. This refuses every reply subject outside that concrete inbox: a different
/// device's `_INBOX_`, a `host.*`/`registry.*` subject, the bare `_INBOX_<fp>.` prefix
/// (an empty remainder is not an address), a subject missing the dot, and the `_INBOX_<fp>.>`
/// wildcard form (a subscription pattern from the permission grant, not a concrete reply
/// inbox). Any `*`/`>` token in the remainder is likewise a pattern, not an address.
///
/// This check exists because NATS authorizes the **PUB subject**, not the reply field: measured
/// in td-fc5a30, `nats-server` does not refuse a foreign `msg.reply`. Without this, a member could
/// make the helper's privileged `app_client` publish into another tenant's subject.
pub fn reply_inbox_belongs_to(reply: &str, device_fp: &Fingerprint) -> bool {
    let prefix = format!("_INBOX_{device_fp}.");
    let Some(remainder) = reply.strip_prefix(&prefix) else {
        return false;
    };
    !remainder.is_empty() && !remainder.contains('*') && !remainder.contains('>')
}

/// Resolves the caller from `subject`'s parametrized token, then checks the reply inbox.
///
/// The subject token (the caller's `nats_fp`) names the session record; the record's `device_fp`
/// is the identity the inbox grant is keyed by (`permissions::client_member_permissions`). A
/// missing or expired session, a malformed subject token, and a host-style session
/// (`device_fp: None`) all fail closed — hosts are never granted these app subjects anyway.
///
/// The check lives here, not in each handler, because the handlers (`turn.rs`, `presence.rs`,
/// `self_revoke.rs`) are purposefully NATS-free and only produce reply bytes; the caller's
/// granted inbox is derived from the session the subject token names, which only
/// `src/bin/helper.rs` — the holder of the store handle — can look up.
pub fn reply_belongs_to_caller(
    reply: &str,
    subject: &str,
    subject_prefix: &str,
    view: &mut impl HelperView,
    now: u64,
) -> bool {
    let Some(nats_fp) = crate::parse_fp_after_prefix(subject, subject_prefix) else {
        return false;
    };
    let Some(session) = view.session_record(&nats_fp, now) else {
        return false;
    };
    let Some(device_fp) = session.device_fp else {
        return false;
    };
    reply_inbox_belongs_to(reply, &device_fp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::AdmissionMode;
    use crate::memory_store::InMemoryHelperView;
    use spindle_core::SigningKey;

    const TURN_PREFIX: &str = "helper.turn.get.";
    const PRESENCE_PREFIX: &str = "helper.presence.get.";
    const REVOKE_PREFIX: &str = "helper.revoke.";

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_parts(&[seed])
    }

    fn store() -> InMemoryHelperView {
        InMemoryHelperView::new(
            AdmissionMode::Open,
            SigningKey::from_bytes(&[0x77; 32]).verifying_key(),
        )
    }

    fn record(nats_fp: Fingerprint, device_fp: Option<Fingerprint>, exp: u64) -> SessionRecord {
        SessionRecord::new(
            nats_fp,
            fp(b"root"),
            Some([0x11; 32]),
            device_fp,
            vec![],
            "member".to_string(),
            exp,
        )
    }

    #[test]
    fn reply_belongs_to_caller_accepts_the_granted_inbox_for_each_app_subject() {
        for prefix in [TURN_PREFIX, PRESENCE_PREFIX, REVOKE_PREFIX] {
            let nats_fp = fp(b"turn-nats");
            let device_fp = fp(b"turn-device");
            let mut view = store();
            view.put_session_record(record(nats_fp, Some(device_fp), 100));
            let subject = format!("{prefix}{nats_fp}");
            let reply = format!("_INBOX_{device_fp}.abc");
            assert!(
                reply_belongs_to_caller(&reply, &subject, prefix, &mut view, 99),
                "prefix {prefix} should accept its granted inbox"
            );
        }
    }

    #[test]
    fn reply_belongs_to_caller_rejects_another_devices_inbox() {
        let nats_fp = fp(b"other-device-nats");
        let device_fp = fp(b"other-device");
        let mut view = store();
        view.put_session_record(record(nats_fp, Some(device_fp), 100));
        let subject = format!("{TURN_PREFIX}{nats_fp}");
        let reply = format!("_INBOX_{}.abc", fp(b"someone-else"));
        assert!(!reply_belongs_to_caller(
            &reply,
            &subject,
            TURN_PREFIX,
            &mut view,
            99
        ));
    }

    #[test]
    fn reply_belongs_to_caller_rejects_the_sessions_own_nats_fp_inbox() {
        // The grant is by device_fp, so an inbox keyed by the session's nats_fp is not the
        // caller's granted inbox even though both fingerprints name the same connection.
        let nats_fp = fp(b"nats-keyed");
        let device_fp = fp(b"device-keyed");
        let mut view = store();
        view.put_session_record(record(nats_fp, Some(device_fp), 100));
        let subject = format!("{PRESENCE_PREFIX}{nats_fp}");
        let reply = format!("_INBOX_{nats_fp}.abc");
        assert!(!reply_belongs_to_caller(
            &reply,
            &subject,
            PRESENCE_PREFIX,
            &mut view,
            99
        ));
    }

    #[test]
    fn reply_belongs_to_caller_rejects_no_session_and_expired_session() {
        let nats_fp = fp(b"missing-session");
        let device_fp = fp(b"missing-device");
        let subject = format!("{REVOKE_PREFIX}{nats_fp}");
        let reply = format!("_INBOX_{device_fp}.abc");

        let mut no_session = store();
        assert!(!reply_belongs_to_caller(
            &reply,
            &subject,
            REVOKE_PREFIX,
            &mut no_session,
            99
        ));

        let mut expired = store();
        expired.put_session_record(record(nats_fp, Some(device_fp), 100));
        assert!(!reply_belongs_to_caller(
            &reply,
            &subject,
            REVOKE_PREFIX,
            &mut expired,
            100,
        ));
    }

    #[test]
    fn reply_belongs_to_caller_rejects_a_host_style_session() {
        // A host session record carries `device_fp: None`; hosts are never granted these app
        // subjects, and there is no granted inbox to compare against — fail closed.
        let nats_fp = fp(b"host-session");
        let mut view = store();
        view.put_session_record(record(nats_fp, None, 100));
        let subject = format!("{TURN_PREFIX}{nats_fp}");
        let reply = format!("_INBOX_{}.abc", fp(b"unknown-device"));
        assert!(!reply_belongs_to_caller(
            &reply,
            &subject,
            TURN_PREFIX,
            &mut view,
            99
        ));
    }

    #[test]
    fn reply_belongs_to_caller_rejects_wrong_prefix_and_malformed_token() {
        let nats_fp = fp(b"prefix-nats");
        let device_fp = fp(b"prefix-device");
        let mut view = store();
        view.put_session_record(record(nats_fp, Some(device_fp), 100));
        let reply = format!("_INBOX_{device_fp}.abc");
        let subject = format!("{REVOKE_PREFIX}{nats_fp}");
        assert!(
            !reply_belongs_to_caller(&reply, &subject, TURN_PREFIX, &mut view, 99),
            "a subject under a different prefix must not authorize"
        );
        assert!(
            !reply_belongs_to_caller(
                &reply,
                "helper.turn.get.not-a-fingerprint",
                TURN_PREFIX,
                &mut view,
                99
            ),
            "a malformed subject token must not authorize"
        );
    }

    #[test]
    fn reply_inbox_belongs_to_accepts_only_a_concrete_address_in_the_granted_inbox() {
        let device_fp = fp(b"inbox-device");
        assert!(reply_inbox_belongs_to(
            &format!("_INBOX_{device_fp}.abc"),
            &device_fp
        ));
        assert!(reply_inbox_belongs_to(
            &format!("_INBOX_{device_fp}._INBOX.abc"),
            &device_fp
        ));
    }

    #[test]
    fn reply_inbox_belongs_to_rejects_bare_prefix_missing_dot_and_wildcards() {
        let device_fp = fp(b"inbox-device");
        assert!(
            !reply_inbox_belongs_to(&format!("_INBOX_{device_fp}."), &device_fp),
            "the bare prefix has an empty remainder"
        );
        assert!(
            !reply_inbox_belongs_to(&format!("_INBOX_{device_fp}"), &device_fp),
            "the subject is missing the dot"
        );
        assert!(
            !reply_inbox_belongs_to(&format!("_INBOX_{device_fp}.>"), &device_fp),
            "the > form is a permission-grant pattern, not a concrete reply inbox"
        );
        assert!(
            !reply_inbox_belongs_to(&format!("_INBOX_{device_fp}.abc.*"), &device_fp),
            "a * token is a pattern, not an address"
        );
        assert!(
            !reply_inbox_belongs_to(
                &format!("host.{}.sess.abc.def.h2c", fp(b"victim-host")),
                &device_fp
            ),
            "a host.* subject is never the caller's inbox"
        );
        assert!(
            !reply_inbox_belongs_to(&format!("_INBOX_{}.abc", fp(b"another-device")), &device_fp),
            "another device's inbox is not the caller's"
        );
    }

    #[test]
    fn constructor_stores_fields_verbatim() {
        let nats_fp = Fingerprint::of_parts(&[b"nats"]);
        let root_fp = Fingerprint::of_parts(&[b"root"]);
        let device_fp = Fingerprint::of_parts(&[b"device"]);
        let root_pk = [0xA5; 32];
        let host_fps = vec![Fingerprint::of_parts(&[b"host-a"])];
        let rec = SessionRecord::new(
            nats_fp,
            root_fp,
            Some(root_pk),
            Some(device_fp),
            host_fps.clone(),
            "member".to_string(),
            1_234,
        );
        assert_eq!(rec.nats_fp, nats_fp);
        assert_eq!(rec.root_fp, root_fp);
        assert_eq!(rec.root_pk, Some(root_pk));
        assert_eq!(rec.device_fp, Some(device_fp));
        assert_eq!(rec.host_fps, host_fps);
        assert_eq!(rec.quota_profile, "member");
        assert_eq!(rec.exp, 1_234);
    }

    #[test]
    fn constructor_accepts_none_device_fp_for_host_connections() {
        let nats_fp = Fingerprint::of_parts(&[b"nats-host"]);
        let root_fp = Fingerprint::of_parts(&[b"host-root"]);
        let rec = SessionRecord::new(
            nats_fp,
            root_fp,
            None,
            None,
            vec![root_fp],
            "default".to_string(),
            5_678,
        );
        assert_eq!(rec.device_fp, None);
        assert_eq!(rec.root_pk, None, "a host connection has no member root");
    }
}
