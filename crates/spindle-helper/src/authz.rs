//! The Auth Callout decision core (DESIGN.md §A4 "NATS authentication = Auth Callout for every
//! connection", §A5 "Permissions issued by callout"). Pure, deterministic, synchronous — no NATS
//! client, no clock, no I/O. Every external fact (current time, a caller-verified nkey signature,
//! the helper's durable-store lookups) is a parameter, never read implicitly.
//!
//! # Scope
//! This module decides **whether** a presented connection is authorized and **what** it gets —
//! it does not decode raw NATS CONNECT bytes into [`spindle_proto::artifacts::Capability`] /
//! [`spindle_proto::artifacts::DeviceCertificate`] / [`spindle_proto::artifacts::HostOpKeyCert`] /
//! [`spindle_proto::artifacts::AdmissionToken`] (that CBOR decoding, and the actual nkey-signature
//! check against the server nonce, are NATS-library/wiring-layer concerns for a later slice — see
//! the crate-level docs). Callers here have already parsed the presented artifacts and the
//! device/host identity root's public key.
//!
//! # Ordering (DESIGN.md §A4 step 2, §A12 #24)
//! Both [`decide_device_connect`] and [`decide_host_connect`] are written so the **cheapest**
//! checks run first and an early return skips every following, more expensive check —
//! structurally, not just as an aside — because the callout is the DoS surface under a
//! connection flood: count/size checks, then plain field comparisons (`exp`, fingerprint
//! equality), then [`HelperView`] store lookups (revocation, admission mode/record — no crypto),
//! and only then the actually expensive Ed25519 verifications (the caller-supplied nkey check,
//! then `spindle_core::artifacts::verify_*`). See `tests::ordering` below for the counting-stub
//! proof.
//!
//! # Uniform refusal (DESIGN.md §A5: "All rejections are uniform silent drops")
//! [`RefusalReason`] is intentionally granular — it exists for internal metrics and for the
//! negative-test suite below, which needs to assert *which* rule fired. It must **never** be
//! serialized onto the wire. [`AuthzDecision::wire_message`] is the one sanctioned way to turn a
//! decision into wire-facing text, and it collapses every `Refused` variant to the same string.

use spindle_core::artifacts::ArtifactError;
use spindle_core::{root_fp_of, Fingerprint, VerifyingKey};
use spindle_proto::artifacts::{
    AdmissionToken, CapKind, Capability, DeviceCertificate, HostOpKeyCert,
};

use crate::permissions::{self, Limits, SubjectPermissions};
use crate::session::SessionRecord;

/// Max capabilities a device may present in one connection, and (1:1, since a member cap is
/// per-host) the max hosts a connection can be scoped to (DESIGN.md §A4 "max 32 per connection
/// (A10.5)"; §A5 "Max 32 hosts per connection").
pub const MAX_CAPS_PER_CONNECTION: usize = 32;

/// The uniform, wire-facing text every refusal carries. See the module docs' "Uniform refusal"
/// section — do not send [`RefusalReason`]'s own `Display` on the wire.
pub const UNIFORM_REFUSAL_MESSAGE: &str = "authentication refused";

// ================================================================================================
// Decision types
// ================================================================================================

/// The outcome of a callout decision. `Authorized` is boxed since [`Authorization`] is
/// considerably larger than [`RefusalReason`] (a fieldless-ish enum) — this keeps
/// `AuthzDecision` itself small to pass/return by value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDecision {
    Authorized(Box<Authorization>),
    Refused(RefusalReason),
}

impl AuthzDecision {
    /// The uniform wire-facing message for this decision (see module docs). Every `Refused`
    /// variant, regardless of `RefusalReason`, produces the same string — that uniformity is the
    /// point (DESIGN.md §A5, §A12 #4/#32: no oracle for enumerating hosts/members via refusal
    /// granularity or timing).
    pub fn wire_message(&self) -> &'static str {
        match self {
            AuthzDecision::Authorized(_) => "authorized",
            AuthzDecision::Refused(_) => UNIFORM_REFUSAL_MESSAGE,
        }
    }

    pub fn is_authorized(&self) -> bool {
        matches!(self, AuthzDecision::Authorized(_))
    }
}

/// A successful callout decision: the permissions and limits to issue, plus the session record
/// to persist (DESIGN.md §A5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    pub permissions: SubjectPermissions,
    pub limits: Limits,
    pub session_record: SessionRecord,
}

/// Why a connection was refused. **Internal use only** (metrics, logs, this module's own test
/// suite) — never put on the wire; see [`AuthzDecision::wire_message`]. Distinct `Display`
/// messages are provided (via `thiserror`) precisely so internal tooling *can* tell these apart;
/// that is not in tension with the uniform-refusal principle, which is about the wire, not about
/// the helper's own observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RefusalReason {
    #[error("more than {MAX_CAPS_PER_CONNECTION} capabilities presented")]
    TooManyCapabilities,
    #[error("no capabilities presented")]
    NoCapabilitiesPresented,
    #[error("device certificate expired")]
    DeviceCertificateExpired,
    #[error("device certificate signature invalid")]
    BadDeviceCertificate,
    #[error("no presented capability's subject matches the presenting identity root")]
    CapabilitySubjectMismatch,
    #[error("subject is revoked for this host")]
    SubjectRevoked,
    #[error("nkey signature invalid")]
    BadNkeySignature,
    #[error("no presented capability yielded a valid signature")]
    BadCapabilitySignature,
    #[error("host operating-key certificate expired")]
    HostCertificateExpired,
    #[error("host operating-key certificate signature invalid")]
    BadHostSignature,
    #[error("admission mode is invite-only and no admission token was presented")]
    NoAdmissionRecord,
    #[error("admission mode is closed to new hosts")]
    AdmissionClosed,
    #[error("admission token expired")]
    AdmissionTokenExpired,
    #[error("admission token signature invalid")]
    BadAdmissionToken,
    #[error("admission token nonce already burned by a different host")]
    AdmissionTokenAlreadyUsed,
}

// ================================================================================================
// HelperView — the store lookups the callout needs
// ================================================================================================

/// Registry admission mode (DESIGN.md §A3b), switchable at runtime via signed admin commands
/// (not this module's concern — [`HelperView::admission_mode`] just reports the current value).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AdmissionMode {
    /// New hosts must redeem a single-use admission token. Default (DESIGN.md §A3b, A10.17).
    #[default]
    Invite,
    /// Any valid host cert is admitted (quotas apply elsewhere; not this module's concern).
    Open,
    /// No new hosts; existing admitted hosts unaffected.
    Closed,
}

/// `{host_fp, label, admitted_at, quota_profile}` (DESIGN.md §A3b) — written once per admitted
/// host, looked up by `host_fp` on every subsequent host connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRecord {
    pub host_fp: Fingerprint,
    pub label: String,
    pub admitted_at: u64,
    pub quota_profile: String,
}

/// The store lookups a callout decision needs. Implemented against the durable Postgres store in
/// a later slice; this slice only defines the contract and exercises it against in-memory test
/// doubles.
///
/// Every method takes `&mut self` — even the read-only-looking ones — because a real
/// implementation may want to cache or instrument lookups, and there is no benefit to this crate
/// in forcing interior mutability on implementors for what is, either way, a stateful store.
pub trait HelperView {
    /// The revocation epoch high-water mark for `host_fp` (DESIGN.md §A7b: max-wins, never
    /// decreases). `0` if the helper has seen no revocation record for this host yet.
    fn revocation_epoch(&mut self, host_fp: &Fingerprint) -> u64;

    /// True if `subject` (a `root_fp` or a `device_fp`) is revoked for `host_fp` per the
    /// helper's durable revocation store (DESIGN.md §A4: "best-effort" — the host's per-request
    /// enforcement remains authoritative).
    fn is_revoked(&mut self, host_fp: &Fingerprint, subject: &Fingerprint) -> bool;

    /// Current registry admission mode (DESIGN.md §A3b).
    fn admission_mode(&mut self) -> AdmissionMode;

    /// The admission record for `host_fp`, if this host has already been admitted.
    fn admission_record(&mut self, host_fp: &Fingerprint) -> Option<AdmissionRecord>;

    /// The operator admission key's public key, for verifying admission tokens.
    fn operator_pk(&mut self) -> VerifyingKey;

    /// Burns an admission-token nonce for `host_fp`, writing `{host_fp, label, admitted_at,
    /// quota_profile}` durably (DESIGN.md §A3b/§A4).
    ///
    /// **Idempotency contract** (DESIGN.md §A4's invite-redemption rule, extended to admission
    /// tokens by the same section's "the same rule applies to admission invites at the helper"):
    /// - Nonce not seen before → create, store, and return the new record.
    /// - Nonce already burned **by this same `host_fp`** → return the *original* stored record
    ///   unchanged (a crash or lost reply between burn and delivery cannot strand or double-spend
    ///   the connecting host).
    /// - Nonce already burned **by a different `host_fp`** → return `None`. A single-use token
    ///   admitting two different hosts would defeat the whole point of single-use.
    fn burn_admission_token(
        &mut self,
        host_fp: Fingerprint,
        nonce: Vec<u8>,
        label: String,
        quota_profile: String,
        admitted_at: u64,
    ) -> Option<AdmissionRecord>;

    // ============================================================================================
    // Extended in Stage 4 slice 3 (session records + TURN counters + revocation writes).
    //
    // **Discovered gap, reported rather than silently patched**: none of the four methods below
    // existed anywhere in this trait before this slice, even though DESIGN.md §A5 explicitly
    // describes writing a session record ("on each successful auth the callout writes `nats_fp →
    // {root_fp, host_fps, quota_profile, exp}` to the helper store") and §A9b explicitly lists
    // "session records, admission records, ... TURN counters" among the leader's durable writes.
    // Slice 1/2 built [`SessionRecord`] as a plain data type and computed one on every
    // [`AuthzDecision::Authorized`], but **never persisted it** — `src/bin/helper.rs`'s
    // `handle_one` discarded `auth.session_record` after reading only its `host_fps.len()`. There
    // was also no store method to write a revocation epoch/subject at all (only the read side,
    // above, existed) despite DESIGN.md §A9b listing revocation epochs among the leader's writes.
    // This is not a redesign of the existing (read) methods above — it is filling in write/lookup
    // methods the trait needed all along for `helper.turn.get` (this slice) and `registry.revoke.
    // <hfp>` (a still-unwired later slice) to have anything to call.
    // ============================================================================================

    /// Writes (or overwrites) the session record for `record.nats_fp` (DESIGN.md §A5). Upsert
    /// semantics: a later write for the same `nats_fp` (e.g. a reconnect that reuses the same
    /// session nkey, or a renewed `exp`) replaces the stored record rather than erroring or
    /// requiring a separate update call.
    fn put_session_record(&mut self, record: SessionRecord);

    /// Looks up the session record for `nats_fp`. A record whose `exp` is at or before `now` is
    /// treated as absent (DESIGN.md §A5 "cleaned up on DISCONNECT/expiry" — this trait enforces
    /// only the expiry half via an on-read filter; eager DISCONNECT-triggered deletion is a
    /// wiring-layer concern for whichever later slice bridges `$SYS.ACCOUNT.*.DISCONNECT` events,
    /// out of scope for this trait boundary).
    fn session_record(&mut self, nats_fp: &Fingerprint, now: u64) -> Option<SessionRecord>;

    /// Atomically checks-and-increments `root_fp`'s TURN-credential-mint counter for the period
    /// containing `now`, against `monthly_quota`. Returns `Ok(new_count)` (already incremented) if
    /// the mint is admitted, or `Err(current_count)` (not incremented) if `root_fp` is already at
    /// or over `monthly_quota` for this period (DESIGN.md §A8 "quota enforced by the helper per
    /// `root_fp`"; §A9b lists "TURN counters" among the leader's writes).
    ///
    /// **Period definition — a documented deviation, not "monthly" in the calendar sense**: this
    /// trait defines the window as a fixed 30-day rolling bucket (`now / (30 * 86400)`), not a
    /// calendar month. Calendar-month bucketing needs a date/calendar dependency this crate's A9c
    /// dependency manifest does not list for `spindle-helper` (proto + core only); a fixed-size
    /// integer bucket needs no such dependency and is a reasonable, simple stand-in. Flagged for
    /// the coordinator, not silently resolved as literally "monthly".
    fn record_turn_issuance(
        &mut self,
        root_fp: &Fingerprint,
        now: u64,
        monthly_quota: u64,
    ) -> Result<u64, u64>;

    /// Records a revocation for `host_fp`: bumps the stored epoch to `max(existing, epoch)`
    /// (DESIGN.md §A7b "max-wins, never decreases") and adds every fingerprint in
    /// `revoked_subjects` to the durable revoked-subject set for `host_fp` (DESIGN.md §A9b
    /// "revocation epochs ... revoked-subject sets alongside"). Not currently called by
    /// `src/bin/helper.rs` — `registry.revoke.<hfp>` handling is still unwired (a later slice) —
    /// but the store operation and its SQL semantics are this slice's deliverable regardless, so
    /// the read side above (`revocation_epoch`/`is_revoked`) has something to prove itself against
    /// in the store-contract tests.
    fn record_revocation(&mut self, host_fp: Fingerprint, epoch: u64, revoked_subjects: &[Fingerprint]);

    /// Best-effort cleanup of session records whose `exp` has already passed. No-op by default
    /// (the on-read `exp` filter in [`session_record`](HelperView::session_record) already hides
    /// expired rows from callers — this is purely about bounding storage growth for a
    /// long-running process, not correctness). [`crate::pg_store::PgStore`] overrides this with a
    /// real `DELETE`; [`crate::memory_store::InMemoryHelperView`] overrides it to bound its
    /// `HashMap`'s growth too.
    fn purge_expired_sessions(&mut self, _now: u64) {}
}

// ================================================================================================
// Device connections
// ================================================================================================

/// What a device presents on CONNECT (DESIGN.md §A4 step 1), already decoded from the wire.
/// `root_pk` is the identity root's public key carried alongside the device certificate chain —
/// [`spindle_proto::artifacts::DeviceCertificate`] itself carries no `root_pk` field (only
/// `device_fp`/`nats_fp`/`ts`/`exp`/`sig_root`), so the verifier needs it presented out of band,
/// the same way `HostOpKeyCert` needs `host_root_pk` (see [`HostConnectPresented`]).
pub struct DeviceConnectPresented {
    pub root_pk: VerifyingKey,
    pub device_cert: DeviceCertificate,
    /// The capabilities presented for this session: one or more `member` caps, or a single
    /// `invite` cap (DESIGN.md §A4).
    pub caps: Vec<Capability>,
    /// The session nkey's fingerprint, for the session record.
    pub nats_fp: Fingerprint,
}

fn cap_host_fp(cap: &Capability) -> Option<Fingerprint> {
    Fingerprint::from_slice(&cap.host_fp).ok()
}

fn cap_subject_fp(cap: &Capability) -> Option<Fingerprint> {
    Fingerprint::from_slice(&cap.subject).ok()
}

/// Decides whether a device's CONNECT is authorized, and what it gets (DESIGN.md §A4 step 2,
/// §A5). See the module docs for the ordering discipline and the uniform-refusal principle.
///
/// `verify_nkey_sig` is invoked at most once, lazily — only once every cheap check has passed —
/// so a flood of connections that fail a cheap check (too many caps, no caps, subject mismatch,
/// a revoked subject) never pays for a signature verification (DESIGN.md §A12 #24).
pub fn decide_device_connect(
    presented: &DeviceConnectPresented,
    verify_nkey_sig: impl FnOnce() -> bool,
    now: u64,
    view: &mut impl HelperView,
    jitter_source: u64,
) -> AuthzDecision {
    // 1. Cheap count check — first, before anything else.
    if presented.caps.len() > MAX_CAPS_PER_CONNECTION {
        return AuthzDecision::Refused(RefusalReason::TooManyCapabilities);
    }
    if presented.caps.is_empty() {
        return AuthzDecision::Refused(RefusalReason::NoCapabilitiesPresented);
    }

    // 2. Cheap field check — plain integer comparison, no crypto.
    if now > presented.device_cert.exp {
        return AuthzDecision::Refused(RefusalReason::DeviceCertificateExpired);
    }

    // 3. Cheap hashes (not signature verifications) deriving the presenting identity.
    let root_fp = root_fp_of(&presented.root_pk);
    let device_fp = match Fingerprint::from_slice(&presented.device_cert.device_fp) {
        Ok(fp) => fp,
        Err(_) => return AuthzDecision::Refused(RefusalReason::BadDeviceCertificate),
    };

    // 4. Cheap per-cap subject match, then a store lookup (no crypto) for revocation. A cap
    //    whose subject isn't this root_fp contributes nothing and is dropped silently — it is
    //    not, by itself, a reason to refuse the whole connection. A revoked subject, in
    //    contrast, refuses the whole connection outright: DESIGN.md §A4 "only revoked subjects
    //    are refused outright" (never merely downgraded to connect-only), and checking it here —
    //    before any signature work — also means a revoked device can never cost the callout an
    //    Ed25519 verification.
    let mut candidates: Vec<&Capability> = Vec::with_capacity(presented.caps.len());
    for cap in &presented.caps {
        let Some(subject_fp) = cap_subject_fp(cap) else {
            continue;
        };
        if subject_fp != root_fp {
            continue;
        }
        let Some(host_fp) = cap_host_fp(cap) else {
            continue;
        };
        if view.is_revoked(&host_fp, &root_fp) || view.is_revoked(&host_fp, &device_fp) {
            return AuthzDecision::Refused(RefusalReason::SubjectRevoked);
        }
        candidates.push(cap);
    }
    if candidates.is_empty() {
        return AuthzDecision::Refused(RefusalReason::CapabilitySubjectMismatch);
    }

    // 5. Expensive checks from here on: the caller-verified nkey signature (checked lazily —
    //    see the ordering tests), then the device certificate's root signature, then each
    //    candidate capability's host signature.
    if !verify_nkey_sig() {
        return AuthzDecision::Refused(RefusalReason::BadNkeySignature);
    }
    if spindle_core::artifacts::verify_device_certificate(
        &presented.device_cert,
        &presented.root_pk,
        &root_fp,
        now,
    )
    .is_err()
    {
        return AuthzDecision::Refused(RefusalReason::BadDeviceCertificate);
    }

    let mut full_hosts: Vec<Fingerprint> = Vec::new();
    let mut connect_only_hosts: Vec<Fingerprint> = Vec::new();
    for cap in candidates {
        let Some(host_fp) = cap_host_fp(cap) else {
            continue;
        };
        match spindle_core::artifacts::verify_capability(cap, now) {
            Ok(()) => {
                let fresh_epoch = cap.cap_epoch >= view.revocation_epoch(&host_fp);
                if matches!(cap.kind, CapKind::Member) && fresh_epoch {
                    full_hosts.push(host_fp);
                } else {
                    // An invite cap is connect-only *by kind* (DESIGN.md §A4: "scope = connect
                    // only"), always — not just when stale. A member cap whose cap_epoch is
                    // behind the helper's high-water mark for this host is the renewal path
                    // (DESIGN.md §A4/§A7b #42): still connect-only, not a refusal.
                    connect_only_hosts.push(host_fp);
                }
            }
            Err(ArtifactError::Expired) => {
                // `verify_capability` checks host-fingerprint self-consistency and the
                // signature *before* `exp` (see spindle_core::artifacts::capability) — reaching
                // this arm means the signature was valid. This is DESIGN.md §A4's renewal path:
                // "a cap that is expired ... but signature-valid still earns connect-only".
                connect_only_hosts.push(host_fp);
            }
            Err(_) => {
                // Bad signature, or a malformed host_fp/host_pk self-consistency: this
                // capability contributes nothing, full stop — never connect-only for a
                // forged/garbage cap.
            }
        }
    }

    if full_hosts.is_empty() && connect_only_hosts.is_empty() {
        return AuthzDecision::Refused(RefusalReason::BadCapabilitySignature);
    }

    let permissions = match (full_hosts.is_empty(), connect_only_hosts.is_empty()) {
        (false, true) => permissions::client_member_permissions(device_fp, &full_hosts),
        (true, false) => {
            permissions::client_connect_only_permissions(device_fp, &connect_only_hosts)
        }
        (false, false) => permissions::client_member_permissions(device_fp, &full_hosts).merge(
            permissions::client_connect_only_permissions(device_fp, &connect_only_hosts),
        ),
        (true, true) => unreachable!("checked above"),
    };

    let mut host_fps = full_hosts;
    host_fps.extend(connect_only_hosts);
    let limits = Limits::new(host_fps.len() as u32, now, jitter_source);

    AuthzDecision::Authorized(Box::new(Authorization {
        permissions,
        limits,
        session_record: SessionRecord::new(
            presented.nats_fp,
            root_fp,
            host_fps,
            // DESIGN.md §A5's session-record schema has no described source for a client
            // session's quota_profile (see session.rs's doc comment) — fixed placeholder.
            "member".to_string(),
            limits.exp,
        ),
    }))
}

// ================================================================================================
// Host connections
// ================================================================================================

/// What a host presents on CONNECT (DESIGN.md §A4 step 3), already decoded from the wire.
/// `host_root_pk` is presented alongside `host_op_cert` for the same reason
/// [`DeviceConnectPresented::root_pk`] is: [`HostOpKeyCert`] carries no `host_root_pk` field.
pub struct HostConnectPresented {
    pub host_root_pk: VerifyingKey,
    pub host_op_cert: HostOpKeyCert,
    /// Present only on a host's first connection under `invite` admission mode.
    pub admission_token: Option<AdmissionToken>,
    pub nats_fp: Fingerprint,
}

enum AdmissionOutcome<'a> {
    AlreadyAdmitted(AdmissionRecord),
    Open,
    NeedsTokenVerification(&'a AdmissionToken),
}

/// Decides whether a host's CONNECT is authorized (DESIGN.md §A4 step 3, §A3b, §A5).
pub fn decide_host_connect(
    presented: &HostConnectPresented,
    verify_nkey_sig: impl FnOnce() -> bool,
    now: u64,
    view: &mut impl HelperView,
    jitter_source: u64,
) -> AuthzDecision {
    // 1. Cheap field check.
    if now > presented.host_op_cert.exp {
        return AuthzDecision::Refused(RefusalReason::HostCertificateExpired);
    }

    // 2. Cheap hash.
    let host_fp = root_fp_of(&presented.host_root_pk);

    // 3. Cheap store lookups only, resolving how (or whether) this host may proceed, before any
    //    crypto. An already-admitted host skips mode/token checks entirely (DESIGN.md §A3b:
    //    "the host connects on its cert alone; the callout checks the admission record").
    let outcome = if let Some(record) = view.admission_record(&host_fp) {
        AdmissionOutcome::AlreadyAdmitted(record)
    } else {
        match view.admission_mode() {
            AdmissionMode::Closed => {
                return AuthzDecision::Refused(RefusalReason::AdmissionClosed);
            }
            AdmissionMode::Open => AdmissionOutcome::Open,
            AdmissionMode::Invite => {
                let Some(token) = presented.admission_token.as_ref() else {
                    return AuthzDecision::Refused(RefusalReason::NoAdmissionRecord);
                };
                if now > token.exp {
                    return AuthzDecision::Refused(RefusalReason::AdmissionTokenExpired);
                }
                AdmissionOutcome::NeedsTokenVerification(token)
            }
        }
    };

    // 4. Expensive checks from here on.
    if !verify_nkey_sig() {
        return AuthzDecision::Refused(RefusalReason::BadNkeySignature);
    }
    if spindle_core::artifacts::verify_host_op_key_cert(
        &presented.host_op_cert,
        &presented.host_root_pk,
        &host_fp,
        now,
    )
    .is_err()
    {
        return AuthzDecision::Refused(RefusalReason::BadHostSignature);
    }

    let quota_profile = match outcome {
        AdmissionOutcome::AlreadyAdmitted(record) => record.quota_profile,
        // DESIGN.md §A3b's `open` mode admits on cert alone; it describes no admission-record
        // write and no quota-profile source for open-mode hosts. Placeholder, flagged in the
        // crate's Cargo.toml/module docs as a gap for a later slice.
        AdmissionOutcome::Open => "default".to_string(),
        AdmissionOutcome::NeedsTokenVerification(token) => {
            if spindle_core::artifacts::verify_admission_token(token, &view.operator_pk(), now)
                .is_err()
            {
                return AuthzDecision::Refused(RefusalReason::BadAdmissionToken);
            }
            match view.burn_admission_token(
                host_fp,
                token.nonce.clone(),
                token.label.clone(),
                token.quota_profile.clone(),
                now,
            ) {
                Some(record) => record.quota_profile,
                None => {
                    return AuthzDecision::Refused(RefusalReason::AdmissionTokenAlreadyUsed);
                }
            }
        }
    };

    let limits = Limits::new(1, now, jitter_source);
    AuthzDecision::Authorized(Box::new(Authorization {
        permissions: permissions::host_permissions(host_fp),
        limits,
        session_record: SessionRecord::new(
            presented.nats_fp,
            // See session.rs's doc comment: a host connection's "root_fp" field holds the
            // host's own host_fp, and "host_fps" holds just itself.
            host_fp,
            vec![host_fp],
            quota_profile,
            limits.exp,
        ),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::artifacts::{
        issue_admission_token, issue_capability, issue_device_certificate, issue_host_op_key_cert,
    };
    use spindle_core::identity::RootKey;
    use spindle_core::SigningKey;
    use std::cell::Cell;
    use std::collections::{HashMap, HashSet};

    // ---- test doubles -------------------------------------------------------------------

    #[derive(Default)]
    struct MockView {
        revoked: HashSet<(Fingerprint, Fingerprint)>,
        epochs: HashMap<Fingerprint, u64>,
        mode: AdmissionMode,
        records: HashMap<Fingerprint, AdmissionRecord>,
        burned: HashMap<Vec<u8>, AdmissionRecord>,
        operator_pk: Option<VerifyingKey>,
        burn_calls: u32,
        sessions: HashMap<Fingerprint, SessionRecord>,
        turn_usage: HashMap<(Fingerprint, u64), u64>,
    }

    impl HelperView for MockView {
        fn revocation_epoch(&mut self, host_fp: &Fingerprint) -> u64 {
            *self.epochs.get(host_fp).unwrap_or(&0)
        }

        fn is_revoked(&mut self, host_fp: &Fingerprint, subject: &Fingerprint) -> bool {
            self.revoked.contains(&(*host_fp, *subject))
        }

        fn admission_mode(&mut self) -> AdmissionMode {
            self.mode
        }

        fn admission_record(&mut self, host_fp: &Fingerprint) -> Option<AdmissionRecord> {
            self.records.get(host_fp).cloned()
        }

        fn operator_pk(&mut self) -> VerifyingKey {
            self.operator_pk.expect("operator_pk configured")
        }

        fn burn_admission_token(
            &mut self,
            host_fp: Fingerprint,
            nonce: Vec<u8>,
            label: String,
            quota_profile: String,
            admitted_at: u64,
        ) -> Option<AdmissionRecord> {
            if let Some(existing) = self.burned.get(&nonce) {
                return if existing.host_fp == host_fp {
                    Some(existing.clone())
                } else {
                    None
                };
            }
            self.burn_calls += 1;
            let record = AdmissionRecord {
                host_fp,
                label,
                admitted_at,
                quota_profile,
            };
            self.burned.insert(nonce, record.clone());
            self.records.insert(host_fp, record.clone());
            Some(record)
        }

        fn put_session_record(&mut self, record: SessionRecord) {
            self.sessions.insert(record.nats_fp, record);
        }

        fn session_record(&mut self, nats_fp: &Fingerprint, now: u64) -> Option<SessionRecord> {
            self.sessions.get(nats_fp).filter(|r| r.exp > now).cloned()
        }

        fn record_turn_issuance(
            &mut self,
            root_fp: &Fingerprint,
            now: u64,
            monthly_quota: u64,
        ) -> Result<u64, u64> {
            let period = now / (30 * 86_400);
            let key = (*root_fp, period);
            let count = self.turn_usage.entry(key).or_insert(0);
            if *count >= monthly_quota {
                Err(*count)
            } else {
                *count += 1;
                Ok(*count)
            }
        }

        fn record_revocation(
            &mut self,
            host_fp: Fingerprint,
            epoch: u64,
            revoked_subjects: &[Fingerprint],
        ) {
            let entry = self.epochs.entry(host_fp).or_insert(0);
            *entry = (*entry).max(epoch);
            for subject in revoked_subjects {
                self.revoked.insert((host_fp, *subject));
            }
        }
    }

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_parts(&[seed])
    }

    /// A full test host: identity root + operating key + the root's `HostOpKeyCert` — the chain
    /// [`issue_capability`] now needs (decision A10.30). `host_fp` is root-derived
    /// (`root.root_fp()`), matching what `decide_host_connect` derives from `host_root_pk` — this
    /// is the fix for the op-key-derived `host_fp` inconsistency S1 flagged (see module docs):
    /// before A10.30, this test module (like `issue_capability` itself) computed a capability's
    /// `host_fp` from the *operating* key's own public key
    /// (`Fingerprint::of_parts(&[signer.verifying_key().as_bytes()])`), which could never match
    /// `decide_host_connect`'s `root_fp_of(presented.host_root_pk)` for any host whose root and
    /// operating keys actually differ. That workaround is gone: every `host_fp` here now comes
    /// from `TestHost::host_fp` (the root fingerprint), the single definition both sides share.
    struct TestHost {
        root: RootKey,
        op_signer: SigningKey,
        op_cert: HostOpKeyCert,
        host_fp: Fingerprint,
    }

    fn test_host(root_seed: [u8; 32], op_seed: [u8; 32]) -> TestHost {
        let root = RootKey::from_seed(root_seed);
        let op_signer = SigningKey::from_bytes(&op_seed);
        let op_cert = issue_host_op_key_cert(
            &root,
            &op_signer.verifying_key(),
            fp(b"authz-test:op-cert-nats"),
            0,
            u64::MAX,
        );
        let host_fp = root.root_fp();
        TestHost {
            root,
            op_signer,
            op_cert,
            host_fp,
        }
    }

    fn device_setup() -> (RootKey, DeviceCertificate, Fingerprint) {
        let root = RootKey::from_seed([0x01; 32]);
        let device_fp = fp(b"device-1");
        let nats_fp = fp(b"nats-1");
        let cert = issue_device_certificate(&root, device_fp, nats_fp, 1_000, 2_000_000);
        (root, cert, device_fp)
    }

    fn member_cap(host: &TestHost, subject: Fingerprint, epoch: u64, exp: u64) -> Capability {
        issue_capability(
            &host.root.public_key(),
            &host.op_cert,
            &host.op_signer,
            CapKind::Member,
            subject,
            epoch,
            exp,
            vec![0xAA; 8],
        )
    }

    fn invite_cap(host: &TestHost, subject: Fingerprint, exp: u64) -> Capability {
        issue_capability(
            &host.root.public_key(),
            &host.op_cert,
            &host.op_signer,
            CapKind::Invite,
            subject,
            0,
            exp,
            vec![0xBB; 8],
        )
    }

    // ---- decide_device_connect ------------------------------------------------------------

    #[test]
    fn fresh_key_with_no_cap_is_refused() {
        let (_root, cert, _dfp) = device_setup();
        let root_pk = RootKey::from_seed([0x01; 32]).public_key();
        let presented = DeviceConnectPresented {
            root_pk,
            device_cert: cert,
            caps: vec![],
            nats_fp: fp(b"nats-session"),
        };
        let mut view = MockView::default();
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::NoCapabilitiesPresented)
        );
    }

    #[test]
    fn expired_cap_with_bad_signature_is_refused() {
        let (root, cert, _dfp) = device_setup();
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let mut cap = member_cap(&host, root_fp, 0, 1_000); // already expired at now=1_500
        cap.sig[0] ^= 0xff; // forged
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
        };
        let mut view = MockView::default();
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::BadCapabilitySignature)
        );
    }

    #[test]
    fn capability_subject_mismatch_is_refused() {
        let (root, cert, _dfp) = device_setup();
        let host = test_host([0x11; 32], [0x12; 32]);
        let cap = member_cap(&host, fp(b"someone-else"), 0, 2_000_000);
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
        };
        let mut view = MockView::default();
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::CapabilitySubjectMismatch)
        );
    }

    #[test]
    fn revoked_subject_is_refused_outright_never_connect_only() {
        let (root, cert, _dfp) = device_setup();
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let host_fp = host.host_fp;
        // A perfectly valid, non-expired, non-stale cap.
        let cap = member_cap(&host, root_fp, 0, 2_000_000);
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
        };
        let mut view = MockView::default();
        view.revoked.insert((host_fp, root_fp));
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::SubjectRevoked),
            "revoked subject must be refused outright, never connect-only"
        );
    }

    #[test]
    fn expired_but_signature_valid_member_cap_is_connect_only() {
        let (root, cert, device_fp) = device_setup();
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let host_fp = host.host_fp;
        let cap = member_cap(&host, root_fp, 0, 1_000); // expired at now=1_500, sig valid
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
        };
        let mut view = MockView::default();
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 0);
        let AuthzDecision::Authorized(auth) = decision else {
            panic!("expected connect-only authorization, got {decision:?}");
        };
        let expected = permissions::client_connect_only_permissions(device_fp, &[host_fp]);
        assert_eq!(auth.permissions, expected);
    }

    #[test]
    fn stale_epoch_signature_valid_member_cap_is_connect_only_renewal_path() {
        let (root, cert, device_fp) = device_setup();
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let host_fp = host.host_fp;
        let cap = member_cap(&host, root_fp, /* cap_epoch */ 1, 2_000_000); // not expired
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
        };
        let mut view = MockView::default();
        view.epochs.insert(host_fp, 5); // helper's high-water is ahead of the cap's epoch
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 0);
        let AuthzDecision::Authorized(auth) = decision else {
            panic!("expected connect-only authorization (renewal path), got {decision:?}");
        };
        let expected = permissions::client_connect_only_permissions(device_fp, &[host_fp]);
        assert_eq!(
            auth.permissions, expected,
            "stale epoch is a renewal path, not a refusal"
        );
    }

    #[test]
    fn stale_epoch_and_revoked_is_refused_not_connect_only() {
        let (root, cert, _dfp) = device_setup();
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let host_fp = host.host_fp;
        let cap = member_cap(&host, root_fp, 1, 2_000_000);
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
        };
        let mut view = MockView::default();
        view.epochs.insert(host_fp, 5);
        view.revoked.insert((host_fp, root_fp));
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::SubjectRevoked)
        );
    }

    #[test]
    fn too_many_capabilities_is_refused_before_any_signature_work() {
        let (root, cert, _dfp) = device_setup();
        let host = test_host([0x11; 32], [0x12; 32]);
        let caps: Vec<Capability> = (0..(MAX_CAPS_PER_CONNECTION + 1))
            .map(|_| member_cap(&host, root.root_fp(), 0, 2_000_000))
            .collect();
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps,
            nats_fp: fp(b"nats-session"),
        };
        let mut view = MockView::default();
        let nkey_calls = Cell::new(0u32);
        let decision = decide_device_connect(
            &presented,
            || {
                nkey_calls.set(nkey_calls.get() + 1);
                true
            },
            1_500,
            &mut view,
            0,
        );
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::TooManyCapabilities)
        );
        assert_eq!(
            nkey_calls.get(),
            0,
            "the nkey signature must never be checked when the cap-count check already refuses"
        );
    }

    #[test]
    fn invite_cap_is_always_connect_only_even_when_fresh() {
        let (root, cert, device_fp) = device_setup();
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let host_fp = host.host_fp;
        let cap = invite_cap(&host, root_fp, 2_000_000);
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
        };
        let mut view = MockView::default();
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 0);
        let AuthzDecision::Authorized(auth) = decision else {
            panic!("expected connect-only authorization, got {decision:?}");
        };
        assert_eq!(
            auth.permissions,
            permissions::client_connect_only_permissions(device_fp, &[host_fp])
        );
    }

    #[test]
    fn valid_member_cap_is_fully_authorized() {
        let (root, cert, device_fp) = device_setup();
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let host_fp = host.host_fp;
        let cap = member_cap(&host, root_fp, 0, 2_000_000);
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
        };
        let mut view = MockView::default();
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 42);
        let AuthzDecision::Authorized(auth) = decision else {
            panic!("expected authorization, got {decision:?}");
        };
        assert_eq!(
            auth.permissions,
            permissions::client_member_permissions(device_fp, &[host_fp])
        );
        assert_eq!(
            auth.limits.max_subscriptions,
            permissions::max_subscriptions(1)
        );
        assert_eq!(auth.session_record.root_fp, root_fp);
        assert_eq!(auth.session_record.host_fps, vec![host_fp]);
    }

    #[test]
    fn mixed_full_and_connect_only_hosts_merge_permissions() {
        let (root, cert, device_fp) = device_setup();
        let root_fp = root.root_fp();
        // Two distinct hosts (distinct root seeds, not just distinct op seeds) — host_fp is now
        // root-derived (A10.30), so two hosts must differ at the root to land in different
        // `host.<host_fp>.>` namespaces.
        let host_a = test_host([0x11; 32], [0x12; 32]);
        let host_b = test_host([0x21; 32], [0x22; 32]);
        let full_host = host_a.host_fp;
        let stale_host = host_b.host_fp;
        let full_cap = member_cap(&host_a, root_fp, 0, 2_000_000);
        let stale_cap = member_cap(&host_b, root_fp, 0, 1_000); // expired -> connect-only
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![full_cap, stale_cap],
            nats_fp: fp(b"nats-session"),
        };
        let mut view = MockView::default();
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 0);
        let AuthzDecision::Authorized(auth) = decision else {
            panic!("expected authorization, got {decision:?}");
        };
        let expected = permissions::client_member_permissions(device_fp, &[full_host]).merge(
            permissions::client_connect_only_permissions(device_fp, &[stale_host]),
        );
        assert_eq!(auth.permissions, expected);
    }

    // ---- decide_host_connect --------------------------------------------------------------

    fn host_setup() -> (RootKey, SigningKey, HostOpKeyCert, Fingerprint) {
        let host_root = RootKey::from_seed([0x51; 32]);
        let op_signing = SigningKey::from_bytes(&[0x52; 32]);
        let op_pk = op_signing.verifying_key();
        let cert = issue_host_op_key_cert(&host_root, &op_pk, fp(b"host-nats"), 1_000, 2_000_000);
        let host_fp = host_root.root_fp();
        (host_root, op_signing, cert, host_fp)
    }

    #[test]
    fn host_with_valid_cert_but_no_admission_record_in_invite_mode_is_refused() {
        let (host_root, _op, cert, _hfp) = host_setup();
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            admission_token: None,
            nats_fp: fp(b"host-session"),
        };
        let mut view = MockView {
            mode: AdmissionMode::Invite,
            ..Default::default()
        };
        let decision = decide_host_connect(&presented, || true, 1_500, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::NoAdmissionRecord)
        );
    }

    #[test]
    fn host_admission_closed_refuses_new_hosts_but_not_existing_ones() {
        let (host_root, _op, cert, host_fp) = host_setup();
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert.clone(),
            admission_token: None,
            nats_fp: fp(b"host-session"),
        };
        let mut view = MockView {
            mode: AdmissionMode::Closed,
            ..Default::default()
        };
        let decision = decide_host_connect(&presented, || true, 1_500, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::AdmissionClosed)
        );

        // Now simulate an already-admitted host: closed mode must not affect it.
        view.records.insert(
            host_fp,
            AdmissionRecord {
                host_fp,
                label: "workshop-nas".to_string(),
                admitted_at: 500,
                quota_profile: "default".to_string(),
            },
        );
        let presented2 = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            admission_token: None,
            nats_fp: fp(b"host-session-2"),
        };
        let decision2 = decide_host_connect(&presented2, || true, 1_500, &mut view, 0);
        assert!(
            decision2.is_authorized(),
            "an already-admitted host must stay admitted under closed mode, got {decision2:?}"
        );
    }

    #[test]
    fn host_admission_open_mode_cert_alone_suffices() {
        let (host_root, _op, cert, _hfp) = host_setup();
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            admission_token: None,
            nats_fp: fp(b"host-session"),
        };
        let mut view = MockView {
            mode: AdmissionMode::Open,
            ..Default::default()
        };
        let decision = decide_host_connect(&presented, || true, 1_500, &mut view, 0);
        assert!(decision.is_authorized());
    }

    #[test]
    fn host_admission_closed_refuses_before_any_signature_work() {
        let (host_root, _op, cert, _hfp) = host_setup();
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            admission_token: None,
            nats_fp: fp(b"host-session"),
        };
        let mut view = MockView {
            mode: AdmissionMode::Closed,
            ..Default::default()
        };
        let nkey_calls = Cell::new(0u32);
        let decision = decide_host_connect(
            &presented,
            || {
                nkey_calls.set(nkey_calls.get() + 1);
                true
            },
            1_500,
            &mut view,
            0,
        );
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::AdmissionClosed)
        );
        assert_eq!(nkey_calls.get(), 0);
    }

    #[test]
    fn host_with_valid_admission_token_is_authorized_and_token_burned_exactly_once() {
        let (host_root, _op, cert, host_fp) = host_setup();
        let operator = SigningKey::from_bytes(&[0x61; 32]);
        let token = issue_admission_token(
            &operator,
            vec![0xCC; 8],
            2_000_000,
            "workshop-nas".to_string(),
            "gold".to_string(),
        );
        let mut view = MockView {
            mode: AdmissionMode::Invite,
            operator_pk: Some(operator.verifying_key()),
            ..Default::default()
        };

        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert.clone(),
            admission_token: Some(token.clone()),
            nats_fp: fp(b"host-session"),
        };
        let decision = decide_host_connect(&presented, || true, 1_500, &mut view, 0);
        let AuthzDecision::Authorized(auth) = decision else {
            panic!("expected authorization, got {decision:?}");
        };
        assert_eq!(auth.session_record.quota_profile, "gold");
        assert_eq!(view.burn_calls, 1);

        // Idempotent replay: same nonce, same host, presented again (e.g. a retried CONNECT
        // after a lost reply). Must not burn a second time and must yield the same record.
        let presented_again = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            admission_token: Some(token),
            nats_fp: fp(b"host-session-retry"),
        };
        let decision2 = decide_host_connect(&presented_again, || true, 1_500, &mut view, 0);
        assert!(decision2.is_authorized());
        assert_eq!(
            view.burn_calls, 1,
            "re-presenting the same nonce must not burn it a second time"
        );
        let _ = host_fp;
    }

    #[test]
    fn burn_admission_token_rejects_a_different_host_reusing_the_same_nonce() {
        let mut view = MockView::default();
        let nonce = vec![0xDD; 8];
        let host_a = fp(b"host-a");
        let host_b = fp(b"host-b");
        let first = view.burn_admission_token(
            host_a,
            nonce.clone(),
            "label".to_string(),
            "default".to_string(),
            1_000,
        );
        assert!(first.is_some());
        assert_eq!(view.burn_calls, 1);

        let replay_same_host = view.burn_admission_token(
            host_a,
            nonce.clone(),
            "label".to_string(),
            "default".to_string(),
            1_000,
        );
        assert_eq!(
            replay_same_host, first,
            "same host replay returns the stored record"
        );
        assert_eq!(view.burn_calls, 1, "must not burn twice");

        let replay_other_host = view.burn_admission_token(
            host_b,
            nonce,
            "label".to_string(),
            "default".to_string(),
            1_000,
        );
        assert_eq!(
            replay_other_host, None,
            "a different host reusing the same nonce must be rejected"
        );
        assert_eq!(view.burn_calls, 1);
    }

    #[test]
    fn host_cert_expired_is_refused() {
        let (host_root, _op, cert, _hfp) = host_setup();
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            admission_token: None,
            nats_fp: fp(b"host-session"),
        };
        let mut view = MockView::default();
        let decision = decide_host_connect(&presented, || true, 3_000_000, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::HostCertificateExpired)
        );
    }

    // ---- uniform refusal --------------------------------------------------------------------

    #[test]
    fn wire_message_is_uniform_across_every_refusal_reason() {
        let reasons = [
            RefusalReason::TooManyCapabilities,
            RefusalReason::NoCapabilitiesPresented,
            RefusalReason::CapabilitySubjectMismatch,
            RefusalReason::SubjectRevoked,
            RefusalReason::BadNkeySignature,
            RefusalReason::AdmissionClosed,
            RefusalReason::AdmissionTokenAlreadyUsed,
        ];
        for reason in reasons {
            assert_eq!(
                AuthzDecision::Refused(reason).wire_message(),
                UNIFORM_REFUSAL_MESSAGE
            );
        }
    }
}
