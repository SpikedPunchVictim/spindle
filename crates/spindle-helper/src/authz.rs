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
    AdmissionToken, CapKind, Capability, DeviceCertificate, HostOpKeyCert, HostSessionAttestation,
    SessionAttestation,
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
    /// §A4 step 2 (td-0bcab4). A **single** reason covers every way
    /// [`spindle_core::artifacts::verify_session_attestation`] (or the cheap pre-check in
    /// [`decide_device_connect`]) can fail: a mismatched `nats_fp`, a `ts` outside the skew
    /// window, or a bad `sig_device`. This mirrors [`RefusalReason::BadDeviceCertificate`] and
    /// [`RefusalReason::BadHostSignature`] above/below, and — since v0.9.31/td-583db5 —
    /// [`RefusalReason::BadHostSessionAttestation`] too: the host path is now structurally
    /// symmetric with this one, a cheap pre-check and an authoritative verification that both test
    /// the *same* fact (does this session_attest bind to this session), collapsed to a single
    /// reason for the identical rationale given there. Collapsing either pair to one reason isn't
    /// losing information a caller needs; it's declining to hand a would-be attacker a way to
    /// distinguish "wrong session key" from "bad signature" from a refused connection, when every
    /// `Refused` variant collapses to the same [`UNIFORM_REFUSAL_MESSAGE`] on the wire anyway (§A5
    /// uniform silent drops) — the distinction would only ever be observable through timing or
    /// side channels this module's ordering discipline already exists to close off.
    #[error("device session attestation is missing, malformed, or names a different session key")]
    BadSessionAttestation,
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
    /// v0.9.31 (td-583db5). A **single** reason covers every way
    /// [`spindle_core::artifacts::verify_host_session_attestation`] (or the cheap pre-check in
    /// [`decide_host_connect`]) can fail: a mismatched `nats_fp`, a `ts` outside the skew window,
    /// or a bad `sig_op`. This mirrors [`RefusalReason::BadSessionAttestation`] above — the two
    /// paths are symmetric: both call sites (cheap pre-check and authoritative verification) test
    /// the *same* fact — does this session_attest bind to this session — so collapsing them to one
    /// reason isn't losing information a caller needs; it's declining to hand a would-be attacker
    /// a way to distinguish "wrong session key" from "bad signature" from a refused connection,
    /// when every `Refused` variant collapses to the same [`UNIFORM_REFUSAL_MESSAGE`] on the wire
    /// anyway (§A5 uniform silent drops).
    #[error("host session attestation is missing, malformed, or names a different session key")]
    BadHostSessionAttestation,
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
    // methods the trait needed all along for `helper.turn.get.<nfp>` (this slice) and `registry.
    // revoke.<hfp>` (a still-unwired later slice) to have anything to call.
    // ============================================================================================

    /// Writes (or overwrites) the session record for `record.nats_fp` (DESIGN.md §A5). Upsert
    /// semantics: a later write for the same `nats_fp` (e.g. a reconnect that reuses the same
    /// session nkey, or a renewed `exp`) replaces the stored record rather than erroring or
    /// requiring a separate update call.
    fn put_session_record(&mut self, record: SessionRecord);

    /// Looks up the session record for `nats_fp`. A record whose `exp` is at or before `now` is
    /// treated as absent (DESIGN.md §A5 "cleaned up on DISCONNECT/expiry" — this trait enforces
    /// only the expiry half via an on-read filter; eager DISCONNECT-triggered deletion is
    /// [`Self::delete_session_record`], wired to `$SYS.ACCOUNT.*.DISCONNECT` events by
    /// `src/bin/helper.rs`'s presence bridging (DESIGN.md §A3/§A6, `presence.rs`)).
    fn session_record(&mut self, nats_fp: &Fingerprint, now: u64) -> Option<SessionRecord>;

    /// Eagerly deletes the session record for `nats_fp`, if any (DESIGN.md §A5: "cleaned up on
    /// DISCONNECT/expiry" — the DISCONNECT half; [`Self::session_record`]'s `now`-filter already
    /// covers the expiry half). Called by `src/bin/helper.rs` on every `$SYS.ACCOUNT.*.DISCONNECT`
    /// event, for both device and host connections alike — a session record exists for either
    /// kind (see [`crate::session::SessionRecord`]'s doc comment), and this is a general-purpose
    /// cleanup, not a presence-specific one (the presence connection map's own bookkeeping,
    /// [`crate::presence::ConnectionMap`], is a separate concern that only tracks *registered
    /// host* users). A no-op if no record exists for `nats_fp` — callers don't need to check
    /// first.
    fn delete_session_record(&mut self, nats_fp: &Fingerprint);

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
    /// "revocation epochs ... revoked-subject sets alongside"). Wired: `src/bin/helper.rs`
    /// subscribes to `registry.revoke.*` and hands each message to
    /// `revoke::ingest_revocation`, which calls this method (`crates/spindle-helper/src/
    /// revoke.rs:170`) once it has checked the subject token's `host_fp` against the record's own
    /// — so the store operation and its SQL semantics are exercised by that real entry point, not
    /// only by the store-contract tests the read side above (`revocation_epoch`/`is_revoked`)
    /// proves itself against.
    fn record_revocation(
        &mut self,
        host_fp: Fingerprint,
        epoch: u64,
        revoked_subjects: &[Fingerprint],
    );

    /// Best-effort cleanup of session records whose `exp` has already passed. No-op by default
    /// (the on-read `exp` filter in [`session_record`](HelperView::session_record) already hides
    /// expired rows from callers — this is purely about bounding storage growth for a
    /// long-running process, not correctness). [`crate::pg_store::PgStore`] overrides this with a
    /// real `DELETE`; [`crate::memory_store::InMemoryHelperView`] overrides it to bound its
    /// `HashMap`'s growth too.
    fn purge_expired_sessions(&mut self, _now: u64) {}

    // ============================================================================================
    // Added for the kick relay's prerequisite (DESIGN.md §A3/§A4, DESIGN.md v0.9.18 amendment to
    // §A5's session-record schema). Not the kick relay itself — no `$SYS.REQ.SERVER.*.KICK` wiring
    // exists yet, and none is added here; this is only the lookup a later slice's kick relay needs
    // to have something to call.
    // ============================================================================================

    /// The live session records that a revocation naming `subject` must reach (DESIGN.md §A4: "a
    /// revocation names `root_fp | device_fp`"). Matches every stored session record whose
    /// `root_fp` equals `subject` **or** whose `device_fp` equals `subject` — both sides of the
    /// OR, not either-or: revoking a person's `root_fp` must reach every one of their live device
    /// sessions, while revoking a single `device_fp` must reach only that device's session, never
    /// a sibling session that merely shares the same `root_fp`. Expired records (`exp <= now`) are
    /// excluded, exactly like [`Self::session_record`]'s own on-read expiry filter.
    ///
    /// **No default implementation** — deliberately, unlike [`Self::purge_expired_sessions`]
    /// above, whose no-op default is safe only because the on-read `exp` filter elsewhere still
    /// enforces correctness. There is no equivalent backstop here: a default that silently
    /// returned an empty `Vec` would make "no live sessions matched" indistinguishable from
    /// "nobody implemented this," and for a revocation lookup that difference is exactly the
    /// false-green class this crate treats as severity zero — a revocation that appears to succeed
    /// while cutting nobody off. Every [`HelperView`] implementor, including
    /// `spikes/s1-callout/src/bin/responder.rs`'s `InMemoryHelperView`, must provide its own.
    fn sessions_for_subject(&mut self, subject: &Fingerprint, now: u64) -> Vec<SessionRecord>;
}

// ================================================================================================
// Device connections
// ================================================================================================

/// What a device presents on CONNECT (DESIGN.md §A4 step 1), already decoded from the wire.
/// `root_pk` is the identity root's public key carried alongside the device certificate chain —
/// [`spindle_proto::artifacts::DeviceCertificate`] itself carries no `root_pk` field (only
/// `device_fp`/`alg_id`/`sign_pk`/`agree_pk`/`ts`/`exp`/`sig_root` — `nats_fp` was removed from it
/// in v0.9.29, td-0bcab4; see [`SessionAttestation`] below), so the verifier needs `root_pk`
/// presented out of band, the same way `HostOpKeyCert` needs `host_root_pk` (see
/// [`HostConnectPresented`]).
pub struct DeviceConnectPresented {
    pub root_pk: VerifyingKey,
    pub device_cert: DeviceCertificate,
    /// The capabilities presented for this session: one or more `member` caps, or a single
    /// `invite` cap (DESIGN.md §A4).
    pub caps: Vec<Capability>,
    /// The session nkey's fingerprint, for the session record.
    pub nats_fp: Fingerprint,
    /// §A4 step 2 (added v0.9.29, td-0bcab4): `sig_device(nats_fp, ts)`, proving the device's own
    /// **identity** key — not just whichever nkey happens to be presenting — authorized this
    /// session. Before this artifact existed, `{root_pk, device_cert, caps}` was a pure bearer
    /// bundle: `verify_nkey_sig` only proves possession of the presenting nkey, and nothing
    /// anywhere compared a device-bound fingerprint against it, so anyone holding a copy of the
    /// bundle could connect as that member from any nkey. See [`decide_device_connect`]'s two
    /// check sites for how this is enforced.
    pub session_attest: SessionAttestation,
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

    // A cheap early rejection, not the authoritative check — that's check (ii) below, after
    // `verify_device_certificate` succeeds. This is a byte comparison against the caller-supplied
    // `nats_fp` (derived from whichever nkey is presenting, before any crypto has run), so a
    // stolen `{root_pk, device_cert, caps, session_attest}` bundle replayed from an attacker's own
    // nkey — exactly the attack td-0bcab4 closes — gets refused here rather than costing the
    // callout two Ed25519 verifications (`verify_nkey_sig` plus `verify_session_attestation`)
    // first (DESIGN.md §A12 #24; see the module docs' "Ordering" section and this file's
    // `Cell`-counter ordering tests). It is deliberately redundant with check (ii): a
    // self-consistent forged bundle could in principle carry a `session_attest.nats_fp` that
    // matches `presented.nats_fp` while everything else is garbage, so this alone proves nothing
    // — only that the cheap case can be dismissed without paying for crypto.
    if !presented.nats_fp.matches(&presented.session_attest.nats_fp) {
        return AuthzDecision::Refused(RefusalReason::BadSessionAttestation);
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

    // (ii) The authoritative session-binding check (§A4 step 2, td-0bcab4) — and it must sit
    // exactly here, after `verify_device_certificate` has succeeded and before any capability is
    // trusted. `presented.device_cert.sign_pk` is only trustworthy once the certificate carrying
    // it has been verified against the pinned root above: verifying `session_attest` against an
    // *unverified* certificate's `sign_pk` would let an attacker present a self-made, unsigned (or
    // wrongly-signed) certificate naming their own key and satisfy the attestation check with a
    // signature they themselves produced — checking a signature against a key the attacker chose
    // proves nothing about the device this connection claims to be. The cheap comparison in (i)
    // above is not a substitute for this: it only ever inspects field bytes, never a signature.
    let Ok(sign_pk_bytes) = <[u8; 32]>::try_from(presented.device_cert.sign_pk.as_slice()) else {
        return AuthzDecision::Refused(RefusalReason::BadSessionAttestation);
    };
    let Some(device_sign_pk) = spindle_core::checked_verifying_key(&sign_pk_bytes) else {
        return AuthzDecision::Refused(RefusalReason::BadSessionAttestation);
    };
    if spindle_core::artifacts::verify_session_attestation(
        &presented.session_attest,
        &device_sign_pk,
        &presented.nats_fp,
        now,
    )
    .is_err()
    {
        return AuthzDecision::Refused(RefusalReason::BadSessionAttestation);
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
        (false, true) => {
            permissions::client_member_permissions(device_fp, presented.nats_fp, &full_hosts)
        }
        (true, false) => {
            permissions::client_connect_only_permissions(device_fp, &connect_only_hosts)
        }
        (false, false) => {
            permissions::client_member_permissions(device_fp, presented.nats_fp, &full_hosts).merge(
                permissions::client_connect_only_permissions(device_fp, &connect_only_hosts),
            )
        }
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
            // DESIGN.md §A5, amended v0.9.18: the device fingerprint, so a device-scoped
            // revocation can resolve back to this live session (see session.rs's
            // SessionRecord::device_fp doc comment).
            Some(device_fp),
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
    /// v0.9.31 (td-583db5): `sig_op(nats_fp, ts)`, proving the host's own **operating** key — not
    /// just whichever nkey happens to be presenting — authorized this session. `HostOpKeyCert`
    /// used to carry its own `nats_fp` field for this purpose, but that field was enforced by
    /// exactly one manual comparison at one call site (the td-0bcab4 defect class); td-583db5
    /// domain-separates the issuance chain (`HostOpKeyCert`, no `nats_fp`) from this per-connect
    /// binding, mirroring [`DeviceConnectPresented::session_attest`]. See
    /// [`decide_host_connect`]'s two check sites for how this is enforced.
    pub session_attest: HostSessionAttestation,
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

    // A cheap early rejection, not the authoritative check — that's the authoritative check below,
    // after `verify_host_op_key_cert` succeeds. This is a byte comparison against the
    // caller-supplied `nats_fp` (derived from whichever nkey is presenting, before any crypto has
    // run), so a stolen `{host_root_pk, host_op_cert, session_attest}` bundle replayed from an
    // attacker's own nkey gets refused here rather than costing the callout two Ed25519
    // verifications (`verify_nkey_sig` plus `verify_host_session_attestation`) first (DESIGN.md
    // §A12 #24; see the module docs' "Ordering" section and this file's `Cell`-counter ordering
    // tests). It is deliberately redundant with the authoritative check: a self-consistent forged
    // bundle could in principle carry a `session_attest.nats_fp` that matches `presented.nats_fp`
    // while everything else is garbage, so this alone proves nothing — only that the cheap case
    // can be dismissed without paying for crypto.
    if !presented.nats_fp.matches(&presented.session_attest.nats_fp) {
        return AuthzDecision::Refused(RefusalReason::BadHostSessionAttestation);
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

    // The authoritative session-binding check (v0.9.31, td-583db5) — and it must sit exactly
    // here, after `verify_host_op_key_cert` has succeeded and before any admission/quota work is
    // trusted. `presented.host_op_cert.host_op_pk` is only trustworthy once the certificate
    // carrying it has been verified against the pinned host root above: verifying
    // `session_attest` against an *unverified* cert's `host_op_pk` would let an attacker present a
    // self-made cert naming their own key and satisfy the attestation with a signature they
    // produced themselves — checking a signature against a key the attacker chose proves nothing.
    // The cheap comparison above is not a substitute for this: it only ever inspects field bytes,
    // never a signature.
    let Ok(host_op_pk_bytes) = <[u8; 32]>::try_from(presented.host_op_cert.host_op_pk.as_slice())
    else {
        return AuthzDecision::Refused(RefusalReason::BadHostSessionAttestation);
    };
    let Some(host_op_pk) = spindle_core::checked_verifying_key(&host_op_pk_bytes) else {
        return AuthzDecision::Refused(RefusalReason::BadHostSessionAttestation);
    };
    if spindle_core::artifacts::verify_host_session_attestation(
        &presented.session_attest,
        &host_op_pk,
        &presented.nats_fp,
        now,
    )
    .is_err()
    {
        return AuthzDecision::Refused(RefusalReason::BadHostSessionAttestation);
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
            // A host connection has no client device fingerprint (see session.rs's
            // SessionRecord::device_fp doc comment) — None is the honest value, not a
            // placeholder.
            None,
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
        issue_host_session_attestation, issue_session_attestation,
    };
    use spindle_core::identity::{DeviceKey, RootKey};
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

        fn delete_session_record(&mut self, nats_fp: &Fingerprint) {
            self.sessions.remove(nats_fp);
        }

        fn sessions_for_subject(&mut self, subject: &Fingerprint, now: u64) -> Vec<SessionRecord> {
            self.sessions
                .values()
                .filter(|r| r.exp > now && (r.root_fp == *subject || r.device_fp == Some(*subject)))
                .cloned()
                .collect()
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
        let op_cert = issue_host_op_key_cert(&root, &op_signer.verifying_key(), 0, u64::MAX);
        let host_fp = root.root_fp();
        TestHost {
            root,
            op_signer,
            op_cert,
            host_fp,
        }
    }

    /// `session_fp` is the `nats_fp` the returned [`SessionAttestation`] is issued for — callers
    /// must present that same fingerprint in `DeviceConnectPresented.nats_fp` (td-0bcab4:
    /// `decide_device_connect` now enforces that the two match). Mirrors `host_setup` below, and
    /// exists for the identical reason: this helper previously hardcoded a `nats_fp` (baked into
    /// the now-removed `DeviceCertificate.nats_fp` field) that no caller ever matched — the exact
    /// trap `host_setup`'s own doc comment / commit 7903370 flags on the host side. Every call
    /// site below passes `fp(b"nats-session")`, the same value it puts in
    /// `DeviceConnectPresented.nats_fp`, so the valid-path tests genuinely exercise a *matching*
    /// binding, not merely a present-but-unchecked field.
    fn device_setup(
        session_fp: Fingerprint,
    ) -> (RootKey, DeviceCertificate, SessionAttestation, Fingerprint) {
        let root = RootKey::from_seed([0x01; 32]);
        // A10.34: `issue_device_certificate` derives device_fp from real device keys now, so a
        // certificate that must pass its own binding check needs a genuine `DeviceKey` rather
        // than a fabricated fingerprint.
        let device = DeviceKey::from_seeds([0x02; 32], [0x03; 32]);
        let cert = issue_device_certificate(
            &root,
            device.alg_id(),
            &device.sign_public_key(),
            &device.agree_public_key(),
            1_000,
            2_000_000,
        );
        // ts=1_500 matches every caller's `now` argument to `decide_device_connect` below — the
        // attestation's own clock-skew window (±120s, `SESSION_ATTESTATION_CLOCK_SKEW_SECS`) is a
        // property of `verify_session_attestation` itself (already covered by that function's own
        // unit tests in spindle-core), not something this file's tests need to re-prove.
        let session_attest = issue_session_attestation(&device, session_fp, 1_500);
        (root, cert, session_attest, device.device_fp())
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
        let (_root, cert, attest, _dfp) = device_setup(fp(b"nats-session"));
        let root_pk = RootKey::from_seed([0x01; 32]).public_key();
        let presented = DeviceConnectPresented {
            root_pk,
            device_cert: cert,
            caps: vec![],
            nats_fp: fp(b"nats-session"),
            session_attest: attest,
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
        let (root, cert, attest, _dfp) = device_setup(fp(b"nats-session"));
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let mut cap = member_cap(&host, root_fp, 0, 1_000); // already expired at now=1_500
        cap.sig[0] ^= 0xff; // forged
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
            session_attest: attest,
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
        let (root, cert, attest, _dfp) = device_setup(fp(b"nats-session"));
        let host = test_host([0x11; 32], [0x12; 32]);
        let cap = member_cap(&host, fp(b"someone-else"), 0, 2_000_000);
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
            session_attest: attest,
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
        let (root, cert, attest, _dfp) = device_setup(fp(b"nats-session"));
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
            session_attest: attest,
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
        let (root, cert, attest, device_fp) = device_setup(fp(b"nats-session"));
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let host_fp = host.host_fp;
        let cap = member_cap(&host, root_fp, 0, 1_000); // expired at now=1_500, sig valid
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
            session_attest: attest,
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
        let (root, cert, attest, device_fp) = device_setup(fp(b"nats-session"));
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let host_fp = host.host_fp;
        let cap = member_cap(&host, root_fp, /* cap_epoch */ 1, 2_000_000); // not expired
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
            session_attest: attest,
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
        let (root, cert, attest, _dfp) = device_setup(fp(b"nats-session"));
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let host_fp = host.host_fp;
        let cap = member_cap(&host, root_fp, 1, 2_000_000);
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
            session_attest: attest,
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
        let (root, cert, attest, _dfp) = device_setup(fp(b"nats-session"));
        let host = test_host([0x11; 32], [0x12; 32]);
        let caps: Vec<Capability> = (0..(MAX_CAPS_PER_CONNECTION + 1))
            .map(|_| member_cap(&host, root.root_fp(), 0, 2_000_000))
            .collect();
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps,
            nats_fp: fp(b"nats-session"),
            session_attest: attest,
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
        let (root, cert, attest, device_fp) = device_setup(fp(b"nats-session"));
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let host_fp = host.host_fp;
        let cap = invite_cap(&host, root_fp, 2_000_000);
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: fp(b"nats-session"),
            session_attest: attest,
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
        let nats_fp = fp(b"nats-session");
        let (root, cert, attest, device_fp) = device_setup(nats_fp);
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let host_fp = host.host_fp;
        let cap = member_cap(&host, root_fp, 0, 2_000_000);
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp,
            session_attest: attest,
        };
        let mut view = MockView::default();
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 42);
        let AuthzDecision::Authorized(auth) = decision else {
            panic!("expected authorization, got {decision:?}");
        };
        assert_eq!(
            auth.permissions,
            permissions::client_member_permissions(device_fp, nats_fp, &[host_fp])
        );
        assert_eq!(
            auth.limits.max_subscriptions,
            permissions::max_subscriptions(1)
        );
        assert_eq!(auth.session_record.root_fp, root_fp);
        assert_eq!(auth.session_record.host_fps, vec![host_fp]);
        assert_eq!(
            auth.session_record.device_fp,
            Some(device_fp),
            "decide_device_connect must populate device_fp in the session record it returns"
        );
    }

    #[test]
    fn mixed_full_and_connect_only_hosts_merge_permissions() {
        let nats_fp = fp(b"nats-session");
        let (root, cert, attest, device_fp) = device_setup(nats_fp);
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
            nats_fp,
            session_attest: attest,
        };
        let mut view = MockView::default();
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 0);
        let AuthzDecision::Authorized(auth) = decision else {
            panic!("expected authorization, got {decision:?}");
        };
        let expected =
            permissions::client_member_permissions(device_fp, nats_fp, &[full_host]).merge(
                permissions::client_connect_only_permissions(device_fp, &[stale_host]),
            );
        assert_eq!(auth.permissions, expected);
    }

    /// td-0bcab4 §A4 step 2, unit-level twin of the live repro this fix closes: before this
    /// change, `{root_pk, device_cert, caps}` was a pure bearer bundle — a copy of it authorized a
    /// connection from *any* nkey, not just the one it was issued for. Here every artifact in the
    /// bundle is otherwise genuinely valid (a real cert, a real member cap, a real
    /// `SessionAttestation`) — the *only* thing wrong is that the attestation names a different
    /// session key than the one actually connecting. That must still be refused.
    #[test]
    fn device_bundle_presented_from_a_different_nkey_is_refused() {
        let issued_for = fp(b"nats-session");
        let (root, cert, attest, _dfp) = device_setup(issued_for);
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let cap = member_cap(&host, root_fp, 0, 2_000_000);
        let presented_fp = fp(b"nats-session-attacker");
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: presented_fp,
            session_attest: attest,
        };
        let mut view = MockView::default();
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::BadSessionAttestation)
        );
    }

    /// This is the test that would fail if someone later "optimized away" the Ed25519 verification
    /// in check (ii) and kept only the cheap `nats_fp` comparison from check (i): the attestation
    /// here *does* name the connecting session key, so the cheap check alone would wave it
    /// through. The signature, however, was produced by a different device's identity key than the
    /// one `device_cert` (and its `sign_pk`) actually names — so only the authoritative check in
    /// `decide_device_connect`, which verifies `sig_device` under the certificate's own (now
    /// cert-verified) `sign_pk`, can catch this.
    #[test]
    fn device_session_attestation_with_wrong_device_signature_is_refused() {
        let nats_fp = fp(b"nats-session");
        let (root, cert, _genuine_attest, _dfp) = device_setup(nats_fp);
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let cap = member_cap(&host, root_fp, 0, 2_000_000);
        // A different device's identity key signs an attestation naming the *correct* nats_fp —
        // the binding field matches, but the signature does not belong to the device the
        // certificate names.
        let attacker_device = DeviceKey::from_seeds([0x88; 32], [0x89; 32]);
        // ts=1_500 matches `now` below so this test fails on the signature check specifically,
        // not incidentally on clock skew.
        let forged_attest = issue_session_attestation(&attacker_device, nats_fp, 1_500);
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp,
            session_attest: forged_attest,
        };
        let mut view = MockView::default();
        let decision = decide_device_connect(&presented, || true, 1_500, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::BadSessionAttestation)
        );
    }

    /// Mirrors `host_op_cert_session_mismatch_is_refused_before_any_signature_work` — the cheap
    /// pre-check (i) in `decide_device_connect` must refuse a mismatched `session_attest.nats_fp`
    /// without ever calling `verify_nkey_sig`, exactly like the host half's ordering test proves
    /// for `BadHostSessionAttestation` (DESIGN.md §A12 #24; see the module docs' "Ordering"
    /// section).
    #[test]
    fn device_session_mismatch_is_refused_before_any_signature_work() {
        let issued_for = fp(b"nats-session");
        let (root, cert, attest, _dfp) = device_setup(issued_for);
        let root_fp = root.root_fp();
        let host = test_host([0x11; 32], [0x12; 32]);
        let cap = member_cap(&host, root_fp, 0, 2_000_000);
        let presented_fp = fp(b"nats-session-attacker");
        let presented = DeviceConnectPresented {
            root_pk: root.public_key(),
            device_cert: cert,
            caps: vec![cap],
            nats_fp: presented_fp,
            session_attest: attest,
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
            AuthzDecision::Refused(RefusalReason::BadSessionAttestation)
        );
        assert_eq!(
            nkey_calls.get(),
            0,
            "the nkey signature must never be checked when the session-attestation mismatch \
             check already refuses"
        );
    }

    // ---- decide_host_connect --------------------------------------------------------------

    /// `session_fp` is the `nats_fp` the returned [`HostSessionAttestation`] is issued for —
    /// callers must present that same fingerprint in `HostConnectPresented.nats_fp` (v0.9.31,
    /// td-583db5: `decide_host_connect` enforces that the two match). Mirrors `device_setup`
    /// above, and exists for the identical reason: `HostOpKeyCert` no longer carries a `nats_fp`
    /// of its own to (mis)match against — the binding now lives entirely in the attestation this
    /// helper builds separately.
    fn host_setup(
        session_fp: Fingerprint,
    ) -> (
        RootKey,
        SigningKey,
        HostOpKeyCert,
        HostSessionAttestation,
        Fingerprint,
    ) {
        let host_root = RootKey::from_seed([0x51; 32]);
        let op_signing = SigningKey::from_bytes(&[0x52; 32]);
        let op_pk = op_signing.verifying_key();
        let cert = issue_host_op_key_cert(&host_root, &op_pk, 1_000, 2_000_000);
        // ts=1_500 matches every caller's `now` argument to `decide_host_connect` below — the
        // attestation's own clock-skew window (±120s, `HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS`)
        // is a property of `verify_host_session_attestation` itself (already covered by that
        // function's own unit tests in spindle-core), not something this file's tests need to
        // re-prove.
        let session_attest = issue_host_session_attestation(&op_signing, session_fp, 1_500);
        let host_fp = host_root.root_fp();
        (host_root, op_signing, cert, session_attest, host_fp)
    }

    #[test]
    fn host_with_valid_cert_but_no_admission_record_in_invite_mode_is_refused() {
        let session_fp = fp(b"host-session");
        let (host_root, _op, cert, attest, _hfp) = host_setup(session_fp);
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            session_attest: attest,
            admission_token: None,
            nats_fp: session_fp,
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
        let session_fp = fp(b"host-session");
        let (host_root, _op, cert, attest, host_fp) = host_setup(session_fp);
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert.clone(),
            session_attest: attest.clone(),
            admission_token: None,
            nats_fp: session_fp,
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

        // Now simulate an already-admitted host: closed mode must not affect it. Same cert, same
        // session — this test is about admission-mode behavior, not session rebinding.
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
            session_attest: attest,
            admission_token: None,
            nats_fp: session_fp,
        };
        let decision2 = decide_host_connect(&presented2, || true, 1_500, &mut view, 0);
        assert!(
            decision2.is_authorized(),
            "an already-admitted host must stay admitted under closed mode, got {decision2:?}"
        );
    }

    #[test]
    fn host_admission_open_mode_cert_alone_suffices() {
        let session_fp = fp(b"host-session");
        let (host_root, _op, cert, attest, _hfp) = host_setup(session_fp);
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            session_attest: attest,
            admission_token: None,
            nats_fp: session_fp,
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
        let session_fp = fp(b"host-session");
        let (host_root, _op, cert, attest, _hfp) = host_setup(session_fp);
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            session_attest: attest,
            admission_token: None,
            nats_fp: session_fp,
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
        let session_fp = fp(b"host-session");
        let (host_root, _op, cert, attest, host_fp) = host_setup(session_fp);
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
            session_attest: attest.clone(),
            admission_token: Some(token.clone()),
            nats_fp: session_fp,
        };
        let decision = decide_host_connect(&presented, || true, 1_500, &mut view, 0);
        let AuthzDecision::Authorized(auth) = decision else {
            panic!("expected authorization, got {decision:?}");
        };
        assert_eq!(auth.session_record.quota_profile, "gold");
        assert_eq!(view.burn_calls, 1);
        assert_eq!(
            auth.session_record.device_fp, None,
            "a host connection has no client device fingerprint — decide_host_connect must leave \
             device_fp None, not invent a placeholder value"
        );

        // Idempotent replay: same nonce, same host, same session, presented again (e.g. a
        // retried CONNECT after a lost reply — the cert is bound to `session_fp`, so the retry
        // must present that same fingerprint too). Must not burn a second time and must yield
        // the same record.
        let presented_again = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            session_attest: attest,
            admission_token: Some(token),
            nats_fp: session_fp,
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
        let session_fp = fp(b"host-session");
        let (host_root, _op, cert, attest, _hfp) = host_setup(session_fp);
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            session_attest: attest,
            admission_token: None,
            nats_fp: session_fp,
        };
        let mut view = MockView::default();
        let decision = decide_host_connect(&presented, || true, 3_000_000, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::HostCertificateExpired)
        );
    }

    /// v0.9.31/td-583db5, the host-side twin of
    /// `device_bundle_presented_from_a_different_nkey_is_refused`:
    /// `HostSessionAttestation.nats_fp` is now the entire mechanism binding a root-signed host
    /// cert's operating key to one NATS session (DESIGN.md v0.9.31, §A4 step 3).
    /// An attestation issued for one session fingerprint, presented alongside a *different*
    /// session's fingerprint, must be refused — even for an already-admitted host, so the refusal
    /// cannot be attributed to admission rather than the session binding. (Previously this was
    /// `HostOpKeyCert`'s own `nats_fp` field and `RefusalReason::HostCertificateSessionMismatch`;
    /// td-583db5 moved the binding into `HostSessionAttestation` and this refusal into
    /// `RefusalReason::BadHostSessionAttestation` — see that variant's doc comment.)
    #[test]
    fn host_session_attestation_for_a_different_nkey_is_refused() {
        let issued_for = fp(b"host-session");
        let (host_root, _op, cert, attest, host_fp) = host_setup(issued_for);
        let presented_fp = fp(b"host-session-attacker");
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            session_attest: attest,
            admission_token: None,
            nats_fp: presented_fp,
        };
        let mut view = MockView::default();
        view.records.insert(
            host_fp,
            AdmissionRecord {
                host_fp,
                label: "workshop-nas".to_string(),
                admitted_at: 500,
                quota_profile: "default".to_string(),
            },
        );
        let decision = decide_host_connect(&presented, || true, 1_500, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::BadHostSessionAttestation)
        );
    }

    /// Mirrors `device_session_mismatch_is_refused_before_any_signature_work` — the cheap
    /// pre-check in `decide_host_connect` must refuse a mismatched `session_attest.nats_fp`
    /// without ever calling `verify_nkey_sig`, for `BadHostSessionAttestation` (DESIGN.md §A12
    /// #24; see the module docs' "Ordering" section).
    #[test]
    fn host_op_cert_session_mismatch_is_refused_before_any_signature_work() {
        let issued_for = fp(b"host-session");
        let (host_root, _op, cert, attest, host_fp) = host_setup(issued_for);
        let presented_fp = fp(b"host-session-attacker");
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            session_attest: attest,
            admission_token: None,
            nats_fp: presented_fp,
        };
        let mut view = MockView::default();
        view.records.insert(
            host_fp,
            AdmissionRecord {
                host_fp,
                label: "workshop-nas".to_string(),
                admitted_at: 500,
                quota_profile: "default".to_string(),
            },
        );
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
            AuthzDecision::Refused(RefusalReason::BadHostSessionAttestation)
        );
        assert_eq!(
            nkey_calls.get(),
            0,
            "the nkey signature must never be checked when the session-mismatch check already \
             refuses"
        );
    }

    /// This is the test that would fail if someone later "optimized away" the Ed25519 verification
    /// in the authoritative check and kept only the cheap `nats_fp` comparison above it: the
    /// attestation here *does* name the connecting session key, so the cheap check alone would
    /// wave it through. The signature, however, was produced by a different operating key than the
    /// one `host_op_cert` (and its `host_op_pk`) actually names — so only the authoritative check
    /// in `decide_host_connect`, which verifies `sig_op` under the certificate's own (now
    /// cert-verified) `host_op_pk`, can catch this. Mirrors
    /// `device_session_attestation_with_wrong_device_signature_is_refused`.
    #[test]
    fn host_session_attestation_with_wrong_op_key_signature_is_refused() {
        let session_fp = fp(b"host-session");
        let (host_root, _op, cert, _genuine_attest, host_fp) = host_setup(session_fp);
        // A different operating key signs an attestation naming the *correct* nats_fp — the
        // binding field matches, but the signature does not belong to the key the certificate
        // names.
        let attacker_op = SigningKey::from_bytes(&[0x99; 32]);
        // ts=1_500 matches `now` below so this test fails on the signature check specifically,
        // not incidentally on clock skew.
        let forged_attest = issue_host_session_attestation(&attacker_op, session_fp, 1_500);
        let presented = HostConnectPresented {
            host_root_pk: host_root.public_key(),
            host_op_cert: cert,
            session_attest: forged_attest,
            admission_token: None,
            nats_fp: session_fp,
        };
        let mut view = MockView::default();
        view.records.insert(
            host_fp,
            AdmissionRecord {
                host_fp,
                label: "workshop-nas".to_string(),
                admitted_at: 500,
                quota_profile: "default".to_string(),
            },
        );
        let decision = decide_host_connect(&presented, || true, 1_500, &mut view, 0);
        assert_eq!(
            decision,
            AuthzDecision::Refused(RefusalReason::BadHostSessionAttestation)
        );
    }

    // ---- uniform refusal --------------------------------------------------------------------

    #[test]
    fn wire_message_is_uniform_across_every_refusal_reason() {
        // This test used to hand-enumerate a subset of `RefusalReason` (7 of the then-16
        // variants) and silently kept passing when `BadSessionAttestation` was added as the
        // 17th — the list was never wrong, just incomplete, and nothing forced anyone to notice.
        // `wire_message` itself can't be relied on to catch that: it matches on `AuthzDecision`,
        // not on `RefusalReason`, so a reason that was never listed here is indistinguishable
        // from one that was.
        //
        // The macro below makes the variant list the single source for two things at once: the
        // `match` (with no `_` arm) that must name every `RefusalReason` variant to compile, and
        // the values this test actually exercises. There is no second list to fall out of sync
        // with — adding a `RefusalReason` variant without adding it to the invocation below is a
        // compile error, not a silent gap. (Verified by hand: adding a dummy variant to
        // `RefusalReason` without updating this list fails `cargo test -p spindle-helper` with
        // "non-exhaustive patterns: `RefusalReason::Dummy` not covered".)
        macro_rules! assert_uniform_for_every_reason {
            ($($variant:ident),+ $(,)?) => {{
                fn assert_exhaustive(reason: RefusalReason) {
                    match reason {
                        $(RefusalReason::$variant => {})+
                    }
                }
                $(
                    assert_exhaustive(RefusalReason::$variant);
                    assert_eq!(
                        AuthzDecision::Refused(RefusalReason::$variant).wire_message(),
                        UNIFORM_REFUSAL_MESSAGE
                    );
                )+
            }};
        }

        assert_uniform_for_every_reason!(
            TooManyCapabilities,
            NoCapabilitiesPresented,
            DeviceCertificateExpired,
            BadDeviceCertificate,
            BadSessionAttestation,
            CapabilitySubjectMismatch,
            SubjectRevoked,
            BadNkeySignature,
            BadCapabilitySignature,
            HostCertificateExpired,
            BadHostSessionAttestation,
            BadHostSignature,
            NoAdmissionRecord,
            AdmissionClosed,
            AdmissionTokenExpired,
            BadAdmissionToken,
            AdmissionTokenAlreadyUsed,
        );
    }
}
