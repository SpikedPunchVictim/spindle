//! `helper.revoke.<nfp>` — a caller depositing a root-signed `spindle-self-rev-v1` record for its
//! own identity root (DESIGN.md §A4/§A5 subject table, §A7b **[amended v0.9.47]**, S14). Follows
//! `turn.rs`/`presence.rs`/`revoke.rs`'s shape closely: pure/NATS-free — no `async-nats` type
//! appears anywhere in this module's API — so `src/bin/helper.rs` is the only caller that touches
//! an actual subscription.
//!
//! # Identity source: the subject token, proven by NATS, plus a signature check this time
//! Caller identity is the `helper.revoke.<nfp>` subject token, exactly like `helper.turn.get.<nfp>`
//! and `helper.presence.get.<nfp>` (DESIGN.md §A5, A12 #45/#46): the callout only ever grants a
//! connection `pub helper.revoke.<own_nats_fp>` (see `permissions::client_member_permissions`), so
//! `<nfp>` is the one fact about the caller NATS itself already enforced — never a payload field.
//! Unlike those two subjects, the *content* here is signed, and the helper holds the verifying key
//! it needs: the session record now retains `root_pk` (DESIGN.md §A5, **[amended v0.9.47]**), so a
//! record is accepted only if all of the following hold, in this order:
//!
//! 1. the session record for `<nfp>` is live (`view.session_record`);
//! 2. that session carries a member root (`root_pk: Some`) — a host session has no member root to
//!    self-revoke under (`session.root_fp` for a host is the host's own `host_fp`; its root
//!    key is never presented);
//! 3. the record's own `root_fp` equals the session's `root_fp` byte-for-byte;
//! 4. the caller's **device** still has pre-crypto attempt budget (see the bucket section; keyed
//!    by `device_fp`, so a reconnect does not reset it);
//! 5. `root_pk` rebuilds into a [`spindle_core::VerifyingKey`] (including the canonical-encoding
//!    pre-check [`spindle_core::artifacts::checked_verifying_key`] applies everywhere else), and
//!    [`spindle_core::artifacts::verify_self_revocation`] accepts the signature;
//! 6. every `revoked` entry is exactly 32 bytes (deduplicated before the write);
//! 7. the record is not already fully applied (the no-op check below);
//! 8. the **root** still has a token, charged only now — after verification and only if the
//!    record changes state.
//!
//! Steps 3 and 5 are the "helper accepts the record only if its signer is the `root_fp` in the
//! caller's session record" rule from §A4/§A5's subject table. Step 3 runs first because it is the
//! cheap, non-cryptographic half of that rule; step 5 is the cryptographic half, and every failure
//! there (unusable key or bad signature) maps to **one uniform** wire error, so the reply never
//! distinguishes the two.
//!
//! # No epoch gate [deliberate]
//! Every signature-valid record is applied, including a lower-epoch or equal-epoch replay.
//! `revoke.rs`'s module doc already made this argument for host records, and it holds verbatim
//! here: a self-revocation is a one-way lattice — the accepted `revoked` set is the **monotone
//! union** of every accepted record's entries (DESIGN.md §A7b, *[amended v0.9.47]*) — so a replayed
//! record can only re-add subjects that were genuinely revoked at some point. It can never remove
//! one. Rejecting a stale-epoch record would silently lose real revocations (a redelivered
//! message, an operator re-publishing during recovery) for no security benefit, because the epoch
//! counter is separately protected by [`HelperView::record_self_revocation`]'s own max-wins rule.
//! The epoch is therefore a **reported high-water mark only** (the number in the success reply),
//! never an acceptance gate in this module.
//!
//! # Malformed `revoked` entries reject the whole record [deliberate, unlike `revoke.rs`]
//! `revoke.rs` drops an individual entry that does not decode as a 32-byte [`Fingerprint`], because
//! its admission rule is the subject-token check and the record itself is trusted by scope. Here
//! the record is trusted because it is *signed*: the signature covers every entry byte-for-byte,
//! so silently dropping one would mean accepting a signed artifact while quietly ignoring part of
//! what was signed. A single entry of any other length therefore rejects the entire record before
//! anything is written — the signature verified, but the artifact as a whole is malformed for this
//! ingestion path (see `spindle_core::artifacts::verify_self_revocation`'s doc: the verifier
//! itself carries entries opaquely and leaves length policy to ingestion).
//!
//! # Already-applied records are no-ops (no root token)
//! After verification, if every deduplicated `revoked` entry is already
//! [`HelperView::is_self_revoked`] under the root **and** `record.epoch` is at or below the stored
//! high-water mark, the record is already fully reflected in the store. The handler replies `ok`
//! with that same epoch and neither writes nor charges the per-root budget — otherwise replaying
//! one recorded message could drain the root's bucket at no cost to the replayer. This is an
//! optimization over monotone idempotence, not a semantic change: the write it skips would have
//! changed nothing. (A first-ever record that is empty at epoch 0 is likewise a no-op and reports
//! epoch 0, the zero used in the comparison; nothing is stored, and a later non-empty record is
//! written normally.)
//!
//! # Per-device and per-root token buckets (neither is authorization)
//! DESIGN.md §A5's subject table specifies a "per-root token bucket" for `helper.revoke.<nfp>`.
//! [`SelfRevokeLimits`] implements two budgets in memory, sharing integer token-bucket internals:
//!
//! - a **per-device pre-crypto attempt budget**, keyed by the session's `device_fp` (falling back
//!   to `nats_fp` when absent) and consumed before the key rebuild and signature check. Keying by
//!   device, not by the session nkey, matters because a device holds its own nkey secret and can
//!   reconnect with a fresh `nats_fp` at will — a reconnect must not hand it a fresh budget. A
//!   device can only spend its own budget, so a compromised device under root R cannot use
//!   unsigned or badly signed traffic to starve R's other devices — or R's root budget;
//! - a **per-root budget**, charged only *after* a record has verified and only when it is not
//!   already fully applied (the no-op check above). Root tokens are therefore spent only by
//!   records the root key actually signed and that change state, so an ordinary compromised
//!   device (valid cert/cap/session, no root key) cannot drain the root's budget and thereby
//!   suppress the root's own revocation deposit.
//!
//! Defaults: a burst of [`SELF_REVOKE_BURST`] per root, refilling one token every
//! [`SELF_REVOKE_REFILL_SECS`] seconds (≈10/min sustained); the per-device attempt budget uses
//! [`SELF_REVOKE_ATTEMPT_BURST`] and [`SELF_REVOKE_ATTEMPT_REFILL_SECS`]. Both budgets are
//! **per helper instance**: replicas do not share them, so N replicas permit N times each burst.
//!
//! Neither budget is authorization. The session lookup, the `root_fp` equality, and the signature
//! check are the authorization. A per-device denial can only refuse requests that device itself
//! sent (across reconnects), and a per-root denial can only follow a request that already verified
//! under the root's key. So a denial never substitutes for a trust decision the checks above did
//! not make — it reports that an attempt or accepted-write rate is exhausted, and nothing about
//! whether the caller is entitled to revoke under that root.
//!
//! **Residual, stated rather than hidden**: an observer who captures a *not-yet-applied* valid
//! record can replay it before the legitimate deposit lands, spending one root token (and, if it
//! arrives first, applying it). That is not added power: the same observer on the message path
//! can already drop the legitimate message outright. An already-applied record is detected by the
//! no-op check and costs no root token.
//!
//! # No producer exists in this workspace yet
//! Nothing here mints or deposits these records yet: no client publishes `helper.revoke.*`, and
//! the wire type deliberately has no TypeScript issuer (the TS twin parses records; it does not
//! mint them). This handler is therefore exercised only by this module's in-crate tests today.
//! DESIGN.md §A5b's status row records the missing producer; this paragraph is the code-side
//! record of the same gap, in the style of `revoke.rs`'s "Out of scope" section rather than
//! leaving the absence implicit.
//!
//! # Wire schema (following `presence.rs`'s `{ok, ...}` envelope precedent)
//! ```text
//! subject:   helper.revoke.<nfp>          nfp = caller's session nkey fingerprint (base32
//!                                         Display, same parsing rules as every other `<...fp>`
//!                                         subject token — see permissions.rs's module doc)
//! request:   canonical CBOR of a spindle-self-rev-v1 SelfRevocationRecord
//!            (`SelfRevocationRecord::from_canonical_bytes` — strict decoding rejects unknown
//!            fields, matching every other wire artifact in this codebase)
//! reply ok:  { "ok": true, "root_fp": "<base32>", "epoch": <n> }
//! reply err: { "ok": false, "error": "<human-readable reason>" }
//! ```
//! `src/bin/helper.rs` subscribes `helper.revoke.*`, passes `msg.subject` and `msg.payload` into
//! [`handle_self_revoke`], publishes [`SelfRevokeResult::reply`] to `msg.reply`, and kicks the
//! sessions of [`SelfRevokeResult::newly_revoked`] — see that type's doc for why only the newly
//! added set, not the whole union, is what drives kicks.

use serde::{Deserialize, Serialize};
use spindle_core::artifacts::verify_self_revocation;
use spindle_core::checked_verifying_key;
use spindle_core::Fingerprint;
use spindle_proto::artifacts::SelfRevocationRecord;
use std::collections::HashMap;

use crate::authz::HelperView;

/// The `helper.revoke.` subject prefix; `<nfp>` follows it as the final subject token.
const SUBJECT_PREFIX: &str = "helper.revoke.";

/// Tokens a fresh per-`root_fp` bucket starts with. Only a verified, not-already-applied record
/// charges this budget — see the module doc's bucket section for what it is and is not.
pub const SELF_REVOKE_BURST: u32 = 10;

/// Seconds of wall time that buy one per-root token back, once a bucket is below its burst. Ten
/// tokens per minute sustained matches the burst chosen above.
pub const SELF_REVOKE_REFILL_SECS: u64 = 6;

/// Tokens a fresh **per-device** pre-crypto attempt budget starts with. Deliberately its own
/// constant (not shared with [`SELF_REVOKE_BURST`]) so the two budgets can be tuned independently:
/// this one caps work an unverified caller can cause, the per-root one caps accepted writes.
pub const SELF_REVOKE_ATTEMPT_BURST: u32 = 10;

/// Seconds of wall time that buy one per-device attempt back.
pub const SELF_REVOKE_ATTEMPT_REFILL_SECS: u64 = 6;

/// The single wire error for every cryptographic failure in [`handle_self_revoke`] (unusable
/// `root_pk` encoding, wrong key, bad signature). Deliberately one string: the reply must not let
/// a caller distinguish "the key could not be rebuilt" from "the signature did not verify".
const VERIFICATION_FAILED: &str = "self-revocation verification failed";

/// One key's token bucket.
#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: u32,
    last_refill: u64,
}

/// One budget: a burst size, a refill interval, and one [`TokenBucket`] per key. Both the
/// per-device and per-root budgets use this same integer-only implementation; only their
/// constants and key spaces differ.
#[derive(Debug)]
struct Budget {
    burst: u32,
    refill_secs: u64,
    buckets: HashMap<Fingerprint, TokenBucket>,
}

impl Budget {
    fn new(burst: u32, refill_secs: u64) -> Self {
        Self {
            burst,
            refill_secs,
            buckets: HashMap::new(),
        }
    }

    /// Consumes one token for `key` at `now`, returning whether the attempt is admitted. Refills
    /// only whole `refill_secs` intervals elapsed since the last refill (capped at `burst`), so
    /// sub-interval time is never lost: `last_refill` advances by exactly the number of whole
    /// intervals consumed. A fresh bucket starts full. A rejected attempt consumes nothing (there
    /// is nothing to consume) and does not reset the bucket.
    fn allow(&mut self, key: &Fingerprint, now: u64) -> bool {
        let burst = self.burst;
        let refill_secs = self.refill_secs;
        let bucket = self.buckets.entry(*key).or_insert(TokenBucket {
            tokens: burst,
            last_refill: now,
        });

        if now > bucket.last_refill {
            let elapsed = now - bucket.last_refill;
            let intervals = elapsed / refill_secs;
            if intervals > 0 {
                // `intervals` can be huge, but saturating at the burst size is all the refill
                // needs; `last_refill` still advances by every whole interval (`intervals *
                // refill_secs <= elapsed`, so it can never overtake `now`).
                let refilled = intervals.min(u64::from(burst)) as u32;
                bucket.tokens = bucket.tokens.saturating_add(refilled).min(burst);
                bucket.last_refill += intervals * refill_secs;
            }
        }

        if bucket.tokens == 0 {
            false
        } else {
            bucket.tokens -= 1;
            true
        }
    }
}

/// In-memory rate limits for `helper.revoke.<nfp>`, owned by the helper's responder state
/// (`src/bin/helper.rs`). Holds the per-device pre-crypto budget and the per-root accepted-write
/// budget; see the module doc's bucket section for the ordering, the defaults, and why neither
/// budget is authorization.
#[derive(Debug)]
pub struct SelfRevokeLimits {
    per_device: Budget,
    per_root: Budget,
}

impl SelfRevokeLimits {
    pub fn new() -> Self {
        Self {
            per_device: Budget::new(SELF_REVOKE_ATTEMPT_BURST, SELF_REVOKE_ATTEMPT_REFILL_SECS),
            per_root: Budget::new(SELF_REVOKE_BURST, SELF_REVOKE_REFILL_SECS),
        }
    }

    /// Consumes one pre-crypto attempt from `device_fp`'s budget. Called after the cheap identity
    /// checks but before the key rebuild and signature verification. The key is the session's
    /// `device_fp`, not its `nats_fp`, so a reconnect with a fresh session nkey shares the same
    /// budget; only a caller with no `device_fp` at all falls back to the session fingerprint (a
    /// member session always carries `Some(device_fp)` — see `session.rs`).
    pub fn allow_attempt(&mut self, device_fp: &Fingerprint, now: u64) -> bool {
        self.per_device.allow(device_fp, now)
    }

    /// Consumes one token from `root_fp`'s budget. Called only after a record has verified and
    /// only when it is not already fully applied, so root tokens are spendable solely by records
    /// the root key actually signed.
    pub fn charge_root(&mut self, root_fp: &Fingerprint, now: u64) -> bool {
        self.per_root.allow(root_fp, now)
    }
}

impl Default for SelfRevokeLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// `helper.revoke.<nfp>` reply envelope (see the module doc's wire schema). Public so
/// `src/bin/helper.rs` can decode the handler's own JSON to decide whether to log an acceptance or
/// a rejection; the wire shape is exactly this struct.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelfRevokeReply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_fp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SelfRevokeReply {
    fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            root_fp: None,
            epoch: None,
            error: Some(message.into()),
        }
    }

    fn ok(root_fp: String, epoch: u64) -> Self {
        Self {
            ok: true,
            root_fp: Some(root_fp),
            epoch: Some(epoch),
            error: None,
        }
    }
}

/// The outcome of one [`handle_self_revoke`] call: the wire reply plus the set of devices this
/// particular deposit **newly** added to the root's revoked set.
///
/// `newly_revoked` is deliberately *not* the whole post-write union. It is the deduplicated,
/// first-seen-ordered subset of the record's `revoked` entries that were not already
/// [`HelperView::is_self_revoked`] under the root when this call ran. That is exactly the set
/// `src/bin/helper.rs` kicks (DESIGN.md §A3's kick relay, S9 leg 3):
///
/// - a replay/no-op (or a record whose entries are all already revoked) reports an empty list, so
///   it kicks nothing — re-kicking sessions on every redelivery would be pointless traffic;
/// - an entry that was revoked by an earlier deposit is already gone from the live sessions that
///   matter, and kicking it again is unnecessary;
/// - and a rejected record reports nothing, because nothing was applied.
///
/// The reply bytes are exactly today's wire JSON (see the module doc's wire schema), unchanged by
/// this addition.
#[derive(Debug, PartialEq, Eq)]
pub struct SelfRevokeResult {
    /// The JSON reply to publish (`SelfRevokeReply` serialized).
    pub reply: Vec<u8>,
    /// Devices this call newly added to the union, in first-seen order. Empty on a no-op, a
    /// rejection, or a store error.
    pub newly_revoked: Vec<Fingerprint>,
}

/// Parses the caller's `nats_fp` out of a `helper.revoke.<nfp>` subject, via the shared
/// [`crate::parse_fp_after_prefix`] helper every `<...fp>` subject parser in this crate uses.
fn parse_subject_nats_fp(subject: &str) -> Option<Fingerprint> {
    crate::parse_fp_after_prefix(subject, SUBJECT_PREFIX)
}

/// Decodes and admits one `helper.revoke.<nfp>` deposit. Pure with respect to NATS — the caller
/// (`src/bin/helper.rs`) owns the subscription and the reply publish; this function only computes
/// the JSON reply bytes (which are [`SelfRevokeReply`]) and the newly-added revoked set.
///
/// Checks run in the order the module doc's identity section lists: subject token, live session,
/// member root present, record decodes, record `root_fp` matches the session's, the caller's
/// per-device attempt budget, signature (via the session's retained `root_pk`), every `revoked`
/// entry exactly 32 bytes (deduplicated), the already-applied no-op check, and only then the
/// per-root token. After all of those it calls [`HelperView::record_self_revocation`] and replies
/// with the *returned* post-write epoch — never with a re-read or an `expect`.
///
/// The returned [`SelfRevokeResult::newly_revoked`] is what the caller kicks: the entries this
/// deposit added, not the whole union. See that type's doc.
pub fn handle_self_revoke(
    subject: &str,
    payload: &[u8],
    view: &mut impl HelperView,
    limits: &mut SelfRevokeLimits,
    now: u64,
) -> SelfRevokeResult {
    let (reply, newly_revoked) = handle_self_revoke_inner(subject, payload, view, limits, now);
    SelfRevokeResult {
        reply: serde_json::to_vec(&reply).expect("SelfRevokeReply always serializes"),
        newly_revoked,
    }
}

fn handle_self_revoke_inner(
    subject: &str,
    payload: &[u8],
    view: &mut impl HelperView,
    limits: &mut SelfRevokeLimits,
    now: u64,
) -> (SelfRevokeReply, Vec<Fingerprint>) {
    let Some(nats_fp) = parse_subject_nats_fp(subject) else {
        return (SelfRevokeReply::err("malformed subject"), Vec::new());
    };

    let Some(session) = view.session_record(&nats_fp, now) else {
        return (SelfRevokeReply::err("no active session"), Vec::new());
    };

    // A host connection's session record reuses this shape with `root_pk: None` (see
    // `session.rs`'s doc comment): a host has no member root, so there is nothing this subject
    // could legitimately revoke under one. Refuse rather than fall back to any other key.
    let Some(root_pk) = session.root_pk else {
        return (
            SelfRevokeReply::err("session has no member root"),
            Vec::new(),
        );
    };

    let Ok(record) = SelfRevocationRecord::from_canonical_bytes(payload) else {
        return (SelfRevokeReply::err("malformed record"), Vec::new());
    };

    // The cheap half of "the signer is the session's root": compare the record's claimed
    // `root_fp` against the session record before touching any cryptography.
    if !session.root_fp.matches(&record.root_fp) {
        return (
            SelfRevokeReply::err("record root_fp does not match the session's root"),
            Vec::new(),
        );
    }

    // Per-device, pre-crypto attempt budget. Keyed by the session's `device_fp` (falling back to
    // `nats_fp` only when no device identity exists): a device holds its nkey secret and can
    // reconnect with a fresh `nats_fp`, so keying by the session nkey would reset its budget on
    // every reconnect. Keyed this way a compromised device can only spend its own budget and
    // cannot starve the root's token budget (which is not charged until verification below).
    let attempt_key = session.device_fp.unwrap_or(session.nats_fp);
    if !limits.allow_attempt(&attempt_key, now) {
        return (SelfRevokeReply::err("rate limited"), Vec::new());
    }

    // Rebuild the retained key exactly as every other artifact verifier does — including the
    // RFC 8032 §5.1.3 canonical-encoding round trip — then check the signature. One uniform error
    // for both halves: the wire reply never says which one failed.
    let Some(vk) = checked_verifying_key(&root_pk) else {
        return (SelfRevokeReply::err(VERIFICATION_FAILED), Vec::new());
    };
    if verify_self_revocation(&record, &vk).is_err() {
        return (SelfRevokeReply::err(VERIFICATION_FAILED), Vec::new());
    }

    // Every entry is covered by the signature, so a single wrong-length entry makes the signed
    // artifact malformed for this ingestion path — reject all of it, never drop an entry. Dedup
    // before the write: the union semantics make duplicate entries meaningless, and one
    // deduplicated set is what keeps the durable write a single statement (see `pg_store`). The
    // `HashSet` is membership only; the `Vec` preserves first-seen order, which is the order the
    // caller kicks in and the order the tests assert. In the same pass, record which entries are
    // genuinely new to the root's revoked set — that, not the whole union, is what the caller
    // kicks (see `SelfRevokeResult`'s doc).
    let mut seen: std::collections::HashSet<Fingerprint> =
        std::collections::HashSet::with_capacity(record.revoked.len());
    let mut deduped: Vec<Fingerprint> = Vec::with_capacity(record.revoked.len());
    let mut newly_revoked: Vec<Fingerprint> = Vec::new();
    for entry in &record.revoked {
        let Ok(fp) = Fingerprint::from_slice(entry) else {
            return (SelfRevokeReply::err("malformed revoked entry"), Vec::new());
        };
        if !seen.insert(fp) {
            continue;
        }
        if !view.is_self_revoked(&session.root_fp, &fp) {
            newly_revoked.push(fp);
        }
        deduped.push(fp);
    }

    // Already-applied check: if this deposit would add nothing to the union and the epoch does not
    // advance the high-water mark, it would change nothing. Reply with the stored epoch without
    // writing and, crucially, without charging a root token — otherwise replaying one recorded
    // message could drain the root's bucket. (`None` means no record yet, i.e. a high-water mark of
    // 0 for comparison.) `newly_revoked.is_empty()` is exactly "every deduplicated entry is
    // already in the union".
    let stored_epoch = view.self_revocation_epoch(&session.root_fp);
    let already_applied = newly_revoked.is_empty() && record.epoch <= stored_epoch.unwrap_or(0);
    if already_applied {
        return (
            SelfRevokeReply::ok(session.root_fp.to_string(), stored_epoch.unwrap_or(0)),
            Vec::new(),
        );
    }

    // Per-root budget, charged only now: this record verified under the root's key and changes
    // state, so only the root's own signed records can spend its tokens.
    if !limits.charge_root(&session.root_fp, now) {
        return (SelfRevokeReply::err("rate limited"), Vec::new());
    }

    // No epoch gate: every signature-valid, not-already-applied record unions its subjects (see
    // the module doc's "No epoch gate" section). The store applies max-wins to the epoch itself.
    // `deduped` is in first-seen order, so the write and the reported set agree.
    let Some(epoch) = view.record_self_revocation(&session.root_fp, record.epoch, &deduped) else {
        // The store did not persist the write; it cannot report a post-write epoch, and inventing
        // one here would claim state that is not durable.
        return (SelfRevokeReply::err("record not stored"), Vec::new());
    };
    (
        SelfRevokeReply::ok(session.root_fp.to_string(), epoch),
        newly_revoked,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{AdmissionMode, HelperView};
    use crate::memory_store::InMemoryHelperView;
    use crate::session::SessionRecord;
    use spindle_core::artifacts::issue_self_revocation;
    use spindle_core::{root_fp_of, SigningKey};
    use std::collections::HashSet;

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_parts(&[seed])
    }

    fn store() -> InMemoryHelperView {
        InMemoryHelperView::new(
            AdmissionMode::Open,
            SigningKey::from_bytes(&[0x51; 32]).verifying_key(),
        )
    }

    fn root_signer() -> SigningKey {
        SigningKey::from_bytes(&[0x61; 32])
    }

    fn subject_for(nats_fp: &Fingerprint) -> String {
        format!("helper.revoke.{nats_fp}")
    }

    /// Stores a member session for `nats_fp` whose root is `signer`'s, the shape
    /// `authz::decide_device_connect` writes (DESIGN.md §A5, amended v0.9.47). The device identity
    /// is derived from `nats_fp` so distinct sessions in these tests get distinct per-device
    /// attempt budgets; the reconnect tests pass a shared `device_fp` explicitly.
    fn put_member_session(
        view: &mut InMemoryHelperView,
        nats_fp: Fingerprint,
        signer: &SigningKey,
    ) {
        let device_fp = Fingerprint::of_parts(&[b"member-device-for", nats_fp.as_bytes()]);
        put_member_session_with_device(view, nats_fp, device_fp, signer);
    }

    /// The explicit form of [`put_member_session`], for tests that need to control which device a
    /// session belongs to (e.g. one device reconnecting with a fresh `nats_fp`).
    fn put_member_session_with_device(
        view: &mut InMemoryHelperView,
        nats_fp: Fingerprint,
        device_fp: Fingerprint,
        signer: &SigningKey,
    ) {
        view.put_session_record(SessionRecord::new(
            nats_fp,
            root_fp_of(&signer.verifying_key()),
            Some(signer.verifying_key().to_bytes()),
            Some(device_fp),
            vec![],
            "member".to_string(),
            10_000,
        ));
    }

    fn record_bytes(signer: &SigningKey, epoch: u64, revoked: Vec<Fingerprint>) -> Vec<u8> {
        issue_self_revocation(signer, epoch, revoked, 1_000).to_canonical_bytes()
    }

    fn reply(bytes: &[u8]) -> SelfRevokeReply {
        serde_json::from_slice(bytes).unwrap()
    }

    fn deposit_result(
        subject: &str,
        payload: &[u8],
        view: &mut InMemoryHelperView,
        limiter: &mut SelfRevokeLimits,
        now: u64,
    ) -> SelfRevokeResult {
        handle_self_revoke(subject, payload, view, limiter, now)
    }

    fn deposit(
        subject: &str,
        payload: &[u8],
        view: &mut InMemoryHelperView,
        limiter: &mut SelfRevokeLimits,
        now: u64,
    ) -> SelfRevokeReply {
        reply(&deposit_result(subject, payload, view, limiter, now).reply)
    }

    // ---- handle_self_revoke: accept ---------------------------------------------------------

    #[test]
    fn signed_record_from_the_session_root_is_applied_and_replies_with_the_epoch() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let nats_fp = fp(b"nats-self-rev-ok");
        put_member_session(&mut view, nats_fp, &root);
        let lost_device = fp(b"lost-device");
        let payload = record_bytes(&root, 3, vec![lost_device]);

        let got = deposit(
            &subject_for(&nats_fp),
            &payload,
            &mut view,
            &mut limiter,
            1_000,
        );

        assert!(got.ok, "signed record must be accepted: {got:?}");
        assert_eq!(
            got.root_fp,
            Some(root_fp_of(&root.verifying_key()).to_string())
        );
        assert_eq!(got.epoch, Some(3));
        assert_eq!(got.error, None);
        assert!(view.is_self_revoked(&root_fp_of(&root.verifying_key()), &lost_device));
    }

    // ---- handle_self_revoke: rejected paths --------------------------------------------------

    #[test]
    fn malformed_subject_is_refused() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let payload = record_bytes(&root, 1, vec![]);

        for subject in [
            "helper.revoke",
            "helper.revoke.",
            "helper.revoke.not-a-fingerprint!!",
            "helper.turn.get.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let got = deposit(subject, &payload, &mut view, &mut limiter, 1_000);
            assert!(!got.ok, "{subject} must be refused");
            assert_eq!(got.error.as_deref(), Some("malformed subject"));
        }
    }

    #[test]
    fn no_session_record_is_refused() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let nats_fp = fp(b"nats-no-session-self-rev");
        let payload = record_bytes(&root, 1, vec![fp(b"x")]);

        let got = deposit(
            &subject_for(&nats_fp),
            &payload,
            &mut view,
            &mut limiter,
            1_000,
        );

        assert!(!got.ok);
        assert_eq!(got.error.as_deref(), Some("no active session"));
    }

    #[test]
    fn expired_session_record_is_treated_as_no_session() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let nats_fp = fp(b"nats-expired-self-rev");
        view.put_session_record(SessionRecord::new(
            nats_fp,
            root_fp_of(&root.verifying_key()),
            Some(root.verifying_key().to_bytes()),
            None,
            vec![],
            "member".to_string(),
            500, // already expired at now = 1_000
        ));
        let payload = record_bytes(&root, 1, vec![fp(b"x")]);

        let got = deposit(
            &subject_for(&nats_fp),
            &payload,
            &mut view,
            &mut limiter,
            1_000,
        );

        assert_eq!(got.error.as_deref(), Some("no active session"));
    }

    #[test]
    fn host_session_without_a_member_root_is_refused() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let host_fp = fp(b"host-self-rev");
        // A host connection's session record: `root_pk: None` (session.rs's interpretive
        // choice 1). Even a genuinely signed record must be refused — a host has no member root.
        view.put_session_record(SessionRecord::new(
            host_fp,
            host_fp,
            None,
            None,
            vec![host_fp],
            "default".to_string(),
            10_000,
        ));
        let payload = record_bytes(&root, 1, vec![fp(b"x")]);

        let got = deposit(
            &subject_for(&host_fp),
            &payload,
            &mut view,
            &mut limiter,
            1_000,
        );

        assert!(!got.ok);
        assert_eq!(got.error.as_deref(), Some("session has no member root"));
        assert_eq!(view.self_revocation_epoch(&host_fp), None);
    }

    #[test]
    fn record_root_fp_that_differs_from_the_session_root_is_refused() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let session_root = root_signer();
        let other_root = SigningKey::from_bytes(&[0x62; 32]);
        let nats_fp = fp(b"nats-root-mismatch");
        put_member_session(&mut view, nats_fp, &session_root);
        // A perfectly valid record — but signed by (and naming) a different root.
        let payload = record_bytes(&other_root, 1, vec![fp(b"victim")]);
        let victim = fp(b"victim");

        let got = deposit(
            &subject_for(&nats_fp),
            &payload,
            &mut view,
            &mut limiter,
            1_000,
        );

        assert!(!got.ok);
        assert_eq!(
            got.error.as_deref(),
            Some("record root_fp does not match the session's root")
        );
        assert!(!view.is_self_revoked(&root_fp_of(&session_root.verifying_key()), &victim));
        assert_eq!(
            view.self_revocation_epoch(&root_fp_of(&session_root.verifying_key())),
            None
        );
    }

    #[test]
    fn tampered_signature_is_refused_uniformly() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let nats_fp = fp(b"nats-tampered");
        put_member_session(&mut view, nats_fp, &root);
        let mut record = issue_self_revocation(&root, 1, vec![fp(b"victim")], 1_000);
        record.sig_root[0] ^= 0xff;
        let payload = record.to_canonical_bytes();
        let victim = fp(b"victim");

        let got = deposit(
            &subject_for(&nats_fp),
            &payload,
            &mut view,
            &mut limiter,
            1_000,
        );

        assert!(!got.ok);
        assert_eq!(got.error.as_deref(), Some(VERIFICATION_FAILED));
        assert!(!view.is_self_revoked(&root_fp_of(&root.verifying_key()), &victim));
    }

    #[test]
    fn forgery_claiming_the_session_root_but_signed_by_another_key_is_refused() {
        // The record's `root_fp` names the session's root (so the cheap equality check passes),
        // but the signature was produced by a different key entirely. This is the actual forgery
        // shape a compromised device would attempt; flipping a bit of a genuine signature (the
        // test above) does not exercise it.
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let attacker = SigningKey::from_bytes(&[0x63; 32]);
        let nats_fp = fp(b"nats-forged-root-fp");
        put_member_session(&mut view, nats_fp, &root);
        let victim = fp(b"victim");

        // Signed by the attacker (over a preimage naming the attacker's root), then relabelled to
        // claim the session's root. The signature no longer covers the relabelled preimage.
        let mut record = issue_self_revocation(&attacker, 1, vec![victim], 1_000);
        record.root_fp = root_fp_of(&root.verifying_key()).to_vec();
        let payload = record.to_canonical_bytes();

        let got = deposit(
            &subject_for(&nats_fp),
            &payload,
            &mut view,
            &mut limiter,
            1_000,
        );

        assert!(!got.ok);
        assert_eq!(
            got.error.as_deref(),
            Some(VERIFICATION_FAILED),
            "a record claiming the session root must verify under that root's key"
        );
        assert!(!view.is_self_revoked(&root_fp_of(&root.verifying_key()), &victim));
        assert_eq!(
            view.self_revocation_epoch(&root_fp_of(&root.verifying_key())),
            None
        );
    }

    #[test]
    fn unusable_root_pk_and_bad_signature_are_indistinguishable_on_the_wire() {
        // Two different failures — a key that cannot be rebuilt, and a bad signature under a
        // usable key — must produce the same error string (no oracle for which half failed).
        let root = root_signer();
        let bad_sig = {
            let mut view = store();
            let mut limiter = SelfRevokeLimits::new();
            let nats_fp = fp(b"nats-bad-sig-uniform");
            put_member_session(&mut view, nats_fp, &root);
            let mut record = issue_self_revocation(&root, 1, vec![], 1_000);
            record.sig_root[0] ^= 0xff;
            deposit(
                &subject_for(&nats_fp),
                &record.to_canonical_bytes(),
                &mut view,
                &mut limiter,
                1_000,
            )
        };
        let bad_key = {
            let mut view = store();
            let mut limiter = SelfRevokeLimits::new();
            let nats_fp = fp(b"nats-bad-key-uniform");
            // A session whose retained root_pk is not a canonical Ed25519 encoding. The record's
            // `root_fp` must still match the session's separate `root_fp` field to reach the key
            // step, which is exactly the state a corrupt stored session would produce.
            view.put_session_record(SessionRecord::new(
                nats_fp,
                root_fp_of(&root.verifying_key()),
                Some([0xff; 32]),
                None,
                vec![],
                "member".to_string(),
                10_000,
            ));
            let payload = record_bytes(&root, 1, vec![]);
            deposit(
                &subject_for(&nats_fp),
                &payload,
                &mut view,
                &mut limiter,
                1_000,
            )
        };

        assert_eq!(bad_sig.error.as_deref(), Some(VERIFICATION_FAILED));
        assert_eq!(bad_key.error.as_deref(), Some(VERIFICATION_FAILED));
        assert_eq!(bad_sig.error, bad_key.error);
    }

    #[test]
    fn garbage_payload_is_refused() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let nats_fp = fp(b"nats-garbage");
        put_member_session(&mut view, nats_fp, &root);

        let got = deposit(
            &subject_for(&nats_fp),
            b"not canonical cbor at all",
            &mut view,
            &mut limiter,
            1_000,
        );

        assert!(!got.ok);
        assert_eq!(got.error.as_deref(), Some("malformed record"));
        assert_eq!(
            view.self_revocation_epoch(&root_fp_of(&root.verifying_key())),
            None
        );
    }

    #[test]
    fn one_non_32_byte_entry_rejects_the_whole_record_and_drops_the_valid_entry() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let nats_fp = fp(b"nats-short-entry");
        put_member_session(&mut view, nats_fp, &root);
        let root_fp = root_fp_of(&root.verifying_key());
        let valid_device = fp(b"valid-device");

        // Sign a record whose `revoked` carries one well-formed 32-byte entry and one 3-byte
        // entry, by building the unsigned fields by hand and signing `signing_input()` — the
        // signature must cover the malformed entry for this test to reach the entry check.
        let mut record = issue_self_revocation(&root, 1, vec![valid_device], 1_000);
        record.revoked.push(vec![0xAA, 0xBB, 0xCC]);
        record.sig_root = spindle_core::sign_bytes(&root, &record.signing_input());
        let payload = record.to_canonical_bytes();

        let got = deposit(
            &subject_for(&nats_fp),
            &payload,
            &mut view,
            &mut limiter,
            1_000,
        );

        assert!(!got.ok);
        assert_eq!(got.error.as_deref(), Some("malformed revoked entry"));
        assert!(
            !view.is_self_revoked(&root_fp, &valid_device),
            "the well-formed entry must not be silently applied from a rejected record"
        );
        assert_eq!(view.self_revocation_epoch(&root_fp), None);
    }

    #[test]
    fn exhausted_root_bucket_refuses_further_state_changing_deposits() {
        // Two sessions under one root, so exhausting the root's burst is not confused with
        // exhausting either session's own pre-crypto budget: five state-changing records each.
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let root_fp = root_fp_of(&root.verifying_key());
        let nats_a = fp(b"nats-root-burst-a");
        let nats_b = fp(b"nats-root-burst-b");
        put_member_session(&mut view, nats_a, &root);
        put_member_session(&mut view, nats_b, &root);

        let mut epoch = 0;
        for nats_fp in [nats_a, nats_b] {
            for _ in 0..(SELF_REVOKE_BURST / 2) {
                epoch += 1;
                let device = fp(format!("burst-device-{epoch}").as_bytes());
                let got = deposit(
                    &subject_for(&nats_fp),
                    &record_bytes(&root, epoch, vec![device]),
                    &mut view,
                    &mut limiter,
                    1_000,
                );
                assert!(
                    got.ok,
                    "record {epoch} within the root burst must apply: {got:?}"
                );
            }
        }

        // Session A still has its own attempt budget left, so this reaches the root budget.
        let device = fp(b"burst-device-overflow");
        let refused = deposit(
            &subject_for(&nats_a),
            &record_bytes(&root, epoch + 1, vec![device]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert!(!refused.ok);
        assert_eq!(refused.error.as_deref(), Some("rate limited"));
        assert!(!view.is_self_revoked(&root_fp, &device));
    }

    #[test]
    fn rejected_records_consume_session_tokens_and_do_not_reset_the_bucket() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let nats_fp = fp(b"nats-bucket-rejects");
        put_member_session(&mut view, nats_fp, &root);
        let subject = subject_for(&nats_fp);
        let mut tampered = issue_self_revocation(&root, 1, vec![fp(b"victim")], 1_000);
        tampered.sig_root[0] ^= 0xff;
        let tampered = tampered.to_canonical_bytes();

        for _ in 0..SELF_REVOKE_ATTEMPT_BURST {
            let got = deposit(&subject, &tampered, &mut view, &mut limiter, 1_000);
            assert_eq!(got.error.as_deref(), Some(VERIFICATION_FAILED));
        }

        // If a rejected record had reset (or not consumed) the attempt budget, this valid deposit
        // from the same session would be admitted.
        let valid = record_bytes(&root, 2, vec![fp(b"victim")]);
        let got = deposit(&subject, &valid, &mut view, &mut limiter, 1_000);
        assert!(!got.ok);
        assert_eq!(got.error.as_deref(), Some("rate limited"));
        assert!(!view.is_self_revoked(&root_fp_of(&root.verifying_key()), &fp(b"victim")));
    }

    #[test]
    fn a_compromised_session_cannot_starve_the_roots_budget() {
        // A device under root R holds a valid session but not R's root key. Its forged records
        // name R (so they reach verification) but fail the signature. They can burn only this
        // session's own attempt budget; R's root budget is charged only after a record verifies,
        // so the legitimate session's signed record still applies.
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let compromised_nats = fp(b"nats-compromised-device");
        let legitimate_nats = fp(b"nats-legitimate-device");
        put_member_session(&mut view, compromised_nats, &root);
        put_member_session(&mut view, legitimate_nats, &root);

        for i in 0..SELF_REVOKE_ATTEMPT_BURST {
            let mut forged = issue_self_revocation(&root, i as u64 + 1, vec![fp(b"victim")], 1_000);
            forged.sig_root[0] ^= 0xff;
            let got = deposit(
                &subject_for(&compromised_nats),
                &forged.to_canonical_bytes(),
                &mut view,
                &mut limiter,
                1_000,
            );
            assert_eq!(got.error.as_deref(), Some(VERIFICATION_FAILED));
        }

        let victim = fp(b"victim");
        let got = deposit(
            &subject_for(&legitimate_nats),
            &record_bytes(&root, 1, vec![victim]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert!(
            got.ok,
            "the root's own signed record must still be accepted after another device's \
             forged flood: {got:?}"
        );
        assert!(view.is_self_revoked(&root_fp_of(&root.verifying_key()), &victim));
    }

    #[test]
    fn the_attempt_budget_exhausts_only_its_own_device() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let root_fp = root_fp_of(&root.verifying_key());
        let exhausted_nats = fp(b"nats-session-exhausted");
        let fresh_nats = fp(b"nats-session-fresh");
        put_member_session(&mut view, exhausted_nats, &root);
        put_member_session(&mut view, fresh_nats, &root);

        let mut tampered = issue_self_revocation(&root, 1, vec![fp(b"victim")], 1_000);
        tampered.sig_root[0] ^= 0xff;
        let tampered = tampered.to_canonical_bytes();
        for _ in 0..SELF_REVOKE_ATTEMPT_BURST {
            let got = deposit(
                &subject_for(&exhausted_nats),
                &tampered,
                &mut view,
                &mut limiter,
                1_000,
            );
            assert_eq!(got.error.as_deref(), Some(VERIFICATION_FAILED));
        }

        let own_valid = deposit(
            &subject_for(&exhausted_nats),
            &record_bytes(&root, 2, vec![fp(b"own-device")]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert_eq!(own_valid.error.as_deref(), Some("rate limited"));
        assert!(!view.is_self_revoked(&root_fp, &fp(b"own-device")));

        let other_valid = deposit(
            &subject_for(&fresh_nats),
            &record_bytes(&root, 3, vec![fp(b"other-device")]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert!(
            other_valid.ok,
            "a different device keeps a fresh budget: {other_valid:?}"
        );
        assert!(view.is_self_revoked(&root_fp, &fp(b"other-device")));
    }

    #[test]
    fn reconnecting_sessions_of_one_device_share_the_attempt_budget() {
        // A device holds its own nkey secret, so it can reconnect with a fresh `nats_fp`. Keying
        // the pre-crypto budget by `device_fp` means the new session inherits the exhausted
        // budget instead of getting a fresh one.
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let root_fp = root_fp_of(&root.verifying_key());
        let device = fp(b"reconnecting-device");
        let other_device = fp(b"uninvolved-device");
        let first_nats = fp(b"nats-reconnect-before");
        let second_nats = fp(b"nats-reconnect-after");
        let other_nats = fp(b"nats-other-device");

        put_member_session_with_device(&mut view, first_nats, device, &root);
        put_member_session_with_device(&mut view, second_nats, device, &root);
        put_member_session_with_device(&mut view, other_nats, other_device, &root);

        let mut tampered = issue_self_revocation(&root, 1, vec![fp(b"victim")], 1_000);
        tampered.sig_root[0] ^= 0xff;
        let tampered = tampered.to_canonical_bytes();
        for _ in 0..SELF_REVOKE_ATTEMPT_BURST {
            let got = deposit(
                &subject_for(&first_nats),
                &tampered,
                &mut view,
                &mut limiter,
                1_000,
            );
            assert_eq!(got.error.as_deref(), Some(VERIFICATION_FAILED));
        }

        // A fresh session nkey for the same device shares the exhausted budget...
        let reconnected = deposit(
            &subject_for(&second_nats),
            &record_bytes(&root, 2, vec![fp(b"own-device")]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert_eq!(reconnected.error.as_deref(), Some("rate limited"));
        assert!(!view.is_self_revoked(&root_fp, &fp(b"own-device")));

        // ...while a different device is unaffected.
        let other = deposit(
            &subject_for(&other_nats),
            &record_bytes(&root, 3, vec![fp(b"other-device")]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert!(
            other.ok,
            "a different device keeps its own budget: {other:?}"
        );
        assert!(view.is_self_revoked(&root_fp, &fp(b"other-device")));
    }

    #[test]
    fn replaying_an_applied_record_does_not_charge_the_root_budget() {
        // Root burst = SELF_REVOKE_BURST. Nine state-changing records via session A leave one
        // root token. Replaying record #1 through A is a no-op: it must not spend that token.
        // Session B's next new record must therefore still apply, which is what proves the replay
        // charged nothing; a further new record is then refused by the exhausted root budget.
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let root_fp = root_fp_of(&root.verifying_key());
        let nats_a = fp(b"nats-replay-budget-a");
        let nats_b = fp(b"nats-replay-budget-b");
        put_member_session(&mut view, nats_a, &root);
        put_member_session(&mut view, nats_b, &root);

        let apply_count = SELF_REVOKE_BURST - 1;
        let mut first_payload = None;
        for epoch in 1..=apply_count {
            let device = fp(format!("replay-budget-device-{epoch}").as_bytes());
            let payload = record_bytes(&root, epoch as u64, vec![device]);
            let got = deposit(
                &subject_for(&nats_a),
                &payload,
                &mut view,
                &mut limiter,
                1_000,
            );
            assert!(got.ok, "record {epoch} must apply: {got:?}");
            if first_payload.is_none() {
                first_payload = Some(payload);
            }
        }

        let replay = deposit(
            &subject_for(&nats_a),
            first_payload.as_ref().unwrap(),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert!(replay.ok);
        assert_eq!(replay.epoch, Some(apply_count as u64));

        let last_device = fp(b"replay-budget-device-10");
        let last = deposit(
            &subject_for(&nats_b),
            &record_bytes(&root, 10, vec![last_device]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert!(
            last.ok,
            "the root had one token left; a no-op replay must not have spent it: {last:?}"
        );
        assert!(view.is_self_revoked(&root_fp, &last_device));

        let over = deposit(
            &subject_for(&nats_b),
            &record_bytes(&root, 11, vec![fp(b"replay-budget-overflow")]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert_eq!(over.error.as_deref(), Some("rate limited"));
        assert!(!view.is_self_revoked(&root_fp, &fp(b"replay-budget-overflow")));
    }

    #[test]
    fn duplicate_revoked_entries_are_deduplicated_and_accepted() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let root_fp = root_fp_of(&root.verifying_key());
        let nats_fp = fp(b"nats-duplicate-entries");
        put_member_session(&mut view, nats_fp, &root);
        let device = fp(b"device-duplicate");

        // The signature covers the duplicated list; dedup happens after verification, so this is
        // a valid root-signed record that carries the same subject twice.
        let payload = record_bytes(&root, 1, vec![device, device]);
        let got = deposit(
            &subject_for(&nats_fp),
            &payload,
            &mut view,
            &mut limiter,
            1_000,
        );

        assert!(
            got.ok,
            "duplicate entries are valid, just redundant: {got:?}"
        );
        assert_eq!(got.epoch, Some(1));
        assert!(view.is_self_revoked(&root_fp, &device));
        // And re-depositing it is a no-op, not an error.
        let replay = deposit(
            &subject_for(&nats_fp),
            &payload,
            &mut view,
            &mut limiter,
            1_000,
        );
        assert!(replay.ok);
        assert_eq!(replay.epoch, Some(1));
    }

    // ---- SelfRevokeLimits ------------------------------------------------------------------

    #[test]
    fn rate_limit_constants_are_pinned_to_their_literal_values() {
        // Written against the literals, not the named constants: a test that compares a constant
        // to itself leaves the number free (a change from 10 to 3600 would still pass).
        assert_eq!(SELF_REVOKE_BURST, 10, "per-root burst");
        assert_eq!(
            SELF_REVOKE_REFILL_SECS, 6,
            "per-root refill interval, seconds"
        );
        assert_eq!(SELF_REVOKE_ATTEMPT_BURST, 10, "per-device attempt burst");
        assert_eq!(
            SELF_REVOKE_ATTEMPT_REFILL_SECS, 6,
            "per-device attempt refill interval, seconds"
        );
    }

    #[test]
    fn root_budget_allows_a_full_burst_then_refuses() {
        let mut limits = SelfRevokeLimits::new();
        let root = fp(b"bucket-root");
        for _ in 0..SELF_REVOKE_BURST {
            assert!(limits.charge_root(&root, 1_000));
        }
        assert!(!limits.charge_root(&root, 1_000));
    }

    #[test]
    fn root_budget_refills_one_token_per_interval_and_carries_the_remainder() {
        let mut limits = SelfRevokeLimits::new();
        let root = fp(b"bucket-refill");
        let t0 = 1_000;
        for _ in 0..SELF_REVOKE_BURST {
            assert!(limits.charge_root(&root, t0));
        }
        assert!(!limits.charge_root(&root, t0 + SELF_REVOKE_REFILL_SECS - 1));

        // Exactly one interval restores exactly one token...
        assert!(limits.charge_root(&root, t0 + SELF_REVOKE_REFILL_SECS));
        assert!(!limits.charge_root(&root, t0 + SELF_REVOKE_REFILL_SECS));

        // ...and the sub-interval remainder is not lost: at t0 + 2*interval the one whole
        // interval since the last refill yields one more token, not zero.
        assert!(limits.charge_root(&root, t0 + 2 * SELF_REVOKE_REFILL_SECS));
        assert!(!limits.charge_root(&root, t0 + 2 * SELF_REVOKE_REFILL_SECS));
    }

    #[test]
    fn root_budget_refill_never_exceeds_the_burst() {
        let mut limits = SelfRevokeLimits::new();
        let root = fp(b"bucket-cap");
        assert!(limits.charge_root(&root, 1_000));
        // A very long idle period must not accumulate more than a full burst.
        for _ in 0..SELF_REVOKE_BURST {
            assert!(limits.charge_root(&root, 1_000 + 1_000_000));
        }
        assert!(!limits.charge_root(&root, 1_000 + 1_000_000));
    }

    #[test]
    fn root_budgets_are_isolated_per_root() {
        let mut limits = SelfRevokeLimits::new();
        let exhausted = fp(b"bucket-root-a");
        let fresh = fp(b"bucket-root-b");
        for _ in 0..SELF_REVOKE_BURST {
            assert!(limits.charge_root(&exhausted, 1_000));
        }
        assert!(!limits.charge_root(&exhausted, 1_000));
        assert!(
            limits.charge_root(&fresh, 1_000),
            "another root's budget must be untouched"
        );
    }

    #[test]
    fn attempt_budgets_are_isolated_per_device() {
        let mut limits = SelfRevokeLimits::new();
        let exhausted = fp(b"device-a");
        let fresh = fp(b"device-b");
        for _ in 0..SELF_REVOKE_ATTEMPT_BURST {
            assert!(limits.allow_attempt(&exhausted, 1_000));
        }
        assert!(!limits.allow_attempt(&exhausted, 1_000));
        assert!(
            limits.allow_attempt(&fresh, 1_000),
            "another device's budget must be untouched"
        );
    }

    #[test]
    fn attempt_and_root_budgets_do_not_share_buckets() {
        let mut limits = SelfRevokeLimits::new();
        let same_fp = fp(b"same-fingerprint");
        // Exhaust the attempt budget keyed by this fingerprint; the root budget keyed by the very
        // same fingerprint must be independent.
        for _ in 0..SELF_REVOKE_ATTEMPT_BURST {
            assert!(limits.allow_attempt(&same_fp, 1_000));
        }
        assert!(!limits.allow_attempt(&same_fp, 1_000));
        assert!(limits.charge_root(&same_fp, 1_000));
    }

    // ---- semantics: union, replay, empty ----------------------------------------------------

    fn revoke_set(view: &mut InMemoryHelperView, root: &Fingerprint) -> HashSet<Fingerprint> {
        // `HelperView` exposes point lookups, so probe the handful of candidates these tests use.
        [
            b"device-a".as_slice(),
            b"device-b".as_slice(),
            b"device-c".as_slice(),
        ]
        .into_iter()
        .map(fp)
        .filter(|d| view.is_self_revoked(root, d))
        .collect()
    }

    #[test]
    fn two_deposits_union_their_subjects() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let root_fp = root_fp_of(&root.verifying_key());
        let nats_fp = fp(b"nats-union");
        put_member_session(&mut view, nats_fp, &root);
        let subject = subject_for(&nats_fp);

        let a = fp(b"device-a");
        let b = fp(b"device-b");
        assert!(
            deposit(
                &subject,
                &record_bytes(&root, 1, vec![a]),
                &mut view,
                &mut limiter,
                1_000
            )
            .ok
        );
        let second = deposit(
            &subject,
            &record_bytes(&root, 2, vec![b]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert!(second.ok);
        assert_eq!(second.epoch, Some(2));
        assert_eq!(revoke_set(&mut view, &root_fp), HashSet::from([a, b]));
    }

    #[test]
    fn a_lower_epoch_non_empty_deposit_still_unions_and_never_lowers_the_epoch() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let root_fp = root_fp_of(&root.verifying_key());
        let nats_fp = fp(b"nats-lower-epoch");
        put_member_session(&mut view, nats_fp, &root);
        let subject = subject_for(&nats_fp);

        let newer = fp(b"device-a");
        let older = fp(b"device-b");
        let first = deposit(
            &subject,
            &record_bytes(&root, 5, vec![newer]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert_eq!(first.epoch, Some(5));

        let second = deposit(
            &subject,
            &record_bytes(&root, 2, vec![older]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert!(
            second.ok,
            "a stale-epoch record must still be accepted: {second:?}"
        );
        assert_eq!(
            second.epoch,
            Some(5),
            "the reported epoch is the high-water mark"
        );
        assert_eq!(
            revoke_set(&mut view, &root_fp),
            HashSet::from([newer, older])
        );
    }

    #[test]
    fn an_empty_deposit_adds_nothing_and_does_not_clear_the_set() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let root_fp = root_fp_of(&root.verifying_key());
        let nats_fp = fp(b"nats-empty-revoked");
        put_member_session(&mut view, nats_fp, &root);
        let subject = subject_for(&nats_fp);

        let device = fp(b"device-a");
        assert!(
            deposit(
                &subject,
                &record_bytes(&root, 1, vec![device]),
                &mut view,
                &mut limiter,
                1_000
            )
            .ok
        );
        let empty = deposit(
            &subject,
            &record_bytes(&root, 2, vec![]),
            &mut view,
            &mut limiter,
            1_000,
        );

        assert!(empty.ok);
        assert_eq!(empty.epoch, Some(2));
        assert_eq!(
            revoke_set(&mut view, &root_fp),
            HashSet::from([device]),
            "an empty list is not an un-revoke instruction"
        );
    }

    #[test]
    fn replaying_the_same_record_is_idempotent() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let root_fp = root_fp_of(&root.verifying_key());
        let nats_fp = fp(b"nats-replay");
        put_member_session(&mut view, nats_fp, &root);
        let subject = subject_for(&nats_fp);
        let device = fp(b"device-a");
        let payload = record_bytes(&root, 4, vec![device]);

        let first = deposit(&subject, &payload, &mut view, &mut limiter, 1_000);
        let replay = deposit(&subject, &payload, &mut view, &mut limiter, 1_000);

        assert_eq!(first, replay);
        assert_eq!(replay.epoch, Some(4));
        assert_eq!(revoke_set(&mut view, &root_fp), HashSet::from([device]));
    }

    // ---- SelfRevokeResult::newly_revoked (what the caller kicks) ---------------------------

    #[test]
    fn a_fresh_record_reports_every_deduplicated_entry_in_first_seen_order() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let nats_fp = fp(b"nats-newly-revoked-fresh");
        put_member_session(&mut view, nats_fp, &root);
        let a = fp(b"device-a");
        let b = fp(b"device-b");

        // A duplicate is signed into the artifact on purpose: the reported set must be the
        // deduplicated one, and order must be first-seen, not `HashSet` iteration order.
        let result = deposit_result(
            &subject_for(&nats_fp),
            &record_bytes(&root, 1, vec![b, a, b]),
            &mut view,
            &mut limiter,
            1_000,
        );

        assert!(reply(&result.reply).ok, "record must be accepted");
        assert_eq!(result.newly_revoked, vec![b, a]);
    }

    #[test]
    fn a_replay_reports_nothing_newly_revoked() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let nats_fp = fp(b"nats-newly-revoked-replay");
        put_member_session(&mut view, nats_fp, &root);
        let subject = subject_for(&nats_fp);
        let device = fp(b"device-a");
        let payload = record_bytes(&root, 1, vec![device]);

        let first = deposit_result(&subject, &payload, &mut view, &mut limiter, 1_000);
        assert_eq!(first.newly_revoked, vec![device]);

        // The replay is the already-applied no-op branch: it must report nothing to kick, or every
        // redelivery would re-kick the same sessions.
        let replay = deposit_result(&subject, &payload, &mut view, &mut limiter, 1_000);
        assert!(reply(&replay.reply).ok);
        assert!(
            replay.newly_revoked.is_empty(),
            "an already-applied record must not re-report its entries: {replay:?}"
        );
    }

    #[test]
    fn a_partially_applied_record_reports_only_the_new_entries() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let nats_fp = fp(b"nats-newly-revoked-partial");
        put_member_session(&mut view, nats_fp, &root);
        let subject = subject_for(&nats_fp);
        let already = fp(b"device-a");
        let fresh = fp(b"device-b");

        let first = deposit_result(
            &subject,
            &record_bytes(&root, 1, vec![already]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert_eq!(first.newly_revoked, vec![already]);

        // `already` is in the union; only `fresh` is new. The union is monotone, so the second
        // record is still accepted and written — but only `fresh` may be kicked.
        let second = deposit_result(
            &subject,
            &record_bytes(&root, 2, vec![already, fresh]),
            &mut view,
            &mut limiter,
            1_000,
        );
        assert!(reply(&second.reply).ok);
        assert_eq!(second.newly_revoked, vec![fresh]);
    }

    #[test]
    fn an_empty_revoked_list_reports_nothing_newly_revoked() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let nats_fp = fp(b"nats-newly-revoked-empty");
        put_member_session(&mut view, nats_fp, &root);

        // Epoch 1 is above the absent high-water mark, so this is a state-changing write (it
        // charges a root token and writes), not the already-applied no-op — and still adds no
        // device, so there is nothing to kick.
        let result = deposit_result(
            &subject_for(&nats_fp),
            &record_bytes(&root, 1, vec![]),
            &mut view,
            &mut limiter,
            1_000,
        );

        let parsed = reply(&result.reply);
        assert!(parsed.ok);
        assert_eq!(parsed.epoch, Some(1), "the empty record itself was written");
        assert!(result.newly_revoked.is_empty());
    }

    #[test]
    fn a_rejected_record_reports_nothing_newly_revoked() {
        let mut view = store();
        let mut limiter = SelfRevokeLimits::new();
        let root = root_signer();
        let nats_fp = fp(b"nats-newly-revoked-rejected");
        put_member_session(&mut view, nats_fp, &root);
        let mut tampered = issue_self_revocation(&root, 1, vec![fp(b"victim")], 1_000);
        tampered.sig_root[0] ^= 0xff;

        let result = deposit_result(
            &subject_for(&nats_fp),
            &tampered.to_canonical_bytes(),
            &mut view,
            &mut limiter,
            1_000,
        );

        assert!(!reply(&result.reply).ok);
        assert!(
            result.newly_revoked.is_empty(),
            "a rejected record applied nothing, so it must kick nothing: {result:?}"
        );
    }

    // ---- parse_subject_nats_fp ---------------------------------------------------------------

    #[test]
    fn parse_subject_round_trips_a_fingerprint() {
        let nats_fp = fp(b"nats-self-rev-parse");
        assert_eq!(parse_subject_nats_fp(&subject_for(&nats_fp)), Some(nats_fp));
    }

    #[test]
    fn parse_subject_rejects_wrong_prefix_or_empty_token() {
        let nats_fp = fp(b"nats-self-rev-wrong");
        assert_eq!(parse_subject_nats_fp("helper.revoke"), None);
        assert_eq!(
            parse_subject_nats_fp(&format!("helper.turn.get.{nats_fp}")),
            None
        );
        assert_eq!(parse_subject_nats_fp("helper.revoke."), None);
    }
}
