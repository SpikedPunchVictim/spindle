//! Kick relay — leg 3 of DESIGN.md §A4's revoke -> kick -> reject chain (S9). Follows
//! `presence.rs`/`turn.rs`/`revoke.rs`'s shape exactly: pure/NATS-free, no `async-nats` type
//! appears anywhere in this module's API — `src/bin/helper.rs` is the only place a
//! `$SYS.REQ.SERVER.<id>.KICK` request is actually sent.
//!
//! # Wire mechanics this module assumes (measured, not designed here)
//! `spikes/s9-revoke-kick/RESULTS.md` (commit `bc4f2bb`) pinned down the mechanics DESIGN.md
//! §A4 got wrong on paper: the subject is `$SYS.REQ.SERVER.<server_id>.KICK` (there is **no**
//! `PING.KICK` broadcast form — a concrete `server_id` is always required), the payload field is
//! `cid` (not `id`), and — most importantly — **a reply arrives either way**: a failed kick still
//! gets a reply (an error object), not a transport failure, so "got a reply" is never proof of a
//! kick. This module only computes *what* to kick ([`KickTarget`]s); actually sending the
//! request and checking the reply for an `error` key (not any positive success marker — there
//! isn't one, per RESULTS.md §4) is `src/bin/helper.rs`'s job, exactly like every other
//! subscribe/publish in this crate.
//!
//! # `KickMap` is keyed by `Fingerprint` (`nats_fp`), not the raw nkey string [deliberate,
//! opposite of `presence::ConnectionMap`]
//! `presence::ConnectionMap::user_to_host` is deliberately keyed by the raw nkey **string** —
//! its own doc comment explains why: `$SYS` events and CONNZ rows hand back the nkey as a string,
//! so registering/looking it up that way needs no decoding on that module's hot path (every
//! CONNECT/DISCONNECT event and every `helper.presence.get.<nfp>` snapshot).
//!
//! [`KickMap`] inverts that choice on purpose, because its hot path is different: it is never
//! looked up from a raw event string. It is looked up from [`crate::session::SessionRecord::nats_fp`]
//! — an already-decoded [`Fingerprint`] handed back by
//! [`crate::authz::HelperView::sessions_for_subject`] — once per session, per revocation, not once
//! per `$SYS` event. Keying by the raw nkey string here would just mean re-encoding a
//! [`Fingerprint`] back to a string (or storing a second nkey-string field on every
//! [`crate::session::SessionRecord`]) purely to decode it right back on the very next line. Keying
//! by [`Fingerprint`] instead means CONNECT/DISCONNECT ingestion pays one decode
//! ([`crate::auth_token::nats_fp_of_nkey`], the same call `presence.rs`'s own module doc says the
//! callout and `seed_presence_map` already make at connect time) and every subsequent lookup is a
//! plain hash-map hit — the opposite trade of `presence.rs`'s map, made because the two maps are
//! read from opposite directions.
//!
//! # Reconnect: a stale DISCONNECT must not evict a newer connection [deliberate]
//! A revoked identity's session nkey can be reused across a reconnect (unlike `presence.rs`'s
//! host-key reconnect case, a client session's `nats_fp` is stable for the life of its cert, so a
//! clean reconnect keeps the *same* `nats_fp`) — meaning [`KickMap::connect`] can be called twice
//! for the same [`Fingerprint`] with two different `cid`s before the first connection's own
//! `DISCONNECT` event is processed (the exact "CONNECT before stale DISCONNECT" ordering
//! `presence.rs`'s module doc names for its own map). If [`KickMap::disconnect`] removed the
//! entry unconditionally, that stale DISCONNECT would evict the *new* connection's live
//! coordinates, leaving a revoked-and-still-connected session unkickable until its next CONNECT.
//!
//! [`KickMap::connect`] therefore always overwrites with the newest `(server_id, cid)` — last
//! writer wins, matching "kick relay is one-to-many per identity ... reconnect overlap ... never
//! flips a live host offline" (DESIGN.md §A6, the same principle applied here to connection
//! coordinates instead of a presence count) — and [`KickMap::disconnect`] only removes the entry
//! if the `cid` it's asked to remove still matches the currently stored `cid`. A disconnect for a
//! `cid` that's already been superseded by a newer connection is a no-op, not an eviction.
//!
//! # Key shape: `Fingerprint -> (server_id, cid)`, not `device_fp -> (server_id, cid)`
//! [DESIGN.md §A3 deviation, flagged not silently resolved]
//! DESIGN.md §A3/§A6 describe the kick relay's key as `device_fp -> (server_id, cid)`,
//! "one-to-many per `device_fp`". This module keys by `nats_fp` instead. The two are equivalent
//! for what this relay actually needs: [`kicks_for_revocation`] already gets its fan-out (one
//! revoked subject -> many live sessions) from
//! [`crate::authz::HelperView::sessions_for_subject`], which returns one
//! [`crate::session::SessionRecord`] *per live connection*, each carrying its own `nats_fp`
//! (DESIGN.md §A5's session record — v0.9.18 added `device_fp` to that record specifically so
//! this resolution step could exist at all). Keying the connection map itself by `nats_fp` rather
//! than `device_fp` means a device with two simultaneous connections (§A6: "multiple connections
//! per identity are normal — native app + browser tab") naturally gets two independent map
//! entries and two independent kicks, with no multimap needed — `nats_fp` is already
//! one-per-connection, where `device_fp` is one-per-device. The one-to-many-per-`device_fp`
//! behavior DESIGN.md describes falls out of `sessions_for_subject` returning multiple session
//! records for the same `device_fp` (or `root_fp`), not out of this map's own key shape.
//!
//! # Out of scope (DESIGN.md items this module deliberately does not implement)
//! **CONNZ seeding is implemented, but entirely on `src/bin/helper.rs`'s side of this module's
//! boundary.** `seed_maps` (renamed from `seed_presence_map` when this graduated) backfills BOTH
//! `presence::ConnectionMap` and [`KickMap`] from the same startup `$SYS.REQ.SERVER.PING.CONNZ`
//! reply, so a connection that predates this helper process is kickable immediately rather than
//! only after its next CONNECT. This module has no code of its own for that: `seed_maps` seeds
//! [`KickMap`] by calling [`KickMap::connect`] per CONNZ row, the exact same public entry point a
//! live `$SYS.ACCOUNT.*.CONNECT` event already uses — CONNZ seeding is a second *feed* into this
//! map's existing API, not new logic inside it. A miss a delayed re-plan still can't resolve (see
//! [`KickPlan`]'s doc comment on why `unresolved` names sessions, not just counts) falls back to a
//! second, on-demand CONNZ request (`src/bin/helper.rs`'s `connz_kick_fallback`) for the same
//! reason — still wiring, still on the other side of the boundary this file's opening section
//! describes.
//!
//! **Actually sending the KICK request.** See this module doc's opening section — that, and
//! parsing the reply for an `error` key, is `src/bin/helper.rs`'s job entirely.

use spindle_core::Fingerprint;
use std::collections::HashMap;

use crate::auth_token::nats_fp_of_nkey;
use crate::authz::HelperView;

/// One live connection's kick coordinates, and which revoked subject led to it. Carries enough
/// to both issue the `$SYS.REQ.SERVER.<server_id>.KICK` request and write a useful log line —
/// `src/bin/helper.rs`'s only job with a value of this type is exactly those two things.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KickTarget {
    /// `server.id` from the CONNECT event that registered this connection — the concrete server
    /// id `$SYS.REQ.SERVER.<server_id>.KICK` requires (there is no broadcast form, see the module
    /// doc).
    pub server_id: String,
    /// `client.id` from the same CONNECT event — the `cid` the KICK payload names.
    pub cid: u64,
    /// The connection's own `nats_fp`, for the log line.
    pub nats_fp: Fingerprint,
    /// Which entry of the revocation's `revoked` list resolved to this connection (a `root_fp` or
    /// a `device_fp`). When both a root and one of its devices resolve to the *same* connection
    /// (the de-dup case [`kicks_for_revocation`] handles), this is whichever entry was processed
    /// first — see that function's doc comment.
    pub matched_subject: Fingerprint,
}

/// One session [`kicks_for_revocation`] matched to a revoked subject but found no live entry for
/// in the [`KickMap`] snapshot it was given — see [`KickPlan`]'s doc comment for why this is
/// carried as an identity, not folded into a bare count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedSession {
    /// The connection's own `nats_fp` — same meaning as [`KickTarget::nats_fp`], and what
    /// [`KickMap::target_for`] re-looks-up on a retry.
    pub nats_fp: Fingerprint,
    /// Which entry of the revocation's `revoked` list resolved to this session — same meaning as
    /// [`KickTarget::matched_subject`], carried forward so a retry that later succeeds can still
    /// log which revoked subject drove it.
    pub matched_subject: Fingerprint,
}

/// The outcome of planning kicks for one accepted revocation: the connections to actually kick,
/// plus the sessions that matched but had no live entry in the map at that moment.
/// **Deliberately not just `Vec<KickTarget>`**: a session record can outlive the connection it
/// describes (DISCONNECT hasn't been processed yet, or never will be — a crash dropped the TCP
/// connection without an advisory), and silently dropping that fact entirely would make "nobody
/// was live to kick" indistinguishable from "everybody who should have been kicked, was" — the
/// same false-green class this crate treats as severity zero (see `revoke.rs`'s and
/// `spikes/s9-revoke-kick/RESULTS.md`'s own framing of that concern).
///
/// `unresolved` names *which* sessions missed, not merely how many, because a miss produced by
/// this function is not necessarily permanent. DESIGN.md §A4's revoke -> kick -> reject chain runs
/// advisories (`$SYS.ACCOUNT.*.CONNECT`/`.DISCONNECT`) and revocations (`registry.revoke.<hfp>`)
/// over two independent connections (`sys_client` and `app_client`), so a CONNECT advisory that
/// simply hasn't been drained into the [`KickMap`] yet produces the exact same "no live entry"
/// shape this type reports for a connection that is genuinely gone. Carrying the identity — not
/// just a count — lets `src/bin/helper.rs` retry those specific sessions against the map's later
/// state via [`KickMap::target_for`], instead of only logging that some number of kicks silently
/// didn't happen.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KickPlan {
    /// Targets to kick, already de-duplicated by connection (see [`kicks_for_revocation`]).
    pub targets: Vec<KickTarget>,
    /// Sessions [`crate::authz::HelperView::sessions_for_subject`] matched that had no live entry
    /// in the [`KickMap`] at all — not kicked, but named rather than silently dropped, so a caller
    /// can retry them (see this struct's doc comment).
    pub unresolved: Vec<UnresolvedSession>,
}

/// The broker helper's kick-relay connection map (DESIGN.md §A3, S9). Pure/NATS-free, following
/// `presence.rs`/`revoke.rs`'s pattern: `src/bin/helper.rs` feeds it `$SYS.ACCOUNT.*.
/// CONNECT|DISCONNECT` events; this type only tracks `nats_fp -> (server_id, cid)` and decides
/// which entry a lookup resolves to — no NATS type appears anywhere in its API. See the module
/// doc for why this is keyed by [`Fingerprint`] (opposite of `presence::ConnectionMap`'s raw
/// nkey-string key) and how reconnects are handled.
#[derive(Debug, Default)]
pub struct KickMap {
    conns: HashMap<Fingerprint, (String, u64)>,
}

impl KickMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records (or overwrites) the live kick coordinates for whichever `nats_fp` `user_pk`
    /// decodes to. A `user_pk` that doesn't decode as a valid nkey is silently ignored — the same
    /// tolerance `presence::ConnectionMap`'s callers already apply to malformed `$SYS` events;
    /// this map has no reply subject of its own to report a decode failure on.
    ///
    /// Always overwrites, even if `nats_fp` already has an entry — see the module doc's
    /// "Reconnect" section: a reconnect under the same `nats_fp` produces a new CONNECT with a
    /// new `cid`, and the newest coordinates are always the ones a KICK should target.
    pub fn connect(&mut self, user_pk: &str, server_id: impl Into<String>, cid: u64) {
        let Ok(nats_fp) = nats_fp_of_nkey(user_pk) else {
            return;
        };
        self.conns.insert(nats_fp, (server_id.into(), cid));
    }

    /// Removes the live kick coordinates for whichever `nats_fp` `user_pk` decodes to, **only
    /// if** the currently stored `cid` for it still equals `cid` — see the module doc's
    /// "Reconnect" section for why an unconditional removal here would be wrong. A `user_pk` that
    /// doesn't decode, or a `nats_fp` with no entry, or an entry whose stored `cid` no longer
    /// matches (already superseded by a newer connection), are all silent no-ops.
    pub fn disconnect(&mut self, user_pk: &str, cid: u64) {
        let Ok(nats_fp) = nats_fp_of_nkey(user_pk) else {
            return;
        };
        if let std::collections::hash_map::Entry::Occupied(entry) = self.conns.entry(nats_fp) {
            if entry.get().1 == cid {
                entry.remove();
            }
        }
    }

    /// The live `(server_id, cid)` for `nats_fp`, if this map has one.
    fn lookup(&self, nats_fp: &Fingerprint) -> Option<(&str, u64)> {
        self.conns
            .get(nats_fp)
            .map(|(sid, cid)| (sid.as_str(), *cid))
    }

    /// Re-resolves one [`UnresolvedSession`] against this map's *current* state. Public (unlike
    /// [`Self::lookup`]) because it is `src/bin/helper.rs`'s entry point for a delayed re-plan: a
    /// [`KickPlan::unresolved`] entry recorded a miss against an earlier snapshot of this map, and
    /// by the time the retry runs (`KICK_REPLAN_DELAY` later, per that file's doc comment) a
    /// queued CONNECT advisory that raced the original revocation may since have landed. Returns
    /// `None` if the session is still not live here — the caller's next move at that point is the
    /// CONNZ fallback ([`crate::kick`]'s module doc, "Out of scope"), not another retry of this
    /// same map.
    pub fn target_for(&self, unresolved: &UnresolvedSession) -> Option<KickTarget> {
        let (server_id, cid) = self.lookup(&unresolved.nats_fp)?;
        Some(KickTarget {
            server_id: server_id.to_string(),
            cid,
            nats_fp: unresolved.nats_fp,
            matched_subject: unresolved.matched_subject,
        })
    }
}

/// Computes the [`KickTarget`]s an accepted revocation (`revoked` — the record's own `revoked`
/// list, a mix of `root_fp`s and `device_fp`s per DESIGN.md §A4) must reach: for each revoked
/// subject, resolves every live session via
/// [`crate::authz::HelperView::sessions_for_subject`], then resolves each session's `nats_fp`
/// through `map`. Pure with respect to NATS — `src/bin/helper.rs` is the only caller that ever
/// sends the actual KICK request.
///
/// **De-duplication**: a `root_fp` and one of its own `device_fp`s can both appear in the same
/// revocation's `revoked` list (e.g. a full account revocation revokes the root and every device
/// individually) and both resolve to the *same* live session (same `nats_fp`) — that connection
/// must be kicked exactly once. This function tracks every `nats_fp` it has already produced a
/// decision for (kicked or not) and skips it on a later match, so the first revoked-subject entry
/// to reach a given connection is the one credited as `matched_subject` on its [`KickTarget`],
/// and a connection with no live map entry is only ever pushed once into
/// [`KickPlan::unresolved`], not once per revoked subject that happened to resolve to it.
pub fn kicks_for_revocation(
    revoked: &[Fingerprint],
    map: &KickMap,
    view: &mut impl HelperView,
    now: u64,
) -> KickPlan {
    let mut seen = std::collections::HashSet::new();
    let mut plan = KickPlan::default();

    for subject in revoked {
        for session in view.sessions_for_subject(subject, now) {
            if !seen.insert(session.nats_fp) {
                // Already resolved via an earlier revoked subject in this same batch — kick (or
                // count) this connection once, not once per matching subject.
                continue;
            }
            match map.lookup(&session.nats_fp) {
                Some((server_id, cid)) => plan.targets.push(KickTarget {
                    server_id: server_id.to_string(),
                    cid,
                    nats_fp: session.nats_fp,
                    matched_subject: *subject,
                }),
                None => plan.unresolved.push(UnresolvedSession {
                    nats_fp: session.nats_fp,
                    matched_subject: *subject,
                }),
            }
        }
    }

    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::AdmissionMode;
    use crate::memory_store::InMemoryHelperView;
    use crate::session::SessionRecord;
    use spindle_core::SigningKey;

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_parts(&[seed])
    }

    fn store() -> InMemoryHelperView {
        InMemoryHelperView::new(
            AdmissionMode::Open,
            SigningKey::from_bytes(&[0x66; 32]).verifying_key(),
        )
    }

    /// A throwaway nkey keypair's public-key string, for feeding `KickMap::connect`/`disconnect`
    /// (which — like the real `$SYS` events they model — take the nkey pubkey string, not a
    /// [`Fingerprint`] directly). Each call yields a distinct, freshly-generated keypair.
    fn nkey_pk() -> String {
        nkeys::KeyPair::new_user().public_key()
    }

    fn put_session(
        s: &mut InMemoryHelperView,
        nats_fp: Fingerprint,
        root_fp: Fingerprint,
        device_fp: Option<Fingerprint>,
        exp: u64,
    ) {
        s.put_session_record(SessionRecord::new(
            nats_fp,
            root_fp,
            device_fp,
            vec![],
            "member".to_string(),
            exp,
        ));
    }

    // ---- KickMap: connect / disconnect / reconnect -----------------------------------------

    #[test]
    fn connect_then_lookup_round_trips() {
        let mut map = KickMap::new();
        let user_pk = nkey_pk();
        let nats_fp = nats_fp_of_nkey(&user_pk).unwrap();
        map.connect(&user_pk, "server-1", 42);
        assert_eq!(map.lookup(&nats_fp), Some(("server-1", 42)));
    }

    #[test]
    fn malformed_user_pk_is_ignored_on_connect_and_disconnect() {
        let mut map = KickMap::new();
        map.connect("not-an-nkey", "server-1", 1);
        assert!(map.conns.is_empty());
        map.disconnect("not-an-nkey", 1); // must not panic
    }

    #[test]
    fn disconnect_removes_the_matching_cid() {
        let mut map = KickMap::new();
        let user_pk = nkey_pk();
        let nats_fp = nats_fp_of_nkey(&user_pk).unwrap();
        map.connect(&user_pk, "server-1", 7);
        map.disconnect(&user_pk, 7);
        assert_eq!(map.lookup(&nats_fp), None);
    }

    #[test]
    fn reconnect_then_stale_disconnect_does_not_evict_the_new_connection() {
        // Same nats_fp (same nkey reused across a reconnect), new cid — then the OLD cid's
        // DISCONNECT arrives late.
        let mut map = KickMap::new();
        let user_pk = nkey_pk();
        let nats_fp = nats_fp_of_nkey(&user_pk).unwrap();

        map.connect(&user_pk, "server-1", 100); // old connection
        map.connect(&user_pk, "server-1", 200); // reconnect: new cid, overwrites

        map.disconnect(&user_pk, 100); // stale DISCONNECT for the OLD cid

        assert_eq!(
            map.lookup(&nats_fp),
            Some(("server-1", 200)),
            "the newer connection's coordinates must survive a stale disconnect for the old cid"
        );
    }

    #[test]
    fn disconnect_for_the_current_cid_after_reconnect_still_removes_it() {
        let mut map = KickMap::new();
        let user_pk = nkey_pk();
        let nats_fp = nats_fp_of_nkey(&user_pk).unwrap();

        map.connect(&user_pk, "server-1", 100);
        map.connect(&user_pk, "server-1", 200);
        map.disconnect(&user_pk, 200);

        assert_eq!(map.lookup(&nats_fp), None);
    }

    // ---- kicks_for_revocation ---------------------------------------------------------------

    #[test]
    fn revoked_root_with_one_live_device_session_yields_one_target() {
        let mut s = store();
        let mut map = KickMap::new();
        let root_fp = fp(b"root-one-device");
        let device_fp = fp(b"device-one");
        let nats_fp = fp(b"nats-one-device");
        put_session(&mut s, nats_fp, root_fp, Some(device_fp), 10_000);

        // `kicks_for_revocation` looks the session's own `nats_fp` up in the map directly — no
        // nkey string is involved at this layer (see the module doc's key-shape section), so
        // these tests populate `KickMap` at its own granularity rather than round-tripping
        // through a throwaway nkey.
        map.conns.insert(nats_fp, ("server-a".to_string(), 111));

        let plan = kicks_for_revocation(&[root_fp], &map, &mut s, 1_000);

        assert_eq!(plan.targets.len(), 1);
        assert_eq!(plan.targets[0].server_id, "server-a");
        assert_eq!(plan.targets[0].cid, 111);
        assert_eq!(plan.targets[0].nats_fp, nats_fp);
        assert_eq!(plan.targets[0].matched_subject, root_fp);
        assert_eq!(plan.unresolved.len(), 0);
    }

    #[test]
    fn revoked_root_with_two_live_device_sessions_yields_two_targets() {
        let mut s = store();
        let mut map = KickMap::new();
        let root_fp = fp(b"root-two-devices");
        let nats_fp_a = fp(b"nats-device-a");
        let nats_fp_b = fp(b"nats-device-b");
        put_session(&mut s, nats_fp_a, root_fp, Some(fp(b"device-a")), 10_000);
        put_session(&mut s, nats_fp_b, root_fp, Some(fp(b"device-b")), 10_000);
        map.conns.insert(nats_fp_a, ("server-a".to_string(), 1));
        map.conns.insert(nats_fp_b, ("server-a".to_string(), 2));

        let plan = kicks_for_revocation(&[root_fp], &map, &mut s, 1_000);

        assert_eq!(
            plan.targets.len(),
            2,
            "revoking a person must reach all their devices"
        );
        let nats_fps: std::collections::HashSet<_> =
            plan.targets.iter().map(|t| t.nats_fp).collect();
        assert!(nats_fps.contains(&nats_fp_a));
        assert!(nats_fps.contains(&nats_fp_b));
        assert_eq!(plan.unresolved.len(), 0);
    }

    #[test]
    fn revoked_device_fp_yields_only_that_devices_target() {
        let mut s = store();
        let mut map = KickMap::new();
        let root_fp = fp(b"root-shared");
        let device_a = fp(b"device-target");
        let device_b = fp(b"device-sibling");
        let nats_fp_a = fp(b"nats-target");
        let nats_fp_b = fp(b"nats-sibling");
        put_session(&mut s, nats_fp_a, root_fp, Some(device_a), 10_000);
        put_session(&mut s, nats_fp_b, root_fp, Some(device_b), 10_000);
        map.conns.insert(nats_fp_a, ("server-a".to_string(), 1));
        map.conns.insert(nats_fp_b, ("server-a".to_string(), 2));

        let plan = kicks_for_revocation(&[device_a], &map, &mut s, 1_000);

        assert_eq!(plan.targets.len(), 1);
        assert_eq!(plan.targets[0].nats_fp, nats_fp_a);
        assert_eq!(
            plan.unresolved.len(),
            0,
            "the sibling session was never matched at all, not matched-and-skipped"
        );
    }

    #[test]
    fn session_with_no_connection_yields_no_target_and_does_not_panic() {
        let mut s = store();
        let map = KickMap::new();
        let root_fp = fp(b"root-no-conn");
        let nats_fp = fp(b"nats-no-conn");
        put_session(
            &mut s,
            nats_fp,
            root_fp,
            Some(fp(b"device-no-conn")),
            10_000,
        );

        let plan = kicks_for_revocation(&[root_fp], &map, &mut s, 1_000);

        assert!(plan.targets.is_empty());
        assert_eq!(plan.unresolved.len(), 1);
        assert_eq!(
            plan.unresolved[0],
            UnresolvedSession {
                nats_fp,
                matched_subject: root_fp,
            },
            "unresolved must name the exact session and the revoked subject that reached it, not \
             just count it"
        );
    }

    #[test]
    fn dedup_root_and_its_own_device_in_one_revocation_yields_one_target() {
        let mut s = store();
        let mut map = KickMap::new();
        let root_fp = fp(b"root-dedup");
        let device_fp = fp(b"device-dedup");
        let nats_fp = fp(b"nats-dedup");
        put_session(&mut s, nats_fp, root_fp, Some(device_fp), 10_000);
        map.conns.insert(nats_fp, ("server-a".to_string(), 55));

        // Revoking BOTH the root and one of its devices in the same record.
        let plan = kicks_for_revocation(&[root_fp, device_fp], &map, &mut s, 1_000);

        assert_eq!(
            plan.targets.len(),
            1,
            "the shared session must be kicked once, not once per matching revoked subject"
        );
        assert_eq!(plan.targets[0].nats_fp, nats_fp);
        assert_eq!(
            plan.targets[0].matched_subject, root_fp,
            "the first revoked-subject entry to reach this connection is credited"
        );
    }

    #[test]
    fn map_removal_on_disconnect_means_a_later_revocation_yields_no_target() {
        let mut s = store();
        let mut map = KickMap::new();
        let root_fp = fp(b"root-post-disconnect");
        let nats_fp = fp(b"nats-post-disconnect");
        put_session(
            &mut s,
            nats_fp,
            root_fp,
            Some(fp(b"device-post-disconnect")),
            10_000,
        );
        map.conns.insert(nats_fp, ("server-a".to_string(), 9));
        map.conns.remove(&nats_fp); // simulates the DISCONNECT-driven removal

        let plan = kicks_for_revocation(&[root_fp], &map, &mut s, 1_000);

        assert!(plan.targets.is_empty());
        assert_eq!(plan.unresolved.len(), 1);
        assert_eq!(plan.unresolved[0].nats_fp, nats_fp);
        assert_eq!(plan.unresolved[0].matched_subject, root_fp);
    }

    // ---- KickMap::target_for -----------------------------------------------------------------

    #[test]
    fn target_for_resolves_once_the_map_gains_an_entry() {
        // Models the delayed-re-plan case this type exists for (see `KickPlan`'s doc comment): a
        // session was unresolved against an earlier map snapshot, but by the time a retry runs,
        // the connection has since been armed (a queued CONNECT advisory finally drained in).
        let mut map = KickMap::new();
        let nats_fp = fp(b"nats-retry-hit");
        let root_fp = fp(b"root-retry-hit");
        let unresolved = UnresolvedSession {
            nats_fp,
            matched_subject: root_fp,
        };

        assert_eq!(map.target_for(&unresolved), None, "not armed yet");

        map.conns.insert(nats_fp, ("server-a".to_string(), 77));

        assert_eq!(
            map.target_for(&unresolved),
            Some(KickTarget {
                server_id: "server-a".to_string(),
                cid: 77,
                nats_fp,
                matched_subject: root_fp,
            })
        );
    }

    #[test]
    fn target_for_stays_none_when_the_map_never_gains_an_entry() {
        let map = KickMap::new();
        let unresolved = UnresolvedSession {
            nats_fp: fp(b"nats-retry-miss"),
            matched_subject: fp(b"root-retry-miss"),
        };
        assert_eq!(map.target_for(&unresolved), None);
    }
}
