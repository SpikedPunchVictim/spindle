//! Live connection map + `helper.presence.get.<nfp>` handler (DESIGN.md §A3/§A5/§A6; §A9's UX
//! bar additionally names an `unresponsive` state — see below for why this module doesn't track
//! it). Subject parametrized the same way `helper.turn.get.<nfp>` was in v0.9.7 (A12 #45): caller
//! identity is the subject token the callout granted, never a request-body field. Pending doc
//! amendment (v0.9.8) parametrizes `helper.presence.get` identically; this module is written
//! against that target shape per the task brief, not against the not-yet-amended `docs/DESIGN.md`
//! text as of this writing.
//!
//! # Connection count, not a boolean (§A6)
//! "Multiple connections per identity are normal (native app + browser tab) ... presence is by
//! connection count, not a boolean, and reconnect overlap (CONNECT before stale DISCONNECT) never
//! flips a live host to offline." [`ConnectionMap`] tracks one `u32` count per `host_fp`: every
//! `CONNECT` for a *registered* NATS user increments it, every `DISCONNECT` decrements it
//! (saturating at zero), and a host is `online` iff its count is `> 0`. A host that reconnects
//! with a fresh session nkey (a new NATS user, re-registered via [`ConnectionMap::register_host_user`]
//! at the next successful host-auth) increments the count for its *existing* `host_fp` under a
//! *different* user key — so the stale connection's later `DISCONNECT` only decrements the count
//! by one, never enough to reach zero while the new connection is still up. This is what makes
//! reconnect overlap safe without tracking individual connection IDs at all.
//!
//! # `unresponsive` is not this module's job
//! DESIGN.md §A6/§A9 name three UI states: online, offline, unresponsive (a dead-but-not-yet-
//! disconnected socket, caught by the server's own `ping_interval`/`ping_max` and surfaced to us
//! as an ordinary `DISCONNECT` event once the server gives up — "`ping_interval` ~20s / `ping_max`
//! 2 so a dead socket flips ≤ ~60s"). Nothing about that is this map's concern: by the time we
//! ever hear about a dead socket, the server has already turned it into a `DISCONNECT`, which
//! this map handles exactly like a clean one. `unresponsive` is purely a *client-side* UI
//! affordance (showing "last seen Ns ago" instead of a hard offline before the server's own
//! timeout fires) — nothing server-side to build here. Hence: this module only ever reports
//! `online`/`offline` + `last_seen`, never a third state.
//!
//! # Wire schema (invented, following `turn.rs`'s precedent for an unspecified request/reply
//! shape — DESIGN.md §A5/§A6 say a request/reply snapshot and a push-delta exist, and the delta's
//! JSON shape (`{host_fp, state, last_seen}`), but not the snapshot reply's own envelope)
//! ```text
//! subject:   helper.presence.get.<nfp>   (nfp = base32 Display of the caller's session-nkey
//!                                          fingerprint — same encoding, same parsing rules, as
//!                                          `helper.turn.get.<nfp>`; see permissions.rs's module
//!                                          doc and turn.rs's doc comment)
//! request:   (no payload is read at all — identity is 100% the subject token; unlike
//!             `helper.turn.get.<nfp>`, this subject never had a payload-borne identity field to
//!             stay tolerant of, so `handle_presence_get` doesn't take a payload parameter)
//! reply ok:  { "ok": true, "hosts": [ {"host_fp": "<base32>", "state": "online"|"offline",
//!               "last_seen": <unix secs> | null}, ... ] }   (one entry per host_fp in the
//!               caller's session record, in that order; a host_fp this helper process has never
//!               seen a connection for is reported offline with last_seen: null)
//! reply err: { "ok": false, "error": "<human-readable reason>" }
//! ```
//! **Delta payload** on `host.<hfp>.presence` (DESIGN.md §A6, verbatim: "push deltas `{host_fp,
//! state, last_seen}` only") is exactly one [`PresenceEntry`] — the same shape as one element of
//! the snapshot reply's `hosts` array, published standalone rather than wrapped in an envelope.
//! Pushed only when a host's state actually flips (see [`ConnectionMap::connect`]/
//! [`ConnectionMap::disconnect`]'s doc comments) — `src/bin/helper.rs` is the only caller that
//! touches an actual NATS publish; this module just computes the delta.
//!
//! # Out of scope (DESIGN.md items this module deliberately does not implement)
//! Kick relay (§A3) — now implemented, see [`crate::kick`] (keyed by `nats_fp`, not `device_fp`;
//! that module's own doc comment explains the deviation from §A3's literal key shape); the "two
//! daemons with the same restored host key" split-brain newest-wins policy (§A6); multi-server
//! `CONNZ` reply aggregation (§A6
//! defers this explicitly — "confirmed by S1's negative-test suite" language aside, HA is S8's
//! job, and `src/bin/helper.rs`'s CONNZ-seeding step takes only the first reply); leader-only
//! delta publishing (A10.23 — today there is exactly one helper binary, so every helper instance
//! publishing its own deltas is a non-issue until HA lands).

use serde::{Deserialize, Serialize};
use spindle_core::Fingerprint;
use std::collections::HashMap;

use crate::authz::HelperView;

/// `helper.presence.get.` — the subject prefix; `<nfp>` follows as the final subject token
/// (exactly the same shape as `turn.rs`'s `helper.turn.get.` prefix).
const SUBJECT_PREFIX: &str = "helper.presence.get.";

/// One host's live-connection bookkeeping.
#[derive(Debug, Clone, Copy)]
struct HostState {
    /// Live connection count for this `host_fp` (§A6: "presence is by connection count").
    count: u32,
    /// Unix seconds of the most recent CONNECT or DISCONNECT this map processed for this host
    /// (whichever was later) — reported verbatim in both snapshots and deltas.
    last_seen: u64,
}

impl HostState {
    fn is_online(&self) -> bool {
        self.count > 0
    }
}

/// `online`/`offline` only — see the module doc for why `unresponsive` isn't tracked here.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PresenceState {
    Online,
    Offline,
}

/// One host's reported presence — identical shape whether it's an element of a
/// `helper.presence.get.<nfp>` snapshot's `hosts` array or a standalone `host.<hfp>.presence`
/// delta payload (DESIGN.md §A6: "push deltas `{host_fp, state, last_seen}` only").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceEntry {
    pub host_fp: String,
    pub state: PresenceState,
    pub last_seen: Option<u64>,
}

/// A `host.<hfp>.presence` delta: [`ConnectionMap::connect`]/[`ConnectionMap::disconnect`] return
/// one of these only when the host's state actually flipped. `host_fp` is carried both as the
/// typed [`Fingerprint`] (so `src/bin/helper.rs` can build the `host.<hfp>.presence` subject
/// string) and, redundantly, inside `entry` as the base32 string the wire payload actually needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceDelta {
    pub host_fp: Fingerprint,
    pub entry: PresenceEntry,
}

fn entry_for(host_fp: &Fingerprint, state: PresenceState, last_seen: Option<u64>) -> PresenceEntry {
    PresenceEntry {
        host_fp: host_fp.to_string(),
        state,
        last_seen,
    }
}

/// The broker helper's live connection map (DESIGN.md §A3/§A6). Pure/NATS-free, following
/// `turn.rs`'s pattern: `src/bin/helper.rs` feeds it CONNZ snapshot rows and `$SYS.ACCOUNT.*.
/// CONNECT|DISCONNECT` events; this type only tracks state and computes deltas — no NATS type
/// appears anywhere in its API.
#[derive(Debug, Default)]
pub struct ConnectionMap {
    /// NATS user identity (the session nkey **public-key string** the callout issued the user
    /// JWT for — i.e. `connect_opts.nkey`/`client_info.user` in this codebase's own terms, the
    /// same string `$SYS.ACCOUNT.*.CONNECT|DISCONNECT` events and `CONNZ` rows report back as
    /// `client.user`) -> `host_fp`, registered once per connection at host-auth time
    /// ([`ConnectionMap::register_host_user`]). Deliberately keyed by the raw nkey string, not a
    /// [`Fingerprint`] — that's the identity `$SYS` events hand back, so looking it up needs no
    /// decoding on the hot path.
    ///
    /// A device's or the helper's own connection's user is never registered here, so their
    /// CONNECT/DISCONNECT events are silently ignored by [`connect`](Self::connect)/
    /// [`disconnect`](Self::disconnect) (a plain `HashMap` miss) — presence only exists for
    /// hosts (DESIGN.md §A6 talks about "host list" presence throughout; devices have no
    /// equivalent subject to push to).
    user_to_host: HashMap<String, Fingerprint>,
    hosts: HashMap<Fingerprint, HostState>,
}

impl ConnectionMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds `user_pk` (this connection's session-nkey public-key string) to `host_fp` for the
    /// lifetime of the map (or until re-registered). Called once per successful host-auth
    /// (`decide_host_connect` authorizing a connection) — the callout is the only place that
    /// knows both facts at once. Idempotent: registering the same `user_pk` again just overwrites
    /// the mapping (harmless — a host never changes its own `host_fp` mid-connection).
    pub fn register_host_user(&mut self, user_pk: impl Into<String>, host_fp: Fingerprint) {
        self.user_to_host.insert(user_pk.into(), host_fp);
    }

    /// Records one more live connection for whichever `host_fp` `user_pk` is registered to.
    /// Returns `Some(delta)` only if this host was offline (count `0`) and is now online (§A6:
    /// deltas are pushed, not every raw event) — `None` for an unregistered `user_pk` (ignored,
    /// see the module doc) or for a host that was already online (a second/third connection for
    /// the same identity, or the "new connection established before the old one's DISCONNECT
    /// arrives" reconnect-overlap case — neither is a state change).
    pub fn connect(&mut self, user_pk: &str, now: u64) -> Option<PresenceDelta> {
        let host_fp = *self.user_to_host.get(user_pk)?;
        let state = self.hosts.entry(host_fp).or_insert(HostState {
            count: 0,
            last_seen: now,
        });
        let was_online = state.is_online();
        state.count += 1;
        state.last_seen = now;
        if was_online {
            None
        } else {
            Some(PresenceDelta {
                host_fp,
                entry: entry_for(&host_fp, PresenceState::Online, Some(now)),
            })
        }
    }

    /// Records one fewer live connection for whichever `host_fp` `user_pk` is registered to.
    /// Saturates at zero (a stray/duplicate DISCONNECT can never underflow into a bogus "very
    /// online" count). Returns `Some(delta)` only if this host was online and just dropped to
    /// zero — the actual offline transition, never an intermediate decrement while other
    /// connections for the same host remain live (this is the "reconnect overlap never flips a
    /// live host offline" guarantee: a stale connection's late DISCONNECT only ever decrements,
    /// it can't reach zero while a newer connection already bumped the count back up).
    pub fn disconnect(&mut self, user_pk: &str, now: u64) -> Option<PresenceDelta> {
        let host_fp = *self.user_to_host.get(user_pk)?;
        let state = self.hosts.entry(host_fp).or_insert(HostState {
            count: 0,
            last_seen: now,
        });
        let was_online = state.is_online();
        state.count = state.count.saturating_sub(1);
        state.last_seen = now;
        if was_online && !state.is_online() {
            Some(PresenceDelta {
                host_fp,
                entry: entry_for(&host_fp, PresenceState::Offline, Some(now)),
            })
        } else {
            None
        }
    }

    /// One [`PresenceEntry`] per `host_fp` in `host_fps`, in order — the `hosts` array of a
    /// `helper.presence.get.<nfp>` reply. A `host_fp` this map has never seen a connection for
    /// (this helper process never observed a CONNECT/DISCONNECT or CONNZ row naming it — e.g. the
    /// host has never been online since this helper started, or CONNZ-seeding couldn't resolve
    /// its `host_fp`) is reported `offline` with `last_seen: None`, distinguishing "confirmed
    /// offline at some known time" from "presence unknown."
    ///
    /// `now` is accepted for API symmetry with `connect`/`disconnect` and reserved for a future
    /// staleness computation (there is none today — see the module doc on why `unresponsive`
    /// isn't this map's job); unused for now.
    pub fn snapshot(&self, host_fps: &[Fingerprint], _now: u64) -> Vec<PresenceEntry> {
        host_fps
            .iter()
            .map(|host_fp| match self.hosts.get(host_fp) {
                Some(state) if state.is_online() => {
                    entry_for(host_fp, PresenceState::Online, Some(state.last_seen))
                }
                Some(state) => entry_for(host_fp, PresenceState::Offline, Some(state.last_seen)),
                None => entry_for(host_fp, PresenceState::Offline, None),
            })
            .collect()
    }
}

/// `helper.presence.get.<nfp>` reply envelope (see the module doc's wire-schema section).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceGetReply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<PresenceEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PresenceGetReply {
    fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            hosts: None,
            error: Some(message.into()),
        }
    }

    fn ok(hosts: Vec<PresenceEntry>) -> Self {
        Self {
            ok: true,
            hosts: Some(hosts),
            error: None,
        }
    }
}

/// Parses the caller's `nats_fp` out of a `helper.presence.get.<nfp>` subject — same rejection
/// conditions as `turn.rs`'s `parse_subject_nats_fp` (wrong/missing prefix, empty token, a token
/// that doesn't decode as a [`Fingerprint`]), via the shared [`crate::parse_fp_after_prefix`]
/// helper both modules use.
fn parse_subject_nats_fp(subject: &str) -> Option<Fingerprint> {
    crate::parse_fp_after_prefix(subject, SUBJECT_PREFIX)
}

/// Decodes and answers one `helper.presence.get.<nfp>` request: caller identity comes from
/// `subject` alone (see the module doc — there is no request payload to even look at), the
/// caller's hosts come from their session record, and their current state comes from `map`. Pure
/// with respect to NATS — `src/bin/helper.rs` is the only caller that touches an actual
/// subscription/publish.
pub fn handle_presence_get(
    subject: &str,
    view: &mut impl HelperView,
    map: &ConnectionMap,
    now: u64,
) -> Vec<u8> {
    let reply = handle_presence_get_inner(subject, view, map, now);
    serde_json::to_vec(&reply).expect("PresenceGetReply always serializes")
}

fn handle_presence_get_inner(
    subject: &str,
    view: &mut impl HelperView,
    map: &ConnectionMap,
    now: u64,
) -> PresenceGetReply {
    let Some(nats_fp) = parse_subject_nats_fp(subject) else {
        return PresenceGetReply::err("malformed subject");
    };

    let Some(session) = view.session_record(&nats_fp, now) else {
        return PresenceGetReply::err("no active session");
    };

    PresenceGetReply::ok(map.snapshot(&session.host_fps, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_store::InMemoryHelperView;
    use crate::session::SessionRecord;
    use spindle_core::SigningKey;

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_parts(&[seed])
    }

    fn store() -> InMemoryHelperView {
        InMemoryHelperView::new(
            crate::authz::AdmissionMode::Open,
            SigningKey::from_bytes(&[0x33; 32]).verifying_key(),
        )
    }

    fn subject_for(nats_fp: &Fingerprint) -> String {
        format!("helper.presence.get.{nats_fp}")
    }

    // ---- ConnectionMap: count semantics ------------------------------------------------------

    #[test]
    fn unregistered_user_is_ignored() {
        let mut map = ConnectionMap::new();
        assert_eq!(map.connect("U-unknown", 1_000), None);
        assert_eq!(map.disconnect("U-unknown", 1_000), None);
        // No phantom host entries were created.
        assert_eq!(
            map.snapshot(&[fp(b"host-a")], 1_000),
            vec![PresenceEntry {
                host_fp: fp(b"host-a").to_string(),
                state: PresenceState::Offline,
                last_seen: None,
            }]
        );
    }

    #[test]
    fn first_connect_flips_offline_to_online() {
        let mut map = ConnectionMap::new();
        let host = fp(b"host-a");
        map.register_host_user("U-a1", host);
        let delta = map
            .connect("U-a1", 1_000)
            .expect("first connect must flip online");
        assert_eq!(delta.host_fp, host);
        assert_eq!(delta.entry.state, PresenceState::Online);
        assert_eq!(delta.entry.last_seen, Some(1_000));
        assert_eq!(delta.entry.host_fp, host.to_string());
    }

    #[test]
    fn two_connects_then_one_disconnect_stays_online() {
        let mut map = ConnectionMap::new();
        let host = fp(b"host-a");
        map.register_host_user("U-a1", host);
        map.register_host_user("U-a2", host);

        assert!(map.connect("U-a1", 1_000).is_some(), "0 -> 1 is a flip");
        assert_eq!(map.connect("U-a2", 1_001), None, "1 -> 2 is not a flip");
        assert_eq!(
            map.disconnect("U-a1", 1_002),
            None,
            "2 -> 1 is not a flip — one connection is still live"
        );
        assert_eq!(
            map.snapshot(&[host], 1_002),
            vec![PresenceEntry {
                host_fp: host.to_string(),
                state: PresenceState::Online,
                last_seen: Some(1_002),
            }]
        );
    }

    #[test]
    fn reconnect_overlap_never_flips_a_live_host_offline() {
        // The host reconnects with a fresh session nkey (a new NATS user) *before* its old
        // connection's DISCONNECT event is processed — exactly DESIGN.md §A6's "CONNECT before
        // stale DISCONNECT" scenario.
        let mut map = ConnectionMap::new();
        let host = fp(b"host-a");
        map.register_host_user("U-old", host);
        assert!(map.connect("U-old", 1_000).is_some());

        // New connection established (new nkey, registered by a fresh host-auth) while the old
        // one is still technically live from the map's point of view.
        map.register_host_user("U-new", host);
        assert_eq!(map.connect("U-new", 1_050), None, "already online, no flip");

        // The stale connection's late DISCONNECT arrives now.
        assert_eq!(
            map.disconnect("U-old", 1_060),
            None,
            "must NOT flip offline — the new connection is still up"
        );
        assert_eq!(
            map.snapshot(&[host], 1_060),
            vec![PresenceEntry {
                host_fp: host.to_string(),
                state: PresenceState::Online,
                last_seen: Some(1_060),
            }],
            "host must still read online after the stale disconnect"
        );
    }

    #[test]
    fn last_connection_disconnecting_flips_online_to_offline() {
        let mut map = ConnectionMap::new();
        let host = fp(b"host-a");
        map.register_host_user("U-a1", host);
        map.connect("U-a1", 1_000);

        let delta = map
            .disconnect("U-a1", 1_100)
            .expect("last connection dropping must flip offline");
        assert_eq!(delta.host_fp, host);
        assert_eq!(delta.entry.state, PresenceState::Offline);
        assert_eq!(delta.entry.last_seen, Some(1_100));
    }

    #[test]
    fn disconnect_count_saturates_at_zero_and_never_double_fires() {
        let mut map = ConnectionMap::new();
        let host = fp(b"host-a");
        map.register_host_user("U-a1", host);
        map.connect("U-a1", 1_000);
        assert!(
            map.disconnect("U-a1", 1_100).is_some(),
            "the real offline flip"
        );
        assert_eq!(
            map.disconnect("U-a1", 1_200),
            None,
            "a spurious extra DISCONNECT must not underflow or re-fire the offline delta"
        );
    }

    #[test]
    fn deltas_fire_only_on_transitions_across_a_full_lifecycle() {
        let mut map = ConnectionMap::new();
        let host = fp(b"host-a");
        map.register_host_user("U-a1", host);
        map.register_host_user("U-a2", host);

        assert!(map.connect("U-a1", 1).is_some(), "0->1 flips");
        assert_eq!(map.connect("U-a2", 2), None, "1->2 no flip");
        assert_eq!(map.disconnect("U-a1", 3), None, "2->1 no flip");
        assert!(map.disconnect("U-a2", 4).is_some(), "1->0 flips");
    }

    // ---- ConnectionMap: snapshot ---------------------------------------------------------------

    #[test]
    fn snapshot_reports_unknown_hosts_offline_with_null_last_seen() {
        let map = ConnectionMap::new();
        let unknown = fp(b"never-seen");
        assert_eq!(
            map.snapshot(&[unknown], 5_000),
            vec![PresenceEntry {
                host_fp: unknown.to_string(),
                state: PresenceState::Offline,
                last_seen: None,
            }]
        );
    }

    #[test]
    fn snapshot_preserves_input_order_and_mixes_known_unknown() {
        let mut map = ConnectionMap::new();
        let online_host = fp(b"host-online");
        let offline_host = fp(b"host-offline");
        let unknown_host = fp(b"host-unknown");
        map.register_host_user("U-online", online_host);
        map.register_host_user("U-offline", offline_host);
        map.connect("U-online", 10);
        map.connect("U-offline", 10);
        map.disconnect("U-offline", 20);

        let snap = map.snapshot(&[unknown_host, online_host, offline_host], 30);
        assert_eq!(
            snap,
            vec![
                PresenceEntry {
                    host_fp: unknown_host.to_string(),
                    state: PresenceState::Offline,
                    last_seen: None,
                },
                PresenceEntry {
                    host_fp: online_host.to_string(),
                    state: PresenceState::Online,
                    last_seen: Some(10),
                },
                PresenceEntry {
                    host_fp: offline_host.to_string(),
                    state: PresenceState::Offline,
                    last_seen: Some(20),
                },
            ]
        );
    }

    #[test]
    fn snapshot_of_empty_host_list_is_empty() {
        let map = ConnectionMap::new();
        assert_eq!(map.snapshot(&[], 1_000), vec![]);
    }

    // ---- PresenceState wire encoding ------------------------------------------------------------

    #[test]
    fn presence_state_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&PresenceState::Online).unwrap(),
            "\"online\""
        );
        assert_eq!(
            serde_json::to_string(&PresenceState::Offline).unwrap(),
            "\"offline\""
        );
    }

    // ---- parse_subject_nats_fp ------------------------------------------------------------------

    #[test]
    fn parse_subject_round_trips_a_fingerprint() {
        let nats_fp = fp(b"nats-presence-parse");
        assert_eq!(parse_subject_nats_fp(&subject_for(&nats_fp)), Some(nats_fp));
    }

    #[test]
    fn parse_subject_rejects_wrong_prefix() {
        let nats_fp = fp(b"nats-wrong-prefix");
        assert_eq!(parse_subject_nats_fp("helper.presence.get"), None);
        assert_eq!(
            parse_subject_nats_fp(&format!("helper.turn.get.{nats_fp}")),
            None,
            "turn.get's own subject must never satisfy presence.get's parser"
        );
    }

    #[test]
    fn parse_subject_rejects_empty_token() {
        assert_eq!(parse_subject_nats_fp("helper.presence.get."), None);
    }

    #[test]
    fn parse_subject_rejects_a_token_that_does_not_decode_as_a_fingerprint() {
        assert_eq!(
            parse_subject_nats_fp("helper.presence.get.not-a-fingerprint!!"),
            None
        );
        assert_eq!(parse_subject_nats_fp("helper.presence.get.my"), None);
    }

    // ---- handle_presence_get ----------------------------------------------------------------------

    #[test]
    fn malformed_subject_is_refused() {
        let mut s = store();
        let map = ConnectionMap::new();
        let reply_bytes = handle_presence_get("helper.presence.get", &mut s, &map, 1_000);
        let reply: PresenceGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert!(!reply.ok);
        assert_eq!(reply.error.as_deref(), Some("malformed subject"));
    }

    #[test]
    fn no_session_record_is_refused() {
        let mut s = store();
        let map = ConnectionMap::new();
        let nats_fp = fp(b"nats-no-session");
        let reply_bytes = handle_presence_get(&subject_for(&nats_fp), &mut s, &map, 1_000);
        let reply: PresenceGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert!(!reply.ok);
        assert_eq!(reply.error.as_deref(), Some("no active session"));
    }

    #[test]
    fn a_subject_fp_with_no_matching_session_is_refused_even_if_other_sessions_exist() {
        let mut s = store();
        let map = ConnectionMap::new();
        s.put_session_record(SessionRecord::new(
            fp(b"nats-unrelated"),
            fp(b"root-unrelated"),
            None,
            vec![fp(b"host-x")],
            "member".to_string(),
            10_000,
        ));
        let caller_fp = fp(b"nats-caller-no-session");
        let reply_bytes = handle_presence_get(&subject_for(&caller_fp), &mut s, &map, 1_000);
        let reply: PresenceGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("no active session"));
    }

    #[test]
    fn empty_session_host_list_returns_empty_hosts_array() {
        let mut s = store();
        let map = ConnectionMap::new();
        let nats_fp = fp(b"nats-empty-hosts");
        s.put_session_record(SessionRecord::new(
            nats_fp,
            fp(b"root-empty-hosts"),
            None,
            vec![],
            "member".to_string(),
            10_000,
        ));
        let reply_bytes = handle_presence_get(&subject_for(&nats_fp), &mut s, &map, 1_000);
        let reply: PresenceGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert!(reply.ok);
        assert_eq!(reply.hosts, Some(vec![]));
    }

    #[test]
    fn happy_path_reports_one_entry_per_session_host_reflecting_live_state() {
        let mut s = store();
        let mut map = ConnectionMap::new();
        let online_host = fp(b"host-online-2");
        let offline_host = fp(b"host-offline-2");
        map.register_host_user("U-online-2", online_host);
        map.connect("U-online-2", 500);

        let nats_fp = fp(b"nats-happy-path");
        s.put_session_record(SessionRecord::new(
            nats_fp,
            fp(b"root-happy-path"),
            None,
            vec![online_host, offline_host],
            "member".to_string(),
            10_000,
        ));

        let reply_bytes = handle_presence_get(&subject_for(&nats_fp), &mut s, &map, 1_000);
        let reply: PresenceGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert!(reply.ok);
        assert_eq!(
            reply.hosts,
            Some(vec![
                PresenceEntry {
                    host_fp: online_host.to_string(),
                    state: PresenceState::Online,
                    last_seen: Some(500),
                },
                PresenceEntry {
                    host_fp: offline_host.to_string(),
                    state: PresenceState::Offline,
                    last_seen: None,
                },
            ])
        );
    }

    #[test]
    fn expired_session_record_is_treated_as_no_session() {
        let mut s = store();
        let map = ConnectionMap::new();
        let nats_fp = fp(b"nats-expired");
        s.put_session_record(SessionRecord::new(
            nats_fp,
            fp(b"root-expired"),
            None,
            vec![],
            "member".to_string(),
            500, // already expired at now=1_000
        ));
        let reply_bytes = handle_presence_get(&subject_for(&nats_fp), &mut s, &map, 1_000);
        let reply: PresenceGetReply = serde_json::from_slice(&reply_bytes).unwrap();
        assert_eq!(reply.error.as_deref(), Some("no active session"));
    }
}
