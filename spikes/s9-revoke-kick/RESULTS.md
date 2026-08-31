# S9 — KICK mechanics probe — RESULTS

**Status: PARTIAL — run 2026-08-31.** This spike settles **KICK mechanics only**: the exact
subject form, payload field name, and reply shape of the nats-server admin `KICK` request, and
proof (not inference) that a given reply actually corresponds to the target connection dropping.
It runs against the composed reference deployment (`deploy/docker-compose.yml`'s `nats` +
`postgres` + `helper`, `nats-server:2.10-alpine` == v2.10.29 — already up and healthy; nothing was
restarted/rebuilt/torn down for this spike). **The full S9 end-to-end revoke → kick → reject
timing run is a later step, not attempted here.**

## Method

`spikes/s9-revoke-kick/src/main.rs`: a standalone throwaway binary (no fixtures reused — this
probe only needs two NATS connections, no admission/CBOR plumbing). It:

1. Opens a `SYS_CONN_SEED`-authenticated connection (genuine `SYS` account member, same identity
   `crates/spindle-helper/src/bin/helper.rs`'s `sys_client` uses) and subscribes to
   `$SYS.ACCOUNT.*.CONNECT` and `$SYS.ACCOUNT.*.DISCONNECT` **before** opening any other
   connection.
2. Opens an `APP_CONN_SEED`-authenticated connection and captures the resulting real
   `$SYS.ACCOUNT.APP.CONNECT` advisory verbatim — closing the elision in
   `spikes/s5-presence/RESULTS.md`, which recorded the advisory's `server` object as
   `{ "...": "..." }`.
3. Sends `$SYS.REQ.SERVER.PING.CONNZ` with `{"auth": true}` (matching `helper.rs`'s
   `seed_presence_map`) and prints the full reply verbatim.
4. Runs four KICK attempts, one per (subject form × payload field name) combination, each against
   a live, freshly-confirmed target connection (a fresh connection is opened for the next attempt
   whenever the previous one was actually kicked):
   - **A**: `$SYS.REQ.SERVER.<server_id>.KICK` with `{"id": <cid>}` (DESIGN.md §A4's exact claim)
   - **B**: `$SYS.REQ.SERVER.<server_id>.KICK` with `{"cid": <cid>}`
   - **C**: `$SYS.REQ.SERVER.PING.KICK` (broadcast form) with `{"id": <cid>}`
   - **D**: `$SYS.REQ.SERVER.PING.KICK` (broadcast form) with `{"cid": <cid>}`

   After every attempt it prints the raw reply verbatim, watches `$SYS.ACCOUNT.*.DISCONNECT` for
   up to 5 s for an advisory matching the target `cid`, and independently checks the target
   client's own `async_nats::Client::connection_state()`. A reply is **never** treated as "it
   worked" on its own — only a real DISCONNECT advisory and/or an observed `Disconnected` state
   counts as proof.

No repeat attempts were needed — all four combinations produced an unambiguous, decisive result on
the first live run (the 3-attempt cap was never approached).

## Answers (evidence-backed)

### 1. Where does the server id live?

**`server.id`** in the `$SYS.REQ.SERVER.PING.CONNZ` reply's top-level `server` object (also
duplicated at `data.server_id`). It is **also** present, identically, in the `server` object of
every `$SYS.ACCOUNT.*.CONNECT`/`.DISCONNECT` advisory — cross-confirmed by this run: both showed
`NCRAF5Z74DEWK5ULLQHYX2FHWQG5X7E4CKJT6Q2BY5FB5INIZZJMZVT5` for the same running server. This
resolves spikes/s5-presence's elision (`"server": { "...": "..." }`) — the full shape is:

```json
"server": {
  "flags": 0,
  "host": "0.0.0.0",
  "id": "NCRAF5Z74DEWK5ULLQHYX2FHWQG5X7E4CKJT6Q2BY5FB5INIZZJMZVT5",
  "jetstream": false,
  "name": "NCRAF5Z74DEWK5ULLQHYX2FHWQG5X7E4CKJT6Q2BY5FB5INIZZJMZVT5",
  "seq": 563,
  "time": "2026-08-31T22:50:49.419816958Z",
  "ver": "2.10.29"
}
```

(`name` == `id` because this stack's `nats-server.conf` sets no explicit `server_name`; nats-server
auto-generates a server identity and uses it as both.)

### 2. Which KICK subject form(s) work?

- **`$SYS.REQ.SERVER.<server_id>.KICK`** (per-server, concrete id) — **WORKS**.
- **`$SYS.REQ.SERVER.PING.KICK`** (the hoped-for broadcast form, by analogy with
  `PING.CONNZ`) — **DOES NOT EXIST**. Both attempts against it (C, D) came back as an
  `async-nats` client-side error, not a server reply at all:

  ```
  reply: ERROR — request error: no responders: no responders
  ```

  This is a clean "no responders", not a permission or parsing error — nats-server does not
  special-case `PING` for the `KICK` verb the way it does for `CONNZ`. **A concrete server id is
  required; there is no way to avoid it, even in a single-server deployment.** DESIGN.md §A4's
  premise (kicking via `$SYS.REQ.SERVER.<id>.KICK`) is thus confirmed as the *only* viable form —
  the broadcast shortcut hoped for in this task's brief does not exist.

### 3. Which payload field name is correct?

**`{"cid": <cid>}` — not `{"id": <cid>}`.** DESIGN.md §A4's literal text (`{id: cid}`) is
**wrong**. Evidence, both attempts against the identical subject
(`$SYS.REQ.SERVER.<server_id>.KICK`), same target connection (cid 26), back to back:

- Attempt A, `{"id": 26}` → reply: `{"error":{"code":500,"description":"no such client or
  leafnode id"}}`. No DISCONNECT advisory arrived; `connection_state()` stayed `Connected`.
  **Confirmed no-op** — the server did not recognize `"id"` as the connection identifier at all
  (it looked up some other/default value and found nothing).
- Attempt B, `{"cid": 26}` (same subject, same target) → reply: `{"server": {...}}` (no error).
  A **real** `$SYS.ACCOUNT.APP.DISCONNECT` advisory for cid 26 arrived immediately after, with
  `"reason": "Kicked"`, and `connection_state()` flipped to `Disconnected`. **Confirmed working.**

### 4. Reply shape

- **Success** (subject `$SYS.REQ.SERVER.<server_id>.KICK`, payload `{"cid": <cid>}`):
  ```json
  {
    "server": {
      "flags": 0, "host": "0.0.0.0",
      "id": "NCRAF5Z74DEWK5ULLQHYX2FHWQG5X7E4CKJT6Q2BY5FB5INIZZJMZVT5",
      "jetstream": false,
      "name": "NCRAF5Z74DEWK5ULLQHYX2FHWQG5X7E4CKJT6Q2BY5FB5INIZZJMZVT5",
      "seq": 570, "time": "2026-08-31T22:50:54.477246127Z", "ver": "2.10.29"
    }
  }
  ```
  No `"data"` field, no explicit "ok" — success is signaled purely by the **absence** of an
  `"error"` key. A caller must check for `error`'s absence, not for any positive success marker.

- **Error** (same subject, payload `{"id": <cid>}` — nats-server didn't find a matching
  connection under that field name):
  ```json
  {
    "server": { "...": "same shape as above, seq/time differ" },
    "error": { "code": 500, "description": "no such client or leafnode id" }
  }
  ```

- **Client-side "no responders"** (broadcast form `$SYS.REQ.SERVER.PING.KICK` — no server ever
  answers this subject for KICK): the `async-nats` `request()` call itself returns
  `Err("no responders: no responders")` — there is no server-generated reply payload to parse at
  all, because nothing is subscribed to answer it.

### 5. Proof the connection actually dropped

Verbatim `$SYS.ACCOUNT.APP.DISCONNECT` advisory captured immediately after the successful KICK
(attempt B, `{"cid": 26}`):

```json
{
  "client": {
    "acc": "APP", "client_type": "nats", "host": "192.168.65.1", "id": 26,
    "issuer_key": "APP", "kind": "Client", "lang": "rust", "rtt": 1615500,
    "start": "2026-08-31T22:50:49.401247333Z", "stop": "2026-08-31T22:50:54.476841377Z",
    "user": "UAOUJCRS3HXWQ2GKAA2PZA7QA5WQN3QTPTBSFX2KYC2XTY7P67U2252X", "ver": "0.35.1"
  },
  "id": "YLZKfewMTvJ99iygQLeXOU",
  "reason": "Kicked",
  "received": { "bytes": 0, "msgs": 0 },
  "sent": { "bytes": 0, "msgs": 0 },
  "server": {
    "flags": 0, "host": "0.0.0.0",
    "id": "NCRAF5Z74DEWK5ULLQHYX2FHWQG5X7E4CKJT6Q2BY5FB5INIZZJMZVT5",
    "jetstream": false,
    "name": "NCRAF5Z74DEWK5ULLQHYX2FHWQG5X7E4CKJT6Q2BY5FB5INIZZJMZVT5",
    "seq": 571, "time": "2026-08-31T22:50:54.477774377Z", "ver": "2.10.29"
  },
  "timestamp": "2026-08-31T22:50:54.476841377Z",
  "type": "io.nats.server.advisory.v1.client_disconnect"
}
```

`reason: "Kicked"` — a value not seen in any of spikes/s5-presence's captured disconnects (which
only ever saw `"Client Closed"` and `"Stale Connection"`) — is itself proof this disconnect was
caused by the KICK admin request specifically, not a coincidental client-initiated close.
Independently, `target.client.connection_state()` (the kicked connection's own handle, still held
by this probe process) read back `Disconnected` immediately after.

No false green was observed anywhere in this run: every reply that did **not** correspond to a
real drop also carried no confirming DISCONNECT advisory and left `connection_state()` at
`Connected` (attempts A, C, D) — the invariant this task asked to guard held throughout.

## Permissions

No `Permissions Violation` (or any other async client error) was ever observed via the SYS
connection's `event_callback` across any of the four attempts. The genuine `SYS`-account
`SYS_CONN_USER` identity (`deploy/nats/nats-server.conf`) has whatever permission is needed to
issue `$SYS.REQ.SERVER.<id>.KICK` — this stack's config imposes no obstacle. **No critical finding
here**; nats-server's default SYS-account behavior already permits it.

## A curiosity noted, not chased further (out of this spike's scope)

During the run, kicking a connection whose underlying `async_nats::Client` handle is still held by
this process triggers the client library's own automatic reconnect (default `async-nats`
behavior) — a **new** cid (27) appeared, connected and then cleanly closed (`"reason": "Client
Closed"`) a few milliseconds later, when this probe's own code dropped the old `CapturedConn`
value to move on to the next attempt. This is an artifact of the probe's connection-reuse/drop
logic, not a nats-server behavior under test, and does not affect any of the answers above (each
answer is anchored to the specific cid targeted by that attempt's KICK payload). Worth remembering
for the real S9 revoke→kick→reject implementation: **a kicked device/host may auto-reconnect** on
its own network stack, so "kicked" alone is not sufficient to keep it out — the callout/auth layer
must also refuse the reconnect (already the plan, per DESIGN.md §A4's revocation-store check on
every connect) for revocation to actually stick.

## Full raw output

The complete verbatim run (every printed line, both CONNECT/DISCONNECT advisories, the full CONNZ
reply, and all four kick attempts) is not checked in (this is throwaway spike output, regenerable
via `cargo run -p spike-s9-revoke-kick` against the live stack) — every fact quoted above was
copied verbatim from that run, not paraphrased or reconstructed from memory.

## Correction: the probe's original automated verdict was wrong (a false green)

**Found 2026-08-31, on a later re-run of the checked-in binary.** The probe's verdict logic
originally read:

```rust
let dropped = disconnect_evidence.is_some()
    || matches!(state, async_nats::connection::State::Disconnected);
```

This counts **any** `$SYS.ACCOUNT.*.DISCONNECT` advisory matching the target `cid` as proof of a
kick. That is wrong: the probe's own teardown of a connection between attempts (see "A curiosity
noted, not chased further" above — the auto-reconnect race that can leave a stray connection open
for a target cid) also generates a real DISCONNECT advisory for that cid, carrying
`"reason": "Client Closed"`, not `"Kicked"`. On a re-run, attempts **C** and **D** — both against
the nonexistent `PING.KICK` broadcast subject, which always fails client-side with "no responders"
— were printed as `ACTUALLY DROPPED (confirmed)` purely because a stray `"Client Closed"` advisory
for their target cid happened to land inside the 5s watch window. That verdict directly
contradicted the `connection_state() after: Connected` line printed immediately above it, and
contradicted attempt B's own captured evidence in this document (§5 above), which already
identifies `reason: "Kicked"` as the one value that distinguishes a real kick from every disconnect
reason seen anywhere else in this project (including every disconnect captured in
`spikes/s5-presence`, which only ever saw `"Client Closed"` and `"Stale Connection"`).

**What was and wasn't affected**: the raw captures printed by every run (the replies, the
advisories, `connection_state()`) were always correct and complete — nothing was fabricated or
lost. The prose conclusions in this document (§§1-5 above, all written from the original run's
evidence) were also always correct: they already cite attempt B alone, and already call out
`reason: "Kicked"` as the distinguishing signal, and already state that A, C, and D did not drop
the connection. **Only the probe's own automated `dropped` verdict, printed at the bottom of a
re-run, was wrong** — and only for C and D. B's verdict was always correct, because B is the one
case where a real kick and its own `"Kicked"`-reason advisory coincide.

**The fix**: the verdict is now `kicked = disconnect_reason == Some("Kicked")` — a captured
DISCONNECT advisory for the target cid counts only if its top-level `reason` is exactly
`"Kicked"`. Any other reason (or no advisory at all) is reported as `NOT KICKED`, and when an
advisory with a different reason was captured, the probe now says so explicitly and loudly (naming
the reason and stating it is not a kick) rather than silently printing "NO". `connection_state()`
is still printed after every attempt, but purely as corroborating detail — it no longer
participates in the verdict.

**Regression guard added**: each of the four attempts now carries an explicit expected outcome
(A/C/D: not kicked; B: kicked), and the probe compares actual against expected at the end, printing
a PASS/FAIL per attempt and an overall `REGRESSION CHECK` line, exiting non-zero on any mismatch.
Re-running the fixed probe (`cargo run -q -p spike-s9-revoke-kick`) against the same live stack
confirms: A, C, and D report `NOT KICKED` (C and D explicitly naming `"Client Closed"` as the
captured reason on runs where the auto-reconnect race produces an advisory at all — it is
timing-dependent and does not fire every run, but the verdict is correct either way), B still
reports `KICKED` on `reason: "Kicked"`, and all four match their expected outcome
(`REGRESSION CHECK: ALL 4 ATTEMPTS MATCHED THEIR EXPECTED OUTCOME — PASS`, exit code 0).

This project treats a false green as the most serious defect class, because it silently destroys
trust in every other signal a tool reports. This one did not change any conclusion already
published in this document, but it would have misled anyone who re-ran the checked-in binary and
trusted its bottom-line verdict instead of reading the raw evidence above it.

## Ambiguities / things not resolved by this spike

- **Multi-server clustering**: this stack runs a single `nats-server` instance. Whether/how
  `$SYS.REQ.SERVER.<id>.KICK` behaves when the target connection is on a *different* cluster node
  than the one answering the request is untested — deferred to the HA slice, same scoping as
  spikes/s5-presence's CONNZ aggregation caveat.
- **The full S9 revoke→kick→reject timing bar** (DESIGN.md's actual deliverable) is not measured
  here at all — this spike only proves the wire mechanics work; it does not exercise the helper's
  own revocation-store lookup, does not measure end-to-end latency from a revocation write to the
  target's connection actually dropping, and does not test the callout's refusal of the
  auto-reconnect noted above.
