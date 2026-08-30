# S2 leg A step A — §A6 connect handshake over real NATS + Auth Callout — results

**Status: PASS — 8/8 automated checks green against the live composed stack**
(`deploy/docker-compose.yml`'s `nats:2.10-alpine` v2.10.29 + `postgres:16-alpine` + the real
`helper` image), reproduced clean on two independent runs, 2026-08-30.

Scope (deliberate, per the task brief): this step answers only whether the §A6 connect handshake
(offer → answer) and trickle-ICE subjects work at all over real NATS under real Auth Callout
scoping. It does **not** touch ICE (the real libwebrtc/webrtc-rs kind) or QUIC — no `rtc-ice`,
`quinn`, or `spindle-net` dependency was added. SDP/ICE-candidate contents are opaque placeholder
strings throughout; step B replaces those with real ICE parameters.

## Method

A single OS process (`src/bin/s2-tests.rs`). The "host" runs as an in-process `tokio::spawn`ed
task holding its own real `async-nats` connection, authenticated exactly like
`spike-s5-presence`'s `fake_host` (`spike_s1_callout::fixtures::{new_host_identity,
host_op_key_cert, host_auth_token}`, then `async_nats::ConnectOptions::new().nkey(...).token(...)`)
— a genuine NATS peer subject to the composed helper's real Auth Callout scoping, not a stand-in.
Unlike S5's `fake_host`, this host runs real application-level protocol logic (open/verify
envelopes, reply, track per-session replay state), so it lives in-process rather than as a
separate OS binary. The "client" is a real device connection minted with a member capability for
the host (`spike_s1_callout::fixtures::member_capability`), driving the actual A7 crypto
(`spindle_core::envelope::{seal,open}`) end to end.

Run command: `cargo run -p spike-s2-signaling --bin s2-tests` (env `NATS_URL`, default
`nats://127.0.0.1:4222`).

## The kind constants chosen

`spindle_proto::artifacts::Envelope.kind` is a bare `u16` with no named constants today. This
spike defines its own, spike-local (see "why crate-local" below):

```rust
pub const KIND_OFFER: u16 = 1;
pub const KIND_ANSWER: u16 = 2;
pub const KIND_ICE: u16 = 3;
```

Small, sequential, distinct — matching the three payload roles §A6's flow diagram sketches
(`env{offer}` / `env{answer}` / `env{ice}`). No significance beyond distinctness; the real values
are for the eventual `spindle_proto` promotion (per `IMPLEMENTATION_PLAN.md` Stage 5's note) to
settle, once the payload shape is evidence-backed.

## Why the payload types are crate-local

Per the recorded decision (`IMPLEMENTATION_PLAN.md` Stage 5's newest Note): signaling payload
shapes are spiked crate-local first, promoted to `spindle_proto` (with golden vectors + a TS twin)
only once the shape is settled. `OfferPayload { offer, inbox }` / `AnswerPayload { answer }` /
`IcePayload { candidate }` live in `spikes/s2-signaling/src/lib.rs`, JSON-encoded (`serde_json`)
inside the envelope's `ciphertext` — nothing outside this crate ever decodes them, so JSON needs no
interop justification. The envelope itself (header, AEAD, signature — the thing actually under
test) is unaffected by this choice.

## Full transcript (verbatim, one representative run)

```
[PASS] setup_host_connects -- host_fp=q7xhha35joqcbydupefue5t2gt2dl2hpmdznjso2u5z3prbfdjaa
[PASS] setup_device_a_connects -- member cap for host + host2
[PASS] a_connect_handshake_round_trip -- 20 handshakes, every decrypted answer matched the host's expected value

== SIGNALING-HALF LATENCY (loopback, no ICE, no QUIC -- NOT the S2 bar) ==
  n=20 median=3.83ms max=8.59ms

[PASS] b_inbox_reply_prefix_validation -- bogus reply="_INBOX_not-the-real-device-fp.deadbeef" host event=Some(ConnectDroppedBadReplyPrefix { reply: Some("_INBOX_not-the-real-device-fp.deadbeef") }) (positive case already proven by all 20 check-1 round trips)
[PASS] c_trickle_ice_subject_round_trip -- c2h seq=1 host_event=Some(IceAccepted { seq: 1 }) h2c_verified=true
[PASS] d_no_responders_is_instant -- elapsed=1.3ms is_no_responders=true result=Err(Error { kind: NoResponders, source: Some("no responders") })
[2026-08-30T21:05:31Z INFO async_nats: event: server error: nats: Permissions Violation for Publish to "host.q7xhha35joqcbydupefue5t2gt2dl2hpmdznjso2u5z3prbfdjaa.sess.k7xyyhhqug6w4iigv4w5notgzgyxbic7z5j7wccrmdghdiqcykeq.dc925fbb3430c0067aa2f696f0adbd67.c2h"
[PASS] e_scoping_refusal_cross_session_publish_denied -- subject=host.q7xhha35joqcbydupefue5t2gt2dl2hpmdznjso2u5z3prbfdjaa.sess.k7xyyhhqug6w4iigv4w5notgzgyxbic7z5j7wccrmdghdiqcykeq.dc925fbb3430c0067aa2f696f0adbd67.c2h violation_seen=true

== CHECK 6 OBSERVATION: seq reordering vs. retry (DESIGN.md §A7 vs. §A6) ==
  seq=3 (sent first, skips ahead)              -> Some(IceAccepted { seq: 3 })
  seq=2 (sent second, arrives "late")       -> Some(IceDroppedEnvelopeError { seq: 2, detail: "seq is not strictly increasing for (sid, direction)" })
  seq=3 (sent third, exact retry of the first) -> Some(IceDroppedEnvelopeError { seq: 3, detail: "seq is not strictly increasing for (sid, direction)" })
[PASS] f_seq_reordering_observation -- ahead=Some(IceAccepted { seq: 3 }) reordered=Some(IceDroppedEnvelopeError { seq: 2, detail: "seq is not strictly increasing for (sid, direction)" }) retry=Some(IceDroppedEnvelopeError { seq: 3, detail: "seq is not strictly increasing for (sid, direction)" }) -- see RESULTS.md for the finding

==== S2 leg A step A suite summary: 8/8 checks passed ====
```

Reproduced on a second independent run: identical outcome shape, latency `n=20 median=3.26ms
max=8.13ms`.

## Checklist against the task brief

| # | Check | Result | Measured |
|---|-------|--------|----------|
| 1 | Connect handshake round trip (offer → answer, full envelope open+verify both sides) | **PASS** | 20/20 handshakes; every decrypted answer matched the host's expected value |
| 2 | `_INBOX` reply-prefix validation | **PASS** | negative case: a request with a reply subject not matching `_INBOX_<from_fp>.` was silently dropped (no answer sent); positive case proven by all 20 check-1 round trips |
| 3 | Trickle-ICE subject round trip (`c2h` then `h2c`) | **PASS** | client → host `c2h` accepted and opened by host; host → client `h2c` echo received and verified by client |
| 4 | No-responders is instant | **PASS** | `NoResponders` in **1.3ms** (well under the 5s answer timeout) |
| 5 | Scoping refusal (cross-session publish) | **PASS** | async `Permissions Violation for Publish` observed on the offending subject, captured via `EventLog`/`event_callback` |
| 6 | `seq` reordering observation | **CAPTURED** (not a pass/fail check — see finding below) | both the reordered-but-never-seen `seq` and the genuine retry were rejected identically as `EnvelopeError::ReplaySeq` |

Latency (signaling half only, loopback, no ICE, no QUIC — **not** the S2 bar, which covers connect
through transport-ready and is < 2s LAN / < 5s cross-NAT): **median 3.83ms / 3.26ms, max 8.59ms /
8.13ms** across the two runs (n=20 each). This number says nothing about the S2 bar; it is not
compared to it.

## Finding: `seq` reordering and retry are indistinguishable under strict monotonicity (Check 6)

This is the one item the task explicitly asked not to paper over.

DESIGN.md §A7 requires `seq` strictly increasing per `(sid, direction)`; §A6 says ICE losses are
"tolerated/retried." The harness sent, on the client→host (`c2h`) direction of an already
established session:

1. `seq=3` first (skipping `seq=2` entirely) → **accepted** (first-seen, arrived first;
   `min_seq_c2h` becomes 3).
2. `seq=2` second — a candidate that was never actually transmitted before, merely delayed in
   arrival relative to `seq=3` (a textbook "reordering", not a replay) → **rejected**, with the
   exact same error as a real replay: `EnvelopeError::ReplaySeq` ("seq is not strictly increasing
   for (sid, direction)").
3. `seq=3` again — an exact retry of message 1 → **rejected** with the identical error.

The receiver has no way to distinguish these two cases: both are "a seq less than or equal to the
highest already accepted", and `spindle_core::envelope::open`'s monotonicity check
(`env.seq <= min_seq_exclusive` in `crates/spindle-core/src/envelope.rs`) treats them identically
by construction. This means a literal reading of §A7's "strictly increasing" rule silently
conflicts with §A6's "tolerated/retried" promise for real network reordering (not just duplicate
retries) of trickled ICE candidates: any implementation that accepts §A7 as written **cannot** use
a single per-direction monotonic counter as the wire identity of an ICE candidate that also wants
to survive real UDP-style reordering. A real implementation needs one of:

- accept that a genuinely reordered (but never-before-delivered) candidate is dropped — the sender
  must detect the drop (e.g. via an application-level ack or a `sess`-level gap check) and
  **resend it under a fresh, higher `seq`** rather than "retrying" it under its original number
  (which is itself then indistinguishable from step 2 above and would also be dropped); or
- decouple ICE-candidate identity from the A7 replay-window `seq` entirely (e.g. a separate
  per-candidate id inside the plaintext payload, with `seq` used only for the AEAD nonce / basic
  ordering-of-arrival, not for candidate deduplication).

DESIGN.md does not currently pick between these, and this spike does not resolve it — it only
establishes, empirically, that the naive "just send trickled candidates with an incrementing
`seq`" implementation silently loses candidates under real reordering, with no distinguishable
signal to the sender (per §A5's own uniform-silent-drop philosophy, the receiver's rejection is
not observable by the peer either).

## Ambiguities and gaps surfaced (resolved locally, flagged for real-slice review)

1. **The A7 key-derivation bootstrap gap.** DESIGN.md §A7's formula `k =
   HKDF(eph_dh || dev_dh, ...)` presumes both peers' ephemeral public keys are already known when
   `k` is derived, but §A6's flow has the client send the *first* message (the offer) before it
   has ever seen the host's ephemeral key — there is no way for the client to compute a "real"
   ephemeral-ephemeral shared secret at that point, and DESIGN.md does not spell out a bootstrap
   for this. This spike's resolution (documented in `src/lib.rs`'s module doc, not silently
   assumed): the **offer** uses `eph_dh = X25519(eph_c, host_device_static_pk)` (ephemeral-static,
   computable immediately by the client and reproduced by the host from its own static secret);
   the **answer and every later message** use the full ephemeral-ephemeral `X25519(eph_c,
   eph_pk_h) = X25519(eph_h, eph_pk_c)`. This means the offer and everything after it are sealed
   under two **different** derived session keys within one `sid` — a genuine spec gap, not
   resolved here, only worked around so the round trip could run at all.
2. **No wire artifact carries a device's raw public keys.** `spindle_proto::artifacts::
   DeviceCertificate` carries only a `device_fp` (a hash) — never the actual Ed25519/X25519
   public keys behind it. There is currently no registry/enrollment mechanism in the codebase that
   would let a host recover a member device's real public keys from its `device_fp` (or vice
   versa). This spike sidesteps the gap entirely by pre-sharing both sides' public keys directly
   in test setup — deliberately out of scope for this step (registry/enrollment is a separate
   concern), but a real slice cannot skip it.
3. **The host's own "device" identity is undefined by DESIGN.md.** The envelope module's own doc
   comment refers to "the host's device_fp" as one of the two fixed session roles, but nothing in
   `spindle-helper`/`spindle-core` defines how a host's *NATS-authenticating* identity (`host_fp`,
   root-derived, used for subject scoping and capability chains) relates to a "device" identity
   used for E2E envelope crypto. This harness mints the host a separate, ad hoc
   `spindle_core::identity::DeviceKey` purely for this spike's crypto — a decision, not a finding
   from DESIGN.md, and flagged for whoever designs the real host-side signaling module.
4. **`inbox` payload field is a claim, not independently cross-checked.** §A6's diagram carries an
   `inbox` field inside the encrypted offer payload alongside the NATS-level reply-to. This spike
   populates it (the client's inbox prefix) but the host does not cross-check it against the
   actual observed reply-to subject — only the NATS-level reply-to prefix (Check 2) is validated.
   Whether the payload-level `inbox` is meant as a binding cross-check or is purely informational
   is not stated in DESIGN.md.

## What a real slice should keep vs. redo (per this repo's spike convention)

**Keep**: the subject-scoping mechanics proved here (host's `sub host.<own>.>` / `pub
host.<own>.sess.*.*.h2c`; client's per-host `pub connect` / `pub …c2h` / `sub …h2c` — all exactly
as `spindle-helper::permissions` already implements and as this spike exercised against the real
callout, no code changes needed there); the `_INBOX` reply-prefix validation as an application-
level check the host must run itself (NATS does not enforce it); the A7 envelope
`seal`/`open` call shape (unchanged, used as-is).

**Redo**: the payload types (placeholder strings) once step B lands real ICE parameters; the
key-derivation bootstrap resolution (needs an actual design decision, not a spike improvisation);
device/host public-key distribution (needs the registry/enrollment mechanism this spike bypassed);
the `seq`/reordering handling for trickled ICE (needs the design decision flagged above before any
real implementation is written, since a real implementation that reuses this spike's naive
increment-and-send approach will silently lose candidates in the field).

## Not exercised

Nothing in the task's checklist was skipped or made vacuous — every one of the six required checks
ran against the real crypto/subject/NATS path and produced a genuine, verified outcome (including
Check 6, which is explicitly an observation rather than a pass/fail gate, per the task brief).
The "sender is an active member device" / unknown-sender MUST-check is implemented in the host
handler (`handle_connect`'s member-registry lookup) but was not exercised by a dedicated check —
it wasn't in the required checklist, and this harness's only registered device is legitimate
throughout, so there was no natural place in the six required checks to trigger it without adding
a seventh, unscoped test. Flagged here rather than silently claimed as covered.
