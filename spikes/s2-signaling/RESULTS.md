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

---

# S2 leg A step B — trickle ICE + quinn punch — results

**Status: PASS — real ICE punch + real QUIC handshake, over the real A7-verified NATS envelope
path, with trickled candidates, against the live composed stack, reproduced clean on two
independent runs (n=7 each), 2026-08-30.**

Scope: this step replaces step A's opaque placeholder payloads with the real thing — a real
`rtc_ice::agent::Agent` punch (ported from `spikes/s19-quic-transport`'s already-proven leg 2, not
redesigned) driven entirely by A7-sealed envelopes over NATS, followed by a real `quinn` QUIC
handshake mutually pinned to the fingerprints carried inside those envelopes, followed by one real
application-stream round trip. Binary: `src/bin/s2-connect.rs`. Run command:
`cargo run -p spike-s2-signaling --bin s2-connect` (env `NATS_URL`, default
`nats://127.0.0.1:4222`).

## The v0.9.14 two-key schedule, as implemented

Step A's finding #1 ("the A7 key-derivation bootstrap gap") is exactly what DESIGN.md v0.9.14
settles. This step implements the settled schedule, not step A's improvisation:

- **Offer only**: `k0 = HKDF-SHA256(X25519(eph_c, dev_agree_h) || X25519(dev_agree_c, dev_agree_h),
  info = "spindle-sess-boot-v1" || sid || from_fp || to_fp)`.
- **Answer and every message after it, both directions**: `k1 = HKDF-SHA256(X25519(eph_self,
  eph_peer) || X25519(dev_self, dev_agree_peer), info = "spindle-sess-v1" || sid || from_fp ||
  to_fp)` — unchanged from step A/DESIGN.md §A7.

Two distinct `info` domains, enforced structurally: a receiver decrypts `kind=offer` under `k0`
via a hand-rolled `boot_seal_payload`/`boot_open_payload` (`lib.rs`) and everything else under
`k1` via the real `spindle_core::envelope::{seal,open}` — never both under the same function.

**`k0` cannot be produced through `spindle-core`'s public API.** `SessionKey` has no public
raw-bytes constructor, and `derive_session_key`'s HKDF `info` domain
(`SESSION_KEY_INFO_DOMAIN = b"spindle-sess-v1"`) is a private compile-time constant — there is no
way to ask spindle-core for a session key under a *different* domain string. `derive_boot_key`/
`boot_seal_payload`/`boot_open_payload` in `lib.rs` replicate `spindle_core::envelope`'s exact
seal/open construction (same AEAD, same nonce layout, same AAD, same signature domain, same
`EnvelopeError` variants and MUST-check order) against a raw `[u8; 32]` key instead of the opaque
`SessionKey`, reusing `spindle_proto::artifacts::Envelope`'s already-public
`header_canonical_bytes()`/`signing_input()` and spindle-core's public `direction_byte()` so the
duplication is confined to "accept a raw key" — not a second crypto implementation with its own
drift. **Promotion candidate for the real slice**: `spindle-core` needs either a
`SessionKey::from_bytes`-style constructor or a parameterized `info` domain on
`derive_session_key`, so a two-key schedule doesn't require reimplementing `seal`/`open` outside
the crate that owns them.

## Method

Same one-process shape as step A (`s2-connect.rs`): the host is an in-process `tokio::spawn`ed
task with its own real `async-nats` connection under the composed helper's real Auth Callout
scoping; the client drives the connect from `main`. Every run performs: offer (k0) → answer (k1) →
both sides trickle their own local ICE candidate + end-of-candidates as two separate `KIND_ICE`
envelopes → both sides feed trickled candidates into a live `rtc_ice::agent::Agent` as they arrive
→ on selected pair, the punched `std::net::UdpSocket` is handed to `quinn::Endpoint::new(...)`
(S19's design (a), never `Endpoint::server`/`Endpoint::client`) → mutually-pinned TLS 1.3 handshake
→ one bidirectional stream, "ping"/"pong". Client-side `Instant` markers only, matching "the
connect latency a caller experiences": t0 before offer publish, t1 after answer verified, t2 after
ICE selected pair, t3 after QUIC handshake, t4 after the stream round trip completes.
Loopback/local only (127.0.0.1 host candidates; no STUN/TURN — see "Not exercised").

## Q1 — Does trickle work through the envelope path (candidates arriving asynchronously)?

**PASS, with a genuine nuance found empirically, not assumed.** Across both 7-run samples (14 runs
total), every run's end-of-candidates envelope was consumed before the ICE loop returned in 13/14
runs (`eoc_seen=true`), and the client-side trickled candidate was actually fed into
`add_remote_candidate` (`candidates_applied=1`) in 12/14 runs. In the remaining runs
(2 in the first sample, 0 in the second — see raw output below), the ICE agent selected a pair
*before* the trickled envelope had been decoded and applied, with `candidates_applied=0`. This is
not a trickle failure: on loopback, ICE's own peer-reflexive-candidate mechanism (RFC 8445
§5.1.2.2 — an inbound STUN binding check from an address not yet known as a remote candidate
causes the receiving agent to synthesize a peer-reflexive candidate for it on the spot) can win the
race against the NATS envelope round trip, which is real network+crypto work. **Both mechanisms
worked**; which one supplies the winning candidate is a genuine, sub-millisecond race on loopback,
not a defect in either path. Every run still reached a selected pair and a working QUIC connection
regardless of which mechanism won.

## Q2 — Real connect latency, n≥5, loopback

Two independent samples, n=7 each (exceeds the n≥5 bar), full per-run values below — every number
is a real measured `Instant` delta from an actual run against the live composed stack, none
invented or estimated.

**Sample 1:**

| run | (a) offer→answer (ms) | (b) answer→selected (ms) | (c) selected→QUIC (ms) | (d) TOTAL offer→stream (ms) |
|---|---|---|---|---|
| 0 | 12.21 | 37.68 | 11.91 | 62.58 |
| 1 | 15.07 | 7.86 | 8.51 | 33.14 |
| 2 | 5.74 | 5.41 | 5.06 | 17.07 |
| 3 | 12.93 | 4.32 | 3.51 | 22.05 |
| 4 | 7.47 | 3.21 | 3.94 | 15.35 |
| 5 | 34.46 | 4.52 | 3.38 | 42.98 |
| 6 | 28.37 | 4.99 | 3.08 | 37.03 |
| **median** | **12.93** | **4.99** | **3.94** | **33.14** |

**Sample 2 (independent re-run):**

| run | (a) offer→answer (ms) | (b) answer→selected (ms) | (c) selected→QUIC (ms) | (d) TOTAL offer→stream (ms) |
|---|---|---|---|---|
| 0 | 22.96 | 32.91 | 15.46 | 72.04 |
| 1 | 15.91 | 6.44 | 7.57 | 31.58 |
| 2 | 10.83 | 4.64 | 6.56 | 23.93 |
| 3 | 7.21 | 4.99 | 3.86 | 17.17 |
| 4 | 12.10 | 4.95 | 4.47 | 22.40 |
| 5 | 12.40 | 5.03 | 5.33 | 23.76 |
| 6 | 15.67 | 4.81 | 4.94 | 26.74 |
| **median** | **12.40** | **4.99** | **5.33** | **23.93** |

Both samples' medians land well under the S2 bar (< 2s LAN), with run 0 of each sample being a
consistent high outlier for stage (b) (~33–38ms vs. ~5ms median) — the first ICE punch after a
fresh `tokio::spawn` cold-starts the agent's timer/retransmit machinery; later runs in the same
process are faster. This is measured, not modeled: no attempt was made to isolate the cause
further, and it is flagged here rather than smoothed over.

## Q3 — Does the envelope-carried fingerprint pin correctly, both directions?

**PASS, both directions proven.**

- **Matching connects**: all 14 successful runs across both samples connected using the exact
  server-cert fingerprint extracted from the verified `AnswerPayload.cert_fp` — i.e., every
  passing run *is* the positive-direction proof; QUIC could not have completed its TLS 1.3
  handshake under `PinServerCert`/`PinClientCert` otherwise (mutual pinning: both directions are
  checked, not just server→client as in S19).
- **Deliberately corrupted is REJECTED**: one dedicated negative run per sample flipped one byte of
  the client's locally-held expected server fingerprint (`expected_server_fp[0] ^= 0xFF`) *after*
  genuinely receiving and verifying the real answer envelope — isolating the QUIC-layer pin check
  itself, not a broken envelope. Verbatim client-side error (sample 2):

  ```
  quinn handshake (client): the cryptographic handshake failed: error 40: unexpected error:
  s2-connect: server certificate fingerprint mismatch: expected
  sha256:1c57da0620210e53f23af6f966bb896282abc8160fafc91dab44016c73077cbd, got
  sha256:e357da0620210e53f23af6f966bb896282abc8160fafc91dab44016c73077cbd
  ```

  Host-side (same run), confirming the rejection is real and not a client-only artifact:

  ```
  s2-connect: host: session task failed: accepting quinn connection (host): aborted by peer:
  the cryptographic handshake failed: error 40: unexpected error: s2-connect: server
  certificate fingerprint mismatch: expected
  sha256:4424032261277f1f9cdb2a82c52cec59c0a889a85eb9e461b1fa8442e1936fbf, got
  sha256:bb24032261277f1f9cdb2a82c52cec59c0a889a85eb9e461b1fa8442e1936fbf
  ```

  (The two fingerprint pairs differ between the host- and client-side log lines only because each
  side logs its own corrupted-vs-real view of the same handshake, from the same run.)

## Q4 — What must `IcePayload` actually carry (feeds `spindle-proto` promotion)?

Concrete field lists, as implemented and exercised:

```rust
pub struct OfferPayload {
    pub inbox: String,       // client's NATS inbox prefix (step A's field, unchanged)
    pub transport: String,   // "quic" -- lets a future signaling flow negotiate transport
    pub ufrag: String,       // this side's ICE local username fragment
    pub pwd: String,         // this side's ICE local password
    pub cert_fp: String,     // "sha256:<64 hex chars>" -- this side's QUIC cert fingerprint
}

pub struct AnswerPayload {
    pub transport: String,
    pub ufrag: String,
    pub pwd: String,
    pub cert_fp: String,
}

pub struct IcePayload {
    pub candidate: Option<String>,   // a marshaled ICE candidate line (SDP a=candidate), or...
    pub end_of_candidates: bool,     // ...end-of-candidates, mutually exclusive with `candidate`
}
```

`IcePayload` uses one envelope per event (either exactly one candidate, or end-of-candidates —
never both, never batched) rather than a `Vec<String>`, which is what makes trickle (Q1) meaningful
at the wire level: each candidate is independently authenticated, ordered, and repla­y-checked by
`seq` as it is discovered, not gathered into a batch first.

## Q5 — Does strict-monotonic `seq` drop candidates in practice?

**Zero drops observed, across both directions, across every run of both samples (14 successful
runs + 2 negative-test runs = 16 total).** `client-side (h2c) ICE envelopes rejected for
non-monotonic seq: 0` and `host-side (c2h) ICE envelopes rejected for non-monotonic seq: 0` in
both samples. This is the honest zero the task brief explicitly allows: this harness's trickle
traffic per session is exactly two envelopes per direction (`candidate` at `seq=1`, then
`end_of_candidates` at `seq=2`), sent back-to-back over a single, uncontended loopback path with no
concurrent sessions — there is no reordering pressure in this harness for step A's Check 6 finding
to manifest. **This measurement does not contradict step A's Check 6 finding** (that a genuinely
reordered, never-before-delivered `seq` is indistinguishable from a replay and gets silently
dropped); it simply means this step's traffic pattern never produced real reordering to exercise
that failure mode. The finding stands as a design gap for whoever builds the real slice, unresolved
by this step.

## Q6 — What API does `spindle-net::quic` lack?

`crates/spindle-net/src/quic.rs`'s `QuicServer::bind(addr, cert, expected_client_fp)` calls
`quinn::Endpoint::server(server_config, addr)` internally — it **binds its own UDP socket**.
Symmetrically, `QuicClient::connect(addr, server_fp, cert)` calls `Endpoint::client(bind_addr)`
internally — also binds its own socket. ICE (this step, and the real slice) hands the caller an
**already-punched** `std::net::UdpSocket` (the exact socket the ICE agent just spent a connectivity
check establishing a peer-reachable mapping for); there is no `spindle-net` constructor that
accepts a pre-bound socket, so this binary bypasses `QuicServer`/`QuicClient` entirely and calls
`quinn::Endpoint::new(EndpointConfig::default(), Some(server_config), punched_socket, runtime)`
directly (mirrored on the client side with `server_config: None`). **What's needed, precisely**: a
`QuicServer::from_socket(std::net::UdpSocket, cert, expected_client_fp) -> Result<Self, QuicError>`
and a `QuicClient::from_socket(std::net::UdpSocket, remote_addr, server_fp, cert) -> Result<Self,
QuicError>` (or an equivalent split of the existing constructors into "build the rustls config" +
"bind or accept a socket" steps) so the ICE-punch caller can hand off the socket it already owns
instead of `spindle-net` binding a second, useless one. `spindle-net`'s existing
`PinnedServerCertVerifier`/`PinnedClientCertVerifier` and mutual-pinning `ServerConfig`/
`ClientConfig` construction logic did not need to change at all — this binary's `PinServerCert`/
`PinClientCert` are line-for-line equivalent hand-rolled copies (necessary only because the
originals are private to that crate), which is itself evidence the real logic is already correct
and just needs the socket-injection seam added.

## A real bug found by running this against the live stack, not by inspection

Every one of the first seven runs (before this was found and fixed) failed at the exact same point:
the client's `read_exact` of the "pong" bytes returned `connection lost: closed by peer: 0`, even
though the host's own log showed `stream round trip complete` immediately beforehand — i.e. the
host really did send "pong" before the error. Root cause: `host_session_ice_and_quic` returned
`Ok(())` immediately after `send.finish()`, dropping its local `Connection` and `Endpoint` handles;
quinn implicitly sends a `CONNECTION_CLOSE` (error code 0) when the last handle to a connection is
dropped, and that implicit close raced the client's read of the already-sent "pong" payload across
the loopback socket — a race the client lost on all seven runs. Fixed by having the host
`await connection.closed()` (bounded by a 5s timeout) before returning, so the host's teardown
waits for the client's own explicit `connection.close(0, b"done")` (sent only after the client has
finished reading "pong") instead of racing it. This is exactly the kind of finding empirical,
drive-the-real-thing testing surfaces that unit tests with fakes would not: nothing about the
sealed envelope, ICE, or the cert-pinning logic was wrong — the bug was purely in this harness's
QUIC connection-lifetime management, and it reproduced deterministically (7/7) until fixed, then
disappeared deterministically (14/14 after the fix, across both samples).

## What a real slice should keep vs. redo

**Keep**: the k0/k1 two-key schedule as specified in DESIGN.md v0.9.14 (implemented here exactly as
written); the ICE↔quinn handoff mechanics (`rtc_ice::agent::Agent` → punched socket →
`quinn::Endpoint::new`, unchanged from S19); mutual QUIC fingerprint pinning driven entirely by
envelope-carried values (never a side channel); the one-candidate-per-envelope trickle wire shape
(Q4); the explicit-close-before-teardown pattern this step had to discover the hard way.

**Redo**: `k0`'s implementation once `spindle-core` gains a way to derive a session key under a
non-default `info` domain (see the promotion candidate above) — this step's `boot_seal_payload`/
`boot_open_payload` duplication should not ship as-is; the `spindle-net::quic` socket-injection
constructors (Q6); the `seq`/reordering handling flagged by step A (still unresolved, still not
exercised by this step's low-traffic pattern per Q5).

## Not exercised

- **STUN/TURN/relay path.** Only loopback host candidates (127.0.0.1) were used; coturn is up in
  the composed stack but was never contacted. No NAT traversal, no relay fallback, no
  cross-machine/cross-NAT scenario of any kind.
- **Concurrent sessions.** Every run is sequential (one connect fully completes, including the
  host's background task settling, before the next begins); the host's per-session dispatch
  (`HostSessions` keyed by `from_fp`) was never exercised with two sessions live at once.
- **Client-certificate corruption (the symmetric negative case).** Q3's negative test corrupts only
  the *client's expectation of the server's* fingerprint. The reverse — the host rejecting a
  client whose presented certificate doesn't match the `cert_fp` carried in the offer — relies on
  the same `PinClientCert` code path (verified structurally, exercised implicitly by every
  successful run's mutual handshake) but was never driven by a dedicated corrupted-client-cert
  test.
- **Multiple trickled candidates per side.** Both peers gather exactly one loopback host candidate
  each; the trickle mechanism was never exercised with more than one real candidate in flight, so
  ordering/interleaving of multiple trickled candidates from the same peer is unproven.
- **Any latency measurement beyond loopback.** All numbers in Q2 are loopback-only; nothing here
  says anything about LAN or cross-NAT latency.
- **The Q5 reordering failure mode itself**, per the Q5 answer above — this step's traffic pattern
  never produced real reordering, so step A's Check 6 finding (reordered vs. retried `seq` are
  indistinguishable) remains unexercised and unresolved by this step, exactly as it was left by
  step A.

---

# S2 across-NAT attempt in the two-container lab — 2026-10-30 (`td-c694b2`)

**Outcome: the across-NAT S2 usable-stream number still does not exist, and the blocker is the
production code, not the lab.** The graduated `spindle-net` signaling stack drives
offer/answer/ICE/QUIC correctly, but its ICE gathering has **no STUN and no TURN**:
`crates/spindle-net/src/signaling/ice.rs` says *"Loopback/LAN host candidates only in this slice —
no STUN/TURN gathering"* and `start_local_ice` adds exactly one `CandidateHostConfig`. Across two
NATs the only candidate is the private address, so ICE cannot select a pair regardless of NAT type
or shaping. `spindle-net` also has no relay transport, so there is no production S2 relay path to
measure. (This section is the better home than the S19 results file because it is S2's across-NATs
bar and the production signaling stack; `spikes/s19-quic-transport/RESULTS.md` carries a
cross-reference.)

## Harness and topology

- `spikes/s2-nat-lab` (new): `s2-host`/`s2-client` bins driving the production
  `SignalingHost`/`SignalingClient` with a lab-local `RegistryAuthorizer` (the live tests' test
  double), fixed lab seeds, and the client's required `_INBOX_<device_fp>` prefix. No production
  crate was modified; the fixed identities stand in for membership, which is not what this
  measures.
- `deploy/lab/`: added `nat-c` 172.28.30.0/24, `gw-c` (wan 172.28.0.23), `peer-c`
  (172.28.30.2), and an unauthenticated `nats-s2` (172.28.0.15) on the wan. Host runs on
  `peer-a` (172.28.10.2, behind gw-a/nat-a); client on `peer-c` (behind gw-c/nat-c). Every gateway
  drops private→other-private forwarding for all other private subnets, so a private host
  candidate cannot be reached around a gateway. Driver: `deploy/lab/run-s2-nat.sh`.
- The NATS Auth Callout/subject scoping is deliberately not exercised (the live tests cover it);
  the lab NATS is anonymous. The production signaling types, subjects, envelopes, ICE and QUIC are
  the real ones.

## Measured (5 s ICE timeout; 5 successes wanted)

| Cell | Netem both peers | Attempts | Successes | Failures | Client failure | Host offers / answers / QUIC usable | Host-side offer→answer ms |
|------|-------------------|----------|-----------|----------|----------------|--------------------------------------|----------------------------|
| unshaped | none | 10 | 0 | 10 | `ICE trickle timed out`, 5108.6 ms median (5076.2-5128.0) | 10 / 10 / 0 | 2.369 (0.859-6.905) |
| delay50 | 50 ms | 5 | 0 | 5 | `ICE trickle timed out`, 5200.3 ms median (5188.1-5236.4) | 5 / 5 / 0 | 56.353 (54.743-61.178) |

- **The offer/answer signaling does cross the NATs.** The host received every offer and published
  every answer, and every client failure is the ICE phase (`ICE trickle timed out`), not the
  answer. The host-side offer→answer figure is the host's receipt to its own observed
  answer-published event — not the client's `ConnectTimings.offer_to_answer` (the production
  client exposes timings only on success) — but it shows the signaling path works through both
  NATs, and the 50 ms cell adds the expected delay.
- **The four phases**: offer→answer is available only in the approximate host-side form above;
  answer→ICE-selected, ICE→QUIC, and offer→usable are **undefined** because ICE never selects.
  The loopback S2 numbers (13.40 ms in the Stage 5 note; 12.33 ms re-measured 2026-09-02, total
  offer→usable) remain the only S2 numbers.
- **Relay**: no production relay transport exists, so there is no S2 relay number. The S19
  `quic-peer --transport relay` figures (77.112 MB/s unshaped symmetric, plus the shaped relay
  variants in `spikes/s19-quic-transport/RESULTS.md`) are the only relay evidence.

## What would close it

Add STUN srflx gathering (and/or TURN) to `crates/spindle-net/src/signaling/ice.rs`, then re-run
`deploy/lab/run-s2-nat.sh`; the two-NAT topology and harness are ready. Until then the S2
across-NATs bar is unmeasured.

## `td-c694b2` status after this attempt

- **Item 1 (ICE loopback-only)**: confirmed at the code level and empirically — across nat-a↔nat-c
  the production stack cannot select an ICE pair at all, unshaped or shaped.
- **Item 2 (S2 across-NATs number)**: still absent, with the precise blocker now named: no
  STUN/TURN candidate gathering and no relay transport in `spindle-net`.
- **Item 3 (envelope `seq` under real reordering)**: unchanged/unmeasured.

---

# S2 across-NAT after STUN/TURN (td-c3badf) — 2026-10-30

**Outcome: the production signaling stack now completes across the two-NAT lab, and the shaped
cell completes only over the TURN relay.** The host-only defect this file recorded above is fixed:
`spindle-net`'s `IceConfig` now gathers one `server_reflexive` candidate per configured STUN server
on the same bound socket, and — when TURN is configured — allocates a relay, advertises a `relay`
candidate over the existing trickle channel, and runs QUIC over the TURN relay. The default empty
`IceConfig` is still host-only, so every loopback live test is unchanged (7/7 `live_signaling`
tests still pass).

## Method

- Two runs of `deploy/lab/run-s2-nat.sh`, same topology and cells (host `peer-a` behind
  nat-a/gw-a, client `peer-c` behind nat-c/gw-c, lab NATS `nats-s2`), same 5 s ICE timeout, N=5
  successes wanted:
  1. **punch**: `STUN_SERVER=172.28.0.14:3478`, no TURN (`RUNS=5 MAX_ATTEMPTS=50` unshaped so the
     medians have N=5; `DELAYED_MAX_ATTEMPTS=5` shaped);
  2. **relay**: `TURN_SERVER=172.28.0.13:3478`, REST secret `spindle-turn-dev-only`, label
     `s2-lab` (`RUNS=MAX_ATTEMPTS=5`).
- Raw per-attempt JSON: `deploy/lab/.artifacts/s2r3-punch/` and `deploy/lab/.artifacts/s2r3-relay/`
  (gitignored). These are the post-review runs: gathering is off the offer/answer path, TURN
  allocation happens after the answer, and the relay adapter has a refresh/release driver,
  source/peer filtering, a bounded send backlog, and prompt backlog wakeups. After the
  allocation-release guard landed, a relay-only confirmation run (`s2r4-relay/`) reproduced 5/5 in
  both cells: unshaped 2.076 / 1.486 / 1.519 / 7.730 ms, 50 ms 103.348 / 152.641 / 102.988 /
  462.229 ms (same four phases).

## Measured (medians)

| Cell | Netem both peers | Transport | Attempts | Successes | offer→answer ms | answer→selected ms | selected→QUIC ms | offer→usable ms |
|------|------------------|-----------|----------|-----------|-----------------|--------------------|------------------|-----------------|
| unshaped | none | punch | 40 | 5 | 4.057 | 609.705 | 7.288 | 618.903 |
| delay50 | 50 ms | punch | 5 | 0 | n/a | n/a | n/a | n/a |
| unshaped | none | relay | 5 | 5 | 1.639 | 2.018 | 1.549 | 5.761 |
| delay50 | 50 ms | relay | 5 | 5 | 104.274 | 156.961 | 103.792 | 468.909 |

- **Punch reproduces td-3c1762.** Unshaped cone:cone succeeded 5/40 (12.5%; the root-caused
  probabilistic Linux-conntrack port-allocation race — same phenomenon as the netns/compose ~25%,
  with run-to-run variance; earlier runs of this cell got 1/10, 5/24 and 5/33). At 50 ms both
  sides: 0/5, every failure `ICE trickle timed out` (median 5234.2 ms). The host received all 40/5
  offers and published all 40/5 answers, so the failures are ICE, not signaling.
- **Relay completes every attempt, shaped included.** 5/5 unshaped and 5/5 at 50 ms, all
  `transport=relay`; failures: none. Offer→usable medians 5.761 ms unshaped and 468.909 ms shaped.
- **Gathering is off the answer path (review fix 1).** The answer/offer is published with the host
  candidate only; STUN runs concurrently with ICE checks inside the drive, and TURN allocation runs
  after the answer. Shaped offer→answer fell from 257.505 ms (pre-fix, allocation on the critical
  path) to 104.274 ms, which is now just the NATS round trips.
- **Phase meaning on the relay path.** `answer→selected` measures "answer verified → TURN
  allocation and CreatePermission complete", not an ICE selection. The allocation's two coturn
  round trips now sit there (156.961 ms shaped), not in offer→answer.

## What this slice does and does not prove

- **Done:** STUN srflx gathering concurrent with ICE; relay allocation after the answer + `relay`
  candidate trickle; permission create; QUIC over a custom `quinn::AsyncUdpSocket` TURN adapter;
  both roles (`ConnectOptions` and `HostOptions` gain `ice: IceConfig`). Credentials come from
  config: static pair or the A8 REST secret+label (coturn `use-auth-secret`), TTL bounded to
  1 s..=24 h. The helper's `helper.turn.get.<nfp>` minting is the production credential source and
  is **not called** here.
- **Review fixes in the adapter/gather paths:** STUN responses are matched by transaction id and
  validated (Binding Success, usable address, same family), so a spoofed response cannot inject a
  candidate; the relay adapter drops wire packets from anything but the configured TURN server and
  relayed data attributed to anything but the negotiated peer; `poll_writable` re-registers after a
  `WouldBlock`, and the send backlog is capped on enqueue while remaining drainable; a driver keeps
  rtc-turn's allocation/permission timers running; a setup-failure guard releases an allocation
  that never reaches the relay socket. On teardown `Drop` **enqueues** a zero-lifetime Refresh and
  sends it once, best-effort — coturn's receipt/acceptance of that release is not verified, and the
  lab sessions last seconds, so neither the release nor the 300 s/600 s refresh is proven over a
  long-lived relay.
- **Not done (scoped follow-up, td-870b25):** punch-first-with-relay-fallback. When TURN is
  configured this slice selects the relay unconditionally; TURN absent means punch only.
  `rtc-ice` cannot route connectivity checks through TURN, and a per-attempt fallback needs both
  peers to agree on the outcome — the conntrack failure is one-sided, so an uncoordinated fallback
  could leave one peer punched and the other relayed.
- **Relay refresh not proven over a real 5-minute session.** The driver and release paths are
  unit-tested (tick clamping, 1 s..=24 h TTL bounds), and the lab relay cells run for seconds, not
  minutes. A >5-minute relayed transfer (past the 300 s permission lifetime) was **not** run.
- **Still one kernel:** both peers are containers in Docker Desktop's Linux VM. This is not S19's
  real-two-host leg, and the relay numbers say nothing about real-WAN relay throughput.

## Tickets

- `td-c3badf`: production STUN srflx + TURN relay (this work). Landed: slice 1 and relay-only
  slice 2, plus the adversarial-review fixes above, measured here.
- `td-c694b2`: the across-NATs S2 number now exists for both transports; its reordering item is
  still unmeasured.
- `td-3c1762`: the punch numbers above are a further reproduction of its root cause, not new
  evidence. Earlier punch runs are retained in `deploy/lab/.artifacts/s2r2-*`,
  `s2-punch-n5/` and `s2-punch/`.
- `td-870b25`: punch-first arbitration (landed; A10.54, this file's newest section), the hostd
  operator surface, and the helper-credential client's **app wiring** (the client half landed in
  `spindle-client-core::turn_credentials`; only URI→transport conversion and the call site remain).

---

# Punch-first with a shared local window (td-870b25) — 2026-10-30

**Outcome: success on this lab — zero transport splits and zero one-sided selections in 50 attempts
with TURN configured on both peers.** The shared local window selected the same transport on both
sides in every observed attempt: the unshaped cell punched 5/40 (12.5%, reproducing td-3c1762) and
**both** sides selected `punch` on each of those five; the other 35 attempts and all 10 shaped
attempts fell back to `relay` on both sides. The cost is the full 3 s window spent on every relay
attempt (offer→usable ≈ 3.0 s unshaped, ≈ 3.4 s at 50 ms, versus 5.8 ms / 468.9 ms for the
td-c3badf relay-only path).

## Policy under test

`IceConfig` gained `punch_window` (default **3 s**, exposed so tests and lab runs can shorten it).
With `turn` configured, both roles allocate TURN in parallel with an ICE attempt bounded by that
window:

- a pair present at the deadline check → use the punched socket and release the relay allocation
  (the existing `AllocationGuard`; the window bounds how long to wait, not whether an
  already-selected pair is used);
- window expiry → stop/tear down the ICE agent, then `CreatePermission` + the relay socket (the
  previous relay path);
- allocation failure → log and continue punch-only;
- no TURN configured → exactly the pre-td-870b25 punch-only path.

The window starts at each side's first ICE poll after the offer/answer exchange: the host once it
has published the answer **and** its host candidate, the client once it has verified the answer and
published its host candidate. The two deadlines therefore differ by the answer's one-way NATS leg
plus the client's verification/decryption — less than one RTT, not a full round trip — and both
peers must use the same `punch_window` (positive values validated to 100 ms..=60 s; `0` is the
explicit relay-only mode, used by the long-relay refresh proof, which skips the ICE attempt). Both
roles log
`transport selected` with the session id before the QUIC handshake, so the two sides can be joined
per attempt even when the handshake fails.

There is no wire field coordinating the choice (the user decision rejected a signed wire decision
for now). A **split** — one peer punched, the other relayed — is the asymmetry `td-8da43e` warned
about: td-3c1762's conntrack mapping failure is one-sided. A split fails the QUIC handshake. Both
roles now bound the handshake at 10 s, so the attempt fails and the caller retries instead of the
host task hanging; the trickle bridge, candidate tee, ICE agent and allocation are torn down on
every path (RAII `AbortOnDrop` replaced the relay path's explicit `bridge.abort()`, which was
skipped whenever allocation or a publish failed).

## Method

- `deploy/lab/run-s2-nat.sh`, same two-NAT topology as the td-c3badf section (host on `peer-a`
  behind nat-a/gw-a, client on `peer-c` behind nat-c/gw-c, lab NATS `nats-s2`),
  `STUN_SERVER=172.28.0.14:3478`, `TURN_SERVER=172.28.0.13:3478` on **both** peers,
  `PUNCH_WINDOW_MS=3000` (the production default), 5 s ICE timeout.
- Cells: unshaped `RUNS=40 MAX_ATTEMPTS=40`; 50 ms both peers `RUNS=40 DELAYED_MAX_ATTEMPTS=10`.
- Each peer was built with a JSON `tracing` subscriber (lab-only) that carries the production
  `transport selected` event. The harness joins the two sides by session id and reports, per cell:
  attempts / successes / failures, each side's transport counts, joined sessions, **splits** (both
  sides selected, different transports), and one-sided sessions (one side selected, the other did
  not).
- Raw artifacts: `deploy/lab/.artifacts/s2punch-first/` (gitignored).

## Measured

| Cell | Netem both peers | Attempts | Successes | Failures | Client transports | Host transports | Joined | Splits | One-sided | Punch phases (n) | Relay phases (n) |
|------|------------------|----------|-----------|----------|-------------------|------------------|--------|--------|-----------|------------------|------------------|
| unshaped | none | 40 | 40 | 0 | punch 5 / relay 35 | punch 5 / relay 35 | 40 | **0** | **0** | 4.846 / 613.567 / 7.075 / 636.005 ms (n=5) | 10.105 / 3011.243 / 10.990 / 3037.235 ms (n=35) |
| delay50 | 50 ms | 10 | 10 | 0 | punch 0 / relay 10 | punch 0 / relay 10 | 10 | **0** | **0** | — | 113.277 / 3059.521 / 112.363 / 3394.280 ms (n=10) |

Phase columns are medians of `offer→answer / answer→selected / selected→QUIC / offer→usable`, in
ms. On a relay attempt `answer→selected` measures "answer verified → TURN allocation and
CreatePermission complete", not an ICE selection.

The five unshaped punch attempts were #3, #5, #22, #29 and #34 (session ids in the harness
output); each reported `client=punch host=punch`. Every other attempt reported
`client=relay host=relay`. The per-attempt lines and raw JSON are in
`deploy/lab/.artifacts/s2punch-first/` (gitignored).

**Review follow-up (2026-10-30).** This run predates three review fixes to the selection policy:
a pair **present at the deadline check** now wins (the deadline branch gives the drive a bounded
10 ms final poll, and `decide_after_window` uses `<=`, so a publish body in flight at the boundary
cannot lose an already-selected pair to the deadline branch); `punch_window` is validated to
100 ms..=60 s (`SignalingError::PunchWindow`, never an `Instant + Duration` panic); and the
relay-candidate fan-out is a bounded capacity-1 channel fed by `try_send`, so a peer cannot grow it
by streaming `typ relay` lines. The first fix can only turn a would-be relay into a punch, so it
cannot introduce a split the measured policy did not have, but a **confirmation run is pending** —
deferred because another agent's long-relay session uses the same `spindle-lab` compose project,
whose fixed 172.28.x subnets and image tags make a concurrent isolated copy unsafe. Unit tests pin
the at-deadline → punch policy and the bounds.

## Reading the result

- **Agreement held in this lab, on this sample.** In 50 attempts the two peers never selected
  different transports, and no attempt was one-sided (one side selecting while the other did not).
  That is the failure mode the wire-less policy was most exposed to: td-3c1762's conntrack mapping
  race is one-sided, so a host-side selection with a client-side timeout would have shown up as a
  split or one-sided session. It did not.
- **What zero splits does not prove.** Only 5 of the 50 punch attempts actually selected a pair, so
  the agreement claim rests on a small punch sample. This is one kernel (Docker Desktop's Linux
  VM) with Linux-conntrack NATs; a real consumer NAT or a WAN loss/jitter distribution this lab
  cannot produce may behave differently. Zero observed splits is evidence for the policy here, not
  proof of universal agreement; A10.54 records it as revisit-able on such evidence.
- **The cost is the window.** Every relay attempt waits the full 3 s before falling back. Relay
  offer→usable is ~3.0 s unshaped and ~3.4 s at 50 ms, against 5.8 ms / 468.9 ms for the old
  relay-only path. A shorter `punch_window` trades that latency for a higher chance of cutting off
  a punch that is still converging; the 3 s default covers the lab's ~614 ms punch selection with
  large margin.
- **A punch win is fast when it happens.** Unshaped punch: ICE selects at 613.567 ms after the
  answer and QUIC completes 7 ms later (636.005 ms offer→usable), versus ~3.0 s for the relay
  fallback in the same cell. The 50 ms cell had no punch wins, as td-3c1762 predicts.
- **Handshake failure semantics were not exercised by a split** (there were none). The 10 s
  handshake bound and the RAII teardown are unit-/code-level guarantees in this run; a synthetic
  split would be needed to drive the failure path end to end. The old relay path's bridge-task leak
  on allocation/publish failure was found by inspection while replacing it, not by a lab failure.

---

# Long-lived relayed session: 300 s permission / 600 s allocation refresh (td-870b25) — 2026-10-30

**Outcome: both the 300 s permission refresh and the 600 s allocation refresh are now proven on a
real relayed session. The session nevertheless died at ~603 s, and the cause is a separate
ChannelBind stale-nonce/channel-number refresh bug — not the allocation or permission refresh.**
The 11-minute survival goal is therefore **not** met; the failure is captured below and was not
retried blindly.

## Method

```bash
CELLS_ONLY=hold HOLD_SECS=660 KEEP_ALIVE_SECS=10 HOLD_READ_TIMEOUT_SECS=30 \
  TURN_SERVER=172.28.0.13:3478 PUNCH_WINDOW_MS=0 \
  deploy/lab/run-s2-nat.sh
```

- One session, no reconnection: host `peer-a` (172.28.10.2, behind nat-a/gw-a), client `peer-c`
  (172.28.30.2, behind nat-c/gw-c), production `SignalingHost`/`SignalingClient`, lab NATS
  `nats-s2`, STUN `172.28.0.14:3478`, coturn `172.28.0.13:3478` (`use-auth-secret`, REST
  credentials). `PUNCH_WINDOW_MS=0` forces relay selection; the client reported
  `transport=relay` on every heartbeat.
- The client exchanged one control-stream frame every 10 s (`HOLD_SECS=660`, 11 min; past coturn's
  default 300 s permission and 600 s allocation lifetimes) and printed a heartbeat with `t_s`,
  `rtt_ms` and `transport`. The host echoed each frame (`host_frame` events).
- Coturn was run with `-v` in the lab compose; its stdout was captured to
  `deploy/lab/.artifacts/s2/hold-coturn.log` (gitignored). Client/host JSON are in the same
  directory (`hold-client.jsonl`, `hold-host.jsonl`).

## Measured

- **Relay path**: allocation `172.28.0.13:49184` (client), peer relay `172.28.0.13:49198`; every
  heartbeat reported `transport=relay`, RTT ~6-112 ms on the unshaped lab path.
- **Heartbeats**: 60/61 succeeded; first at **0.0019 s**, last successful at **592.478 s**.
  The 61st exchange got no echo within 30 s and was recorded as failed at **632.483 s**
  (`"failure":"no echo within 30s"`). The host had echoed the 61st frame at **603.559 s**
  (`host_frame` last `t_ms` = 603558.75), but the reply did not reach the client; the host's next
  read failed with `connection lost`.
- **Coturn evidence** (all timestamps UTC; session created 05:32:01):
  - `05:32:01.773 ALLOCATE processed, success`, `lifetime=600`, relay ports 49184/49198.
  - `CREATE_PERMISSION processed, success` with `peer lifetime updated: 300` at 05:32:01,
    05:34:01, 05:36:01, 05:38:01, 05:40:01 and 05:42:01 — every 120 s, matching `rtc-turn`'s
    `PERM_REFRESH_INTERVAL=120s` / `PERM_LIFETIME=300s`. **The 300 s permission refresh is
    proven.**
  - `REFRESH processed, success`, `lifetime=600` at **05:37:01.776** (300 s after allocation) and
    again at **05:42:01.803** (600 s). `rtc-turn` schedules the allocation refresh at
    `lifetime/2`. **The 600 s allocation refresh is proven.**
  - `CHANNEL_BIND processed, success`, `peer lifetime updated: 600` at 05:37:03.
  - At **05:42:04.274** coturn returned **`438: Stale nonce`**; from 05:42:04.305 onward it
    repeatedly returned **`CHANNEL_BIND ... error 400: You cannot use the same peer with
    different channel number`**. The client logged `bind() failed: ChannelBind error response
    (error 400: )` (`rtc-turn::client::relay:516`) and `dropping malformed TURN packet ...
    wire_len 34` (`spindle-net::signaling::turn`).

## Why the session died at ~603 s (the finding)

`rtc-turn` 0.20.3 refreshes a channel by re-sending ChannelBind with the binding's channel
number. On a **438 Stale nonce** response, `handle_channel_bind_response` updates the nonce but
deletes the binding (`binding_mgr.delete_by_addr`). The next `send_to` finds no binding, and
`BindingManager::create` assigns a **new** channel number. Coturn still held the old channel for
that peer — the channel binding had just been refreshed at 05:37:03 with `peer lifetime 600`,
valid until 05:47:03 — so it rejected the new number with 400 ("same peer with different channel
number"). The `spindle-net` TURN adapter only decodes ChannelData/Send/Data, so it logged the
34-byte error response as a malformed packet and never surfaced or recovered from the 400; the
channel binding never recovered, the host's 603.6 s echo was lost, and the client's 30 s read
timeout fired. The allocation and permission refreshes at 05:42:01 had both succeeded seconds
earlier, so this is a **channel-binding refresh** defect, not the allocation/permission path.

## What is proven, and what is not

- **Proven:** the 300 s permission refresh (CREATE_PERMISSION every 120 s, lifetime 300, data
  flowing at 592 s) and the 600 s allocation refresh (REFRESH at 300 s and 600 s, lifetime 600).
- **Not proven:** an 11-minute relayed session. It died at ~603 s on the ChannelBind stale-nonce
  retry. A production fix needs either `rtc-turn` to retry a stale-nonce ChannelBind with the
  **same** channel number (or reuse the existing binding), or `spindle-net`'s adapter to handle
  ChannelBind error responses and recover; alternatively the relay could avoid ChannelBind and use
  Send indications only, but that is a production behavior change and was not done here.
- **Limits:** one kernel (Docker Desktop's Linux VM), simulated NATs, one 660 s run, liveness
  frames rather than a throughput measurement; coturn 4.17.2. This is not S19's real-two-host leg.
  The allocation/permission refresh path is now live-proven; the channel-binding refresh remains
  the blocker for a long-lived relayed session.

## Fix and re-run — 2026-11-17 (td-67f0c5)

**Outcome: an 11-minute relayed session now completes (70/70 heartbeats, host echoed 70), and the
438/400 ChannelBind failure shape has a deterministic sub-second regression test. The live run did
not itself reproduce a mid-session 438 — see the honesty note below.**

### Fix

`rtc-turn` 0.20.3 deletes the channel binding on any failed ChannelBind. 0.21.1's source still
deletes it, and `BindingManager` is `pub(crate)`, so no public API can repair the binding from
`spindle-net`. The workspace therefore builds a patched 0.20.3 from `third_party/rtc-turn`
(`[patch.crates-io]`; rationale and maintenance note in `third_party/rtc-turn/PATCHES.md`):

- `438 Stale nonce` → keep the binding, state `Idle`; the next send re-binds the **same channel
  number** with the nonce the 438 carried.
- Any other ChannelBind error → keep the binding, state `Failed`; sends use Send Indications, so
  data continues and the bind is not retried in a spin.

`spindle-net`'s adapter also decodes TURN error responses now and logs the method plus numeric
error code (never the server's reason text), instead of only reporting the downstream symptom as
"dropping malformed TURN packet".

**Refresh path (td-8cc6d4, 2026-11-17).** The same vendored crate consumed a `438` on the
allocation Refresh: it updated the nonce, kept the old lifetime, and rescheduled the next attempt
`lifetime / 2` later — at allocation expiry. The patch retries once with the nonce the 438
carried, bounded by a per-relay flag. Covered by
`allocation_refresh_stale_nonce_retries_and_keeps_the_relay` (2 s allocation, forced 438, retry
must arrive within 750 ms, data must still flow); removing the retry makes the test fail at
`1.007 s`, i.e. it catches the next scheduled refresh rather than a retry.

### Deterministic regression

Two tests in `crates/spindle-net/src/signaling/turn.rs` drive the real adapter
(`allocate` → `create_permission` → `TurnRelaySocket`) against a fake TURN server:

- `channel_bind_stale_nonce_rebinds_the_same_channel_and_data_recovers`: server forces a 438 on
  the first ChannelBind; test asserts the retry uses the same channel number and that ChannelData
  flows both ways afterwards (inbound "pong" reaches `poll_recv`).
- `channel_bind_bad_request_keeps_the_binding_and_stops_retrying`: server forces a 400; test
  asserts no further ChannelBind is sent and inbound ChannelData still decodes.

Both tests were DEMONSTRATED to fail with the patch reverted (`left: 16384, right: 16385`; "a
failed bind must not be retried in a spin") and pass with it. They run in <1 s, so this no longer
needs an 11-minute coturn session to check. Coverage limit: both force the 438 on the **first**
bind (`Idle → Request`), while the original failure was a 438 on the periodic ChannelBind refresh.
Both enter the same state-independent handler, but no test drives the `Refresh → bind` transition
because rtc-turn's 300 s timer is not controllable here — and the live run below did not hit a
mid-session 438 either.

### Live re-run

```bash
KEEP_LAB=1 CELLS_ONLY=hold HOLD_SECS=700 KEEP_ALIVE_SECS=10 HOLD_READ_TIMEOUT_SECS=30 \
  TURN_SERVER=172.28.0.13:3478 PUNCH_WINDOW_MS=0 REBUILD=1 \
  ARTIFACTS_DIR="$PWD/deploy/lab/.artifacts/s2-hold-fix2" deploy/lab/run-s2-nat.sh
```

- Client: **70/70 heartbeats**, `transport=relay`, first 0.00047 s, last **690.707 s**, no failure;
  every heartbeat from 600.6 s through 690.7 s succeeded (RTT 3.6–16.5 ms). Host echoed 70 frames;
  client exit 0.
- Coturn (full log read after stopping the container — see the buffering note):
  `ALLOCATE` at 07:43:42; `CHANNEL_BIND processed, success` at 0 s, **300 s (07:48:42.49)** and
  **600 s (07:53:42.79)**; `REFRESH processed, success` at 300 s and 600 s; no `400` anywhere.
  The two `438` lines at 07:55:22 appear at teardown, after the data path had ended (the
  zero-lifetime Refresh releases are the likely source); no `400` was logged anywhere.
- The retained `hold-coturn.log` is the **131-line pre-flush capture**: the 600 s `CHANNEL_BIND`
  and later lines above were read from `docker logs` after `docker stop` and are not in that
  file. `run-s2-nat.sh` now performs that stop/dump/restart so the next run's artifact is complete.
- A first fixed-build run (`s2-hold-fix`) also completed: 66/66 heartbeats, last 650.745 s, host
  66 echoes.

**Honesty note.** This run's 600 s allocation `REFRESH` succeeded and the ChannelBind refresh
0.58 s later also succeeded, so the live session never hit a mid-session 438. It therefore proves
the >11-minute liveness goal and that the fix does not regress the normal path, but it does **not**
by itself prove the stale-nonce retry; that proof is the deterministic fake-server test above. The
original failure was timing-dependent: it needed the nonce to expire between the allocation
refresh and the channel refresh.

**Lab note (cost an hour to discover):** coturn stdout is block-buffered when not a TTY. Logs
written after ~600 s stayed in coturn's stdio buffer; `docker logs` showed nothing past that point
until the container was stopped (131 → 146 lines). Read coturn evidence only after `docker stop`.

**Limits:** one kernel (Docker Desktop's Linux VM), simulated NATs, liveness frames rather than
throughput. Not S19's real-two-host leg.

## Limitation restated (td-c694b2, 2026-11-17)

Envelope `seq` behaviour under **real reordering** remains unmeasured. DESIGN v0.9.14 settles the
semantics (a retry is a new envelope with a fresh `seq`, never a byte-identical retransmit), and a
reordering-capable substrate exists (netem `reorder 25% 50%`), but no test drives envelope-level
reordering. Do not report S2 as fully met on this basis; items 1 (srflx/relay gathering) and 2
(across-NAT relay number) are closed, item 3 is this limitation.
