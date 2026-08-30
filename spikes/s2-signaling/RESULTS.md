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
