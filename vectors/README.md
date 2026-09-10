# vectors/

Golden test vectors: canonical CBOR bytes for every A7b signed-artifact type (envelope,
member/invite capability, admission token, device certificate, session attestation, revocation
record, admin command, host op-key certificate, host device certificate), plus a primitive-level
canonical CBOR encoding vector file — the single source of truth for what "correct wire format"
means across languages.

## Files

| File | Contents |
|---|---|
| `envelope.json` | `Envelope` (A7) — 3 cases: first message with `eph_pk`, a later message with `eph_pk` omitted, and a `seq` value large enough to require the 8-byte canonical uint form. |
| `capability.json` | `Capability` (A4) — 2 cases: `invite` and `member` kinds. |
| `admission-token.json` | `AdmissionToken` (A3b) — 2 cases: default and custom quota profiles. |
| `device-certificate.json` | `DeviceCertificate` (A4) — 2 cases: freshly issued, re-signed on contact. **No `label` field** — see the discrepancy note on `DeviceCertificate` in `crates/spindle-proto/src/artifacts.rs` and the schema table in `crates/spindle-proto/src/lib.rs`. **No `nats_fp` field** as of DESIGN.md v0.9.29 (A10.39, td-0bcab4): that binding moved to its own artifact, `session-attestation.json` below, closing a bearer-bundle vulnerability where nothing at CONNECT ever exercised the device's identity key. Domain tag is now `spindle-dev-cert-v2` (was `spindle-dev-cert-v1`). |
| `session-attestation.json` | `SessionAttestation` (A4, A10.39, added v0.9.29, td-0bcab4) — 2 cases: a freshly-issued attestation, and a second attestation for a different session nkey (per-session rotation). Binds a device's identity key to exactly one NATS session key via `sig_device(nats_fp, ts)`; unlike the other artifacts here, it is minted fresh per session rather than persisting across many. |
| `revocation-record.json` | `RevocationRecord` (A4) — 3 cases, including a zero-length `revoked` array (empty-array encoding edge case). |
| `admin-command.json` | `AdminCommand` (A3b/A7b) — 3 cases exercising `args` as a map, a text-valued map, and CBOR `null`. |
| `host-op-key-cert.json` | `HostOpKeyCert` (A4) — 2 cases: freshly issued, rotated. **No `nats_fp` field** as of DESIGN.md v0.9.31 (td-583db5): that binding moved to its own artifact, `host-session-attestation.json` below, domain-separating the issuance chain from the per-connect NATS credential. Domain tag is now `spindle-host-cert-v2` (was `spindle-host-cert-v1`). |
| `host-session-attestation.json` | `HostSessionAttestation` (A4/A7b, added v0.9.31, td-583db5) — 2 cases: a freshly-issued attestation, and a second attestation for a different session nkey (per-session rotation). Binds the host's operating key to exactly one NATS session key via `sig_op(nats_fp, ts)`; the exact host-side mirror of `session-attestation.json`, minted fresh per session rather than persisting across many. |
| `host-device-cert.json` | `HostDeviceCert` (A4, decision A10.35) — 2 cases: freshly issued, re-signed on the next op-key window. Self-verifying like `capability.json` (embeds `host_fp`/`host_root_pk`/`op_cert`), plus the host's dedicated `host_device_fp`/`alg_id`/`sign_pk`/`agree_pk` — the host's §A7 envelope identity, never a NATS-subject-scoping fingerprint. No `nats_fp` field — see the discrepancy note on `HostDeviceCert` in `crates/spindle-proto/src/artifacts.rs`. |
| `canonical-cbor.json` | Primitive canonical-CBOR encoding cases (RFC 8949 §4.2.1) independent of any Spindle artifact type: integer shortest-form boundaries (23/24/255/256/65535/65536/4294967295/4294967296), negative integers, byte strings, text strings, arrays (including empty), map key ordering (by length, and by content at equal length), nested maps, and the three allowed simple values (`true`/`false`/`null`). For validating a canonical CBOR encoder at the byte level, independent of the artifact-level vectors. |
| `vfs-rpc.json` | VFS RPC wire types (DESIGN.md §A8, Stage 6 slice 3) — **not** one of the ten A7b signed artifacts (no domain tag, no signing input), so this file's shape differs slightly from the artifact files (see below). `requests`: one case per op (`list` with and without a cursor/limit, `stat`, `read`, `mkdir`, `delete`, `whoami`). `replies`: one case per op plus every one of the eight typed [`spindle_proto::vfs_rpc::VfsErrorCode`] values (DESIGN.md's seven named codes plus this crate's own `UnsupportedVersion` addition — see that module's doc comment for why). **The TS twin (`@spindle/proto`) does not implement this schema yet** — flagged as a required follow-up before the CI vector cross-check job can cover it; see `IMPLEMENTATION_PLAN.md`'s Stage 6 slice 3 note. |
| `signaling.json` | Signaling payload wire types (DESIGN.md §A6/§A7, §A10.31/32), promoted from `spikes/s2-signaling`'s crate-local types — **not** one of the ten A7b signed artifacts (no domain tag, no signing input): these payloads are always the plaintext sealed inside an already-signed `Envelope`, so this file's shape matches `vfs-rpc.json`'s (see below), not the artifact files'. `offers`: `OfferPayload` cases for both `transport` values plus a boundary-length case (`inbox`/`ufrag`/`pwd` each at their length cap). `answers`: `AnswerPayload` cases for both `transport` values. `ice`: `IcePayload` cases — a host candidate, a `srflx` candidate with `raddr`/`rport`, the end-of-candidates marker (`candidate` key omitted, not CBOR null), and a boundary-length candidate. Both the Rust encoder and the TS twin (`@spindle/proto`'s `signaling.ts`) are covered by this file from the start — see `packages/proto/test/signaling.test.ts`. |
| `bootstrap.json` | Device bootstrap state bundle wire types (DESIGN.md §A4 "Adding a device (device bootstrap)", :317-330) — **not** one of the ten A7b signed artifacts (no domain tag, no signing input): the bundle travels only over the QR channel that already establishes the new device's trust, so this file's shape matches `vfs-rpc.json`'s (see below), not the artifact files'. `cases`: a one-entry bundle (the minimal realistic bootstrap), a four-entry bundle (DESIGN.md :328-329's stated EC-level-M ceiling for a version-40 QR), a zero-entry bundle (empty host list, a legal encoding), and a boundary case with `registry` at exactly `MAX_REGISTRY_LEN` bytes. Also pins the canonical key order: bundle keys emit as `v`, `entries`, `registry`; entry keys as `sign_pk`, `agree_pk`, `member_cap`. |
| `key-validity.json` | Ed25519/X25519 public-key validity parity between `spindle-core` and `@spindle/crypto` (td-b8c68a) — **not** a wire-format vector at all (no CBOR, no signing input): a flat table of raw 32-byte keys and the accept/reject verdict both languages must reach. `cases`: a byte string that fails to decompress to any Ed25519 curve point at all; `[0xff; 32]`, the non-canonical (RFC 8032 §5.1.3) encoding of `y = 18`, which bare `ed25519_dalek::VerifyingKey::from_bytes` used to accept before this ticket's fix; a genuinely derived, canonically-encoded Ed25519 key; and an X25519 low-order point (`u = 1`), which both languages deliberately **accept** — X25519 public keys are unvalidated by design on both sides (`x25519_dalek::PublicKey::from` is infallible), and this last case pins that as intentional rather than an oversight. Generated by `spindle-core`'s `gen-crypto-vectors` bin (not `spindle-proto`'s `gen-vectors`, since this is a crypto property, not a wire-format one), written directly under `vectors/` rather than `vectors/signed/` because it carries no signature to speak of. Consumed by `crates/spindle-core/tests/vectors.rs` and `packages/crypto/test/key-validity.test.ts`. |

Each artifact-level case has the shape `{name, description, decoded, canonical_cbor_hex,
signing_input_hex}`: `decoded` mirrors the Rust struct's fields as JSON (byte strings as
lowercase hex, `AdminCommand.args` as a generic `{type, value}` tree since JSON can't otherwise
distinguish CBOR byte/text strings or map key types); `canonical_cbor_hex` is the full canonical
CBOR encoding of the artifact (RFC 8949 §4.2.1); `signing_input_hex` is the A7b signature
preimage — `domain_tag || canonical(artifact minus its signature field)` for every artifact
except `Envelope`, whose preimage is `domain_tag || canonical(header) || ciphertext` (A7) since
the ciphertext itself is not re-encoded as a CBOR item. Each `canonical-cbor.json` case has the
shape `{name, description, value, canonical_cbor_hex}` with no `signing_input_hex` — primitives
aren't signed artifacts.

**Signature validity**: `spindle-proto` has no crypto dependency (DESIGN.md §A9c boundary rule
3), so every `sig`/`sig_host`/`sig_operator`/`sig_root`/`sig_host_root` field above is an opaque
fixed byte pattern (e.g. repeated `0x99`), **not** a valid signature over its `signing_input_hex`.
Vectors asserting real signature validity land in Stage 3 once `spindle-core` exists to produce
and verify real Ed25519 signatures over these same canonical bytes.

**`vfs-rpc.json`'s shape**: each case is `{name, description, decoded, canonical_cbor_hex}` — no
`signing_input_hex`, since VFS RPC messages travel inside an already-authenticated,
already-encrypted session (DESIGN.md §A8) and are never individually signed. `decoded` uses the
same generic `{type, value}` CBOR-to-JSON mirror `admin-command.json`'s open-ended `args` field
already relies on, rather than a bespoke per-op JSON shape (the six ops carry different field
sets).

**`signaling.json`'s shape**: same per-case shape as `vfs-rpc.json` — `{name, description, decoded,
canonical_cbor_hex}`, no `signing_input_hex`, same rationale (signaling payloads are the plaintext
of an already-signed `Envelope`, never signed independently). Top-level keys are `offers`,
`answers`, `ice` rather than `requests`/`replies`.

**`bootstrap.json`'s shape**: same per-case shape as `vfs-rpc.json` — `{name, description, decoded,
canonical_cbor_hex}`, no `signing_input_hex`. The bundle is unsigned not because another layer's
signature already covers it (unlike `vfs-rpc.json`/`signaling.json`'s reasoning) but because a
signature here would have no verifier the QR delivery channel doesn't already establish — see
`spindle_proto::bootstrap`'s module doc comment. Top-level key is a single flat `cases` array
(the four cases don't fall into natural request/reply-style groups the way the other two files'
cases do).

**`key-validity.json`'s shape**: `{description, cases}`, where each case is `{name, description,
curve, key_hex, expected}` — `curve` is `"ed25519"` or `"x25519"`, `key_hex` a 32-byte public key,
`expected` the verdict (`"accept"`/`"reject"`) both languages' key-validity check must reach. No
`canonical_cbor_hex`/`signing_input_hex` at all: a raw key is not itself a CBOR-encoded value.

## How they're generated

`cargo run -p spindle-proto --bin gen-vectors` runs the Rust encoder (`spindle-proto`) over a
fixed set of inputs and writes the resulting canonical CBOR bytes (and, for artifact types, the
A7b signing input) into this directory. All inputs are fixed and deterministic, so reruns
reproduce byte-identical files — verified via `git diff` after every regeneration.

`cargo run -p spindle-core --bin gen-crypto-vectors` covers the vectors that need real crypto
rather than just canonical encoding: `vectors/signed/*.json` (real Ed25519 signatures/AES-256-GCM
seals over the same canonical bytes `gen-vectors` produces) and this directory's own
`key-validity.json`. Same determinism/reproducibility guarantee as `gen-vectors`, verified the same
way (`just vectors` runs both generators, then `git diff --exit-code vectors/`).

## How they're verified

`@spindle/proto`'s test suite reads these files and asserts its own TypeScript canonical encoder
produces **byte-identical** output for the same inputs. This runs in CI (see
`.github/workflows/ci.yml`'s `vectors` job); any divergence between the Rust and TypeScript
canonical CBOR encoders **fails the build** (docs/DESIGN.md §A9b).

`crates/spindle-core/tests/vectors.rs` and `@spindle/crypto`'s test suite (`packages/crypto/test/`)
read `vectors/signed/*.json` and `key-validity.json` the same way, re-deriving/re-verifying every
signature, decrypt, and key-validity verdict independently of the generator's own in-process
assertions.
