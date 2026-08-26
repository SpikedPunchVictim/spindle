# vectors/

Golden test vectors: canonical CBOR bytes for every A7b signed-artifact type (envelope,
member/invite capability, admission token, device certificate, revocation record, admin command,
host op-key certificate), plus a primitive-level canonical CBOR encoding vector file — the single
source of truth for what "correct wire format" means across languages.

## Files

| File | Contents |
|---|---|
| `envelope.json` | `Envelope` (A7) — 3 cases: first message with `eph_pk`, a later message with `eph_pk` omitted, and a `seq` value large enough to require the 8-byte canonical uint form. |
| `capability.json` | `Capability` (A4) — 2 cases: `invite` and `member` kinds. |
| `admission-token.json` | `AdmissionToken` (A3b) — 2 cases: default and custom quota profiles. |
| `device-certificate.json` | `DeviceCertificate` (A4) — 2 cases: freshly issued, re-signed on contact. **No `label` field** — see the discrepancy note on `DeviceCertificate` in `crates/spindle-proto/src/artifacts.rs` and the schema table in `crates/spindle-proto/src/lib.rs`. |
| `revocation-record.json` | `RevocationRecord` (A4) — 3 cases, including a zero-length `revoked` array (empty-array encoding edge case). |
| `admin-command.json` | `AdminCommand` (A3b/A7b) — 3 cases exercising `args` as a map, a text-valued map, and CBOR `null`. |
| `host-op-key-cert.json` | `HostOpKeyCert` (A4) — 2 cases: freshly issued, rotated. |
| `canonical-cbor.json` | Primitive canonical-CBOR encoding cases (RFC 8949 §4.2.1) independent of any Spindle artifact type: integer shortest-form boundaries (23/24/255/256/65535/65536/4294967295/4294967296), negative integers, byte strings, text strings, arrays (including empty), map key ordering (by length, and by content at equal length), nested maps, and the three allowed simple values (`true`/`false`/`null`). For validating a canonical CBOR encoder at the byte level, independent of the artifact-level vectors. |
| `vfs-rpc.json` | VFS RPC wire types (DESIGN.md §A8, Stage 6 slice 3) — **not** one of the seven A7b signed artifacts (no domain tag, no signing input), so this file's shape differs slightly from the artifact files (see below). `requests`: one case per op (`list` with and without a cursor/limit, `stat`, `read`, `mkdir`, `delete`, `whoami`). `replies`: one case per op plus every one of the eight typed [`spindle_proto::vfs_rpc::VfsErrorCode`] values (DESIGN.md's seven named codes plus this crate's own `UnsupportedVersion` addition — see that module's doc comment for why). **The TS twin (`@spindle/proto`) does not implement this schema yet** — flagged as a required follow-up before the CI vector cross-check job can cover it; see `IMPLEMENTATION_PLAN.md`'s Stage 6 slice 3 note. |

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

## How they're generated

`cargo run -p spindle-proto --bin gen-vectors` runs the Rust encoder (`spindle-proto`) over a
fixed set of inputs and writes the resulting canonical CBOR bytes (and, for artifact types, the
A7b signing input) into this directory. All inputs are fixed and deterministic, so reruns
reproduce byte-identical files — verified via `git diff` after every regeneration.

## How they're verified

`@spindle/proto`'s test suite reads these files and asserts its own TypeScript canonical encoder
produces **byte-identical** output for the same inputs. This runs in CI (see
`.github/workflows/ci.yml`'s `vectors` job); any divergence between the Rust and TypeScript
canonical CBOR encoders **fails the build** (docs/DESIGN.md §A9b).
