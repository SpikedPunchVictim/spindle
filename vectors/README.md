# vectors/

Golden test vectors: canonical CBOR bytes and signatures for every A7b signed-artifact type
(envelope, member/invite capability, admission token, device certificate, revocation record,
admin command, host op-key certificate) — the single source of truth for what "correct wire
format" means across languages.

## How they're generated

`cargo run -p spindle-proto --bin gen-vectors` runs the Rust encoder (`spindle-proto`) over a
fixed set of inputs and writes the resulting canonical CBOR bytes plus signatures into this
directory.

## How they're verified

`@spindle/proto`'s test suite reads these files and asserts its own TypeScript canonical encoder
produces **byte-identical** output for the same inputs. This runs in CI (see
`.github/workflows/ci.yml`'s `vectors` job); any divergence between the Rust and TypeScript
canonical CBOR encoders **fails the build** (docs/DESIGN.md §A9b).

This directory is currently empty — `gen-vectors` does not exist yet (`spindle-proto`'s
`[[bin]]` entry is commented out in `crates/spindle-proto/Cargo.toml` pending the wire types
themselves). See `IMPLEMENTATION_PLAN.md` Stage 2.
