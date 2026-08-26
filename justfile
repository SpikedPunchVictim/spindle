# Spindle — single front door over the cargo workspace + pnpm workspace (A9c/A10.27).
# CI calls these same targets; see .github/workflows/ci.yml.

default:
    @just --list

# Bootstrap a fresh dev environment: check/install mise, provision the pinned
# toolchain (mise.toml), run per-OS native dependency checks, and install JS deps
# (ADR-010). Works even before `just` itself is installed: `bash scripts/bootstrap.sh`.
bootstrap:
    bash scripts/bootstrap.sh

# Build everything: TS packages/apps, then the Rust workspace.
build:
    pnpm install --frozen-lockfile
    pnpm -r build
    cargo build --workspace

# Test everything: TS packages/apps, then the Rust workspace.
test:
    pnpm install --frozen-lockfile
    pnpm -r test
    cargo test --workspace

# Lint everything: ESLint/Prettier/TS strict, then rustfmt + clippy.
lint:
    pnpm install --frozen-lockfile
    pnpm -r lint
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings

# Generate golden CBOR/signature test vectors from spindle-proto (A9b, A7b) and the real-signature
# crypto vectors from spindle-core (A4/A7/A7b), verify the regeneration is byte-identical to
# what's committed (no drift between the Rust encoders and vectors/*.json / vectors/signed/*.json),
# then cross-check @spindle/proto's TypeScript encoder against those same vectors.
vectors:
    cargo run -p spindle-proto --bin gen-vectors
    cargo run -p spindle-core --bin gen-crypto-vectors
    git diff --exit-code vectors/
    pnpm --filter @spindle/proto test
    pnpm --filter @spindle/crypto test

# Run the reference dev stack: NATS + Postgres + coturn + the graduated spindle-helper Auth
# Callout responder / TURN credential minter, in `open` admission mode (deploy/README.md). The
# local-CA half of "open admission with a local CA" (docs/DESIGN.md §A9b) isn't wired up yet; see
# deploy/README.md's Status section.
dev:
    docker compose -f deploy/docker-compose.yml up --build

# Produce release artifacts: signed/notarized Tauri bundles, hardened web bundle + manifest,
# helper container image, spindle-admin npm tarball (A9b).
# Not implemented yet — packaging/signing lands in the final stage.
package:
    @echo "just package: not implemented yet — see IMPLEMENTATION_PLAN.md Stage 10 (packaging/signing and release train)"
    @exit 1
