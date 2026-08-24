# deploy/Dockerfile — builds the spindle-helper service image for the reference deployment
# (docs/DESIGN.md §A9b). Build context is the repo root (docker-compose.yml's `context: ..`),
# because spindle-helper is one member of the Cargo workspace and `cargo build` needs the whole
# workspace manifest graph (crates/* + the pinned spike crates) to resolve, even though only the
# spindle-helper binary is produced.
#
# ADR-010 notes Dockerfile.toolchain (repo root) as the base for the helper's *release* image
# "later" (mise-provisioned, matching CI/dev exactly). This slice (Stage 4 slice 2) intentionally
# does NOT build on that yet — a plain multi-stage build against an official `rust` image is
# simpler and sufficient to prove the compose stack end to end; switching the builder stage to
# `Dockerfile.toolchain` is a follow-up, not a blocker for this slice.

# --- builder -------------------------------------------------------------------------------
FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Whole-workspace manifest graph first (see header comment) — crates/* and the spike crates
# listed by hand in the root Cargo.toml, since a bare `spikes/*` glob member is deliberately not
# used there (see that file's own comment).
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ ./crates/
COPY spikes/ ./spikes/

RUN cargo build --release -p spindle-helper

# --- runtime -------------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin helper

COPY --from=builder /workspace/target/release/spindle-helper /usr/local/bin/spindle-helper

USER helper
ENTRYPOINT ["/usr/local/bin/spindle-helper"]
