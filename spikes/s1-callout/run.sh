#!/usr/bin/env bash
# S1 end-to-end runner (docs/SPIKES.md §S1 / docs/DESIGN.md §A13): stands up a real
# `nats-server` with Auth Callout configured, starts the real responder (wiring
# `spindle_helper::authz` to the wire), runs the 19-check negative-test suite against it, tears
# everything down, and prints a PASS/FAIL summary. See RESULTS.md for what each check proves.
#
# Usage (from anywhere — path-independent):
#   spikes/s1-callout/run.sh
#
# Requires: docker, and the pinned Rust toolchain on PATH (mise shims, or any `cargo`/`rustc`
# satisfying the workspace's mise.toml pin).
#
# Idempotent / re-runnable: always removes any stale `s1-nats-test` container before starting a
# fresh one, and tears its own container + responder process down on exit (including on failure —
# `trap ... EXIT`), so a prior crashed run never blocks a later one and this script never leaves
# background state behind.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SPIKE_DIR="$REPO_ROOT/spikes/s1-callout"
CONTAINER_NAME="s1-nats-test"
NATS_PORT=14222
WS_PORT=18080
MON_PORT=18222

# Dev/local, throwaway key material only (see server.conf's own dev-note and RESULTS.md's
# "Dependencies added" section) — matches the nkeys embedded in server.conf's `accounts` and
# `auth_callout` blocks. Generated once via `cargo run -p spike-s1-callout --bin genkeys`;
# regenerate both together (this script's seeds AND server.conf's public keys) if either changes.
export CALLOUT_USER_SEED="SUAGWDRUTFTCVRB6RBV54MQVXG7S7TM7FVWUTNPZPLDGKA5YRZN6QE4QU4"
export APP_ACCOUNT_SEED="SAALEVKISF5A5DKY34SNMIAD6VVT3J2DK4R7RNHXZNA3IGSQD2KL2NJK34"
export NATS_URL="nats://127.0.0.1:${NATS_PORT}"

RESPONDER_PID=""
RESPONDER_LOG="$(mktemp -t s1-responder-log)"

cleanup() {
  if [ -n "$RESPONDER_PID" ]; then
    kill "$RESPONDER_PID" >/dev/null 2>&1 || true
  fi
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== S1: building responder + s1-tests ==" >&2
( cd "$REPO_ROOT" && cargo build -p spike-s1-callout --bin responder --bin s1-tests )
RESPONDER_BIN="$REPO_ROOT/target/debug/responder"
TESTS_BIN="$REPO_ROOT/target/debug/s1-tests"

echo "== S1: starting nats-server (container '$CONTAINER_NAME') ==" >&2
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER_NAME" \
  -p "${NATS_PORT}:4222" -p "${WS_PORT}:8080" -p "${MON_PORT}:8222" \
  -v "$SPIKE_DIR/server.conf:/etc/nats/server.conf:ro" \
  nats:2.10-alpine -c /etc/nats/server.conf -m 8222 >/dev/null

# Wait for the monitor endpoint to answer rather than a fixed sleep — bounded retry, not an
# indefinite hang if the container fails to start.
echo "== S1: waiting for nats-server readiness ==" >&2
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${MON_PORT}/varz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
if ! curl -fsS "http://127.0.0.1:${MON_PORT}/varz" >/dev/null 2>&1; then
  echo "S1: nats-server never became ready (see 'docker logs $CONTAINER_NAME')" >&2
  exit 1
fi

echo "== S1: starting responder ==" >&2
"$RESPONDER_BIN" >"$RESPONDER_LOG" 2>&1 &
RESPONDER_PID=$!
sleep 1
if ! kill -0 "$RESPONDER_PID" >/dev/null 2>&1; then
  echo "S1: responder exited immediately — log:" >&2
  cat "$RESPONDER_LOG" >&2
  exit 1
fi

echo "== S1: running negative-test suite ==" >&2
set +e
"$TESTS_BIN"
RESULT=$?
set -e

echo "== S1: responder log ($RESPONDER_LOG) ==" >&2
cat "$RESPONDER_LOG" >&2

exit "$RESULT"
