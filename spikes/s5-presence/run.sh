#!/usr/bin/env bash
# S5 end-to-end runner (docs/SPIKES.md §S5 / docs/DESIGN.md §A13): brings up the composed
# reference deployment (deploy/docker-compose.yml — nats + postgres + helper; coturn is left
# running too, compose has no simple way to start "everything except one service" without
# `--scale coturn=0`, and it costs nothing to leave it up), builds and runs the S5 harness
# (src/bin/s5-tests.rs) against it, dumps the helper's own debug log (real $SYS/CONNZ payload
# samples — see RESULTS.md), and always brings the stack back down on exit.
#
# Usage (from anywhere — path-independent):
#   spikes/s5-presence/run.sh
#
# Requires: docker (with the `compose` plugin), and the pinned Rust toolchain on PATH (mise
# shims). macOS/Linux only — `kill -STOP`/`-CONT` (job-control signals) are what the dead-socket
# scenario depends on.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/deploy/docker-compose.yml"
HELPER_LOG="$REPO_ROOT/spikes/s5-presence/.s5-helper.log"

cleanup() {
  echo "== S5: dumping helper log to $HELPER_LOG ==" >&2
  docker compose -f "$COMPOSE_FILE" logs helper >"$HELPER_LOG" 2>&1 || true
  echo "== S5: bringing the compose stack down ==" >&2
  docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== S5: building fake_host + s5-tests ==" >&2
( cd "$REPO_ROOT" && cargo build -p spike-s5-presence --bin fake_host --bin s5-tests ) || exit 1

echo "== S5: bringing up nats + postgres + helper (docker compose --build) ==" >&2
docker compose -f "$COMPOSE_FILE" up -d --build nats postgres helper || exit 1

echo "== S5: waiting for nats-server readiness ==" >&2
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:8222/varz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
if ! curl -fsS "http://127.0.0.1:8222/varz" >/dev/null 2>&1; then
  echo "S5: nats-server never became ready" >&2
  exit 1
fi

# The helper needs a moment past nats readiness to connect both its own connections, run
# migrations, subscribe to $SYS.ACCOUNT.*.CONNECT|DISCONNECT and helper.presence.get.*, and seed
# its presence map from CONNZ — there is no health check exposed for this (deploy/README.md notes
# nats-server:2.10-alpine's compose healthcheck limitation applies to the helper container too).
echo "== S5: giving the helper a few seconds to finish starting ==" >&2
sleep 5

echo "== S5: running the S5 harness ==" >&2
NATS_URL="nats://127.0.0.1:4222" DEPLOY_COMPOSE_FILE="$COMPOSE_FILE" \
  "$REPO_ROOT/target/debug/s5-tests"
RESULT=$?

exit "$RESULT"
