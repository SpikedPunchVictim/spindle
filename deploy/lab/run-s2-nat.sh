#!/usr/bin/env bash
# S2 across-NAT measurement driver (td-c694b2).
#
# Host = peer-a (172.28.10.2, behind gw-a/nat-a). Client = peer-c (172.28.30.2, behind gw-c/nat-c).
# Both run the PRODUCTION spindle_net::{SignalingHost, SignalingClient} through a lab-local
# unauthenticated NATS (`nats-s2` on the wan). Cells: unshaped cone:cone and 50 ms both peers.
#
# Transport is chosen by the production config the peers receive, not by this script:
#   * default / no TURN_SERVER -- STUN srflx gathering + ICE punch. On this lab's Linux-conntrack
#     NAT the punch is probabilistic unshaped and fails at any nonzero delay (td-3c1762), so this
#     cell measures the punch honestly, including its failures.
#   * TURN_SERVER set -- the production stack (td-c3badf) uses the TURN relay unconditionally;
#     both cells should complete through coturn. The client reports which transport won.
#
# Both peers get the same STUN/TURN environment; a mismatch makes one side wait for a relay
# candidate the other never sends.
#
# Usage: deploy/lab/run-s2-nat.sh   (KEEP_LAB=1 to leave the lab up; RUNS/MAX_ATTEMPTS overrides;
#                                   REBUILD=1 to rebuild the s2lab image; TURN_SERVER=172.28.0.13:3478
#                                   to measure the relay path)
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$LAB_DIR/docker-compose.lab.yml"
PROJECT="${COMPOSE_PROJECT_NAME:-spindle-lab}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$LAB_DIR/.artifacts/s2}"
S2_IMAGE="${S2_IMAGE:-spindle-s2lab:local}"
NATS_URL="${NATS_URL:-nats://172.28.0.15:4222}"
HOST_BIND=172.28.10.2
CLIENT_BIND=172.28.30.2
RUNS="${RUNS:-5}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-10}"
DELAYED_MAX_ATTEMPTS="${DELAYED_MAX_ATTEMPTS:-$RUNS}"
ICE_TIMEOUT_MS="${ICE_TIMEOUT_MS:-5000}"
ANSWER_TIMEOUT_MS="${ANSWER_TIMEOUT_MS:-5000}"
KEEP_LAB="${KEEP_LAB:-0}"
REBUILD="${REBUILD:-0}"
# The lab's in-repo STUN responder (deploy/lab/docker-compose.lab.yml's `stun` service).
STUN_SERVER="${STUN_SERVER:-172.28.0.14:3478}"
# Empty by default (punch). Set to the lab's coturn to measure the relay path.
TURN_SERVER="${TURN_SERVER:-}"
# Must match the lab coturn's --static-auth-secret (docker-compose.lab.yml).
TURN_SECRET="${TURN_SECRET:-spindle-turn-dev-only}"
TURN_LABEL="${TURN_LABEL:-s2-lab}"

compose() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }

cleanup() {
  if [ "$KEEP_LAB" = "1" ]; then
    echo "KEEP_LAB=1: lab left running." >&2
  else
    echo "tearing down lab..." >&2
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

mkdir -p "$ARTIFACTS_DIR"

if [ "$REBUILD" = "1" ] || ! docker image inspect "$S2_IMAGE" >/dev/null 2>&1; then
  echo "== building $S2_IMAGE ==" >&2
  docker build -f "$LAB_DIR/Dockerfile.s2lab" -t "$S2_IMAGE" "$LAB_DIR/../.." || exit 1
fi

echo "== starting lab ==" >&2
compose up -d --build || exit 1

wait_ready() {
  local i
  for i in $(seq 1 180); do
    if compose exec -T gw-a sh -c 'iptables -t nat -S LAB_MASQ | grep -q MASQUERADE' 2>/dev/null \
      && compose exec -T gw-c sh -c 'iptables -t nat -S LAB_MASQ | grep -q MASQUERADE' 2>/dev/null \
      && compose exec -T peer-a sh -c 'ip route show default | grep -q 172.28.10.254' 2>/dev/null \
      && compose exec -T peer-c sh -c 'ip route show default | grep -q 172.28.30.254' 2>/dev/null \
      && compose exec -T peer-c sh -c 'nc -z 172.28.0.15 4222' 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "s2 lab not ready after 180 s" >&2
  compose ps >&2
  compose logs --tail=40 nats-s2 gw-c peer-c peer-a >&2
  return 1
}
wait_ready || exit 1

# Extract the two lab binaries from the scratch image and install them in the peers.
cid=$(docker create "$S2_IMAGE" /s2-host)
docker cp "$cid:/s2-host" "$ARTIFACTS_DIR/s2-host" >/dev/null
docker cp "$cid:/s2-client" "$ARTIFACTS_DIR/s2-client" >/dev/null
docker rm "$cid" >/dev/null
PA=$(compose ps -q peer-a)
PC=$(compose ps -q peer-c)
if [ -z "$PA" ] || [ -z "$PC" ]; then
  echo "could not resolve peer containers" >&2
  exit 1
fi
docker cp "$ARTIFACTS_DIR/s2-host" "$PA:/usr/local/bin/s2-host"
docker cp "$ARTIFACTS_DIR/s2-client" "$PC:/usr/local/bin/s2-client"

apply_netem() {
  compose exec -T "$1" /usr/local/bin/apply-netem.sh "$2" 0 0 0 >/dev/null 2>&1
}

start_host() {
  compose exec -d peer-a sh -c "rm -f /tmp/s2-host.jsonl; NATS_URL='$NATS_URL' BIND_IP='$HOST_BIND' ICE_TIMEOUT_MS='$ICE_TIMEOUT_MS' STUN_SERVERS='$STUN_SERVER' TURN_SERVER='$TURN_SERVER' TURN_SECRET='$TURN_SECRET' TURN_LABEL='$TURN_LABEL' /usr/local/bin/s2-host >/tmp/s2-host.jsonl 2>&1"
  local i
  for i in $(seq 1 100); do
    if compose exec -T peer-a sh -c 'grep -q host_ready /tmp/s2-host.jsonl 2>/dev/null'; then
      sleep 0.5
      return 0
    fi
    sleep 0.1
  done
  echo "s2-host did not report host_ready; log:" >&2
  compose exec -T peer-a cat /tmp/s2-host.jsonl >&2 2>/dev/null || true
  return 1
}

stop_host() {
  compose exec -T peer-a pkill -f /usr/local/bin/s2-host >/dev/null 2>&1 || true
  sleep 0.2
}

run_cell() {
  local label="$1" delay="$2" max="$3"
  echo "" >&2
  echo "== S2 cell $label: ${delay} ms both peers, RUNS=$RUNS MAX_ATTEMPTS=$max ==" >&2
  apply_netem peer-a "$delay"
  apply_netem peer-c "$delay"
  start_host || return 1
  compose exec -T peer-c env \
    NATS_URL="$NATS_URL" BIND_IP="$CLIENT_BIND" RUNS="$RUNS" MAX_ATTEMPTS="$max" \
    ICE_TIMEOUT_MS="$ICE_TIMEOUT_MS" ANSWER_TIMEOUT_MS="$ANSWER_TIMEOUT_MS" LABEL="$label" \
    STUN_SERVERS="$STUN_SERVER" TURN_SERVER="$TURN_SERVER" TURN_SECRET="$TURN_SECRET" \
    TURN_LABEL="$TURN_LABEL" \
    /usr/local/bin/s2-client \
    >"$ARTIFACTS_DIR/$label-client.jsonl" 2>"$ARTIFACTS_DIR/$label-client.err"
  local rc=$?
  stop_host
  compose exec -T peer-a cat /tmp/s2-host.jsonl >"$ARTIFACTS_DIR/$label-host.jsonl" 2>/dev/null || true
  echo "   client exit=$rc" >&2
}

run_cell unshaped 0 "$MAX_ATTEMPTS"
run_cell delay50 50 "$DELAYED_MAX_ATTEMPTS"

# ── report ────────────────────────────────────────────────────────────────────────────────────
echo ""
echo "## S2 across-NAT measurement (production SignalingHost/SignalingClient; simulated, one kernel)"
echo ""
echo "Host peer-a (172.28.10.2, behind nat-a/gw-a) <-> client peer-c (172.28.30.2, behind nat-c/gw-c)."
echo "Signaling: $NATS_URL (lab-local unauthenticated NATS)."
if [ -n "$TURN_SERVER" ]; then
  echo "Production gathering: STUN $STUN_SERVER + TURN $TURN_SERVER -> relay path (td-c3badf)."
else
  echo "Production gathering: STUN $STUN_SERVER, no TURN -> ICE punch (host + srflx candidates)."
fi
echo ""
echo "| Cell | Netem (both peers) | Attempts | Successes | Failures | Transport (ok attempts) | offer->answer ms (median) | answer->selected ms | selected->QUIC ms | offer->usable ms |"
echo "|------|--------------------|----------|-----------|----------|-------------------------|---------------------------|---------------------|-------------------|------------------|"
for label in unshaped delay50; do
  f="$ARTIFACTS_DIR/$label-client.jsonl"
  summary=$(jq -c 'select(.attempts != null and .successes != null)' "$f" 2>/dev/null | tail -1)
  if [ -z "$summary" ]; then
    echo "| $label | - | - | - | - | - | - | - | - | - |"
    continue
  fi
  attempts=$(printf '%s' "$summary" | jq -r '.attempts')
  successes=$(printf '%s' "$summary" | jq -r '.successes')
  failures=$(printf '%s' "$summary" | jq -r '.failures')
  punch=$(printf '%s' "$summary" | jq -r '.punch_successes // 0')
  relay=$(printf '%s' "$summary" | jq -r '.relay_successes // 0')
  a=$(printf '%s' "$summary" | jq -r '.offer_to_answer_ms_median // "n/a"')
  b=$(printf '%s' "$summary" | jq -r '.answer_to_selected_ms_median // "n/a"')
  c=$(printf '%s' "$summary" | jq -r '.selected_to_quic_ms_median // "n/a"')
  d=$(printf '%s' "$summary" | jq -r '.offer_to_stream_ms_median // "n/a"')
  if [ "$label" = "unshaped" ]; then netem="none"; else netem="50 ms"; fi
  used="punch=${punch}, relay=${relay}"
  echo "| $label | $netem | $attempts | $successes | $failures | $used | $a | $b | $c | $d |"
done

echo ""
echo "### Host-observed signaling events (proves the offer/answer crossed the NATs via NATS)"
echo ""
for label in unshaped delay50; do
  h="$ARTIFACTS_DIR/$label-host.jsonl"
  offers=$(jq -r 'select(.event=="offer_received")|.event' "$h" 2>/dev/null | wc -l | tr -d ' ')
  answers=$(jq -r 'select(.event=="answer_published")|.event' "$h" 2>/dev/null | wc -l | tr -d ' ')
  usable=$(jq -r 'select(.event=="quic_usable")|.event' "$h" 2>/dev/null | wc -l | tr -d ' ')
  echo "- \`$label\`: offer_received=$offers answer_published=$answers quic_usable=$usable"
done

echo ""
echo "### Failure mode / time (client side)"
echo ""
for label in unshaped delay50; do
  f="$ARTIFACTS_DIR/$label-client.jsonl"
  echo "- \`$label\` errors:"
  jq -r 'select(.status=="failed")|.error' "$f" 2>/dev/null | sort | uniq -c | sed 's/^/  /'
  jq -s '[.[]|select(.status=="failed")|.elapsed_ms] | if length==0 then "  (none)" else "  failures=\(length) elapsed_ms min=\(min) max=\(max) median=\(sort|.[length/2|floor])" end' "$f" 2>/dev/null | sed 's/^/  /'
done

echo ""
echo "### Reading this table"
echo ""
echo "Production gathering is STUN srflx + ICE punch unless TURN_SERVER was set, in which case the"
echo "stack uses coturn's relay unconditionally (crates/spindle-net/src/signaling/{ice,turn}.rs)."
echo "On this lab's Linux-conntrack NAT, the punch is probabilistic unshaped and fails at any nonzero"
echo "delay (td-3c1762); failures in a punch cell are ICE 'trickle timed out', not signaling failures"
echo "(the host-observed counts above prove offers/answers crossed both NATs). A relay cell should"
echo "complete every attempt with transport=relay. Raw artifacts: $ARTIFACTS_DIR"
