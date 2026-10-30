#!/usr/bin/env bash
# S2 across-NAT measurement driver (td-c694b2).
#
# Host = peer-a (172.28.10.2, behind gw-a/nat-a). Client = peer-c (172.28.30.2, behind gw-c/nat-c).
# Both run the PRODUCTION spindle_net::{SignalingHost, SignalingClient} through a lab-local
# unauthenticated NATS (`nats-s2` on the wan). Cells: unshaped cone:cone and 50 ms both peers.
#
# What this can and cannot measure is determined by the production code, not by this script:
# `spindle-net/src/signaling/ice.rs` gathers a single host candidate and nothing else (no STUN,
# no TURN), so across NATs the only candidate is the private address and ICE cannot select a pair.
# The script therefore records the offer/answer signaling phase (which does cross the NATs via
# NATS) and the ICE failure; it does not invent an across-NAT usable-stream number. The production
# stack also has no relay transport, so there is no production S2 relay number to measure.
#
# Usage: deploy/lab/run-s2-nat.sh   (KEEP_LAB=1 to leave the lab up; RUNS/MAX_ATTEMPTS overrides)
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

if ! docker image inspect "$S2_IMAGE" >/dev/null 2>&1; then
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
  compose exec -d peer-a sh -c "rm -f /tmp/s2-host.jsonl; NATS_URL='$NATS_URL' BIND_IP='$HOST_BIND' ICE_TIMEOUT_MS='$ICE_TIMEOUT_MS' /usr/local/bin/s2-host >/tmp/s2-host.jsonl 2>&1"
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
echo "Signaling: $NATS_URL (lab-local unauthenticated NATS). Production ICE is host-candidates-only:"
echo "no STUN, no TURN, so the only candidate across these NATs is a private address."
echo ""
echo "| Cell | Netem (both peers) | Attempts | Successes | Failures | offer->answer ms (median) | answer->selected ms | selected->QUIC ms | offer->usable ms |"
echo "|------|--------------------|----------|-----------|----------|---------------------------|---------------------|-------------------|------------------|"
for label in unshaped delay50; do
  f="$ARTIFACTS_DIR/$label-client.jsonl"
  summary=$(jq -c 'select(.attempts != null and .successes != null)' "$f" 2>/dev/null | tail -1)
  if [ -z "$summary" ]; then
    echo "| $label | - | - | - | - | - | - | - | - |"
    continue
  fi
  attempts=$(printf '%s' "$summary" | jq -r '.attempts')
  successes=$(printf '%s' "$summary" | jq -r '.successes')
  failures=$(printf '%s' "$summary" | jq -r '.failures')
  a=$(printf '%s' "$summary" | jq -r '.offer_to_answer_ms_median // "n/a"')
  b=$(printf '%s' "$summary" | jq -r '.answer_to_selected_ms_median // "n/a"')
  c=$(printf '%s' "$summary" | jq -r '.selected_to_quic_ms_median // "n/a"')
  d=$(printf '%s' "$summary" | jq -r '.offer_to_stream_ms_median // "n/a"')
  if [ "$label" = "unshaped" ]; then netem="none"; else netem="50 ms"; fi
  echo "| $label | $netem | $attempts | $successes | $failures | $a | $b | $c | $d |"
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
echo "### Why there is no across-NAT usable-stream number"
echo ""
echo "Production ICE gathers one host candidate and no STUN/TURN (crates/spindle-net/src/signaling/ice.rs)."
echo "Across nat-a<->nat-c that candidate is the private address, which the gateways drop; the ICE phase"
echo "cannot select a pair, so answer->selected / selected->QUIC / offer->usable are undefined. The"
echo "offer/answer signaling itself does cross the NATs (host events above). The production stack has no"
echo "relay transport either, so there is no production S2 relay number; the S19 quic-peer relay figures"
echo "in spikes/s19-quic-transport/RESULTS.md are the only relay evidence."
echo ""
echo "Raw artifacts: $ARTIFACTS_DIR"
