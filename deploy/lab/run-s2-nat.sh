#!/usr/bin/env bash
# S2 across-NAT measurement driver (td-c694b2).
#
# Host = peer-a (172.28.10.2, behind gw-a/nat-a). Client = peer-c (172.28.30.2, behind gw-c/nat-c).
# Both run the PRODUCTION spindle_net::{SignalingHost, SignalingClient} through a lab-local
# unauthenticated NATS (`nats-s2` on the wan). Cells: unshaped cone:cone and 50 ms both peers.
#
# Transport is chosen by the production stack from the peers' config, not by this script:
#   * default / no TURN_SERVER -- STUN srflx gathering + ICE punch. On this lab's Linux-conntrack
#     NAT the punch is probabilistic unshaped and fails at any nonzero delay (td-3c1762), so this
#     cell measures the punch honestly, including its failures.
#   * TURN_SERVER set -- punch-first with a shared local window (td-870b25): the production stack
#     allocates in parallel with an ICE attempt bounded by PUNCH_WINDOW_MS, uses the punched socket
#     if a pair is selected, and otherwise falls back to the relay. Each side logs
#     `transport selected` with its session id; the report below joins the two sides per attempt and
#     counts splits (both sides selected, different transports).
#
# Both peers get the same STUN/TURN environment and the same PUNCH_WINDOW_MS; a mismatch makes one
# side switch while the other is still punching (a split, which fails the QUIC handshake).
#
# Usage: deploy/lab/run-s2-nat.sh   (KEEP_LAB=1 to leave the lab up; RUNS/MAX_ATTEMPTS overrides;
#                                   REBUILD=1 to rebuild the s2lab image; TURN_SERVER=172.28.0.13:3478
#                                   to measure punch-first with the relay fallback)
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
# Empty by default (punch). Set to the lab's coturn to measure punch-first + relay fallback.
TURN_SERVER="${TURN_SERVER:-}"
# The shared punch window (production default 3000 ms); both peers must receive the same value.
PUNCH_WINDOW_MS="${PUNCH_WINDOW_MS:-3000}"
# Must match the lab coturn's --static-auth-secret (docker-compose.lab.yml).
TURN_SECRET="${TURN_SECRET:-spindle-turn-dev-only}"
TURN_LABEL="${TURN_LABEL:-s2-lab}"
# td-870b25 long-hold: HOLD_SECS>0 runs ONE relayed session for that long with a frame exchange
# every KEEP_ALIVE_SECS, forcing relay selection with PUNCH_WINDOW_MS=0. Use CELLS_ONLY=hold to run
# only this cell. 660 s is 11 minutes: past coturn's 300 s permission and 600 s allocation
# lifetimes.
HOLD_SECS="${HOLD_SECS:-0}"
KEEP_ALIVE_SECS="${KEEP_ALIVE_SECS:-10}"
HOLD_READ_TIMEOUT_SECS="${HOLD_READ_TIMEOUT_SECS:-30}"
CELLS_ONLY="${CELLS_ONLY:-}"

compose() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }

should_run() {
  [ -z "$CELLS_ONLY" ] && return 0
  case ",$CELLS_ONLY," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

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
  compose exec -d peer-a sh -c "rm -f /tmp/s2-host.jsonl; NATS_URL='$NATS_URL' BIND_IP='$HOST_BIND' ICE_TIMEOUT_MS='$ICE_TIMEOUT_MS' STUN_SERVERS='$STUN_SERVER' PUNCH_WINDOW_MS='$PUNCH_WINDOW_MS' TURN_SERVER='$TURN_SERVER' TURN_SECRET='$TURN_SECRET' TURN_LABEL='$TURN_LABEL' /usr/local/bin/s2-host >/tmp/s2-host.jsonl 2>&1"
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
    STUN_SERVERS="$STUN_SERVER" PUNCH_WINDOW_MS="$PUNCH_WINDOW_MS" TURN_SERVER="$TURN_SERVER" \
    TURN_SECRET="$TURN_SECRET" TURN_LABEL="$TURN_LABEL" \
    /usr/local/bin/s2-client \
    >"$ARTIFACTS_DIR/$label-client.jsonl" 2>"$ARTIFACTS_DIR/$label-client.err"
  local rc=$?
  stop_host
  compose exec -T peer-a cat /tmp/s2-host.jsonl >"$ARTIFACTS_DIR/$label-host.jsonl" 2>/dev/null || true
  echo "   client exit=$rc" >&2
}

run_hold() {
  local label="hold"
  if [ -z "$TURN_SERVER" ]; then
    echo "HOLD_SECS>0 requires TURN_SERVER (a relay-only hold has nothing to test)" >&2
    return 1
  fi
  echo "" >&2
  echo "== S2 hold: relay session for ${HOLD_SECS}s, keepalive ${KEEP_ALIVE_SECS}s, PUNCH_WINDOW_MS=0 ==" >&2
  apply_netem peer-a 0
  apply_netem peer-c 0
  local coturn_id
  coturn_id=$(compose ps -q coturn)
  : >"$ARTIFACTS_DIR/hold-coturn.log"
  local coturn_log_pid=""
  if [ -n "$coturn_id" ]; then
    docker logs -f "$coturn_id" >"$ARTIFACTS_DIR/hold-coturn.log" 2>&1 &
    coturn_log_pid=$!
  fi
  PUNCH_WINDOW_MS=0
  start_host || {
    [ -n "$coturn_log_pid" ] && kill "$coturn_log_pid" 2>/dev/null
    return 1
  }
  compose exec -T peer-c env \
    NATS_URL="$NATS_URL" BIND_IP="$CLIENT_BIND" RUNS=1 MAX_ATTEMPTS=1 \
    HOLD_SECS="$HOLD_SECS" KEEP_ALIVE_SECS="$KEEP_ALIVE_SECS" \
    HOLD_READ_TIMEOUT_SECS="$HOLD_READ_TIMEOUT_SECS" \
    ICE_TIMEOUT_MS="$ICE_TIMEOUT_MS" ANSWER_TIMEOUT_MS="$ANSWER_TIMEOUT_MS" LABEL="$label" \
    STUN_SERVERS="$STUN_SERVER" PUNCH_WINDOW_MS=0 TURN_SERVER="$TURN_SERVER" \
    TURN_SECRET="$TURN_SECRET" TURN_LABEL="$TURN_LABEL" \
    /usr/local/bin/s2-client \
    >"$ARTIFACTS_DIR/hold-client.jsonl" 2>"$ARTIFACTS_DIR/hold-client.err"
  local rc=$?
  stop_host
  [ -n "$coturn_log_pid" ] && kill "$coturn_log_pid" 2>/dev/null || true
  compose exec -T peer-a cat /tmp/s2-host.jsonl >"$ARTIFACTS_DIR/hold-host.jsonl" 2>/dev/null || true
  echo "   client exit=$rc" >&2
}

if should_run unshaped; then run_cell unshaped 0 "$MAX_ATTEMPTS"; fi
if should_run delay50; then run_cell delay50 50 "$DELAYED_MAX_ATTEMPTS"; fi
if should_run hold && [ "$HOLD_SECS" -gt 0 ]; then run_hold; fi

# ── report ────────────────────────────────────────────────────────────────────────────────────
echo ""
echo "## S2 across-NAT measurement (production SignalingHost/SignalingClient; simulated, one kernel)"
echo ""
echo "Host peer-a (172.28.10.2, behind nat-a/gw-a) <-> client peer-c (172.28.30.2, behind nat-c/gw-c)."
echo "Signaling: $NATS_URL (lab-local unauthenticated NATS)."
if [ -n "$TURN_SERVER" ]; then
  echo "Production gathering: STUN $STUN_SERVER + TURN $TURN_SERVER -> punch-first, relay fallback after ${PUNCH_WINDOW_MS} ms (td-870b25)."
else
  echo "Production gathering: STUN $STUN_SERVER, no TURN -> ICE punch only."
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

# ── per-attempt transport agreement (td-870b25) ────────────────────────────────────────────────
#
# Both roles log `transport selected` (a JSON tracing event carrying the session id) as soon as the
# punch-first decision is made — before the QUIC handshake, so a split is observable even when the
# handshake fails and neither side reaches its success path. The client emits one decision per
# attempt immediately before its attempt row; the two are joined in stream order (attempts are
# sequential). The host's decisions are joined to the client's by session id. A **split** is a
# session both sides selected on, with different transports; that is the asymmetry this policy
# must be measured against.
report_transport_agreement() {
  local label="$1"
  python3 -I - "$ARTIFACTS_DIR/$label-client.jsonl" "$ARTIFACTS_DIR/$label-host.jsonl" "$label" <<'PY'
import json
import sys
from collections import Counter

client_path, host_path, label = sys.argv[1], sys.argv[2], sys.argv[3]


def load(path):
    rows = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return rows


def decision(obj):
    fields = obj.get("fields") or {}
    sid = fields.get("sid")
    proto = fields.get("transport")
    if sid and proto:
        return sid, proto
    return None


client_events = load(client_path)
host_events = load(host_path)

# One client decision per attempt, emitted before the attempt row.
attempts = []
phase_rows = {}
pending = None
for obj in client_events:
    found = decision(obj)
    if found is not None:
        pending = found
        continue
    if "status" in obj:
        sid, proto = pending if pending is not None else (None, None)
        attempts.append({"status": obj.get("status"), "sid": sid, "transport": proto})
        if obj.get("status") == "ok":
            phase_rows.setdefault(obj.get("transport"), []).append(obj)
        pending = None

host_map = {}
for obj in host_events:
    found = decision(obj)
    if found is not None:
        host_map[found[0]] = found[1]

client_map = {}
for attempt in attempts:
    if attempt["sid"] is not None:
        client_map[attempt["sid"]] = attempt["transport"]

client_counts = Counter(client_map.values())
host_counts = Counter(host_map.values())
common = set(client_map) & set(host_map)
splits = sorted(sid for sid in common if client_map[sid] != host_map[sid])
one_sided = sorted(set(client_map) ^ set(host_map))
ok = sum(1 for a in attempts if a["status"] == "ok")
failed = len(attempts) - ok
split_failed = sum(1 for a in attempts if a["sid"] in splits and a["status"] != "ok")


def fmt(counts):
    return "punch=%d relay=%d" % (counts.get("punch", 0), counts.get("relay", 0))


print(
    "- `%s`: attempts=%d ok=%d failed=%d | client selected %s | host selected %s | "
    "joined=%d splits=%d (of which client attempts failed=%d) one-sided=%d"
    % (
        label,
        len(attempts),
        ok,
        failed,
        fmt(client_counts),
        fmt(host_counts),
        len(common),
        len(splits),
        split_failed,
        len(one_sided),
    )
)
for index, attempt in enumerate(attempts, 1):
    sid = attempt["sid"] or "-"
    client_transport = attempt["transport"] or "-"
    host_transport = host_map.get(attempt["sid"], "-") if attempt["sid"] else "-"
    print(
        "  - attempt %d: status=%s client=%s host=%s sid=%s"
        % (index, attempt["status"], client_transport, host_transport, sid)
    )
for sid in splits:
    print("  - split `%s`: client=%s host=%s" % (sid, client_map[sid], host_map[sid]))
for sid in one_sided:
    if sid in client_map:
        print("  - one-sided `%s`: client=%s, host selected nothing" % (sid, client_map[sid]))
    else:
        print("  - one-sided `%s`: host=%s, client selected nothing" % (sid, host_map[sid]))


def median(values):
    values = sorted(v for v in values if v is not None)
    if not values:
        return None
    n = len(values)
    return values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2.0


def fmt_ms(value):
    return "n/a" if value is None else "%.3f" % value


for transport in ("punch", "relay"):
    rows = phase_rows.get(transport, [])
    if rows:
        print(
            "  - %s phases (ok attempts n=%d, medians): "
            "offer->answer=%s ms, answer->selected=%s ms, selected->QUIC=%s ms, "
            "offer->usable=%s ms"
            % (
                transport,
                len(rows),
                fmt_ms(median(r.get("offer_to_answer_ms") for r in rows)),
                fmt_ms(median(r.get("answer_to_selected_ms") for r in rows)),
                fmt_ms(median(r.get("selected_to_quic_ms") for r in rows)),
                fmt_ms(median(r.get("offer_to_stream_ms") for r in rows)),
            )
        )
PY
}

echo ""
echo "### Per-attempt transport agreement (punch-first; transport selected on each side)"
echo ""
for label in unshaped delay50; do
  report_transport_agreement "$label"
done

if should_run hold && [ "$HOLD_SECS" -gt 0 ] && [ -s "$ARTIFACTS_DIR/hold-client.jsonl" ]; then
  echo ""
  echo "### Long-held relayed session (td-870b25)"
  echo ""
  summary=$(jq -c 'select(.event=="hold_summary")' "$ARTIFACTS_DIR/hold-client.jsonl" 2>/dev/null | tail -1)
  if [ -n "$summary" ]; then
    transport=$(printf '%s' "$summary" | jq -r '.transport')
    ok=$(printf '%s' "$summary" | jq -r '.heartbeats_ok')
    attempted=$(printf '%s' "$summary" | jq -r '.heartbeats_attempted')
    first=$(printf '%s' "$summary" | jq -r '.first_t_s // "n/a"')
    last=$(printf '%s' "$summary" | jq -r '.last_t_s // "n/a"')
    failed_at=$(printf '%s' "$summary" | jq -r '.failed_at_s // "n/a"')
    failure=$(printf '%s' "$summary" | jq -r '.failure // "none"')
    echo "- transport: $transport; heartbeats: $ok/$attempted; first: ${first}s; last: ${last}s; failed_at: ${failed_at}; failure: ${failure}"
  else
    echo "- no hold_summary (client did not finish the hold); see $ARTIFACTS_DIR/hold-client.err"
  fi
  host_frames=$(jq -r 'select(.event=="host_frame")|.event' "$ARTIFACTS_DIR/hold-host.jsonl" 2>/dev/null | wc -l | tr -d ' ')
  host_last=$(jq -r 'select(.event=="host_frame")|.t_ms' "$ARTIFACTS_DIR/hold-host.jsonl" 2>/dev/null | tail -1)
  echo "- host: echoed frames=$host_frames; last frame t_ms=${host_last:-n/a}"
  if [ -s "$ARTIFACTS_DIR/hold-coturn.log" ]; then
    refresh=$(/usr/bin/grep -ci 'refresh' "$ARTIFACTS_DIR/hold-coturn.log" || echo 0)
    permission=$(/usr/bin/grep -ci 'permission' "$ARTIFACTS_DIR/hold-coturn.log" || echo 0)
    allocation=$(/usr/bin/grep -ci 'allocation' "$ARTIFACTS_DIR/hold-coturn.log" || echo 0)
    echo "- coturn log: $(wc -l <"$ARTIFACTS_DIR/hold-coturn.log" | tr -d ' ') lines; refresh=$refresh permission=$permission allocation=$allocation (raw: $ARTIFACTS_DIR/hold-coturn.log)"
  else
    echo "- coturn log: none captured"
  fi
fi

echo ""
echo "### Reading this table"
echo ""
echo "With TURN_SERVER set, the production stack runs punch-first: STUN srflx + ICE for"
echo "PUNCH_WINDOW_MS, then the relay if no pair was selected (crates/spindle-net/src/signaling/ice.rs)."
echo "On this lab's Linux-conntrack NAT, the punch is probabilistic unshaped and fails at any nonzero"
echo "delay (td-3c1762); failures in a punch attempt are ICE 'trickle timed out', not signaling"
echo "failures (the host-observed counts above prove offers/answers crossed both NATs). Relay attempts"
echo "should complete with transport=relay. A split (both sides selected different transports) fails"
echo "the QUIC handshake and is listed above; it is the asymmetry the shared-window policy must be"
echo "measured against, not a success. Raw artifacts: $ARTIFACTS_DIR"
