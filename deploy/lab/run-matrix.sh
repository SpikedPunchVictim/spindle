#!/usr/bin/env bash
# S19 two-container NAT + netem matrix (deploy/lab/README.md).
#
# Brings the lab up, waits for it to be ready, runs the cells below, tears it down (unless
# KEEP_LAB=1), and prints markdown tables. Raw per-attempt JSON/stderr/stats land in
# .artifacts/ next to this script.
#
# This is NOT S19 leg 4. Everything still runs in one kernel (Docker Desktop's Linux VM); see
# README.md and the RESULTS.md section it feeds for what it does and does not prove.
#
# Cells (each peer's netem is applied to its own egress, so "both sides" = both directions):
#   baseline     no netem, cone:cone, --transport ice
#   delay25      25 ms delay both sides (~50 ms RTT) -- comparable to leg 1's pass-bar cell
#   delay50      50 ms delay both sides (~100 ms RTT)
#   loss1        1% loss both sides, no delay
#   reorder25    10 ms delay + reorder 25% 50% both sides (bare reorder is refused by netem)
#   *_relay      the same shaping as delay25/delay50/reorder25 but over --transport relay; these
#                measure shaped throughput through both NATs when punching cannot be made to work
#   sym_ice      symmetric:symmetric (--random-fully both gateways), --transport ice, expect fail
#   sym_relay    symmetric:symmetric, --transport relay via coturn, expect success
#
# Env overrides: RUNS (successes wanted per cell, default 3), MAX_ATTEMPTS (per cell, default 8),
# BYTES_MIB (32), WINDOW_MIB (2), ICE_TIMEOUT_S (30), KEEP_LAB=1, ARTIFACTS_DIR, and
# CELLS_ONLY=baseline,delay25 to run a subset of cells.
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$LAB_DIR/docker-compose.lab.yml"
PROJECT="${COMPOSE_PROJECT_NAME:-spindle-lab}"

BYTES_MIB="${BYTES_MIB:-32}"
WINDOW_MIB="${WINDOW_MIB:-2}"
RUNS="${RUNS:-3}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-8}"
ICE_TIMEOUT_S="${ICE_TIMEOUT_S:-30}"
START_DELAY_S="${START_DELAY_S:-0.5}"
TURN_SECRET="${TURN_SECRET:-spindle-turn-dev-only}"
KEEP_LAB="${KEEP_LAB:-0}"
CELLS_ONLY="${CELLS_ONLY:-}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$LAB_DIR/.artifacts}"

STUN_IP=172.28.0.14
COTURN_IP=172.28.0.13
GW_B_IP=172.28.0.22
PEER_A_IP=172.28.10.2
PEER_B_IP=172.28.20.2
SIGNAL_PORT_BASE="${SIGNAL_PORT_BASE:-15100}"

# label | delay_ms | loss_pct | reorder_pct | reorder_corr | nat | transport | target_successes | max_attempts
#
# The *_relay rows exist because, in this environment, ANY nonzero delay on the peers' egress
# makes default-MASQUERADE cone punching fail (0/40 measured across 10/25/50 ms). They measure
# shaped throughput through both NATs and coturn, where punching cannot. They are NOT punch
# results and are labelled as such in the report.
CELLS=$(printf '%s\n' \
  "baseline|0|0|0|0|cone|ice|$RUNS|$MAX_ATTEMPTS" \
  "delay25|25|0|0|0|cone|ice|$RUNS|$MAX_ATTEMPTS" \
  "delay50|50|0|0|0|cone|ice|$RUNS|$MAX_ATTEMPTS" \
  "loss1|0|1|0|0|cone|ice|$RUNS|$MAX_ATTEMPTS" \
  "reorder25|10|0|25|50|cone|ice|$RUNS|$MAX_ATTEMPTS" \
  "delay25_relay|25|0|0|0|cone|relay|$RUNS|4" \
  "delay50_relay|50|0|0|0|cone|relay|$RUNS|4" \
  "reorder25_relay|10|0|25|50|cone|relay|$RUNS|4" \
  "sym_ice|0|0|0|0|symmetric|ice|0|$RUNS" \
  "sym_relay|0|0|0|0|symmetric|relay|$RUNS|$MAX_ATTEMPTS")

RESULTS_TSV="$ARTIFACTS_DIR/attempts.tsv"
SUMMARY_TSV="$ARTIFACTS_DIR/summary.tsv"
ATTEMPT_SEQ=0

compose() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }

cleanup() {
  if [ "$KEEP_LAB" = "1" ]; then
    echo "" >&2
    echo "KEEP_LAB=1: lab left running. Tear down with:" >&2
    echo "  docker compose -p $PROJECT -f $COMPOSE_FILE down -v --remove-orphans" >&2
  else
    echo "tearing down lab..." >&2
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

mkdir -p "$ARTIFACTS_DIR"
: >"$RESULTS_TSV"
: >"$SUMMARY_TSV"

wait_ready() {
  local i
  for i in $(seq 1 180); do
    if compose exec -T gw-a sh -c 'iptables -t nat -S LAB_MASQ | grep -q MASQUERADE' 2>/dev/null \
       && compose exec -T gw-b sh -c 'iptables -t nat -S LAB_MASQ | grep -q MASQUERADE' 2>/dev/null \
       && compose exec -T peer-a test -x /usr/local/bin/quic-peer 2>/dev/null \
       && compose exec -T peer-b test -x /usr/local/bin/quic-peer 2>/dev/null \
       && compose exec -T peer-a sh -c 'ip route show default | grep -q 172.28.10.254' 2>/dev/null \
       && compose exec -T peer-b sh -c 'ip route show default | grep -q 172.28.20.254' 2>/dev/null \
       && compose exec -T stun pgrep -x stun-server >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "run-matrix: lab not ready after 180 s" >&2
  compose ps >&2
  compose logs --tail=60 gw-a gw-b peer-a peer-b stun >&2
  return 1
}

apply_netem() {
  local delay="$1" loss="$2" reorder="$3" corr="$4"
  compose exec -T peer-a /usr/local/bin/apply-netem.sh "$delay" "$loss" "$reorder" "$corr" >/dev/null 2>&1
  local rc_a=$?
  compose exec -T peer-b /usr/local/bin/apply-netem.sh "$delay" "$loss" "$reorder" "$corr" >/dev/null 2>&1
  local rc_b=$?
  if [ "$rc_a" -ne 0 ] || [ "$rc_b" -ne 0 ]; then
    echo "run-matrix: apply-netem failed (peer-a=$rc_a peer-b=$rc_b) for delay=$delay loss=$loss reorder=$reorder" >&2
    return 1
  fi
  return 0
}

flush_conntrack() {
  compose exec -T gw-a conntrack -F >/dev/null 2>&1 || true
  compose exec -T gw-b conntrack -F >/dev/null 2>&1 || true
}

set_nat_mode() {
  compose exec -T gw-a /usr/local/bin/gw-nat.sh "$1" >/dev/null 2>&1 || return 1
  compose exec -T gw-b /usr/local/bin/gw-nat.sh "$1" >/dev/null 2>&1 || return 1
  flush_conntrack
  return 0
}

set_signal_port() {
  compose exec -T gw-b /usr/local/bin/gw-signal.sh "$1" >/dev/null 2>&1
}

# Poll (without connecting) until the recv side has bound its TCP --signal listener. Probing
# with a TCP connect would consume the single connection the listener is waiting for, so this
# uses `ss -lnt` inside the peer container instead.
wait_signal_listener() {
  local port="$1" pid="$2" i
  for i in $(seq 1 150); do
    if compose exec -T peer-b sh -c "ss -lnt 2>/dev/null | grep -q ':$port '" </dev/null 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.1
  done
  return 1
}

# run_once <label> <delay> <loss> <reorder> <corr> <transport> <attempt>
# Returns 0 on a completed transfer, 1 otherwise. Appends one row to RESULTS_TSV.
run_once() {
  local label="$1" delay="$2" loss="$3" reorder="$4" corr="$5" transport="$6" attempt="$7"
  ATTEMPT_SEQ=$((ATTEMPT_SEQ + 1))
  local port=$((SIGNAL_PORT_BASE + ATTEMPT_SEQ))
  local base="$ARTIFACTS_DIR/${label}-attempt${attempt}"

  if ! apply_netem "$delay" "$loss" "$reorder" "$corr"; then
    printf '%s\t%s\t0\t\tnetem_failed\t%s\n' "$label" "$attempt" "$transport" >>"$RESULTS_TSV"
    return 1
  fi
  set_signal_port "$port"
  flush_conntrack

  compose exec -T peer-b rm -f "/lab-artifacts/${label}-attempt${attempt}-recv-stats.jsonl" >/dev/null 2>&1 || true
  compose exec -T peer-a rm -f "/lab-artifacts/${label}-attempt${attempt}-send-stats.jsonl" >/dev/null 2>&1 || true

  local recv_args=(--mode recv
    --signal "listen:$port"
    --ice-bind "$PEER_B_IP"
    --bytes "$BYTES_MIB"
    --window "$WINDOW_MIB"
    --json
    --stats-interval-ms 500
    --stats-out "/lab-artifacts/${label}-attempt${attempt}-recv-stats.jsonl")
  local send_args=(--mode send
    --signal "connect:$GW_B_IP:$port"
    --ice-bind "$PEER_A_IP"
    --bytes "$BYTES_MIB"
    --window "$WINDOW_MIB"
    --json
    --stats-interval-ms 500
    --stats-out "/lab-artifacts/${label}-attempt${attempt}-send-stats.jsonl")

  if [ "$transport" = "ice" ]; then
    recv_args+=(--transport ice --stun "$STUN_IP:3478")
    send_args+=(--transport ice --stun "$STUN_IP:3478")
  else
    recv_args+=(--transport relay --turn "$COTURN_IP:3478" --turn-secret "$TURN_SECRET" --turn-user-label peerB)
    send_args+=(--transport relay --turn "$COTURN_IP:3478" --turn-secret "$TURN_SECRET" --turn-user-label peerA)
  fi

  compose exec -T peer-b timeout "${ICE_TIMEOUT_S}s" /usr/local/bin/quic-peer "${recv_args[@]}" \
    </dev/null >"$base-recv.json" 2>"$base-recv.err" &
  local recv_pid=$!
  wait_signal_listener "$port" "$recv_pid" || true
  sleep "$START_DELAY_S"
  compose exec -T peer-a timeout "${ICE_TIMEOUT_S}s" /usr/local/bin/quic-peer "${send_args[@]}" \
    </dev/null >"$base-send.json" 2>"$base-send.err"
  local send_rc=$?
  wait "$recv_pid"
  local recv_rc=$?

  local ok=0 mb="" elapsed="" reason=""
  if [ "$recv_rc" -eq 0 ] && [ "$send_rc" -eq 0 ] && [ -s "$base-recv.json" ]; then
    mb=$(sed -n 's/.*"mb_per_s":\([0-9.]*\).*/\1/p' "$base-recv.json" | head -1)
    elapsed=$(sed -n 's/.*"elapsed_secs":\([0-9.]*\).*/\1/p' "$base-recv.json" | head -1)
    if [ -n "$mb" ]; then
      ok=1
    fi
  fi
  if [ "$ok" -eq 0 ]; then
    reason="recv_exit=$recv_rc send_exit=$send_rc"
    [ "$send_rc" -eq 124 ] && reason="$reason send_timeout"
    [ "$recv_rc" -eq 124 ] && reason="$reason recv_timeout"
    {
      echo "$reason"
      [ -f "$base-send.err" ] && tail -c 500 "$base-send.err"
      [ -f "$base-recv.err" ] && tail -c 500 "$base-recv.err"
    } >"$base-note.txt" 2>/dev/null || true
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$label" "$attempt" "$ok" "$mb" "$reason" "$transport" "$elapsed" >>"$RESULTS_TSV"

  if [ "$ok" -eq 1 ]; then
    return 0
  fi
  return 1
}

summarize_cell() {
  local label="$1"
  local attempts successes median_mb spread median_rtt max_lost note
  attempts=$(awk -F'\t' -v l="$label" '$1==l {n++} END {print n+0}' "$RESULTS_TSV")
  successes=$(awk -F'\t' -v l="$label" '$1==l && $3==1 {n++} END {print n+0}' "$RESULTS_TSV")
  median_mb=$(awk -F'\t' -v l="$label" '$1==l && $3==1 && $4!="" {print $4}' "$RESULTS_TSV" \
    | sort -n \
    | awk '{a[NR]=$1} END {if (NR==0) print "n/a"; else if (NR%2) printf "%.3f", a[(NR+1)/2]; else printf "%.3f", (a[NR/2]+a[NR/2+1])/2}')
  spread=$(awk -F'\t' -v l="$label" '$1==l && $3==1 && $4!="" {print $4}' "$RESULTS_TSV" \
    | sort -n \
    | awk '{a[NR]=$1} END {if (NR==0) print "n/a"; else printf "%.3f-%.3f", a[1], a[NR]}')
  median_rtt=$(awk -F'\t' -v l="$label" '$1==l && $3==1 {print $2}' "$RESULTS_TSV" \
    | while read -r attempt; do
        f="$ARTIFACTS_DIR/${label}-attempt${attempt}-recv-stats.jsonl"
        [ -s "$f" ] && grep -o '"rtt_ms":[0-9.]*' "$f" | tail -1 | cut -d: -f2
      done \
    | sort -n \
    | awk '{a[NR]=$1} END {if (NR==0) print "n/a"; else if (NR%2) printf "%.1f", a[(NR+1)/2]; else printf "%.1f", (a[NR/2]+a[NR/2+1])/2}')
  max_lost=$(awk -F'\t' -v l="$label" '$1==l && $3==1 {print $2}' "$RESULTS_TSV" \
    | while read -r attempt; do
        f="$ARTIFACTS_DIR/${label}-attempt${attempt}-recv-stats.jsonl"
        [ -s "$f" ] && grep -o '"lost_packets":[0-9]*' "$f" | cut -d: -f2
      done \
    | sort -n | tail -1)
  [ -z "$max_lost" ] && max_lost="n/a"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$label" "$attempts" "$successes" "$median_mb" "$spread" "$median_rtt" "$max_lost" >>"$SUMMARY_TSV"
}

# ── bring the lab up ──────────────────────────────────────────────────────────────────────────
echo "== building and starting the lab (project $PROJECT) ==" >&2
if ! compose up -d --build; then
  echo "run-matrix: compose up failed" >&2
  exit 1
fi
if ! wait_ready; then
  exit 1
fi

{
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "docker_server: $(docker version --format '{{.Server.Os}}/{{.Server.Arch}} {{.Server.Version}}' 2>/dev/null)"
  echo "kernel_in_peer: $(compose exec -T peer-a uname -r 2>/dev/null | tr -d '\r')"
  echo "compose: $(docker compose version --short 2>/dev/null)"
  echo "bytes_mib: $BYTES_MIB"
  echo "window_mib: $WINDOW_MIB"
  echo "turn_secret: $TURN_SECRET"
  echo "--- gw-a interfaces ---"
  compose exec -T gw-a ip -o -4 addr show 2>/dev/null
  echo "--- gw-b interfaces ---"
  compose exec -T gw-b ip -o -4 addr show 2>/dev/null
  echo "--- peer-a route ---"
  compose exec -T peer-a ip route show 2>/dev/null
  echo "--- peer-b route ---"
  compose exec -T peer-b ip route show 2>/dev/null
  echo "--- gw-a nat ---"
  compose exec -T gw-a iptables -t nat -S LAB_MASQ 2>/dev/null
  echo "--- gw-b nat ---"
  compose exec -T gw-b iptables -t nat -S LAB_MASQ 2>/dev/null
  echo "--- gw-b signal ---"
  compose exec -T gw-b iptables -t nat -S LAB_SIGNAL 2>/dev/null
} >"$ARTIFACTS_DIR/lab-env.txt" 2>&1

# ── run the cells ─────────────────────────────────────────────────────────────────────────────
# The cell list is read from fd 3, not stdin: `docker compose exec` inside the loop would
# otherwise consume the here-string and end the loop after the first cell (observed: only
# `baseline` ran, the rest reported blank rows).
while IFS='|' read -r label delay loss reorder corr nat transport target max <&3; do
  [ -z "$label" ] && continue
  if [ -n "$CELLS_ONLY" ]; then
    case ",$CELLS_ONLY," in
      *",$label,"*) ;;
      *) continue ;;
    esac
  fi
  echo "" >&2
  echo "== cell $label: netem delay=${delay}ms loss=${loss}% reorder=${reorder}%/${corr}% nat=$nat transport=$transport ==" >&2

  if ! set_nat_mode "$nat"; then
    echo "run-matrix: could not set NAT mode $nat" >&2
    exit 1
  fi

  attempt=0
  successes=0
  while [ "$attempt" -lt "$max" ]; do
    if [ "$target" -gt 0 ] && [ "$successes" -ge "$target" ]; then
      break
    fi
    attempt=$((attempt + 1))
    if run_once "$label" "$delay" "$loss" "$reorder" "$corr" "$transport" "$attempt"; then
      successes=$((successes + 1))
      echo "   attempt $attempt: OK" >&2
    else
      echo "   attempt $attempt: FAILED (see $ARTIFACTS_DIR/${label}-attempt${attempt}-note.txt)" >&2
    fi
  done

  compose exec -T peer-a sh -c 'tc -s qdisc show' </dev/null >"$ARTIFACTS_DIR/${label}-qdisc-peer-a.txt" 2>&1 || true
  compose exec -T peer-b sh -c 'tc -s qdisc show' </dev/null >"$ARTIFACTS_DIR/${label}-qdisc-peer-b.txt" 2>&1 || true
  summarize_cell "$label"
done 3<<<"$CELLS"

# ── report ────────────────────────────────────────────────────────────────────────────────────
echo ""
echo "## Two-container NAT + netem lab — measured results"
echo ""
echo "Docker: $(docker version --format '{{.Server.Os}}/{{.Server.Arch}} {{.Server.Version}}' 2>/dev/null); kernel in peer: $(compose exec -T peer-a uname -r 2>/dev/null | tr -d '\r'); compose: $(docker compose version --short 2>/dev/null)."
echo "Transfer: ${BYTES_MIB} MiB per attempt, quic-peer --window ${WINDOW_MIB} (MiB), --cc cubic, --json; throughput is the recv side's first-byte-to-last-byte rate."
echo "Netem is applied to each peer's egress interface, so both directions are shaped; the RTT column is the last rtt_ms sample in the recv side's --stats-out."
echo ""
echo "| Cell | Netem (each peer, egress) | NAT | Transport | Attempts | Successes | MB/s median | MB/s spread | RTT ms (last sample, median) | max lost_packets | Notes |"
echo "|------|---------------------------|-----|-----------|----------|-----------|-------------|-------------|-------------------------------|------------------|-------|"
while IFS='|' read -r label delay loss reorder corr nat transport target max <&3; do
  [ -z "$label" ] && continue
  row=$(awk -F'\t' -v l="$label" '$1==l' "$SUMMARY_TSV")
  attempts=$(printf '%s\n' "$row" | cut -f2)
  successes=$(printf '%s\n' "$row" | cut -f3)
  median_mb=$(printf '%s\n' "$row" | cut -f4)
  spread=$(printf '%s\n' "$row" | cut -f5)
  median_rtt=$(printf '%s\n' "$row" | cut -f6)
  max_lost=$(printf '%s\n' "$row" | cut -f7)
  if [ "$delay" = "0" ] && [ "$loss" = "0" ] && [ "$reorder" = "0" ]; then
    netem="none"
  elif [ "$reorder" != "0" ]; then
    netem="delay ${delay}ms reorder ${reorder}% ${corr}% (bare reorder refused by kernel)"
  elif [ "$loss" != "0" ]; then
    netem="loss ${loss}%"
  else
    netem="delay ${delay}ms"
  fi
  note=""
  [ "$label" = "sym_ice" ] && note="expected ICE punch failure"
  [ "$label" = "sym_relay" ] && note="TURN-relay fallback"
  [ "$label" = "reorder25" ] && note="QUIC survival under reordering; see stats below"
  [ "$label" = "delay25_relay" ] && note="relay, not punch (punch fails under delay)"
  [ "$label" = "delay50_relay" ] && note="relay, not punch (punch fails under delay)"
  [ "$label" = "reorder25_relay" ] && note="relay, not punch; QUIC survival under reordering"
  echo "| $label | $netem | $nat:$nat | $transport | $attempts | $successes | $median_mb | $spread | $median_rtt | $max_lost | $note |"
done 3<<<"$CELLS"

echo ""
echo "### Per-attempt results"
echo ""
echo "| Cell | Attempt | Result | MB/s | recv elapsed s | Detail |"
echo "|------|---------|--------|------|----------------|--------|"
awk -F'\t' '{ if ($3==1) printf "| %s | %s | OK | %s | %s | |\n", $1, $2, $4, $7; else printf "| %s | %s | FAILED | | | %s |\n", $1, $2, $5 }' "$RESULTS_TSV"

echo ""
echo "### Reordering cell — --stats-out detail (recv side)"
echo ""
for f in "$ARTIFACTS_DIR"/reorder25-attempt*-recv-stats.jsonl \
         "$ARTIFACTS_DIR"/reorder25_relay-attempt*-recv-stats.jsonl; do
  [ -s "$f" ] || continue
  echo "- $(basename "$f"): last sample \`$(tail -1 "$f")\`"
  echo "  - max lost_packets: $(grep -o '"lost_packets":[0-9]*' "$f" | cut -d: -f2 | sort -n | tail -1); max congestion_events: $(grep -o '"congestion_events":[0-9]*' "$f" | cut -d: -f2 | sort -n | tail -1)"
done

echo ""
echo "### Exact commands (per attempt; <port> increments from $SIGNAL_PORT_BASE)"
echo ""
echo '```'
echo "# peer-b (recv):"
echo "quic-peer --mode recv --transport <ice|relay> --signal listen:<port> --ice-bind $PEER_B_IP --bytes $BYTES_MIB --window $WINDOW_MIB --json --stats-interval-ms 500 --stats-out /lab-artifacts/<cell>-attempt<N>-recv-stats.jsonl \\"
echo "  [--stun $STUN_IP:3478 | --turn $COTURN_IP:3478 --turn-secret $TURN_SECRET --turn-user-label peerB]"
echo "# peer-a (send):"
echo "quic-peer --mode send --transport <ice|relay> --signal connect:$GW_B_IP:<port> --ice-bind $PEER_A_IP --bytes $BYTES_MIB --window $WINDOW_MIB --json --stats-interval-ms 500 --stats-out /lab-artifacts/<cell>-attempt<N>-send-stats.jsonl \\"
echo "  [--stun $STUN_IP:3478 | --turn $COTURN_IP:3478 --turn-secret $TURN_SECRET --turn-user-label peerA]"
echo '```'
echo ""
echo "Raw artifacts: $ARTIFACTS_DIR (attempts.tsv, summary.tsv, lab-env.txt, per-attempt JSON/stderr/stats, qdisc snapshots)."
echo ""
echo "This lab is NOT S19 leg 4: both peers are containers in one Docker Desktop Linux VM, sharing one kernel. It adds a routed path through two independent NAT containers, per-side tc netem shaping, and real reordering; it does not validate a real two-host link."
