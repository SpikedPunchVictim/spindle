#!/usr/bin/env bash
# S19 leg 2 milestone 6 — NAT-punch matrix (docs/SPIKES.md §S19 / docs/DESIGN.md §A8/A10.32).
#
# Builds a small network-namespace harness inside the `spindle-toolchain:local` container (Linux,
# CAP_NET_ADMIN — same container as s19-rtt-run.sh, different capability set) with two independent
# NAT gateways sitting between two "peer" namespaces and a shared bridge (the stand-in for "the
# internet"), then runs `quic-peer --transport ice` end to end through that NAT topology, varying
# each gateway's `iptables MASQUERADE` behavior to approximate different NAT types.
#
# ## Topology (per cell, rebuilt fresh — see `teardown`/`setup_topology`)
#
#   peerA (192.168.10.2/24) --- gwA --- br-wan (10.0.0.0/24, root ns) --- gwB --- peerB (192.168.20.2/24)
#                          .1 /                10.0.0.1 (root, STUN server)     \ .1
#                    192.168.10.1/24 = gwA private leg        192.168.20.1/24 = gwB private leg
#                    10.0.0.11/24    = gwA public leg (bridge) 10.0.0.12/24    = gwB public leg (bridge)
#
# Four network namespaces (`gwA`, `gwB`, `peerA`, `peerB`) plus a bridge (`br-wan`) in the
# container's root namespace, which also hosts the STUN server (`stun-server`, `src/bin/
# stun-server.rs` — see its module doc comment for why an in-repo binary was written instead of
# installing coturn) at `10.0.0.1:3478`. `gwA`/`gwB` are real independent NAT boxes: each has its
# own private-side veth (to its peer) and public-side veth (on the shared bridge), `ip_forward=1`,
# and its own `iptables -t nat POSTROUTING ... MASQUERADE` rule — so peerA and peerB really are
# behind *two separate* NAT translations, not one router wearing two hats. A third, deliberately
# *not*-behind-a-NAT namespace for the STUN server was considered and rejected as unnecessary
# complexity: the root namespace already has an interface directly on `br-wan`, which is exactly
# what a public STUN server's network position looks like relative to two NATed peers.
#
# One `/proc/sys` wrinkle worth recording: Docker bind-mounts `/proc/sys` **read-only** inside the
# container by default (`mount | grep proc/sys` shows `proc on /proc/sys type proc (ro,...)`),
# even as root with CAP_NET_ADMIN/CAP_SYS_ADMIN — found empirically when `sysctl` (not installed;
# irrelevant) and then a direct `echo 1 > .../ip_forward` both failed with "Read-only file
# system". `mount -o remount,rw /proc/sys` (root ns *and* inside each new netns via `ip netns exec
# <ns> mount -o remount,rw /proc/sys`, since each network namespace gets its own independent
# `net.ipv4.ip_forward` defaulting to 0) fixes it — no `--sysctl` docker-run flag or `--privileged`
# needed, just the remount, run once per namespace that needs to forward.
#
# ## NAT-type approximation (what this harness does and does not distinguish)
#
# Default Linux `MASQUERADE` (no flags) gives **port-restricted-cone** filtering: conntrack only
# lets an inbound packet back through if it matches the exact (external-ip, external-port,
# peer-ip, peer-port) tuple an earlier outbound packet created — the realistic behavior of most
# consumer NAT/home-router equipment, and the harder of the two cone variants to punch through
# (full-cone accepts inbound from *any* peer once the mapping exists, a strict superset of what
# port-restricted allows). This harness does **not** implement a separately-distinguishable
# "full-cone" NAT: doing so faithfully needs a *static* PREROUTING DNAT rule keyed to the specific
# ephemeral port STUN gathering assigns, installed dynamically before ICE punching happens (full
# cone is really "an always-open port forward", independent of any prior outbound flow/conntrack
# state) — meaningfully more plumbing than a spike justifies, and not attempted here (a deviation
# from the task brief's literal "at minimum" ask, reported rather than silently narrowed). Instead,
# every non-symmetric cell below uses the same port-restricted-cone default, on the reasoning that
# it is the *more restrictive* of the two cone types: a punch that succeeds port-restricted-cone-to-
# port-restricted-cone would also succeed full-cone-to-anything (full cone relaxes exactly the
# restriction port-restricted enforces, never adds a new one). The `--random-fully` MASQUERADE flag
# (`nat_mode=symmetric`) gives genuinely different behavior — a fresh, unpredictable external port
# per (destination-ip, destination-port), which breaks the "learn my one stable mapped address via
# STUN, tell my peer that address, they dial it" assumption ICE's srflx candidates depend on — the
# expected-fail case the task brief anticipated (leg 3's TURN relay is the fix, not attempted here).
#
# Usage (from anywhere — path-independent):
#   spikes/s19-quic-transport/s19-nat-run.sh
#
# Requires: docker, and the `spindle-toolchain:local` image already built locally.
#
# Idempotent / safe to re-run: each cell tears down and rebuilds the entire namespace/bridge/
# iptables topology from scratch (`teardown` before `setup_topology`) rather than reusing state
# across cells — found empirically necessary during interactive prototyping: reusing namespaces
# across attempts left stale conntrack entries that intermittently made a *good* topology's ICE
# punch time out (a NAT-mapped port collision with a dead flow's leftover conntrack entry, not a
# topology bug — confirmed by re-running the identical topology fresh, which then punched
# successfully every time). A fresh `docker run --rm` per invocation of this whole script gives the
# same guarantee at the container level; per-cell teardown gives it at the namespace level too, so
# cells don't need a fresh container each.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SPIKE_DIR="spikes/s19-quic-transport"

if [ "${1:-}" = "--in-container" ]; then
  # ── Everything below runs INSIDE the container, as root (netns/iptables need CAP_NET_ADMIN +
  # CAP_SYS_ADMIN; the /proc/sys remount above needs it too) ──
  cd /workspace

  if ! command -v ip >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq iproute2 iptables >/dev/null
  fi

  # See the module doc comment above: Docker masks /proc/sys read-only by default even with
  # CAP_SYS_ADMIN. Root ns only here — each per-namespace remount happens in setup_topology.
  mount -o remount,rw /proc/sys

  export CARGO_TARGET_DIR=/tmp/target-linux
  cargo build -p spike-s19-quic-transport --release --bin quic-peer --bin stun-server
  BIN="$CARGO_TARGET_DIR/release/quic-peer"
  STUN_BIN="$CARGO_TARGET_DIR/release/stun-server"

  RESULTS_TMP="$SPIKE_DIR/.s19-nat-results.tmp"
  RAW_DIR="$SPIKE_DIR/.s19-nat-raw"
  mkdir -p "$RAW_DIR"
  : >"$RESULTS_TMP"

  ENV_LABEL="Linux container ($(uname -r)), netns+iptables NAT harness, spindle-toolchain:local"
  DATE_STR="$(date -u +%Y-%m-%d)"

  # Diagnostic overrides (all optional):
  #   COMBOS="cone:cone symmetric:cone" -> only run the given natA:natB combos instead of the
  #                                        default matrix below
  #   BYTES_MIB=4                       -> transfer size per cell (small: this is a punch-success
  #                                        matrix, not a throughput benchmark — s19-rtt-run.sh
  #                                        already covers throughput)
  #   WINDOW_MIB=2                      -> --window value (2, not quic-peer's 16 MiB default —
  #                                        see s19-rtt-run.sh's WINDOW_MIB comment for the
  #                                        quinn-proto MAX_CHUNKS crash this avoids; it reproduces
  #                                        in ICE mode too, see RESULTS.md)
  #   PER_RUN_TIMEOUT_S=20              -> per-cell watchdog (ICE punch itself also self-times-out
  #                                        after its own internal 15s — see ice_punch's
  #                                        handshake_timeout)
  COMBOS="${COMBOS:-cone:cone symmetric:cone cone:symmetric symmetric:symmetric}"
  BYTES_MIB="${BYTES_MIB:-4}"
  WINDOW_MIB="${WINDOW_MIB:-2}"
  PER_RUN_TIMEOUT_S="${PER_RUN_TIMEOUT_S:-20}"

  teardown() {
    pkill -f "$STUN_BIN" >/dev/null 2>&1 || true
    pkill -f "$BIN" >/dev/null 2>&1 || true
    for ns in gwA gwB peerA peerB; do
      ip netns del "$ns" >/dev/null 2>&1 || true
    done
    ip link del br-wan >/dev/null 2>&1 || true
    sleep 0.2
  }

  # setup_topology natA natB — natA/natB each "cone" (default MASQUERADE, port-restricted-cone
  # filtering) or "symmetric" (--random-fully MASQUERADE). See the module doc comment for why
  # "full-cone" isn't a separate third option here.
  setup_topology() {
    local nat_a="$1" nat_b="$2"
    teardown

    ip netns add gwA
    ip netns add gwB
    ip netns add peerA
    ip netns add peerB

    ip link add br-wan type bridge
    ip link set br-wan up
    ip addr add 10.0.0.1/24 dev br-wan

    # --- gwA: private leg to peerA (192.168.10.0/24), public leg on br-wan ---
    ip link add vethA-priv type veth peer name vethA-priv-gw
    ip link set vethA-priv netns peerA
    ip link set vethA-priv-gw netns gwA
    ip link add vethA-pub type veth peer name vethA-pub-br
    ip link set vethA-pub netns gwA
    ip link set vethA-pub-br master br-wan
    ip link set vethA-pub-br up

    ip netns exec gwA ip addr add 192.168.10.1/24 dev vethA-priv-gw
    ip netns exec gwA ip link set vethA-priv-gw up
    ip netns exec gwA ip addr add 10.0.0.11/24 dev vethA-pub
    ip netns exec gwA ip link set vethA-pub up
    ip netns exec gwA ip link set lo up
    ip netns exec gwA mount -o remount,rw /proc/sys
    ip netns exec gwA sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
    if [ "$nat_a" = "symmetric" ]; then
      ip netns exec gwA iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o vethA-pub -j MASQUERADE --random-fully
    else
      ip netns exec gwA iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o vethA-pub -j MASQUERADE
    fi

    ip netns exec peerA ip addr add 192.168.10.2/24 dev vethA-priv
    ip netns exec peerA ip link set vethA-priv up
    ip netns exec peerA ip link set lo up
    ip netns exec peerA ip route add default via 192.168.10.1

    # --- gwB: mirror, private leg to peerB (192.168.20.0/24), public leg on br-wan ---
    ip link add vethB-priv type veth peer name vethB-priv-gw
    ip link set vethB-priv netns peerB
    ip link set vethB-priv-gw netns gwB
    ip link add vethB-pub type veth peer name vethB-pub-br
    ip link set vethB-pub netns gwB
    ip link set vethB-pub-br master br-wan
    ip link set vethB-pub-br up

    ip netns exec gwB ip addr add 192.168.20.1/24 dev vethB-priv-gw
    ip netns exec gwB ip link set vethB-priv-gw up
    ip netns exec gwB ip addr add 10.0.0.12/24 dev vethB-pub
    ip netns exec gwB ip link set vethB-pub up
    ip netns exec gwB ip link set lo up
    ip netns exec gwB mount -o remount,rw /proc/sys
    ip netns exec gwB sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
    if [ "$nat_b" = "symmetric" ]; then
      ip netns exec gwB iptables -t nat -A POSTROUTING -s 192.168.20.0/24 -o vethB-pub -j MASQUERADE --random-fully
    else
      ip netns exec gwB iptables -t nat -A POSTROUTING -s 192.168.20.0/24 -o vethB-pub -j MASQUERADE
    fi

    ip netns exec peerB ip addr add 192.168.20.2/24 dev vethB-priv
    ip netns exec peerB ip link set vethB-priv up
    ip netns exec peerB ip link set lo up
    ip netns exec peerB ip route add default via 192.168.20.1

    # DNAT the signaling TCP port through gwB so peerA's plain-TCP --signal connect (this
    # harness's stand-in for the real A7-verified envelope/rendezvous path, NOT part of ICE
    # itself — see quic-peer.rs's module doc comment) can reach peerB despite peerB also sitting
    # behind gwB's NAT. A real deployment's rendezvous is a signaling *server* both sides dial out
    # to, not an inbound port-forward to one peer — this DNAT rule is only needed because this
    # spike's --signal is a direct listen/connect, not a rendezvous server.
    ip netns exec gwB iptables -t nat -A PREROUTING -p tcp --dport "$SIGNAL_PORT" -j DNAT --to-destination 192.168.20.2:"$SIGNAL_PORT"

    sleep 0.3
  }

  port=15000

  for combo in $COMBOS; do
    nat_a="${combo%%:*}"
    nat_b="${combo##*:}"
    SIGNAL_PORT=$((port))
    port=$((port + 1))
    cell="${nat_a}_${nat_b}"

    echo "== NAT combo peerA=${nat_a} peerB=${nat_b} signal_port=${SIGNAL_PORT} ==" >&2

    setup_topology "$nat_a" "$nat_b"

    stun_log="$RAW_DIR/${cell}-stun.log"
    recv_out="$RAW_DIR/${cell}-recv.json"
    recv_err="$RAW_DIR/${cell}-recv.err"
    send_out="$RAW_DIR/${cell}-send.json"
    send_err="$RAW_DIR/${cell}-send.err"
    : >"$stun_log"; : >"$recv_out"; : >"$recv_err"; : >"$send_out"; : >"$send_err"

    "$STUN_BIN" 10.0.0.1:3478 >"$stun_log" 2>&1 &
    stun_pid=$!
    sleep 0.3

    set +e
    ip netns exec peerB "$BIN" --mode recv --transport ice --signal "listen:${SIGNAL_PORT}" \
      --stun 10.0.0.1:3478 --ice-bind 192.168.20.2 --bytes "$BYTES_MIB" --window "$WINDOW_MIB" \
      --json \
      >"$recv_out" 2>"$recv_err" &
    recv_pid=$!
    sleep 0.3

    timeout "${PER_RUN_TIMEOUT_S}s" ip netns exec peerA "$BIN" --mode send --transport ice \
      --signal "connect:10.0.0.12:${SIGNAL_PORT}" --stun 10.0.0.1:3478 --ice-bind 192.168.10.2 \
      --bytes "$BYTES_MIB" --window "$WINDOW_MIB" --json \
      >"$send_out" 2>"$send_err"
    send_rc=$?

    wait "$recv_pid"
    recv_rc=$?
    set -e

    kill "$stun_pid" >/dev/null 2>&1 || true

    if [ "$recv_rc" -eq 0 ] && [ "$send_rc" -eq 0 ] && [ -s "$recv_out" ]; then
      raw="$(cat "$recv_out")"
      mb_per_s="$(printf '%s' "$raw" | sed -n 's/.*"mb_per_s":\([0-9.]*\).*/\1/p')"
      printf '| %s | %s | %s | %s | PUNCHED + TRANSFER OK | %s MB/s | bytes=%sMiB window=%sMiB |\n' \
        "$DATE_STR" "$ENV_LABEL" "$nat_a" "$nat_b" "$mb_per_s" "$BYTES_MIB" "$WINDOW_MIB" \
        >>"$RESULTS_TMP"
    else
      reason="recv_exit=${recv_rc} send_exit=${send_rc}"
      if [ "$send_rc" -eq 124 ]; then
        reason="ICE punch/transfer TIMEOUT after ${PER_RUN_TIMEOUT_S}s ($reason)"
      fi
      tail_err="$(tail -c 300 "$send_err" 2>/dev/null | tr '\n' ' ')"
      printf '| %s | %s | %s | %s | FAILED (punch or relay needed) | %s | send_stderr_tail=%s |\n' \
        "$DATE_STR" "$ENV_LABEL" "$nat_a" "$nat_b" "$reason" "$tail_err" \
        >>"$RESULTS_TMP"
      echo "s19-nat-run: CELL FAILED natA=${nat_a} natB=${nat_b} ($reason)" >&2
    fi
  done

  teardown

  echo "" >&2
  echo "== NAT-punch matrix done. Results table: ==" >&2
  cat "$RESULTS_TMP"
  echo "" >&2
  echo "== Raw per-cell logs: $RAW_DIR/ ==" >&2

  exit 0
fi

# ── Runs on the HOST: launch the container, then re-invoke this same script inside it ──
exec docker run --rm \
  --cap-add NET_ADMIN \
  --cap-add SYS_ADMIN \
  --cap-add NET_RAW \
  --user root \
  -e COMBOS \
  -e BYTES_MIB \
  -e WINDOW_MIB \
  -e PER_RUN_TIMEOUT_S \
  -v "$REPO_ROOT:/workspace" \
  -w /workspace \
  spindle-toolchain:local \
  timeout "${OVERALL_TIMEOUT_S:-600}s" bash "/workspace/$SPIKE_DIR/s19-nat-run.sh" --in-container
