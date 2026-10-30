#!/usr/bin/env bash
# (Re)install this gateway's NAT rule. Called by gw-entrypoint.sh at start and by run-matrix.sh
# to switch a live lab between cone (plain MASQUERADE) and symmetric (--random-fully) modes
# without recreating containers.
#
# A dedicated LAB_MASQ chain is used instead of touching POSTROUTING wholesale: Docker installs
# its own POSTROUTING rules in every container's netns (e.g. DOCKER_POSTROUTING for the embedded
# DNS), and flushing the built-in chain would silently break name resolution.
#
# Usage: gw-nat.sh <cone|symmetric> [wan_iface]
set -euo pipefail

mode="${1:-cone}"
wan_if="${2:-}"
if [ -z "$wan_if" ]; then
  : "${WAN_PREFIX:?WAN_PREFIX must be set when wan_iface is omitted}"
  wan_if=$(ip -o -4 addr show | awk -v p="$WAN_PREFIX" 'index($4, p) == 1 { print $2; exit }')
fi
: "${PRIVATE_SUBNET:?PRIVATE_SUBNET must be set}"
: "${OTHER_PRIVATE_SUBNET:?OTHER_PRIVATE_SUBNET must be set}"
if [ -z "$wan_if" ]; then
  echo "gw-nat: could not locate the wan interface" >&2
  ip -o -4 addr show >&2
  exit 1
fi

iptables -t nat -N LAB_MASQ 2>/dev/null || true
iptables -t nat -F LAB_MASQ
iptables -t nat -C POSTROUTING -j LAB_MASQ 2>/dev/null \
  || iptables -t nat -A POSTROUTING -j LAB_MASQ

case "$mode" in
  cone)
    iptables -t nat -A LAB_MASQ -s "$PRIVATE_SUBNET" -o "$wan_if" -j MASQUERADE
    ;;
  symmetric)
    # --random-fully: a fresh, unpredictable external port per destination, defeating the
    # "one stable STUN-learned mapping" assumption ICE srflx candidates rely on.
    iptables -t nat -A LAB_MASQ -s "$PRIVATE_SUBNET" -o "$wan_if" -j MASQUERADE --random-fully
    ;;
  *)
    echo "gw-nat: unknown mode '$mode' (expected cone|symmetric)" >&2
    exit 2
    ;;
esac

# The peers are NOT allowed to reach each other's private host candidates. Without this DROP,
# the Docker host routes directly between the nat-a and nat-b bridges, so a packet from peer-a to
# 172.28.20.2 is forwarded by gw-a's *default* route (which points at the host), bypassing
# gw-b's NAT entirely. ICE then selects the private host candidates and "succeeds" against
# symmetric NAT for the wrong reason (observed empirically before this rule existed: all six
# sym_ice attempts selected 172.28.10.2/172.28.20.2, not 172.28.0.x). Only the NAT-mapped srflx
# path should be reachable. FORWARD runs before POSTROUTING, so the source is still private here;
# the DNATed signaling flow arrives from the wan subnet and is unaffected.
#
# A dedicated chain keeps the DROP ahead of the ACCEPT regardless of prior runs.
iptables -N LAB_FORWARD 2>/dev/null || true
iptables -F LAB_FORWARD
iptables -C FORWARD -j LAB_FORWARD 2>/dev/null || iptables -A FORWARD -j LAB_FORWARD
iptables -A LAB_FORWARD -s "$PRIVATE_SUBNET" -d "$OTHER_PRIVATE_SUBNET" -j DROP
iptables -A LAB_FORWARD -j ACCEPT

echo "gw-nat: mode=$mode wan_if=$wan_if private_subnet=$PRIVATE_SUBNET other_private=$OTHER_PRIVATE_SUBNET"
