#!/usr/bin/env bash
# Gateway container entrypoint: enable forwarding, install the MASQUERADE rule, and (on gw-b)
# the signaling TCP DNAT rule, then idle. All rules live in this container's own network
# namespace, so NET_ADMIN is sufficient — no host rules, no privileged mode.
#
# Interface names are NOT stable across `docker compose up` runs on this Docker Desktop VM:
# compose declares `wan` before `nat-a`/`nat-b`, but the kernel-visible order has been observed
# both ways (eth0=private/eth1=wan on one run, the reverse on another). Never assume — every
# script here locates interfaces by IPv4 prefix instead.
set -euo pipefail

: "${WAN_PREFIX:?WAN_PREFIX (e.g. 172.28.0.) must be set}"
: "${PRIVATE_PREFIX:?PRIVATE_PREFIX (e.g. 172.28.10.) must be set}"
NAT_MODE="${NAT_MODE:-cone}"
SIGNAL_PORT="${SIGNAL_PORT:-15000}"
WAN_GATEWAY="${WAN_GATEWAY:-172.28.0.1}"

wan_if=$(ip -o -4 addr show | awk -v p="$WAN_PREFIX" 'index($4, p) == 1 { print $2; exit }')
priv_if=$(ip -o -4 addr show | awk -v p="$PRIVATE_PREFIX" 'index($4, p) == 1 { print $2; exit }')
if [ -z "$wan_if" ] || [ -z "$priv_if" ]; then
  echo "gw-entrypoint: could not locate interfaces (wan_prefix=$WAN_PREFIX private_prefix=$PRIVATE_PREFIX)" >&2
  ip -o -4 addr show >&2
  exit 1
fi
if [ "$wan_if" = "$priv_if" ]; then
  echo "gw-entrypoint: wan and private prefixes matched the same interface ($wan_if)" >&2
  exit 1
fi

# Behave like a router whose only uplink is the wan side. Docker's own default route points at
# whichever bridge it attached first, which on this VM can be the private bridge; that would send
# non-connected traffic to the Docker host over the private leg and skip MASQUERADE. The private→
# other-private DROP in gw-nat.sh is what actually prevents the host inter-bridge shortcut.
ip route replace default via "$WAN_GATEWAY" dev "$wan_if"

/usr/local/bin/gw-nat.sh "$NAT_MODE" "$wan_if"
/usr/local/bin/gw-signal.sh "$SIGNAL_PORT"

echo "gw-entrypoint: wan_if=$wan_if private_if=$priv_if nat_mode=$NAT_MODE signal_port=$SIGNAL_PORT wan_gateway=$WAN_GATEWAY"
iptables -t nat -S LAB_MASQ
iptables -t nat -S LAB_SIGNAL

exec sleep infinity
