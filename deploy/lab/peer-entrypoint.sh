#!/usr/bin/env bash
# Peer container entrypoint: point the default route at its NAT gateway container, apply the
# compose-provided netem qdisc, then idle so run-matrix.sh can exec cells into it.
#
# Docker sets the peer's default route to the bridge's own gateway (x.x.x.1, on the Docker host),
# NOT to the gateway container (x.x.x.254). Left alone, traffic would bypass the NAT container
# entirely — the host routes between its own bridges. Replacing the default route with the
# gateway container is what makes the peer actually sit behind the gateway. (x.x.x.1 cannot be
# assigned to the gateway container itself: Docker reserves it for the bridge.)
set -euo pipefail

: "${GW_PRIVATE_IP:?GW_PRIVATE_IP must be set}"
: "${PRIVATE_PREFIX:?PRIVATE_PREFIX must be set}"

iface=$(ip -o -4 addr show | awk -v p="$PRIVATE_PREFIX" 'index($4, p) == 1 { print $2; exit }')
if [ -z "$iface" ]; then
  echo "peer-entrypoint: could not locate the private interface (prefix=$PRIVATE_PREFIX)" >&2
  ip -o -4 addr show >&2
  exit 1
fi

ip route replace default via "$GW_PRIVATE_IP" dev "$iface"
/usr/local/bin/apply-netem.sh \
  "${NETEM_DELAY_MS:-0}" \
  "${NETEM_LOSS_PCT:-0}" \
  "${NETEM_REORDER_PCT:-0}" \
  "${NETEM_REORDER_CORR:-0}"

echo "peer-entrypoint: iface=$iface default via $GW_PRIVATE_IP; $(ip route show default)"
exec sleep infinity
