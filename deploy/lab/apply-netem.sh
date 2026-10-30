#!/usr/bin/env bash
# Apply (or clear) a netem qdisc on the peer's private-facing interface.
#
# Runs inside a peer container. Called by peer-entrypoint.sh at start with the compose-provided
# env, and by run-matrix.sh before every attempt with the cell's parameters.
#
# `tc netem reorder` REFUSES to install without a delay: the kernel returns
#   "reordering not possible without specifying some delay"
# (verified empirically on this Docker Desktop VM, not assumed). So a reorder cell must also
# pass a delay; run-matrix.sh's reorder cell uses 10 ms as the smallest meaningful reorder
# window and reports that deviation from the bare `reorder 25% 50%` form.
#
# Usage: apply-netem.sh <delay_ms> <loss_pct> <reorder_pct> <reorder_corr_pct>
set -euo pipefail

delay_ms="${1:-0}"
loss_pct="${2:-0}"
reorder_pct="${3:-0}"
reorder_corr="${4:-0}"

iface=$(ip -o -4 addr show | awk '$2 != "lo" { print $2; exit }')
if [ -z "$iface" ]; then
  echo "apply-netem: no non-loopback interface found" >&2
  ip -o -4 addr show >&2
  exit 1
fi

# Always clear first so repeated calls (one per matrix attempt) are idempotent.
tc qdisc del dev "$iface" root 2>/dev/null || true

args=()
if [ "$delay_ms" -gt 0 ]; then
  args+=(delay "${delay_ms}ms")
fi
if [ "$loss_pct" -gt 0 ]; then
  args+=(loss "${loss_pct}%")
fi
if [ "$reorder_pct" -gt 0 ]; then
  if [ "$delay_ms" -le 0 ]; then
    echo "apply-netem: netem reorder requires a delay on this kernel (pass delay_ms > 0)" >&2
    exit 2
  fi
  args+=(reorder "${reorder_pct}%" "${reorder_corr}%")
fi

if [ "${#args[@]}" -eq 0 ]; then
  echo "apply-netem: $iface unshaped (no qdisc installed)"
  exit 0
fi

tc qdisc add dev "$iface" root netem "${args[@]}"
echo "apply-netem: $iface netem ${args[*]}"
