#!/usr/bin/env bash
# (Re)install the TCP DNAT rule that forwards the recv peer's --signal listener through this
# gateway, plus the matching SNAT onto the private leg. This is a lab stand-in for a rendezvous
# service both peers dial out to: quic-peer's --signal is a direct listen/connect channel, so
# the send peer must reach the recv peer's port through the recv side's NAT.
#
# Why the SNAT is required (found empirically, not assumed): without it, the DNATed SYN is
# forwarded out the private interface still carrying its original source, the *other* NAT's wan
# address (e.g. 172.28.0.21). gw-b's conntrack shows the DNAT flow as [UNREPLIED] and the peer
# never receives the SYN — the frame crossing onto the private Docker bridge with a source
# belonging to a different bridge is dropped by the host's bridge netfilter/rp_filter. SNATing
# the forwarded signal flow to gw-b's own private address (a second NAT hop) makes peer-b see a
# same-subnet source, and the handshake completes. A real signaling server avoids this entirely
# because both peers dial out to it; only this lab's inbound DNAT needs the extra translation.
#
# The port changes per attempt (run-matrix.sh increments it), so both rules live in dedicated
# chains that can be flushed and repopulated without disturbing Docker's own PREROUTING /
# POSTROUTING entries in this container's netns.
#
# Usage: gw-signal.sh <port>   (PEER_IP is the recv peer's private address)
set -euo pipefail

port="${1:?usage: gw-signal.sh <port>}"
peer_ip="${PEER_IP:-}"
wan_subnet="${WAN_SUBNET:-172.28.0.0/24}"

iptables -t nat -N LAB_SIGNAL 2>/dev/null || true
iptables -t nat -F LAB_SIGNAL
iptables -t nat -C PREROUTING -j LAB_SIGNAL 2>/dev/null \
  || iptables -t nat -A PREROUTING -j LAB_SIGNAL

iptables -t nat -N LAB_SIGNAL_SNAT 2>/dev/null || true
iptables -t nat -F LAB_SIGNAL_SNAT
iptables -t nat -C POSTROUTING -j LAB_SIGNAL_SNAT 2>/dev/null \
  || iptables -t nat -A POSTROUTING -j LAB_SIGNAL_SNAT

if [ -n "$peer_ip" ]; then
  iptables -t nat -A LAB_SIGNAL -p tcp --dport "$port" -j DNAT --to-destination "$peer_ip:$port"
  # POSTROUTING runs after DNAT, so this matches the already-rewritten destination.
  iptables -t nat -A LAB_SIGNAL_SNAT -p tcp -s "$wan_subnet" -d "$peer_ip" \
    --dport "$port" -j MASQUERADE
  echo "gw-signal: tcp/$port -> $peer_ip:$port (DNAT + SNAT to this gateway's private leg)"
else
  echo "gw-signal: no PEER_IP set; chains flushed, no rules installed"
fi
