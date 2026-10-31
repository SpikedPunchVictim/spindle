# Two-container NAT + netem lab (S19 follow-up)

This is a **simulated, still-one-kernel** improvement on the single-container network-namespace
rig in `spikes/s19-quic-transport/s19-nat-run.sh`. It is **not** S19 leg 4, and it does not close
the real-two-host clause in `spikes/s19-quic-transport/RESULTS.md`.

It exists to answer what the netns harness could not:

- a **routed** path through two independent NAT containers, not two network namespaces inside one
  container;
- **per-side** `tc netem` shaping (delay, loss, reordering applied independently on each peer's
  egress), rather than one qdisc on `lo`;
- **real packet reordering** (`netem reorder`), not just the delay-only qdisc's incidental
  reordering.

## Topology

```
                      registry side — docker network "wan" 172.28.0.0/24
   nats .10  helper .11  postgres .12  coturn .13  stun .14  nats-s2 .15
        \         |           |            |          |          /
         +--------+-----------+------------+----------+---------+
                                |
                          wan bridge (Docker)
                    /            |             \
            gw-a .21          gw-b .22          gw-c .23
            MASQUERADE        MASQUERADE        MASQUERADE
            (+ signal DNAT)   (+ signal DNAT)
                 |                |                 |
       nat-a 172.28.10/24  nat-b 172.28.20/24  nat-c 172.28.30/24
            gw-a .254          gw-b .254          gw-c .254
                 |                |                 |
         peer-a .2 (host)     peer-b .2         peer-c .2 (S2 client)
         tc netem             tc netem           tc netem
```

`nats-s2` is a second, deliberately **unauthenticated** NATS used only by the S2 across-NAT
harness (`spikes/s2-nat-lab`); the authenticated `nats`/`helper` stack above is untouched and
still proves the callout path in the live tests. `peer-c` exists so the S2 client is on a private
network distinct from the host's `peer-a` — signaling and media are no longer same-LAN.

- `peer-a` and `peer-b` have **no interface on `wan`**. Their only route off their private
  network is their gateway container, which is a real second network namespace with its own
  conntrack table, `ip_forward=1`, and `MASQUERADE` on its wan-facing leg.
- `gw-b` additionally DNATs the recv peer's TCP `--signal` port, because `quic-peer`'s signaling
  is a direct listen/connect channel rather than a rendezvous server. A real deployment's
  signaling server is dialled out to by both peers; this DNAT is the lab's stand-in for that
  reachability, and is not part of ICE or TURN.
- `stun` is the in-repo `stun-server` binary (`spikes/s19-quic-transport/src/bin/stun-server.rs`)
  on the registry side. `coturn` is the dev stack's relay (`use-auth-secret`, the same
  `TURN_SECRET` the helper is given), also on the registry side.
- `nats`, `postgres`, and `helper` are copied from `deploy/docker-compose.yml` (images, commands,
  environment, volumes unchanged); only static `wan` addresses and the lack of host port
  publications differ. The lab does not exercise them — they are present so the "registry side"
  is the real dev stack rather than a stub.

## Four Docker/kernel facts this lab had to work around (verified empirically)

1. **Interface names are not stable.** `docker-compose.lab.yml` declares `wan` before `nat-a`/
   `nat-b`, but on this Docker Desktop VM the kernel-visible order came out
   `eth0=private, eth1=wan` on one run and `eth0=wan, eth1=private` on another. Every script
   locates interfaces by IPv4 prefix (`WAN_PREFIX`, `PRIVATE_PREFIX`), never by name or
   declaration order.

2. **`.1` is reserved.** Docker assigns the first address of each user-defined subnet to the
   bridge itself, so a NAT-gateway container cannot hold `x.x.x.1`. Gateways use `.254` for
   their private leg, and `peer-entrypoint.sh` replaces Docker's default route (which points at
   the bridge, i.e. the Docker host) with a default route via the gateway container. Without
   that override, peer traffic would bypass the NAT container and be routed by the host between
   its own bridges — the lab would not test NAT at all.

3. **The inbound signaling DNAT needs a second NAT hop.** The DNATed SYN is forwarded out gw-b's
   private interface still carrying the *other* gateway's wan source address (`172.28.0.21`).
   gw-b's conntrack records the DNAT flow as `[UNREPLIED]`, the peer never sees a SYN, and the
   `nc -z`/`quic-peer` connect hangs: the frame crosses onto the private Docker bridge with a
   source belonging to a different bridge and the host's bridge netfilter/rp_filter drops it.
   `gw-signal.sh` therefore SNATs the forwarded signal flow to gw-b's own private address
   (`LAB_SIGNAL_SNAT`), so peer-b sees a same-subnet source. Verified: with the SNAT the TCP
   connect succeeds and conntrack shows the reply; without it, the flow stays `[UNREPLIED]`. A
   real rendezvous server does not need this, because both peers dial *out* to it.

4. **The Docker host routes between the private bridges, so the gateways must drop
   private→other-private forwarding.** Without that drop, a peer's packet to the *other* peer's
   private host candidate is forwarded by its gateway's default route to the Docker host, which
   routes it straight onto the other private bridge. The packet never meets the second NAT, and
   ICE selects the private host candidates (`172.28.20.2`/`172.28.10.2`) — observed empirically:
   all six `sym_ice` attempts "succeeded" against `--random-fully` NAT for exactly this reason.
   `gw-nat.sh` now installs `LAB_FORWARD` with `-s <own-private> -d <other-private> -j DROP` ahead
   of `ACCEPT`, and `gw-entrypoint.sh` sets the gateway's default route to the wan gateway. After
   the fix, a successful punch must select a `172.28.0.x` (NAT-mapped) address; the runner's raw
   logs record the selected address, and the matrix is only meaningful when it is a wan address.

A fifth, kernel-level fact: `tc ... netem reorder 25% 50%` **is refused** without a delay
(`reordering not possible without specifying some delay`). The matrix's reordering cell therefore
uses `delay 10ms reorder 25% 50%` on each peer; this is reported as a deviation from the bare
form in `RESULTS.md`.

## What is and is not simulated

**Simulated / added over the netns rig**

- Three gateway containers (`gw-a`/`gw-b`/`gw-c`), each with its own netns, routing table,
  conntrack table, and MASQUERADE rule. Peers are routed through them, and each gateway drops
  private→other-private forwarding (for *all* other private subnets) so private host candidates
  cannot be reached around the NATs.
- Cone NAT = plain `MASQUERADE` (port-restricted cone filtering). Symmetric NAT =
  `MASQUERADE --random-fully` (a fresh external port per destination).
- Independent per-side shaping on each peer's egress: delay, loss, reordering.
- STUN and TURN reached through the gateways, exactly as a NATed peer reaches a public server.
- A real TCP cross-NAT signaling path (listen on peer-b, DNAT through gw-b, connect from peer-a).

**Not simulated / still unproven**

- **Not two hosts.** Both peers are containers in Docker Desktop's single Linux VM
  (`linuxkit`), sharing one kernel. This is the same nested-virtualization environment that made
  the netns harness's cone-NAT punch probabilistic; the lab measures that environment again, not
  a real home router.
- **Not a real WAN.** netem delay/loss/reorder is synthetic and independent per side; it is not a
  sampled RTT/jitter distribution from a real link.
- **Not the real two-host leg 4.** No physical NICs, no real path between machines, no real
  router. The real-two-host clause of S19's pass bar remains open.
- **No production signaling.** `--signal`/`--cert-fp`/`--turn-secret` are spike stand-ins; the
  A7 envelope path and the helper's credential minting are not exercised.
- **No browser/WebRTC leg.** Native↔native QUIC only.
- **No congestion/latency validation on macOS.** Nothing is shaped on the host; see below.

## macOS / Docker Desktop caveat

`NET_ADMIN`, `iptables`, `tc`, and the gateway sysctls all operate **inside the Linux VM** that
Docker Desktop runs. Nothing is shaped, NATed, or filtered on the macOS host, and the macOS host
sees no part of this topology. Results are properties of the Linux VM's kernel and its virtual
bridge/conntrack implementation, not of the Mac's network stack.

`/proc/sys` is read-only inside these containers (the netns harness remounted it rw), but compose
`sysctls:` are applied by the runtime from outside the container's mount namespace, so
`net.ipv4.ip_forward=1` and `rp_filter=0` take effect without `SYS_ADMIN` or a remount. This was
verified before relying on it.

## Usage

```bash
# full matrix (builds the image, brings the lab up, runs cells, tears down)
deploy/lab/run-matrix.sh

# leave the lab running for manual poking
KEEP_LAB=1 deploy/lab/run-matrix.sh

# S2 across-NAT measurement using the production signaling stack (host on peer-a, client on
# peer-c, signaling via nats-s2). Default is STUN + ICE punch; set TURN_SERVER to measure
# punch-first with the relay fallback (td-870b25). See the S2 section below.
deploy/lab/run-s2-nat.sh
TURN_SERVER=172.28.0.13:3478 REBUILD=1 deploy/lab/run-s2-nat.sh

# fewer/more attempts, smaller transfer
RUNS=3 MAX_ATTEMPTS=8 BYTES_MIB=32 WINDOW_MIB=2 deploy/lab/run-matrix.sh
```

The script prints markdown tables to stdout and writes raw per-attempt evidence to
`deploy/lab/.artifacts/` (gitignored): recv/send `--json` lines, stderr, `--stats-out` samples,
`tc -s qdisc` snapshots, `attempts.tsv`, `summary.tsv`, and `lab-env.txt`.

### Manual cell

```bash
C="docker compose -p spindle-lab -f deploy/lab/docker-compose.lab.yml"

# shape both peers (delay_ms loss_pct reorder_pct reorder_corr_pct)
$C exec -T peer-a /usr/local/bin/apply-netem.sh 25 0 0 0
$C exec -T peer-b /usr/local/bin/apply-netem.sh 25 0 0 0

# install the signaling DNAT for this attempt's port
$C exec -T gw-b /usr/local/bin/gw-signal.sh 15101

# recv (peer-b, behind nat-b)
$C exec -T peer-b /usr/local/bin/quic-peer --mode recv --transport ice \
  --signal listen:15101 --stun 172.28.0.14:3478 --ice-bind 172.28.20.2 \
  --bytes 32 --window 2 --json

# send (peer-a, behind nat-a) -- connect to gw-b's wan address
$C exec -T peer-a /usr/local/bin/quic-peer --mode send --transport ice \
  --signal connect:172.28.0.22:15101 --stun 172.28.0.14:3478 --ice-bind 172.28.10.2 \
  --bytes 32 --window 2 --json
```

Switch NAT behavior on a live lab:

```bash
$C exec -T gw-a /usr/local/bin/gw-nat.sh symmetric
$C exec -T gw-b /usr/local/bin/gw-nat.sh symmetric
$C exec -T gw-a conntrack -F && $C exec -T gw-b conntrack -F
```

### Service names and `extra_hosts`

Docker's embedded DNS is scoped to the networks a container is attached to. Peers are attached
only to their private network, so they cannot resolve `stun`, `coturn`, `gw-b`, etc. Each peer
gets `extra_hosts` entries mapping those names to their static `wan` addresses. Note that
`quic-peer`'s `--signal`, `--stun`, and `--turn` flags parse `SocketAddr` and therefore require
**IP literals**; `run-matrix.sh` passes IPs. The `/etc/hosts` entries are for diagnostics
(`ping stun`, `getent hosts coturn`) and any future hostname-accepting client.

## Cell matrix

| Cell | Each peer's netem | NAT | Transport | Purpose |
|------|-------------------|-----|-----------|---------|
| `baseline` | none | cone:cone | `ice` | punch success + unshaped throughput |
| `delay25` | `delay 25ms` | cone:cone | `ice` | ~50 ms RTT, comparable to leg 1's pass-bar cell |
| `delay50` | `delay 50ms` | cone:cone | `ice` | ~100 ms RTT |
| `loss1` | `loss 1%` | cone:cone | `ice` | QUIC under loss |
| `reorder25` | `delay 10ms reorder 25% 50%` | cone:cone | `ice` | QUIC survival under real reordering |
| `sym_ice` | none | symmetric:symmetric | `ice` | expected punch failure |
| `sym_relay` | none | symmetric:symmetric | `relay` | TURN fallback through coturn |

`run-matrix.sh` repeats until `RUNS` successes (default 3) or `MAX_ATTEMPTS` (default 8),
reporting the success count as well as the median/spread over successful runs. `sym_ice` runs
exactly `RUNS` attempts because failure is the expected result.

## Measured outcome (2026-10-30)

On this Docker Desktop VM (kernel `7.0.14-linuxkit`), with the corrected topology and 32 MiB
transfers, `--window 2`:

- **Cone punch is probabilistic.** Default-MASQUERADE cone×cone punched **3/12 (25%)**, matching
  the netns rig's 3/13; successful punches selected NAT-mapped `172.28.0.x` addresses and ran at
  **326.261 MB/s** median (259.670-372.547).
- **Any nonzero delay prevented punching here** (0/24 at 25 ms each way, 0/6 at 50 ms, 0/10 at
  10 ms + `reorder 25% 50%`, and 0/6 each at 1 ms and 5 ms in the investigation), all with the
  same 15 s no-pair timeout. **1% loss alone did not**:
  3/5 punches, 368.437 MB/s median. This is a Linux-conntrack NAT port-allocation race made
  deterministic by the delay, **not** a delay-tolerance limit: a direct-on-wan pair with the same
  25 ms punches normally. See the investigation in `spikes/s19-quic-transport/RESULTS.md`.
- Because punching fails under delay, shaped throughput was also measured over the **relay**
  fallback: 1.912 MB/s at 51 ms RTT (25 ms shaping), 2.703 MB/s at 101 ms (50 ms shaping), and
  **0.347 MB/s under `reorder 25% 50%`** — QUIC survives reordering but collapses, with 55-78
  lost packets on the recv path.
- Symmetric×symmetric: ICE **0/3** (expected), relay **3/3 at 77.112 MB/s** (74.298-82.317).

These are **not** leg 4 results: one kernel, virtual bridges, synthetic shaping. The full
write-up, exact flags, and what remains unproven are in
`spikes/s19-quic-transport/RESULTS.md` under "Results — two-container lab (simulated; still one
kernel)".

## S2 across NATs (production signaling stack)

`run-s2-nat.sh` drives the production `spindle_net::signaling::{SignalingHost, SignalingClient}`
with the host on `peer-a` (nat-a) and the client on `peer-c` (nat-c), signaling through `nats-s2`.
The fixed identities and the lab-local `RegistryAuthorizer` live in `spikes/s2-nat-lab`; the
binaries are built by `Dockerfile.s2lab` and copied into the peers.

Since **td-c3badf**, `spindle-net`'s `IceConfig` gathers a host candidate plus a server-reflexive
candidate per configured STUN server. Since **td-870b25**, configuring TURN makes it the
**fallback** rather than a mode: both peers run an ICE attempt for a shared `PUNCH_WINDOW_MS`
(default 3000, the production default) while allocating TURN in parallel; a pair selected in the
window wins and the allocation is released, an expired window switches to the relay. A failed
allocation logs and continues punch-only. `run-s2-nat.sh` passes `STUN_SERVER` (default
`172.28.0.14:3478`) and `PUNCH_WINDOW_MS` to both peers; `TURN_SERVER=172.28.0.13:3478` enables the
punch-first path. Both peers must get the same setting. Both roles log `transport selected` with
the session id, so the report joins the two sides per attempt and counts splits (different
transports), which fail the QUIC handshake.

Measured 2026-10-30 on this lab (5 s ICE timeout, 5 successes wanted):

| Cell | Transport | Attempts | Successes | offer→answer ms | answer→selected ms | selected→QUIC ms | offer→usable ms |
|------|-----------|----------|-----------|-----------------|--------------------|------------------|-----------------|
| unshaped | punch | 40 | 5 | 4.057 | 609.705 | 7.288 | 618.903 |
| 50 ms both | punch | 5 | 0 | — | — | — | — |
| unshaped | relay | 5 | 5 | 1.639 | 2.018 | 1.549 | 5.761 |
| 50 ms both | relay | 5 | 5 | 104.274 | 156.961 | 103.792 | 468.909 |

The punch numbers reproduce td-3c1762 on this NAT (5/40 = 12.5% unshaped, 0% at any delay; earlier
runs got 1/10, 5/24 and 5/33, hence the larger unshaped attempt budget). The relay path completes every
shaped attempt; on the relay path `answer→selected` measures "answer verified → TURN allocation +
CreatePermission complete" (no ICE selection runs). The answer is published with the host candidate
only, so STUN gathering and TURN allocation do not sit on the offer/answer path. Exact per-attempt
evidence is in `spikes/s2-signaling/RESULTS.md`.

The TURN rows above predate punch-first and are **superseded** for TURN-configured peers by the
td-870b25 cells in the same RESULTS file: with `PUNCH_WINDOW_MS=3000` on both peers, 40 unshaped
attempts gave 5 punch / 35 relay and 10 shaped attempts gave 10 relay, with **0 splits and 0
one-sided selections**. Punch offer→usable was 636.005 ms unshaped; relay offer→usable was
3037.235 ms unshaped (the 3 s window plus ~11 ms) and 3394.280 ms at 50 ms.

Before td-c3badf this section recorded the host-only failure: unshaped 0/10 and 50 ms 0/5, all
`ICE trickle timed out`; that history and its failure strings remain in the same RESULTS section.

## File map

- `Dockerfile.lab` — multi-stage build of `quic-peer` + `stun-server` (builder pinned by
  `rust-toolchain.toml`) and a runtime with `iproute2`, `iptables`, `conntrack`, `tcpdump`,
  `bash`.
- `docker-compose.lab.yml` — the topology.
- `gw-entrypoint.sh` — gateway startup: forwarding, MASQUERADE, signal DNAT.
- `gw-nat.sh` — switch a live gateway between `cone` and `symmetric`.
- `gw-signal.sh` — (re)install the signaling DNAT rule and its private-leg SNAT.
- `peer-entrypoint.sh` — set the default route to the gateway and apply compose netem.
- `apply-netem.sh` — apply/clear a netem qdisc; refuses reorder without a delay.
- `run-matrix.sh` — orchestration, measurement, markdown output.
- `Dockerfile.s2lab` — scratch image with the two `spikes/s2-nat-lab` binaries.
- `run-s2-nat.sh` — S2 across-NAT driver (unshaped and 50 ms cells).

## Relationship to leg 4

This lab adds a routed two-NAT path, per-side shaping, and real reordering on the *same kernel*.
It does not substitute for two real hosts. The measured numbers are recorded in
`spikes/s19-quic-transport/RESULTS.md` under "Results — two-container lab (simulated; still one
kernel)", which says explicitly what remains unproven.
