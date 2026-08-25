# S19 — quinn-over-punched-ICE native↔native transport results

**Spike question** (`docs/DESIGN.md` §A13, S19): *"quinn-over-punched-ICE-socket native↔native:
punch rate across NATs, throughput at 0/20/50/100 ms, TURN-relay fallback, real-two-host validation
of the netem numbers."* Answers decisions **A10.31** (native↔native transport moves to QUIC via
`quinn`) and **A10.32** (standalone-ICE punching + per-session self-signed cert pinned by
fingerprint), `docs/DESIGN.md` §A8 and `docs/adr/ADR-005-transport-vfs-rpc-file-safety.md`'s
2026-08-24 amendment. S19 is the sole remaining gate on ADR-005's Accepted status (superseding S3
now that S3 is done — `spikes/s3-throughput/RESULTS.md`).

**Pass criterion (verbatim, `docs/DESIGN.md` §A13)**: *"≥ 15 MB/s @ 50 ms; punch or relay success
on all tested NAT combos; netem ceiling confirmed on a real link."* See `docs/SPIKES.md` (§S19) for
the full method sketch this file's four legs implement.

## Status: **Leg 1 complete — pass bar cleared at 50 ms by both congestion controllers. Legs 2–4 not yet run.**

`src/bin/quic-peer.rs` and `s19-rtt-run.sh` exist and are verified to build/clippy clean and pass a
loopback smoke test (fingerprint pin accepted on match, rejected on mismatch — see below). **Leg 1
(container netem throughput matrix) ran for real on 2026-08-25**, including three follow-up cells run
the same day to confirm steady-state throughput and probe the window/cc/RTT interaction further —
see the dated findings paragraph and results table below: the original 8-cell matrix (0/20/50/100 ms
× {cubic, bbr}) all completed, zero netem packet drops on every shaped cell, and the ≥ 15 MB/s @
50 ms clause of the pass bar is cleared by both congestion controllers, confirmed on a 256 MiB
steady-state re-run (cubic: 19.652 MB/s, still 31% above the floor). The NAT-punch matrix, the
TURN-relay fallback measurement, and the real-two-host leg still have not been run — leg 1 only
answers the throughput clause of the pass bar, not the "punch or relay success on all tested NAT
combos" or "confirmed on a real link" clauses. Those sections below remain empty until legs 2–4 land.

## Method (four legs)

- **Leg 1 — quinn throughput under container netem (this harness).** `src/bin/quic-peer.rs`: two
  native OS processes (`--mode recv` = quinn server, `--mode send` = quinn client) transfer
  `--bytes` MiB over one QUIC uni stream on `127.0.0.1`, congestion-controlled by `--cc
  cubic|bbr`. `s19-rtt-run.sh` shapes `lo` with `tc netem delay <RTT/2>ms limit 10000` inside the
  `spindle-toolchain:local` container (same technique as `spikes/s3-throughput/rtt-run.sh`) and
  runs the 0/20/50/100 ms × {cubic, bbr} matrix, one row per cell below. This is the leg that
  answers the throughput clause of the pass bar; it does **not** cover NAT punching — the socket
  under test here is a bound loopback pair, not an ICE-punched one (see leg 2).
- **Leg 2 — ICE punch: `webrtc-ice`'s standalone `Conn` → quinn via a custom `AsyncUdpSocket`
  adapter (deferred).** Per A10.32, standalone ICE (reusing `webrtc-rs`'s `ice` crate rather than
  duplicating it) punches the NAT, and the resulting UDP socket is handed to `quinn`. The
  integration crux: quinn does not accept a plain `UdpSocket` as its I/O — it requires a
  `quinn::AsyncUdpSocket` implementation, a batch-oriented, GSO/GRO/ECN-aware trait with its own
  poll-based readiness contract, while `ice::Conn` exposes a simple one-packet-at-a-time async
  `send`/`recv` socket interface built for SCTP/DTLS traffic. Bridging the two means writing an
  adapter that queues `ice::Conn` reads/writes under quinn's poll contract — real integration work,
  but orthogonal to whether quinn's congestion control clears the throughput bar once bytes are
  flowing over *some* UDP socket (leg 1 answers that first, cheaply). This adapter, and the NAT-type
  punch matrix (full cone / restricted cone / port-restricted / symmetric, paired both ways) it
  would unlock, are deliberately **not** implemented in this scaffold — follow-up work once leg 1's
  numbers are in. See `src/bin/quic-peer.rs`'s module doc comment for the same explanation in
  context.
- **Leg 3 — TURN-relay fallback via coturn UDP relay.** For NAT combinations where punching fails
  (symmetric↔symmetric is the expected failure case), confirm the connection falls back to the
  existing coturn relay cleanly — TURN relays UDP, and QUIC is UDP, so no new relay-side component
  is expected to be needed (A10.32) — and measure throughput over the relayed path too. Depends on
  leg 2's adapter existing (the punch attempt has to fail before fallback is exercised); not run.
- **Leg 4 — real two-host validation of the netem numbers.** S3's whole matrix ran
  netem-on-loopback in one container — a stated external-validity caveat, carried forward
  explicitly into S19 by `docs/adr/ADR-005-transport-vfs-rpc-file-safety.md`'s 2026-08-24
  amendment. This leg reproduces the 0/20/50/100 ms cells on an actual two-host link (two cloud
  instances, two physical machines, or at minimum two separate containers/VMs on different hosts)
  to confirm the netem-shaped numbers hold on a real network path. Not run.

## Loopback smoke test (macOS host, no netem — scaffold verification only)

Run once, manually, to verify the harness itself works before any container matrix. **Not a
throughput measurement** (no RTT shaping; single run; not part of the results table below).

- 16 MiB transfer, default `--cc cubic`, default `--window 16` MiB: completed successfully, byte
  count matched, fingerprint pin accepted.
- A deliberately WRONG `--cert-fp` on the send side: rejected — the connection failed at the TLS
  handshake with a fingerprint-mismatch error from `PinnedFingerprintVerifier`, exactly as
  designed (A10.32's envelope-pin model; see `quic-peer.rs`'s `verify_server_cert`).
- Exact numbers/commands: see the coordinator's verification report for this scaffolding pass (not
  duplicated here — this file records the spike's actual measured results, not scaffold smoke-test
  transcripts).

## Results — RTT × congestion-controller matrix (container, `tc netem` on `lo`)

**Leg 1 complete (2026-08-25).** All 8 cells ran cleanly on the second attempt (see the dated
findings paragraph below for the window-size fix that made that possible); every shaped cell shows
`dropped 0` on its `tc -s qdisc show dev lo` snapshot, so none of the throughput loss below is netem
queue-overflow loss — it is congestion-control response to the emulated RTT, exactly as intended.

| Date | Environment | RTT (ms) | cc | MB/s | Notes |
|------|-------------|----------|-----|------|-------|
| 2026-08-25 | Linux container (6.12.76-linuxkit), `tc netem` on `lo`, `spindle-toolchain:local` | 0 | cubic | 626.745 | 128 MiB, 64 KiB chunks, window=2 MiB; send 618.643 MB/s |
| 2026-08-25 | Linux container (6.12.76-linuxkit), `tc netem` on `lo`, `spindle-toolchain:local` | 0 | bbr | 318.541 | 128 MiB, 64 KiB chunks, window=2 MiB; send 315.609 MB/s |
| 2026-08-25 | Linux container (6.12.76-linuxkit), `tc netem` on `lo`, `spindle-toolchain:local` | 20 | cubic | 24.715 | 128 MiB, 64 KiB chunks, window=2 MiB; send 24.603 MB/s; qdisc dropped 0 |
| 2026-08-25 | Linux container (6.12.76-linuxkit), `tc netem` on `lo`, `spindle-toolchain:local` | 20 | bbr | 37.419 | 128 MiB, 64 KiB chunks, window=2 MiB; send 37.141 MB/s; qdisc dropped 0 |
| 2026-08-25 | Linux container (6.12.76-linuxkit), `tc netem` on `lo`, `spindle-toolchain:local` | 50 | cubic | **21.206** | 32 MiB, 64 KiB chunks, window=2 MiB; send 20.519 MB/s; qdisc dropped 0; **clears ≥15 MB/s bar** |
| 2026-08-25 | Linux container (6.12.76-linuxkit), `tc netem` on `lo`, `spindle-toolchain:local` | 50 | bbr | **16.681** | 32 MiB, 64 KiB chunks, window=2 MiB; send 16.222 MB/s; qdisc dropped 0; **clears ≥15 MB/s bar** |
| 2026-08-25 | Linux container (6.12.76-linuxkit), `tc netem` on `lo`, `spindle-toolchain:local` | 100 | cubic | 12.218 | 32 MiB, 64 KiB chunks, window=2 MiB; send 11.760 MB/s; qdisc dropped 0 |
| 2026-08-25 | Linux container (6.12.76-linuxkit), `tc netem` on `lo`, `spindle-toolchain:local` | 100 | bbr | 10.051 | 32 MiB, 64 KiB chunks, window=2 MiB; send 9.749 MB/s; qdisc dropped 0 |
| 2026-08-25 | Linux container (6.12.76-linuxkit), `tc netem` on `lo`, `spindle-toolchain:local` | 50 | cubic | **19.652** | **steady-state re-run**: 256 MiB, 64 KiB chunks, window=2 MiB, 13.66 s elapsed; send 19.574 MB/s; qdisc dropped 0; supersedes the 32 MiB headline as the number to cite — see findings |
| 2026-08-25 | Linux container (6.12.76-linuxkit), `tc netem` on `lo`, `spindle-toolchain:local` | 100 | cubic | 12.210 | **window=16 MiB re-run** (vs. 2 MiB default): 256 MiB, 64 KiB chunks, 21.98 s elapsed; send 12.153 MB/s; qdisc dropped 0; **identical to the 2 MiB/32 MiB short run (12.218) — confirms 100 ms is cc-limited, not window-limited** |
| 2026-08-25 | Linux container (6.12.76-linuxkit), `tc netem` on `lo`, `spindle-toolchain:local` | 100 | bbr | **FAILED** | window=16 MiB re-run: `quinn-proto` aborted — `too many gaps in stream buffer` (same class of error as the original matrix's window=16 incident, now isolated to bbr@100 ms/16 MiB specifically) — see findings |

### Findings (2026-08-25, leg 1)

**Bar verdict: the ≥ 15 MB/s @ 50 ms clause of the A13 pass bar is CLEARED, by both congestion
controllers** — cubic hits 21.206 MB/s (32 MiB, short run) and bbr hits 16.681 MB/s at 50 ms, both
comfortably above the 15 MB/s floor, with zero netem packet loss recorded on either cell. The 32 MiB
cubic run is short enough (1.58 s) that slow-start is a non-trivial fraction of its elapsed time, so
a 256 MiB steady-state re-run was added as a follow-up: **19.652 MB/s** (13.66 s elapsed, cubic,
window=2 MiB) — still **31% above the 15 MB/s floor**, confirming the bar clears on sustained
throughput, not just a slow-start-flattered short transfer. This steady-state number, not the 21.206
short-run number, is the one to cite going forward. (The other two A13 clauses — NAT-combo
punch/relay success and real-link confirmation — are untouched by leg 1; see legs 2–4.)

**Window-size fix, and why it's a container/netem artifact rather than a quinn defect.** The first
attempt at this matrix failed all 6 shaped-RTT cells (every cell except the two unshaped 0 ms
controls) with `quinn-proto` aborting the stream: `too many gaps in stream buffer`. That error comes
from `quinn-proto` 0.11.17's `Assembler` (`connection/assembler.rs`), which hard-caps a stream at
`MAX_CHUNKS = 1024` distinct non-contiguous buffered spans — an anti-DoS guard against maliciously
gapped frames, not a tunable. `tc -s qdisc show dev lo` showed **zero drops** on every failing cell,
which rules out netem queue-overflow loss as the cause. Manual bisection on a diagnostic container
(rebuilding `quic-peer` at each step) isolated the trigger: `quic-peer`'s own CLI default of
`--window 16 MiB` (deliberately generous — "so flow control never masks congestion control", per the
binary's module doc comment) permits a burst large enough that this container's `tc netem
delay`-only qdisc reorders packets under it, and quinn's assembler sees enough distinct gaps from
that reordering to trip the 1024-chunk cap before the reordered data can be reassembled. 4 MiB still
reproduces the failure at 50 ms and 100 ms on both cc; 2 MiB does not, on any shaped cell, on either
cc, and costs negligible LAN-class (0 ms) throughput (571 vs. 605 MB/s measured at 16 MiB during
bisection). `s19-rtt-run.sh` now defaults to `WINDOW_MIB=2` for exactly this reason (see the script's
inline comment for the full diagnosis); `quic-peer.rs`'s own flag default is deliberately left at
16 MiB, since a real WAN path's own jitter profile may not reproduce this container's netem-specific
reordering at all — that question is exactly what leg 4 (real-two-host) will answer. This is flagged
here as a design-relevant finding rather than a silently-worked-around test artifact: a 2 MiB flow-
control window is well below the BDP at 100 ms for the sustained rates below, which caps rtt=100 ms
throughput independent of congestion control (see next paragraph) — a real deployment tuning
`--window` will need to weigh this same reordering-tolerance-vs-BDP trade-off.

**Follow-up: is 100 ms window-limited or cc-limited, and does the window=16 MiB crash generalize?**
Two follow-up cells re-ran rtt=100 ms at `--window 16 MiB` (the scaffold's original default) with a
256 MiB transfer, to check whether the 2 MiB window found above was itself capping the 100 ms number
(2 MiB / 0.1 s RTT ≈ 20 MB/s theoretical ceiling, uncomfortably close to the 12.218 MB/s measured).
**cubic@100 ms/16 MiB came back at 12.210 MB/s — statistically identical to the 2 MiB/32 MiB short
run's 12.218 MB/s** — so 100 ms is **cc-limited, not window-limited**: cubic's own congestion window
(see the cwnd story below — it never leaves its floor) is the binding constraint here, and a bigger
flow-control window buys nothing. **bbr@100 ms/16 MiB, however, reproduced the original incident**:
`quic-peer: error: reading from uni stream: connection lost: the endpoint encountered an internal
error and cannot continue with the connection: too many gaps in stream buffer` — the same
`quinn-proto` `MAX_CHUNKS = 1024` assembler cap from the original diagnosis, now isolated to one
specific combination (bbr, 100 ms, 16 MiB) rather than "every shaped cell." The stats captured before
the crash show why: bbr's `cwnd` starts at `241200` bytes (vs. cubic's `12000` floor) and grows
further within the first second (`{"t_ms":9,...,"cwnd":241200,...}` → `{"t_ms":1011,...,"cwnd":247129,
"congestion_events":0,"lost_packets":0}` — no loss or congestion event registered before the
connection was aborted), i.e. bbr keeps considerably more data in flight than cubic at the same
window and RTT. At high BDP (100 ms × the sustained rate) that larger in-flight population gives this
container's netem-induced reordering more packets to reorder among, tripping the assembler's gap cap
before bbr ever gets to react to a real loss signal. Read as: **a real quinn receive-reassembly limit
hit by BBR's aggressive in-flight behavior at high BDP, not a bug in the harness or a fluke** — cubic
never hit it, at any window or RTT tested in this leg. This is a genuine interop-with-ourselves
finding to carry into leg 4 (does a real WAN path's jitter profile reproduce it the way this
container's netem does?) and worth raising upstream with `quinn`/`quinn-proto` if leg 4 confirms it's
not container-specific — not something to silently route around by pinning `--cc cubic` and moving
on. For this leg, it does not change the bar verdict: bbr already clears 15 MB/s at 50 ms/2 MiB
(16.681 MB/s) before this larger-window/higher-BDP regime is reached, and `quic-peer.rs`'s own
16 MiB default was never exercised by the passing 50/100 ms cells above (all of which ran at the
script's 2 MiB override).

**cwnd/BDP story from quinn's path stats.** Quinn's `Connection::stats().path` is a materially richer
surface than SCTP ever exposed in earlier spikes — per-interval `cwnd`, `rtt`, `lost_packets`, and
`congestion_events` sampled every 500 ms via `--stats-interval-ms 500`. Across every cell in this
matrix, `lost_packets` and `congestion_events` stayed at **0** throughout — this container link is
lossless once the window-size fix is in, so both controllers are probing an open, uncontended path,
not recovering from loss. cubic's `cwnd` is flat at its floor (`12000` bytes) for the entire transfer
in every cell measured — cubic's slow-start/congestion-avoidance growth curve never gets triggered
because the 2 MiB flow-control window is the binding constraint before cubic's own congestion window
would need to grow past its start value; the delivered rate still climbs each interval (e.g. rtt=50 ms
cubic: `4.096` → `4.403` → `25.416` → `31.963` MB/s over four 500 ms samples) purely from the flight
filling up against a fixed cwnd/window pair, not from cwnd expansion. bbr tells a different story —
its `cwnd` genuinely grows across every cell, e.g. at rtt=50 ms:
```
{"t_ms":2,"bytes":17552,"rate_mb_per_s":8.776,"rtt_ms":54.878,"cwnd":241200,"congestion_events":0,"lost_packets":0}
{"t_ms":502,"bytes":1014668,"rate_mb_per_s":1.994,"rtt_ms":53.515,"cwnd":247202,"congestion_events":0,"lost_packets":0}
{"t_ms":1002,"bytes":11047606,"rate_mb_per_s":20.066,"rtt_ms":51.511,"cwnd":248349,"congestion_events":0,"lost_packets":0}
{"t_ms":1502,"bytes":23026589,"rate_mb_per_s":23.958,"rtt_ms":51.400,"cwnd":249329,"congestion_events":0,"lost_packets":0}
{"t_ms":2001,"bytes":33044289,"rate_mb_per_s":20.076,"rtt_ms":51.728,"cwnd":250326,"congestion_events":0,"lost_packets":0}
```
bbr starts around 20x cubic's floor (`241200` vs `12000` bytes — BBR's initial cwnd is deliberately
larger) and keeps climbing modestly through the whole transfer, consistent with BBR's model-based
bandwidth probing rather than cubic's loss-triggered growth. At rtt=100 ms bbr's cwnd climbs from
`241200` to `250349` across the transfer while `rate_mb_per_s` actually *drops* in the last sample
(`11.014` → `9.412` MB/s). **Correction from the follow-up cells (see above): the 2 MiB flow-control
window is not, in fact, the binding ceiling at 100 ms** — re-running cubic@100 ms at `--window
16 MiB` produced the same 12.2 MB/s, so cubic's own congestion window (flat at its `12000`-byte floor
the entire time, per the steady-state samples below) is what caps it, not flow control. bbr's cwnd
growth at 100 ms is real, but whether it would translate into more throughput at a larger window is
unconfirmed — the bbr@100 ms/16 MiB cell needed to test that crashed with the assembler's gap cap
before steady state (see the follow-up paragraph above), so bbr@100 ms's ceiling is unresolved by
this leg. In short: **cwnd does scale toward BDP the way SCTP's fixed/coarser windows never did (bbr
visibly, cubic implicitly via flight-fill), but which of {cc, flow-control window, assembler cap} is
binding differs by cell** — cubic@50/100 ms is cc-limited (confirmed), bbr@50 ms clears the bar
comfortably, and bbr@100 ms's true ceiling is masked by the reassembly-cap crash at the window size
needed to probe it.

**cubic vs. bbr across the matrix.** The comparison is not monotonic: cubic leads at 0 ms
(626.745 vs. 318.541 MB/s — bbr's pacing is conservative when there's no RTT to hide latency behind),
**bbr leads at 20 ms** (37.419 vs. 24.715 MB/s — bbr's model-based probing ramps faster than cubic's
additive-increase curve once there's a real RTT to pace against), and cubic leads again at 50 ms
(19.652 MB/s steady-state vs. bbr's 16.681 MB/s) and 100 ms (12.218 vs. 10.051 MB/s). No *passing*
cell showed any loss or congestion event for either controller, so these throughput differences are
pacing/ramp-up behavior interacting with the fixed window and each cell's transfer size, not loss
recovery. The one place the two controllers diverge qualitatively rather than just quantitatively is
the window=16 MiB/100 ms follow-up: cubic completed it cleanly at the same throughput as its 2 MiB
run, while bbr crashed the assembler's gap cap outright (see above) — cubic is the more robust choice
under this container's netem-reordering conditions at large windows, even though bbr is competitive
or ahead at low-to-moderate RTT. For this spike's purposes both controllers clear the pass bar at
50 ms; `quic-peer.rs`'s `--cc` flag makes the choice a runtime knob rather than a build-time one, so
this is not a decision this spike needs to force — but the bbr@100 ms/16 MiB finding is a reason to
default to cubic if a single choice is ever needed before leg 4 resolves whether it's container-
specific.

**Remaining work.** Legs 2 (ICE-punch `AsyncUdpSocket` adapter + NAT-type matrix), 3 (TURN-relay
fallback), and 4 (real-two-host validation of these netem numbers) are still not run — see "Method"
above. Leg 1 alone does not close S19; it clears the throughput clause of the pass bar and produces
the window-size finding that legs 2 and 4 will need to account for.

## Results — NAT-punch matrix

**Not yet run** (blocked on leg 2's `AsyncUdpSocket` adapter — see "Method" above).

| Date | Environment | NAT type (local) | NAT type (peer) | Punch result | Time-to-punch | Notes |
|------|-------------|-------------------|------------------|---------------|----------------|-------|
| | | | | | | |

## Results — TURN-relay fallback

**Not yet run** (blocked on leg 2).

| Date | Environment | NAT combo | Relay result | MB/s (relayed) | Notes |
|------|-------------|-----------|---------------|-----------------|-------|
| | | | | | |

## Results — real-two-host validation

**Not yet run.**

| Date | Host pair / link | RTT (ms) | cc | MB/s | Notes |
|------|-------------------|----------|-----|------|-------|
| | | | | | |
