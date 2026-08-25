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

## Status: **Not yet run — scaffold only.**

`src/bin/quic-peer.rs` and `s19-rtt-run.sh` exist and are verified to build/clippy clean and pass a
loopback smoke test (fingerprint pin accepted on match, rejected on mismatch — see below), but the
container RTT matrix, the NAT-punch matrix, the TURN-relay fallback measurement, and the real-two-
host leg have not been run. No throughput numbers, punch-rate numbers, or relay numbers exist yet.
This section will be replaced once each leg below actually runs.

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

**Not yet run.** Table left empty; `s19-rtt-run.sh` appends one row per (RTT, cc) cell here once
executed.

| Date | Environment | RTT (ms) | cc | MB/s | Notes |
|------|-------------|----------|-----|------|-------|
| | | | | | |

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
