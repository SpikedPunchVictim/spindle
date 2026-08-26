# S5 — Presence via `$SYS` events; ping tuning — RESULTS

**Status: PASS — run 2026-08-25/26.** 15/15 automated checks green against the composed reference
deployment (`deploy/docker-compose.yml`'s `nats` + `postgres` + `helper`, `nats-server:2.10-alpine`
== v2.10.29; coturn not started, not needed). `crates/spindle-helper`'s live presence pipeline
(`presence.rs` + `bin/helper.rs`'s `$SYS`/CONNZ bridging, landed in ac9bb98) exercised end-to-end
for the first time — see "Bugs found and fixed" below for two genuine wiring/parsing defects this
spike found and fixed (in scope per the task's explicit allowance to fix `$SYS`/CONNZ parsing
against real payload shapes).

## Method

`spikes/s5-presence/run.sh`: builds `fake_host` (a standalone host-connection process, so it can
be `SIGSTOP`ed as a genuinely separate OS process — TCP stays open, no FIN, only the server's own
PING/PONG can detect it) and `s5-tests` (the harness), brings up `docker compose -f
deploy/docker-compose.yml up -d --build nats postgres helper`, waits for nats-server's `/varz`,
gives the helper a few seconds to finish its own startup (connect three NATS connections, run
Postgres migrations, subscribe, seed presence from CONNZ), runs the harness, dumps
`docker compose logs helper` for evidence, and always brings the stack down
(`docker compose down`) on exit — confirmed via `docker ps` after the final run: empty.

Identity/cap/admission plumbing reused from `spikes/s1-callout::fixtures` via a Cargo path
dependency (device/host identities, member capability minting, the hand-rolled CBOR admission
envelope, `nats_fp_of_nkey`) rather than reimplemented.

## Results — pass/fail vs. bar, per scenario

| # | Scenario | Result | Measured |
|---|----------|--------|----------|
| a | Fake host connects through the callout | PASS | host_fp resolved matches expected |
| b | Device connects w/ member cap, subscribes `host.<hfp>.presence`, `helper.presence.get.<nfp>` → `{ok:true, hosts:[{state:"online",...}]}` | PASS | — |
| b | Negative test: a different session's publish on another session's `helper.presence.get.<nfp>` is refused by NATS perms (A12 #46 property) | **PASS** | `Permissions Violation for Publish to "helper.presence.get.<other nfp>"` observed async via `event_callback` |
| c | Clean disconnect → offline delta on `host.<hfp>.presence`. **Bar: ≤ 5 s** | PASS | **0.01 s** |
| c | Re-query after clean disconnect → offline + `last_seen` set | PASS | — |
| d | Dead socket (`SIGSTOP` on the fake-host child process) → offline delta. **Bar: ≤ 60 s** | PASS | **42.36 s** (with `ping_interval: 20s` / `ping_max: 2`) |
| d | Host reconnect → online delta | PASS | 0.00 s (effectively instant) |
| e | Two live connections for the same `host_fp`, drop one → no offline flip | PASS | no unexpected delta observed |
| e | Second concurrent connect doesn't re-flip already-online state | PASS | no unexpected delta observed |
| e | Reconnect-before-stale-disconnect never flips offline | PASS | no delta on reconnect, none on the later stale disconnect either |
| f | `docker compose restart helper` while host stays online, then `helper.presence.get` still reports online (CONNZ reseed) | **PASS** (after two fixes — see below) | reseeded `state:"online"` after restart |

**Ping tuning used**: `ping_interval: "20s"`, `ping_max: 2` (per DESIGN.md §A6), added to
`deploy/nats/nats-server.conf`. Dead-socket detection landed at 42.36 s — comfortably inside the
60 s bar and consistent with "up to `ping_interval * ping_max`" (40 s) plus the fake host's own
`SIGSTOP` timing jitter and the harness's poll granularity.

## Bugs found and fixed (in scope: real `$SYS`/CONNZ payload validation, per the task)

This was the first live run of the presence pipeline against a real `nats-server`. It surfaced two
genuine defects — not in `presence.rs`'s pure logic (all 114 pre-existing unit tests kept passing
throughout), but in `bin/helper.rs`'s I/O wiring and in the deploy config it depends on. Both are
now fixed, covered by new unit tests using the real captured payload shapes, and confirmed by this
15/15 re-run.

### Bug 1 — `$SYS.ACCOUNT.*.CONNECT|DISCONNECT` subscriptions never fired at all

**Symptom**: on the very first live run, `helper.presence.get.<nfp>` reported the connected fake
host as `{"state":"offline","last_seen":null}` *immediately after* connecting — before any
disconnect scenario had even run. 7 of 15 checks failed as a result (everything downstream of "the
host is ever seen online").

**Root cause**: `deploy/nats/nats-server.conf`'s account topology put the callout/system
connection (`CALLOUT_USER`) in the `AUTH` account, not the `SYS` account (`SYS: { users: [] }` —
empty). `$SYS.REQ.USER.AUTH` and `$SYS.REQ.SERVER.PING.CONNZ` are special-cased request/reply
subjects that nats-server answers to any `auth_callout.auth_users` connection regardless of its
own account (which is why S1's callout flow and the CONNZ startup request already worked) — but
`$SYS.ACCOUNT.*.CONNECT`/`.DISCONNECT` are *ordinary pub/sub broadcasts published on the SYS
account*. Subscribing to them from an AUTH-account connection silently receives nothing; NATS does
not error on the subscribe call itself.

**Fix**: added a third, dedicated nkey identity (`SYS_CONN_USER`) as a genuine member of the `SYS`
account in `nats-server.conf` (also added to `auth_callout.auth_users` so it still bypasses the
callout), a matching `SYS_CONN_SEED` env var in `deploy/docker-compose.yml`, and a `sys_conn_seed`
/ `SYS_CONN_SEED` / `--sys-conn-seed` config field in `bin/helper.rs`. `run()` now opens a third
connection (`sys_client`, falling back to `callout_client` with a loud warning if unset) and
subscribes/requests `$SYS.ACCOUNT.*.CONNECT`, `.DISCONNECT`, and `$SYS.REQ.SERVER.PING.CONNZ` on
it. Confirmed: after this fix, real `$SYS.ACCOUNT.*.CONNECT|DISCONNECT` events started arriving
(captured samples below) and scenarios a–e all passed.

### Bug 2 — CONNZ reseed (`f`) never recovered any host identity

**Symptom**: after Bug 1's fix, 14/15 passed; only `f_connz_reseed_reports_online_after_restart`
failed — after `docker compose restart helper` (host connection untouched, only the helper
container restarts), `presence.get` kept timing out at `{"state":"offline","last_seen":null}`
instead of reseeding to online.

**Root cause (two parts, both required)**:
1. `seed_presence_map`'s `$SYS.REQ.SERVER.PING.CONNZ` request sent an **empty** body. A real
   nats-server 2.10.29 reply to an empty-body CONNZ request has **no user-identity field at all**
   on any connection row (see "Captured real payload samples" below, "before" sample) —
   nats-server's `ConnzOptions.Username` field (JSON key `"auth"`) must be explicitly set to
   `true` in the request to get identity info back.
2. Even after fixing (1), the identity field in a real reply is named **`"authorized_user"`**, not
   `"user"` as originally assumed from general documentation knowledge (`docs/DESIGN.md`/this
   file's own doc comments only ever said `"user"` — no local ground truth existed before this
   spike).

**Fix**: `seed_presence_map` now sends `{"auth": true}` as the CONNZ request body, and the row
parser (extracted into a new pure, unit-tested `connz_row_user_pk` function) checks
`"authorized_user"` first, falling back to `"user"` (kept tolerant in case a future nats-server
version or a differently-configured CONNZ ever uses the other name — never observed in practice).
Confirmed: after both fixes, `f` passed — CONNZ reseed correctly reports the host online again
after a helper restart.

**Unit tests added** (`crates/spindle-helper/src/bin/helper.rs`, `#[cfg(test)] mod tests`, 6 new
tests, using the exact real captured JSON — not hand-invented): a CONNZ row with `authorized_user`
parses correctly; a CONNZ row with no identity field at all (the pre-fix shape) yields `None`; the
`"user"` fallback still works; `authorized_user` is preferred when both are present; a real
`$SYS.ACCOUNT.*.CONNECT` event and a real `.DISCONNECT` event (captured from the `SIGSTOP`
scenario, `reason: "Stale Connection"`) both yield the expected `client.user` pubkey via
`user_from_sys_event` (this function's assumed shape was already correct — no fix needed there,
now backed by a real-payload test instead of general knowledge).

`cargo test -p spindle-helper`: 114 pre-existing + 6 new = **120 passed, 0 failed**.
`cargo check --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`: clean.

## Captured real payload samples (task g deliverable)

### `$SYS.REQ.SERVER.PING.CONNZ` reply — BEFORE the `{"auth": true}` fix (one row, trimmed)

No user-identity field of any kind:

```json
{
  "cid": 19, "idle": "0s", "in_bytes": 0, "in_msgs": 0, "ip": "172.26.0.4", "kind": "Client",
  "lang": "rust", "last_activity": "2026-08-26T04:34:36.267987921Z", "out_bytes": 0,
  "out_msgs": 0, "pending_bytes": 0, "port": 34544, "rtt": "5.156167ms",
  "start": "2026-08-26T04:34:36.219214254Z", "subscriptions": 1, "type": "nats", "uptime": "0s",
  "version": "0.35.1"
}
```

### `$SYS.REQ.SERVER.PING.CONNZ` reply — AFTER the fix (`{"auth": true}` requested, one row, trimmed)

```json
{
  "account": "APP", "authorized_user": "UAOUJCRS3HXWQ2GKAA2PZA7QA5WQN3QTPTBSFX2KYC2XTY7P67U2252X",
  "cid": 20, "idle": "0s", "in_bytes": 0, "in_msgs": 0, "ip": "172.26.0.4", "issuer_key": "APP",
  "kind": "Client", "lang": "rust", "last_activity": "2026-08-26T04:40:26.092235Z",
  "out_bytes": 0, "out_msgs": 0, "pending_bytes": 0, "port": 34748, "rtt": "384µs",
  "start": "2026-08-26T04:40:26.061902097Z", "subscriptions": 2, "type": "nats", "uptime": "0s",
  "version": "0.35.1"
}
```

Diff vs. what `presence.rs`/`bin/helper.rs` originally assumed: `"user"` → **`"authorized_user"`**
(plus a bonus `"account"` field — the account *name*, not used by the current parser but noted for
future reference); everything else (`cid`, `ip`, etc.) matched the general-knowledge assumption.

### `$SYS.ACCOUNT.APP.CONNECT` — real sample

```json
{
  "type": "io.nats.server.advisory.v1.client_connect", "id": "HoUqrLYsWsMsv9m8ZFLQUF",
  "timestamp": "2026-08-26T04:33:42.221103549Z",
  "server": { "...": "..." },
  "client": {
    "start": "2026-08-26T04:33:42.202549549Z", "host": "151.101.42.132", "id": 10,
    "acc": "APP", "user": "UCCDYXIJL3ARVUAHY6QMJWI34OI7QL525CQKOOJSPVKW3NZMEKC2VTE3",
    "lang": "rust", "ver": "0.35.1", "issuer_key": "APP", "kind": "Client", "client_type": "nats"
  }
}
```

### `$SYS.ACCOUNT.APP.DISCONNECT` — real sample, from the `SIGSTOP` dead-socket scenario

```json
{
  "type": "io.nats.server.advisory.v1.client_disconnect", "id": "HoUqrLYsWsMsv9m8ZFLR1N",
  "timestamp": "2026-08-26T04:34:24.677784847Z",
  "server": { "...": "..." },
  "client": {
    "start": "2026-08-26T04:33:42.521603508Z", "host": "151.101.42.132", "id": 13,
    "acc": "APP", "user": "UB5AUMGSNEAINIEWVEYRRSDD4PX6LUWDNO7OLOFCAJCT7IZLLARZWP6N",
    "lang": "rust", "ver": "0.35.1", "rtt": 801000, "stop": "2026-08-26T04:34:24.677784847Z",
    "issuer_key": "APP", "kind": "Client", "client_type": "nats"
  },
  "sent": { "msgs": 0, "bytes": 0 }, "received": { "msgs": 0, "bytes": 0 },
  "reason": "Stale Connection"
}
```

Diff vs. what `user_from_sys_event` assumed: **none** — the `{"client": {"user": "<pubkey>",
...}}` shape it was already written to parse matched exactly. Worth noting for future work:
`client.reason` distinguishes a clean close (`"Client Closed"`, seen in every other disconnect
this run) from a ping-timeout dead-socket disconnect (`"Stale Connection"`, seen only for the
`SIGSTOP`'d fake host) — not consumed by the current parser, but a useful signal if presence ever
wants to report *why* a host went offline.

Full untrimmed replies/events are in `.s5-helper.log` (gitignored, regenerable via `run.sh`).

## Ambiguities / things not fully resolved

- **Multi-server CONNZ aggregation** (a cluster's `$SYS.REQ.SERVER.PING.CONNZ` fans out to every
  node and each replies separately): explicitly out of scope, deferred to the HA slice per
  `seed_presence_map`'s doc comment — this spike only exercises a single-helper-instance
  deployment, matching the current stack.
- **`account` field in CONNZ rows** (e.g. `"APP"`, `"AUTH"`, `"SYS"`): captured but unused by the
  current parser (identity resolution goes entirely through `authorized_user` → `nats_fp` →
  durable session record). Could be used as a cheap pre-filter (skip non-`APP` rows) but isn't
  needed for correctness given the existing session-record lookup already filters correctly.
- The pre-existing, **not** patched here (flagged by S1, out of scope for S5 too): the
  root-key-vs-op-key `host_fp` derivation divergence between `decide_device_connect` and
  `decide_host_connect`. This spike's fake host uses `root_seed == op_seed` (S1's documented
  workaround), same as S1 did, so this divergence never triggered during the run.
