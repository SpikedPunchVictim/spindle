# Vendored `rtc-turn` — spindle patch

Source: crates.io `rtc-turn` 0.20.3 (`checksum 449365ff…`), copied verbatim except for the
patch described below.

## Why

`rtc-turn` 0.20.3 cannot recover from a `438 Stale nonce` on `ChannelBind`
(td-67f0c5, found by the 660 s forced-relay proof):

- `handle_channel_bind_response` updates the nonce **and deletes the binding**.
- The next `send_to` calls `BindingManager::create`, which allocates a **new channel number**
  for the same peer.
- coturn still holds the old channel and answers `400 same peer, different channel number`;
  the handler deletes the binding again.
- Inbound ChannelData for the old channel now fails `ErrChannelBindNotFound`, which the
  `spindle-net` adapter logs as "dropping malformed TURN packet". Data never resumes.

No public API can fix this from outside: `BindingManager` is `pub(crate)` and `Relay` exposes
only `create_permission`, `send_to`, and `close`. Checked 0.21.1's source: the same delete
remains, so upgrading does not fix it either.

## Patch

`src/client/relay.rs`, `handle_channel_bind_response`: on a failed bind, keep the binding.

- `438 Stale nonce` → state `Idle`; the updated nonce is used to re-bind the **same channel
  number** on the next send.
- Any other error → state `Failed`; the send path uses Send Indications, so data keeps flowing
  and the bind is not retried in a spin.

## Maintenance

Drop this fork when upstream ships the fix (and verify the regression test in
`crates/spindle-net/src/signaling/turn.rs` still passes against the released crate). The test
forces the 438 on the first bind; the periodic refresh path enters the same state-independent
handler but is not driven by a test. Upstream: <https://github.com/webrtc-rs/rtc>.

License: MIT/Apache-2.0, per the crate manifest.
