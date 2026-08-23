//! `spindle-net` — NATS client and Auth Callout credential presentation, WebRTC (`webrtc` crate,
//! trickle ICE), and the client-side transfer manager (A8). Depends on `spindle-core` (and
//! transitively `spindle-proto`); per A9c boundary rule 3 nothing below `apps/*/src-tauri`
//! depends on `tauri`, and this crate sits below `spindle-host-core` and `spindle-client-core`
//! in the dependency chain (`proto ← core ← {net, vfs} ← {host-core, client-core}`).

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() {
        assert!(true);
    }
}
