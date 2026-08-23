//! `spindle-client-core` — the client library: sessions, the pinning store, the transfer queue,
//! and key custody. Depends on `spindle-net` and `spindle-vfs` (and transitively
//! `spindle-core`, `spindle-proto`); per A9c boundary rule 3 nothing below `apps/*/src-tauri`
//! depends on `tauri` — the `apps/client` Tauri shell is a thin IPC layer over this crate, and
//! private key material never leaves it (keys/seeds/caps are never sent over IPC).

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
