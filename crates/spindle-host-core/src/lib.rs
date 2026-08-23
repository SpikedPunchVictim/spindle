//! `spindle-host-core` — the host library: members, invites, revocation, the VFS RPC server, and
//! owner live-operations (A4b, A8). Depends on `spindle-net` and `spindle-vfs` (and
//! transitively `spindle-core`, `spindle-proto`); per A9c boundary rule 3 nothing below
//! `apps/*/src-tauri` depends on `tauri` — the `apps/host` Tauri shell embeds this crate
//! in-process and exposes only a minimal, typed IPC command surface over it.

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
