//! `spindle-core` — identity (identity roots, device certs), capabilities, the end-to-end
//! signaling envelope (A7), and signed artifacts generally (A7b). Depends only on
//! `spindle-proto` for wire types; per A9c boundary rule 3 nothing below `apps/*/src-tauri`
//! depends on `tauri`, and this crate sits below both `spindle-net` and `spindle-vfs` in the
//! dependency chain (`proto ← core ← {net, vfs} ← {host-core, client-core}`).

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
