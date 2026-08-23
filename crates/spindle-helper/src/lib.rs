//! `spindle-helper` — the broker-helper service: callout responder, presence, TURN credential
//! minting, the durable revocation store, and the admin-command verifier, backed by Postgres
//! (`sqlx`) (A3, A3b, A9b). Depends only on `spindle-core` and `spindle-proto` — per A9c
//! boundary rule 3 this crate MUST NEVER grow host or client logic (it holds no membership
//! data; see docs/DESIGN.md A2's zero-knowledge definition).

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
