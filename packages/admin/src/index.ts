// @spindle/admin — owns the registry control-plane protocol (A3b): operator admin-command
// signing (same envelope discipline as A7: nonce, ts, canonical CBOR), admission-invite
// minting, a pluggable Signer interface (file key / OS keychain / hardware token / WebCrypto),
// and the NATS connection logic for registry.admin.>. The v1 client (spindle-admin, in
// packages/admin-cli) is a thin CLI over this library; any future admin interface builds on it
// and owns its own transport security. Not implemented yet — see IMPLEMENTATION_PLAN.md Stage 9.
