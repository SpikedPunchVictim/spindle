// @spindle/engine-tauri — the @spindle/engine-api interface implemented as a thin adapter over
// Tauri IPC (@tauri-apps/api), calling into the Rust engine (spindle-client-core) that runs
// in-process inside apps/client's src-tauri shell. Never handles key material directly — it
// only relays typed IPC commands and receives fingerprints/display state. Not implemented yet —
// see IMPLEMENTATION_PLAN.md Stage 7.
