# apps/client

The Spindle **client** app: a Tauri 2 application wrapping `spindle-client-core`, giving native
(macOS/Windows/Linux) users the host list, browse/transfer UI, invite redemption, and device
management flows (A9). It shares its React UI code with `apps/web` via `@spindle/ui`, and both
reach the engine only through `@spindle/engine-api` — the client app wires in `@spindle/engine-tauri`
so the UI code cannot tell it isn't running against the web engine (A9c boundary rule 2).

This directory is a placeholder. `pnpm create tauri-app` (or `tauri init`) scaffolds the real
`src-tauri/` (Rust shell) and `ui/` (React client UI) at the stage named in
`IMPLEMENTATION_PLAN.md` (Stage 7 — client-core + Tauri apps init).

## Layout once initialized (per DESIGN.md §A9c)

- `src-tauri/` — a thin shell over `spindle-client-core` that exposes the engine API over IPC.
- `ui/` — React client UI: host list, browse, transfers, invites, device management.

## Key boundary rules

- **Key custody**: the identity root, device keys, and NATS connect keys never leave Rust
  (`keyring`/OS keystore). The UI receives only fingerprints and display state over IPC — never
  keys, seeds, or capabilities.
- **IPC-only admin**: all engine operations reach `spindle-client-core` through the typed IPC
  command surface exposed by `engine-tauri`; there is no other privileged surface.
- **Minimal capabilities**: the Tauri capability config declares no shell, no frontend fs access,
  and no remote content — only the enumerated IPC command list (see `docs/adr/ADR-009-repo-layout-toolchain.md`
  once written).
