# apps/host

The Spindle **host** app: a single Tauri 2 tray application (decided A10.26) that runs
`spindle-host-core` in-process as the daemon. The tray is always on; an admin window opens on
demand for Shares, People, Groups, Preview-as, Sessions, and Audit (A4b, A9). There is
deliberately **no localhost admin port** — the only administration surface is the tray app's own
IPC-bound UI (A10.11: owner-only, local-UI-only in v1).

This directory is a placeholder. `pnpm create tauri-app` (or `tauri init`) scaffolds the real
`src-tauri/` (Rust shell) and `ui/` (React admin UI) at the stage named in
`IMPLEMENTATION_PLAN.md` (Stage 7 — client-core + Tauri apps init).

## Layout once initialized (per DESIGN.md §A9c)

- `src-tauri/` — tray, autostart, updater, and a minimal typed set of IPC commands that call into
  `spindle-host-core`. No shell access, no frontend filesystem access, no remote content.
- `ui/` — React admin UI: Shares · People · Groups · Preview-as · Sessions · Audit.

## Key boundary rules

- **Key custody**: the host identity root and operating key never leave Rust (`keyring`/OS
  keystore). The UI receives only fingerprints and display state over IPC.
- **IPC-only admin**: every admin action is a typed Tauri command into `spindle-host-core`; there
  is no HTTP admin API, no localhost port, and no remote admin surface in v1.
- **Minimal capabilities**: the Tauri capability config declares no shell, no frontend fs access,
  and no remote content — only the enumerated IPC command list (see `docs/adr/ADR-009-repo-layout-toolchain.md`
  once written).
