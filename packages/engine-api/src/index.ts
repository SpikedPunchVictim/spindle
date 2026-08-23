// @spindle/engine-api — THE client-engine interface: sessions, VFS operations, transfers,
// presence, and security events (key-change walls, etc.). This is the single substitution
// point between UI and engine (DESIGN.md §A9c boundary rule 2): both apps/client/ui and
// apps/web import *only* @spindle/engine-api (lint-enforced) — never @spindle/engine-tauri or
// @spindle/engine-web directly — so UI code cannot tell which engine it is running on, keeping
// native and browser UX identical. The Tauri build wires in @spindle/engine-tauri; the web
// build wires in @spindle/engine-web. Not implemented yet — see IMPLEMENTATION_PLAN.md Stage 7.
