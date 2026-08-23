# apps/web

The Spindle **browser client**: a React UI over `@spindle/engine-web` (a pure-TypeScript engine
implementing the same wire contract as the Rust engine — no Rust, no WASM). Because the web
bundle would otherwise be served by the registry operator (a party the threat model distrusts,
per DESIGN.md §A2), this app ships with **hardened delivery** per `docs/adr/ADR-008-browser-client-delivery.md`
(once written): a reproducible build, a release-key-signed manifest (release key ≠ operator key),
immutable versioned bundles with SRI pinning, and a companion verification extension that checks
the served bundle against the published manifest (decided A10.20).

Like `apps/client`, this app imports **only** `@spindle/engine-api` (lint-enforced, A9c boundary
rule 2) so its UI code is identical to the native client's.

This is a placeholder scaffold; the real Vite + React build pipeline and hardened-delivery
tooling land at the stage named in `IMPLEMENTATION_PLAN.md` (Stage 8 — engine-web + apps/web +
hardened delivery).
