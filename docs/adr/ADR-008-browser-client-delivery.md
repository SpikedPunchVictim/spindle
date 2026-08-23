# ADR-008: Browser Client Delivery

## Status

Accepted

## Context

Spindle's threat model treats the registry operator as **untrusted for payloads, keys, and membership** (ADR-001
§A2 trust boundaries). Every other client-side trust decision in the system — pinned host roots, root-signed device
certificates, the E2E signaling envelope (ADR-004) — assumes the code running on the user's device is the code the
user intended to run. Native apps satisfy that assumption by construction: they are installed once, signed, and
updated through an explicit, user-visible channel.

The browser client breaks that assumption in one specific way: the web bundle would otherwise be **served by the
operator on every page load** — the exact party this model distrusts. Adversary **A2** (compromised or malicious
registry) already wants to MITM session setup and grant itself access (ADR-001 §A2); a malicious or compromised
operator serving the JS bundle directly could instead ship code that steals a device key or NATS token, or
exfiltrates files mid-transfer, which is also adversary **A4**'s goal (browser-side attacker with code execution in
the page) — except here the "browser-side attacker" would be the delivery channel itself (ADR-001 §A12 #40). No
cryptographic mechanism inside the running page can defend against a delivery channel that controls what code runs
in the first place; the defense has to live in how the bundle is built, signed, and verified **before** it executes.

## Decision

Spindle v1 adopts **hardened delivery** for the browser client (decided A10.20, DESIGN.md §A2, §A10.20):

### Reproducible builds

The web bundle is built so that independent parties can rebuild it from source and obtain byte-identical output.
This is the precondition for the signed-manifest and verification-extension mechanisms below to mean anything: a
signature over a non-reproducible build only attests "the operator's build machine produced this," not "this is the
published source."

### Release-key-signed manifest, release key ≠ operator key

A manifest listing the bundle's file hashes is signed by a dedicated **release signing key**, held offline and kept
strictly separate from the operator's admission key and every other operational credential (DESIGN.md §A9b; full
secrets-inventory treatment in ADR-007). This separation means compromising the registry's day-to-day operational
key surface (the admission key, helper DB credentials, TURN secret) does not, by itself, grant the ability to sign
a malicious manifest.

### Immutable versioned bundles with SRI pinning

Each published bundle version is immutable and content-addressed; Subresource Integrity (SRI) hashes pin every
asset the page loads, so a served bundle cannot silently substitute a different file for one already referenced by
the manifest.

### Companion verification extension

A companion **verification extension** (the Code-Verify pattern) independently fetches the published manifest,
recomputes the served bundle's hashes, and compares them — detecting a bundle that was tampered with in transit or
substituted by a malicious or coerced operator, without trusting the operator's own claim of integrity. This is the
mechanism that actually **detects** a divergence between what was published and what was served; the reproducible
build and signed manifest are what make that comparison meaningful.

### Stated residual risk

DESIGN.md is explicit that this does not eliminate first-load trust entirely: **a browser session without the
verification extension installed trusts the operator for code integrity on first load; native apps never do**
(DESIGN.md §A2). This ADR records that residual risk rather than papering over it — it is the honest boundary of
what browser delivery can achieve versus a natively installed, signed application.

### Browser crypto constraints (context, from A7)

The hardened-delivery pipeline delivers code that must itself run the same cryptographic primitives as the native
client. Browsers use **WebCrypto Ed25519/X25519**, available from Firefox 129+, Safari 17+, and Chrome 137+, with a
**`@noble/curves`** fallback for environments below that baseline; AES-GCM and HKDF are used natively via WebCrypto
in both paths (DESIGN.md §A7, ADR-004). This matters to delivery specifically because the fallback path is
additional bundled code that the reproducible-build and manifest pipeline must also cover — there is no separate,
unhardened distribution channel for the fallback crypto library.

### Delivery pipeline placement in the repository

The web app builds with **no Rust** in its own tree — a React UI over `@spindle/engine-web` — and the
hardened-delivery build pipeline (reproducible build, manifest generation, SRI) is a first-class part of that app's
build target (DESIGN.md §A9c, `apps/web/`). `just package` produces the hardened web bundle plus its manifest as one
of the repository's release artifacts, alongside the signed/notarized Tauri bundles, the helper container image, and
the `spindle-admin` npm tarball (DESIGN.md §A9c "Versioning & release").

### CI verification

Because the same monorepo CI matrix that runs the golden-vector cross-check (Rust ↔ TypeScript canonical encoding,
ADR-004) also builds the web app across the 3-OS matrix (DESIGN.md §A9b), a reproducibility regression — a build
that silently stops being byte-identical across runs — is structurally the kind of failure that discipline is
designed to surface early, even before spike S17's dedicated tamper-detection test runs. This ADR does not create a
new CI mechanism; it relies on the delivery-pipeline build already living inside `apps/web`'s standard `just build`
target being exercised by the same CI that exercises every other package.

## Consequences

### Positive

- The registry operator can no longer silently ship key-stealing or file-exfiltrating JavaScript to browser users
  without a detectable divergence from the published, reproducibly-built manifest (ADR-001 §A12 #40).
- Separating the release signing key from the operator's operational keys means the most common operator-side
  compromise scenarios (admission key theft, helper DB credential leak) do not automatically grant bundle-signing
  capability (ADR-007 secrets inventory).
- Immutable, SRI-pinned, versioned bundles remove an entire class of "swap the file after the fact" attacks that a
  mutable, unpinned deployment would be exposed to.
- The residual-risk statement is explicit and testable (S17), rather than an implied guarantee the design cannot
  actually make.

### Negative

- The verification extension is **not** built into the browser; a user who never installs it gets none of the
  detection benefit and is, on every page load, in exactly the trust position this ADR set out to avoid — trusting
  the operator for code integrity on first load (DESIGN.md §A2).
- Reproducible builds are an ongoing engineering discipline (pinned toolchains, deterministic bundling, no
  timestamp/path leakage into output) that must be maintained across every release, not a one-time property.
- The release key, held offline, becomes a single point of process friction for every web-client release; DESIGN.md
  does not state a lifetime or rotation policy for it (see ADR-007's secrets inventory), which this ADR does not
  resolve.
- Native apps have no equivalent first-load trust gap; the browser client is permanently the weaker-by-default
  delivery channel of the three frontends unless the extension is installed.

### Neutral

- The extension follows an established pattern (Code-Verify) rather than a novel mechanism, trading some design
  risk for adoption/discoverability risk (will users actually install it).
- This ADR governs *delivery integrity* only; it does not change the client's cryptographic trust model once the
  correct code is running — that is governed by ADR-003 (identity/capabilities) and ADR-004 (E2E envelope) exactly
  as for native clients.

## Alternatives Considered

From DESIGN.md §A11:

| Alternative | Verdict | Why |
|-------------|---------|-----|
| Operator-served web bundle, plain (no hardening) | Rejected (v0.8) | The operator could ship key-leaking JS with no detection mechanism at all; hardened delivery adopted instead (A10.20) |
| WASM Rust core for browser crypto | Rejected | WebCrypto + `@noble/curves` judged sufficient; avoids a second toolchain and an additional WASM supply-chain surface inside the hardened bundle |
| P-256 fallback cipher suite | Rejected (v0.6) | All target browsers ship Ed25519/X25519; a second suite is downgrade surface, and every additional code path is additional surface the delivery pipeline must also harden |

## Open items

None specific to this ADR. Every decision governing browser client delivery (A10.20) is marked `DECIDED` in
DESIGN.md §A10, not `[USER DECISION]` or `[DEFAULT]`.

## References

- `../DESIGN.md` §A2 (threat model — "Browser client code" paragraph), §A7 (browser crypto: WebCrypto/`@noble/curves`
  availability), §A9b (delivery — `just package` web-bundle artifact), §A9c (`apps/web` hardened-delivery build
  pipeline), §A10 row 20, §A11 (alternatives), §A12 row #40
- [ADR-001: Threat Model](./ADR-001-threat-model.md) — adversaries A2 and A4; §A12 row #40; "Browser client code"
  residual-risk statement reproduced in context
- [ADR-004: End-to-End Signaling Envelope](./ADR-004-e2e-signaling-envelope.md) — browser crypto paths
  (WebCrypto/`@noble/curves`) that the hardened bundle must also deliver intact
- [ADR-007: Registry Control Plane](./ADR-007-registry-control-plane.md) — secrets inventory, including the release
  signing key's separation from the operator admission key
- [ADR-009: Repository Layout & Toolchain](./ADR-009-repo-layout-toolchain.md) — `apps/web` placement, `just
  package` release artifacts
- `../SPIKES.md` S17 (hardened web delivery: reproducible build → signed manifest → verification extension detects a
  tampered bundle, in all three target browsers)
