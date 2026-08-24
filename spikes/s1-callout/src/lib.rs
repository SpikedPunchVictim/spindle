//! S1 spike shared code: hand-rolled NATS v2 JWT claim encoding (see [`natsjwt`]) and CBOR
//! fixture helpers shared between `src/bin/responder.rs` and `src/bin/s1_tests.rs`
//! (docs/SPIKES.md §S1). Spike-only — nothing here is meant to graduate into `spindle-helper`
//! as-is; see RESULTS.md for what a real NATS-wiring slice should keep vs. redo.

pub mod fixtures;
pub mod natsjwt;
