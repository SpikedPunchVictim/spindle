# spikes/

Spikes are evidence-before-code experiments (docs/DESIGN.md §A13): small, throwaway programs
that answer one risky question (throughput, VFS confinement, NAT traversal, ...) with a measured
pass/fail criterion before the corresponding production code or ADR is accepted.

Each spike is a Rust crate and a **cargo workspace member**, added explicitly by name to the root
`Cargo.toml`'s `[workspace] members` list as it's created (not matched by a glob — see the
comment there for why).

Spikes are **deletable** once their question is answered and their negative-test suite (where
applicable) has graduated into permanent CI — they are not meant to live forever.
