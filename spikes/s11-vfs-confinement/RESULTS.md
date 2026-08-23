# S11 — VFS confinement results

Pass criterion (verbatim, `docs/DESIGN.md` §A13): automated negative tests all pass on
macOS/Windows/Linux. See `docs/SPIKES.md` (§S11) and `src/lib.rs` for the full test matrix.

Status: **Not run.** No results recorded yet — all cases below are `#[ignore]`d stubs in
`src/lib.rs`.

| Case | macOS | Windows | Linux | Notes |
|------|-------|---------|-------|-------|
| `..` traversal | | | | |
| Symlink escape | | | | |
| Hardlink bypasses exclusion | | | | |
| Overlapping share roots rejected at add-time | | | | |
| Case-fold collision == overwrite | | | | |
| Unicode NFD collision == overwrite | | | | |
| Exclusion bypass via alternate path | | | | |
| Upload outside granted subpath rejected | | | | |
| Overwrite without `delete` rejected | | | | |
| Windows reserved device name rejected | N/A | | N/A | |
| Windows 8.3 short-name alias | N/A | | N/A | |
| Windows Alternate Data Stream | N/A | | N/A | |
| Windows `\\?\` extended-length path | N/A | | N/A | |
| Rename / TOCTOU race aborts request | | | | |
