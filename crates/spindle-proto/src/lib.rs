//! `spindle-proto` — wire types and canonical CBOR encoding (RFC 8949 §4.2.1) shared by every
//! Spindle component, including the A7b signed-artifact domain-separation tags. This crate is
//! the bottom of the Rust dependency chain (`proto ← core ← {net, vfs} ← {host-core,
//! client-core}`) and per A9c boundary rule 3 it MUST NOT take a crypto dependency — signing and
//! verification belong to `spindle-core`.

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
