//! Overlapping share-root rejection (DESIGN.md §A4b: "no overlapping roots (rejected at add-time
//! by resolved real path *and* device+inode/file-id; re-checked at host start)"). Closes A12 #29
//! (overlapping share roots / hardlinks defeat exclusions).

use super::identity::file_identity;
use super::ConfineError;
use std::path::Path;

/// `true` when two candidate share roots overlap and the second add must be rejected: one's
/// canonicalized real path is a prefix of (or equal to) the other's, **or** — belt and suspenders
/// for alias cases a plain path comparison can miss (e.g. two distinct mount points exposing the
/// same underlying volume) — the two roots share a file identity.
pub fn overlap_check(root_a: &Path, root_b: &Path) -> Result<bool, ConfineError> {
    let real_a = std::fs::canonicalize(root_a)
        .map_err(|e| ConfineError::io(root_a.display().to_string(), e))?;
    let real_b = std::fs::canonicalize(root_b)
        .map_err(|e| ConfineError::io(root_b.display().to_string(), e))?;
    if real_a == real_b || real_a.starts_with(&real_b) || real_b.starts_with(&real_a) {
        return Ok(true);
    }
    let identity_a = file_identity(
        &std::fs::metadata(&real_a)
            .map_err(|e| ConfineError::io(real_a.display().to_string(), e))?,
    );
    let identity_b = file_identity(
        &std::fs::metadata(&real_b)
            .map_err(|e| ConfineError::io(real_b.display().to_string(), e))?,
    );
    Ok(identity_a == identity_b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn overlapping_roots_rejected() {
        let sandbox = tempdir().expect("tempdir");
        let a = sandbox.path().join("share-a");
        let nested = a.join("nested");
        let sibling = sandbox.path().join("share-b");
        std::fs::create_dir_all(&nested).expect("create nested dir");
        std::fs::create_dir(&sibling).expect("create sibling dir");

        assert!(
            overlap_check(&a, &a).expect("overlap_check(a, a)"),
            "a root must be reported as overlapping with itself"
        );
        assert!(
            overlap_check(&a, &nested).expect("overlap_check(a, nested)"),
            "a share root nested inside another must be reported as overlapping"
        );
        assert!(
            overlap_check(&nested, &a).expect("overlap_check(nested, a)"),
            "overlap must be detected regardless of argument order"
        );
        assert!(
            !overlap_check(&a, &sibling).expect("overlap_check(a, sibling)"),
            "two unrelated sibling roots must not be reported as overlapping"
        );
    }
}
