//! The single implementation of DESIGN.md's self-verifying-device-key-pair rule: `device_fp =
//! H(DEVICE_FP_DOMAIN, alg_id, sign_pk, agree_pk)` (DESIGN.md:225-227,
//! `spindle_core::identity::device_fp_of`). A stored [`spindle_vfs::model::Device`] row is only
//! as trustworthy as its own binding to that formula — a row whose `sign_pk`/`agree_pk` do not
//! rehash to its own `device_fp` (corruption, a transposed write, or keys copied from another
//! device) must never be treated as verified, no matter which caller is asking.
//!
//! Two callers in this crate need exactly this check: the connect path (`crate::authorize`'s
//! `HostConnectAuthorizer`, checks 6 through 9 of `authorize()`) and the per-request
//! upload-manifest path (`crate::server`'s `VfsRpcServer::verify_manifest_signature`). This module
//! exists because those two paths previously disagreed (td-ad318f): the connect path parsed the
//! stored keys and rehashed them against `device_fp` before trusting them, while the request path
//! parsed `sign_pk` alone and verified a manifest signature under it without ever checking that
//! `sign_pk` actually belongs to the row's `device_fp` — a stored-but-unbound key would silently
//! verify a manifest signature it should not be trusted to verify. Factoring the rehash-and-bind
//! logic out to one place, shared by both callers, makes that kind of drift a compile-time
//! impossibility rather than something a future reviewer has to notice twice.
//!
//! This module deliberately knows nothing about either caller's *policy* for what to do with a
//! failure. In particular it must never reference `crate::authorize`'s
//! `deny_with_equalized_work` — the connect path's timing-equalization behavior for a denied
//! connect offer is that module's concern, not this one's. This module hands back a plain
//! [`Result`]; the call site decides how to act on it (including, on the connect path, how long
//! to spend acting on it).

use spindle_core::identity::device_fp_of;
use spindle_core::{Fingerprint, VerifyingKey, X25519PublicKey, ALG_ID_V1};
use spindle_vfs::model::Device;

/// A device's two public key halves, once both have been parsed and proven to be the exact
/// preimage of the row's own `device_fp` (see the module doc comment). Everything a caller needs
/// to verify a signature or derive a shared secret against this device, and nothing else.
pub(crate) struct CheckedDeviceKeys {
    pub(crate) sign_pk: VerifyingKey,
    pub(crate) agree_pk: X25519PublicKey,
}

/// Why [`checked_device_keys`] could not hand back a [`CheckedDeviceKeys`].
///
/// The two variants are not interchangeable and a caller must match on both explicitly rather
/// than collapsing to `Err(_)`: the connect path's timing-equalization policy treats them
/// differently (see `crate::authorize`'s `deny_with_equalized_work` call sites and the comment on
/// why the final binding check is deliberately left un-equalized), because the two variants reach
/// their `Err` after paying different amounts of real work. Merging them would erase the
/// distinction the call site depends on.
#[derive(Debug)]
pub(crate) enum DeviceKeyError {
    /// This device's row cannot be verified at all: a key is missing, a key fails to parse (wrong
    /// length, or — for the Ed25519 half — not a valid curve point), or `alg_id` is missing or
    /// names anything other than `ALG_ID_V1`. A missing or unrecognized `alg_id` is folded into
    /// this same variant rather than treated as "skip the check": `sign_pk`/`agree_pk` are parsed
    /// as Ed25519/X25519 unconditionally, which is the only parse this codebase knows how to do,
    /// so a row naming (or missing) an algorithm this parse cannot actually speak for is exactly
    /// as unverifiable as a row with no keys at all. Hashing that `alg_id` into `device_fp_of`
    /// anyway would manufacture a hash that happens to match a row nobody can actually verify —
    /// strictly worse than refusing to check it.
    Unverifiable,
    /// Both keys parsed cleanly and `alg_id` names `ALG_ID_V1`, but rehashing
    /// `device_fp_of(alg_id, sign_pk, agree_pk)` from the row's own fields does not reproduce the
    /// row's own `device_fp`. This is what makes the stored key pair *self-verifying* (DESIGN.md
    /// §A7b clarification-6): a row whose keys were corrupted, transposed, or swapped for another
    /// device's cannot silently pass, because it simply fails to rehash to its own fingerprint.
    BindingMismatch,
}

/// Parses a device row's stored `sign_pk`/`agree_pk` and proves they are the exact preimage of
/// `device_fp` under `device_fp_of` (DESIGN.md:225-227) before handing them back to a caller.
///
/// Fails closed at every step — a missing key, an unparseable key, a missing or non-v1 `alg_id`,
/// or a fingerprint mismatch are all refusals, never a "skip this part of the check". See
/// [`DeviceKeyError`]'s doc comment for why its two variants must be matched exhaustively rather
/// than collapsed.
pub(crate) fn checked_device_keys(
    device: &Device,
    device_fp: &Fingerprint,
) -> Result<CheckedDeviceKeys, DeviceKeyError> {
    // Either key is missing on file. Fail closed; a missing key is never "skip the check".
    let (Some(sign_pk_bytes), Some(agree_pk_bytes)) = (&device.sign_pk, &device.agree_pk) else {
        return Err(DeviceKeyError::Unverifiable);
    };

    // Either key fails to parse (wrong length, or — for the Ed25519 sign key — not a valid curve
    // point).
    let Ok(sign_pk_arr): Result<[u8; 32], _> = sign_pk_bytes.as_slice().try_into() else {
        return Err(DeviceKeyError::Unverifiable);
    };
    let Some(sign_pk) = spindle_core::checked_verifying_key(&sign_pk_arr) else {
        return Err(DeviceKeyError::Unverifiable);
    };
    let Ok(agree_pk_arr): Result<[u8; 32], _> = agree_pk_bytes.as_slice().try_into() else {
        return Err(DeviceKeyError::Unverifiable);
    };
    let agree_pk = X25519PublicKey::from(agree_pk_arr);

    // The stored `alg_id` is missing, or names anything other than `ALG_ID_V1` (td-6c01e3:
    // `devices.alg_id`, DESIGN.md:225-227's `device_fp = H(DEVICE_FP_DOMAIN, alg_id, sign_pk,
    // agree_pk)`). `sign_pk`/`agree_pk` were just parsed above as Ed25519/X25519 unconditionally
    // — that parsing is what pins the algorithm, not this integer — so a row whose `alg_id` is
    // `None` (a row with keys but no algorithm — impossible after the SCHEMA_V9 backfill, but
    // this codebase's house style never unwraps an invariant instead of failing closed) or names
    // something other than v1 cannot be verified by this code path at all. Hashing that `alg_id`
    // into `device_fp_of` anyway would manufacture a hash that matches for a row nobody can
    // actually verify; refusing is the only sound answer.
    //
    // Written as an explicit bind-then-compare rather than `let Some(ALG_ID_V1) = device.alg_id
    // else { ... }`. That form type-checks today only because `ALG_ID_V1` happens to resolve to
    // an in-scope `const` in SCREAMING_SNAKE_CASE, which is a lexical convention Rust's pattern
    // matching leans on but does not enforce — nothing about the type system requires it. A
    // future rename away from that convention, or a local shadowing binding named `ALG_ID_V1`,
    // would silently turn `Some(ALG_ID_V1)` from a refutable constant pattern into an irrefutable
    // *binding* pattern that accepts every `Some(_)` — and it would still compile, because the
    // name is used again on the next lines (as the now-shadowed binding, not the constant). That
    // failure mode is silent and would not show up as a type or lint error, only as this check
    // quietly accepting every alg_id. Binding the value under its own name and comparing with
    // `!=` cannot be reinterpreted that way: renaming or shadowing `ALG_ID_V1` would break the
    // `!=` comparison at compile time (or, at worst, compare against the wrong but still-explicit
    // value), never silently widen this into a no-op check.
    let Some(alg_id) = device.alg_id else {
        return Err(DeviceKeyError::Unverifiable);
    };
    if alg_id != ALG_ID_V1 {
        return Err(DeviceKeyError::Unverifiable);
    }

    // The binding does not hold (DESIGN.md §A7b clarification-6 — the same check
    // `verify_device_certificate` performs). This is what makes the stored key pair
    // *self-verifying*: `device_fp` is the hash of exactly `(DEVICE_FP_DOMAIN, alg_id, sign_pk,
    // agree_pk)`, so a row whose keys were corrupted, transposed, or swapped for another device's
    // cannot silently authorize — it simply fails to rehash to `device_fp`.
    //
    // Uses `alg_id` (the value just read from and validated against this row), not a hardcoded
    // `ALG_ID_V1` constant — the check above already proved they're equal for this row, but
    // recomputing the hash from the row's own field, rather than a compile-time constant, is what
    // makes this the actual device_fp recompute td-6c01e3 requires: a future second algorithm
    // added as another `Some(alg_id) if alg_id != ALG_ID_V1` arm above would still rehash
    // correctly here without this line needing to change at all.
    if device_fp_of(alg_id, &sign_pk, &agree_pk) != *device_fp {
        return Err(DeviceKeyError::BindingMismatch);
    }

    Ok(CheckedDeviceKeys { sign_pk, agree_pk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::identity::DeviceKey;

    /// Builds a `Device` row whose stored `device_fp` is genuinely `device_fp_of(alg_id, sign_pk,
    /// agree_pk)` for the given keys — the row is internally self-consistent, exactly like a row
    /// a real enrollment path would write.
    fn self_consistent_device(alg_id: u8, sign: &DeviceKey, agree: &DeviceKey) -> Device {
        let sign_pk = sign.sign_public_key();
        let agree_pk = agree.agree_public_key();
        let device_fp = device_fp_of(alg_id, &sign_pk, &agree_pk);
        Device {
            device_fp,
            label: "laptop".to_string(),
            added: 0,
            revoked: false,
            sign_pk: Some(sign_pk.as_bytes().to_vec()),
            agree_pk: Some(agree_pk.as_bytes().to_vec()),
            alg_id: Some(alg_id),
        }
    }

    #[test]
    fn well_formed_device_that_genuinely_rehashes_returns_ok_with_the_original_keys() {
        let dev = DeviceKey::from_seeds([0x01; 32], [0x02; 32]);
        let device = self_consistent_device(ALG_ID_V1, &dev, &dev);

        let checked = checked_device_keys(&device, &device.device_fp).expect("should verify");
        assert_eq!(checked.sign_pk, dev.sign_public_key());
        assert_eq!(checked.agree_pk, dev.agree_public_key());
    }

    #[test]
    fn missing_sign_pk_is_unverifiable() {
        let dev = DeviceKey::from_seeds([0x03; 32], [0x04; 32]);
        let mut device = self_consistent_device(ALG_ID_V1, &dev, &dev);
        device.sign_pk = None;

        match checked_device_keys(&device, &device.device_fp) {
            Err(DeviceKeyError::Unverifiable) => {}
            Err(DeviceKeyError::BindingMismatch) => {
                panic!("expected Unverifiable, not a binding mismatch — there is no key to bind")
            }
            Ok(_) => panic!("a device with no sign_pk must never verify"),
        }
    }

    #[test]
    fn missing_agree_pk_is_unverifiable() {
        let dev = DeviceKey::from_seeds([0x05; 32], [0x06; 32]);
        let mut device = self_consistent_device(ALG_ID_V1, &dev, &dev);
        device.agree_pk = None;

        match checked_device_keys(&device, &device.device_fp) {
            Err(DeviceKeyError::Unverifiable) => {}
            Err(DeviceKeyError::BindingMismatch) => {
                panic!("expected Unverifiable, not a binding mismatch — there is no key to bind")
            }
            Ok(_) => panic!("a device with no agree_pk must never verify"),
        }
    }

    #[test]
    fn missing_alg_id_is_unverifiable() {
        let dev = DeviceKey::from_seeds([0x07; 32], [0x08; 32]);
        let mut device = self_consistent_device(ALG_ID_V1, &dev, &dev);
        device.alg_id = None;

        match checked_device_keys(&device, &device.device_fp) {
            Err(DeviceKeyError::Unverifiable) => {}
            Err(DeviceKeyError::BindingMismatch) => panic!(
                "expected Unverifiable, not a binding mismatch — a row with no alg_id cannot be \
                 verified at all, so the rehash must never even run"
            ),
            Ok(_) => panic!("a device with no alg_id must never verify"),
        }
    }

    #[test]
    fn non_v1_alg_id_is_unverifiable_even_though_the_row_rehashes_under_it() {
        // Build the row so it is self-consistent under alg_id = 2 (device_fp genuinely equals
        // device_fp_of(2, sign_pk, agree_pk)) — proving the alg_id gate rejects BEFORE the rehash
        // gets a chance to manufacture a match. A row that fails to rehash under alg 2 would
        // prove nothing about the alg_id gate itself, since BindingMismatch would fire regardless
        // of whether the gate existed.
        let dev = DeviceKey::from_seeds([0x09; 32], [0x0a; 32]);
        let device = self_consistent_device(2, &dev, &dev);

        match checked_device_keys(&device, &device.device_fp) {
            Err(DeviceKeyError::Unverifiable) => {}
            Err(DeviceKeyError::BindingMismatch) => panic!(
                "expected Unverifiable: alg_id = 2 must be rejected before the rehash runs, not \
                 after it happens to fail"
            ),
            Ok(_) => panic!(
                "alg_id = 2 names an algorithm sign_pk/agree_pk are not parsed as — this must \
                 never verify even though device_fp genuinely commits to alg 2"
            ),
        }
    }

    #[test]
    fn wrong_length_sign_pk_is_unverifiable() {
        let dev = DeviceKey::from_seeds([0x0b; 32], [0x0c; 32]);
        let mut device = self_consistent_device(ALG_ID_V1, &dev, &dev);
        device.sign_pk = Some(vec![0x11; 31]);

        match checked_device_keys(&device, &device.device_fp) {
            Err(DeviceKeyError::Unverifiable) => {}
            Err(DeviceKeyError::BindingMismatch) => panic!(
                "expected Unverifiable — the key fails to parse before any rehash is possible"
            ),
            Ok(_) => panic!("a 31-byte sign_pk must never verify"),
        }
    }

    #[test]
    fn sign_pk_of_correct_length_but_not_a_valid_curve_point_is_unverifiable() {
        let dev = DeviceKey::from_seeds([0x0d; 32], [0x0e; 32]);
        let mut device = self_consistent_device(ALG_ID_V1, &dev, &dev);
        // 32 bytes, but not a valid compressed Ed25519 point: the high (sign) byte's low 7 bits
        // encode a `y` for which no valid curve point decompresses (verified empirically against
        // this workspace's pinned `ed25519-dalek` version — not every all-0xNN byte string fails
        // to decompress, so this exact pattern is load-bearing, not an arbitrary placeholder).
        let mut bad_sign_pk = [0u8; 32];
        bad_sign_pk[31] = 0xa9;
        device.sign_pk = Some(bad_sign_pk.to_vec());

        match checked_device_keys(&device, &device.device_fp) {
            Err(DeviceKeyError::Unverifiable) => {}
            Err(DeviceKeyError::BindingMismatch) => panic!(
                "expected Unverifiable — the key fails to parse before any rehash is possible"
            ),
            Ok(_) => panic!("an invalid Ed25519 curve point must never verify"),
        }
    }

    #[test]
    fn keys_that_parse_but_do_not_rehash_to_device_fp_are_a_binding_mismatch() {
        let dev = DeviceKey::from_seeds([0x0f; 32], [0x10; 32]);
        let mut device = self_consistent_device(ALG_ID_V1, &dev, &dev);
        // Corrupt device_fp so it no longer matches what the stored keys rehash to. Both keys
        // parse cleanly and alg_id is valid, so this must reach the rehash comparison and fail
        // there specifically.
        let other = Fingerprint::of_parts(&[b"a-different-device-fp-entirely"]);
        assert_ne!(other, device.device_fp, "sanity: must actually differ");
        device.device_fp = other;

        match checked_device_keys(&device, &device.device_fp) {
            Err(DeviceKeyError::BindingMismatch) => {}
            Err(DeviceKeyError::Unverifiable) => panic!(
                "expected BindingMismatch: both keys parse and alg_id is valid, so this must \
                 fail at the rehash comparison, not earlier"
            ),
            Ok(_) => panic!("a device_fp that does not match its own keys must never verify"),
        }
    }

    #[test]
    fn transposed_sign_and_agree_keys_do_not_verify() {
        // Two distinct devices; store device A's agree key in the sign_pk slot and device A's
        // sign key in the agree_pk slot (a transposition), next to device A's own device_fp.
        let a = DeviceKey::from_seeds([0x20; 32], [0x21; 32]);
        let b = DeviceKey::from_seeds([0x22; 32], [0x23; 32]);
        let mut device = self_consistent_device(ALG_ID_V1, &a, &a);
        device.sign_pk = Some(b.agree_public_key().as_bytes().to_vec());
        device.agree_pk = Some(b.sign_public_key().as_bytes().to_vec());

        // `X25519PublicKey::from` is infallible (any 32 bytes are a valid Montgomery u-coordinate
        // candidate), so the agree_pk half always parses. Whether the sign_pk half (an X25519
        // point reinterpreted as an Ed25519 compressed point) happens to decompress is not
        // guaranteed either way — so this lands in either `Unverifiable` (sign_pk fails to parse
        // as a curve point) or `BindingMismatch` (it parses, but the rehash of these swapped keys
        // does not reproduce device A's device_fp). Either way, `Ok` must never happen.
        match checked_device_keys(&device, &device.device_fp) {
            Err(DeviceKeyError::Unverifiable) | Err(DeviceKeyError::BindingMismatch) => {}
            Ok(_) => panic!("transposed sign_pk/agree_pk must never verify"),
        }
    }
}
