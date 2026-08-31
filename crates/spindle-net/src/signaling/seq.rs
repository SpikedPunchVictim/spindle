//! [`SeqFloor`] — the per-`(sid, direction)` replay-window bookkeeping DESIGN.md §A7's `seq`
//! MUST-check needs a caller to maintain. `spindle_core::envelope::open` takes the current floor
//! as an input (`OpenParams::min_seq_exclusive`) and rejects an envelope that doesn't clear it, but
//! it does not itself remember anything between calls — durable state is explicitly the caller's
//! job (see that module's `OpenParams` doc comment). This type is that state, factored out so it
//! is unit-testable on its own, with no envelope/NATS/ICE machinery involved.
//!
//! # A documented, unresolved gap this type does not paper over
//!
//! `spikes/s2-signaling`'s RESULTS.md (Check 6) found that a genuinely reordered-but-never-before-
//! delivered `seq` and an exact retry are indistinguishable under strict per-direction
//! monotonicity: both look like "a seq less than or equal to the floor" to the receiver, and
//! `spindle_core::envelope::open` (by design, per DESIGN.md §A7) rejects both identically as
//! `EnvelopeError::ReplaySeq`. [`SeqFloor`] inherits that property exactly — advancing the floor
//! only on a successfully-opened envelope (never on a rejected one) is necessary but not
//! sufficient to fix it. DESIGN.md does not yet pick between the two resolutions RESULTS.md lists
//! (resend under a fresh `seq` on detected loss, or decouple candidate identity from `seq`
//! entirely); this crate does not resolve it either — flagged here again, at the real call site,
//! rather than only in a spike's throwaway report.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SeqFloor(Option<u64>);

impl SeqFloor {
    /// A fresh floor for a direction that has not yet accepted any envelope — matches
    /// `spindle_core::envelope::OpenParams::min_seq_exclusive: None`, "the first message of this
    /// direction, no floor yet".
    pub fn new() -> Self {
        Self(None)
    }

    /// The value to pass as `OpenParams::min_seq_exclusive` for the next envelope in this
    /// direction.
    pub fn min_seq_exclusive(&self) -> Option<u64> {
        self.0
    }

    /// Records a successfully-opened envelope's `seq` as the new floor. Callers MUST only call
    /// this after `spindle_core::envelope::open` has already accepted the envelope this `seq`
    /// belongs to — advancing the floor for a rejected envelope would let a genuine later retry at
    /// that same `seq` succeed once, then start silently rejecting every subsequent legitimate
    /// duplicate delivery as a replay, which is exactly the ambiguity this type's own doc comment
    /// (and RESULTS.md's Check 6) already flags as unresolved; advancing on a rejection would make
    /// the floor itself an unreliable record of what was actually accepted.
    pub fn advance(&mut self, seq: u64) {
        debug_assert!(
            self.0.is_none_or(|floor| seq > floor),
            "SeqFloor::advance called with a non-increasing seq (floor={:?}, seq={seq})",
            self.0
        );
        self.0 = Some(seq);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_with_no_floor() {
        let floor = SeqFloor::new();
        assert_eq!(floor.min_seq_exclusive(), None);
    }

    #[test]
    fn advance_sets_the_floor_to_the_given_seq() {
        let mut floor = SeqFloor::new();
        floor.advance(0);
        assert_eq!(floor.min_seq_exclusive(), Some(0));
    }

    #[test]
    fn advance_moves_the_floor_forward_across_multiple_calls() {
        let mut floor = SeqFloor::new();
        floor.advance(1);
        floor.advance(2);
        floor.advance(9);
        assert_eq!(floor.min_seq_exclusive(), Some(9));
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(SeqFloor::default(), SeqFloor::new());
    }

    #[test]
    #[should_panic(expected = "non-increasing")]
    fn advance_panics_on_a_repeated_seq() {
        let mut floor = SeqFloor::new();
        floor.advance(5);
        floor.advance(5);
    }

    #[test]
    #[should_panic(expected = "non-increasing")]
    fn advance_panics_on_a_seq_that_moves_backward() {
        let mut floor = SeqFloor::new();
        floor.advance(9);
        floor.advance(3);
    }
}
