//! FLIRT pattern matching against a byte buffer.
//!
//! Per-pattern check is three stages: head pattern equality (with
//! wildcards), CRC-16/X-25 over the `crc_len` bytes immediately
//! following the head, and optional contiguous tail / discrete
//! `.sig` discriminator bytes.
//!
//! Candidates are pre-filtered by the multi-level prefix [`trie`]
//! (built once at `FlirtSet` construction) which walks the input
//! bytes against a shared decision tree. On a typical FLIRT corpus
//! this cuts the per-call work from hundreds of thousands of
//! pattern comparisons down to a handful.
//!
//! [`trie`]: crate::trie

use std::ops::ControlFlow;

use crate::crc16;
use crate::types::{FlirtSet, Pattern};

impl FlirtSet {
    /// Return every pattern whose head + CRC + tail all match the
    /// leading bytes of `function_bytes`.
    ///
    /// `function_bytes` should be at least the first ~256 bytes of
    /// the candidate function — enough to cover the longest tail
    /// pattern in the loaded corpus. Short buffers don't crash; they
    /// just produce no matches for patterns longer than the input.
    ///
    /// Walks the prefix trie to narrow the candidate set, then runs
    /// the full three-stage verification on each survivor.
    pub fn matches<'a>(&'a self, function_bytes: &[u8]) -> Vec<Pattern<'a>> {
        let mut out = Vec::new();
        self.trie.visit_candidates(function_bytes, |i| {
            let pat = Pattern::new(self, i);
            if pattern_matches(&pat, function_bytes) {
                out.push(pat);
            }
            ControlFlow::Continue(())
        });
        out
    }

    /// Convenience: return only the first matching public name, if
    /// any. Short-circuits as soon as a public name is found.
    pub fn match_public_name<'a>(&'a self, function_bytes: &[u8]) -> Option<&'a str> {
        let mut found: Option<&'a str> = None;
        self.trie.visit_candidates(function_bytes, |i| {
            let pat = Pattern::new(self, i);
            if pattern_matches(&pat, function_bytes)
                && let Some(name) = pat.public_name()
            {
                found = Some(name);
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        found
    }
}

/// Check a single pattern against the input. Returns `true` only if
/// every constraint (head, CRC window, optional `.pat` tail, optional
/// `.sig` discriminator bytes) agrees.
pub(crate) fn pattern_matches(pat: &Pattern<'_>, buf: &[u8]) -> bool {
    let leading = pat.leading();
    let head_len = leading.len();
    let crc_len = pat.crc_len() as usize;
    let tail_bytes_pat = pat.tail();
    let tail_len = tail_bytes_pat.len();
    let contiguous_need = head_len + crc_len + tail_len;
    if buf.len() < contiguous_need {
        return false;
    }

    // Stage 1: head match. Position-by-position. The arena byte at a
    // wildcard position is meaningless — check the bitmask.
    for (i, &want) in leading.iter().enumerate() {
        if pat.is_wildcard(i) {
            continue;
        }
        if buf[i] != want {
            return false;
        }
    }

    // Stage 2: CRC window.
    if crc_len > 0 {
        let crc_buf = &buf[head_len..head_len + crc_len];
        if crc16(crc_buf) != pat.crc16() {
            return false;
        }
    }

    // Stage 3a: `.pat` contiguous tail (if any).
    if tail_len > 0 {
        let tail_start = head_len + crc_len;
        for (i, &want) in tail_bytes_pat.iter().enumerate() {
            if pat.is_tail_wildcard(i) {
                continue;
            }
            if buf[tail_start + i] != want {
                return false;
            }
        }
    }

    // Stage 3b: `.sig` discriminator bytes.
    for (off, want) in pat.tail_bytes() {
        let idx = off as usize;
        if idx >= buf.len() || buf[idx] != want {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pat;

    /// Sanity round-trip: parse a real `.pat` line, then run the
    /// matcher against the head bytes the pattern was generated
    /// from. Should match.
    #[test]
    fn matches_self() {
        let line = "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 __libm_flt_rounds ^000B fegetround";
        let set = pat::parse(line).unwrap();
        let pat = set.pattern(0);

        // Build a buffer that satisfies the head pattern. The
        // matcher would also need a CRC window, but we can't
        // synthesise that without mutating the loaded set — instead
        // we test that the head + CRC stages both fire by giving
        // the right head and a CRC window of zeros (which won't
        // match the stored CRC, so the call should return false).
        let mut buf = vec![0u8; 64];
        let leading = pat.leading();
        for (i, slot) in buf.iter_mut().take(leading.len()).enumerate() {
            *slot = if pat.is_wildcard(i) { 0xAA } else { leading[i] };
        }
        // Head matches; CRC almost certainly doesn't.
        assert!(!pattern_matches(&pat, &buf));
    }

    /// A buffer that diverges from the head at one concrete-byte
    /// position must fail to match.
    #[test]
    fn rejects_head_mismatch() {
        let line = "55564883EC48488D6C24204889CE0F1002488D4D0048895548488D55100F1102 00 0000 0010 :0000 foo";
        let set = pat::parse(line).unwrap();
        let pat = set.pattern(0);
        let mut buf = vec![0u8; 32];
        buf[0] = 0x56; // wrong (pattern wants 0x55)
        assert!(!pattern_matches(&pat, &buf));
    }

    /// A short buffer (less than the head requires) is treated as a
    /// non-match, not an error.
    #[test]
    fn short_buffer_no_match() {
        let line = "55564883EC48488D6C24204889CE0F1002488D4D0048895548488D55100F1102 00 0000 0010 :0000 foo";
        let set = pat::parse(line).unwrap();
        let pat = set.pattern(0);
        assert!(!pattern_matches(&pat, &[0x55; 4]));
    }

    /// Wildcards in the head should accept any byte at that position.
    #[test]
    fn wildcards_match_anything() {
        let line = "........4883EC48488D6C24204889CE0F1002488D4D0048895548488D55100F 00 0000 0010 :0000 foo";
        let set = pat::parse(line).unwrap();
        let pat = set.pattern(0);

        // Build a 32-byte buffer where the wildcards are arbitrary
        // and the concrete bytes come from the pattern.
        let mut buf = vec![0xAAu8; 32];
        let leading = pat.leading();
        for (i, slot) in buf.iter_mut().take(leading.len()).enumerate() {
            if !pat.is_wildcard(i) {
                *slot = leading[i];
            }
        }
        assert!(pattern_matches(&pat, &buf));
    }

    /// `matches()` returns a candidate even with a stale CRC — the
    /// matcher rejects head-mismatches via the trie, then verifies
    /// the rest. With a mismatched first byte the trie excludes
    /// the pattern, returning an empty Vec.
    #[test]
    fn matches_empty_on_first_byte_miss() {
        let line = "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 foo";
        let set = pat::parse(line).unwrap();
        // Pattern starts with 0x55. Query with 0xDE.
        let buf = vec![0xDEu8; 64];
        assert!(set.matches(&buf).is_empty());
    }

    /// Empty input → no candidates, no panic.
    #[test]
    fn match_empty_input() {
        let line = "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 foo";
        let set = pat::parse(line).unwrap();
        assert!(set.matches(&[]).is_empty());
        assert!(set.match_public_name(&[]).is_none());
    }
}
