//! FLIRT pattern matching against a byte buffer.
//!
//! Three-stage check per pattern: head pattern equality (with
//! wildcards), CRC-16/X-25 over the next `crc_len` bytes, and
//! optional tail pattern equality.
//!
//! 0.1 implementation walks every pattern in the set linearly per
//! call (`O(N * head_len)`). A trie-based bulk matcher keyed on the
//! significant byte positions is the obvious next step (issue
//! tracked in the repo); the [`FlirtSet::matches`] API stays the
//! same so callers don't move when the internals do.

use crate::crc16;
use crate::types::{FlirtSet, Pattern, PatternByte};

impl FlirtSet {
    /// Return every pattern whose head + CRC + tail all match the
    /// leading bytes of `function_bytes`.
    ///
    /// `function_bytes` should be at least the first ~256 bytes of
    /// the candidate function — enough to cover the longest tail
    /// pattern in the loaded corpus. Short buffers don't crash; they
    /// just produce no matches for patterns longer than the input.
    ///
    /// Uses the first-byte index built at construction time:
    /// candidates are restricted to patterns whose `leading[0]`
    /// equals `function_bytes[0]` plus the small set whose first
    /// position is a wildcard. Each candidate is then verified
    /// against the full three-stage check.
    pub fn matches<'a>(&'a self, function_bytes: &[u8]) -> Vec<&'a Pattern> {
        let mut out = Vec::new();
        self.for_each_candidate(function_bytes, |pat| {
            if pattern_matches(pat, function_bytes) {
                out.push(pat);
            }
        });
        out
    }

    /// Convenience: return only the first matching public name, if
    /// any. Mirrors how capa-rs's driver consumes the matcher —
    /// "is this function a known library function, and if so what's
    /// its name?". Short-circuits as soon as a match with a public
    /// name is found.
    pub fn match_public_name<'a>(&'a self, function_bytes: &[u8]) -> Option<&'a str> {
        // Manual loop instead of `for_each_candidate` so we can
        // early-return out of the closure.
        let first = *function_bytes.first()?;
        let bucket = &self.index.buckets[first as usize];
        for &i in bucket.iter().chain(self.index.wildcards.iter()) {
            let pat = &self.patterns[i as usize];
            if pattern_matches(pat, function_bytes)
                && let Some(name) = pat.public_name()
            {
                return Some(name);
            }
        }
        None
    }

    /// Walk every pattern that survives first-byte filtering. Internal
    /// helper for `matches()` and any future bulk-match callers.
    /// If the input is empty there are no candidates (FLIRT patterns
    /// always require ≥1 byte).
    #[inline]
    fn for_each_candidate<'a, F: FnMut(&'a Pattern)>(&'a self, function_bytes: &[u8], mut f: F) {
        let Some(&first) = function_bytes.first() else {
            return;
        };
        let bucket = &self.index.buckets[first as usize];
        for &i in bucket.iter().chain(self.index.wildcards.iter()) {
            f(&self.patterns[i as usize]);
        }
    }
}

/// Check a single pattern against the input. Returns `true` only if
/// every constraint (head, CRC window, optional `.pat` tail, optional
/// `.sig` discriminator bytes) agrees.
pub(crate) fn pattern_matches(pat: &Pattern, buf: &[u8]) -> bool {
    let head_len = pat.leading.len();
    let crc_len = pat.crc_len as usize;
    let tail_len = pat.tail.len();
    let contiguous_need = head_len + crc_len + tail_len;
    if buf.len() < contiguous_need {
        return false;
    }

    // Stage 1: head match. Position-by-position; wildcards match
    // anything, concrete bytes must equal.
    if !pattern_eq(&pat.leading, &buf[..head_len]) {
        return false;
    }

    // Stage 2: CRC window. The CRC is over the `crc_len` bytes
    // immediately following the head. `crc_len = 0` short-circuits
    // (FLIRT signatures with no CRC happen when the original
    // function was 16 bytes or fewer).
    if crc_len > 0 {
        let crc_buf = &buf[head_len..head_len + crc_len];
        if crc16(crc_buf) != pat.crc16 {
            return false;
        }
    }

    // Stage 3a: `.pat` contiguous tail (if present). Sits immediately
    // after the CRC window. Like the head, uses position-by-position
    // comparison with wildcards.
    if tail_len > 0 {
        let tail_start = head_len + crc_len;
        if !pattern_eq(&pat.tail, &buf[tail_start..tail_start + tail_len]) {
            return false;
        }
    }

    // Stage 3b: `.sig` discriminator bytes (if any). Each entry is a
    // function-relative offset + expected byte value. The buffer
    // must extend far enough to cover each offset.
    for &(off, want) in &pat.tail_bytes {
        let idx = off as usize;
        if idx >= buf.len() || buf[idx] != want {
            return false;
        }
    }
    true
}

/// Position-by-position comparison of a pattern against a byte
/// slice. `pat.len()` must equal `buf.len()` — caller ensures this.
#[inline]
fn pattern_eq(pat: &[PatternByte], buf: &[u8]) -> bool {
    debug_assert_eq!(pat.len(), buf.len());
    for (p, &b) in pat.iter().zip(buf.iter()) {
        if !p.matches(b) {
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
        // Public function with empty tail — simpler match path.
        let line = "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 __libm_flt_rounds ^000B fegetround";
        let patterns = pat::parse(line).unwrap();
        let p = &patterns[0];

        // Reconstruct a buffer that satisfies the head pattern,
        // produces the expected CRC over the next `crc_len` bytes,
        // and has no tail constraint. The head is the first 32
        // bytes; we synthesise the CRC window from zeros and patch
        // the stored CRC to match — we want to exercise the
        // matcher, not test our own CRC implementation here.
        let mut buf = Vec::with_capacity(64);
        for pb in &p.leading {
            buf.push(match pb {
                PatternByte::Byte(b) => *b,
                PatternByte::Wildcard => 0xAA,
            });
        }
        // Zero-filled CRC window. We hand-compute what its CRC
        // would be and stuff it into a clone of the pattern so the
        // comparison succeeds — this is the cleanest test of the
        // matcher orchestration.
        let crc_window = vec![0u8; p.crc_len as usize];
        buf.extend_from_slice(&crc_window);

        let mut p2 = p.clone();
        p2.crc16 = crate::crc16(&crc_window);
        p2.tail.clear();
        p2.tail_bytes.clear();

        assert!(pattern_matches(&p2, &buf));
    }

    /// A buffer that diverges from the head at one concrete-byte
    /// position must fail to match.
    #[test]
    fn rejects_head_mismatch() {
        let line = "55564883EC48488D6C24204889CE0F1002488D4D0048895548488D55100F1102 00 0000 0010 :0000 foo";
        let patterns = pat::parse(line).unwrap();
        let p = &patterns[0];
        // Head is 32 bytes; build a 32-byte buffer with the first
        // byte intentionally wrong (pattern wants 0x55, supply 0x56).
        let mut buf = vec![0u8; 32];
        buf[0] = 0x56;
        assert!(!pattern_matches(p, &buf));
    }

    /// A short buffer (less than the head requires) is treated as a
    /// non-match, not an error.
    #[test]
    fn short_buffer_no_match() {
        let line = "55564883EC48488D6C24204889CE0F1002488D4D0048895548488D55100F1102 00 0000 0010 :0000 foo";
        let patterns = pat::parse(line).unwrap();
        let p = &patterns[0];
        // Pattern needs 32 head bytes; 4 bytes can't possibly match.
        assert!(!pattern_matches(p, &[0x55; 4]));
    }

    /// Wildcards in the head should accept any byte at that position.
    #[test]
    fn wildcards_match_anything() {
        let line = "........4883EC48488D6C24204889CE0F1002488D4D0048895548488D55100F 00 0000 0010 :0000 foo";
        let patterns = pat::parse(line).unwrap();
        let p = &patterns[0];

        // Reconstruct a 32-byte buffer straight from the parsed
        // pattern: wildcards get an arbitrary sentinel byte (0xAA) so
        // we're actually testing that the matcher tolerates them.
        let buf: Vec<u8> = p
            .leading
            .iter()
            .map(|pb| match pb {
                PatternByte::Byte(b) => *b,
                PatternByte::Wildcard => 0xAA,
            })
            .collect();
        assert_eq!(buf.len(), 32);
        assert!(pattern_matches(p, &buf));
    }

    // -----------------------------------------------------------
    // Indexed-matcher tests — exercise the FlirtSet path that goes
    // through the first-byte bucket index instead of pattern_matches
    // directly.
    // -----------------------------------------------------------

    use crate::FlirtSet;

    /// Build a buffer that satisfies a pattern's head + zero-byte
    /// CRC window, and adjust the pattern's stored CRC + clear tails
    /// so the matcher accepts our synthetic input. Returns the
    /// `(FlirtSet, buf)` pair.
    fn synthesize_match(line: &str) -> (FlirtSet, Vec<u8>) {
        let mut patterns = pat::parse(line).unwrap();
        let p = &mut patterns[0];
        let mut buf: Vec<u8> = p
            .leading
            .iter()
            .map(|pb| match pb {
                PatternByte::Byte(b) => *b,
                PatternByte::Wildcard => 0xAA,
            })
            .collect();
        let crc_window = vec![0u8; p.crc_len as usize];
        buf.extend_from_slice(&crc_window);
        p.crc16 = crate::crc16(&crc_window);
        p.tail.clear();
        p.tail_bytes.clear();
        (FlirtSet::with_patterns(patterns), buf)
    }

    /// Concrete-first-byte pattern: should land in
    /// `index.buckets[0x55]` and be retrievable by `matches()` when
    /// the input starts with 0x55.
    #[test]
    fn indexed_matches_concrete_first_byte() {
        let (set, buf) = synthesize_match(
            "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 __libm_flt_rounds ^000B fegetround",
        );
        let hits = set.matches(&buf);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].public_name(), Some("__libm_flt_rounds"));
    }

    /// Wildcard-first-byte pattern: should land in `index.wildcards`
    /// and still be returned regardless of `buf[0]`.
    #[test]
    fn indexed_matches_wildcard_first_byte() {
        let (set, mut buf) = synthesize_match(
            "........4883EC48488D6C24204889CE0F1002488D4D0048895548488D55100F 00 0000 0010 :0000 fizz",
        );
        // First byte intentionally arbitrary — wildcard means any.
        buf[0] = 0xDE;
        let hits = set.matches(&buf);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].public_name(), Some("fizz"));
    }

    /// Input that doesn't match the indexed bucket and isn't in the
    /// wildcard set should return no candidates.
    #[test]
    fn indexed_returns_empty_on_first_byte_miss() {
        let (set, mut buf) = synthesize_match(
            "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 foo",
        );
        // Flip the first byte so the input now starts with 0xDE
        // instead of 0x55 — bucket lookup should miss entirely and
        // the wildcard fallback is empty.
        buf[0] = 0xDE;
        assert!(set.matches(&buf).is_empty());
    }

    /// `match_public_name` short-circuits on first hit — exercise it
    /// against the same fixture as `indexed_matches_concrete_first_byte`.
    #[test]
    fn match_public_name_via_index() {
        let (set, buf) = synthesize_match(
            "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 __libm_flt_rounds ^000B fegetround",
        );
        assert_eq!(set.match_public_name(&buf), Some("__libm_flt_rounds"));
    }

    /// Empty input → no candidates, no panic.
    #[test]
    fn match_empty_input() {
        let (set, _buf) = synthesize_match(
            "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 foo",
        );
        assert!(set.matches(&[]).is_empty());
        assert!(set.match_public_name(&[]).is_none());
    }
}
