//! Core data model for FLIRT signatures.
//!
//! Patterns are held as owned `Vec<PatternByte>` rather than a
//! mask + byte-array — cleaner per-position branching for the trie
//! matcher and `Send + Sync` semantics without any `unsafe`.

use smallvec::SmallVec;

/// One position in a FLIRT pattern: either a specific byte or a
/// wildcard (`..` in `.pat`, the mask bit clear in `.sig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternByte {
    Byte(u8),
    Wildcard,
}

impl PatternByte {
    /// Returns `true` if this position matches `b`. Wildcards match
    /// everything.
    #[inline]
    pub fn matches(self, b: u8) -> bool {
        match self {
            PatternByte::Byte(p) => p == b,
            PatternByte::Wildcard => true,
        }
    }

    /// Returns the concrete byte if this isn't a wildcard. Used by
    /// the trie matcher to key branches on significant positions.
    #[inline]
    pub fn as_byte(self) -> Option<u8> {
        match self {
            PatternByte::Byte(b) => Some(b),
            PatternByte::Wildcard => None,
        }
    }
}

/// A named entity attached to a FLIRT pattern. The `offset` is the
/// byte position within the matched function where the name applies
/// (FLAIR records this so disassemblers can label internal labels,
/// not just the function entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub offset: i64,
    pub name: String,
}

/// FLIRT name tag.
///
/// - `Public`: the canonical name exposed to the user.
/// - `Local`: an internal label inside the function body (e.g. loop
///   entry, jump target). Disambiguation only — usually not surfaced.
/// - `Reference`: name of a callee referenced from inside the matched
///   pattern; used by the recursive disambiguation pass (not yet
///   implemented in fast-flirt 0.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Symbol {
    Public(Name),
    Local(Name),
    Reference(Name),
}

impl Symbol {
    /// Borrow the inner `Name` regardless of variant.
    pub fn name(&self) -> &Name {
        match self {
            Symbol::Public(n) | Symbol::Local(n) | Symbol::Reference(n) => n,
        }
    }
}

/// One FLIRT signature. A `.pat` line or one entry in the `.sig`
/// binary trie maps to one of these.
///
/// Matching proceeds in stages:
/// 1. The first 32 bytes of input must agree with `leading` at every
///    non-wildcard position.
/// 2. The next `crc_len` bytes (with all-wildcard positions short-
///    circuiting `crc_len = 0`) must produce `crc16` under the FLIRT
///    polynomial.
/// 3. Optionally, the bytes after that must agree with `tail` (used
///    when head + CRC collide between multiple signatures — the
///    `.pat` form, a contiguous trailing pattern).
/// 4. Optionally, every `(offset, value)` in `tail_bytes` must agree
///    byte-for-byte (the `.sig` form — discrete discriminator bytes
///    at function-relative offsets).
///
/// `.pat` patterns populate `tail`; `.sig` patterns populate
/// `tail_bytes`. Both default to empty and are zero-cost when unused.
///
/// `module_len` is the total length the original library function had
/// — informational; matching never reads more than what the
/// constraints above require.
///
/// **Equality**: the derived `PartialEq` compares `names` as an ordered
/// sequence, not a set. Two patterns with the same names in different
/// order compare unequal. This is intentional — name ordering is
/// preserved from the source `.pat` / `.sig` and is part of the
/// pattern's identity — but if you're using `Pattern` as a `HashSet`
/// key for de-duplication, normalise the names first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub leading: Vec<PatternByte>,
    pub crc_len: u8,
    pub crc16: u16,
    pub module_len: u32,
    /// Per-pattern named labels. SmallVec because the typical pattern
    /// has 1 name; some have 2-3; very rarely more.
    pub names: SmallVec<[Symbol; 2]>,
    /// `.pat`-style contiguous trailing pattern. Empty for `.sig`
    /// patterns and for `.pat` lines with no tail.
    pub tail: Vec<PatternByte>,
    /// `.sig`-style discriminator bytes — `(function_offset, value)`
    /// pairs that must match exactly. The offset is relative to the
    /// start of the function (i.e. position 0 = first byte of
    /// `leading`).
    pub tail_bytes: Vec<(u32, u8)>,
}

impl Pattern {
    /// Convenience: returns the first `Public` name on this pattern,
    /// or `None` if none exists (rare — usually the disassembler-
    /// facing entry point name).
    pub fn public_name(&self) -> Option<&str> {
        self.names.iter().find_map(|s| match s {
            Symbol::Public(n) => Some(n.name.as_str()),
            _ => None,
        })
    }

    /// Total bytes this pattern checks against input (leading + CRC
    /// window + max(tail, highest tail_byte offset + 1)). Useful as
    /// the lower-bound on how many bytes the caller needs to feed
    /// the matcher.
    pub fn min_input_len(&self) -> usize {
        let contiguous = self.leading.len() + self.crc_len as usize + self.tail.len();
        let discrete = self
            .tail_bytes
            .iter()
            .map(|(off, _)| *off as usize + 1)
            .max()
            .unwrap_or(0);
        contiguous.max(discrete)
    }
}

/// A loaded corpus of FLIRT signatures. Construct via the `pat::parse`
/// or `sig::parse` module entry points; query via [`FlirtSet::matches`].
///
/// `FlirtSet` owns its patterns (the underlying data, after .sig
/// inflation, is parsed once at load and lives for the lifetime of
/// the set). The matcher itself never allocates and never mutates
/// state, so a single `&FlirtSet` can be shared across rayon workers
/// without `Mutex` or `Arc`.
///
/// At construction time the set builds a small first-byte index: a
/// 256-way bucket of pattern indices keyed on `leading[0]` (plus a
/// fallback bucket for patterns whose first position is a wildcard).
/// `matches()` consults a single bucket per call instead of scanning
/// the whole corpus, dropping per-call work from O(N · head_len) to
/// O((|bucket| + |wildcards|) · head_len).
#[derive(Debug, Clone, Default)]
pub struct FlirtSet {
    pub(crate) patterns: Vec<Pattern>,
    pub(crate) index: FirstByteIndex,
}

/// First-byte bucket index — see [`FlirtSet`] for the design note.
///
/// `buckets[b]` holds the indices into `FlirtSet::patterns` for every
/// pattern whose `leading[0]` equals `Byte(b)`. `wildcards` holds the
/// indices for patterns whose `leading[0]` is a wildcard (or whose
/// `leading` is empty — defensive, shouldn't occur in well-formed
/// FLIRT corpora). Lookup walks `buckets[buf[0]]` + `wildcards`.
#[derive(Debug, Clone)]
pub(crate) struct FirstByteIndex {
    pub(crate) buckets: Box<[Vec<u32>; 256]>,
    pub(crate) wildcards: Vec<u32>,
}

impl Default for FirstByteIndex {
    fn default() -> Self {
        // Construct via array-of-Vecs through a const-init helper.
        // `Box::new([Vec::new(); 256])` doesn't compile because Vec
        // isn't Copy; std::array::from_fn does the right thing.
        Self {
            buckets: Box::new(std::array::from_fn(|_| Vec::new())),
            wildcards: Vec::new(),
        }
    }
}

impl FirstByteIndex {
    /// Build an index over `patterns`. Linear scan; called once at
    /// `FlirtSet` construction.
    pub(crate) fn build(patterns: &[Pattern]) -> Self {
        let mut idx = Self::default();
        for (i, pat) in patterns.iter().enumerate() {
            let i = i as u32;
            match pat.leading.first() {
                Some(PatternByte::Byte(b)) => idx.buckets[*b as usize].push(i),
                // `Wildcard` first byte → wildcards bucket (always
                // scanned). `None` (empty leading) is filtered out at
                // `FlirtSet::with_patterns`, so it shouldn't reach
                // here — but defend with the same fallback.
                Some(PatternByte::Wildcard) | None => idx.wildcards.push(i),
            }
        }
        idx
    }
}

impl FlirtSet {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            index: FirstByteIndex::default(),
        }
    }

    /// Construct a [`FlirtSet`] from a pre-built pattern list.
    ///
    /// Patterns with an empty `leading` field are silently dropped —
    /// FLIRT signatures require at least one head byte, and admitting
    /// them would match almost any input (the head check trivially
    /// passes against a zero-length pattern). If you need to round-
    /// trip such patterns for inspection, hold them in your own
    /// container outside `FlirtSet`.
    pub fn with_patterns(patterns: Vec<Pattern>) -> Self {
        let patterns: Vec<Pattern> = patterns
            .into_iter()
            .filter(|p| !p.leading.is_empty())
            .collect();
        let index = FirstByteIndex::build(&patterns);
        Self { patterns, index }
    }

    /// Number of signatures loaded.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Borrow the loaded patterns. Mostly useful for tests +
    /// introspection.
    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }
}

// Statically affirm Send + Sync — the whole point of fast-flirt is
// that a single loaded set can be shared across threads with no
// locking. If a refactor ever accidentally introduces interior
// mutability that breaks this, the compile fails here.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FlirtSet>();
    assert_send_sync::<Pattern>();
    assert_send_sync::<Symbol>();
    assert_send_sync::<Name>();
};
