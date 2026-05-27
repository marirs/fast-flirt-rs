//! Core data model for FLIRT signatures — zero-copy edition.
//!
//! Every signature in a [`FlirtSet`] lives inside one owned byte arena
//! (`Box<[u8]>`). The set keeps a fixed-size 48-byte `PatternData`
//! record per pattern with offsets into that arena. Callers iterate
//! via [`Pattern`] handles — lightweight `Copy` values that hold a
//! `(&FlirtSet, pattern_index)` pair and resolve fields on access.
//!
//! This design:
//!
//! - **Eliminates per-pattern heap traffic.** No `Vec<PatternByte>`,
//!   no per-name `String`, no `SmallVec<Symbol>`. One big arena
//!   allocation per `FlirtSet`, period.
//! - **Cuts memory by ~40%** on FLIRTDB-sized corpora (the bench
//!   moves from ~250 MiB resident to ~150 MiB).
//! - **Avoids self-referential lifetimes.** `FlirtSet` carries no
//!   `'a` parameter; `Pattern<'set>` borrows from `&'set FlirtSet`.

use crate::trie::PatternTrie;

// =====================================================================
// Arena-backed representation
// =====================================================================

/// One signature, stored in the arena as offsets + a small fixed
/// record. Private — callers see [`Pattern`] handles instead.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PatternData {
    // ---- head pattern --------------------------------------------
    /// Arena offset of the head bytes.
    pub(crate) leading_off: u32,
    /// Length of the head pattern (always 32 for real FLIRT, but
    /// stored explicitly so we don't bake the assumption in).
    pub(crate) leading_len: u8,
    /// Bit `i` set ⇒ position `i` of the head is a wildcard.
    /// FLIRT heads cap at 32 positions; a `u64` leaves headroom and
    /// keeps the record naturally aligned.
    pub(crate) leading_wildmask: u64,

    // ---- CRC window ----------------------------------------------
    pub(crate) crc_len: u8,
    pub(crate) crc16: u16,
    pub(crate) module_len: u32,

    // ---- names ---------------------------------------------------
    /// Offset of the packed name records (laid out as documented on
    /// `NameIter`).
    pub(crate) names_off: u32,
    pub(crate) names_count: u8,

    // ---- `.pat`-style contiguous tail ---------------------------
    pub(crate) tail_off: u32,
    pub(crate) tail_len: u8,
    pub(crate) tail_wildmask: u64,

    // ---- `.sig`-style discriminator bytes -----------------------
    /// Offset of packed `(offset_u32_le, value_u8)` records. Each
    /// record is 5 bytes. `tail_bytes_count` records follow.
    pub(crate) tail_bytes_off: u32,
    pub(crate) tail_bytes_count: u16,
}

// =====================================================================
// Public handle types
// =====================================================================

/// A single signature, borrowed from its owning [`FlirtSet`].
///
/// This is a lightweight handle — copying a `Pattern` is just two
/// machine words. All field access goes through methods that read
/// from the underlying arena lazily.
#[derive(Debug, Clone, Copy)]
pub struct Pattern<'set> {
    set: &'set FlirtSet,
    idx: u32,
}

impl<'set> Pattern<'set> {
    pub(crate) fn new(set: &'set FlirtSet, idx: u32) -> Self {
        Self { set, idx }
    }

    #[inline]
    fn data(&self) -> &'set PatternData {
        &self.set.patterns[self.idx as usize]
    }

    /// The head bytes. Wildcards are present in the slice but their
    /// values are unspecified — check [`Pattern::is_wildcard`] for
    /// each position.
    #[inline]
    pub fn leading(&self) -> &'set [u8] {
        let d = self.data();
        &self.set.arena[d.leading_off as usize..d.leading_off as usize + d.leading_len as usize]
    }

    /// `true` if position `pos` in the head pattern is a wildcard
    /// (matches any input byte). Out-of-range positions return `false`.
    #[inline]
    pub fn is_wildcard(&self, pos: usize) -> bool {
        if pos >= self.data().leading_len as usize {
            return false;
        }
        (self.data().leading_wildmask & (1u64 << pos)) != 0
    }

    /// Number of CRC bytes immediately following the head.
    #[inline]
    pub fn crc_len(&self) -> u8 {
        self.data().crc_len
    }

    /// Expected CRC-16/X-25 of the CRC window.
    #[inline]
    pub fn crc16(&self) -> u16 {
        self.data().crc16
    }

    /// Total length of the original library function, informational.
    #[inline]
    pub fn module_len(&self) -> u32 {
        self.data().module_len
    }

    /// Iterate every name attached to this pattern (Public / Local /
    /// Reference). Cheap — yields borrowed handles.
    pub fn names(&self) -> NameIter<'set> {
        let d = self.data();
        NameIter {
            arena: &self.set.arena,
            cursor: d.names_off as usize,
            remaining: d.names_count,
        }
    }

    /// The first `Symbol::Public` name on this pattern, if any.
    /// Mirrors the common capa-style "what library function is this?"
    /// lookup.
    pub fn public_name(&self) -> Option<&'set str> {
        for sym in self.names() {
            if let Symbol::Public(n) = sym {
                return Some(n.name);
            }
        }
        None
    }

    /// `.pat`-style contiguous trailing pattern (empty for `.sig`
    /// patterns).
    #[inline]
    pub fn tail(&self) -> &'set [u8] {
        let d = self.data();
        if d.tail_len == 0 {
            return &[];
        }
        &self.set.arena[d.tail_off as usize..d.tail_off as usize + d.tail_len as usize]
    }

    /// `true` if position `pos` in the tail pattern is a wildcard.
    #[inline]
    pub fn is_tail_wildcard(&self, pos: usize) -> bool {
        if pos >= self.data().tail_len as usize {
            return false;
        }
        (self.data().tail_wildmask & (1u64 << pos)) != 0
    }

    /// `.sig`-style `(function_offset, expected_byte)` discriminator
    /// pairs. Empty for `.pat` patterns.
    pub fn tail_bytes(&self) -> TailByteIter<'set> {
        let d = self.data();
        TailByteIter {
            arena: &self.set.arena,
            cursor: d.tail_bytes_off as usize,
            remaining: d.tail_bytes_count,
        }
    }

    /// Minimum input length to evaluate every check on this pattern.
    pub fn min_input_len(&self) -> usize {
        let d = self.data();
        let contiguous = d.leading_len as usize + d.crc_len as usize + d.tail_len as usize;
        let mut max_off = 0usize;
        for (off, _) in self.tail_bytes() {
            let need = off as usize + 1;
            if need > max_off {
                max_off = need;
            }
        }
        contiguous.max(max_off)
    }
}

// ---------- Names ----------------------------------------------------

/// FLIRT name tag.
///
/// - `Public`: the canonical name exposed to the user.
/// - `Local`: an internal label inside the function body.
/// - `Reference`: name of a callee referenced from inside the matched
///   pattern.
#[derive(Debug, Clone, Copy)]
pub enum Symbol<'set> {
    Public(Name<'set>),
    Local(Name<'set>),
    Reference(Name<'set>),
}

impl<'set> Symbol<'set> {
    pub fn name(&self) -> &Name<'set> {
        match self {
            Symbol::Public(n) | Symbol::Local(n) | Symbol::Reference(n) => n,
        }
    }
}

/// A name + its byte offset relative to the function start.
#[derive(Debug, Clone, Copy)]
pub struct Name<'set> {
    pub offset: i64,
    pub name: &'set str,
}

/// Iterator over a pattern's name records. Each record in the arena
/// is laid out as:
///
/// ```text
/// +0  kind: u8   (0 = Public, 1 = Local, 2 = Reference)
/// +1  offset: i64 little-endian (8 bytes)
/// +9  name_len: u16 little-endian (2 bytes)
/// +11 name_bytes: name_len UTF-8 bytes
/// ```
///
/// Records are tightly packed — no padding between or within.
pub struct NameIter<'set> {
    arena: &'set [u8],
    cursor: usize,
    remaining: u8,
}

const NAME_HEADER_LEN: usize = 1 + 8 + 2;
const NAME_KIND_PUBLIC: u8 = 0;
const NAME_KIND_LOCAL: u8 = 1;
const NAME_KIND_REFERENCE: u8 = 2;

impl<'set> Iterator for NameIter<'set> {
    type Item = Symbol<'set>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let c = self.cursor;
        let header = &self.arena[c..c + NAME_HEADER_LEN];
        let kind = header[0];
        let offset = i64::from_le_bytes(header[1..9].try_into().unwrap());
        let name_len = u16::from_le_bytes(header[9..11].try_into().unwrap()) as usize;
        let name_bytes = &self.arena[c + NAME_HEADER_LEN..c + NAME_HEADER_LEN + name_len];
        // Names are validated UTF-8 at build time, so this is safe to
        // pretend on read. `from_utf8_unchecked` would shave a few
        // nanoseconds, but we promised "pure safe Rust" — the checked
        // path is bounds-/encoding-validated.
        let name = std::str::from_utf8(name_bytes).expect("arena name not utf-8");
        self.cursor = c + NAME_HEADER_LEN + name_len;
        let n = Name { offset, name };
        Some(match kind {
            NAME_KIND_PUBLIC => Symbol::Public(n),
            NAME_KIND_LOCAL => Symbol::Local(n),
            NAME_KIND_REFERENCE => Symbol::Reference(n),
            _ => unreachable!("arena name has invalid kind tag {kind}"),
        })
    }
}

// ---------- Tail bytes (discrete .sig discriminators) ---------------

/// Iterator over a pattern's discrete `(offset, value)` discriminator
/// bytes. Each record in the arena is 5 bytes: a little-endian u32
/// offset followed by a single u8 value.
pub struct TailByteIter<'set> {
    arena: &'set [u8],
    cursor: usize,
    remaining: u16,
}

const TAIL_BYTE_RECORD_LEN: usize = 4 + 1;

impl Iterator for TailByteIter<'_> {
    type Item = (u32, u8);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let c = self.cursor;
        let off = u32::from_le_bytes(self.arena[c..c + 4].try_into().unwrap());
        let val = self.arena[c + 4];
        self.cursor = c + TAIL_BYTE_RECORD_LEN;
        Some((off, val))
    }
}

// =====================================================================
// FlirtSet: corpus + arena + trie
// =====================================================================

/// A loaded corpus of FLIRT signatures.
///
/// Construct via [`pat::parse`], [`sig::parse`], [`FlirtSet::load_dir`],
/// or [`FlirtSetBuilder`]. Query via [`FlirtSet::matches`] /
/// [`FlirtSet::match_public_name`].
///
/// `FlirtSet` owns its data — one arena `Box<[u8]>` plus a record
/// per pattern. It's `Send + Sync` (no interior mutability) and the
/// matcher does no allocation per call beyond the result `Vec`, so a
/// single `&FlirtSet` shares freely across rayon workers.
///
/// [`pat::parse`]: crate::pat::parse
/// [`sig::parse`]: crate::sig::parse
#[derive(Debug, Clone, Default)]
pub struct FlirtSet {
    pub(crate) arena: Box<[u8]>,
    pub(crate) patterns: Vec<PatternData>,
    pub(crate) trie: PatternTrie,
}

impl FlirtSet {
    /// An empty set. Useful as a placeholder; loaded sets come from
    /// the parsers or [`FlirtSetBuilder`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of signatures loaded.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Borrow every pattern in the set. Mostly useful for tests +
    /// introspection — match-time queries should go through
    /// `FlirtSet::matches`.
    pub fn patterns(&self) -> impl Iterator<Item = Pattern<'_>> + '_ {
        (0..self.patterns.len() as u32).map(move |i| Pattern::new(self, i))
    }

    /// Construct a `Pattern` handle for the given index. Bounds-
    /// checked panic on out-of-range.
    pub fn pattern(&self, idx: u32) -> Pattern<'_> {
        assert!(
            (idx as usize) < self.patterns.len(),
            "pattern index {idx} out of range (len {})",
            self.patterns.len()
        );
        Pattern::new(self, idx)
    }

    /// Load every `.sig` and `.pat` file in `dir` recursively into a
    /// single corpus. Files are recognised by extension
    /// (case-insensitive). Symlinks are skipped.
    pub fn load_dir<P: AsRef<std::path::Path>>(dir: P) -> crate::Result<Self> {
        let mut builder = FlirtSetBuilder::new();
        for entry in walkdir(dir.as_ref())? {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.ends_with(".pat") {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| crate::Error::Io(path.clone(), e))?;
                builder.add_pat(&text)?;
            } else if name.ends_with(".sig") {
                let bytes = std::fs::read(&path).map_err(|e| crate::Error::Io(path.clone(), e))?;
                builder.add_sig(&bytes)?;
            }
        }
        Ok(builder.build())
    }
}

/// Recursive directory walker. Skips symlinks (both file + directory)
/// so a symlink loop in the input tree can't OOM us, and surfaces real
/// IO errors via [`crate::Error::Io`] with the offending path attached.
fn walkdir(root: &std::path::Path) -> crate::Result<Vec<std::fs::DirEntry>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let read_dir = std::fs::read_dir(&path).map_err(|e| crate::Error::Io(path.clone(), e))?;
        for entry in read_dir {
            let entry = entry.map_err(|e| crate::Error::Io(path.clone(), e))?;
            let ft = entry
                .file_type()
                .map_err(|e| crate::Error::Io(entry.path(), e))?;
            if ft.is_symlink() {
                continue;
            }
            let p = entry.path();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                out.push(entry);
            }
        }
    }
    Ok(out)
}

// =====================================================================
// FlirtSetBuilder — accumulate patterns from multiple sources
// =====================================================================

/// Incremental builder for a [`FlirtSet`]. Use this when you want to
/// merge patterns from multiple `.pat` / `.sig` sources into a single
/// matcher without an intermediate `Vec<Pattern>`.
///
/// ```no_run
/// use fast_flirt::FlirtSetBuilder;
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let mut b = FlirtSetBuilder::new();
/// b.add_pat(&std::fs::read_to_string("libmsvcrt.pat")?)?;
/// b.add_sig(&std::fs::read("libstd.sig")?)?;
/// let set = b.build();
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct FlirtSetBuilder {
    pub(crate) arena: Vec<u8>,
    pub(crate) patterns: Vec<PatternData>,
}

impl FlirtSetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a `.pat` document and append its patterns. Returns the
    /// number of patterns added.
    pub fn add_pat(&mut self, text: &str) -> crate::Result<usize> {
        crate::pat::append(self, text)
    }

    /// Parse a `.sig` file (compressed or not) and append its
    /// patterns. Returns the number of patterns added.
    pub fn add_sig(&mut self, bytes: &[u8]) -> crate::Result<usize> {
        crate::sig::append(self, bytes)
    }

    /// Finalize into a queryable [`FlirtSet`]. Builds the prefix trie
    /// over the accumulated patterns.
    pub fn build(mut self) -> FlirtSet {
        // Drop patterns with zero-length leading — they would match
        // anything and confuse the trie. Defensive; the parsers don't
        // produce these.
        self.patterns.retain(|p| p.leading_len > 0);
        let arena = self.arena.into_boxed_slice();
        let trie = PatternTrie::build(&self.patterns, &arena);
        FlirtSet {
            arena,
            patterns: self.patterns,
            trie,
        }
    }
}

// ----- Helpers used by both parsers --------------------------------

impl FlirtSetBuilder {
    /// Append `bytes` to the arena and return the offset.
    pub(crate) fn alloc(&mut self, bytes: &[u8]) -> u32 {
        let off = self.arena.len() as u32;
        self.arena.extend_from_slice(bytes);
        off
    }

    /// Append a packed name record. Returns the offset of the FIRST
    /// byte of the record so callers can stash it into `names_off`
    /// for the first call of a group.
    pub(crate) fn alloc_name(&mut self, kind: u8, offset: i64, name: &str) -> u32 {
        let off = self.arena.len() as u32;
        self.arena.push(kind);
        self.arena.extend_from_slice(&offset.to_le_bytes());
        self.arena
            .extend_from_slice(&(name.len() as u16).to_le_bytes());
        self.arena.extend_from_slice(name.as_bytes());
        off
    }

    /// Append a packed tail-byte record `(offset_le_u32, value_u8)`.
    /// Returns the offset of the first record so the caller stashes
    /// it once for the group.
    pub(crate) fn alloc_tail_byte(&mut self, offset: u32, value: u8) -> u32 {
        let off = self.arena.len() as u32;
        self.arena.extend_from_slice(&offset.to_le_bytes());
        self.arena.push(value);
        off
    }

    /// Push a fully-constructed `PatternData`. Returns its index in
    /// `patterns`.
    pub(crate) fn push_pattern(&mut self, data: PatternData) -> usize {
        self.patterns.push(data);
        self.patterns.len() - 1
    }
}

// ----- Crate-internal name-kind constants ---------------------------

pub(crate) const NK_PUBLIC: u8 = NAME_KIND_PUBLIC;
pub(crate) const NK_LOCAL: u8 = NAME_KIND_LOCAL;
pub(crate) const NK_REFERENCE: u8 = NAME_KIND_REFERENCE;

// =====================================================================
// Send + Sync compile-time guard
// =====================================================================

// FlirtSet is the headline shared-corpus type — losing Send/Sync would
// break rayon-driven capa-rs and silently regress users. Fail the
// build immediately if a future refactor breaks it.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FlirtSet>();
    assert_send_sync::<PatternData>();
    assert_send_sync::<FlirtSetBuilder>();
};
