//! Error type for fast-flirt.

use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("truncated input at offset {0}: expected {1} more bytes")]
    Truncated(usize, usize),

    #[error("invalid magic bytes (expected `IDASGN`, got {0:?})")]
    BadMagic([u8; 6]),

    #[error("unsupported .sig version {0} (supported: 5-10)")]
    UnsupportedVersion(u8),

    #[error("zlib inflate failed: {0}")]
    Inflate(String),

    /// The compressed body would have inflated beyond [`MAX_INFLATED`].
    /// Defends against zlib bombs from untrusted `.sig` input.
    ///
    /// [`MAX_INFLATED`]: crate::sig::MAX_INFLATED
    #[error("inflated .sig body would exceed {limit} bytes (bomb defence)")]
    InflateBomb { limit: usize },

    #[error("malformed .pat line {0}: {1}")]
    BadPatLine(usize, &'static str),

    #[error("invalid hex byte at offset {0}: {1:?}")]
    BadHex(usize, [u8; 2]),

    #[error("invalid utf-8 in name: {0}")]
    BadUtf8(#[from] std::str::Utf8Error),

    #[error("integer overflow in varint at offset {0}")]
    VarintOverflow(usize),

    #[error("invalid feature bits 0x{0:04x} in .sig header")]
    BadFeatures(u16),

    #[error("invalid name flags 0x{0:02x} in .sig body at offset {1}")]
    BadNameFlags(u8, usize),

    #[error("invalid parsing flags 0x{0:02x} in .sig body at offset {1}")]
    BadParsingFlags(u8, usize),

    #[error("wildcard mask exceeds supported width (>64 bits) at offset {0}")]
    MaskTooWide(usize),

    /// A wildcard-mask declared more set bits than the pattern's length.
    /// Indicates corruption or a hostile `.sig` — fail loud rather than
    /// silently truncating the literal slice.
    #[error("wildcard mask popcount {popcount} exceeds length {length} at offset {pos}")]
    BadMask {
        pos: usize,
        length: u16,
        popcount: u32,
    },

    /// `.sig` trie recursion exceeded the configured depth limit. Real
    /// FLIRT trees are shallow (<32 in practice); the cap defends
    /// against stack-overflow DoS from crafted input.
    #[error("`.sig` trie depth exceeded the {limit}-node limit at offset {pos}")]
    TooDeep { pos: usize, limit: u32 },

    /// A wire-encoded count (children per node, modules per CRC group,
    /// tail-bytes per module, …) was too large to be plausible given
    /// the remaining input. Defends against allocation DoS.
    #[error("implausible count {count} at offset {pos} (max {max})")]
    ImplausibleCount { pos: usize, count: u64, max: usize },

    /// A `.sig`-encoded function size exceeded `u32::MAX`. `module_len`
    /// is `u32` in our model; truncating silently would mis-report the
    /// size for hostile input, so we error explicitly.
    #[error("module_len {size} exceeds u32::MAX at offset {pos}")]
    ModuleLenOverflow { pos: usize, size: u64 },

    #[error("trailing data after .sig parse at offset {0}: {1} bytes remain")]
    TrailingData(usize, usize),

    /// IO error while loading a signature file. Preserves the path so
    /// callers get a useful "permission denied on /sigs/foo.sig" instead
    /// of an opaque parse error.
    #[error("io error on {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),

    /// `FlirtSetBuilder::alloc*` would have pushed past the 4 GiB
    /// `u32` offset ceiling. Reachable only when accumulating
    /// extremely large signature corpora into a single set; defends
    /// against silent offset wrap that would corrupt every later
    /// pattern lookup.
    #[error(
        "arena overflow: cannot fit {requested} more bytes (current arena {current} bytes, cap {})",
        u32::MAX
    )]
    ArenaOverflow { current: usize, requested: usize },

    /// A `PatternData` record points at arena bytes that are outside
    /// the arena. Validated at `FlirtSetBuilder::build` time; should
    /// never fire from the bundled parsers, but defends against
    /// future producers / corrupt round-trips.
    #[error(
        "pattern {pattern_idx}: arena bounds violation — field {field} at offset {offset} length {length} exceeds arena length {arena_len}"
    )]
    ArenaBounds {
        pattern_idx: usize,
        field: &'static str,
        offset: u32,
        length: usize,
        arena_len: usize,
    },

    /// Too many names attached to one signature (limit: `u16::MAX`).
    /// Real FLIRT signatures have a handful; this defends against
    /// crafted `.sig` input that would silently saturate.
    #[error("too many names on pattern at offset {pos} (max {max})")]
    TooManyNames { pos: usize, max: u16 },

    /// Too many discrete tail-byte discriminators on one signature
    /// (limit: `u32::MAX`). See `TooManyNames`.
    #[error("too many tail_bytes on pattern at offset {pos} (max {max})")]
    TooManyTailBytes { pos: usize, max: u32 },
}

pub type Result<T> = std::result::Result<T, Error>;
