//! `.sig` (FLIRT binary signature) file parser.
//!
//! Format reference (Hex-Rays FLAIR + reverse-engineered notes):
//!
//! ```text
//! +--------+----------------------------------------------------+
//! | offset | field                                              |
//! +--------+----------------------------------------------------+
//! |   0    | magic "IDASGN" (6 bytes)                           |
//! |   6    | version u8 (supported: 5..=10)                     |
//! |   7    | arch u8                                            |
//! |   8    | file_types u32 (LE)                                |
//! |   C    | os_types u16 (LE)                                  |
//! |   E    | app_types u16 (LE)                                 |
//! |  10    | features u16 (LE)  -- bit 0x10 = zlib-compressed   |
//! |  12    | (skipped u16)                                      |
//! |  14    | crc16 u16 (LE)                                     |
//! |  16    | (skipped 12 bytes — ctype string)                  |
//! |  22    | library_name_length u8                             |
//! |  23    | alt_ctype_crc16 u16 (LE)                           |
//! |  25    | version-specific extra (4 / 6 / 8 bytes)           |
//! |  ...   | library_name (UTF-8, library_name_length bytes)    |
//! |  ...   | trie body (optionally zlib-deflated)               |
//! +--------+----------------------------------------------------+
//! ```
//!
//! The trie body is a recursive structure. Each *node* starts with
//! a `vint16` child count: if zero, a *leaf* follows; otherwise
//! that many `(length, wildcard_mask, byte_literals, child_node)`
//! tuples. Walking the trie accumulates the head pattern; the leaf
//! emits one or more [`Pattern`]s (one per "module" — multiple
//! functions can share a head and CRC, distinguished by tail bytes).
//!
//! `.sig` discriminators land in `Pattern::tail_bytes` (discrete
//! offset/value pairs), not `Pattern::tail` (which is the `.pat`
//! contiguous form).

use crate::error::{Error, Result};
use crate::types::{Name, Pattern, PatternByte, Symbol};
use smallvec::SmallVec;

// -----------------------------------------------------------------
// Header
// -----------------------------------------------------------------

const MAGIC: &[u8; 6] = b"IDASGN";

/// `features & FEATURE_COMPRESSED` is set when the body is zlib-
/// deflated. All other feature bits are observational; we don't
/// branch on them.
const FEATURE_COMPRESSED: u16 = 0x10;

/// Aggregate of all valid feature bits as of FLIRT v10. Reject
/// anything outside this set: it signals a future format we don't
/// understand and we'd rather fail loud than skip data.
const ALL_FEATURES: u16 = 0x3F;

// -----------------------------------------------------------------
// DoS-defence caps (0.1.1)
// -----------------------------------------------------------------
//
// FLIRT `.sig` files come from untrusted sources (FLAIR, third-party
// corpora, samples in malware-analysis pipelines). Every wire-encoded
// count or recursion path needs a plausibility cap so a hand-crafted
// file can't blow the stack or exhaust memory.

/// Maximum bytes the decompressed body may occupy. Real FLIRT corpora
/// (the published Hex-Rays bundles + FLIRTDB) are well under 100 MiB
/// inflated; 256 MiB leaves headroom for unusually large libraries
/// while still blocking zlib bombs cold.
pub const MAX_INFLATED: usize = 256 * 1024 * 1024;

/// Maximum depth of the `.sig` trie. Real trees in FLIRTDB are
/// shallow (typically <16, never >32 in the 192-file sweep we tested
/// against during 0.1.0). 256 leaves comfortable headroom while
/// killing crafted "chain of single-child nodes" stack-overflow input.
const MAX_TRIE_DEPTH: u32 = 256;

/// Hard ceiling on any single wire-encoded count (children per node,
/// modules per CRC group, tail-bytes per module, etc.). 1 << 20 is
/// orders of magnitude larger than anything observed in practice and
/// stops `for _ in 0..count { Vec::push(...) }` DoS amplifiers.
const MAX_COUNT: usize = 1 << 20;

#[derive(Debug, Clone, Copy)]
struct Header {
    version: u8,
    /// Width of the head pattern, in bytes. 32 for v5..=7; explicit
    /// field for v8..=10 (but always 32 in practice).
    pattern_size: u16,
    features: u16,
    /// Byte length of the header, including library name and any
    /// version-specific extra. Body starts at this offset within
    /// the raw `.sig` file (compressed or uncompressed).
    header_len: usize,
}

impl Header {
    fn is_compressed(self) -> bool {
        (self.features & FEATURE_COMPRESSED) != 0
    }
}

// -----------------------------------------------------------------
// Byte-cursor primitives
// -----------------------------------------------------------------

/// Mutable parse cursor over a byte slice. Every read advances `pos`
/// and bounds-checks; on underflow we return `Error::Truncated` so a
/// malformed file can never panic.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Truncated(self.pos, n));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn peek_u8(&self) -> Result<u8> {
        if self.remaining() == 0 {
            return Err(Error::Truncated(self.pos, 1));
        }
        Ok(self.buf[self.pos])
    }

    fn le_u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn le_u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn be_u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

// -----------------------------------------------------------------
// FLIRT variable-length integers (big-endian)
// -----------------------------------------------------------------

/// Variable-length integer up to 16 bits.
///
/// Encoding: read one byte. If high bit clear, that's the value
/// (range 0..=0x7F). Otherwise read a second byte and combine:
/// `((high & 0x7F) << 8) | low` (range 0..=0x7FFF).
fn vint16(cur: &mut Cursor<'_>) -> Result<u16> {
    let high = cur.u8()?;
    if (high & 0x80) == 0 {
        return Ok(high as u16);
    }
    let low = cur.u8()?;
    Ok(((high as u16 & 0x7F) << 8) | low as u16)
}

/// Variable-length integer up to 32 bits.
///
/// Encoding (FLIRT's "varint" — same idea as Protocol Buffers but
/// the continuation bits are in the high two bits of the first byte
/// rather than per-byte):
///
/// - `0xxxxxxx`              → 1 byte  (0..=0x7F)
/// - `10xxxxxx yyyyyyyy`     → 2 bytes (0..=0x3FFF, encoded `((h & 0x7F) << 8) | l`)
/// - `110xxxxx yyyyyyyy zzzzzzzz zzzzzzzz` → 4 bytes
/// - `111xxxxx aaaaaaaa aaaaaaaa bbbbbbbb bbbbbbbb`      → 5 bytes
fn vint32(cur: &mut Cursor<'_>) -> Result<u32> {
    let b = cur.u8()?;
    if (b & 0x80) == 0 {
        return Ok(b as u32);
    }
    if (b & 0xC0) != 0xC0 {
        let low = cur.u8()? as u32;
        return Ok(((b as u32 & 0x7F) << 8) | low);
    }
    if (b & 0xE0) != 0xE0 {
        // 4-byte form `110xxxxx`: top 3 bits are the discriminator,
        // bottom 5 bits are payload. Bit 5 is always 0 in this
        // branch (the 5-byte branch below would have fired
        // otherwise), so `& 0x1F` and `& 0x3F` give the same numeric
        // result today — `& 0x1F` is the self-documenting choice
        // that survives any future re-ordering of the branches.
        let mid = cur.u8()? as u32;
        let low = cur.be_u16()? as u32;
        return Ok((((b as u32 & 0x1F) << 8 | mid) << 16) | low);
    }
    let hi = cur.be_u16()? as u32;
    let lo = cur.be_u16()? as u32;
    Ok((hi << 16) | lo)
}

/// `vword` picks the right varint width for the file version.
/// FLIRT v9 widened most counts from 16 bits to 32 bits to support
/// larger libraries; older files stay in `vint16`.
fn vword(cur: &mut Cursor<'_>, version: u8) -> Result<u64> {
    if version < 9 {
        Ok(vint16(cur)? as u64)
    } else {
        Ok(vint32(cur)? as u64)
    }
}

// -----------------------------------------------------------------
// Header parser
// -----------------------------------------------------------------

fn parse_header(input: &[u8]) -> Result<Header> {
    let mut cur = Cursor::new(input);

    // Magic
    let magic = cur.take(6)?;
    if magic != MAGIC {
        let mut got = [0u8; 6];
        got.copy_from_slice(magic);
        return Err(Error::BadMagic(got));
    }

    // Fixed-shape preamble.
    let version = cur.u8()?;
    if !(5..=10).contains(&version) {
        return Err(Error::UnsupportedVersion(version));
    }
    let _arch = cur.u8()?;
    let _file_types = cur.le_u32()?;
    let _os_types = cur.le_u16()?;
    let _app_types = cur.le_u16()?;
    let features = cur.le_u16()?;
    if (features & !ALL_FEATURES) != 0 {
        return Err(Error::BadFeatures(features));
    }
    let _padding = cur.le_u16()?;
    let _crc16 = cur.le_u16()?;
    let _ctype = cur.take(12)?;
    let library_name_length = cur.u8()?;
    let _alt_ctype_crc16 = cur.le_u16()?;

    // Version-specific extra block. We only care about pattern_size;
    // the function-count fields are informational.
    let pattern_size = match version {
        5 => 32,
        6 | 7 => {
            let _functions = cur.le_u32()?;
            32
        }
        8 | 9 => {
            let _functions = cur.le_u32()?;
            cur.le_u16()?
        }
        10 => {
            let _functions = cur.le_u32()?;
            let ps = cur.le_u16()?;
            let _unknown = cur.le_u16()?;
            ps
        }
        _ => unreachable!("version range checked above"),
    };

    // Library name (UTF-8). Length-prefixed by the `library_name_length`
    // byte we already read.
    let _lib_name = cur.take(library_name_length as usize)?;

    Ok(Header {
        version,
        pattern_size,
        features,
        header_len: cur.pos,
    })
}

// -----------------------------------------------------------------
// Wildcard-mask + node literals
// -----------------------------------------------------------------

/// Read a wildcard mask covering `length` pattern bytes. Each set bit
/// in the returned value marks a wildcard at that bit position in the
/// upcoming literal slot.
///
/// FLIRT uses a tight encoding: the mask is a varint sized by how
/// many bits it must cover. For `length > 64` the original tool
/// supports an extended encoding we don't yet handle (and have never
/// seen in practice for typical 32-byte patterns).
fn wildcard_mask(cur: &mut Cursor<'_>, length: u16) -> Result<u64> {
    Ok(if length == 0 {
        0
    } else if length < 0x10 {
        vint16(cur)? as u64
    } else if length <= 0x20 {
        vint32(cur)? as u64
    } else if length <= 0x40 {
        let high = vint32(cur)? as u64;
        let low = vint32(cur)? as u64;
        (high << 32) | low
    } else {
        return Err(Error::MaskTooWide(cur.pos));
    })
}

// Parsing flags — bit-packed continuation markers attached to each
// parsed name. Names them by purpose; we never bitflags-derive these.
const PFLAG_MORE_PUBLIC_NAMES: u8 = 0x01;
const PFLAG_TAIL_BYTES: u8 = 0x02;
const PFLAG_REFERENCED_FUNCTIONS: u8 = 0x04;
const PFLAG_MORE_MODULES_WITH_SAME_CRC: u8 = 0x08;
const PFLAG_MORE_MODULES: u8 = 0x10;
const PFLAG_ALL: u8 = PFLAG_MORE_PUBLIC_NAMES
    | PFLAG_TAIL_BYTES
    | PFLAG_REFERENCED_FUNCTIONS
    | PFLAG_MORE_MODULES_WITH_SAME_CRC
    | PFLAG_MORE_MODULES;

const NFLAG_LOCAL: u8 = 0x02;
const NFLAG_NEGATIVE_OFFSET: u8 = 0x10;
const NFLAG_ALL: u8 = 0x1F;

// -----------------------------------------------------------------
// Trie recursion: nodes + leaves
// -----------------------------------------------------------------

/// Recurse into a trie node, appending discovered patterns to `out`.
/// `prefix` is the head pattern bytes accumulated by parent nodes.
///
/// `depth` is the current trie depth (0 at the root). We refuse to
/// recurse beyond [`MAX_TRIE_DEPTH`] to defend against stack-overflow
/// DoS from crafted "chain of single-child nodes" input — real FLIRT
/// trees are shallow (<32 in the FLIRTDB corpus).
fn parse_node(
    cur: &mut Cursor<'_>,
    header: &Header,
    prefix: &mut Vec<PatternByte>,
    out: &mut Vec<Pattern>,
    depth: u32,
) -> Result<()> {
    if depth >= MAX_TRIE_DEPTH {
        return Err(Error::TooDeep {
            pos: cur.pos,
            limit: MAX_TRIE_DEPTH,
        });
    }

    let child_count = vint16(cur)?;
    if child_count == 0 {
        return parse_leaf(cur, header, prefix, out);
    }

    // Cap child_count against remaining input: every child consumes at
    // least one byte for its length field, plus mask/literals/child
    // subtree. A count larger than `cur.remaining()` is provably
    // implausible regardless of how cheap each child encodes.
    let child_count = bound_count(child_count as u64, cur)?;

    for _ in 0..child_count {
        // Each child contributes `length` more bytes to the pattern
        // prefix. v10 widened this from u8 to vint16.
        let length: u16 = if header.version < 10 {
            cur.u8()? as u16
        } else {
            vint16(cur)?
        };
        let mask = wildcard_mask(cur, length)?;

        // Defence: a hostile mask could claim more set bits than the
        // pattern length. Without this check the u16 subtraction
        // panics in debug builds and wraps to a huge number in
        // release, then drives a doomed `take()`.
        let popcount = mask.count_ones();
        if popcount as u64 > length as u64 {
            return Err(Error::BadMask {
                pos: cur.pos,
                length,
                popcount,
            });
        }
        let literal_count = length - popcount as u16;
        let literals = cur.take(literal_count as usize)?;

        // Expand mask + literals into the prefix. FLIRT packs literals
        // in reverse order relative to the pattern, so we walk a
        // descending index into `literals` while iterating positions
        // left-to-right. (Equivalently: append then reverse the
        // just-added slice, which is what we do here because it's
        // easier to read.)
        let prev_len = prefix.len();
        let mut j: usize = literal_count as usize;
        for i in 0..length as u64 {
            if (mask & (1 << i)) != 0 {
                prefix.push(PatternByte::Wildcard);
            } else {
                prefix.push(PatternByte::Byte(literals[j - 1]));
                j -= 1;
            }
        }
        prefix[prev_len..].reverse();

        parse_node(cur, header, prefix, out, depth + 1)?;

        // Pop our contribution before the next sibling.
        prefix.truncate(prev_len);
    }

    Ok(())
}

/// Clamp a wire-encoded count against both a hard ceiling
/// ([`MAX_COUNT`]) and the remaining input length, surfacing
/// [`Error::ImplausibleCount`] when either bound is exceeded. Used
/// for child-counts, modules-per-leaf, tail-byte counts, and
/// referenced-name counts.
fn bound_count(count: u64, cur: &Cursor<'_>) -> Result<usize> {
    let max = MAX_COUNT.min(cur.remaining());
    if count > max as u64 {
        return Err(Error::ImplausibleCount {
            pos: cur.pos,
            count,
            max,
        });
    }
    Ok(count as usize)
}

/// Parse a leaf — one or more "modules" (functions) that share the
/// accumulated head prefix. Each module gets its own [`Pattern`].
fn parse_leaf(
    cur: &mut Cursor<'_>,
    header: &Header,
    prefix: &[PatternByte],
    out: &mut Vec<Pattern>,
) -> Result<()> {
    // Outer loop: groups of modules sharing the same head but
    // different CRCs.
    // Inner loop: individual modules within one CRC group (rare —
    // requires tail-byte disambiguation).
    loop {
        let crc_len = cur.u8()?;
        let crc16 = cur.be_u16()?;

        let last_pflags: u8 = loop {
            let function_size = vword(cur, header.version)?;

            // Names. The first name carries a base offset; subsequent
            // names' offsets stack atop it (delta-encoded). The
            // `loop { ... break }` guarantees `pflags` is assigned
            // before any later read.
            let mut names: SmallVec<[Symbol; 2]> = SmallVec::new();
            let mut current_offset: i64 = 0;
            let mut tail_bytes: Vec<(u32, u8)> = Vec::new();
            let pflags: u8 = loop {
                let (sym, new_offset, flags) = parse_name(cur, header.version, current_offset)?;
                current_offset = new_offset;
                names.push(sym);
                if (flags & PFLAG_MORE_PUBLIC_NAMES) == 0 {
                    break flags;
                }
            };

            // Optional tail-byte discriminators. Format: varint count
            // (or implicit 1 for v<8), then `count` × (offset_vword,
            // value_u8).
            if (pflags & PFLAG_TAIL_BYTES) != 0 {
                let count_raw = if header.version < 8 {
                    1u64
                } else {
                    vword(cur, header.version)?
                };
                let count = bound_count(count_raw, cur)?;
                for _ in 0..count {
                    let off = vword(cur, header.version)?;
                    let val = cur.u8()?;
                    // FLIRT tail-byte offsets fit comfortably in u32
                    // (function size capped well under 4 GiB).
                    if off > u32::MAX as u64 {
                        return Err(Error::VarintOverflow(cur.pos));
                    }
                    tail_bytes.push((off as u32, val));
                }
            }

            // Optional referenced functions: discriminator that names
            // a *callee* the function must reach at a given offset.
            // We surface these as `Symbol::Reference` entries on the
            // pattern; the matcher caller decides what to do with
            // them (full resolution requires recursive matching).
            if (pflags & PFLAG_REFERENCED_FUNCTIONS) != 0 {
                let count_raw = if header.version < 8 {
                    1u64
                } else {
                    vword(cur, header.version)?
                };
                let count = bound_count(count_raw, cur)?;
                for _ in 0..count {
                    let off = vword(cur, header.version)?;
                    // Defensive: keep the same u32::MAX bound as
                    // tail_bytes. Today this is unreachable because
                    // `vword` is capped at u32::MAX, but if the
                    // varint widens in future the check stays valid.
                    if off > u32::MAX as u64 {
                        return Err(Error::VarintOverflow(cur.pos));
                    }
                    let size_byte = cur.u8()?;
                    // size == 0 → extended length stored as vint16.
                    let size: u16 = if size_byte == 0 {
                        vint16(cur)?
                    } else {
                        size_byte as u16
                    };
                    let name_bytes = cur.take(size as usize)?;
                    let name = std::str::from_utf8(name_bytes)?.to_string();
                    names.push(Symbol::Reference(Name {
                        offset: off as i64,
                        name,
                    }));
                }
            }

            // Reject silently-truncating module_len. Real libraries
            // are well under 4 GiB; a wire value above u32::MAX means
            // the file is either corrupt or hostile.
            if function_size > u32::MAX as u64 {
                return Err(Error::ModuleLenOverflow {
                    pos: cur.pos,
                    size: function_size,
                });
            }
            out.push(Pattern {
                leading: prefix.to_vec(),
                crc_len,
                crc16,
                module_len: function_size as u32,
                names,
                tail: Vec::new(),
                tail_bytes,
            });

            if (pflags & PFLAG_MORE_MODULES_WITH_SAME_CRC) == 0 {
                break pflags;
            }
        };

        if (last_pflags & PFLAG_MORE_MODULES) == 0 {
            break;
        }
    }
    Ok(())
}

/// Parse one name + its trailing parsing-flags byte.
///
/// Returns `(symbol, updated_offset, parsing_flags)`. The new offset
/// is the (delta-decoded, possibly negative) starting point for the
/// next name in the same module.
fn parse_name(cur: &mut Cursor<'_>, version: u8, base_offset: i64) -> Result<(Symbol, i64, u8)> {
    let delta = vword(cur, version)?;

    // The optional name-flags byte is present iff the next byte is
    // < 0x20 (ASCII control range — name characters are always
    // >= 0x20). Peek to decide.
    let name_flags = if cur.peek_u8()? < 0x20 {
        let nf = cur.u8()?;
        if (nf & !NFLAG_ALL) != 0 {
            return Err(Error::BadNameFlags(nf, cur.pos));
        }
        nf
    } else {
        0
    };

    let offset = if (name_flags & NFLAG_NEGATIVE_OFFSET) != 0 {
        base_offset - delta as i64
    } else {
        base_offset + delta as i64
    };

    // Name runs to the first byte < 0x20 (the next parsing-flags
    // byte). Bounds-checked by `take`.
    let start = cur.pos;
    while cur.peek_u8()? >= 0x20 {
        cur.pos += 1;
    }
    let name_bytes = &cur.buf[start..cur.pos];
    let name = std::str::from_utf8(name_bytes)?.to_string();

    let pflags = cur.u8()?;
    if (pflags & !PFLAG_ALL) != 0 {
        return Err(Error::BadParsingFlags(pflags, cur.pos));
    }

    let n = Name { offset, name };
    let sym = if (name_flags & NFLAG_LOCAL) != 0 {
        Symbol::Local(n)
    } else {
        Symbol::Public(n)
    };
    Ok((sym, offset, pflags))
}

// -----------------------------------------------------------------
// Public entry point
// -----------------------------------------------------------------

/// Parse a complete `.sig` file (compressed or not) into a list of
/// patterns. The header is parsed first; if the `COMPRESSED` feature
/// bit is set, the body is zlib-inflated before trie traversal.
///
/// Inflation is capped at [`MAX_INFLATED`] bytes. A `.sig` whose
/// compressed body would exceed that limit returns
/// [`Error::InflateBomb`] without ever materialising the output —
/// defence against zlib decompression bombs on untrusted input.
pub fn parse(input: &[u8]) -> Result<Vec<Pattern>> {
    let header = parse_header(input)?;

    // Body bytes — either the trailing slice of `input`, or the
    // inflated result. We keep both possibilities behind a `Cow`-
    // style local owned `Vec` to avoid a borrow split.
    let body_owned: Vec<u8>;
    let body: &[u8] = if header.is_compressed() {
        let compressed = &input[header.header_len..];
        body_owned =
            miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(compressed, MAX_INFLATED)
                .map_err(|e| {
                    // `TINFLStatus::HasMoreOutput` is the specific status the
                    // limit-form of the API returns when the cap is hit. Other
                    // statuses (CRC mismatch, bad header, truncated stream)
                    // are wire-corruption errors — surface them under Inflate.
                    use miniz_oxide::inflate::TINFLStatus;
                    if e.status == TINFLStatus::HasMoreOutput {
                        Error::InflateBomb {
                            limit: MAX_INFLATED,
                        }
                    } else {
                        Error::Inflate(format!("{:?}", e.status))
                    }
                })?;
        &body_owned
    } else {
        &input[header.header_len..]
    };

    let mut cur = Cursor::new(body);
    let mut prefix = Vec::with_capacity(header.pattern_size as usize);
    let mut out = Vec::new();
    parse_node(&mut cur, &header, &mut prefix, &mut out, 0)?;
    // We don't enforce zero trailing bytes — some `.sig` files have a
    // few bytes of padding that aren't part of the formal grammar
    // (probably alignment in the FLAIR writer). If we ever want
    // strict mode, swap this back to an error.
    Ok(out)
}

// -----------------------------------------------------------------
// Tests
// -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vint16_one_byte() {
        let data = [0x05u8];
        let mut cur = Cursor::new(&data);
        assert_eq!(vint16(&mut cur).unwrap(), 0x05);
        assert_eq!(cur.pos, 1);
    }

    #[test]
    fn vint16_two_bytes() {
        // 0x80 sets continuation; value = ((0x80 & 0x7F) << 8) | 0x42 = 0x42.
        // Use 0x81 0x42 → ((0x81 & 0x7F) << 8) | 0x42 = 0x142.
        let data = [0x81u8, 0x42];
        let mut cur = Cursor::new(&data);
        assert_eq!(vint16(&mut cur).unwrap(), 0x142);
        assert_eq!(cur.pos, 2);
    }

    #[test]
    fn vint32_one_byte() {
        let data = [0x7Fu8];
        let mut cur = Cursor::new(&data);
        assert_eq!(vint32(&mut cur).unwrap(), 0x7F);
    }

    #[test]
    fn vint32_two_bytes() {
        // 10xxxxxx form: 0x81 0xAB → ((0x81 & 0x7F) << 8) | 0xAB = 0x1AB.
        let data = [0x81u8, 0xAB];
        let mut cur = Cursor::new(&data);
        assert_eq!(vint32(&mut cur).unwrap(), 0x1AB);
    }

    #[test]
    fn vint32_four_bytes() {
        // 110xxxxx form: 0xC1 0x02 0x03 0x04 →
        //   (((0xC1 & 0x3F) << 8) | 0x02) << 16 | (0x0304)
        //   = ((0x01 << 8) | 0x02) << 16 | 0x0304
        //   = 0x0102 << 16 | 0x0304 = 0x01020304
        let data = [0xC1u8, 0x02, 0x03, 0x04];
        let mut cur = Cursor::new(&data);
        assert_eq!(vint32(&mut cur).unwrap(), 0x01020304);
    }

    #[test]
    fn vint32_five_bytes() {
        // 111xxxxx form: 0xE0 + 4 BE bytes.
        let data = [0xE0u8, 0x12, 0x34, 0x56, 0x78];
        let mut cur = Cursor::new(&data);
        assert_eq!(vint32(&mut cur).unwrap(), 0x12345678);
    }

    #[test]
    fn truncated_vint16_errors() {
        // Continuation bit set but no follow-up byte.
        let data = [0x80u8];
        let mut cur = Cursor::new(&data);
        assert!(vint16(&mut cur).is_err());
    }

    #[test]
    fn bad_magic_rejected() {
        let bad = b"NOTSIGfoo".to_vec();
        let err = parse(&bad).unwrap_err();
        assert!(matches!(err, Error::BadMagic(_)));
    }

    #[test]
    fn unsupported_version_rejected() {
        // IDASGN + version 11 = unsupported. Pad enough bytes that
        // parse_header reaches the version-range check before any
        // truncation check fires.
        let mut buf = b"IDASGN".to_vec();
        buf.push(11);
        buf.resize(buf.len() + 0x40, 0);
        let err = parse(&buf).unwrap_err();
        assert!(matches!(err, Error::UnsupportedVersion(11)));
    }

    #[test]
    fn truncated_header_errors() {
        // Just the magic — definitely too short.
        let err = parse(b"IDASGN").unwrap_err();
        assert!(matches!(err, Error::Truncated(_, _)));
    }

    // -----------------------------------------------------------
    // 0.1.1 hardening tests: confirm the new validation paths fire
    // on the inputs they're meant to reject. We construct minimal
    // synthetic bytes that exercise one guard each.
    // -----------------------------------------------------------

    #[test]
    fn bound_count_rejects_oversize() {
        let buf = [0u8; 16];
        let cur = Cursor { buf: &buf, pos: 0 };
        // Hard ceiling: 1 << 20. Anything above that, regardless of
        // remaining, fails.
        let err = bound_count(2_000_000, &cur).unwrap_err();
        assert!(matches!(err, Error::ImplausibleCount { .. }));
    }

    #[test]
    fn bound_count_rejects_more_than_remaining() {
        let buf = [0u8; 4];
        let cur = Cursor { buf: &buf, pos: 0 };
        // Below the hard ceiling but more than `cur.remaining()`.
        let err = bound_count(100, &cur).unwrap_err();
        assert!(matches!(err, Error::ImplausibleCount { .. }));
    }

    #[test]
    fn bound_count_accepts_in_range() {
        let buf = [0u8; 64];
        let cur = Cursor { buf: &buf, pos: 0 };
        assert_eq!(bound_count(8, &cur).unwrap(), 8);
        assert_eq!(bound_count(0, &cur).unwrap(), 0);
    }
}
