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
//! The body is a recursive trie. The parser walks it, accumulating a
//! head prefix as it descends, and emits one `PatternData` per
//! "module" (function) at each leaf. Names and tail-byte
//! discriminators flow into the [`FlirtSetBuilder`]'s arena.
//!
//! `.sig` discriminators land in `PatternData::tail_bytes_off`
//! (discrete offset/value pairs), not in `tail_off` (which is the
//! `.pat` contiguous form).

use crate::error::{Error, Result};
use crate::types::{FlirtSet, FlirtSetBuilder, NK_LOCAL, NK_PUBLIC, NK_REFERENCE, PatternData};

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
// DoS-defence caps
// -----------------------------------------------------------------

/// Maximum bytes the decompressed body may occupy. Defence against
/// zlib decompression bombs.
pub const MAX_INFLATED: usize = 256 * 1024 * 1024;

/// Hard depth cap on `.sig` trie recursion.
const MAX_TRIE_DEPTH: u32 = 256;

/// Hard ceiling on any single wire-encoded count.
const MAX_COUNT: usize = 1 << 20;

#[derive(Debug, Clone, Copy)]
struct Header {
    version: u8,
    pattern_size: u16,
    features: u16,
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

fn vint16(cur: &mut Cursor<'_>) -> Result<u16> {
    let high = cur.u8()?;
    if (high & 0x80) == 0 {
        return Ok(high as u16);
    }
    let low = cur.u8()?;
    Ok(((high as u16 & 0x7F) << 8) | low as u16)
}

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
        // 4-byte form `110xxxxx`: bit 5 always 0, mask 0x1F.
        let mid = cur.u8()? as u32;
        let low = cur.be_u16()? as u32;
        return Ok((((b as u32 & 0x1F) << 8 | mid) << 16) | low);
    }
    let hi = cur.be_u16()? as u32;
    let lo = cur.be_u16()? as u32;
    Ok((hi << 16) | lo)
}

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
    let magic = cur.take(6)?;
    if magic != MAGIC {
        let mut got = [0u8; 6];
        got.copy_from_slice(magic);
        return Err(Error::BadMagic(got));
    }
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

// Parsing flags
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

/// One slot in the prefix accumulator. `Wildcard(b)` carries an
/// arbitrary stand-in byte (FLIRT wildcards have no constrained
/// value); the bit position in the eventual `leading_wildmask` is
/// what marks it.
#[derive(Debug, Clone, Copy)]
enum PrefixByte {
    Byte(u8),
    Wildcard,
}

fn parse_node(
    cur: &mut Cursor<'_>,
    header: &Header,
    prefix: &mut Vec<PrefixByte>,
    builder: &mut FlirtSetBuilder,
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
        return parse_leaf(cur, header, prefix, builder);
    }
    let child_count = bound_count(child_count as u64, cur)?;

    for _ in 0..child_count {
        let length: u16 = if header.version < 10 {
            cur.u8()? as u16
        } else {
            vint16(cur)?
        };
        let mask = wildcard_mask(cur, length)?;
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

        let prev_len = prefix.len();
        let mut j: usize = literal_count as usize;
        for i in 0..length as u64 {
            if (mask & (1 << i)) != 0 {
                prefix.push(PrefixByte::Wildcard);
            } else {
                prefix.push(PrefixByte::Byte(literals[j - 1]));
                j -= 1;
            }
        }
        prefix[prev_len..].reverse();

        parse_node(cur, header, prefix, builder, depth + 1)?;

        prefix.truncate(prev_len);
    }

    Ok(())
}

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

fn parse_leaf(
    cur: &mut Cursor<'_>,
    header: &Header,
    prefix: &[PrefixByte],
    builder: &mut FlirtSetBuilder,
) -> Result<()> {
    // Materialise the accumulated prefix into the arena ONCE per
    // leaf. Every module under this leaf shares the same head bytes
    // and wildcard mask, so the alloc is amortised.
    let (leading_bytes, leading_mask) = materialise_prefix(prefix);
    let leading_off = builder.alloc(&leading_bytes)?;
    let leading_len = leading_bytes.len() as u8;

    loop {
        let crc_len = cur.u8()?;
        let crc16 = cur.be_u16()?;

        let last_pflags: u8 = loop {
            let function_size = vword(cur, header.version)?;

            // Name parsing. Public names land in the arena directly;
            // names_off captures the offset of the first record.
            // Reference names are STAGED first (see below) so they
            // can be appended to the same contiguous run after we've
            // consumed the wire-mandated tail_bytes section — without
            // that staging, tail_byte records would sit between the
            // public names and the references, breaking NameIter's
            // contiguous-records assumption.
            let mut names_off: u32 = 0;
            let mut names_count: u16 = 0;
            let mut current_offset: i64 = 0;

            let pflags: u8 = loop {
                let (kind, new_offset, name_bytes, flags) =
                    parse_name(cur, header.version, current_offset)?;
                current_offset = new_offset;
                let name = std::str::from_utf8(name_bytes)?;
                let off = builder.alloc_name(kind, new_offset, name)?;
                if names_count == 0 {
                    names_off = off;
                }
                names_count = names_count.checked_add(1).ok_or(Error::TooManyNames {
                    pos: cur.pos,
                    max: u16::MAX,
                })?;
                if (flags & PFLAG_MORE_PUBLIC_NAMES) == 0 {
                    break flags;
                }
            };

            // Wire-format: tail-byte discriminators come FIRST on the
            // wire, then references. Arena-format: references must be
            // contiguous with the public names (NameIter walks one
            // back-to-back run). So we *stage* tail-byte values now,
            // alloc references next, then flush the staged tail
            // bytes into a contiguous run of their own.
            let mut staged_tail_bytes: Vec<(u32, u8)> = Vec::new();
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
                    if off > u32::MAX as u64 {
                        return Err(Error::VarintOverflow(cur.pos));
                    }
                    staged_tail_bytes.push((off as u32, val));
                }
            }

            // References → arena-allocated as Reference names,
            // immediately after the public names so the whole names
            // run stays contiguous.
            if (pflags & PFLAG_REFERENCED_FUNCTIONS) != 0 {
                let count_raw = if header.version < 8 {
                    1u64
                } else {
                    vword(cur, header.version)?
                };
                let count = bound_count(count_raw, cur)?;
                for _ in 0..count {
                    let off = vword(cur, header.version)?;
                    if off > u32::MAX as u64 {
                        return Err(Error::VarintOverflow(cur.pos));
                    }
                    let size_byte = cur.u8()?;
                    let size: u16 = if size_byte == 0 {
                        vint16(cur)?
                    } else {
                        size_byte as u16
                    };
                    let name_bytes = cur.take(size as usize)?;
                    let name = std::str::from_utf8(name_bytes)?;
                    let rec_off = builder.alloc_name(NK_REFERENCE, off as i64, name)?;
                    if names_count == 0 {
                        names_off = rec_off;
                    }
                    names_count = names_count.checked_add(1).ok_or(Error::TooManyNames {
                        pos: cur.pos,
                        max: u16::MAX,
                    })?;
                }
            }

            // Now flush the staged tail-byte records as their own
            // contiguous run. `tail_bytes_off` points at the first
            // record.
            let mut tail_bytes_off: u32 = 0;
            let mut tail_bytes_count: u32 = 0;
            for (i, (tb_off, tb_val)) in staged_tail_bytes.iter().enumerate() {
                let rec_off = builder.alloc_tail_byte(*tb_off, *tb_val)?;
                if i == 0 {
                    tail_bytes_off = rec_off;
                }
                tail_bytes_count =
                    tail_bytes_count
                        .checked_add(1)
                        .ok_or(Error::TooManyTailBytes {
                            pos: cur.pos,
                            max: u32::MAX,
                        })?;
            }

            if function_size > u32::MAX as u64 {
                return Err(Error::ModuleLenOverflow {
                    pos: cur.pos,
                    size: function_size,
                });
            }

            builder.push_pattern(PatternData {
                leading_off,
                leading_len,
                leading_wildmask: leading_mask,
                crc_len,
                crc16,
                module_len: function_size as u32,
                names_off,
                names_count,
                tail_off: 0,
                tail_len: 0,
                tail_wildmask: 0,
                tail_bytes_off,
                tail_bytes_count,
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

/// Walk the prefix vec and produce (concrete bytes, wildcard mask).
/// The byte slice is `prefix.len()` bytes long; wildcards land as 0.
fn materialise_prefix(prefix: &[PrefixByte]) -> (Vec<u8>, u64) {
    let mut bytes = Vec::with_capacity(prefix.len());
    let mut mask: u64 = 0;
    for (i, pb) in prefix.iter().enumerate() {
        match pb {
            PrefixByte::Byte(b) => bytes.push(*b),
            PrefixByte::Wildcard => {
                bytes.push(0);
                if i < 64 {
                    mask |= 1u64 << i;
                }
            }
        }
    }
    (bytes, mask)
}

/// Parse one name + its trailing parsing-flags byte.
///
/// Returns `(kind, updated_offset, name_bytes, parsing_flags)`. We
/// return the raw bytes (not a `&str` or `String`) so the caller can
/// alloc them into the arena exactly once.
fn parse_name<'a>(
    cur: &mut Cursor<'a>,
    version: u8,
    base_offset: i64,
) -> Result<(u8, i64, &'a [u8], u8)> {
    let delta = vword(cur, version)?;
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

    let start = cur.pos;
    while cur.peek_u8()? >= 0x20 {
        cur.pos += 1;
    }
    let name_bytes = &cur.buf[start..cur.pos];
    // Validate UTF-8 here (early) so the caller can `str::from_utf8`
    // without re-validating.
    std::str::from_utf8(name_bytes)?;

    let pflags = cur.u8()?;
    if (pflags & !PFLAG_ALL) != 0 {
        return Err(Error::BadParsingFlags(pflags, cur.pos));
    }

    let kind = if (name_flags & NFLAG_LOCAL) != 0 {
        NK_LOCAL
    } else {
        NK_PUBLIC
    };
    Ok((kind, offset, name_bytes, pflags))
}

// -----------------------------------------------------------------
// Public entry point + builder hook
// -----------------------------------------------------------------

/// Parse a complete `.sig` file (compressed or not) into a fully-
/// built [`FlirtSet`].
///
/// To merge multiple `.sig`/`.pat` sources into one matcher, use
/// [`FlirtSetBuilder`] directly and call
/// [`FlirtSetBuilder::add_sig`] for each input.
pub fn parse(input: &[u8]) -> Result<FlirtSet> {
    let mut builder = FlirtSetBuilder::new();
    append(&mut builder, input)?;
    builder.build()
}

/// Internal: parse `input` and push its patterns onto `builder`'s
/// running arena. Returns the count of patterns appended.
pub(crate) fn append(builder: &mut FlirtSetBuilder, input: &[u8]) -> Result<usize> {
    let before = builder.patterns.len();
    let header = parse_header(input)?;

    let body_owned: Vec<u8>;
    let body: &[u8] = if header.is_compressed() {
        let compressed = &input[header.header_len..];
        body_owned =
            miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(compressed, MAX_INFLATED)
                .map_err(|e| {
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
    let mut prefix: Vec<PrefixByte> = Vec::with_capacity(header.pattern_size as usize);
    parse_node(&mut cur, &header, &mut prefix, builder, 0)?;
    Ok(builder.patterns.len() - before)
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
        let data = [0x81u8, 0xAB];
        let mut cur = Cursor::new(&data);
        assert_eq!(vint32(&mut cur).unwrap(), 0x1AB);
    }

    #[test]
    fn vint32_four_bytes() {
        let data = [0xC1u8, 0x02, 0x03, 0x04];
        let mut cur = Cursor::new(&data);
        assert_eq!(vint32(&mut cur).unwrap(), 0x01020304);
    }

    #[test]
    fn vint32_five_bytes() {
        let data = [0xE0u8, 0x12, 0x34, 0x56, 0x78];
        let mut cur = Cursor::new(&data);
        assert_eq!(vint32(&mut cur).unwrap(), 0x12345678);
    }

    #[test]
    fn truncated_vint16_errors() {
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
        let mut buf = b"IDASGN".to_vec();
        buf.push(11);
        buf.resize(buf.len() + 0x40, 0);
        let err = parse(&buf).unwrap_err();
        assert!(matches!(err, Error::UnsupportedVersion(11)));
    }

    #[test]
    fn truncated_header_errors() {
        let err = parse(b"IDASGN").unwrap_err();
        assert!(matches!(err, Error::Truncated(_, _)));
    }

    #[test]
    fn bound_count_rejects_oversize() {
        let buf = [0u8; 16];
        let cur = Cursor { buf: &buf, pos: 0 };
        let err = bound_count(2_000_000, &cur).unwrap_err();
        assert!(matches!(err, Error::ImplausibleCount { .. }));
    }

    #[test]
    fn bound_count_rejects_more_than_remaining() {
        let buf = [0u8; 4];
        let cur = Cursor { buf: &buf, pos: 0 };
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
