//! `.pat` (FLAIR pattern) text-format parser.
//!
//! Format reference: Hex-Rays' FLAIR utility documentation. One line
//! per signature, whitespace-separated fields:
//!
//! ```text
//! <head 64 chars>  <crc_len 2>  <crc16 4>  <mod_len 4>  <names...>  [tail]
//! ```
//!
//! Where:
//!
//! - `<head>` is 64 characters — either pairs of uppercase hex digits
//!   or `..` for a wildcard byte. Encodes the first 32 bytes of the
//!   function.
//! - `<crc_len>` is a 2-hex-digit count of bytes following the head
//!   that are covered by the CRC.
//! - `<crc16>` is a 4-hex-digit CRC-16/X-25 of those bytes.
//! - `<mod_len>` is the 4-hex-digit total length of the original
//!   library function (informational; not used at match time).
//! - `<names>` is one or more occurrences of either
//!   `:OFFSET[@] NAME` (a public, or `@`-tagged static, name at that
//!   byte offset inside the function) or `^OFFSET NAME` (a reference
//!   to another library symbol at that offset, used for collision
//!   disambiguation).
//! - `[tail]` is an optional pattern, same head encoding (hex pairs
//!   or `..`), appended for disambiguation when head+CRC collide
//!   between signatures.
//!
//! A line of three dashes `---` marks end of file. Lines starting
//! with `#` or `;` are comments.

use crate::error::{Error, Result};
use crate::types::{FlirtSet, FlirtSetBuilder, NK_LOCAL, NK_PUBLIC, NK_REFERENCE, PatternData};

/// Parse a `.pat` document into a fully-built [`FlirtSet`].
///
/// To merge multiple `.pat`/`.sig` sources into one matcher, use
/// [`FlirtSetBuilder`] directly and call [`FlirtSetBuilder::add_pat`]
/// for each input.
pub fn parse(text: &str) -> Result<FlirtSet> {
    let mut builder = FlirtSetBuilder::new();
    append(&mut builder, text)?;
    builder.build()
}

/// 0.2.2: parse a gzip-wrapped `.pat.gz` document into a fully-built
/// [`FlirtSet`]. FLARE distributes many `.pat` files as `.pat.gz` to
/// save bandwidth; consumers used to have to `gunzip` ahead of time.
///
/// Pure-Rust: gz framing is stripped manually (header + trailer per
/// RFC 1952); the deflate stream is inflated via `miniz_oxide`. No C
/// dependency, no `flate2`.
///
/// For incremental loading into a shared builder, use
/// [`FlirtSetBuilder::add_pat_gz`].
pub fn parse_gz(bytes: &[u8]) -> Result<FlirtSet> {
    let mut builder = FlirtSetBuilder::new();
    append_gz(&mut builder, bytes)?;
    builder.build()
}

/// Internal: gunzip `bytes` and append the resulting `.pat` text to
/// `builder`'s arena. Returns the count of patterns appended.
pub(crate) fn append_gz(builder: &mut FlirtSetBuilder, bytes: &[u8]) -> Result<usize> {
    let deflate = strip_gz_header(bytes)?;
    let decompressed = miniz_oxide::inflate::decompress_to_vec(deflate)
        .map_err(|e| Error::PatGz(format!("inflate failed: {:?}", e.status)))?;
    let text = std::str::from_utf8(&decompressed)
        .map_err(|e| Error::PatGz(format!("decompressed body not utf-8: {e}")))?;
    append(builder, text)
}

/// Strip a gzip header (RFC 1952) and the trailing CRC32 + ISIZE
/// footer (8 bytes), returning the inner deflate stream.
///
/// Vendor-shipped FLARE `.pat.gz` files use the minimal header (no
/// FEXTRA / FNAME / FCOMMENT / FHCRC), but the optional fields are
/// handled here for robustness against community sources.
fn strip_gz_header(input: &[u8]) -> Result<&[u8]> {
    // Minimum gz size: 10-byte header + 8-byte trailer + at least an
    // empty deflate block (2 bytes).
    if input.len() < 20 {
        return Err(Error::PatGz(format!(
            "input too short for gzip framing: {} bytes",
            input.len()
        )));
    }
    if input[0] != 0x1f || input[1] != 0x8b {
        return Err(Error::PatGz(format!(
            "bad gzip magic: 0x{:02x} 0x{:02x} (expected 0x1f 0x8b)",
            input[0], input[1]
        )));
    }
    if input[2] != 8 {
        return Err(Error::PatGz(format!(
            "unsupported compression method {} (only deflate=8 supported)",
            input[2]
        )));
    }
    let flg = input[3];
    let mut off: usize = 10;

    // FEXTRA: 2-byte XLEN + XLEN extra bytes
    if flg & 0x04 != 0 {
        if off + 2 > input.len() {
            return Err(Error::PatGz("truncated FEXTRA length".into()));
        }
        let xlen = u16::from_le_bytes([input[off], input[off + 1]]) as usize;
        off = off
            .checked_add(2)
            .and_then(|o| o.checked_add(xlen))
            .ok_or_else(|| Error::PatGz("FEXTRA overflow".into()))?;
        if off > input.len() {
            return Err(Error::PatGz("truncated FEXTRA body".into()));
        }
    }
    // FNAME: null-terminated original filename
    if flg & 0x08 != 0 {
        while off < input.len() && input[off] != 0 {
            off += 1;
        }
        if off >= input.len() {
            return Err(Error::PatGz("truncated FNAME (no null)".into()));
        }
        off += 1; // skip the null
    }
    // FCOMMENT: null-terminated comment
    if flg & 0x10 != 0 {
        while off < input.len() && input[off] != 0 {
            off += 1;
        }
        if off >= input.len() {
            return Err(Error::PatGz("truncated FCOMMENT (no null)".into()));
        }
        off += 1;
    }
    // FHCRC: 2-byte header CRC16 (we don't verify — non-critical for
    // signature-corpus use)
    if flg & 0x02 != 0 {
        if off + 2 > input.len() {
            return Err(Error::PatGz("truncated FHCRC".into()));
        }
        off += 2;
    }

    // Trailer is 8 bytes (CRC32 + ISIZE). miniz_oxide stops at end of
    // deflate stream and tolerates trailing bytes, but trimming makes
    // the contract explicit and lets us validate framing length.
    if input.len() < off + 8 {
        return Err(Error::PatGz(
            "no room for deflate body after header + trailer".into(),
        ));
    }
    Ok(&input[off..input.len() - 8])
}

/// Internal: parse `text` and push its patterns onto `builder`'s
/// running arena. Returns the count of patterns appended.
pub(crate) fn append(builder: &mut FlirtSetBuilder, text: &str) -> Result<usize> {
    let mut count = 0;
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim_end_matches(['\r']);
        if line.is_empty() {
            continue;
        }
        // Terminator. Everything after `---` is ignored.
        if line.starts_with("---") {
            break;
        }
        // Comment conventions: `;` (classic FLAIR), `#` (FLARE
        // header lines like "# FLIRT signature for ...").
        if line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        // Continuation lines (leading whitespace) are not yet
        // supported. We haven't seen them in the FLARE / FLIRTDB
        // corpora capa-rs ships; if a real file needs them we'll
        // add a state machine.
        if line.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }
        parse_line_into(builder, line, idx + 1)?;
        count += 1;
    }
    Ok(count)
}

/// Parse one `.pat` line and push the resulting `PatternData` onto
/// `builder`. All hex / wildcard bytes flow into the builder's arena
/// in the layout documented on `crate::types::PatternData`.
fn parse_line_into(builder: &mut FlirtSetBuilder, line: &str, line_no: usize) -> Result<()> {
    let mut toks = line.split_ascii_whitespace();

    // 1. Head pattern: 32 bytes encoded as 64 hex/wildcard chars.
    let head_tok = toks
        .next()
        .ok_or(Error::BadPatLine(line_no, "missing head pattern"))?;
    if head_tok.len() != 64 {
        return Err(Error::BadPatLine(line_no, "head pattern not 64 chars"));
    }
    let (head_bytes, head_mask) = decode_pattern_str(head_tok, line_no)?;
    let leading_off = builder.alloc(&head_bytes)?;
    let leading_len = head_bytes.len() as u8;

    // 2-4. CRC length, CRC16, module length.
    let crc_len = parse_hex_u8(
        toks.next()
            .ok_or(Error::BadPatLine(line_no, "missing crc_len"))?,
        line_no,
    )?;
    let crc16 = parse_hex_u16(
        toks.next()
            .ok_or(Error::BadPatLine(line_no, "missing crc16"))?,
        line_no,
    )?;
    let module_len = parse_hex_u16(
        toks.next()
            .ok_or(Error::BadPatLine(line_no, "missing module_len"))?,
        line_no,
    )? as u32;

    // 5+. Names + references, then an optional tail pattern.
    //
    // We need to know `names_off` (offset of the FIRST name record).
    // Track it as the offset of the first allocation; subsequent
    // names extend the contiguous block. Bytes between are nothing —
    // alloc_name pushes records back-to-back.
    // `.pat` has a simpler arena interleaving than `.sig`: all
    // names (public + reference, in source order) come BEFORE the
    // optional tail token, so the contiguous-names invariant holds
    // naturally. We allocate names directly, then (if present) the
    // tail pattern.
    let mut names_off: u32 = 0;
    let mut names_count: u16 = 0;
    let mut tail_off: u32 = 0;
    let mut tail_len: u8 = 0;
    let mut tail_mask: u64 = 0;

    while let Some(tok) = toks.next() {
        if let Some(rest) = tok.strip_prefix(':') {
            let (offset, is_static) = parse_name_offset(rest, line_no)?;
            let name_str = toks
                .next()
                .ok_or(Error::BadPatLine(line_no, "missing name after `:OFFSET`"))?;
            let kind = if is_static { NK_LOCAL } else { NK_PUBLIC };
            let off = builder.alloc_name(kind, offset, name_str)?;
            if names_count == 0 {
                names_off = off;
            }
            names_count = names_count.checked_add(1).ok_or(Error::TooManyNames {
                pos: 0,
                max: u16::MAX,
            })?;
        } else if let Some(rest) = tok.strip_prefix('^') {
            let (offset, _) = parse_name_offset(rest, line_no)?;
            let name_str = toks
                .next()
                .ok_or(Error::BadPatLine(line_no, "missing name after `^OFFSET`"))?;
            let off = builder.alloc_name(NK_REFERENCE, offset, name_str)?;
            if names_count == 0 {
                names_off = off;
            }
            names_count = names_count.checked_add(1).ok_or(Error::TooManyNames {
                pos: 0,
                max: u16::MAX,
            })?;
        } else {
            // Tail pattern (last token).
            let (bytes, mask) = decode_pattern_str(tok, line_no)?;
            tail_off = builder.alloc(&bytes)?;
            tail_len = bytes.len() as u8;
            tail_mask = mask;
            if toks.next().is_some() {
                return Err(Error::BadPatLine(line_no, "unexpected token after tail"));
            }
            break;
        }
    }

    builder.push_pattern(PatternData {
        leading_off,
        leading_len,
        leading_wildmask: head_mask,
        crc_len,
        crc16,
        module_len,
        names_off,
        names_count,
        tail_off,
        tail_len,
        tail_wildmask: tail_mask,
        tail_bytes_off: 0,
        tail_bytes_count: 0,
    });
    Ok(())
}

/// Parse the `OFFSET[@]` substring after `:` or `^`. Returns
/// (offset, is_static_flag).
fn parse_name_offset(s: &str, line_no: usize) -> Result<(i64, bool)> {
    let (hex, is_static) = if let Some(stripped) = s.strip_suffix('@') {
        (stripped, true)
    } else {
        (s, false)
    };
    let off = i64::from_str_radix(hex, 16)
        .map_err(|_| Error::BadPatLine(line_no, "bad hex offset after `:` / `^`"))?;
    Ok((off, is_static))
}

/// Decode a hex+wildcard pattern token into raw bytes + a wildcard
/// bitmask (bit `i` set ⇒ position `i` is `..`). The byte at a
/// wildcard position is irrelevant to matching; we leave 0x00.
///
/// FLIRT heads are 32 bytes (64 chars) so the mask fits in a u64.
/// For longer tails we cap the mask at 64 positions — patterns longer
/// than 64 bytes would lose wildcard info past position 63, but the
/// FLAIR format itself doesn't produce them.
fn decode_pattern_str(s: &str, line_no: usize) -> Result<(Vec<u8>, u64)> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::BadPatLine(line_no, "pattern has odd char count"));
    }
    let n = bytes.len() / 2;
    let mut out = Vec::with_capacity(n);
    let mut mask: u64 = 0;
    let mut i = 0;
    let mut pos: usize = 0;
    while i < bytes.len() {
        let hi = bytes[i];
        let lo = bytes[i + 1];
        if hi == b'.' && lo == b'.' {
            if pos < 64 {
                mask |= 1u64 << pos;
            }
            out.push(0);
        } else {
            let h = hex_nibble(hi).ok_or(Error::BadHex(i, [hi, lo]))?;
            let l = hex_nibble(lo).ok_or(Error::BadHex(i, [hi, lo]))?;
            out.push((h << 4) | l);
        }
        i += 2;
        pos += 1;
    }
    Ok((out, mask))
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn parse_hex_u8(s: &str, line_no: usize) -> Result<u8> {
    if s.len() != 2 {
        return Err(Error::BadPatLine(line_no, "expected 2-hex u8 field"));
    }
    u8::from_str_radix(s, 16).map_err(|_| Error::BadPatLine(line_no, "bad hex u8 field"))
}

fn parse_hex_u16(s: &str, line_no: usize) -> Result<u16> {
    if s.len() != 4 {
        return Err(Error::BadPatLine(line_no, "expected 4-hex u16 field"));
    }
    u16::from_str_radix(s, 16).map_err(|_| Error::BadPatLine(line_no, "bad hex u16 field"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Symbol;

    const ONE_LINE: &str = "55564883EC48488D6C24204889CE0F1002488D4D0048895548488D55100F1102 02 ABB7 0040 :0000 __tanq ^0022 __libm___tanq_chosen_core_func ........0F1045004889F00F1106488D65285E5DC3660F1F840000000000";

    #[test]
    fn parses_one_pattern() {
        let set = parse(ONE_LINE).unwrap();
        assert_eq!(set.len(), 1);
        let pat = set.pattern(0);

        // Head: 64 chars → 32 bytes. First byte is 0x55, last byte
        // before the CRC window is 0x02. No wildcards in the head.
        assert_eq!(pat.leading().len(), 32);
        assert_eq!(pat.leading()[0], 0x55);
        assert_eq!(pat.leading()[31], 0x02);
        assert!(!pat.is_wildcard(0));
        assert!(!pat.is_wildcard(31));

        assert_eq!(pat.crc_len(), 0x02);
        assert_eq!(pat.crc16(), 0xABB7);
        assert_eq!(pat.module_len(), 0x0040);

        // 1 public name + 1 reference.
        let names: Vec<_> = pat.names().collect();
        assert_eq!(names.len(), 2);
        assert!(matches!(
            names[0],
            Symbol::Public(n) if n.offset == 0 && n.name == "__tanq"
        ));
        assert!(matches!(
            names[1],
            Symbol::Reference(n)
                if n.offset == 0x22 && n.name == "__libm___tanq_chosen_core_func"
        ));

        // Tail starts with 4 wildcards (`........`) then 0x0F 0x10 0x45...
        assert!(pat.is_tail_wildcard(0));
        assert!(pat.is_tail_wildcard(3));
        assert_eq!(pat.tail()[4], 0x0F);
    }

    #[test]
    fn skips_terminator_and_comments() {
        let doc = "# header comment\n; classic FLAIR comment\n---\nbogus line after terminator";
        let set = parse(doc).unwrap();
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn parses_static_at_flag() {
        let line = "55565741544883EC48488D6C24204989CC48630D........488D05........48 0B 5813 00B0 :0000@ __libm___tanq_dispatch_table_init";
        let set = parse(line).unwrap();
        assert_eq!(set.len(), 1);
        let pat = set.pattern(0);
        let first = pat.names().next().unwrap();
        assert!(matches!(
            first,
            Symbol::Local(n) if n.offset == 0 && n.name == "__libm___tanq_dispatch_table_init"
        ));
    }

    #[test]
    fn parses_empty_tail() {
        let line = "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 __libm_flt_rounds ^000B fegetround";
        let set = parse(line).unwrap();
        assert_eq!(set.pattern(0).tail().len(), 0);
    }

    #[test]
    fn rejects_odd_length_pattern() {
        let line = "555 02 ABB7 0040 :0000 foo";
        assert!(parse(line).is_err());
    }
}
