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
use crate::types::{Name, Pattern, PatternByte, Symbol};
use smallvec::SmallVec;

/// Parse a `.pat` document into a list of [`Pattern`]s.
///
/// Best-effort: malformed lines are returned as errors immediately
/// (no partial-load semantics) — callers that want lenient loading
/// can split the input by line and call this per-line. The whole-
/// file path is preferred because it pre-allocates the result Vec.
pub fn parse(text: &str) -> Result<Vec<Pattern>> {
    let mut out = Vec::new();
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
        out.push(parse_line(line, idx + 1)?);
    }
    Ok(out)
}

fn parse_line(line: &str, line_no: usize) -> Result<Pattern> {
    let mut toks = line.split_ascii_whitespace();

    // 1. Head pattern: 32 bytes encoded as 64 hex/wildcard chars.
    let head_tok = toks
        .next()
        .ok_or(Error::BadPatLine(line_no, "missing head pattern"))?;
    if head_tok.len() != 64 {
        return Err(Error::BadPatLine(line_no, "head pattern not 64 chars"));
    }
    let leading = parse_pattern_str(head_tok, line_no)?;

    // 2-4. CRC length, CRC16, module length. All 16-bit fields
    // encoded as uppercase hex.
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

    // 5+. Names + references, then an optional tail pattern. We
    // keep reading until we hit a token that doesn't start with
    // `:` or `^` — that token is either the tail or invalid.
    let mut names: SmallVec<[Symbol; 2]> = SmallVec::new();
    let mut tail: Vec<PatternByte> = Vec::new();

    while let Some(tok) = toks.next() {
        if let Some(rest) = tok.strip_prefix(':') {
            // `:OFFSET` or `:OFFSET@`.
            let (offset, is_static) = parse_name_offset(rest, line_no)?;
            let name_str = toks
                .next()
                .ok_or(Error::BadPatLine(line_no, "missing name after `:OFFSET`"))?;
            let n = Name {
                offset,
                name: name_str.to_string(),
            };
            // FLAIR's `@` flag marks the symbol as static / collision-
            // local; we map that to `Symbol::Local`. Without `@`,
            // it's the canonical public entry point.
            names.push(if is_static {
                Symbol::Local(n)
            } else {
                Symbol::Public(n)
            });
        } else if let Some(rest) = tok.strip_prefix('^') {
            // `^OFFSET NAME` — reference to an external symbol used
            // for disambiguating callee names.
            let (offset, _) = parse_name_offset(rest, line_no)?;
            let name_str = toks
                .next()
                .ok_or(Error::BadPatLine(line_no, "missing name after `^OFFSET`"))?;
            names.push(Symbol::Reference(Name {
                offset,
                name: name_str.to_string(),
            }));
        } else {
            // Anything else at this point is the tail pattern. It
            // uses the same hex+wildcard encoding as the head, but
            // its length is variable (whatever was left of the line
            // beyond head + CRC window in the original lib function).
            tail = parse_pattern_str(tok, line_no)?;
            // Tail is always the last token; if more follow it's a
            // malformed line.
            if toks.next().is_some() {
                return Err(Error::BadPatLine(line_no, "unexpected token after tail"));
            }
            break;
        }
    }

    Ok(Pattern {
        leading,
        crc_len,
        crc16,
        module_len,
        names,
        tail,
        tail_bytes: Vec::new(),
    })
}

/// Parse the `OFFSET[@]` substring after `:` or `^`. Returns
/// (offset, is_static_flag).
fn parse_name_offset(s: &str, line_no: usize) -> Result<(i64, bool)> {
    // The `@` suffix (FLAIR's "static" or "weak collision" flag) is
    // optional. Strip it before hex-decoding the offset.
    let (hex, is_static) = if let Some(stripped) = s.strip_suffix('@') {
        (stripped, true)
    } else {
        (s, false)
    };
    let off = i64::from_str_radix(hex, 16)
        .map_err(|_| Error::BadPatLine(line_no, "bad hex offset after `:` / `^`"))?;
    Ok((off, is_static))
}

/// Parse a pattern token (sequence of hex pairs and `..` wildcards)
/// into a `Vec<PatternByte>`. The input length must be even —
/// odd-length pattern strings are malformed.
fn parse_pattern_str(s: &str, line_no: usize) -> Result<Vec<PatternByte>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::BadPatLine(line_no, "pattern has odd char count"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = bytes[i];
        let lo = bytes[i + 1];
        if hi == b'.' && lo == b'.' {
            out.push(PatternByte::Wildcard);
        } else {
            let h = hex_nibble(hi).ok_or(Error::BadHex(i, [hi, lo]))?;
            let l = hex_nibble(lo).ok_or(Error::BadHex(i, [hi, lo]))?;
            out.push(PatternByte::Byte((h << 4) | l));
        }
        i += 2;
    }
    Ok(out)
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

    const ONE_LINE: &str = "55564883EC48488D6C24204889CE0F1002488D4D0048895548488D55100F1102 02 ABB7 0040 :0000 __tanq ^0022 __libm___tanq_chosen_core_func ........0F1045004889F00F1106488D65285E5DC3660F1F840000000000";

    #[test]
    fn parses_one_pattern() {
        let p = parse(ONE_LINE).unwrap();
        assert_eq!(p.len(), 1);
        let pat = &p[0];

        // Head: 64 chars → 32 bytes. First byte is 0x55, last byte
        // before the CRC window is 0x02.
        assert_eq!(pat.leading.len(), 32);
        assert_eq!(pat.leading[0], PatternByte::Byte(0x55));
        assert_eq!(pat.leading[31], PatternByte::Byte(0x02));

        assert_eq!(pat.crc_len, 0x02);
        assert_eq!(pat.crc16, 0xABB7);
        assert_eq!(pat.module_len, 0x0040);

        // 1 public name + 1 reference.
        assert_eq!(pat.names.len(), 2);
        assert!(matches!(
            &pat.names[0],
            Symbol::Public(n) if n.offset == 0 && n.name == "__tanq"
        ));
        assert!(matches!(
            &pat.names[1],
            Symbol::Reference(n)
                if n.offset == 0x22 && n.name == "__libm___tanq_chosen_core_func"
        ));

        // Tail starts with 4 wildcards (`........`) followed by
        // 0x0F 0x10 0x45 ...
        assert!(matches!(pat.tail[0], PatternByte::Wildcard));
        assert!(matches!(pat.tail[3], PatternByte::Wildcard));
        assert_eq!(pat.tail[4], PatternByte::Byte(0x0F));
    }

    #[test]
    fn skips_terminator_and_comments() {
        let doc = "# header comment\n; classic FLAIR comment\n---\nbogus line after terminator";
        let p = parse(doc).unwrap();
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn parses_static_at_flag() {
        // `:0000@` (static / collision) maps to Symbol::Local.
        let line = "55565741544883EC48488D6C24204989CC48630D........488D05........48 0B 5813 00B0 :0000@ __libm___tanq_dispatch_table_init";
        let p = parse(line).unwrap();
        assert_eq!(p.len(), 1);
        assert!(matches!(
            &p[0].names[0],
            Symbol::Local(n) if n.offset == 0 && n.name == "__libm___tanq_dispatch_table_init"
        ));
    }

    #[test]
    fn parses_empty_tail() {
        // `554883EC30...` with no trailing tail pattern.
        let line = "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 __libm_flt_rounds ^000B fegetround";
        let p = parse(line).unwrap();
        assert_eq!(p[0].tail.len(), 0);
    }

    #[test]
    fn rejects_odd_length_pattern() {
        let line = "555 02 ABB7 0040 :0000 foo";
        assert!(parse(line).is_err());
    }
}
