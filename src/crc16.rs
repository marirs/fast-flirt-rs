//! CRC-16/X-25 — the variant FLIRT uses for tail verification.
//!
//! Parameters (CRC catalogue notation):
//!
//! ```text
//! width    = 16
//! poly     = 0x1021  (reflected form: 0x8408)
//! init     = 0xFFFF
//! refin    = true   (process input bytes LSB first)
//! refout   = true
//! xorout   = 0xFFFF (final NOT)
//! check    = 0x906E (for ASCII "123456789")
//! ```
//!
//! Validated against the X-25 check value (see `tests` below).
//!
//! Why FLIRT picked this specifically: HDLC standardised on X-25 in
//! the 80s and the early IDA team grabbed an existing implementation
//! rather than designing a custom polynomial. The bit-reflected form
//! (`0x8408`) shows up in the inner loop because the original IDA
//! code was written for an LSB-first bit stream.

/// Compute the CRC-16/X-25 of `buf`.
///
/// FLIRT signatures encode this as 4 hex digits (uppercase in `.pat`,
/// little-endian u16 in `.sig`) covering the `crc_len` bytes that
/// immediately follow the 32-byte head pattern.
#[inline]
pub fn crc16(buf: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in buf {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::crc16;

    /// The CRC catalogue's standard "check" value: CRC-16/X-25 of
    /// the ASCII string "123456789" is 0x906E. If this fails, the
    /// implementation has drifted from the spec.
    #[test]
    fn check_value() {
        assert_eq!(crc16(b"123456789"), 0x906E);
    }

    /// CRC of the empty input is the final XOR applied to the init
    /// value: `!0xFFFF == 0x0000`. Edge case that comes up when a
    /// pattern's `crc_len` field is 0 (no CRC window).
    #[test]
    fn empty() {
        assert_eq!(crc16(b""), 0x0000);
    }

    /// Single byte — smoke test that the bit-loop runs eight
    /// iterations and the byte-XOR happens at the right place.
    /// Fixtures cross-checked against the reference Python CRC-16/X-25
    /// implementation.
    #[test]
    fn single_byte() {
        assert_eq!(crc16(&[0x00]), 0xF078);
        assert_eq!(crc16(&[0xFF]), 0xFF00);
    }
}
