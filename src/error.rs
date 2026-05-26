//! Error type for fast-flirt.

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

    #[error("trailing data after .sig parse at offset {0}: {1} bytes remain")]
    TrailingData(usize, usize),
}

pub type Result<T> = std::result::Result<T, Error>;
