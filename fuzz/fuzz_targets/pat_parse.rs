//! Fuzz target for `fast_flirt::pat::parse`.
//!
//! `.pat` is text-based, so we accept any UTF-8 input. Non-UTF-8 byte
//! sequences are skipped at the fuzzer level (they'd fail the type
//! signature anyway).
//!
//! Surfaces:
//! - Lines with odd-length hex tokens, bad hex characters.
//! - Names containing control bytes, lone `@` markers.
//! - Garbage trailing tail tokens.
//! - Truncated `:OFFSET` / `^OFFSET` annotations.
//! - Lines that look like patterns but aren't 64 chars.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = fast_flirt::pat::parse(text);
    }
});
