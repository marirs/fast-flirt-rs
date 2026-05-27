//! Fuzz target for `fast_flirt::sig::parse`.
//!
//! The contract under test: for ANY byte sequence the function must
//! either return `Ok(Vec<Pattern>)` or return `Err(_)` — it must
//! never panic, abort, infinite-loop, or trigger UB.
//!
//! Notable inputs this surfaces:
//! - Truncated headers, malformed version bytes.
//! - Corrupt zlib payloads (CRC mismatch, bad magic).
//! - Zlib bombs that should hit `Error::InflateBomb`.
//! - Pathological trie shapes (deep recursion, wide fanout,
//!   wildcard-only patterns, popcount > length masks).
//! - Off-by-one varints at every encoding boundary.
//!
//! Any crash that escapes goes to `fuzz/artifacts/sig_parse/`. File
//! the crashing input as a regression fixture before fixing.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // We deliberately ignore the result — the fuzz invariant is "no
    // panic", not "no error". Errors are correct behaviour on
    // malformed input.
    let _ = fast_flirt::sig::parse(data);
});
