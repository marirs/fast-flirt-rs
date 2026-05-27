//! # fast-flirt
//!
//! A pure-Rust, thread-safe, **zero-copy** parser and matcher for
//! FLIRT (Fast Library Identification and Recognition Technology)
//! signatures — the format IDA Pro uses to identify statically-linked
//! library functions inside compiled binaries.
//!
//! ## Quick start
//!
//! ```no_run
//! use fast_flirt::FlirtSet;
//!
//! // Load all signatures from a directory of `.sig` / `.pat` files.
//! let set = FlirtSet::load_dir("path/to/flirt-sigs")?;
//!
//! // Test some function bytes against the loaded corpus.
//! let function_head: &[u8] = &[/* ... at least 256 bytes ... */];
//! for pat in set.matches(function_head) {
//!     if let Some(name) = pat.public_name() {
//!         println!("matched library function: {}", name);
//!     }
//! }
//! # Ok::<(), fast_flirt::Error>(())
//! ```
//!
//! ## Design notes
//!
//! - **Zero-copy.** A loaded [`FlirtSet`] owns one byte arena and a
//!   ~48-byte record per pattern. Names, head bytes, and tails all
//!   live inside the arena as borrowed slices via [`Pattern`] handles.
//!   No per-pattern `Vec`, no per-name `String`.
//! - **Trie matcher.** Per-call work is O(depth + leaf size), not
//!   O(corpus). Beats per-signature linear scan by ~250×.
//! - **Thread-safe by construction.** [`FlirtSet`] is `Send + Sync`
//!   with no interior mutability; share a single loaded set across
//!   rayon workers without `Mutex` or `Arc`.
//! - **Lean dep tree.** Three direct deps: `miniz_oxide` (zlib for
//!   compressed `.sig` bodies), `smallvec`, `thiserror`. No CLI
//!   crates, no logging frameworks, no date/time libraries.

pub mod crc16;
mod error;
mod matcher;
pub mod pat;
pub mod sig;
mod trie;
mod types;

pub use crc16::crc16;
pub use error::{Error, Result};
pub use types::{FlirtSet, FlirtSetBuilder, Name, NameIter, Pattern, Symbol, TailByteIter};
