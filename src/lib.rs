//! # fast-flirt
//!
//! A pure-Rust, thread-safe parser and matcher for FLIRT (Fast Library
//! Identification and Recognition Technology) signatures — the format
//! IDA Pro uses to identify statically-linked library functions
//! inside compiled binaries.
//!
//! ## Quick start
//!
//! ```no_run
//! use fast_flirt::FlirtSet;
//! use std::fs;
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
//! - **Thread-safe by construction.** `FlirtSet` is `Send + Sync`
//!   with no interior mutability; share a single loaded set across
//!   rayon workers without `Mutex` or `Arc`.
//! - **Lean dep tree.** Three direct deps: `miniz_oxide` (zlib for
//!   compressed `.sig` bodies), `smallvec`, `thiserror`. No CLI
//!   crates, no logging frameworks, no date/time libraries.
//! - **Symbol enum shape** — `Symbol::{Public, Local, Reference}(Name)`
//!   mirrors FLIRT's three name classes directly.

pub mod crc16;
mod error;
mod matcher;
pub mod pat;
pub mod sig;
mod types;

pub use crc16::crc16;
pub use error::{Error, Result};
pub use types::{FlirtSet, Name, Pattern, PatternByte, Symbol};

use std::path::Path;

impl FlirtSet {
    /// Load every `.sig` and `.pat` file in `dir` recursively into a
    /// single corpus. Files are recognised by extension
    /// (case-insensitive).
    ///
    /// Fails fast on the first malformed file. Callers that want
    /// lenient loading should iterate the directory themselves and
    /// call `pat::parse` / `sig::parse` per file.
    pub fn load_dir<P: AsRef<Path>>(dir: P) -> Result<Self> {
        let mut patterns = Vec::new();
        for entry in walkdir(dir.as_ref())? {
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.ends_with(".pat") {
                let text = std::fs::read_to_string(entry.path())
                    .map_err(|e| Error::Truncated(0, 0).context_io(format!("{}: {}", name, e)))?;
                let mut p = pat::parse(&text)?;
                patterns.append(&mut p);
            } else if name.ends_with(".sig") {
                let bytes = std::fs::read(entry.path())
                    .map_err(|e| Error::Truncated(0, 0).context_io(format!("{}: {}", name, e)))?;
                let mut p = sig::parse(&bytes)?;
                patterns.append(&mut p);
            }
        }
        Ok(FlirtSet::with_patterns(patterns))
    }
}

// Minimal recursive directory walker — we don't pull `walkdir` here
// because std::fs::read_dir + a vec stack does the job in 15 lines
// and avoids an extra dep. The standard `walkdir` crate is overkill
// for what we need (no symlink handling, no max-depth, no filtering
// at traversal time).
fn walkdir(root: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let read_dir = std::fs::read_dir(&path).map_err(|_| Error::Truncated(0, 0))?;
        for entry in read_dir.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(entry);
            }
        }
    }
    Ok(out)
}

// Sketch helper for adding I/O context to an error without pulling
// `anyhow`. Used only in `load_dir` for the moment.
impl Error {
    fn context_io(self, _msg: String) -> Self {
        // 0.1: keep errors thin. We can surface the IO message via a
        // dedicated variant if it turns out to matter for diagnostics.
        self
    }
}
