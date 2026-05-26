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
    /// Symlinks (both file and directory) are deliberately skipped to
    /// avoid loops and to keep the trust boundary clear — if you want
    /// to follow symlinks, canonicalise the directory yourself.
    ///
    /// Fails fast on the first malformed file. Callers that want
    /// lenient loading should iterate the directory themselves and
    /// call `pat::parse` / `sig::parse` per file. Errors include the
    /// path they originated on (no more opaque `Truncated(0,0)`).
    pub fn load_dir<P: AsRef<Path>>(dir: P) -> Result<Self> {
        let mut patterns = Vec::new();
        for entry in walkdir(dir.as_ref())? {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.ends_with(".pat") {
                let text =
                    std::fs::read_to_string(&path).map_err(|e| Error::Io(path.clone(), e))?;
                let mut p = pat::parse(&text)?;
                patterns.append(&mut p);
            } else if name.ends_with(".sig") {
                let bytes = std::fs::read(&path).map_err(|e| Error::Io(path.clone(), e))?;
                let mut p = sig::parse(&bytes)?;
                patterns.append(&mut p);
            }
        }
        Ok(FlirtSet::with_patterns(patterns))
    }
}

/// Recursive directory walker. Skips symlinks (both file + directory)
/// so a symlink loop in the input tree can't OOM us, and surfaces real
/// IO errors via [`Error::Io`] with the offending path attached.
fn walkdir(root: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let read_dir = std::fs::read_dir(&path).map_err(|e| Error::Io(path.clone(), e))?;
        for entry in read_dir {
            let entry = entry.map_err(|e| Error::Io(path.clone(), e))?;
            // Skip symlinks unconditionally. `file_type` is cheap on
            // every platform (no extra syscall on Unix; pre-cached on
            // Windows). A failure here surfaces with the entry path.
            let ft = entry.file_type().map_err(|e| Error::Io(entry.path(), e))?;
            if ft.is_symlink() {
                continue;
            }
            let p = entry.path();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                out.push(entry);
            }
            // Sockets, fifos, block devices etc. silently ignored —
            // they're not signature files.
        }
    }
    Ok(out)
}
