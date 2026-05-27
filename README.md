# fast-flirt

[![CI](https://github.com/marirs/fast-flirt-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/fast-flirt-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/fast-flirt.svg)](https://crates.io/crates/fast-flirt)
[![Docs.rs](https://docs.rs/fast-flirt/badge.svg)](https://docs.rs/fast-flirt)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue.svg)](#requirements)
[![Thread-safe](https://img.shields.io/badge/thread--safe-yes-brightgreen.svg)](#thread-safety)

A pure-Rust, thread-safe parser and matcher for **FLIRT** (Fast Library Identification and Recognition Technology) signatures — the format IDA Pro uses to identify statically-linked library functions inside compiled binaries.

`fast-flirt` ships the full FLIRT pipeline in a small, focused crate: parse `.pat` (FLAIR ASCII) and `.sig` (binary trie, compressed or uncompressed) corpora, then match candidate function bytes against the loaded set. It exists to give Rust-side static-analysis tools (capa-rs, custom RE workflows) a fast, lock-free FLIRT engine without dragging in a C build, a CLI dependency tree, or a logging framework.

## Features

- **Both formats**: `.pat` (FLAIR sigmake text output) and `.sig` (FLIRT v5–v10 binary trie, with zlib-compressed body).
- **Three-stage match**: 32-byte head pattern (with wildcards), CRC-16/X-25 over the post-head bytes, optional contiguous tail (.pat) or discrete discriminator bytes (.sig).
- **Indexed matcher**: 256-way bucket keyed on `leading[0]` built once at load time. `matches()` consults a single bucket per call instead of scanning the full corpus.
- **Thread-safe by construction**: `FlirtSet` is `Send + Sync` with no interior mutability — share one loaded set across `rayon` workers without `Arc` or `Mutex`.
- **Lean dep tree**: three direct deps (`miniz_oxide`, `smallvec`, `thiserror`). No CLI crates, no logging, no date/time, no `nom`, no `bitflags`. Pure Rust, no C build required.
- **Allocation-free match path**: `matches()` only allocates the result `Vec<&Pattern>`; the inner check is a pure scan over borrowed data.

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
fast-flirt = "0.1"
```

Load a corpus and look up a function:

```rust
use fast_flirt::FlirtSet;

fn main() -> fast_flirt::Result<()> {
    // Walk a directory of .pat / .sig files into a single corpus.
    // Mixed extensions are fine; each file is parsed by the right module.
    let set = FlirtSet::load_dir("path/to/flirt-sigs")?;
    println!("loaded {} signatures", set.len());

    // Hand the first ~256 bytes of a candidate function to the matcher.
    // Short buffers don't panic — patterns longer than the input just
    // don't match.
    let function_head: &[u8] = &[/* … */];
    if let Some(name) = set.match_public_name(function_head) {
        println!("matched library function: {}", name);
    }

    // Or enumerate every pattern that matches:
    for pat in set.matches(function_head) {
        if let Some(name) = pat.public_name() {
            println!("  {}", name);
        }
    }
    Ok(())
}
```

If you already have signature bytes in memory (e.g. from an embedded corpus), call the parsers directly:

```rust
use fast_flirt::{pat, sig, FlirtSet};

let pat_text = std::fs::read_to_string("libmsvcrt.pat")?;
let sig_bytes = std::fs::read("libstd.sig")?;

let mut patterns = pat::parse(&pat_text)?;
patterns.extend(sig::parse(&sig_bytes)?);

let set = FlirtSet::with_patterns(patterns);
```

## Thread safety

`FlirtSet` and every type it contains is `Send + Sync` with no interior mutability. A static compile-time assertion in `types.rs` fails the build if a future refactor ever breaks this:

```rust
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FlirtSet>();
    assert_send_sync::<Pattern>();
};
```

In practice this means you load the corpus once and share `&FlirtSet` across as many workers as you want — no `Arc`, no `Mutex`:

```rust
use rayon::prelude::*;
let set = FlirtSet::load_dir("sigs")?;
let names: Vec<_> = functions
    .par_iter()
    .filter_map(|f| set.match_public_name(&f.bytes).map(str::to_owned))
    .collect();
```

## How matching works

Each `Pattern` carries up to four constraints; `matches()` checks them in order and short-circuits on the first failure:

1. **Head pattern** — `leading: Vec<PatternByte>`, position-by-position. `PatternByte::Wildcard` matches any byte; `PatternByte::Byte(b)` matches `b`.
2. **CRC window** — `crc16` over the `crc_len` bytes immediately following the head, computed under CRC-16/X-25 (poly `0x1021`, init `0xFFFF`, refin/refout, xorout `0xFFFF`).
3. **`.pat` tail** — `tail: Vec<PatternByte>`, the contiguous post-CRC pattern used when head + CRC collide between sigmake outputs.
4. **`.sig` discriminator bytes** — `tail_bytes: Vec<(u32, u8)>`, discrete `(function-relative offset, expected byte)` pairs that disambiguate functions sharing a CRC group in the .sig trie.

`.pat`-derived patterns populate `tail`; `.sig`-derived patterns populate `tail_bytes`. Both default to empty and are zero-cost when unused.

The first-byte index makes the per-call work `O((|bucket| + |wildcards|) · head_len)` instead of `O(N · head_len)`. For typical FLIRT corpora — where the overwhelming majority of patterns begin with a concrete byte like `0x55` (`push rbp`) or `0x48` (REX prefix) — this is close to a 256× constant-factor improvement.

## API surface

```rust
// Top-level
fast_flirt::FlirtSet        // owned corpus + first-byte index
fast_flirt::Pattern         // one signature
fast_flirt::PatternByte     // Byte(u8) | Wildcard
fast_flirt::Symbol          // Public(Name) | Local(Name) | Reference(Name)
fast_flirt::Name            // { offset: i64, name: String }
fast_flirt::Error           // typed parse / load errors
fast_flirt::Result<T>

// Parsers
fast_flirt::pat::parse(&str)  -> Result<Vec<Pattern>>
fast_flirt::sig::parse(&[u8]) -> Result<Vec<Pattern>>

// Matcher
FlirtSet::load_dir<P: AsRef<Path>>(dir: P) -> Result<FlirtSet>
FlirtSet::with_patterns(Vec<Pattern>) -> FlirtSet
FlirtSet::matches(&self, &[u8])             -> Vec<&Pattern>
FlirtSet::match_public_name(&self, &[u8])   -> Option<&str>
FlirtSet::patterns(&self) -> &[Pattern]
FlirtSet::len(&self) / is_empty(&self)

// CRC
fast_flirt::crc16(&[u8]) -> u16   // CRC-16/X-25
```

## Requirements

- Rust **1.95** or newer (2024 edition).

## Benchmark

End-to-end benchmark (load + match) lives in `examples/bench.rs`:

```bash
cargo run --release --example bench -- ../FLIRTDB
cargo run --release --example bench -- ../FLIRTDB ../some-sample.exe
```

The first form reports `load_dir` time + corpus stats. The second additionally sweeps the matcher across the sample's bytes and reports `matches()` / `match_public_name()` throughput.

## Fuzzing

Two `cargo fuzz` targets live in `fuzz/`. They feed arbitrary bytes to the parsers and assert that no input ever panics:

```bash
cargo install cargo-fuzz
cargo fuzz run sig_parse
cargo fuzz run pat_parse
```

Crashing inputs land in `fuzz/artifacts/<target>/` — file each one as a regression fixture before patching. The fuzz crate is excluded from the published `.crate` and adds no runtime dependencies.

## Used by

- [capa-rs](https://github.com/marirs/capa-rs) — static capability extractor for PE / ELF / shellcode / .NET binaries.

## License

Licensed under the [Apache License 2.0](LICENSE).

## Acknowledgements

- Hex-Rays for designing and documenting the FLAIR / FLIRT format.
- The [Maktm/FLIRTDB](https://github.com/Maktm/FLIRTDB) corpus, used for cross-validation during development.
