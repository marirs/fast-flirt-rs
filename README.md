# fast-flirt

[![CI](https://github.com/marirs/fast-flirt-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/fast-flirt-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/fast-flirt.svg)](https://crates.io/crates/fast-flirt)
[![Docs.rs](https://docs.rs/fast-flirt/badge.svg)](https://docs.rs/fast-flirt)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue.svg)](#requirements)
[![Thread-safe](https://img.shields.io/badge/thread--safe-yes-brightgreen.svg)](#thread-safety)
[![Zero-copy](https://img.shields.io/badge/zero--copy-yes-brightgreen.svg)](#zero-copy)

A pure-Rust, thread-safe, **zero-copy** parser and matcher for **FLIRT** (Fast Library Identification and Recognition Technology) signatures — the format IDA Pro uses to identify statically-linked library functions inside compiled binaries.

`fast-flirt` ships the full FLIRT pipeline in a small, focused crate: parse `.pat` (FLAIR ASCII) and `.sig` (binary trie, compressed or uncompressed) corpora, then match candidate function bytes against the loaded set. It exists to give Rust-side static-analysis tools (capa-rs, custom RE workflows) a fast, lock-free FLIRT engine without dragging in a C build, a CLI dependency tree, or a logging framework.

On a real FLIRTDB-derived corpus (944k patterns) matched against a typical 800 KB PE, `matches()` runs at **9.5M calls/sec** — roughly **240×** faster than a per-signature linear scan.

## Features

- **Both formats**: `.pat` (FLAIR sigmake text output) and `.sig` (FLIRT v5–v10 binary trie, with zlib-compressed body).
- **Three-stage match**: 32-byte head pattern (with wildcards), CRC-16/X-25 over the post-head bytes, optional contiguous tail (.pat) or discrete discriminator bytes (.sig).
- **Multi-level trie matcher**: a variable-depth prefix trie built once at load time. Per-call work drops from `O(N · head_len)` to `O(depth + |leaf|)` — independent of corpus size.
- **Zero-copy parse**: a loaded `FlirtSet` owns one byte arena plus a fixed-size 48-byte record per pattern. Head bytes, names, and tails are stored as offsets into the arena. No per-pattern `Vec`, no per-name `String`. ~70% less resident memory than an owned-tree design.
- **Thread-safe by construction**: `FlirtSet` is `Send + Sync` with no interior mutability — share one loaded set across `rayon` workers without `Arc` or `Mutex`.
- **Lean dep tree**: three direct deps (`miniz_oxide`, `smallvec`, `thiserror`). No CLI crates, no logging, no date/time, no `nom`, no `bitflags`. Pure Rust, no C build required.
- **DoS hardening**: zlib bomb cap, trie depth cap, plausibility checks on wire-encoded counts, module-length validation, symlink-loop guard in the directory walker.

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
fast-flirt = "0.2"
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
use fast_flirt::{pat, sig};

let pat_text  = std::fs::read_to_string("libmsvcrt.pat")?;
let sig_bytes = std::fs::read("libstd.sig")?;

// Each parser returns a fully-built FlirtSet.
let set_a = pat::parse(&pat_text)?;
let set_b = sig::parse(&sig_bytes)?;
```

To merge multiple sources into a single matcher, use `FlirtSetBuilder`:

```rust
use fast_flirt::FlirtSetBuilder;

let mut b = FlirtSetBuilder::new();
b.add_pat(&std::fs::read_to_string("libmsvcrt.pat")?)?;
b.add_sig(&std::fs::read("libstd.sig")?)?;
let set = b.build();
```

## Thread safety

`FlirtSet` and every type it contains is `Send + Sync` with no interior mutability. A static compile-time assertion in `types.rs` fails the build if a future refactor ever breaks this:

```rust
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FlirtSet>();
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

## Zero-copy

A `FlirtSet` is a single owned `Box<[u8]>` arena plus one 48-byte `PatternData` record per signature. Everything else — head bytes, wildcard bitmasks, name strings, tail discriminators — lives inside the arena as borrowed slices. Iteration hands out lightweight `Pattern<'set>` handles (`Copy`, two machine words) that resolve fields lazily via accessor methods.

Concretely:

- No `Vec<PatternByte>` per pattern. Heads are stored as 32 raw bytes + a `u64` wildcard bitmask.
- No `String` per name. Names are byte slices into the arena, surfaced as `&'set str`.
- No `Vec<(u32, u8)>` per pattern for tail discriminators. Pairs are packed into the arena and iterated lazily.

On the 944k-pattern FLIRTDB-derived corpus, resident memory drops from ~250 MiB (owned-tree) to ~75 MiB (arena), and load time stays at ~360 ms despite the trie build.

## How matching works

Each pattern carries up to four constraints; the matcher checks them in order and short-circuits on the first failure:

1. **Head pattern** — `leading()` returns a `&[u8]` of up to 32 bytes; `is_wildcard(i)` tells you whether position `i` is a wildcard. Concrete-byte positions must equal the input.
2. **CRC window** — `crc16()` over the `crc_len()` bytes immediately following the head, computed under CRC-16/X-25 (poly `0x1021`, init `0xFFFF`, refin/refout, xorout `0xFFFF`).
3. **`.pat` tail** — `tail()` returns a `&[u8]` of contiguous post-CRC bytes used when head + CRC collide between sigmake outputs. `is_tail_wildcard(i)` for the wildcard check.
4. **`.sig` discriminator bytes** — `tail_bytes()` yields `(function_offset, expected_byte)` pairs that disambiguate functions sharing a CRC group in the binary trie.

`.pat`-derived patterns populate `tail`; `.sig`-derived patterns populate `tail_bytes`. Both default to empty and are zero-cost when unused.

The matcher uses a **multi-level prefix trie** built at `FlirtSet` construction. It branches on the byte position at each depth, with a dedicated "wildcard" branch followed regardless of the input byte. A traversal walks the trie in ~5–8 hops and hands the surviving handful of leaf candidates to the per-pattern verifier. This is what makes the match path `O(depth + |leaf|)` instead of `O(N · head_len)`.

## API surface

```rust
// Top-level
fast_flirt::FlirtSet         // owned corpus + arena + trie
fast_flirt::Pattern<'set>    // lightweight borrowed handle
fast_flirt::Symbol<'set>     // Public(Name) | Local(Name) | Reference(Name)
fast_flirt::Name<'set>       // { offset: i64, name: &'set str }
fast_flirt::NameIter<'set>   // iterator over Pattern::names()
fast_flirt::TailByteIter<'set>
fast_flirt::FlirtSetBuilder  // accumulate patterns from multiple sources
fast_flirt::Error            // typed parse / load errors
fast_flirt::Result<T>

// Parsers — each returns a fully-built FlirtSet
fast_flirt::pat::parse(&str)  -> Result<FlirtSet>
fast_flirt::sig::parse(&[u8]) -> Result<FlirtSet>

// FlirtSet
FlirtSet::load_dir<P: AsRef<Path>>(dir: P) -> Result<FlirtSet>
FlirtSet::matches(&self, &[u8])           -> Vec<Pattern<'_>>
FlirtSet::match_public_name(&self, &[u8]) -> Option<&str>
FlirtSet::patterns(&self) -> impl Iterator<Item = Pattern<'_>>
FlirtSet::pattern(&self, idx: u32) -> Pattern<'_>
FlirtSet::len(&self) / FlirtSet::is_empty(&self)

// Pattern handle methods
Pattern::leading()        -> &[u8]
Pattern::is_wildcard(i)   -> bool
Pattern::crc_len()        -> u8
Pattern::crc16()          -> u16
Pattern::module_len()     -> u32
Pattern::names()          -> NameIter
Pattern::public_name()    -> Option<&str>
Pattern::tail()           -> &[u8]
Pattern::is_tail_wildcard(i) -> bool
Pattern::tail_bytes()     -> TailByteIter
Pattern::min_input_len()  -> usize

// FlirtSetBuilder
FlirtSetBuilder::new() -> Self
FlirtSetBuilder::add_pat(&mut self, &str)  -> Result<usize>
FlirtSetBuilder::add_sig(&mut self, &[u8]) -> Result<usize>
FlirtSetBuilder::build(self) -> FlirtSet

// CRC
fast_flirt::crc16(&[u8]) -> u16   // CRC-16/X-25
```

## Performance

Benchmark on a 944k-pattern corpus from capa-rs's bundled signatures matched against an 808 KB Windows PE (mimikatz), sweeping the binary at a 16-byte stride for 50,522 candidate windows:

| Operation | Throughput | Wall-clock |
|---|---|---|
| `load_dir` (parse + build trie) | 2.6 M patterns/sec | 361 ms |
| `matches()` | 9.5 M calls/sec | 5.3 ms |
| `match_public_name()` | 15.5 M calls/sec | 3.3 ms |

The same workload on a per-signature linear scan (the 0.1.0 design before the trie) took 1.3 seconds for `matches()` — the trie gives a ~240× constant-factor improvement.

Run the bench yourself with `cargo run --release --example bench -- <flirt-corpus-dir> [sample-binary]`.

## Requirements

- Rust **1.95** or newer (2024 edition).

## Benchmark

End-to-end benchmark (load + match) lives in `examples/bench.rs`:

```bash
cargo run --release --example bench -- ./FLIRTDB
cargo run --release --example bench -- ./FLIRTDB ./some-sample.exe
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

## Migrating from 0.1.x

`fast-flirt 0.2.0` is a breaking release. The matcher is ~240× faster and the loaded set uses ~70% less memory, but the public types changed:

- `Pattern` is now `Pattern<'set>` — a borrowed handle, not an owned struct. Access fields via methods (`pat.leading()`, `pat.crc16()`, `pat.names()`, …) instead of struct fields.
- `Name` is now `Name<'set> { offset: i64, name: &'set str }` (was `String`-backed).
- `Symbol` carries the lifetimed `Name<'set>`.
- `pat::parse` and `sig::parse` return `Result<FlirtSet>` directly, not `Result<Vec<Pattern>>`.
- `FlirtSet::with_patterns` is replaced by `FlirtSetBuilder`.
- `PatternByte` is gone. Wildcards are now a bitmask; use `Pattern::is_wildcard(i)` plus `Pattern::leading()[i]`.

The matching API itself (`matches`, `match_public_name`, `load_dir`) keeps the same signature shape, just with `Pattern<'_>` in place of `Pattern`.

## Used by

- [capa-rs](https://github.com/marirs/capa-rs) — static capability extractor for PE / ELF / shellcode / .NET binaries.

## License

Licensed under the [Apache License 2.0](LICENSE).

## Acknowledgements

- Hex-Rays for designing and documenting the FLAIR / FLIRT format.
- The [Maktm/FLIRTDB](https://github.com/Maktm/FLIRTDB) corpus, used for cross-validation during development.
