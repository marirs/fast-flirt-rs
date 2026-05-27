//! Simple end-to-end benchmark for fast-flirt.
//!
//! Usage:
//!
//! ```bash
//! cargo run --release --example bench -- path/to/flirt-corpus
//! cargo run --release --example bench -- path/to/flirt-corpus path/to/sample.bin
//! ```
//!
//! Without a sample, only the load timing + corpus stats are
//! reported. With a sample, we additionally synthesise candidate
//! function buffers from the binary's executable bytes and time
//! `matches()` + `match_public_name()` over them.
//!
//! Output goes to stdout in a column layout you can paste into
//! release notes. No criterion / black-box dance — we're after
//! order-of-magnitude numbers, not microbenchmark precision.

use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use fast_flirt::FlirtSet;

const USAGE: &str = "\
usage: bench <flirt-corpus-dir> [sample-binary]

  flirt-corpus-dir  directory of .pat / .sig files (e.g. ../FLIRTDB)
  sample-binary     optional binary to sweep candidate windows over
";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }
    let corpus = Path::new(&args[1]);
    let sample = args.get(2).map(Path::new);

    // ---- Load ---------------------------------------------------
    let t0 = Instant::now();
    let set = match FlirtSet::load_dir(corpus) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("load_dir({}) failed: {e}", corpus.display());
            return ExitCode::FAILURE;
        }
    };
    let load_ns = t0.elapsed();
    let total_patterns = set.len();

    // Bucket distribution — useful for spotting "everything's in
    // the wildcards fallback" pathologies.
    let (bucket_max, bucket_total, wildcards) = index_stats(&set);

    println!("{:>22}  {}", "corpus", corpus.display(),);
    println!(
        "{:>22}  {} files walked",
        "load source",
        count_files(corpus)
    );
    println!(
        "{:>22}  {:>10} patterns  in  {:>8.2?}  ({:>6.2} kpat/s)",
        "load_dir",
        total_patterns,
        load_ns,
        (total_patterns as f64) / load_ns.as_secs_f64() / 1000.0,
    );
    println!(
        "{:>22}  buckets: max={}  total={}  wildcards={}",
        "first-byte index", bucket_max, bucket_total, wildcards,
    );

    // ---- Optional matching workload -----------------------------
    let Some(sample) = sample else {
        println!();
        println!("(no sample binary given; skipping match-rate measurement)");
        return ExitCode::SUCCESS;
    };
    let buf = match std::fs::read(sample) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read({}) failed: {e}", sample.display());
            return ExitCode::FAILURE;
        }
    };

    // Walk the binary at a coarse stride and run the matcher at
    // each offset. We don't try to be smart about basic-block
    // boundaries — this is a wall-clock measurement, not a
    // capa-style real workload. 16 bytes is enough to skip the
    // bulk of duplicate-result work without distorting the timing.
    const STRIDE: usize = 16;
    const HEAD_WINDOW: usize = 256;
    let candidates: Vec<&[u8]> = buf.windows(HEAD_WINDOW).step_by(STRIDE).collect();
    println!();
    println!(
        "{:>22}  {} bytes / {} candidate windows (stride={}, window={})",
        "sample",
        buf.len(),
        candidates.len(),
        STRIDE,
        HEAD_WINDOW,
    );

    // matches() — full result vector.
    let t0 = Instant::now();
    let mut hits = 0usize;
    for w in &candidates {
        hits += set.matches(w).len();
    }
    let matches_ns = t0.elapsed();

    // match_public_name() — short-circuits on first public name,
    // typically much faster.
    let t0 = Instant::now();
    let mut named = 0usize;
    for w in &candidates {
        if set.match_public_name(w).is_some() {
            named += 1;
        }
    }
    let name_ns = t0.elapsed();

    let calls = candidates.len() as f64;
    println!(
        "{:>22}  {:>10} hits     in  {:>8.2?}  ({:>6.2} M calls/s)",
        "matches()",
        hits,
        matches_ns,
        calls / matches_ns.as_secs_f64() / 1_000_000.0,
    );
    println!(
        "{:>22}  {:>10} named    in  {:>8.2?}  ({:>6.2} M calls/s)",
        "match_public_name()",
        named,
        name_ns,
        calls / name_ns.as_secs_f64() / 1_000_000.0,
    );

    ExitCode::SUCCESS
}

/// Walk the same way `load_dir` does just to give a file-count
/// stat alongside the load time. Pure UX nicety.
fn count_files(root: &Path) -> usize {
    fn walk(p: &Path, n: &mut usize) {
        let Ok(it) = std::fs::read_dir(p) else { return };
        for entry in it.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                walk(&path, n);
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let ext = ext.to_ascii_lowercase();
                if ext == "sig" || ext == "pat" {
                    *n += 1;
                }
            }
        }
    }
    let mut n = 0;
    walk(root, &mut n);
    n
}

/// First-byte distribution for diagnostic display. Counts patterns
/// by `leading[0]` value (skipping wildcards at position 0).
fn index_stats(set: &FlirtSet) -> (usize, usize, usize) {
    let mut counts = [0usize; 256];
    let mut wildcards = 0usize;
    for pat in set.patterns() {
        if pat.is_wildcard(0) || pat.leading().is_empty() {
            wildcards += 1;
        } else {
            counts[pat.leading()[0] as usize] += 1;
        }
    }
    let max = counts.iter().copied().max().unwrap_or(0);
    let total: usize = counts.iter().sum();
    (max, total, wildcards)
}
