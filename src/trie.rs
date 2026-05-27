//! Multi-level prefix trie over the head bytes of FLIRT patterns.
//!
//! The trie is the lever that earns "fast" in fast-flirt. At each
//! depth `d`, the node partitions its patterns by `leading[d]`:
//! patterns with concrete byte `b` flow into `children[b]`,
//! patterns with a wildcard at depth `d` flow into `wildcard_child`
//! (and are followed for *every* input byte at that depth). The
//! traversal stops at a leaf — a node that holds the surviving
//! candidate pattern indices for linear `pattern_matches` verification.
//!
//! Build is one-shot at `FlirtSet::with_patterns` time and runs in
//! `O(N · depth_visited)`. Match-time is `O(depth + |leaf|)`,
//! independent of corpus size — that's the headline win over the
//! linear-scan + first-byte-bucket designs.
//!
//! Memory: each pattern lives in exactly one leaf (`u32` index, 4
//! bytes). Each node carries a small `Vec` of children + an optional
//! wildcard pointer. For the FLIRTDB corpus (944k patterns) the
//! whole structure is a few tens of MiB.
//!
//! Design tradeoffs:
//!
//! - **Branch on depth, not on best-information-gain position.**
//!   A best-position search would shave another factor or two off
//!   the worst-case leaf size but adds significant build cost
//!   (`O(N · pattern_len · 256)` per node). Real FLIRT patterns are
//!   densely populated at low positions, so sequential depth wins
//!   most of the value at a fraction of the cost.
//! - **`MAX_DEPTH = 8`.** Empirically all reasonable corpora produce
//!   small leaves by depth 6–8; further branching is mostly waste.
//! - **`LEAF_THRESHOLD = 8`.** Below this, a sequential scan beats
//!   another branch (cache friendlier, no recursion overhead).

use std::ops::ControlFlow;

use crate::types::PatternData;

/// Stop branching when a partition contains this many or fewer
/// patterns — sequential `pattern_matches` is cheaper than another
/// hash lookup + recursion at that point.
const LEAF_THRESHOLD: usize = 8;

/// Hard depth cap. Empirical max needed for FLIRTDB-class corpora
/// is ~6; 8 leaves headroom for larger corpora and pathological
/// distributions without growing the trie unboundedly.
const MAX_DEPTH: u8 = 8;

/// One node in the trie.
///
/// At depth `d`, the input byte `buf[d]` selects exactly one child
/// (if any) via [`Self::children`], plus the wildcard branch (if
/// any) which represents patterns with `..` at depth `d` and is
/// followed regardless of `buf[d]`.
///
/// Leaves drop the children/wildcard fields and hold the surviving
/// pattern indices directly in `leaves`. A node can simultaneously
/// have children AND leaves only when MAX_DEPTH is hit — patterns
/// that reach max depth without being narrowed below the threshold
/// land in the leaves list of the deepest node.
#[derive(Debug, Clone, Default)]
pub(crate) struct TrieNode {
    /// Which input byte position this node branches on. Crucially,
    /// this can *skip* positions where the partition would be
    /// trivial (all patterns share the same byte at that depth) —
    /// the query reads `node.depth` rather than counting hops.
    pub(crate) depth: u8,
    /// Sorted `(byte_value, child_node_index)` pairs. Binary-search
    /// at match time. Typical fanout is small (~tens) so linear
    /// search would also be fine, but binary search is `O(log n)`
    /// for the rare wide-fanout nodes.
    pub(crate) children: Vec<(u8, u32)>,
    /// Index of the child handling patterns with wildcard at this
    /// depth. `None` if no such patterns. Always followed during
    /// traversal regardless of input byte.
    pub(crate) wildcard_child: Option<u32>,
    /// Pattern indices that terminate at this node (either because
    /// the bucket fell below `LEAF_THRESHOLD` or because we hit
    /// `MAX_DEPTH`). The matcher runs full `pattern_matches`
    /// verification on each.
    pub(crate) leaves: Vec<u32>,
}

/// The trie itself — an arena of nodes addressed by `u32` indices
/// plus a `root` pointer. The arena is built depth-first so a
/// parent's id is always *higher* than its descendants' ids; this
/// gives the build a one-pass append-only structure without any
/// swap-and-fix-up dance.
#[derive(Debug, Clone, Default)]
pub(crate) struct PatternTrie {
    nodes: Vec<TrieNode>,
    root: u32,
}

impl PatternTrie {
    /// Build a trie over `patterns`. Reads head bytes from the shared
    /// `arena` byte buffer (the [`FlirtSet`]'s arena). Linear scan +
    /// recursive partition; called once at [`FlirtSet`] build time.
    pub(crate) fn build(patterns: &[PatternData], arena: &[u8]) -> Self {
        let mut nodes = Vec::new();
        let all: Vec<u32> = (0..patterns.len() as u32).collect();
        let root = if all.is_empty() {
            nodes.push(TrieNode::default());
            0
        } else {
            Self::build_node(&mut nodes, patterns, arena, all, 0)
        };
        Self { nodes, root }
    }

    /// Read the byte at depth `d` of pattern `i`'s head, returning
    /// `None` if the pattern is too short or the position is a
    /// wildcard, `Some(b)` for a concrete byte.
    #[inline]
    fn leading_byte_at(patterns: &[PatternData], arena: &[u8], i: u32, d: usize) -> Option<u8> {
        let p = &patterns[i as usize];
        if d >= p.leading_len as usize {
            return None;
        }
        if (p.leading_wildmask & (1u64 << d)) != 0 {
            return None;
        }
        Some(arena[p.leading_off as usize + d])
    }

    /// `true` if the byte at depth `d` of pattern `i` is a wildcard.
    /// `false` for concrete bytes OR for positions past the pattern's
    /// `leading_len` (out-of-range is handled by the caller via
    /// `leading_byte_at`).
    #[inline]
    fn leading_is_wildcard(patterns: &[PatternData], i: u32, d: usize) -> bool {
        let p = &patterns[i as usize];
        d < p.leading_len as usize && (p.leading_wildmask & (1u64 << d)) != 0
    }

    /// Recursive node-builder. Partitions `indices` by the byte at
    /// `depth`, recurses on each non-trivial partition, and returns
    /// the id of the node it created.
    fn build_node(
        nodes: &mut Vec<TrieNode>,
        patterns: &[PatternData],
        arena: &[u8],
        indices: Vec<u32>,
        depth: u8,
    ) -> u32 {
        if indices.len() <= LEAF_THRESHOLD || depth >= MAX_DEPTH {
            let id = nodes.len() as u32;
            nodes.push(TrieNode {
                depth,
                children: Vec::new(),
                wildcard_child: None,
                leaves: indices,
            });
            return id;
        }

        let mut by_byte: Vec<Vec<u32>> = (0..256).map(|_| Vec::new()).collect();
        let mut wild: Vec<u32> = Vec::new();
        let mut terminal: Vec<u32> = Vec::new();

        let d = depth as usize;
        for i in indices {
            if Self::leading_is_wildcard(patterns, i, d) {
                wild.push(i);
            } else if let Some(b) = Self::leading_byte_at(patterns, arena, i, d) {
                by_byte[b as usize].push(i);
            } else {
                terminal.push(i);
            }
        }

        let nonempty = by_byte.iter().filter(|v| !v.is_empty()).count();
        let only_wild = nonempty == 0 && !wild.is_empty();
        let single_byte = nonempty == 1 && wild.is_empty();
        if only_wild || single_byte {
            let combined: Vec<u32> = by_byte
                .into_iter()
                .flatten()
                .chain(wild)
                .chain(terminal)
                .collect();
            return Self::build_node(nodes, patterns, arena, combined, depth + 1);
        }

        let mut children: Vec<(u8, u32)> = Vec::with_capacity(nonempty);
        for (b, bucket) in by_byte.into_iter().enumerate() {
            if bucket.is_empty() {
                continue;
            }
            let child_id = Self::build_node(nodes, patterns, arena, bucket, depth + 1);
            children.push((b as u8, child_id));
        }

        let wildcard_child = if wild.is_empty() {
            None
        } else {
            Some(Self::build_node(nodes, patterns, arena, wild, depth + 1))
        };

        let id = nodes.len() as u32;
        nodes.push(TrieNode {
            depth,
            children,
            wildcard_child,
            leaves: terminal,
        });
        id
    }

    /// Visit every candidate pattern index for `input`. The matcher
    /// then runs `pattern_matches` on each — only the indices
    /// surviving the trie traversal need that check.
    ///
    /// `f` is called with each candidate id and returns a
    /// [`ControlFlow`] — `Break` short-circuits the rest of the
    /// traversal (used by `match_public_name` once it has a hit),
    /// `Continue` keeps walking.
    ///
    /// Traversal is iterative using an explicit stack to avoid
    /// blowing the call stack on pathologically deep tries (we cap
    /// depth at 8 but the wildcard-skip path can in principle visit
    /// nodes deeper than that, and we don't want a recursive call
    /// per step in any hot loop).
    #[inline]
    pub(crate) fn visit_candidates(&self, input: &[u8], mut f: impl FnMut(u32) -> ControlFlow<()>) {
        // Stack holds just node ids — each node carries its own
        // `depth` field, so the query needs no running counter.
        // This is what lets the build skip trivial single-byte
        // partitions without breaking query correctness.
        let mut stack: Vec<u32> = Vec::with_capacity(MAX_DEPTH as usize * 2);
        stack.push(self.root);
        while let Some(node_id) = stack.pop() {
            let node = &self.nodes[node_id as usize];
            for &i in &node.leaves {
                if f(i).is_break() {
                    return;
                }
            }
            // Always follow the wildcard branch (if any) — those
            // patterns don't care what byte is at this depth.
            if let Some(wc) = node.wildcard_child {
                stack.push(wc);
            }
            // Follow the concrete-byte child matching input[node.depth].
            if let Some(&b) = input.get(node.depth as usize)
                && let Ok(ix) = node.children.binary_search_by_key(&b, |(byte, _)| *byte)
            {
                stack.push(node.children[ix].1);
            }
        }
    }

    /// Number of nodes in the trie. Useful for benchmarks/diagnostics.
    #[allow(dead_code)]
    pub(crate) fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pat;
    use crate::types::FlirtSetBuilder;

    /// Build a trie standalone from a `.pat` document by routing
    /// through the builder and reading its internal state.
    fn trie_from(text: &str) -> (PatternTrie, Vec<PatternData>, Vec<u8>) {
        let mut b = FlirtSetBuilder::new();
        pat::append(&mut b, text).unwrap();
        let arena_vec = b.arena.clone();
        let patterns = b.patterns.clone();
        let trie = PatternTrie::build(&patterns, &arena_vec);
        (trie, patterns, arena_vec)
    }

    /// Trie over an empty set should still be queryable.
    #[test]
    fn empty_trie() {
        let trie = PatternTrie::build(&[], &[]);
        let mut hits = Vec::new();
        trie.visit_candidates(&[0x55; 64], |i| {
            hits.push(i);
            ControlFlow::Continue(())
        });
        assert!(hits.is_empty());
    }

    /// Single-pattern trie should return that pattern for any input
    /// that starts with its leading byte.
    #[test]
    fn single_pattern() {
        let (trie, _p, _a) = trie_from(
            "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 foo",
        );
        let mut input = vec![0u8; 64];
        input[0] = 0x55;
        input[1] = 0x48;
        let mut hits = Vec::new();
        trie.visit_candidates(&input, |i| {
            hits.push(i);
            ControlFlow::Continue(())
        });
        assert!(hits.contains(&0), "expected pattern 0 in candidates");
    }

    /// Pattern with a wildcard at position 0 should be returned
    /// for ANY input byte at position 0.
    #[test]
    fn wildcard_at_root() {
        let (trie, _, _) = trie_from(
            "........4883EC48488D6C24204889CE0F1002488D4D0048895548488D55100F 00 0000 0010 :0000 fizz",
        );
        let mut hits = Vec::new();
        trie.visit_candidates(&[0xDE, 0xAD, 0xBE, 0xEF], |i| {
            hits.push(i);
            ControlFlow::Continue(())
        });
        assert!(hits.contains(&0));
    }

    /// With patterns that diverge at depth 1, the trie must branch
    /// once each group is above `LEAF_THRESHOLD`.
    #[test]
    fn two_patterns_branch_when_above_threshold() {
        let foo_line = "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 foo";
        let bar_line = "55564883EC48488D6C24204889CE0F1002488D4D0048895548488D55100F1102 02 ABB7 0040 :0000 bar";
        let mut text = String::new();
        for _ in 0..10 {
            text.push_str(foo_line);
            text.push('\n');
        }
        for _ in 0..10 {
            text.push_str(bar_line);
            text.push('\n');
        }
        let (trie, _, _) = trie_from(&text);

        let mut hits: Vec<u32> = Vec::new();
        trie.visit_candidates(&[0x55, 0x56, 0x00, 0x00], |i| {
            hits.push(i);
            ControlFlow::Continue(())
        });
        assert!(!hits.is_empty(), "expected bar copies in candidates");
        assert!(
            hits.iter().all(|&i| i >= 10),
            "expected ONLY bar copies (idx ≥10); got {:?}",
            hits
        );
    }

    /// Short input (fewer bytes than trie depth) should still
    /// traverse cleanly — query just stops descending when input
    /// runs out.
    #[test]
    fn short_input() {
        let (trie, _, _) = trie_from(
            "554883EC30488D6C2420E8........3D000C0000743385C074223D0008000075 30 2AF9 0050 :0000 foo",
        );
        let mut hits = Vec::new();
        trie.visit_candidates(&[0x55, 0x48], |i| {
            hits.push(i);
            ControlFlow::Continue(())
        });
        assert!(hits.contains(&0));
    }
}
