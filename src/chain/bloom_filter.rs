//! Adaptive Bloom filter for vchain-plus.
//!
//! Each block-time-window owns a Bloom filter sized by its own keyword
//! cardinality at a fixed target false-positive rate. The filter answers:
//!
//!     "Is keyword K possibly in (block, time_win)'s keyword set?"
//!
//! Negative answers are 100% reliable (no false negatives) and let
//! query verification short-circuit the trie path. Positive answers
//! may be false positives and fall through to the existing trie path.
//!
//! Hash function: blake2b (same as the rest of the codebase). The 512-bit
//! digest is partitioned into `k` non-overlapping 32-bit chunks, each
//! interpreted as a position index modulo `size`.

use crate::digest::{blake2, Digest, Digestible};
use serde::{Deserialize, Serialize};

/// 【方案 X】块级 Bloom 过滤器的默认目标假阳率 (1%)
///
/// 实验中如需调整可修改此常量。1% 是 VBF 论文表 1 中 k=8、m/n=12
/// 配置的目标值，便于跨论文对比。
pub const DEFAULT_BLOOM_TARGET_FPR: f64 = 0.01;

/// Wrapper over the Bloom filter's digest, mirroring `TrieRoot`.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BloomFilterRoot {
    pub(crate) root_hash: Digest,
}

impl Digestible for BloomFilterRoot {
    fn to_digest(&self) -> Digest {
        self.root_hash
    }
}

/// An adaptive Bloom filter: parameters `(size, k)` are derived per-block
/// from `(n_items, target_fpr)`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdaptiveBloomFilter {
    /// Number of bits in the filter.
    pub size: u32,
    /// Number of hash chunks used per item.
    pub k: u8,
    /// Bit array, ceil(size / 8) bytes.
    pub bits: Vec<u8>,
}

impl Default for AdaptiveBloomFilter {
    fn default() -> Self {
        Self {
            size: 0,
            k: 0,
            bits: Vec::new(),
        }
    }
}

/// Optimal Bloom filter size in bits for `n` items at target FPR `p`:
///     m = ceil(-n * ln(p) / ln(2)^2)
#[inline]
fn optimal_size_bits(n_items: usize, target_fpr: f64) -> u32 {
    if n_items == 0 {
        return 8; // 1 byte minimum to keep digesting well-defined
    }
    let m = -(n_items as f64) * target_fpr.ln() / (std::f64::consts::LN_2.powi(2));
    m.ceil() as u32
}

/// Optimal number of hash chunks:
///     k = round((m / n) * ln(2))
#[inline]
fn optimal_k(size_bits: u32, n_items: usize) -> u8 {
    if n_items == 0 {
        return 1;
    }
    let k = (size_bits as f64 / n_items as f64) * std::f64::consts::LN_2;
    let k_round = k.round().max(1.0).min(16.0); // cap at 16 chunks (blake2b gives 512 bits = 16 * 32 bits)
    k_round as u8
}

impl AdaptiveBloomFilter {
    /// Build a Bloom filter over `keywords` at the given target false-positive rate.
    pub fn new_for_keywords(keywords: &[Vec<u8>], target_fpr: f64) -> Self {
        let n = keywords.len();
        let size = optimal_size_bits(n, target_fpr);
        let k = optimal_k(size, n);
        let n_bytes = ((size as usize) + 7) / 8;
        let mut bf = Self {
            size,
            k,
            bits: vec![0u8; n_bytes],
        };
        for kw in keywords {
            bf.insert(kw);
        }
        bf
    }

    /// Internal: derive k bit positions for an item.
    /// We use a 64-byte blake2b digest (not the project's 32-byte one) so
    /// that up to 16 independent 32-bit position slices are available.
    /// The 32-byte `Digestible` digest below is reserved for the BF root.
    fn positions(&self, item: &[u8]) -> Vec<u32> {
        let mut state = blake2b_simd::Params::new()
            .hash_length(64)
            .to_state();
        state.update(item);
        let hash = state.finalize();
        let bytes = hash.as_bytes(); // 64 bytes
        let k = self.k as usize;
        let mut positions = Vec::with_capacity(k);
        for i in 0..k {
            let offset = i * 4;
            let chunk = [
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ];
            let h = u32::from_le_bytes(chunk);
            positions.push(h % self.size);
        }
        positions
    }

    /// Insert an item.
    pub fn insert(&mut self, item: &[u8]) {
        for pos in self.positions(item) {
            let byte_idx = (pos / 8) as usize;
            let bit_idx = (pos % 8) as u8;
            self.bits[byte_idx] |= 1u8 << bit_idx;
        }
    }

    /// Test whether an item *may* be in the filter.
    /// Returns `false` only when the item is definitely not present.
    pub fn may_contain(&self, item: &[u8]) -> bool {
        if self.size == 0 {
            return false;
        }
        for pos in self.positions(item) {
            let byte_idx = (pos / 8) as usize;
            let bit_idx = (pos % 8) as u8;
            if self.bits[byte_idx] & (1u8 << bit_idx) == 0 {
                return false;
            }
        }
        true
    }

    /// Return a witness for a NEGATIVE membership claim: the index of a
    /// position that the item maps to which is zero in the filter.
    /// `None` if the item is (possibly) present.
    pub fn witness_negation(&self, item: &[u8]) -> Option<u32> {
        if self.size == 0 {
            return None;
        }
        for pos in self.positions(item) {
            let byte_idx = (pos / 8) as usize;
            let bit_idx = (pos % 8) as u8;
            if self.bits[byte_idx] & (1u8 << bit_idx) == 0 {
                return Some(pos);
            }
        }
        None
    }

    /// Serialize parameters and bit array into the filter's root digest.
    pub fn root(&self) -> BloomFilterRoot {
        BloomFilterRoot {
            root_hash: self.to_digest(),
        }
    }
}

impl Digestible for AdaptiveBloomFilter {
    fn to_digest(&self) -> Digest {
        let mut state = blake2().to_state();
        state.update(&self.size.to_le_bytes());
        state.update(&[self.k]);
        state.update(&self.bits);
        Digest::from(state.finalize())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn kws(items: &[&str]) -> Vec<Vec<u8>> {
        items.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn empty_filter_rejects_everything() {
        let bf = AdaptiveBloomFilter::default();
        assert!(!bf.may_contain(b"anything"));
    }

    #[test]
    fn inserted_items_always_found() {
        // No false negatives is the critical property
        let items = kws(&[
            "0xae2fc483527b8ef99eb5d9b44875f005ba1fae13",
            "0x1f2f10d1c40777ae1da742455c65828ff36df387",
            "0xfea37c8f04d0622e4434c50e5dd51a45ba7c7527",
        ]);
        let bf = AdaptiveBloomFilter::new_for_keywords(&items, 0.01);
        for item in &items {
            assert!(bf.may_contain(item), "false negative on {:?}", item);
        }
    }

    #[test]
    fn negation_witness_for_absent_items() {
        let items = kws(&["alice", "bob", "carol"]);
        let bf = AdaptiveBloomFilter::new_for_keywords(&items, 0.01);
        // An item NOT in the filter should usually get a witness
        // (unless it happens to be a false positive)
        let absent = b"david_not_in_filter_random";
        if !bf.may_contain(absent) {
            let w = bf.witness_negation(absent);
            assert!(w.is_some());
            let pos = w.unwrap();
            let byte_idx = (pos / 8) as usize;
            let bit_idx = (pos % 8) as u8;
            assert_eq!(bf.bits[byte_idx] & (1u8 << bit_idx), 0,
                       "witness must point to a zero bit");
        }
    }

    #[test]
    fn fpr_in_expected_range() {
        // With 1000 items at 1% target FPR, observed FPR should be roughly 1-3%
        // (small filters have noisy FPR; we allow generous slack)
        let inserted: Vec<Vec<u8>> = (0..1000)
            .map(|i| format!("inserted_{}", i).into_bytes())
            .collect();
        let bf = AdaptiveBloomFilter::new_for_keywords(&inserted, 0.01);

        let mut fp = 0;
        let trials = 10_000;
        for i in 0..trials {
            let probe = format!("probe_{}", i);
            if bf.may_contain(probe.as_bytes()) {
                fp += 1;
            }
        }
        let observed_fpr = fp as f64 / trials as f64;
        // Should be close to 1% but not absurdly far
        assert!(observed_fpr < 0.05,
                "observed FPR {} is way above 1% target", observed_fpr);
        eprintln!("observed FPR: {:.4} (target 0.01)", observed_fpr);
    }

    #[test]
    fn adaptive_sizing_for_different_block_sizes() {
        // Sparse block: 10 keywords → small filter
        let small = AdaptiveBloomFilter::new_for_keywords(
            &(0..10).map(|i| format!("k{}", i).into_bytes()).collect::<Vec<_>>(),
            0.01,
        );
        // Dense block: 500 keywords → large filter
        let big = AdaptiveBloomFilter::new_for_keywords(
            &(0..500).map(|i| format!("k{}", i).into_bytes()).collect::<Vec<_>>(),
            0.01,
        );
        assert!(big.size > small.size * 10,
                "size should scale linearly with n_items");
        eprintln!("sparse block: {} bits, dense block: {} bits",
                  small.size, big.size);
    }

    #[test]
    fn digest_is_deterministic_and_sensitive_to_content() {
        let items_a = kws(&["alice", "bob"]);
        let items_b = kws(&["alice", "bob"]);
        let items_c = kws(&["alice", "carol"]);
        let bf_a = AdaptiveBloomFilter::new_for_keywords(&items_a, 0.01);
        let bf_b = AdaptiveBloomFilter::new_for_keywords(&items_b, 0.01);
        let bf_c = AdaptiveBloomFilter::new_for_keywords(&items_c, 0.01);
        assert_eq!(bf_a.to_digest(), bf_b.to_digest());
        assert_ne!(bf_a.to_digest(), bf_c.to_digest());
    }
}