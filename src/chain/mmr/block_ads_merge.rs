//! BlockADSRoot 的 MMR 合并实现
//!
//! 【创新点2】链级承诺的核心组件
//!
//! 为 MMR 提供合并两个 BlockADSRoot 哈希的能力。
//! 当 MMR 需要将两个子节点合并成父节点时，会调用此模块的 merge 函数。
//!
//! ## 在 MMR 中的作用
//!
//! ```text
//!        MMR Root (链级承诺)
//!            │
//!        ┌───┴───┐
//!        │       │
//!       ┌┴┐     ┌┴┐    ← 内部节点由 merge() 计算
//!       │ │     │ │
//!      B0 B1   B2 B3   ← 叶子节点是每个区块的 BlockADSRoot
//! ```
//!
//! ## 使用示例
//!
//! ```ignore
//! use vchain_plus::chain::mmr::{MMR, BlockADSMerge};
//!
//! // 创建使用 BlockADSMerge 的 MMR
//! let mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store);
//!
//! // 插入 BlockADSRoot
//! mmr.push(block_ads_root.to_digest())?;
//! ```

use crate::chain::mmr::error::Result;
use crate::chain::mmr::merge::Merge;
use crate::digest::{blake2, Digest};

/// BlockADSRoot 的 MMR 合并器
///
/// 实现 `Merge` trait，用于在 MMR 中合并两个 BlockADSRoot 的 Digest。
/// 
/// 合并算法：`parent = Blake2b(left || right)`
/// 
/// 这确保了：
/// - 确定性：相同输入总是产生相同输出
/// - 抗碰撞：不同输入产生相同输出的概率极低
/// - 顺序敏感：`merge(a, b) != merge(b, a)`
pub struct BlockADSMerge;

impl Merge for BlockADSMerge {
    type Item = Digest;

    /// 合并两个子节点哈希，生成父节点哈希
    ///
    /// 用于 MMR 内部节点的计算。
    ///
    /// # 参数
    /// - `left`: 左子节点的哈希（较早的区块）
    /// - `right`: 右子节点的哈希（较晚的区块）
    ///
    /// # 返回
    /// 合并后的父节点哈希
    ///
    /// # 计算方式
    /// ```text
    /// parent = Blake2b(left.as_bytes() || right.as_bytes())
    /// ```
    fn merge(left: &Digest, right: &Digest) -> Result<Digest> {
        let mut state = blake2().to_state();
        state.update(left.as_bytes());
        state.update(right.as_bytes());
        Ok(Digest::from(state.finalize()))
    }

    /// 合并两个峰值哈希（用于 MMR 根计算）
    ///
    /// MMR 的特点是可能有多个峰值（peaks），最终需要将所有峰值合并成一个根。
    /// 
    /// **注意**：MMR 的峰值合并是从右到左进行的（bagging），
    /// 即先合并最右边的两个峰值，然后依次向左合并。
    /// 
    /// # 参数
    /// - `right_peak`: 右侧峰值（通常是较小的子树）
    /// - `left_peak`: 左侧峰值（通常是较大的子树）
    ///
    /// # 计算方式
    /// ```text
    /// bagged = Blake2b(right_peak || left_peak)
    /// ```
    fn merge_peaks(right_peak: &Digest, left_peak: &Digest) -> Result<Digest> {
        let mut state = blake2().to_state();
        state.update(right_peak.as_bytes());
        state.update(left_peak.as_bytes());
        Ok(Digest::from(state.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 辅助函数：创建测试用的 Digest
    fn make_digest(byte: u8) -> Digest {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        Digest::from(bytes)
    }

    #[test]
    fn test_merge_deterministic() {
        // 相同输入应产生相同输出（确定性）
        let left = make_digest(1);
        let right = make_digest(2);

        let result1 = BlockADSMerge::merge(&left, &right).unwrap();
        let result2 = BlockADSMerge::merge(&left, &right).unwrap();

        assert_eq!(result1, result2, "合并结果应该是确定性的");
    }

    #[test]
    fn test_merge_order_matters() {
        // 不同顺序应产生不同结果（顺序敏感）
        let a = make_digest(1);
        let b = make_digest(2);

        let result_ab = BlockADSMerge::merge(&a, &b).unwrap();
        let result_ba = BlockADSMerge::merge(&b, &a).unwrap();

        assert_ne!(result_ab, result_ba, "merge(a,b) 应该不等于 merge(b,a)");
    }

    #[test]
    fn test_merge_different_inputs_different_outputs() {
        // 不同输入应产生不同结果
        let left1 = make_digest(1);
        let right1 = make_digest(2);

        let left2 = make_digest(3);
        let right2 = make_digest(4);

        let result1 = BlockADSMerge::merge(&left1, &right1).unwrap();
        let result2 = BlockADSMerge::merge(&left2, &right2).unwrap();

        assert_ne!(result1, result2, "不同输入应产生不同输出");
    }

    #[test]
    fn test_merge_not_equal_to_default() {
        // 合并结果不应该是默认值（除非输入都是零）
        let left = make_digest(1);
        let right = make_digest(2);

        let result = BlockADSMerge::merge(&left, &right).unwrap();

        assert_ne!(result, Digest::default(), "合并结果不应为默认值");
    }

    #[test]
    fn test_merge_peaks_deterministic() {
        // 峰值合并也应该是确定性的
        let peak1 = make_digest(10);
        let peak2 = make_digest(20);

        let result1 = BlockADSMerge::merge_peaks(&peak1, &peak2).unwrap();
        let result2 = BlockADSMerge::merge_peaks(&peak1, &peak2).unwrap();

        assert_eq!(result1, result2, "峰值合并应该是确定性的");
    }

    #[test]
    fn test_merge_peaks_order_matters() {
        // 峰值合并的顺序也应该敏感
        let peak1 = make_digest(10);
        let peak2 = make_digest(20);

        let result_12 = BlockADSMerge::merge_peaks(&peak1, &peak2).unwrap();
        let result_21 = BlockADSMerge::merge_peaks(&peak2, &peak1).unwrap();

        assert_ne!(result_12, result_21, "merge_peaks(a,b) 应该不等于 merge_peaks(b,a)");
    }

    #[test]
    fn test_merge_vs_merge_peaks_different() {
        // merge 和 merge_peaks 使用相同参数但顺序不同，结果应该不同
        let a = make_digest(1);
        let b = make_digest(2);

        // merge(left, right) = Blake2b(left || right)
        let merge_result = BlockADSMerge::merge(&a, &b).unwrap();
        
        // merge_peaks(right, left) = Blake2b(right || left)
        // 如果用相同的 a, b 调用，merge_peaks(a, b) = Blake2b(a || b)
        let peaks_result = BlockADSMerge::merge_peaks(&a, &b).unwrap();

        // 由于两者都是 Blake2b(a || b)，结果应该相同
        assert_eq!(merge_result, peaks_result, 
            "当参数顺序相同时，merge 和 merge_peaks 结果应该相同");
    }

    #[test]
    fn test_simulated_mmr_construction() {
        // 模拟 MMR 构建过程
        // 
        //       root
        //      /    \
        //    p01    B2
        //   /  \
        //  B0  B1
        //
        let block0 = make_digest(100);
        let block1 = make_digest(101);
        let block2 = make_digest(102);

        // 合并 B0 和 B1
        let parent_01 = BlockADSMerge::merge(&block0, &block1).unwrap();

        // 此时有两个峰值：parent_01 和 block2
        // MMR 根 = merge_peaks(block2, parent_01)  // 从右到左
        let root = BlockADSMerge::merge_peaks(&block2, &parent_01).unwrap();

        assert_ne!(root, Digest::default(), "MMR 根不应为空");
        assert_ne!(root, parent_01, "根应该不等于中间节点");
        assert_ne!(root, block2, "根应该不等于叶子节点");

        println!("模拟 MMR 构建成功:");
        println!("  Block0: {:?}", block0);
        println!("  Block1: {:?}", block1);
        println!("  Block2: {:?}", block2);
        println!("  Parent(0,1): {:?}", parent_01);
        println!("  MMR Root: {:?}", root);
    }
}