//! 【创新点2】两层式历史状态证明
//!
//! 本模块实现基于 MMR 的两层式历史状态证明系统：
//!
//! ## 两层式证明结构
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     第一层：MMR 链级证明                         │
//! │  证明 BlockADSRoot 属于主链                                      │
//! │  MMR Root → BlockADSRoot (O(log n) 证明)                        │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     第二层：块内证明                              │
//! │  证明查询结果属于 BlockADSRoot                                   │
//! │  BlockADSRoot → Components → 具体索引证明                        │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## 使用示例
//!
//! ```ignore
//! use vchain_plus::chain::mmr::{TwoLayerProof, ChainProofContext};
//!
//! // 1. 生成两层式证明
//! let proof = TwoLayerProof::generate(
//!     &chain,
//!     block_height,
//!     block_ads_root,
//!     block_proof,
//! )?;
//!
//! // 2. 验证两层式证明
//! let is_valid = proof.verify(mmr_root)?;
//! ```

use crate::chain::block::block_ads_root::{BlockADSComponents, BlockADSRoot};
use crate::chain::block::Height;
use crate::chain::mmr::helper::leaf_index_to_pos;
use crate::chain::mmr::mmr::MerkleProof as MMRMerkleProof;
use crate::chain::mmr::{BlockADSMerge, Error, Result};
use crate::chain::verify::hash::{ads_hash, bplus_roots_hash, compute_multi_ads_hash};
use crate::digest::Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 两层式证明
///
/// 包含 MMR 链级证明和块内证明，用于验证历史状态查询结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoLayerProof {
    /// 第一层：MMR 包含性证明
    pub mmr_proof: MMRProofData,
    /// 第二层：块内证明（BlockADSRoot 展开）
    pub block_proof: BlockProofData,
}

/// MMR 证明数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MMRProofData {
    /// MMR 大小（用于验证）
    pub mmr_size: u64,
    /// 区块在 MMR 中的位置
    pub position: u64,
    /// MMR 证明项
    pub proof_items: Vec<Digest>,
    /// 目标 BlockADSRoot
    pub block_ads_root: Digest,
}

/// 块内证明数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProofData {
    /// 区块高度
    pub block_height: Height,
    /// BlockADSRoot 的组件（用于展开验证）
    pub components: BlockADSComponents,
    /// 具体索引类型的证明（可选，根据查询类型）
    pub index_proof: Option<IndexProof>,
}

/// 索引证明类型
///
/// 根据不同的查询类型，包含不同的索引证明。
/// BPlusTree 和 Trie 变体携带兄弟哈希，用于重算 multi_ads_hash 并与
/// BlockADSComponents 中的承诺值比对，确保索引根确实被包含在一体化承诺中。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndexProof {
    /// ID 树证明：直接与 components.id_tree_root_hash 比对即可
    IdTree {
        /// ID 树根哈希
        root_hash: Digest,
    },
    /// B+ 树范围查询证明
    ///
    /// 验证路径: root_hash + sibling_bplus_hashes → bplus_roots_hash
    ///           → ads_hash(bplus_roots_hash, trie_root_hash)
    ///           + sibling_ads_hashes → multi_ads_hash
    ///           → 与 components.multi_ads_hash 比对
    BPlusTree {
        /// 目标维度
        dimension: u8,
        /// 目标时间窗口
        time_window: u16,
        /// 目标 B+ 树根哈希
        root_hash: Digest,
        /// 同一时间窗口内其他维度的 B+ 树根哈希（用于重建 bplus_roots_hash）
        sibling_bplus_hashes: BTreeMap<u8, Digest>,
        /// 同一时间窗口的 Trie 根哈希（用于重建单窗口 ads_hash）
        trie_root_hash: Digest,
        /// 其他时间窗口的 ads_hash（用于重建 multi_ads_hash）
        sibling_ads_hashes: BTreeMap<u16, Digest>,
    },
    /// Trie 关键词查询证明
    ///
    /// 验证路径: bplus_roots_hash + root_hash → ads_hash
    ///           + sibling_ads_hashes → multi_ads_hash
    ///           → 与 components.multi_ads_hash 比对
    Trie {
        /// 目标时间窗口
        time_window: u16,
        /// 目标 Trie 根哈希
        root_hash: Digest,
        /// 同一时间窗口所有 B+ 树根的聚合哈希（已预计算）
        bplus_roots_hash: Digest,
        /// 其他时间窗口的 ads_hash（用于重建 multi_ads_hash）
        sibling_ads_hashes: BTreeMap<u16, Digest>,
    },
    /// 复合证明（多个索引）
    Composite {
        /// 多个索引证明
        proofs: Vec<IndexProof>,
    },
}

impl TwoLayerProof {
    /// 创建新的两层式证明
    ///
    /// # 参数
    /// - `mmr_proof`: MMR 证明数据
    /// - `block_proof`: 块内证明数据
    pub fn new(mmr_proof: MMRProofData, block_proof: BlockProofData) -> Self {
        Self {
            mmr_proof,
            block_proof,
        }
    }

    /// 从 MMR 证明和区块信息构建两层式证明
    ///
    /// # 参数
    /// - `mmr_merkle_proof`: MMR 的 MerkleProof
    /// - `block_height`: 区块高度
    /// - `block_ads_root`: BlockADSRoot 摘要
    /// - `components`: BlockADSComponents
    /// - `index_proof`: 可选的索引证明
    pub fn from_mmr_proof(
        mmr_merkle_proof: &MMRMerkleProof<Digest, BlockADSMerge>,
        block_height: Height,
        block_ads_root: Digest,
        components: BlockADSComponents,
        index_proof: Option<IndexProof>,
    ) -> Self {
        let position = leaf_index_to_pos(block_height.0 as u64 - 1);
        
        Self {
            mmr_proof: MMRProofData {
                mmr_size: mmr_merkle_proof.mmr_size(),
                position,
                proof_items: mmr_merkle_proof.proof_items().to_vec(),
                block_ads_root,
            },
            block_proof: BlockProofData {
                block_height,
                components,
                index_proof,
            },
        }
    }

    /// 验证两层式证明
    ///
    /// # 参数
    /// - `mmr_root`: 当前 MMR 根哈希
    ///
    /// # 返回
    /// - `Ok(true)`: 验证通过
    /// - `Ok(false)`: 验证失败
    /// - `Err`: 验证过程出错
    pub fn verify(&self, mmr_root: Digest) -> Result<bool> {
        // 第一层验证：MMR 包含性证明
        let mmr_valid = self.verify_mmr_proof(mmr_root)?;
        if !mmr_valid {
            return Ok(false);
        }

        // 第二层验证：BlockADSRoot 组件一致性
        let block_valid = self.verify_block_proof()?;
        if !block_valid {
            return Ok(false);
        }

        Ok(true)
    }

    /// 验证第一层：MMR 包含性证明
    fn verify_mmr_proof(&self, mmr_root: Digest) -> Result<bool> {
        let proof = MMRMerkleProof::<Digest, BlockADSMerge>::new(
            self.mmr_proof.mmr_size,
            self.mmr_proof.proof_items.clone(),
        );

        let leaves = vec![(self.mmr_proof.position, self.mmr_proof.block_ads_root)];
        proof.verify(mmr_root, leaves)
    }

    /// 验证第二层：BlockADSRoot 组件一致性
    fn verify_block_proof(&self) -> Result<bool> {
        // 验证组件是否能生成正确的 BlockADSRoot
        let computed_root = self.block_proof.components.compute_root();
        
        if computed_root != self.mmr_proof.block_ads_root {
            return Ok(false);
        }

        // 如果有索引证明，验证索引证明与组件的一致性
        if let Some(ref index_proof) = self.block_proof.index_proof {
            return self.verify_index_proof(index_proof);
        }

        Ok(true)
    }

    /// 验证索引证明
    ///
    /// 对于 BPlusTree/Trie，利用携带的兄弟哈希重算 multi_ads_hash，
    /// 并与 BlockADSComponents 中已承诺的值比对。
    /// 这条验证链路与 verify.rs::inner_verify 中的逻辑完全一致。
    fn verify_index_proof(&self, index_proof: &IndexProof) -> Result<bool> {
        match index_proof {
            IndexProof::IdTree { root_hash } => {
                // 验证 ID 树根哈希与组件中的一致
                Ok(*root_hash == self.block_proof.components.id_tree_root_hash)
            }
            IndexProof::BPlusTree {
                dimension,
                time_window,
                root_hash,
                sibling_bplus_hashes,
                trie_root_hash,
                sibling_ads_hashes,
            } => {
                // Step 1: 将目标 B+ 树根与兄弟根合并，重算 bplus_roots_hash
                let mut all_bplus: BTreeMap<u8, Digest> = sibling_bplus_hashes.clone();
                all_bplus.insert(*dimension, *root_hash);
                let bplus_hash = bplus_roots_hash(all_bplus.iter());

                // Step 2: 计算当前时间窗口的 ads_hash
                let this_ads = ads_hash(bplus_hash, *trie_root_hash);

                // Step 3: 将当前窗口与兄弟窗口合并，重算 multi_ads_hash
                let mut all_ads: BTreeMap<u16, Digest> = sibling_ads_hashes.clone();
                all_ads.insert(*time_window, this_ads);
                let computed_multi_ads_hash = compute_multi_ads_hash(all_ads.iter());

                // Step 4: 与 components 中已承诺的 multi_ads_hash 比对
                Ok(computed_multi_ads_hash == self.block_proof.components.multi_ads_hash)
            }
            IndexProof::Trie {
                time_window,
                root_hash,
                bplus_roots_hash: bplus_hash,
                sibling_ads_hashes,
            } => {
                // Step 1: 计算当前时间窗口的 ads_hash
                let this_ads = ads_hash(*bplus_hash, *root_hash);

                // Step 2: 将当前窗口与兄弟窗口合并，重算 multi_ads_hash
                let mut all_ads: BTreeMap<u16, Digest> = sibling_ads_hashes.clone();
                all_ads.insert(*time_window, this_ads);
                let computed_multi_ads_hash = compute_multi_ads_hash(all_ads.iter());

                // Step 3: 与 components 中已承诺的 multi_ads_hash 比对
                Ok(computed_multi_ads_hash == self.block_proof.components.multi_ads_hash)
            }
            IndexProof::Composite { proofs } => {
                // 验证所有子证明
                for proof in proofs {
                    if !self.verify_index_proof(proof)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    /// 获取区块高度
    pub fn block_height(&self) -> Height {
        self.block_proof.block_height
    }

    /// 获取 BlockADSRoot
    pub fn block_ads_root(&self) -> Digest {
        self.mmr_proof.block_ads_root
    }

    /// 获取 BlockADSComponents
    pub fn components(&self) -> &BlockADSComponents {
        &self.block_proof.components
    }

    /// 获取 MMR 位置
    pub fn mmr_position(&self) -> u64 {
        self.mmr_proof.position
    }
}

/// 链证明上下文
///
/// 用于生成和验证两层式证明的辅助结构
#[derive(Debug, Clone)]
pub struct ChainProofContext {
    /// 当前 MMR 根
    pub mmr_root: Digest,
    /// 当前 MMR 大小
    pub mmr_size: u64,
    /// 区块总数
    pub block_count: u64,
}

impl ChainProofContext {
    /// 创建新的链证明上下文
    pub fn new(mmr_root: Digest, mmr_size: u64, block_count: u64) -> Self {
        Self {
            mmr_root,
            mmr_size,
            block_count,
        }
    }

    /// 验证区块高度是否有效
    pub fn is_valid_height(&self, height: Height) -> bool {
        height.0 > 0 && height.0 as u64 <= self.block_count
    }

    /// 获取区块在 MMR 中的位置
    pub fn get_mmr_position(&self, height: Height) -> Option<u64> {
        if !self.is_valid_height(height) {
            return None;
        }
        Some(leaf_index_to_pos(height.0 as u64 - 1))
    }
}

/// 两层式证明验证结果
#[derive(Debug, Clone)]
pub struct TwoLayerVerifyResult {
    /// MMR 证明是否有效
    pub mmr_valid: bool,
    /// 块内证明是否有效
    pub block_valid: bool,
    /// 索引证明是否有效（如果有）
    pub index_valid: Option<bool>,
    /// 总体是否有效
    pub is_valid: bool,
    /// 验证的区块高度
    pub block_height: Height,
    /// 验证的 BlockADSRoot
    pub block_ads_root: Digest,
}

impl TwoLayerVerifyResult {
    /// 创建验证成功的结果
    pub fn success(block_height: Height, block_ads_root: Digest) -> Self {
        Self {
            mmr_valid: true,
            block_valid: true,
            index_valid: Some(true),
            is_valid: true,
            block_height,
            block_ads_root,
        }
    }

    /// 创建 MMR 验证失败的结果
    pub fn mmr_failed(block_height: Height, block_ads_root: Digest) -> Self {
        Self {
            mmr_valid: false,
            block_valid: false,
            index_valid: None,
            is_valid: false,
            block_height,
            block_ads_root,
        }
    }

    /// 创建块内验证失败的结果
    pub fn block_failed(block_height: Height, block_ads_root: Digest) -> Self {
        Self {
            mmr_valid: true,
            block_valid: false,
            index_valid: None,
            is_valid: false,
            block_height,
            block_ads_root,
        }
    }
}

/// 扩展的两层式证明验证
impl TwoLayerProof {
    /// 详细验证并返回验证结果
    pub fn verify_detailed(&self, mmr_root: Digest) -> Result<TwoLayerVerifyResult> {
        let block_height = self.block_proof.block_height;
        let block_ads_root = self.mmr_proof.block_ads_root;

        // 第一层验证：MMR
        let mmr_valid = self.verify_mmr_proof(mmr_root)?;
        if !mmr_valid {
            return Ok(TwoLayerVerifyResult::mmr_failed(block_height, block_ads_root));
        }

        // 第二层验证：BlockADSRoot 组件
        let computed_root = self.block_proof.components.compute_root();
        let block_valid = computed_root == block_ads_root;
        if !block_valid {
            return Ok(TwoLayerVerifyResult::block_failed(block_height, block_ads_root));
        }

        // 索引证明验证（如果有）
        let index_valid = if let Some(ref index_proof) = self.block_proof.index_proof {
            Some(self.verify_index_proof(index_proof)?)
        } else {
            None
        };

        let is_valid = mmr_valid && block_valid && index_valid.unwrap_or(true);

        Ok(TwoLayerVerifyResult {
            mmr_valid,
            block_valid,
            index_valid,
            is_valid,
            block_height,
            block_ads_root,
        })
    }
}

/// 批量两层式证明
///
/// 用于一次验证多个区块的证明
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTwoLayerProof {
    /// MMR 大小
    pub mmr_size: u64,
    /// 多个区块的证明
    pub proofs: Vec<SingleBlockProof>,
    /// 共享的 MMR 证明项（优化存储）
    pub shared_mmr_proof_items: Vec<Digest>,
}

/// 单个区块的证明（用于批量证明）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleBlockProof {
    /// 区块高度
    pub block_height: Height,
    /// MMR 位置
    pub position: u64,
    /// BlockADSRoot
    pub block_ads_root: Digest,
    /// BlockADSComponents
    pub components: BlockADSComponents,
    /// 索引证明（可选）
    pub index_proof: Option<IndexProof>,
}

impl BatchTwoLayerProof {
    /// 创建批量证明
    pub fn new(
        mmr_size: u64,
        proofs: Vec<SingleBlockProof>,
        shared_mmr_proof_items: Vec<Digest>,
    ) -> Self {
        Self {
            mmr_size,
            proofs,
            shared_mmr_proof_items,
        }
    }

    /// 验证批量证明
    pub fn verify(&self, mmr_root: Digest) -> Result<Vec<bool>> {
        let mut results = Vec::with_capacity(self.proofs.len());

        // 构造 MMR 证明
        let mmr_proof = MMRMerkleProof::<Digest, BlockADSMerge>::new(
            self.mmr_size,
            self.shared_mmr_proof_items.clone(),
        );

        // 收集所有叶子节点
        let leaves: Vec<(u64, Digest)> = self
            .proofs
            .iter()
            .map(|p| (p.position, p.block_ads_root))
            .collect();

        // 验证 MMR 证明
        let mmr_valid = mmr_proof.verify(mmr_root, leaves)?;

        // 验证每个区块的组件一致性
        for proof in &self.proofs {
            let computed_root = proof.components.compute_root();
            let block_valid = computed_root == proof.block_ads_root;
            results.push(mmr_valid && block_valid);
        }

        Ok(results)
    }

    /// 获取区块数量
    pub fn block_count(&self) -> usize {
        self.proofs.len()
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
    fn test_two_layer_proof_creation() {
        let components = BlockADSComponents::new(
            make_digest(1),
            make_digest(2),
            make_digest(3),
        );
        let block_ads_root = components.compute_root();

        let mmr_proof = MMRProofData {
            mmr_size: 1,
            position: 0,
            proof_items: vec![],
            block_ads_root,
        };

        let block_proof = BlockProofData {
            block_height: Height(1),
            components: components.clone(),
            index_proof: None,
        };

        let proof = TwoLayerProof::new(mmr_proof, block_proof);

        assert_eq!(proof.block_height(), Height(1));
        assert_eq!(proof.block_ads_root(), block_ads_root);
        assert_eq!(proof.components(), &components);
    }

    #[test]
    fn test_block_proof_verification() {
        let components = BlockADSComponents::new(
            make_digest(1),
            make_digest(2),
            make_digest(3),
        );
        let block_ads_root = components.compute_root();

        let mmr_proof = MMRProofData {
            mmr_size: 1,
            position: 0,
            proof_items: vec![],
            block_ads_root,
        };

        let block_proof = BlockProofData {
            block_height: Height(1),
            components,
            index_proof: None,
        };

        let proof = TwoLayerProof::new(mmr_proof, block_proof);

        // 验证块内证明应该通过
        assert!(proof.verify_block_proof().unwrap());
    }

    #[test]
    fn test_block_proof_verification_failure() {
        let components = BlockADSComponents::new(
            make_digest(1),
            make_digest(2),
            make_digest(3),
        );
        
        // 使用错误的 block_ads_root
        let wrong_root = make_digest(99);

        let mmr_proof = MMRProofData {
            mmr_size: 1,
            position: 0,
            proof_items: vec![],
            block_ads_root: wrong_root,
        };

        let block_proof = BlockProofData {
            block_height: Height(1),
            components,
            index_proof: None,
        };

        let proof = TwoLayerProof::new(mmr_proof, block_proof);

        // 验证块内证明应该失败
        assert!(!proof.verify_block_proof().unwrap());
    }

    #[test]
    fn test_index_proof_id_tree() {
        let id_tree_hash = make_digest(2);
        let components = BlockADSComponents::new(
            make_digest(1),
            id_tree_hash,
            make_digest(3),
        );
        let block_ads_root = components.compute_root();

        let mmr_proof = MMRProofData {
            mmr_size: 1,
            position: 0,
            proof_items: vec![],
            block_ads_root,
        };

        let block_proof = BlockProofData {
            block_height: Height(1),
            components,
            index_proof: Some(IndexProof::IdTree {
                root_hash: id_tree_hash,
            }),
        };

        let proof = TwoLayerProof::new(mmr_proof, block_proof);

        // 验证索引证明应该通过
        assert!(proof.verify_block_proof().unwrap());
    }

    #[test]
    fn test_chain_proof_context() {
        let ctx = ChainProofContext::new(make_digest(1), 15, 10);

        assert!(ctx.is_valid_height(Height(1)));
        assert!(ctx.is_valid_height(Height(10)));
        assert!(!ctx.is_valid_height(Height(0)));
        assert!(!ctx.is_valid_height(Height(11)));

        assert_eq!(ctx.get_mmr_position(Height(1)), Some(0));
        assert_eq!(ctx.get_mmr_position(Height(2)), Some(1));
        assert_eq!(ctx.get_mmr_position(Height(3)), Some(3));
    }

    #[test]
    fn test_verify_detailed() {
        let components = BlockADSComponents::new(
            make_digest(1),
            make_digest(2),
            make_digest(3),
        );
        let block_ads_root = components.compute_root();

        let mmr_proof = MMRProofData {
            mmr_size: 1,
            position: 0,
            proof_items: vec![],
            block_ads_root,
        };

        let block_proof = BlockProofData {
            block_height: Height(1),
            components,
            index_proof: None,
        };

        let proof = TwoLayerProof::new(mmr_proof, block_proof);

        // 验证详细结果
        let result = proof.verify_detailed(block_ads_root).unwrap();
        
        assert!(result.mmr_valid);
        assert!(result.block_valid);
        assert!(result.is_valid);
        assert_eq!(result.block_height, Height(1));
    }
}