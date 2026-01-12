//! MMR (Merkle Mountain Range) 链级承诺模块
//!
//! 【创新点2】基于 MMR 的 BlockADSRoot 链级承诺与两层式历史状态证明
//!
//! ## 模块结构
//!
//! - `mmr`: MMR 核心数据结构和算法
//! - `merge`: Merge trait 定义
//! - `block_ads_merge`: BlockADSRoot 的 Merge 实现
//! - `mmr_store`: MMR 存储 trait 定义
//! - `helper`: MMR 辅助函数
//! - `error`: 错误类型定义
//!
//! ## 使用示例
//!
//! ```ignore
//! use vchain_plus::chain::mmr::{MMR, BlockADSMerge, MemStore};
//! use vchain_plus::digest::Digest;
//!
//! // 创建内存存储
//! let store = MemStore::default();
//!
//! // 创建 MMR
//! let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store);
//!
//! // 插入 BlockADSRoot
//! let pos = mmr.push(block_ads_root.to_digest())?;
//!
//! // 获取 MMR 根
//! let root = mmr.get_root()?;
//!
//! // 生成包含性证明
//! let proof = mmr.gen_proof(vec![pos])?;
//!
//! // 验证证明
//! assert!(proof.verify(root, vec![(pos, block_ads_root.to_digest())])?);
//! ```

pub mod block_ads_merge;
pub mod error;
pub mod helper;
pub mod merge;
pub mod mmr;
pub mod mmr_store;

// 重新导出常用类型
pub use block_ads_merge::BlockADSMerge;
pub use error::{Error, Result};
pub use merge::Merge;
pub use mmr::{MerkleProof, MMR};
pub use mmr_store::{MMRBatch, MMRStoreReadOps, MMRStoreWriteOps, MemStore};