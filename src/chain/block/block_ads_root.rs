//! BlockADSRoot: 块内多类型索引与累加器的一体化承诺
//!
//! 创新点1：将各类索引根、摘要，通过确定性密码学哈希函数进行组合承诺，
//! 聚合为一个统一的 BlockADSRoot。
//!
//! 该设计在不改变各索引结构内部优化空间的前提下，将多种索引和集合摘要
//! 对外统一为单一块级承诺接口，使多类型查询的可验证性可以共用同一个块级根。

use crate::digest::{blake2, Digest, Digestible};
use serde::{Deserialize, Serialize};

/// BlockADSRoot 的组成部分
///
/// 明确定义承诺的各个组件，提供结构化的展开验证接口。
/// 后续如需添加新的索引类型或新的累加器摘要，只需扩展此结构即可。
#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct BlockADSComponents {
    /// 对象 ID 集合的哈希承诺
    /// 用于验证返回的对象 ID 是合法的区块内 ID
    pub id_set_root_hash: Digest,

    /// ID 树根哈希
    /// 用于提供 "给定 ID 能找到对应对象" 的证明路径
    pub id_tree_root_hash: Digest,

    /// BlockMultiADS 的哈希（包含各时间窗口的 B+树根和 Trie 根）
    /// 用于范围查询和关键词查询的验证
    pub multi_ads_hash: Digest,
}

impl BlockADSComponents {
    /// 创建新的 BlockADSComponents
    pub fn new(
        id_set_root_hash: Digest,
        id_tree_root_hash: Digest,
        multi_ads_hash: Digest,
    ) -> Self {
        Self {
            id_set_root_hash,
            id_tree_root_hash,
            multi_ads_hash,
        }
    }

    /// 计算组件的统一承诺根
    ///
    /// 使用 Blake2b 哈希函数，按确定顺序拼接各组件进行承诺：
    /// root = Blake2b(id_set_root_hash || id_tree_root_hash || multi_ads_hash)
    pub fn compute_root(&self) -> Digest {
        let mut state = blake2().to_state();
        state.update(self.id_set_root_hash.as_bytes());
        state.update(self.id_tree_root_hash.as_bytes());
        state.update(self.multi_ads_hash.as_bytes());
        Digest::from(state.finalize())
    }
}

impl Digestible for BlockADSComponents {
    fn to_digest(&self) -> Digest {
        self.compute_root()
    }
}

/// 块内多类型索引与累加器的一体化承诺根
///
/// BlockADSRoot 作为块内所有认证数据结构的统一承诺接口：
/// - 轻节点只需跟踪 32 字节的 root
/// - 验证时通过 components 展开验证
/// - 为 MMR 链级承诺提供自然接口
#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct BlockADSRoot {
    /// 统一的 32 字节承诺
    root: Digest,
}

impl BlockADSRoot {
    /// 从组件构建 BlockADSRoot
    pub fn from_components(components: &BlockADSComponents) -> Self {
        Self {
            root: components.compute_root(),
        }
    }

    /// 从已计算的根哈希创建（用于从存储加载）
    pub fn from_digest(root: Digest) -> Self {
        Self { root }
    }

    /// 获取统一承诺根（轻节点只需存储这个）
    pub fn root(&self) -> &Digest {
        &self.root
    }

    /// 获取根的 Digest 值
    pub fn to_digest_value(&self) -> Digest {
        self.root
    }

    /// 验证组件是否与根一致
    ///
    /// 轻节点持有 root，全节点提供 components，
    /// 通过此方法验证 components 确实能生成 root
    pub fn verify_components(&self, components: &BlockADSComponents) -> bool {
        components.compute_root() == self.root
    }
}

impl Digestible for BlockADSRoot {
    fn to_digest(&self) -> Digest {
        self.root
    }
}

impl From<Digest> for BlockADSRoot {
    fn from(digest: Digest) -> Self {
        Self::from_digest(digest)
    }
}

impl From<BlockADSRoot> for Digest {
    fn from(root: BlockADSRoot) -> Self {
        root.root
    }
}

impl From<&BlockADSComponents> for BlockADSRoot {
    fn from(components: &BlockADSComponents) -> Self {
        Self::from_components(components)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_ads_root_creation() {
        // 创建测试用的组件
        let id_set_hash = Digest::default();
        let id_tree_hash = Digest::default();
        let multi_ads_hash = Digest::default();

        let components = BlockADSComponents::new(id_set_hash, id_tree_hash, multi_ads_hash);

        // 从组件创建 BlockADSRoot
        let ads_root = BlockADSRoot::from_components(&components);

        // 验证组件
        assert!(ads_root.verify_components(&components));
    }

    #[test]
    fn test_block_ads_root_deterministic() {
        // 相同的组件应该产生相同的根
        let components1 = BlockADSComponents::new(
            Digest::default(),
            Digest::default(),
            Digest::default(),
        );

        let components2 = BlockADSComponents::new(
            Digest::default(),
            Digest::default(),
            Digest::default(),
        );

        let root1 = BlockADSRoot::from_components(&components1);
        let root2 = BlockADSRoot::from_components(&components2);

        assert_eq!(root1.root(), root2.root());
    }

    #[test]
    fn test_block_ads_root_different_components() {
        // 不同的组件应该产生不同的根
        let components1 = BlockADSComponents::new(
            Digest::default(),
            Digest::default(),
            Digest::default(),
        );

        // 创建一个非默认的 Digest
        let mut different_bytes = [0u8; 32];
        different_bytes[0] = 1;
        let different_digest = Digest::from(different_bytes);

        let components2 = BlockADSComponents::new(
            different_digest,
            Digest::default(),
            Digest::default(),
        );

        let root1 = BlockADSRoot::from_components(&components1);
        let root2 = BlockADSRoot::from_components(&components2);

        assert_ne!(root1.root(), root2.root());
    }

    #[test]
    fn test_verify_components_failure() {
        let components1 = BlockADSComponents::new(
            Digest::default(),
            Digest::default(),
            Digest::default(),
        );

        let root = BlockADSRoot::from_components(&components1);

        // 创建不同的组件
        let mut different_bytes = [0u8; 32];
        different_bytes[0] = 1;
        let different_digest = Digest::from(different_bytes);

        let components2 = BlockADSComponents::new(
            different_digest,
            Digest::default(),
            Digest::default(),
        );

        // 验证应该失败
        assert!(!root.verify_components(&components2));
    }

    #[test]
    fn test_digestible_trait() {
        let components = BlockADSComponents::new(
            Digest::default(),
            Digest::default(),
            Digest::default(),
        );

        let root = BlockADSRoot::from_components(&components);

        // Digestible trait 应该返回相同的值
        assert_eq!(root.to_digest(), *root.root());
        assert_eq!(components.to_digest(), *root.root());
    }
}