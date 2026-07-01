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
///
/// **方案 X 扩展（向后兼容）**：新增 `bloom_root_hash` 字段用于承诺
/// 块级自适应 Bloom 过滤器。为保持与 Paper A 实验路径的兼容性，
/// `compute_root` 在 `bloom_root_hash == Digest::zero()` 时跳过该字段，
/// 退化为原始 t=3 哈希；非零时按 t=4 哈希。
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

    /// 【方案 X】块级自适应 Bloom 过滤器的根哈希
    /// 用于加速否定查询的可验证 O(1) 证明
    /// 为零时表示未启用 Bloom 承诺（Paper A 兼容路径）
    pub bloom_root_hash: Digest,
}

impl BlockADSComponents {
    /// 创建新的 BlockADSComponents（Paper A 路径，不含 Bloom 承诺）
    ///
    /// `bloom_root_hash` 默认为 `Digest::zero()`，`compute_root` 会自动跳过该字段，
    /// 保持与 Paper A 论文中描述的 t=3 哈希一致。
    pub fn new(
        id_set_root_hash: Digest,
        id_tree_root_hash: Digest,
        multi_ads_hash: Digest,
    ) -> Self {
        Self {
            id_set_root_hash,
            id_tree_root_hash,
            multi_ads_hash,
            bloom_root_hash: Digest::zero(),
        }
    }

    /// 【方案 X】创建带 Bloom 承诺的 BlockADSComponents
    ///
    /// 当 `bloom_root_hash` 非零时，`compute_root` 会把该字段计入哈希，
    /// 形成 t=4 的承诺结构。Bloom 加速否定查询的方案 X 走此路径。
    pub fn new_with_bloom(
        id_set_root_hash: Digest,
        id_tree_root_hash: Digest,
        multi_ads_hash: Digest,
        bloom_root_hash: Digest,
    ) -> Self {
        Self {
            id_set_root_hash,
            id_tree_root_hash,
            multi_ads_hash,
            bloom_root_hash,
        }
    }

    /// 计算组件的统一承诺根
    ///
    /// 使用 Blake2b 哈希函数，按确定顺序拼接各组件进行承诺：
    ///
    /// - 当 `bloom_root_hash` 为零（Paper A 路径）：
    ///   `root = Blake2b(id_set || id_tree || multi_ads)`
    /// - 当 `bloom_root_hash` 非零（方案 X 路径）：
    ///   `root = Blake2b(id_set || id_tree || multi_ads || bloom_root)`
    ///
    /// 这一条件性设计确保 Paper A 已发表实验的承诺哈希值不受影响，
    /// 同时为方案 X 提供干净的扩展点。
    pub fn compute_root(&self) -> Digest {
        let mut state = blake2().to_state();
        state.update(self.id_set_root_hash.as_bytes());
        state.update(self.id_tree_root_hash.as_bytes());
        state.update(self.multi_ads_hash.as_bytes());
        // 方案 X 扩展：仅在 Bloom 承诺非零时纳入哈希
        if !self.bloom_root_hash.is_zero() {
            state.update(self.bloom_root_hash.as_bytes());
        }
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
    /// 组件（用于验证时展开）
    components: BlockADSComponents,
}

impl BlockADSRoot {
    /// 从组件构建 BlockADSRoot
    pub fn from_components(components: BlockADSComponents) -> Self {
        let root = components.compute_root();
        Self { root, components }
    }

    /// 从已计算的根哈希创建（用于从存储加载，不含组件）
    pub fn from_digest(root: Digest) -> Self {
        Self { 
            root, 
            components: BlockADSComponents::default(),
        }
    }

    /// 从根和组件创建（用于完整恢复）
    pub fn from_digest_and_components(root: Digest, components: BlockADSComponents) -> Self {
        Self { root, components }
    }

    /// 从根和组件创建（与 from_digest_and_components 相同，提供更简洁的API）
    ///
    /// # 参数
    /// - `root`: 已知的 BlockADSRoot 根哈希（通常从 BlockHead 加载）
    /// - `components`: BlockADSComponents（通常从 BlockContent 加载）
    ///
    /// # 使用场景
    /// 从存储加载时重建完整的 BlockADSRoot：
    /// ```ignore
    /// let root = block_head.ads_root;
    /// let components = block_content.get_ads_components().clone();
    /// let block_ads_root = BlockADSRoot::new(root, components);
    /// ```
    pub fn new(root: Digest, components: BlockADSComponents) -> Self {
        Self { root, components }
    }

    /// 获取统一承诺根（轻节点只需存储这个）
    pub fn root(&self) -> &Digest {
        &self.root
    }

    /// 获取组件引用
    pub fn components(&self) -> &BlockADSComponents {
        &self.components
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

    /// 验证内部一致性（root 是否由 components 正确计算得出）
    pub fn verify_self(&self) -> bool {
        self.components.compute_root() == self.root
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
        Self::from_components(components.clone())
    }
}

impl From<BlockADSComponents> for BlockADSRoot {
    fn from(components: BlockADSComponents) -> Self {
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
        let ads_root = BlockADSRoot::from_components(components.clone());

        // 验证组件
        assert!(ads_root.verify_components(&components));
        // 验证内部一致性
        assert!(ads_root.verify_self());
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

        let root1 = BlockADSRoot::from_components(components1);
        let root2 = BlockADSRoot::from_components(components2);

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

        let root1 = BlockADSRoot::from_components(components1);
        let root2 = BlockADSRoot::from_components(components2);

        assert_ne!(root1.root(), root2.root());
    }

    #[test]
    fn test_verify_components_failure() {
        let components1 = BlockADSComponents::new(
            Digest::default(),
            Digest::default(),
            Digest::default(),
        );

        let root = BlockADSRoot::from_components(components1);

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

        let root = BlockADSRoot::from_components(components);

        // Digestible trait 应该返回相同的值
        assert_eq!(root.to_digest(), *root.root());
        assert_eq!(root.components().to_digest(), *root.root());
    }

    #[test]
    fn test_verify_self() {
        let components = BlockADSComponents::new(
            Digest::default(),
            Digest::default(),
            Digest::default(),
        );

        let root = BlockADSRoot::from_components(components);
        assert!(root.verify_self());
    }

    #[test]
    fn test_components_accessor() {
        let id_set_hash = Digest::default();
        let id_tree_hash = Digest::default();
        let multi_ads_hash = Digest::default();

        let components = BlockADSComponents::new(id_set_hash, id_tree_hash, multi_ads_hash);
        let root = BlockADSRoot::from_components(components.clone());

        assert_eq!(root.components(), &components);
    }

    #[test]
    fn test_new_method() {
        // 测试新增的 new() 方法
        let components = BlockADSComponents::new(
            Digest::default(),
            Digest::default(),
            Digest::default(),
        );
        let root_digest = components.compute_root();
        
        // 使用 new() 方法创建
        let ads_root = BlockADSRoot::new(root_digest, components.clone());
        
        // 验证内部一致性
        assert!(ads_root.verify_self());
        assert_eq!(*ads_root.root(), root_digest);
        assert_eq!(ads_root.components(), &components);
    }

    #[test]
    fn test_new_equals_from_components() {
        // 验证 new() 和 from_components() 产生相同结果
        let components = BlockADSComponents::new(
            Digest::default(),
            Digest::default(),
            Digest::default(),
        );
        
        let root1 = BlockADSRoot::from_components(components.clone());
        let root2 = BlockADSRoot::new(*root1.root(), components.clone());
        
        assert_eq!(root1.root(), root2.root());
        assert_eq!(root1.components(), root2.components());
    }

    #[test]
    fn test_from_digest_without_components() {
        // 测试轻节点场景：只有 root 没有 components
        let mut some_bytes = [0u8; 32];
        some_bytes[0] = 42;
        let some_digest = Digest::from(some_bytes);
        
        let root = BlockADSRoot::from_digest(some_digest);
        
        // root 应该是我们传入的值
        assert_eq!(*root.root(), some_digest);
        
        // components 是默认值，所以 verify_self 应该失败
        // （除非 some_digest 恰好等于默认 components 的哈希，概率极低）
        assert!(!root.verify_self());
    }

    // ========================================================================
    // 方案 X (Bloom 集成) 测试
    // ========================================================================

    /// 关键测试：Paper A 路径的哈希值在 Step 2 引入 bloom_root_hash 字段后
    /// 必须保持不变。这是向后兼容性的硬约束。
    #[test]
    fn test_paper_a_path_hash_unchanged() {
        // 使用三参数 new()（Paper A 路径），bloom_root_hash 默认为 zero
        let components = BlockADSComponents::new(
            Digest::default(),
            Digest::default(),
            Digest::default(),
        );

        // 复现 Paper A 原始 t=3 哈希（直接 blake2 三字段串联）
        let mut state = blake2().to_state();
        state.update(Digest::default().as_bytes());
        state.update(Digest::default().as_bytes());
        state.update(Digest::default().as_bytes());
        let expected = Digest::from(state.finalize());

        // compute_root() 必须产生与原始 t=3 完全一致的哈希
        assert_eq!(components.compute_root(), expected,
            "Step 2 broke Paper A backward compatibility: hash differs!");
    }

    /// 方案 X 路径：bloom_root_hash 非零时，哈希必须计入该字段
    #[test]
    fn test_scheme_x_path_includes_bloom() {
        let mut bloom_bytes = [0u8; 32];
        bloom_bytes[0] = 7;
        bloom_bytes[31] = 99;
        let bloom_digest = Digest::from(bloom_bytes);

        let components_paper_a = BlockADSComponents::new(
            Digest::default(),
            Digest::default(),
            Digest::default(),
        );
        let components_scheme_x = BlockADSComponents::new_with_bloom(
            Digest::default(),
            Digest::default(),
            Digest::default(),
            bloom_digest,
        );

        // Paper A 路径与方案 X 路径必须产生不同的哈希
        assert_ne!(
            components_paper_a.compute_root(),
            components_scheme_x.compute_root(),
            "scheme X must produce a distinct commitment when bloom_root_hash is set"
        );
    }

    /// new_with_bloom 接受零 bloom_root_hash 时应退化为 Paper A 路径
    /// （等同于直接调用 new）
    #[test]
    fn test_new_with_zero_bloom_degrades_to_paper_a() {
        let components_a = BlockADSComponents::new(
            Digest::default(),
            Digest::default(),
            Digest::default(),
        );
        let components_b = BlockADSComponents::new_with_bloom(
            Digest::default(),
            Digest::default(),
            Digest::default(),
            Digest::zero(),
        );

        assert_eq!(components_a.compute_root(), components_b.compute_root());
    }

    /// 方案 X 路径下，bloom_root_hash 不同的两个组件必须产生不同的根
    /// （否则 Bloom 承诺无效，可被攻击者替换）
    #[test]
    fn test_bloom_field_affects_root() {
        let mut bloom_v1_bytes = [0u8; 32];
        bloom_v1_bytes[0] = 1;
        let mut bloom_v2_bytes = [0u8; 32];
        bloom_v2_bytes[0] = 2;

        let components_v1 = BlockADSComponents::new_with_bloom(
            Digest::default(),
            Digest::default(),
            Digest::default(),
            Digest::from(bloom_v1_bytes),
        );
        let components_v2 = BlockADSComponents::new_with_bloom(
            Digest::default(),
            Digest::default(),
            Digest::default(),
            Digest::from(bloom_v2_bytes),
        );

        assert_ne!(components_v1.compute_root(), components_v2.compute_root(),
            "different bloom_root_hash must produce different commitments");
    }
}