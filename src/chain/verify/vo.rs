use crate::{
    acc::{AccValue, FinalProof, IntermediateProof, Set},
    chain::{
        block::{block_ads_root::BlockADSComponents, Height},
        bloom_filter::AdaptiveBloomFilter,
        bplus_tree,
        id_tree::{self, ObjId},
        traits::Num,
        trie_tree,
        verify::hash::merkle_proof_hash,
    },
    digest::Digest,
};
use anyhow::{bail, Result};
use petgraph::graph::NodeIndex;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Serialize, Deserialize)]
pub enum VONode<K: Num> {
    Range(VORangeNode<K>),
    Keyword(VOKeywordNode),
    /// 【方案 X】Bloom-skip 短路证明节点
    ///
    /// 当 Bloom 过滤器判定关键词一定不在窗口内 w 个块的任何一个中时，
    /// 用此节点代替原来的 Keyword(VOKeywordNode)。验证时不再需要 Trie proof，
    /// 只需验证 w 个 BF 的完整性与 BF 说的"不在"。
    KeywordBloomNeg(VOKeywordBloomNeg),
    BlkRt(VOBlkRtNode),
    InterUnion(VOInterUnion),
    FinalUnion(VOFinalUnion),
    InterIntersec(VOInterIntersec),
    FinalIntersec(VOFinalIntersec),
    InterDiff(VOInterDiff),
    FinalDiff(VOFinalDiff),
}

impl<K: Num> VONode<K> {
    pub(crate) fn get_acc(&self) -> Result<&AccValue> {
        match self {
            VONode::Range(n) => Ok(&n.acc),
            VONode::Keyword(n) => Ok(&n.acc),
            // 【方案 X】Bloom-skip 节点：结果集为空，acc 为空集累加器
            VONode::KeywordBloomNeg(n) => Ok(&n.acc),
            VONode::BlkRt(n) => Ok(&n.acc),
            VONode::InterUnion(n) => Ok(&n.acc),
            VONode::FinalUnion(_) => bail!("This is a final union operation"),
            VONode::InterIntersec(n) => Ok(&n.acc),
            VONode::FinalIntersec(_) => bail!("This is a final intersec operation"),
            VONode::InterDiff(n) => Ok(&n.acc),
            VONode::FinalDiff(_) => bail!("This is a final diff operation"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VORangeNode<K: Num> {
    pub(crate) blk_height: Height,
    pub(crate) win_size: u16,
    pub(crate) acc: AccValue,
    pub(crate) proof: bplus_tree::proof::Proof<K>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VOKeywordNode {
    pub(crate) blk_height: Height,
    pub(crate) win_size: u16,
    pub(crate) acc: AccValue,
}

/// 【方案 X】Bloom-skip 证明节点
///
/// 当查询关键词在滑动窗口 [blk_height - win_size + 1, blk_height] 内所有 w 个块的
/// per-block Bloom 过滤器中都被判为 "一定不在"，可跳过 Trie 全路径，直接返回空集。
///
/// # 验证不变式
///
/// - `bloom_data.len() == win_size`
/// - `bloom_data[i].0` (Height) 是从 start 到 blk_height 的连续块高度
/// - 对每个 `bloom_data[i].1` (BF), `bf.may_contain(keyword) == false`
/// - 每个 BF 的 `to_digest()` 必须匹配对应块的 `BlockADSComponents.bloom_root_hash`
///   （由 `merkle_proofs` 验证链完成）
#[derive(Debug, Serialize, Deserialize)]
pub struct VOKeywordBloomNeg {
    /// 挂载块高度（与查询 DAG 中 Keyword 节点的 blk_height 一致）
    pub(crate) blk_height: Height,
    /// 滑动窗口大小
    pub(crate) win_size: u16,
    /// 查询的关键词（供验证时 replay may_contain 判断）
    pub(crate) keyword: SmolStr,
    /// 空集累加器（结果集为空时的 acc value）
    pub(crate) acc: AccValue,
    /// 涉及的 w 个块的 (Height, Bloom filter) 数据
    /// - 顺序：从 start = blk_height - win_size + 1 到 blk_height（升序）
    /// - 每个 BF 都必须 says "keyword 不在"
    pub(crate) bloom_data: Vec<(Height, AdaptiveBloomFilter)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VOBlkRtNode {
    pub(crate) blk_height: Height,
    pub(crate) win_size: u16,
    pub(crate) acc: AccValue,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VOInterUnion {
    pub(crate) acc: AccValue,
    pub(crate) proof: IntermediateProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VOFinalUnion {
    pub(crate) proof: FinalProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VOInterIntersec {
    pub(crate) acc: AccValue,
    pub(crate) proof: Option<IntermediateProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VOFinalIntersec {
    pub(crate) proof: FinalProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VOInterDiff {
    pub(crate) acc: AccValue,
    pub(crate) proof: Option<IntermediateProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VOFinalDiff {
    pub(crate) proof: FinalProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub(crate) id_tree_root_hash: Option<Digest>,
    pub(crate) id_set_root_hash: Digest,
    pub(crate) ads_hashes: BTreeMap<u16, Digest>,
    pub(crate) extra_bplus_rt_hashes: HashMap<u8, Digest>,
    /// 【方案 X】块级 Bloom 承诺根哈希
    ///
    /// - `None`：Paper A 路径（构建时 `enable_bloom = false`），验证走 t=3 哈希
    /// - `Some(digest)`：方案 X 路径（构建时 `enable_bloom = true`），验证走 t=4 哈希
    ///
    /// 通过 `#[serde(default)]` 保证旧的 VO 反序列化时该字段为 `None`，向后兼容。
    #[serde(default)]
    pub(crate) bloom_root_hash: Option<Digest>,
}

impl MerkleProof {
    /// 【原有方法】计算 ads_root_hash（保持向后兼容）
    pub(crate) fn ads_root_hash(
        &self,
        id_tree_root_hash: &Digest,
        rest_ads_hashes: impl Iterator<Item = (u16, Digest)>,
    ) -> Digest {
        let mut ads_hashes = self.ads_hashes.clone();
        for (time_win, hash) in rest_ads_hashes {
            ads_hashes.insert(time_win, hash);
        }
        merkle_proof_hash(&self.id_set_root_hash, id_tree_root_hash, ads_hashes.iter())
    }

    /// 【创新点1】使用 BlockADSComponents 进行验证
    ///
    /// 该方法将计算得到的组件与提供的 BlockADSComponents 进行比对，
    /// 验证各子组件是否一致，然后验证统一承诺根。
    pub(crate) fn verify_with_components(
        &self,
        id_tree_root_hash: &Digest,
        multi_ads_hash: Digest,
        expected_ads_root: &Digest,
    ) -> Result<()> {
        // 构建计算得到的组件
        let computed_components = BlockADSComponents::new(
            self.id_set_root_hash,
            *id_tree_root_hash,
            multi_ads_hash,
        );

        // 计算统一承诺根
        let computed_root = computed_components.compute_root();

        // 验证是否匹配
        if computed_root != *expected_ads_root {
            bail!(
                "BlockADSRoot verification failed: computed {:?}, expected {:?}",
                computed_root,
                expected_ads_root
            );
        }

        Ok(())
    }
}

/// 【创新点1】BlockADSRoot 的验证证明
///
/// 用于在 VO 中携带 BlockADSRoot 的展开验证信息
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockADSProof {
    /// 区块高度
    pub block_height: Height,
    /// 使用的时间窗口大小
    pub win_size: u16,
    /// BlockADSRoot 的组件（用于展开验证）
    pub components: BlockADSComponents,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VoDagContent<K: Num> {
    pub(crate) output_sets: HashMap<NodeIndex, Set>,
    pub(crate) dag_content: HashMap<NodeIndex, VONode<K>>,
}

#[derive(Serialize, Deserialize)]
pub struct VO<K: Num> {
    pub(crate) vo_dag_content: VoDagContent<K>,
    pub(crate) trie_proofs: HashMap<Height, trie_tree::proof::Proof>,
    pub(crate) id_tree_proof: id_tree::proof::Proof,
    pub(crate) cur_obj_id: ObjId,
    pub(crate) merkle_proofs: HashMap<Height, MerkleProof>,
}