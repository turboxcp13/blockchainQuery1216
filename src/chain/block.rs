pub mod block_ads;
pub mod block_ads_root;
pub mod build;
pub mod hash;

use crate::{
    chain::id_tree::IdTreeRoot,
    digest::{Digest, Digestible},
};
use block_ads::BlockMultiADS;
use block_ads_root::BlockADSComponents;
use crate::chain::bloom_filter::AdaptiveBloomFilter;
use hash::block_head_hash;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;
/// 区块头（轻节点存储）
///
/// BlockHead 包含区块的关键元数据和承诺根，轻节点通过同步区块头
/// 可以验证查询结果而无需下载完整区块内容。
///
/// # 【创新点1】ads_root 字段
/// `ads_root` 是块内所有认证数据结构的统一承诺根，通过 Blake2b
/// 从 BlockADSComponents 计算得出。轻节点只需存储这32字节即可
/// 验证所有类型的查询（ID Set、ID Tree、MultiADS）。
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    derive_more::Deref,
    derive_more::DerefMut,
    derive_more::Display,
    derive_more::From,
    derive_more::Into,
)]
pub struct Height(pub u32);//u32 4字节

#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct BlockContent {
    pub blk_height: Height,//u32 4字节
    pub prev_hash: Digest,
    pub id_tree_root: IdTreeRoot,
    pub ads: BlockMultiADS,
    pub obj_hashes: Vec<Digest>,
    pub obj_id_nums: Vec<NonZeroU16>,
    /// 【创新点1】BlockADSRoot 的组件，用于验证时展开
    pub ads_components: BlockADSComponents,
    /// 【方案 X】块级自适应 Bloom 过滤器
    ///
    /// 仅当构建时 `Parameter::enable_bloom = true` 才被实际填充；
    /// 否则保持 `AdaptiveBloomFilter::default()`（空过滤器，digest 为零）。
    /// 序列化时若旧 block_content 无此字段，默认为空，保证向后兼容。
    #[serde(default)]
    pub bloom_filter: AdaptiveBloomFilter,
}

impl BlockContent {
    pub fn new(blk_height: Height, prev_hash: Digest) -> Self {
        Self {
            blk_height,
            prev_hash,
            id_tree_root: IdTreeRoot::default(),
            ads: BlockMultiADS::default(),
            obj_hashes: Vec::<Digest>::new(),
            obj_id_nums: Vec::<NonZeroU16>::new(),
            ads_components: BlockADSComponents::default(),
            bloom_filter: AdaptiveBloomFilter::default(),
        }
    }

    pub fn set_id_tree_root(&mut self, new_id_tree_root: IdTreeRoot) {
        self.id_tree_root = new_id_tree_root;
    }

    pub fn set_multi_ads(&mut self, new_ads: BlockMultiADS) {
        self.ads = new_ads;
    }

    pub fn set_obj_hashes(&mut self, new_hashes: Vec<Digest>) {
        self.obj_hashes = new_hashes;
    }

    pub fn set_obj_id_nums(&mut self, new_id_nums: Vec<NonZeroU16>) {
        self.obj_id_nums = new_id_nums;
    }

    pub fn read_obj_id_nums(&self) -> Vec<NonZeroU16> {
        self.obj_id_nums.clone()
    }

    /// 【创新点1】设置 BlockADSComponents
    pub fn set_ads_components(&mut self, components: BlockADSComponents) {
        self.ads_components = components;
    }

    /// 【创新点1】获取 BlockADSComponents
    pub fn get_ads_components(&self) -> &BlockADSComponents {
        &self.ads_components
    }

    /// 【方案 X】设置块级 Bloom 过滤器
    pub fn set_bloom_filter(&mut self, bf: AdaptiveBloomFilter) {
        self.bloom_filter = bf;
    }

    /// 【方案 X】获取块级 Bloom 过滤器
    pub fn get_bloom_filter(&self) -> &AdaptiveBloomFilter {
        &self.bloom_filter
    }

    /// 【方案 X】查询块内是否可能含某关键词
    ///
    /// 返回 `false` 表示该关键词一定不在本块（用于查询路径的 Bloom-skip）；
    /// 返回 `true` 表示可能在本块（需要进入 Trie 路径完整验证）。
    ///
    /// 此方法在 Step 4 (查询路径集成) 中会被调用。
    pub fn bloom_may_contain(&self, keyword: &str) -> bool {
        self.bloom_filter.may_contain(keyword.as_bytes())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct BlockHead {//块头固定100字节
    // 【创新点1】BlockADSRoot 的统一承诺（32字节）
    // 轻节点只需存储这个值，验证时通过 BlockContent.ads_components 展开
    pub blk_height: Height,//u32 4字节
    //pub const DIGEST_LEN: usize = 32;
    pub prev_hash: Digest,//32字节
    pub ads_root: Digest,//32字节
    pub obj_root_hash: Digest,//32字节
}

impl Digestible for BlockHead {
    fn to_digest(&self) -> Digest {
        block_head_hash(
            self.blk_height,
            &self.prev_hash,
            &self.ads_root,
            &self.obj_root_hash,
        )
    }
}

impl BlockHead {
    /// 【创新点1】设置 BlockADSRoot（统一承诺）
    pub(crate) fn set_ads_root(&mut self, new_root: Digest) {
        self.ads_root = new_root;
    }

    pub(crate) fn set_obj_root_hash(&mut self, new_hash: Digest) {
        self.obj_root_hash = new_hash;
    }

    /// 【创新点1】获取 BlockADSRoot（统一承诺）
    pub fn get_ads_root(&self) -> Digest {
        self.ads_root
    }

    /// 【兼容性】保留原方法名，内部调用新方法
    #[deprecated(note = "请使用 get_ads_root() 代替")]
    pub(crate) fn get_ads_root_hash(&self) -> Digest {
        self.ads_root
    }

    /// 【创新点1】验证 BlockADSComponents 是否与 ads_root 一致
    ///
    /// 轻节点持有 BlockHead（包含 ads_root），全节点提供 BlockADSComponents，
    /// 轻节点通过此方法验证 components 确实能生成 ads_root，
    /// 从而确认全节点提供的组件数据是可信的。
    ///
    /// # 参数
    /// - `components`: 全节点提供的 BlockADSComponents
    ///
    /// # 返回
    /// - `true`: components 能正确生成 ads_root
    /// - `false`: components 与 ads_root 不匹配（可能被篡改）
    pub fn verify_ads_components(&self, components: &BlockADSComponents) -> bool {
        components.compute_root() == self.ads_root
    }
}