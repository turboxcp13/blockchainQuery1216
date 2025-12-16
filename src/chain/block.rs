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
use hash::block_head_hash;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;

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
pub struct Height(pub u32);

#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct BlockContent {
    pub blk_height: Height,
    pub prev_hash: Digest,
    pub id_tree_root: IdTreeRoot,
    pub ads: BlockMultiADS,
    pub obj_hashes: Vec<Digest>,
    pub obj_id_nums: Vec<NonZeroU16>,
    /// 【创新点1】BlockADSRoot 的组件，用于验证时展开
    pub ads_components: BlockADSComponents,
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
}

#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct BlockHead {
    pub blk_height: Height,
    pub prev_hash: Digest,
    /// 【创新点1】BlockADSRoot 的统一承诺（32字节）
    /// 轻节点只需存储这个值，验证时通过 BlockContent.ads_components 展开
    pub ads_root: Digest,
    pub obj_root_hash: Digest,
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
}