use serde::{Deserialize, Serialize};

pub mod block;
pub mod bloom_filter; //src\chain\bloom_filter.rs
pub mod bplus_tree;
pub mod hash;
pub mod id_tree;
pub mod mmr;  // 【创新点2】MMR 链级承诺模块
pub mod object;
pub mod query;
pub mod range;
pub mod traits;
pub mod trie_tree;
pub mod verify;

pub const MAX_ININE_ID_FANOUT: usize = 32;
pub const MAX_INLINE_BTREE_FANOUT: usize = 32;
pub const COST_COEFFICIENT: usize = 200;

#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Parameter {
    pub time_win_sizes: Vec<u16>,
    pub id_tree_fanout: u8,
    pub max_id_num: u16,
    pub bplus_tree_fanout: u8,
    pub num_dim: u8,
    /// 【方案 X】是否启用块级自适应 Bloom 过滤器
    ///
    /// - `false`（默认，Paper A 路径）：完全跟原版 vchain+ 一致，承诺 t=3 哈希。
    /// - `true`（方案 X 路径）：每块在构建时附加自适应 Bloom，承诺 t=4 哈希。
    ///
    /// 序列化时若旧配置文件未指定，默认为 false，保证向后兼容。
    #[serde(default)]
    pub enable_bloom: bool,
}

#[cfg(test)]
pub(crate) mod tests;