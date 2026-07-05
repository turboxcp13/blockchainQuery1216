//! API 请求 / 响应数据传输对象
//!
//! 定义所有 HTTP 端点的 JSON body 结构。这些结构不会跟核心库的
//! 内部类型强耦合——通过转换函数把它们映射到 `QueryParam` 等内部类型，
//! 保持"API 契约"和"内部实现"解耦。

use crate::{
    chain::{
        object::Object,
        query::query_param::{Node, QueryParam},
        range::Range,
        Parameter,
    },
    digest::Digest,
    utils::{QueryTime, Time},
};
use crate::chain::verify::VOSize;
use serde::{Deserialize, Serialize};

// ============================================================================
// GET /api/chain/info
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ChainInfoResponse {
    /// 链上对象总数
    pub total_objects: u32,
    /// 当前最大区块高度
    pub max_block_height: u32,
    /// MMR 大小（内部节点数）
    pub mmr_size: u64,
    /// MMR 根哈希（十六进制字符串）
    pub mmr_root: Digest,
    /// 已插入的区块数（MMR 叶子数）
    pub block_count: u64,
    /// 链数据路径（便于展示）
    pub chain_path: String,
    /// 密钥路径（便于展示）
    pub key_path: String,
}

// ============================================================================
// GET /api/chain/params
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ChainParamsResponse {
    pub parameter: Parameter,
}

// ============================================================================
// GET /api/blocks
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct BlocksQuery {
    /// 起始区块高度（含），默认 1
    pub start: Option<u32>,
    /// 结束区块高度（含），默认为最大高度
    pub end: Option<u32>,
    /// 页码（从 1 开始），默认 1
    pub page: Option<u32>,
    /// 每页大小，默认 20，最大 100
    pub size: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct BlockSummary {
    pub height: u32,
    /// 区块头 ADS 根哈希（创新点 1 的统一承诺）
    pub ads_root: Digest,
    /// 前一区块哈希
    pub prev_hash: Digest,
    /// 对象根哈希
    pub obj_root_hash: Digest,
}

#[derive(Debug, Serialize)]
pub struct BlocksResponse {
    pub items: Vec<BlockSummary>,
    pub total: u32,
    pub page: u32,
    pub size: u32,
}

// ============================================================================
// GET /api/block/:height
// ============================================================================

#[derive(Debug, Serialize)]
pub struct BlockDetailResponse {
    pub height: u32,
    pub ads_root: Digest,
    pub prev_hash: Digest,
    pub obj_root_hash: Digest,
    /// BlockADSComponents 的四个组成部分（创新点 1 的展开）
    pub ads_components: AdsComponentsDto,
    /// 对象数量
    pub object_count: usize,
    /// 是否启用 Bloom
    pub bloom_enabled: bool,
    /// Bloom 过滤器大小
    pub bloom_size: usize,
}

#[derive(Debug, Serialize)]
pub struct AdsComponentsDto {
    pub id_set_root_hash: Digest,
    pub id_tree_root_hash: Digest,
    pub multi_ads_hash: Digest,
    pub bloom_root_hash: Digest,
}

// ============================================================================
// GET /api/block/:height/objects
// ============================================================================

#[derive(Debug, Serialize)]
pub struct BlockObjectsResponse {
    pub height: u32,
    pub objects: Vec<Object<u32>>,
}

// ============================================================================
// POST /api/query
// ============================================================================

/// 单条查询请求
///
/// 完全兼容你现有 `query.json` 文件的格式，
/// 但可以附加优化选项（不带则用默认值）
#[derive(Debug, Deserialize)]
pub struct QueryRequest {
    pub start_blk: u32,
    pub end_blk: u32,
    pub range: Vec<[u32; 2]>,
    pub keyword_exp: Option<Node>,
    /// 是否启用空集剪枝（对应 CLI 的 -n），默认 true
    #[serde(default = "default_true")]
    pub empty_set: bool,
    /// 是否启用 egg 优化（对应 CLI 的 -e），默认 true
    #[serde(default = "default_true")]
    pub egg_opt: bool,
    /// 验证使用的线程数，默认 4
    #[serde(default = "default_verify_threads")]
    pub verify_thread_num: usize,
}

fn default_true() -> bool {
    true
}
fn default_verify_threads() -> usize {
    4
}

impl QueryRequest {
    /// 转成核心库的 QueryParam 类型
    pub fn to_query_param(&self) -> QueryParam<u32> {
        QueryParam {
            start_blk: self.start_blk,
            end_blk: self.end_blk,
            range: self
                .range
                .iter()
                .map(|[lo, hi]| Range::new(*lo, *hi))
                .collect(),
            keyword_exp: self.keyword_exp.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct QueryResponse {
    /// 匹配的对象列表（可能为多个时间窗口的子结果，这里聚合展平）
    pub objects: Vec<Object<u32>>,
    /// 各阶段查询耗时（μs）
    pub query_time: QueryTime,
    /// 验证耗时（μs）
    pub verify_time: Time,
    /// VO 各部分大小（字节）
    pub vo_size: VOSize,
    /// 匹配对象总数
    pub total_matched: usize,
}

// ============================================================================
// POST /api/query/verify (只做验证，把已生成的 VO/results 传回来重新验)
// ============================================================================
//
// 说明：完整的 VO 序列化很复杂（涉及 acc、petgraph::Graph 等）；
// 为了演示 demo，这个端点先接收和 /api/query 相同的 QueryRequest，
// 内部会重跑查询+验证（因为 VO 无法方便传输回来）。
// 这个端点本质上就是"再跑一次 verify"—— demo 里够用。
// 如需真正的"仅验证"，Phase 2 会实现 VO 的完整序列化。

pub type VerifyRequest = QueryRequest;

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    /// 验证耗时；失败时为 None
    pub verify_time: Option<Time>,
    pub vo_size: VOSize,
    pub passed: bool,
    pub message: String,
}

// ============================================================================
// GET /api/block/:height/proof
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ProofQuery {
    /// 索引类型：id_tree | bplus_tree | trie
    #[serde(rename = "type")]
    pub proof_type: String,
    /// 仅 bplus_tree 类型需要：维度
    pub dimension: Option<u8>,
    /// bplus_tree / trie 类型需要：时间窗口
    pub time_window: Option<u16>,
}

/// 两层式证明的响应（结构化展示）
///
/// 为了演示效果，把关键字段单独抽出来。
/// 完整的 proof 也一同返回（供前端做展开展示）。
#[derive(Debug, Serialize)]
pub struct TwoLayerProofResponse {
    /// MMR 层信息
    pub mmr: MmrProofDto,
    /// 块内层信息
    pub block: BlockProofDto,
    /// 索引证明类型
    pub index_proof_type: String,
    /// 完整的证明（可用于后续验证）
    pub full_proof: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct MmrProofDto {
    pub mmr_size: u64,
    pub position: u64,
    pub block_ads_root: Digest,
    /// MMR 证明项数（层级）
    pub proof_items_count: usize,
}

#[derive(Debug, Serialize)]
pub struct BlockProofDto {
    pub block_height: u32,
    pub components: AdsComponentsDto,
}

// ============================================================================
// POST /api/proof/verify
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ProofVerifyRequest {
    /// 待验证的完整证明（来自 /api/block/:h/proof 的 full_proof）
    pub proof: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ProofVerifyResponse {
    pub passed: bool,
    pub message: String,
    pub verify_time_us: u128,
}

// ============================================================================
// GET /api/health
// ============================================================================

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
}
