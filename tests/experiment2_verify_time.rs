//! 【实验2】验证时间对比实验 - 多链长 × 多查询类型 × 四方案对比
//!
//! ## 实验设计
//! - 维度一（主图）：23个链长点 × 4方案的链级验证时间对比
//! - 维度二（覆盖表）：6种查询类型的块级验证时间，证明多场景覆盖
//! - 维度三（组合分析）：链长=20000时4方案的总验证时间分解（链级+块级）
//! - 附加：各方案链级承诺结构存储开销分析
//!
//! ## 对比方案
//! - HC-S:   头链同步 + 分散承诺
//! - MT-S:   Merkle树 + 分散承诺
//! - MMR-S:  MMR + 分散承诺
//! - MMR-U:  MMR + 统一承诺BlockADSRoot（本文方案）
//!
//! ## 运行命令
//! ```
//! cargo test --test experiment2_verify_time --release -- --nocapture
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use vchain_plus::acc::AccPublicKey;
use vchain_plus::chain::block::Height;
use vchain_plus::chain::object::Object;
use vchain_plus::chain::query::query;
use vchain_plus::chain::verify::verify;
use vchain_plus::digest::{blake2, Digest, Digestible};
use vchain_plus::utils::{load_query_param_from_file, KeyPair};
use vchain_plus::SimChain;
use serde::{Deserialize, Serialize};
use std::hint::black_box;

// ============================================================================
// 实验配置
// ============================================================================

const KEY_PATH: &str = "output/pk_eth.key";
const DB_PATH: &str = "output/db_eth";
const QUERY_PATH: &str = "output/query_eth2.json";

/// 23个链长测试点（与实验1保持一致）
const CHAIN_LENGTHS: [u64; 23] = [
    100, 200, 300, 400, 500, 750, 1000, 1500, 2000, 2500,
    3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000,
    12000, 14000, 16000, 18000, 20000,
];

/// 基准操作测量迭代次数
const BASE_ITERATIONS: usize = 500;
/// 预热次数
const WARMUP_ITERATIONS: usize = 50;
/// 截断均值去除比例（上下各10%）
const TRIM_PERCENT: f64 = 10.0;

/// MMR验证测量迭代次数
const MMR_VERIFY_ITERATIONS: usize = 500;

/// 块级验证测量迭代次数
const BLOCK_VERIFY_ITERATIONS: usize = 20;
/// 块级验证预热次数
const BLOCK_VERIFY_WARMUP: usize = 3;

/// 分散承诺块头大小(字节)
/// height(4) + prev_hash(32) + id_set_root(32) + id_tree_root(32) + multi_ads_hash(32) + obj_root(32) = 164B
const SCATTERED_BLOCK_HEADER_SIZE: usize = 164;
/// 统一承诺块头大小(字节)
/// height(4) + prev_hash(32) + ads_root(32) + obj_root(32) = 100B
const UNIFIED_BLOCK_HEADER_SIZE: usize = 100;
/// 哈希摘要大小(字节)
const HASH_SIZE: usize = 32;
/// BlockADSComponents大小(字节): 3 × 32 = 96B
const BLOCK_ADS_COMPONENTS_SIZE: usize = 96;

// ============================================================================
// 查询类型定义
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
enum QueryType {
    SingleKeyword,
    BooleanOr,
    BooleanAnd,
    BooleanNot,
    NestedBoolean,
    RangeOnly,
}

impl QueryType {
    fn from_index(i: usize) -> Self {
        match i {
            0 => QueryType::SingleKeyword,
            1 => QueryType::BooleanOr,
            2 => QueryType::BooleanAnd,
            3 => QueryType::BooleanNot,
            4 => QueryType::NestedBoolean,
            5 => QueryType::RangeOnly,
            _ => QueryType::RangeOnly,
        }
    }

    fn label(&self) -> &str {
        match self {
            QueryType::SingleKeyword => "SingleKeyword",
            QueryType::BooleanOr => "BooleanOR",
            QueryType::BooleanAnd => "BooleanAND",
            QueryType::BooleanNot => "BooleanNOT",
            QueryType::NestedBoolean => "NestedBoolean",
            QueryType::RangeOnly => "RangeOnly",
        }
    }

    fn description(&self) -> &str {
        match self {
            QueryType::SingleKeyword => "关键词+范围",
            QueryType::BooleanOr => "布尔OR+范围",
            QueryType::BooleanAnd => "布尔AND+范围",
            QueryType::BooleanNot => "布尔NOT+范围",
            QueryType::NestedBoolean => "嵌套布尔(OR∧AND)+范围",
            QueryType::RangeOnly => "纯范围查询",
        }
    }
}

// ============================================================================
// 方案定义
// ============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
enum ChainProofType {
    HeaderChain,
    Merkle,
    MMR,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
enum BlockCommitmentType {
    Scattered,
    Unified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SchemeConfig {
    name: String,
    chain_proof_type: ChainProofType,
    block_commitment_type: BlockCommitmentType,
    description: String,
    block_header_size: usize,
}

impl SchemeConfig {
    fn header_chain() -> Self {
        Self {
            name: "HC-S".to_string(),
            chain_proof_type: ChainProofType::HeaderChain,
            block_commitment_type: BlockCommitmentType::Scattered,
            description: "头链同步+分散承诺".to_string(),
            block_header_size: SCATTERED_BLOCK_HEADER_SIZE,
        }
    }
    fn merkle() -> Self {
        Self {
            name: "MT-S".to_string(),
            chain_proof_type: ChainProofType::Merkle,
            block_commitment_type: BlockCommitmentType::Scattered,
            description: "Merkle树+分散承诺".to_string(),
            block_header_size: SCATTERED_BLOCK_HEADER_SIZE,
        }
    }
    fn mmr_scattered() -> Self {
        Self {
            name: "MMR-S".to_string(),
            chain_proof_type: ChainProofType::MMR,
            block_commitment_type: BlockCommitmentType::Scattered,
            description: "MMR+分散承诺".to_string(),
            block_header_size: SCATTERED_BLOCK_HEADER_SIZE,
        }
    }
    fn two_layer() -> Self {
        Self {
            name: "MMR-U".to_string(),
            chain_proof_type: ChainProofType::MMR,
            block_commitment_type: BlockCommitmentType::Unified,
            description: "MMR+统一承诺BlockADSRoot（本文方案）".to_string(),
            block_header_size: UNIFIED_BLOCK_HEADER_SIZE,
        }
    }
    fn all_schemes() -> Vec<Self> {
        vec![Self::header_chain(), Self::merkle(), Self::mmr_scattered(), Self::two_layer()]
    }
}

// ============================================================================
// 统计工具
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimeStats {
    mean_us: f64,
    trimmed_mean_us: f64,
    min_us: u64,
    max_us: u64,
    std_us: f64,
    sample_count: usize,
}

fn calculate_std(values: &[u64], mean: f64) -> f64 {
    if values.len() <= 1 { return 0.0; }
    let variance: f64 = values.iter()
        .map(|&v| { let d = v as f64 - mean; d * d })
        .sum::<f64>() / (values.len() - 1) as f64;
    variance.sqrt()
}

fn calculate_time_stats(times_ns: &[u64]) -> TimeStats {
    if times_ns.is_empty() {
        return TimeStats {
            mean_us: 0.0, trimmed_mean_us: 0.0,
            min_us: 0, max_us: 0, std_us: 0.0, sample_count: 0,
        };
    }
    let mean_ns = times_ns.iter().sum::<u64>() as f64 / times_ns.len() as f64;
    TimeStats {
        mean_us: mean_ns / 1000.0,
        trimmed_mean_us: calculate_trimmed_mean_us(times_ns, TRIM_PERCENT),
        min_us: times_ns.iter().min().unwrap() / 1000,
        max_us: times_ns.iter().max().unwrap() / 1000,
        std_us: calculate_std(times_ns, mean_ns) / 1000.0,
        sample_count: times_ns.len(),
    }
}

fn calculate_trimmed_mean_us(times_ns: &[u64], trim_percent: f64) -> f64 {
    let n = times_ns.len();
    if n == 0 { return 0.0; }
    let mut sorted = times_ns.to_vec();
    sorted.sort_unstable();
    let trim_count = ((n as f64) * trim_percent / 100.0).floor() as usize;
    let start = trim_count;
    let end = n.saturating_sub(trim_count).max(start + 1);
    let trimmed = &sorted[start..end];
    (trimmed.iter().sum::<u64>() as f64 / trimmed.len() as f64) / 1000.0
}

fn calculate_time_stats_us(times_us: &[f64]) -> TimeStats {
    if times_us.is_empty() {
        return TimeStats {
            mean_us: 0.0, trimmed_mean_us: 0.0,
            min_us: 0, max_us: 0, std_us: 0.0, sample_count: 0,
        };
    }
    let mean_us = times_us.iter().sum::<f64>() / times_us.len() as f64;
    let min_us = times_us.iter().cloned().fold(f64::INFINITY, f64::min) as u64;
    let max_us = times_us.iter().cloned().fold(f64::NEG_INFINITY, f64::max) as u64;
    let std_us = if times_us.len() > 1 {
        (times_us.iter().map(|&v| (v - mean_us).powi(2)).sum::<f64>()
            / (times_us.len() - 1) as f64).sqrt()
    } else { 0.0 };

    let mut sorted = times_us.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted.len();
    let tc = ((n as f64) * TRIM_PERCENT / 100.0).floor() as usize;
    let s = tc;
    let e = n.saturating_sub(tc).max(s + 1);
    let trimmed_mean_us = sorted[s..e].iter().sum::<f64>() / (e - s) as f64;

    TimeStats { mean_us, trimmed_mean_us, min_us, max_us, std_us, sample_count: times_us.len() }
}

// ============================================================================
// 基准时间测量
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaseTimes {
    single_hash: TimeStats,
    header_hash_scattered: TimeStats,
    header_hash_unified: TimeStats,
    ads_root_expand: TimeStats,
}

fn measure_hash_time(data_size: usize, iterations: usize) -> TimeStats {
    let data = vec![0u8; data_size];
    for _ in 0..WARMUP_ITERATIONS {
        let mut s = blake2().to_state();
        s.update(&data);
        black_box(s.finalize());
    }
    let mut times: Vec<u64> = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let t = Instant::now();
        let mut s = blake2().to_state();
        s.update(&data);
        black_box(s.finalize());
        times.push(t.elapsed().as_nanos() as u64);
    }
    calculate_time_stats(&times)
}

fn measure_ads_root_expand_time(iterations: usize) -> TimeStats {
    let c1 = Digest::default();
    let c2 = Digest::default();
    let c3 = Digest::default();
    let expected = Digest::default();
    for _ in 0..WARMUP_ITERATIONS {
        let mut s = blake2().to_state();
        s.update(c1.as_bytes());
        s.update(c2.as_bytes());
        s.update(c3.as_bytes());
        black_box(Digest::from(s.finalize()) == expected);
    }
    let mut times: Vec<u64> = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let t = Instant::now();
        let mut s = blake2().to_state();
        s.update(c1.as_bytes());
        s.update(c2.as_bytes());
        s.update(c3.as_bytes());
        black_box(Digest::from(s.finalize()) == expected);
        times.push(t.elapsed().as_nanos() as u64);
    }
    calculate_time_stats(&times)
}

fn measure_base_times() -> BaseTimes {
    BaseTimes {
        single_hash: measure_hash_time(HASH_SIZE, BASE_ITERATIONS),
        header_hash_scattered: measure_hash_time(SCATTERED_BLOCK_HEADER_SIZE, BASE_ITERATIONS),
        header_hash_unified: measure_hash_time(UNIFIED_BLOCK_HEADER_SIZE, BASE_ITERATIONS),
        ads_root_expand: measure_ads_root_expand_time(BASE_ITERATIONS),
    }
}

// ============================================================================
// MMR验证时间测量
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MMRMeasurement {
    target_height: u32,
    proof_items: usize,
    verify_time: TimeStats,
    per_item_us: f64,
}

fn measure_mmr_verify_at_height(
    chain: &SimChain,
    height: Height,
    iterations: usize,
) -> anyhow::Result<MMRMeasurement> {
    let proof = chain.gen_two_layer_proof(height, None)?;
    let mmr_root = chain.get_mmr_root();
    let items = proof.mmr_proof.proof_items.len();

    // 预热
    for _ in 0..WARMUP_ITERATIONS {
        black_box(proof.verify(mmr_root)?);
    }
    // 正式测量
    let mut times: Vec<u64> = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let t = Instant::now();
        black_box(proof.verify(mmr_root)?);
        times.push(t.elapsed().as_nanos() as u64);
    }
    let stats = calculate_time_stats(&times);
    let per_item = if items > 0 {
        stats.trimmed_mean_us / items as f64
    } else {
        0.0
    };

    Ok(MMRMeasurement {
        target_height: height.0,
        proof_items: items,
        verify_time: stats,
        per_item_us: per_item,
    })
}

// ============================================================================
// 块级验证时间测量
// ============================================================================

fn measure_block_verify_time(
    chain: &SimChain,
    results: &[(
        std::collections::HashMap<vchain_plus::chain::id_tree::ObjId, Object<u32>>,
        vchain_plus::chain::verify::vo::VO<u32>,
    )],
    dag: &petgraph::Graph<vchain_plus::chain::query::query_dag::DagNode<u32>, bool>,
    pk: &AccPublicKey,
    iterations: usize,
    warmup: usize,
) -> anyhow::Result<TimeStats> {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(4).build()?;

    // 预热
    for _ in 0..warmup {
        let _ = pool.install(|| verify(chain, results, dag, pk));
    }
    // 正式测量
    let mut times_us: Vec<f64> = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let t = Instant::now();
        let _ = pool.install(|| verify(chain, results, dag, pk));
        times_us.push(t.elapsed().as_nanos() as f64 / 1000.0);
    }
    Ok(calculate_time_stats_us(&times_us))
}

// ============================================================================
// 结果数据结构
// ============================================================================

// ── 维度一：链级验证时间（23个链长点 × 4方案） ──

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainLevelSchemeResult {
    scheme_name: String,
    chain_verify_time_us: f64,
    formula: String,
    /// 链级验证所需的哈希操作次数
    hash_operations: u64,
    /// 链级证明中涉及的完整区块头数量
    header_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainLengthVerifyResult {
    chain_length: u64,
    log2_n: f64,
    target_height: u64,
    mmr_proof_items_theoretical: u64,
    schemes: Vec<ChainLevelSchemeResult>,
}

// ── 维度二：块级验证时间（6种查询类型） ──

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueryBlockVerifyResult {
    query_index: usize,
    query_type: String,
    query_description: String,
    block_range: (u32, u32),
    range_condition: String,
    has_keyword: bool,
    query_exec_time_us: u64,
    result_count: usize,
    block_verify_time: TimeStats,
}

// ── 维度三：组合分析（链长=20000时，链级+块级） ──

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CombinedSchemeResult {
    scheme_name: String,
    chain_verify_time_us: f64,
    block_verify_time_us: f64,
    total_verify_time_us: f64,
    speedup_vs_hc: f64,
    chain_percent: f64,
    block_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CombinedQueryResult {
    query_type: String,
    query_description: String,
    block_verify_time_us: f64,
    schemes: Vec<CombinedSchemeResult>,
}

// ── 存储开销分析 ──

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SchemeStorageOverhead {
    scheme_name: String,
    /// 链级证明中涉及的区块头数量
    proof_header_count: u64,
    /// 链级证明中的哈希节点数量
    proof_hash_node_count: u64,
    /// 链级证明大小(字节)
    chain_proof_bytes: u64,
    /// 块级信息大小(字节) - 传输给轻节点用于块级验证的额外数据
    block_info_bytes: u64,
    /// 总证明大小(字节) = 链级证明 + 块级信息
    total_proof_bytes: u64,
    /// 全节点维护链级承诺结构的额外存储开销(字节)
    structure_extra_storage_bytes: u64,
    /// 存储开销复杂度说明
    storage_complexity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainLengthStorageResult {
    chain_length: u64,
    schemes: Vec<SchemeStorageOverhead>,
}

// ── MMR校准数据 ──

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MMRCalibration {
    measurements: Vec<MMRMeasurement>,
    avg_per_item_us: f64,
}

// ── 实验汇总 ──

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentSummary {
    /// 各查询类型的块级验证时间 (query_type, time_us)
    block_verify_by_query_type: Vec<(String, f64)>,
    /// 所有查询类型的平均块级验证时间
    avg_block_verify_us: f64,
    /// 链长=20000时各方案的链级验证时间
    chain_verify_at_20000: Vec<(String, f64)>,
    /// 链长=20000时各方案的平均总验证时间（链级+所有查询类型平均块级）
    total_verify_at_20000: Vec<(String, f64)>,
    /// 链长=20000时各方案的平均加速比（相对HC-S）
    speedup_at_20000: Vec<(String, f64)>,
    /// 各方案在链长=20000时的链级承诺结构额外存储开销(字节)
    structure_storage_at_20000: Vec<(String, u64)>,
    /// MMR-U 相对 MT-S 的验证时间变化百分比（正值=增加）
    mmr_u_vs_mt_s_time_change_percent: f64,
    /// MMR-U 相对 MMR-S 的验证时间变化百分比（负值=减少）
    mmr_u_vs_mmr_s_time_change_percent: f64,
    total_query_types: usize,
    total_chain_length_points: usize,
}

// ── 完整输出 ──

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentMetadata {
    experiment_name: String,
    description: String,
    timestamp: u64,
    db_path: String,
    key_path: String,
    query_path: String,
    chain_block_count: u64,
    chain_lengths: Vec<u64>,
    base_iterations: usize,
    mmr_verify_iterations: usize,
    block_verify_iterations: usize,
    block_verify_warmup: usize,
    trim_percent: f64,
    schemes: Vec<SchemeConfig>,
    block_header_sizes: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentOutput {
    metadata: ExperimentMetadata,
    base_times: BaseTimes,
    mmr_calibration: MMRCalibration,
    /// 维度一：23个链长 × 4方案 的链级验证时间
    chain_level_results: Vec<ChainLengthVerifyResult>,
    /// 维度二：6种查询类型的块级验证时间
    block_level_results: Vec<QueryBlockVerifyResult>,
    /// 维度三：链长=20000时 6种查询 × 4方案 的总验证时间分解
    combined_results: Vec<CombinedQueryResult>,
    /// 存储开销：23个链长 × 4方案
    storage_overhead: Vec<ChainLengthStorageResult>,
    summary: ExperimentSummary,
}

// ============================================================================
// 链级验证时间计算（基于实测基准操作耗时）
// ============================================================================

fn calculate_chain_level_times(
    chain_length: u64,
    target_height: u64,
    base: &BaseTimes,
    mmr_per_item_us: f64,
) -> Vec<ChainLevelSchemeResult> {
    let log2_n = (chain_length as f64).log2().ceil() as u64;
    let hc_headers = chain_length - target_height + 1;

    vec![
        // HC-S: 逐块同步 (n-h+1) 个区块头，每个做一次哈希校验
        ChainLevelSchemeResult {
            scheme_name: "HC-S".to_string(),
            chain_verify_time_us: hc_headers as f64
                * base.header_hash_scattered.trimmed_mean_us,
            formula: format!(
                "({}-{}+1) * T_header_hash(164B)",
                chain_length, target_height
            ),
            hash_operations: hc_headers,
            header_count: hc_headers,
        },
        // MT-S: log2(n) 次路径哈希 + 1次块头哈希校验
        ChainLevelSchemeResult {
            scheme_name: "MT-S".to_string(),
            chain_verify_time_us: log2_n as f64
                * base.single_hash.trimmed_mean_us
                + base.header_hash_scattered.trimmed_mean_us,
            formula: format!(
                "ceil(log2({})) * T_hash + T_header_hash(164B)",
                chain_length
            ),
            hash_operations: log2_n + 1,
            header_count: 1,
        },
        // MMR-S: MMR路径验证 + 块头哈希校验
        ChainLevelSchemeResult {
            scheme_name: "MMR-S".to_string(),
            chain_verify_time_us: log2_n as f64 * mmr_per_item_us
                + base.header_hash_scattered.trimmed_mean_us,
            formula: format!(
                "ceil(log2({})) * T_mmr_step + T_header_hash(164B)",
                chain_length
            ),
            hash_operations: log2_n + 1,
            header_count: 1,
        },
        // MMR-U: MMR路径验证 + BlockADSRoot展开验证
        ChainLevelSchemeResult {
            scheme_name: "MMR-U".to_string(),
            chain_verify_time_us: log2_n as f64 * mmr_per_item_us
                + base.ads_root_expand.trimmed_mean_us,
            formula: format!(
                "ceil(log2({})) * T_mmr_step + T_ads_expand",
                chain_length
            ),
            hash_operations: log2_n + 1,
            // MMR-U 不需要完整块头，仅需 BlockADSComponents
            header_count: 0,
        },
    ]
}

// ============================================================================
// 存储开销计算
// ============================================================================

fn calculate_storage_overhead(
    chain_length: u64,
    target_height: u64,
) -> Vec<SchemeStorageOverhead> {
    let log2_n = (chain_length as f64).log2().ceil() as u64;
    let hc_headers = chain_length - target_height + 1;

    vec![
        // HC-S: 无额外结构，链级证明 = (n-h+1)个完整块头
        SchemeStorageOverhead {
            scheme_name: "HC-S".to_string(),
            proof_header_count: hc_headers,
            proof_hash_node_count: 0,
            chain_proof_bytes: hc_headers * SCATTERED_BLOCK_HEADER_SIZE as u64,
            block_info_bytes: 0, // 块头中已包含索引根
            total_proof_bytes: hc_headers * SCATTERED_BLOCK_HEADER_SIZE as u64,
            structure_extra_storage_bytes: 0,
            storage_complexity: "O(1) extra storage; O(n) proof".to_string(),
        },
        // MT-S: Merkle树 ~2n个内部节点
        SchemeStorageOverhead {
            scheme_name: "MT-S".to_string(),
            proof_header_count: 1,
            proof_hash_node_count: log2_n,
            chain_proof_bytes: log2_n * HASH_SIZE as u64,
            block_info_bytes: SCATTERED_BLOCK_HEADER_SIZE as u64,
            total_proof_bytes: log2_n * HASH_SIZE as u64
                + SCATTERED_BLOCK_HEADER_SIZE as u64,
            // Merkle树约 2n 个内部节点，每个 32B
            structure_extra_storage_bytes: 2 * chain_length * HASH_SIZE as u64,
            storage_complexity: "O(n) extra (Merkle nodes); O(log n) proof".to_string(),
        },
        // MMR-S: MMR ~2n个节点
        SchemeStorageOverhead {
            scheme_name: "MMR-S".to_string(),
            proof_header_count: 1,
            proof_hash_node_count: log2_n,
            chain_proof_bytes: log2_n * HASH_SIZE as u64,
            block_info_bytes: SCATTERED_BLOCK_HEADER_SIZE as u64,
            total_proof_bytes: log2_n * HASH_SIZE as u64
                + SCATTERED_BLOCK_HEADER_SIZE as u64,
            // MMR约 2n 个节点，每个 32B
            structure_extra_storage_bytes: 2 * chain_length * HASH_SIZE as u64,
            storage_complexity: "O(n) extra (MMR nodes); O(log n) proof; O(log n) append"
                .to_string(),
        },
        // MMR-U: MMR节点 + BlockADSComponents存储
        SchemeStorageOverhead {
            scheme_name: "MMR-U".to_string(),
            proof_header_count: 0, // 无需完整块头
            proof_hash_node_count: log2_n,
            chain_proof_bytes: log2_n * HASH_SIZE as u64,
            block_info_bytes: BLOCK_ADS_COMPONENTS_SIZE as u64,
            total_proof_bytes: log2_n * HASH_SIZE as u64
                + BLOCK_ADS_COMPONENTS_SIZE as u64,
            // MMR节点(2n×32B) + 全节点保存Components用于证明生成(n×96B)
            structure_extra_storage_bytes: 2 * chain_length * HASH_SIZE as u64
                + chain_length * BLOCK_ADS_COMPONENTS_SIZE as u64,
            storage_complexity: "O(n) extra (MMR+Components); O(log n) proof; O(log n) append"
                .to_string(),
        },
    ]
}

// ============================================================================
// 辅助函数
// ============================================================================

fn load_public_key(key_path: &Path) -> anyhow::Result<AccPublicKey> {
    let key_pair = KeyPair::load(key_path)?;
    Ok(key_pair.pk)
}

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ============================================================================
// 实验主函数
// ============================================================================

#[test]
fn experiment2_verify_time() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════════════╗");
    println!("║     【实验2】验证时间对比 - 23链长 × 6查询类型 × 4方案（含存储开销）              ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════╝");
    println!();

    let schemes = SchemeConfig::all_schemes();
    println!("【对比方案】");
    for (i, s) in schemes.iter().enumerate() {
        println!(
            "  {}. {} (块头{}B): {}",
            i + 1,
            s.name,
            s.block_header_size,
            s.description
        );
    }
    println!();

    // ── 加载数据库和公钥 ──────────────────────────────────────────────
    let db_path = Path::new(DB_PATH);
    let key_path = Path::new(KEY_PATH);
    let query_path = Path::new(QUERY_PATH);

    if !db_path.exists() {
        panic!(
            "数据库不存在: {}，请先运行 build_chain",
            db_path.display()
        );
    }
    if !key_path.exists() {
        panic!("公钥不存在: {}", key_path.display());
    }
    if !query_path.exists() {
        panic!("查询文件不存在: {}", query_path.display());
    }

    println!("【打开已有数据库】{}", db_path.display());
    let chain = SimChain::open(db_path).expect("打开数据库失败");

    let block_count = {
        let meta_path = db_path.join("mmr_meta.json");
        if meta_path.exists() {
            let meta: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
            meta["block_count"].as_u64().unwrap_or(20000)
        } else {
            20000
        }
    };
    println!("  区块数: {}", block_count);

    println!("【加载公钥】");
    let pk = load_public_key(key_path).expect("加载公钥失败");

    // ═══════════════════════════════════════════════════════════════════
    // 第一步：测量基准操作时间
    // ═══════════════════════════════════════════════════════════════════
    println!("\n================================================================");
    println!("  第一步：测量基准操作时间（{} 次迭代）", BASE_ITERATIONS);
    println!("================================================================");

    let base_times = measure_base_times();
    println!(
        "  单次哈希(32B):       {:.3} us",
        base_times.single_hash.trimmed_mean_us
    );
    println!(
        "  块头哈希(164B):      {:.3} us",
        base_times.header_hash_scattered.trimmed_mean_us
    );
    println!(
        "  块头哈希(100B):      {:.3} us",
        base_times.header_hash_unified.trimmed_mean_us
    );
    println!(
        "  ADS展开(3x32B):      {:.3} us",
        base_times.ads_root_expand.trimmed_mean_us
    );

    // ═══════════════════════════════════════════════════════════════════
    // 第二步：MMR验证校准 - 在多个高度实测以确定per-item成本
    // ═══════════════════════════════════════════════════════════════════
    println!("\n================================================================");
    println!(
        "  第二步：MMR验证校准测量（{} 次迭代）",
        MMR_VERIFY_ITERATIONS
    );
    println!("================================================================");

    let calibration_heights: Vec<u32> = vec![100, 500, 1000, 5000, 10000, 15000, 19000];
    let mut mmr_measurements: Vec<MMRMeasurement> = Vec::new();

    for &h in &calibration_heights {
        match measure_mmr_verify_at_height(&chain, Height(h), MMR_VERIFY_ITERATIONS) {
            Ok(m) => {
                println!(
                    "  高度 {:>5}: 证明项={}, 验证={:.3} us, 每项={:.4} us",
                    m.target_height,
                    m.proof_items,
                    m.verify_time.trimmed_mean_us,
                    m.per_item_us
                );
                mmr_measurements.push(m);
            }
            Err(e) => println!("  高度 {:>5}: 测量失败 - {}", h, e),
        }
    }

    // 计算平均 per-item 成本
    let avg_per_item_us = if !mmr_measurements.is_empty() {
        mmr_measurements.iter().map(|m| m.per_item_us).sum::<f64>()
            / mmr_measurements.len() as f64
    } else {
        // 降级：使用单次哈希时间作为近似
        base_times.single_hash.trimmed_mean_us
    };
    println!(
        "\n  >>> 平均每项MMR验证成本: {:.4} us",
        avg_per_item_us
    );

    let mmr_calibration = MMRCalibration {
        measurements: mmr_measurements,
        avg_per_item_us,
    };

    // ═══════════════════════════════════════════════════════════════════
    // 第三步（维度一）：链级验证时间 × 23个链长点
    // ═══════════════════════════════════════════════════════════════════
    println!("\n================================================================");
    println!(
        "  第三步(维度一): 链级验证时间 x {} 个链长点",
        CHAIN_LENGTHS.len()
    );
    println!("================================================================");

    let mut chain_level_results: Vec<ChainLengthVerifyResult> = Vec::new();
    let mut storage_overhead_results: Vec<ChainLengthStorageResult> = Vec::new();

    println!(
        "\n  {:>6} | {:>5} | {:>12} {:>10} {:>10} {:>10}",
        "chain_n", "log2n", "HC-S(us)", "MT-S(us)", "MMR-S(us)", "MMR-U(us)"
    );
    println!("  -------+-------+---------------------------------------------------");

    for &n in &CHAIN_LENGTHS {
        let target_h = n / 2;
        let log2_n_val = (n as f64).log2().ceil();
        let mmr_items_theoretical = log2_n_val as u64;

        let scheme_results =
            calculate_chain_level_times(n, target_h, &base_times, avg_per_item_us);

        print!("  {:>6} | {:>5.1} |", n, log2_n_val);
        for sr in &scheme_results {
            print!(" {:>11.2}", sr.chain_verify_time_us);
        }
        println!();

        chain_level_results.push(ChainLengthVerifyResult {
            chain_length: n,
            log2_n: log2_n_val,
            target_height: target_h,
            mmr_proof_items_theoretical: mmr_items_theoretical,
            schemes: scheme_results,
        });

        // 计算该链长的存储开销
        let storage = calculate_storage_overhead(n, target_h);
        storage_overhead_results.push(ChainLengthStorageResult {
            chain_length: n,
            schemes: storage,
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // 第四步（维度二）：块级验证时间 × 6种查询类型
    // ═══════════════════════════════════════════════════════════════════
    println!("\n================================================================");
    println!("  第四步(维度二): 块级验证时间 x 6种查询类型");
    println!("================================================================");

    println!("【加载查询参数】{}", query_path.display());
    let query_params = load_query_param_from_file(query_path).expect("加载查询文件失败");
    println!("  查询条数: {}", query_params.len());

    let mut block_level_results: Vec<QueryBlockVerifyResult> = Vec::new();

    for (i, qp) in query_params.into_iter().enumerate() {
        let qt = QueryType::from_index(i);
        let has_kw = qp.keyword_exp.is_some();
        println!(
            "\n  --- Q{}: {} ({}) ---",
            i,
            qt.label(),
            qt.description()
        );
        println!(
            "    区块范围: [{}, {}], Range: {:?}",
            qp.start_blk, qp.end_blk, qp.range
        );
        println!(
            "    关键词: {}",
            if has_kw { "有" } else { "无（纯范围）" }
        );

        let range_str = format!("{:?}", qp.range);

        // 执行查询
        let t0 = Instant::now();
        let qr = query(true, true, &chain, qp.clone(), &pk);
        let query_us = t0.elapsed().as_micros() as u64;

        match qr {
            Ok((results, res_dags, _)) => {
                let count: usize = results.iter().map(|(r, _)| r.len()).sum();
                println!("    查询耗时: {} us, 结果数: {}", query_us, count);

                // 测量块级验证时间
                println!(
                    "    测量块级验证时间 ({} 次)...",
                    BLOCK_VERIFY_ITERATIONS
                );
                match measure_block_verify_time(
                    &chain,
                    &results,
                    &res_dags,
                    &pk,
                    BLOCK_VERIFY_ITERATIONS,
                    BLOCK_VERIFY_WARMUP,
                ) {
                    Ok(bv) => {
                        println!(
                            "    块级验证: {:.2} us (trimmed), {:.2} us (mean)",
                            bv.trimmed_mean_us, bv.mean_us
                        );

                        block_level_results.push(QueryBlockVerifyResult {
                            query_index: i,
                            query_type: qt.label().to_string(),
                            query_description: qt.description().to_string(),
                            block_range: (qp.start_blk, qp.end_blk),
                            range_condition: range_str,
                            has_keyword: has_kw,
                            query_exec_time_us: query_us,
                            result_count: count,
                            block_verify_time: bv,
                        });
                    }
                    Err(e) => println!("    块级验证失败: {}", e),
                }
            }
            Err(e) => println!("    查询失败: {}", e),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // 第五步（维度三）：组合分析 - 链长=20000时的总验证时间分解
    // ═══════════════════════════════════════════════════════════════════
    println!("\n================================================================");
    println!("  第五步(维度三): 组合分析（链长=20000, 链级+块级）");
    println!("================================================================");

    // 获取链长=20000时的链级验证时间
    let chain_at_20000 = chain_level_results
        .iter()
        .find(|r| r.chain_length == 20000)
        .expect("未找到链长=20000的链级结果");

    // HC-S 的链级验证时间（用于计算加速比）
    let hc_chain_us = chain_at_20000
        .schemes
        .iter()
        .find(|s| s.scheme_name == "HC-S")
        .unwrap()
        .chain_verify_time_us;

    let mut combined_results: Vec<CombinedQueryResult> = Vec::new();

    for blr in &block_level_results {
        let block_us = blr.block_verify_time.trimmed_mean_us;
        let hc_total = hc_chain_us + block_us;

        let mut combined_schemes: Vec<CombinedSchemeResult> = Vec::new();
        for cs in &chain_at_20000.schemes {
            let total = cs.chain_verify_time_us + block_us;
            combined_schemes.push(CombinedSchemeResult {
                scheme_name: cs.scheme_name.clone(),
                chain_verify_time_us: cs.chain_verify_time_us,
                block_verify_time_us: block_us,
                total_verify_time_us: total,
                speedup_vs_hc: if total > 0.0 {
                    hc_total / total
                } else {
                    1.0
                },
                chain_percent: if total > 0.0 {
                    cs.chain_verify_time_us / total * 100.0
                } else {
                    0.0
                },
                block_percent: if total > 0.0 {
                    block_us / total * 100.0
                } else {
                    0.0
                },
            });
        }

        println!(
            "\n  [{}] 块级={:.2} us",
            blr.query_type, block_us
        );
        println!("  +---------+----------+----------+----------+----------+---------+---------+");
        println!("  | Scheme  | Chain us | Block us | Total us | Speedup  | Chain%  | Block%  |");
        println!("  +---------+----------+----------+----------+----------+---------+---------+");
        for r in &combined_schemes {
            println!(
                "  | {:<7} | {:>8.2} | {:>8.2} | {:>8.2} | {:>7.1}x | {:>6.1}% | {:>6.1}% |",
                r.scheme_name,
                r.chain_verify_time_us,
                r.block_verify_time_us,
                r.total_verify_time_us,
                r.speedup_vs_hc,
                r.chain_percent,
                r.block_percent
            );
        }
        println!("  +---------+----------+----------+----------+----------+---------+---------+");

        combined_results.push(CombinedQueryResult {
            query_type: blr.query_type.clone(),
            query_description: blr.query_description.clone(),
            block_verify_time_us: block_us,
            schemes: combined_schemes,
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // 第六步：存储开销汇总
    // ═══════════════════════════════════════════════════════════════════
    println!("\n================================================================");
    println!("  第六步: 链级承诺结构存储开销分析");
    println!("================================================================");

    // 打印部分典型链长的存储开销
    let typical_lengths: Vec<u64> = vec![100, 1000, 5000, 10000, 20000];
    println!("\n  典型链长下各方案的存储开销:");
    println!(
        "  {:>6} | {:<7} | {:>8} | {:>8} | {:>10} | {:>12}",
        "链长n", "方案", "块头数", "哈希数", "证明(B)", "结构存储(B)"
    );
    println!("  -------+---------+----------+----------+------------+--------------");

    for n in &typical_lengths {
        if let Some(sr) = storage_overhead_results
            .iter()
            .find(|r| r.chain_length == *n)
        {
            for (idx, s) in sr.schemes.iter().enumerate() {
                if idx == 0 {
                    print!("  {:>6} |", n);
                } else {
                    print!("         |");
                }
                println!(
                    " {:<7} | {:>8} | {:>8} | {:>10} | {:>12}",
                    s.scheme_name,
                    s.proof_header_count,
                    s.proof_hash_node_count,
                    s.total_proof_bytes,
                    s.structure_extra_storage_bytes
                );
            }
            println!("  -------+---------+----------+----------+------------+--------------");
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // 汇总统计与输出
    // ═══════════════════════════════════════════════════════════════════
    println!("\n================================================================");
    println!("  汇总统计");
    println!("================================================================");

    // 块级验证按查询类型汇总
    let block_verify_by_type: Vec<(String, f64)> = block_level_results
        .iter()
        .map(|r| {
            (
                r.query_type.clone(),
                r.block_verify_time.trimmed_mean_us,
            )
        })
        .collect();

    let avg_block_us = if !block_level_results.is_empty() {
        block_level_results
            .iter()
            .map(|r| r.block_verify_time.trimmed_mean_us)
            .sum::<f64>()
            / block_level_results.len() as f64
    } else {
        0.0
    };

    // 链长=20000时各方案的链级验证时间
    let chain_verify_at_20000: Vec<(String, f64)> = chain_at_20000
        .schemes
        .iter()
        .map(|s| (s.scheme_name.clone(), s.chain_verify_time_us))
        .collect();

    // 链长=20000时各方案的总验证时间和加速比（取所有查询类型的平均）
    let scheme_names = ["HC-S", "MT-S", "MMR-S", "MMR-U"];
    let mut total_verify_at_20000 = Vec::new();
    let mut speedup_at_20000 = Vec::new();

    for name in &scheme_names {
        let totals: Vec<f64> = combined_results
            .iter()
            .flat_map(|q| q.schemes.iter())
            .filter(|s| s.scheme_name == *name)
            .map(|s| s.total_verify_time_us)
            .collect();
        let speedups: Vec<f64> = combined_results
            .iter()
            .flat_map(|q| q.schemes.iter())
            .filter(|s| s.scheme_name == *name)
            .map(|s| s.speedup_vs_hc)
            .collect();
        if !totals.is_empty() {
            total_verify_at_20000.push((
                name.to_string(),
                totals.iter().sum::<f64>() / totals.len() as f64,
            ));
        }
        if !speedups.is_empty() {
            speedup_at_20000.push((
                name.to_string(),
                speedups.iter().sum::<f64>() / speedups.len() as f64,
            ));
        }
    }

    // 存储开销 at 20000
    let structure_storage_at_20000: Vec<(String, u64)> = storage_overhead_results
        .iter()
        .find(|r| r.chain_length == 20000)
        .map(|r| {
            r.schemes
                .iter()
                .map(|s| (s.scheme_name.clone(), s.structure_extra_storage_bytes))
                .collect()
        })
        .unwrap_or_default();

    // MMR-U vs MT-S / MMR-S 的验证时间变化百分比
    let mt_s_chain = chain_at_20000
        .schemes
        .iter()
        .find(|s| s.scheme_name == "MT-S")
        .map(|s| s.chain_verify_time_us)
        .unwrap_or(1.0);
    let mmr_s_chain = chain_at_20000
        .schemes
        .iter()
        .find(|s| s.scheme_name == "MMR-S")
        .map(|s| s.chain_verify_time_us)
        .unwrap_or(1.0);
    let mmr_u_chain = chain_at_20000
        .schemes
        .iter()
        .find(|s| s.scheme_name == "MMR-U")
        .map(|s| s.chain_verify_time_us)
        .unwrap_or(1.0);

    let mmr_u_vs_mt_s_pct = (mmr_u_chain - mt_s_chain) / mt_s_chain * 100.0;
    let mmr_u_vs_mmr_s_pct = (mmr_u_chain - mmr_s_chain) / mmr_s_chain * 100.0;

    let summary = ExperimentSummary {
        block_verify_by_query_type: block_verify_by_type.clone(),
        avg_block_verify_us: avg_block_us,
        chain_verify_at_20000: chain_verify_at_20000.clone(),
        total_verify_at_20000: total_verify_at_20000.clone(),
        speedup_at_20000: speedup_at_20000.clone(),
        structure_storage_at_20000: structure_storage_at_20000.clone(),
        mmr_u_vs_mt_s_time_change_percent: mmr_u_vs_mt_s_pct,
        mmr_u_vs_mmr_s_time_change_percent: mmr_u_vs_mmr_s_pct,
        total_query_types: block_level_results.len(),
        total_chain_length_points: chain_level_results.len(),
    };

    // ── 打印汇总 ─────────────────────────────────────────────────────

    println!("\n  【各查询类型的块级验证时间（维度二覆盖表数据）】");
    println!(
        "    {:<20} {:<15} {:>10} {:>14}",
        "查询类型", "说明", "结果数", "块级验证(us)"
    );
    println!("    {}", "-".repeat(62));
    for blr in &block_level_results {
        println!(
            "    {:<20} {:<15} {:>10} {:>14.2}",
            blr.query_type, blr.query_description, blr.result_count,
            blr.block_verify_time.trimmed_mean_us
        );
    }
    println!("    平均块级验证时间: {:.2} us", avg_block_us);

    println!("\n  【链长=20000时各方案的链级验证时间】");
    for (n, t) in &chain_verify_at_20000 {
        println!("    {:<8}: {:.2} us", n, t);
    }

    println!("\n  【链长=20000时各方案的平均总验证时间（链级+块级平均）】");
    for (n, t) in &total_verify_at_20000 {
        println!("    {:<8}: {:.2} us", n, t);
    }

    println!("\n  【链长=20000时各方案的平均加速比（vs HC-S）】");
    for (n, s) in &speedup_at_20000 {
        println!("    {:<8}: {:.1}x", n, s);
    }

    println!("\n  【链长=20000时各方案的链级承诺结构额外存储开销】");
    for (n, s) in &structure_storage_at_20000 {
        println!("    {:<8}: {} B ({:.2} KB)", n, s, *s as f64 / 1024.0);
    }

    println!(
        "\n  【MMR-U vs MT-S 链级验证时间变化: {:+.1}%】",
        mmr_u_vs_mt_s_pct
    );
    println!(
        "  【MMR-U vs MMR-S 链级验证时间变化: {:+.1}%】",
        mmr_u_vs_mmr_s_pct
    );

    // ── 构建输出 JSON ────────────────────────────────────────────────

    let mut header_sizes = BTreeMap::new();
    header_sizes.insert("scattered".to_string(), SCATTERED_BLOCK_HEADER_SIZE);
    header_sizes.insert("unified".to_string(), UNIFIED_BLOCK_HEADER_SIZE);
    header_sizes.insert("ads_components".to_string(), BLOCK_ADS_COMPONENTS_SIZE);

    let output = ExperimentOutput {
        metadata: ExperimentMetadata {
            experiment_name: "experiment2_verify_time_comprehensive".to_string(),
            description:
                "验证时间对比实验 - 23链长x6查询类型x4方案（含存储开销分析）"
                    .to_string(),
            timestamp: get_timestamp(),
            db_path: DB_PATH.to_string(),
            key_path: KEY_PATH.to_string(),
            query_path: QUERY_PATH.to_string(),
            chain_block_count: block_count,
            chain_lengths: CHAIN_LENGTHS.to_vec(),
            base_iterations: BASE_ITERATIONS,
            mmr_verify_iterations: MMR_VERIFY_ITERATIONS,
            block_verify_iterations: BLOCK_VERIFY_ITERATIONS,
            block_verify_warmup: BLOCK_VERIFY_WARMUP,
            trim_percent: TRIM_PERCENT,
            schemes,
            block_header_sizes: header_sizes,
        },
        base_times,
        mmr_calibration,
        chain_level_results,
        block_level_results,
        combined_results,
        storage_overhead: storage_overhead_results,
        summary,
    };

    let json = serde_json::to_string_pretty(&output).expect("JSON序列化失败");
    let _ = fs::create_dir_all("output");
    fs::write("output/experiment2_results.json", &json).expect("写入结果失败");

    println!("\n\n================================================================");
    println!("                   实验2结果已保存");
    println!("================================================================");
    println!("  output/experiment2_results.json");
    println!();
    println!("  数据包含:");
    println!("    (1) chain_level_results : 23个链长 x 4方案 的链级验证时间（主对比图）");
    println!("    (2) block_level_results : 6种查询类型的块级验证时间（覆盖表）");
    println!("    (3) combined_results    : 链长=20000时总时间分解（堆叠柱状图）");
    println!("    (4) storage_overhead    : 23个链长 x 4方案 的存储开销（存储分析）");
    println!("    (5) mmr_calibration     : MMR实测校准数据");
    println!("    (6) summary             : 汇总统计数据");
    println!();
    println!("  实验2完成");
}