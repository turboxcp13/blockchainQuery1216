//! 【实验2】验证时间对比实验 - 多方案对比
//!
//! ## 实验目标
//! 对比四种方案的验证时间，展示两层式证明的效率及权衡分析
//!
//! ## 对比方案
//! - HeaderChain: 区块头链同步验证（最原始方案）
//! - Merkle: Merkle树证明验证（常见优化方案）
//! - MMR-Scattered: MMR验证 + 分散索引根（仅链级优化）
//! - Two-Layer: MMR验证 + BlockADSRoot展开验证（本文方案）
//!
//! ## 两层式验证结构
//! - 第一层（链级）: MMR证明验证，验证BlockADSRoot属于主链
//! - 第二层（块级）: BlockADSRoot展开验证，验证Components一致性
//!
//! ## 运行命令
//! ```bash
//! cargo test --test experiment2_verify_time --release -- --nocapture
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use vchain_plus::acc::AccPublicKey;
use vchain_plus::chain::block::build::build_block_with_mmr;
use vchain_plus::chain::block::Height;
use vchain_plus::chain::object::Object;
use vchain_plus::chain::Parameter;
use vchain_plus::digest::{blake2, Digest, Digestible};
use vchain_plus::utils::{load_raw_obj_from_file, KeyPair};
use vchain_plus::SimChain;
use serde::{Deserialize, Serialize};
use std::io::Write;

// ============================================================================
// 实验配置常量
// ============================================================================

/// 公钥文件路径
const KEY_PATH: &str = "output/pk_eth.key";

/// 数据集路径
const DATASET_PATH: &str = "data/dataset/eth.dat";

/// 验证迭代次数（用于取平均值，提高测量精度）
const VERIFY_ITERATIONS: usize = 100;

/// 单个哈希大小（字节）
const HASH_SIZE: usize = 32;

/// 分散索引根块头大小（字节）
const SCATTERED_BLOCK_HEADER_SIZE: usize = 164;

/// 一体化块头大小（字节）
const UNIFIED_BLOCK_HEADER_SIZE: usize = 100;

// ============================================================================
// 方案定义
// ============================================================================

/// 链级证明类型
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
enum ChainProofType {
    /// 区块头链同步（线性验证）
    HeaderChain,
    /// Merkle树证明（对数验证）
    Merkle,
    /// MMR证明（对数验证）
    MMR,
}

/// 块级验证类型
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
enum BlockVerifyType {
    /// 无额外块级验证（索引根已在块头中）
    None,
    /// 块头哈希验证（验证块头完整性）
    HeaderHash,
    /// BlockADSRoot展开验证（验证Components一致性）
    AdsRootExpand,
}

/// 方案配置
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SchemeConfig {
    /// 方案名称
    name: String,
    /// 链级证明类型
    chain_proof_type: ChainProofType,
    /// 块级验证类型
    block_verify_type: BlockVerifyType,
    /// 方案描述
    description: String,
    /// 块头大小（字节）
    block_header_size: usize,
    /// 是否为两层式验证
    is_two_layer: bool,
}

impl SchemeConfig {
    fn header_chain() -> Self {
        Self {
            name: "HeaderChain".to_string(),
            chain_proof_type: ChainProofType::HeaderChain,
            block_verify_type: BlockVerifyType::None,
            description: "区块头链同步验证（最原始方案）".to_string(),
            block_header_size: SCATTERED_BLOCK_HEADER_SIZE,
            is_two_layer: false,
        }
    }

    fn merkle() -> Self {
        Self {
            name: "Merkle".to_string(),
            chain_proof_type: ChainProofType::Merkle,
            block_verify_type: BlockVerifyType::HeaderHash,
            description: "Merkle树证明验证（常见优化方案）".to_string(),
            block_header_size: SCATTERED_BLOCK_HEADER_SIZE,
            is_two_layer: false,
        }
    }

    fn mmr_scattered() -> Self {
        Self {
            name: "MMR-Scattered".to_string(),
            chain_proof_type: ChainProofType::MMR,
            block_verify_type: BlockVerifyType::HeaderHash,
            description: "MMR验证 + 分散索引根（仅链级优化）".to_string(),
            block_header_size: SCATTERED_BLOCK_HEADER_SIZE,
            is_two_layer: false,
        }
    }

    fn two_layer() -> Self {
        Self {
            name: "Two-Layer".to_string(),
            chain_proof_type: ChainProofType::MMR,
            block_verify_type: BlockVerifyType::AdsRootExpand,
            description: "MMR验证 + BlockADSRoot展开验证（本文两层式方案）".to_string(),
            block_header_size: UNIFIED_BLOCK_HEADER_SIZE,
            is_two_layer: true,
        }
    }

    fn all_schemes() -> Vec<Self> {
        vec![
            Self::header_chain(),
            Self::merkle(),
            Self::mmr_scattered(),
            Self::two_layer(),
        ]
    }
}

// ============================================================================
// 实验结果数据结构
// ============================================================================

/// 验证时间统计
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimeStats {
    /// 平均值（微秒）
    mean_us: f64,
    /// 最小值（微秒）
    min_us: u64,
    /// 最大值（微秒）
    max_us: u64,
    /// 标准差（微秒）
    std_us: f64,
}

/// 单个方案在特定链长下的验证时间结果
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SchemeVerifyResult {
    /// 方案名称
    scheme_name: String,
    /// 链级验证时间（微秒）
    chain_verify_time_us: f64,
    /// 块级验证时间（微秒）
    block_verify_time_us: f64,
    /// 总验证时间（微秒）
    total_verify_time_us: f64,
    /// 相对于HeaderChain的加速比
    speedup_vs_header_chain: f64,
}

/// 两层式验证时间分解
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TwoLayerVerifyBreakdown {
    /// 第一层：MMR证明验证时间（微秒）
    layer1_mmr_verify: TimeStats,
    /// 第二层：BlockADSRoot展开验证时间（微秒）
    layer2_ads_root_expand: TimeStats,
    /// 两层总时间（微秒）
    total: TimeStats,
    /// 第二层占总时间的百分比
    layer2_overhead_percent: f64,
}

/// 实测的基准时间数据
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MeasuredBaseTimes {
    /// 单次哈希计算时间
    single_hash: TimeStats,
    /// 块头哈希计算时间（164B输入）
    header_hash_scattered: TimeStats,
    /// 块头哈希计算时间（100B输入）
    header_hash_unified: TimeStats,
    /// BlockADSRoot展开验证时间（3×32B输入）
    ads_root_expand: TimeStats,
}

/// 单个链长的所有方案结果
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainLengthResult {
    /// 链长
    chain_length: u64,
    /// log₂(n)
    log2_n: f64,
    /// 测试区块高度
    test_block_height: u32,
    /// 实际MMR证明项数量
    actual_mmr_proof_items: usize,
    /// 各方案结果
    schemes: Vec<SchemeVerifyResult>,
    /// 两层式验证时间分解（仅Two-Layer方案）
    two_layer_breakdown: TwoLayerVerifyBreakdown,
    /// 实测的基准时间
    measured_base_times: MeasuredBaseTimes,
    /// 实测的MMR验证时间统计
    mmr_verify_stats: TimeStats,
}

/// 实验元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentMetadata {
    experiment_name: String,
    description: String,
    timestamp: u64,
    dataset_path: String,
    key_path: String,
    chain_lengths: Vec<u64>,
    verify_iterations: usize,
    hash_size: usize,
    scattered_block_header_size: usize,
    unified_block_header_size: usize,
    schemes: Vec<SchemeConfig>,
}

/// 实验汇总
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentSummary {
    /// 各方案的平均加速比（相对于HeaderChain）
    avg_speedup_ratios: Vec<(String, f64)>,
    /// 最大链长时各方案的验证时间
    max_chain_verify_times: Vec<(String, f64)>,
    /// Two-Layer的额外开销分析
    two_layer_overhead_analysis: TwoLayerOverheadAnalysis,
    /// 总测试点数
    total_data_points: usize,
}

/// Two-Layer方案的额外开销分析
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TwoLayerOverheadAnalysis {
    /// 平均第二层验证开销（微秒）
    avg_layer2_overhead_us: f64,
    /// 第二层开销占总时间的平均百分比
    avg_layer2_overhead_percent: f64,
    /// 相对于MMR-Scattered的总时间增加百分比
    overhead_vs_mmr_scattered_percent: f64,
}

/// 完整实验输出
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentOutput {
    metadata: ExperimentMetadata,
    results: Vec<ChainLengthResult>,
    summary: ExperimentSummary,
}

// ============================================================================
// 辅助函数
// ============================================================================

fn make_test_param() -> Parameter {
    Parameter {
        id_tree_fanout: 4,
        bplus_tree_fanout: 4,
        num_dim: 1,
        max_id_num: 4095,
        time_win_sizes: vec![2, 4, 8, 16, 32, 64],
    }
}

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

/// 计算标准差
fn calculate_std(values: &[u64], mean: f64) -> f64 {
    if values.len() <= 1 {
        return 0.0;
    }
    let variance: f64 = values.iter()
        .map(|&v| {
            let diff = v as f64 - mean;
            diff * diff
        })
        .sum::<f64>() / (values.len() - 1) as f64;
    variance.sqrt()
}

/// 计算时间统计
fn calculate_time_stats(times_ns: &[u64]) -> TimeStats {
    if times_ns.is_empty() {
        return TimeStats {
            mean_us: 0.0,
            min_us: 0,
            max_us: 0,
            std_us: 0.0,
        };
    }
    let mean_ns = times_ns.iter().sum::<u64>() as f64 / times_ns.len() as f64;
    let mean_us = mean_ns / 1000.0;
    let min_us = times_ns.iter().min().unwrap() / 1000;
    let max_us = times_ns.iter().max().unwrap() / 1000;
    let std_us = calculate_std(times_ns, mean_ns) / 1000.0;
    
    TimeStats {
        mean_us,
        min_us,
        max_us,
        std_us,
    }
}

/// 测量单次哈希计算时间
fn measure_single_hash_time(iterations: usize) -> TimeStats {
    let test_data = [0u8; 32];
    let mut times: Vec<u64> = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let mut state = blake2().to_state();
        state.update(&test_data);
        let _result = state.finalize();
        times.push(start.elapsed().as_nanos() as u64);
    }
    
    calculate_time_stats(&times)
}

/// 测量块头哈希计算时间（分散索引根块头，164B）
fn measure_header_hash_scattered_time(iterations: usize) -> TimeStats {
    let test_data = [0u8; SCATTERED_BLOCK_HEADER_SIZE];
    let mut times: Vec<u64> = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let mut state = blake2().to_state();
        state.update(&test_data);
        let _result = state.finalize();
        times.push(start.elapsed().as_nanos() as u64);
    }
    
    calculate_time_stats(&times)
}

/// 测量块头哈希计算时间（一体化块头，100B）
fn measure_header_hash_unified_time(iterations: usize) -> TimeStats {
    let test_data = [0u8; UNIFIED_BLOCK_HEADER_SIZE];
    let mut times: Vec<u64> = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let mut state = blake2().to_state();
        state.update(&test_data);
        let _result = state.finalize();
        times.push(start.elapsed().as_nanos() as u64);
    }
    
    calculate_time_stats(&times)
}

/// 测量BlockADSRoot展开验证时间
/// 验证: Hash(id_set_root || id_tree_root || multi_ads_hash) == ads_root
fn measure_ads_root_expand_time(iterations: usize) -> TimeStats {
    let component1 = Digest::default();
    let component2 = Digest::default();
    let component3 = Digest::default();
    let expected_root = Digest::default();
    
    let mut times: Vec<u64> = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        
        // 计算 Hash(c1 || c2 || c3)
        let mut state = blake2().to_state();
        state.update(component1.as_bytes());
        state.update(component2.as_bytes());
        state.update(component3.as_bytes());
        let computed_root = Digest::from(state.finalize());
        
        // 比较（实际验证中会检查是否相等）
        let _is_valid = computed_root == expected_root;
        
        times.push(start.elapsed().as_nanos() as u64);
    }
    
    calculate_time_stats(&times)
}

/// 测量MMR验证时间
fn measure_mmr_verify_time(
    chain: &SimChain,
    test_block_height: Height,
    iterations: usize,
) -> anyhow::Result<(TimeStats, usize)> {
    let proof = chain.gen_two_layer_proof(test_block_height, None)?;
    let mmr_root = chain.get_mmr_root();
    let mmr_items = proof.mmr_proof.proof_items.len();
    
    let mut times: Vec<u64> = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = proof.verify(mmr_root)?;
        times.push(start.elapsed().as_nanos() as u64);
    }
    
    Ok((calculate_time_stats(&times), mmr_items))
}

/// 测量两层式完整验证时间
fn measure_two_layer_verify_time(
    chain: &SimChain,
    test_block_height: Height,
    iterations: usize,
) -> anyhow::Result<TwoLayerVerifyBreakdown> {
    let proof = chain.gen_two_layer_proof(test_block_height, None)?;
    let mmr_root = chain.get_mmr_root();
    
    // 模拟BlockADSRoot的组件
    let component1 = Digest::default();
    let component2 = Digest::default();
    let component3 = Digest::default();
    
    let mut layer1_times: Vec<u64> = Vec::with_capacity(iterations);
    let mut layer2_times: Vec<u64> = Vec::with_capacity(iterations);
    let mut total_times: Vec<u64> = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let total_start = Instant::now();
        
        // 第一层：MMR验证
        let layer1_start = Instant::now();
        let _ = proof.verify(mmr_root)?;
        let layer1_elapsed = layer1_start.elapsed().as_nanos() as u64;
        layer1_times.push(layer1_elapsed);
        
        // 第二层：BlockADSRoot展开验证
        let layer2_start = Instant::now();
        let mut state = blake2().to_state();
        state.update(component1.as_bytes());
        state.update(component2.as_bytes());
        state.update(component3.as_bytes());
        let _computed_root = Digest::from(state.finalize());
        let layer2_elapsed = layer2_start.elapsed().as_nanos() as u64;
        layer2_times.push(layer2_elapsed);
        
        total_times.push(total_start.elapsed().as_nanos() as u64);
    }
    
    let layer1_stats = calculate_time_stats(&layer1_times);
    let layer2_stats = calculate_time_stats(&layer2_times);
    let total_stats = calculate_time_stats(&total_times);
    
    let layer2_overhead_percent = if total_stats.mean_us > 0.0 {
        layer2_stats.mean_us / total_stats.mean_us * 100.0
    } else {
        0.0
    };
    
    Ok(TwoLayerVerifyBreakdown {
        layer1_mmr_verify: layer1_stats,
        layer2_ads_root_expand: layer2_stats,
        total: total_stats,
        layer2_overhead_percent,
    })
}

/// 计算各方案的验证时间
fn calculate_scheme_verify_times(
    scheme: &SchemeConfig,
    chain_length: u64,
    test_block_height: u64,
    base_times: &MeasuredBaseTimes,
    mmr_verify_time_us: f64,
    two_layer_breakdown: &TwoLayerVerifyBreakdown,
    header_chain_total: f64,
) -> SchemeVerifyResult {
    let (chain_verify_time, block_verify_time) = match scheme.chain_proof_type {
        ChainProofType::HeaderChain => {
            // 区块头链：需要验证 (n-h+1) 个区块头哈希
            let headers_to_verify = chain_length - test_block_height + 1;
            let chain_time = headers_to_verify as f64 * base_times.header_hash_scattered.mean_us;
            (chain_time, 0.0)
        }
        ChainProofType::Merkle => {
            // Merkle树：log₂(n) 个哈希验证 + 块头哈希
            let tree_height = (chain_length as f64).log2().ceil() as u64;
            let chain_time = tree_height as f64 * base_times.single_hash.mean_us;
            let block_time = base_times.header_hash_scattered.mean_us;
            (chain_time, block_time)
        }
        ChainProofType::MMR => {
            match scheme.block_verify_type {
                BlockVerifyType::HeaderHash => {
                    // MMR-Scattered：MMR验证 + 块头哈希
                    (mmr_verify_time_us, base_times.header_hash_scattered.mean_us)
                }
                BlockVerifyType::AdsRootExpand => {
                    // Two-Layer：使用实测的两层式验证时间
                    (
                        two_layer_breakdown.layer1_mmr_verify.mean_us,
                        two_layer_breakdown.layer2_ads_root_expand.mean_us
                    )
                }
                BlockVerifyType::None => {
                    (mmr_verify_time_us, 0.0)
                }
            }
        }
    };
    
    let total_verify_time = chain_verify_time + block_verify_time;
    let speedup = if total_verify_time > 0.0 {
        header_chain_total / total_verify_time
    } else {
        1.0
    };

    SchemeVerifyResult {
        scheme_name: scheme.name.clone(),
        chain_verify_time_us: chain_verify_time,
        block_verify_time_us: block_verify_time,
        total_verify_time_us: total_verify_time,
        speedup_vs_header_chain: speedup,
    }
}

/// 计算实验汇总
fn calculate_summary(results: &[ChainLengthResult], schemes: &[SchemeConfig]) -> ExperimentSummary {
    if results.is_empty() {
        return ExperimentSummary {
            avg_speedup_ratios: vec![],
            max_chain_verify_times: vec![],
            two_layer_overhead_analysis: TwoLayerOverheadAnalysis {
                avg_layer2_overhead_us: 0.0,
                avg_layer2_overhead_percent: 0.0,
                overhead_vs_mmr_scattered_percent: 0.0,
            },
            total_data_points: 0,
        };
    }

    // 计算各方案的平均加速比
    let mut avg_speedup_ratios = Vec::new();
    for scheme in schemes {
        let speedups: Vec<f64> = results
            .iter()
            .flat_map(|r| r.schemes.iter())
            .filter(|s| s.scheme_name == scheme.name)
            .map(|s| s.speedup_vs_header_chain)
            .collect();
        
        if !speedups.is_empty() {
            let avg = speedups.iter().sum::<f64>() / speedups.len() as f64;
            avg_speedup_ratios.push((scheme.name.clone(), avg));
        }
    }

    // 获取最大链长时各方案的验证时间
    let max_chain_result = results.last().unwrap();
    let max_chain_verify_times: Vec<(String, f64)> = max_chain_result
        .schemes
        .iter()
        .map(|s| (s.scheme_name.clone(), s.total_verify_time_us))
        .collect();

    // Two-Layer的额外开销分析
    let layer2_overheads: Vec<f64> = results
        .iter()
        .map(|r| r.two_layer_breakdown.layer2_ads_root_expand.mean_us)
        .collect();
    
    let layer2_percents: Vec<f64> = results
        .iter()
        .map(|r| r.two_layer_breakdown.layer2_overhead_percent)
        .collect();
    
    let two_layer_totals: Vec<f64> = results
        .iter()
        .flat_map(|r| r.schemes.iter())
        .filter(|s| s.scheme_name == "Two-Layer")
        .map(|s| s.total_verify_time_us)
        .collect();
    
    let mmr_scattered_totals: Vec<f64> = results
        .iter()
        .flat_map(|r| r.schemes.iter())
        .filter(|s| s.scheme_name == "MMR-Scattered")
        .map(|s| s.total_verify_time_us)
        .collect();

    let avg_layer2_overhead = if !layer2_overheads.is_empty() {
        layer2_overheads.iter().sum::<f64>() / layer2_overheads.len() as f64
    } else {
        0.0
    };

    let avg_layer2_percent = if !layer2_percents.is_empty() {
        layer2_percents.iter().sum::<f64>() / layer2_percents.len() as f64
    } else {
        0.0
    };

    let overhead_vs_mmr_scattered = if !two_layer_totals.is_empty() 
        && !mmr_scattered_totals.is_empty() 
        && two_layer_totals.len() == mmr_scattered_totals.len() {
        let overhead_percents: Vec<f64> = two_layer_totals
            .iter()
            .zip(mmr_scattered_totals.iter())
            .map(|(t, m)| if *m > 0.0 { (*t - *m) / *m * 100.0 } else { 0.0 })
            .collect();
        overhead_percents.iter().sum::<f64>() / overhead_percents.len() as f64
    } else {
        0.0
    };

    ExperimentSummary {
        avg_speedup_ratios,
        max_chain_verify_times,
        two_layer_overhead_analysis: TwoLayerOverheadAnalysis {
            avg_layer2_overhead_us: avg_layer2_overhead,
            avg_layer2_overhead_percent: avg_layer2_percent,
            overhead_vs_mmr_scattered_percent: overhead_vs_mmr_scattered,
        },
        total_data_points: results.len(),
    }
}

// ============================================================================
// 实验主函数
// ============================================================================

#[test]
fn experiment2_verify_time() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════════════╗");
    println!("║              【实验2】验证时间对比实验 - 多方案对比                                ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════╝");
    println!();

    let schemes = SchemeConfig::all_schemes();
    
    println!("【对比方案】");
    for (i, scheme) in schemes.iter().enumerate() {
        println!("  {}. {}: {}", i + 1, scheme.name, scheme.description);
    }
    println!();

    // 数据点分布（与实验1保持一致）
    let chain_lengths: Vec<u64> = vec![
        100, 200, 300, 400, 500, 750, 1000, 1500, 2000, 2500,
        3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000,
        12000, 14000, 16000, 18000, 20000
    ];
    
    let max_chain_length = *chain_lengths.last().unwrap();
    let dataset_path = Path::new(DATASET_PATH);
    let key_path = Path::new(KEY_PATH);

    if !dataset_path.exists() {
        println!("❌ 数据集不存在: {}", dataset_path.display());
        panic!("Dataset not found");
    }
    if !key_path.exists() {
        println!("❌ 公钥不存在: {}", key_path.display());
        panic!("Key not found");
    }

    println!("【加载公钥】");
    let pk = load_public_key(key_path).expect("加载公钥失败");
    
    println!("【加载数据集】");
    let raw_objs: BTreeMap<Height, Vec<Object<u32>>> = 
        load_raw_obj_from_file(dataset_path).expect("加载数据集失败");
    println!("  总区块数: {}", raw_objs.len());
    println!("  测试点数: {}", chain_lengths.len());
    println!("  验证迭代次数: {}", VERIFY_ITERATIONS);

    let param = make_test_param();

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("experiment_chain");
    let mut chain = SimChain::create(&chain_path, param.clone()).expect("创建链失败");

    let mut results: Vec<ChainLengthResult> = Vec::new();
    let mut prev_hash = Digest::default();
    let mut current_length = 0u64;
    let mut length_idx = 0;

    println!("\n【增量构建并测量】");
    
    for (blk_height, objs) in raw_objs.iter() {
        let (block_head, _mmr_pos, _mmr_root, _duration) = build_block_with_mmr(
            *blk_height,
            prev_hash,
            objs.clone(),
            &mut chain,
            &param,
            &pk,
        ).expect("构建区块失败");

        prev_hash = block_head.to_digest();
        current_length += 1;

        if current_length % 1000 == 0 {
            print!("\r  构建进度: {}/{} ({:.1}%)", 
                current_length, max_chain_length, 
                current_length as f64 / max_chain_length as f64 * 100.0);
            std::io::stdout().flush().ok();
        }

        if length_idx < chain_lengths.len() && current_length == chain_lengths[length_idx] {
            println!("\n  ━━━ 链长 {} 达成，测量验证时间 ━━━", current_length);
            
            let test_height = Height((current_length / 2) as u32);
            let log2_n = (current_length as f64).log2();

            // 测量基准时间
            let base_times = MeasuredBaseTimes {
                single_hash: measure_single_hash_time(VERIFY_ITERATIONS),
                header_hash_scattered: measure_header_hash_scattered_time(VERIFY_ITERATIONS),
                header_hash_unified: measure_header_hash_unified_time(VERIFY_ITERATIONS),
                ads_root_expand: measure_ads_root_expand_time(VERIFY_ITERATIONS),
            };

            // 测量MMR验证时间
            match measure_mmr_verify_time(&chain, test_height, VERIFY_ITERATIONS) {
                Ok((mmr_stats, mmr_items)) => {
                    // 测量两层式验证时间
                    match measure_two_layer_verify_time(&chain, test_height, VERIFY_ITERATIONS) {
                        Ok(two_layer_breakdown) => {
                            // 先计算HeaderChain的总时间（用于计算加速比）
                            let header_chain = SchemeConfig::header_chain();
                            let header_chain_result = calculate_scheme_verify_times(
                                &header_chain,
                                current_length,
                                test_height.0 as u64,
                                &base_times,
                                mmr_stats.mean_us,
                                &two_layer_breakdown,
                                1.0,
                            );
                            let header_chain_total = header_chain_result.total_verify_time_us;

                            // 计算各方案结果
                            let scheme_results: Vec<SchemeVerifyResult> = schemes
                                .iter()
                                .map(|s| calculate_scheme_verify_times(
                                    s,
                                    current_length,
                                    test_height.0 as u64,
                                    &base_times,
                                    mmr_stats.mean_us,
                                    &two_layer_breakdown,
                                    header_chain_total,
                                ))
                                .collect();

                            println!("    log₂(n): {:.2}, MMR项数: {}", log2_n, mmr_items);
                            println!("    Two-Layer: 第一层={:.2}μs, 第二层={:.3}μs, 总={:.2}μs",
                                two_layer_breakdown.layer1_mmr_verify.mean_us,
                                two_layer_breakdown.layer2_ads_root_expand.mean_us,
                                two_layer_breakdown.total.mean_us
                            );

                            results.push(ChainLengthResult {
                                chain_length: current_length,
                                log2_n,
                                test_block_height: test_height.0,
                                actual_mmr_proof_items: mmr_items,
                                schemes: scheme_results,
                                two_layer_breakdown,
                                measured_base_times: base_times,
                                mmr_verify_stats: mmr_stats,
                            });
                        }
                        Err(e) => println!("  ❌ 两层式验证测量失败: {}", e),
                    }
                }
                Err(e) => println!("  ❌ MMR验证测量失败: {}", e),
            }

            length_idx += 1;
        }

        if length_idx >= chain_lengths.len() {
            break;
        }
    }

    // 计算汇总
    let summary = calculate_summary(&results, &schemes);

    // 构建输出
    let output = ExperimentOutput {
        metadata: ExperimentMetadata {
            experiment_name: "experiment2_verify_time_comparison".to_string(),
            description: "验证时间多方案对比实验（含两层式验证时间分解）".to_string(),
            timestamp: get_timestamp(),
            dataset_path: DATASET_PATH.to_string(),
            key_path: KEY_PATH.to_string(),
            chain_lengths,
            verify_iterations: VERIFY_ITERATIONS,
            hash_size: HASH_SIZE,
            scattered_block_header_size: SCATTERED_BLOCK_HEADER_SIZE,
            unified_block_header_size: UNIFIED_BLOCK_HEADER_SIZE,
            schemes,
        },
        results,
        summary,
    };

    // 保存JSON
    let json_output = serde_json::to_string_pretty(&output).expect("JSON序列化失败");
    let _ = fs::create_dir_all("output");
    fs::write("output/experiment2_results.json", &json_output).expect("写入失败");

    println!("\n\n【汇总统计】");
    println!("  各方案平均加速比（相对于HeaderChain）:");
    for (name, speedup) in &output.summary.avg_speedup_ratios {
        println!("    {}: {:.2}x", name, speedup);
    }
    
    println!("\n  Two-Layer额外开销分析:");
    println!("    平均第二层验证开销: {:.3} μs", output.summary.two_layer_overhead_analysis.avg_layer2_overhead_us);
    println!("    第二层占总时间比例: {:.2}%", output.summary.two_layer_overhead_analysis.avg_layer2_overhead_percent);
    println!("    相对MMR-Scattered增加: {:.2}%", output.summary.two_layer_overhead_analysis.overhead_vs_mmr_scattered_percent);

    println!("\n【结果已保存】");
    println!("  output/experiment2_results.json");
    println!("\n✓ 实验完成");
}