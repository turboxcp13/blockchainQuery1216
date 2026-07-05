//! 【实验1】链级证明大小对比实验 - 多方案对比
//!
//! ## 实验目标
//! 对比四种方案的证明大小，展示两层式方案的优势
//!
//! ## 对比方案
//! - HeaderChain: 区块头链同步 + 分散索引根 (最原始方案)
//! - Merkle: Merkle树 + 分散索引根 (常见优化方案)
//! - MMR-Scattered: MMR + 分散索引根 (仅链级优化)
//! - Two-Layer: MMR + 一体化BlockADSRoot (本文两层式方案)
//!
//! ## 块头结构对比
//! - 分散索引根块头(164B): height(4) + prev_hash(32) + id_set_root(32) + id_tree_root(32) + multi_ads_hash(32) + obj_root(32)
//! - 一体化块头(100B): height(4) + prev_hash(32) + ads_root(32) + obj_root(32)
//!
//! ## 运行命令
//! ```
//! cargo test --test experiment1_proof_size --release -- --nocapture
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
use vchain_plus::digest::{Digest, Digestible};
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

/// 单个哈希/摘要大小（字节）
const HASH_SIZE: usize = 32;

/// 分散索引根数量（id_set_root, id_tree_root, multi_ads_hash）
const SCATTERED_ROOTS_COUNT: usize = 3;

/// 分散索引根块头大小（字节）
/// 结构: height(4) + prev_hash(32) + id_set_root(32) + id_tree_root(32) + multi_ads_hash(32) + obj_root(32) = 164B
const SCATTERED_BLOCK_HEADER_SIZE: usize = 4 + 32 + 32 + 32 + 32 + 32; // 164B

/// 一体化块头大小（字节）
/// 结构: height(4) + prev_hash(32) + ads_root(32) + obj_root(32) = 100B
const UNIFIED_BLOCK_HEADER_SIZE: usize = 4 + 32 + 32 + 32; // 100B

/// BlockADSComponents大小（字节）
/// 用于展开验证一体化BlockADSRoot: id_set_root(32) + id_tree_root(32) + multi_ads_hash(32) = 96B
const BLOCK_ADS_COMPONENTS_SIZE: usize = SCATTERED_ROOTS_COUNT * HASH_SIZE; // 96B

// ============================================================================
// 方案定义
// ============================================================================

/// 链级证明类型
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
enum ChainProofType {
    /// 区块头链同步（线性）
    HeaderChain,
    /// Merkle树证明（对数）
    Merkle,
    /// MMR证明（对数）
    MMR,
}

/// 块级承诺类型
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
enum BlockCommitmentType {
    /// 分散索引根（块头164B，含3个独立索引根）
    Scattered,
    /// 一体化BlockADSRoot（块头100B，验证时需Components 96B）
    Unified,
}

/// 方案配置
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SchemeConfig {
    /// 方案名称
    name: String,
    /// 链级证明类型
    chain_proof_type: ChainProofType,
    /// 块级承诺类型
    block_commitment_type: BlockCommitmentType,
    /// 方案描述
    description: String,
    /// 块头大小（字节）
    block_header_size: usize,
    /// 是否为两层式方案
    is_two_layer: bool,
}

impl SchemeConfig {
    fn header_chain() -> Self {
        Self {
            name: "HeaderChain".to_string(),
            chain_proof_type: ChainProofType::HeaderChain,
            block_commitment_type: BlockCommitmentType::Scattered,
            description: "区块头链同步 + 分散索引根（最原始方案）".to_string(),
            block_header_size: SCATTERED_BLOCK_HEADER_SIZE, // 164B
            is_two_layer: false,
        }
    }

    fn merkle() -> Self {
        Self {
            name: "Merkle".to_string(),
            chain_proof_type: ChainProofType::Merkle,
            block_commitment_type: BlockCommitmentType::Scattered,
            description: "Merkle树 + 分散索引根（常见优化方案）".to_string(),
            block_header_size: SCATTERED_BLOCK_HEADER_SIZE, // 164B
            is_two_layer: false,
        }
    }

    fn mmr_scattered() -> Self {
        Self {
            name: "MMR-Scattered".to_string(),
            chain_proof_type: ChainProofType::MMR,
            block_commitment_type: BlockCommitmentType::Scattered,
            description: "MMR + 分散索引根（仅链级优化）".to_string(),
            block_header_size: SCATTERED_BLOCK_HEADER_SIZE, // 164B
            is_two_layer: false,
        }
    }

    fn two_layer() -> Self {
        Self {
            name: "Two-Layer".to_string(),
            chain_proof_type: ChainProofType::MMR,
            block_commitment_type: BlockCommitmentType::Unified,
            description: "MMR + 一体化BlockADSRoot（本文两层式方案）".to_string(),
            block_header_size: UNIFIED_BLOCK_HEADER_SIZE, // 100B
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

/// 单个方案在特定链长下的结果
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SchemeResult {
    /// 方案名称
    scheme_name: String,
    /// 链级证明大小（字节）
    chain_proof_size_bytes: usize,
    /// 块级信息大小（字节）- 验证时需要传输的块级数据
    block_info_size_bytes: usize,
    /// 总证明大小（字节）
    total_proof_size_bytes: usize,
    /// 相对于HeaderChain的压缩比
    compression_ratio_vs_header_chain: f64,
}

/// 两层式证明大小分解
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TwoLayerProofBreakdown {
    /// 第一层：MMR证明大小（字节）
    layer1_mmr_proof_bytes: usize,
    /// 第二层：BlockADSComponents大小（字节）
    layer2_ads_components_bytes: usize,
    /// 总大小（字节）
    total_bytes: usize,
    /// 相对于MMR-Scattered节省的字节数
    saved_vs_mmr_scattered_bytes: i64,
    /// 相对于MMR-Scattered节省的百分比
    saved_vs_mmr_scattered_percent: f64,
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
    /// 实际MMR证明项数量（从实验获取）
    actual_mmr_proof_items: usize,
    /// 各方案结果
    schemes: Vec<SchemeResult>,
    /// 两层式证明大小分解
    two_layer_breakdown: TwoLayerProofBreakdown,
    /// 构建时间（毫秒）
    build_time_ms: u64,
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
    hash_size: usize,
    scattered_block_header_size: usize,
    unified_block_header_size: usize,
    block_ads_components_size: usize,
    schemes: Vec<SchemeConfig>,
}

/// 实验汇总
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentSummary {
    /// 各方案的平均压缩比（相对于HeaderChain）
    avg_compression_ratios: Vec<(String, f64)>,
    /// 最大链长时各方案的证明大小
    max_chain_proof_sizes: Vec<(String, usize)>,
    /// Two-Layer相对于各方案的平均改进
    two_layer_improvement_vs_others: Vec<(String, f64)>,
    /// Two-Layer节省分析
    two_layer_savings_analysis: TwoLayerSavingsAnalysis,
    /// 总测试点数
    total_data_points: usize,
}

/// Two-Layer节省分析
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TwoLayerSavingsAnalysis {
    /// 相对于MMR-Scattered平均节省的字节数
    avg_saved_vs_mmr_scattered_bytes: f64,
    /// 相对于MMR-Scattered平均节省的百分比
    avg_saved_vs_mmr_scattered_percent: f64,
    /// 块头大小节省（164B → 100B）
    block_header_saved_bytes: usize,
    /// 块级信息节省（164B → 96B）
    block_info_saved_bytes: usize,
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
        enable_bloom: false,
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

/// 计算链级证明大小
fn calculate_chain_proof_size(
    scheme: &SchemeConfig,
    chain_length: u64,
    test_block_height: u64,
    actual_mmr_items: usize,
) -> usize {
    match scheme.chain_proof_type {
        ChainProofType::HeaderChain => {
            // 区块头链同步：需要同步从目标区块到链尾的所有区块头
            let headers_to_sync = chain_length - test_block_height + 1;
            (headers_to_sync as usize) * scheme.block_header_size
        }
        ChainProofType::Merkle => {
            // Merkle树证明：log₂(n) 个哈希节点
            let tree_height = (chain_length as f64).log2().ceil() as usize;
            tree_height * HASH_SIZE
        }
        ChainProofType::MMR => {
            // MMR证明：使用实际测量的证明项数量
            actual_mmr_items * HASH_SIZE
        }
    }
}

/// 计算块级信息大小（验证时需要传输的数据）
fn calculate_block_info_size(scheme: &SchemeConfig) -> usize {
    match scheme.chain_proof_type {
        ChainProofType::HeaderChain => {
            // 区块头链同步：块头已包含索引根，无需额外块级信息
            0
        }
        ChainProofType::Merkle | ChainProofType::MMR => {
            // Merkle树/MMR证明：需要额外传输块级信息用于验证
            match scheme.block_commitment_type {
                BlockCommitmentType::Scattered => {
                    // 分散方案：需要传输完整块头（用于计算块头哈希验证）
                    scheme.block_header_size // 164B
                }
                BlockCommitmentType::Unified => {
                    // 一体化方案：需要传输Components（用于展开BlockADSRoot验证）
                    BLOCK_ADS_COMPONENTS_SIZE // 96B
                }
            }
        }
    }
}

/// 计算单个方案的结果
fn calculate_scheme_result(
    scheme: &SchemeConfig,
    chain_length: u64,
    test_block_height: u64,
    actual_mmr_items: usize,
    header_chain_total: usize,
) -> SchemeResult {
    let chain_proof_size = calculate_chain_proof_size(
        scheme,
        chain_length,
        test_block_height,
        actual_mmr_items,
    );
    let block_info_size = calculate_block_info_size(scheme);
    let total_proof_size = chain_proof_size + block_info_size;
    
    let compression_ratio = if total_proof_size > 0 {
        header_chain_total as f64 / total_proof_size as f64
    } else {
        1.0
    };

    SchemeResult {
        scheme_name: scheme.name.clone(),
        chain_proof_size_bytes: chain_proof_size,
        block_info_size_bytes: block_info_size,
        total_proof_size_bytes: total_proof_size,
        compression_ratio_vs_header_chain: compression_ratio,
    }
}

/// 计算两层式证明大小分解
fn calculate_two_layer_breakdown(
    actual_mmr_items: usize,
    mmr_scattered_total: usize,
) -> TwoLayerProofBreakdown {
    let layer1_size = actual_mmr_items * HASH_SIZE;
    let layer2_size = BLOCK_ADS_COMPONENTS_SIZE;
    let total = layer1_size + layer2_size;
    
    let saved_bytes = mmr_scattered_total as i64 - total as i64;
    let saved_percent = if mmr_scattered_total > 0 {
        saved_bytes as f64 / mmr_scattered_total as f64 * 100.0
    } else {
        0.0
    };
    
    TwoLayerProofBreakdown {
        layer1_mmr_proof_bytes: layer1_size,
        layer2_ads_components_bytes: layer2_size,
        total_bytes: total,
        saved_vs_mmr_scattered_bytes: saved_bytes,
        saved_vs_mmr_scattered_percent: saved_percent,
    }
}

/// 计算实验汇总
fn calculate_summary(results: &[ChainLengthResult], schemes: &[SchemeConfig]) -> ExperimentSummary {
    if results.is_empty() {
        return ExperimentSummary {
            avg_compression_ratios: vec![],
            max_chain_proof_sizes: vec![],
            two_layer_improvement_vs_others: vec![],
            two_layer_savings_analysis: TwoLayerSavingsAnalysis {
                avg_saved_vs_mmr_scattered_bytes: 0.0,
                avg_saved_vs_mmr_scattered_percent: 0.0,
                block_header_saved_bytes: 0,
                block_info_saved_bytes: 0,
            },
            total_data_points: 0,
        };
    }

    // 计算各方案的平均压缩比
    let mut avg_compression_ratios = Vec::new();
    for scheme in schemes {
        let ratios: Vec<f64> = results
            .iter()
            .flat_map(|r| r.schemes.iter())
            .filter(|s| s.scheme_name == scheme.name)
            .map(|s| s.compression_ratio_vs_header_chain)
            .collect();
        
        if !ratios.is_empty() {
            let avg = ratios.iter().sum::<f64>() / ratios.len() as f64;
            avg_compression_ratios.push((scheme.name.clone(), avg));
        }
    }

    // 获取最大链长时各方案的证明大小
    let max_chain_result = results.last().unwrap();
    let max_chain_proof_sizes: Vec<(String, usize)> = max_chain_result
        .schemes
        .iter()
        .map(|s| (s.scheme_name.clone(), s.total_proof_size_bytes))
        .collect();

    // 计算Two-Layer相对于各方案的平均改进
    let mut two_layer_improvement_vs_others = Vec::new();
    let two_layer_sizes: Vec<usize> = results
        .iter()
        .flat_map(|r| r.schemes.iter())
        .filter(|s| s.scheme_name == "Two-Layer")
        .map(|s| s.total_proof_size_bytes)
        .collect();

    for scheme in schemes {
        if scheme.name == "Two-Layer" {
            continue;
        }
        let other_sizes: Vec<usize> = results
            .iter()
            .flat_map(|r| r.schemes.iter())
            .filter(|s| s.scheme_name == scheme.name)
            .map(|s| s.total_proof_size_bytes)
            .collect();

        if other_sizes.len() == two_layer_sizes.len() && !other_sizes.is_empty() {
            let improvements: Vec<f64> = other_sizes
                .iter()
                .zip(two_layer_sizes.iter())
                .map(|(o, t)| *o as f64 / *t as f64)
                .collect();
            let avg_improvement = improvements.iter().sum::<f64>() / improvements.len() as f64;
            two_layer_improvement_vs_others.push((scheme.name.clone(), avg_improvement));
        }
    }

    // Two-Layer节省分析
    let saved_bytes: Vec<i64> = results
        .iter()
        .map(|r| r.two_layer_breakdown.saved_vs_mmr_scattered_bytes)
        .collect();
    let saved_percents: Vec<f64> = results
        .iter()
        .map(|r| r.two_layer_breakdown.saved_vs_mmr_scattered_percent)
        .collect();

    let avg_saved_bytes = if !saved_bytes.is_empty() {
        saved_bytes.iter().sum::<i64>() as f64 / saved_bytes.len() as f64
    } else {
        0.0
    };

    let avg_saved_percent = if !saved_percents.is_empty() {
        saved_percents.iter().sum::<f64>() / saved_percents.len() as f64
    } else {
        0.0
    };

    ExperimentSummary {
        avg_compression_ratios,
        max_chain_proof_sizes,
        two_layer_improvement_vs_others,
        two_layer_savings_analysis: TwoLayerSavingsAnalysis {
            avg_saved_vs_mmr_scattered_bytes: avg_saved_bytes,
            avg_saved_vs_mmr_scattered_percent: avg_saved_percent,
            block_header_saved_bytes: SCATTERED_BLOCK_HEADER_SIZE - UNIFIED_BLOCK_HEADER_SIZE, // 64B
            block_info_saved_bytes: SCATTERED_BLOCK_HEADER_SIZE - BLOCK_ADS_COMPONENTS_SIZE, // 68B
        },
        total_data_points: results.len(),
    }
}

/// 从实际链中测量MMR证明项数量
fn measure_actual_mmr_proof_items(
    chain: &SimChain,
    test_block_height: Height,
) -> anyhow::Result<usize> {
    let proof = chain.gen_two_layer_proof(test_block_height, None)?;
    Ok(proof.mmr_proof.proof_items.len())
}

// ============================================================================
// 实验主函数
// ============================================================================

#[test]
fn experiment1_proof_size() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════════════╗");
    println!("║              【实验1】链级证明大小对比实验 - 多方案对比                            ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════╝");
    println!();

    let schemes = SchemeConfig::all_schemes();
    
    println!("【对比方案】");
    for (i, scheme) in schemes.iter().enumerate() {
        println!("  {}. {} (块头{}B): {}", i + 1, scheme.name, scheme.block_header_size, scheme.description);
    }
    println!();

    // 数据点分布
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

    let param = make_test_param();

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("experiment_chain");
    let mut chain = SimChain::create(&chain_path, param.clone()).expect("创建链失败");

    let mut results: Vec<ChainLengthResult> = Vec::new();
    let mut prev_hash = Digest::default();
    let mut current_length = 0u64;
    let mut length_idx = 0;

    let build_start = Instant::now();

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
            println!("\n  ━━━ 链长 {} 达成，测量证明大小 ━━━", current_length);
            
            let test_height = Height((current_length / 2) as u32);
            let build_time = build_start.elapsed();
            let log2_n = (current_length as f64).log2();

            match measure_actual_mmr_proof_items(&chain, test_height) {
                Ok(actual_mmr_items) => {
                    // 先计算HeaderChain的总大小（用于计算压缩比）
                    let header_chain = SchemeConfig::header_chain();
                    let header_chain_result = calculate_scheme_result(
                        &header_chain,
                        current_length,
                        test_height.0 as u64,
                        actual_mmr_items,
                        1,
                    );
                    let header_chain_total = header_chain_result.total_proof_size_bytes;

                    // 计算MMR-Scattered的总大小（用于Two-Layer对比）
                    let mmr_scattered = SchemeConfig::mmr_scattered();
                    let mmr_scattered_result = calculate_scheme_result(
                        &mmr_scattered,
                        current_length,
                        test_height.0 as u64,
                        actual_mmr_items,
                        header_chain_total,
                    );
                    let mmr_scattered_total = mmr_scattered_result.total_proof_size_bytes;

                    // 计算各方案结果
                    let scheme_results: Vec<SchemeResult> = schemes
                        .iter()
                        .map(|s| calculate_scheme_result(
                            s,
                            current_length,
                            test_height.0 as u64,
                            actual_mmr_items,
                            header_chain_total,
                        ))
                        .collect();

                    // 计算两层式分解
                    let two_layer_breakdown = calculate_two_layer_breakdown(
                        actual_mmr_items,
                        mmr_scattered_total,
                    );

                    println!("    log₂(n): {:.2}, MMR项数: {}", log2_n, actual_mmr_items);
                    println!("    Two-Layer: 第一层={}B, 第二层={}B, 总={}B, 节省={}B ({:.1}%)",
                        two_layer_breakdown.layer1_mmr_proof_bytes,
                        two_layer_breakdown.layer2_ads_components_bytes,
                        two_layer_breakdown.total_bytes,
                        two_layer_breakdown.saved_vs_mmr_scattered_bytes,
                        two_layer_breakdown.saved_vs_mmr_scattered_percent
                    );

                    results.push(ChainLengthResult {
                        chain_length: current_length,
                        log2_n,
                        test_block_height: test_height.0,
                        actual_mmr_proof_items: actual_mmr_items,
                        schemes: scheme_results,
                        two_layer_breakdown,
                        build_time_ms: build_time.as_millis() as u64,
                    });
                }
                Err(e) => println!("  ❌ 测量失败: {}", e),
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
            experiment_name: "experiment1_proof_size_comparison".to_string(),
            description: "链级证明大小多方案对比实验（含两层式证明大小分解）".to_string(),
            timestamp: get_timestamp(),
            dataset_path: DATASET_PATH.to_string(),
            key_path: KEY_PATH.to_string(),
            chain_lengths,
            hash_size: HASH_SIZE,
            scattered_block_header_size: SCATTERED_BLOCK_HEADER_SIZE,
            unified_block_header_size: UNIFIED_BLOCK_HEADER_SIZE,
            block_ads_components_size: BLOCK_ADS_COMPONENTS_SIZE,
            schemes,
        },
        results,
        summary,
    };

    // 保存JSON
    let json_output = serde_json::to_string_pretty(&output).expect("JSON序列化失败");
    let _ = fs::create_dir_all("output");
    fs::write("output/experiment1_results.json", &json_output).expect("写入失败");

    println!("\n\n【汇总统计】");
    println!("  各方案平均压缩比（相对于HeaderChain）:");
    for (name, ratio) in &output.summary.avg_compression_ratios {
        println!("    {}: {:.2}x", name, ratio);
    }
    
    println!("\n  Two-Layer相对于各方案的平均改进:");
    for (name, improvement) in &output.summary.two_layer_improvement_vs_others {
        println!("    vs {}: {:.2}x", name, improvement);
    }

    println!("\n  Two-Layer节省分析:");
    println!("    相对MMR-Scattered平均节省: {:.1}B ({:.2}%)", 
        output.summary.two_layer_savings_analysis.avg_saved_vs_mmr_scattered_bytes,
        output.summary.two_layer_savings_analysis.avg_saved_vs_mmr_scattered_percent);
    println!("    块头大小节省: {}B (164B → 100B)", 
        output.summary.two_layer_savings_analysis.block_header_saved_bytes);
    println!("    块级信息节省: {}B (164B → 96B)", 
        output.summary.two_layer_savings_analysis.block_info_saved_bytes);

    println!("\n【结果已保存】");
    println!("  output/experiment1_results.json");
    println!("\n✓ 实验完成");
}