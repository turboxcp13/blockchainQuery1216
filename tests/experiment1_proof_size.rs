//! 【实验1】链级证明大小对比实验
//!
//! ## 实验目标
//! 展示 MMR 证明大小随链长对数增长，而区块头链同步线性增长
//!
//! ## 运行命令
//! ```bash
//! # 方案A: 使用已有数据库（快速，仅测试最大链长）
//! cargo test --test experiment1_proof_size experiment1_use_existing_db --release -- --nocapture
//!
//! # 方案B: 增量构建（完整实验，获取所有链长数据）
//! cargo test --test experiment1_proof_size experiment1_incremental_build --release -- --nocapture
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

/// 已构建的数据库路径
const EXISTING_DB_PATH: &str = "output/db_eth";

/// 区块头大小（字节）
const BLOCK_HEADER_SIZE: usize = 100;

// ============================================================================
// 实验结果数据结构
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentResult {
    chain_length: u64,
    test_block_height: u32,
    mmr_proof_path_size_bytes: usize,
    mmr_proof_items_count: usize,
    two_layer_proof_size_bytes: usize,
    header_chain_size_bytes: usize,
    headers_to_sync_count: u64,
    log2_n: f64,
    mmr_path_vs_log2: f64,
    compression_ratio_path: f64,
    compression_ratio_two_layer: f64,
    mmr_size: u64,
    mmr_root_hex: String,
    block_ads_root_hex: String,
    build_time_ms: u64,
    proof_gen_time_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentMetadata {
    experiment_name: String,
    description: String,
    timestamp: u64,
    dataset_path: String,
    key_path: String,
    chain_lengths: Vec<u64>,
    block_header_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentOutput {
    metadata: ExperimentMetadata,
    results: Vec<ExperimentResult>,
    summary: ExperimentSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentSummary {
    min_compression_ratio_path: f64,
    max_compression_ratio_path: f64,
    avg_compression_ratio_path: f64,
    min_compression_ratio_two_layer: f64,
    max_compression_ratio_two_layer: f64,
    avg_compression_ratio_two_layer: f64,
    mmr_items_range: (usize, usize),
    total_experiments: usize,
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

fn calculate_header_chain_size(chain_length: u64, target_block_height: u64) -> usize {
    let headers_to_sync = chain_length - target_block_height + 1;
    (headers_to_sync as usize) * BLOCK_HEADER_SIZE
}

fn digest_to_hex(digest: &Digest) -> String {
    hex::encode(digest.as_bytes())
}

fn calculate_summary(results: &[ExperimentResult]) -> ExperimentSummary {
    if results.is_empty() {
        return ExperimentSummary {
            min_compression_ratio_path: 0.0,
            max_compression_ratio_path: 0.0,
            avg_compression_ratio_path: 0.0,
            min_compression_ratio_two_layer: 0.0,
            max_compression_ratio_two_layer: 0.0,
            avg_compression_ratio_two_layer: 0.0,
            mmr_items_range: (0, 0),
            total_experiments: 0,
        };
    }
    
    let compression_ratios_path: Vec<f64> = results.iter().map(|r| r.compression_ratio_path).collect();
    let compression_ratios_two_layer: Vec<f64> = results.iter().map(|r| r.compression_ratio_two_layer).collect();
    let mmr_items: Vec<usize> = results.iter().map(|r| r.mmr_proof_items_count).collect();

    ExperimentSummary {
        min_compression_ratio_path: compression_ratios_path.iter().cloned().fold(f64::INFINITY, f64::min),
        max_compression_ratio_path: compression_ratios_path.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        avg_compression_ratio_path: compression_ratios_path.iter().sum::<f64>() / compression_ratios_path.len() as f64,
        min_compression_ratio_two_layer: compression_ratios_two_layer.iter().cloned().fold(f64::INFINITY, f64::min),
        max_compression_ratio_two_layer: compression_ratios_two_layer.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        avg_compression_ratio_two_layer: compression_ratios_two_layer.iter().sum::<f64>() / compression_ratios_two_layer.len() as f64,
        mmr_items_range: (*mmr_items.iter().min().unwrap(), *mmr_items.iter().max().unwrap()),
        total_experiments: results.len(),
    }
}

// ============================================================================
// 【方案A】使用已有数据库 - 快速测试
// ============================================================================

/// 从已有数据库测量证明大小
fn measure_proof_from_existing_chain(
    chain: &SimChain,
    chain_length: u64,
    test_block_height: Height,
) -> anyhow::Result<ExperimentResult> {
    println!("\n  测量区块 {} 的证明大小 (链长={})", test_block_height.0, chain_length);

    // 生成两层式证明
    let proof_gen_start = Instant::now();
    let proof = chain.gen_two_layer_proof(test_block_height, None)?;
    let proof_gen_time = proof_gen_start.elapsed();

    // 计算各种大小
    let mmr_proof_items_count = proof.mmr_proof.proof_items.len();
    let mmr_proof_path_size = mmr_proof_items_count * 32;

    let two_layer_proof_serialized = bincode::serialize(&proof)?;
    let two_layer_proof_size = two_layer_proof_serialized.len();

    let headers_to_sync = chain_length - test_block_height.0 as u64 + 1;
    let header_chain_size = calculate_header_chain_size(chain_length, test_block_height.0 as u64);

    let log2_n = (chain_length as f64).log2();
    let mmr_path_vs_log2 = mmr_proof_items_count as f64 / log2_n;
    let compression_ratio_path = header_chain_size as f64 / mmr_proof_path_size as f64;
    let compression_ratio_two_layer = header_chain_size as f64 / two_layer_proof_size as f64;

    let mmr_root = chain.get_mmr_root();
    let block_ads_root = proof.block_ads_root();

    println!("    MMR证明路径: {} bytes ({} items)", mmr_proof_path_size, mmr_proof_items_count);
    println!("    两层式证明:  {} bytes", two_layer_proof_size);
    println!("    区块头链:    {} bytes ({} headers)", header_chain_size, headers_to_sync);
    println!("    压缩比:      {:.1}x", compression_ratio_path);

    Ok(ExperimentResult {
        chain_length,
        test_block_height: test_block_height.0,
        mmr_proof_path_size_bytes: mmr_proof_path_size,
        mmr_proof_items_count,
        two_layer_proof_size_bytes: two_layer_proof_size,
        header_chain_size_bytes: header_chain_size,
        headers_to_sync_count: headers_to_sync,
        log2_n,
        mmr_path_vs_log2,
        compression_ratio_path,
        compression_ratio_two_layer,
        mmr_size: chain.get_mmr_size(),
        mmr_root_hex: digest_to_hex(&mmr_root),
        block_ads_root_hex: digest_to_hex(&block_ads_root),
        build_time_ms: 0,  // 使用已有数据库，无需构建
        proof_gen_time_us: proof_gen_time.as_micros() as u64,
    })
}

/// 【方案A】使用已构建的数据库进行实验（快速）
#[test]
fn experiment1_use_existing_db() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║     【实验1-方案A】使用已有数据库测试（快速）                              ║");
    println!("╚══════════════════════════════════════════════════════════════════════════╝");
    println!();

    let db_path = Path::new(EXISTING_DB_PATH);

    if !db_path.exists() {
        println!("❌ 数据库不存在: {}", db_path.display());
        println!("   请先运行 build_chain.exe 构建数据库");
        panic!("Database not found");
    }

    println!("【打开已有数据库】");
    println!("  路径: {}", db_path.display());
    
    let chain = SimChain::open(db_path).expect("打开数据库失败");
    
    let chain_length = chain.get_mmr_block_count();
    println!("  链长: {} 个区块", chain_length);
    println!("  MMR大小: {}", chain.get_mmr_size());
    println!();

    // 测试多个区块位置
    let test_positions = vec![
        Height(1),                              // 链头
        Height((chain_length / 4) as u32),      // 1/4 位置
        Height((chain_length / 2) as u32),      // 中间
        Height((chain_length * 3 / 4) as u32),  // 3/4 位置
        Height((chain_length - 1) as u32),      // 链尾附近
    ];

    println!("【测量不同位置的证明大小】");
    let mut results: Vec<ExperimentResult> = Vec::new();

    for test_height in test_positions {
        if test_height.0 == 0 || test_height.0 as u64 > chain_length {
            continue;
        }
        match measure_proof_from_existing_chain(&chain, chain_length, test_height) {
            Ok(result) => results.push(result),
            Err(e) => println!("  ❌ 测量失败: {}", e),
        }
    }

    // 保存结果
    let output = ExperimentOutput {
        metadata: ExperimentMetadata {
            experiment_name: "experiment1_existing_db".to_string(),
            description: "使用已有数据库测量证明大小".to_string(),
            timestamp: get_timestamp(),
            dataset_path: EXISTING_DB_PATH.to_string(),
            key_path: KEY_PATH.to_string(),
            chain_lengths: vec![chain_length],
            block_header_size: BLOCK_HEADER_SIZE,
        },
        results: results.clone(),
        summary: calculate_summary(&results),
    };

    let json_output = serde_json::to_string_pretty(&output).expect("JSON序列化失败");
    let _ = fs::create_dir_all("output");
    fs::write("output/experiment1_existing_db_results.json", &json_output).expect("写入失败");

    println!("\n【结果已保存】");
    println!("  output/experiment1_existing_db_results.json");
    println!("\n✓ 完成");
}

// ============================================================================
// 【方案B】增量构建 - 完整实验
// ============================================================================

/// 【方案B】增量构建，获取所有链长的数据
#[test]
fn experiment1_incremental_build() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║     【实验1-方案B】增量构建（完整实验）                                    ║");
    println!("╚══════════════════════════════════════════════════════════════════════════╝");
    println!();

    let chain_lengths: Vec<u64> = vec![100, 500, 1000, 2000, 5000, 10000, 15000, 20000];
    let dataset_path = Path::new(DATASET_PATH);
    let key_path = Path::new(KEY_PATH);

    // 检查文件
    if !dataset_path.exists() {
        println!("❌ 数据集不存在: {}", dataset_path.display());
        panic!("Dataset not found");
    }
    if !key_path.exists() {
        println!("❌ 公钥不存在: {}", key_path.display());
        panic!("Key not found");
    }

    // 加载公钥和数据集
    println!("【加载公钥】");
    let pk = load_public_key(key_path).expect("加载公钥失败");
    
    println!("【加载数据集】");
    let raw_objs: BTreeMap<Height, Vec<Object<u32>>> = 
        load_raw_obj_from_file(dataset_path).expect("加载数据集失败");
    println!("  总区块数: {}", raw_objs.len());

    let param = make_test_param();

    // 创建临时目录，只构建一次
    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("incremental_chain");
    let mut chain = SimChain::create(&chain_path, param.clone()).expect("创建链失败");

    let mut results: Vec<ExperimentResult> = Vec::new();
    let mut prev_hash = Digest::default();
    let mut current_length = 0u64;
    let mut length_idx = 0;

    let build_start = Instant::now();

    println!("\n【增量构建并测量】");
    
    for (blk_height, objs) in raw_objs.iter() {
        // 构建区块
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

        // 进度显示
        if current_length % 2000 == 0 {
            print!("\r  构建进度: {}/20000 ({:.1}%)", 
                current_length, current_length as f64 / 200.0);
            std::io::stdout().flush().ok();
        }

        // 检查是否达到目标链长
        if length_idx < chain_lengths.len() && current_length == chain_lengths[length_idx] {
            println!("\n\n  ━━━ 链长 {} 达成，测量证明 ━━━", current_length);
            
            let test_height = Height((current_length / 2) as u32);
            let build_time = build_start.elapsed();

            match measure_proof_from_existing_chain(&chain, current_length, test_height) {
                Ok(mut result) => {
                    result.build_time_ms = build_time.as_millis() as u64;
                    results.push(result);
                }
                Err(e) => println!("  ❌ 测量失败: {}", e),
            }

            length_idx += 1;
        }

        // 达到最大测试长度后退出
        if length_idx >= chain_lengths.len() {
            break;
        }
    }

    // 输出结果表格
    println!("\n\n╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║                           实验结果汇总                                    ║");
    println!("╚══════════════════════════════════════════════════════════════════════════╝");

    println!("\n【链级证明大小对比】");
    println!("┌──────────┬──────────┬──────────────┬──────────────┬──────────────┬──────────┐");
    println!("│ 链长(n)  │ log₂(n)  │ MMR路径大小  │ 两层式证明   │ 区块头链大小 │ 压缩比   │");
    println!("├──────────┼──────────┼──────────────┼──────────────┼──────────────┼──────────┤");
    for r in &results {
        println!("│ {:>8} │ {:>8.2} │ {:>8} B   │ {:>8} B   │ {:>9} B  │ {:>7.1}x │",
            r.chain_length,
            r.log2_n,
            r.mmr_proof_path_size_bytes,
            r.two_layer_proof_size_bytes,
            r.header_chain_size_bytes,
            r.compression_ratio_path
        );
    }
    println!("└──────────┴──────────┴──────────────┴──────────────┴──────────────┴──────────┘");

    // 保存结果
    let summary = calculate_summary(&results);
    let output = ExperimentOutput {
        metadata: ExperimentMetadata {
            experiment_name: "experiment1_incremental_build".to_string(),
            description: "增量构建 - 链级证明大小对比实验".to_string(),
            timestamp: get_timestamp(),
            dataset_path: DATASET_PATH.to_string(),
            key_path: KEY_PATH.to_string(),
            chain_lengths,
            block_header_size: BLOCK_HEADER_SIZE,
        },
        results,
        summary,
    };

    let json_output = serde_json::to_string_pretty(&output).expect("JSON序列化失败");
    let _ = fs::create_dir_all("output");
    fs::write("output/experiment1_incremental_results.json", &json_output).expect("写入失败");

    println!("\n【结果已保存】");
    println!("  output/experiment1_incremental_results.json");
    println!("\n✓ 实验完成");
}