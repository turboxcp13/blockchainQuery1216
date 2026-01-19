//! 【实验2】链级区块头认证时间对比实验
//!
//! ## 实验目标
//! 展示 MMR 验证时间随链长对数增长，而区块头链验证时间线性增长
//!
//! ## 实验设计
//! - 链长 n = [100, 500, 1000, 2000, 5000, 10000, 15000, 20000]
//! - 使用以太坊数据集 (eth.dat)
//! - 测试区块位置：链中间 (n/2)
//! - 验证时间：多次迭代取平均值
//!
//! ## 运行命令
//! ```bash
//! # 方案A: 使用已有数据库（快速）
//! cargo test --test experiment2_verify_time --release -- experiment2_use_existing_db --nocapture
//!
//! # 方案B: 增量构建（完整实验）
//! cargo test --test experiment2_verify_time --release -- experiment2_incremental_build --nocapture
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

/// 验证迭代次数（用于取平均值）
const VERIFY_ITERATIONS: usize = 100;

/// 模拟单个区块头哈希验证时间（微秒）
/// 实际中每个区块头需要计算哈希并与前一个区块头比对
const HEADER_VERIFY_TIME_US: u64 = 1;

// ============================================================================
// 实验结果数据结构
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentResult {
    /// 链长（区块数量）
    chain_length: u64,
    /// 测试区块高度
    test_block_height: u32,
    
    // === MMR 验证时间 ===
    /// MMR 证明验证时间（微秒）- 平均值
    mmr_verify_time_us: f64,
    /// MMR 证明验证时间（微秒）- 最小值
    mmr_verify_time_min_us: u64,
    /// MMR 证明验证时间（微秒）- 最大值
    mmr_verify_time_max_us: u64,
    /// MMR 证明验证时间（微秒）- 标准差
    mmr_verify_time_std_us: f64,
    
    // === 区块头链验证时间 ===
    /// 区块头链验证时间（微秒）- 模拟值
    header_chain_verify_time_us: u64,
    /// 需要验证的区块头数量
    headers_to_verify_count: u64,
    
    // === 对比指标 ===
    /// 理论值 log2(n)
    log2_n: f64,
    /// 加速比（区块头链验证时间 / MMR验证时间）
    speedup_ratio: f64,
    /// MMR验证时间 vs log2(n) 的比值
    mmr_time_vs_log2: f64,
    
    // === MMR 证明信息 ===
    /// MMR 证明项数量
    mmr_proof_items_count: usize,
    /// MMR 证明大小（字节）
    mmr_proof_size_bytes: usize,
    
    // === 额外信息 ===
    /// 验证迭代次数
    verify_iterations: usize,
    /// 证明生成时间（微秒）
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
    verify_iterations: usize,
    header_verify_time_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentOutput {
    metadata: ExperimentMetadata,
    results: Vec<ExperimentResult>,
    summary: ExperimentSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExperimentSummary {
    /// 最小加速比
    min_speedup_ratio: f64,
    /// 最大加速比
    max_speedup_ratio: f64,
    /// 平均加速比
    avg_speedup_ratio: f64,
    /// MMR验证时间范围（微秒）
    mmr_verify_time_range_us: (f64, f64),
    /// 区块头链验证时间范围（微秒）
    header_verify_time_range_us: (u64, u64),
    /// 总实验数量
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

fn digest_to_hex(digest: &Digest) -> String {
    hex::encode(digest.as_bytes())
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

/// 计算区块头链验证时间（模拟）
/// 假设每个区块头需要验证哈希，从目标区块到链尾
fn calculate_header_chain_verify_time(chain_length: u64, target_block_height: u64) -> u64 {
    let headers_to_verify = chain_length - target_block_height + 1;
    headers_to_verify * HEADER_VERIFY_TIME_US
}

fn calculate_summary(results: &[ExperimentResult]) -> ExperimentSummary {
    if results.is_empty() {
        return ExperimentSummary {
            min_speedup_ratio: 0.0,
            max_speedup_ratio: 0.0,
            avg_speedup_ratio: 0.0,
            mmr_verify_time_range_us: (0.0, 0.0),
            header_verify_time_range_us: (0, 0),
            total_experiments: 0,
        };
    }

    let speedup_ratios: Vec<f64> = results.iter().map(|r| r.speedup_ratio).collect();
    let mmr_times: Vec<f64> = results.iter().map(|r| r.mmr_verify_time_us).collect();
    let header_times: Vec<u64> = results.iter().map(|r| r.header_chain_verify_time_us).collect();

    ExperimentSummary {
        min_speedup_ratio: speedup_ratios.iter().cloned().fold(f64::INFINITY, f64::min),
        max_speedup_ratio: speedup_ratios.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        avg_speedup_ratio: speedup_ratios.iter().sum::<f64>() / speedup_ratios.len() as f64,
        mmr_verify_time_range_us: (
            mmr_times.iter().cloned().fold(f64::INFINITY, f64::min),
            mmr_times.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        ),
        header_verify_time_range_us: (
            *header_times.iter().min().unwrap(),
            *header_times.iter().max().unwrap(),
        ),
        total_experiments: results.len(),
    }
}

// ============================================================================
// 核心测量函数
// ============================================================================

/// 测量验证时间
fn measure_verify_time(
    chain: &SimChain,
    chain_length: u64,
    test_block_height: Height,
) -> anyhow::Result<ExperimentResult> {
    println!("\n  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  链长: {}, 测试区块: {}", chain_length, test_block_height.0);
    println!("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // 生成证明
    println!("  [1/3] 生成证明...");
    let proof_gen_start = Instant::now();
    let proof = chain.gen_two_layer_proof(test_block_height, None)?;
    let proof_gen_time = proof_gen_start.elapsed();

    let mmr_proof_items_count = proof.mmr_proof.proof_items.len();
    let mmr_proof_size = mmr_proof_items_count * 32;

    // 获取验证所需的数据
    let mmr_root = chain.get_mmr_root();

    // 多次迭代测量MMR验证时间
    println!("  [2/3] 测量MMR验证时间 ({} 次迭代)...", VERIFY_ITERATIONS);
    let mut verify_times: Vec<u64> = Vec::with_capacity(VERIFY_ITERATIONS);

    for i in 0..VERIFY_ITERATIONS {
        let start = Instant::now();
        
        // 执行验证（只需要传 mmr_root）
        let _result = proof.verify(mmr_root)?;
        
        let elapsed = start.elapsed().as_micros() as u64;
        verify_times.push(elapsed);

        // 进度显示
        if (i + 1) % 20 == 0 {
            print!("\r       进度: {}/{}", i + 1, VERIFY_ITERATIONS);
            std::io::stdout().flush().ok();
        }
    }
    println!();

    // 计算统计值
    let mmr_verify_time_avg = verify_times.iter().sum::<u64>() as f64 / verify_times.len() as f64;
    let mmr_verify_time_min = *verify_times.iter().min().unwrap();
    let mmr_verify_time_max = *verify_times.iter().max().unwrap();
    let mmr_verify_time_std = calculate_std(&verify_times, mmr_verify_time_avg);

    // 计算区块头链验证时间（模拟）
    println!("  [3/3] 计算区块头链验证时间（模拟）...");
    let headers_to_verify = chain_length - test_block_height.0 as u64 + 1;
    let header_chain_verify_time = calculate_header_chain_verify_time(chain_length, test_block_height.0 as u64);

    // 计算对比指标
    let log2_n = (chain_length as f64).log2();
    let speedup_ratio = header_chain_verify_time as f64 / mmr_verify_time_avg;
    let mmr_time_vs_log2 = mmr_verify_time_avg / log2_n;

    // 输出结果
    println!("\n  【结果】");
    println!("    MMR验证时间:        {:>10.2} μs (±{:.2})", mmr_verify_time_avg, mmr_verify_time_std);
    println!("    MMR验证时间范围:    {:>10} ~ {} μs", mmr_verify_time_min, mmr_verify_time_max);
    println!("    区块头链验证时间:   {:>10} μs ({} headers × {} μs)", 
        header_chain_verify_time, headers_to_verify, HEADER_VERIFY_TIME_US);
    println!("    加速比:             {:>10.2}x", speedup_ratio);
    println!("    log₂(n):            {:>10.2}", log2_n);
    println!("    MMR证明项数:        {:>10}", mmr_proof_items_count);

    Ok(ExperimentResult {
        chain_length,
        test_block_height: test_block_height.0,
        mmr_verify_time_us: mmr_verify_time_avg,
        mmr_verify_time_min_us: mmr_verify_time_min,
        mmr_verify_time_max_us: mmr_verify_time_max,
        mmr_verify_time_std_us: mmr_verify_time_std,
        header_chain_verify_time_us: header_chain_verify_time,
        headers_to_verify_count: headers_to_verify,
        log2_n,
        speedup_ratio,
        mmr_time_vs_log2,
        mmr_proof_items_count,
        mmr_proof_size_bytes: mmr_proof_size,
        verify_iterations: VERIFY_ITERATIONS,
        proof_gen_time_us: proof_gen_time.as_micros() as u64,
    })
}

// ============================================================================
// 【方案A】使用已有数据库 - 快速测试
// ============================================================================

#[test]
fn experiment2_use_existing_db() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║     【实验2-方案A】链级区块头认证时间对比（使用已有数据库）                ║");
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
    println!("  验证迭代次数: {}", VERIFY_ITERATIONS);
    println!();

    // 测试多个区块位置
    let test_positions = vec![
        Height(1),
        Height((chain_length / 4) as u32),
        Height((chain_length / 2) as u32),
        Height((chain_length * 3 / 4) as u32),
        Height((chain_length - 1) as u32),
    ];

    println!("【测量不同位置的验证时间】");
    let mut results: Vec<ExperimentResult> = Vec::new();

    for test_height in test_positions {
        if test_height.0 == 0 || test_height.0 as u64 > chain_length {
            continue;
        }
        match measure_verify_time(&chain, chain_length, test_height) {
            Ok(result) => results.push(result),
            Err(e) => println!("  ❌ 测量失败: {}", e),
        }
    }

    // 输出结果表格
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║                           实验结果汇总                                    ║");
    println!("╚══════════════════════════════════════════════════════════════════════════╝");

    println!("\n【验证时间对比】");
    println!("┌──────────┬──────────────┬──────────────┬──────────────┬──────────┐");
    println!("│ 测试区块 │ MMR验证(μs)  │ 区块头链(μs) │ 加速比       │ 证明项数 │");
    println!("├──────────┼──────────────┼──────────────┼──────────────┼──────────┤");
    for r in &results {
        println!("│ {:>8} │ {:>12.2} │ {:>12} │ {:>11.1}x │ {:>8} │",
            r.test_block_height,
            r.mmr_verify_time_us,
            r.header_chain_verify_time_us,
            r.speedup_ratio,
            r.mmr_proof_items_count
        );
    }
    println!("└──────────┴──────────────┴──────────────┴──────────────┴──────────┘");

    // 保存结果
    let output = ExperimentOutput {
        metadata: ExperimentMetadata {
            experiment_name: "experiment2_existing_db".to_string(),
            description: "链级区块头认证时间对比 - 使用已有数据库".to_string(),
            timestamp: get_timestamp(),
            dataset_path: EXISTING_DB_PATH.to_string(),
            key_path: KEY_PATH.to_string(),
            chain_lengths: vec![chain_length],
            verify_iterations: VERIFY_ITERATIONS,
            header_verify_time_us: HEADER_VERIFY_TIME_US,
        },
        results: results.clone(),
        summary: calculate_summary(&results),
    };

    let json_output = serde_json::to_string_pretty(&output).expect("JSON序列化失败");
    let _ = fs::create_dir_all("output");
    fs::write("output/experiment2_existing_db_results.json", &json_output).expect("写入失败");

    println!("\n【结果已保存】");
    println!("  output/experiment2_existing_db_results.json");
    println!("\n✓ 完成");
}

// ============================================================================
// 【方案B】增量构建 - 完整实验
// ============================================================================

#[test]
fn experiment2_incremental_build() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║     【实验2-方案B】链级区块头认证时间对比（增量构建）                      ║");
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
    println!("  验证迭代次数: {}", VERIFY_ITERATIONS);

    let param = make_test_param();

    // 创建临时目录，只构建一次
    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("incremental_chain");
    let mut chain = SimChain::create(&chain_path, param.clone()).expect("创建链失败");

    let mut results: Vec<ExperimentResult> = Vec::new();
    let mut prev_hash = Digest::default();
    let mut current_length = 0u64;
    let mut length_idx = 0;

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
            println!("\n");
            
            let test_height = Height((current_length / 2) as u32);

            match measure_verify_time(&chain, current_length, test_height) {
                Ok(result) => results.push(result),
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

    println!("\n【表1】链级区块头认证时间对比");
    println!("┌──────────┬──────────┬──────────────┬──────────────┬──────────────┬──────────┐");
    println!("│ 链长(n)  │ log₂(n)  │ MMR验证(μs)  │ 区块头链(μs) │ 加速比       │ 证明项数 │");
    println!("├──────────┼──────────┼──────────────┼──────────────┼──────────────┼──────────┤");
    for r in &results {
        println!("│ {:>8} │ {:>8.2} │ {:>12.2} │ {:>12} │ {:>11.1}x │ {:>8} │",
            r.chain_length,
            r.log2_n,
            r.mmr_verify_time_us,
            r.header_chain_verify_time_us,
            r.speedup_ratio,
            r.mmr_proof_items_count
        );
    }
    println!("└──────────┴──────────┴──────────────┴──────────────┴──────────────┴──────────┘");

    println!("\n【表2】MMR验证时间详细统计");
    println!("┌──────────┬──────────────┬──────────────┬──────────────┬──────────────┐");
    println!("│ 链长(n)  │ 平均(μs)     │ 最小(μs)     │ 最大(μs)     │ 标准差(μs)   │");
    println!("├──────────┼──────────────┼──────────────┼──────────────┼──────────────┤");
    for r in &results {
        println!("│ {:>8} │ {:>12.2} │ {:>12} │ {:>12} │ {:>12.2} │",
            r.chain_length,
            r.mmr_verify_time_us,
            r.mmr_verify_time_min_us,
            r.mmr_verify_time_max_us,
            r.mmr_verify_time_std_us
        );
    }
    println!("└──────────┴──────────────┴──────────────┴──────────────┴──────────────┘");

    // 汇总统计
    let summary = calculate_summary(&results);
    println!("\n【汇总统计】");
    println!("  加速比范围: {:.1}x ~ {:.1}x (平均 {:.1}x)",
        summary.min_speedup_ratio,
        summary.max_speedup_ratio,
        summary.avg_speedup_ratio);
    println!("  MMR验证时间范围: {:.2} ~ {:.2} μs",
        summary.mmr_verify_time_range_us.0,
        summary.mmr_verify_time_range_us.1);

    // 保存结果
    let output = ExperimentOutput {
        metadata: ExperimentMetadata {
            experiment_name: "experiment2_incremental_build".to_string(),
            description: "链级区块头认证时间对比 - 增量构建".to_string(),
            timestamp: get_timestamp(),
            dataset_path: DATASET_PATH.to_string(),
            key_path: KEY_PATH.to_string(),
            chain_lengths,
            verify_iterations: VERIFY_ITERATIONS,
            header_verify_time_us: HEADER_VERIFY_TIME_US,
        },
        results,
        summary,
    };

    let json_output = serde_json::to_string_pretty(&output).expect("JSON序列化失败");
    let _ = fs::create_dir_all("output");
    fs::write("output/experiment2_incremental_results.json", &json_output).expect("写入失败");

    println!("\n【结果已保存】");
    println!("  output/experiment2_incremental_results.json");
    println!("\n✓ 实验完成");
}