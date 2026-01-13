//! 【创新点2】SimChain MMR 集成测试
//!
//! 测试 MMR 与 SimChain 的集成功能
//!
//! ## 运行测试
//! ```bash
//! # 运行所有集成测试
//! cargo test --test simchain_mmr_integration_test
//!
//! # 运行特定测试
//! cargo test --test simchain_mmr_integration_test test_chain_create_with_mmr
//!
//! # 显示测试输出
//! cargo test --test simchain_mmr_integration_test -- --nocapture
//! ```

use std::path::Path;
use tempfile::tempdir;
use vchain_plus::chain::block::Height;
use vchain_plus::chain::Parameter;
use vchain_plus::digest::{Digest, Digestible};
use vchain_plus::SimChain;

// === 辅助函数 ===

/// 模拟哈希函数
fn mock_hash(data: &[u8]) -> Digest {
    data.to_digest()
}

/// 创建测试用参数
fn make_test_param() -> Parameter {
    Parameter {
        id_tree_fanout: 4,
        bplus_tree_fanout: 4,
        num_dim: 2,
        max_id_num: std::num::NonZeroU16::new(1000).unwrap(),
        time_win_sizes: vec![10, 20],
    }
}

// === 测试用例 ===

/// 测试1：创建带 MMR 的新链
#[test]
fn test_chain_create_with_mmr() {
    println!("\n=== 测试1：创建带 MMR 的新链 ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");

    // 创建新链
    let chain = SimChain::create(&chain_path, make_test_param())
        .expect("创建链失败");

    println!("链创建成功: {:?}", chain_path);

    // 验证 MMR 初始状态
    assert_eq!(chain.get_mmr_size(), 0, "新链 MMR 大小应为 0");
    assert_eq!(chain.get_mmr_block_count(), 0, "新链区块计数应为 0");
    assert_eq!(chain.get_mmr_root(), Digest::default(), "新链 MMR 根应为默认值");

    println!("MMR 初始状态:");
    println!("  - mmr_size: {}", chain.get_mmr_size());
    println!("  - block_count: {}", chain.get_mmr_block_count());
    println!("  - mmr_root: {:?}", chain.get_mmr_root());

    // 验证 MMR 元数据
    let meta = chain.get_mmr_meta();
    assert_eq!(meta.mmr_size, 0);
    assert_eq!(meta.block_count, 0);

    println!("\n✓ 测试1通过：创建带 MMR 的新链成功\n");
}

/// 测试2：打开已存在的链并恢复 MMR 状态
#[test]
fn test_chain_open_with_mmr() {
    println!("\n=== 测试2：打开已存在的链并恢复 MMR 状态 ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");

    // 创建链并插入一些数据
    let expected_mmr_root;
    let expected_mmr_size;
    let expected_block_count;
    {
        let mut chain = SimChain::create(&chain_path, make_test_param())
            .expect("创建链失败");

        // 插入几个 BlockADSRoot
        for i in 0..5 {
            let block_ads_root = mock_hash(format!("block_{}", i).as_bytes());
            chain.push_to_mmr(block_ads_root).expect("push_to_mmr 失败");
        }

        expected_mmr_root = chain.get_mmr_root();
        expected_mmr_size = chain.get_mmr_size();
        expected_block_count = chain.get_mmr_block_count();

        println!("插入 5 个区块后的 MMR 状态:");
        println!("  - mmr_size: {}", expected_mmr_size);
        println!("  - block_count: {}", expected_block_count);
        println!("  - mmr_root: {:?}...", &expected_mmr_root.as_bytes()[..4]);
    }
    // chain 在此处 drop，关闭数据库

    // 重新打开链
    println!("\n重新打开链...");
    let chain = SimChain::open(&chain_path).expect("打开链失败");

    // 验证 MMR 状态恢复
    assert_eq!(chain.get_mmr_root(), expected_mmr_root, "MMR 根应恢复");
    assert_eq!(chain.get_mmr_size(), expected_mmr_size, "MMR 大小应恢复");
    assert_eq!(chain.get_mmr_block_count(), expected_block_count, "区块计数应恢复");

    println!("恢复后的 MMR 状态:");
    println!("  - mmr_size: {}", chain.get_mmr_size());
    println!("  - block_count: {}", chain.get_mmr_block_count());
    println!("  - mmr_root: {:?}...", &chain.get_mmr_root().as_bytes()[..4]);

    println!("\n✓ 测试2通过：打开链并恢复 MMR 状态成功\n");
}

/// 测试3：push_to_mmr 基本功能
#[test]
fn test_push_to_mmr() {
    println!("\n=== 测试3：push_to_mmr 基本功能 ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");

    let mut chain = SimChain::create(&chain_path, make_test_param())
        .expect("创建链失败");

    println!("插入 BlockADSRoot 到 MMR:");

    // 插入第一个
    let root1 = mock_hash(b"block_1");
    let (pos1, mmr_root1) = chain.push_to_mmr(root1).expect("push_to_mmr 失败");
    
    println!("  Block 1: pos={}, mmr_size={}", pos1, chain.get_mmr_size());
    assert_eq!(pos1, 0, "第一个位置应为 0");
    assert_eq!(chain.get_mmr_block_count(), 1);

    // 插入第二个
    let root2 = mock_hash(b"block_2");
    let (pos2, mmr_root2) = chain.push_to_mmr(root2).expect("push_to_mmr 失败");
    
    println!("  Block 2: pos={}, mmr_size={}", pos2, chain.get_mmr_size());
    assert_eq!(pos2, 1, "第二个位置应为 1");
    assert_eq!(chain.get_mmr_block_count(), 2);
    assert_ne!(mmr_root1, mmr_root2, "MMR 根应该变化");

    // 插入第三个
    let root3 = mock_hash(b"block_3");
    let (pos3, mmr_root3) = chain.push_to_mmr(root3).expect("push_to_mmr 失败");
    
    println!("  Block 3: pos={}, mmr_size={}", pos3, chain.get_mmr_size());
    assert_eq!(pos3, 3, "第三个位置应为 3（MMR 特性）");
    assert_eq!(chain.get_mmr_block_count(), 3);

    // 验证最终状态
    println!("\n最终 MMR 状态:");
    println!("  - mmr_size: {}", chain.get_mmr_size());
    println!("  - block_count: {}", chain.get_mmr_block_count());
    println!("  - mmr_root: {:?}...", &mmr_root3.as_bytes()[..4]);

    println!("\n✓ 测试3通过：push_to_mmr 基本功能正确\n");
}

/// 测试4：gen_mmr_proof 功能
#[test]
fn test_gen_mmr_proof() {
    println!("\n=== 测试4：gen_mmr_proof 功能 ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");

    let mut chain = SimChain::create(&chain_path, make_test_param())
        .expect("创建链失败");

    // 插入多个区块
    let mut roots = Vec::new();
    let mut positions = Vec::new();

    for i in 0..10 {
        let root = mock_hash(format!("block_{}", i).as_bytes());
        let (pos, _) = chain.push_to_mmr(root).expect("push_to_mmr 失败");
        roots.push(root);
        positions.push(pos);
    }

    println!("插入 10 个区块，位置: {:?}", positions);

    // 生成单个位置的证明
    println!("\n生成单个位置证明:");
    for (i, pos) in positions.iter().enumerate() {
        let proof = chain.gen_mmr_proof(vec![*pos]).expect("gen_mmr_proof 失败");
        
        // 验证证明
        let is_valid = proof.verify(chain.get_mmr_root(), vec![(*pos, roots[i])])
            .expect("verify 失败");
        assert!(is_valid, "位置 {} 的证明验证失败", pos);
        
        println!("  ✓ 位置 {} 证明验证通过", pos);
    }

    // 生成多个位置的批量证明
    println!("\n生成批量证明:");
    let batch_positions = vec![positions[0], positions[4], positions[9]];
    let batch_proof = chain.gen_mmr_proof(batch_positions.clone()).expect("gen_mmr_proof 失败");
    
    let batch_leaves: Vec<(u64, Digest)> = batch_positions.iter()
        .enumerate()
        .map(|(idx, pos)| {
            let original_idx = if idx == 0 { 0 } else if idx == 1 { 4 } else { 9 };
            (*pos, roots[original_idx])
        })
        .collect();
    
    let is_valid = batch_proof.verify(chain.get_mmr_root(), batch_leaves)
        .expect("verify 失败");
    assert!(is_valid, "批量证明验证失败");
    println!("  ✓ 批量证明验证通过");

    println!("\n✓ 测试4通过：gen_mmr_proof 功能正确\n");
}

/// 测试5：get_mmr_position_by_height 功能
#[test]
fn test_get_mmr_position_by_height() {
    println!("\n=== 测试5：get_mmr_position_by_height 功能 ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");

    let mut chain = SimChain::create(&chain_path, make_test_param())
        .expect("创建链失败");

    // 插入一些区块
    for i in 0..5 {
        let root = mock_hash(format!("block_{}", i).as_bytes());
        chain.push_to_mmr(root).expect("push_to_mmr 失败");
    }

    println!("测试高度到 MMR 位置的映射:");

    // 测试有效高度
    let test_cases = vec![
        (Height(1), Some(0)),
        (Height(2), Some(1)),
        (Height(3), Some(3)),
        (Height(4), Some(4)),
        (Height(5), Some(7)),
    ];

    for (height, expected_pos) in &test_cases {
        let pos = chain.get_mmr_position_by_height(*height);
        assert_eq!(pos, *expected_pos, "Height {:?} 的位置应为 {:?}", height, expected_pos);
        println!("  Height({}) -> pos {:?} ✓", height.0, pos);
    }

    // 测试无效高度
    println!("\n测试无效高度:");
    assert_eq!(chain.get_mmr_position_by_height(Height(0)), None);
    println!("  Height(0) -> None ✓");
    assert_eq!(chain.get_mmr_position_by_height(Height(6)), None);
    println!("  Height(6) -> None ✓");
    assert_eq!(chain.get_mmr_position_by_height(Height(100)), None);
    println!("  Height(100) -> None ✓");

    println!("\n✓ 测试5通过：get_mmr_position_by_height 功能正确\n");
}

/// 测试6：verify_block_in_mmr 功能
#[test]
fn test_verify_block_in_mmr() {
    println!("\n=== 测试6：verify_block_in_mmr 功能 ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");

    let mut chain = SimChain::create(&chain_path, make_test_param())
        .expect("创建链失败");

    // 插入一些区块
    let mut roots = Vec::new();
    for i in 0..5 {
        let root = mock_hash(format!("block_{}", i).as_bytes());
        chain.push_to_mmr(root).expect("push_to_mmr 失败");
        roots.push(root);
    }

    // 验证正确的区块
    println!("验证正确的区块:");
    for (i, root) in roots.iter().enumerate() {
        let height = Height((i + 1) as u32);
        let is_valid = chain.verify_block_in_mmr(height, *root)
            .expect("verify_block_in_mmr 失败");
        assert!(is_valid, "Block {} 验证应通过", i + 1);
        println!("  ✓ Block {} 验证通过", i + 1);
    }

    // 验证错误的区块
    println!("\n验证错误的区块:");
    let wrong_root = mock_hash(b"wrong_block");
    let is_valid = chain.verify_block_in_mmr(Height(1), wrong_root)
        .expect("verify_block_in_mmr 失败");
    assert!(!is_valid, "错误的区块验证应失败");
    println!("  ✓ 错误区块被正确检测");

    // 验证无效高度
    println!("\n验证无效高度:");
    let result = chain.verify_block_in_mmr(Height(0), roots[0]);
    assert!(result.is_err(), "Height(0) 应返回错误");
    println!("  ✓ Height(0) 正确返回错误");

    let result = chain.verify_block_in_mmr(Height(100), roots[0]);
    assert!(result.is_err(), "Height(100) 应返回错误");
    println!("  ✓ Height(100) 正确返回错误");

    println!("\n✓ 测试6通过：verify_block_in_mmr 功能正确\n");
}

/// 测试7：get_proof_context 功能
#[test]
fn test_get_proof_context() {
    println!("\n=== 测试7：get_proof_context 功能 ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");

    let mut chain = SimChain::create(&chain_path, make_test_param())
        .expect("创建链失败");

    // 插入一些区块
    for i in 0..5 {
        let root = mock_hash(format!("block_{}", i).as_bytes());
        chain.push_to_mmr(root).expect("push_to_mmr 失败");
    }

    // 获取证明上下文
    let ctx = chain.get_proof_context();

    println!("证明上下文:");
    println!("  - mmr_root: {:?}...", &ctx.mmr_root.as_bytes()[..4]);
    println!("  - mmr_size: {}", ctx.mmr_size);
    println!("  - block_count: {}", ctx.block_count);

    // 验证内容正确
    assert_eq!(ctx.mmr_root, chain.get_mmr_root());
    assert_eq!(ctx.mmr_size, chain.get_mmr_size());
    assert_eq!(ctx.block_count, chain.get_mmr_block_count());

    // 测试上下文功能
    assert!(ctx.is_valid_height(Height(1)));
    assert!(ctx.is_valid_height(Height(5)));
    assert!(!ctx.is_valid_height(Height(0)));
    assert!(!ctx.is_valid_height(Height(6)));

    println!("\n✓ 测试7通过：get_proof_context 功能正确\n");
}

/// 测试8：大量区块的 MMR 性能
#[test]
fn test_mmr_large_scale() {
    println!("\n=== 测试8：大量区块的 MMR 性能 ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");

    let mut chain = SimChain::create(&chain_path, make_test_param())
        .expect("创建链失败");

    let num_blocks = 1000;

    // 计时插入
    let start = std::time::Instant::now();
    for i in 0..num_blocks {
        let root = mock_hash(format!("block_{}", i).as_bytes());
        chain.push_to_mmr(root).expect("push_to_mmr 失败");
    }
    let insert_time = start.elapsed();

    println!("插入 {} 个区块:", num_blocks);
    println!("  - 总耗时: {:?}", insert_time);
    println!("  - 平均每个: {:?}", insert_time / num_blocks);
    println!("  - MMR size: {}", chain.get_mmr_size());

    // 计时生成证明
    let start = std::time::Instant::now();
    let positions: Vec<u64> = (0..100).map(|i| {
        chain.get_mmr_position_by_height(Height((i * 10 + 1) as u32)).unwrap()
    }).collect();
    
    for pos in &positions {
        let _proof = chain.gen_mmr_proof(vec![*pos]).expect("gen_mmr_proof 失败");
    }
    let proof_time = start.elapsed();

    println!("\n生成 100 个证明:");
    println!("  - 总耗时: {:?}", proof_time);
    println!("  - 平均每个: {:?}", proof_time / 100);

    // 验证最后一个区块
    let last_root = mock_hash(format!("block_{}", num_blocks - 1).as_bytes());
    let is_valid = chain.verify_block_in_mmr(Height(num_blocks as u32), last_root)
        .expect("verify 失败");
    assert!(is_valid);

    println!("\n✓ 测试8通过：大量区块 MMR 性能测试完成\n");
}