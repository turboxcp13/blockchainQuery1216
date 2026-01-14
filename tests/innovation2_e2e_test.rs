//! 【创新点2】端到端完整流程测试
//!
//! 测试完整的构建 → 查询 → 验证流程
//!
//! ## 运行测试
//! ```bash
//! # 运行所有端到端测试
//! cargo test --test innovation2_e2e_test
//!
//! # 运行特定测试
//! cargo test --test innovation2_e2e_test test_full_workflow
//!
//! # 显示测试输出
//! cargo test --test innovation2_e2e_test -- --nocapture
//! ```

use std::collections::HashSet;
use std::num::NonZeroU16;
use tempfile::tempdir;
use vchain_plus::acc::AccPublicKey;
use vchain_plus::chain::block::build::build_block_with_mmr;
use vchain_plus::chain::block::Height;
use vchain_plus::chain::mmr::{ChainProofContext, IndexProof};
use vchain_plus::chain::object::Object;
use vchain_plus::chain::traits::ReadInterface;
use vchain_plus::chain::Parameter;
use vchain_plus::digest::{Digest, Digestible};
use vchain_plus::SimChain;

// === 辅助函数 ===

/// 创建测试用参数
fn make_test_param() -> Parameter {
    Parameter {
        id_tree_fanout: 4,
        bplus_tree_fanout: 4,
        num_dim: 2,
        max_id_num: NonZeroU16::new(1000).unwrap().get(),
        time_win_sizes: vec![10],
    }
}

/// 创建测试用对象
fn make_test_objects(height: Height, count: usize) -> Vec<Object<u32>> {
    (0..count)
        .map(|i| Object {
            blk_height: height,
            num_data: vec![(i * 10) as u32, (i * 20) as u32],
            keyword_data: HashSet::from([format!("keyword_{}", i)]),
        })
        .collect()
}

/// 创建累加器公钥（测试用）
fn make_test_pk() -> AccPublicKey {
    use vchain_plus::acc::{AccSecretKey, AccSecretKeyWithPowCache};
    use rand::thread_rng;
    let sk = AccSecretKey::rand(thread_rng());
    let sk_cache: AccSecretKeyWithPowCache = sk.into();
    AccPublicKey::gen_key(&sk_cache, 40) // q = 40
}

// === 端到端测试用例 ===

/// 测试1：完整工作流程
/// 构建区块 → 生成两层式证明 → 验证证明
#[test]
fn test_full_workflow() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           【创新点2】端到端测试：完整工作流程                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");
    let param = make_test_param();
    let pk = make_test_pk();

    // ============================================================
    // 阶段1：初始化链
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 阶段1：初始化链                                             │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let mut chain = SimChain::create(&chain_path, param.clone())
        .expect("创建链失败");

    println!("  ✓ 链创建成功");
    println!("  - 路径: {:?}", chain_path);
    println!("  - 初始 MMR size: {}", chain.get_mmr_size());
    println!("  - 初始 block_count: {}", chain.get_mmr_block_count());
    println!();

    // ============================================================
    // 阶段2：构建区块（带 MMR 集成）
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 阶段2：构建区块（带 MMR 集成）                               │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let num_blocks = 10;
    let mut prev_hash = Digest::default();
    let mut block_records: Vec<(Height, Digest, u64)> = Vec::new();

    println!("  构建 {} 个区块...", num_blocks);

    for i in 1..=num_blocks {
        let height = Height(i as u32);
        let objects = make_test_objects(height, 5);

        let (block_head, mmr_pos, mmr_root, time) = build_block_with_mmr(
            height,
            prev_hash,
            objects,
            &mut chain,
            &param,
            &pk,
        ).expect("build_block_with_mmr 失败");

        block_records.push((height, block_head.ads_root, mmr_pos));
        prev_hash = block_head.to_digest();

        println!("    Block {:2}: mmr_pos={:2}, mmr_size={:2}, time={:?}",
            i, mmr_pos, chain.get_mmr_size(), time);
    }

    println!();
    println!("  ✓ 区块构建完成");
    println!("  - 最终 MMR size: {}", chain.get_mmr_size());
    println!("  - 最终 block_count: {}", chain.get_mmr_block_count());
    println!("  - 最终 MMR root: {:?}...", &chain.get_mmr_root().as_bytes()[..4]);
    println!();

    // ============================================================
    // 阶段3：验证 MMR 包含性
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 阶段3：验证 MMR 包含性                                       │");
    println!("└─────────────────────────────────────────────────────────────┘");

    println!("  验证所有区块在 MMR 中...");

    for (height, ads_root, _pos) in &block_records {
        let is_valid = chain.verify_block_in_mmr(*height, *ads_root)
            .expect("verify_block_in_mmr 失败");
        assert!(is_valid, "Block {:?} 不在 MMR 中", height);
    }

    println!("  ✓ 所有 {} 个区块验证通过", num_blocks);
    println!();

    // ============================================================
    // 阶段4：生成两层式证明
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 阶段4：生成两层式证明                                        │");
    println!("└─────────────────────────────────────────────────────────────┘");

    // 选择几个区块生成证明
    let test_heights = vec![Height(1), Height(5), Height(10)];

    for height in &test_heights {
        println!("  Block {}:", height.0);

        // 生成基本两层式证明
        let proof = chain.gen_two_layer_proof(*height, None)
            .expect("gen_two_layer_proof 失败");

        println!("    - MMR position: {}", proof.mmr_position());
        println!("    - BlockADSRoot: {:?}...", &proof.block_ads_root().as_bytes()[..4]);

        // 验证证明
        let is_valid = chain.verify_two_layer_proof(&proof)
            .expect("verify_two_layer_proof 失败");
        assert!(is_valid);
        println!("    ✓ 两层式证明验证通过");
    }
    println!();

    // ============================================================
    // 阶段5：生成带索引证明的两层式证明
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 阶段5：生成带索引证明的两层式证明                            │");
    println!("└─────────────────────────────────────────────────────────────┘");

    // ID Tree 索引证明
    let proof_id = chain.gen_two_layer_proof_with_id_tree(Height(5))
        .expect("gen_two_layer_proof_with_id_tree 失败");
    let is_valid = chain.verify_two_layer_proof(&proof_id)
        .expect("verify 失败");
    assert!(is_valid);
    println!("  ✓ ID Tree 索引证明验证通过");

    println!();

    // ============================================================
    // 阶段6：模拟轻节点验证
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 阶段6：模拟轻节点验证                                        │");
    println!("└─────────────────────────────────────────────────────────────┘");

    // 轻节点只持有 MMR root（32 bytes）
    let light_node_mmr_root = chain.get_mmr_root();
    println!("  轻节点持有的 MMR root: {:?}...", &light_node_mmr_root.as_bytes()[..4]);

    // 轻节点请求验证 Block 7 的数据
    let target_height = Height(7);
    println!("  轻节点请求验证 Block {} 的数据", target_height.0);

    // 全节点生成两层式证明
    let proof = chain.gen_two_layer_proof(target_height, None)
        .expect("gen_two_layer_proof 失败");

    // 轻节点使用 MMR root 验证证明
    let is_valid = proof.verify(light_node_mmr_root)
        .expect("verify 失败");
    assert!(is_valid);

    println!("  ✓ 轻节点验证成功（仅使用 32 bytes MMR root）");
    println!();

    // ============================================================
    // 阶段7：详细验证结果
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 阶段7：详细验证结果                                          │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let result = chain.verify_two_layer_proof_detailed(&proof)
        .expect("verify_detailed 失败");

    println!("  详细验证结果:");
    println!("    - mmr_valid:    {}", result.mmr_valid);
    println!("    - block_valid:  {}", result.block_valid);
    println!("    - index_valid:  {:?}", result.index_valid);
    println!("    - is_valid:     {}", result.is_valid);
    println!("    - block_height: {:?}", result.block_height);

    assert!(result.is_valid);
    println!("  ✓ 详细验证通过");
    println!();

    // ============================================================
    // 完成
    // ============================================================
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    ✓ 端到端测试通过                          ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}

/// 测试2：数据持久化和恢复
#[test]
fn test_persistence_and_recovery() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           【创新点2】端到端测试：数据持久化和恢复             ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");
    let param = make_test_param();
    let pk = make_test_pk();

    // 记录期望的状态
    let expected_mmr_root;
    let expected_mmr_size;
    let expected_block_count;
    let block_ads_roots: Vec<Digest>;

    // ============================================================
    // 阶段1：首次运行 - 构建区块
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 阶段1：首次运行 - 构建区块                                   │");
    println!("└─────────────────────────────────────────────────────────────┘");

    {
        let mut chain = SimChain::create(&chain_path, param.clone())
            .expect("创建链失败");

        let mut roots = Vec::new();
        let mut prev_hash = Digest::default();

        for i in 1..=5 {
            let height = Height(i as u32);
            let objects = make_test_objects(height, 3);

            let (block_head, _mmr_pos, _mmr_root, _time) = build_block_with_mmr(
                height,
                prev_hash,
                objects,
                &mut chain,
                &param,
                &pk,
            ).expect("build_block_with_mmr 失败");

            roots.push(block_head.ads_root);
            prev_hash = block_head.to_digest();
            println!("  构建 Block {}", i);
        }

        expected_mmr_root = chain.get_mmr_root();
        expected_mmr_size = chain.get_mmr_size();
        expected_block_count = chain.get_mmr_block_count();
        block_ads_roots = roots;

        println!();
        println!("  首次运行状态:");
        println!("    - mmr_size: {}", expected_mmr_size);
        println!("    - block_count: {}", expected_block_count);
        println!("    - mmr_root: {:?}...", &expected_mmr_root.as_bytes()[..4]);
    }
    // chain 被 drop，数据库关闭
    println!("  ✓ 链已关闭");
    println!();

    // ============================================================
    // 阶段2：重新打开 - 验证恢复
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 阶段2：重新打开 - 验证恢复                                   │");
    println!("└─────────────────────────────────────────────────────────────┘");

    {
        let chain = SimChain::open(&chain_path).expect("打开链失败");

        // 验证 MMR 状态
        assert_eq!(chain.get_mmr_root(), expected_mmr_root);
        assert_eq!(chain.get_mmr_size(), expected_mmr_size);
        assert_eq!(chain.get_mmr_block_count(), expected_block_count);

        println!("  恢复后状态:");
        println!("    - mmr_size: {} (expected: {})", 
            chain.get_mmr_size(), expected_mmr_size);
        println!("    - block_count: {} (expected: {})", 
            chain.get_mmr_block_count(), expected_block_count);
        println!("    - mmr_root 匹配: {}", 
            chain.get_mmr_root() == expected_mmr_root);

        // 验证所有区块仍在 MMR 中
        println!();
        println!("  验证区块:");
        for (i, ads_root) in block_ads_roots.iter().enumerate() {
            let height = Height((i + 1) as u32);
            let is_valid = chain.verify_block_in_mmr(height, *ads_root)
                .expect("verify_block_in_mmr 失败");
            assert!(is_valid);
            println!("    ✓ Block {} 验证通过", i + 1);
        }

        // 验证两层式证明仍然有效
        println!();
        println!("  验证两层式证明:");
        for i in 1..=5 {
            let proof = chain.gen_two_layer_proof(Height(i as u32), None)
                .expect("gen_two_layer_proof 失败");
            let is_valid = chain.verify_two_layer_proof(&proof)
                .expect("verify 失败");
            assert!(is_valid);
            println!("    ✓ Block {} 两层式证明验证通过", i);
        }
    }
    println!();

    // ============================================================
    // 阶段3：继续构建 - 验证追加
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 阶段3：继续构建 - 验证追加                                   │");
    println!("└─────────────────────────────────────────────────────────────┘");

    {
        let mut chain = SimChain::open(&chain_path).expect("打开链失败");

        // 读取上一个区块的哈希
        let chain_ref = &chain as &SimChain;
        let last_block = chain_ref.read_block_head(Height(5)).expect("read 失败");
        let mut prev_hash = last_block.to_digest();

        // 继续构建区块
        for i in 6..=8 {
            let height = Height(i as u32);
            let objects = make_test_objects(height, 3);

            let (block_head, _mmr_pos, _mmr_root, _time) = build_block_with_mmr(
                height,
                prev_hash,
                objects,
                &mut chain,
                &param,
                &pk,
            ).expect("build_block_with_mmr 失败");

            prev_hash = block_head.to_digest();
            println!("  追加 Block {}", i);
        }

        assert_eq!(chain.get_mmr_block_count(), 8);
        println!();
        println!("  追加后状态:");
        println!("    - mmr_size: {}", chain.get_mmr_size());
        println!("    - block_count: {}", chain.get_mmr_block_count());

        // 验证所有 8 个区块
        println!();
        println!("  验证所有 8 个区块:");
        for i in 1..=8 {
            let proof = chain.gen_two_layer_proof(Height(i as u32), None)
                .expect("gen_two_layer_proof 失败");
            let is_valid = chain.verify_two_layer_proof(&proof)
                .expect("verify 失败");
            assert!(is_valid);
            println!("    ✓ Block {} 验证通过", i);
        }
    }
    println!();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              ✓ 数据持久化和恢复测试通过                       ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}

/// 测试3：轻节点模拟场景
#[test]
fn test_light_node_simulation() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           【创新点2】端到端测试：轻节点模拟场景               ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");
    let param = make_test_param();
    let pk = make_test_pk();

    // ============================================================
    // 全节点：构建区块
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 全节点：构建区块                                             │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let mut chain = SimChain::create(&chain_path, param.clone())
        .expect("创建链失败");

    let mut prev_hash = Digest::default();
    for i in 1..=20 {
        let height = Height(i as u32);
        let objects = make_test_objects(height, 5);

        let (block_head, _mmr_pos, _mmr_root, _time) = build_block_with_mmr(
            height,
            prev_hash,
            objects,
            &mut chain,
            &param,
            &pk,
        ).expect("build_block_with_mmr 失败");

        prev_hash = block_head.to_digest();
    }

    println!("  ✓ 全节点构建 20 个区块完成");
    println!("  - MMR size: {}", chain.get_mmr_size());
    println!("  - Block count: {}", chain.get_mmr_block_count());
    println!();

    // ============================================================
    // 轻节点：同步 MMR root
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 轻节点：同步 MMR root                                        │");
    println!("└─────────────────────────────────────────────────────────────┘");

    // 轻节点只需要存储 MMR root（32 bytes）
    let light_node_state = chain.get_mmr_root();
    let light_node_context = chain.get_proof_context();

    println!("  轻节点状态（仅 32 bytes）:");
    println!("    - MMR root: {:?}", light_node_state);
    println!("  轻节点上下文:");
    println!("    - block_count: {}", light_node_context.block_count);
    println!();

    // ============================================================
    // 轻节点：验证历史数据请求
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 轻节点：验证历史数据请求                                     │");
    println!("└─────────────────────────────────────────────────────────────┘");

    // 场景1：轻节点请求验证 Block 15 的数据
    println!("  场景1：验证 Block 15");
    {
        let target = Height(15);
        
        // 全节点生成证明
        let proof = chain.gen_two_layer_proof(target, None)
            .expect("gen_proof 失败");

        // 轻节点验证（只使用 MMR root）
        let is_valid = proof.verify(light_node_state).expect("verify 失败");
        assert!(is_valid);
        
        println!("    - 请求 Block: {}", target.0);
        println!("    - 证明大小: ~{} bytes", 
            std::mem::size_of_val(&proof));
        println!("    ✓ 验证通过");
    }

    // 场景2：轻节点批量验证多个区块
    println!();
    println!("  场景2：批量验证 Block 5, 10, 15, 20");
    {
        let targets = vec![Height(5), Height(10), Height(15), Height(20)];
        
        for target in &targets {
            let proof = chain.gen_two_layer_proof(*target, None)
                .expect("gen_proof 失败");
            let is_valid = proof.verify(light_node_state).expect("verify 失败");
            assert!(is_valid);
            println!("    ✓ Block {} 验证通过", target.0);
        }
    }

    // 场景3：检测伪造的区块数据
    println!();
    println!("  场景3：检测伪造的区块数据");
    {
        let target = Height(10);
        let proof = chain.gen_two_layer_proof(target, None)
            .expect("gen_proof 失败");

        // 使用错误的 MMR root 验证
        let fake_mmr_root = [0u8; 32].to_digest();
        let is_valid = proof.verify(fake_mmr_root).expect("verify 失败");
        assert!(!is_valid);
        println!("    ✓ 成功检测到伪造（错误的 MMR root）");
    }
    println!();

    // ============================================================
    // 统计信息
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 统计信息                                                     │");
    println!("└─────────────────────────────────────────────────────────────┘");

    println!("  轻节点存储需求:");
    println!("    - MMR root: 32 bytes");
    println!("    - 对比全节点 MMR: {} 个节点", chain.get_mmr_size());
    println!();
    println!("  验证效率:");
    println!("    - MMR 证明大小: O(log n)");
    println!("    - 对于 {} 个区块: ~{} 个哈希值", 
        chain.get_mmr_block_count(),
        (chain.get_mmr_block_count() as f64).log2().ceil() as u32);
    println!();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                ✓ 轻节点模拟场景测试通过                       ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}

/// 测试4：性能基准测试
#[test]
fn test_performance_benchmark() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           【创新点2】端到端测试：性能基准测试                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");
    let param = make_test_param();
    let pk = make_test_pk();

    let mut chain = SimChain::create(&chain_path, param.clone())
        .expect("创建链失败");

    // ============================================================
    // 区块构建性能
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 区块构建性能                                                 │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let num_blocks = 100;
    let mut prev_hash = Digest::default();

    let start = std::time::Instant::now();
    for i in 1..=num_blocks {
        let height = Height(i as u32);
        let objects = make_test_objects(height, 10);

        let (block_head, _mmr_pos, _mmr_root, _time) = build_block_with_mmr(
            height,
            prev_hash,
            objects,
            &mut chain,
            &param,
            &pk,
        ).expect("build_block_with_mmr 失败");

        prev_hash = block_head.to_digest();
    }
    let build_time = start.elapsed();

    println!("  构建 {} 个区块（每个 10 对象）:", num_blocks);
    println!("    - 总耗时: {:?}", build_time);
    println!("    - 平均每个区块: {:?}", build_time / num_blocks);
    println!("    - 吞吐量: {:.2} blocks/sec", 
        num_blocks as f64 / build_time.as_secs_f64());
    println!();

    // ============================================================
    // 证明生成性能
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 证明生成性能                                                 │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let num_proofs = 100;
    let heights: Vec<Height> = (1..=num_proofs).map(|i| Height(i as u32)).collect();

    let start = std::time::Instant::now();
    for height in &heights {
        let _proof = chain.gen_two_layer_proof(*height, None)
            .expect("gen_proof 失败");
    }
    let gen_time = start.elapsed();

    println!("  生成 {} 个两层式证明:", num_proofs);
    println!("    - 总耗时: {:?}", gen_time);
    println!("    - 平均每个: {:?}", gen_time / num_proofs);
    println!("    - 吞吐量: {:.2} proofs/sec", 
        num_proofs as f64 / gen_time.as_secs_f64());
    println!();

    // ============================================================
    // 证明验证性能
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 证明验证性能                                                 │");
    println!("└─────────────────────────────────────────────────────────────┘");

    // 预先生成证明
    let proofs: Vec<_> = heights.iter()
        .map(|h| chain.gen_two_layer_proof(*h, None).unwrap())
        .collect();

    let mmr_root = chain.get_mmr_root();

    let start = std::time::Instant::now();
    for proof in &proofs {
        let _is_valid = proof.verify(mmr_root).expect("verify 失败");
    }
    let verify_time = start.elapsed();

    println!("  验证 {} 个两层式证明:", num_proofs);
    println!("    - 总耗时: {:?}", verify_time);
    println!("    - 平均每个: {:?}", verify_time / num_proofs);
    println!("    - 吞吐量: {:.2} verifications/sec", 
        num_proofs as f64 / verify_time.as_secs_f64());
    println!();

    // ============================================================
    // MMR 操作性能
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ MMR 操作性能                                                 │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let num_lookups = 1000;
    
    let start = std::time::Instant::now();
    for i in 0..num_lookups {
        let height = Height((i % num_blocks + 1) as u32);
        let _pos = chain.get_mmr_position_by_height(height);
    }
    let lookup_time = start.elapsed();

    println!("  {} 次高度到 MMR 位置查询:", num_lookups);
    println!("    - 总耗时: {:?}", lookup_time);
    println!("    - 平均每次: {:?}", lookup_time / num_lookups);
    println!();

    // ============================================================
    // 总结
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 性能总结                                                     │");
    println!("└─────────────────────────────────────────────────────────────┘");

    println!("  最终链状态:");
    println!("    - 区块数: {}", chain.get_mmr_block_count());
    println!("    - MMR 节点数: {}", chain.get_mmr_size());
    println!("    - 每区块对象数: 10");
    println!();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                  ✓ 性能基准测试完成                           ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}

/// 测试5：错误处理和边界条件
#[test]
fn test_error_handling() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           【创新点2】端到端测试：错误处理和边界条件           ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");
    let param = make_test_param();
    let pk = make_test_pk();

    let mut chain = SimChain::create(&chain_path, param.clone())
        .expect("创建链失败");

    // 构建一些区块
    let mut prev_hash = Digest::default();
    for i in 1..=5 {
        let height = Height(i as u32);
        let objects = make_test_objects(height, 3);

        let (block_head, _mmr_pos, _mmr_root, _time) = build_block_with_mmr(
            height,
            prev_hash,
            objects,
            &mut chain,
            &param,
            &pk,
        ).expect("build_block_with_mmr 失败");

        prev_hash = block_head.to_digest();
    }

    println!("  准备：构建 5 个区块完成");
    println!();

    // ============================================================
    // 测试无效高度
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 测试无效高度                                                 │");
    println!("└─────────────────────────────────────────────────────────────┘");

    // Height(0)
    let result = chain.gen_two_layer_proof(Height(0), None);
    assert!(result.is_err());
    println!("  ✓ Height(0) 正确返回错误");

    // Height 超出范围
    let result = chain.gen_two_layer_proof(Height(100), None);
    assert!(result.is_err());
    println!("  ✓ Height(100) 正确返回错误");

    // verify_block_in_mmr 无效高度
    let result = chain.verify_block_in_mmr(Height(0), Digest::default());
    assert!(result.is_err());
    println!("  ✓ verify_block_in_mmr Height(0) 正确返回错误");

    println!();

    // ============================================================
    // 测试错误的 BlockADSRoot
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 测试错误的 BlockADSRoot                                      │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let fake_root = [0u8; 32].to_digest();
    let is_valid = chain.verify_block_in_mmr(Height(3), fake_root)
        .expect("verify 失败");
    assert!(!is_valid);
    println!("  ✓ 错误的 BlockADSRoot 被正确检测");

    println!();

    // ============================================================
    // 测试空链边界
    // ============================================================
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ 测试空链边界                                                 │");
    println!("└─────────────────────────────────────────────────────────────┘");

    let empty_chain_path = temp_dir.path().join("empty_chain");
    let empty_chain = SimChain::create(&empty_chain_path, param.clone())
        .expect("创建空链失败");

    assert_eq!(empty_chain.get_mmr_block_count(), 0);
    assert_eq!(empty_chain.get_mmr_size(), 0);
    
    // 空链的 MMR 位置查询
    assert_eq!(empty_chain.get_mmr_position_by_height(Height(1)), None);
    println!("  ✓ 空链处理正确");

    println!();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              ✓ 错误处理和边界条件测试通过                     ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}