//! 【创新点2】build_block_with_mmr 集成测试
//!
//! 测试带 MMR 集成的区块构建功能
//!
//! ## 运行测试
//! ```bash
//! # 运行所有集成测试
//! cargo test --test build_block_mmr_test
//!
//! # 运行特定测试
//! cargo test --test build_block_mmr_test test_build_single_block_with_mmr
//!
//! # 显示测试输出
//! cargo test --test build_block_mmr_test -- --nocapture
//! ```

use std::collections::HashSet;
use std::num::NonZeroU16;
use tempfile::tempdir;
use vchain_plus::acc::AccPublicKey;
use vchain_plus::chain::block::build::{build_block, build_block_with_mmr};
use vchain_plus::chain::block::Height;
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

// === 测试用例 ===

/// 测试1：构建单个区块（带 MMR）
#[test]
fn test_build_single_block_with_mmr() {
    println!("\n=== 测试1：构建单个区块（带 MMR）===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");
    let param = make_test_param();
    let pk = make_test_pk();

    let mut chain = SimChain::create(&chain_path, param.clone())
        .expect("创建链失败");

    // 准备测试对象
    let objects = make_test_objects(Height(1), 5);
    println!("准备 {} 个测试对象", objects.len());

    // 验证初始 MMR 状态
    assert_eq!(chain.get_mmr_block_count(), 0, "初始区块计数应为 0");

    // 构建区块（带 MMR）
    let (block_head, mmr_pos, mmr_root, time) = build_block_with_mmr(
        Height(1),
        Digest::default(),
        objects,
        &mut chain,
        &param,
        &pk,
    ).expect("build_block_with_mmr 失败");

    println!("\n区块构建结果:");
    println!("  - block_height: {:?}", block_head.blk_height);
    println!("  - ads_root: {:?}...", &block_head.ads_root.as_bytes()[..4]);
    println!("  - mmr_pos: {}", mmr_pos);
    println!("  - mmr_root: {:?}...", &mmr_root.as_bytes()[..4]);
    println!("  - build_time: {:?}", time);

    // 验证 MMR 状态更新
    assert_eq!(chain.get_mmr_block_count(), 1, "区块计数应为 1");
    assert_eq!(chain.get_mmr_root(), mmr_root, "MMR 根应匹配");
    assert_eq!(mmr_pos, 0, "第一个区块位置应为 0");

    // 验证区块在 MMR 中
    let is_valid = chain.verify_block_in_mmr(Height(1), block_head.ads_root)
        .expect("verify_block_in_mmr 失败");
    assert!(is_valid, "区块应在 MMR 中");

    println!("\n✓ 测试1通过：构建单个区块（带 MMR）成功\n");
}

/// 测试2：构建多个连续区块（带 MMR）
#[test]
fn test_build_multiple_blocks_with_mmr() {
    println!("\n=== 测试2：构建多个连续区块（带 MMR）===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");
    let param = make_test_param();
    let pk = make_test_pk();

    let mut chain = SimChain::create(&chain_path, param.clone())
        .expect("创建链失败");

    let num_blocks = 5;
    let mut prev_hash = Digest::default();
    let mut block_info: Vec<(Height, Digest, u64)> = Vec::new();

    println!("构建 {} 个连续区块:", num_blocks);

    for i in 1..=num_blocks {
        let height = Height(i as u32);
        let objects = make_test_objects(height, 3);

        let (block_head, mmr_pos, mmr_root, _time) = build_block_with_mmr(
            height,
            prev_hash,
            objects,
            &mut chain,
            &param,
            &pk,
        ).expect("build_block_with_mmr 失败");

        block_info.push((height, block_head.ads_root, mmr_pos));
        prev_hash = block_head.to_digest();

        println!("  Block {}: mmr_pos={}, mmr_size={}", 
            i, mmr_pos, chain.get_mmr_size());
    }

    // 验证 MMR 状态
    assert_eq!(chain.get_mmr_block_count(), num_blocks as u64);
    println!("\n最终 MMR 状态:");
    println!("  - mmr_size: {}", chain.get_mmr_size());
    println!("  - block_count: {}", chain.get_mmr_block_count());

    // 验证所有区块在 MMR 中
    println!("\n验证所有区块在 MMR 中:");
    for (height, ads_root, _pos) in &block_info {
        let is_valid = chain.verify_block_in_mmr(*height, *ads_root)
            .expect("verify_block_in_mmr 失败");
        assert!(is_valid, "Block {:?} 应在 MMR 中", height);
        println!("  ✓ Block {} 验证通过", height.0);
    }

    println!("\n✓ 测试2通过：构建多个连续区块（带 MMR）成功\n");
}

/// 测试3：对比 build_block 和 build_block_with_mmr
#[test]
fn test_compare_build_functions() {
    println!("\n=== 测试3：对比 build_block 和 build_block_with_mmr ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let param = make_test_param();
    let pk = make_test_pk();

    // 创建两条链
    let chain_path1 = temp_dir.path().join("chain1");
    let chain_path2 = temp_dir.path().join("chain2");

    let mut chain1 = SimChain::create(&chain_path1, param.clone())
        .expect("创建 chain1 失败");
    let mut chain2 = SimChain::create(&chain_path2, param.clone())
        .expect("创建 chain2 失败");

    // 使用相同的对象
    let objects1 = make_test_objects(Height(1), 5);
    let objects2 = objects1.clone();

    // 使用 build_block（原有函数）
    let (block_head1, _time1) = build_block(
        Height(1),
        Digest::default(),
        objects1,
        &mut chain1,
        &param,
        &pk,
    ).expect("build_block 失败");

    // 使用 build_block_with_mmr（带 MMR）
    let (block_head2, mmr_pos, mmr_root, _time2) = build_block_with_mmr(
        Height(1),
        Digest::default(),
        objects2,
        &mut chain2,
        &param,
        &pk,
    ).expect("build_block_with_mmr 失败");

    println!("build_block 结果:");
    println!("  - ads_root: {:?}...", &block_head1.ads_root.as_bytes()[..4]);
    println!("  - chain1 MMR block_count: {}", chain1.get_mmr_block_count());

    println!("\nbuild_block_with_mmr 结果:");
    println!("  - ads_root: {:?}...", &block_head2.ads_root.as_bytes()[..4]);
    println!("  - mmr_pos: {}", mmr_pos);
    println!("  - mmr_root: {:?}...", &mmr_root.as_bytes()[..4]);
    println!("  - chain2 MMR block_count: {}", chain2.get_mmr_block_count());

    // 验证 BlockHead 内容相同
    assert_eq!(block_head1.blk_height, block_head2.blk_height);
    assert_eq!(block_head1.prev_hash, block_head2.prev_hash);
    assert_eq!(block_head1.ads_root, block_head2.ads_root, "ads_root 应相同");
    assert_eq!(block_head1.obj_root_hash, block_head2.obj_root_hash);

    println!("\n✓ 两个函数生成的 BlockHead 内容相同");

    // 验证 MMR 差异
    assert_eq!(chain1.get_mmr_block_count(), 0, "chain1 不应有 MMR 区块");
    assert_eq!(chain2.get_mmr_block_count(), 1, "chain2 应有 1 个 MMR 区块");

    println!("✓ MMR 状态差异正确：build_block_with_mmr 更新了 MMR");

    println!("\n✓ 测试3通过：对比 build_block 和 build_block_with_mmr 成功\n");
}

/// 测试4：区块内容和 MMR 的一致性验证
#[test]
fn test_block_content_mmr_consistency() {
    println!("\n=== 测试4：区块内容和 MMR 的一致性验证 ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");
    let param = make_test_param();
    let pk = make_test_pk();

    let mut chain = SimChain::create(&chain_path, param.clone())
        .expect("创建链失败");

    // 构建区块
    let objects = make_test_objects(Height(1), 5);
    let (block_head, _mmr_pos, _mmr_root, _time) = build_block_with_mmr(
        Height(1),
        Digest::default(),
        objects,
        &mut chain,
        &param,
        &pk,
    ).expect("build_block_with_mmr 失败");

    // 从链中读取区块内容
    let chain_ref = &chain as &SimChain;
    let read_block_head = chain_ref.read_block_head(Height(1))
        .expect("read_block_head 失败");
    let read_block_content = chain_ref.read_block_content(Height(1))
        .expect("read_block_content 失败");

    println!("验证区块数据一致性:");

    // 验证 BlockHead
    assert_eq!(read_block_head.blk_height, block_head.blk_height);
    assert_eq!(read_block_head.ads_root, block_head.ads_root);
    println!("  ✓ BlockHead 一致");

    // 验证 BlockADSComponents
    let components = read_block_content.get_ads_components();
    let computed_root = components.compute_root();
    assert_eq!(computed_root, block_head.ads_root, "组件计算的根应与 BlockHead 一致");
    println!("  ✓ BlockADSComponents 一致");

    // 验证 MMR 中的 BlockADSRoot
    let is_valid = chain.verify_block_in_mmr(Height(1), block_head.ads_root)
        .expect("verify_block_in_mmr 失败");
    assert!(is_valid);
    println!("  ✓ MMR 中的 BlockADSRoot 一致");

    println!("\n✓ 测试4通过：区块内容和 MMR 的一致性验证成功\n");
}

/// 测试5：重启后的 MMR 持久化验证
#[test]
fn test_mmr_persistence_after_build() {
    println!("\n=== 测试5：重启后的 MMR 持久化验证 ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");
    let param = make_test_param();
    let pk = make_test_pk();

    // 构建区块并记录状态
    let expected_mmr_root;
    let expected_mmr_size;
    let expected_block_count;
    let block_ads_roots: Vec<Digest>;

    {
        let mut chain = SimChain::create(&chain_path, param.clone())
            .expect("创建链失败");

        let mut roots = Vec::new();
        let mut prev_hash = Digest::default();

        // 构建多个区块
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
        }

        expected_mmr_root = chain.get_mmr_root();
        expected_mmr_size = chain.get_mmr_size();
        expected_block_count = chain.get_mmr_block_count();
        block_ads_roots = roots;

        println!("构建完成后的 MMR 状态:");
        println!("  - mmr_size: {}", expected_mmr_size);
        println!("  - block_count: {}", expected_block_count);
        println!("  - mmr_root: {:?}...", &expected_mmr_root.as_bytes()[..4]);
    }
    // chain drop，关闭数据库

    // 重新打开链
    println!("\n重新打开链...");
    let chain = SimChain::open(&chain_path).expect("打开链失败");

    // 验证 MMR 状态恢复
    assert_eq!(chain.get_mmr_root(), expected_mmr_root);
    assert_eq!(chain.get_mmr_size(), expected_mmr_size);
    assert_eq!(chain.get_mmr_block_count(), expected_block_count);

    println!("恢复后的 MMR 状态:");
    println!("  - mmr_size: {}", chain.get_mmr_size());
    println!("  - block_count: {}", chain.get_mmr_block_count());
    println!("  - mmr_root: {:?}...", &chain.get_mmr_root().as_bytes()[..4]);

    // 验证所有区块仍在 MMR 中
    println!("\n验证所有区块仍在 MMR 中:");
    for (i, ads_root) in block_ads_roots.iter().enumerate() {
        let is_valid = chain.verify_block_in_mmr(Height((i + 1) as u32), *ads_root)
            .expect("verify_block_in_mmr 失败");
        assert!(is_valid, "Block {} 应在 MMR 中", i + 1);
        println!("  ✓ Block {} 验证通过", i + 1);
    }

    println!("\n✓ 测试5通过：重启后的 MMR 持久化验证成功\n");
}

/// 测试6：生成两层式证明（完整流程）
#[test]
fn test_generate_two_layer_proof_after_build() {
    println!("\n=== 测试6：生成两层式证明（完整流程）===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");
    let param = make_test_param();
    let pk = make_test_pk();

    let mut chain = SimChain::create(&chain_path, param.clone())
        .expect("创建链失败");

    // 构建多个区块
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

    println!("构建 5 个区块完成");
    println!("MMR 状态: size={}, block_count={}", 
        chain.get_mmr_size(), chain.get_mmr_block_count());

    // 为每个区块生成两层式证明
    println!("\n为每个区块生成两层式证明:");
    for i in 1..=5 {
        let height = Height(i as u32);
        
        // 生成基本两层式证明
        let proof = chain.gen_two_layer_proof(height, None)
            .expect("gen_two_layer_proof 失败");

        // 验证证明
        let is_valid = chain.verify_two_layer_proof(&proof)
            .expect("verify_two_layer_proof 失败");
        assert!(is_valid, "Block {} 两层式证明验证失败", i);

        println!("  ✓ Block {} 两层式证明生成并验证通过", i);
    }

    // 生成带索引证明的两层式证明
    println!("\n生成带索引证明的两层式证明:");
    
    // ID Tree 索引证明
    let proof_id = chain.gen_two_layer_proof_with_id_tree(Height(3))
        .expect("gen_two_layer_proof_with_id_tree 失败");
    let is_valid = chain.verify_two_layer_proof(&proof_id)
        .expect("verify 失败");
    assert!(is_valid);
    println!("  ✓ ID Tree 索引证明验证通过");

    println!("\n✓ 测试6通过：生成两层式证明（完整流程）成功\n");
}

/// 测试7：详细验证两层式证明
#[test]
fn test_verify_two_layer_proof_detailed() {
    println!("\n=== 测试7：详细验证两层式证明 ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");
    let param = make_test_param();
    let pk = make_test_pk();

    let mut chain = SimChain::create(&chain_path, param.clone())
        .expect("创建链失败");

    // 构建一个区块
    let objects = make_test_objects(Height(1), 5);
    let (_block_head, _mmr_pos, _mmr_root, _time) = build_block_with_mmr(
        Height(1),
        Digest::default(),
        objects,
        &mut chain,
        &param,
        &pk,
    ).expect("build_block_with_mmr 失败");

    // 生成两层式证明
    let proof = chain.gen_two_layer_proof(Height(1), None)
        .expect("gen_two_layer_proof 失败");

    // 详细验证
    let result = chain.verify_two_layer_proof_detailed(&proof)
        .expect("verify_two_layer_proof_detailed 失败");

    println!("详细验证结果:");
    println!("  - mmr_valid: {}", result.mmr_valid);
    println!("  - block_valid: {}", result.block_valid);
    println!("  - index_valid: {:?}", result.index_valid);
    println!("  - is_valid: {}", result.is_valid);
    println!("  - block_height: {:?}", result.block_height);
    println!("  - block_ads_root: {:?}...", &result.block_ads_root.as_bytes()[..4]);

    assert!(result.mmr_valid, "MMR 验证应通过");
    assert!(result.block_valid, "块内验证应通过");
    assert!(result.is_valid, "总体验证应通过");
    assert_eq!(result.block_height, Height(1));

    println!("\n✓ 测试7通过：详细验证两层式证明成功\n");
}

/// 测试8：批量生成两层式证明
#[test]
fn test_batch_two_layer_proofs() {
    println!("\n=== 测试8：批量生成两层式证明 ===");

    let temp_dir = tempdir().expect("创建临时目录失败");
    let chain_path = temp_dir.path().join("test_chain");
    let param = make_test_param();
    let pk = make_test_pk();

    let mut chain = SimChain::create(&chain_path, param.clone())
        .expect("创建链失败");

    // 构建多个区块
    let num_blocks = 10;
    let mut prev_hash = Digest::default();
    
    for i in 1..=num_blocks {
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

    println!("构建 {} 个区块完成", num_blocks);

    // 批量生成证明
    let heights: Vec<Height> = (1..=num_blocks).map(|i| Height(i as u32)).collect();
    
    let start = std::time::Instant::now();
    let proofs = chain.gen_batch_two_layer_proofs(heights.clone())
        .expect("gen_batch_two_layer_proofs 失败");
    let gen_time = start.elapsed();

    println!("\n批量生成 {} 个证明:", proofs.len());
    println!("  - 耗时: {:?}", gen_time);
    println!("  - 平均每个: {:?}", gen_time / num_blocks as u32);

    // 验证所有证明
    println!("\n验证所有证明:");
    let start = std::time::Instant::now();
    for (i, proof) in proofs.iter().enumerate() {
        let is_valid = chain.verify_two_layer_proof(proof)
            .expect("verify 失败");
        assert!(is_valid, "Proof {} 验证失败", i + 1);
    }
    let verify_time = start.elapsed();

    println!("  - 验证耗时: {:?}", verify_time);
    println!("  - 平均每个: {:?}", verify_time / num_blocks as u32);
    println!("  ✓ 所有 {} 个证明验证通过", proofs.len());

    println!("\n✓ 测试8通过：批量生成两层式证明成功\n");
}