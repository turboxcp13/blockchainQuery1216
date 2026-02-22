//! 【创新点2】两层式证明集成测试
//!
//! 测试两层式历史状态证明的生成与验证
//!
//! ## 运行测试
//! ```bash
//! # 运行所有集成测试
//! cargo test --test two_layer_proof_integration_test
//!
//! # 运行特定测试
//! cargo test --test two_layer_proof_integration_test test_two_layer_proof_basic
//!
//! # 显示测试输出
//! cargo test --test two_layer_proof_integration_test -- --nocapture
//! ```

use vchain_plus::chain::block::block_ads_root::BlockADSComponents;
use vchain_plus::chain::block::Height;
use vchain_plus::chain::mmr::{
    BlockADSMerge, BlockProofData, ChainProofContext, IndexProof, MMRProofData,
    TwoLayerProof, TwoLayerVerifyResult, BatchTwoLayerProof, SingleBlockProof,
    MemStore, MMR,
};
use vchain_plus::digest::{blake2, Digest, Digestible};
use std::collections::BTreeMap;

// === 辅助函数 ===

/// 创建测试用 Digest
fn make_digest(byte: u8) -> Digest {
    let mut bytes = [0u8; 32];
    bytes[0] = byte;
    Digest::from(bytes)
}

/// 模拟哈希函数
fn mock_hash(data: &[u8]) -> Digest {
    data.to_digest()
}

/// 创建测试用 BlockADSComponents
fn make_components(block_num: u8) -> BlockADSComponents {
    BlockADSComponents::new(
        mock_hash(format!("block{}_id_set", block_num).as_bytes()),
        mock_hash(format!("block{}_id_tree", block_num).as_bytes()),
        mock_hash(format!("block{}_multi_ads", block_num).as_bytes()),
    )
}

// === 测试用例 ===

/// 测试1：两层式证明基本创建和验证
#[test]
fn test_two_layer_proof_basic() {
    println!("\n=== 测试1：两层式证明基本创建和验证 ===");

    // 1. 创建 BlockADSComponents 和 BlockADSRoot
    let components = make_components(1);
    let block_ads_root = components.compute_root();

    println!("步骤1: 创建 BlockADSComponents");
    println!("  - id_set_root_hash: {:?}...", &components.id_set_root_hash.as_bytes()[..4]);
    println!("  - id_tree_root_hash: {:?}...", &components.id_tree_root_hash.as_bytes()[..4]);
    println!("  - block_ads_root: {:?}...", &block_ads_root.as_bytes()[..4]);

    // 2. 创建 MMR 并插入 BlockADSRoot
    let store = MemStore::default();
    let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store);
    
    let pos = mmr.push(block_ads_root).expect("MMR push failed");
    let mmr_root = mmr.get_root().expect("MMR get_root failed");
    let mmr_size = mmr.mmr_size();

    println!("\n步骤2: 插入 MMR");
    println!("  - MMR position: {}", pos);
    println!("  - MMR size: {}", mmr_size);
    println!("  - MMR root: {:?}...", &mmr_root.as_bytes()[..4]);

    // 3. 生成 MMR 证明
    let mmr_merkle_proof = mmr.gen_proof(vec![pos]).expect("gen_proof failed");

    println!("\n步骤3: 生成 MMR 证明 ✓");

    // 4. 构建两层式证明
    let two_layer_proof = TwoLayerProof::from_mmr_proof(
        &mmr_merkle_proof,
        Height(1),
        block_ads_root,
        components.clone(),
        None,
    );

    println!("\n步骤4: 构建两层式证明 ✓");
    println!("  - block_height: {:?}", two_layer_proof.block_height());
    println!("  - mmr_position: {}", two_layer_proof.mmr_position());

    // 5. 验证两层式证明
    let is_valid = two_layer_proof.verify(mmr_root).expect("verify failed");
    assert!(is_valid, "两层式证明验证失败");

    println!("\n步骤5: 验证两层式证明 ✓");
    println!("\n✓ 测试1通过：两层式证明基本创建和验证成功\n");
}

/// 测试2：详细验证结果
#[test]
fn test_two_layer_proof_detailed_verification() {
    println!("\n=== 测试2：详细验证结果 ===");

    // 构建测试数据
    let components = make_components(2);
    let block_ads_root = components.compute_root();

    let store = MemStore::default();
    let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store);
    let pos = mmr.push(block_ads_root).expect("MMR push failed");
    let mmr_root = mmr.get_root().expect("MMR get_root failed");
    let mmr_merkle_proof = mmr.gen_proof(vec![pos]).expect("gen_proof failed");

    let proof = TwoLayerProof::from_mmr_proof(
        &mmr_merkle_proof,
        Height(1),
        block_ads_root,
        components,
        None,
    );

    // 详细验证
    let result = proof.verify_detailed(mmr_root).expect("verify_detailed failed");

    println!("详细验证结果:");
    println!("  - mmr_valid: {}", result.mmr_valid);
    println!("  - block_valid: {}", result.block_valid);
    println!("  - index_valid: {:?}", result.index_valid);
    println!("  - is_valid: {}", result.is_valid);
    println!("  - block_height: {:?}", result.block_height);

    assert!(result.mmr_valid, "MMR 验证应通过");
    assert!(result.block_valid, "块内验证应通过");
    assert!(result.is_valid, "总体验证应通过");

    println!("\n✓ 测试2通过：详细验证结果正确\n");
}

/// 辅助函数：按照 verify::hash 的逻辑手动计算 bplus_roots_hash
/// bplus_roots_hash = blake2(dim0_digest || dim1_digest || ...)
fn compute_bplus_roots_hash(hashes: &BTreeMap<u8, Digest>) -> Digest {
    let mut state = blake2().to_state();
    for (_dim, hash) in hashes {
        state.update(hash.as_bytes());
    }
    Digest::from(state.finalize())
}

/// 辅助函数：按照 verify::hash 的逻辑手动计算 ads_hash
/// ads_hash = blake2(bplus_roots_hash || trie_root_hash)
fn compute_ads_hash(bplus_hash: Digest, trie_hash: Digest) -> Digest {
    let mut state = blake2().to_state();
    state.update(bplus_hash.as_bytes());
    state.update(trie_hash.as_bytes());
    Digest::from(state.finalize())
}

/// 辅助函数：按照 verify::hash 的逻辑手动计算 multi_ads_hash
/// multi_ads_hash = blake2(tw1.to_digest() || ads1 || tw2.to_digest() || ads2 || ...)
fn compute_multi_ads_hash(ads_map: &BTreeMap<u16, Digest>) -> Digest {
    let mut state = blake2().to_state();
    for (tw, ads) in ads_map {
        state.update(tw.to_digest().as_bytes());
        state.update(ads.as_bytes());
    }
    Digest::from(state.finalize())
}

/// 测试3：带索引证明的两层式证明
#[test]
fn test_two_layer_proof_with_index_proof() {
    println!("\n=== 测试3：带索引证明的两层式证明 ===");

    // === 构建真实的索引数据，使 multi_ads_hash 可验证 ===
    // 定义两个维度的 B+ 树根和一个 Trie 根
    let bplus_root_dim0 = mock_hash(b"bplus_dim0");
    let bplus_root_dim1 = mock_hash(b"bplus_dim1");
    let trie_root = mock_hash(b"trie_root");

    // 正向计算哈希链：bplus_roots → ads_hash → multi_ads_hash
    let mut bplus_hashes = BTreeMap::new();
    bplus_hashes.insert(0u8, bplus_root_dim0);
    bplus_hashes.insert(1u8, bplus_root_dim1);
    let bplus_hash = compute_bplus_roots_hash(&bplus_hashes);
    let ads_hash_tw10 = compute_ads_hash(bplus_hash, trie_root);

    // 也定义第二个时间窗口用于测试 sibling_ads_hashes
    let bplus_root_tw20 = mock_hash(b"bplus_tw20");
    let trie_root_tw20 = mock_hash(b"trie_tw20");
    let mut bplus_hashes_tw20 = BTreeMap::new();
    bplus_hashes_tw20.insert(0u8, bplus_root_tw20);
    let bplus_hash_tw20 = compute_bplus_roots_hash(&bplus_hashes_tw20);
    let ads_hash_tw20 = compute_ads_hash(bplus_hash_tw20, trie_root_tw20);

    let mut all_ads = BTreeMap::new();
    all_ads.insert(10u16, ads_hash_tw10);
    all_ads.insert(20u16, ads_hash_tw20);
    let multi_ads_hash = compute_multi_ads_hash(&all_ads);

    // 用正确的 multi_ads_hash 构建 components
    let components = BlockADSComponents::new(
        mock_hash(b"id_set_root"),
        mock_hash(b"id_tree_root"),
        multi_ads_hash,
    );
    let block_ads_root = components.compute_root();

    let store = MemStore::default();
    let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store);
    let pos = mmr.push(block_ads_root).expect("MMR push failed");
    let mmr_root = mmr.get_root().expect("MMR get_root failed");
    let mmr_merkle_proof = mmr.gen_proof(vec![pos]).expect("gen_proof failed");

    // --- 测试 IdTree 索引证明 ---
    println!("测试 IdTree 索引证明:");
    let id_tree_proof = IndexProof::IdTree {
        root_hash: components.id_tree_root_hash,
    };

    let proof_with_id = TwoLayerProof::from_mmr_proof(
        &mmr_merkle_proof,
        Height(1),
        block_ads_root,
        components.clone(),
        Some(id_tree_proof),
    );

    let is_valid = proof_with_id.verify(mmr_root).expect("verify failed");
    assert!(is_valid, "IdTree 索引证明验证失败");
    println!("  ✓ IdTree 索引证明验证通过");

    // --- 测试 BPlusTree 索引证明 ---
    println!("\n测试 BPlusTree 索引证明:");
    let mut sibling_bplus = BTreeMap::new();
    sibling_bplus.insert(1u8, bplus_root_dim1);
    let mut sibling_ads = BTreeMap::new();
    sibling_ads.insert(20u16, ads_hash_tw20);

    let bplus_proof = IndexProof::BPlusTree {
        dimension: 0,
        time_window: 10,
        root_hash: bplus_root_dim0,
        sibling_bplus_hashes: sibling_bplus.clone(),
        trie_root_hash: trie_root,
        sibling_ads_hashes: sibling_ads.clone(),
    };

    let proof_with_bplus = TwoLayerProof::from_mmr_proof(
        &mmr_merkle_proof,
        Height(1),
        block_ads_root,
        components.clone(),
        Some(bplus_proof),
    );

    let is_valid = proof_with_bplus.verify(mmr_root).expect("verify failed");
    assert!(is_valid, "BPlusTree 索引证明验证失败");
    println!("  ✓ BPlusTree 索引证明验证通过");

    // --- 测试 BPlusTree 索引证明 - 篡改后应失败 ---
    println!("\n测试 BPlusTree 索引证明（篡改检测）:");
    let tampered_bplus_proof = IndexProof::BPlusTree {
        dimension: 0,
        time_window: 10,
        root_hash: mock_hash(b"TAMPERED"),  // 伪造的根哈希
        sibling_bplus_hashes: sibling_bplus,
        trie_root_hash: trie_root,
        sibling_ads_hashes: sibling_ads.clone(),
    };

    let proof_tampered = TwoLayerProof::from_mmr_proof(
        &mmr_merkle_proof,
        Height(1),
        block_ads_root,
        components.clone(),
        Some(tampered_bplus_proof),
    );

    let is_valid = proof_tampered.verify(mmr_root).expect("verify failed");
    assert!(!is_valid, "篡改后的 BPlusTree 索引证明不应通过验证");
    println!("  ✓ 篡改后的 BPlusTree 索引证明正确拒绝");

    // --- 测试 Trie 索引证明 ---
    println!("\n测试 Trie 索引证明:");
    let trie_proof = IndexProof::Trie {
        time_window: 10,
        root_hash: trie_root,
        bplus_roots_hash: bplus_hash,
        sibling_ads_hashes: sibling_ads,
    };

    let proof_with_trie = TwoLayerProof::from_mmr_proof(
        &mmr_merkle_proof,
        Height(1),
        block_ads_root,
        components.clone(),
        Some(trie_proof),
    );

    let is_valid = proof_with_trie.verify(mmr_root).expect("verify failed");
    assert!(is_valid, "Trie 索引证明验证失败");
    println!("  ✓ Trie 索引证明验证通过");

    // --- 测试复合索引证明 ---
    println!("\n测试复合索引证明:");
    let mut composite_sibling_bplus = BTreeMap::new();
    composite_sibling_bplus.insert(1u8, bplus_root_dim1);
    let mut composite_sibling_ads = BTreeMap::new();
    composite_sibling_ads.insert(20u16, ads_hash_tw20);

    let composite_proof = IndexProof::Composite {
        proofs: vec![
            IndexProof::IdTree {
                root_hash: components.id_tree_root_hash,
            },
            IndexProof::BPlusTree {
                dimension: 0,
                time_window: 10,
                root_hash: bplus_root_dim0,
                sibling_bplus_hashes: composite_sibling_bplus,
                trie_root_hash: trie_root,
                sibling_ads_hashes: composite_sibling_ads,
            },
        ],
    };

    let proof_with_composite = TwoLayerProof::from_mmr_proof(
        &mmr_merkle_proof,
        Height(1),
        block_ads_root,
        components,
        Some(composite_proof),
    );

    let is_valid = proof_with_composite.verify(mmr_root).expect("verify failed");
    assert!(is_valid, "复合索引证明验证失败");
    println!("  ✓ 复合索引证明验证通过");

    println!("\n✓ 测试3通过：带索引证明的两层式证明正确\n");
}

/// 测试4：多区块 MMR 的两层式证明
#[test]
fn test_multi_block_mmr_proof() {
    println!("\n=== 测试4：多区块 MMR 的两层式证明 ===");

    let store = MemStore::default();
    let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store);

    // 插入多个区块
    let num_blocks = 10;
    let mut block_data: Vec<(u64, Digest, BlockADSComponents)> = Vec::new();

    println!("插入 {} 个区块到 MMR:", num_blocks);
    for i in 0..num_blocks {
        let components = make_components(i as u8);
        let block_ads_root = components.compute_root();
        let pos = mmr.push(block_ads_root).expect("MMR push failed");
        block_data.push((pos, block_ads_root, components));
        println!("  - Block {}: pos={}", i + 1, pos);
    }

    let mmr_root = mmr.get_root().expect("MMR get_root failed");
    let mmr_size = mmr.mmr_size();
    println!("\nMMR 状态: size={}, root={:?}...", mmr_size, &mmr_root.as_bytes()[..4]);

    // 为每个区块生成并验证两层式证明
    println!("\n验证每个区块的两层式证明:");
    for (i, (pos, block_ads_root, components)) in block_data.iter().enumerate() {
        let mmr_proof = mmr.gen_proof(vec![*pos]).expect("gen_proof failed");
        
        let proof = TwoLayerProof::from_mmr_proof(
            &mmr_proof,
            Height((i + 1) as u32),
            *block_ads_root,
            components.clone(),
            None,
        );

        let is_valid = proof.verify(mmr_root).expect("verify failed");
        assert!(is_valid, "Block {} 两层式证明验证失败", i + 1);
        println!("  ✓ Block {} 验证通过", i + 1);
    }

    println!("\n✓ 测试4通过：多区块 MMR 两层式证明正确\n");
}

/// 测试5：ChainProofContext 功能
#[test]
fn test_chain_proof_context() {
    println!("\n=== 测试5：ChainProofContext 功能 ===");

    let mmr_root = mock_hash(b"mmr_root");
    let ctx = ChainProofContext::new(mmr_root, 15, 10);

    println!("创建 ChainProofContext:");
    println!("  - mmr_root: {:?}...", &ctx.mmr_root.as_bytes()[..4]);
    println!("  - mmr_size: {}", ctx.mmr_size);
    println!("  - block_count: {}", ctx.block_count);

    // 测试高度有效性
    println!("\n测试高度有效性:");
    assert!(ctx.is_valid_height(Height(1)), "Height(1) 应有效");
    assert!(ctx.is_valid_height(Height(10)), "Height(10) 应有效");
    assert!(!ctx.is_valid_height(Height(0)), "Height(0) 应无效");
    assert!(!ctx.is_valid_height(Height(11)), "Height(11) 应无效");
    println!("  ✓ 高度有效性检查正确");

    // 测试 MMR 位置计算
    println!("\n测试 MMR 位置计算:");
    assert_eq!(ctx.get_mmr_position(Height(1)), Some(0));
    assert_eq!(ctx.get_mmr_position(Height(2)), Some(1));
    assert_eq!(ctx.get_mmr_position(Height(3)), Some(3));
    assert_eq!(ctx.get_mmr_position(Height(0)), None);
    assert_eq!(ctx.get_mmr_position(Height(11)), None);
    println!("  ✓ MMR 位置计算正确");

    println!("\n✓ 测试5通过：ChainProofContext 功能正确\n");
}

/// 测试6：恶意证明检测
#[test]
fn test_malicious_proof_detection() {
    println!("\n=== 测试6：恶意证明检测 ===");

    let components = make_components(6);
    let block_ads_root = components.compute_root();

    let store = MemStore::default();
    let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store);
    let pos = mmr.push(block_ads_root).expect("MMR push failed");
    let mmr_root = mmr.get_root().expect("MMR get_root failed");
    let mmr_merkle_proof = mmr.gen_proof(vec![pos]).expect("gen_proof failed");

    // 测试1：错误的 components
    println!("测试1：检测错误的 components");
    let wrong_components = make_components(99); // 不同的组件
    
    let proof_wrong_components = TwoLayerProof::from_mmr_proof(
        &mmr_merkle_proof,
        Height(1),
        block_ads_root,
        wrong_components, // 错误的组件
        None,
    );

    let result = proof_wrong_components.verify_detailed(mmr_root).expect("verify failed");
    assert!(!result.block_valid, "应检测到错误的 components");
    println!("  ✓ 成功检测到错误的 components");

    // 测试2：错误的 MMR root
    println!("\n测试2：检测错误的 MMR root");
    let proof_correct = TwoLayerProof::from_mmr_proof(
        &mmr_merkle_proof,
        Height(1),
        block_ads_root,
        components.clone(),
        None,
    );

    let wrong_mmr_root = mock_hash(b"wrong_mmr_root");
    let result = proof_correct.verify_detailed(wrong_mmr_root).expect("verify failed");
    assert!(!result.mmr_valid, "应检测到错误的 MMR root");
    println!("  ✓ 成功检测到错误的 MMR root");

    // 测试3：错误的 block_ads_root
    println!("\n测试3：检测错误的 block_ads_root");
    let wrong_block_ads_root = mock_hash(b"wrong_block_ads_root");
    
    let proof_wrong_root = TwoLayerProof::from_mmr_proof(
        &mmr_merkle_proof,
        Height(1),
        wrong_block_ads_root, // 错误的 block_ads_root
        components,
        None,
    );

    let result = proof_wrong_root.verify_detailed(mmr_root).expect("verify failed");
    assert!(!result.is_valid, "应检测到错误的 block_ads_root");
    println!("  ✓ 成功检测到错误的 block_ads_root");

    println!("\n✓ 测试6通过：恶意证明检测正确\n");
}

/// 测试7：批量两层式证明
#[test]
fn test_batch_two_layer_proof() {
    println!("\n=== 测试7：批量两层式证明 ===");

    let store = MemStore::default();
    let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store);

    // 插入多个区块
    let num_blocks = 5;
    let mut single_proofs: Vec<SingleBlockProof> = Vec::new();

    println!("插入 {} 个区块:", num_blocks);
    for i in 0..num_blocks {
        let components = make_components(i as u8);
        let block_ads_root = components.compute_root();
        let pos = mmr.push(block_ads_root).expect("MMR push failed");
        
        single_proofs.push(SingleBlockProof {
            block_height: Height((i + 1) as u32),
            position: pos,
            block_ads_root,
            components,
            index_proof: None,
        });
        
        println!("  - Block {}: pos={}", i + 1, pos);
    }

    let mmr_root = mmr.get_root().expect("MMR get_root failed");
    let mmr_size = mmr.mmr_size();

    // 生成批量证明的共享 MMR 证明
    let positions: Vec<u64> = single_proofs.iter().map(|p| p.position).collect();
    let batch_mmr_proof = mmr.gen_proof(positions).expect("gen_proof failed");

    // 创建批量两层式证明
    let batch_proof = BatchTwoLayerProof::new(
        mmr_size,
        single_proofs,
        batch_mmr_proof.proof_items().to_vec(),
    );

    println!("\n批量证明信息:");
    println!("  - block_count: {}", batch_proof.block_count());
    println!("  - mmr_size: {}", batch_proof.mmr_size);

    // 验证批量证明
    let results = batch_proof.verify(mmr_root).expect("batch verify failed");
    
    println!("\n验证结果:");
    for (i, valid) in results.iter().enumerate() {
        assert!(*valid, "Block {} 批量验证失败", i + 1);
        println!("  ✓ Block {} 验证通过", i + 1);
    }

    println!("\n✓ 测试7通过：批量两层式证明正确\n");
}

/// 测试8：证明序列化
#[test]
fn test_proof_serialization() {
    println!("\n=== 测试8：证明序列化 ===");

    let components = make_components(8);
    let block_ads_root = components.compute_root();
    // 保存 id_tree_root_hash 用于 IndexProof
    let id_tree_root_hash = components.id_tree_root_hash;

    let store = MemStore::default();
    let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store);
    let pos = mmr.push(block_ads_root).expect("MMR push failed");
    let mmr_root = mmr.get_root().expect("MMR get_root failed");
    let mmr_merkle_proof = mmr.gen_proof(vec![pos]).expect("gen_proof failed");

    let proof = TwoLayerProof::from_mmr_proof(
        &mmr_merkle_proof,
        Height(1),
        block_ads_root,
        components,
        Some(IndexProof::IdTree {
            root_hash: id_tree_root_hash,  // 使用正确的 id_tree_root_hash
        }),
    );

    // 序列化
    let serialized = serde_json::to_string(&proof).expect("serialize failed");
    println!("序列化后大小: {} bytes", serialized.len());

    // 反序列化
    let deserialized: TwoLayerProof = serde_json::from_str(&serialized).expect("deserialize failed");

    // 验证反序列化后的证明
    let is_valid = deserialized.verify(mmr_root).expect("verify failed");
    assert!(is_valid, "反序列化后的证明验证失败");

    // 验证内容一致
    assert_eq!(proof.block_height(), deserialized.block_height());
    assert_eq!(proof.mmr_position(), deserialized.mmr_position());
    assert_eq!(proof.block_ads_root(), deserialized.block_ads_root());

    println!("  ✓ 序列化/反序列化成功");
    println!("  ✓ 反序列化后验证通过");

    println!("\n✓ 测试8通过：证明序列化正确\n");
}