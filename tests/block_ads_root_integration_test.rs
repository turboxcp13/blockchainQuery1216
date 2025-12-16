//! 【创新点1】BlockADSRoot 集成测试
//!
//! 测试一体化承诺在完整区块构建和验证流程中的正确性
//! 
//! ## 运行测试
//! ```bash
//! # 运行所有集成测试
//! cargo test --test block_ads_root_integration_test
//!
//! # 运行特定测试
//! cargo test --test block_ads_root_integration_test test_light_node_verification_flow
//!
//! # 显示测试输出
//! cargo test --test block_ads_root_integration_test -- --nocapture
//! ```

use vchain_plus::chain::block::{
    block_ads_root::{BlockADSComponents, BlockADSRoot},
    BlockContent, BlockHead, Height,
};
use vchain_plus::digest::Digest;

/// 测试1：模拟轻节点验证流程
#[test]
fn test_light_node_verification_flow() {
    println!("\n=== 测试1：轻节点验证流程 ===");
    
    // === 全节点构建区块 ===
    
    // 1. 计算各组件的哈希（模拟真实构建）
    let id_set_hash = mock_hash(b"id_set_data");
    let id_tree_hash = mock_hash(b"id_tree_data");
    let multi_ads_hash = mock_hash(b"multi_ads_data");

    // 2. 构建 BlockADSComponents
    let ads_components = BlockADSComponents::new(
        id_set_hash,
        id_tree_hash,
        multi_ads_hash,
    );

    // 3. 【使用完整的 BlockADSRoot】体现一体化承诺
    let block_ads_root = BlockADSRoot::from_components(ads_components.clone());
    
    // 验证内部一致性
    assert!(block_ads_root.verify_self(), "BlockADSRoot 内部不一致");
    println!("✓ 构建 BlockADSRoot 成功");

    // 4. BlockHead 存储统一根（轻节点会同步这个）
    let block_head = BlockHead {
        blk_height: Height(1),
        prev_hash: Digest::default(),
        ads_root: *block_ads_root.root(),
        obj_root_hash: Digest::default(),
    };

    // 5. BlockContent 存储完整组件（全节点保存）
    let mut block_content = BlockContent::new(Height(1), Digest::default());
    block_content.set_ads_components(block_ads_root.components().clone());

    // === 轻节点验证 ===
    
    // 轻节点持有 BlockHead（32字节 ads_root）
    // 全节点提供 BlockADSComponents
    
    // 验证 components 是否与 ads_root 一致
    assert!(
        block_head.verify_ads_components(&ads_components),
        "轻节点验证失败：components 与 ads_root 不匹配"
    );

    println!("✓ 轻节点验证成功：components 与 ads_root 匹配");

    // 验证可以正确提取各组件进行具体查询验证
    assert_eq!(ads_components.id_set_root_hash, id_set_hash);
    assert_eq!(ads_components.id_tree_root_hash, id_tree_hash);
    assert_eq!(ads_components.multi_ads_hash, multi_ads_hash);

    println!("✓ 组件提取成功：可用于具体查询验证\n");
}

/// 测试2：BlockADSRoot 的完整生命周期
#[test]
fn test_block_ads_root_lifecycle() {
    println!("\n=== 测试2：BlockADSRoot 生命周期 ===");
    
    // === 构建阶段 ===
    
    let components = BlockADSComponents::new(
        mock_hash(b"component1"),
        mock_hash(b"component2"),
        mock_hash(b"component3"),
    );

    // 创建完整的 BlockADSRoot
    let ads_root_full = BlockADSRoot::from_components(components.clone());

    // 验证内部一致性
    assert!(
        ads_root_full.verify_self(),
        "BlockADSRoot 内部不一致"
    );

    println!("✓ BlockADSRoot 构建成功，内部一致性验证通过");

    // === 存储阶段 ===
    
    // 提取 root 存入 BlockHead（轻节点会同步）
    let ads_root_digest = ads_root_full.to_digest_value();
    
    // 提取 components 存入 BlockContent（仅全节点保存）
    let stored_components = ads_root_full.components().clone();

    println!("✓ 存储分离：root -> BlockHead, components -> BlockContent");

    // === 加载阶段 ===
    
    // 模拟从存储加载
    let loaded_block_head = BlockHead {
        blk_height: Height(1),
        prev_hash: Digest::default(),
        ads_root: ads_root_digest,
        obj_root_hash: Digest::default(),
    };

    let loaded_components = stored_components;

    // === 验证阶段 ===
    
    // 重建 BlockADSRoot（如果需要）
    let reconstructed = BlockADSRoot::new(
        loaded_block_head.ads_root,
        loaded_components.clone(),
    );

    // 验证重建的 BlockADSRoot 与原始一致
    assert_eq!(reconstructed.root(), ads_root_full.root());
    assert_eq!(reconstructed.components(), ads_root_full.components());

    println!("✓ 从存储重建 BlockADSRoot 成功");

    // 验证 components 与 root 匹配
    assert!(loaded_block_head.verify_ads_components(&loaded_components));

    println!("✓ 验证流程完整测试通过\n");
}

/// 测试3：恶意 components 检测
#[test]
fn test_malicious_components_detection() {
    println!("\n=== 测试3：恶意 components 检测 ===");
    
    // 正确的 components
    let correct_components = BlockADSComponents::new(
        mock_hash(b"correct1"),
        mock_hash(b"correct2"),
        mock_hash(b"correct3"),
    );

    let block_ads_root = BlockADSRoot::from_components(correct_components.clone());

    let block_head = BlockHead {
        blk_height: Height(1),
        prev_hash: Digest::default(),
        ads_root: *block_ads_root.root(),
        obj_root_hash: Digest::default(),
    };

    // 恶意全节点提供错误的 components
    let malicious_components = BlockADSComponents::new(
        mock_hash(b"malicious1"),
        mock_hash(b"correct2"),
        mock_hash(b"correct3"),
    );

    // 验证应该失败
    assert!(
        !block_head.verify_ads_components(&malicious_components),
        "未能检测到恶意 components"
    );

    println!("✓ 成功检测到恶意 components");

    // 验证正确的 components 能通过
    assert!(block_head.verify_ads_components(&correct_components));

    println!("✓ 正确的 components 验证通过\n");
}

/// 测试4：多区块场景（为 MMR 准备）
#[test]
fn test_multi_block_scenario() {
    println!("\n=== 测试4：多区块场景（MMR 准备）===");
    
    let mut ads_roots = Vec::new();

    // 模拟构建多个区块
    for i in 0..10 {
        let components = BlockADSComponents::new(
            mock_hash(format!("block{}_id_set", i).as_bytes()),
            mock_hash(format!("block{}_id_tree", i).as_bytes()),
            mock_hash(format!("block{}_multi_ads", i).as_bytes()),
        );

        // 【使用完整的 BlockADSRoot】
        let block_ads_root = BlockADSRoot::from_components(components.clone());
        
        // 验证每个 BlockADSRoot 的内部一致性
        assert!(block_ads_root.verify_self());
        
        let ads_root = *block_ads_root.root();
        ads_roots.push(ads_root);

        // 验证每个区块的 components 都能正确生成对应的 ads_root
        assert_eq!(components.compute_root(), ads_root);
    }

    println!("✓ 生成 {} 个区块的 ads_root", ads_roots.len());

    // 所有 ads_root 应该互不相同（除非数据相同）
    for i in 0..ads_roots.len() {
        for j in i + 1..ads_roots.len() {
            assert_ne!(
                ads_roots[i], ads_roots[j],
                "不同区块的 ads_root 不应相同"
            );
        }
    }

    println!("✓ 所有区块的 ads_root 互不相同");

    // 这些 ads_root 可以直接用于构建 MMR
    println!("✓ 多区块场景测试通过，可用于 MMR 构建\n");
}

/// 测试5：确定性（相同输入产生相同输出）
#[test]
fn test_deterministic_computation() {
    println!("\n=== 测试5：确定性测试 ===");
    
    let components1 = BlockADSComponents::new(
        mock_hash(b"data1"),
        mock_hash(b"data2"),
        mock_hash(b"data3"),
    );

    let components2 = BlockADSComponents::new(
        mock_hash(b"data1"),
        mock_hash(b"data2"),
        mock_hash(b"data3"),
    );

    // 相同的 components 应产生相同的 root
    assert_eq!(components1.compute_root(), components2.compute_root());

    let root1 = BlockADSRoot::from_components(components1.clone());
    let root2 = BlockADSRoot::from_components(components2.clone());

    assert_eq!(root1.root(), root2.root());

    println!("✓ 确定性测试通过：相同输入产生相同输出\n");
}

/// 测试6：组件顺序的重要性
#[test]
fn test_component_order_matters() {
    println!("\n=== 测试6：组件顺序敏感性 ===");
    
    let hash1 = mock_hash(b"hash1");
    let hash2 = mock_hash(b"hash2");
    let hash3 = mock_hash(b"hash3");

    // 不同顺序的组件
    let components_abc = BlockADSComponents::new(hash1, hash2, hash3);
    let components_bac = BlockADSComponents::new(hash2, hash1, hash3);
    let components_cab = BlockADSComponents::new(hash3, hash1, hash2);

    // 应产生不同的 root（因为 Blake2b 对输入顺序敏感）
    let root_abc = components_abc.compute_root();
    let root_bac = components_bac.compute_root();
    let root_cab = components_cab.compute_root();

    assert_ne!(root_abc, root_bac);
    assert_ne!(root_abc, root_cab);
    assert_ne!(root_bac, root_cab);

    println!("✓ 组件顺序测试通过：不同顺序产生不同结果\n");
}

/// 测试7：BlockADSRoot 的各种创建方式
#[test]
fn test_block_ads_root_creation_methods() {
    println!("\n=== 测试7：BlockADSRoot 创建方式 ===");
    
    let components = BlockADSComponents::new(
        mock_hash(b"test1"),
        mock_hash(b"test2"),
        mock_hash(b"test3"),
    );

    // 方法1：from_components（推荐）
    let root1 = BlockADSRoot::from_components(components.clone());
    println!("✓ 方法1：from_components() 创建成功");

    // 方法2：new（从存储加载）
    let root2 = BlockADSRoot::new(
        components.compute_root(),
        components.clone(),
    );
    println!("✓ 方法2：new() 创建成功");

    // 方法3：from_digest（轻节点）
    let root3 = BlockADSRoot::from_digest(components.compute_root());
    println!("✓ 方法3：from_digest() 创建成功");

    // root1 和 root2 应该完全相同
    assert_eq!(root1.root(), root2.root());
    assert_eq!(root1.components(), root2.components());

    // root3 只有 root，components 为默认值
    assert_eq!(root3.root(), root1.root());
    assert_ne!(root3.components(), root1.components()); // components 不同

    println!("✓ 所有创建方式测试通过\n");
}

/// 测试8：【新增】build.rs 风格的完整流程测试
#[test]
fn test_build_style_workflow() {
    println!("\n=== 测试8：模拟 build.rs 的完整流程 ===");
    
    // === 模拟 build.rs 中的构建流程 ===
    
    // 1. 计算各个索引的根哈希（模拟真实区块构建）
    let id_set_root_hash = mock_hash(b"obj_id_nums_data");
    let id_tree_root_hash = mock_hash(b"id_tree_root_data");
    let multi_ads_hash = mock_hash(b"block_multi_ads_data");
    
    println!("步骤1: 计算各索引根哈希");
    println!("  - id_set_root_hash: {:?}...", &id_set_root_hash.as_bytes()[..4]);
    println!("  - id_tree_root_hash: {:?}...", &id_tree_root_hash.as_bytes()[..4]);
    println!("  - multi_ads_hash: {:?}...", &multi_ads_hash.as_bytes()[..4]);

    // 2. 构建 BlockADSComponents
    let ads_components = BlockADSComponents::new(
        id_set_root_hash,
        id_tree_root_hash,
        multi_ads_hash,
    );
    println!("\n步骤2: 构建 BlockADSComponents ✓");
    
    // 3. 【关键】从组件构建完整的 BlockADSRoot（体现一体化承诺）
    let block_ads_root = BlockADSRoot::from_components(ads_components);
    println!("步骤3: 构建 BlockADSRoot ✓");
    
    // 4. 验证内部一致性（调试模式）
    assert!(
        block_ads_root.verify_self(),
        "BlockADSRoot 内部一致性验证失败！"
    );
    println!("步骤4: 内部一致性验证 ✓");

    // 5. 从 BlockADSRoot 提取数据分别存储
    let mut block_head = BlockHead {
        blk_height: Height(100),
        prev_hash: mock_hash(b"prev_block"),
        ads_root: *block_ads_root.root(),  // BlockHead 存储统一根
        obj_root_hash: mock_hash(b"obj_root"),
    };
    
    let mut block_content = BlockContent::new(Height(100), mock_hash(b"prev_block"));
    block_content.set_ads_components(block_ads_root.components().clone());
    
    println!("步骤5: 分别存储到 BlockHead 和 BlockContent ✓");
    println!("  - BlockHead.ads_root: {:?}...", block_head.ads_root.as_bytes()[..4]);
    println!("  - BlockContent.ads_components: 已保存");

    // === 验证阶段（模拟轻节点） ===
    
    println!("\n步骤6: 模拟轻节点验证");
    
    // 6. 轻节点从网络获取 BlockHead
    let light_node_head = block_head.clone();
    
    // 7. 查询时全节点返回 components
    let full_node_components = block_content.get_ads_components();
    
    // 8. 轻节点验证 components 是否合法
    assert!(
        light_node_head.verify_ads_components(full_node_components),
        "轻节点验证失败"
    );
    
    println!("  - ✓ 轻节点成功验证 components");
    
    // 9. 轻节点可以使用各个组件根进行具体查询验证
    println!("\n步骤7: 使用组件进行查询验证");
    println!("  - 可用于 ID Set 查询: {:?}...", full_node_components.id_set_root_hash.as_bytes()[..4]);
    println!("  - 可用于 ID Tree 查询: {:?}...", full_node_components.id_tree_root_hash.as_bytes()[..4]);
    println!("  - 可用于 MultiADS 查询: {:?}...", full_node_components.multi_ads_hash.as_bytes()[..4]);
    
    println!("\n✓ 完整流程测试通过！\n");
}

// === 辅助函数 ===

/// 模拟哈希函数（使用 Blake2b）
fn mock_hash(data: &[u8]) -> Digest {
    use blake2::{Blake2b512, Digest as Blake2Digest};

    let mut hasher = Blake2b512::new();
    hasher.update(data);
    let result = hasher.finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result[..32]);
    Digest::from(bytes)
}