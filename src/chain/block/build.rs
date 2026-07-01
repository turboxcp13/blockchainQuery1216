use crate::{
    acc::AccPublicKey,
    chain::{
        block::{
            block_ads::BlockMultiADS,
            block_ads_root::{BlockADSComponents, BlockADSRoot},
            hash::{obj_id_nums_hash, obj_root_hash},
            BlockContent, BlockHead, Height,
        },
        bloom_filter::{AdaptiveBloomFilter, DEFAULT_BLOOM_TARGET_FPR},
        bplus_tree::{self, BPlusTreeNode, BPlusTreeNodeId, BPlusTreeRoot},
        id_tree::{self, ObjId},
        object::Object,
        traits::{Num, ReadInterface, WriteInterface},
        trie_tree::{self, TrieNode, TrieNodeId, TrieRoot},
        Parameter,
    },
    digest::{Digest, Digestible},
};
use anyhow::{bail, Context, Result};
use howlong::ProcessDuration;
use smol_str::SmolStr;
use std::{collections::{HashMap, HashSet}, num::NonZeroU16};

pub fn build_block<K: Num, T: ReadInterface<K = K> + WriteInterface<K = K>>(
    blk_height: Height,
    prev_hash: Digest,
    raw_objs: Vec<Object<K>>,
    mut chain: T,
    param: &Parameter,
    pk: &AccPublicKey,
) -> Result<(BlockHead, ProcessDuration)> {
    info!("Building block {}...", blk_height);
    let timer = howlong::ProcessCPUTimer::new();
    let mut block_head = BlockHead {
        blk_height,
        prev_hash,
        ..Default::default()
    };
    let mut block_content = BlockContent::new(blk_height, prev_hash);
    let max_id_num = param.max_id_num;
    let mut blk_multi_ads: BlockMultiADS = BlockMultiADS::default();
    let pre_blk_content = if blk_height.0 > 1 {
        chain.read_block_content(Height(blk_height.0 - 1))?
    } else {
        BlockContent::default()
    };

    let multi_ads = pre_blk_content.ads.read_adses();
    let time_wins = &param.time_win_sizes;

    // id tree ctx
    let id_tree_root = pre_blk_content.id_tree_root;
    let mut id_tree_ctx = id_tree::write::WriteContext::new(&chain, id_tree_root);
    // trie ctxes
    let mut trie_ctxes = Vec::<(u16, trie_tree::write::WriteContext<T>)>::new();
    // bplus tree
    let mut bplus_ctxes = Vec::<(u16, Vec<bplus_tree::write::WriteContext<K, T>>)>::new();

    for &k in time_wins {
        let pre_k_blk_content = if blk_height.0 > k.into() {
            chain.read_block_content(Height(blk_height.0 - k as u32))?
        } else {
            BlockContent::default()
        };
        let pre_k_blk_obj_hashes = &pre_k_blk_content.obj_hashes;
        let pre_k_blk_obj_id_nums = &pre_k_blk_content.obj_id_nums;

        // trie part
        let trie_root = if let Some(block_ads) = multi_ads.get(&k) {
            block_ads.trie_root
        } else {
            TrieRoot::default()
        };
        let mut trie_ctx = trie_tree::write::WriteContext::new(&chain, trie_root);
        for (idx, obj_hash) in pre_k_blk_obj_hashes.iter().enumerate() {
            let raw_obj = chain.read_object(*obj_hash)?;
            let obj_id_num = pre_k_blk_obj_id_nums
                .get(idx)
                .context("Cannot find object id number!")?;
            for key in &raw_obj.keyword_data {
                trie_ctx.delete(SmolStr::from(key), ObjId(*obj_id_num), pk)?;
            }
        }
        trie_ctxes.push((k, trie_ctx));

        //bplus tree part
        let mut bplus_ctx_vec = Vec::<bplus_tree::write::WriteContext<K, T>>::new();
        for dim in 0..param.num_dim {
            let bplus_tree_root = if let Some(block_ads) = multi_ads.get(&k) {
                if let Some(bplus_root) = block_ads.bplus_tree_roots.get(dim as usize) {
                    *bplus_root
                } else {
                    bail!(
                        "Cannot find BPlusRoot for dimension {} in time window {}!",
                        dim,
                        k
                    );
                }
            } else {
                BPlusTreeRoot::default()
            };
            let mut bplus_ctx = bplus_tree::write::WriteContext::new(&chain, bplus_tree_root);
            for (idx, obj_hash) in pre_k_blk_obj_hashes.iter().enumerate() {
                let raw_obj = chain.read_object(*obj_hash)?;
                let obj_id_num = pre_k_blk_obj_id_nums
                    .get(idx)
                    .context("Cannot find object id number!")?;
                if let Some(num_data) = raw_obj.num_data.get(dim as usize) {
                    bplus_ctx.delete(*num_data, ObjId(*obj_id_num), param.bplus_tree_fanout, pk)?;
                }
            }
            bplus_ctx_vec.push(bplus_ctx);
        }
        bplus_ctxes.push((k, bplus_ctx_vec));
    }

    let mut obj_hashes = Vec::<Digest>::with_capacity(raw_objs.len());
    let mut obj_id_nums = Vec::<NonZeroU16>::with_capacity(raw_objs.len());

    for obj in &raw_objs {
        // build id tree
        let obj_hash = obj.to_digest();
        let obj_id = id_tree_ctx.insert(obj_hash, max_id_num, param.id_tree_fanout)?;
        // build trie
        for (_k, trie_ctx) in &mut trie_ctxes {
            for key in &obj.keyword_data {
                trie_ctx.insert(SmolStr::from(key), obj_id, pk)?;
            }
        }
        // build bplus tree
        for (_k, bplus_ctx_vec) in &mut bplus_ctxes {
            for (dim, bplus_ctx) in bplus_ctx_vec.iter_mut().enumerate() {
                if let Some(key) = obj.num_data.get(dim) {
                    bplus_ctx.insert(*key, obj_id, param.bplus_tree_fanout, pk)?;
                }
            }
        }
        obj_hashes.push(obj_hash);
        obj_id_nums.push(obj_id.0);
    }

    // handle id tree changes
    let id_tree_changes = id_tree_ctx.changes();

    // handle trie changes
    let mut new_trie_nodes = Vec::<HashMap<TrieNodeId, TrieNode>>::new();
    let mut new_trie_roots = Vec::<(u16, TrieRoot)>::new();
    for (k, trie_ctx) in trie_ctxes {
        let trie_changes = trie_ctx.changes();
        new_trie_roots.push((k, trie_changes.root));
        new_trie_nodes.push(trie_changes.nodes);
    }
    blk_multi_ads.set_multi_trie_roots(new_trie_roots.iter());

    // handle bplus tree changes
    let mut new_bplus_roots = Vec::<(u16, Vec<BPlusTreeRoot>)>::new();
    let mut new_bplus_nodes = Vec::<HashMap<BPlusTreeNodeId, BPlusTreeNode<K>>>::new();
    for (k, bplus_ctx_vec) in bplus_ctxes {
        let mut new_bplus_roots_dim = Vec::<BPlusTreeRoot>::new();
        for bplus_ctx in bplus_ctx_vec {
            let bplus_tree_changes = bplus_ctx.changes();
            new_bplus_roots_dim.push(bplus_tree_changes.root);
            new_bplus_nodes.push(bplus_tree_changes.nodes);
        }
        new_bplus_roots.push((k, new_bplus_roots_dim));
    }
    blk_multi_ads.set_multi_bplus_roots(new_bplus_roots.iter());

    // write nodes to chain
    for (id, node) in id_tree_changes.nodes {
        chain.write_id_tree_node(id, &node)?;
    }
    for map in new_trie_nodes {
        for (id, node) in map {
            chain.write_trie_node(id, &node)?;
        }
    }
    for map in new_bplus_nodes {
        for (id, node) in map {
            chain.write_bplus_tree_node(id, &node)?;
        }
    }

    // write objs to chain
    for (obj, obj_hash) in raw_objs.iter().zip(obj_hashes.iter()) {
        chain.write_object(*obj_hash, obj)?;
    }

    let obj_root_hash = obj_root_hash(obj_hashes.iter());
    let id_set_root_hash = obj_id_nums_hash(obj_id_nums.iter());
    let multi_ads_hash = blk_multi_ads.to_digest();
    let id_tree_root_hash = id_tree_changes.root.to_digest();

    // 【方案 X】块级自适应 Bloom 过滤器
    //
    // 当 enable_bloom = true 时：
    //   1. 收集本块所有对象的关键词集合（去重）
    //   2. 构建一个 (m, k) 自适应于该块关键词数的 Bloom
    //   3. 取 Bloom 的 root 哈希参与 BlockADSComponents 的 t=4 聚合承诺
    //
    // 当 enable_bloom = false 时：
    //   1. Bloom 保持默认（空）状态
    //   2. bloom_root_hash 为 Digest::zero()
    //   3. BlockADSComponents 走 Paper A 路径（t=3 哈希，向后兼容）
    let (bloom_filter, bloom_root_hash) = if param.enable_bloom {
        let mut keyword_set: HashSet<Vec<u8>> = HashSet::new();
        for obj in &raw_objs {
            for kw in &obj.keyword_data {
                keyword_set.insert(kw.as_bytes().to_vec());
            }
        }
        let keywords: Vec<Vec<u8>> = keyword_set.into_iter().collect();
        let bf = AdaptiveBloomFilter::new_for_keywords(&keywords, DEFAULT_BLOOM_TARGET_FPR);
        let root = bf.to_digest();
        (bf, root)
    } else {
        (AdaptiveBloomFilter::default(), Digest::zero())
    };

    // 【创新点1 + 方案 X】构建一体化的 BlockADSRoot
    // 根据 enable_bloom 选择对应的构造路径，避免破坏 Paper A 哈希
    let ads_components = if param.enable_bloom {
        BlockADSComponents::new_with_bloom(
            id_set_root_hash,
            id_tree_root_hash,
            multi_ads_hash,
            bloom_root_hash,
        )
    } else {
        BlockADSComponents::new(
            id_set_root_hash,
            id_tree_root_hash,
            multi_ads_hash,
        )
    };

    // 从组件构建完整的 BlockADSRoot（体现一体化承诺的设计理念）
    let block_ads_root = BlockADSRoot::from_components(ads_components);
    
    // 验证内部一致性（调试模式下）
    #[cfg(debug_assertions)]
    {
        debug_assert!(
            block_ads_root.verify_self(),
            "BlockADSRoot 内部一致性验证失败！"
        );
        debug!("✓ Block {} BlockADSRoot 一致性验证通过", blk_height);
    }

    // 从 BlockADSRoot 提取数据分别存储
    // BlockHead 存储统一根（32字节，轻节点同步）
    block_head.set_obj_root_hash(obj_root_hash);
    block_head.set_ads_root(*block_ads_root.root());

    // BlockContent 存储完整组件（全节点保存，用于验证时展开）
    block_content.set_multi_ads(blk_multi_ads);
    block_content.set_obj_hashes(obj_hashes);
    block_content.set_obj_id_nums(obj_id_nums);
    block_content.set_id_tree_root(id_tree_changes.root);
    block_content.set_ads_components(block_ads_root.components().clone());
    // 【方案 X】存储块级 Bloom（enable_bloom=false 时为空 BF）
    block_content.set_bloom_filter(bloom_filter);

    chain.write_block_content(blk_height, &block_content)?;
    chain.write_block_head(blk_height, &block_head)?;
    let time = timer.elapsed();
    info!("Time elapsed : {}.", time);

    Ok((block_head, time))
}

/// 【创新点2】构建区块并插入 MMR 的增强版本
/// 
/// 此函数在 `build_block` 的基础上，额外将 BlockADSRoot 插入到链级 MMR 中，
/// 实现完整的两层式历史状态证明支持。
/// 
/// # 参数
/// - `blk_height`: 区块高度
/// - `prev_hash`: 前一区块哈希
/// - `raw_objs`: 区块内的原始对象
/// - `chain`: SimChain 可变引用
/// - `param`: 链参数
/// - `pk`: 累加器公钥
/// 
/// # 返回
/// - `Ok((block_head, mmr_pos, mmr_root, time))`: 区块头、MMR位置、新MMR根、耗时
/// - `Err`: 构建失败
/// 
/// # 示例
/// ```ignore
/// let (block_head, mmr_pos, mmr_root, time) = build_block_with_mmr(
///     Height(1),
///     Digest::default(),
///     objects,
///     &mut chain,
///     &param,
///     &pk,
/// )?;
/// 
/// // 可以验证该区块确实在 MMR 中
/// let proof = chain.gen_mmr_proof(vec![mmr_pos])?;
/// assert!(proof.verify(mmr_root, vec![(mmr_pos, block_head.get_ads_root())])?);
/// ```
pub fn build_block_with_mmr(
    blk_height: Height,
    prev_hash: Digest,
    raw_objs: Vec<Object<u32>>,
    chain: &mut crate::SimChain,
    param: &Parameter,
    pk: &AccPublicKey,
) -> Result<(BlockHead, u64, Digest, ProcessDuration)> {
    info!("Building block {} with MMR integration...", blk_height);
    let timer = howlong::ProcessCPUTimer::new();
    
    // 使用原有的 build_block 逻辑构建区块
    // 注意：这里传入 &mut *chain 以获得正确的引用类型
    let (block_head, _build_time) = build_block(
        blk_height,
        prev_hash,
        raw_objs,
        &mut *chain,
        param,
        pk,
    )?;

    // 【创新点2】将 BlockADSRoot 插入 MMR
    let block_ads_root = block_head.get_ads_root();
    let (mmr_pos, mmr_root) = chain.push_to_mmr(block_ads_root)?;

    let time = timer.elapsed();
    info!(
        "✓ Block {} built with MMR: pos={}, mmr_root={:?}, time={}",
        blk_height, mmr_pos, mmr_root, time
    );

    Ok((block_head, mmr_pos, mmr_root, time))
}