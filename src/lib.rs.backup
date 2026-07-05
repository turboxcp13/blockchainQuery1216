#![cfg_attr(not(test), warn(clippy::unwrap_used))]

#[macro_use]
extern crate tracing;

pub mod acc;
pub mod chain;
pub mod digest;
pub mod utils;

use anyhow::{Context, Result};
use chain::{
    block::{block_ads_root::BlockADSComponents, BlockContent, BlockHead, Height},
    bplus_tree::{BPlusTreeNode, BPlusTreeNodeId},
    id_tree::{IdTreeNode, IdTreeNodeId},
    mmr::{
        BlockADSMerge, BlockProofData, ChainProofContext, IndexProof, MerkleProof,
        MMRProofData, MMRStoreWriteOps, RocksStore, TwoLayerProof, TwoLayerVerifyResult, MMR,
    },
    object::Object,
    range::Range,
    traits::{ReadInterface, ScanQueryInterface, WriteInterface},
    trie_tree::{TrieNode, TrieNodeId},
    Parameter,
};
use digest::{Digest, Digestible};
use rocksdb::{self, DB};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

/// 【创新点2】链级 MMR 承诺的元数据
/// 
/// 存储 MMR 的当前状态，用于持久化和恢复
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ChainMMRMeta {
    /// MMR 当前大小（节点总数）
    pub mmr_size: u64,
    /// 最新的 MMR 根哈希
    pub mmr_root: Digest,
    /// 已插入的区块数量（叶子节点数）
    pub block_count: u64,
}

pub struct SimChain {
    root_path: PathBuf,
    param: Parameter,
    block_head_db: DB,
    block_content_db: DB,
    id_tree_db: DB,
    bplus_tree_db: DB,
    trie_db: DB,
    obj_db: DB,
    /// 【创新点2】MMR 数据库 - 存储链级承诺
    mmr_db: Arc<DB>,
    /// 【创新点2】MMR 元数据
    mmr_meta: ChainMMRMeta,
}

impl SimChain {
    pub fn create(path: &Path, param: Parameter) -> Result<Self> {
        fs::create_dir_all(path).with_context(|| format!("failed to create dir {:?}", path))?;
        fs::write(
            path.join("param.json"),
            serde_json::to_string_pretty(&param)?,
        )?;
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        
        // 【创新点2】创建 MMR 数据库
        let mmr_db = Arc::new(DB::open(&opts, path.join("mmr.db"))?);
        
        // 初始化 MMR 元数据
        let mmr_meta = ChainMMRMeta::default();
        fs::write(
            path.join("mmr_meta.json"),
            serde_json::to_string_pretty(&mmr_meta)?,
        )?;
        
        Ok(Self {
            root_path: path.to_owned(),
            param,
            block_head_db: DB::open(&opts, path.join("blk_head.db"))?,
            block_content_db: DB::open(&opts, path.join("block_content.db"))?,
            id_tree_db: DB::open(&opts, path.join("id_tree.db"))?,
            bplus_tree_db: DB::open(&opts, path.join("bplus_tree.db"))?,
            trie_db: DB::open(&opts, path.join("trie.db"))?,
            obj_db: DB::open(&opts, path.join("obj.db"))?,
            mmr_db,
            mmr_meta,
        })
    }

    pub fn open(path: &Path) -> Result<Self> {
        // 【创新点2】加载 MMR 元数据
        let mmr_meta_path = path.join("mmr_meta.json");
        let mmr_meta = if mmr_meta_path.exists() {
            serde_json::from_str::<ChainMMRMeta>(&fs::read_to_string(&mmr_meta_path)?)?
        } else {
            // 兼容旧版本：如果没有 MMR 元数据文件，创建默认的
            ChainMMRMeta::default()
        };
        
        // 【创新点2】打开或创建 MMR 数据库
        let mmr_db_path = path.join("mmr.db");
        let mmr_db = if mmr_db_path.exists() {
            Arc::new(DB::open_default(&mmr_db_path)?)
        } else {
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            Arc::new(DB::open(&opts, &mmr_db_path)?)
        };
        
        Ok(Self {
            root_path: path.to_owned(),
            param: serde_json::from_str::<Parameter>(&fs::read_to_string(
                path.join("param.json"),
            )?)?,
            block_head_db: DB::open_default(path.join("blk_head.db"))?,
            block_content_db: DB::open_default(path.join("block_content.db"))?,
            id_tree_db: DB::open_default(path.join("id_tree.db"))?,
            bplus_tree_db: DB::open_default(path.join("bplus_tree.db"))?,
            trie_db: DB::open_default(path.join("trie.db"))?,
            obj_db: DB::open_default(path.join("obj.db"))?,
            mmr_db,
            mmr_meta,
        })
    }

    // ============================================================================
    // 【创新点2】MMR 链级承诺相关方法
    // ============================================================================

    /// 获取 MMR 存储
    pub fn get_mmr_store(&self) -> RocksStore<Digest> {
        RocksStore::new(Arc::clone(&self.mmr_db))
    }

    /// 获取当前 MMR 大小
    pub fn get_mmr_size(&self) -> u64 {
        self.mmr_meta.mmr_size
    }

    /// 获取当前 MMR 根
    pub fn get_mmr_root(&self) -> Digest {
        self.mmr_meta.mmr_root
    }

    /// 获取已插入的区块数量
    pub fn get_mmr_block_count(&self) -> u64 {
        self.mmr_meta.block_count
    }

    /// 获取 MMR 元数据
    pub fn get_mmr_meta(&self) -> &ChainMMRMeta {
        &self.mmr_meta
    }

    /// 将 BlockADSRoot 插入 MMR 并更新状态
    /// 
    /// # 参数
    /// - `block_ads_root`: 区块的 BlockADSRoot 摘要
    /// 
    /// # 返回
    /// - `Ok((pos, new_root))`: 插入位置和新的 MMR 根
    /// - `Err`: 插入失败
    pub fn push_to_mmr(&mut self, block_ads_root: Digest) -> Result<(u64, Digest)> {
        let store = self.get_mmr_store();
        let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(self.mmr_meta.mmr_size, store);
        
        // 插入新的 BlockADSRoot
        let pos = mmr.push(block_ads_root)
            .map_err(|e| anyhow::anyhow!("MMR push failed: {}", e))?;
        
        // 获取新的 MMR 根
        let new_root = mmr.get_root()
            .map_err(|e| anyhow::anyhow!("MMR get_root failed: {}", e))?;
        
        // 提交批次数据到存储
        let batch = mmr.batch();
        let mut store = self.get_mmr_store();
        for (start_pos, elems) in batch.get_batch_data().iter() {
            store.append(*start_pos, elems.clone())
                .map_err(|e| anyhow::anyhow!("MMR store append failed: {}", e))?;
        }
        
        // 更新元数据
        self.mmr_meta.mmr_size = mmr.mmr_size();
        self.mmr_meta.mmr_root = new_root;
        self.mmr_meta.block_count += 1;
        
        // 持久化元数据
        self.save_mmr_meta()?;
        
        info!(
            "✓ BlockADSRoot 已插入 MMR: pos={}, mmr_size={}, block_count={}",
            pos, self.mmr_meta.mmr_size, self.mmr_meta.block_count
        );
        
        Ok((pos, new_root))
    }

    /// 生成 MMR 包含性证明
    /// 
    /// # 参数
    /// - `positions`: 需要证明的位置列表
    /// 
    /// # 返回
    /// - `Ok(proof)`: MMR 证明
    /// - `Err`: 生成失败
    pub fn gen_mmr_proof(&self, positions: Vec<u64>) -> Result<MerkleProof<Digest, BlockADSMerge>> {
        let store = self.get_mmr_store();
        let mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(self.mmr_meta.mmr_size, store);
        
        mmr.gen_proof(positions)
            .map_err(|e| anyhow::anyhow!("MMR gen_proof failed: {}", e))
    }

    /// 根据区块高度获取其在 MMR 中的位置
    /// 
    /// # 参数
    /// - `block_height`: 区块高度（从1开始）
    /// 
    /// # 返回
    /// - `Some(pos)`: MMR 中的位置
    /// - `None`: 区块不存在
    pub fn get_mmr_position_by_height(&self, block_height: Height) -> Option<u64> {
        if block_height.0 == 0 || block_height.0 as u64 > self.mmr_meta.block_count {
            return None;
        }
        // 区块高度从1开始，MMR 叶子索引从0开始
        let leaf_index = block_height.0 as u64 - 1;
        Some(chain::mmr::helper::leaf_index_to_pos(leaf_index))
    }

    /// 验证 BlockADSRoot 是否属于当前 MMR
    /// 
    /// # 参数
    /// - `block_height`: 区块高度
    /// - `block_ads_root`: 待验证的 BlockADSRoot
    /// 
    /// # 返回
    /// - `Ok(true)`: 验证通过
    /// - `Ok(false)`: 验证失败
    /// - `Err`: 验证过程出错
    pub fn verify_block_in_mmr(&self, block_height: Height, block_ads_root: Digest) -> Result<bool> {
        let pos = self.get_mmr_position_by_height(block_height)
            .context("Block height out of range")?;
        
        let proof = self.gen_mmr_proof(vec![pos])?;
        
        proof.verify(self.mmr_meta.mmr_root, vec![(pos, block_ads_root)])
            .map_err(|e| anyhow::anyhow!("MMR verify failed: {}", e))
    }

    /// 保存 MMR 元数据到文件
    fn save_mmr_meta(&self) -> Result<()> {
        let data = serde_json::to_string_pretty(&self.mmr_meta)?;
        fs::write(self.root_path.join("mmr_meta.json"), data)?;
        Ok(())
    }

    /// 重建 MMR（用于数据迁移或修复）
    /// 
    /// 从现有区块头重建 MMR
    pub fn rebuild_mmr(&mut self) -> Result<()> {
        info!("开始重建 MMR...");
        
        // 获取链上的区块数量
        let (_, max_height) = (&self as &SimChain).get_chain_info()?;
        
        if max_height == 0 {
            info!("链为空，无需重建 MMR");
            return Ok(());
        }
        
        // 重置 MMR 状态
        self.mmr_meta = ChainMMRMeta::default();
        
        // 遍历所有区块，将 BlockADSRoot 插入 MMR
        for height in 1..=max_height {
            let block_head = (&self as &SimChain).read_block_head(Height(height))?;
            let block_ads_root = block_head.get_ads_root();
            
            self.push_to_mmr(block_ads_root)?;
        }
        
        info!(
            "MMR 重建完成: mmr_size={}, block_count={}, root={:?}",
            self.mmr_meta.mmr_size,
            self.mmr_meta.block_count,
            self.mmr_meta.mmr_root
        );
        
        Ok(())
    }

    // ============================================================================
    // 【创新点2】两层式证明相关方法
    // ============================================================================

    /// 获取链证明上下文
    ///
    /// 用于验证两层式证明
    pub fn get_proof_context(&self) -> ChainProofContext {
        ChainProofContext::new(
            self.mmr_meta.mmr_root,
            self.mmr_meta.mmr_size,
            self.mmr_meta.block_count,
        )
    }

    /// 生成两层式证明
    ///
    /// # 参数
    /// - `block_height`: 区块高度
    /// - `index_proof`: 可选的索引证明
    ///
    /// # 返回
    /// - `Ok(TwoLayerProof)`: 两层式证明
    /// - `Err`: 生成失败
    ///
    /// # 示例
    /// ```ignore
    /// let proof = chain.gen_two_layer_proof(Height(5), None)?;
    /// assert!(proof.verify(chain.get_mmr_root())?);
    /// ```
    pub fn gen_two_layer_proof(
        &self,
        block_height: Height,
        index_proof: Option<IndexProof>,
    ) -> Result<TwoLayerProof> {
        // 验证区块高度有效性
        if block_height.0 == 0 || block_height.0 as u64 > self.mmr_meta.block_count {
            anyhow::bail!("Invalid block height: {}", block_height.0);
        }

        // 读取区块头和区块内容
        let block_head = (&self as &SimChain).read_block_head(block_height)?;
        let block_content = (&self as &SimChain).read_block_content(block_height)?;

        // 获取 BlockADSRoot 和组件
        let block_ads_root = block_head.get_ads_root();
        let components = block_content.get_ads_components().clone();

        // 获取 MMR 位置并生成 MMR 证明
        let pos = self.get_mmr_position_by_height(block_height)
            .context("Failed to get MMR position")?;
        let mmr_proof = self.gen_mmr_proof(vec![pos])?;

        // 构建两层式证明
        let proof = TwoLayerProof::from_mmr_proof(
            &mmr_proof,
            block_height,
            block_ads_root,
            components,
            index_proof,
        );

        Ok(proof)
    }

    /// 生成带 ID 树索引证明的两层式证明
    pub fn gen_two_layer_proof_with_id_tree(&self, block_height: Height) -> Result<TwoLayerProof> {
        let block_content = (&self as &SimChain).read_block_content(block_height)?;
        let id_tree_root_hash = block_content.get_ads_components().id_tree_root_hash;

        let index_proof = IndexProof::IdTree {
            root_hash: id_tree_root_hash,
        };

        self.gen_two_layer_proof(block_height, Some(index_proof))
    }

    /// 生成带 B+ 树索引证明的两层式证明
    ///
    /// 收集目标 B+ 树根的所有兄弟哈希，使验证端能重算 multi_ads_hash
    pub fn gen_two_layer_proof_with_bplus_tree(
        &self,
        block_height: Height,
        dimension: u8,
        time_window: u16,
    ) -> Result<TwoLayerProof> {
        let block_content = (&self as &SimChain).read_block_content(block_height)?;
        
        let ads = &block_content.ads;
        let all_adses = ads.read_adses();

        let block_ads = all_adses
            .get(&time_window)
            .context("Time window not found")?;
        
        // 目标 B+ 树根哈希
        let root_hash = block_ads.bplus_tree_roots
            .get(dimension as usize)
            .context("Dimension not found")?
            .to_digest();

        // 收集同一时间窗口内其他维度的 B+ 树根哈希
        let mut sibling_bplus_hashes = BTreeMap::new();
        for (dim, bplus_root) in block_ads.bplus_tree_roots.iter().enumerate() {
            let dim = dim as u8;
            if dim != dimension {
                sibling_bplus_hashes.insert(dim, bplus_root.to_digest());
            }
        }

        // 同一时间窗口的 Trie 根哈希
        let trie_root_hash = block_ads.trie_root.to_digest();

        // 收集其他时间窗口的 ads_hash
        let mut sibling_ads_hashes = BTreeMap::new();
        for (&tw, tw_ads) in all_adses {
            if tw != time_window {
                sibling_ads_hashes.insert(tw, tw_ads.to_digest());
            }
        }

        let index_proof = IndexProof::BPlusTree {
            dimension,
            time_window,
            root_hash,
            sibling_bplus_hashes,
            trie_root_hash,
            sibling_ads_hashes,
        };

        self.gen_two_layer_proof(block_height, Some(index_proof))
    }

    /// 生成带 Trie 索引证明的两层式证明
    ///
    /// 收集目标 Trie 根的所有兄弟哈希，使验证端能重算 multi_ads_hash
    pub fn gen_two_layer_proof_with_trie(
        &self,
        block_height: Height,
        time_window: u16,
    ) -> Result<TwoLayerProof> {
        let block_content = (&self as &SimChain).read_block_content(block_height)?;
        
        let ads = &block_content.ads;
        let all_adses = ads.read_adses();

        let block_ads = all_adses
            .get(&time_window)
            .context("Time window not found")?;
        
        // 目标 Trie 根哈希
        let root_hash = block_ads.trie_root.to_digest();

        // 预计算同一时间窗口所有 B+ 树根的聚合哈希
        // 与 verify::hash::bplus_roots_hash 计算方式一致
        let bplus_hashes: BTreeMap<u8, Digest> = block_ads.bplus_tree_roots
            .iter()
            .enumerate()
            .map(|(dim, root)| (dim as u8, root.to_digest()))
            .collect();
        let bplus_roots_hash = chain::verify::hash::bplus_roots_hash(bplus_hashes.iter());

        // 收集其他时间窗口的 ads_hash
        let mut sibling_ads_hashes = BTreeMap::new();
        for (&tw, tw_ads) in all_adses {
            if tw != time_window {
                sibling_ads_hashes.insert(tw, tw_ads.to_digest());
            }
        }

        let index_proof = IndexProof::Trie {
            time_window,
            root_hash,
            bplus_roots_hash,
            sibling_ads_hashes,
        };

        self.gen_two_layer_proof(block_height, Some(index_proof))
    }

    /// 验证两层式证明
    ///
    /// # 参数
    /// - `proof`: 两层式证明
    ///
    /// # 返回
    /// - `Ok(true)`: 验证通过
    /// - `Ok(false)`: 验证失败
    /// - `Err`: 验证过程出错
    pub fn verify_two_layer_proof(&self, proof: &TwoLayerProof) -> Result<bool> {
        proof.verify(self.mmr_meta.mmr_root)
            .map_err(|e| anyhow::anyhow!("Two layer proof verification failed: {}", e))
    }

    /// 详细验证两层式证明
    ///
    /// 返回详细的验证结果，包括各层的验证状态
    pub fn verify_two_layer_proof_detailed(
        &self,
        proof: &TwoLayerProof,
    ) -> Result<TwoLayerVerifyResult> {
        proof.verify_detailed(self.mmr_meta.mmr_root)
            .map_err(|e| anyhow::anyhow!("Two layer proof verification failed: {}", e))
    }

    /// 批量生成两层式证明
    ///
    /// # 参数
    /// - `block_heights`: 区块高度列表
    ///
    /// # 返回
    /// - `Ok(Vec<TwoLayerProof>)`: 两层式证明列表
    /// - `Err`: 生成失败
    pub fn gen_batch_two_layer_proofs(
        &self,
        block_heights: Vec<Height>,
    ) -> Result<Vec<TwoLayerProof>> {
        let mut proofs = Vec::with_capacity(block_heights.len());
        
        for height in block_heights {
            let proof = self.gen_two_layer_proof(height, None)?;
            proofs.push(proof);
        }
        
        Ok(proofs)
    }
}

impl ReadInterface for &SimChain {
    type K = u32;
    fn get_parameter(&self) -> Result<Parameter> {
        Ok(self.param.clone())
    }
    fn read_block_head(&self, blk_heihgt: Height) -> Result<BlockHead> {
        let data = self
            .block_head_db
            .get(blk_heihgt.to_le_bytes())?
            .context("failed to read block head")?;
        Ok(bincode::deserialize::<BlockHead>(&data[..])?)
    }
    fn read_block_content(&self, blk_height: Height) -> Result<BlockContent> {
        let data = self
            .block_content_db
            .get(blk_height.to_le_bytes())?
            .context("failed to read block content")?;
        Ok(bincode::deserialize::<BlockContent>(&data[..])?)
    }
    fn read_id_tree_node(&self, id_tree_node_id: IdTreeNodeId) -> Result<IdTreeNode> {
        let data = self
            .id_tree_db
            .get(id_tree_node_id.to_le_bytes())?
            .context("failed to read id tree node")?;
        Ok(bincode::deserialize::<IdTreeNode>(&data[..])?)
    }
    fn read_bplus_tree_node(
        &self,
        bplus_tree_node_id: BPlusTreeNodeId,
    ) -> Result<BPlusTreeNode<Self::K>> {
        let data = self
            .bplus_tree_db
            .get(bplus_tree_node_id.to_le_bytes())?
            .with_context(|| {
                format!(
                    "failed to read bplus tree node with id {:?}",
                    bplus_tree_node_id
                )
            })?;
        Ok(bincode::deserialize::<BPlusTreeNode<Self::K>>(&data[..])?)
    }
    fn read_trie_node(&self, trie_node_id: TrieNodeId) -> Result<TrieNode> {
        let data = self
            .trie_db
            .get(trie_node_id.to_le_bytes())?
            .context("failed to read trie node")?;
        Ok(bincode::deserialize::<TrieNode>(&data[..])?)
    }
    fn read_object(&self, obj_hash: Digest) -> Result<Object<Self::K>> {
        let data = self
            .obj_db
            .get(obj_hash.as_bytes())?
            .context("failed to read object")?;
        Ok(bincode::deserialize::<Object<Self::K>>(&data[..])?)
    }
}

impl ReadInterface for &mut SimChain {
    type K = u32;
    fn get_parameter(&self) -> Result<Parameter> {
        Ok(self.param.clone())
    }
    fn read_block_head(&self, blk_heihgt: Height) -> Result<BlockHead> {
        let data = self
            .block_head_db
            .get(blk_heihgt.to_le_bytes())?
            .context("failed to read block head")?;
        Ok(bincode::deserialize::<BlockHead>(&data[..])?)
    }
    fn read_block_content(&self, blk_height: Height) -> Result<BlockContent> {
        let data = self
            .block_content_db
            .get(blk_height.to_le_bytes())?
            .context("failed to read block content")?;
        Ok(bincode::deserialize::<BlockContent>(&data[..])?)
    }
    fn read_id_tree_node(&self, id_tree_node_id: IdTreeNodeId) -> Result<IdTreeNode> {
        let data = self
            .id_tree_db
            .get(id_tree_node_id.to_le_bytes())?
            .context("failed to read id tree node")?;
        Ok(bincode::deserialize::<IdTreeNode>(&data[..])?)
    }
    fn read_bplus_tree_node(
        &self,
        bplus_tree_node_id: BPlusTreeNodeId,
    ) -> Result<BPlusTreeNode<Self::K>> {
        let data = self
            .bplus_tree_db
            .get(bplus_tree_node_id.to_le_bytes())?
            .with_context(|| {
                format!(
                    "failed to read bplus tree node with id {:?}",
                    bplus_tree_node_id
                )
            })?;
        Ok(bincode::deserialize::<BPlusTreeNode<Self::K>>(&data[..])?)
    }
    fn read_trie_node(&self, trie_node_id: TrieNodeId) -> Result<TrieNode> {
        let data = self
            .trie_db
            .get(trie_node_id.to_le_bytes())?
            .context("failed to read trie node")?;
        Ok(bincode::deserialize::<TrieNode>(&data[..])?)
    }
    fn read_object(&self, obj_hash: Digest) -> Result<Object<Self::K>> {
        let data = self
            .obj_db
            .get(obj_hash.as_bytes())?
            .context("failed to read object")?;
        Ok(bincode::deserialize::<Object<Self::K>>(&data[..])?)
    }
}

impl WriteInterface for SimChain {
    type K = u32;
    fn set_parameter(&mut self, param: &Parameter) -> Result<()> {
        self.param = param.clone();
        let data = serde_json::to_string_pretty(&self.param)?;
        fs::write(self.root_path.join("param.json"), data)?;
        Ok(())
    }
    fn write_block_head(&mut self, blk_height: Height, block_head: &BlockHead) -> Result<()> {
        let bytes = bincode::serialize(block_head)?;
        self.block_head_db.put(blk_height.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_block_content(
        &mut self,
        blk_height: Height,
        block_content: &BlockContent,
    ) -> Result<()> {
        let bytes = bincode::serialize(block_content)?;
        self.block_content_db.put(blk_height.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_id_tree_node(&mut self, n_id: IdTreeNodeId, node: &IdTreeNode) -> Result<()> {
        let bytes = bincode::serialize(node)?;
        self.id_tree_db.put(n_id.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_bplus_tree_node(
        &mut self,
        n_id: BPlusTreeNodeId,
        node: &BPlusTreeNode<Self::K>,
    ) -> Result<()> {
        let bytes = bincode::serialize(node)?;
        self.bplus_tree_db.put(n_id.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_trie_node(&mut self, n_id: TrieNodeId, node: &TrieNode) -> Result<()> {
        let bytes = bincode::serialize(node)?;
        self.trie_db.put(n_id.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_object(&mut self, obj_hash: Digest, obj: &Object<Self::K>) -> Result<()> {
        let bytes = bincode::serialize(obj)?;
        self.obj_db.put(obj_hash.as_bytes(), bytes)?;
        Ok(())
    }
}

impl WriteInterface for &mut SimChain {
    type K = u32;
    fn set_parameter(&mut self, param: &Parameter) -> Result<()> {
        self.param = param.clone();
        let data = serde_json::to_string_pretty(&self.param)?;
        fs::write(self.root_path.join("param.json"), data)?;
        Ok(())
    }
    fn write_block_head(&mut self, blk_height: Height, block_head: &BlockHead) -> Result<()> {
        let bytes = bincode::serialize(block_head)?;
        self.block_head_db.put(blk_height.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_block_content(
        &mut self,
        blk_height: Height,
        block_content: &BlockContent,
    ) -> Result<()> {
        let bytes = bincode::serialize(block_content)?;
        self.block_content_db.put(blk_height.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_id_tree_node(&mut self, n_id: IdTreeNodeId, node: &IdTreeNode) -> Result<()> {
        let bytes = bincode::serialize(node)?;
        self.id_tree_db.put(n_id.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_bplus_tree_node(
        &mut self,
        n_id: BPlusTreeNodeId,
        node: &BPlusTreeNode<Self::K>,
    ) -> Result<()> {
        let bytes = bincode::serialize(node)?;
        self.bplus_tree_db.put(n_id.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_trie_node(&mut self, n_id: TrieNodeId, node: &TrieNode) -> Result<()> {
        let bytes = bincode::serialize(node)?;
        self.trie_db.put(n_id.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_object(&mut self, obj_hash: Digest, obj: &Object<Self::K>) -> Result<()> {
        let bytes = bincode::serialize(obj)?;
        self.obj_db.put(obj_hash.as_bytes(), bytes)?;
        Ok(())
    }
}

impl ScanQueryInterface for &SimChain {
    type K = u32;
    fn range_query(
        &self,
        query: Range<Self::K>,
        start_blk_height: Height,
        end_blk_height: Height,
        dim: usize,
    ) -> Result<HashSet<Digest>> {
        let mut res = HashSet::<Digest>::new();
        let db_iter = self.obj_db.iterator(rocksdb::IteratorMode::Start);
        for (_key, val) in db_iter {
            let o = bincode::deserialize::<Object<u32>>(&val[..])?;
            if o.blk_height <= end_blk_height && o.blk_height >= start_blk_height {
                let o_num_val = if let Some(n) = o.num_data.get(dim) {
                    *n
                } else {
                    0
                };
                if query.is_in_range(o_num_val) {
                    res.insert(o.to_digest());
                }
            }
        }
        Ok(res)
    }

    fn keyword_query(
        &self,
        keyword: &str,
        start_blk_height: Height,
        end_blk_height: Height,
    ) -> Result<HashSet<Digest>> {
        let mut res = HashSet::<Digest>::new();
        let db_iter = self.obj_db.iterator(rocksdb::IteratorMode::Start);
        for (_key, val) in db_iter {
            let o = bincode::deserialize::<Object<u32>>(&val[..])?;
            if o.blk_height <= end_blk_height && o.blk_height >= start_blk_height {
                for k in o.keyword_data.iter() {
                    if keyword == k {
                        res.insert(o.to_digest());
                    }
                }
            }
        }
        Ok(res)
    }

    fn root_query(&self, height: Height, win_size: u16) -> Result<HashSet<Digest>> {
        let mut res = HashSet::<Digest>::new();
        let db_iter = self.obj_db.iterator(rocksdb::IteratorMode::Start);
        for (_key, val) in db_iter {
            let o = bincode::deserialize::<Object<u32>>(&val[..])?;
            if o.blk_height <= height && o.blk_height.0 + win_size as u32 >= height.0 + 1 {
                res.insert(o.to_digest());
            }
        }
        Ok(res)
    }

    #[allow(clippy::type_complexity)]
    fn get_range_info(
        &self,
        start_blk_height: Height,
        end_blk_height: Height,
        dim_num: usize,
    ) -> Result<Vec<Range<Self::K>>> {
        let mut num_ranges = Vec::<Range<Self::K>>::new();
        let db_iter = self.obj_db.iterator(rocksdb::IteratorMode::Start);
        let mut num_range_scope = Vec::<(Self::K, Self::K)>::new();
        for _ in 0..dim_num {
            num_range_scope.push((std::u32::MAX, 0));
        }
        for (_key, val) in db_iter {
            let o = bincode::deserialize::<Object<u32>>(&val[..])?;
            if o.blk_height <= end_blk_height && o.blk_height >= start_blk_height {
                let o_num_vals = o.num_data;
                for (i, num_val) in o_num_vals.iter().enumerate() {
                    if i < dim_num {
                        let lower_bound = &num_range_scope
                            .get(i)
                            .with_context(|| {
                                format!("Object does not have numerical value at dim {}", i)
                            })?
                            .0;
                        let upper_bound = &num_range_scope
                            .get(i)
                            .with_context(|| {
                                format!("Object does not have numerical value at dim {}", i)
                            })?
                            .1;
                        if num_val < lower_bound {
                            num_range_scope
                                .get_mut(i)
                                .with_context(|| {
                                    format!("Object does not have numerical value at dim {}", i)
                                })?
                                .0 = *num_val;
                        } else if num_val > upper_bound {
                            num_range_scope
                                .get_mut(i)
                                .with_context(|| {
                                    format!("Object does not have numerical value at dim {}", i)
                                })?
                                .1 = *num_val;
                        }
                    }
                }
            }
        }

        for (min, max) in num_range_scope {
            num_ranges.push(Range::new(min, max));
        }

        Ok(num_ranges)
    }

    fn get_keyword_info(
        &self,
        start_blk_height: Height,
        end_blk_height: Height,
    ) -> Result<HashSet<String>> {
        let mut res = HashSet::<String>::new();
        let db_iter = self.obj_db.iterator(rocksdb::IteratorMode::Start);
        for (_key, val) in db_iter {
            let o = bincode::deserialize::<Object<u32>>(&val[..])?;
            if o.blk_height < end_blk_height && o.blk_height > start_blk_height {
                for k in o.keyword_data.iter() {
                    res.insert(k.to_string());
                }
            }
        }
        Ok(res)
    }
    fn get_chain_info(&self) -> Result<(u32, u32)> {
        let db_iter = self.obj_db.iterator(rocksdb::IteratorMode::Start);
        let mut cur_height_num = 0;
        let mut total_num = 0;
        for (_key, val) in db_iter {
            let o = bincode::deserialize::<Object<u32>>(&val[..])?;
            if cur_height_num < o.blk_height.0 {
                cur_height_num = o.blk_height.0;
            }
            total_num += 1;
        }
        Ok((total_num, cur_height_num))
    }
}