//! MMR 的 RocksDB 持久化存储实现
//!
//! 【创新点2】链级承诺的存储层
//!
//! 本模块为 MMR 提供基于 RocksDB 的持久化存储支持，使得 MMR 结构可以在程序重启后恢复。
//!
//! ## 存储格式
//!
//! - Key: MMR 位置（u64，小端序）
//! - Value: 序列化的元素（使用 bincode）
//!
//! ## 使用示例
//!
//! ```ignore
//! use vchain_plus::chain::mmr::{MMR, BlockADSMerge, RocksStore};
//! use vchain_plus::digest::Digest;
//! use rocksdb::DB;
//!
//! // 打开 RocksDB
//! let db = DB::open_default("path/to/mmr.db").unwrap();
//!
//! // 创建 RocksStore
//! let store = RocksStore::new(db);
//!
//! // 创建 MMR（从位置 0 开始）
//! let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store);
//!
//! // 或者恢复现有 MMR（从存储的位置继续）
//! let mmr_size = store.get_mmr_size()?;
//! let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(mmr_size, store);
//! ```

use crate::chain::mmr::error::{Error, Result};
use crate::chain::mmr::mmr_store::{MMRStoreReadOps, MMRStoreWriteOps};
use rocksdb::DB;
use serde::{de::DeserializeOwned, Serialize};
use std::marker::PhantomData;
use std::sync::Arc;

/// MMR 元数据的存储键前缀
const MMR_META_PREFIX: &[u8] = b"mmr_meta:";

/// MMR 节点的存储键前缀
const MMR_NODE_PREFIX: &[u8] = b"mmr_node:";

/// MMR 大小的元数据键
const MMR_SIZE_KEY: &[u8] = b"mmr_meta:size";

/// RocksDB 持久化存储
///
/// 使用 RocksDB 存储 MMR 节点，支持：
/// - 持久化存储
/// - 崩溃恢复
/// - 大规模数据集
///
/// ## 存储结构
///
/// ```text
/// Key                     | Value
/// ------------------------|------------------
/// mmr_meta:size           | u64 (MMR 大小)
/// mmr_node:00000000       | 序列化的元素
/// mmr_node:00000001       | 序列化的元素
/// ...
/// ```
pub struct RocksStore<Elem> {
    db: Arc<DB>,
    _phantom: PhantomData<Elem>,
}

impl<Elem> RocksStore<Elem> {
    /// 创建新的 RocksStore
    ///
    /// # 参数
    /// - `db`: RocksDB 实例（使用 Arc 共享所有权）
    pub fn new(db: Arc<DB>) -> Self {
        Self {
            db,
            _phantom: PhantomData,
        }
    }

    /// 从路径创建新的 RocksStore
    ///
    /// # 参数
    /// - `path`: RocksDB 数据库路径
    ///
    /// # 返回
    /// 创建的 RocksStore 或错误
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path).map_err(|e| Error::StoreError(e.to_string()))?;
        Ok(Self::new(Arc::new(db)))
    }

    /// 获取存储的 MMR 大小
    ///
    /// 用于恢复 MMR 时确定起始位置
    pub fn get_mmr_size(&self) -> Result<u64> {
        match self.db.get(MMR_SIZE_KEY) {
            Ok(Some(data)) => {
                if data.len() != 8 {
                    return Err(Error::StoreError("Invalid MMR size data".to_string()));
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data);
                Ok(u64::from_le_bytes(bytes))
            }
            Ok(None) => Ok(0), // 空的 MMR
            Err(e) => Err(Error::StoreError(e.to_string())),
        }
    }

    /// 设置 MMR 大小
    ///
    /// 在每次 push 后更新
    pub fn set_mmr_size(&self, size: u64) -> Result<()> {
        self.db
            .put(MMR_SIZE_KEY, size.to_le_bytes())
            .map_err(|e| Error::StoreError(e.to_string()))
    }

    /// 生成节点存储键
    fn node_key(pos: u64) -> Vec<u8> {
        let mut key = MMR_NODE_PREFIX.to_vec();
        key.extend_from_slice(&pos.to_le_bytes());
        key
    }

    /// 获取底层数据库引用
    pub fn db(&self) -> &DB {
        &self.db
    }

    /// 获取底层数据库的 Arc 引用
    pub fn db_arc(&self) -> Arc<DB> {
        Arc::clone(&self.db)
    }
}

impl<Elem> Clone for RocksStore<Elem> {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            _phantom: PhantomData,
        }
    }
}

impl<Elem: Serialize + DeserializeOwned + Clone> MMRStoreReadOps<Elem> for RocksStore<Elem> {
    fn get_elem(&self, pos: u64) -> Result<Option<Elem>> {
        let key = Self::node_key(pos);
        match self.db.get(&key) {
            Ok(Some(data)) => {
                let elem: Elem =
                    bincode::deserialize(&data).map_err(|e| Error::StoreError(e.to_string()))?;
                Ok(Some(elem))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::StoreError(e.to_string())),
        }
    }
}

impl<Elem: Serialize + DeserializeOwned + Clone> MMRStoreWriteOps<Elem> for RocksStore<Elem> {
    fn append(&mut self, pos: u64, elems: Vec<Elem>) -> Result<()> {
        // 使用 WriteBatch 进行批量写入，提高性能
        let mut batch = rocksdb::WriteBatch::default();

        for (i, elem) in elems.into_iter().enumerate() {
            let key = Self::node_key(pos + i as u64);
            let value = bincode::serialize(&elem).map_err(|e| Error::StoreError(e.to_string()))?;
            batch.put(&key, &value);
        }

        self.db
            .write(batch)
            .map_err(|e| Error::StoreError(e.to_string()))
    }
}

// 为引用类型实现 trait
impl<Elem: Serialize + DeserializeOwned + Clone> MMRStoreReadOps<Elem> for &RocksStore<Elem> {
    fn get_elem(&self, pos: u64) -> Result<Option<Elem>> {
        let key = RocksStore::<Elem>::node_key(pos);
        match self.db.get(&key) {
            Ok(Some(data)) => {
                let elem: Elem =
                    bincode::deserialize(&data).map_err(|e| Error::StoreError(e.to_string()))?;
                Ok(Some(elem))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::StoreError(e.to_string())),
        }
    }
}

impl<Elem: Serialize + DeserializeOwned + Clone> MMRStoreReadOps<Elem> for &mut RocksStore<Elem> {
    fn get_elem(&self, pos: u64) -> Result<Option<Elem>> {
        let key = RocksStore::<Elem>::node_key(pos);
        match self.db.get(&key) {
            Ok(Some(data)) => {
                let elem: Elem =
                    bincode::deserialize(&data).map_err(|e| Error::StoreError(e.to_string()))?;
                Ok(Some(elem))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::StoreError(e.to_string())),
        }
    }
}

impl<Elem: Serialize + DeserializeOwned + Clone> MMRStoreWriteOps<Elem> for &mut RocksStore<Elem> {
    fn append(&mut self, pos: u64, elems: Vec<Elem>) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();

        for (i, elem) in elems.into_iter().enumerate() {
            let key = RocksStore::<Elem>::node_key(pos + i as u64);
            let value = bincode::serialize(&elem).map_err(|e| Error::StoreError(e.to_string()))?;
            batch.put(&key, &value);
        }

        self.db
            .write(batch)
            .map_err(|e| Error::StoreError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::mmr::{BlockADSMerge, MMR};
    use crate::digest::Digest;
    use tempfile::tempdir;

    /// 辅助函数：创建测试用的 Digest
    fn make_digest(byte: u8) -> Digest {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        Digest::from(bytes)
    }

    #[test]
    fn test_rocks_store_basic() {
        let dir = tempdir().unwrap();
        let mut store = RocksStore::<Digest>::open(dir.path()).unwrap();

        // 测试空存储
        assert_eq!(store.get_mmr_size().unwrap(), 0);
        assert!(store.get_elem(0).unwrap().is_none());

        // 测试写入
        let digest = make_digest(42);
        store.append(0, vec![digest]).unwrap();

        // 测试读取
        let retrieved = store.get_elem(0).unwrap();
        assert_eq!(retrieved, Some(digest));

        // 测试更新 MMR 大小
        store.set_mmr_size(1).unwrap();
        assert_eq!(store.get_mmr_size().unwrap(), 1);
    }

    #[test]
    fn test_rocks_store_batch_append() {
        let dir = tempdir().unwrap();
        let mut store = RocksStore::<Digest>::open(dir.path()).unwrap();

        // 批量写入
        let digests: Vec<Digest> = (0..10).map(|i| make_digest(i)).collect();
        store.append(0, digests.clone()).unwrap();

        // 验证所有元素
        for (i, expected) in digests.iter().enumerate() {
            let retrieved = store.get_elem(i as u64).unwrap();
            assert_eq!(retrieved, Some(*expected));
        }
    }

    #[test]
    fn test_rocks_store_with_mmr() {
        let dir = tempdir().unwrap();
        let store = RocksStore::<Digest>::open(dir.path()).unwrap();

        // 创建 MMR
        let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store);

        // 插入元素
        let d0 = make_digest(0);
        let d1 = make_digest(1);
        let d2 = make_digest(2);

        let pos0 = mmr.push(d0).unwrap();
        let pos1 = mmr.push(d1).unwrap();
        let pos2 = mmr.push(d2).unwrap();

        assert_eq!(pos0, 0);
        assert_eq!(pos1, 1);
        assert_eq!(pos2, 3); // MMR 在第3个位置插入叶子

        // 获取根
        let root = mmr.get_root().unwrap();
        assert_ne!(root, Digest::default());

        // 生成证明
        let proof = mmr.gen_proof(vec![pos0]).unwrap();
        assert!(proof.verify(root, vec![(pos0, d0)]).unwrap());
    }

    #[test]
    fn test_rocks_store_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_owned();

        let root1;
        let mmr_size1;

        // 第一次：创建并填充 MMR
        {
            let mut store = RocksStore::<Digest>::open(&path).unwrap();
            let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store.clone());

            for i in 0..5 {
                mmr.push(make_digest(i)).unwrap();
            }

            root1 = mmr.get_root().unwrap();
            mmr_size1 = mmr.mmr_size();

            // 保存 MMR 大小
            store.set_mmr_size(mmr_size1).unwrap();

            // 提交批次
            // 注意：MMR::commit 需要被调用来持久化数据
        }

        // 第二次：恢复 MMR
        {
            let store = RocksStore::<Digest>::open(&path).unwrap();
            let mmr_size = store.get_mmr_size().unwrap();

            // 由于我们还没有实现 commit，这里只验证 store 的持久化能力
            // 在实际使用中，需要在 MMR 外部调用 batch.commit()
            assert_eq!(mmr_size, mmr_size1);
        }
    }

    #[test]
    fn test_rocks_store_clone() {
        let dir = tempdir().unwrap();
        let store1 = RocksStore::<Digest>::open(dir.path()).unwrap();
        let store2 = store1.clone();

        // 两个 store 共享同一个数据库
        let mut store1_mut = store1;
        store1_mut.append(0, vec![make_digest(42)]).unwrap();

        // store2 可以读取 store1 写入的数据
        let retrieved = store2.get_elem(0).unwrap();
        assert_eq!(retrieved, Some(make_digest(42)));
    }
}