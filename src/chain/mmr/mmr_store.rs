use crate::chain::mmr::error::Result;
use std::collections::HashMap;
use std::vec::Vec;

#[derive(Default)]
pub struct MMRBatch<Elem, Store> {
    memory_batch: Vec<(u64, Vec<Elem>)>,
    store: Store,
}

impl<Elem, Store> MMRBatch<Elem, Store> {
    pub fn new(store: Store) -> Self {
        MMRBatch {
            memory_batch: Vec::new(),
            store,
        }
    }

    pub fn append(&mut self, pos: u64, elems: Vec<Elem>) {
        self.memory_batch.push((pos, elems));
    }

    pub fn store(&self) -> &Store {
        &self.store
    }
}

impl<Elem: Clone, Store: MMRStoreReadOps<Elem>> MMRBatch<Elem, Store> {
    pub fn get_elem(&self, pos: u64) -> Result<Option<Elem>> {
        for (start_pos, elems) in self.memory_batch.iter().rev() {
            if pos < *start_pos {
                continue;
            } else if pos < start_pos + elems.len() as u64 {
                return Ok(elems.get((pos - start_pos) as usize).cloned());
            } else {
                break;
            }
        }
        self.store.get_elem(pos)
    }
}

impl<Elem, Store: MMRStoreWriteOps<Elem>> MMRBatch<Elem, Store> {
    pub fn commit(&mut self) -> Result<()> {
        for (pos, elems) in self.memory_batch.drain(..) {
            self.store.append(pos, elems)?;
        }
        Ok(())
    }
}

impl<Elem, Store> IntoIterator for MMRBatch<Elem, Store> {
    type Item = (u64, Vec<Elem>);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.memory_batch.into_iter()
    }
}

pub trait MMRStoreReadOps<Elem> {
    fn get_elem(&self, pos: u64) -> Result<Option<Elem>>;
}

pub trait MMRStoreWriteOps<Elem> {
    fn append(&mut self, pos: u64, elems: Vec<Elem>) -> Result<()>;
}

// ============================================================================
// 内存存储实现 - 用于测试和轻量级场景
// ============================================================================

/// 内存存储实现
///
/// 使用 HashMap 存储 MMR 节点，适用于：
/// - 单元测试
/// - 集成测试
/// - 临时/短期存储场景
///
/// ## 使用示例
///
/// ```ignore
/// use vchain_plus::chain::mmr::{MMR, BlockADSMerge, MemStore};
/// use vchain_plus::digest::Digest;
///
/// let store = MemStore::<Digest>::default();
/// let mut mmr: MMR<Digest, BlockADSMerge, _> = MMR::new(0, store);
/// ```
#[derive(Debug, Clone, Default)]
pub struct MemStore<Elem> {
    data: HashMap<u64, Elem>,
}

impl<Elem> MemStore<Elem> {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    /// 获取存储的元素数量
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// 检查存储是否为空
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<Elem: Clone> MMRStoreReadOps<Elem> for MemStore<Elem> {
    fn get_elem(&self, pos: u64) -> Result<Option<Elem>> {
        Ok(self.data.get(&pos).cloned())
    }
}

impl<Elem: Clone> MMRStoreWriteOps<Elem> for MemStore<Elem> {
    fn append(&mut self, pos: u64, elems: Vec<Elem>) -> Result<()> {
        for (i, elem) in elems.into_iter().enumerate() {
            self.data.insert(pos + i as u64, elem);
        }
        Ok(())
    }
}

// 为可变引用实现 trait
impl<Elem: Clone> MMRStoreReadOps<Elem> for &MemStore<Elem> {
    fn get_elem(&self, pos: u64) -> Result<Option<Elem>> {
        Ok(self.data.get(&pos).cloned())
    }
}

impl<Elem: Clone> MMRStoreReadOps<Elem> for &mut MemStore<Elem> {
    fn get_elem(&self, pos: u64) -> Result<Option<Elem>> {
        Ok(self.data.get(&pos).cloned())
    }
}

impl<Elem: Clone> MMRStoreWriteOps<Elem> for &mut MemStore<Elem> {
    fn append(&mut self, pos: u64, elems: Vec<Elem>) -> Result<()> {
        for (i, elem) in elems.into_iter().enumerate() {
            self.data.insert(pos + i as u64, elem);
        }
        Ok(())
    }
}