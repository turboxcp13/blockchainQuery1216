//! API 应用共享状态
//!
//! 存放 API 服务运行时需要跨请求共享的对象：
//! - `SimChain`：已打开的区块链数据库（读操作可并发）
//! - `AccPublicKey`：累加器公钥（只读，大对象，共享减少内存占用）
//!
//! 都用 `Arc` 包装以便克隆到各请求处理函数中。

use crate::{acc::AccPublicKey, SimChain};
use std::{path::PathBuf, sync::Arc};

/// 全局应用状态，跨请求共享
#[derive(Clone)]
pub struct AppState {
    /// 已打开的链数据库（读操作线程安全）
    pub chain: Arc<SimChain>,
    /// 累加器公钥
    pub pk: Arc<AccPublicKey>,
    /// 链数据库路径（用于展示）
    pub chain_path: PathBuf,
    /// 密钥路径（用于展示）
    pub key_path: PathBuf,
}

impl AppState {
    pub fn new(
        chain: SimChain,
        pk: AccPublicKey,
        chain_path: PathBuf,
        key_path: PathBuf,
    ) -> Self {
        Self {
            chain: Arc::new(chain),
            pk: Arc::new(pk),
            chain_path,
            key_path,
        }
    }
}
