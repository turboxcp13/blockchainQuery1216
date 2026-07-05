//! Web API 服务层
//!
//! 将 vchain_plus 核心库包装为 REST API，供前端使用。
//!
//! # 架构
//! ```text
//! Vue 前端 <--HTTP/JSON--> Axum API 层 <--Rust 调用--> vchain_plus 核心库
//!                              ↓
//!                          AppState (Arc<SimChain>, Arc<AccPublicKey>)
//! ```
//!
//! # 端点分组
//! - `/api/chain/*` - 链元信息
//! - `/api/blocks`, `/api/block/:height/*` - 区块浏览
//! - `/api/query`, `/api/query/verify` - 可验证查询
//! - `/api/block/:height/proof`, `/api/proof/verify` - 两层式证明
//! - `/api/health` - 健康检查

pub mod errors;
pub mod handlers;
pub mod models;
pub mod router;
pub mod state;

pub use router::build_router;
pub use state::AppState;
