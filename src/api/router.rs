//! 路由装配
//!
//! 把所有 handler 注册到统一的 Router，
//! 挂上 CORS 中间件（允许前端跨域），
//! 注入共享 `AppState`。

use crate::api::{handlers, state::AppState};
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

/// 构建完整的 API Router
///
/// # 参数
/// - `state`: 共享应用状态
///
/// # 返回
/// 装配好中间件和所有端点的 Router
pub fn build_router(state: Arc<AppState>) -> Router {
    // CORS: 允许所有源（demo 用；生产要收紧）
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // 健康检查
        .route("/api/health", get(handlers::health))
        // 链元信息
        .route("/api/chain/info", get(handlers::get_chain_info))
        .route("/api/chain/params", get(handlers::get_chain_params))
        // 区块浏览
        .route("/api/blocks", get(handlers::list_blocks))
        .route("/api/block/:height", get(handlers::get_block))
        .route(
            "/api/block/:height/objects",
            get(handlers::get_block_objects),
        )
        // 可验证查询
        .route("/api/query", post(handlers::execute_query))
        .route("/api/query/verify", post(handlers::verify_query))
        // 两层式证明（创新点 2）
        .route("/api/block/:height/proof", get(handlers::get_block_proof))
        .route("/api/proof/verify", post(handlers::verify_two_layer_proof))
        // 中间件
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        // 注入共享状态
        .with_state(state)
}
