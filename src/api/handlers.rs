//! API 请求处理函数
//!
//! 每个函数对应一个 HTTP 端点，负责：
//! 1. 解析请求参数
//! 2. 调用核心库函数
//! 3. 转换结果到响应 DTO
//!
//! # 关键设计
//! - 查询/验证等 CPU 密集操作用 `tokio::task::spawn_blocking` 移出
//!   异步执行器，防止阻塞其他请求
//! - 所有对 `SimChain` 的访问都通过 `Arc::clone` 拿到只读引用

use crate::{
    api::{
        errors::ApiError,
        models::*,
        state::AppState,
    },
    chain::{
        block::{block_ads_root::BlockADSComponents, Height},
        mmr::{IndexProof, TwoLayerProof},
        query::query,
        traits::{ReadInterface, ScanQueryInterface},
        verify::verify,
    },
    SimChain,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use std::sync::Arc;

// ============================================================================
// GET /api/health
// ============================================================================

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "vchain-plus-api",
        version: env!("CARGO_PKG_VERSION"),
    })
}

// ============================================================================
// GET /api/chain/info
// ============================================================================

pub async fn get_chain_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ChainInfoResponse>, ApiError> {
    let chain_ref: &SimChain = &state.chain;
    let (total_objects, max_block_height) = chain_ref.get_chain_info()?;

    Ok(Json(ChainInfoResponse {
        total_objects,
        max_block_height,
        mmr_size: state.chain.get_mmr_size(),
        mmr_root: state.chain.get_mmr_root(),
        block_count: state.chain.get_mmr_block_count(),
        chain_path: state.chain_path.display().to_string(),
        key_path: state.key_path.display().to_string(),
    }))
}

// ============================================================================
// GET /api/chain/params
// ============================================================================

pub async fn get_chain_params(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ChainParamsResponse>, ApiError> {
    let chain_ref: &SimChain = &state.chain;
    let parameter = chain_ref.get_parameter()?;
    Ok(Json(ChainParamsResponse { parameter }))
}

// ============================================================================
// GET /api/blocks
// ============================================================================

pub async fn list_blocks(
    State(state): State<Arc<AppState>>,
    Query(q): Query<BlocksQuery>,
) -> Result<Json<BlocksResponse>, ApiError> {
    let chain_ref: &SimChain = &state.chain;
    let (_, max_height) = chain_ref.get_chain_info()?;

    if max_height == 0 {
        return Ok(Json(BlocksResponse {
            items: vec![],
            total: 0,
            page: 1,
            size: 0,
        }));
    }

    let start = q.start.unwrap_or(1).max(1);
    let end = q.end.unwrap_or(max_height).min(max_height);
    if start > end {
        return Err(ApiError::BadRequest(format!(
            "start ({}) must be <= end ({})",
            start, end
        )));
    }

    let page = q.page.unwrap_or(1).max(1);
    let size = q.size.unwrap_or(20).clamp(1, 100);

    let total = end - start + 1;
    let offset = (page - 1) * size;
    let page_end = (offset + size).min(total);

    if offset >= total {
        return Ok(Json(BlocksResponse {
            items: vec![],
            total,
            page,
            size,
        }));
    }

    let mut items = Vec::new();
    for i in offset..page_end {
        let h = Height(start + i);
        let head = chain_ref.read_block_head(h)?;
        items.push(BlockSummary {
            height: head.blk_height.0,
            ads_root: head.ads_root,
            prev_hash: head.prev_hash,
            obj_root_hash: head.obj_root_hash,
        });
    }

    Ok(Json(BlocksResponse {
        items,
        total,
        page,
        size,
    }))
}

// ============================================================================
// GET /api/block/:height
// ============================================================================

pub async fn get_block(
    State(state): State<Arc<AppState>>,
    Path(height): Path<u32>,
) -> Result<Json<BlockDetailResponse>, ApiError> {
    if height == 0 {
        return Err(ApiError::BadRequest(
            "block height must be >= 1".to_string(),
        ));
    }
    let chain_ref: &SimChain = &state.chain;
    let (_, max_height) = chain_ref.get_chain_info()?;
    if height > max_height {
        return Err(ApiError::NotFound(format!(
            "block {} not found (max height: {})",
            height, max_height
        )));
    }

    let h = Height(height);
    let head = chain_ref.read_block_head(h)?;
    let content = chain_ref.read_block_content(h)?;
    let components = content.get_ads_components();
    let bloom = content.get_bloom_filter();

    Ok(Json(BlockDetailResponse {
        height,
        ads_root: head.ads_root,
        prev_hash: head.prev_hash,
        obj_root_hash: head.obj_root_hash,
        ads_components: components_to_dto(components),
        object_count: content.obj_hashes.len(),
        bloom_enabled: bloom.size > 0,
        bloom_size: bloom.size as usize,
    }))
}

// ============================================================================
// GET /api/block/:height/objects
// ============================================================================

pub async fn get_block_objects(
    State(state): State<Arc<AppState>>,
    Path(height): Path<u32>,
) -> Result<Json<BlockObjectsResponse>, ApiError> {
    if height == 0 {
        return Err(ApiError::BadRequest(
            "block height must be >= 1".to_string(),
        ));
    }
    let chain_ref: &SimChain = &state.chain;
    let (_, max_height) = chain_ref.get_chain_info()?;
    if height > max_height {
        return Err(ApiError::NotFound(format!(
            "block {} not found (max height: {})",
            height, max_height
        )));
    }

    let h = Height(height);
    let content = chain_ref.read_block_content(h)?;
    let mut objects = Vec::with_capacity(content.obj_hashes.len());
    for obj_hash in &content.obj_hashes {
        let obj = chain_ref.read_object(*obj_hash)?;
        objects.push(obj);
    }

    Ok(Json(BlockObjectsResponse { height, objects }))
}

// ============================================================================
// POST /api/query
// ============================================================================

pub async fn execute_query(
    State(state): State<Arc<AppState>>,
    Json(req): Json<QueryRequest>,
) -> Result<Json<QueryResponse>, ApiError> {
    // 参数校验
    if req.start_blk == 0 || req.start_blk > req.end_blk {
        return Err(ApiError::BadRequest(format!(
            "invalid block range: [{}, {}]",
            req.start_blk, req.end_blk
        )));
    }
    if req.range.is_empty() {
        return Err(ApiError::BadRequest("range cannot be empty".to_string()));
    }
    for (i, r) in req.range.iter().enumerate() {
        if r[0] > r[1] {
            return Err(ApiError::BadRequest(format!(
                "range[{}] invalid: [{}, {}]",
                i, r[0], r[1]
            )));
        }
    }

    let query_param = req.to_query_param();
    let empty_set = req.empty_set;
    let egg_opt = req.egg_opt;
    let verify_thread_num = req.verify_thread_num.clamp(1, 32);

    let chain = Arc::clone(&state.chain);
    let pk = Arc::clone(&state.pk);

    // 查询 + 验证是 CPU 密集，放到 blocking 线程池
    let response = tokio::task::spawn_blocking(move || -> anyhow::Result<QueryResponse> {
        // 1. 执行查询
        let chain_ref: &SimChain = &chain;
        let (results, res_dag, query_time) =
            query(empty_set, egg_opt, chain_ref, query_param, &pk)?;

        // 2. 执行验证
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(verify_thread_num)
            .build()?;
        let verify_info = pool.install(|| verify(chain_ref, &results, &res_dag, &pk))?;

        // 3. 聚合各子结果的对象
        let mut all_objects = Vec::new();
        for (obj_map, _vo) in &results {
            for obj in obj_map.values() {
                all_objects.push(obj.clone());
            }
        }
        let total_matched = all_objects.len();

        Ok(QueryResponse {
            objects: all_objects,
            query_time,
            verify_time: verify_info.verify_time,
            vo_size: verify_info.vo_size,
            total_matched,
        })
    })
    .await
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("blocking task join failed: {}", e)))??;

    Ok(Json(response))
}

// ============================================================================
// POST /api/query/verify
//
// 说明：完整的 VO 序列化非常复杂（涉及 acc 类型和 petgraph::Graph 的
// 完整往返序列化）。为了 demo 简化，这个端点接收和 /api/query 相同的输入，
// 内部重跑查询然后验证。它的价值在于："给定同样的查询，可以独立触发
// verify 阶段并观察验证的 VO 大小和耗时"，可用于演示验证独立性。
// ============================================================================

pub async fn verify_query(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let query_param = req.to_query_param();
    let empty_set = req.empty_set;
    let egg_opt = req.egg_opt;
    let verify_thread_num = req.verify_thread_num.clamp(1, 32);

    let chain = Arc::clone(&state.chain);
    let pk = Arc::clone(&state.pk);

    let response = tokio::task::spawn_blocking(move || -> anyhow::Result<VerifyResponse> {
        let chain_ref: &SimChain = &chain;
        let (results, res_dag, _q_time) =
            query(empty_set, egg_opt, chain_ref, query_param, &pk)?;

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(verify_thread_num)
            .build()?;
        let verify_res = pool.install(|| verify(chain_ref, &results, &res_dag, &pk));

        match verify_res {
            Ok(info) => Ok(VerifyResponse {
                verify_time: Some(info.verify_time),
                vo_size: info.vo_size,
                passed: true,
                message: "verification passed".to_string(),
            }),
            Err(e) => Ok(VerifyResponse {
                verify_time: None,
                vo_size: crate::chain::verify::VOSize::new(0, 0, 0, 0, 0, 0),
                passed: false,
                message: format!("verification failed: {:#}", e),
            }),
        }
    })
    .await
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("blocking task join failed: {}", e)))??;

    Ok(Json(response))
}

// ============================================================================
// GET /api/block/:height/proof?type=<id_tree|bplus_tree|trie>
// ============================================================================

pub async fn get_block_proof(
    State(state): State<Arc<AppState>>,
    Path(height): Path<u32>,
    Query(q): Query<ProofQuery>,
) -> Result<Json<TwoLayerProofResponse>, ApiError> {
    if height == 0 {
        return Err(ApiError::BadRequest(
            "block height must be >= 1".to_string(),
        ));
    }
    let chain = Arc::clone(&state.chain);
    let proof_type = q.proof_type.clone();
    let dimension = q.dimension;
    let time_window = q.time_window;

    let proof = tokio::task::spawn_blocking(move || -> anyhow::Result<TwoLayerProof> {
        let h = Height(height);
        match proof_type.as_str() {
            "id_tree" => chain.gen_two_layer_proof_with_id_tree(h),
            "bplus_tree" => {
                let d = dimension.ok_or_else(|| {
                    anyhow::anyhow!("bplus_tree proof requires ?dimension=<u8>")
                })?;
                let tw = time_window.ok_or_else(|| {
                    anyhow::anyhow!("bplus_tree proof requires ?time_window=<u16>")
                })?;
                chain.gen_two_layer_proof_with_bplus_tree(h, d, tw)
            }
            "trie" => {
                let tw = time_window
                    .ok_or_else(|| anyhow::anyhow!("trie proof requires ?time_window=<u16>"))?;
                chain.gen_two_layer_proof_with_trie(h, tw)
            }
            other => Err(anyhow::anyhow!(
                "unknown proof type: {} (expected: id_tree | bplus_tree | trie)",
                other
            )),
        }
    })
    .await
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("blocking task join failed: {}", e)))??;

    // 构建响应 DTO
    let full_proof = serde_json::to_value(&proof)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize proof: {}", e)))?;

    let response = TwoLayerProofResponse {
        mmr: MmrProofDto {
            mmr_size: proof.mmr_proof.mmr_size,
            position: proof.mmr_proof.position,
            block_ads_root: proof.mmr_proof.block_ads_root,
            proof_items_count: proof.mmr_proof.proof_items.len(),
        },
        block: BlockProofDto {
            block_height: proof.block_proof.block_height.0,
            components: components_to_dto(&proof.block_proof.components),
        },
        index_proof_type: match &proof.block_proof.index_proof {
            Some(IndexProof::IdTree { .. }) => "id_tree".to_string(),
            Some(IndexProof::BPlusTree { .. }) => "bplus_tree".to_string(),
            Some(IndexProof::Trie { .. }) => "trie".to_string(),
            Some(_) => "composite".to_string(),
            None => "none".to_string(),
        },
        full_proof,
    };

    Ok(Json(response))
}

// ============================================================================
// POST /api/proof/verify
// ============================================================================

pub async fn verify_two_layer_proof(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProofVerifyRequest>,
) -> Result<Json<ProofVerifyResponse>, ApiError> {
    let proof: TwoLayerProof = serde_json::from_value(req.proof)
        .map_err(|e| ApiError::BadRequest(format!("invalid proof: {}", e)))?;

    let chain = Arc::clone(&state.chain);

    let response =
        tokio::task::spawn_blocking(move || -> anyhow::Result<ProofVerifyResponse> {
            let start = std::time::Instant::now();
            let result = chain.verify_two_layer_proof(&proof);
            let elapsed = start.elapsed().as_micros();
            match result {
                Ok(true) => Ok(ProofVerifyResponse {
                    passed: true,
                    message: "two-layer proof verified".to_string(),
                    verify_time_us: elapsed,
                }),
                Ok(false) => Ok(ProofVerifyResponse {
                    passed: false,
                    message: "two-layer proof rejected".to_string(),
                    verify_time_us: elapsed,
                }),
                Err(e) => Ok(ProofVerifyResponse {
                    passed: false,
                    message: format!("verification error: {:#}", e),
                    verify_time_us: elapsed,
                }),
            }
        })
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("blocking task join failed: {}", e)))??;

    Ok(Json(response))
}

// ============================================================================
// 辅助函数
// ============================================================================

fn components_to_dto(c: &BlockADSComponents) -> AdsComponentsDto {
    AdsComponentsDto {
        id_set_root_hash: c.id_set_root_hash,
        id_tree_root_hash: c.id_tree_root_hash,
        multi_ads_hash: c.multi_ads_hash,
        bloom_root_hash: c.bloom_root_hash,
    }
}
