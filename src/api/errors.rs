//! API 错误类型
//!
//! 统一所有处理函数的错误返回：
//! - `NotFound`：请求的资源（区块、对象）不存在 → HTTP 404
//! - `BadRequest`：请求参数校验失败 → HTTP 400
//! - `Internal`：内部执行错误（查询失败、验证失败等）→ HTTP 500
//!
//! 所有错误都会以统一的 JSON 结构返回：
//! ```json
//! { "error": { "code": "NOT_FOUND", "message": "Block 999 not found" } }
//! ```

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// API 统一错误类型
#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    BadRequest(String),
    Internal(anyhow::Error),
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, "NOT_FOUND", m),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", m),
            ApiError::Internal(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                format!("{:#}", e),
            ),
        };
        let body = ErrorBody {
            error: ErrorDetail { code, message },
        };
        (status, Json(body)).into_response()
    }
}

/// 允许 `?` 运算符从 `anyhow::Error` 自动转换
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e)
    }
}
