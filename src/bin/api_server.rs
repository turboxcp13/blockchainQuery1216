//! # vchain-plus API 服务器
//!
//! 启动一个 HTTP 服务，把 `vchain_plus` 库的能力对外暴露成 REST API。
//!
//! ## 用法
//!
//! 首先需要已经通过 `gen_key` 和 `build_chain` 生成好密钥和链数据，
//! 然后启动 API 服务：
//!
//! ```powershell
//! .\target\release\api_server.exe `
//!   -k D:\vchain-plus-master\output\pk_eth.key `
//!   -c D:\vchain-plus-master\output\db_eth `
//!   -p 3000
//! ```
//!
//! 打开浏览器访问 http://localhost:3000/api/health 应看到 `{"status":"ok",...}`。

#[macro_use]
extern crate tracing;

use anyhow::{Context, Result};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use structopt::StructOpt;
use vchain_plus::{
    api::{build_router, AppState},
    utils::{init_tracing_subscriber, KeyPair},
    SimChain,
};

#[derive(StructOpt, Debug)]
#[structopt(
    name = "api_server",
    about = "vchain-plus REST API server for verifiable blockchain query"
)]
struct Opt {
    /// 公钥路径（gen_key 输出的目录）
    #[structopt(short = "k", long, parse(from_os_str))]
    key_path: PathBuf,

    /// 链数据库路径（build_chain 输出的目录）
    #[structopt(short = "c", long, parse(from_os_str))]
    chain_path: PathBuf,

    /// 监听端口，默认 3000
    #[structopt(short = "p", long, default_value = "3000")]
    port: u16,

    /// 监听地址，默认 127.0.0.1（仅本地）；改成 0.0.0.0 可局域网访问
    #[structopt(long, default_value = "127.0.0.1")]
    host: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志（默认 info 级别，可通过 RUST_LOG 环境变量覆盖）
    init_tracing_subscriber(
        "api_server=info,vchain_plus::api=info,vchain_plus::chain=warn,tower_http=info",
    )?;

    let opt = Opt::from_args();

    // 1. 打开链数据库
    info!("Opening chain database at {:?}", opt.chain_path);
    let chain = SimChain::open(&opt.chain_path)
        .with_context(|| format!("failed to open chain at {:?}", opt.chain_path))?;
    let (obj_count, max_height) = {
        use vchain_plus::chain::traits::ScanQueryInterface;
        (&chain).get_chain_info()?
    };
    info!(
        "Chain loaded: {} objects, max_height = {}, mmr_size = {}",
        obj_count,
        max_height,
        chain.get_mmr_size()
    );

    // 2. 加载公钥
    info!("Loading public key from {:?}", opt.key_path);
    let pk = KeyPair::load(&opt.key_path)
        .with_context(|| format!("failed to load key at {:?}", opt.key_path))?
        .pk;
    info!("Public key loaded");

    // 3. 构建应用状态
    let state = Arc::new(AppState::new(
        chain,
        pk,
        opt.chain_path.clone(),
        opt.key_path.clone(),
    ));

    // 4. 构建路由
    let app = build_router(state);

    // 5. 启动服务
    let addr: SocketAddr = format!("{}:{}", opt.host, opt.port)
        .parse()
        .with_context(|| format!("invalid host/port: {}:{}", opt.host, opt.port))?;

    info!("╔════════════════════════════════════════════════════════════╗");
    info!("║  vchain-plus API server                                    ║");
    info!("║                                                            ║");
    info!("║  Listening on http://{}                        ║", addr);
    info!("║  Try: curl http://{}/api/health                ║", addr);
    info!("╚════════════════════════════════════════════════════════════╝");

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    info!("Server shut down gracefully");
    Ok(())
}

/// 监听 Ctrl+C 信号实现优雅关闭
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    info!("Received shutdown signal");
}
