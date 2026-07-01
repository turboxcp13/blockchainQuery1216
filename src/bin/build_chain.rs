#[macro_use]
extern crate tracing;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use vchain_plus::utils::{init_tracing_subscriber, KeyPair};
use vchain_plus::{
    chain::{
        block::{build::build_block_with_mmr, Height},  // 修改：使用 build_block_with_mmr
        object::Object,
        traits::WriteInterface,
        Parameter,
    },
    digest::{Digest, Digestible},
    utils::{load_raw_obj_from_file, Time},
    SimChain,
};

#[derive(StructOpt, Debug)]
struct Opt {
    /// time windows
    #[structopt(short, long)]
    time_win_sizes: Vec<u16>,

    /// id tree fanout
    #[structopt(long)]
    id_fanout: u8,

    /// max id num
    #[structopt(short, long)]
    max_id: u16,

    /// bplus tree fanout
    #[structopt(short, long)]
    bplus_fanout: u8,

    /// dimension
    #[structopt(short, long)]
    dim: u8,

    /// 【方案 X】启用块级自适应 Bloom 过滤器（默认关闭，保持 Paper A 兼容）
    ///
    /// 跑方案 X 实验时加上 `--enable-bloom`；跑 Paper A 对照实验时省略。
    #[structopt(long)]
    enable_bloom: bool,

    /// key path
    #[structopt(short, long, parse(from_os_str))]
    key_path: PathBuf,

    /// input path, should be a file
    #[structopt(short, long, parse(from_os_str))]
    input: PathBuf,

    /// result path, should be a file
    #[structopt(short, long, parse(from_os_str))]
    result: PathBuf,

    /// output path, should be a directory
    #[structopt(short, long, parse(from_os_str))]
    output: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct BuildTime {
    blk_height: Height,
    build_time: Time,
    // 【创新点2】新增 MMR 相关信息
    mmr_pos: u64,
}

fn build_chain(
    data_path: &Path,
    key_path: &Path,
    db_path: &Path,
    res_path: &Path,
    param: &Parameter,
) -> Result<()> {
    if db_path.exists() {
        fs::remove_dir_all(db_path)?;
    }
    fs::create_dir_all(db_path)?;
    let mut chain = SimChain::create(db_path, param.clone())?;
    chain.set_parameter(param)?;
    let mut prev_hash = Digest::zero();
    let raw_objs: BTreeMap<Height, Vec<Object<u32>>> = load_raw_obj_from_file(data_path)?;
    let timer = howlong::ProcessCPUTimer::new();
    let pk = KeyPair::load(key_path)?.pk;
    let time = timer.elapsed();
    info!("Time for loading public key: {}", time);
    let mut time_set = Vec::<BuildTime>::new();
    let timer = howlong::ProcessCPUTimer::new();
    
    // 【创新点2】使用 build_block_with_mmr 替代 build_block
    for (blk_height, objs) in raw_objs {
        let (blk_head, mmr_pos, mmr_root, duration) = build_block_with_mmr(
            blk_height,
            prev_hash,
            objs,
            &mut chain,
            param,
            &pk,
        )?;
        
        prev_hash = blk_head.to_digest();
        
        // 记录 MMR 信息
        info!(
            "Block {}: mmr_pos={}, mmr_root={:?}...",
            blk_height.0,
            mmr_pos,
            &mmr_root.as_bytes()[..4]
        );
        
        time_set.push(BuildTime {
            blk_height,
            build_time: duration.into(),
            mmr_pos,
        });
    }
    
    let time = timer.elapsed();
    info!("Block building finished. Time elapsed: {}", time);
    
    // 【创新点2】输出 MMR 最终状态
    info!(
        "MMR final state: size={}, block_count={}, root={:?}...",
        chain.get_mmr_size(),
        chain.get_mmr_block_count(),
        &chain.get_mmr_root().as_bytes()[..4]
    );
    
    let res = json!({
        "total_time": Time::from(time),
        "time_set": time_set,
        // 【创新点2】新增 MMR 状态信息
        "mmr_info": {
            "mmr_size": chain.get_mmr_size(),
            "block_count": chain.get_mmr_block_count(),
            "mmr_root": format!("{:?}", chain.get_mmr_root()),
        }
    });
    let s = serde_json::to_string_pretty(&res)?;
    fs::write(res_path, &s)?;
    Ok(())
}

fn main() -> Result<()> {
    init_tracing_subscriber("info")?;
    let opts = Opt::from_args();
    let param = Parameter {
        time_win_sizes: opts.time_win_sizes,
        id_tree_fanout: opts.id_fanout,
        max_id_num: opts.max_id,
        bplus_tree_fanout: opts.bplus_fanout,
        num_dim: opts.dim,
        enable_bloom: opts.enable_bloom,
    };
    build_chain(
        &opts.input,
        &opts.key_path,
        &opts.output,
        &opts.result,
        &param,
    )?;
    Ok(())
}