### 启动 API 服务

```powershell
.\target\release\api_server.exe -k D:\vchain-plus-master\output\pk_eth2024.key -c D:\vchain-plus-master\output\db_eth2024_schemex -p 8081
```

启动后应看到：

```
Listening on http://127.0.0.1:8081
```

### 验证服务正常

```powershell
curl http://127.0.0.1:8081/api/health
# 期望: {"status":"ok","service":"vchain-plus-api","version":"0.1.0"}

curl http://127.0.0.1:8081/api/chain/info
# 返回链的元信息、MMR 状态、区块数等
```

## API 接口清单

| 方法 | 路径                                | 说明                                   | 对应核心库函数                           |
| ---- | ----------------------------------- | -------------------------------------- | ---------------------------------------- |
| GET  | `/api/health`                       | 健康检查                               | —                                        |
| GET  | `/api/chain/info`                   | 链元信息（对象数/高度/MMR 状态）       | `SimChain::get_chain_info` / `get_mmr_*` |
| GET  | `/api/chain/params`                 | 链参数（时间窗、fanout、Bloom 开关等） | `SimChain::get_parameter`                |
| GET  | `/api/blocks?start&end&page&size`   | 分页列出区块                           | `SimChain::read_block_head`              |
| GET  | `/api/block/:height`                | 单区块详情（含 ADS 组件展开）          | `SimChain::read_block_head/content`      |
| GET  | `/api/block/:height/objects`        | 该区块的所有对象                       | `SimChain::read_object`                  |
| POST | `/api/query`                        | 执行可验证查询（含查询 + 验证）        | `query()` + `verify()`                   |
| POST | `/api/query/verify`                 | 独立验证阶段（重跑查询、独立验证计时） | 同上                                     |
| GET  | `/api/block/:height/proof?type=...` | 生成两层式证明                         | `SimChain::gen_two_layer_proof_with_*`   |
| POST | `/api/proof/verify`                 | 验证两层式证明                         | `SimChain::verify_two_layer_proof`       |

## 示例请求

### 执行一个 AND 查询

```powershell
# 请求体（保存为 query.json）
'{
    "start_blk": 1,
    "end_blk": 100,
    "range": [[21000, 500000]],
    "keyword_exp": {
        "and": [
            { "input": "''0x174bfa6600bf90c885c7c01c7031389ed1461ab9''" },
            { "input": "''0xdeadbeef00000000000000000000000000000001''" }
        ]
    },
    "egg_opt": true,
    "empty_set": true,
    "verify_thread_num": 4
}' | Out-File -Encoding utf8 query.json

# 发送
curl -X POST http://127.0.0.1:8081/api/query `
    -H "Content-Type: application/json" `
    -d "@query.json"
```

响应结构：

```json
{
    "objects": [ ... ],
    "query_time": {
        "stage1": { "real": 88022717, "sys": ..., "user": ... },
        "stage2": { ... },
        "stage3": { ... },
        "stage4": { ... },
        "total": { ... }
    },
    "verify_time": { "real": 700606, "sys": ..., "user": ... },
    "vo_size": {
        "vo_dag_s": 1665000,
        "trie_proof_s": 2987252,
        "id_proof_s": 47500,
        "cur_id_s": 2500,
        "merkle_s": 162500,
        "total_s": 4864752
    },
    "total_matched": 12
}
```

### 生成两层式证明（创新点 2 演示）

```powershell
# ID 树类型证明
curl "http://127.0.0.1:8081/api/block/5/proof?type=id_tree"

# B+ 树类型证明（需要指定维度和时间窗口）
curl "http://127.0.0.1:8081/api/block/5/proof?type=bplus_tree&dimension=0&time_window=8"

# Trie 类型证明
curl "http://127.0.0.1:8081/api/block/5/proof?type=trie&time_window=8"
```

响应结构：

```json
{
    "mmr": {
        "mmr_size": 100,
        "position": 8,
        "block_ads_root": "abc123...",
        "proof_items_count": 6
    },
    "block": {
        "block_height": 5,
        "components": {
            "id_set_root_hash": "...",
            "id_tree_root_hash": "...",
            "multi_ads_hash": "...",
            "bloom_root_hash": "0000..."
        }
    },
    "index_proof_type": "id_tree",
    "full_proof": { ...完整证明数据... }
}
```

### 验证两层式证明

```powershell
# 把上一步 GET 的 full_proof 字段作为 body 提交验证
curl -X POST http://127.0.0.1:8081/api/proof/verify `
    -H "Content-Type: application/json" `
    -d '{ "proof": { ...从 /api/block/:h/proof 返回的 full_proof... } }'
```

## 与前端集成的建议

CORS 已默认允许所有来源（demo 用），Vue 前端可以直接 `axios.get('http://127.0.0.1:8081/api/chain/info')`。

生产环境请把 `src/api/router.rs` 的 `allow_origin(Any)` 改成显式域名列表。

## 目录结构

```
src/
├── api.rs                    # 模块声明
├── api/
│   ├── state.rs              # AppState (Arc<SimChain>, Arc<AccPublicKey>)
│   ├── errors.rs             # 统一错误类型 + HTTP 响应转换
│   ├── models.rs             # 请求/响应 DTO
│   ├── handlers.rs           # 处理函数（10 个端点）
│   └── router.rs             # 路由装配 + 中间件
└── bin/
    └── api_server.rs         # 二进制入口
```

新增代码没有触碰任何核心库文件，除了 `src/lib.rs` 加了一行 `pub mod api;` 声明。你原有的 3 个 CLI 二进制（`gen_key`、`build_chain`、`query`）完全不受影响。

## 已知限制（Phase 1 demo 范围内）

1. **`POST /api/query/verify`** 目前会重跑查询——因为 VO 里包含 `petgraph::Graph<DagNode>` 和一堆 `acc` 类型，完整的往返 JSON 序列化非常繁琐。demo 阶段这个端点仍能演示"验证阶段的独立耗时和 VO 大小"，够用。Phase 2 会补齐真正的仅验证端点。
2. **管理型端点未实现**（上传数据集、触发构建链）。这类操作时间很长（几十分钟到几小时），需要异步任务系统。目前假定链是预先用 CLI 构建好的。
3. **CORS 是全放开的**——只适合本地 demo，不能上线。
