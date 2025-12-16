src/acc/acc_value.rs：实现了一个基于椭圆曲线配对的累加器系统。
src/acc/keys.rs：实现了累加器密钥的生成和访问，支持高效的预计算，以加速后续运算（如累加值计算）。它强调安全性（随机生成）、性能（并行+预计算）和正确性（测试）。提供生成 acc_value 所需的密钥
src/acc/ops.rs：实现了基于累加器的集合操作，包括交集、并集和差集。这些操作使用多项式表示集合，并生成零知识证明，允许验证操作结果的正确性，而无需揭示集合的完整内容或中间计算细节
src/acc/poly.rs：基于有限域（Field）的多项式（Polynomial）数据结构和运算。多项式在这里用于表示集合的代数形式，支持变量 S 和 R（可能对应私钥中的 s 和 r），以便在密码学累加器系统中进行集合操作的零知识证明
src/acc/serde_impl.rs：实现了累加器值的序列化和反序列化，支持将累加器值转换为字节流进行存储或传输，并从字节流中恢复累加器值。这在分布式系统中尤为重要，因为它允许在不同节点之间传递和存储累加器值，同时保持数据的完整性和隐私性
src/acc/set.rs：实现了集合的表示和操作，包括集合的创建、合并、差集、交集和并集等。该模块通过高效的集合运算，为上层密码学协议提供基础数据支撑，与 poly 模块共同构成可验证计算的核心数学基础
src/acc/utils.rs：实现了一些通用的工具函数和数据结构，用于支持累加器系统的运行。这些工具包括随机数生成、哈希函数、位操作等，为系统的安全和性能提供基础支持
utils ──► keys ──► acc_value ──► ops
------------└─► poly ─┘
--------------- ▲
--------------- │
-------------- set
serde_impl (横跨 keys, acc_value, ops)
典型工作流程从密钥生成开始，到集合操作和证明验证结束。假设用户有一个集合 Set，需要进行操作并验证。utils 的预计算贯穿 keys 和后续计算。
初始化与密钥生成 (keys + utils)：
使用 utils 的随机数（rand）生成私钥 AccSecretKey（Fr 元素如 s, r, beta 等）。
构建 AccSecretKeyWithPowCache：使用 FixedBaseScalarPow 预计算 s^i/r^i 等（Fr 幂），FixedBaseCurvePow 预计算 g^{s^i} 等（群幂）。
生成公钥 AccPublicKey：使用 rayon 并行 + utils 预计算填充向量（如 g_s_i = g.pow(s^i)）。
（可选）使用 serde_impl 序列化密钥存储/传输。
集合准备与多项式表示 (set + poly)：
创建 Set（e.g., set! {1,2,3}）。
使用 poly_a(Set, S) 构建 \sum s^i（遍历 Set iter()）。
使用 poly_b(Set, R, S, q) 构建 \sum r^i s^{q-i}。
累加值计算 (acc_value + keys + set + utils)：
输入 Set 和公钥（或私钥），计算 AccValue：
cal_acc_pk 并行求和公钥的预计算元素（e.g., sum get_g_s_i(i) for i in Set iter()）。
utils 的 FixedBaseCurvePow 确保 getter 高效（预计算表加速）。
（可选）使用 serde_impl 序列化 AccValue。
集合操作与证明生成 (ops + 所有前模块)：
输入：Op 类型、lhs_set/rhs_set、lhs_acc/rhs_acc、公钥。
计算交集 Set（使用 set 的 &）。
构建 q_poly = poly_a(lhs) \* poly_b(rhs)，remove_intersected_term 去除交集项（poly）。
生成证明（e.g., IntersectionProof）：
Poly 的 coeff_par_iter_with_index 填充 MSM bases（从 keys getter 获取群元素，如 get_g_r_i_s_j(i,j)，utils 预计算确保快）。
计算 MSM 得到证明字段（如 q_x_y）。
根据 Op 计算 result_set（set 的 | /）和 result_acc（acc_value 的加减 + cal_acc_pk）。
输出：result_set, result_acc, 证明。
（可选）使用 serde_impl 序列化证明。
验证 (ops + acc_value + keys + utils)：
输入：证明、lhs_acc/rhs_acc、result_set/acc、公钥。
使用双线性配对验证等式（e.g., e(g_x, h_beta) == e(g_x_beta, h)）。
检查 result_acc 是否匹配 cal_acc_pk(result_set, keys getter)（utils 加速）。
如果验证通过，确认操作正确。
持久化与传输 (serde_impl)：
贯穿全程：序列化/反序列化 keys、acc_value、证明，用于存储或传输。
性能与安全考虑：
性能：utils 的窗口预计算减少幂运算（O(bits/K) lookups）；rayon 并行（keys, poly, acc_value, ops）；MSM（ops）。
安全：随机密钥（keys）；配对验证（ops）；checked 序列化（serde_impl）。
测试整合：各模块测试使用 Bn254/Fr，utils 测试验证 pow 正确，ops 测试整个

---

## src/bin

src/bin/gen_key.rs：密钥生成器，生成累加器所需的椭圆曲线密钥对
src/bin/build_chain.rs：区块链构建器，将原始数据集转换为可验证区块链
src/bin/query.rs - 查询处理器，执行查询并生成可验证证明

gen_key → build_chain → query
↓ ↓ ↓
(pk,sk) → 区块链 DB → 查询结果+证明

### src/chain/block/ - 区块核心模块：区块链基础结构构建

src/chain/block/build.rs：区块构建逻辑，包含对象插入和哈希计算
src/chain/block/hash.rs：区块哈希算法实现
src/chain/block/block_ads.rs：区块认证数据结构(ADS)

### src/chain/bplus_tree/ - B+树索引：提供多种索引结构支持不同查询类型

src/chain/bplus_tree/bplus_tree.rs：B+树接口定义
src/chain/bplus_tree/read.rs：B+树读取操作
src/chain/bplus_tree/write.rs：B+树写入操作
src/chain/bplus_tree/hash.rs：B+树节点哈希计算
src/chain/bplus_tree/proof/：B+树范围查询证明生成

### src/chain/id_tree/ - ID 树索引：支持快速 ID 范围查询

src/chain/id_tree/id_tree.rs：ID 树接口定义
src/chain/id_tree/read.rs：ID 查找操作
src/chain/id_tree/write.rs：ID 插入操作
src/chain/id_tree/hash.rs：ID 树节点哈希
src/chain/id_tree/proof/：ID 存在性证明

### src/chain/trie_tree/ - 字典树索引：支持前缀查询

src/chain/trie_tree/trie_tree.rs：字典树接口
src/chain/trie_tree/read.rs：读取操作实现
src/chain/trie_tree/write.rs：写入操作实现
src/chain/trie_tree/hash.rs：字典树节点哈希
src/chain/trie_tree/proof.rs：验证功能、提供累加器值验证和根哈希验证
src/chain/trie_tree/tests.rs：测试用例
src/chain/trie_tree/proof/：证明组件实现

**关系：三种索引树并行工作，分别优化不同查询场景**

### src/chain/query/ - 查询处理引擎：智能查询优化和执行

src/chain/query/query.rs：查询主入口和结果处理
src/chain/query/query_plan.rs：查询计划生成器
src/chain/query/query_dag.rs：DAG 查询优化图
src/chain/query/egg_qp.rs：基于 egg 框架的查询重写优化
src/chain/query/query_param.rs：查询参数定义和解析
**关系：接收用户查询 → 生成查询计划 → 优化执行策略**

### src/chain/verify/ - 验证系统：可验证性证明生成和校验

src/chain/verify/verify.rs：验证主逻辑
src/chain/verify/vo.rs：可验证对象(VO)构造
src/chain/verify/hash.rs：验证相关的哈希计算

### src/chain/block.rs：定义了区块的基本结构和操作接口，为上层的功能（如区块构建、查询、验证等）提供了数据基础

### src/chain/bplus_tree.rs：定义了 B+树的核心数据结构和操作接口，为上层的索引树功能提供了基础支持

### src/chain/hash.rs 是区块链系统中各种数据结构的哈希计算工具模块，为整个链提供统一的加密哈希功能

### src/chain/id_tree.rs：定义了 ID 树的核心数据结构和操作接口，为上层的 ID 范围查询功能提供了基础支持

### src/chain/object.rs 定义了区块链中可验证对象的通用数据结构，包含区块高度、数值数据和关键词数据，并提供哈希计算功能

### src/chain/query.rs：查询引擎核心，负责解析查询参数、生成并行查询计划、执行范围/关键词查询并生成可验证的查询结果

### src/chain/range.rs 定义了范围查询的基础数据结构 Range<K>，提供范围比较、覆盖判断、交集检测等功能，是 B+树范围查询的核心组件

### src/chain/tests.rs：测试用例模块，包含对 B+树、ID 树、字典树、查询引擎等核心组件的测试用例

### src/chain/traits.rs:文件的作用是定义区块链系统的核心接口和抽象 trait，它是整个链式数据结构的基础契约

### src/chain/trie_tree.rs：定义了字典树的核心数据结构和操作接口，为上层的前缀查询功能提供了基础支持

### src/chain/verify.rs：实现查询结果的可验证性验证，通过密码学证明确保查询结果的完整性和正确性

### src/digest.rs - 哈希摘要系统：提供统一的哈希摘要计算和序列化框架

Digest 结构体：32 字节哈希值封装，支持零值检测和字节访问
Digestible trait：统一的数据到哈希转换接口
Blake2b 哈希算法：使用 blake2b_simd 库实现高性能哈希
序列化支持：支持 JSON（十六进制）和二进制格式序列化

### src/utils.rs - 工具函数库：提供项目通用的工具函数和辅助功能

ID 类型生成宏：create_id_type_by_u32!和 create_id_type_by_u16!
数据加载函数：从文件加载查询参数和原始对象数据
密钥对管理：KeyPair 结构体支持密钥生成、保存和加载
日志系统初始化：init_tracing_subscriber 函数

### src/lib.rs - 主库入口和 SimChain 实现：定义项目主库结构和区块链核心实现

模块导出：导出 acc、chain、digest、utils 等子模块
SimChain 结构体：区块链核心实现，管理 7 个 RocksDB 实例
接口实现：为&SimChain 和&mut SimChain 实现 ReadInterface、WriteInterface、ScanQueryInterface

### src/chain.rs - 区块链模块定义：定义区块链相关的子模块和参数结构

模块声明：声明 block、bplus_tree、id_tree、query 等子模块
系统常量定义：定义索引树的分支因子等系统参数
Parameter 结构体：区块链配置参数封装

### src/acc.rs - 累加器模块主入口：作为密码学累加器系统的 统一入口和类型别名定义

统一入口：为整个累加器系统提供简洁的 API 接口
类型安全：通过类型别名确保类型一致性
性能优化：使用#[inline(always)]内联关键函数
密码学安全：基于 BN254 椭圆曲线提供强安全性保证
**WARNING**: This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

If you find the code here useful, please consider to cite the following papers:

```bibtex
@inproceedings{ICDE22:vchain-plus,
  author = {Wang, Haixin and Xu, Cheng and Zhang, Ce and Xu, Jianliang and Peng, Zhe and Pei, Jian},
  title = {{vChain+}: Optimizing Verifiable Blockchain Boolean Range Queries},
  booktitle = {Proceedings of the 38th IEEE International Conference on Data Engineering},
  year = {2022},
  month = may,
  address = {Kuala Lumpur, Malaysia},
  pages = {1928--1941},
  issn = {2375-026X},
  doi = {10.1109/ICDE53745.2022.00190}
}
```

## Build

-   Install Rust from <https://rustup.rs>.
-   Run `cargo test` for unit test.
-   Run `cargo build --release` to build the binaries, which will be located at `target/release/` folder.

## Generate public key

Run `gen_key` to generate the public key. You need to specify the universe size q. For example:

```
./target/release/gen_key -q 4096 -o /path/to/output_key
```

Run `./target/release/gen_key --help` for more info.

## Create Blockchain DB

#### Input Dataset Format

The input is a text file with each line represent an object.

```
obj := block_id [ v_data ] { w_data }
v_data := v_1, v_2, ...
w_data := w_1, w_2, ...
```

For 1-dimensional example

```
1 [1] {a,b,c}
1 [6] {a}
2 [4] {a,e}
```

For 2-dimensional example

```
1 [1,2] {a,b,c}
1 [1,5] {a}
2 [3,4] {a,e}
```

#### Build Blockchain

Run `build_chain` to build blockchain. You need to specify the sliding window size(s), the fan-out of ObjReg index and SWA-B+-Tree, the MaxID, and the numerical value dimension. Due to implementation design, please note that:

-   the sliding window sizes should be defined in an ascending order;
-   the suggested fan-out is 4;
-   the MaxID should be at most q-1, where q is the universe size for public key generation.

For example:

```
./target/release/build_chain -t 2 -t 4 -t 8 -t 16 -t 32 --id-fanout 4 -b 4 -m 4095 -d 1 -k /path/to/pk -i /path/to/dataset.dat -r /path/to/res/build_time.json -o /path/to/output/db
```

Run `./target/release/build_chain --help` for more info.

## Query Processing & Verification

Encode query parameter as a JSON object. The following example specifies the query json file containing a query with the time window as [1, 50] and range as [10, 20], [5, 15] for 2 dimensional objects, and bool expression as "a" AND "b".

```json
[
    {
        "start_blk": 1,
        "end_blk": 50,
        "range": [
            [10, 20],
            [5, 15]
        ],
        "keyword_exp": {
            "and": [
                {
                    "input": "'a'"
                },
                {
                    "input": "'b'"
                }
            ]
        }
    }
]
```

Run `query` to process queries & verify results. You need to specify the optimization(s) applied. Specifically:

-   `-e`: enable optimizing query plan;
-   `-n`: enable pruning empty sets.

In our implementation, query processing uses all available CPU cores while result verification uses only 4 threads as default to simulate a lightweight user. You can set the thread number for verification by setting the `-v` option. For example:

```
./target/release/query -e -n -k /path/to/pk -i /path/to/db -q /path/to/query.json -r /path/to/result/process_time.json -v 2
```

Run `./target/release/query --help` for more info.
