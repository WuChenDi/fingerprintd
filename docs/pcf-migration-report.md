# P-CF 迁移报告:fingerprintd 上 Cloudflare Workers

> 类型:部署形态迁移(新增 CF Workers 目标) ｜ 记录人:L1 ｜ 2026-07-06
> 关联:BKD 项目 `qdxgw8qt` / L1 issue `d5kfhl46` ｜ base main `45de60f`

---

## 1. 目标与非目标

**目标**:让 fingerprintd 能部署到 CF Workers,形态 = **TS Worker host + Rust→WASM 计算核心 + DO/D1 状态**。

**非目标 / 保留**:
- **不删现有 Axum 服务端**。P-CF **新增一个部署目标**,与 Axum 服务端**共享抽出的 `fp-core`**。既有 85 测试保持绿。
- 不做真实 CF 部署认证(见 §5 环境限制)。

## 2. 为什么是重架构(不是重编译)

现状:Rust Axum 常驻服务 + **进程内状态**(`InMemoryNonceStore`、`FuzzyStore` 内存倒排)。CF Workers 是 **V8 isolate + fetch handler,无常驻 tokio/TCP、无进程内持久状态**。所以:

- Axum/tokio handler **不能原样搬**,要重写到 Worker 模型。
- 进程内状态**必须外置**到 CF 原语。

## 3. 状态映射(关键,已与用户确认方向)

| 数据 | 需求 | CF 原语 | 理由 |
|------|------|---------|------|
| **nonce**(一次性 + TTL) | **原子消费一次** | **Durable Object** | DO 单线程强一致 → 原子烧毁。**KV 不行**(最终一致 + 无原子 CAS → 重放窗口) |
| 指纹库 + blocking 倒排 + 频率 | 可查询、blocking-key 查找 | **D1**(SQLite) | 关系查询;纯 KV 撑不动倒排/频率 |
| 探针/签名密钥 | 机密 | **Worker Secrets**(wrangler) | 非数据存储 |

> `NonceStore` trait 当初就是为此留的抽象——换 DO 后端不动判定逻辑。指纹库需新增 `CandidateSource`/`FingerprintStore` trait,内存实现(Axum)与 D1 实现(Worker)各一。

## 4. 计算/存储拆分(核心设计)

**纯计算**(无 I/O,进 WASM):blocking-key 派生、Fellegi-Sunter 打分、HMAC 探针、HMAC 签名、nonce 变换。
**I/O 编排**(host 层):nonce DO 原子烧毁、D1 候选查询、D1 漂移写回、路由。

**待拍板的架构分叉**:
- **(a) TS host + Rust WASM 计算**(推荐,契合用户"gino 式"设想):TS Worker 管路由 + DO/D1 I/O,调 WASM 做纯计算。候选集(几百条)从 D1 查出后传入 WASM 打分。
- **(b) 全 Rust `workers-rs`**:整个 Worker 用 Rust 编 WASM,DO/D1 绑定走 worker crate,逻辑全留 Rust、无 TS host。

两者都可行;(a) 跨语言边界有序列化开销但符合 gino 对齐,(b) 逻辑不出 Rust 但偏离"TS host"。**默认按 (a) 推进,除非你选 (b)。**

## 5. 环境限制(同 PC,须认可)

本环境**无 CF 账号、无 wrangler 登录、DO/D1 是付费功能**。所以 P-CF 只能做到:
- 代码 + **miniflare/workerd 本地模拟**(`bunx wrangler dev --local`,D1 本地 sqlite,DO 本地)测试;
- **真实 CF 部署认证需你线下做**。无真实指标/真实部署声明。

## 6. 分期拆分(建议)

| L3 | 内容 | deps |
|----|------|------|
| **PCF1** | 抽 `fp-core` crate(纯计算 + 存储 traits);Axum 服务端改依赖它,**行为不变、85 测试绿**(纯重构,受既有测试守护) | none |
| **PCF2** | `fp-core` 计算经 wasm-bindgen 暴露给 JS(scorer / blocking-keys / probe / sign) | PCF1 |
| **PCF3** | TS Worker host 脚手架(wrangler 配置 + 路由对齐 PRD §5 + 接 WASM),miniflare 本地测试(状态先桩) | PCF2 |
| **PCF4** | 状态层:nonce DO(原子烧毁)+ D1 schema/迁移(指纹库/倒排/频率)+ host I/O + 漂移写回 | PCF3 |
| **PCF5** | 集成 + **parity**(Worker 路径对固定输入产出与原生服务端一致的 visitorId/confidence)+ Secrets + 部署/README 文档 | PCF4 |

**DAG**:PCF1 → PCF2 → PCF3 → PCF4 → PCF5(基本线性)。

**验收**:各 L3 过对应门(Rust:fmt/clippy-D/nextest 85/build/deny;WASM:build + cargo test;TS/Worker:biome/tsc/vitest + `wrangler dev --local` 冒烟);PCF5 的 parity 证明 Worker 与原生同解。

## 7. 下一步

1. 本报告已记录。
2. **待用户拍板**:架构分叉 (a)/(b);是否认可环境限制(本地 miniflare 层)。
3. 确认后 L1 起 BKD campaign,L2 分解 PCF1–PCF5 调度,各过门 → L1 审后合并 main。
