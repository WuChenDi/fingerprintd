# fingerprintd

[English](README.md) · **中文**

一个**以服务端为准**的设备指纹服务,面向反欺诈与反自动化。客户端只负责**采集**证据;
服务端签发一次性挑战,将证据与其指纹库进行模糊匹配,并返回
`visitorId` + `confidence` + `decision`。身份从不在客户端计算,因此无法被伪造或重放。

- **两种部署形态,同一套引擎。** 原生 [Axum 服务](crates/fingerprintd) 与
  [Cloudflare Worker](apps/edge) 承载同一个计算核心
  ([`crates/fp-core`](crates/fp-core),经 [`crates/fp-wasm`](crates/fp-wasm)
  编译为 WASM);客户端无需改动即可对接任意一方。
- **浏览器 SDK。** [`@cdlab/fingerprintd-client`](packages/client) 集成
  FingerprintJS/BotD,在 WASM 中计算 nonce 新鲜度 probe 并提交 —— 它从不推导 id。
- **技术栈。** 引擎与原生服务采用 Rust(edition 2024、`#![forbid(unsafe_code)]`);
  SDK、边缘 Worker 与 playground 采用 TypeScript/Bun + Biome。

## 它做什么

在高风险动作(登录、注册、结账、优惠券核销)发生时,调用方会得到一个稳定的
`visitorId` 和一个 `confidence`,供其风控引擎消费:这是不是一台新设备、它是否与某台
已知设备一致,以及自我上报的浏览器 `signals` 是否与不可伪造的网络层信号(bot 检测)吻合。

它刻意**不**追求牢不可破的防御 —— L3 级对手可以伪造任意单一信号。其价值在于抬高伪造成本,
并交叉核验多个信号的一致性。它是一个反欺诈工具,**而非**跨站追踪器。完整的设计理据、
威胁模型与匹配引擎见 [`DESIGN.md`](DESIGN.zh-CN.md)。

## 工作原理

```
1. GET /challenge
   server mints a one-time nonce (short TTL, single-use) and returns
   it plus the collection plan

2. client collects (packages/client):
   - stable_components — canvas / webgl / fonts / audio / screen / UA …
     (NO nonce mixed in) → the identity-matching input
   - probe — hex(HMAC-SHA256(key, nonce)) computed in WASM
     → a freshness proof, NEVER a matching signal (defense in depth)

3. POST /identify  { nonce, stable_components, probe?, ts? }
   server:
     a. consume the nonce (burn-on-use)                    ← replay protection
     b. blocking-key recall → Fellegi–Sunter scoring       ← de-avalanche, high precision
     c. fuse passive JA4 / IP signals (UA↔TLS consistency) ← anti-forgery cross-check
     → visitorId + confidence + decision (+ passive signals)
```

## 端点

两套栈提供相同的传输契约;参见 [`DESIGN.md` 架构 §5](DESIGN.zh-CN.md#5-http-接口)。

| Endpoint        | Method | 用途                                           |
| --------------- | ------ | ---------------------------------------------- |
| `/health`       | GET    | 存活探测(`200 OK`)                            |
| `/challenge`    | GET    | 签发一次性 nonce 挑战                          |
| `/identify`     | POST   | 计算 `visitorId` + `confidence` + `decision`   |
| `/visitor/{id}` | DELETE | GDPR 擦除 —— 删除一个访客(受 admin-key 门控) |

## 快速开始

运行原生服务(默认监听 `127.0.0.1:8080`):

```bash
cargo run -p fingerprintd

# override the bind address
FINGERPRINTD_BIND_ADDR=0.0.0.0:9000 cargo run -p fingerprintd

# probe liveness
curl -i http://127.0.0.1:8080/health
```

日志级别由 `RUST_LOG` 控制(默认为 `info`)。

若要从浏览器调用,请使用 SDK:

```ts
import { createCollector, run } from '@cdlab/fingerprintd-client'

const { identity } = await run({
  baseUrl: 'https://fp.example.com',
  collect: createCollector(),          // FingerprintJS + BotD + WASM probe
})
// identity: { visitorId, confidence, decision, is_new_device, collision_risk, signals }
```

关于 Serverless 部署(Cloudflare Worker + Durable Object nonce + D1 指纹库),参见
[`apps/edge`](apps/edge/README.md)。[playground](apps/web/README.md) 在浏览器中驱动完整流程,
并可视化客户端发送的内容与服务端判定的结果之间的差异。

## 配置

分层生效(优先级递增):内置默认值 → `fingerprintd.toml` →
以 `FINGERPRINTD_` 为前缀的环境变量。

| Key                          | Env var                                   | Default          | 含义                                                                        |
| ---------------------------- | ----------------------------------------- | ---------------- | --------------------------------------------------------------------------- |
| `bind_addr`                  | `FINGERPRINTD_BIND_ADDR`                  | `127.0.0.1:8080` | 监听地址。                                                                  |
| `nonce_ttl_secs`             | `FINGERPRINTD_NONCE_TTL_SECS`             | `30`             | 一次性 nonce 存活期,以 `expires_in` 对外公布。                             |
| `trust_edge_headers`         | `FINGERPRINTD_TRUST_EDGE_HEADERS`         | `false`          | 是否信任边缘注入的被动信号 header(JA4/IP)。**故障关闭:** 仅在位于受信边缘之后时开启;可被直连的源站必须保持关闭。 |
| `probe_key`                  | `FINGERPRINTD_PROBE_KEY`                  | *(未设置)*       | 启用 nonce-probe 校验的 HMAC 密钥(纵深防御)。未设置则关闭。               |
| `response_signing_key`       | `FINGERPRINTD_RESPONSE_SIGNING_KEY`       | *(未设置)*       | 启用 `/identify` 响应签名的 HMAC 密钥。未设置则关闭。                       |
| `enforce_ts_window`          | `FINGERPRINTD_ENFORCE_TS_WINDOW`          | `false`          | 强制校验请求时间戳窗口。                                                    |
| `ts_skew_secs`               | `FINGERPRINTD_TS_SKEW_SECS`               | `30`             | 窗口开启时允许的时钟偏移。                                                  |
| `admin_key`                  | `FINGERPRINTD_ADMIN_KEY`                  | *(未设置)*       | 门控 `DELETE /visitor/{id}` 的 Bearer 密钥。未设置则禁用擦除。             |
| `retention_secs`             | `FINGERPRINTD_RETENTION_SECS`             | `0`              | 驱逐超过该年龄(秒)的存储记录。`0` 禁用清扫。                             |
| `fuzzy_max_records`          | `FINGERPRINTD_FUZZY_MAX_RECORDS`          | `1000000`        | 最大不同访客数;超过上限时驱逐最早出现者。                                  |
| `fuzzy_record_ttl_secs`      | `FINGERPRINTD_FUZZY_RECORD_TTL_SECS`      | `0`              | 驱逐在该窗口内未再出现的记录。`0` 禁用 TTL。                               |
| `fuzzy_max_block`            | `FINGERPRINTD_FUZZY_MAX_BLOCK`            | `1024`           | blocking 索引每个 block 的访客上限;超限的插入被丢弃。                     |
| `fuzzy_max_frequency_values` | `FINGERPRINTD_FUZZY_MAX_FREQUENCY_VALUES` | `1000000`        | 追踪的不同 `u_i` 频率值上限;超限的新值被丢弃。                            |

`probe_key` / `response_signing_key` / `admin_key` 这些控制项均为**故障关闭且默认关闭**
—— 只有在其密钥被设置后,对应控制才会激活。内存容量上界宽裕且故障安全:小负载的行为与
无界存储完全一致,且每次驱逐或丢弃都会被计数,绝不静默。这些上界仅适用于原生服务;
无状态的边缘按请求处理。

## 设计文档

[`DESIGN.md`](DESIGN.zh-CN.md)([English](DESIGN.md))是权威规范 —— 架构(背景、威胁模型、
挑战-响应拆分、被动信号信任边界、HTTP 契约、隐私与合规、部署目标)与模糊匹配引擎(两阶段
blocking + Fellegi–Sunter 打分、漂移、冷启动、离线评估)。源码文档注释以
`architecture §N` / `fuzzy-matching §N` 引用其章节编号。

## 项目结构

```
crates/
  fp-core/          framework-free compute + storage traits (shared engine)
  fingerprintd/     native Axum server (challenge / identify / erasure)
  fp-wasm/          Rust→WASM probe core + edge FpEngine
packages/
  client/           TypeScript browser SDK (FingerprintJS/BotD + collector)
apps/
  edge/             Cloudflare Worker (TS host + WASM engine + Durable Object/D1)
  web/              React/Vite playground for the challenge/identify flow
DESIGN.md           architecture + fuzzy-matching spec (bilingual)
```

`crates/fingerprintd/src/lib.rs` 暴露 `build_router() -> axum::Router`,
这是挂载 HTTP 路由的唯一位置。

## 构建与质量门禁

完整绿灯(在 workspace 根目录运行):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features          # or: cargo test --all-features
cargo build --all-targets
cargo deny check
```

deny-warnings 策略定义在 `[workspace.lints]`;CI 运行相同的命令,
外加 SDK 与边缘 Worker 的测试套件(`.github/workflows/ci.yml`)。两套 Rust/TS
栈由一份在两侧共同执行的**共享 parity fixture** 约束到同一行为
(参见 [`apps/edge/README.md`](apps/edge/README.md))。

各组件工具链:

- **SDK** —— `cd packages/client && bun run lint && bun run typecheck && bun run test`
- **边缘 Worker** —— `cd apps/edge && bun run test`(在 miniflare 中跑 router + state + parity)
- **Playground** —— `cd apps/web && bun run typecheck && bun run build`

## 安全

漏洞上报政策见 [`SECURITY.md`](SECURITY.md)。随客户端 WASM/JS 一起分发的 probe 与
响应签名密钥是**纵深防御,而非决定性控制** —— 一次性 nonce 与 TLS 仍是首要保证。

## 许可证

[Apache-2.0](LICENSE)
