# fingerprintd 架构文档

[English](architecture.md) · **中文**

> 面向**反欺诈 / 反自动化**的服务端设备指纹。判定以服务端为准:客户端只负责采集;
> 服务端签发一次性 challenge、做模糊匹配、融合被动信号,并返回
> `visitorId` + `confidence`。

本文是权威**架构文档**,实现以本文为准。章节编号是稳定锚点 —— 源码文档注释以
`§N` 引用它们。二阶匹配引擎另有独立文档:
[fuzzy-matching.zh-CN.md](fuzzy-matching.zh-CN.md)。

---

## 1. 背景

纯客户端指纹(如开源的 FingerprintJS)存在结构性缺陷:

- **可伪造** —— id 在客户端用客户端可控的值计算得出。
- **无重放防护** —— 静态 id 被捕获一次后即可任意重复提交。
- **不精确** —— 精确的客户端哈希会*雪崩*:任一组件变化就让同一台设备看起来是新设备,
  而同型号设备之间又相互碰撞。
- **对抗性弱** —— 隐私浏览器 / 反指纹扩展会主动加噪。

| 问题 | 根因 | 方向 |
|---|---|---|
| 可伪造 | 信任客户端上报的值 | 用**客户端无法自报的被动信号**做交叉校验 |
| 无重放防护 | id 是静态的 | 绑定新鲜度证明的**一次性 challenge** |
| 不精确 | 精确客户端哈希 + 雪崩 | **服务端模糊匹配 + 多源融合** |

判定完全移到服务端;客户端只负责采集 —— 这正是 FingerprintJS Pro / DataDome /
Akamai 共同采取的路线。

---

## 2. 目标与威胁模型

在高风险动作(登录、注册、结账、优惠券核销)处,每个请求都产出一个稳定的
`visitorId` 和一个供风控引擎使用的 `confidence`:这是不是一台新设备、它是否关联到某台
已知设备、以及自报的浏览器特征是否与网络层一致(bot 检测)?

### 威胁模型

| 对手 | 能力 | 系统目标 |
|---|---|---|
| **L1 脚本** | curl / 脚本,无 JS | 必须拒绝(无采集 / TLS 不一致) |
| **L2 自动化** | 无头浏览器,运行 JS,伪造 UA/JS 值 | 通过被动信号 + 一致性识别 |
| **L3 高级** | curl-impersonate / uTLS 伪造 JA3/JA4 + 完整栈 | **降低 confidence + 交叉验证**,而非绝对封禁 |

不宣称有绝对防御。L3 对手可以伪造任何单一信号;价值在于**抬高伪造成本**和
**多信号一致性检测**,而非做到不可攻破。

### 目标

- **G1** —— 服务端签发一次性 challenge;结果绑定新鲜度,因此重放无效。
- **G2** —— 把客户端组件 + 被动网络信号融合为 `visitorId` + `confidence`。
- **G3** —— 用模糊匹配取代精确哈希,消除雪崩;稳定性优先于唯一性。
- **G4** —— 决策 P99 延迟 ≤ 50ms(不含客户端采集);单实例 ≥ 2k RPS。

### 非目标

- 不做完整的客户端 SDK UI/遥测框架 —— 只提供最小化的采集 + challenge 外壳。
- 不做不可攻破的防篡改(WASM 外壳抬高 hook 成本,并非决定性)。
- 不做跨站追踪 / 广告归因。
- 当前版本不做设备关联图(账号 ↔ 设备聚类);数据为之预留。

---

## 3. 成功指标

| 指标 | 定义 | 目标 |
|---|---|---|
| 稳定率 | 同一设备在两周内多次访问被重新解析到同一个 `visitorId` | ≥ 95% |
| 碰撞率 | 不同设备被解析到同一个 `visitorId` | ≤ 1% |
| L1/L2 检出 | 脚本 / 伪造请求被标为低 confidence | ≥ 90% |
| 决策 P99 | 提交 → 返回 `visitorId` | ≤ 50ms |
| 重放拒绝 | 拒绝过期 / 重用的 nonce | 100% |

> 稳定率/碰撞率目标需通过**针对带标注语料库的离线评测**验证 ——
> 见 [fuzzy-matching.zh-CN.md §10](fuzzy-matching.zh-CN.md#10-离线评估)。
> 不得用合成 fixture 数据上报这些指标。

---

## 4. 架构:挑战-响应 + 服务端融合

### 4.1 新鲜度与身份(核心拆分)

匹配要求同一台设备每次都产出**相同**的稳定输出。因此证据被拆为两条永不混合的通道:

- **`stable_components`** —— 不混入 nonce;原始值进入指纹库并驱动身份匹配。
- **freshness proof(新鲜度证明)** —— 依赖服务端签发的 nonce,证明本次采集是实时的;
  它**绝不**参与身份匹配。

**重放防护**建立在两层之上,按权威性排序:

1. **一次性 nonce(主锁)。** 服务端铸造一个短 TTL、单次使用的 nonce,并在消费时销毁。
   重用或过期的 nonce 以 `401` 拒绝。这是决定性保证。
2. **Nonce probe(纵深防御,可选)。** 当配置了 `probe_key` 时,服务端在 challenge 中
   声明一个确定性变换;客户端返回 `hex(HMAC-SHA256(key, nonce))`,在 WASM 中计算。这证明
   客户端按协议实时计算,而非重放固定值。它是叠加在一次性 nonce 之上的纵深,而非主锁 ——
   密钥随客户端 WASM 发布且可被提取,因此它抬高门槛却非决定性。

> 早期设计曾把 nonce 混入 canvas/audio 的绘制种子(`challenge_response`)。它已被移除:
> 依赖"每次输出都不同"的新鲜度无法被服务端独立验证,而一次性 nonce 可以。HMAC probe
> 取代它成为实时采集证明。

### 4.2 被动信号与信任边界

TLS JA3/JA4 **不是**高熵的单设备标识符,也**不是**不可伪造的:

- 低熵 —— 数百万台同型号 Chrome 实例共享同一个 JA3,因此它不能作为 `visitorId` 的来源。
- 可伪造 —— curl-impersonate / uTLS 可以构造任意 ClientHello。

它真正的价值在于**一致性交叉校验**,加权计入 `confidence`,绝不计入 `visitorId`:

- JS 声称是 Chrome/Windows 但 JA4 是 Python/Go 栈 → 强异常,confidence 大幅降低。
- IP 信誉(数据中心 / 代理 / 风险源)→ 辅助,非决定性。

**部署约束(硬性)。** 连接层信号只能由终结客户端 TLS 连接的一方捕获。在 Cloudflare 代理
之后,源站看到的是 CF↔源站这一段,因此客户端层信号必须被透传过来。

- **当前拓扑** —— Cloudflare 提取 JA3/JA4 并通过 header 转发。可用性取决于账户(JA4 header
  绑定 Bot Management、Enterprise):存在 → 使用;**缺失 → 自动降级**(连接层信号被中和并
  降权,请求**不**被封禁;通过 `CF-Connecting-IP` 获得的真实客户端 IP 仍供 IP 信誉使用)。
- **信任边界(fail-closed)。** 边缘注入的被动信号 header **仅**在部署被配置为信任边缘
  (`trust_edge_headers`)时才读取;否则任何客户端提供的副本都被忽略。这可防止客户端塞入
  伪造的 JA4。自管理的 nginx/envoy 边缘注入其自身受信 JA4 header 属未来扩展。

### 4.3 模糊匹配与候选集生成

匹配**不是**哈希查表,也不能线性扫描整个库。分两阶段:(1) blocking / LSH 召回把库压缩到
数十至数百个候选;(2) 加权概率打分(Fellegi–Sunter)对其排序并决策。完整文档:
[fuzzy-matching.zh-CN.md](fuzzy-matching.zh-CN.md)。

### 4.4 客户端采集:复用 FingerprintJS / BotD

客户端只负责采集;判定在服务端(§4)。采集器复用现成的 MIT 库,而非重新发明:

| 库 | 许可证 | 复用方式 | 边界 |
|---|---|---|---|
| **FingerprintJS**(OSS) | MIT | npm 依赖;取其**原始 `components`** 作为 `stable_components` | 丢弃其客户端 `visitorId` 哈希 |
| **BotD**(OSS) | MIT | npm 依赖;bot 信号折入服务端 `confidence` | 客户端信号可伪造,属次要输入 |

Nonce probe(§4.1)为自研 —— FingerprintJS 不会对服务端 nonce 计算带密钥的变换。客户端
适配器在提交前把 FingerprintJS 嵌套的 `{value, duration}` 组件结构和键名映射到服务端
schema,使真实浏览器 probe 可被匹配。见 [`packages/client`](../packages/client/README.md)。

---

## 5. HTTP 接口

两种部署目标(§8)提供相同的通信契约。

### GET /challenge

```
200: {
  nonce: string,          // one-time, server-issued
  expires_in: 30,         // seconds (nonce_ttl_secs)
  collect: {
    stable: [...],                 // components to gather
    challenge: {
      verify?: { ... }             // advertised only when a probe_key is configured
    }
  }
}
```

### POST /identify

```
Req: {
  nonce: string,
  stable_components: { ... },   // raw values, no nonce mixed in
  probe?: string,               // hex(HMAC-SHA256(key, nonce)); required when the server enforces the probe
  ts?: number                   // client Unix ms; checked only when the timestamp window is enforced
}
200: {
  visitorId: string,
  confidence: 0.0..1.0,         // DECISION confidence, not identity trust — see §6
  decision: "match" | "review" | "new_device",
  is_new_device: boolean,
  collision_risk: boolean,
  signals: {                    // for the risk engine; raw passive signals are never echoed
    ua_tls_consistent: boolean,
    ip_risk: "low" | "medium" | "high"
  }
}
401: nonce expired / reused, or an enforced probe / timestamp check failed
```

请求体是 `deny_unknown_fields` —— 出现预期外的顶层键即以 `400` 拒绝(两个栈皆然)。当设置了
`response_signing_key` 时,成功响应会额外携带 `x-fp-timestamp` + `x-fp-signature`
(`hex(HMAC-SHA256(key, be64(issuedMs) ++ body))`)。

被动信号(JA4/IP)由服务端从连接层获取(§4.2),**绝不**从客户端请求体接受。

### DELETE /visitor/{id}

GDPR 被遗忘权(§7)。受 admin-key 门控(`admin_key`):未设置 ⇒ 该路由被禁用。擦除是幂等的 ——
即使该 visitor 不存在也返回 `204`。

---

## 6. 数据模型

- **fingerprints** —— `visitorId` → 各组件的加盐哈希、blocking key、首次/末次可见时间、
  观测计数。原始值**不**存储(§7);类别组件是加盐哈希,集合组件是逐元素哈希(保留
  Jaccard)。见 [fuzzy-matching.zh-CN.md §3](fuzzy-matching.zh-CN.md#3-存储表示)。
- **nonce** —— `nonce` → `{issued_at, used}`,TTL = `expires_in`,使用时销毁。
- **frequency** —— 供 `u_i` 稀有度估计使用的逐值计数
  ([fuzzy-matching.zh-CN.md §9](fuzzy-matching.zh-CN.md#9-参数估计与冷启动))。

**`confidence` 语义。** `confidence` 是**决策置信度**,不是身份可信度:一台从未见过的
全新设备会以高决策置信度被判为 `new_device`(引擎确信它是新的)。风控消费方必须读取
`is_new_device` / `decision` 来判断身份可信度,不得把高 confidence 的 `new_device` 当作
高可信度身份。

---

## 7. 隐私与合规

存储派生指纹比纯客户端方案敏感度更高,因此:

- **法律依据** —— 在 GDPR/CCPA/PIPL 下,设备指纹通常属于个人数据;反欺诈一般基于正当利益,
  需要一份 DPIA 记录。
- **数据最小化** —— 只存加盐哈希,绝不存原始组件值
  (§6 / [fuzzy-matching.zh-CN.md §3](fuzzy-matching.zh-CN.md#3-存储表示))。
- **保留期** —— 超过 `retention_secs` 的记录被清扫并删除;`0` 关闭清扫。
- **擦除** —— `DELETE /visitor/{id}`(§5)实现被遗忘权。
- **严格输入** —— 请求体上的 `deny_unknown_fields` 防止静默接受未建模字段。
- **目的限制** —— 仅用于反欺诈;用于广告/追踪会改变法律依据,超出范围。
- **透明度** —— 在隐私政策中披露设备指纹。

---

## 8. 部署目标

一套引擎([`crates/fp-core`](../crates/fp-core)),两个宿主。客户端对两者均无需改动即可工作;
二者通过在双侧运行的共享 parity fixture 被约束为行为一致。

| 关注点 | 原生服务端(`crates/fingerprintd`) | 边缘 Worker(`apps/edge`) |
|---|---|---|
| 运行时 | Axum / Tokio,长驻进程 | Cloudflare Worker(V8 isolate,按请求) |
| Nonce 存储 | 内存,单次使用 + TTL,有界 + 回收 | Durable Object(原子 check-and-burn + TTL alarm) |
| 指纹库 | 内存倒排索引 + 频次表,有界/驱逐 | D1(SQLite):`templates` + `blocking_index` |
| 计算 | 原生 `fp_core` | `fp_core` 编译为 WASM(`crates/fp-wasm`) |
| 被动信号 | 完整 JA4/IP 融合(§4.2) | 默认中立;JA4/IP 需受信边缘 |
| 密钥 | config / env | Worker Secrets |

原生存储是进程本地的:重启会重新铸造设备,因此要在生产上获得单实例稳定的 `visitorId`,
需要一个持久后端(D1/Durable Object 接缝,或位于 `NonceStore` / `FingerprintStore` /
`CandidateSource` trait 之后的外部存储)。持久化部署见 [`apps/edge`](../apps/edge/README.md)。

---

## 9. 纵深防御控制(配置门控,默认关闭)

三者皆为 fail-closed,且仅在其密钥被设置后才激活:

- **Nonce probe**(`probe_key`,§4.1)—— 校验 WASM 计算出的 `probe`;错误/缺失 ⇒ `401`。
  同一密钥必须烘焙进客户端 WASM 构建。
- **响应签名**(`response_signing_key`,§5)—— 对每个 `/identify` 成功响应签名,使客户端
  能检测篡改。
- **时间戳窗口**(`enforce_ts_window` + `ts_skew_secs`,§5)—— 限定请求 `ts` 可以有多陈旧。

它们是叠加在一次性 nonce 和 TLS 之上的纵深,后两者仍为主控。内嵌的客户端密钥可被提取,
不得被提升为决定性控制。
