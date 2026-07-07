# fingerprintd — 服务端设备指纹与识别服务 PRD

> 状态:草案 v0.3 ｜ 最后更新:2026-07-06
> 已定档:场景 = **反欺诈 / 反自动化的设备识别**(非追踪/归因,见 §2)。
> 已定档:TLS 拓扑 = **Cloudflare header 透传**(拓扑①)。JA3/JA4 header 绑定 Bot Management,
> 取决于部署账号套餐;**取不到即自动降级**(连接层信号置空,不阻断)。自管 nginx/envoy 为后续扩展(见 §4.2)。

---

## 1. 背景与问题

现有纯客户端方案(以 FingerprintJS 开源版为代表)的结构性缺陷:

- **易伪造 / 篡改**:指纹在客户端计算并自报,信任了客户端可控的值。
- **无法防重放**:指纹是静态值,采集一次即可重复提交。
- **精度不足**:客户端精确哈希,任一分量变动即"雪崩",导致同设备被判为新设备;
  同质设备(同型号 + 同浏览器版本)又易碰撞。
- **抗对抗弱**:隐私浏览器 / 反指纹扩展会主动加噪。

### 三个问题 → 根因 → 对策

| 问题        | 根因                            | 对策方向                                   |
| ----------- | ------------------------------- | ------------------------------------------ |
| 易伪造/篡改 | 信任了客户端自报的值            | 引入**客户端无法自报的被动信号**做交叉校验 |
| 无法防重放  | 指纹是静态值,采一次能重复提交  | **一次性 challenge-response** + 时效绑定    |
| 精度不够    | 客户端精确哈希 + 雪崩           | 服务端**模糊匹配 + 多源融合**              |

判定权全部收归服务端,客户端只负责采集——这是 FingerprintJS Pro / DataDome / Akamai 一致的路子。

---

## 2. 目标与非目标

### 使用场景(主)
在登录、注册、下单、领券等**高风险动作**处,为每个请求产出一个稳定的 `visitorId`
和 `confidence`,供风控引擎判断:是否新设备、是否与已知欺诈设备关联、
自报浏览器与网络层特征是否一致(机器人识别)。

### 威胁模型
| 对手等级 | 能力                                    | 本系统的应对目标            |
| -------- | --------------------------------------- | --------------------------- |
| L1 脚本  | curl/脚本直连,不跑 JS                   | 必须拦截(无采集/JA3 不符) |
| L2 自动化 | headless 浏览器,能跑 JS,伪造 UA/JS 值 | 通过被动信号 + 一致性识别   |
| L3 高级  | curl-impersonate / utls 伪造 JA3+完整栈 | **降低置信度 + 交叉验证**,不追求绝对拦截 |

> 明确不做绝对防御。L3 对手可伪造任意单一信号;系统价值在于**提高伪造成本**
> 和**多信号一致性检测**,而非"不可绕过"。

### 目标(Goals)
- G1 服务端签发一次性 challenge,采集结果绑定时效,重放无效。
- G2 融合客户端 components + 被动网络信号,产出 `visitorId` + `confidence`。
- G3 模糊匹配替代精确哈希,消除雪崩;稳定率优先于唯一率。
- G4 P99 判定延迟 ≤ 50ms(不含客户端采集);单实例 ≥ 2k RPS。

### 非目标(Non-Goals)
- 不做客户端 SDK 的完整 UI/埋点框架,只提供采集 + challenge 交互的最小壳。
- 不做绝对不可绕过的防篡改(WASM 壳仅提高 hook 成本,非决定性)。
- 不做跨站追踪 / 广告归因。
- 首版不做设备关联图谱(account ↔ device 聚类),仅预留数据。

---

## 3. 成功指标

| 指标            | 定义                                        | 目标(首版) |
| --------------- | ------------------------------------------- | ------------ |
| 稳定率          | 同设备两周内多次访问判为同一 visitorId 的比例 | ≥ 95%        |
| 碰撞率          | 不同设备被判为同一 visitorId 的比例         | ≤ 1%         |
| L1/L2 识别率    | 脚本/伪造请求被标记为低 confidence 的比例    | ≥ 90%        |
| 判定 P99 延迟   | 提交到返回 visitorId                        | ≤ 50ms       |
| challenge 重放拦截 | 过期/复用 nonce 的请求被拒                | 100%         |

---

## 4. 架构:Challenge-Response + 服务端融合

```
1. GET /challenge
   服务端签发 nonce(短时效 + 一次性,存 Redis),返回 nonce + 采集参数

2. 客户端采集:
   - 稳定分量(不掺 nonce):canvas/webgl/字体/audio/屏幕/UA 等 → 用于身份匹配
   - 挑战分量(掺 nonce 作绘制种子):canvas/audio → 仅用于证明本次采集新鲜
   - WASM 壳执行采集逻辑(提高 hook 成本)

3. POST /identify  { nonce, stable_components, challenge_response, ts }
   服务端:
     a. 校验 nonce 未过期 + 未使用(用后即焚)        ← 防重放
     b. 提取 TLS JA3/JA4、HTTP/2 帧序、UA 一致性       ← 反伪造/交叉校验
     c. stable_components 候选集生成 → 加权模糊匹配     ← 去雪崩、高精度
     d. 融合被动信号 → 输出 visitorId + confidence
```

### 4.1 分量拆分(修正原设计的核心矛盾)

指纹能匹配的前提是**同设备每次输出一致**。若把 nonce 掺进所有分量,
结果每次都变,就无法匹配。因此**必须分两类**:

- **稳定分量 `stable_components`**:不含 nonce,原始值上报,进指纹库,用于身份匹配。
- **挑战分量 `challenge_response`**:nonce 作为 canvas/audio 绘制种子,
  输出同时依赖设备与 nonce,**只用于新鲜度证明,不参与身份匹配**。

**新鲜度校验逻辑**:掺 nonce 后服务端无法预知期望输出(输出依赖设备)。
故服务端能验证的是:
1. 该 nonce 从未被使用(Redis 用后即焚)—— 这是防重放的主锁;
2. `challenge_response` 与该设备历史上"相同 nonce"的结果不同(nonce 不复用则天然满足);
3. (可选增强)服务端下发时附带一个**已知答案的探针项**(如要求对 nonce 做特定
   确定性变换并回绘),用于验证客户端确实按协议实时计算,而非回放固定值。

> 注:防重放的**决定性保证来自 §4.1(1) 的一次性 nonce**,掺种子是纵深增强,
> 不是主锁。避免把安全性寄托在"结果每次不同"这一不可被服务端独立验证的性质上。

### 4.2 被动信号的正确定位(修正 JA3 定位)

TLS JA3/JA4 **不是高熵个体识别信号,也不是不可伪造**:
- 熵极低:百万级同型号 Chrome 共享同一 JA3,**不能作为 visitorId 主来源**。
- 可伪造:curl-impersonate / utls 能构造任意 ClientHello。

其真正价值是**一致性交叉校验**,权重体现在 confidence 而非 visitorId:
- JS 自报 Chrome/Win,但 JA3 是 Python/Go 栈 → 强异常,confidence 大幅下调。
- HTTP/2 SETTINGS 帧顺序、TCP 参数与自报浏览器不符 → 异常。
- IP 信誉(数据中心/代理/风险库)→ 辅助信号,非决定。

**部署约束(硬性)**:连接层被动信号(JA3/JA4 + HTTP/2 帧指纹)只有**终止客户端连接的那一方**能采集。
入口挂在 Cloudflare 代理模式下,源站看到的 TLS/HTTP2 是 **CF↔源站**段,客户端连接层信号需 Cloudflare 透传才能拿到。

- **当前实现(拓扑①)**:由 **Cloudflare 提取 JA3/JA4 并经 header 透传**到源站。
  - **可用性取决于账号**:JA3/JA4 header 绑定 **Bot Management**(企业版)。
    部署账号有则用,**没有则自动降级**——该请求连接层信号置空并降权,**不阻断主流程**
    (仍保留 IP 层信号:真实客户端 IP 经 `CF-Connecting-IP` 可得 → IP 信誉/ASN/机房识别)。
    ("Full 模式回源校验"是 CF↔源站证书校验,与客户端指纹无关,不提供 JA3/JA4。)
  - **安全硬要求**:源站入口必须**剥离/覆盖客户端自带的同名 header**,只信任来自
    Cloudflare 的那一份(回源鉴权 / IP allowlist 保证来源可信),否则客户端可自塞假 JA4。
- **后续扩展(TODO,非当前实现)**:自管 nginx/envoy 边缘提取 JA4 并注入可信 header
  (脱离 Bot Management 依赖、可控字段格式)。视规模与账号情况再启动。

> 无需全站取 JA4:仅 `/challenge`、`/identify` 端点需要,当前直接复用 Cloudflare header 即可。

### 4.3 模糊匹配与候选集生成(补足性能真相)

模糊匹配**不是哈希查表**,不能全库线性扫。分两步:

1. **候选集生成(blocking / ANN)**:用高稳定、高区分的分量(如 canvas hash 前缀、
   webgl vendor+renderer、时区+语言)构造 blocking key 或做近似最近邻(LSH),
   把候选压到几十~几百条,而非全库。
2. **加权模糊评分**:对候选逐一计算相似度——
   - 分量分权:稳定分量(webgl/canvas)高权,易变分量(字体列表/分辨率)低权;
   - N 中 M 容错:允许少数分量不匹配;
   - 时间衰减:近期出现的指纹权重更高;
   - 阈值:得分 ≥ T_hi 判为同一 visitorId;T_lo~T_hi 归为"疑似"低 confidence;< T_lo 判新设备。

> 首版可用 blocking key + 内存倒排;规模上来后再引入向量 ANN。此为已知最难点,
> 详见独立设计文档 `design-fuzzy-matching.md`(打分采用 Fellegi-Sunter 概率记录链接模型)。

### 4.4 客户端采集选型:复用 FingerprintJS / BotD

客户端只负责采集,判定全在服务端(§4)。采集器**复用现成 MIT 库,不自造轮子**,
但明确复用边界——这两个库只覆盖客户端采集的一部分,不提供本项目的差异化能力
(nonce 防重放、JA4 被动信号、服务端模糊匹配均自建)。

| 库 | 许可证 | 复用方式 | 边界 |
| --- | --- | --- | --- |
| **FingerprintJS**(OSS v5) | MIT | npm 依赖,取其 **`components` 原始值** 作为 `stable_components` | **丢弃其客户端 visitorId 哈希**(即本项目要抛弃的"客户端判定") |
| **BotD**(OSS) | MIT | npm 依赖,机器人信号并入服务端 confidence | 客户端信号**可伪造**,仅作次要输入;OSS 版仅基础检测 |

**依赖优先,fork 只在必要处**:
- 用 npm 依赖可白嫖其跟随浏览器更新的采集器维护;vendor/fork 则需自行维护,浏览器一变即腐化。
- **必须自写**的部分:**nonce 挑战分量(§4.1)**——FingerprintJS 不支持"nonce 混入
  canvas/audio 绘制种子",需单独写 nonce-seeded 挑战采集器(可以其 canvas/audio 采集器为基底)。
- **后续可 patch**:P3 的 WASM 采集壳、剥离遥测/upsell。

**落地节奏**:P0 直接依赖取稳定分量;做防重放时再补一个自写的 nonce 挑战采集器。

> 实现注意:核对所拉包的 LICENSE 为 MIT 开源库,勿误引其商用 Pro SDK。

---

## 5. 接口契约(草案)

### GET /challenge
```
Resp 200: {
  nonce: string,          // 服务端签发,一次性
  expires_in: 30,         // 秒
  collect: {              // 采集参数(可下发探针项)
    stable: [...],
    challenge: { seed: nonce, targets: ["canvas","audio"] }
  }
}
```

### POST /identify
```
Req: {
  nonce: string,
  ts: number,                       // 客户端时间戳
  stable_components: { ... },       // 原始值,不含 nonce
  challenge_response: { ... }       // 掺 nonce 的绘制结果
}
Resp 200: {
  visitorId: string,
  confidence: 0.0~1.0,
  is_new_device: boolean,
  signals: {                        // 供风控消费,不回传原始被动信号
    ua_tls_consistent: boolean,
    ip_risk: "low"|"medium"|"high"
  }
}
Resp 401: nonce 过期/复用 → 拒绝
```

被动信号(JA3/JA4/IP)由服务端从连接侧独立获取,**不接受客户端上报**。

---

## 6. 数据模型(草案)

- `fingerprints`:visitorId、稳定分量原始值、blocking key、首次/末次见到时间、出现次数。
- `nonce`(Redis):nonce → {issued_at, used}, TTL = expires_in,用后即焚。
- `observations`(可选,合规允许下):每次 identify 的信号快照,供后续关联分析。

---

## 7. 隐私与合规(阻塞项,不可省)

服务端存储 components 原始值,敏感度高于纯客户端方案,首版必须明确:

- **法域与法律基础**:GDPR/CCPA/PIPL 下设备指纹通常构成个人数据,需 consent 或
  合法利益评估(反欺诈通常可走"合法利益",但须 DPIA 记录)。
- **数据最小化**:只存风控必需分量;评估是否可存哈希而非原始值(与模糊匹配权衡)。
- **留存期限**:fingerprints 与 observations 设 TTL;超期删除。
- **用途限定**:仅用于反欺诈,禁止用于广告/追踪(否则合规基础改变)。
- **透明度**:在隐私政策中披露设备指纹用途。

> 合规结论未定前不进入生产。此项与 §2 场景强绑定。

---

## 8. 分期落地

- **P0 骨架**:/challenge + /identify + nonce 一次性(Redis)+ 稳定分量精确回退匹配。
  验收:防重放 100%,端到端打通。
- **P1 模糊匹配**:blocking key + 加权评分 + 阈值。验收:稳定率 ≥ 95%,碰撞率 ≤ 1%。
- **P2 被动信号**:IP 信号 + UA/JS 一致性 + Cloudflare JA3/JA4 header(有则用、无则降级,§4.2)。
  验收:L1/L2 识别率 ≥ 90%(在拿到连接层信号的账号下)。
- **P3 加固**:WASM 采集壳、探针项、响应签名;规模化后引入 ANN。

技术栈落点(Rust):
- 服务端:nonce 管理 + 模糊匹配引擎 + 高并发查询。
- 网络层:ClientHello 解析出 JA3/JA4(`rustls` / 自定义解析)。
- 客户端:WASM 采集壳(P3,纵深防御非决定性)。

---

## 9. 待解决问题(Open Questions)

1. ~~场景确认~~ → **已定档:反欺诈**(§2)。
2. ~~TLS 终止拓扑~~ → **已定档:Cloudflare header 透传(拓扑①)**,JA3/JA4 取决于账号 Bot Management,
   取不到自动降级;自管 nginx/envoy 为 TODO(§4.2)。
4. **候选集生成方案**:blocking key 够不够,何时上 ANN?需独立设计文档(§4.3)。
5. **原始值 vs 哈希存储**:合规最小化与模糊匹配精度的权衡(§6/§7)。
6. **confidence 融合模型**:各信号权重是规则加权还是学习模型?首版建议规则。
