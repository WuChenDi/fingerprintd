# fingerprintd PRD 审计报告

> 类型:需求文档审计(对原始 `prd.md` 的评审记录) ｜ 记录人:L1 ｜ 2026-07-06
> 关联:BKD 项目 `qdxgw8qt` / L1 issue `d5kfhl46`
> 范围:仅审计 PRD 与配套设计文档,**不含代码**(当前无代码库)。

---

## 1. 审计结论

原始 PRD 架构方向正确(判定权归服务端 + challenge 时效 + 多源融合),但存在 **2 个致命技术矛盾、
2 个高危缺失、2 个部署/选型盲点**。全部 6 项已在评审中逐条处置并落回文档,**当前无未闭合的设计缺陷**;
剩余为需在实现阶段拍板的**开放决策**(见 §3)。

---

## 2. 审计发现(Findings)

| ID | 级别 | 问题 | 根因 | 处置 | 状态 |
| -- | ---- | ---- | ---- | ---- | ---- |
| F1 | 致命 | nonce 掺入 canvas/audio 绘制种子,与"指纹稳定性"直接冲突——每次输出都变则无法匹配 | 混淆了"防重放新鲜度"与"身份匹配"两类信号 | 分量拆分:**稳定分量**(不掺 nonce,匹配用)+ **挑战分量**(掺 nonce,仅证明新鲜);防重放主锁改为一次性 nonce | 已解决 → PRD §4.1 |
| F2 | 致命 | JA3/JA4 被定位为"决定性、客户端改不了"的识别信号 | 高估:utls/curl-impersonate 可伪造,且熵极低(百万级共享) | 重定位为**一致性交叉校验**,权重进 confidence 而非 visitorId;补 TLS 终止点部署约束 | 已解决 → PRD §4.2 |
| F3 | 高 | 模糊匹配当成"高吞吐哈希查表",忽略其非哈希本质 | 未意识到模糊匹配不能全库线性扫 | 两阶段:候选集生成(blocking/LSH)→ Fellegi-Sunter 概率打分 | 已解决 → `design-fuzzy-matching.md` |
| F4 | 高 | 缺 PRD 核心要素:威胁模型、成功指标、隐私合规、接口契约、数据模型 | 文档是架构论证草稿而非 PRD | 补齐 §2 威胁模型 / §3 指标 / §5 接口 / §6 数据模型 / §7 合规 | 已解决 → PRD §2/§3/§5/§6/§7 |
| F5 | 中 | 依赖 Cloudflare 透传 JA3/JA4,但免费版不提供(仅企业版 Bot Management) | 未核实 CF 套餐能力;代理模式下客户端连接层信号本就丢失 | 拓扑①为准 + **取不到自动降级**(连接层信号置空不阻断);自管 nginx/envoy 列为 TODO | 已解决 → PRD §4.2 |
| F6 | 提示 | 客户端采集是否自造 | 未定复用边界 | 复用 MIT 的 FingerprintJS(取 components,弃其 visitorId)+ BotD(信号入 confidence);仅 nonce 挑战采集器自写 | 已解决 → PRD §4.4 |

---

## 3. 遗留开放决策(实现阶段须闭合)

来自 PRD §9 与 `design-fuzzy-matching.md` §12,均为**待拍板项**,非设计缺陷:

- **D1 连接层信号取法**:拓扑①(CF header,依赖账号 Bot Management)/ 自管 nginx-envoy 何时启用。
- **D2 存储形态**:类别/集合分量存原始值 vs 哈希——合规最小化 vs 匹配精度权衡。
- **D3 候选集参数**:blocking key 组合、MinHash band 数 / τ、block 大小上限与兜底。
- **D4 打分参数估计**:`m_i/u_i` 冷启动先验 + EM 收敛所需标注样本量。
- **D5 confidence 融合**:规则加权(首版)vs 学习模型。
- **D6 评估集**:登录态/长期 cookie 地面真值,用于验收稳定率/碰撞率并调阈值。

---

## 4. 实施任务拆分建议(待用户确认后转 L2/L3)

> 技术栈:Rust(pma-rust 基线)。以下为**建议**,派工前需用户确认范围与优先级。

**阶段划分对齐 PRD §8(P0→P3):**

- **T1 项目骨架**:pma-rust workspace、Axum 服务、配置、CI 质量门(lint/test/build)。
- **T2 challenge/identify 接口 + Redis nonce**:一次性 nonce 签发/校验(防重放主锁),接口契约见 PRD §5。
- **T3 数据模型 + 指纹库存储**:fingerprints / nonce / observations,决策依赖 D2。
- **T4 模糊匹配引擎**:候选集生成(blocking/LSH)+ Fellegi-Sunter 打分,依赖 `design-fuzzy-matching.md`、D3/D4。
- **T5 被动信号接入**:CF header 解析 JA3/JA4 + IP 信号 + UA/JS 一致性 → confidence,依赖 D1。
- **T6 客户端采集壳**:接入 FingerprintJS/BotD 取 components + 自写 nonce 挑战采集器。
- **T7 评估与验收**:评估集 + 稳定率/碰撞率/延迟指标验证,依赖 D6。

**DAG 依赖**:T1 → T2 → {T3 → T4, T5, T6} → T7。

---

## 5. 建议下一步

1. 本报告已记录(满足"先记录报告")。
2. **待用户确认**:是否按 §4 拆分启动实现?范围是"全量实现 P0–P3"还是"先闭合开放决策 D1–D6 再实现"?
3. 确认后,L1 创建 L2 派工issue(useWorktree),由 L2 分解为 T1–T7 的 L3 并调度。
