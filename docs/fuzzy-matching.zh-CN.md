# 模糊匹配引擎

[English](fuzzy-matching.md) · **中文**

> [architecture.md §4.3](architecture.zh-CN.md#43-模糊匹配与候选集生成)
> 背后的第二阶段匹配引擎。
> 目标（[architecture.md §3](architecture.zh-CN.md#3-成功指标)）：稳定率 ≥ 95%，
> 碰撞率 ≤ 1%，决策 P99 ≤ 50ms，单实例 ≥ 2k RPS。

各章节编号是稳定锚点——源码文档注释以 `§N` 形式引用它们。

---

## 1. 问题定义

输入：一次观测的稳定组件集合，`probe = {c_1, …, c_n}`。
输出：匹配到的 `visitorId`（同一设备）或新设备判定，外加一个
`confidence`。

三条约束彼此拉扯：

- **De-avalanche（去雪崩）** —— 单个组件变化（浏览器自动升级、新装字体、
  外接显示器）不得铸造出新的 `visitorId`。
- **Anti-collision（防碰撞）** —— 两台同型号 + 同浏览器版本的不同设备不得
  解析为同一个 `visitorId`。
- **高吞吐** —— 百万级记录库不可能对每次请求做线性扫描。

两个核心决策：

1. **两阶段** —— 候选生成（§4）→ 概率打分（§5）。
2. **打分采用 Fellegi–Sunter (FS) 概率化记录链接模型**（§5），
   而非手工调参的加权平均 —— FS 的两个参数 `m_i / u_i`
   分别对 *稳定性* 与 *区分度* 建模，天然对应上述两种失败模式。

---

## 2. 分量分类(建模前提)

每个组件在两条正交轴上被刻画 —— 这是每一个权重的来源：

- **Stability（稳定性）** —— 同一设备多次访问间该组件保持不变的概率
  （→ FS `m_i`）。
- **Distinctiveness（区分度）** —— 两台不同设备取相同值的概率（→ FS `u_i`；
  越罕见 `u` 越低）。

| Component | Type | Stability | Distinctiveness | Notes |
|---|---|---|---|---|
| WebGL vendor+renderer | category | high | medium | GPU 硬件，极少变化 |
| Canvas hash | category | med-high | high | 驱动/浏览器升级时整体翻转 |
| Audio fingerprint | category | high | med-high | 音频栈，稳定 |
| Font list | set | medium | high | 增量变化 → Jaccard/MinHash |
| Timezone / language / platform | category | high | low | 低熵，单独不足 |
| Screen resolution + depth | numeric | medium | med-low | 外接显示器会改变它 |
| CPU cores / device memory | numeric | high | low | |
| Browser version / UA | version | **low** | medium | **雪崩之源**，每隔几周自动升级 |
| Plugins / mimeTypes | set | medium | medium | |

> 关键洞见：UA/浏览器版本频繁变化 —— 精确哈希会不断铸造出
> “新设备”，这正是 FingerprintJS 的雪崩问题。在 FS 下它的 `m_i`
> 很低，因此一次失配几乎不惩罚；它会自动淡出。

---

## 3. 存储表示

为满足数据最小化
（[architecture.md §7](architecture.zh-CN.md#7-隐私与合规)），在保留匹配能力的同时
从不存储原始值：

- **Category 组件** —— 存储加盐哈希 `H(salt || value)`。仍支持
  相等比较 + 频次统计（用于 `u_i`）。
- **Set 组件（fonts 等）** —— 存储 **逐元素哈希** 后的集合
  `{H(f) for f in fonts}`。逐元素哈希 **保留 Jaccard**，因此集合
  相似度 + MinHash 仍然可用。
- **Numeric 组件** —— 存储该值或分桶后的值。
- 每个 `visitorId` 还存储：各组件的最新值、`first_seen`、
  `last_seen`、`observation_count`，以及用于漂移的逐组件新鲜度（§7）。

---

## 4. 阶段一:候选集生成(blocking)

目标：从百万级记录库中，以近 O(1) 得到数十到数百个候选，
**且不漏掉真正的匹配**（召回优先）。

不能只用单个精确键 —— 任意一个组件变化就会漏掉。要用
**多个相互独立的分块键，取并集** 以获得召回冗余：

- `K1 = H(webgl_renderer || platform || timezone)` —— 一个高稳定性子集
- `K2 = H(audio_hash || cpu_cores || device_memory)` —— 一个不相交的高稳定性子集
- `K3 = MinHash-LSH(font set)` 的 band 桶 —— 容忍字体的增量变化
- （可选）`K4 = Simhash(all-component tokens)` 的 Hamming 近邻桶

召回率 = 1 − P(所有键都漏)。每个键使用不相交的稳定组件子集，因此
当某个组件恰好变化时，另一个键仍能命中。候选集 = ∪（各键命中的
`visitorId`）。

**索引** —— `blocking_key → set<visitorId>` 倒排索引。MinHash-LSH：
`band signature → bucket → visitorId`。

**热块膨胀** —— 一个流行配置（默认 Safari 的 iPhone）会让某个块
变得巨大（信息量低）。缓解：

- 限制块大小；超过上限后该键携带的信息很少、无法收窄
  候选 —— 必须由第二阶段打分（§5）来消歧；
- 超上限的丢弃 **必须记录日志**（不得静默截断），从而杜绝
  “看似覆盖实则没有”。

---

## 5. 阶段二:概率打分(Fellegi–Sunter)

对每个候选 `cand` 与 `probe`，逐组件比较并累加
对数似然比。

### 5.1 单分量一致性 `agree_i`

- Category —— 哈希相等 → agree，否则 disagree。
- Set —— Jaccard `J = |A∩B| / |A∪B|`；`J ≥ τ` → agree（τ ≈ 0.8），否则
  线性插值（见 5.3）。
- Numeric —— 相等或同桶 → agree。
- Version —— 主版本相同 → agree；相邻主版本 → partial（见 5.3）；否则 disagree。

### 5.2 两个参数

- `m_i = P(agree_i | same device)` —— 由 **高置信匹配的回访** 估计；
  对稳定性建模。
- `u_i = P(agree_i | different device)` —— 由该组件取值在 **库中的频率** 估计；
  对区分度建模。罕见值 → `u_i` 极低 → 相等是强证据；
  常见的 Chrome/Windows 值 → `u_i` 高 → 相等几乎不算数。

### 5.3 单分量得分

```
agree:      w_i = log2( m_i / u_i )                      // positive; rarer = larger
disagree:   w_i = log2( (1 - m_i) / (1 - u_i) )          // negative; more stable = more negative
partial (set/version): w_i = J · log2(m_i/u_i) + (1-J) · log2((1-m_i)/(1-u_i))
missing (either side lacks it): w_i = 0                  // not compared, not scored (see §8)
```

合计：`score(cand) = Σ_i w_i`。

**为什么该模型是对的：**

- **De-avalanche** —— UA 的 `m_i` 很低 → `(1-m_i)/(1-u_i)` ≈ 1，`log` ≈ 0 → 一次 UA
  失配几乎不惩罚。
- **Anti-collision** —— 两台同型号设备在高熵组件
  （canvas/fonts）上不一致，而它们的 `m_i` 很高 → 该不一致带来大的负值，
  把总分拉到阈值以下 → 判为不同设备。
- **Low-entropy auto-fade（低熵自动淡出）** —— timezone/language 的 `u_i` 很高 → 一致几乎不
  加分，因此“同处一个时区”永远不会强制匹配。

### 5.4 判定

取最高候选 `best`；两个阈值 `T_hi > T_lo`：

- `score(best) ≥ T_hi` → **同一设备**；返回其 `visitorId`，应用漂移（§7）。
- `T_lo ≤ score(best) < T_hi` → **疑似**；返回该 `visitorId`，但降低
  置信度并打上 `review` 标记。
- `score(best) < T_lo` → **新设备**；铸造一个全新的 `visitorId`。
- **≥ 2 个候选 ≥ T_hi 且差距很小** → 碰撞风险；取最高者并抬起
  一个 `collision_risk` 标记。

---

## 6. confidence 输出

`confidence ∈ [0,1]`，由三部分融合而成（规则加权；当前版本无
学习模型）：

- **Match margin（匹配裕度）** —— `score(best)` 超出 `T_hi` 的幅度，加上与次高者的差距
  （差距越大 → 越确定）。
- **Passive-signal consistency（被动信号一致性）** —— JA4/UA 一致 → 提升；不一致 → 大幅
  下调（防伪造的核心，
  [architecture.md §4.2](architecture.zh-CN.md#42-被动信号与信任边界)）。
- **Component completeness（组件完整度）** —— 有多少组件参与了比较；缺失越多 → 置信度
  越低（§8）。

---

## 7. 漂移(模板自适应)与投毒防护

若无漂移，已存组件（UA 等）会陈旧，几次浏览器升级后匹配
质量下降。规则：

- **仅在高置信匹配（≥ T_hi）时** 刷新该 `visitorId` 的最新
  组件值与 `last_seen`。
- **模板投毒防御** —— 攻击者可能通过反复的低置信匹配，把 A 的指纹缓慢
  改造成 B。因此：
  - 低置信 / review 命中 **不** 触发更新；
  - 原始观测历史被保留；更新只覆盖
    “最新值”层，绝不覆盖历史；
  - 单次更新的变化幅度有上界；异常跳变会被标记。

---

## 8. 边界情况

- **隐私浏览器屏蔽 canvas（null/空）** —— 缺失组件计 `w_i = 0`
  且不参与比较。绝不能把“null canvas”当作可匹配的值 —— 否则
  所有隐私用户在该组件上都一致 → 大规模碰撞。缺失越多 → 置信度越低。
- **Brave 式的按会话 canvas 随机化** —— 该组件在同一设备的每次访问
  都变化 → `m_i → 0`，因此 FS 会自动忽略它，回退到
  fonts/audio/webgl。进阶：识别出 canvas 始终变化的一类人群，并为其屏蔽
  该组件（未来）。
- **企业金镜像 / 完全相同的 VM** —— 真正不同的设备却有
  完全相同的指纹；模糊匹配无法区分它们，会发生碰撞。必须
  回退到 IP + 账户行为；这是一条 **已知能力边界**，
  本引擎不解决。

---

## 9. 参数估计与冷启动

- `u_i` —— 维护逐组件取值的频次计数，在存储中增量更新。
- `m_i` —— 需要“同设备回访”标签。冷启动使用 **先验**（依 §2
  分类：高稳定性 = 0.95，中 = 0.80，低 = 0.50）；上线后，
  在高置信匹配回访上做 **EM 迭代** 使其收敛。这是一个
  迭代过程，而非一次性完成。
- 冷库阶段：一切都被判为新设备；分块索引与
  频率统计随时间逐步积累。

---

## 10. 离线评估

证明 §3 的目标，首先需要一个带标注的评测集：

- **Ground truth（真值）** —— 用登录态 / 长效 cookie 标注“同一设备的
  多次访问”。
- **Stability rate（稳定率）** —— 同设备回访被解析到单一 `visitorId` 的比例
  （扫描 `T_hi`）。
- **Collision rate（碰撞率）** —— 不同设备被解析到单一 `visitorId` 的比例。
- 网格搜索 `T_lo / T_hi / τ` 与组件先验；绘制
  稳定–碰撞权衡曲线以设定阈值。
- 上线后，持续把 review/collision_risk 样本重新喂给人工评审，
  以精炼 `m_i/u_i` 与阈值。

> 本仓库附带一个合成夹具，用于 **方向性地** 检验打分接线 ——
> 它是冒烟测试，而非数值目标的证据。它打印的
> 比率不得当作生产环境的稳定率/碰撞率数字来报告。

---

## 11. 数据结构与性能

| Use | Structure | Notes |
|---|---|---|
| Blocking inverted index | `key → set<visitorId>` | 内存 / Redis Set / PG GIN |
| MinHash-LSH | `band signature → bucket` | 面向 set 组件的召回 |
| Fingerprint library | `visitorId → component hashes + frequency material + timestamps` | KV / D1 / PG |
| Frequency stats | `component value hash → count` | 估计 `u_i` |

性能：第一阶段为 O(candidates)；第二阶段为 O(candidates × 常数
组件数)。把候选控制在低数百量级即可满足 P99 ≤ 50ms。在
原生服务器上，倒排索引 + 打分常驻内存；频率/指纹库
持久化层异步落盘。

---

## 12. 待解决问题

1. set 组件的 MinHash band 数量 / τ —— 需要真实数据测量。
2. EM 收敛 `m_i` 需要多少带标注的回访样本。
3. 块大小上限，以及超上限人群的回退方案（强制高熵一致？）。
4. 频率统计的时间衰减窗口（对陈旧值降权？）。
5. 是否按设备人群分层做参数估计（移动端 vs 桌面端的 `m/u` 不同）。
