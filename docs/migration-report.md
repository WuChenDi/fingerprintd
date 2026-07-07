# fingerprintd 仓库结构迁移报告(对齐 gino,scope A)

> 类型:仓库级组织约定迁移 ｜ 记录人:L1 ｜ 2026-07-06
> 关联:BKD 项目 `qdxgw8qt` / L1 issue `d5kfhl46`
> 参考:`/srv/gino`(pma-bun 项目:Bun + drizzle + eslint @antfu,`src/modules` + `tests/{unit,integration,contract}` + `docs/` + `scripts/`)

---

## 1. 范围界定(已与用户确认 = A)

**仅仓库级组织约定对齐**,不改 Rust 服务端语言/分层。

- ✅ 纳入:`docs/` 归位、`scripts/`、`.github/workflows` 结构、README、TS 客户端测试命名。
- ❌ 排除:Rust 服务端重写、`src/modules` 化(TS 约定,不适用 Rust)、顶层 `tests/` 化(与 Cargo 惯例冲突)。
- ⏸ 单列 backlog:**P-CF**(CF Workers 部署 = TS Worker host + Rust→WASM 计算核心 + D1/DO 状态)——独立大项目,非本次。

## 2. 根本约束(为何不能字面照搬 gino)

gino 与 fingerprintd 是**镜像相反的混合栈**:gino = TS host 为主 + Rust runner 为辅;fingerprintd = **Rust server 为主** + TS 客户端 + Rust WASM。gino 的 `src/modules`、`tests/{unit,integration,contract}` 是 **TS/Bun 约定**,**对 Rust 主体不适用**:

- Rust 走 cargo 惯例:单测在 `src/*.rs` 内、集成测试在 `crates/*/tests/`——**不能搬到顶层 `tests/`**,否则与 Cargo 打架。
- `crates/*` 布局、in-crate 测试是**正确的 Rust 结构,保持不动**。

故 A 实际落在**文档 / 脚本 / CI / README**这层。

## 3. 迁移映射

| # | 动作 | 现状 → 目标 | 注意 |
|---|------|-------------|------|
| M1 | docs 归位 | 根 `prd.md` / `design-fuzzy-matching.md` / `audit-report.md` / `migration-report.md` → `docs/`(`audit-report.md` → `docs/audit/`) | **必须同步更新引用**:`crates/fingerprintd/src/fuzzy/mod.rs`(doc 注释指向 design 文档)+ `README.md`(指向 prd.md) |
| M2 | README 对齐 | 顶层 README 补"项目结构"段,指向 `docs/`;**修正过时状态**("P0 skeleton" → P0–PC 全量 + 客户端壳) | 不夸大;标注真实测试数(server 85 / client 34 / wasm 3) |
| M3 | scripts/ | 新增 `scripts/`,放跨栈 helper(如 `check.sh` 串联 Rust+TS 双门、`clean`) | 对齐 gino `check` 概念(lint+typecheck+test+build);纯脚本,不改构建逻辑 |
| M4 | CI 对齐 | `.github/workflows/ci.yml` 结构/命名对齐 gino,确保 Rust 门 + TS 门 + WASM 门都在 | 只调结构,不弱化门 |
| M5 | 客户端测试命名 | `clients/web/test` → 对齐 `tests/{unit,integration}` 命名(TS 侧) | 仅 TS;Rust 侧不动 |

**DAG**:M1(docs+引用)→ M2(README 依赖 docs 落位);M3 / M4 / M5 相互独立,可并行。

## 4. 验收

- 每个 L3 过对应质量门:Rust 侧 `cargo fmt/clippy -D/nextest/build/deny`(server 85 不破);TS 侧 `biome check + tsc + vitest 34 + build`;WASM `cargo test -p fp-wasm 3`。
- **无死引用**:移动 docs 后 grep 全仓无指向旧根路径的链接。
- 迁移是**纯组织性**:无任何服务端判定逻辑/客户端采集逻辑变更(diff 只含文件移动 + 引用/文档/脚本/CI)。

## 5. 下一步

1. 本报告已记录("先记录报告")。
2. **待用户确认**:按 §3 起 BKD campaign 处理 M1–M5?
3. 确认后 L1 创建 L2(useWorktree)→ 分解 M1–M5 为 L3 调度 → 各过门 → L1 审后合并 main。
