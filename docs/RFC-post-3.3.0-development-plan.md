# RFC: Post-3.3.0 Development Plan（v3.3.0 黄金基线后续开发计划）

> 状态：已批准（2026-08-24 总体评审通过）
> 基线：`v3.3.0`（2026-08-24 正式发布）
> 评审结论：范围、工作包治理、依赖、门禁与估算可作为后续实施依据；WP-01–WP-06 仍保持 `proposed`，须分别满足 `ready` 条件后开工。
> 关联：
> - 条件输出现状与历史设计：`docs/RFC-conditional-output-CN.md`
> - 发布流程：`docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md`
> - 无值守 A/B 操作流：`docs/UNATTENDED_AB_OPERATION_FLOW_CN.md`
> - 主子线备忘：`docs/RFC-whois-client-split.md`
>
> 本文档是 post-3.3.0 后续实施工作的主规划入口：所有 Phase/工作包必须在本文档登记后开工，完成回填后关闭。

## 1. 背景与目标

v3.3.0 已作为新黄金基线发布，产品语义冻结（响应分类契约、地址空间前置分类器、DNS/重试策略、标题/尾行/折叠输出契约均视为强契约）。本次发版暴露并确认了以下工具链与规划问题：

1. **一键发布版本号竞态**：`one_click_release.ps1` 在 `skipTag=true + buildSync=true` 时，构建先于标签创建，远程构建脚本退化为 `git describe` 得到旧版本串（`v3.2.12-663-g8328aad1`），已错误发布过一次并修正。
2. **校验清单漏暂存**：脚本只 `git add ...\whois-*`，`SHA256SUMS-static.txt` 不在暂存集合（已修复于 `c68f622f`，但缺回归断言）。
3. **令牌回显风险**：`GITEE_TOKEN` / `GH_TOKEN` 曾以明文出现在命令回显与日志中。
4. **遗留项定性**：standalone selftest 的 `injection-view-fallback: FAIL` 为历史遗留、非本轮回归，尚未正式定性或修复。
5. **RFC 历史叠加**：`RFC-conditional-output-CN.md` 是历史叠加稿，部分设计（如 `--fold kv`）已被现状替代或与现有 CLI 冲突，不能直接按旧路线开工。

### 目标（排序）

1. 完成发布工具链根因修复与防回归（Phase 1）。
2. 建立可重复、离线、多架构的性能黄金基准（Phase 2）。
3. 重定版条件输出 Phase 2.5，并按风险从低到高增量落地（Phase 3）。

### 1.1 总体评审记录

- 评审日期：2026-08-24。
- 结论：通过，无总体阻断项。
- 批准范围：Phase 1–3 的目标与非目标、WP-01–WP-06 编号与依赖、执行方式判定、适用门禁、风险缓冲和回填机制。
- 保留门禁：总体批准不批准尚未冻结的 CLI 细节，不授权创建 A/B 任务定义，也不使任何工作包自动进入 `ready` 或 `active`。
- 后续评审：每个工作包开工前完成 `ready` 评审；WP-03–WP-06 还须先通过 5.5 的 CLI 契约定稿门禁；采用无人值守 A/B 时另行评审 Vx 任务定义与 start-file。

### 1.2 截至基线日的现状账本

本表用于区分“已经落地但缺证据”“尚未实现”和“已有能力待复用”，避免按问题清单重复开发。状态变化必须在执行回填中更新，不以聊天结论替代。

| 事项 | 2026-08-24 现状 | 后续动作 |
|---|---|---|
| 校验清单暂存 | `c68f622f` 已显式暂存 `whois-*` 与 `SHA256SUMS-static.txt` | 只补 dry-run 回归断言，不重复修改暂存逻辑 |
| 标签/构建顺序 | 当前仍先创建 tag，再执行 build/sync/commit | WP-01 调整顺序并增加强制版本 fail-close |
| token 传递 | 当前 Bash 命令串内联 token，且 `Invoke-GitBash` 会回显完整命令 | WP-01 改为不进入命令文本和日志的传递方式并加泄漏断言 |
| `injection-view-fallback` | standalone selftest 已知 FAIL，未完成正式定性 | WP-01 独立实施项修复或结构化 known-issue |
| workbuf 统计 | 已有 `WC_WORKBUF_ENABLE_STATS`、查询级和 selftest `[WORKBUF-STATS]` | WP-02 复用并冻结现有字段，不新造平行统计协议 |
| 条件输出新 CLI | `--no-body`、`--print-meta`、`--print-chain`、`--pick`、`--stats` 尚未实现 | WP-03–WP-06 按契约定稿门禁依次实施 |

## 2. 原则与红线

- **默认行为零变化**：所有新能力一律 opt-in，默认运行输出与原版本完全一致。
- **黄金对照**：任何行为变化必须能与 `v3.3.0` 制品做 diff 级对照；Golden/Batch/Selftest 基准同步更新，禁止静默改期望。
- **输出分工不变**：stdout 仅业务输出；stderr 仅诊断/指标；新标签沿用既有风格，禁止改名。
- **BusyBox 友好优先**：采用行式 `k=v`（TAB 分隔）朴素文本协议；JSON/CSV 延后，默认不提供。
- **DNS/重试冻结**：`v3.2.8–v3.2.9` 冻结的候选/健康/回退策略只允许可观测性或 bugfix 级别改动。
- **工作包与执行方式解耦**：本文使用 `WP-xx` 标识规划工作包；`A/B <n>` 只表示实际启动的无人值守 A/B 会话，不预留、不推定，也不与 `WP-xx` 一一对应。
- **A/B Vx-first（条件适用）**：仅当开工评审决定采用无人值守 A/B code-change 8R 时，才分配当时连续可用的 A/B 串行号，并从 `testdata/autopilot_code_step_tasks_vx_template.json` 编制成对任务定义。任务定义须保留 `schemaVersion=vx-draft`、`qualityPolicy.operationSafetyPolicy=enforce`、TODO-free；小切片可合并，但需满足目标独立、无冲突、完整静态检查与真实编译验证，且不得借合并绕过独立评审要求。
- **文档同步**：任何改变 CLI/契约/门禁的落地必须同步 `docs/USAGE_CN.md`、`docs/USAGE_EN.md`、根目录 `RELEASE_NOTES.md`、相关 RFC 与黄金/矩阵说明。

## 3. Phase 1：发布工程收口（WP-01）

### 3.1 一键发布顺序与版本注入（硬性）

目标顺序（与现状相反）：

```
build+verify → stage statics + checksum → commit+push → create tag → publish release
```

要求：

- `one_click_release.ps1`：当 `BuildAndSyncIf=true` 时，若目标标签尚不存在，必须自动注入 `WHOIS_FORCE_VERSION=v<Version>` 到远程构建脚本（或等效强制版本机制）；不满足时 fail-close，禁止静默回退到 `git describe`。
- 标签创建必须发生在“静态产物提交并推送”之后，且标签必须指向最终产物提交。
- 提交暂存集合必须包含 `release/lzispro/whois/whois-*` **和** `SHA256SUMS-static.txt`（防回归断言）。

### 3.2 令牌脱敏

- 禁止在 `bash -lc` 命令串、终端回显与日志中出现任何 token 明文。
- 通过环境变量或临时凭据文件传递；脚本内部 `Write-Host`/`Write-Warning` 不得输出凭据。
- 增加静态自检：检索发布/远程脚本中不应存在 `TOKEN='...'` 内联模式；dry-run 输出不得包含 token。

### 3.3 一号发布 dry-run 防回归

扩展 `tools/test/oneclick_dryrun_guard_smoke.ps1`（或等价回归）断言：

- `statics_staged` 集合包含九架构 `whois-*` 与 `SHA256SUMS-static.txt`；
- 标签指向的提交包含本次产物（`tag_target_contains_statics=true`）；
- 构建版本串精确等于 `v<Version>`（无 fallback）；
- `git_state_unchanged` 在 dry-run 下仍为 true。

### 3.4 遗留项定性

- `injection-view-fallback: FAIL` 独立小切片：优先定位并修复，使 FAIL 变 PASS 并同步 selftest golden；若确认属已知边界，则正式降级为 known-issue 并在 selftest 报告中结构化标注（`SKIP/known`），两类路径均须在 RFC 与 Release Notes 记录结论。

### Phase 1 验收

- `oneclick_dryrun_guard_smoke` 断言全部 PASS。
- 一次端到端演练（可在预发布窗口）：产物版本 = `v3.3.0`（或目标版本），无竞态。
- 日志审计无 token 明文。
- 编码门禁、`git diff --check`、无 TODO。

## 4. Phase 2：性能黄金基线（WP-02）

### 4.1 离线样本与工具

- 建立固定离线响应样本集：覆盖多 RIR（APNIC/ARIN/RIPE/AFRINIC/LACNIC/IANA）、长行、CRLF、高密度续行、空/banner 响应。
- 建立仅供测试/基准使用的确定性响应注入入口，优先复用现有 selftest injection 边界；不得为基准向生产 CLI 暴露任意本地响应文件读取能力。
- 新增基准脚本（建议 `tools/dev/bench_conditional_output.ps1`，PowerShell 兼容 + Git Bash 可选）：
  - 输入：样本集 + 场景矩阵（`raw` / `-g` / `--grep` / `--fold` / `--fold-unique` / 批量 `-B`）。
  - 输出：结构化 CSV/JSON 到 `out/artifacts/bench/<timestamp>/`（内部证据，**不进入客户端输出协议**）。

### 4.2 指标

| 指标 | 说明 |
|---|---|
| wall_time_ms | 每查询与整批墙钟 |
| output_bytes | stdout 字节数 |
| peak_rss_kb | 峰值内存（可用平台） |
| reserves | workbuf reserve/view 分配观测次数（既有 `[WORKBUF-STATS]` 字段） |
| grow | workbuf 容量增长次数（既有 `[WORKBUF-STATS]` 字段） |
| max_request | 最大请求字节数（既有 `[WORKBUF-STATS]` 字段） |
| max_cap | 峰值 workbuf 容量（既有 `[WORKBUF-STATS]` 字段） |
| max_view | 峰值 view 偏移与游标之和（既有 `[WORKBUF-STATS]` 字段） |
| throughput_qps | 查询/秒 |
| scan_bytes | 实际扫描字节数（与 `--max-bytes` 预留观测） |

### 4.3 既有可观测性复用

- 查询路径已在编译期开启 `WC_WORKBUF_ENABLE_STATS` 且运行时启用 debug 时向 stderr 输出单行 `[WORKBUF-STATS] action=query reserves=... grow=... max_request=... max_cap=... max_view=...`；selftest 已输出同标签。WP-02 直接消费并为解析器增加字段兼容测试，不新增第二种标签或重命名字段。
- `[WORKBUF-STATS]` 仅进入诊断流，不得改变 stdout；默认生产构建继续允许关闭编译期统计。
- 各架构分别记录：linux x86_64、aarch64、win64（可用时）。

### 4.4 基准可重复性协议

- 固定并记录：commit/tag、编译器与版本、完整 CFLAGS/LTO 配置、目标架构、OS/CPU、样本集 SHA-256、场景参数和脚本版本。
- 主性能对比必须在同一主机、同一架构和同一构建参数下执行；跨架构数据只分别建基线，不做直接快慢结论。
- 每个场景先 warm-up，再至少执行 5 次；保存原始样本，汇总至少给出 median 与 p95，不只记录单次最优值。
- 计时前先对每个场景做正确性检查：stdout、stderr 和退出码须匹配该样本的冻结期望；正确性失败的轮次不得进入性能汇总。
- 离线场景不得访问公网或依赖 RIR 实时状态；若无法证明输入来自固定样本注入路径，该结果不得作为优化依据。
- 基准失败、样本哈希变化或工具链变化必须显式标记，不得与旧基线直接合并。

### 4.5 决策规则

- 仅依据基准结果对实际热点做优化；**禁止**无基准依据的“缓冲复用重构”。
- 基准报告随 RFC 回填保存；发现热点后按登记时下一个未占用的 `WP-xx` 编号新建独立工作包，不得与 Phase 3 功能切片混批。

### Phase 2 验收

- 基准脚本可重复执行，结果落盘并生成汇总（`summary.csv`/`summary.json`）。
- 至少保存一份 `v3.3.0` 基线报告作为对照锚点。
- 默认输出零变化；统计编译启用时，既有 `[WORKBUF-STATS]` 标签仍仅写 stderr。

### 4.6 基线回填（2026-08-24）

- 样本与场景：9 份固定离线响应，覆盖 IANA、五个 RIR、CRLF/长行/高密度续行、banner 与零字节响应；`raw/title/grep/fold/fold-unique` 各 9 例，加 `batch/all`，共 46 例。
- 执行参数：每例 warm-up 1 次、测量 5 次、每次进程内执行 1000 iterations；`raw.csv` 230 行，`summary.csv` 与 `summary.json` 各 46 项。样本集 SHA-256 为 `5dbf193e0a91b49f75d51a668fa59db2029558af350256a0da87937dcf38436b`。
- 正确性：三架构 46 例退出码、诊断指标和冻结 stdout SHA 均通过，跨架构 stdout SHA 差异为 0；Windows runner 使用 binary stdout，避免 CRT CRLF 转换污染冻结值。
- 源码锚点：`v3.3.0` 条件输出实现，仓库提交 `59990eeacae1a5c3819f6e98d740f51d01aa9ede`，叠加本工作包在压力样本中发现并以 ASan 复现的 `fold-unique` workbuf 扩容后旧指针读取修复。相对 `v3.3.0`，条件输出生产代码仅删除 `src/cond/fold.c` 两处无效旧 token 数组复制；未修复版本因 heap-use-after-free 不作为可运行性能锚点。
- 报告：win64=`out/artifacts/bench/wp02-win64-final/20260824-093556`；linux x86_64=`out/artifacts/bench/wp02-linux-x86_64/20260824-092208`；linux aarch64（QEMU）=`out/artifacts/bench/wp02-linux-aarch64-qemu/20260824-092221`。各目录均含 `raw.csv`、`summary.csv`、`summary.json`。
- 工具链：win64 MinGW GCC 13-win32；linux x86_64 GCC 13.3.0；linux aarch64 musl GCC 11.2.1，静态 runner 由 `qemu-aarch64-static` 执行。完整 CFLAGS、runner/脚本 SHA、OS/CPU 与场景参数保存在各 `summary.json`；QEMU 数据仅作为 aarch64 独立锚点，不与原生架构作快慢结论。
- 代表结果：linux x86_64 的 `fold/stress-crlf` median/p95 为 31.027/33.256 ms，`fold-unique/stress-crlf` 为 32.779/37.418 ms，`batch/all` 为 8.222/8.707 ms；均为每次 1000 iterations。当前热点证据集中在高密度 fold 路径，后续优化须另立工作包，不并入 WP-02。
- 限制：Windows PowerShell 5.1 无可靠子进程 peak working set 采样时报告 `peak_rss_kb=0`，表示该平台指标不可用，不解释为零内存；Linux 报告由 `/usr/bin/time -f %M` 采集峰值 RSS。
- 生产制品复核：纳入 `fold.c` 安全修复后，Strict `lto-auto` 默认轮无编译/LTO 告警，九架构产物及仓库内、外部 lzispro 同步目录均按本轮清单 `9/9` 匹配；Linux/QEMU、win32、win64 冒烟分别完成 `18/3/3` 条查询且标题/权威尾行一一对应、零告警，Golden 与 IANA/ARIN/AFRINIC 三起点 referral 全 PASS（`out/artifacts/20260824-094617`，299s）。本轮无需追加代码修复。

## 5. Phase 3：条件输出 Phase 2.5 重定版（WP-03–WP-06）

### 5.0 前置：RFC 定版（随 WP-03 提交文档修订）

将 `docs/RFC-conditional-output-CN.md` 重组为四栏：

- **已实现**：`-g`、`--grep/--grep-cs`（行/块+续行）、现有 `--fold`（含 `--fold-sep/--fold-unique/--no-fold-upper`）。
- **待实现（本计划）**：`--no-body`、稳定元信息输出、链路输出、轻量字段抽取、`--stats`。
- **废弃/冲突设计**：`--fold kv`（与现有 `--fold` 冲突）、`--title-grep`（已被 `-g` 替代）等。
- **风险项（暂缓）**：见 5.6。

### 5.1 WP-03：`--no-body`

- 仅抑制最终正文渲染；**不提前停止网络读取**（与 `--max-bytes` 解耦）。
- 默认保留首行 `=== Query: ... ===` 与尾行 `=== Authoritative RIR: ... ===`（契约不变）。
- 与 `-g/--grep/--fold` 组合语义：filter 先于 body 控制生效，`--no-body` 只影响最终 stdout 渲染。
- 验收：单条 + 批量 golden 新样例；BusyBox 管道样例；与现有 `--plain` 语义对照文档化。

### 5.2 WP-04：稳定元信息输出

- 新增 `--print-meta`（或 `--meta`，**不复用 `--fold` 名称**）。
- 输出行式 TAB 分隔 `k=v`：`query`、`rir`、`status`、`duration_ms`、`attempts`、`redirects`；续加字段须在 RFC 登记。
- 语义与响应分类契约一致：`status=success|error`，error 分类复用 `Failure > Non-Authoritative > Semantic Empty > Authoritative` 的最终判定。
- 默认关闭；与 `--fold`/`--no-body` 组合行为需在回填中定义并在 USAGE 示例给出。
- 验收：单条 + 批量 golden；与现有元信息（如 Address Status 行）不冲突。

### 5.3 WP-05：链路输出与轻量字段抽取

- `--print-chain`：输出重定向链 `server1>server2>...>final`（stdout 元信息行，与业务行分隔约定记录在 RFC）。
- `--pick <k1,k2,...>`：基于标题投影（复用 `-g` 前缀匹配能力）抽取字段；`--pick-mode first|join`；多行值折叠规则沿用既有续行归一。
- 字段白名单（尽力而为）：`netname`、`country`、`inetnum`、`inet6num`、`origin`、`route`、`descr`。
- **不做**跨 RIR 语义归一（`--normalize-keys` 延后）。
- 验收：`--pick` 与 `-g/--grep` 组合测试；BusyBox 管道示例；冲突字段（如大小写）示例记录。

### 5.4 WP-06：`--stats`（独立工作包）

- 批量生命周期末尾输出；输出位置（stdout 末尾 vs stderr）需先在 RFC 定稿并评审。
- 指标：总数/成功数/错误分类分布/RIR 分布/时延分位（p50/p95）。
- 与 `--no-body`、`--fold`、`--print-meta` 的组合行为必须显式定义。

### 5.5 CLI 契约定稿门禁

WP-03–WP-06 在修改产品源码前，必须先在重定版 `docs/RFC-conditional-output-CN.md` 冻结本工作包涉及的协议；存在“或”“待定”“回填时定义”的关键行为时不得开工。每项至少明确：

- stdout/stderr 归属、单条与批量记录边界、字段顺序，以及首行/正文/元信息/尾行/统计行的固定排列。
- 选项组合优先级和冲突处理，特别是 `--plain`、`-g`、`--grep*`、`--fold*`、`--no-body`、`--print-meta`、`--pick`、`--stats`；非法组合须 fail-fast，不得静默忽略。
- TAB、换行、`=`、反斜杠和不可打印字节的转义或归一规则，确保 `k=v` 输出可无歧义解析。
- 缺失字段、重复字段、大小写、空值、unknown、失败查询和部分结果的稳定表示。
- 退出码是否沿用现有查询结果；观测选项不得掩盖查询失败或改变权威判定。
- 字段新增兼容策略：既有字段名称与含义冻结；新增字段只允许追加，并同步解析器/黄金测试。
- 每个新选项的资源上限（参数长度、字段数、累计输出长度）和越界诊断。

### 5.6 暂缓（单独立项，不在本计划前装）

- `--max-bytes`（正文读取上限）：可能影响响应分类与权威判定，风险高。
- 网络读取早停/“命中即停”：影响重定向链与尾部契约，暂缓。
- 并发批量查询与限速联合控制：涉及网络行为与 RIR 限流，暂缓。
- DNS/重试策略调整：冻结区，仅可观测性或 bugfix。
- JSON/CSV 输出：非核心，默认不提供。
- `--normalize-keys`：跨 RIR 语义归一，成本高。

## 6. 工作包映射与执行治理

### 6.1 工作包与顺序

| 工作包 | 状态 | 阶段 | 内容 | 备注 |
|---|---|---|---|---|
| WP-01 | active | Phase 1 | 一键发布顺序/版本注入 + 令牌脱敏 + dry-run 防回归 | 发布脚本与本地 dry-run 防回归已落地；远程 build+sync 演练和遗留 selftest 定性待完成 |
| WP-02 | done | Phase 2 | 离线性能基准脚本 + workbuf 可观测性 + 基线报告 | 46 场景三架构安全基线与冻结 SHA 已回填；发现并修复 fold UAF |
| WP-03 | done | Phase 3 | RFC 定版 + `--no-body` | 协议、产品实现、合同 smoke 与完整发布门禁均已完成 |
| WP-04 | proposed | Phase 3 | `--print-meta` | 依赖 WP-03 的 RFC 定版，不要求与 WP-03 使用相同执行方式 |
| WP-05 | proposed | Phase 3 | `--print-chain` + `--pick` | 依赖 WP-04 的元信息定义；合并实施须单独评审 |
| WP-06 | proposed | Phase 3 | `--stats` | 输出位置与组合语义先评审，再决定执行方式 |
| 后续编号 | 未登记 | 待定 | 按基准结果单独立项的性能优化 | 每项建立独立工作包，使用登记时下一个未占用的 `WP-xx` 编号 |

`WP-xx` 是稳定的需求与回填标识，不代表任务定义文件数量、D/V 轮次或 A/B 串行号。历史 Vx A/B 55/56 仍只表示已经完成的第 55/56 份无人值守执行，不得据此把本计划的后续工作包称为 A/B 57–62，也不得提前占用这些串行号。

合并原则：仅当切片目标文件/函数域独立、无依赖冲突、合并后静态检查与真实编译验证通过时才允许合并；不为凑 A/B 轮次而合并或制造源码改动（遵 `copilot-instructions.md` 任务切片设计原则）。

### 6.2 任务类型与执行方式判定

开工前先把工作包拆成可独立验收的实施项，再选择执行方式。文件类型本身不自动决定是否使用 A/B；决定条件是风险、改动量、是否适合 D1–D4 的确定性源码变换，以及是否明确批准进入无人值守 8R。

| 实施项类型 | 典型内容 | 默认执行方式 | Vx A/B 任务定义 |
|---|---|---|---|
| DOC | RFC/USAGE/Release Notes 审核、基线报告回填、现状定性 | 文档评审或传统交互式 | 不生成 |
| TEST/TOOL | 基准、dry-run、发布或测试脚本；离线样本 | 传统交互式，小步修改并专项验证 | 默认不生成；仅获批进入无人值守 A/B 时生成 |
| PRODUCT | C 源码/头文件、CLI、输出或运行时行为 | 按风险选择传统交互式或无人值守 A/B | 传统交互式不生成；无人值守 A/B 必须生成成对 Vx 定义 |
| MIXED | 文档、脚本与产品源码组合 | 优先按可独立验收边界拆分 | 仅纳入无人值守 A/B 的目标进入完整 Vx target closure |

执行决策遵循以下硬规则：

1. 仅 DOC、审计、报告或现状定性工作，不得为取得 A/B 编号而添加源码 operation 或伪造 `noop` 任务定义。
2. 工作包需要修改源码，不等于必须运行 A/B；小而清晰、可即时专项验证的改动可采用传统交互式开发。
3. 一旦决定运行无人值守 A/B，须按开工时仓库状态分配真实串行号，编制并完整验收 A/B 两份 Vx 任务定义及 start-file；编号写入执行记录，不回写替代 `WP-xx`。
4. 一个工作包可拆成多个实施项并采用不同执行方式；一次 A/B 也可在满足独立、无冲突和验证覆盖条件时承载多个小工作包。两者通过回填中的 `执行映射` 关联。
5. 未完成执行方式评审前，路线图只登记 `WP-xx`，不得预建空任务定义、预留 A/B 编号或推断任务定义文件名。

### 6.3 生命周期、依赖与完成定义

每个工作包使用 `proposed -> ready -> active -> blocked | done` 状态；不再计划的事项标记 `deferred` 或 `cancelled` 并记录原因。状态只在本 RFC 的工作包表或执行回填中更新。

- `ready`：范围、非目标、依赖、执行方式、目标文件/产物、适用门禁与回退方案已明确；PRODUCT/MIXED 还须通过 5.5 的 CLI 契约定稿门禁（如适用）。
- `active`：已有明确实施入口；若采用无人值守 A/B，任务定义与 start-file 已完成编制期验收后才可进入此状态。
- `blocked`：记录阻塞事实、责任边界和解除条件，不以降低门禁方式解除。
- `done`：代码/文档/脚本已落地，全部适用门禁通过，证据路径与决策已回填，且无未登记的后续修补项。

依赖顺序固定为：WP-01 可立即启动；WP-02 可与 WP-01 并行；WP-03 须先完成条件输出 RFC 重定版；WP-04 依赖 WP-03 的元信息/正文组合契约；WP-05 依赖 WP-04 的字段协议；WP-06 依赖 WP-04 的状态与时延字段定义。依赖只约束契约，不要求使用相同执行方式或同一次 A/B。

### 6.4 工作量与日历估算

以下是 `proposed` 阶段的区间估算，按 1 人日 = 8 小时计算。估算包含设计/实现、邻近测试、文档同步和本工作包适用门禁，但不包含 5.6 暂缓项、基准发现后新立项的性能优化、正式发布等待窗口或不可控外部网络故障。

| 工作包 | 主要成本 | 估算人日 | 单人日历时间 |
|---|---|---:|---:|
| WP-01 | 发布顺序/强制版本、凭据传递、dry-run 回归、遗留 selftest 定性 | 3–6 | 1–2 周 |
| WP-02 | 固定样本、测试专用注入、基准脚本/解析、三架构基线报告 | 5–9 | 1.5–3 周 |
| WP-03 | 条件输出 RFC 重定版、`--no-body`、组合 golden 与文档 | 3–5 | 0.5–1.5 周 |
| WP-04 | 元信息数据贯通、稳定字段协议、单条/批量输出与错误路径 | 4–7 | 1–2 周 |
| WP-05 | 重定向链保留、字段抽取/多值规则、组合矩阵与 BusyBox 样例 | 5–9 | 1.5–3 周 |
| WP-06 | 批量聚合、错误/RIR 分布、p50/p95、组合与空批次边界 | 3–6 | 1–2 周 |
| **合计（未加风险缓冲）** |  | **23–42** |  |
| **计划值（加 25% 缓冲）** |  | **29–53** | **约 7–12 周** |

推荐对外采用 **单人 8–10 周** 作为最可能区间，并保留 7–12 周上下界。两名熟悉代码库的开发者可并行 WP-01/WP-02 和协议准备，但 WP-03 -> WP-04 -> WP-05 的契约关键路径及共享发布门禁不能完全并行，预计仍需约 4–7 周。

估算假设与校正规则：

1. 默认采用传统交互式开发；每个 PRODUCT/MIXED 工作包预留一次完整发布侧回归。历史基线显示 Strict 单轮约 3–6 分钟，Batch 四策略约 20–25 分钟，Selftest 四策略约 20–25 分钟，叠加 CIDR/矩阵/Step47 与结果审计后，每次完整门禁按 1–2 小时预留。
2. 若决定采用无人值守 A/B，每新增一组成对会话，另加约 1–3 人日用于 Vx 任务定义、链式静态验收和 start-file；运行墙钟按历史正常 14–17 小时、含一次事故上界约 24 小时估算。A/B 运行时间不能等同开发工时，也不能与其他会修改同一工作区的工作并行。
3. WP-02 的最大不确定性是测试专用离线注入边界；WP-04/WP-05 的最大不确定性是现有查询结果结构是否已完整保留 attempts、redirect chain 和失败分类。完成开工 spike 后应重新估算，若单项偏差超过 30%，更新本节与工作包状态。
4. `injection-view-fallback` 若仅完成 known-issue 定性，WP-01 取区间下半；若根因涉及注入视图生命周期与多路径修复，取上半。
5. 任何新增范围必须登记新的 `WP-xx`，不得消耗本节缓冲后静默并入。

## 7. 工作包门禁（发布侧回归清单）

门禁按变更范围取并集，不因未使用 A/B 而降低验证标准：

- DOC：编码门禁、链接/路径核验、`git diff --check`、文档诊断；不要求创建 Vx 文件或运行与内容无关的全量产品矩阵。
- TEST/TOOL：DOC 门禁 + 修改脚本的专项回归；发布脚本须跑 one-click dry-run，基准脚本须证明离线可重复。
- PRODUCT/MIXED：执行下列完整发布侧回归清单；若明确裁剪，必须在开工评审中说明未受影响路径和替代证据。
- 无人值守 A/B：除对应类型门禁外，追加 Vx 定义、A/B 前置链、start-file 与 8R 运行门禁。

PRODUCT/MIXED 的完整门禁顺序固定：

1. 编码门禁：`tools/dev/enforce_utf8_bom_lf_changed.ps1 -Mode check -Policy enforce`
2. `Remote: Build (Strict Version)`（`lto-auto`）：Local hash / Golden / referral 全 PASS，无编译与 LTO 告警
3. Batch Golden 四策略（raw/health-first/plan-a/plan-b）全 PASS
4. Selftest Golden 四策略全 PASS（核心断言含新增用例，禁止对应 FAIL）
5. `Test: CIDR Contract Bundle (prefilled)`：`body_status=pass`、`matrix_status=pass`
6. `Test: Redirect Matrix (10x6)`：`authMismatchFiles=0`、`errorFiles=0`
7. `Test: Step47 PreRelease Check`（含 preclass gate）
8. 文档/契约：USAGE_CN/EN、RELEASE_NOTES、RFC 回填、README（如涉及亮点）
9. `git diff --check`、无 TODO 占位；采用无人值守 A/B 时，任务文件须满足 Vx 模板与链式验收

失败策略：任一适用门禁失败即中止该工作包，不允许先发布后补修。

## 8. 风险与回退

| 风险 | 缓解/回退 |
|---|---|
| 新 opt-in 选项与既有 CLI 冲突 | 选项名在 RFC 登记评审；默认关闭，最坏移除开关即回退 |
| golden 漂移/基线污染 | 每个适用工作包以 v3.3.0 制品做 diff 对照；禁止无记录改期望 |
| 发布工具改动引入新竞态 | dry-run 断言全覆盖；真实演练一次后方可进入正式发布 |
| 性能基准波动（网络、架构差异） | 离线样本；分架构记录；同参数重复跑 |
| 合并切片互相干扰 | 按 6 节合并原则；合并工作包失败时拆回独立实施项 |
| token 泄漏复发 | 静态自检 + 日志审计纳入 Phase 1 回归 |

## 9. 非目标（明确不做）

- 不改变默认查询/权威裁决语义。
- 不引入 JSON/CSV 作为首选接口。
- 不重开已关闭的 A/B 直接 resume / 历史 PASS 快照 / 失败自动续跑路线（见 `docs/RFC-whois-client-split.md` 顶部状态治理）。
- 不调整 DNS 候选/健康/回退冻结策略。

## 10. 执行回填模板

每个工作包或其实施项完成后在本 RFC 追加：

```text
### WP-<xx>/<实施项>（<日期>）
- 状态：proposed | ready | active | blocked | done | deferred | cancelled
- 类型：DOC | TEST/TOOL | PRODUCT | MIXED
- 执行方式：文档评审 | 传统交互式 | 无人值守 A/B
- 执行映射：A/B=<n>/<n+1> 或不适用；task-definition=<paths 或不适用>
- 基线/依赖：<commit/tag；依赖工作包及状态>
- 结果：<PASS/结论；采用 A/B 时附 A/B/SESSION 状态>
- run：<out/artifacts/... 或不适用>
- 门禁：strict=<ts> batch=<ts..> selftest=<ts..> cidr=<ts> matrix=<ts> step47=<ts>
- 变更：<文件/功能摘要>
- 决策/回退：<如有>
```

### WP-01/发布脚本与 dry-run 防回归（2026-08-24）
- 状态：active
- 类型：TEST/TOOL
- 执行方式：传统交互式
- 执行映射：A/B=不适用；task-definition=不适用
- 基线/依赖：v3.3.0；无前置工作包
- 结果：本地 dry-run PASS；`injection-view-fallback` 已修复并纳入 core golden；最终 Strict 重建与双目录制品同步 PASS；真实 one-click 最终 tag 指向演练待预发布窗口完成
- run：`out/artifacts/oneclick_dryrun_guard/20260824-071904`；Fast=`out/artifacts/20260824-073602`；selftest=`20260824-073602/074252/074814/075417/080035`；Strict=`out/artifacts/20260824-081341`
- 门禁：专项 dry-run=PASS；Fast x86_64/win64 build/hash/smoke/golden=PASS；standalone selftest exit=0；core 与四策略 selftest golden=PASS；Strict `lto-auto` 默认轮无编译/LTO 告警、九架构 hash `9/9`、Golden/referral PASS（281s），三份 smoke 无硬错误，双同步目录九架构哈希一致；其余发布侧门禁待本工作包后续实施项完成后执行
- 变更：构建/同步/静态产物提交前移到 tag 创建之前；目标 tag 不存在时以进程环境注入 `WHOIS_FORCE_VERSION`；现有 tag 不指向最终提交时 fail-close；GitHub/Gitee token 不再进入 Bash 命令文本；smoke 新增顺序、强制版本、token 内联与九架构加 checksum 集合断言；修正 `injection-view-fallback` 对 handler 返回契约的反向断言，并新增 core golden 双向门禁
- 决策/回退：保留 opt-in 发布行为与默认远程构建入口；生产查询逻辑未因 selftest 修复改变；真实发布演练前不关闭 WP-01

### WP-02/离线条件输出性能基线（2026-08-24）
- 状态：done
- 类型：MIXED
- 执行方式：传统交互式
- 执行映射：A/B=不适用；task-definition=不适用
- 基线/依赖：v3.3.0 条件输出实现；commit=`59990eeacae1a5c3819f6e98d740f51d01aa9ede` + 本工作包 fold UAF 安全修复；无前置工作包
- 结果：46/46 场景在 win64、linux x86_64、linux aarch64（QEMU）均 PASS；三架构冻结 stdout SHA 完全一致；每份报告含 230 行 raw 与 46 行 summary
- run：win64=`out/artifacts/bench/wp02-win64-final/20260824-093556`；linux x86_64=`out/artifacts/bench/wp02-linux-x86_64/20260824-092208`；linux aarch64 QEMU=`out/artifacts/bench/wp02-linux-aarch64-qemu/20260824-092221`；最终生产远程构建/冒烟=`out/artifacts/20260824-094617`
- 门禁：harness strict compile（`-Wall -Wextra -Werror`）=PASS；ASan fold-unique stress/batch=PASS；冻结 SHA 复跑=PASS；最终 Strict `lto-auto` 无编译/LTO 告警，九架构 build/hash=9/9 PASS；Linux/win32/win64 smoke=`18/3/3` 且零告警；Golden/referral=PASS；双同步目录 hash=9/9 PASS；编码与 diff 门禁=PASS
- 变更：新增固定 fixture/manifest/expected SHA、C harness、PowerShell 与 Python 驱动；报告记录 commit/version、工具链/CFLAGS、架构、OS/CPU、样本/runner/脚本 SHA、median/p95 与原始测量；修复 `wc_fold_build_line_wb` 扩容后从已失效 token 指针复制导致的 heap-use-after-free
- 决策/回退：基准不暴露生产 CLI 文件注入；`[BENCH]` 仅由测试 harness 写 stderr，生产 `[WORKBUF-STATS]` 契约不变；aarch64 QEMU 仅作独立架构锚点；性能优化根据报告另立工作包

### WP-03/`--no-body` 实现与验证（2026-08-24）
- 状态：done
- 类型：PRODUCT
- 执行方式：文档评审/传统交互式
- 执行映射：A/B=不适用；task-definition=不适用
- 基线/依赖：v3.3.0 条件输出实现；WP-02=done
- 结果：冻结并实现无参数 `--no-body` 的渲染边界、单条/批量记录、组合优先级、非法组合、退出码与资源规则；合同 smoke 13/13 PASS；默认输出、CIDR、权威判定与 Step47 契约无回归
- run：合同 smoke=`out/artifacts/no_body_contract/20260824-102929`；首次九架构构建/冒烟=`out/artifacts/20260824-102905`；Batch Golden=`out/artifacts/batch_raw/20260824-103621`、`batch_health/20260824-104230`、`batch_plan/20260824-105010`、`batch_planb/20260824-105800`；CIDR bundle=`out/artifacts/cidr_bundle/cidr_bundle_summary_20260824-110410.txt`；12x6 matrix=`out/artifacts/redirect_matrix_10x6/20260824-110443`；Step47 preflight=`out/artifacts/step47_preclass_preflight/20260824-111043`；最终同步制品 Strict `lto-auto`=`out/artifacts/20260824-115609`；最终 win64 制品合同复核=`out/artifacts/no_body_contract/20260824-120031`
- 门禁：standalone/core selftest PASS（含 `opts-no-body-parser`）；Batch Golden 4/4 PASS；Selftest Golden core+4 策略 PASS；CIDR body/draft=`4/4 + 9/9`；12x6 `authMismatchFiles=0 errorFiles=0`；Step47 preflight=`5/5`；最终 Strict 九架构 build/hash、Golden、三起点 referral PASS 且无编译/LTO 告警（248s）；Linux/QEMU、win32、win64 smoke=`18/3/3`，首尾一一对应且零告警；仓库内、外部 lzispro 同步目录均与 artifact `9/9` SHA 一致；最终 win64 制品合同 smoke=`13/13`
- 变更：`--no-body` 贯穿 opts/config/render 路径并覆盖成功、失败、私网、无效输入和 Phase C；新增 parser selftest 与合同 smoke；修正 Selftest Golden raw 策略在无 batch 输入时错误要求私网正文的编排断言；RFC/USAGE/Release Notes 双语回填
- 决策/回退：`--no-body` 只抑制最终正文渲染，保留首行、Phase C Address Status（如适用）与尾行；不提前停止网络读取；与 `--plain` 或任一 fold 开关组合时 fail-fast

### 起步检查单

- [x] WP-01：一键发布顺序与版本注入（本地实现与静态断言完成，真实演练待办）
- [x] WP-01：令牌脱敏 + 静态自检
- [x] WP-01：dry-run 防回归断言（本地无构建路径；远程 build+sync 路径待办）
- [x] WP-01：`injection-view-fallback` 定性/修复
- [x] WP-02：离线基准脚本与 v3.3.0 安全基线报告
- [x] WP-03：条件输出 RFC 定版 + `--no-body`
- [ ] WP-04：`--print-meta`
- [ ] WP-05：`--print-chain` + `--pick`
- [ ] WP-06：`--stats`
- [ ] 后续：性能热点优化（按证据逐项登记新的 `WP-xx`）
