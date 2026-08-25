# RFC: Post-3.3.0 Development Plan（v3.3.0 黄金基线后续开发计划）

> 状态：已批准（2026-08-24 总体评审通过）
> 原始规划基线：`v3.3.0`（2026-08-24 正式发布）
> 当前基线：`v3.3.1`（2026-08-25 正式发布；WP-08 性能重基线已完成）；`v3.3.0` 仅继续作为本文历史规划与 WP-02 性能对照基线。
> 评审结论：原范围、工作包治理、依赖、门禁与估算继续有效；WP-01–WP-10 已完成，WP-11 按第 11 节保留为证据触发的候选工作。
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
| 条件输出新 CLI | `--no-body`、`--print-meta`、`--print-chain`、`--pick`、`--stats` 已实现 | WP-03–WP-06 已完成；后续仅按独立登记工作包实施有基准证据的优化 |

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

- 新增 `--print-meta`（选项名冻结；**不复用 `--fold` 名称**）。
- 输出行式 TAB 分隔 `k=v`：`query`、`rir`、`status`、`duration_ms`、`attempts`、`redirects`；续加字段须在 RFC 登记。
- 语义与响应分类契约一致：`status=success|error`，error 分类复用 `Failure > Non-Authoritative > Semantic Empty > Authoritative` 的最终判定。
- 默认关闭；与 `--fold`/`--no-body` 组合行为已在 `docs/RFC-conditional-output-CN.md` WP-04 第 3 节定版，实现时同步 USAGE 示例。
- 已实现并完成独立复核：失败 fold 与 lookup 前短路均保持每输入一条元信息；值归一化无堆分配；attempts 绑定本次 lookup 实际网络上下文。
- 验收：扩展合同 `18/18` PASS（`out/artifacts/print_meta_contract/20260824-151824`），覆盖单条、显式/自动批量、组合、失败、本地短路及未启用 `--print-meta` 时的 fold 失败 stdout 兼容性；与现有元信息（如 Address Status 行）不冲突。

### 5.3 WP-05：链路输出与轻量字段抽取

- 按数据所有权拆为两个独立验收切片：WP-05A `--print-chain`（查询执行器有序 hop 观测）与 WP-05B `--pick`/`--pick-mode`（条件输出管道精确标题抽取）；可在同一版本交付，但不得共享隐式状态或互相替代门禁。
- `--print-chain`：输出 `chain=server1>server2>...`；必须单独捕获有序逻辑 hop，不得从会增删/别名折叠的 `visited[]` 推导。无网络 hop 固定 `chain=unknown`，上限 16，溢出追加 `>truncated`。
- `--pick <k1,k2,...>`：大小写不敏感、完整标题名精确匹配；`--pick-mode first|join`；续行先以 `; ` 合并，同名多次出现的 join 再以 `|` 合并。抽取源固定为 title → grep 后、fold 前视图。
- 字段白名单（尽力而为）：`netname`、`country`、`inetnum`、`inet6num`、`origin`、`route`、`descr`。
- **不做**跨 RIR 语义归一（`--normalize-keys` 延后）。
- 记录排列冻结为业务行 → pick → chain → WP-04 meta；与 `--no-body`/`--fold`/`-g`/`--grep*`/批量合法，与 `--plain` 查询前 fail-fast。完整缺失值、归一化、资源上限与验收矩阵见 `docs/RFC-conditional-output-CN.md` WP-05。
- 实施顺序：先完成 WP-05A 数据模型/CLI/渲染及专项合同，再完成 WP-05B parser/抽取/组合合同；每个切片通过聚焦构建和专项 smoke 后再进入 PRODUCT/MIXED 完整门禁。
- WP-05A 已完成实现与聚焦验收：专项合同 `12/12` PASS（`out/artifacts/print_chain_contract/20260824-155911`）；x86_64/win32/win64 `lto-auto` build/hash/smoke 与三起点 referral PASS（`out/artifacts/20260824-155726`，294s）；standalone parser/冲突自测 PASS。
- WP-05B 已完成实现与聚焦验收：专项合同 `12/12` PASS（`out/artifacts/pick_contract/20260824-164050`）；最终 standalone selftest 含 parser、冲突、first/join/续行及逐字段 64 KiB 截断边界并全部 PASS；三目标 build/hash 与三起点 referral PASS（`out/artifacts/20260824-164010`，233s）。该轮 win64 Wine 网络 smoke 有一次环境性非零 WARN，前一轮三平台 smoke 已 PASS（`out/artifacts/20260824-163234`）。
- WP-05 最终重建复核 PASS（`out/artifacts/20260824-170256`，351s）：Strict 版本九架构 `lto-auto` 无编译/LTO 告警，artifact 与两个发布目录 SHA-256 均 `9/9` 一致；Linux/QEMU/native smoke=`18`、win32=`3`、win64=`3` 且零告警，Golden 与三起点 referral PASS。

### 5.4 WP-06：`--stats`（独立工作包）

- 协议已在 `docs/RFC-conditional-output-CN.md` 冻结：仅批量合法，完整 EOF 后向 stdout 追加固定 18 字段统计行；单条与 `--plain` 查询前 fail-fast。
- 指标已实现为总数、success/error、lookup/rejected/internal 错误分类、固定 RIR 桶及精确 nearest-rank p50/p95；聚合直接消费结构化查询结果，不解析 stdout，也不复用 `[WORKBUF-STATS]`。
- 精确分位采用有界 32-bit 时长数组，每批最多 1,000,000 个有效输入项；超限、分配失败或 SIGINT 不输出部分汇总。
- 与 `--no-body`、`--fold`、过滤、pick/chain/meta 和显式/自动批量的组合已实现。真实联网复核修复了 pipeline 渲染后 `res.body` 已被清空、stats 因此把成功查询误计为 lookup error 的问题；成功状态现于渲染前冻结，meta/fold 两种双查询组合均为 `success=2 error=0`，ARIN/APNIC 各 1。
- 最终同步 win64 专项合同 `12/12` 与 standalone 新增三项 selftest 唯一 PASS（`out/artifacts/stats_contract/20260824-190108`）。
- 修复后最终 Strict 九架构 `lto-auto` build/hash、Golden、三起点 referral 与双发布目录同步全部 PASS且无编译/LTO 告警（`out/artifacts/20260824-185823`，316s）；可运行 Linux/QEMU、win32、win64 smoke=`18/3/3`，首尾对应且零告警；artifact、仓库 release 与外部 lzispro release SHA-256 均 `9/9` 一致。

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
| WP-01 | done | Phase 1 | 一键发布顺序/版本注入 + 令牌脱敏 + dry-run 防回归 | 发布脚本、本地 dry-run 防回归、遗留 selftest 定性/修复与 v3.3.1 真实 one-click 发布演练全部完成（2026-08-25） |
| WP-02 | done | Phase 2 | 离线性能基准脚本 + workbuf 可观测性 + 基线报告 | 46 场景三架构安全基线与冻结 SHA 已回填；发现并修复 fold UAF |
| WP-03 | done | Phase 3 | RFC 定版 + `--no-body` | 协议、产品实现、合同 smoke 与完整发布门禁均已完成 |
| WP-04 | done | Phase 3 | `--print-meta` | 契约冻结、产品实现、合同 smoke 18/18 与最终 Strict 九架构构建/Golden/referral 均通过（2026-08-24） |
| WP-05 | completed | Phase 3 | WP-05A `--print-chain` + WP-05B `--pick` | 两个切片及专项合同完成；九架构 Strict/Golden/referral/双目录 sync 最终复核 PASS（`20260824-170256`） |
| WP-06 | completed | Phase 3 | `--stats` | 协议、实现、真实联网成功计数修复、专项合同与最终 Strict 九架构/Golden/referral/release sync 全部完成（`20260824-185823`） |
| WP-07 | done | Phase 2 follow-up | fold token 容量预留优化 | 三架构冻结基准、sanitizer 与重建 Strict 九架构/Golden/referral/双目录 sync 全部完成（`20260824-205103`） |
| WP-08 | done | Phase 4 | v3.3.1 性能重基线与回归预算 | 三架构各 3 次完整复跑、共 414 个 case 汇总全部通过；初始预算采用正确性硬门禁与性能复测告警（2026-08-25） |
| WP-09 | done | Phase 4 | 条件输出 sanitizer 确定性回归门禁与重叠复制修复 | Linux native ASan/UBSan 64 个正向场景、受控负例、最终 Strict 九架构回归及三架构 grep selftest 全部 PASS（2026-08-25） |
| WP-10 | done | Phase 4 study | 响应读取上限语义审计与 `--max-bytes` 可行性决策 | 真实接收上限就是 `--buffer-size`；离线审计确认静默截断会造成分类漂移，决定不新增重复 CLI（2026-08-25） |
| WP-11 | proposed | Phase 4 backlog | `--stats` / `--pick` 小幅扩展候选池 | 仅由真实用户场景触发；未形成需求证据前不得进入 `ready` |

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

原阶段依赖为：WP-01 可立即启动；WP-02 可与 WP-01 并行；WP-03 须先完成条件输出 RFC 重定版；WP-04 依赖 WP-03 的元信息/正文组合契约；WP-05 依赖 WP-04 的字段协议；WP-06 依赖 WP-04 的状态与时延字段定义。下一阶段依赖见第 11 节。依赖只约束契约，不要求使用相同执行方式或同一次 A/B。

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
- 不建设公告发布或置顶自动化；发布频率低，继续采用人工操作。

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

### WP-01/真实 one-click 发布演练（2026-08-25）
- 状态：done
- 类型：TEST/TOOL（发布流程真实演练）
- 执行方式：真实一键发布（one_click_release.ps1，BuildAndSyncIf=true）
- 执行映射：A/B=不适用；task-definition=不适用
- 基线/依赖：v3.3.1 发布准备提交 `6d2b04f5`；WP-02=done
- 结果：真实 one-click 全流程 PASS（build+verify → statics 同步与提交 → annotated tag v3.3.1 → GitHub/Gitee Release 更新），过程中无任何故障与不适；构建版本串精确为 v3.3.1（无 git describe fallback）；tag 指向最终静态产物提交
- run：构建产物=`out/artifacts/20260825-101612`（build_out 含 build_report/golden_report/三份 smoke/SHA256SUMS-static.txt 与九架构二进制）；statics 提交=`4357c6a0`（release: update whois statics for v3.3.1）；tag=`v3.3.1`（annotated，2026-08-25 10:16:29 +0800，message=`whois v3.3.1`，指向 `4357c6a0`）；Gitee Release body 更新命令 exit=0；origin/master 已同步至 `4357c6a0`
- 门禁：golden=`[golden] PASS`；Linux/QEMU、win32、win64 smoke=`18/3/3` 且 alerts=0；build_report 覆盖九架构；statics 提交同时更新九架构二进制与 `SHA256SUMS-static.txt`；tag 指向静态产物提交；日志无 token 明文；`git status` 干净
- 变更：无源码/脚本变更；本轮为发布流程真实演练
- 决策/回退：WP-01 关闭（done）；后续版本发布沿用真实 one-click 路径

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

### WP-04/`--print-meta` 实现与验证（2026-08-24）
- 状态：done
- 类型：CONTRACT + PRODUCT
- 执行方式：文档评审/传统交互式
- 结果：在 `docs/RFC-conditional-output-CN.md` 定版 `--print-meta` 无参数观测选项并完成实现——记录尾后追加单行 TAB 分隔 `k=v`（字段顺序冻结：`query`/`rir`/`status`/`duration_ms`/`attempts`/`redirects`）；`status` 仅 `success|error`，`error` 绑定最终失败判定；数值字段来源已登记（单调时钟差值、连接计数差值、`hops-1`）；与 `--no-body`/`--fold`/`-g`/`--grep*` 合法，与 `--plain` 查询前 fail-fast；字段名与语义冻结，新增字段只允许追加并在 RFC 登记。
- run：合同 smoke=`out/artifacts/print_meta_contract/20260824-151824`；最终同步制品 Strict `lto-auto`=`out/artifacts/20260824-151759`（350s）
- 门禁：win64 standalone selftest（含 `opts-print-meta-parser`/`opts-print-meta-plain-conflict`）=PASS；合同 smoke=`18/18`；最终 Strict 九架构 build/hash、Golden、三起点 referral PASS 且无编译/LTO 告警；Linux/QEMU、win32、win64 smoke 首尾对应、零告警；两个 lzispro 同步目录与 artifact `9/9` SHA 一致；编码与 diff 门禁=PASS
- 变更：`--print-meta` 贯穿 opts/config/render 路径；`wc_result_meta` 新增 `duration_ms`/`attempts`（`wc_lookup_execute` 生命周期采样）；`wc_pipeline_render_meta` 在尾行/折叠行后输出元信息，失败报告路径同步挂载；新增 parser selftest、合同 smoke 与双语 USAGE/Release Notes；修复 `wc_workbuf_reserve` 同缓冲覆盖与失败路径缺元信息两处缺陷
- 决策：选项名固定 `--print-meta`；元信息行位于记录末尾（尾行或折叠行之后）；观测选项不改变退出码、权威判定与诊断标签；数值字段不可测量输出 0

### WP-07/fold token 容量预留优化（2026-08-24）
- 状态：done
- 类型：PRODUCT
- 执行方式：传统交互式
- 执行映射：A/B=不适用；task-definition=不适用
- 基线/依赖：commit=`40565aaa`；WP-02=done；linux x86_64 基线=`out/artifacts/bench/wp02-linux-x86_64/20260824-092208`
- 结果：将 `append_token_with_format` 的逐字节 `wc_workbuf_reserve` 合并为每个 token 一次最坏情况容量预留；linux x86_64、linux aarch64 QEMU 与 win64 各 46/46 冻结 stdout SHA 场景 PASS。x86_64 `fold/stress-crlf` median/p95 从 `31.027/33.256 ms` 降至 `13.924/14.974 ms`，`fold-unique/stress-crlf` 从 `32.779/37.418 ms` 降至 `15.957/18.787 ms`；aarch64 QEMU 两场景分别从 `220.282/234.764 ms` 降至 `129.867/141.111 ms`、从 `276.801/301.222 ms` 降至 `128.857/145.508 ms`；win64 稳定复跑分别从 `93.026/100.760 ms` 降至 `89.364/97.868 ms`、从 `93.898/100.974 ms` 降至 `82.023/85.876 ms`。reserve 在三架构均从 `1,417,000/1,420,000` 降至 `26,000/29,000`；grow、max cap 与 stdout SHA 不变
- run：聚焦生产 x86_64 build/hash=`out/artifacts/wp07-focused-build/20260824-191734`；x86_64=`out/artifacts/bench/wp07-fold-reserve/20260824-191832`；aarch64 QEMU=`out/artifacts/bench/wp07-fold-reserve-aarch64/20260824-193742`；win64 稳定复跑=`out/artifacts/bench/wp07-fold-reserve-win64/20260824-194059`；最终 Strict 重建=`out/artifacts/20260824-205103`
- 门禁：严格 GCC/MinGW harness（`-Wall -Wextra -Werror`）=PASS；ASan/UBSan stress fold 与 fold-unique 各 1000 iterations=PASS；三架构冻结矩阵各 `46/46` PASS；最终 Strict `lto-auto` 重建无编译/LTO 告警，九架构 hash、Golden、三起点 referral PASS（311s）；Linux/QEMU、win32、win64 smoke=`18/3/3` 且首尾对应、alerts=0；IANA/ARIN/AFRINIC 三起点均收敛至 AFRINIC；artifact、仓库 release 与外部 release 均 `9/9` SHA 一致；编码诊断与 `git diff --check`=PASS
- 变更：仅修改 `src/cond/fold.c` 的 token 输出容量检查频率；不改变扫描、空白折叠、大小写、CR/LF 截断、分隔符、去重或输出协议
- 决策/回退：预留上界为当前长度 + 可选分隔符长度 + 原 token 长度，格式化输出不会超过该上界；若跨架构基准退化或 sanitizer/冻结 SHA 失败，回退本工作包单一源码改动

### WP-08/v3.3.1 性能重基线与回归预算（2026-08-25）
- 状态：done
- 类型：TEST/TOOL + DOC
- 执行方式：传统交互式
- 执行映射：A/B=不适用；task-definition=不适用
- 基线/依赖：commit=`ce6ea09649f55ef6589c19bf6b833fa5454dcb81`（`v3.3.1-3-gce6ea096`）；发布基线=`v3.3.1`；WP-02/WP-07=done；从 WP-07 完成提交 `83523269` 到本提交，runner、驱动、固定样本及其直接生产源码无差异
- 结果：linux x86_64、linux aarch64 QEMU 与 win64 各执行 3 次完整独立复跑；每次均为 46/46 case、warm-up 1、测量 5 次、每次 1000 iterations，共 9 份 `summary.json`、414 个 case 汇总和 2070 行原始测量。全部 stdout SHA 与样本集 SHA `5dbf193e0a91b49f75d51a668fa59db2029558af350256a0da87937dcf38436b` 冻结一致；每架构 46/46 case 的 output bytes、reserve/grow/max-request/max-cap/max-view 及 stdout SHA 在三轮间完全一致
- 代表值：三轮 median 的中位数（范围）——linux x86_64 `fold/stress-crlf=22.972 ms (16.102–23.019)`、`fold-unique/stress-crlf=27.858 ms (18.395–30.016)`、`batch/all=9.991 ms (6.868–11.030)`；aarch64 QEMU 分别为 `91.613 ms (84.466–137.465)`、`125.587 ms (116.650–150.427)`、`41.487 ms (33.585–50.742)`；win64 分别为 `93.123 ms (87.757–139.532)`、`102.723 ms (86.264–114.097)`、`83.974 ms (81.080–99.082)`。三架构对应 reserve/grow/max-cap 稳定为 fold `26000/4/2048`、fold-unique `29000/3004/2048`、batch `9000/2/2048`
- run：linux x86_64=`out/artifacts/bench/wp08-v331-linux-x86_64/{20260825-152116,20260825-152435,20260825-152437}`；linux aarch64 QEMU=`out/artifacts/bench/wp08-v331-linux-aarch64-qemu/{20260825-152132,20260825-152606,20260825-152620}`；win64=`out/artifacts/bench/wp08-v331-win64/{20260825-152345,20260825-152450,20260825-152523}`
- 构建复现：runner 源闭包固定为 `bench_conditional_output_harness.c + header.c + title.c + grep.c + fold.c + workbuf.c`；x86_64 使用 GCC 13.3.0、`-std=c11 -O3 -Wall -Wextra -Werror -DWC_WORKBUF_ENABLE_STATS`；aarch64 使用 musl GCC 11.2.1、`-O2` 加 `-static` 并由 `qemu-aarch64-static` 运行；win64 使用 MinGW GCC 13-win32、`-O2` 加 `-static-libgcc -static-libstdc++ -lwinpthread -lregex`，测试 runner 同目录提供工具链的 `libgnurx-0.dll`。Linux 调用 `bench_conditional_output.py`，Windows 调用 `bench_conditional_output.ps1`，其余参数均为 `repetitions=5/warmup=1/iterations-per-run=1000`
- 初始回归预算：冻结 SHA、退出码、46 case 完整性及 workbuf 结构化指标为硬门禁，任一变化立即失败；计时只比较同主机、同架构、同编译配置下至少 3 次完整复跑的 median-of-medians。当前环境短 case、QEMU 与 win64 调度波动明显，单轮计时不设硬失败线；复测汇总相对本基线同时超过以下相对值和绝对值时进入人工回归评审：x86_64 `50% + 10 ms`、aarch64 QEMU `75% + 50 ms`、win64 `60% + 50 ms`。阈值是噪声隔离告警线，不是可接受性能退化目标；连续积累 3 个可比基线后重新收紧
- 门禁：三架构严格编译零告警；9/9 完整报告、414/414 case 与冻结 SHA PASS；三架构各 46/46 结构化指标三轮一致；产物仅写 `out/artifacts/bench`，未修改生产源码、默认输出或诊断标签
- 决策/回退：未发现可由本基线证明的新生产热点，不登记性能优化工作包；WP-08 关闭。后续性能变更须复用本节命令与预算，若环境或工具链变化则新建分层基线，不覆盖本组报告

### WP-09/条件输出 sanitizer 确定性回归门禁（2026-08-25）
- 状态：done
- 类型：MIXED（PRODUCT bugfix + TEST/TOOL）
- 执行方式：传统交互式
- 执行映射：A/B=不适用；task-definition=不适用
- 基线/依赖：commit=`35fa9977c1965fe4c5129807160201cc7c6068a4` + 当前工作树；WP-02/WP-07/WP-08=done
- 发现：生产 pipeline 将原始响应复制到共享 `filter_wb` 后，依次把同一地址传给 title/grep。title 的保留行复制与 grep line 模式的四处直接保留行复制均可能把较后的源区间压缩到较前的目标区间，原 `memcpy` 在区间重叠时属于未定义行为；ASan 已在 title/arin 路径报告 `memcpy-param-overlap`。grep block 模式从独立 `blk_wb` flush，不属于同一缺陷类
- 修复：仅将五处已确认可能同 workbuf 重叠的 `line_start -> out + opos` 复制改为 `memmove`；独立 workbuf、栈临时缓冲与最终 owned-copy 的 `memcpy` 保持不变。默认输出、过滤顺序、正则、续行、折叠与诊断协议不变
- 门禁：新增 `tools/test/conditional_output_sanitizer_gate.sh`，仅支持 native Linux + GCC sanitizer runtime；严格编译真实 harness 后复跑既有 46 项冻结 SHA，并覆盖 `grep-line` / `grep-line-cont` × 9 fixture 的 18 项独立冻结 SHA；每个新增场景双跑一致。test-only 负例使用重叠 `memcpy`，必须被 ASan 以 `memcpy-param-overlap` 非零拦截，否则 fail-close
- run：最终 sanitizer gate=`out/artifacts/conditional_output_sanitizer/20260825-084057`，`positive_cases=64`、`frozen_cases=46`、`extended_cases=18`、`negative_probe=detected`、`negative_exit=134`
- 工具链边界：GCC 13.3.0 native linux x86_64 支持 ASan/UBSan；当前 MinGW GCC 13-win32 与 aarch64 musl GCC 11.2.1 均缺少 sanitizer runtime，因此不伪造跨架构 sanitizer 结论，跨架构行为继续由严格构建、冻结 SHA 与 Golden 覆盖
- 产品回归：源码修改后的最终 Strict Version `lto-auto` 默认轮无编译/LTO 告警，九架构构建与本地 SHA、Golden、IANA/ARIN/AFRINIC 三起点 referral 全部 PASS（`out/artifacts/20260825-171420`，285s）。Linux/QEMU 六架构各执行 `8.8.8.8`、`1.1.1.1`、`10.0.0.8`，共 18 组查询；win32/win64 各 3 组，共 6 组查询，标题/权威尾行完整，公网查询分别收敛 ARIN/APNIC，私网查询保持 `unknown @ unknown`。九个 artifact SHA-256 实算与清单 `9/9` 一致，仓库内外两个 release 同步目录共 `20/20` 文件与 artifact 一致；三条 referral 路径均收敛 AFRINIC 且 retry `failures=0`
- 专项回归：启用 `WHOIS_GREP_TEST` 的 x86_64/win32/win64 聚焦构建与 `--selftest-grep` smoke 全部 PASS，三架构的 block、line/no-cont、line/keep-cont 共 9 项通过（`out/artifacts/20260825-165446`，184s）
- 关闭结论：sanitizer、受控负例、编码、ShellCheck/Bash syntax、最终 Strict 产品回归、双目录同步复核与聚焦 grep selftest 均通过，WP-09 关闭

### 起步检查单

- [x] WP-01：一键发布顺序与版本注入（本地实现、静态断言与 v3.3.1 真实 one-click 演练完成，2026-08-25）
- [x] WP-01：令牌脱敏 + 静态自检
- [x] WP-01：dry-run 防回归断言（本地无构建路径与真实 one-click build+sync 路径均完成，2026-08-25）
- [x] WP-01：`injection-view-fallback` 定性/修复
- [x] WP-02：离线基准脚本与 v3.3.0 安全基线报告
- [x] WP-03：条件输出 RFC 定版 + `--no-body`
- [x] WP-04：`--print-meta`
- [x] WP-05：`--print-chain` + `--pick`
- [x] WP-06：`--stats`
- [x] WP-07：按 WP-02 证据登记 fold token 容量预留优化
- [x] WP-07：ASan/UBSan、win64、aarch64 QEMU 与最终发布门禁
- [x] WP-08：v3.3.1 三架构各 3 次完整性能重基线与初始回归预算
- [x] WP-09：Linux native ASan/UBSan 确定性门禁、受控负例与生产重叠复制修复
- [x] WP-10：响应读取上限数据流、截断分类漂移与 `--max-bytes` 决策审计

## 11. v3.3.1 后续工作计划（2026-08-25 登记）

### 11.1 规划判断与优先级

v3.3.1 已完成原计划中的发布工程、性能基线、条件输出和 fold 热点优化。下一阶段不以增加 CLI 数量为目标，优先固化已有能力的可测性和回归防护，再由证据决定是否实施产品改动。

执行顺序：

1. **P0：WP-08**，先建立 v3.3.1 可重复性能基线，为后续判断提供同口径证据。
2. **P0：WP-09**，把已经用于 WP-02/WP-07 的 sanitizer 压力验证整理为可重复门禁；若门禁暴露生产内存安全缺陷，只做有 sanitizer 与同缓冲数据流证据的最小 bugfix。WP-08 与 WP-09 可串行或在互不修改同一工作区时独立执行。
3. **P1：WP-10**，完成响应读取上限的契约与实现审计；只有研究结论明确证明新增公开选项有独立价值且不损害权威判定，才另行批准 PRODUCT 实施项。
4. **P2：WP-11**，保留小幅可观测性扩展入口，但必须先有真实用户场景、跨 RIR 样本和稳定字段语义；无证据则保持 `proposed`。

默认执行方式为传统交互式开发。WP-08 和 WP-10 的首个实施项分别为 TEST/TOOL、DOC/TEST；WP-09 因 sanitizer 实证缺陷调整为 MIXED。三者均不创建 A/B 任务定义；只有后续获批且改动量、风险适合确定性 D1–D4 编排的 PRODUCT 实施项，才单独评审是否采用 Vx A/B。

### 11.2 WP-08：v3.3.1 性能重基线与回归预算

- 复用 WP-02 的 46 场景离线样本、冻结 stdout SHA、指标字段和 linux x86_64 / linux aarch64 QEMU / win64 三架构口径；先验证 harness 对 v3.3.1 仍可完整复跑。
- 记录 v3.3.1 的 median、p95、workbuf reserve/grow/max-cap 与产物 SHA，明确主机、架构、编译配置和重复次数；不同环境的数据不得直接判定回归。
- 以 v3.3.1 数据建立后续同环境回归预算。预算阈值必须依据复跑波动再定，不在取样前预设百分比，也不把单次慢样本判为退化。
- 若发现热点，仅登记新的独立工作包；WP-08 本身不修改生产 C 代码，不以“必须找到优化项”为完成条件。
- 完成条件：三架构场景与 stdout SHA 全通过，基线报告及复现命令回填；若环境不可比，记录限制并保持基线分层，不制造跨环境结论。

### 11.3 WP-09：条件输出 sanitizer 确定性回归门禁

- 将现有 title、grep、fold / fold-unique stress 与 batch 的 ASan/UBSan 验证整理为离线、固定输入、冻结 SHA 且失败码稳定的专项入口，覆盖同 workbuf 压缩、block/line 模式、续行开关、workbuf 扩容、长 token、CR/LF 截断、去重和格式化组合。
- 第一阶段复用已有 harness 与源码路径，并补齐 `grep-line` / `grep-line-cont`；不凭推测扩展到 pick、stats 或无内存安全边界证据的组合。
- 门禁不得依赖公网，不修改 stdout/stderr 产品契约，不因新增工具入口进行全仓告警清理或无关重构；不新增 VS Code task，优先接入现有测试脚本或 Makefile 入口。
- 当前工具链范围限定 native Linux x86_64 GCC ASan/UBSan；MinGW 与 aarch64 musl 缺 sanitizer runtime 时明确记录 unavailable，不把环境缺口判为产品失败，也不降低其他架构的严格构建与 Golden 门禁。
- 完成条件：同一命令可重复构建并运行，64 个正常用例退出 0 且冻结输出一致，受控 test-only 重叠复制负例被稳定识别，生产缺陷完成最小修复，相关文档写明工具链前提与适用范围。

### 11.4 WP-10：响应读取上限语义审计与 `--max-bytes` 决策门禁

- 先盘点 `--buffer-size`、`wc_recv_until_idle(..., max_bytes)`、默认配置和协议安全最大响应之间的真实数据流，说明各上限控制的是分配容量、实际接收截断还是事后协议校验，避免新增重复概念。
- 用离线响应样本证明截断点位于 referral、拒绝访问、ERX/IANA 标记、权威尾部或续行字段附近时的现状行为；审计必须覆盖 IPv4、IPv6、CIDR 与批量路径，并以 `docs/RFC-ipv4-ipv6-whois-lookup-rules.md` 为最高契约。
- 研究阶段不得改网络读取行为或公开 CLI。只有同时满足“独立于 `--buffer-size` 的用户价值明确”“截断可观测且 fail-close”“不误判权威 RIR”“默认行为零变化”，才可把 PRODUCT 实施项提升为 `ready`。
- 任一条件无法满足，或现有 `--buffer-size` 已足以表达需求，则以“不新增 `--max-bytes`”关闭研究；禁止退化为网络命中即停。

实施回填（2026-08-25）：

- 数据流结论：`--buffer-size` 默认 512 KiB，并作为主查询路径传给 `wc_recv_until_idle(..., max_bytes)`，同时控制工作缓冲容量和实际网络接收上限；协议安全层的 10 MiB 最大响应约束未接入该主接收路径。因而 `--max-bytes` 没有独立于现有选项的控制对象。
- native Linux GCC socketpair 审计直接调用真实 `wc_recv_until_idle`：低于上限、恰好上限、超过上限 3 个案例全部 PASS；超过上限时函数返回成功且只交付上限内字节，调用方没有截断状态，确认 `silent_truncation=confirmed`。
- 分类审计覆盖 IPv4 权威尾部、IPv6 referral、CIDR ERX/IANA 标记和批量拒绝访问标记 4 个案例，完整响应与截断响应均走真实分类 helper；7 个总案例全部 PASS，并确认四类 `classification_drift=confirmed`。复现入口为 `tools/test/response_limit_audit.sh`，证据为 `out/artifacts/response_limit_audit/20260825-183151/report.txt`。
- 决策：关闭 WP-10，不新增 `--max-bytes`。该选项与 `--buffer-size` 重复，且“截断可观测且 fail-close”“不误判权威 RIR”两项 PRODUCT 门禁不满足；默认网络行为和公开 CLI 保持不变。
- 后续边界：静默截断应作为独立的内部 fail-close bugfix 候选另行评审，目标是让接收上限耗尽可区分并阻止部分响应进入权威判定；不得借该候选引入第二个公开字节上限或网络命中即停。

### 11.5 WP-11：证据触发的 stats/pick 小幅扩展

- 候选范围仅限现有稳定模型可表达的附加 stats 字段或 pick allowlist 字段；stats 只能追加稳定键，pick 只能在跨 RIR 样本确认值语义、续行和多值规则后增加字段。
- 每个候选先提交用户场景、样本、默认输出不变证明和 CN/EN 协议草案，再决定是否拆成独立工作包或实施项；不得把推测性字段一次性批量加入。
- 不在本工作包引入跨 RIR 语义归一、JSON/CSV 主输出、并发批量、DNS/重试修改或网络早停。
- 完成条件：没有真实需求时保持 `proposed` 即为正常状态；不能为了关闭工作包制造产品改动。

### 11.6 本阶段继续不立项

- 公告发布与置顶自动化：低频人工流程已足够，自动化维护成本高于收益。
- 并发批量查询与限速控制、网络读取早停/命中即停：会改变网络行为、重定向链或 RIR 限流风险。
- DNS 候选、健康记忆与重试策略调整：继续冻结，仅接受有复现证据的 bugfix 或不改变决策的可观测性修复。
- `--normalize-keys`、JSON/CSV 主输出：当前缺少足够跨 RIR 语义需求与兼容收益。

### 11.7 阶段复审点

WP-08 与 WP-09 完成后进行一次轻量复审：依据新基线、sanitizer 覆盖缺口和实际用户反馈，决定 WP-10 是否进入研究、WP-11 是否出现可立项候选。若没有新的证据，允许本阶段停在测试与文档增强，不以新增产品功能作为阶段完成标准。

复审回填（2026-08-25）：WP-08 基线未证明新的生产性能热点，WP-09 已关闭共享 workbuf 的实证内存安全缺陷；据此完成 WP-10 研究并作出“不新增 `--max-bytes`”决定。当前没有 WP-11 所需的真实用户场景、跨 RIR 样本或稳定字段语义，WP-11 保持 `proposed`，不进入实施。
