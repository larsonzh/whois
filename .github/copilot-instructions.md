# Copilot Instructions for whois

面向：在 VS Code 中协助维护本仓库的 AI 代理，需让新人快速上手并避免破坏既有契约。

## 架构与数据流（务必先掌握）
- 入口：命令行解析与主流程在 [../src/whois_client.c](../src/whois_client.c)，配置结构定义在 [../include/wc/wc_config.h](../include/wc/wc_config.h)。
- 核心模块：选项 [../src/core/opts.c](../src/core/opts.c)、起始服务器 [../src/core/server.c](../src/core/server.c)、DNS 候选与健康记忆 [../src/core/dns.c](../src/core/dns.c)、拨号/转发 [../src/core/lookup.c](../src/core/lookup.c)、非阻塞网络与重试 [../src/core/net.c](../src/core/net.c)、单条查询执行 [../src/core/whois_query_exec.c](../src/core/whois_query_exec.c)。
- 条件输出链：标题投影/正则/折叠分别在 [../src/cond/title.c](../src/cond/title.c)、[../src/cond/grep.c](../src/cond/grep.c)、[../src/cond/fold.c](../src/cond/fold.c)，编排 glue 在 [../src/core/pipeline.c](../src/core/pipeline.c)。
- 心智模型：query → server+dns 解析 → connect+referral → title (-g) → grep (--grep*) → fold (--fold)。stdout 仅业务输出；stderr 仅诊断/指标（保持分工）。

## 输出契约（不要破坏）
- IPv4/IPv6 规则契约（强约束）：任何查询链路、权威判定、CIDR 行为与输出语义改动，必须遵守 [../docs/RFC-ipv4-ipv6-whois-lookup-rules.md](../docs/RFC-ipv4-ipv6-whois-lookup-rules.md)。若与其他描述存在冲突，以该规则文档为准，并在变更中同步更新相关文档与测试样例。
- 标题行：`=== Query: <item> === via <host-or-alias> @ <ip|unknown>`；尾行：`=== Authoritative RIR: <rir-host> @ <ip|unknown> ===`；折叠行：`<query> <UPPER_VALUE_...> <RIR>`（无 IP）。
- 批量模式：`-B` 或 stdin 非 TTY 自动逐行读取；契约需兼容 BusyBox 管道。
- 处理顺序固定：title 投影 → grep（行/块+续行策略）→ fold，任何改动保持顺序与格式稳定，必要时同步黄金样例与文档。
- 重定向补充：RIR 限流/拒绝访问视为“非权威重定向”继续查找；若无 ERX/IANA 标记且已查遍所有 RIR，权威回落 unknown，否则为首个 ERX/IANA 标记 RIR；LACNIC 首跳内部重定向后遇拒绝访问与首跳直连 RIR 拒绝访问均按“不污染轮询序列”处理。
- 设计原则细节请查：[../docs/RFC-whois-client-split.md](../docs/RFC-whois-client-split.md)、[../docs/USAGE_CN.md](../docs/USAGE_CN.md)、[../docs/USAGE_EN.md](../docs/USAGE_EN.md)、[../docs/OPERATIONS_CN.md](../docs/OPERATIONS_CN.md)、[../docs/OPERATIONS_EN.md](../docs/OPERATIONS_EN.md)。

## 日志与指标习惯
- DNS 调试标签 `[DNS-CAND]/[DNS-FALLBACK]/[DNS-CACHE]/[DNS-HEALTH]` 仅在 `--debug` 或 `--retry-metrics` 打开，写 stderr。
- `--dns-cache-stats` 在进程退出时输出单行 `[DNS-CACHE-SUM] hits=<n> neg_hits=<n> misses=<n>`，每进程一次；保持字段名不变。
- 重试指标 `[RETRY-METRICS*]` 由 [../src/core/net.c](../src/core/net.c) 打印，远程冒烟会 grep 这些标签。

## 自测与调试
- 编译期开关：`-DWHOIS_LOOKUP_SELFTEST`、`-DWHOIS_GREP_TEST` 等，逻辑见 [../src/core/selftest*.c](../src/core) 与 [../include/wc/wc_selftest.h](../include/wc/wc_selftest.h)。
- 运行期开关：`--selftest*`、`--debug`、`--retry-metrics`、`--dns-cache-stats`，常用命令：`whois-x86_64 --debug --retry-metrics --dns-cache-stats [--selftest] 8.8.8.8`。
- 修改折叠/grep/title 逻辑后请跑相关自测或黄金检查，确保 stderr 标签与 stdout 契约未变。

## 构建与冒烟工作流
- 推荐远程多架构脚本 [../tools/remote/remote_build_and_test.sh](../tools/remote/remote_build_and_test.sh)，Windows 示例：`"C:\\Program Files\\Git\\bin\\bash.exe" -lc "cd /d/LZProjects/whois; tools/remote/remote_build_and_test.sh -r 1"`。
- VS Code 任务：Remote/Strict 版本、Git: Quick Push、Golden/Selftest suites 已预置，可直接用任务面板触发。
- 本地快速构建：`make`（见 [../Makefile](../Makefile)）；清理脚本 [../tools/dev/prune_artifacts.ps1](../tools/dev/prune_artifacts.ps1)。

## 代码与设计约定
- 公共 API 统一 `wc_*` 前缀，新增模块需补头文件并保持命名一致；共享小工具放 [../src/core/util.c](../src/core/util.c)。
- DNS 候选/健康/回退策略已在 v3.2.8–v3.2.9 冻结，仅做可观测性或 bugfix 级别改动。
- 新增诊断/指标一律写 stderr，沿用已有标签风格；避免更改标签名称，防止黄金与脚本失效。

## D/V 轮次任务定义设计指导
- **新任务默认 Vx-first（硬规则）**：今后新建 A/B 任务定义统一从 `testdata/autopilot_code_step_tasks_vx_template.json` 编制并保留 `schemaVersion=vx-draft`，即使任务只修改一个文件，也使用单条 `targetFiles[]`、稳定 target id、`defaultTarget` 和显式 target-bound operation/assertion。`testdata/autopilot_code_step_tasks_template.json` 仅用于既有 `schemaVersion=1` 文件的兼容读取、重跑和修复；不得批量迁移历史 V1，不得在 start-file 已生成或会话运行中切换 schema。包装器、checker、repair 与恢复命令接口保持不变，不增加人工 `-TargetId` 参数。
- **任务切片设计与合并原则（硬规则）**：当前代码已趋于成熟稳定，A/B 任务设计中任何代码改动都必须全盘深入考虑与评估后再做出，最大限度减少缺陷产生，不给代码整体执行带来负面影响；严禁为“凑轮次”引入不必要或未经充分论证的改动。A/B 无人值守脚本编译/验证环节较多、任务整体耗时较长；当单个任务切片代码开发量较小（单独占用一次 A/B 会造成轮次不饱和、时间成本浪费过大）时，优先评估将多个独立、无冲突的小切片合并编排进同一次 A/B 任务，或评估直接采用传统交互式开发。合并前提：各切片目标文件/函数域相互独立、无依赖冲突，合并后的 D1-D4 编排须通过完整静态检查与真实编译验证；若 A/B 任务内验证无法覆盖某切片特有需求，任务结束后单独执行专项验证测试并记录证据；有独立评审要求的改动（默认翻转、开关放量等）仍须独立任务或独立评审记录，不得借合并混批绕过；合并后任一切片失败按 first-fail-stop 阻断整轮，故每片保持小而独立、合并数量适度。
- **start-file 前初始编制（硬规则）**：从 Vx 模板新建正式任务定义时，尚无运行会话、事故票、故障轮或故障 op；代理使用 VS Code `apply_patch` 直接填写新建的正式 `testdata/*.json`，不得伪造 ticket 或调用 `task_definition_repair_transaction.ps1`。模板复制及不改变 JSON 值、数组顺序或 operation 结构的编码/EOL 规范化可使用机械命令，所有 JSON 语义修改仍禁止终端内联 Python/PowerShell、here-string、重定向、通用字符串替换或格式化器。模板中的 `preclass_source/preclass_header/query_exec` 仅为结构示例，必须替换为本任务的完整目标闭包并删除未使用 target/op/marker/assertion，禁止保留推测性 target 或未使用的 `lifecycle=create` 条目。每个目标使用稳定 `id/file/kind/lifecycle`；每个 operation、`idempotentContainsByTarget` 和 assertion 显式绑定 target，跨文件 operation 按 declaration -> definition -> caller 等真实依赖全局排序。依次完成 TODO-free、`-SyntaxOnly`、Vx 专项安全回归、A 全定义静态检查、B 使用 A 作为 `-PrerequisiteTaskDefinitionFiles` 的链式全定义检查，以及完整 target set 的编译/黄金/Step47 验证；`-RoundTag/-OperationIndex` 仅可缩小诊断范围，不能作为最终验收。A/B 均通过后才生成 start-file。
- **`create-file` 跨轮设计（硬规则）**：同一任务定义中，`lifecycle=create` target 必须由恰好一个 `create-file` 首次引入，且该 operation 必须是创建轮内唯一触碰该 target 的 operation；不得在同轮后续 op 对该 target 执行 `regex-patch`。checker 的整轮 replay 要求 target 最终内容与 `create-file.contentSha256` 一致，同轮继续修改必然失败。后续修改最早放到下一 D 轮，且创建轮产出的文件必须可独立通过当轮语法/编译门禁；若没有后续轮，则将最终完整内容直接写入 `create-file.content`。同轮可以修改其他 existing target 以接入新文件，但完整 effective target map 必须在轮末可编译。由 prerequisite 任务创建、供当前任务继续修改的文件按当前任务真实基线登记，不得重复 `create-file`。
- **四类检查/编辑边界（硬规则）**：初始编制可直接 `apply_patch` 新正式任务定义并做完整验收；start-file 生成后的 launcher 只执行 `-SyntaxOnly` 装载门禁；每个实际 D 轮由独立 checker 基于当时权威源码执行整轮检查并生成哈希绑定产物；仅运行期 task-static 或经确认的编译/验证代码故障才使用 `Prepare -> Inspect -> Validate -> Promote` 候选事务。不得用 launcher 的 SyntaxOnly 替代初始完整验收，也不得用初始编制自由编辑规则绕过运行期 ticket、stage、round、op 边界。
- **跨编译环境的预处理契约（硬规则）**：本地 mandatory syntax gate 与真实远程构建因 OS、SDK、C 运行库或编译器不同而暴露头文件契约缺口、类型缺失或隐式函数声明时，若首个诊断证明这是源码可移植性代码故障，可在任务定义中为相关 `c-source` / `c-header` target 增加 operation，由 replacement 写入真实平台宏控制的 `#if/#else/#include/#define/typedef`，并保留其他平台原实现。宏必须对应差异的真实来源：编译器/SDK 头文件契约按编译器宏区分，MSVC 与 clang-cl 使用 `_MSC_VER` 和 `<BaseTsd.h>` / `SSIZE_T`；Ubuntu VM 上的 MinGW win32/win64 即使定义 `_WIN32`，也应使用 `<sys/types.h>` / `ssize_t`，不得把 `_WIN32 || __MINGW32__` 当作 `<BaseTsd.h>` 可用性的证明。只有 Windows 目标平台或 CRT API 差异（如 `Sleep`、`_stricmp`）才使用 `_WIN32` / `__MINGW32__`。所有受影响 source/header 必须进入 Vx 完整 target closure，operation/marker/assertion 显式绑定 target；不得直接预改业务源码，否则 `restore-source` / snapshot 恢复后会丢失。禁止定义 checker-only 宏、伪造空声明、关闭隐式声明告警或只改 checker 命令来换取 PASS；编译器/SDK 缺失仍是 noncode。完成后必须同时通过完整 effective target map 的本地 task-static syntax gate 与真实远程/目标工具链构建。参考 A/43 `testdata/autopilot_code_step_tasks_20270316_20270322.json` D1：`wc_net.h` 以 `_MSC_VER` 选择 `<BaseTsd.h>` + `typedef SSIZE_T ssize_t`，MinGW/POSIX 分支保留 `<sys/types.h>`；`client_flow.c` 在 POSIX 分支保留 `<strings.h>`，Windows 目标分支映射 `strcasecmp/_stricmp`、`strncasecmp/_strnicmp`，并以 `Sleep` / `nanosleep` 条件分支处理延时调用。

### 运行期自愈修复专用规则
- **脚本故障自愈开关与排查专用流程（硬规则）**：start-file 的 `LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED` 默认 `false`；字段缺失、空值或非法值均按关闭处理。关闭时脚本故障票必须进入 `incident-script-diagnose-only`，Agent 只允许只读取证、根因分析、修复方案、聊天汇报和原子收尾；禁止修改任何文件、创建脚本、停止/重启进程、执行 `business_resume`/`continue_watch_command`、改变环境或实施恢复。报告须包含现象、首次错误、调用链、根因与证据路径、影响、置信度、最小修改建议、验证命令、风险与回滚，并声明未修改文件及未控制进程。仅显式为 `true` 时才允许沿用脚本自愈专用流程。
- **运行期被动收票与三分钟收尾（硬规则）**：A/B 无人值守运行期间，guard/trigger/dispatch 负责监控、产票和向会话投送消息。Agent 只需保持会话在线并静默等待事件驱动票或状态票；等待本身不执行任何命令。收到工单后，必须严格按工单指令与 `next_command_order` 执行所有无需用户确认的预授权操作，不得遗漏；事件票若提供 brief 的 `recovery_transaction_command`，则只执行一次该恢复事务命令，否则最终只执行一次 brief 的 `atomic_closeout_command`，由事务/原子命令统一完成 `handled_at`、processed、ledger receipt 与 closure 校验，旧分步回执字段仅作审计兼容。闭环后继续静默等待。禁止 Agent 自行创建或运行定时巡检监控脚本、轮询循环、后台 job、watcher、常驻 PowerShell 命令或长时间跨轮次巡检命令，禁止自行周期性调用 heartbeat 或 `poll_agent_tickets.ps1`；这些命令可能在下一张事件票到达时中断任务、收尾和回执。一次性执行工单明确给出的 poll/heartbeat/回执命令不受此限制。通过标准 stage window 重启主进程后，3 分钟仅是完成事务/原子收尾的目标窗口，不是 Agent 可执行的事务总墙钟超时或强杀授权。Agent 执行 `recovery_transaction_command` 后必须等待该同步命令自然退出；即使运行超过 3 分钟或 240 秒，也不得调用 kill、`Stop-Process`、终端中止或工具超时终止该事务及其子进程。240 秒仅是事务脚本内部的 stage 主进程启动验证预算，atomic closeout 另有 120 秒 acknowledge 超时；是否失败只由命令退出码和 JSON 机器事实判定。若执行环境自身中断命令，只如实报告阻塞，不得伪造闭环或再次执行事务。
- **Agent 工具与机器回执门禁（硬规则）**：任务定义 JSON 的语义修改必须使用 VS Code `apply_patch` 编辑工具；其他仓库文件修改也应使用结构化编辑工具。禁止使用终端内联 Python、`powershell -Command` 多层嵌套字符串、here-string、shell 重定向、通用字符串替换或格式化器来修改任务定义语义。格式化器仅可做不改变 JSON 值、数组顺序或 operation 结构的机械格式化。任务定义编辑后必须依次完成 `-SyntaxOnly` 装载检查、故障目标 op 快检（可定位时）和当前故障 D 轮的不带 `-OperationIndex` 递进严格检查；后续轮检查范围服从 `TASK_STATIC_CROSS_ROUND_REPAIR_ENABLED`。复杂转换应先落为仓库内已有或经审查的单用途脚本，再以一次性同步命令执行；不得用无超时的交互式命令承担编辑或闭环。事件票若提供 brief 的 `recovery_transaction_command`，必须优先执行该事务命令；否则必须执行 brief 的 `atomic_closeout_command`。仅当事务/原子命令退出码为 0 且 JSON 机器事实满足对应门禁（原子命令需 `success=true`、`processed=true`、`ledger_status=done`、`receipt_valid=true`、`closure_pass=true` 和有效 `handled_at`）时，才可原样回传该时间并声称闭环。命令缺失、锁忙、JSON 不可解析或任一事实门禁失败时必须 fail-close，只报告阻塞，禁止自行编造 `handled_at` 或用聊天文本替代持久化回执。`running-status-report` 继续遵守只读规则，不执行该有副作用的事务或原子收尾命令。
- **任务定义隔离候选事务（硬规则）**：代码自愈不得直接编辑正式任务定义。先执行 `tools/test/task_definition_repair_transaction.ps1 -Mode Prepare`，读取其生成的 `operation-preview.json`、`operation-preview.txt` 与 `apply-patch-context.txt`，只用 VS Code `apply_patch` 修改事务目录中的 `candidate.json`；候选修改后推荐执行只读 `-Mode Inspect` 刷新 SHA-256 绑定预览，发现零/多匹配、替换后 pattern 仍匹配或双重转义风险时继续修 candidate。Vx 下正式定义的 schema、target registry 与 `target_set_sha256` 在 start-file 会话内冻结：candidate 不得新增、删除、重命名 target，不得修改 target 的 `file/kind/lifecycle` 或 `defaultTarget`；可编辑 op 只能引用已注册 target。全局 `OperationIndex` 按跨文件 operation 数组排序，Inspect 必须模拟所有前置 op，而不是只模拟同 target 的前置项；跨文件 declaration/definition/caller 修复拆成多个单目标 op 并逐 target 断言。`create-file` 故障只允许修 candidate，绝不授权直接创建或覆盖业务文件。Inspect 不修改 candidate、正式任务定义或业务源码，也不替代验证门禁；再按 `Validate -> Promote` 顺序处理。默认单轮模式的 Validate 依次通过 SyntaxOnly、故障目标 op 快检（可定位时）和当前故障轮递进严格检查；跨轮模式在 Prepare/Validate 时同时传入 `-ValidateThroughRound D4 -ChainRounds`，在同一 candidate 中完成全部范围轮次修复，并由一次 checker 调用将故障轮至 D4 顺序应用于同一内存源码。Promote 必须最后且只执行一次，重新校验哈希、target set、候选哈希，原子替换正式文件并通过写后 SyntaxOnly。仅局部 checker/Inspect PASS、candidate 已编辑或 preview 已刷新均不表示修复完成；执行 `recovery_transaction_command`、重启或 resume 前必须确认同票据 `manifest.state=promoted`，`validated_candidate_sha256`、`promoted_sha256` 与正式文件 SHA-256 一致，`promotion-receipt.json` 的 `success=true`、ticket/hash/target set 匹配；单轮模式再次严格检查当前故障轮，跨轮模式还要求 manifest/receipt 的 `validated_rounds` 精确覆盖故障轮至 D4，并从故障轮执行一次 `-ChainRounds` 严格复检正式文件。`prepared`、`validation_failed`、`promotion_failed`、`quarantined`、`abandoned`、receipt 缺失、覆盖不完整、registry 漂移或哈希不一致时必须 fail-close，只继续修 candidate 或报告阻塞，禁止执行 recovery、重启、resume、handled 成功回执。全部成功后删除 candidate/baseline，保留 manifest、预览、日志和 promotion receipt；验证失败、基线漂移、候选漂移或提升失败时正式文件保持或恢复原状并保留候选现场。放弃修复使用 `-Mode Abandon`；工具参数出现额外词元、路径插字或上下文畸变时立即 fail-close，重新读取权威文件并用 `-Mode Quarantine -Reason tool-call-parameter-corruption` 隔离候选，禁止提升、重启或 resume。
- **定时状态票只读汇报（硬规则）**：所有 `running-status-report` 只允许读取并汇报 SESSION/A/B、run_dir、main_round、业务/监控进程存活、heartbeat 与待处理事故票摘要，并回传 `handled_at`。无论 `normal`、`anti-missent` 或 `low-disturb`，状态票均不得执行自愈修复、故障处理、主进程/guard 重启、`business_resume`、源码/脚本/任务定义修改、环境稳定化或其他恢复动作；不得因观察到异常而切换为修复流程。异常只汇报并等待 guard 生成独立事故票，后续处置必须走事故票与全局停机门禁。状态票 brief/work order 不得提供 `continue_watch_command`、resume/restart 或 closure/dedup 等有副作用命令。
- **所有故障动作必须停机后执行（硬规则）**：任何会触发 AI 故障处理、自愈修改、自动修复、restart 或 `business_resume` 的票据与 guard 分支，必须先通过 A/B 阶段业务进程快照确认全部主进程已停止。状态字段为 `FAIL/BLOCKED`、PID 清零或存在 exit artifact 均不能单独作为离线证明；统一快照必须扫描 start-file 绑定候选进程，并仅用 start-file、PID/候选和新鲜度均匹配的终态 artifact 过滤 `-NoExit` 空宿主窗口。仍有业务进程时只记录 `fault_processing_wait` / `fault_action_ticket_wait`，不得打包修复事故、发故障动作票、修改任务定义/源码或执行恢复。`running-status-report`、A→B 阶段通知和会话终态通知可在运行中发送，但不得携带修复动作。D1 stall 必须先停止 A 进程树并由统一快照确认离线，再写 FAIL、发 `incident-captured`；禁止检测后即时 auto-restart，恢复统一走票据闭环。
- **D 轮执行前门禁与报票时序（硬规则）**：A/B 启动入口只运行 `check_task_definition_static.ps1 -SyntaxOnly`，检查文件存在、JSON 可解析、非空 `rounds`，并按 schema 校验 V1 的 `targetFile` 或 Vx 的 `targetFiles/defaultTarget/target` 基础结构；该门禁不读取业务源码、不检查 D1-op1，也不得用 `runtime-ticket` 延迟无效任务定义。每个实际 D 轮先由独立 task-static checker 在跨文件内存映射中按全局顺序处理 operations：当前 op 唯一匹配、替换和安全检查通过后才推进到下一 op；首个失败立即退出，不检查后续 op 或后续轮，整轮通过后生成绑定完整 target set 的 manifest/payload。code-step 仅执行读取绑定产物、全量预验证、journal、逐文件原子写入、写后验证，并在失败时整组回滚；任何 journal/rollback 故障均为 noncode，`rollback_status=incomplete` 硬阻断恢复。guard 必须在阶段业务进程停止后再生成 `incident-captured`。Vx 票据除 stage/round/phase/kind/category/global op/task-definition 外，还必须携带 schema、target set hash、失败 target id/path/kind/lifecycle 及 artifact/journal/rollback 机器事实；事实缺失或不一致时 fail-close，不得猜 target。
- **阶段与代码自愈边界（硬规则）**：只有 `task-static` 故障，以及编译/验证阶段经结构化 category 和证据确认的源码编译、链接、业务逻辑或输出契约故障，才允许进入 code-fix。编译器/工具链不可用、权限、磁盘、网络、远程锁和测试基础设施故障必须进入 noncode。`code-step` 只执行“读 -> 验证 -> 原子写 -> 写后验证”；任何 code-step 故障均属于 noncode，禁止修改源码或任务定义。历史 `code-edit-failure` 也按 noncode 处理，不得作为代码自愈授权。
- **静态检查语义与级联失败风险（硬规则）**：独立 checker 采用顺序内存文本语义；**首个 operation 失败即停止**，失败 op 的 replacement 不进入内存副本，后续 op、replay、`postApplyAssertions` 和后续轮均不执行。这意味着**当前故障 op 之后的 op 即使也有缺陷（如括号计数错误、pattern 引用不存在代码等），在当前故障修复完成前不会被发现**。这不是回退，而是 checker 的预期行为 — 修复当前故障 op 并通过后继续检查时，后续 op 可能暴露新的失败，这是正常的，应按顺序逐一修复。AI 修复 task-static 故障后，可先用 `-RoundTag <Dn> -OperationIndex <n>` 快检当前 op；checker 会只读模拟 op1 至 op(n-1)。恢复前再对当前故障轮运行不带 `-OperationIndex` 的递进严格检查。checker 通过后生成绑定产物，code-step 不重复执行 checker。
- **task-static 跨轮次修复开关（硬规则）**：`TASK_STATIC_CROSS_ROUND_REPAIR_ENABLED` 默认 `false`，字段缺失、空值或非法值均按关闭。关闭时 task-static 自愈只修当前故障 D 轮，后续轮由运行时门禁检查；开启时当前故障轮通过后，按顺序逐轮检查并修复后续 D 轮直到 D4，范围内全部通过后才恢复。每轮 checker 仍首错即停。该开关只作用于 task-static 代码自愈票，不授权 code-step 或非代码故障编辑任务定义，也不扩大编译/验证故障的追加式修复边界。
  - **跨轮次修复的可执行路径**：事务工具按 ticket ID 锁定一个事务目录，但一个 candidate 可承载故障轮到 D4 的全部允许修改。Prepare 时传入 `-ValidateThroughRound D4 -ChainRounds`。每次 checker 都必须从故障票发生轮次传入 `-RoundTag <故障轮> -ChainRounds`，由同一内存文本顺序重放已收敛轮并停在首个未收敛轮；不得为后续轮单独启动以故障轮源码为基线的 checker。上一轮未收敛时禁止检查或修复下一轮；checker 暴露某轮首错后，只修该轮自身 operations，再从故障轮重跑完整链。轮次之间禁止 Promote。全部范围修复写入后执行一次 `Validate -ValidateThroughRound D4 -ChainRounds`；只有 Validate 成功且 manifest 的 `validated_rounds` 精确覆盖故障轮到 D4，Promote 才允许执行。Promote 脚本必须再次核对完整覆盖，任一轮缺失均 fail-close。禁止 Promote 后直接编辑正式文件或尝试第二次 Prepare；这会破坏 receipt/hash 门禁。
- **静态检查进程安全（硬规则）**：checker 按仓库使用 named Mutex 单实例运行；锁冲突立即以 `single_instance_conflict=true` 和退出码 4 失败，不排队。正则有内部 timeout，明显嵌套量词在编译前拒绝，外层 worker 有总时限；任一 timeout 或 worker 异常均 fail-close，禁止重启。
- **operation 安全契约（硬规则）**：保持 `qualityPolicy.operationSafetyPolicy=enforce`。每个 op 必须使用由自身 replacement 产生且不与其他 op 复用的 `idempotentContains` marker；replacement 后原 pattern 必须零命中，整轮第二次应用不得改变文本。每个 regex-patch 轮必须维护 `postApplyAssertions`，以精确计数验证 definition、prototype、真实 call site 及旧形态移除；静态检查通过不替代编译和业务验证。
- **空 D 轮表达与禁止绕过（硬规则）**：仅当任务编制阶段已确认某 D 轮从设计上没有代码变更目标时，才将该轮定义为最小 `{"type":"noop","description":"..."}`，且不得包含 `operations`、`idempotentContains` 或 `postApplyAssertions`。禁止用 pattern 与 replacement 相同的自替换 op 或无意义替换伪装 no-op。若原轮有真实目标，只是执行/自愈时发现已被前置轮吸收、replacement 结果已存在或 pattern 不再命中，必须保持 `type=regex-patch`，用逐 op 自有 marker 证明 `absorbed-by-prior-round` / `idempotent-replay` 并完成整轮检查；不得把失败轮改成 `noop` 绕过 pattern、replay、断言或编辑边界门禁。自愈中仅当整轮尚未执行、整轮均可编辑且已确认无变更目标时，才可改为 `noop`，否则继续修复或报告阻塞。
- **跨轮次修改边界（硬规则）**：D1 故障可改 D1-D4；D2 故障可改 D2-D4、不得改 D1；D3 故障可改 D3-D4、不得改 D1-D2；D4 故障仅可改 D4、不得改 D1-D3。V1-V4 是验证轮次而非 JSON 轮次键：不得改 D1-D3，也不得修改或删除 D4 既有内容，只能在 D4 `operations` 末尾连续追加一个或多个 op。未来轮是否在恢复前检查由 `TASK_STATIC_CROSS_ROUND_REPAIR_ENABLED` 决定；关闭时由实际 code-step 前的 task-static 门禁逐轮检查，开启时代理按顺序检查到 D4。
- **轮次归属不可转移（硬规则）**：无论跨轮次修复开启或关闭，某个 D 轮自身的任务定义问题只能在该轮 `rounds.<Dn>.operations` 内通过修改、追加、插入或删除 op 处理，并仅在该轮 operation 结果变化时同步该轮 `postApplyAssertions`；禁止通过修改、追加、插入或删除其他 D 轮的 op 来修复、绕过或吸收本轮问题。“跨轮次修改边界”只定义哪些轮可在同一事务中依次接受各自问题的修复，不授权把一个轮次的问题转移到另一个轮次。跨轮模式下，只有链式 checker 已证明前一轮收敛并把首错推进到后续轮，才允许开始修改该后续轮。
- **D 轮次内操作边界（硬规则）**：task-static 阶段失败时，当前故障 op 之前的 op 为只读；仅允许从故障 op 位置起修改、删除、插入或追加 op。编译/验证阶段仅在已确认是代码故障时适用代码修复边界：该轮原有 op 均为只读，只能在该轮末尾连续追加一个或多个 op。code-step 和编译/验证非代码故障不得编辑任务定义。
- **改动量评估优先**：先评估代码改动量。改动量小，在当前 D 轮次末尾追加 op 补丁（追加模式）；改动量大，则重设计当前 D 轮次所有 ops（重构模式）。追加模式优先，重构模式仅当追加模式导致 ops 数量膨胀或语义混乱时选用。
- **低成本模型任务定义编辑最小操作清单（GPT-5 mini 等）**：
  - 只改允许范围内的 `rounds.<Dn>.operations`；仅在 operation 结构结果变化时同步更新同轮 `postApplyAssertions`。不要改 `rounds` 键名、轮次编号、顶层 schema 字段或前置只读契约。
  - 先定位“当前故障 op”在 operations 中的索引；前置轮次和该索引之前的 op 只读，禁止修改。
  - 允许动作仅限跨轮次矩阵允许的 D 轮，以及当前故障 op 及其后续：修改、删除、插入或追加 op；每个首错只能改首错所属轮，不得改别轮来消除该首错。
  - 每次编辑后，保持 operations 内 op 顺序稳定；不要因为格式化或重排导致语义漂移。
  - pattern/replacement 诊断必须区分 JSON 源码、`ConvertFrom-Json` 解码后的 PowerShell 字符串与 `.NET Regex` 三层；checker 使用标准 `ConvertFrom-Json`，合法 JSON `"\\)"` 会解码为正则 `\)` 并匹配字面量 `)`。`pattern_unmatched=0` 说明 JSON 已加载且正则已编译，只表示对当前顺序内存文本零命中；不得误判为 JSON 解码器不兼容或据此修改 checker。优先读取 `operation-preview.txt` 的解码视图、源码匹配与 checker 首错。
  - 修改 pattern/replacement 时必须同时保证“唯一命中 + 可落地替换 + marker 自有且唯一 + pattern 收敛 + 整轮 replay 稳定 + 精确断言通过”；若无法唯一命中，优先在允许边界内追加新 op，不要强改前置 op。
  - 不得以自替换 op 表示空轮，也不得把失败或运行时已吸收的 `regex-patch` 改成 `noop`；设计时确无变更目标才使用不含 operations/marker/assertions 的最小 `type=noop` 结构。
  - 单轮模式重启前先跑 `-SyntaxOnly`，可定位时跑目标 op 快检，再跑当前故障轮的递进严格检查。跨轮模式每次修改后都从故障票轮次运行 `-ChainRounds`，已收敛轮由链自动重放；若失败，只修链式首错所属轮，禁止跳过失败轮、回头改前置轮或单独检查后续轮。
- 任何重启前必须运行当前故障轮静态检查（`tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce -RoundTag <Dn>`）；若检查失败，必须根据首个诊断继续在允许修改边界内修复并重新检查。只有当前故障轮通过才可重启；后续轮由实际 code-step 检查。若无法合规通过，报告阻塞并停止重启，禁止绕过门禁。
- 修改 D 轮次任务定义后，务必检查该轮次中每个 op 是否在源码中遗留了**孤儿函数体**。当 op 的 pattern 只匹配函数签名而不匹配其函数体时，签名被替换后原函数体将残留为悬空代码块，导致编译错误。修复必须服从编辑边界：仅当问题 op 可编辑时修改其 pattern；编译/验证或 V 轮故障只能在允许轮次末尾追加清理 op，不得回改只读 op。修复后用精确断言证明旧孤儿形态为 0。
- 修改 helper 前向声明时必须保留 helper 的函数定义；若首次 caller 调用之前没有 prototype，则在 caller 前添加，并删除 caller 之后或其他位置的重复 prototype。完成后同一 helper 必须恰好保留一个 prototype，且位于首次 caller 之前。“删除旧 prototype + 插入 caller 前 prototype”必须作为原子归一化操作，任一步失败都不得写入部分源码或持久化不完整 operations。
- D 轮次代码设计必须基于 whois 项目的整体方案，包括但不限于：
  - 项目架构文档与 RFC（`docs/` 目录下），当前代码改动涉及的具体方案见 [../docs/RFC-address-space-preclassifier.md](../docs/RFC-address-space-preclassifier.md)。
  - 输出契约（标题行、尾行、折叠行格式等），详见 [../docs/USAGE_CN.md](../docs/USAGE_CN.md) 与 [../docs/USAGE_EN.md](../docs/USAGE_EN.md)。
  - IPv4/IPv6 查询规则契约，详见 [../docs/RFC-ipv4-ipv6-whois-lookup-rules.md](../docs/RFC-ipv4-ipv6-whois-lookup-rules.md)。
  - DNS 与重试策略契约（v3.2.8–v3.2.9 冻结），详见 [../docs/RFC-dns-phase2.md](../docs/RFC-dns-phase2.md)、[../docs/RFC-dns-phase4-ip-health.md](../docs/RFC-dns-phase4-ip-health.md)。
- Step47 矩阵契约是不可逾越的红线，不得因代码变更改变其预期结果。
- **预算耗尽与待办修复的优先级（2026-07-05）**：当收到 `budget-exhausted-stop` 通告时，若此前同一会话中已有一张 `incident-captured`（或类似）票据允许了 `code-fix-workflow` / `script-fix-workflow` 但尚未执行对应的修复动作，则**先完成已有修复后再处理预算通告**。budget-exhausted 仅限制 guard 自动重启次数，不影响 task-definition 修复的手动执行。修复完成并静态检查通过后，再按 rerun-scope-decision 的结论重启对应阶段（A 或 B），不要等待额外的人工确认——budget-exhausted 的 `blocked_actions` 不影响 Agent 在修复后通过 launcher 手动重启。相同指纹预算耗尽不得静默退出，必须投送结构化 `manual-wait-paused`，至少包含 `hard_block=true`、`hard_block_reason`、`failure_fingerprint`、`retry_count`、`retry_limit`、`auto_restart_allowed=false` 与 `task_definition`；该票只报告并原子收尾，不得自动重启。
- **防无限循环保护（2026-07-05）**：Agent 在每次重启对应阶段前，应将当前故障的 `main_round` + `failure_fingerprint` 写入 session memory（`/memories/session/last_failure.md`）。重启后若收到新的 `incident-captured` 票据，其 `main_round` 与 `failure_fingerprint` 均与 session memory 中记录的上一次一致，则判定为**同一故障点连续失败**。此时 Agent 应停止自动重启，向用户报告修复未生效，等待人工介入。session memory 中的记录应在以下任一条件满足时清除：(a) 新的故障指纹与上次不同（修复已改变故障表现），(b) 该阶段全部 8 轮完成且未再触发同一故障。
- **相同指纹门禁三段化（2026-07-21）**：仅编译/验证阶段经结构化证据确认为代码故障时采用 `pending_review -> override_window -> hard_block` 状态机。默认预算 `CODEFIX_IDENTICAL_FP_MAX_RETRIES=3`（可按 stage 覆盖）。`task-static` 由 SyntaxOnly、目标 op 与当前轮递进严格检查判定修复有效性，不进入该状态机；`code-step` 只做绑定产物文件 I/O，任何故障均为 noncode，也不进入该状态机。第 2/3 次代码修复重启必须有有效修复证据（任务定义哈希变化 / 轮次任务定义印记变化 / 轮次源码摘要变化），否则直接进入 `hard_block`。
- **人工修复后解锁规则（2026-07-08）**：`hard_block` 不是永久封禁。人工修复后仅在“有效修复证据 + 静态检查通过”时允许从 `hard_block` 自动回到 `pending_review` 并重置同指纹预算；证据不足时保持阻断，禁止重启。
- 无人值守运行期间禁止执行检出、提交与推送操作（如 `git checkout` / `git commit` / `git push`）；仅在用户明确同轮授权后，才可进入版本控制提交发布步骤。

## 任务定义编辑工具选择硬规则（优先级高于一切）

### 适用范围
编辑 `testdata/autopilot_code_step_tasks_*.json` 正式任务定义，以及 `out/artifacts/task_definition_repair/<ticket>/` 下的 `candidate.json`。

### 允许的工具链

| 阶段 | 工具 | 说明 |
|------|------|------|
| 读取文件 | `read_file` | 读取 operation-preview.txt、apply-patch-context.txt、candidate.json |
| 语义编辑（首选） | `apply_patch` | VS Code 的 JSON-aware 结构化替换引擎；处理 JSON 转义、正则转义和字面量三层 |
| 语义编辑（回退） | `replace_string_in_file` / `multi_replace_string_in_file` | **仅当 `apply_patch` 在当前会话中不可用时使用**。必须包含前后各至少 3-5 行上下文以确保唯一匹配；编辑后立即通过 `-Mode Inspect` 验证转义正确性 |
| 运行验证 | `run_in_terminal` | 仅用于调用 Inspect/Validate/Promote 等只读验证命令，不得用于编辑 JSON |

### 禁止的操作（硬阻断）

以下操作在任何情况下均禁止：

- ❌ **禁止使用 `run_in_terminal`** 执行内联 Python / PowerShell / sed 修改 JSON
- ❌ **禁止使用 `create_file` 覆写** candidate.json 或正式任务定义
- ❌ **禁止使用终端重定向**（`>`、`>>`）、here-string、管道拼接做任何替换
- ❌ **禁止 `git checkout` 回滚源码或任务定义文件**
- ❌ **运行期禁止直接编辑正式任务定义** — start-file 生成后必须通过 `Prepare → Inspect → Validate → Promote` 事务流程；start-file 前新任务的初始编制按上文规则直接编辑新正式文件

### 条件允许的操作（回退策略）

以下操作仅在 `apply_patch` 不可用且严格遵守安全约束时才允许：

- ✅ **条件允许使用 `replace_string_in_file` / `multi_replace_string_in_file`** 编辑 candidate.json 中的 JSON 语义
  - **约束条件**:
    1. 必须包含唯一确定的字符串段，前后各至少 3-5 行上下文
    2. 编辑后**必须立即**通过 `-Mode Inspect` 验证 JSON 转义和正则可编译性
    3. 不得通过反复猜测转义层级来试错；若 Inspect 失败，仔细分析 `operation-preview.txt` 的三层编码视图后重新编辑
    4. 若编辑导致 candidate.json 损坏，执行 `-Mode Quarantine -Reason candidate-corrupted` 后重新 `-Mode Prepare`
  - **已知风险**: 
    - 这些工具不理解 JSON 编码层（如 pattern 中的 `\\` 在 JSON 源码中表示为 `\\\\`），替换时易破坏转义链
    - **`multi_replace_string_in_file` 风险高于 `replace_string_in_file`**：前者在一次调用中执行多处替换，任一处转义问题都会导致整体失败；且后续替换基于已修改的文件内容，前后替换可能相互干扰，排查难度更大。尽可能优先使用单次 `replace_string_in_file` 逐处修改，每修改一处后立即验证。

### 自检声明（每次编辑前必须执行）

在调用任何编辑工具前，必须根据当时可用工具输出对应的自检声明并等待工具执行结果：

#### 当 `apply_patch` 可用时：

```
SELF-CHECK: task-definition JSON edit.
Target file: <path to candidate.json or official task definition>
Allowed tool for this edit: apply_patch
Blocked tools for this operation: run_in_terminal, create_file, replace_string_in_file, multi_replace_string_in_file
Confirmed: I am NOT using terminal/Python/sed/regex to modify JSON.
```

#### 当 `apply_patch` 不可用，回退到 `replace_string_in_file` 时：

```
SELF-CHECK: task-definition JSON edit.
Target file: <path to candidate.json>
apply_patch is NOT available in this session.
Fallback tool: replace_string_in_file / multi_replace_string_in_file.
RISK: These tools do NOT understand JSON/Regex encoding. I must:
  1. Include at least 3-5 lines of context BEFORE and AFTER the exact target string
  2. Only replace a UNIQUE, unambiguous string segment
  3. Immediately run -Mode Inspect to verify JSON escaping and regex compilability
  4. NOT blindly retry with different escaping guesses
Blocked for editing: run_in_terminal, create_file
Confirmed: I am NOT using terminal/Python/sed/regex to modify JSON.
```

### 负面示例（代理代理可能错误倾向）

```text
❌ 错误：在 apply_patch 可用时使用 replace_string_in_file 修改 candidate.json 的 pattern
   → 结果：JSON 转义被破坏，pattern/replacement 字符串失真
   → 正确做法：apply_patch 可用时始终优先使用 apply_patch

❌ 错误：在回退 replace_string_in_file 时不加足够上下文就替换
   → 结果：匹配到多处导致错误替换，JSON 结构损坏

❌ 错误（高发）：使用 multi_replace_string_in_file 同时修改 candidate.json 中多处
   → 结果：任一处的转义偏差都会导致整批失败；后续替换基于已修改内容，前后干扰难以排查
   → 正确做法：尽可能使用单次 replace_string_in_file 逐处修改，每处修改后立即 -Mode Inspect 验证

❌ 错误：用 run_in_terminal 执行 powershell 替换操作
   → 结果：JSON 编码不匹配，checker 无法编译正则

❌ 错误：用 git checkout 恢复源码
   → 结果：破坏 A 快照产物，B 阶段源码基线被错误覆盖

❌ 错误：用 create_file 重新写入 candidate.json
   → 结果：丢失事务上下文，哈希绑定断裂
```

### 违规后果

任何不合规编辑方式造成的 JSON 损坏、pattern 失真或任务定义不可用，由执行该错误的 Agent 全权负责恢复。同一票据内第二次违规将直接阻断整张修复票，不再允许继续自愈。

### candidate.json 损坏或不可恢复时的回退方案

如果 `candidate.json` 在修复过程中被严重污染（pattern/replacement 被不可逆破坏、JSON 结构断裂、哈希绑定三视图无法对齐），可以重新开始：

1. 不需要人工介入 — 先执行 `-Mode Quarantine -Reason candidate-corrupted` 保留现场
2. 票据 ID 不变，再次执行 `-Mode Prepare`，工具会用**当前正式任务定义文件**重新生成一份干净候选
3. 基于干净候选重新开始修复流程

注意：
- 重新 Prepare 会丢失 previous candidate 中的所有未提升修改，因此如果之前有已经通过局部 checker 但尚未 Promote 的修复，需要重新做
- 正式任务定义文件始终保持只读，绝不会被 Prepare 覆盖
- 只要尚未执行 `-Mode Promote`，重新 Prepare 是安全的（正式文件未被修改）

### 推荐修复验证节奏（经验总结，减少 Validate throw 风险）

从多轮 D1-D4 task-static 修复实践中总结出的稳妥三步验证法，可避免修复不完整导致事务 `Validate` 阶段的 `checker throw`：

1. **Pre-check（直接 checker 验证整轮）**
   - 修改 `candidate.json` 后，不急于走事务 `Validate`，先通过独立 checker 直接验证该轮全部 ops：
     ```powershell
     powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 `
         -TaskDefinitionFile "out/artifacts/task_definition_repair/<ticket>/candidate.json" `
         -Policy enforce -RoundTag <Dn>
     ```
   - 这比 `Inspect -OperationIndex` 更全面，它会顺序执行该轮所有 ops、replay、postApplyAssertions 和 C syntax gate。
   - 首错即停，按诊断在允许编辑边界内修复后重新检查，直到该轮全通过（`summary errors=0`）。

2. **Operate（事务 Validate）**
   - Pre-check 通过后，再走事务 `Validate`：
     ```powershell
     powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/task_definition_repair_transaction.ps1 `
         -Mode Validate -TaskDefinitionFile "<正式文件>" -TicketId "<ticket>" -Stage <A|B> -RoundTag <Dn> -OperationIndex <n>
     ```
   - 此时 checker 已经在第 1 步验证过，Validate 应该通过，不会触发 `throw`。

3. **Promote（原子提升）**
   - Validate 通过后立即执行 `-Mode Promote`，不拖延。

**关键原则**：不要在未通过 checker 全轮验证时直接跑事务 `Validate`。事务 `Validate` 内部的 `throw` 不是脚本缺陷，而是 fail-close 门禁 — 它只是忠实地报告 checker 的失败结果。第 1 步的 pre-check 就是在事务外提前补齐验证，把问题消灭在提交事务 Validate 之前。

## 终端命令操作提醒（硬规则，跨模型通用）
- **PowerShell `>>` 陷阱**：`>>` 在 PowerShell 中是**追加输出重定向操作符**（等价 `Out-File -Append`），后面必须跟文件路径，不是续行符或多行提示符。命令末尾误加 `>>` 会导致 PowerShell 阻塞等待文件名输入，直至超时或被 kill。**构造任何 `powershell -Command`、`run_in_terminal` 或内联 PowerShell 命令时，禁止在命令末尾出现孤立的 `>>`。**
  - 正确做法：多语句用 `;`（分号）串联，例如 `cmd1; cmd2; cmd3`。
  - 自查方法：提交命令前，检查最后非空白字符是否为 `>`，若是则删除或补全文件路径。
  - 已知高危模型：DeepSeek V4 Flash 等低参数量模型易将 `>>` 混淆为 Shell/REPL 续行提示，需额外留意。

## 临时文件与调试目录规范（硬规则）
- 修复过程中产生的临时文件（如通过 `-OutputEffectiveTargetFile` 生成的有效源码快照、regex 调试脚本、pattern 解码测试输出等）**必须写入项目 `tmp/` 目录**（如 `tmp/checker_debug/`）
- **禁止写入 `C:\temp`、`$env:TEMP` 或用户桌面**等系统临时目录 — 这些路径不随项目清理，且远程构建/冒烟无法访问
- 修复完成后必须清理 `tmp/` 下对应票据的临时文件，避免工作区污染
- 例外：编译器的临时 `.c` 文件（由 checker 自动在 `src/core/.task-static-*.c` 管理）不受此限

## 协作与文档
- 交流用中文；代码/注释/提交信息用英文。
- 变更输出契约、DNS/重试策略或自测流程时，请同步更新 [../docs/USAGE_CN.md](../docs/USAGE_CN.md)、[../docs/USAGE_EN.md](../docs/USAGE_EN.md)、[../RELEASE_NOTES.md](../RELEASE_NOTES.md) 与相关 RFC/黄金脚本说明。
- 日终或重要改动请在 [../docs/RFC-whois-client-split.md](../docs/RFC-whois-client-split.md) 记录进展与待办，确保上下文可追溯。
