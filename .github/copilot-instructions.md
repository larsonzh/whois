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

## D/V 轮次任务定义设计指导（自愈修复专用）
- **运行期被动收票与三分钟收尾（硬规则）**：A/B 无人值守运行期间，guard/trigger/dispatch 负责监控、产票和向会话投送消息。Agent 只需保持会话在线并静默等待事件驱动票或状态票；等待本身不执行任何命令。收到工单后，必须严格按工单指令与 `next_command_order` 执行所有无需用户确认的预授权操作，不得遗漏；事件票最终只执行一次 brief 的 `atomic_closeout_command`，由该命令统一完成 `handled_at`、processed、ledger receipt 与 closure 校验，旧分步回执字段仅作审计兼容。闭环后继续静默等待。禁止 Agent 自行创建或运行定时巡检监控脚本、轮询循环、后台 job、watcher、常驻 PowerShell 命令或长时间跨轮次巡检命令，禁止自行周期性调用 heartbeat 或 `poll_agent_tickets.ps1`；这些命令可能在下一张事件票到达时中断任务、收尾和回执。一次性执行工单明确给出的 poll/heartbeat/回执命令不受此限制。通过标准 stage window 重启主进程后，Agent 必须在 3 分钟内执行原子收尾并通过全部机器事实门禁，然后回到静默被动等待；3 分钟是闭环上限，不是继续巡检的窗口。若无法按时闭环，立即如实报告阻塞，不得用主动巡检延长处置。
- **Agent 工具与机器回执门禁（硬规则）**：任务定义 JSON 的语义修改必须使用 VS Code `apply_patch` 编辑工具；其他仓库文件修改也应使用结构化编辑工具。禁止使用终端内联 Python、`powershell -Command` 多层嵌套字符串、here-string、shell 重定向、通用字符串替换或格式化器来修改任务定义语义。格式化器仅可做不改变 JSON 值、数组顺序或 operation 结构的机械格式化。任务定义编辑后必须依次完成 `-SyntaxOnly` 装载检查、故障目标 op 快检（可定位时）和当前故障 D 轮的不带 `-OperationIndex` 递进严格检查；不得预演后续 D 轮来阻断当前轮恢复。复杂转换应先落为仓库内已有或经审查的单用途脚本，再以一次性同步命令执行；不得用无超时的交互式命令承担编辑或闭环。若终端进入续行提示、等待非敏感输入或输出无法判定完成，立即停止该命令并改用结构化编辑/专用脚本，不得继续追加转义文本碰运气。事件票收尾必须执行 brief 的 `atomic_closeout_command`；仅当退出码为 0 且 JSON 同时满足 `success=true`、`processed=true`、`ledger_status=done`、`receipt_valid=true`、`closure_pass=true` 和有效 `handled_at` 时，才可原样回传该时间并声称闭环。命令缺失、锁忙、JSON 不可解析或任一事实门禁失败时必须 fail-close，只报告阻塞，禁止自行编造 `handled_at` 或用聊天文本替代持久化回执。`running-status-report` 继续遵守只读规则，不执行该有副作用的原子收尾命令。
- **定时状态票只读汇报（硬规则）**：所有 `running-status-report` 只允许读取并汇报 SESSION/A/B、run_dir、main_round、业务/监控进程存活、heartbeat 与待处理事故票摘要，并回传 `handled_at`。无论 `normal`、`anti-missent` 或 `low-disturb`，状态票均不得执行自愈修复、故障处理、主进程/guard 重启、`business_resume`、源码/脚本/任务定义修改、环境稳定化或其他恢复动作；不得因观察到异常而切换为修复流程。异常只汇报并等待 guard 生成独立事故票，后续处置必须走事故票与全局停机门禁。状态票 brief/work order 不得提供 `continue_watch_command`、resume/restart 或 closure/dedup 等有副作用命令。
- **所有故障动作必须停机后执行（硬规则）**：任何会触发 AI 故障处理、自愈修改、自动修复、restart 或 `business_resume` 的票据与 guard 分支，必须先通过 A/B 阶段业务进程快照确认全部主进程已停止。状态字段为 `FAIL/BLOCKED`、PID 清零或存在 exit artifact 均不能单独作为离线证明；统一快照必须扫描 start-file 绑定候选进程，并仅用 start-file、PID/候选和新鲜度均匹配的终态 artifact 过滤 `-NoExit` 空宿主窗口。仍有业务进程时只记录 `fault_processing_wait` / `fault_action_ticket_wait`，不得打包修复事故、发故障动作票、修改任务定义/源码或执行恢复。`running-status-report`、A→B 阶段通知和会话终态通知可在运行中发送，但不得携带修复动作。D1 stall 必须先停止 A 进程树并由统一快照确认离线，再写 FAIL、发 `incident-captured`；禁止检测后即时 auto-restart，恢复统一走票据闭环。
- **D 轮执行前门禁与报票时序（硬规则）**：A/B 启动入口只运行 `check_task_definition_static.ps1 -SyntaxOnly`，检查文件存在、JSON 可解析、非空 `targetFile` 与非空 `rounds`；该门禁不读取业务源码、不检查 D1-op1，也不得用 `runtime-ticket` 延迟无效任务定义。每个实际 D 轮由 code-step 在内存副本上按顺序处理 operations：当前 op 唯一匹配、替换和安全检查通过后才推进到下一 op；首个失败立即退出，不检查后续 op 或后续轮，整轮通过后才一次性写源码。guard 必须在阶段业务进程停止后再生成 `incident-captured`。票据必须包含 stage、round、op（可定位时）和 task-definition。
- **静态检查语义（硬规则）**：checker 与 code-step 均采用顺序内存文本语义；首个 operation 失败即停止，失败 op 的 replacement 不进入内存副本，后续 op、replay、`postApplyAssertions` 和后续轮均不执行。AI 修复 code-step 故障后，可先用 `-RoundTag <Dn> -OperationIndex <n>` 快检当前 op；checker 会只读模拟 op1 至 op(n-1)。恢复前再对当前故障轮运行不带 `-OperationIndex` 的递进严格检查，不得用未来轮的缺陷阻断当前轮恢复。
- **静态检查进程安全（硬规则）**：checker 按仓库使用 named Mutex 单实例运行；锁冲突立即以 `single_instance_conflict=true` 和退出码 4 失败，不排队。正则有内部 timeout，明显嵌套量词在编译前拒绝，外层 worker 有总时限；任一 timeout 或 worker 异常均 fail-close，禁止重启。
- **operation 安全契约（硬规则）**：保持 `qualityPolicy.operationSafetyPolicy=enforce`。每个 op 必须使用由自身 replacement 产生且不与其他 op 复用的 `idempotentContains` marker；replacement 后原 pattern 必须零命中，整轮第二次应用不得改变文本。每个 regex-patch 轮必须维护 `postApplyAssertions`，以精确计数验证 definition、prototype、真实 call site 及旧形态移除；静态检查通过不替代编译和业务验证。
- **空 D 轮表达与禁止绕过（硬规则）**：仅当任务编制阶段已确认某 D 轮从设计上没有代码变更目标时，才将该轮定义为最小 `{"type":"noop","description":"..."}`，且不得包含 `operations`、`idempotentContains` 或 `postApplyAssertions`。禁止用 pattern 与 replacement 相同的自替换 op 或无意义替换伪装 no-op。若原轮有真实目标，只是执行/自愈时发现已被前置轮吸收、replacement 结果已存在或 pattern 不再命中，必须保持 `type=regex-patch`，用逐 op 自有 marker 证明 `absorbed-by-prior-round` / `idempotent-replay` 并完成整轮检查；不得把失败轮改成 `noop` 绕过 pattern、replay、断言或编辑边界门禁。自愈中仅当整轮尚未执行、整轮均可编辑且已确认无变更目标时，才可改为 `noop`，否则继续修复或报告阻塞。
- **跨轮次修改边界（硬规则）**：D1 故障可改 D1-D4；D2 故障可改 D2-D4、不得改 D1；D3 故障可改 D3-D4、不得改 D1-D2；D4 故障仅可改 D4、不得改 D1-D3。V1-V4 是验证轮次而非 JSON 轮次键：不得改 D1-D3，也不得修改或删除 D4 既有内容，只能在 D4 `operations` 末尾连续追加一个或多个 op。允许编辑未来轮不代表恢复前要预演未来轮；未来轮在实际 code-step 到达时自行递进检查。
- **D 轮次内操作边界（硬规则）**：code-step 阶段失败时，当前故障 op 之前的 op 为只读；仅允许从故障 op 位置起修改、删除、插入或追加 op。编译/验证阶段失败时，该轮原有 op 均为只读，只能在该轮末尾连续追加一个或多个 op。
- **改动量评估优先**：先评估代码改动量。改动量小，在当前 D 轮次末尾追加 op 补丁（追加模式）；改动量大，则重设计当前 D 轮次所有 ops（重构模式）。追加模式优先，重构模式仅当追加模式导致 ops 数量膨胀或语义混乱时选用。
- **低成本模型任务定义编辑最小操作清单（GPT-5 mini 等）**：
  - 只改允许范围内的 `rounds.<Dn>.operations`；仅在 operation 结构结果变化时同步更新同轮 `postApplyAssertions`。不要改 `rounds` 键名、轮次编号、顶层 schema 字段或前置只读契约。
  - 先定位“当前故障 op”在 operations 中的索引；前置轮次和该索引之前的 op 只读，禁止修改。
  - 允许动作仅限跨轮次矩阵允许的 D 轮，以及当前故障 op 及其后续：修改、删除、插入或追加 op。
  - 每次编辑后，保持 operations 内 op 顺序稳定；不要因为格式化或重排导致语义漂移。
  - 修改 pattern/replacement 时必须同时保证“唯一命中 + 可落地替换 + marker 自有且唯一 + pattern 收敛 + 整轮 replay 稳定 + 精确断言通过”；若无法唯一命中，优先在允许边界内追加新 op，不要强改前置 op。
  - 不得以自替换 op 表示空轮，也不得把失败或运行时已吸收的 `regex-patch` 改成 `noop`；设计时确无变更目标才使用不含 operations/marker/assertions 的最小 `type=noop` 结构。
  - 重启前先跑 `-SyntaxOnly`，可定位时跑目标 op 快检，再跑当前故障轮的递进严格检查；若失败，继续在当前故障 op 及其后续修复，禁止回头改前置 op或预演后续轮。
- 任何重启前必须运行当前故障轮静态检查（`tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce -RoundTag <Dn>`）；若检查失败，必须根据首个诊断继续在允许修改边界内修复并重新检查。只有当前故障轮通过才可重启；后续轮由实际 code-step 检查。若无法合规通过，报告阻塞并停止重启，禁止绕过门禁。
- 修改 D 轮次任务定义后，务必检查该轮次中每个 op 是否在源码中遗留了**孤儿函数体**。当 op 的 pattern 只匹配函数签名而不匹配其函数体时，签名被替换后原函数体将残留为悬空代码块，导致编译错误。修复必须服从编辑边界：仅当问题 op 可编辑时修改其 pattern；编译/验证或 V 轮故障只能在允许轮次末尾追加清理 op，不得回改只读 op。修复后用精确断言证明旧孤儿形态为 0。
- 修改 helper 前向声明时必须保留 helper 的函数定义；若首次 caller 调用之前没有 prototype，则在 caller 前添加，并删除 caller 之后或其他位置的重复 prototype。完成后同一 helper 必须恰好保留一个 prototype，且位于首次 caller 之前。“删除旧 prototype + 插入 caller 前 prototype”必须作为原子归一化操作，任一步失败都不得写入部分源码或持久化不完整 operations。
- D 轮次代码设计必须基于 whois 项目的整体方案，包括但不限于：
  - 项目架构文档与 RFC（`docs/` 目录下），当前代码改动涉及的具体方案见 [../docs/RFC-address-space-preclassifier.md](../docs/RFC-address-space-preclassifier.md)。
  - 输出契约（标题行、尾行、折叠行格式等），详见 [../docs/USAGE_CN.md](../docs/USAGE_CN.md) 与 [../docs/USAGE_EN.md](../docs/USAGE_EN.md)。
  - IPv4/IPv6 查询规则契约，详见 [../docs/RFC-ipv4-ipv6-whois-lookup-rules.md](../docs/RFC-ipv4-ipv6-whois-lookup-rules.md)。
  - DNS 与重试策略契约（v3.2.8–v3.2.9 冻结），详见 [../docs/RFC-dns-phase2.md](../docs/RFC-dns-phase2.md)、[../docs/RFC-dns-phase4-ip-health.md](../docs/RFC-dns-phase4-ip-health.md)。
- Step47 矩阵契约是不可逾越的红线，不得因代码变更改变其预期结果。
- **预算耗尽与待办修复的优先级（2026-07-05）**：当收到 `budget-exhausted-stop` 通告时，若此前同一会话中已有一张 `incident-captured`（或类似）票据允许了 `code-fix-workflow` / `script-fix-workflow` 但尚未执行对应的修复动作，则**先完成已有修复后再处理预算通告**。budget-exhausted 仅限制 guard 自动重启次数，不影响 task-definition 修复的手动执行。修复完成并静态检查通过后，再按 rerun-scope-decision 的结论重启对应阶段（A 或 B），不要等待额外的人工确认——budget-exhausted 的 `blocked_actions` 不影响 Agent 在修复后通过 launcher 手动重启。
- **防无限循环保护（2026-07-05）**：Agent 在每次重启对应阶段前，应将当前故障的 `main_round` + `failure_fingerprint` 写入 session memory（`/memories/session/last_failure.md`）。重启后若收到新的 `incident-captured` 票据，其 `main_round` 与 `failure_fingerprint` 均与 session memory 中记录的上一次一致，则判定为**同一故障点连续失败**。此时 Agent 应停止自动重启，向用户报告修复未生效，等待人工介入。session memory 中的记录应在以下任一条件满足时清除：(a) 新的故障指纹与上次不同（修复已改变故障表现），(b) 该阶段全部 8 轮完成且未再触发同一故障。
- **相同指纹门禁三段化（2026-07-08）**：D 轮次 `code-step` 的相同指纹门禁采用 `pending_review -> override_window -> hard_block` 状态机。默认预算 `CODESTEP_IDENTICAL_FP_MAX_RETRIES=3`（可按 stage 覆盖）。第 2/3 次重试必须有有效修复证据（任务定义哈希变化 / 轮次任务定义印记变化 / 轮次源码摘要变化），否则直接进入 `hard_block`。
- **人工修复后解锁规则（2026-07-08）**：`hard_block` 不是永久封禁。人工修复后仅在“有效修复证据 + 静态检查通过”时允许从 `hard_block` 自动回到 `pending_review` 并重置同指纹预算；证据不足时保持阻断，禁止重启。

## 协作与文档
- 交流用中文；代码/注释/提交信息用英文。
- 变更输出契约、DNS/重试策略或自测流程时，请同步更新 [../docs/USAGE_CN.md](../docs/USAGE_CN.md)、[../docs/USAGE_EN.md](../docs/USAGE_EN.md)、[../RELEASE_NOTES.md](../RELEASE_NOTES.md) 与相关 RFC/黄金脚本说明。
- 日终或重要改动请在 [../docs/RFC-whois-client-split.md](../docs/RFC-whois-client-split.md) 记录进展与待办，确保上下文可追溯。
