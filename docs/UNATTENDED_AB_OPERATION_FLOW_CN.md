# A/B 无人值守任务完整操作流程（CN）

## 1. 目的

本文给出 whois 仓库中 A/B 无人值守任务的完整操作链路，覆盖从最早的任务设计、模板生成、启动文件编制、启动执行，到运行中监控、任务结束回填、失败后重跑的全流程。

本文重点解决五个问题：
- 明确“正确入口脚本”是什么，避免会话代理绕开既有入口，自行新写脚本导致流程跑偏。
- 给出可直接执行的命令示例，减少临时拼命令和口头记忆带来的误操作。
- 固定“准备完成后必须先由用户确认、且只有用户发出启动命令后才可开跑”的授权边界。
- 说明用户 <-> 无人值守脚本 <-> AI 三者在运行过程中的地位、作用和优先级。
- 明确故障处理、自愈修复、工单执行的默认动作，避免 AI 在无人值守期间反复停下来向用户要确认。

下次开工清单固定写在以下两份 RFC 中：
- docs/RFC-whois-client-split.md
- docs/RFC-address-space-preclassifier.md

## 2. 核心原则

### 2.1 只走既有入口，不新增私有启动脚本

正确做法：
- 使用现有任务定义模板：testdata/autopilot_code_step_tasks_template.json
- 使用现有启动模板与生成器：docs/UNATTENDED_AB_START_TEMPLATE_CN.md、tools/test/create_unattended_ab_start_file.ps1
- 操作员/AI 只使用窗口包装器入口：tools/test/open_unattended_ab_stage_window.ps1

禁止做法：
- 不要为某一轮 A/B 临时再写一套新的 A 启动脚本、B 启动脚本、wrapper 或任务分发脚本。
- 不要把 start_dev_verify_fastmode_A.ps1 / start_dev_verify_fastmode_B.ps1 当作人工操作入口直接执行，它们是 stage window 内部拉起的主进程负载脚本，不是标准操作口。
- 不要绕开 stage window 包装器，直接拼一长串底层 multiround 参数，除非你明确在做底层调试。
- 不要让会话代理“自己发明流程”。先对照本文，再执行现有入口。

### 2.2 产物顺序固定

正确顺序是：
- 任务定义模板
- 任务定义文件
- 下次开工清单（RFC 内）
- 启动模板
- 启动文件
- 静态体检 / 字段同步检查
- 用户确认
- 用户启动命令
- A 启动
- A 收口与快照
- B 启动
- B 收口
- RFC 回填

不是：
- 先写新脚本
- 再猜参数
- 再临时回头补任务定义和启动文件

### 2.3 准备完成后必须先由用户确认

以下三类产物在“准备完成”后，都必须先交由用户确认：
- 任务定义文件
- 两份 RFC 中的下次开工清单
- 任务启动文件

确认前允许做的事：
- 生成文件
- 修正文案
- 跑静态体检和字段同步检查
- 把预检状态整理到可检查状态
- 直接运行统一启动前检查脚本，批量完成 start-file 校验、A/B 任务静态体检、字段同步检查和 `PRECHECK_*` 回填

确认前禁止做的事：
- 启动 A
- 启动 B
- 自动拉起监控长跑链
- 把“准备完成”误当成“允许开跑”

### 2.4 只有用户发出启动命令后才可启动

`PRECHECK_STATUS=PASS`、`PRECHECK_START_GATE=READY` 只表示“技术上可以启动”，不表示“已经获得启动授权”。

真正允许启动的条件是同时满足：
- 任务定义文件已准备好并通过静态体检
- RFC 内下次开工清单已准备好
- 启动文件已准备好并通过字段同步检查
- 上述产物已经过用户确认
- 用户明确发出本轮启动命令

结论：
- 若用户只说“继续整理”“继续准备”“继续补文档”，都不构成启动授权。
- AI 在准备阶段不需要为每个检查子项逐条向用户申请确认；可直接运行统一检查脚本完成所有准备检查。
- 只有用户明确发出“启动 A/B 无人值守任务”“执行这轮 A/B”这类命令后，才可真正启动。

推荐的准备期工作方式：
- AI（包括 GPT-5 mini 这类轻量模型）在准备阶段可直接执行统一检查脚本：`tools/test/check_unattended_ab_launch_ready.ps1`。
- 脚本内部会顺序执行：目标 start-file 校验、A/B 任务静态体检、启动文件字段同步检查、预检与 `PRECHECK_*` 回填。
- 默认输出为精简模式，终端最后一行固定输出 `AB_LAUNCH_READY_RESULT=PASS|FAIL`，便于快速确认整体是否通过。
- 若需要查看完整子步骤明细，可显式追加 `-DetailedOutput`。
- 若其中任一步失败，AI 直接把脚本返回的失败项与失败原因汇总给用户，不需要针对每个检查动作单独申请授权。
- 只有当该脚本整体返回 PASS，且产物内容也已准备妥当时，AI 才向用户发起一次“是否启动 A（带 `-StartMonitors`）”的最终授权请求。

### 2.5 长时间运行脚本必须在 VS Code 外部 PowerShell 窗口执行

长跑任务一律不建议放在 VS Code 集成终端里运行，因为集成终端更容易受窗口、renderer、extension host、terminal host 等环境因素影响，不适合长时间驻留。

必须放在 VS Code 外部 PowerShell 窗口运行的长跑脚本包括：
- A/B 主运行窗口（由 stage window 拉起）
- session guard 脚本（已合并 supervisor/companion 功能）
- takeover trigger 脚本

推荐外部窗口入口：
- tools/test/open_unattended_ab_stage_window.ps1
- tools/test/open_unattended_ab_session_guard_window.ps1
- tools/test/open_unattended_ab_takeover_trigger_window.ps1

VS Code 集成终端的推荐用途仅限：
- 短命令检查
- 只读查询
- 文件对比与临时校验
- 非长跑的一次性脚本

### 2.6 用户 <-> 无人值守脚本 <-> AI 的关系与地位

用户：
- 是最高授权方。
- 决定是否开跑、是否继续、是否停止、是否接受本轮准备产物。
- 对任务定义、开工清单和启动文件拥有最终确认权。

无人值守脚本：
- 是正式执行层。
- 负责真正启动 A/B、跑轮次、执行重启门禁、记录状态、产生日志与工单。
- 脚本状态和产物高于聊天描述，出现冲突时以脚本真实状态与落盘产物为准。

AI：
- 是协助层，不是授权层，也不是执行入口替代品。
- 负责帮助生成任务定义、起草 RFC、整理启动文件、读取工单、解释状态、调用现有入口脚本。
- AI 不应自行发明新的主流程，不应擅自跳过用户确认，也不应在未获启动命令时开跑。
- 进入无人值守运行期后，事件驱动票中列出的既定动作属于预授权执行项；AI 应按事件票 `next_command_order` 执行。定时状态票是严格例外，只预授权只读状态查询、状态汇报与 `handled_at` 回执，不预授权任何故障处理或进程控制动作。
- 运行期工单由既有 guard/trigger/dispatch 链负责生成并投送。AI 只需保持在线并静默等待已投送的事件驱动票或状态票；等待期间不执行命令，不主动定时 heartbeat/poll，不创建或运行定时巡检脚本、轮询循环、后台 job、watcher、常驻内存命令或长时间跨轮次巡检命令。此类命令可能在下一张事件票到达时中断任务、收尾与回执写入。
- 收到工单后，AI 严格按工单指令与 `next_command_order` 执行所有无需用户确认的预授权操作，不得遗漏；若事件票提供 `recovery_transaction_command`，优先将其作为“业务恢复 + 继续监控 + 原子闭环”的单次事务入口执行；未提供事务命令的事件票才执行唯一的 `atomic_closeout_command` 完成 `handled_at`、processed、ledger receipt 与 closure 校验。机器事实门禁全部通过后才算闭环，随后继续静默等待下一张工单。
- 通过标准 stage window 重启主进程后，3 分钟是完成事件票 `recovery_transaction_command` 或唯一 `atomic_closeout_command` 的目标窗口，不是 AI 可执行的事务总墙钟超时或强杀授权。AI 启动恢复事务后必须等待该同步命令自然退出；即使超过 3 分钟或 240 秒，也不得调用 kill、`Stop-Process`、终止承载终端或取消事务及其子进程。240 秒仅是事务脚本内部的 stage 主进程启动验证预算，atomic closeout 另有 120 秒 acknowledge 超时；是否闭环只按命令退出码和 JSON 机器事实判定。执行器自身意外中断命令时只报告阻塞，不得重跑事务或伪造 `handled_at`。
- `ticket_closure_check_command`、`event_dedup_health_check_command`、`final_status_closeout_command` 与 `final_status_closeout_apply_ack_command` 仅作审计兼容展示；事件票不得逐条执行这些旧分步命令，其校验职责统一由事务命令或 `atomic_closeout_command` 内部完成。`running-status-report` 不执行事件票原子收尾。
- 事件驱动票具有高优先级，始终凌驾于 `normal/anti-missent/low-disturb/event-only` 模式之上；事件票处理标准在所有模式下保持一致，不受模式降级影响。
- `event-only` 仅定义“是否触发/发送常规状态票”的调度策略，不得在事件票或故障处置话术中表述为“按 low-disturb 流程执行”。
- 对 `running-status-report`，只汇报当前观测状态；healthy 时写“运行正常”，异常时只描述异常与待处理事故票，不提供或执行修复路径。不得仅凭旧失败摘要、旧 `latest_b_exit.json` 或历史 exit artifact 推断需要重启 B。
- 模式只影响状态票的生成、投送和文本密度，不改变“只汇报、零处置”边界。状态票观察到异常时不得切换 normal 修复口径，必须等待独立事故票。
- 运行期不得手工创建新的 `chat_heartbeat*.jsonl`、`handled_tickets/*.md` 等临时回执产物；应仅使用现有脚本输出的 ledger/heartbeat。
- 运行期不得在未获用户明确同意时创建非 `tmp/` 新脚本，也不得偏题提出 PR、服务化改造或其他超出当前票据闭环的实施方案。
- 任务定义 JSON 的语义修改必须使用 VS Code `apply_patch` 编辑工具。禁止通过终端内联 Python、PowerShell 多层命令、here-string、重定向、通用字符串替换或格式化器修改任务定义；格式化器只允许做不改变 JSON 值、数组顺序和 operation 结构的机械格式化。编辑后固定按“SyntaxOnly 装载检查 -> 故障目标 op 快检（可定位时）-> 当前故障 D 轮递进严格检查”验证。
- 无人值守运行期间禁止执行提交与推送操作（如 `git commit` / `git push`）；仅在用户明确同轮授权后，才可进入版本控制提交发布步骤。

### 2.7 自愈修复与故障处理原则

- start-file 的 `LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED` 控制脚本故障处置，默认关闭；字段缺失、空值或非法值均按关闭处理。
- 关闭时脚本故障必须路由到 `incident-script-diagnose-only`。AI 只允许读取事故包、日志、start-file、相关脚本和近期相关变更，并使用无副作用的语法解析、静态检查或 dry-run 定位根因；禁止修改文件、创建脚本、停止/重启进程、执行 `business_resume`/`continue_watch_command`、改变环境或实施恢复。
- 排查报告必须在聊天中列出故障现象、首次错误、调用链、根因与证据路径、影响、置信度、最小修改建议、验证命令、风险和回滚方法，并声明未修改文件、未停止或重启进程。随后只执行一次 `atomic_closeout_command`，等待用户决定。
- 仅当该字段显式为 `true` 时，脚本故障才沿用 `incident-auto-resume-script-fix` / `incident-manual-script-fix`。
- 处理代码修复、非代码恢复、事件评审或其他非脚本工单时若新发现 guard/trigger/dispatch/poll 脚本故障，必须立即停止原工单的修复或恢复动作并按上述开关重新分类；不得在原车道内顺手修改脚本。开关显式为 `true` 时转入脚本自愈专用流程，否则转入脚本故障排查专用流程。
- 代码自愈修复不允许直接手改源码；必须修改当前阶段任务定义文件中对应轮次的代码改动内容。
- 修改任务定义文件后，必须先通过 `-SyntaxOnly`，再通过故障目标 op 快检（可定位时）及当前故障 D 轮递进严格检查，才允许重启本阶段主进程；后续轮在实际 code-step 到达时检查。
- 新任务定义默认设置 `qualityPolicy.operationSafetyPolicy=enforce`。每个 op 必须声明由自身 replacement 唯一产生的 `idempotentContains`；replacement 后 pattern 必须收敛为零命中，整轮二次应用不得改变文本。
- 每轮必须用 `postApplyAssertions` 声明生成代码契约，对 helper definition、prototype、真实 call site 及被移除旧形态做精确正则计数。pattern 若替换函数定义，必须消费完整原函数体，禁止遗留孤儿函数体。
- 启动或重启前除静态检测外，运行 `tools/test/task_definition_safety_regression.ps1`，确保 marker 冲突、非收敛替换、孤儿函数体和契约断言失败仍会被硬拒绝。
- 自愈发生在 A 阶段：从 A 阶段开始处重启；A 主进程会自动把源码回滚到项目基线后再执行本轮任务定义。
- 自愈发生在 B 阶段：从 B 阶段开始处重启；B 主进程会自动以 A 结束时的成功快照为基线回滚后再执行本轮任务定义。
- 故障处理优先顺序固定为：留证 -> 修改本阶段任务定义 -> 静态体检 -> 用 stage window 重启本阶段 -> 恢复监控链。

#### 2.7.1 故障发生分布与通用分类原则

无人值守脚本链中的故障先按“发生位置/阶段”定位，再按“根因性质”分类。阶段只说明故障在哪里被发现，不直接决定它是代码、非代码还是脚本故障；分类必须以结构化 exit code、脚本结果行、首个错误、环境门禁、编译/验证输出和 wrapper 调用链共同判定。

脚本故障的强判据只有一个：主脚本或主脚本进程链路中的子脚本在运行中异常中断，且没有可信的结构化退出结果或退出码可归因到业务子流程。PowerShell wrapper 栈帧（例如 `*.ps1:<line>`、`line: <n> char: <n>`）只能作为调用链证据；若同一日志已经包含 `[AB-UNATTENDED-RESULT] ... exit_code=<n>`、`oneclick_end exit_code=<n>` 或其他子流程结构化失败结果，应继承子流程分类，不得仅凭 wrapper 抛错归为脚本故障。

非代码故障贯穿所有阶段，典型原因包括远程锁、网络、SSH/认证、权限、磁盘、工具链缺失、测试基础设施、脚本互斥锁、进程锚点/监控链状态、产物 stale、I/O 和资源限制。非代码故障优先稳定环境或按同阶段恢复；不得编辑源码或任务定义。

代码故障只存在于主要代码相关业务阶段：task-static 发现任务定义与源码形态不匹配，或 compile/verify 阶段的编译、链接、业务逻辑、输出契约、黄金样例、Step47/preclass/矩阵/自测等验证失败。若无环境扰动证据，所有结构化验证失败都应按代码故障进入 code-fix，而不是按具体验证脚本名称特判。

| 位置/阶段 | 可能分类 | 分类要点 | 默认路由 |
|---|---|---|---|
| 入口门禁 / launch-ready / start-file 预检 | 非代码故障 / 脚本故障 | 缺字段、锁、网络、进程冲突、工作区状态等为非代码；预检脚本自身无结构化退出结果异常中断才是脚本故障 | noncode 或 script-diagnose/script-fix |
| D 轮次环境门禁 | 非代码故障 / 脚本故障 | 远程锁、网络、磁盘、进程冲突、工具链和权限为非代码；门禁脚本链异常无退出码才是脚本故障 | noncode 或 script-diagnose/script-fix |
| D 轮次 task-static 阶段 | 代码故障 / 非代码故障 / 脚本故障 | op 匹配、替换、marker、replay、断言失败为任务定义代码故障；checker 互斥锁、timeout、worker/环境资源为非代码；checker 脚本内部契约异常且无结构化结果为脚本故障 | code-fix、noncode 或 script-diagnose/script-fix |
| D 轮次 code-step 阶段 | 非代码故障 / 脚本故障 | code-step 只读取、验证、原子写入和写后验证；绑定产物 stale、I/O、权限、Replace/Move 失败为非代码；脚本状态机或内部契约异常才是脚本故障。code-step 故障不授权编辑源码或任务定义 | noncode 或 script-diagnose/script-fix |
| D 轮次编译阶段 | 代码故障 / 非代码故障 / 脚本故障 | C 编译/链接/类型错误、警告门禁和由生成源码导致的构建失败为代码故障；编译器缺失、远程环境、权限、磁盘、锁和网络为非代码；编译 wrapper 异常无结构化退出码才是脚本故障。编译阶段内部的 hash、产物、编码、包完整性等验证也按同一规则分类 | code-fix、noncode 或 script-diagnose/script-fix |
| D 轮次验证阶段 | 代码故障 / 非代码故障 / 脚本故障 | 业务输出契约、黄金样例、Step47/preclass、CIDR/redirect 矩阵、自测、smoke 等结构化验证失败，无环境扰动时为代码故障；测试基础设施或环境扰动为非代码；验证脚本链异常无退出码才是脚本故障 | code-fix、noncode 或 script-diagnose/script-fix |
| V 轮次编译阶段 | 代码故障 / 非代码故障 / 脚本故障 | 与 D 编译阶段相同；V 轮是验证轮，不是任务定义 JSON 键。代码修复只能按 V 轮边界追加到 D4 末尾 | code-fix、noncode 或 script-diagnose/script-fix |
| V 轮次验证阶段 | 代码故障 / 非代码故障 / 脚本故障 | 与 D 验证阶段相同；所有验证方式都遵循“结构化验证失败优先继承子流程分类”的规则，不能只为 Step47 特判 | code-fix、noncode 或 script-diagnose/script-fix |
| A 成功快照生成阶段 | 非代码故障 / 脚本故障 | 快照目录、摘要、源码状态、hash、复制/写入/I/O 为非代码；快照脚本异常无结构化退出结果为脚本故障；不属于代码修复入口 | noncode 或 script-diagnose/script-fix |
| B 入口 A PASS + A 快照检查阶段 | 非代码故障 / 脚本故障 | A PASS 状态缺失、快照不完整、hash 不一致、回滚失败、I/O/权限为非代码；检查脚本异常无结构化退出结果为脚本故障；不属于代码修复入口 | noncode 或 script-diagnose/script-fix |

分类优先级应固定为：结构化任务定义失败 -> 结构化子流程验证/编译失败 -> 环境/基础设施 marker -> 强脚本故障 marker -> 未知保守分支。wrapper 栈帧只补充 `failure_source` 和调用链，不能覆盖已有结构化失败结果。

### 2.8 临时脚本约束

- 运行中优先使用项目现有脚本。
- 如确需创建临时脚本，只能放在 tmp 目录下。
- 临时脚本用完即删，不得沉淀为新的长期入口。

### 2.9 票据路由预检闸门（强制）

- 每次接管票据前，先执行 route guard 预检脚本：
	- `powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_takeover_route_guard.ps1 -BriefPath <takeover_brief_path> -QueuePath out/artifacts/ab_agent_queue/agent_tickets.jsonl -AsJson`
- 必须按 `route.classification` 进入对应分支，不允许跳步：
  - `status-health-check-only`：仅执行只读状态查询、状态汇报与 handled_at；禁止 self-heal、fault handling、continue_watch、stage/guard restart、business_resume、文件修改和环境恢复。
	- `incident-auto-resume-script-fix` / `incident-manual-script-fix`：脚本自愈专用流程（guard/trigger/dispatch/poll），先报根因与脚本修复路径；manual 分支需先报阻断条件，不得盲目 resume。
  - `incident-script-diagnose-only`：脚本开关关闭时的排查专用流程。只允许只读取证、根因分析、修复方案、聊天汇报和 handled_at；文件修改、进程控制、重启/resume、环境修改与创建脚本均为硬禁止项。
	- `incident-auto-resume-code-fix` / `incident-manual-code-fix`：代码修复专用流程（源码/任务定义/编译校验）；manual 分支先报阻断条件，再决定是否恢复。
	- `incident-auto-resume-noncode` / `incident-manual-noncode`：非代码故障专用流程（环境/监控链/瞬态），优先稳定化，不与代码修复流程混用。
	- `notice-manual-wait` / `notice-budget-exhausted` / `notice-known-infra-transient`：通告类事件专用流程，按事件性质执行对应决策与回执，禁止跨流程盲目恢复。
	- `superseded-status-ticket`：状态票被更新的事故票覆盖，禁止按旧状态票执行恢复动作。
- `takeover` 简报中已提供 `route_guard_command` 与 `route_guard_expected`，应优先使用并校验。
- 对 `incident-*` 且需要 `stage_restart`/`business_resume` 的票据，`brief` 的推荐执行链应固定为：`route_guard_command` -> `tools/test/check_unattended_ab_launch_ready.ps1` -> `tools/test/open_unattended_ab_stage_window.ps1 -Stage A|B -StartMonitors`，先完成 start-file 预检与 `PRECHECK_*` 回填，再执行主进程重启。
- 对涉及 task-definition 自愈修复的 `brief`，必须显式写明：只有在 `tools/test/check_task_definition_static.ps1` 静态检测通过后，才允许执行任何 `stage_restart` 或 `business_resume`；静态检测未通过时禁止重启。
- 对涉及阶段重启的 `brief`，必须显式写明目标主进程：A 阶段故障只能重启 A 主进程，B 阶段故障只能重启 B 主进程；禁止因 brief 模糊、旧 exit 证据或人工猜测而启错阶段主进程，也禁止绕开 stage window 自行挑选其他入口。
- 执行层必须 fail-close，不允许“仅提示不拦截”：
	- `route_guard_command` 为空、执行失败、输出无效、`route.classification` 为空时，必须阻断后续执行。
	- 若 `route_guard_expected` 存在且与 `route.classification` 不一致，必须阻断后续执行。
	- 仅当 route guard 判定通过时，才允许进入后续命令执行。
- 当前仓库的执行层门控落点：
	- `tools/test/run_unattended_status_only_autoflow.ps1`：对 status-only 执行链逐步校验 `route.allowed_actions`。
	- `tools/test/unattended_ab_takeover_trigger.ps1`：在 external trigger 启动前先执行 route guard 校验（普通票据与 final-status 路径均适用）。
- `tools/test/poll_agent_tickets.ps1`：事件驱动票按队列顺序幂等排空，且仅处理“本期执行启动基线之后”的事件票（`created_at >= event_queue_floor_at`）；启动基线之前的历史事件票应自动标记已处理并跳过。
- 事件排空循环规则：先找“本期内最早未处理事件票”，若事件仍存在则处理；若事件不存在则直接回写 `handled_at/done` 后继续下一张；直到本期事件票全部排空。
- 当本期事件票排空后，外部投送链自动回到进入事件处置前的工作模式（`normal/anti-missent/low-disturb/event-only`）；AI 回到静默等待，不自行恢复轮询或监控命令。
- 运行期观测锚点（用于快速确认门控生效）：
	- 放行：`external_trigger_route_allowed` / `final_status_trigger_route_allowed`
	- 阻断：`external_trigger_blocked` / `final_status_trigger_blocked`
	- 后续执行：`external_trigger_started` 或 `external_trigger_failed`

一句话关系：
- 用户负责授权与确认。
- 脚本负责执行与落盘。
- AI 负责整理、辅助、解释和按既有入口驱动脚本。

### 2.10 Code-step 原子写入机制与自愈源码基线保证

本节解释 code-step（`autopilot_code_step_rounds.ps1`）在单轮内执行多个 operations 时的原子写入设计，以及这一设计对故障自愈中静态检查所依赖的源码基线的影响。

#### 2.10.1 整轮内存计算、成功后才统一写盘

独立 checker 与 code-step 处理单轮（D1~D4）时，采用以下流程：

```
独立 checker 读取磁盘源码并生成当前轮有效源码与绑定 manifest
  ├─ 任一 op、replay、postApplyAssertions 或 effective-C gate 失败 → TASK-STATIC-FAIL，不进入 code-step
  └─ 完整安全契约通过 → code-step 校验任务定义、基线源码和有效源码三个 SHA-256 → 原子写入目标文件
```

关键实现分布在 runner、checker 和 `autopilot_code_step_rounds.ps1`：
- runner 在 code-step 前以当前目标源码作为 `-BaselineTargetFile` 调用 `check_task_definition_static.ps1`。
- checker 在同一内存副本上顺序执行当前轮 operations，并统一验证 marker 所有权、pattern 收敛、整轮 replay 与 `postApplyAssertions`。
- checker 仅在完整门禁通过后写出 `-OutputEffectiveTargetFile` 和 `TASK_STATIC_VALIDATED_ARTIFACT_V1` manifest；code-step 不重复运行 checker。
- code-step 写回前验证 manifest 契约与三个 SHA-256；全部一致时才通过同目录临时文件和 Replace/Move 原子写回业务目标文件。
- checker 失败、单实例冲突、正则超时或 worker 超时均为 `task-static / task-definition-mismatch`；绑定产物 stale 或普通 I/O 为 `environment-transient / noncode-transient`；manifest/state/未知内部契约异常为 `script-edit-failure / script-fault`。

该设计的核心语义是**一轮写入视为一个原子事务**：要么本轮全部 op 的改动完整落盘，要么磁盘源码与进入本轮前完全一致。

#### 2.10.2 三种故障场景与静态检查的基线可靠性

| 故障场景 | 磁盘源码是否包含本轮改动 | 静态检查读到的基线 | 自愈操作限制 |
|---|---|---|---|
| **task-static op 匹配/替换/断言失败** | 否。独立 checker 不写业务源码 | 正确基线 = 进入本轮前的磁盘源码 | 从故障 op 起修改/删除/插入/追加；可用 `-OperationIndex <n>` 聚焦检查 |
| **code-step 全部通过，但随后的 compile/verify 失败** | 是。全部 op 已完整写入 | 已包含本轮全部 op 后的源码 | 该轮既有 op 全部只读，只能在该轮 `operations` 末尾连续追加新 op 补丁 |
| **绑定产物 stale 或 code-step I/O 异常** | 原子提交前失败时不含本轮改动 | 与 manifest 绑定摘要不一致或提交失败 | 进入非代码故障流程；重新稳定环境并重跑独立 checker，不修改任务定义 |
| **manifest/state/未知内部契约异常** | fail-close，不授权继续应用 | 产物链或脚本状态不可证明 | 进入脚本故障流程；自愈开关关闭时只读诊断并交人工 |

对于任务定义自愈的触发场景，失败发生在独立 `task-static` 阶段，磁盘源码未被当前轮污染，静态检查读取的基线完整且可重现。code-step 失败本身不授权修改任务定义。

#### 2.10.3 前置 op 的模拟机制

使用 `-RoundTag <Dn> -OperationIndex <n>` 聚焦检查故障 op 时，checker 会从磁盘读取目标文件，然后在内存中依次模拟该轮前 `n-1` 个 op（`isPrerequisiteSimulation = true`），只把第 `n` 个 op 作为实际检查目标。

相关逻辑在 `check_task_definition_static.ps1` 中：
```powershell
$isPrerequisiteSimulation = ($RequestedOperationIndex -gt 0 -and $operationOrdinal -lt $RequestedOperationIndex)
```

前置 op 模拟成功时才认为检查前提成立；若前置 op 模拟失败（如 pattern 不再唯一匹配），checker 会报告 `prerequisite simulation failed`，提示前置 op 的条件可能已因源码（轮次外）改动而失效。

这一设计确保 AI 修复第 `n` 个 op 时，可以放心调整目标 pattern 和 replacement，而不必担心前置 op 在复盘中重复应用或干扰结果。

#### 2.10.4 Forward declaration 必须由任务定义表达

code-step 写回路径不再执行 checker 之后的 forward declaration 自动注入。helper definition、首次 caller 前唯一 prototype、真实 call site 及重复 prototype 清理必须由当前轮 operations 和 `postApplyAssertions` 完整表达，并在 checker 生成有效源码前通过验证。禁止在 checker 通过后再用运行时副作用修改源码，否则会破坏任务定义与实际写回文本的一致性。

#### 2.10.5 对自愈修复操作的建议

1. **先定位故障阶段**：通过事故票中的 `failure_phase`、`failure_kind`、`failure_category` 和 `round_tag` 区分 task-static、code-step、compile/verify。
2. **task-static 阶段故障**：磁盘源码是干净的轮次基线。修改任务定义后，可先用 `-OperationIndex <n>` 聚焦检查故障 op，但重启前仍须运行不带 `-OperationIndex` 的当前轮递进严格检查。
3. **compile/verify 阶段故障**：磁盘源码已包含本轮全部 op。只能在该轮 `operations` 末尾追加补丁 op，不得修改或删除既有 op。
4. **code-step stale/I/O 故障**：进入非代码恢复，不修改任务定义；重新生成绑定产物前必须确认阶段业务进程已停且基线正确。
5. **code-step manifest/state/内部契约故障**：进入脚本修复或只读诊断流程；未知故障 fail-close，不得回落到代码自愈。
6. **修改完成后**：任何任务定义修改均需 `check_task_definition_static.ps1 -Policy enforce` 通过，才允许执行 `stage_restart` 或 `business_resume`。
7. **重启时**：A 阶段重启恢复项目基线，B 阶段重启恢复 A 成功快照。独立 checker 从磁盘基线重新生成绑定产物；前置轮次成功后已落盘的内容在重启后不会丢失。
8. **诊断先下钻首错**：外层 wrapper、PowerShell 调用栈和最终聚合失败只用于定位调用链；存在结构化子结果时，以最内层首个 compiler/test 错误、exit code、checker 有效源码与 manifest 为准。不得根据“任务定义未提交或未推送”直接推断远端看不到修改；先检查实际传输脚本和本轮 upload、`VERSION.txt`、哈希与严格日志。本仓库 `tools/remote/remote_build_and_test.sh` 上传当前本地工作树。
9. **工具参数污染 fail-close**：若工具回显中出现请求之外的词元、路径被插字、命令或 `apply_patch` 上下文畸变，先归类为工具调用参数污染，不得把该错误当作源码、脚本或任务定义故障。停止复杂重试，改用最小精确调用或结构化文件接口；重新读取权威文件并确认是否发生写入。任务定义可能被修改时，先隔离候选并运行 `SyntaxOnly`；机器事实不明确时禁止提升、重启或 resume。

#### 2.10.6 任务定义修复候选事务

任务定义自愈不再直接把正式 `testdata/*.json` 当作编辑工作区。使用 `tools/test/task_definition_repair_transaction.ps1` 建立哈希绑定事务：

```powershell
# 1. 准备候选；正式文件保持不变
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/task_definition_repair_transaction.ps1 -Mode Prepare -TaskDefinitionFile <TASK.json> -TicketId <TICKET> -Stage A -RoundTag D3 -OperationIndex 8

# 2. 只用 VS Code apply_patch 修改输出目录中的 candidate.json

# 2.1 可选：修改后只读刷新源码匹配、替换结果与 JSON 邻接上下文
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/task_definition_repair_transaction.ps1 -Mode Inspect -TaskDefinitionFile <TASK.json> -TicketId <TICKET> -Stage A -RoundTag D3 -OperationIndex 8

# 3. 绑定正式基线哈希，并依次执行 SyntaxOnly、目标 op 和当前轮检查
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/task_definition_repair_transaction.ps1 -Mode Validate -TaskDefinitionFile <TASK.json> -TicketId <TICKET> -Stage A -RoundTag D3 -OperationIndex 8

# 4. 验证通过后原子提升；重新校验正式/候选哈希并执行写后 SyntaxOnly
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/task_definition_repair_transaction.ps1 -Mode Promote -TaskDefinitionFile <TASK.json> -TicketId <TICKET> -Stage A -RoundTag D3 -OperationIndex 8
```

事务目录默认位于 `out/artifacts/task_definition_repair/<ticket-id>/`：

- `baseline.json`：准备时的正式文件字节基线。
- `candidate.json`：唯一允许代理修改的候选文件。
- `manifest.json`：正式路径、stage/round/op 边界、基线及候选 SHA-256、事务状态和验证日志。
- `operation-preview.json`：绑定 baseline、candidate 与目标源码 SHA-256 的机器可读预览，包含前置 op 只读模拟、目标 pattern 命中位置和替换后剩余命中数。
- `operation-preview.txt`：pattern/replacement 解码视图、控制字符可视化、双重转义风险与局部源码预览。
- `apply-patch-context.txt`：目标 operation 的 JSON Path 及前一项/当前项/后一项只读上下文；仅用于辅助定位，仍只能用 VS Code `apply_patch` 修改 `candidate.json`。
- `promotion-receipt.json`：原子提升成功后的正式文件哈希与写后检查收据。

生命周期规则：

- task-static 修复的完成事实只能由同票据事务证明：`manifest.state=promoted`，非空的 `validated_candidate_sha256` 与 `promoted_sha256` 相等，正式任务定义 SHA-256 与 promoted hash 相等，`promotion-receipt.json` 存在且 `success=true`、ticket/hash 匹配，并且正式文件再次通过当前故障轮不带 `-OperationIndex` 的严格检查。局部 checker/Inspect PASS、candidate 已编辑、preview 已刷新或聊天中声称“已修复”均不是完成证据。
- 上述门禁全部满足前不得执行 `recovery_transaction_command`、`stage_restart`、`business_resume` 或成功 handled 收尾。`prepared`、`validation_failed`、`promotion_failed`、`quarantined`、`abandoned`、receipt 缺失或哈希不一致必须 fail-close；可继续修复的非终态事务继续修改 candidate，终态事务重新 Prepare 新 ticket/事务，无法继续时只报告阻塞。
- 提升、写后哈希、写后 `SyntaxOnly` 和 receipt 全部成功后，删除 `candidate.json` 与 `baseline.json`，保留 manifest、验证日志和 promotion receipt。
- 验证失败、正式基线漂移、候选验证后漂移或提升失败时，正式文件保持或恢复原状，候选现场保留。
- `Prepare` 自动生成首份预览；候选修改后可重复执行 `Inspect` 刷新。`Validate` 对比当前 candidate SHA-256 与预览绑定并输出 `preview_stale=true|false`；预览陈旧是显式诊断状态，不替代 SyntaxOnly、目标 op 和当前轮严格检查。
- `Inspect` 只读取 candidate 与目标源码并更新事务目录中的预览 sidecar/manifest，不修改 candidate、正式任务定义或业务源码；正式基线漂移时 fail-close。
- 诊断 pattern/replacement 时必须区分三层文本：JSON 源码、`ConvertFrom-Json` 解码后的 PowerShell 字符串、`.NET Regex` 接收的 pattern。checker 没有自制 JSON 解码器；例如合法 JSON `"\\)"` 解码为正则 `\)`，用于匹配字面量 `)`。`pattern_unmatched=0` 表示 JSON 已加载且正则已编译、但对当前顺序内存文本零命中，不得归因为 JSON 解码失败；JSON 解析失败或正则非法会走更早的独立错误分支。应以 `operation-preview.txt` 的 `[PATTERN DECODED]`、源码匹配和 checker 首错定位实际的转义、源码形态或幂等状态问题，禁止为此修改 checker 的 JSON 处理。
- 会话放弃时执行 `-Mode Abandon -Reason <reason>`；工具参数污染时执行 `-Mode Quarantine -Reason tool-call-parameter-corruption`。两者均禁止后续提升。
- 候选清理失败只输出 `cleanup_warning=true`，不得回滚已经验证成功的正式提升。
- `tools/dev/prune_artifacts_all.ps1` 保留最近 20 个事务目录，统一清理更早的成功或失败现场。

## 3. 涉及的软件与脚本

### 3.1 必备软件

- PowerShell 5.1 或兼容环境
- Git
- SSH 可用（远端构建场景）
- VS Code（推荐，用于查看文档、任务和日志）

### 3.2 关键文件与脚本

任务定义：
- testdata/autopilot_code_step_tasks_template.json
- testdata/autopilot_code_step_tasks_*.json

启动模板与启动文件：
- docs/UNATTENDED_AB_START_TEMPLATE_CN.md
- testdata/unattended_start/active/*.md
- testdata/unattended_start/smoke/*.md

生成/重置/校验：
- tools/test/create_unattended_ab_start_file.ps1
- tools/test/reset_unattended_ab_start_file.ps1
- tools/test/check_task_definition_static.ps1
- tools/test/check_unattended_start_field_sync.ps1
- tools/test/check_unattended_ab_launch_ready.ps1

任务定义修复事务：
- tools/test/task_definition_repair_transaction.ps1（`Prepare -> Inspect（推荐只读刷新）-> Validate -> Promote`，另支持 `Abandon` / `Quarantine`）
- `Prepare` / `Inspect` 生成的 `operation-preview.json`、`operation-preview.txt` 与 `apply-patch-context.txt` 是事务产物，不是独立脚本；只允许修改同一事务目录中的 `candidate.json`。

操作入口（人工/AI 使用）：
- tools/test/open_unattended_ab_stage_window.ps1

共享写盘核心（维护约束）：
- tools/test/unattended_startfile_identity.ps1
- start-file 的 key=value 更新逻辑以 `Invoke-KeyValueFileValueUpdateCore` 为唯一实现入口。
- stage/resume/guard 仅允许通过参数差异表达策略（如 Copy/Move、重试次数、RequireExistingFile），不再在各脚本内复制独立实现。
- fastmode（A/B）属于同一活跃路径，新增/调整 start-file 写回时同样优先复用共享核心，不再新增本地同类实现。
- 如需调整写盘行为，先改共享核心并做全链路回归；禁止在 stage/resume/guard 内重新引入同名本地写盘函数。
- trigger 可做非 mutex 区域重构；但其内部与特殊 mutex 相关的代码（含单实例锁与触发器内部互斥策略）视为受保护区，重构默认不改动该区块。
- `tools/test/check_unattended_write_core_guard.ps1` 现支持 `-Scope active|expanded`：默认 `active`（仅活跃路径 + trigger 非 mutex 受保护检查）；需要覆盖辅助脚本时显式使用 `-Scope expanded`。

运行中监控/接管：
- tools/test/poll_agent_tickets.ps1
- tools/test/check_unattended_routine_status.ps1
- tools/test/update_chat_session_heartbeat.ps1
- tools/test/watch_ab_light.ps1

票据生成/接管投送：
- tools/test/unattended_ab_takeover_trigger.ps1（生成 takeover brief、路由范围与工单执行提示）
- tools/test/dispatch_takeover_to_chat.ps1（组装并投送中英文 Agent 提示及事务安全 suffix）

关键契约回归：
- tools/test/task_definition_repair_transaction_regression.ps1（事务、哈希漂移、Inspect/preview 与转义风险回归）
- tools/test/status_ticket_mini_regression.ps1（状态票、brief、dispatch 及多层任务定义安全口径一致性回归）

### 3.3 长跑脚本的运行位置

默认建议：
- 正常运行时，A/B 主进程一律通过 `open_unattended_ab_stage_window.ps1` 在 VS Code 外部 PowerShell 窗口中拉起。
- 标准优先方式是由 stage window 带上 `-StartMonitors`，让包装器在外部窗口里拉起监控链。

主运行：
- tools/test/open_unattended_ab_stage_window.ps1

2 个监控链脚本：
- tools/test/open_unattended_ab_session_guard_window.ps1（已合并 supervisor/companion 功能）
- tools/test/open_unattended_ab_takeover_trigger_window.ps1

不推荐：
- 把以上长跑脚本直接放在 VS Code 集成终端里长期运行

集成终端用途：
- 仅用于调试、只读检查、临时校验和短命令试跑
- 如需触发 `tools/test/open_unattended_ab_stage_window.ps1 ... -StartMonitors`，可以从集成终端发起，但被拉起的主进程和监控链必须落在外部 PowerShell 窗口运行
- 不作为标准无人值守长跑承载环境

### 3.4 主进程与监控链生命周期契约

本节定义 A/B 主进程与监控链进程（`guard` / `trigger`）的启动、复用、健康检查和退出行为。目标是避免重复实例、空壳 PowerShell、监控断链，且保证主进程退出事件在监控链仍在线时送达 AI 代理。

#### 3.4.1 A/B 主进程单实例与清理边界

- A/B 的唯一人工/AI 启动入口仍是 `tools/test/open_unattended_ab_stage_window.ps1 -Stage A|B -StartMonitors`；`start_dev_verify_fastmode_A.ps1` 与 `start_dev_verify_fastmode_B.ps1` 仅由该入口拉起。
- A 与 B 共享仓库级主运行互斥锁。同一时刻只能有一个真实 A/B 主运行链持有该锁；已持锁的主进程存在时，后续 A 或 B 启动必须快速失败，不能通过杀掉对方或同阶段活进程来“让路”。
- stage window 不得按命令行文本无条件结束同阶段 entry 脚本。主进程空壳/僵尸的清理由已获取主互斥锁的 fastmode 执行：仅清理不再持有执行锁、但仍残留的同阶段进程。
- 启动 A 只处理 A 的残留主进程；启动 B 只处理 B 的残留主进程。主进程启动或重启过程中不得主动杀掉仍在运行的 `guard` / `trigger`。

#### 3.4.2 D1 前的阻塞式监控链引导

- stage window 拉起主进程后，应逐次检查并拉起所需监控链：`guard` 必需；当 `AUTO_START_TAKEOVER_TRIGGER=true` 时，`trigger` 也必需。
- 监控 bootstrap gate 在 D1/round loop 之前生效。主进程必须等待 gate 发布 `ready` 或 `degraded` 状态后，才可进入 D1。
- 在配置的 bootstrap 时限内，入口应持续尝试修复缺失或空壳 monitor；若最终仍无法达到完整在线，必须把 `MONITOR_CHAIN_DEGRADED=true`、缺失角色及原因写回 start-file，再以 `degraded` 状态放行主进程。不得无限等待，也不得伪造“监控已就绪”。

#### 3.4.3 guard/trigger 的单实例、真实性判定与复用

- `open_unattended_ab_session_guard_window.ps1` 与 `open_unattended_ab_takeover_trigger_window.ps1` 均以 start-file 路径为作用域使用启动互斥锁；不同 start-file 的实例不能互相误判为同一实例。
- 启动器发现同一 start-file 的旧实例时，必须先做真实性判定：进程存在还不够，还要结合状态文件、终态标记、状态文件更新时间和新进程暖机窗口判断其是否仍在执行脚本。
- 真实在线的旧实例应复用，而不是停掉再拉起；启动器应刷新可用锚点，使其在下一轮轮询绑定当前主进程。
- 已终止脚本但仍保留 `-NoExit` shell 的空壳、状态终止或已过期实例，必须先清理，再正常启动新的角色实例。`-NoRestartIfRunning` 只避免对真实实例造成 stop/start 抖动，不能绕过空壳判断。

#### 3.4.4 运行期锚定与主进程切换

- `guard` 每个轮询周期都从 start-file 读取 `A_LAUNCH_PID` / `B_LAUNCH_PID` 及阶段状态，并验证 PID 的真实存活。
- 当 A 重启、A PASS 后切换到 B、B 重启或 PID 发生变化时，guard 必须更新锚点并继续绑定新的主进程；旧 PID 消失本身不能立即被视为最终失败。
- trigger 通过同一 start-file 作用域运行，并持续读取会话状态和票据队列；A->B 交接、主进程 PID 更新或运行目录锚点更新不得导致它被误判为过期实例。
- B 由 guard 派生启动时，stage window 可将同一 start-file 的 guard 父进程视为连续性证据，避免仅因子窗口命令行探测短暂缺失而重复拉起 guard。

#### 3.4.5 监控链健康检查与自动恢复

- guard 在运行期约每五分钟对 trigger 做真实性健康检查。trigger 缺失、终态或空壳时，guard 应通过既有 trigger launcher 自动恢复；真实在线的 trigger 必须复用。
- 主进程的 multiround 在代码步骤后和每个轮次转换之间检查 `guard` / `trigger`。发现缺失或空壳时应请求或执行既有 launcher 恢复，再继续下一轮；不得把“PowerShell PID 存在”当作唯一健康依据。
- 触发器恢复必须保留 start-file 作用域、既有 route guard 和票据闭环语义；健康检查不得为了恢复 trigger 而清空队列、删除未处理票据或覆盖其他会话锚点。

#### 3.4.6 主进程退出前的监控保障

- A/B fastmode 在写 `latest_a_exit.json` / `latest_b_exit.json` 等阶段退出证据前，必须阻塞式确认 `guard` / `trigger` 真实在线。
- 若发现角色缺失或空壳，退出路径应调用既有健康恢复 launcher，并在有限时限内轮询等待其真实在线；超时必须记录 `monitor_chain_timeout` 类诊断，但不得静默跳过检查。
- 该检查的目的不是延长主任务，而是确保 guard/trigger 能观察并投递主进程的 PASS、FAIL、exit artifact、incident 或最终状态事件。

#### 3.4.7 主进程故障退出后的温窗期与宽限期

- guard 发现 A/B 主进程 PID 消失时，先进入温窗期（主进程缺失观察窗口）：默认 180 秒，由 `LOCAL_GUARD_A_RUNNING_NO_PROCESS_GRACE_SEC` / `LOCAL_GUARD_B_RUNNING_NO_PROCESS_GRACE_SEC` 控制。温窗期用于确认 PID 缺失不是瞬时切换，并收集 exit artifact、运行日志和状态文件证据；不得以一次轮询的 PID 缺失立即将会话判死。
- 温窗期结束且仍确认主进程故障退出后，guard 写入 FAIL 与故障证据，并按既定策略生成完整事件票；随后才进入宽限期（默认 60 分钟，由 `MONITOR_CHAIN_GRACE_MINUTES` 或 `LOCAL_GUARD_MAIN_EXIT_MONITOR_GRACE_MINUTES` 控制），保持监控链在线以等待恢复、重锚定和票据闭环。60 分钟默认值用于覆盖中阶/低阶模型处理高密度任务定义及开启跨轮次修复后的串行检查时间；显式配置仍可在允许范围内覆盖。
- 温窗期或宽限期内若 start-file 出现新的有效 A/B PID，guard/trigger 必须自动重锚定、清除对应窗口状态并恢复正常监控。
- 对应 A/B 阶段或 SESSION 已确认 PASS 时不得为该范围新建温窗或宽限期；若此前对应窗口仍存在，guard/trigger 必须立即清除其 started-at、stage、detail 与 last-notice 状态，且 PASS 清窗不得再次开启 startup warmup。SESSION 全 PASS 的正常收尾只走最终状态通知与关闭门禁，不得进入 trigger 的 terminal fallback grace。
- guard helper 在只读检查或状态刷新时必须原样保留已有宽限期的 started-at、stage、detail 与 last-notice；禁止只保留 started-at 而清空其余元数据。此类半状态无法按 stage 在主进程恢复时清除，并会在后续无进程故障分支中被误判为早已过期。
- guard 内部的 60 分钟恢复宽限统一由一个 recovery-grace 状态管理，`kind`、`scope`、`reason`、`source`、`expiry_action`、`detail`、`started_at`、`last_notice_at` 与 `generation` 必须原子创建、更新和清除。旧的两族状态变量及兼容投影已删除；`main_process_exit_grace_*` / `monitor_chain_grace_*` 仅作为日志标签保留，计时、判断、清除与到期分派必须直接读取 canonical recovery-grace 状态。
- recovery-grace 的 SESSION scope 优先于 A/B scope：SESSION grace 可以替换阶段 grace，活动中的 SESSION grace 不得被阶段 rebind 覆盖。`known-infra-transient-stop`、`budget-exhausted-stop` 与 `final-state-no-followup` 到期执行 monitor-chain shutdown；`a-fail-incident-ticket` 到期只记录并清窗；A/B main-exit 与 `b-recoverable-ticket` 到期执行 main-exit shutdown。
- 本节合并范围仅限 guard 内部两套 60 分钟状态。A/B PID 缺失的 180 秒 warm window 继续独立工作；trigger 的跨进程 terminal fallback 仍是 guard 缺失时的跟随/兜底机制，不与 guard 内存状态共享所有权。
- A 或 B 因 `task-definition-mismatch` 结束时，应统一生成可自动接管的 code-fix 事件：自动修复对应阶段的任务定义、通过静态体检后按标准 Stage A/B 入口恢复。guard 不得在修复落地前盲目重启失败阶段，也不得为任一阶段另设人工等待或专属常驻流程；只有自动修复配额或相同故障指纹配额耗尽时，才转人工处置。
- 若宽限期届满仍没有新的有效主进程，guard 应写入结束/故障证据，并请求监控链有序关闭；trigger 必须先完成已生成关键票据与最终状态的投递门禁。
- 对未关闭的恢复票据，trigger 不得因会话表面终态而提前停止；应延后自动停止，直到票据闭环或按策略完成宽限期处置。

#### 3.4.8 观测与排障要求

- 启动期关注：`monitor_chain_probe_*`、`monitor_bootstrap_gate_*`、`monitor_parent_reuse`、`monitor_restart_single`。
- 运行期关注：`trigger_health_check_run`、`monitor_health_check_error`、`restart` / `zombie-detected` / `zombie-killed`、`a_anchor_refresh` / `b_anchor_refresh`。
- 退出期关注：`monitor_chain_ready`、`monitor_chain_recovery`、`monitor_chain_timeout`、`main_process_exit_grace`、`monitor_chain_grace_*`、`auto_stop_deferred`。
- 出现监控链问题时，先区分“真实进程在线但锚点待刷新”“进程空壳”“实例缺失”“主进程故障宽限中”四种状态；不得仅根据一个旧 PID、旧日志或旧 exit artifact 直接重启 A/B。

#### 3.4.9 配置键与状态字段兼容契约

- guard 读取配置时采用“新键优先、旧键后备”：
  - 最大恢复次数：`LOCAL_GUARD_MAX_RECOVERY_ATTEMPTS` 优先，`LOCAL_GUARD_MAX_B_RECOVERY_ATTEMPTS` 后备。
  - 自动恢复开关：`LOCAL_GUARD_AUTO_RECOVER` 优先，`LOCAL_GUARD_AUTO_RECOVER_B` 后备。
- `guard_state.json` 与运行期状态写回采用通用键 + 兼容键双写，保持脚本升级平滑：
  - 最大恢复次数：`max_recovery_attempts` + `max_b_recovery_attempts`
  - 自动恢复：`auto_recover` + `auto_recover_b`
  - 当前恢复计数：`recovery_attempts` + `b_recovery_attempts`
  - 最近恢复时间：`recovery_last_at` + `last_recovery_at`
- 兼容键在迁移窗口内不得移除；任何消费方（监控、接管、报表）应优先读取通用键，旧键仅作为后备。

## 4. 全流程总览

### 4.1 阶段 0：确定本轮目标

先回答以下问题：
- 本轮窗口是什么，例如 `2026-10-31 ~ 2026-11-15`
- A 对应哪一份任务定义文件
- B 对应哪一份任务定义文件
- 本轮是否继续沿用 `foreground-visible + single-param-fastmode`
- 本轮是否需要 `event-only` 或 `low-disturb`
- 本轮是否需要外部 NoExit 窗口

若这些问题还没定，不要直接启动 A/B。

### 4.2 阶段 1：从模板生成任务定义文件

目标：先把“做什么”写清楚，再进入启动阶段。

最简示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command '$dst = "testdata/autopilot_code_step_tasks_local.json"; Copy-Item -LiteralPath "testdata/autopilot_code_step_tasks_template.json" -Destination $dst -Force; $text = [System.IO.File]::ReadAllText($dst); $text = ($text -replace "`r`n", "`n") -replace "`r", "`n"; [System.IO.File]::WriteAllText($dst, $text, (New-Object System.Text.UTF8Encoding $true)); Write-Output ("[TASK-TEMPLATE] created=" + $dst + " encoding=utf8-bom eol=lf")'
```

按窗口生成示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command '$window = "20261031_20261107"; $dst = ("testdata/autopilot_code_step_tasks_{0}.json" -f $window); Copy-Item -LiteralPath "testdata/autopilot_code_step_tasks_template.json" -Destination $dst -Force; $text = [System.IO.File]::ReadAllText($dst); $text = ($text -replace "`r`n", "`n") -replace "`r", "`n"; [System.IO.File]::WriteAllText($dst, $text, (New-Object System.Text.UTF8Encoding $true)); Write-Output ("[TASK-TEMPLATE] created=" + $dst + " encoding=utf8-bom eol=lf")'
```

完成后必须做的事：
- 填写 D1~D4 任务内容
- 去掉所有 TODO 占位
- 保证描述与当前轮目标一致

#### 4.2.1 任务定义填写规范

任务定义不是普通的文本替换清单，而是可顺序重放、可静态证明、可在失败后精确续修的源码变更计划。编制时应先确定每轮的行为目标和验收条件，再填写 regex；禁止先凑 op 数量，再为已有 replacement 寻找理由。

##### 顶层字段

从 `testdata/autopilot_code_step_tasks_template.json` 复制后，按以下规则填写：

- `schemaVersion`：保留模板当前版本，不自行发明新版本值。
- `name`：使用可区分阶段、窗口或清单的稳定名称，不写 `TODO`、`test` 等无法追溯的临时名称。
- `targetFile`：填写仓库相对路径。单文件 schema 下所有 D 轮只能修改该目标文件；不要在 replacement 中顺带修改其他文件。
- `qualityPolicy.operationSafetyPolicy`：新任务固定为 `enforce`，不得为绕过检查改成 `warn` 或 `off`。
- `qualityPolicy.notes`：说明本任务的安全边界或特殊 no-op 约束，不用于替代轮次验收条件。
- `executionHints`：只描述执行密度和策略，不定义业务语义。`minOperationsPerDRound` 应服从真实改动量，禁止为了达到数字而拆分原子改动或增加无调用 helper。
- `rounds`：仅使用 `D1`、`D2`、`D3`、`D4`。`V1`~`V4` 是验证阶段，不是 JSON 轮次键。

##### D1-D4 轮次拆分

每个 D 轮应形成一个可独立解释和验证的增量：

- `description` 写清“改什么、为什么、保持什么不变”，不要只写“refactor”或“cleanup”。
- 同一轮中的 `operations` 按依赖顺序排列；op2 可以依赖 op1 的 replacement，checker 和执行器都会使用顺序内存文本。
- helper 的定义、所需 prototype、真实调用点替换和旧形态清理应放在同轮，或者确保前一轮结束时源码已经可独立编译。不得把“新增未调用 helper”留给不确定的后续轮补齐。
- 不同业务 token 不得因文本相似而合并。例如 action、reason、class、confidence 各自属于不同语义域，replacement 必须逐 token 保持原行为。
- 一项不可分割的变更尽量由一个 op 完成。尤其是“删除旧 prototype + 在首次 caller 前插入唯一 prototype”应作为原子归一化操作。
- 若在任务编制阶段已确定某轮不需要任何代码改动，该轮必须显式定义为 `"type": "noop"`，只保留清楚说明原因的 `description`；不得填写 `operations`、`idempotentContains` 或 `postApplyAssertions`，不得保留 TODO regex，也不得用 pattern 与 replacement 相同的自替换 operation 或其他无意义替换伪装 no-op、满足密度提示或绕过门禁。
- `type=noop` 只表示该轮从设计上没有代码变更目标。若该轮原本有真实变更目标，只是在执行或自愈时发现目标已由前置轮吸收、源码已具备 replacement 结果或 pattern 因基线变化而不再命中，仍应保持 `type=regex-patch`，通过每个 op 自有的 `idempotentContains` 证明 `absorbed-by-prior-round` / `idempotent-replay`，并完成整轮 replay 与断言检查；不得事后改成 `noop` 掩盖 task-definition mismatch。

设计时空轮示例：

```json
"D3": {
  "type": "noop",
  "description": "No code change is required in D3"
}
```

##### 单个 operation 的编写

每个 `operations[]` 至少包含 `pattern`、`replacement`、`idempotentContains`，并同时满足以下条件：

1. `pattern` 在该 op 的有效输入文本中恰好命中一次。锚点应包含足够的函数名、邻接语句或结构上下文，避免只匹配常见字面量。
2. `replacement` 必须是完整、可落地的最终文本。JSON 中使用正常转义，不得把应当成为换行或 tab 的内容写成二次转义字面量。
3. replacement 应使本 op 的 pattern 收敛为零命中。若属于“在旧锚点前插入新代码”，应使用 negative lookahead 或同时消费/改写旧锚点，不能只依赖 marker 掩盖仍可重复命中的 pattern。
4. `idempotentContains` 中每个 marker 必须由本 op 自己的 replacement 产生，并能唯一证明该 op 已应用。不同 op 不得复用同一 marker；不要使用原源码中早已存在的通用片段。
5. marker 应尽量选择完整函数签名、完整调用语句或该 op 独有的稳定文本，不要选择单个函数名、`return 1;` 等可能碰撞的短片段。
6. 若 replacement 重写函数定义，pattern 必须消费原函数的完整签名和函数体。只匹配签名却 replacement 一个完整函数会留下孤儿函数体，属于硬失败。
7. 新增 helper 时必须同时确认：恰好一个 definition；若首次 caller 位于 definition 前，则恰好一个 prototype 且在 caller 前；至少一个真实 call site；没有遗留重复 prototype 或未使用 helper。

推荐的单 op 结构：

```json
{
  "pattern": "old_call\\(value, \"OLD_TOKEN\"\\);",
  "replacement": "old_call(value, wc_example_token_literal());",
  "idempotentContains": [
    "old_call(value, wc_example_token_literal())"
  ]
}
```

上例只展示字段关系。实际 pattern 必须根据目标源码增加足够上下文，并验证 replacement 前唯一命中、replacement 后零命中。

##### postApplyAssertions 编写

每个 regex-patch 轮次都必须填写 `postApplyAssertions`，用生成后的整轮文本证明结构和语义结果。每项包含：

- `name`：稳定、可读的英文契约名，诊断时可直接定位意图。
- `pattern`：对整轮首次应用后的文本执行的正则。
- `expectedCount`：非负精确计数，不使用“至少一次”一类模糊条件。

断言至少覆盖本轮涉及的以下项目：

- 新 helper definition 数量为 `1`。
- 所需 prototype 数量为 `1`，或无需 prototype 时为 `0`。
- 真实 call site 数量符合预期，通常至少为 `1`。
- 被替换的旧调用、旧 token 或重复声明数量为 `0`。
- 对输出契约、Step47 或分类 token 有影响时，关键保留形态数量符合原设计。

示例：

```json
"postApplyAssertions": [
  {
    "name": "example-helper-definition",
    "pattern": "static const char\\* wc_example_token_literal\\(void\\)\\r?\\n\\{",
    "expectedCount": 1
  },
  {
    "name": "example-helper-call",
    "pattern": "old_call\\(value, wc_example_token_literal\\(\\)\\);",
    "expectedCount": 1
  },
  {
    "name": "legacy-token-call-removed",
    "pattern": "old_call\\(value, \"OLD_TOKEN\"\\);",
    "expectedCount": 0
  }
]
```

##### 编制顺序

建议按以下顺序完成一份新任务定义：

1. 阅读目标源码、相关 RFC、输出契约和邻近测试，写出 D1-D4 每轮行为目标。
2. 为每轮先写 `description` 和 `postApplyAssertions`，明确生成代码应满足的结构，再设计 operations。
3. 按实际依赖顺序填写每个 op 的 `pattern`、`replacement` 和独立 marker。
4. 人工复核 token 语义、完整函数体消费、helper definition/prototype/call site 和跨轮可编译性。
5. 删除全部 TODO，解析 JSON，并运行专项安全回归。
6. 对完整任务定义运行全轮静态检查；仅在自愈定位故障 op 时使用 `-RoundTag <Dn> -OperationIndex <n>`。
7. 对生成源码运行适用的编译、语法检查或窄测试。静态 checker 通过只证明变换安全条件，不替代 C 编译和业务验证。

编制完成后的最小命令集：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/task_definition_safety_regression.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/<TASK_DEFINITION>.json -Policy enforce -FailOnWarnings
```

##### 禁止事项

- 禁止使用 round-level marker 代替 op-level marker；执行器按 op 顺序判断幂等。
- 禁止多个 op 共享同一 marker，或让 marker 由其他 op 的 replacement 产生。
- 禁止 replacement 后 pattern 仍可命中，并把这种状态解释为“反正 marker 会跳过”。
- 禁止只替换函数签名却在 replacement 中写入完整函数体。
- 禁止新增没有真实调用点的 helper，或留下 caller 后 prototype、重复 prototype。
- 禁止为了满足 `minOperationsPerDRound`、高密度描述或清单字数而引入无语义价值的转换。
- 禁止通过降低 `operationSafetyPolicy`、跳过 `postApplyAssertions` 或忽略 checker 失败来推进启动。
- 禁止把静态检查通过等同于业务语义正确；仍须执行对应编译、黄金样例、Step47 或模块自测。

### 4.3 阶段 2：静态体检任务定义文件

目的：在启动前发现任务定义错误，而不是运行到中途才失败。

参数速览（`tools/test/check_task_definition_static.ps1`）：
- `-TaskDefinitionFile <path>`：必填，任务定义 JSON 文件。
- `-PrerequisiteTaskDefinitionFiles <path[]>`：可选，按传入顺序在内存中完整检查并应用前置任务定义，再以结果作为当前任务定义基线；未传时直接使用当前源码。
- `-RepoRoot <path>`：可选，仓库根目录（默认自动解析到当前仓库）。
- `-Policy off|warn|enforce`：可选，默认 `enforce`；`off` 直接跳过。
- `-FailOnWarnings`：可选，开启后 warning 也会按失败返回（建议无人值守门禁开启）。
- `-RoundTag D1..D4|V1..V4`：可选，只检查指定轮次。
- `-OperationIndex <n>`：可选，只检查指定轮次中的第 n 个 operation；必须与 `-RoundTag` 一起使用。

示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261031_20261107.json -Policy enforce -FailOnWarnings
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261108_20261115.json -PrerequisiteTaskDefinitionFiles testdata/autopilot_code_step_tasks_20261031_20261107.json -Policy enforce -FailOnWarnings

# 仅检查 A 的 D1 第 1 个 operation（启动前基线检查常用）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261031_20261107.json -Policy enforce -FailOnWarnings -RoundTag D1 -OperationIndex 1

# 仅检查某个验证轮（例如 V2）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261108_20261115.json -Policy enforce -FailOnWarnings -RoundTag V2
```

前置任务定义必须与当前定义指向同一目标源码；任一前置定义未通过完整安全检查时，checker 会阻断且不再检查当前定义，避免基于无效中间文本产生级联误报。该参数用于初始设计期的 A -> B 链式模拟，不写入源码，也不替代运行期 A PASS snapshot；运行期 B 仍以 snapshot 对齐后的当前源码为权威基线。

通过标准：
- 不残留 TODO
- 不存在 replacement 双转义风险
- pattern 唯一匹配
- 目标锚点可达
- `operationSafetyPolicy=enforce`
- 每个 op 的 marker 由自身 replacement 唯一产生，且与其他 op 不冲突
- replacement 后原 pattern 不再命中，整轮第二次应用不改变文本
- 函数替换不遗留孤儿函数体
- 每轮 `postApplyAssertions` 全部达到精确计数
- helper 的 definition、prototype、真实 call site 数量符合契约

未通过时：
- 先修任务定义
- 不要跳过体检直接启动

### 4.4 阶段 3：在 RFC 中起草“下次开工清单”

两份主 RFC：
- docs/RFC-whois-client-split.md
- docs/RFC-address-space-preclassifier.md

说明：
- 下次开工清单固定落在以上两份 RFC 中，不写到其他临时文档或聊天记录里。
- Checklist A / Checklist B 都应在这两份 RFC 中能找到明确落点，便于后续启动、复盘和回填共用同一条证据链。

此阶段的目标不是启动，而是把以下内容固定下来：
- A/B 对应窗口
- A/B 任务定义文件名
- 当前运行模式
- 串行约束
- 推荐执行命令
- 预期验证范围
- 任务结束后的回填位置

建议写法：
- Checklist A：只描述 A 本轮的目标、命令和验收
- Checklist B：只描述 B 本轮的目标、命令和验收
- 明确“B 仅在 A PASS 后启动”

### 4.5 阶段 4：从模板生成启动文件

目标：把“如何启动、如何监控、如何回填”固化到 start-file，而不是靠会话临时记忆。

推荐脚本：
- tools/test/create_unattended_ab_start_file.ps1

最简示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/create_unattended_ab_start_file.ps1 -ATaskDefinition autopilot_code_step_tasks_20261031_20261107.json -BTaskDefinition autopilot_code_step_tasks_20261108_20261115.json -Window "2026-10-31 ~ 2026-11-15"
```

固定文件名示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/create_unattended_ab_start_file.ps1 -ATaskDefinition autopilot_code_step_tasks_20261031_20261107.json -BTaskDefinition autopilot_code_step_tasks_20261108_20261115.json -Window "2026-10-31 ~ 2026-11-15" -OutputFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -Force
```

生成 smoke 示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/create_unattended_ab_start_file.ps1 -ATaskDefinition autopilot_code_step_tasks_20261031_20261107.json -BTaskDefinition autopilot_code_step_tasks_20261108_20261115.json -Window "2026-10-31 ~ 2026-11-15" -OutputCategory smoke
```

生成并检查完成后，必须先把以下三类产物交用户确认：
- 任务定义文件
- 两份 RFC 中的下次开工清单
- 启动文件

在用户明确确认前，停在“准备完成，待启动授权”状态，不要开跑。

### 4.6 阶段 5：补齐并核对启动文件

运行期物理事件名多于处理职责，必须先归并再授权动作：
- 代码/脚本/非代码事故可使用 `incident-captured`，兼容事件还包括 `task-definition-fix-required`、`recovery-await-confirmation`、`auto-fix-await-confirmation`、`main-process-exit-review`；事件名本身不授予代码修复权限，最终以 phase/category/evidence 和 start-file 开关决定 lane。
- `manual-wait-paused`、`budget-exhausted-stop`、`known-infra-transient-stop` 是阻断/通告票，不是新的修复 lane。当前通告票只允许报告、对应决策和原子收尾，固定命令顺序为 `route_guard_command -> atomic_closeout_command`；不得修改文件或环境，不得执行 `business_resume`、`continue_watch_command`、guard/stage 重启。后续实际处置必须由独立的已授权事故票按 phase/category/evidence 进入代码、脚本或非代码流程，或由用户明确授权。
- `a-pass-conclusion-b-started` 与 `chat-session-final-status` 是只读阶段结论票，`running-status-report` 是只读定时状态票，均不得触发修复、恢复或进程控制。
- 发送链内部或未知事件不得直接授权修复；进入票据链后必须先经 route guard，未知事件默认 `event-review`。

阶段结论票必须携带可直接投影到聊天回复的最低内容要求和确定性耗时，dispatch 不得在投递时重新计算：
- `a-pass-conclusion-b-started` 的评审回复至少包含 A 阶段最终结论、关键检查点与最终证据、重要事故/恢复及结果、B 已启动，以及 A 阶段总用时和起止锚点。A 阶段总用时按 `SESSION_INITIAL_LAUNCH_AT` 到该评审票 `created_at` 计算。
- `chat-session-final-status` 的总结回复至少包含 SESSION/A/B 最终结论、执行时间线、重要事故/根因/修复与恢复动作、状态票和 ACK/heartbeat 结果、会话结束时间，以及 B 阶段总用时和 A/B 两阶段合计总用时。B 阶段总用时按 `B_TASK_FIRST_START_AT` 到总结票 `created_at` 计算；A/B 合计总用时按 `SESSION_INITIAL_LAUNCH_AT` 到同一结束时间计算。
- `SESSION_INITIAL_LAUNCH_AT` 是当前 start-file 会话的首次启动时间，只写一次，统计会包含 launcher/preflight、阶段交接和恢复等待；它不是纯 A worker 运行时间。全新独立 A/B 任务必须由模板重建 start-file 并重新生成该值；同一会话内的恢复不得清空它。
- 任一基准时间缺失或格式非法时，对应格式化耗时必须输出 `unknown`、秒数输出 `-1`，不得伪造或用当前时间替代起点。

启动文件中必须确认的关键项：
- `ENTRY_MODE=single-param-fastmode`
- `ENTRY_SCRIPT_A` / `ENTRY_SCRIPT_B` 保持模板默认值，不作为人工/AI 手工执行命令使用
- `RUN_MODE=foreground-visible`
- `A_FAILURE_BLOCKS_B=true`
- `B_START_REQUIRES_A_PASS_WITH_SNAPSHOT=true`
- `PRECHECK_REQUIRED=true`
- `TASK_STATIC_PRECHECK_POLICY=enforce`
- `TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS=true`
- `TASK_STATIC_PRECHECK_FAILURE_MODE=runtime-ticket`（允许启动监控链；启动预检只打印结果，不发票；D1 整轮静态失败且主进程停止后才进入自愈票链）
- `TASK_STATIC_CROSS_ROUND_REPAIR_ENABLED=false`（默认只修当前 task-static 故障轮；缺失、空值或非法值也按关闭）

`TASK_STATIC_CROSS_ROUND_REPAIR_ENABLED` 只控制 task-static 代码自愈工单的检查/修复范围，不改变 checker 的单轮首错即停语义，也不改变运行时 D 轮管线。关闭时，当前故障轮通过后即可按同阶段恢复，后续轮由运行时门禁检查；开启时，当前故障轮通过后从下一 D 轮开始按顺序逐轮调用 checker 到 D4，遇到首错即停并只在该轮允许边界内修复，范围内全部通过后才允许恢复。该开关不授权 code-step 或非代码故障编辑任务定义，也不扩大编译/验证代码故障的追加式修复边界。takeover brief 必须同步输出开关值和一致的 `task_definition_check_order`。

所有故障动作统一停机门禁：
- guard 在进入 `FAIL/BLOCKED` 故障处理、生成任何可修复/重启类票据或执行 auto-fix/recovery 前，必须通过 A/B 统一业务进程快照确认全部主进程已停止。
- 统一快照同时检查 start-file 绑定候选进程；仅当终态 exit artifact 的 start-file、PID/候选和 10 分钟新鲜度全部匹配时，才把 `-NoExit` 遗留的 PowerShell 宿主窗口视为业务脚本已退出。
- 任一业务进程仍存活或存活状态无法确认时，只记录 `fault_processing_wait` / `fault_action_ticket_wait`，不得发故障动作票、修改任务定义/源码或执行 restart/`business_resume`。
- `running-status-report`、`a-pass-conclusion-b-started`、`chat-session-final-status` 属于观察/通知票，可在运行中发送，但不得触发故障修复。
- D1 stall 的固定顺序为：检测停滞 → 停止 A 进程树 → 统一快照确认离线 → 写 FAIL/采集证据 → 发 `incident-captured`。不再在 stall 检测分支即时 auto-restart，恢复统一由 AI 在停机票据闭环中完成。

如果要低打扰或 event-only：
- 只改 `AI_CHAT_POLICY_WORK_MODE`
- 不要手工随意发明一整组派生键
- 模式差异只作用于“非故障状态票生成/分发与回执文本密度”；不应关闭事件票（如 `incident-captured`、`task-definition-fix-required`）的自愈闭环能力。
- 对 `running-status-report` 的主进程健康检查，`normal/anti-missent/low-disturb` 都只允许只读检查；进程缺失只汇报，不得由状态票触发脚本自愈或事件升级。`event-only` 不生成状态票。
- 状态票永远不得触发故障处理或自愈动作；任何处置必须等待独立事故票并遵守停机门禁。
- 对 B 阶段编译/验证故障，只有结构化 category 与证据确认属于源码编译、链接、业务逻辑或输出契约故障时，route guard 才进入 `incident-auto-resume-code-fix`；工具链不可用、权限、磁盘、网络、远程锁和测试基础设施故障进入 noncode。task-static 失配进入 code-fix；任何 code-step 故障均进入 noncode。

### 4.7 阶段 6：启动文件同步检查

目的：确认模板、active/smoke 启动文件、reset 规则仍一致。

示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_start_field_sync.ps1
```

通过标准：
- `result=pass`
- `missing_field_files=0`
- `missing_reset_files=0`

未通过时：
- 先修 start-file 或模板同步
- 不要继续启动 A/B

### 4.8 阶段 7：清理当前任务进程及终端窗口

目的：在启动新任务前，确保旧的无人值守进程及其终端窗口已被清理，避免残留进程干扰预检与启动。

推荐命令：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/stop_unattended_ab_oneclick.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261116-20261130.md"
```

说明：
- 该命令会扫描并停止与当前 start-file 关联的主进程树及监控链进程。
- 若所有相关进程及终端窗口已被清除，输出 `[AB-STOP] no-target-process-found` 并以 exit code 0 退出。
- 执行后应确认旧的无人值守外部 PowerShell 窗口已真正关闭，而不是仅认为脚本逻辑已经结束。
- 若残留进程未清理干净，统一启动前检查中的 `PRECHECK_LOCAL_RELATED_PROCESSES` 会报 FAIL。

### 4.9 阶段 8：统一启动前检查

推荐做法：优先直接运行统一检查脚本，而不是把静态体检、字段同步、预检回填拆成多次人工确认。

参数速览（`tools/test/check_unattended_ab_launch_ready.ps1`）：
- `-StartFile <path>`：必填，待启动的 start-file。
- `-Stage A|B`：可选，默认 `A`；用于按阶段执行门禁策略。
- `-Operator <name>`：可选，默认 `Copilot`；用于预检回填操作者标记。
- `-RequireCleanWorkspace`：可选，要求工作区必须 clean。
- `-DryRun`：可选，只检查不写回 `PRECHECK_*`。
- `-DetailedOutput`：可选，输出完整明细（默认会做摘要压缩）。
- `-AsJson`：可选，按 JSON 输出结果，便于脚本解析。

标准命令：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md"
```

若只想先试跑、不写回 `PRECHECK_*`：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -DryRun
```

若需要完整排障明细：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -DryRun -DetailedOutput

# B 阶段启动前检查（按 stage=B 策略）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -Stage B -DryRun

# 机器可读输出（例如 CI 或包装脚本）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -Stage A -AsJson
```

该脚本内部固定顺序：
- 检查目标 start-file
- 读取并验证 `A_TASK_DEFINITION` / `B_TASK_DEFINITION`
- 按阶段对当前任务定义执行 `-SyntaxOnly` 技术装载检查：`Stage=A` 检查 `A_TASK_DEFINITION`，`Stage=B` 检查 `B_TASK_DEFINITION`；不读取目标源码、不检查 D1-op1、不执行 operation 正则
- 执行启动文件字段同步检查
- 默认跳过耗时较长的 status-ticket、retry-budget、route-guard 完整回归和 repository 全仓扫描；这些检查由对应 start-file 开关显式启用，或通过独立回归/发布门禁执行
- 执行增量编码检查（基于 `git diff --name-only`）；非 DryRun 场景先自动修复增量不合规编码
- 执行 src 变更编码门禁（`tools/dev/enforce_utf8_lf_src_changed.ps1`）
- 执行本地进程、任务文件、入口、SSH 和远程锁预检；非 DryRun 原子回填 `PRECHECK_*`，DryRun 只报告拟写入值

完整检查 opt-in 开关：
- `STATUS_TICKET_MINI_REGRESSION_ENABLED=true`：执行 `tools/test/status_ticket_mini_regression.ps1`
- `RETRY_BUDGET_MINI_REGRESSION_ENABLED=true`：执行 `tools/test/retry_budget_minimal_regression.ps1`
- `ROUTE_GUARD_SMOKE_SUITE_ENABLED=true`：执行 `tools/test/route_guard_smoke_suite.ps1`
- `LAUNCH_READY_REPOSITORY_GUARDS_ENABLED=true`：执行 PS5.1 inline-if guard 和 tracked 文件编码全仓门禁

返回约定：
- 任一步失败，立即返回 `step`、`status=FAIL`、`reason`，并停止后续步骤；任务定义 SyntaxOnly 装载失败必须硬阻断，不得通过 `TASK_STATIC_PRECHECK_FAILURE_MODE=runtime-ticket` 延迟。
- `Stage=B` 会先检查 A PASS snapshot baseline；baseline 缺失或不可用时，在 SyntaxOnly、字段同步和编码等后续步骤之前 fail-fast，并输出 `step=b-start-baseline` 的 START/DONE 进度。这是串行 A -> B 门禁，不是遗漏 A 阶段的检查项。
- 全部通过，返回 `step=launch-ready`、`status=PASS`，表示当前 A/B 任务已具备启动条件。
- D 轮 operation 的唯一匹配、替换、marker、收敛、replay 与断言检查由运行期独立 checker 执行。失败时主进程在 code-step 前停止，guard 通过阶段进程快照确认主进程已停止后，才生成 `incident-captured` 自愈票；仍运行时只写 `task_definition_repair_wait`。
- 默认直接看终端最后一行：`AB_LAUNCH_READY_RESULT=PASS` 或 `AB_LAUNCH_READY_RESULT=FAIL`。

AI 在此阶段的工作方式：
- 可直接运行上述统一检查脚本，不必为每个检查子项逐项向用户申请确认。
- 若脚本失败，AI 只需把失败项和失败原因反馈给用户，并继续停留在准备态。
- 若脚本成功，AI 再向用户发起一次最终启动授权请求，而不是把每个检查动作拆成多次授权。

补充经验：
- 本地预检中的“相关进程”判定看的是实际 `powershell.exe` / 相关进程是否仍存活，不只看任务是否“似乎已经跑完”。
- 若无人值守窗口仍保持打开，窗口背后的 PowerShell 进程通常也仍然存活，可能导致 `PRECHECK_LOCAL_RELATED_PROCESSES=FAIL`。
- 因此在重新执行统一检查脚本前，应先确认旧的无人值守外部 PowerShell 窗口已经真正关闭，而不是仅认为脚本逻辑已经结束。

编码格式门禁与修复（UTF-8 with BOM + LF）：

仅检查（建议 gate 使用）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dev/enforce_utf8_bom_lf.ps1 -Mode check -Policy enforce -Scope tracked
```

若发现不合规文件，按顺序修复并复检：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dev/enforce_utf8_bom_lf.ps1 -Mode fix -Policy warn -Scope tracked
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dev/enforce_utf8_bom_lf.ps1 -Mode check -Policy enforce -Scope tracked
```

无人值守运行期间建议使用轻量增量脚本（按 `git diff --name-only` 取增量）：

```powershell
# 仅检查增量
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dev/enforce_utf8_bom_lf_changed.ps1 -Mode check -Policy enforce

# 增量自动修复并强校验（推荐无人值守）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dev/enforce_utf8_bom_lf_changed.ps1 -Mode fix -Policy enforce -IncludeUntracked
```

src 目录 C 源码（UTF-8 + LF，无 BOM）轻量门禁：

```powershell
# 仅检查 src 增量 .c/.h
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dev/enforce_utf8_lf_src_changed.ps1 -Mode check -Policy enforce

# 无人值守推荐：增量自动修复 + 强校验
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dev/enforce_utf8_lf_src_changed.ps1 -Mode fix -Policy enforce -IncludeUntracked
```

默认行为说明：
- `tools/test/check_unattended_ab_launch_ready.ps1` 默认走轻量启动路径；在非 `-DryRun` 场景会执行增量自动修复，并原子写回 `PRECHECK_*`。
- `-DryRun` 场景只做检查，不修复编码，也不写回 start-file。
- `start_dev_verify_fastmode_A.ps1` 与 `start_dev_verify_fastmode_B.ps1` 在启动前会依次执行：文本增量编码门禁（BOM+LF）和 src C 源码增量门禁（UTF-8+LF，无 BOM），降低 A->B 切换期因编码问题中断的概率。

取舍建议（减少运行期开销）：
- 启动前默认只保留 SyntaxOnly、字段同步、增量编码、进程、SSH 和远程锁等启动必要门禁，避免完整集成回归把主进程启动延长到数分钟。
- status-ticket、retry-budget、route-guard 和 repository guards 的完整覆盖保留在独立回归、事故票 contract gate 或发布门禁中；需要在启动前强制执行时再通过 start-file 开关显式启用。
- retry-budget 独立回归使用一次共享 session-floor seed 和三次 ack-only 校验覆盖 yes/missing/no receipt，不再重复 ticket selection；该优化只减少测试进程初始化，不改变生产 poll 的 receipt 校验或 ledger 终态语义。
- 无人值守运行期间优先增量自动修复（`enforce_utf8_bom_lf_changed.ps1 -Mode fix -Policy enforce`），避免频繁全量扫描导致抖动。
- 在阶段切换（A->B）或关键里程碑后，再执行一次全量 `-Scope tracked` 收口检查。

锁冲突处理语义（建议固定）：
- 无人值守默认 `skip-on-lock`：锁忙时输出 `lock=busy action=skip`，保持连续性。
- 人工排障/发布前可切 `-FailIfLocked`：锁忙直接失败，获得强一致诊断。
- 预检失败原因优先看关键字段：`lock=busy`、`mutex busy`、`lock_busy=true`、`remaining=`。

### 4.10 阶段 9：预检并回填 PRECHECK 字段

目的：把“可以启动”写进 start-file，而不是靠口头说已经检查过。

说明：
- 这一阶段通常由 `tools/test/check_unattended_ab_launch_ready.ps1` 内部自动完成。
- 只有在调试、拆分排障或需要单独复跑预检时，才建议直接调用底层预检脚本。

底层单独执行示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/precheck_unattended_ab_start_file.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md"
```

至少应核对：
- 本地相关进程无残留
- 远端相关进程无残留
- SSH 连通
- A/B 任务定义文件存在
- A/B 任务定义文件已 TODO-free
- 工作区状态已记录
- remote lock 状态明确
- 网络预检结果可接受

回填后目标状态：
- `PRECHECK_STATUS=PASS`
- `PRECHECK_START_GATE=READY`
- `PRECHECK_REMOTE_LOCK=absent` 或 `held-by-self`

### 4.11 阶段 10：Trigger Route Guard 门控 smoke（可选）

目的：快速验证 takeover trigger 路径满足“先 route guard 决策，再进入 trigger 执行计划”的执行层门控要求。

推荐命令：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/trigger_route_guard_gate_smoke.ps1
```

VS Code 可选任务入口：
- `Test: Trigger Route Guard Gate Smoke`

产物位置：
- `out/artifacts/trigger_route_guard_gate_smoke/<timestamp>/summary.json`
- `out/artifacts/trigger_route_guard_gate_smoke/<timestamp>/evidence.log`

通过标准：
- 终端输出 `result=pass`
- `summary.json` 中以下检查项均为 true：
	- `status_route_allowed`
	- `incident_route_allowed`
	- `status_trigger_failed_after_guard`
	- `incident_trigger_failed_after_guard`

说明：
- smoke 会故意使用不受支持的 trigger 模板，`*_trigger_failed_after_guard=true` 属于预期行为，用于证明“guard 放行后才进入执行计划”。

自动触发与默认策略（2026-07 更新）：
- `open_unattended_ab_stage_window.ps1` 在调用 launch-ready gate 时会进入 `check_unattended_ab_launch_ready.ps1`。
- `TASK_STATIC_PRECHECK_FAILURE_MODE` 缺省为 `block`；仅显式设为 `runtime-ticket` 时，A 基线静态失败可进入监控启动流程。启动预检不发修复票；必须等待 D1 整轮静态 gate 失败、业务主进程停止，再由 guard 发 `incident-captured` 自愈票。该设置不改变运行期整轮静态 gate、operation safety 或失败预算阻断。
- 当该流程属于守护管理启动（`-GuardManagedLaunch`）且不在 CI 环境时，`route_guard_smoke_suite.ps1` 默认跳过，避免 guard 重启期间反复写入 smoke 产物。
- 以下场景默认执行 `route_guard_smoke_suite.ps1`：
  - 非守护链路直接调用 launch-ready gate；
  - CI 环境（如 `CI=true`、`GITHUB_ACTIONS=true`、`TF_BUILD=true`）。
- 可在 start-file 设置 `ROUTE_GUARD_SMOKE_SUITE_ENABLED=true|false` 显式覆盖，优先级高于默认策略。

兼容性说明：
- `tools/test/trigger_route_guard_gate_smoke.ps1` 保持 one-shot 语义不变。
- `tools/test/route_guard_smoke_suite.ps1` 保持现有行为不变。
- VS Code 任务 `Test: Trigger Route Guard Gate Smoke` 保持原入口不变。

若不满足：
- 入口脚本会硬闸阻断

即使已经达到 `READY`：
- 若用户尚未明确发出启动命令，仍然不得启动 A/B。

### 4.12 阶段 11：正确启动 A/B

这是最关键的一步。

前提条件：
- 用户已经确认任务定义文件、RFC 下次开工清单、启动文件
- `tools/test/check_unattended_ab_launch_ready.ps1` 已整体返回 PASS
- 用户已经明确发出本轮启动命令
- 长跑脚本准备在 VS Code 外部 PowerShell 窗口运行

推荐授权边界：
- AI 在准备阶段直接跑完整检查脚本，不逐项向用户申请确认。
- 只有当统一检查脚本 PASS 后，AI 才向用户提一次“启动 A（带 `-StartMonitors`）”的授权请求。
- 用户给出启动授权后，再由 AI/操作员执行 stage window 启动命令。

正确做法一：标准方式，外部 PowerShell 窗口里用 stage window 入口，并显式带 `-StartMonitors`

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage B -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
```

说明：
- 这是正常运行时的首选命令组。
- 由主进程包装器负责在外部 PowerShell 窗口中拉起监控链。
- A 先启动
- B 只在 A PASS 且快照已固化后启动
- 不要在 A 尚未收口时抢跑 B
- 对 B 来说，stage window 会根据当前源码是否已偏离 A 成功快照，自动决定是“直接附着现有监控链”还是“以 A 快照为基线回滚并全量重绑监控链”。

正确做法二：A 阶段重启 / 自愈后重跑

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
```

说明：
- 适用于 A 阶段失败、自愈修复、或需要从 A 开始重跑的场景。
- A 主进程会自动以项目基线回滚源码，然后重新执行 A 阶段任务定义。
- 监控链由 stage window 同步拉起，不需要手工再补 4 个监控窗口命令。

正确做法三：B 阶段重启 / 自愈后重跑

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage B -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
```

补充说明：
- 适用于 B 阶段失败、自愈修复、或需要从 B 开始重跑的场景。
- B 主进程会自动检查当前源码与 A 成功快照是否一致；若不一致，则自动以 A 成功快照为基线回滚源码后再进入 B 阶段执行。
- 若需要兼容旧执行口径并强制全量重绑监控链，可在 B 命令后追加 `-EnableBMonitorRestart`，但这不是首选常态命令。
- 即使某些 start-file 已把 `AUTO_START_MONITORS=true` 写入默认配置，标准执行口径仍应显式带上 `-StartMonitors`，不要把是否自动拉起监控链建立在隐式默认值上。
- 即使这组命令是从 VS Code 集成终端里触发，`open_unattended_ab_stage_window.ps1` 及其后续 monitor launcher 也会继续拉起外部 PowerShell 窗口承载实际长跑进程。
- VS Code 集成终端内运行仅用于调试，不作为标准运行方式。

错误做法：
- 直接手工执行 start_dev_verify_fastmode_A.ps1 / start_dev_verify_fastmode_B.ps1
- 会话代理自己写 `start_ab_round_A_custom.ps1`
- 会话代理自己绕开 stage window 包装器，直接重拼 multiround 参数
- 会话代理写一套“看起来差不多”的新入口脚本替代现有入口
- 把主运行和 4 个监控链脚本长期挂在 VS Code 集成终端里

### 4.13 阶段 12：运行中监控与工单处理

正确监控链路：
- guard 产票
- trigger/dispatch 将工单投送到会话
- AI 被动接收工单；仅在工单指令要求时一次性调用 `poll_agent_tickets.ps1`
- 自动恢复类事件票优先执行 `recovery_transaction_command`；该事务命令会重新读取当前票据行并复核 route guard，随后按不同工单生成的字段执行授权的 `business_command`、`continue_watch_command` 与 `atomic_closeout_command`，把主进程重启后到闭环的间隙收敛到同一 PowerShell 进程内
- 未提供 `recovery_transaction_command` 的事件票执行唯一的 `atomic_closeout_command`；该单入口命令先通过 poll mutex 原子写入 `handled_at/done/processed_ids`，释放 poll 子事务锁后立即校验当前票的 ledger、receipt 与 closure。当前票 closure 校验使用 `check_unattended_ticket_closure.ps1 -TicketId <ticket-id>` 聚焦模式，不得因其他历史票或孤立 brief 阻断本票闭环；不带 `-TicketId` 的 checker 仍用于独立全局巡检。这里的“原子”指单命令、幂等、任一后置条件失败即整体 fail-close，不表示三项后置校验全程持有同一 mutex
- 仅当事务/原子命令退出码为 0 且 JSON 机器事实满足对应门禁（事务命令 `success=true` 且有效 `handled_at`；原子命令还需 `processed=true`、`ledger_status=done`、`receipt_valid=true`、`closure_pass=true`）时，才可回传机器输出中的时间并声称闭环

票据分类、恢复与重启矩阵：

| 物理事件/条件 | route guard 最终分类 | 允许修复 | 恢复事务内重启 A/B | 标准收尾入口 |
|---|---|---:|---:|---|
| 可自愈的 task-static 或已确认代码故障 | `incident-auto-resume-code-fix` | 是，按代码修复边界 | 是 | `recovery_transaction_command` |
| 可自愈脚本故障，且 `LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED=true` | `incident-auto-resume-script-fix` | 是，按脚本自愈边界 | 是 | `recovery_transaction_command` |
| 可恢复的环境、监控链或其他非代码故障 | `incident-auto-resume-noncode` | 是，仅限授权的非代码处置 | 是 | `recovery_transaction_command` |
| 事故存在预算、冷却、不可恢复环境、阶段缺失等阻断 | `incident-manual-code-fix` / `incident-manual-script-fix` / `incident-manual-noncode` | 仅分析并等待人工决策 | 否 | `atomic_closeout_command` |
| 脚本故障且脚本自愈开关缺失、空值、非法或为 `false` | `incident-script-diagnose-only` | 否，只读取证和给出方案 | 否 | `atomic_closeout_command` |
| `manual-wait-paused` | `notice-manual-wait` | 否，仅人工恢复决策 | 否 | `atomic_closeout_command` |
| `budget-exhausted-stop` | `notice-budget-exhausted` | 否，仅重跑范围决策；不削弱更早事故票已有授权 | 否 | `atomic_closeout_command` |
| `known-infra-transient-stop` | `notice-known-infra-transient` | 否，仅环境稳定化决策 | 否 | `atomic_closeout_command` |
| `running-status-report` | `status-health-check-only` / `superseded-status-ticket` | 否，只读汇报 | 否 | 状态票专用 handled 回执；不得调用恢复事务 |
| 当前会话启动前的旧票 | `pre-start-skip` | 否 | 否 | 标记 handled 后继续 |
| `a-pass-conclusion-b-started`、`chat-session-final-status` 或其他非事故事件 | `event-review` / `event-review-low-disturb-text-only` | 否 | 否 | `atomic_closeout_command` 或对应专项 closeout |
| 缺失或未知分类、brief 与实时分类不一致 | 无有效授权 | 否 | 否，fail-close | 不收尾、不伪造 `handled_at`，报告阻塞 |

矩阵解释：
- `incident-captured`、`task-definition-fix-required`、`recovery-await-confirmation`、`auto-fix-await-confirmation`、`main-process-exit-review` 只是物理事件入口，不能单独决定是否修复或重启；必须结合 phase/category/evidence、start-file 开关和实时 route guard 得到最终分类。
- 只有 `incident-auto-resume-code-fix`、`incident-auto-resume-script-fix`、`incident-auto-resume-noncode` 三个精确分类允许恢复事务生成并执行 stage-window 重启命令。不得用 `incident-auto-resume-*` 的模糊前缀、事件名或历史默认值扩展该集合。
- 自动恢复还必须同时满足：brief 的 `next_command_order` 包含 `recovery_transaction_command`（兼容行可显式为 `business_command`）、`business_command_stage`/`preferred_stage` 为 A 或 B、实时分类与 `route_guard_expected` 完全一致、`must_trigger_business_resume=true`、`must_avoid_stage_restart=false`，且 `allowed_actions` 授权 `business_resume`。任一条件缺失均 fail-close。
- trigger/poll 只应为三类 auto-resume 票生成 `recovery_transaction_command`。manual、diagnose-only、notice 和 event-review 正常只生成 `atomic_closeout_command`；旧 brief 即使误把非自动恢复票交给恢复事务，事务也不得生成或执行 `business_command`。
- `recovery_transaction_command` 表示“复核实时授权后执行允许的业务动作并完成原子收尾”，不等同于“必然重启”。分类在投票后发生漂移时，以实时 route guard 为最终权限来源，但实时分类必须与 brief 快照一致；不一致时停止而不是静默降级或继续收尾。

运行期执行规则：
- 事件驱动票中的工作内容视为预授权操作，AI 按事件票 `next_command_order` 执行。定时状态票只预授权只读查询、汇报与 handled 回执。
- AI 不得自行创建或运行定时巡检脚本、轮询循环、后台 job、watcher、常驻 PowerShell 命令或长时间跨轮次巡检命令，也不得为了“保持监控”周期性执行 heartbeat/poll。工单通过事务命令或唯一原子收尾命令完成真实回执与闭环后只需静默等待下一条投送消息；3 分钟是收尾目标，不是 Agent 可执行的总墙钟超时，事务启动后等待同步命令自然退出，不得按 3 分钟或 240 秒主动终止。
- 对 `running-status-report` 这类需要 handled 收据的工单，必须立即写入 `handled_at`；`handled_at` 是强制项，不可省略。
- `handled_at` 现在应优先作为 `poll_agent_tickets.ps1` ledger 中的一等状态字段理解；额外的 `handled_tickets/*.md` 仅在显式开启 `LOCAL_GUARD_WRITE_HANDLED_ARTIFACTS=true` 时才写入，不再作为默认必需产物。
- 对 `running-status-report`，默认处置为只读状态查询、汇报与 handled 回执；不得执行 continue_watch、故障处理或恢复动作。
- 自动恢复类事件票默认执行顺序为：`route_guard_command -> pre_restart_launch_ready_command -> recovery_transaction_command`；`task-definition-fix-required` 在 route guard 后额外执行 `contract_gate_command`，完整顺序为 `route_guard_command -> contract_gate_command -> pre_restart_launch_ready_command -> recovery_transaction_command`。快速 contract gate 与 launch-ready 均在主进程重启前完成。事务命令内部按当前工单字段执行 `business_command -> continue_watch_command -> atomic_closeout_command`，不重复执行 contract regression；三分钟温窗是主进程重启后完成原子收尾的目标，不替代恢复事务原有的弹性超时，也不授权 Agent 强杀。事务必须等待自然退出，stage 主进程验证保留脚本内部 240 秒容错预算，atomic closeout 保留 120 秒 acknowledge 超时；任一内部超时仍 fail-close。无事务命令的事件票按 `route_guard_command -> atomic_closeout_command` 或专项 closeout 字段执行；具体以票据 `next_command_order` 为准。状态票不适用该顺序。
- `handled_receipt_command`、`validate_receipt_command`、`mark_processed_command`、`post_check_command` 继续作为审计与旧消费者兼容字段输出，但 Agent 不得逐条重复执行；原子命令已覆盖写入、校验和 closure。
- 若 `recovery_transaction_command` / `atomic_closeout_command` 按当前票据应存在却缺失、锁忙、JSON 无法解析或任一机器事实门禁失败，必须 fail-close 并报告阻塞；不得自行生成 `handled_at`，不得用聊天文本替代 ledger 状态。
- 聊天输出层（relay/转录）校验默认关闭，不作为常态强门禁；该层信号仅作为辅证，不替代 ledger 的强约束状态。
- 仅在故障排查或专项验收窗口临时启用聊天输出层校验，且建议抽样执行，避免高频轮询带来的额外资源开销与交互抖动。
- 只有以下情形才需要重新请求用户指令：用户明确下达 `stop monitoring`；需要跨阶段改计划；需要更换 start-file；需要执行超出当前票据既定工作流的高风险动作。
- 若工单处理过程中确需辅助脚本，优先调用现有脚本；确需临时脚本时，只能放在 tmp，下游动作完成后删除。
- 不得手工补写 `chat_heartbeat*.jsonl`、`chat_heartbeat_reports_additional_*.jsonl` 或额外 handled 回执文件来“模拟完成”；心跳使用 `tools/test/update_chat_session_heartbeat.ps1`，事件票回执与 closure 优先执行 brief 的 `recovery_transaction_command`，无事务命令时只执行 `atomic_closeout_command`。其内部调用 `poll_agent_tickets.ps1 -AcknowledgeTicketIds ...`，Agent 不得再单独重复调用旧分步命令。

一次性工单消费/排障示例（仅在收到工单指令或人工排障时执行，不得包装为定时循环）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -IncludeStatusReports -AsJson
```

状态文件命名与兼容规则：
- `poll_agent_tickets.ps1`、`update_chat_session_heartbeat.ps1`、`unattended_ab_takeover_trigger.ps1`、`dispatch_takeover_to_chat.ps1` 及其配套检查脚本，在未显式指定路径时，默认使用基于 start-file 完整路径生成的 stable token 命名状态文件。
- 这批默认文件包括会话心跳、poll state、ledger、trigger log/state、dispatch log、latest relay、status-report message state。
- stable token 的目标是隔离“不同目录下同名 start-file”的状态文件，避免串锚。
- 升级过渡期若默认 stable 路径文件不存在而 legacy 旧命名文件仍存在，脚本会自动回读并沿用旧文件，不要求人工迁移或重命名现有状态文件。
- 一旦用户或 start-file 已显式指定路径，则以显式配置为准，不启用默认路径猜测或 fallback。

查看 routine 状态：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_routine_status.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -AsJson
```

写入会话心跳：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/update_chat_session_heartbeat.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -Source "chat-session-active" -AsJson
```

### 4.14 阶段 13：A 收口后再启动 B

进入 B 之前必须满足：
- A 已 PASS
- A 成功快照已固化
- A 的 `final_status.json` 路径已确定
- A 的 `summary.csv` 路径已确定
- A 结束时源码状态摘要已记录

如果 A 失败：
- 禁止启动 B
- 先在 A 任务定义中修 A
- 必要时 reset start-file 后从 A-D1 重跑

### 4.15 阶段 14：自愈修复 / 故障处理

适用场景：
- 编译失败
- 静态体检失败
- 规则误判
- 任务定义中的 patch / anchor / replacement 漂移

固定原则：
1. 先留证，确认失败发生在 A 还是 B。
2. 先判断路由属于哪一类，再决定修改面：
	- `incident-auto-resume-script-fix` / `incident-manual-script-fix`：只修 guard/trigger/dispatch/poll 等无人值守脚本链路，不碰业务源码。
		- PowerShell 5.1 兼容强约束：禁止在脚本修复中引入内联 `$(if(...){...} else {...})` 子表达式（尤其是 `-f` 参数或字符串插值场景）；统一采用“先计算变量，再格式化/传参”。
	- `incident-auto-resume-code-fix` / `incident-manual-code-fix`：修改当前阶段任务定义文件中对应轮次的定义内容，不直接改产出物源码；例如当前是 B D4，就改 B 任务定义文件里 D4 轮次的任务定义或在该轮次追加补丁。
    - 规则：先按跨轮次边界确定可改范围，再按故障阶段确定 op 边界。D1 故障可改 D1-D4；D2 故障仅可改 D2-D4；D3 故障仅可改 D3-D4；D4 故障仅可改 D4。V1-V4 不对应 JSON 轮次：仅可在 D4 `operations` 末尾连续追加一个或多个 op，不得改 D1-D3 或修改/删除 D4 既有内容。
    - **[D1-D4 task-static 阶段失败]（task-definition-mismatch）**：源码尚未被当前轮次修改；当前故障 op 之前的 op 只读，仅可从故障 op 位置起修改、删除、插入或追加 op。
    - **[D1-D4 code-step 阶段已通过，但编译/验证阶段失败]**：源码已被该轮次修改；该轮既有 op 全部只读，只能在该轮 `operations` 数组末尾连续追加一个或多个新 op。
	- `incident-auto-resume-noncode` / `incident-manual-noncode`：只做环境、监控链、瞬态故障稳定化，不改源码也不改任务定义。
  - `notice-manual-wait` / `notice-budget-exhausted` / `notice-known-infra-transient`：只报阻塞、预算或基础设施状态，给出对应决策并执行唯一原子收尾；不修改文件或环境，不执行 `business_resume`、`continue_watch_command`、guard/stage 重启，也不从当前票进入自愈。实际修复等待独立的已授权事故票或用户明确授权。
3. 对需要修改的任务定义文件运行静态体检。
4. 事件驱动票据进入重启分支时，重启前先执行 `tools/test/check_unattended_ab_launch_ready.ps1`；仅在返回 `AB_LAUNCH_READY_RESULT=PASS` 后再执行 stage window 启动命令。
5. 通过 stage window 从本阶段开始处重启。
6. 让主进程自动完成基线回滚与自愈执行。

补充要求：
- 这类事件的 brief 必须写明具体分支与修改对象，尤其是 code-fix 场景要明确目标 stage / round / task-definition 文件；不要只写“repair scripts and code”这种泛化措辞。
- 若 brief 里已知目标是 task-definition mismatch，应直接写成“修改对应轮次任务定义文件”，而不是让接管者再猜测是否要改源码。

示例：A 阶段自愈后重启

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261031_20261107.json -Policy enforce -FailOnWarnings
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md"
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
```

示例：B 阶段自愈后重启

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261108_20261115.json -Policy enforce -FailOnWarnings
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md"
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage B -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
```

### 4.16 阶段 15：任务结束后回填文档

任务完成后，不要只留在聊天记录里。

但在真正回填文档前，必须先获得用户明确授权。

固定顺序：
- 先汇报本轮任务最终结果、关键产物路径、异常与修复情况。
- 给用户留出检查、复盘与评估窗口。
- 只有在用户明确同意“回填 RFC / 回填文档”后，才回填以下两份 RFC。

必须回填：
- docs/RFC-whois-client-split.md
- docs/RFC-address-space-preclassifier.md

建议回填内容：
- A_FINAL_STATUS / B_FINAL_STATUS / SESSION_FINAL_STATUS
- A/B 实际运行目录
- 关键产物路径
- 本轮验证覆盖面
- 是否发生卡滞、重启、自动修复
- 结论与下一步建议

## 5. 常见操作场景

### 5.1 标准新一轮 A/B 启动

适用场景：
- 新窗口
- 新 A/B 任务定义
- 新一轮 start-file

顺序：
- 复制任务定义模板
- 填写 A/B 任务定义
- 运行 `tools/test/check_unattended_ab_launch_ready.ps1`
- 若脚本失败，按失败项修复后重跑
- 在 RFC 中起草下次开工清单
- 用 `create_unattended_ab_start_file.ps1` 生成启动文件
- 脚本整体 PASS 后，再向用户提一次启动授权
- 等待用户明确发出“启动 A（带 -StartMonitors）”命令
- 用 stage window 启动 A
- A PASS 后用 stage window 启动 B
- 任务结束后先汇报结果，待用户授权后再回填 RFC

### 5.2 复用已有 start-file 重新跑 A

适用场景：
- A 失败，需要修复后从 A 重新开始

顺序：

默认 A reset（解除 A/SESSION 的 `BLOCKED`，并将 stop 留下的 `B_FINAL_STATUS=BLOCKED` 恢复为 `NOT_RUN`，准备完整 A->B 串行重跑）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md
```

默认 B reset（先验证 A PASS snapshot；通过后恢复 `A_FINAL_STATUS=PASS`、清零旧 A PID，再解除 B/SESSION 的 `BLOCKED` 并启用 snapshot 恢复）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -Stage B -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -Stage B
```

补充：
- reset 支持 `-Stage A|B`，省略时兼容为 `-Stage A`。默认 A reset 将 A/SESSION 作用域内当前为 `BLOCKED` 的字段及 `B_FINAL_STATUS=BLOCKED` 改为 `NOT_RUN`，因为从 A 重跑代表重新进入完整 A->B 串行链；其他 `B_*` 运行证据保持不变。B reset 必须先验证 A final status 为 PASS 且 snapshot 通过 manifest/hash 检查；通过后将 stop 留下的 `A_FINAL_STATUS=BLOCKED` 归一化为 `PASS`、清零旧 `A_LAUNCH_PID`，再解除 B/SESSION 作用域的 `BLOCKED`，其他 `A_*` 证据保持不变。两者均设置 `START_ROUND=1`，不会清除 `SESSION_INITIAL_LAUNCH_AT`、失败轮次或其他运行证据，因此从 D1 进入并在原失败轮恢复完整执行。
- `-Stage A -UseTemplateBaseline` 按当前模式重建整份 start-file，保留 A/B 任务定义、窗口与 remote 配置，其余所有键值恢复至初始未运行状态，从仓库基线开始新的 A-D1 完整流程。
- `-Stage B` 默认 reset 要求 A final status 为 PASS 且 `a_success_snapshot` 通过 manifest/hash 检查；失败时不写 start-file。通过后将 `A_FINAL_STATUS` 归一化为 `PASS`、清零 `A_LAUNCH_PID`，执行 B/SESSION 作用域内的 `BLOCKED -> NOT_RUN`，并设置 `START_ROUND=1`、`B_RESTORE_FROM_A_SNAPSHOT=true`；保留失败轮、`SESSION_INITIAL_LAUNCH_AT` 和其他运行证据，从 B-D1 进入并在原失败轮恢复完整执行。
- `-Stage B -UseTemplateBaseline` 复用相同 A PASS snapshot 门禁。该模式不重建 start-file，而是额外原位设置 `RESUME_FAILED_ROUND=D1`；保留所有其他运行状态，从 A snapshot 基线开始新的 B-D1 完整流程。B launch-ready 仍会再次执行 snapshot 完整性检查。

完整 A 模板基线 reset（委托 create 脚本按当前模式重建 start-file）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -UseTemplateBaseline -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -UseTemplateBaseline
```

完整 B snapshot 基线 reset（A final status 与 snapshot manifest/hash 必须有效）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -Stage B -UseTemplateBaseline -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -Stage B -UseTemplateBaseline
```

仅重置明确字段或字段前缀（selector 以分号分隔，末尾 `*` 表示前缀匹配）：

```powershell
# A：只清理预检和网络预检运行态
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -Stage A -ResetFields 'PRECHECK_*;NETWORK_PRECHECK_LAST_*' -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -Stage A -ResetFields 'PRECHECK_*;NETWORK_PRECHECK_LAST_*'

# B：只清理 B 终态和运行目录；A_* selector 会被 B 阶段边界过滤
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -Stage B -ResetFields 'B_FINAL_STATUS;B_RUN_DIR' -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -Stage B -ResetFields 'B_FINAL_STATUS;B_RUN_DIR'
```

reset 操作约束：
- 先用统一进程快照确认 A/B 业务主进程均已停止；不得在主进程运行期间 reset start-file。
- 所有写入模式必须先运行对应的 `-DryRun`，核对 `stage`、`reset_scope`、`matched_keys`、`changed_keys` 与逐字段 change 输出后，再去掉 `-DryRun`。
- 显式 `-ResetFields` 至少要匹配一个目标阶段允许的字段，否则脚本硬失败；B 阶段会过滤所有 `A_*` 字段。
- 默认 reset 是 `stage-blocked-only`，不会因为 start-file 中存在 `RERUN_FROM_A_STARTFILE_RESET_FIELDS` 就扩大修改范围；Stage A 唯一允许跨入 B 作用域的字段是 `B_FINAL_STATUS`，用于解除 stop 对后续 B 的串行阻断。只有显式 `-ResetFields` 才进入 `explicit-selectors`。
- A `-UseTemplateBaseline` 会清除旧 session/recovery 状态并开启新会话；B `-UseTemplateBaseline` 不重建整份文件，只在已验证的 A snapshot 基线上准备新的 B-D1。

然后：
- 重新运行 `tools/test/check_unattended_ab_launch_ready.ps1`
- 脚本 PASS 后，再次向用户提一次是否重跑 A 的启动授权
- 只有用户明确下令后，再从 A-D1 用 stage window 启动

### 5.2.1 A 监控链复用验证

适用场景：
- 需要验证“主进程 A 退出后，监控链在结束宽限期内仍保持存活，并可在 A 重启时直接复用”

规则：
- 除 A/B 正常完成外，监控链结束前都应保留 10-15 分钟宽限期，用于事件票自愈、主进程重启和复用取证。
- 复用验证时，只停止主进程 A，不主动停止 session guard、takeover trigger。
- 主进程异常退出后的时序约束（A/B 同步适用）：
  1) guard 先进入温窗期（主进程缺失观察窗口），避免瞬时抖动误判。
  2) 温窗期结束后若仍确认主进程失败/故障退出，则进入宽限期（grace）。
  3) 宽限期结束后若仍未恢复，guard 执行收敛停机。
- 恢复优先级：
  1) 温窗期内发现主进程恢复运行，立即退出温窗期并恢复常态监控。
  2) 宽限期内发现主进程恢复运行，立即退出宽限期并恢复常态监控。
  3) “恢复运行”判定必须包含主进程真实存活（不是仅看 RUNNING 状态或残留 PID）。
- trigger 可选温窗（默认关闭）：
  1) 默认仍由 guard 负责主进程温窗判定，trigger 只跟随宽限/收敛流程。
  2) 如需在 trigger 侧增加 terminal 温窗，可设置：
     - `AI_CHAT_TRIGGER_TERMINAL_WARM_WINDOW_ENABLED=true`
     - `AI_CHAT_TRIGGER_TERMINAL_WARM_WINDOW_MINUTES=<1..60>`（默认 3）
  3) 开启后 trigger 行为：先进入 terminal warm window，再进入 monitor-chain grace；若在任一窗口检测到阶段恢复运行，则自动清窗并恢复常态轮询。

操作步骤：
1. 用 stage window 启动 A，并显式带 `-StartMonitors`，直到监控链 4 个进程全部拉起。
2. 记录 A 主进程 PID；优先使用 start-file 中的 `A_LAUNCH_PID`。
3. 只停止主进程 A，必要时同步把 start-file 状态回填为 `BLOCKED`，让 session guard 进入宽限窗口而不是直接判定正常完成。
4. 在宽限期内处理 `incident-captured` / `main-process-exit-review` 一类事件票，完成自愈修复后重新启动 A。
5. 观察并取证监控链是否复用成功；关键证据点包括 trigger 未重启、guard 未退出，以及重启后日志中出现 grace cleared / reuse_existing 一类记录。

命令用法：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/stop_unattended_ab_oneclick.ps1 -MainPid 123456 -MainProcessOnly -UpdateStartFileStatus
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/stop_unattended_ab_oneclick.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261116-20261130.md" -MainPid 123456 -UpdateStartFileStatus
```

补充说明：
- `-MainPid` 只针对主进程树；未命中 start-file 时，不会顺带停止监控链。
- `-MainProcessOnly` 只停止主进程树，不碰监控链；未命中 start-file 时，等同于 `-MainPid` 模式。如果不加，脚本会扩展到 A_LAUNCH_PID/B_LAUNCH_PID/WATCH_LAUNCH_PID 与关键词进程，容易把监控链一起停掉。
- `-UpdateStartFileStatus` 会把 `A_FINAL_STATUS`、`B_FINAL_STATUS`、`SESSION_FINAL_STATUS` 回填为 `BLOCKED`，并在 `SESSION_FINAL_NOTES` 中写入人工停止留证路径，便于后续事件票接管。
- 为兼容旧命令拼写，脚本也接受 `-pdateStartFileStatus` 作为 `-UpdateStartFileStatus` 的别名，但推荐统一使用正式参数名。
- 建议先执行一遍 `-DryRun` 看目标 PID 集，再执行真实停止。

### 5.3 复用已有 start-file 重新跑 B

适用场景：
- A 已 PASS 且 A 成功快照可用
- B 失败，需要修复后仅从 B 重新开始

顺序：
- 留证并确认 A 成功快照仍有效
- 修改 B 任务定义文件
- 重新运行 `tools/test/check_unattended_ab_launch_ready.ps1`
- 必要时清理/更新 start-file 中 B 相关运行态字段
- 脚本 PASS 后，用户明确下令，再用 stage window 从 B 重新启动

示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261108_20261115.json -Policy enforce -FailOnWarnings
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage B -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
```

### 5.4 event-only 低成本联调

适用场景：
- 不想启用定时状态票
- 只验证事件票链路

推荐顺序：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_start_field_sync.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_routine_status.ps1 -StartFile "testdata/unattended_start/smoke/unattended_ab_start_event_only_smoke.md" -AsJson
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "testdata/unattended_start/smoke/unattended_ab_start_event_only_smoke.md" -IncludeStatusReports -Last 20 -AsJson
```

### 5.5 运行中热切换 start-file 模式

适用场景：
- 无人值守已在跑，希望在不重建 start-file 的前提下切换 `normal/anti-missent/low-disturb/event-only`。

说明：
- 使用 `tools/test/switch_unattended_start_file_mode.ps1`。
- 脚本会先检查模式相关关键字段是否完整；若缺失会自动补齐，再应用目标模式。
- 切换后会输出 `final_mode`，并标注该变更对后续工单生效（`effect_dispatch=next-ticket`、`effect_trigger=next-poll`）。

示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/switch_unattended_start_file_mode.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -Mode low-disturb -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/switch_unattended_start_file_mode.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -Mode low-disturb
```

## 6. 常见错误与纠偏

### 6.1 错误：先写新脚本再启动

问题：
- 流程和仓库既有契约脱节
- 会绕过 stage window 的固定门禁、remote lock 检查、网络硬闸、静态体检和监控链拉起逻辑

纠偏：
- 回到现有入口：`open_unattended_ab_stage_window.ps1`

### 6.2 错误：任务定义还没体检就开跑

问题：
- 运行中才暴露 TODO、pattern 不唯一、锚点不存在

纠偏：
- 先跑 `check_task_definition_static.ps1`

### 6.3 错误：只改聊天/策略派生键，不改源键

问题：
- start-file 漂移
- 之后入口脚本回写又改回去

纠偏：
- 优先改 `AI_CHAT_POLICY_*` 源键

### 6.4 错误：A 还没 PASS 就启动 B

问题：
- 破坏 A/B 串行契约

纠偏：
- 固守 `A_FAILURE_BLOCKS_B=true`
- 固守 `B_START_REQUIRES_A_PASS_WITH_SNAPSHOT=true`

### 6.5 错误：只在聊天里记录，没有回填 RFC

问题：
- 会话结束后上下文丢失

纠偏：
- 任务结束后先汇报结果并等待用户授权，再回填两份 RFC

### 6.6 错误：准备完成就自动启动

问题：
- 把“已经 READY”误当成“已经获授权”

纠偏：
- 交由用户确认产物
- 等待用户明确发出启动命令

### 6.7 错误：长跑脚本放在 VS Code 集成终端里

问题：
- 更容易受 renderer、extension host、terminal host 等环境因素影响
- 不适合长期驻留

纠偏：
- 把 A/B 主脚本和 4 个监控链脚本全部放到 VS Code 外部 PowerShell 窗口执行

### 6.8 错误：自愈时直接改源码

问题：
- 破坏无人值守任务定义驱动模型
- 会让下一次重启回滚覆盖掉人工源码修补，导致修复不可复现

纠偏：
- 改本阶段任务定义文件，不直接改源码
- 体检通过后，用 stage window 重启本阶段，让主进程自动执行自愈

### 6.9 错误：处理工单时反复向用户确认

问题：
- 用户不在场时，既定工单工作流无法前进
- `running-status-report`、`incident-captured` 等票据会堆积，导致守护链路失去闭环

纠偏：
- 把票据中的既定动作视为预授权执行项
- AI 按 `next_command_order` 执行业务动作；自动恢复类票据以 `recovery_transaction_command` 事务完成恢复与闭环，无事务命令的事件票以唯一的 `atomic_closeout_command` 完成持久化回执、processed 状态与 closure 校验。
- 只有原子命令退出码为 0 且 JSON 机器事实全部通过，才回传其中的 `handled_at`；否则 fail-close 并报告阻塞。
- 对强制收据票立即写 `handled_at`

## 7. 最小可执行示例

假设本轮窗口是 `2026-10-31 ~ 2026-11-15`。

### 7.1 生成并体检任务定义

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261031_20261107.json -Policy enforce -FailOnWarnings
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261108_20261115.json -Policy enforce -FailOnWarnings
```

### 7.2 生成启动文件

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/create_unattended_ab_start_file.ps1 -ATaskDefinition autopilot_code_step_tasks_20261031_20261107.json -BTaskDefinition autopilot_code_step_tasks_20261108_20261115.json -Window "2026-10-31 ~ 2026-11-15" -OutputFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -Force
```

### 7.3 统一启动前检查

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md"
```

说明：
- 日常查看时，直接看终端最后一行 `AB_LAUNCH_READY_RESULT=PASS|FAIL` 即可。
- 若需要排障，追加 `-DetailedOutput` 查看完整子步骤明细。

### 7.4 脚本 PASS 且用户一次授权后，在外部 PowerShell 窗口启动 A/B

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage B -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
```

若 A 或 B 因故障/自愈需要重启，仍然使用同一组 stage window 命令，不切换到 fastmode 直跑口。

## 8. 10 行极简执行版（准备完成后）

1. 确认 A/B 任务定义文件都已 TODO-free，并已通过 `tools/test/check_task_definition_static.ps1`。
2. 确认两份 RFC 中的下次开工清单都已写好，并已交用户确认。
3. 直接运行 `tools/test/check_unattended_ab_launch_ready.ps1`；脚本会顺序完成 start-file 校验、A/B 静态体检、字段同步与 `PRECHECK_*` 回填。
4. 若统一检查脚本未 PASS，先看终端最后一行 `AB_LAUNCH_READY_RESULT=FAIL`；停在准备态，只向用户报告失败项与失败原因，不启动任何 A/B 主脚本或监控链脚本。
5. 若统一检查脚本 PASS，再向用户提一次启动 A 的授权；用户未明确下令前，仍然不得启动。
6. 正常运行时，只在 VS Code 外部 PowerShell 窗口执行 `open_unattended_ab_stage_window.ps1 ... -StartMonitors` 这组主进程命令。
7. A 阶段重启仍用 `-Stage A -StartMonitors`；B 阶段重启仍用 `-Stage B -StartMonitors`；不要再引入第二套人工操作入口。
8. 自愈修复只改本阶段任务定义，不直改源码；体检通过后再重启本阶段。
9. 事件驱动票与状态票属于预授权既定工作，AI 直接执行，不逐项询问用户；对强制收据票立即写 `handled_at`。
10. VS Code 集成终端仅用于调试，不用于承载标准无人值守长跑；任务结束后先汇报结果并等待用户授权，再回填两份 RFC 和 start-file 最终状态。

## 9. 建议结论

### 9.1 三层治理落地

为防止会话代理在无人值守流程中漂移，实际执行口径固定为三层治理，三层缺一不可：

1. 运行时硬门禁：`tools/test/open_unattended_ab_stage_window.ps1` 负责启动前的强约束。A/B 只认 stage window；B 只有在 A 成功快照真实存在、可解析且满足门禁时才允许启动；失败试启动不得先清空 shutdown / restart 证据。
2. 命令生成硬门禁：takeover brief、poll 输出、trigger/ticket 生成脚本只允许吐出 `open_unattended_ab_stage_window.ps1 -Stage A|B -StartMonitors` 这一类命令，不再给 B 生成 `open_unattended_ab_resume_window.ps1` 路径，也不允许 AI 自行换成 fastmode 直跑入口。
3. 文档与模板硬门禁：操作文档、start-file 模板、RFC 口径保持同一条规则链。用户授权边界、标准入口、A/B 串行条件、A 成功快照约束、票据预授权范围都必须写成固定条款，不给“临时解释”留口子。

### 9.2 硬门禁矩阵

| 层级 | 载体 | 允许动作 | 禁止动作 | 失败结果 |
| --- | --- | --- | --- | --- |
| L1 运行时 | `open_unattended_ab_stage_window.ps1` | `-Stage A -StartMonitors`、`-Stage B -StartMonitors` | 未过预检启动、A 未形成成功快照就启动 B、先清证据再试启动 | 直接阻断并回填原因 |
| L2 发令链 | `poll_agent_tickets.ps1`、`unattended_ab_takeover_trigger.ps1`、`dispatch_takeover_to_chat.ps1` | 输出 `business_command` / `continue_watch_command` 指向 stage window | 为 B 生成 resume window 命令、绕过 stage window 直跑 fastmode | 票据输出与 takeover brief 必须保持空或给出 stage window 命令 |
| L3 授权与口径 | `UNATTENDED_AB_OPERATION_FLOW_CN.md`、`UNATTENDED_AB_START_TEMPLATE_CN.md` | 统一检查 PASS 后向用户提一次启动授权；运行期票据按预授权执行 | 把 READY 当授权、把 resume 当 B 标准入口、把 AI 聊天决定当成流程真相 | 视为流程违规，先纠偏文档/模板/脚本再继续 |

以后凡是做 whois 仓库的 A/B 无人值守任务，都应按以下口径执行：
- 先任务定义，后启动文件，再启动。
- 优先用 `tools/test/check_unattended_ab_launch_ready.ps1` 一次性完成启动前检查，再进入长跑。
- 统一检查脚本日常默认看最后一行 `AB_LAUNCH_READY_RESULT=PASS|FAIL`；只有排障时再加 `-DetailedOutput`。
- 只走仓库现有入口脚本，不新增私有启动脚本。
- 操作入口只认 stage window；A/B 启动与重启都统一走 `open_unattended_ab_stage_window.ps1`；工单/接管脚本生成的恢复命令也只能是 stage window。
- 默认状态文件命名按 start-file 完整路径 stable token 隔离；升级过渡期若仅存在 legacy 旧命名文件，则脚本自动 fallback 并沿用旧文件，避免长会话中途断点。
- 任务定义文件 / RFC 下次开工清单 / 启动文件准备好后都必须先交用户确认。
- AI 在准备阶段不必为每个检查子项逐项申请确认；只有统一检查脚本 PASS 后，才向用户提一次启动授权。
- 只有用户明确发出启动命令后，才允许启动 A/B。
- 正常情况下，应在 VS Code 外部 PowerShell 窗口中执行带 `-StartMonitors` 的主进程入口，由主进程拉起监控链。
- 如果只是从 VS Code 集成终端触发这组命令，也应确认真正承载长跑的是后续弹出的外部 PowerShell 窗口，而不是集成终端本身。
- 若旧的无人值守外部 PowerShell 窗口没有真正关闭，即使其中任务逻辑已经结束，也可能因残留 `powershell.exe` 进程导致统一检查脚本卡在 `PRECHECK_LOCAL_RELATED_PROCESSES=FAIL`。
- VS Code 集成终端仅用于调试。
- A 先于 B，A 不 PASS 不启动 B。
- B 阶段的恢复命令、接管票据建议和人工操作口径都不得再切换到 `open_unattended_ab_resume_window.ps1`；B 只允许 `open_unattended_ab_stage_window.ps1 -Stage B -StartMonitors`。
- A 重启以项目基线为回滚基线；B 重启以 A 成功快照为回滚基线。
- 自愈修复通过“改任务定义 + 静态体检 + 重启本阶段”完成，不通过直接改源码完成。
- 事件驱动票和定时状态票中的既定动作默认预授权执行；AI 不应为既定工单步骤反复向用户要确认。
- 运行中如确需临时脚本，只能放在 tmp，用完删除。
- 运行中靠现有工单、心跳、routine、watch 链路监控。
- 结束后必须回填 RFC，而不是只停留在聊天记录中；但回填前必须先得到用户明确授权。

若会话代理无法正确进入入口脚本，应优先检查：
- 是否已经给出了明确的任务定义文件名
- 是否已经生成并确认 start-file
- 是否错误地尝试“重写一套新脚本”或直接调用 fastmode 负载脚本，而不是调用既有窗口包装器入口
- 是否忘记先通过静态体检与预检硬闸


## 10. 源码自愈修复规则与 fast-pass 流程

### 设计目的

该规则解决了动态、增量方式定位变更后静态检测中的源码对齐问题：

- **task-static 阶段故障**：独立 checker 尚未授权写入，当前源码仅被之前轮次修改过；任务定义可按故障 op 边界修复。
- **code-step 阶段故障**：只发生在绑定产物读取、哈希/契约验证、原子写入或写后验证过程中，统一属于非代码故障，不授权修改任务定义或源码。
- **编译/验证阶段故障（D1-D4 内）**：当前源码已被故障所在轮次的已有操作修改过，静态检查仅验证新增 op 的入口匹配性，不检查原有停止匹配的 op。
- **V1-V4 故障**：当前源码为 D1-D4 全部执行完成的最终状态，在 D4 追加 op 的静态检查仅验证新增 op 与最终源码的对齐。

此规则使源码自愈修复操作流程更加规范化，减少因代码基线偏移导致的静态检查误判。

### 10.1 源码自愈修复规则

自愈修复的源码修改应通过变更当前阶段任务定义文件中所在轮次的任务定义进行，而非直接编辑源文件。

核心约束（按故障阶段和故障类型区分）：

#### 10.1.1 故障类型说明

每个开发轮次（D1/D2/D3/D4）内部包含三个子阶段：
1. **task-static 阶段**——独立 checker 在内存中执行 operation、replay、断言和 effective-source 检查，生成哈希绑定产物
2. **code-step 阶段**——读取绑定产物、验证 manifest 与摘要、原子写入、写后验证，不执行任务定义业务判定
3. **编译/验证阶段**——该轮次源码改动完成后，执行编译和验证，并进一步区分代码故障与非代码故障

因此故障可能发生在以下场景：

- **task-static 阶段故障（D1-D4 轮次内）：**
  - 发生在独立 checker 执行 operation、replay、断言或 effective-source 检查期间
  - 故障原因通常是 operation 的 pattern 无法匹配当前源码、regex/replacement 错误、marker/replay 不收敛或断言失败
  - 此时该轮次的源码改动尚未生效
  - 修复方式：只可前向变更任务定义：D1 故障可改 D1-D4，D2 可改 D2-D4，D3 可改 D3-D4，D4 仅可改 D4；不得改前置 D 轮。当前故障 op 之前为只读，可从故障 op 起修改、增加、删除对应 operation。

- **code-step 阶段故障（D1-D4 轮次内）：**
  - 发生在“读绑定产物 -> 验证 manifest/摘要 -> 原子写 -> 写后验证”过程
  - 无论具体 kind/category 或异常文本为何，均进入非代码故障流程
  - 禁止通过修改任务定义或源码处理；先确认阶段业务进程已停，再按 noncode 流程检查产物新鲜度、路径、权限、锁、磁盘和状态文件，并由标准阶段入口重新生成绑定产物

- **编译/验证阶段故障（D1-D4 轮次内）：**
  - 发生在该轮次 code-step 已成功执行、源码已被该轮次改动过后，在随后的编译或验证步骤中失败
  - 此时该轮次的源码改动已经生效，当前轮次的源码已被修改
  - 必须先依据结构化 `failure_category` 和证据区分代码故障与非代码故障；编译器不可用、权限、磁盘、网络、远程锁、测试基础设施等进入 noncode，不得因 `compile-failure` / `verify-failure` 名称直接触发代码修复
  - 仅当确认是源码编译、链接、业务逻辑或输出契约故障时，才进入代码修复：只可前向变更任务定义；由于该轮既有 operation 已执行完毕，只能在故障轮 `operations` 末尾连续追加一个或多个 op

- **V1-V4 轮次故障：**
  - V1-V4 轮次是纯验证轮次，不涉及源码改动
  - 故障通常由系统软硬件环境、网络环境等非代码因素引起；若为验证失败（编译通过但逻辑验证未通过），则与源码的业务设计有关
  - 修复方式：属于非代码故障的走环境/监控链稳定化流程；需要修改业务逻辑时，只能在 D4 轮次既有 operations 的末尾追加 op，不可修改/删除 D1-D4 原有已通过编译验证的 op。

#### 10.1.2 通用约束

- 静态检查通过后，重启主进程，源码会自动恢复到阶段基线：
  - **A 阶段基线**：仓库中上次提交推送后形成的基线（git HEAD）
  - **B 阶段基线**：A 阶段完成时的源码及源码快照
- A PASS 快照必须包含 `source_manifest.json`，逐文件记录规范化相对路径、字节长度和 SHA-256。guard 在快照生成后立即自校验；B 启动前必须校验 manifest、实际文件树以及 A 任务定义允许的目标集合，任何缺失、篡改、额外源码或越权路径都 fail-close。
- B 从 A PASS 快照恢复后必须逐文件复核目标工作区哈希，并在编码门禁结束后再次复核。旧快照若缺少 manifest，不得兼容降级或直接启动 B，应重跑 A 生成新快照。
- 脚本按照任务定义文件中各轮次的顺序依次执行源码的改动
- **绝对禁止 AI 直接修改源码**——所有变更须通过任务定义的 operation 间接实现

### 10.2 启动任务定义静态检查

A/B 启动入口只执行 `check_task_definition_static.ps1 -SyntaxOnly`：确认任务定义文件存在且为普通文件、JSON 可解析、`targetFile` 非空、`rounds` 存在且非空。入口不读取目标源码，不检查 D1-op1，也不执行任何 operation 正则。装载失败必须在 launcher 硬阻断，不得用 `runtime-ticket` 延迟到主流程。

每个 D 轮在 code-step 前执行独立 checker。checker 将当前目标源码作为轮次基线，在内存副本上逐 op 检查唯一匹配、替换、安全 marker、收敛与正则时限，当前 op 全部通过后才推进到下一 op，首错立即停止。整轮 operations 通过后还必须通过 replay、`postApplyAssertions` 和 effective C source 语法检查，随后生成有效源码临时文件及 `TASK_STATIC_VALIDATED_ARTIFACT_V1` manifest。manifest 绑定 stage、round、任务定义路径与 SHA-256、目标路径、基线源码 SHA-256 和有效源码 SHA-256。

code-step 不重复运行 checker，只消费独立 checker 生成的绑定产物。写回前必须重新校验任务定义、当前目标源码和有效源码的 SHA-256；任一不匹配均 fail-close，不修改源码。全部绑定通过后，code-step 才以同目录临时文件替换方式原子写回。checker 失败对应 `TASK-STATIC-FAIL / task-static / task-definition-mismatch`，且不会进入 code-step。独立 gate 不允许关闭，且必须执行完整轮次；`RoundTaskStaticGateOperationIndex` 必须为 0，局部 op 快检只供人工诊断，不得生成可写回产物。

checker 按仓库使用 named Mutex 单实例运行。第二实例不等待，输出 `single_instance_conflict=true` 并返回 4。明显嵌套量词在进入正则引擎前拒绝，正则本身有 timeout，外层 worker 也有总时限；任何超时均按失败处理。

### 10.3 常规流程

```
A/B 启动
  → 任务定义 SyntaxOnly 装载门禁
  → D1（独立 checker fail-fast → code-step 原子应用绑定产物 → strict build gate）
  → D2（独立 checker fail-fast → code-step 原子应用绑定产物 → strict build gate）
  → D3（独立 checker fail-fast → code-step 原子应用绑定产物 → strict build gate）
  → D4（独立 checker fail-fast → code-step 原子应用绑定产物 → strict build gate）
  → V1（verify round）
  → V2（verify round）
  → V3（verify round）
  → V4（verify round）
```

### 10.4 fast-pass 流程（自愈修复后）

自愈修复仅发生在某一轮次，之前已验证通过的轮次无需再次完整验证。fast-pass 流程前缀带有 **"Fast-"** 标记表示该轮跳过了冗重的全量验证（仍执行 code-step，跳过 smoketest/golden 等验证集）。

fast-pass 只适用于故障轮之前的 DEV 轮。D1 修复没有前置 DEV 轮，因此 D1-D4 都必须完整执行，D2-D4 的 runtime gate 也不得因 fast-pass 被关闭。只有 D4 或 V1-V4 恢复属于“恢复锚点之后没有 DEV 轮”的场景；V1-V4 恢复统一以 D4 作为完整 code-step、编译与验证锚点。

**自愈修复发生在 D1：**
```
A/B 启动
  → 任务定义 SyntaxOnly 装载门禁
  → D1 → D2 → D3 → D4 → V1 → V2 → V3 → V4
```

**自愈修复发生在 D2：**
```
A/B 启动
  → 任务定义 SyntaxOnly 装载门禁
  → Fast-D1 → D2 → D3 → D4 → V1 → V2 → V3 → V4
```

**自愈修复发生在 D3：**
```
A/B 启动
  → 任务定义 SyntaxOnly 装载门禁
  → Fast-D1 → Fast-D2 → D3 → D4 → V1 → V2 → V3 → V4
```

**自愈修复发生在 D4：**
```
A/B 启动
  → 任务定义 SyntaxOnly 装载门禁
  → Fast-D1 → Fast-D2 → Fast-D3 → D4 → V1 → V2 → V3 → V4
```

**自愈修复发生在 V1-V4：**
```
A/B 启动
  → 任务定义 SyntaxOnly 装载门禁
  → Fast-D1 → Fast-D2 → Fast-D3 → D4（在 D4 追加 operation） → V1 → V2 → V3 → V4
```

> **说明：** 故障发生在 V1-V4 轮次时，优先将增量补丁追加到 D4 轮次的现有定义后面，而非改写已经过编译验证的 D1-D4 轮次定义。

### 10.5 自愈修复中 AI 修改任务定义后的静态检查规则

AI 在自愈修复中变更完成所在阶段任务定义文件里对应开发轮次的任务定义后，应基于当前源码执行任务定义静态检查。检查策略按故障类型区分如下：

静态检查是重启前的阻断门禁：若检查失败，AI 必须根据检查诊断继续在本节规定的允许修改边界内修复任务定义，并重新运行静态检查；只有检查通过后才可重启主进程完成自愈。若无法在不违反修改边界或其他门禁的前提下通过检查，必须报告阻塞并停止重启，禁止绕过或忽略失败结果。

静态检查按以下顺序执行：

1. **装载检查**：运行 `-SyntaxOnly`，验证文件、JSON 和基础结构。
2. **目标 op 快检**：task-static 故障可用 `-RoundTag <Dn> -OperationIndex <n>` 顺序模拟只读前置 op，只检查目标 op。
3. **当前故障轮递进严格检查**：重启前运行不带 `-OperationIndex` 的 `-RoundTag <Dn>`。checker 从 op1 开始，当前 op 通过才推进内存副本；首错立即停止。仅当本轮全部 op 通过才执行 replay 与 `postApplyAssertions`。

不再要求恢复前检查“所有受影响的后续 D 轮”。跨轮次编辑边界仍然有效，但未来轮的业务语义必须在实际执行到该轮时由 code-step 检查；未来轮缺陷不得提前阻断当前故障轮恢复。

修改或追加 operation 时，必须同步维护所在轮的 `postApplyAssertions`。断言变更仅可描述允许编辑范围内 operation 产生的结构结果，不得借机改变前置只读 op 的既有契约；若现有断言仍准确，则保持不动。

自愈修复不得把失败的 `regex-patch` 轮改成 `type=noop` 来消除 pattern、marker、replay 或断言错误。若执行时发现目标已由前置轮吸收，保留 `regex-patch` 并补齐逐 op 幂等证据；只有在该轮执行前已明确确认“从设计上无代码变更目标”、整轮均处于允许编辑范围、且不存在已执行或只读 operation/契约时，才可按 4.2.1 的空轮结构定义为 `noop`。不能满足这些条件时必须继续修复任务定义或报告阻塞，不得以 `noop` 绕过静态门禁。

#### 10.5.1 D1-D4 轮次内 task-static 阶段故障

故障发生时独立 checker 尚未生成可提交的绑定产物，该轮次的源码改动尚未生效。AI 修改任务定义后，先运行 `-SyntaxOnly`，可定位时对当前 op 执行一次目标快检，再对当前故障轮执行递进严格检查。使用 `-OperationIndex` 时，checker 会按顺序模拟同轮 op1 至 op(n-1) 来构造目标输入，但只把 op(n) 作为目标检查；前置 op 仍为只读，不因模拟而扩大编辑范围。

若修复涉及 helper 前向声明，必须保留 helper 的函数定义；若首次 caller 调用之前没有 prototype，则在 caller 前添加，并删除 caller 调用之后或其他位置的重复 prototype。修复完成后，同一 helper 必须恰好保留一个 prototype，且位于首次 caller 之前。自动注入过程必须将“删除旧 prototype + 插入 caller 前 prototype”作为原子归一化操作，任一步失败都不得写入部分结果或持久化不完整 operations。

任务定义编辑边界（D1-D4 task-static 阶段失败，`task-definition-mismatch`）：
- 跨轮次范围只能前向：D1 -> D1-D4，D2 -> D2-D4，D3 -> D3-D4，D4 -> D4；不得回改任何前置 D 轮。
- 当前故障 op 之前的 op 为只读；仅允许从故障 op 位置起修改、删除、插入或追加 op。
- 静态门禁只验证当前故障轮；允许修改的后续轮在各自实际执行时验证，不得借此扩大前置轮编辑范围。

- 若该轮次有**修改**或**追加**的 op，则先静态检查编辑后的当前故障 op；若在其前方删除或插入了允许编辑的 op，`OperationIndex` 使用编辑后的实际索引
- 若该轮次仅有**删除**的 op：
  - 先目标检查删除位置之后的第一个 op（按编辑后排序）
  - 若删除的是最后一项，则没有目标 op 快检，但仍必须执行当前轮递进严格检查
- 若同一轮次同时存在修改/追加和删除的 op：
  - 目标检查编辑后最靠前的修改/追加 op；若其前方删除导致索引变化，使用新索引
  - 目标检查通过后仍须执行当前轮递进严格检查，不能跳过 replay 和断言验证

#### 10.5.2 D1-D4 轮次内编译/验证阶段故障

只有该阶段经分类确认是代码故障时才适用本节；若为权限、磁盘、网络、远程锁、工具链不可用或测试基础设施故障，必须进入 noncode 流程且不得修改任务定义。代码故障发生时该轮次的源码改动已经生效（code-step 已成功执行），当前源码状态为该轮次改动完成后的状态。由于该轮次原有 op 已经执行完毕，目标 op 快检按该轮次所**追加 op** 的排序，以**最靠前优先原则**进行一次；随后基于正确阶段基线对当前轮运行递进严格检查：

- 先目标检查该轮次排序最靠前的新追加 op
- 不检查该轮次原有 op（原有 op 的 pattern 在当前已被该轮次修改过的源码上可能不再匹配，属于预期行为）
- 重启前基于正确阶段基线执行当前轮递进严格检查，验证原有 op 与追加 op 的顺序 replay 和断言

#### 10.5.3 V1-V4 轮次故障

V1-V4 是纯验证轮次，当前源码状态为 D1-D4 全部执行完成后的最终源码。若需要修改业务逻辑，只能在 D4 轮次**既有 operations 的末尾**连续追加一个或多个 op；不得改 D1-D3，也不得修改或删除 D4 原有 op。先目标检查 D4 最靠前的新追加 op；随后基于正确阶段基线对 D4 运行递进严格检查：

- 先目标检查 D4 轮次排序最靠前的新追加 op
- 不检查 D4 轮次原有 op（原有 op 的 pattern 在 D1-D4 已全部执行完成的最终源码上可能不再匹配，属于预期行为）
- 重启前递进检查 D4 的原有 op 与追加 op，验证完整顺序 replay 和断言

#### 10.5.4 低成本模型任务定义编辑最小操作清单（GPT-5 mini 等）

- 只改允许范围内的 `rounds.<Dn>.operations`；仅当 operation 的结构结果变化时同步更新同轮 `postApplyAssertions`。不要改 `rounds` 键名、轮次编号、顶层 schema 字段或前置只读契约。
- 先定位“当前故障 op”在 operations 中的索引；索引之前的 op 只读，禁止修改。
- 允许动作仅限当前故障 op 及其后续：修改该 op、在其后追加新 op、删除其后不再需要的 op。
- 每次编辑后，保持 operations 内 op 顺序稳定；不要因为格式化或重排导致语义漂移。
- 修改 pattern/replacement 时必须同时保证：唯一命中、可落地替换、marker 由自身 replacement 唯一产生、替换后 pattern 零命中、整轮 replay 不变、精确断言通过。若无法唯一命中，优先在允许边界内追加新 op，不要强改前置 op。
- 不得用 pattern 与 replacement 相同的自替换 op 表示空轮，也不得把失败或被前置轮吸收的 `regex-patch` 改成 `noop`。设计时确无代码目标才使用最小 `type=noop` 结构；运行时吸收仍保留 `regex-patch` 和逐 op 幂等证据。
- 重启前先跑 `-SyntaxOnly`，可定位时跑目标 op 快检，再跑当前故障轮递进严格检查；若失败，继续在当前故障 op 及其后续修复，禁止回头改前置 op或预演后续轮。

### 10.6 D/V 轮次任务定义设计补充规则

#### 10.6.1 改动量评估优先

先评估代码改动量：
- **追加模式（优先）**：改动量小，在当前 D 轮次末尾追加 op 补丁。
- **重构模式（备选）**：改动量大，则重设计当前 D 轮次所有 ops。仅当追加模式导致 ops 数量膨胀或语义混乱时选用。

#### 10.6.2 孤儿函数体检查

修改 D 轮次任务定义后，务必检查该轮次中每个 op 是否在源码中遗留了**孤儿函数体**。当 op 的 pattern 只匹配函数签名而不匹配其函数体时，签名被替换后原函数体将残留为悬空代码块，导致编译错误。

修复方式必须服从 10.5 的编辑边界：code-step 故障且问题 op 位于可编辑范围内时，可修改该 op 的 pattern 使其一次消费完整原函数体；编译/验证或 V 轮故障时既有 op 只读，只能在允许轮次末尾追加清理 op。不得为了消除孤儿体回改前置轮或当前故障 op 之前的只读 operation。无论采用哪种方式，都应补充精确断言证明旧孤儿形态为 `0`，并完成整轮严格检查。

#### 10.6.3 契约约束

D 轮次代码设计必须基于 whois 项目的整体方案，包括但不限于：
- 项目架构文档与 RFC（`docs/` 目录下），当前代码改动涉及的具体方案见 [RFC-address-space-preclassifier.md](RFC-address-space-preclassifier.md)。
- 输出契约（标题行、尾行、折叠行格式等），详见 [USAGE_CN.md](USAGE_CN.md) 与 [USAGE_EN.md](USAGE_EN.md)。
- IPv4/IPv6 查询规则契约，详见 [RFC-ipv4-ipv6-whois-lookup-rules.md](RFC-ipv4-ipv6-whois-lookup-rules.md)。
- DNS 与重试策略契约（v3.2.8–v3.2.9 冻结），详见 [RFC-dns-phase2.md](RFC-dns-phase2.md)、[RFC-dns-phase4-ip-health.md](RFC-dns-phase4-ip-health.md)。

Step47 矩阵契约是不可逾越的红线，不得因代码变更改变其预期结果。

#### 10.6.4 预算耗尽与待办修复的优先级（2026-07-05）

当收到 `budget-exhausted-stop` 通告时，若此前同一会话中已有一张 `incident-captured`（或类似）票据允许了 `code-fix-workflow` / `script-fix-workflow` 但尚未执行对应的修复动作，则**先完成已有修复后再处理预算通告**。

这里的优先级只沿用先前事故票已经授予的权限；`budget-exhausted-stop` 自身不新增文件修改、环境变更、resume 或重启权限。预算通告本身仍只执行 rerun 范围决策与原子收尾。

- `budget-exhausted` 仅限制 guard 自动重启次数，不影响 task-definition 修复的手动执行。
- 修复完成并静态检查通过后，按 rerun-scope-decision 的结论重启对应阶段（A 或 B），**不要等待额外的人工确认**。
- `budget-exhausted` 的 `blocked_actions` 不影响 Agent 在修复后通过 launcher 手动重启。

#### 10.6.5 防无限循环保护（2026-07-05）

Agent 在每次重启对应阶段前，应将当前故障的 `main_round` + `failure_fingerprint` 写入 session memory（`/memories/session/last_failure.md`）。重启后若收到新的 `incident-captured` 票据，其 `main_round` 与 `failure_fingerprint` 均与 session memory 中记录的上一次一致，则判定为**同一故障点连续失败**。此时 Agent 应停止自动重启，向用户报告修复未生效，等待人工介入。

session memory 中的记录应在以下任一条件满足时清除：
- 新的故障指纹与上次不同（修复已改变故障表现）
- 该阶段全部 8 轮完成且未再触发同一故障

具体判断流程：

```
收到 incident-captured
  ├─ 读取 /memories/session/last_failure.md
  │   └─ 文件不存在或无记录 → 正常处理，写入本轮故障信息
  ├─ main_round 与 failure_fingerprint 均与上次一致
  │   └─ → 判定为连续重复失败 → 停止重启，报告用户
  └─ main_round 或 failure_fingerprint 不一致
      └─ → 正常处理，更新 session memory 中的故障信息
```

#### 10.6.6 代码修复相同指纹门禁与重试预算（2026-07-21）

相同指纹只有在“代码修复已经实施并重启后，同一代码故障再次出现”时才有阻断意义。因此该门禁只用于编译/验证阶段经结构化证据确认为代码故障的分支。

- 适用范围：仅 `compile/verify` 且结构化分类明确为代码故障。
- `task-static` 不适用：修复有效性由 `SyntaxOnly`、可定位时的目标 op 检查和当前轮递进严格检查确定；检查通过后不得再用历史运行指纹阻断恢复。
- `code-step` 不适用：该阶段只读取、验证、原子写入并写后验证绑定产物，不直接设计代码修改；任何故障均属于 noncode。
- 脚本、工具链、权限、磁盘、网络、远程锁、测试基础设施及未知分类不适用，按各自 noncode/人工判定流程处理。
- 状态机：`pending_review -> override_window -> hard_block`。
  - `pending_review`：检测到相同指纹，进入待评审态。
  - `override_window`：满足重试条件后放行一次重启窗口。
  - `hard_block`：预算耗尽或证据不足，转人工处置，禁止自动重启。
- 默认预算：`CODEFIX_IDENTICAL_FP_MAX_RETRIES=3`（可用 stage 级键覆盖：`A_CODEFIX_IDENTICAL_FP_MAX_RETRIES` / `B_CODEFIX_IDENTICAL_FP_MAX_RETRIES`）。
- 该预算只统计“修复后重启主进程，仍再次产生相同 `stage + main_round + phase + failure_fingerprint`”的恢复尝试；`task_start_at` 仅作为证据字段，不参与清零预算。该预算不限制单张自愈工单内调用 checker 的次数。代理可按首错诊断依次修复 op1、op2……并反复运行目标 op 快检和当前轮严格检查，直至本轮通过或确认阻塞；这些未重启主进程的本地检查不消耗相同指纹预算。
- 第 2/3 次重试必须有“有效修复证据”，否则直接进入 `hard_block`：
  - 任务定义文件哈希变化；或
  - 轮次级任务定义印记（round operations imprint）变化；或
  - 轮次源码摘要变化。

实现约束：

- 相同指纹比较以 `stage + main_round + phase + failure_fingerprint` 为主键，跨 stage 启动窗口累计；`task_start_at` 只用于审计和定位，不得触发重试状态重置。
- 指纹滚动时必须同时写回当前/上一次证据字段：
  - `*_FAILURE_TASKDEF_HASH` 与 `*_PREVIOUS_FAILURE_TASKDEF_HASH`
  - `*_FAILURE_SOURCE_HASH` 与 `*_PREVIOUS_FAILURE_SOURCE_HASH`
  - `*_FAILURE_TASKDEF_ROUND_IMPRINT_HASH` 与 `*_PREVIOUS_FAILURE_TASKDEF_ROUND_IMPRINT_HASH`
- 门禁状态字段建议统一：
  - `*_CODEFIX_IDENTICAL_FP_RETRY_COUNT`
  - `*_CODEFIX_IDENTICAL_FP_STATE`
  - `*_CODEFIX_IDENTICAL_FP_STATE_AT`

人工修复后的解锁规则：

- `hard_block` 并非永久封禁。
- 人工修复完成后，若检测到“有效修复证据”且静态检查通过，可自动从 `hard_block` 回到 `pending_review`，重置同指纹预算后允许重启。
- 若无有效修复证据，保持 `hard_block`，不得重启。

