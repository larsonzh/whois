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
- 进入无人值守运行期后，事件驱动票与定时状态票中列出的既定动作属于预授权执行项；AI 应直接执行工单工作流，不应为 `business_command`、`continue_watch_command`、`mark_processed_command`、`handled_at` 回执再向用户逐项征求确认。
- 当票据或 brief 中给出 `ticket_closure_check_command`、`event_dedup_health_check_command`、`final_status_closeout_command`（以及 final-status 场景的 `final_status_closeout_apply_ack_command`）时，应在 route guard 通过后按 `next_command_order` 执行；`chat-session-final-status` 优先执行 final-status 收口链。
- 事件驱动票具有高优先级，始终凌驾于 `normal/anti-missent/low-disturb/event-only` 模式之上；事件票处理标准在所有模式下保持一致，不受模式降级影响。
- `event-only` 仅定义“是否触发/发送常规状态票”的调度策略，不得在事件票或故障处置话术中表述为“按 low-disturb 流程执行”。
- 对 healthy 的 `running-status-report`，根因应写成“无活动故障/常规定时状态票”，修复路径应写成“continue_watch only”；不得仅凭旧失败摘要、旧 `latest_b_exit.json` 或历史 exit artifact 推断需要重启 B。
- 模式仅影响“非故障状态票”的对话密度与展示形式；一旦进入自愈修复/故障处理期（含 `route_guard_expected != status-health-check-only`），状态票回复标准必须强制提升到 normal 口径，问题闭环后再回归原模式。
- 运行期不得手工创建新的 `chat_heartbeat*.jsonl`、`handled_tickets/*.md` 等临时回执产物；应仅使用现有脚本输出的 ledger/heartbeat。
- 运行期不得在未获用户明确同意时创建非 `tmp/` 新脚本，也不得偏题提出 PR、服务化改造或其他超出当前票据闭环的实施方案。
- 无人值守运行期间禁止执行提交与推送操作（如 `git commit` / `git push`）；仅在用户明确同轮授权后，才可进入版本控制提交发布步骤。

### 2.7 自愈修复与故障处理原则

- 代码自愈修复不允许直接手改源码；必须修改当前阶段任务定义文件中对应轮次的代码改动内容。
- 修改任务定义文件后，必须先通过 `tools/test/check_task_definition_static.ps1` 静态检测，再重启本阶段主进程。
- 自愈发生在 A 阶段：从 A 阶段开始处重启；A 主进程会自动把源码回滚到项目基线后再执行本轮任务定义。
- 自愈发生在 B 阶段：从 B 阶段开始处重启；B 主进程会自动以 A 结束时的成功快照为基线回滚后再执行本轮任务定义。
- 故障处理优先顺序固定为：留证 -> 修改本阶段任务定义 -> 静态体检 -> 用 stage window 重启本阶段 -> 恢复监控链。

### 2.8 临时脚本约束

- 运行中优先使用项目现有脚本。
- 如确需创建临时脚本，只能放在 tmp 目录下。
- 临时脚本用完即删，不得沉淀为新的长期入口。

### 2.9 票据路由预检闸门（强制）

- 每次接管票据前，先执行 route guard 预检脚本：
	- `powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_takeover_route_guard.ps1 -BriefPath <takeover_brief_path> -QueuePath out/artifacts/ab_agent_queue/agent_tickets.jsonl -AsJson`
- 必须按 `route.classification` 进入对应分支，不允许跳步：
	- `status-health-check-only`：仅执行最小健康检查（business_command）+ continue_watch + handled_at，禁止 stage restart/business_resume。
	- `incident-auto-resume-script-fix` / `incident-manual-script-fix`：脚本自愈专用流程（guard/trigger/dispatch/poll），先报根因与脚本修复路径；manual 分支需先报阻断条件，不得盲目 resume。
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
- 当本期事件票排空后，执行链自动回到进入事件处置前的工作模式（`normal/anti-missent/low-disturb/event-only`），继续常规轮询与监控节奏。
- 运行期观测锚点（用于快速确认门控生效）：
	- 放行：`external_trigger_route_allowed` / `final_status_trigger_route_allowed`
	- 阻断：`external_trigger_blocked` / `final_status_trigger_blocked`
	- 后续执行：`external_trigger_started` 或 `external_trigger_failed`

一句话关系：
- 用户负责授权与确认。
- 脚本负责执行与落盘。
- AI 负责整理、辅助、解释和按既有入口驱动脚本。

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

### 4.3 阶段 2：静态体检任务定义文件

目的：在启动前发现任务定义错误，而不是运行到中途才失败。

参数速览（`tools/test/check_task_definition_static.ps1`）：
- `-TaskDefinitionFile <path>`：必填，任务定义 JSON 文件。
- `-RepoRoot <path>`：可选，仓库根目录（默认自动解析到当前仓库）。
- `-Policy off|warn|enforce`：可选，默认 `enforce`；`off` 直接跳过。
- `-FailOnWarnings`：可选，开启后 warning 也会按失败返回（建议无人值守门禁开启）。
- `-RoundTag D1..D4|V1..V4`：可选，只检查指定轮次。
- `-OperationIndex <n>`：可选，只检查指定轮次中的第 n 个 operation；必须与 `-RoundTag` 一起使用。

示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261031_20261107.json -Policy enforce -FailOnWarnings
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261108_20261115.json -Policy enforce -FailOnWarnings

# 仅检查 A 的 D1 第 1 个 operation（启动前基线检查常用）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261031_20261107.json -Policy enforce -FailOnWarnings -RoundTag D1 -OperationIndex 1

# 仅检查某个验证轮（例如 V2）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261108_20261115.json -Policy enforce -FailOnWarnings -RoundTag V2
```

通过标准：
- 不残留 TODO
- 不存在 replacement 双转义风险
- pattern 唯一匹配
- 目标锚点可达

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

启动文件中必须确认的关键项：
- `ENTRY_MODE=single-param-fastmode`
- `ENTRY_SCRIPT_A` / `ENTRY_SCRIPT_B` 保持模板默认值，不作为人工/AI 手工执行命令使用
- `RUN_MODE=foreground-visible`
- `A_FAILURE_BLOCKS_B=true`
- `B_START_REQUIRES_A_PASS_WITH_SNAPSHOT=true`
- `PRECHECK_REQUIRED=true`
- `TASK_STATIC_PRECHECK_POLICY=enforce`
- `TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS=true`

如果要低打扰或 event-only：
- 只改 `AI_CHAT_POLICY_WORK_MODE`
- 不要手工随意发明一整组派生键
- 模式差异只作用于“非故障状态票生成/分发与回执文本密度”；不应关闭事件票（如 `incident-captured`、`task-definition-fix-required`）的自愈闭环能力。
- 对 `running-status-report` 的主进程健康检查，`normal/anti-missent/low-disturb/event-only` 都应保留“进程缺失 -> 脚本自愈+事件票升级”的能力。
- 当状态票触发故障处理或自愈动作时，回复与回执应立即切换到 normal 标准；闭环完成后恢复原工作模式。
- 对 B 阶段可恢复编译类故障（含任务定义失配导致的编译失败），route guard 应进入 `incident-auto-resume-code-fix`，执行 `fix -> verify -> business_resume -> continue_watch -> handled_at`。

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
- 按阶段执行静态体检：
	- `Stage=A`：执行 A 基线静态体检（`A_TASK_DEFINITION` 的 `D1:op1`）
	- `Stage=B`：跳过启动前静态体检（由运行期 fail-fast 静态门禁兜底）
- 执行启动文件字段同步检查
- 执行 `tools/test/status_ticket_mini_regression.ps1` 迷你回归门禁
- 执行 `tools/test/route_guard_smoke_suite.ps1` 门禁
- 执行 `tools/test/check_ps51_format_inline_if_guard.ps1 -Scope tracked` 门禁
- 执行增量编码检查（基于 `git diff --name-only`）
- 非 DryRun 场景下，先自动修复增量不合规编码，再继续全量硬门禁检查
- 执行 tracked 文件编码门禁（`tools/dev/enforce_utf8_bom_lf.ps1 -Mode check -Policy enforce -Scope tracked`）
- 执行 src 变更编码门禁（`tools/dev/enforce_utf8_lf_src_changed.ps1`）
- 执行预检并回填 `PRECHECK_*`

返回约定：
- 任一步失败，立即返回 `step`、`status=FAIL`、`reason`，并停止后续步骤。
- 全部通过，返回 `step=launch-ready`、`status=PASS`，表示当前 A/B 任务已具备启动条件。
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
- `tools/test/check_unattended_ab_launch_ready.ps1` 在非 `-DryRun` 场景会先执行增量自动修复，再执行全量硬门禁。
- `-DryRun` 场景只做增量检查，不落盘修改。
- `start_dev_verify_fastmode_A.ps1` 与 `start_dev_verify_fastmode_B.ps1` 在启动前会依次执行：文本增量编码门禁（BOM+LF）和 src C 源码增量门禁（UTF-8+LF，无 BOM），降低 A->B 切换期因编码问题中断的概率。

取舍建议（减少运行期开销）：
- 启动前预检阶段仍保留一次全量 `-Scope tracked` 硬门禁，保证“可提交工作区”质量下限。
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
- 会话轮询 `poll_agent_tickets.ps1`
- 执行 `business_command`
- 执行 `continue_watch_command`
- 执行 `handled_receipt_command`（写入 `handled_at`）
- 执行 `validate_receipt_command`（硬校验 `handled_at`；默认沿用与 `poll_agent_tickets.ps1` 一致的稳定 ledger 路径，不需要手工补 `-LedgerPath`）
- 执行 `mark_processed_command`

运行期执行规则：
- 事件驱动票和定时状态票中的工作内容视为预授权操作，AI 在无人值守运行期间应直接执行，不再向用户逐条确认。
- 对 `running-status-report` 这类需要 handled 收据的工单，必须立即写入 `handled_at`；`handled_at` 是强制项，不可省略。
- `handled_at` 现在应优先作为 `poll_agent_tickets.ps1` ledger 中的一等状态字段理解；额外的 `handled_tickets/*.md` 仅在显式开启 `LOCAL_GUARD_WRITE_HANDLED_ARTIFACTS=true` 时才写入，不再作为默认必需产物。
- 对 healthy 的 `running-status-report`，默认处置应为“最小健康检查 + continue_watch only”；不得因为历史失败证据或旧 exit 文件自动上升为 B 重启建议。
- 默认执行顺序固定为：`business_command -> continue_watch_command -> handled_receipt_command -> validate_receipt_command -> mark_processed_command`。
- 若票据附带检查器命令，执行顺序扩展为：`... -> post_check_command -> ticket_closure_check_command -> event_dedup_health_check_command -> final_status_closeout_command`（仅在命令存在时执行）。`chat-session-final-status` 可继续执行 `final_status_closeout_apply_ack_command` 完成收口确认。
- 若 `validate_receipt_command` 未检测到有效 `handled_at`，应自动补发 `handled-receipt-reminder` 工单（轻量提醒票）并阻断本票 `mark_processed`，不得仅靠人工观察补救。
- 聊天输出层（relay/转录）校验默认关闭，不作为常态强门禁；该层信号仅作为辅证，不替代 ledger 的强约束状态。
- 仅在故障排查或专项验收窗口临时启用聊天输出层校验，且建议抽样执行，避免高频轮询带来的额外资源开销与交互抖动。
- 只有以下情形才需要重新请求用户指令：用户明确下达 `stop monitoring`；需要跨阶段改计划；需要更换 start-file；需要执行超出当前票据既定工作流的高风险动作。
- 若工单处理过程中确需辅助脚本，优先调用现有脚本；确需临时脚本时，只能放在 tmp，下游动作完成后删除。
- 不得手工补写 `chat_heartbeat*.jsonl`、`chat_heartbeat_reports_additional_*.jsonl` 或额外 handled 回执文件来“模拟完成”；应使用 `tools/test/update_chat_session_heartbeat.ps1` 与 `poll_agent_tickets.ps1 -AcknowledgeTicketIds ...` 的正式链路。

示例：

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
		- 规则：修改位置取决于故障阶段。
			- **[D1-D4 code-step 阶段失败]（code-edit-failure / task-definition-mismatch）**：源码尚未被该轮次修改。可在该轮次内修改/追加/删除 op。
			- **[D1-D4 code-step 阶段已通过，但编译/验证阶段失败]**：源码已被该轮次修改。在**该轮次 operations 数组末尾追加新 op**，不可修改或删除原有 op。
			- **[V1-V4 验证阶段]（不是 JSON 轮次键名——只有 D1-D4 是轮次条目）**：将修复作为新 op 追加到 **D4 operations 数组末尾**，不得创建 V1-V4 轮次条目。
	- `incident-auto-resume-noncode` / `incident-manual-noncode`：只做环境、监控链、瞬态故障稳定化，不改源码也不改任务定义。
	- `notice-manual-wait` / `notice-budget-exhausted` / `notice-known-infra-transient`：只报阻塞、预算或基础设施状态并回执，不进入自愈重启。
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

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md
```

补充：
- 默认 reset 会恢复未运行态字段并保留当前模式（normal/anti-missent/low-disturb/event-only）。
- 若需“按当前模式回到模板基线”，可显式传 `-UseTemplateBaseline`：该模式会委托 `tools/test/create_unattended_ab_start_file.ps1` 按“当前 start-file 文件名 + 当前模式（`AI_CHAT_POLICY_WORK_MODE`，缺失回退 `normal`）”重建并覆盖当前文件。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -UseTemplateBaseline -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -UseTemplateBaseline
```

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
- AI 直接执行 `business_command -> continue_watch_command -> handled_receipt_command -> validate_receipt_command -> mark_processed_command`
- 若票据返回了闭环/去重/收口命令，则继续按 `next_command_order` 执行对应检查器命令并回传结果摘要。
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

- **code-step 阶段故障**：当前源码仅被之前轮次修改过，尚未被当前轮次修改，静态检查可验证当前轮次最靠前的修改/追加 op 的入口匹配性。
- **编译/验证阶段故障（D1-D4 内）**：当前源码已被故障所在轮次的已有操作修改过，静态检查仅验证新增 op 的入口匹配性，不检查原有停止匹配的 op。
- **V1-V4 故障**：当前源码为 D1-D4 全部执行完成的最终状态，在 D4 追加 op 的静态检查仅验证新增 op 与最终源码的对齐。

此规则使源码自愈修复操作流程更加规范化，减少因代码基线偏移导致的静态检查误判。

### 10.1 源码自愈修复规则

自愈修复的源码修改应通过变更当前阶段任务定义文件中所在轮次的任务定义进行，而非直接编辑源文件。

核心约束（按故障阶段和故障类型区分）：

#### 10.1.1 故障类型说明

每个开发轮次（D1/D2/D3/D4）内部包含两个子阶段：
1. **code-step 阶段**——执行该轮次的 operation，对源码进行改动
2. **编译/验证阶段**——该轮次源码改动完成后，执行编译和验证

因此故障可能发生在以下场景：

- **code-step 阶段故障（D1-D4 轮次内）：**
  - 发生在 operation 执行期间，即该轮次对源码的改动步骤中
  - 故障原因通常是 operation 的 pattern 无法匹配当前源码、regex 语法错误或 replacement 内容有误
  - 此时该轮次的源码改动尚未生效（code-step 阶段失败导致该轮次中断）
  - 修复方式：只变更触发自愈修复发生轮次的任务定义（例如故障发生在 D3，只改 D3 轮次），可修改、增加、删除对应轮次的 operation

- **编译/验证阶段故障（D1-D4 轮次内）：**
  - 发生在该轮次 code-step 已成功执行、源码已被该轮次改动过后，在随后的编译或验证步骤中失败
  - 此时该轮次的源码改动已经生效，当前轮次的源码已被修改
  - 修复方式：由于该轮次原有的 operation 已经执行完毕（源码已改变），任务定义变更必须以在**该轮次追加 op** 的方式进行，**不可修改/删除**该轮次原有 op

- **V1-V4 轮次故障：**
  - V1-V4 轮次是纯验证轮次，不涉及源码改动
  - 故障通常由系统软硬件环境、网络环境等非代码因素引起；若为验证失败（编译通过但逻辑验证未通过），则与源码的业务设计有关
  - 修复方式：属于非代码故障的走环境/监控链稳定化流程；需要修改业务逻辑的，采取在 D4 轮次追加 op 的方式进行，不可修改/删除 D1-D4 原有已通过编译验证的 op

#### 10.1.2 通用约束

- 静态检查通过后，重启主进程，源码会自动恢复到阶段基线：
  - **A 阶段基线**：仓库中上次提交推送后形成的基线（git HEAD）
  - **B 阶段基线**：A 阶段完成时的源码及源码快照
- 脚本按照任务定义文件中各轮次的顺序依次执行源码的改动
- **绝对禁止 AI 直接修改源码**——所有变更须通过任务定义的 operation 间接实现

### 10.2 启动任务定义静态检查

A/B 启动时基于当前源码执行 D1-op1 的静态检查（pattern_match=1 且无错误），以确保入口操作可正常匹配。此检查通过后方可进入主流程。

### 10.3 常规流程

```
A/B 启动
  → 静态检查 D1-op1（基于当前源码，仅检查 D1-op1 匹配性与语法）
  → D1（code-step + strict build gate）
  → D2（code-step + strict build gate）
  → D3（code-step + strict build gate）
  → D4（code-step + strict build gate）
  → V1（verify round）
  → V2（verify round）
  → V3（verify round）
  → V4（verify round）
```

### 10.4 fast-pass 流程（自愈修复后）

自愈修复仅发生在某一轮次，之前已验证通过的轮次无需再次完整验证。fast-pass 流程前缀带有 **"Fast-"** 标记表示该轮跳过了冗重的全量验证（仍执行 code-step，跳过 smoketest/golden 等验证集）。

**自愈修复发生在 D1：**
```
A/B 启动
  → 静态检查 D1-op1
  → D1 → D2 → D3 → D4 → V1 → V2 → V3 → V4
```

**自愈修复发生在 D2：**
```
A/B 启动
  → 静态检查 D1-op1
  → Fast-D1 → D2 → D3 → D4 → V1 → V2 → V3 → V4
```

**自愈修复发生在 D3：**
```
A/B 启动
  → 静态检查 D1-op1
  → Fast-D1 → Fast-D2 → D3 → D4 → V1 → V2 → V3 → V4
```

**自愈修复发生在 D4：**
```
A/B 启动
  → 静态检查 D1-op1
  → Fast-D1 → Fast-D2 → Fast-D3 → D4 → V1 → V2 → V3 → V4
```

**自愈修复发生在 V1-V4：**
```
A/B 启动
  → 静态检查 D1-op1
  → Fast-D1 → Fast-D2 → Fast-D3 → D4（在 D4 追加 operation） → V1 → V2 → V3 → V4
```

> **说明：** 故障发生在 V1-V4 轮次时，优先将增量补丁追加到 D4 轮次的现有定义后面，而非改写已经过编译验证的 D1-D4 轮次定义。

### 10.5 自愈修复中 AI 修改任务定义后的静态检查规则

AI 在自愈修复中变更完成所在阶段任务定义文件里对应开发轮次的任务定义后，应基于当前源码执行任务定义静态检查。检查策略按故障类型区分如下：

#### 10.5.1 D1-D4 轮次内 code-step 阶段故障

故障发生时该轮次的源码改动尚未生效（code-step 阶段中断），当前源码状态为该轮次开始执行之前的基线。静态检查按该开发轮次所涉及操作（修改/追加/删除 op）的排序，以**最靠前优先原则**进行，最多执行一次：

任务定义编辑边界（D1-D4 code-step 阶段失败，`code-edit-failure` / `task-definition-mismatch`）：
- 源码尚未变更，可修改/追加/删除该轮次中的 op。
- 为避免误改已验证步骤，禁止修改当前故障 op 之前的 op。
- 仅允许从当前故障 op 位置开始，向后修改/追加/删除该轮次中的 op。

- 若该轮次有**修改**或**追加**的 op，则静态检查排序最靠前的那一个 op
- 若该轮次仅有**删除**的 op：
  - 静态检查被删除 op 之后的第一个 op（按排序）
  - 若被删除的 op 是该轮次最后一项，则跳过静态检查
- 若同一轮次同时存在修改/追加和删除的 op：
  - 当所删除 op 的排序在修改/追加 op 的排序**之前**时，静态检查修改/追加 op 之后的第一个 op
  - 当修改/追加 op 的排序在删除 op 的排序**之前**时，按修改/追加优先原则处理

#### 10.5.2 D1-D4 轮次内编译/验证阶段故障

故障发生时该轮次的源码改动已经生效（code-step 已成功执行），当前源码状态为该轮次改动完成后的状态。由于该轮次原有 op 已经执行完毕，静态检查按该轮次所**追加 op** 的排序，以**最靠前优先原则**进行，最多执行一次：

- 仅检查该轮次排序最靠前的新追加 op
- 不检查该轮次原有 op（原有 op 的 pattern 在当前已被该轮次修改过的源码上可能不再匹配，属于预期行为）

#### 10.5.3 V1-V4 轮次故障

V1-V4 是纯验证轮次，当前源码状态为 D1-D4 全部执行完成后的最终源码。若需要修改业务逻辑，变更采取在 D4 轮次追加 op 的方式进行。静态检查按 D4 轮次所**追加 op** 的排序，以**最靠前优先原则**进行，最多执行一次：

- 仅检查 D4 轮次排序最靠前的新追加 op
- 不检查 D4 轮次原有 op（原有 op 的 pattern 在 D1-D4 已全部执行完成的最终源码上可能不再匹配，属于预期行为）

#### 10.5.4 低成本模型任务定义编辑最小操作清单（GPT-5 mini 等）

- 只改 `rounds.<Dn>.operations`，不要改 `rounds` 键名、轮次编号、顶层 schema 字段。
- 先定位“当前故障 op”在 operations 中的索引；索引之前的 op 只读，禁止修改。
- 允许动作仅限当前故障 op 及其后续：修改该 op、在其后追加新 op、删除其后不再需要的 op。
- 每次编辑后，保持 operations 内 op 顺序稳定；不要因为格式化或重排导致语义漂移。
- 修改 pattern/replacement 时必须保证“唯一命中 + 可落地替换”；若无法唯一命中，优先追加新 op，不要强改前置 op。
- 提交前必跑静态检查；若静态检查失败，继续在当前故障 op 及其后续修复，禁止回头改前置 op。

### 10.6 D/V 轮次任务定义设计补充规则

#### 10.6.1 改动量评估优先

先评估代码改动量：
- **追加模式（优先）**：改动量小，在当前 D 轮次末尾追加 op 补丁。
- **重构模式（备选）**：改动量大，则重设计当前 D 轮次所有 ops。仅当追加模式导致 ops 数量膨胀或语义混乱时选用。

#### 10.6.2 孤儿函数体检查

修改 D 轮次任务定义后，务必检查该轮次中每个 op 是否在源码中遗留了**孤儿函数体**。当 op 的 pattern 只匹配函数签名而不匹配其函数体时，签名被替换后原函数体将残留为悬空代码块，导致编译错误。发现后应在该轮次末尾追加删除孤儿体的 op，或修改原 op 的 pattern 使其一并消耗原函数体。

#### 10.6.3 契约约束

D 轮次代码设计必须基于 whois 项目的整体方案，包括但不限于：
- 项目架构文档与 RFC（`docs/` 目录下），当前代码改动涉及的具体方案见 [RFC-address-space-preclassifier.md](RFC-address-space-preclassifier.md)。
- 输出契约（标题行、尾行、折叠行格式等），详见 [USAGE_CN.md](USAGE_CN.md) 与 [USAGE_EN.md](USAGE_EN.md)。
- IPv4/IPv6 查询规则契约，详见 [RFC-ipv4-ipv6-whois-lookup-rules.md](RFC-ipv4-ipv6-whois-lookup-rules.md)。
- DNS 与重试策略契约（v3.2.8–v3.2.9 冻结），详见 [RFC-dns-phase2.md](RFC-dns-phase2.md)、[RFC-dns-phase4-ip-health.md](RFC-dns-phase4-ip-health.md)。

Step47 矩阵契约是不可逾越的红线，不得因代码变更改变其预期结果。

#### 10.6.4 预算耗尽与待办修复的优先级（2026-07-05）

当收到 `budget-exhausted-stop` 通告时，若此前同一会话中已有一张 `incident-captured`（或类似）票据允许了 `code-fix-workflow` / `script-fix-workflow` 但尚未执行对应的修复动作，则**先完成已有修复后再处理预算通告**。

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

#### 10.6.6 相同指纹门禁三段化与重试预算（2026-07-08）

为避免“历史首次失败 + AI 接手一次失败”即触发硬阻断，且继续保持防无限循环能力，D 轮次 code-step 的相同指纹门禁采用三段化状态机与条件重试预算。

- 适用范围：仅 `code-step` 相同指纹分支；`compile/verify` 分支保持原有严格门禁。
- 状态机：`pending_review -> override_window -> hard_block`。
  - `pending_review`：检测到相同指纹，进入待评审态。
  - `override_window`：满足重试条件后放行一次重启窗口。
  - `hard_block`：预算耗尽或证据不足，转人工处置，禁止自动重启。
- 默认预算：`CODESTEP_IDENTICAL_FP_MAX_RETRIES=3`（可用 stage 级键覆盖：`A_CODESTEP_IDENTICAL_FP_MAX_RETRIES` / `B_CODESTEP_IDENTICAL_FP_MAX_RETRIES`）。
- 第 2/3 次重试必须有“有效修复证据”，否则直接进入 `hard_block`：
  - 任务定义文件哈希变化；或
  - 轮次级任务定义印记（round operations imprint）变化；或
  - 轮次源码摘要变化。

实现约束：

- 相同指纹比较仍以 `main_round + phase + task_start_at + failure_fingerprint` 为主键。
- 指纹滚动时必须同时写回当前/上一次证据字段：
  - `*_FAILURE_TASKDEF_HASH` 与 `*_PREVIOUS_FAILURE_TASKDEF_HASH`
  - `*_FAILURE_SOURCE_HASH` 与 `*_PREVIOUS_FAILURE_SOURCE_HASH`
  - `*_FAILURE_TASKDEF_ROUND_IMPRINT_HASH` 与 `*_PREVIOUS_FAILURE_TASKDEF_ROUND_IMPRINT_HASH`
- 门禁状态字段建议统一：
  - `*_CODESTEP_IDENTICAL_FP_RETRY_COUNT`
  - `*_CODESTEP_IDENTICAL_FP_STATE`
  - `*_CODESTEP_IDENTICAL_FP_STATE_AT`

人工修复后的解锁规则：

- `hard_block` 并非永久封禁。
- 人工修复完成后，若检测到“有效修复证据”且静态检查通过，可自动从 `hard_block` 回到 `pending_review`，重置同指纹预算后允许重启。
- 若无有效修复证据，保持 `hard_block`，不得重启。

