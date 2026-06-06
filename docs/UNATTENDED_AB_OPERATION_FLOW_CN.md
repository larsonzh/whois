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
- supervisor 监控脚本
- companion 监控脚本
- session guard 脚本
- takeover trigger 脚本

推荐外部窗口入口：
- tools/test/open_unattended_ab_stage_window.ps1
- tools/test/open_unattended_ab_supervisor_window.ps1
- tools/test/open_unattended_ab_companion_window.ps1
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
- 对 healthy 的 `running-status-report`，根因应写成“无活动故障/常规定时状态票”，修复路径应写成“continue_watch only”；不得仅凭旧失败摘要、旧 `latest_b_exit.json` 或历史 exit artifact 推断需要重启 B。
- 运行期不得手工创建新的 `chat_heartbeat*.jsonl`、`handled_tickets/*.md` 等临时回执产物；应仅使用现有脚本输出的 ledger/heartbeat。
- 运行期不得在未获用户明确同意时创建非 `tmp/` 新脚本，也不得偏题提出 PR、服务化改造或其他超出当前票据闭环的实施方案。

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

4 个监控链脚本：
- tools/test/open_unattended_ab_supervisor_window.ps1
- tools/test/open_unattended_ab_companion_window.ps1
- tools/test/open_unattended_ab_session_guard_window.ps1
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

示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261031_20261107.json -Policy enforce -FailOnWarnings
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261108_20261115.json -Policy enforce -FailOnWarnings
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

### 4.8 阶段 7：统一启动前检查

推荐做法：优先直接运行统一检查脚本，而不是把静态体检、字段同步、预检回填拆成多次人工确认。

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
```

该脚本内部固定顺序：
- 检查目标 start-file
- 读取并验证 `A_TASK_DEFINITION` / `B_TASK_DEFINITION`
- 对 A/B 任务定义分别执行静态体检
- 执行启动文件字段同步检查
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

### 4.9 阶段 8：预检并回填 PRECHECK 字段

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

若不满足：
- 入口脚本会硬闸阻断

即使已经达到 `READY`：
- 若用户尚未明确发出启动命令，仍然不得启动 A/B。

### 4.10 阶段 9：正确启动 A/B

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

### 4.11 阶段 10：运行中监控与工单处理

正确监控链路：
- guard 产票
- 会话轮询 `poll_agent_tickets.ps1`
- 执行 `business_command`
- 执行 `continue_watch_command`
- 执行 `mark_processed_command`
- 如要求则写入 `handled_at`

运行期执行规则：
- 事件驱动票和定时状态票中的工作内容视为预授权操作，AI 在无人值守运行期间应直接执行，不再向用户逐条确认。
- 对 `running-status-report` 这类需要 handled 收据的工单，必须立即写入 `handled_at`；`handled_at` 是强制项，不可省略。
- `handled_at` 现在应优先作为 `poll_agent_tickets.ps1` ledger 中的一等状态字段理解；额外的 `handled_tickets/*.md` 仅在显式开启 `LOCAL_GUARD_WRITE_HANDLED_ARTIFACTS=true` 时才写入，不再作为默认必需产物。
- 对 healthy 的 `running-status-report`，默认处置应为“最小健康检查 + continue_watch only”；不得因为历史失败证据或旧 exit 文件自动上升为 B 重启建议。
- 默认执行顺序固定为：`business_command -> continue_watch_command -> mark_processed_command -> handled_receipt_command`。
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

### 4.12 阶段 11：A 收口后再启动 B

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

### 4.13 阶段 12：自愈修复 / 故障处理

适用场景：
- 编译失败
- 静态体检失败
- 规则误判
- 任务定义中的 patch / anchor / replacement 漂移

固定流程：
1. 先留证，确认失败发生在 A 还是 B。
2. 只修改本阶段任务定义文件中对应轮次的定义内容，不直接改源码。
3. 对被修改的任务定义文件运行静态体检。
4. 体检通过后，用 stage window 从本阶段开始处重启。
5. 让主进程自动完成基线回滚与代码自愈执行。

示例：A 阶段自愈后重启

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261031_20261107.json -Policy enforce -FailOnWarnings
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
```

示例：B 阶段自愈后重启

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20261108_20261115.json -Policy enforce -FailOnWarnings
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage B -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
```

### 4.14 阶段 13：任务结束后回填文档

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

然后：
- 重新运行 `tools/test/check_unattended_ab_launch_ready.ps1`
- 脚本 PASS 后，再次向用户提一次是否重跑 A 的启动授权
- 只有用户明确下令后，再从 A-D1 用 stage window 启动

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
- AI 直接执行 `business_command -> continue_watch_command -> mark_processed_command -> handled_receipt_command`
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
