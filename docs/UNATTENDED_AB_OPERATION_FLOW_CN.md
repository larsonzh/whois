# A/B 无人值守任务完整操作流程（CN）

## 1. 目的

本文给出 whois 仓库中 A/B 无人值守任务的完整操作链路，覆盖从最早的任务设计、模板生成、启动文件编制、启动执行，到运行中监控、任务结束回填、失败后重跑的全流程。

本文重点解决四个问题：
- 明确“正确入口脚本”是什么，避免会话代理绕开既有入口，自行新写脚本导致流程跑偏。
- 给出可直接执行的命令示例，减少临时拼命令和口头记忆带来的误操作。
- 固定“准备完成后必须先由用户确认、且只有用户发出启动命令后才可开跑”的授权边界。
- 说明用户 <-> 无人值守脚本 <-> AI 三者在运行过程中的地位、作用和优先级。

## 2. 核心原则

### 2.1 只走既有入口，不新增私有启动脚本

正确做法：
- 使用现有任务定义模板：testdata/autopilot_code_step_tasks_template.json
- 使用现有启动模板与生成器：docs/UNATTENDED_AB_START_TEMPLATE_CN.md、tools/test/create_unattended_ab_start_file.ps1
- 使用现有 A/B 启动入口：tools/test/start_dev_verify_fastmode_A.ps1、tools/test/start_dev_verify_fastmode_B.ps1
- 如需外部 NoExit 窗口，使用：tools/test/open_unattended_ab_stage_window.ps1

禁止做法：
- 不要为某一轮 A/B 临时再写一套新的 A 启动脚本、B 启动脚本、wrapper 或任务分发脚本。
- 不要绕开 fastmode A/B 入口，直接拼一长串底层 multiround 参数，除非你明确在做底层调试。
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
- 只有用户明确发出“启动 A/B 无人值守任务”“执行这轮 A/B”这类命令后，才可真正启动。

### 2.5 长时间运行脚本必须在 VS Code 外部 PowerShell 窗口执行

长跑任务一律不建议放在 VS Code 集成终端里运行，因为集成终端更容易受窗口、renderer、extension host、terminal host 等环境因素影响，不适合长时间驻留。

必须放在 VS Code 外部 PowerShell 窗口运行的长跑脚本包括：
- A/B 主运行脚本
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

正确启动入口：
- tools/test/start_dev_verify_fastmode_A.ps1
- tools/test/start_dev_verify_fastmode_B.ps1

可见窗口启动入口：
- tools/test/open_unattended_ab_stage_window.ps1
- tools/test/open_unattended_ab_resume_window.ps1

运行中监控/接管：
- tools/test/poll_agent_tickets.ps1
- tools/test/check_unattended_routine_status.ps1
- tools/test/update_chat_session_heartbeat.ps1
- tools/test/watch_ab_light.ps1

### 3.3 长跑脚本的运行位置

默认建议：
- 正常运行时，所有 A/B 主脚本和 4 个监控链脚本都在 VS Code 外部 PowerShell 窗口中运行。
- 标准优先方式是由主进程入口带上 `-StartMonitors`，让包装器在外部窗口里拉起监控链。

主运行：
- tools/test/start_dev_verify_fastmode_A.ps1
- tools/test/start_dev_verify_fastmode_B.ps1
- 或使用 tools/test/open_unattended_ab_stage_window.ps1 间接拉起

4 个监控链脚本：
- tools/test/open_unattended_ab_supervisor_window.ps1
- tools/test/open_unattended_ab_companion_window.ps1
- tools/test/open_unattended_ab_session_guard_window.ps1
- tools/test/open_unattended_ab_takeover_trigger_window.ps1

不推荐：
- 把以上长跑脚本直接放在 VS Code 集成终端里长期运行

集成终端用途：
- 仅用于调试、只读检查、临时校验和短命令试跑
- 如需触发 `tools/test/open_unattended_ab_stage_window.ps1 ... -StartMonitors`，可以从集成终端发起，但被拉起的主进程和监控链应落在外部 PowerShell 窗口运行
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
- `ENTRY_SCRIPT_A=tools/test/start_dev_verify_fastmode_A.ps1`
- `ENTRY_SCRIPT_B=tools/test/start_dev_verify_fastmode_B.ps1`
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

### 4.8 阶段 7：预检并回填 PRECHECK 字段

目的：把“可以启动”写进 start-file，而不是靠口头说已经检查过。

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

### 4.9 阶段 8：正确启动 A/B

这是最关键的一步。

前提条件：
- 用户已经确认任务定义文件、RFC 下次开工清单、启动文件
- 用户已经明确发出本轮启动命令
- 长跑脚本准备在 VS Code 外部 PowerShell 窗口运行

正确做法一：标准方式，外部 PowerShell 窗口里用 stage window 入口，并带 `-StartMonitors`

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage B -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors -EnableBMonitorRestart
```

说明：
- 这是正常运行时的首选命令组。
- 由主进程包装器负责在外部 PowerShell 窗口中拉起监控链。
- A 先启动
- B 只在 A PASS 且快照已固化后启动
- 不要在 A 尚未收口时抢跑 B

正确做法二：若不通过包装器自动带起，则分别手工启动主脚本和 4 个监控链

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_A.ps1 autopilot_code_step_tasks_20261031_20261107.json
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_B.ps1 autopilot_code_step_tasks_20261108_20261115.json
```

适用场景：
- 需要精细控制主脚本和监控链的启动顺序
- 需要单独调试某一个监控链窗口

此时监控链需要分别在外部 PowerShell 窗口中启动，推荐入口：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_supervisor_window.ps1 -CurrentARunDir out/artifacts/dev_verify_multiround/<CURRENT_RUN> -CurrentAStartRound 1
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_companion_window.ps1 -SupervisorLog out/artifacts/ab_supervisor/<YYYYMMDD-HHMMSS>/supervisor.log
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_session_guard_window.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md"
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_takeover_trigger_window.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md"
```

补充说明：
- 如果直接运行 `start_dev_verify_fastmode_A.ps1` / `start_dev_verify_fastmode_B.ps1`，监控链不会由这两个 fastmode 主脚本自动无条件带起。
- 需要“主进程负责拉起监控链”时，应使用 `open_unattended_ab_stage_window.ps1 ... -StartMonitors` 这组命令。
- 即使某些 start-file 已把 `AUTO_START_MONITORS=true` 写入默认配置，标准执行口径仍应显式带上 `-StartMonitors`，不要把是否自动拉起监控链建立在隐式默认值上。
- 即使这组命令是从 VS Code 集成终端里触发，`open_unattended_ab_stage_window.ps1` 及其后续 monitor launcher 也会继续拉起外部 PowerShell 窗口承载实际长跑进程。
- VS Code 集成终端内运行仅用于调试，不作为标准运行方式。

错误做法：
- 会话代理自己写 `start_ab_round_A_custom.ps1`
- 会话代理自己绕开 fastmode 包装器，直接重拼 multiround 参数
- 会话代理写一套“看起来差不多”的新入口脚本替代现有入口
- 把主运行和 4 个监控链脚本长期挂在 VS Code 集成终端里

### 4.10 阶段 9：运行中监控与工单处理

正确监控链路：
- guard 产票
- 会话轮询 `poll_agent_tickets.ps1`
- 执行 `business_command`
- 执行 `continue_watch_command`
- 执行 `mark_processed_command`
- 如要求则回 `handled_at`

示例：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/poll_agent_tickets.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -IncludeStatusReports -AsJson
```

查看 routine 状态：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_routine_status.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -AsJson
```

写入会话心跳：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/update_chat_session_heartbeat.ps1 -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -Source "chat-session-active" -AsJson
```

### 4.11 阶段 10：A 收口后再启动 B

进入 B 之前必须满足：
- A 已 PASS
- A 成功快照已固化
- A 的 `final_status.json` 路径已确定
- A 的 `summary.csv` 路径已确定
- A 结束时源码状态摘要已记录

如果 A 失败：
- 禁止启动 B
- 先修 A
- 必要时 reset start-file 后从 A-D1 重跑

### 4.12 阶段 11：任务结束后回填文档

任务完成后，不要只留在聊天记录里。

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
- 跑静态体检
- 在 RFC 中起草下次开工清单
- 用 `create_unattended_ab_start_file.ps1` 生成启动文件
- 跑 `check_unattended_start_field_sync.ps1`
- 回填预检字段
- 交用户确认
- 等待用户明确启动命令
- 启动 A
- A PASS 后启动 B
- 回填 RFC

### 5.2 复用已有 start-file 重新跑 A

适用场景：
- A 失败，需要修复后从 A 重新开始

顺序：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md
```

然后：
- 重新执行预检
- 回填 `PRECHECK_*`
- 再次交用户确认是否重跑
- 只有用户明确下令后，再从 A-D1 启动

### 5.3 event-only 低成本联调

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
- 会绕过 fastmode A/B 的固定参数、remote lock 检查、网络硬闸、静态体检

纠偏：
- 回到现有入口：`start_dev_verify_fastmode_A.ps1` / `start_dev_verify_fastmode_B.ps1`

### 6.2 错误：任务定义还没体检就开跑

问题：
- 运行中才暴露 TODO、pattern 不唯一、锚点不存在

纠偏：
- 先跑 `check_task_definition_static.ps1`

### 6.3 错误：只改聊天/策略派生键，不改源键

问题：
- start-file 漂移
- 之后 stage/resume 回写又改回去

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
- 任务结束后立即回填两份 RFC

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

### 7.3 做字段同步检查

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_start_field_sync.ps1
```

### 7.4 用户确认后，在外部 PowerShell 窗口启动 A/B

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage B -StartFile "testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md" -StartMonitors -EnableBMonitorRestart
```

若需要手工分开启动，则使用主脚本命令加 4 个监控链命令的两组组合，不建议把它作为默认流程。

## 8. 10 行极简执行版（准备完成后）

1. 确认 A/B 任务定义文件都已 TODO-free，并已通过 `tools/test/check_task_definition_static.ps1`。
2. 确认两份 RFC 中的下次开工清单都已写好，并已交用户确认。
3. 确认启动文件已生成，且 `tools/test/check_unattended_start_field_sync.ps1` 为 `pass`。
4. 确认任务定义文件、RFC 清单、启动文件三者都已经过用户确认。
5. 若用户尚未明确发出启动命令，停在 READY，不启动任何 A/B 主脚本或监控链脚本。
6. 正常运行时，只在 VS Code 外部 PowerShell 窗口执行 `open_unattended_ab_stage_window.ps1 ... -StartMonitors` 这组主进程命令。
7. 若不用 `-StartMonitors` 自动带起，就把主脚本和 4 个监控链脚本分开在外部 PowerShell 窗口手工启动。
8. VS Code 集成终端仅用于调试，不用于承载标准无人值守长跑；若从集成终端触发 `open_unattended_ab_stage_window.ps1 ... -StartMonitors`，应确认主进程和监控链已经落到外部 PowerShell 窗口继续运行。
9. A 未 PASS 不启动 B；A PASS 且快照固化后，再由既有入口启动 B。
10. 任务结束后立即回填两份 RFC 和 start-file 最终状态，不只在聊天里总结。

## 9. 建议结论

以后凡是做 whois 仓库的 A/B 无人值守任务，都应按以下口径执行：
- 先任务定义，后启动文件，再启动。
- 先静态体检与字段同步，再进入长跑。
- 只走仓库现有入口脚本，不新增私有启动脚本。
- 任务定义文件 / RFC 下次开工清单 / 启动文件准备好后都必须先交用户确认。
- 只有用户明确发出启动命令后，才允许启动 A/B。
- 正常情况下，应在 VS Code 外部 PowerShell 窗口中执行带 `-StartMonitors` 的主进程入口，由主进程拉起监控链。
- 如果只是从 VS Code 集成终端触发这组命令，也应确认真正承载长跑的是后续弹出的外部 PowerShell 窗口，而不是集成终端本身。
- 如果不走 `-StartMonitors` 自动带起模式，则主脚本和 4 个监控链脚本都应分别在外部 PowerShell 窗口中手工启动。
- VS Code 集成终端仅用于调试。
- A 先于 B，A 不 PASS 不启动 B。
- 运行中靠现有工单、心跳、routine、watch 链路监控。
- 结束后必须回填 RFC，而不是只停留在聊天记录中。

若会话代理无法正确进入入口脚本，应优先检查：
- 是否已经给出了明确的任务定义文件名
- 是否已经生成并确认 start-file
- 是否错误地尝试“重写一套新脚本”而不是调用既有入口
- 是否忘记先通过静态体检与预检硬闸
