# A/B 无人值守启动文本模板（CN）

## 会话内事件驱动盯盘复制语句（建议）

极简一行版（聊天框速贴）：
从现在起，会话内代理按“event-only 事件票 + 主动心跳”节奏维持监控并汇报，不要结束会话；修改 start-file 用 UTF-8 with BOM 编码 + LF 行尾；发现脚本故障可直接修复脚本；允许在预算内闭环自动修复代码（修复->静态检查->同阶段重启->复核->记录）；工单来源为 LOCAL_GUARD_AGENT_QUEUE_PATH（默认 out/artifacts/ab_agent_queue/agent_tickets.jsonl），每次通过 tools/test/poll_agent_tickets.ps1 -StartFile "<start-file>" -AsJson 取事件票并逐条执行（business_command -> continue_watch_command -> mark_processed_command -> post_check_command，补偿直到 no_pending_rows；continue_watch_command 已内置 -NoRestartIfRunning）；任务定义修复先对故障 op 运行带 -OperationIndex 的目标检查，再对全部受影响 D 轮运行不带 -OperationIndex 的整轮检查；运行时已吸收或幂等命中必须保持 regex-patch 并使用自有 marker，禁止改成 noop 绕过；会话心跳按每轮工单后或既定间隔主动执行 tools/test/update_chat_session_heartbeat.ps1 -StartFile "<start-file>" -Source "chat-session-active" -AsJson，poll 仅取工单与读取心跳；若 strict 策略违规先修正 LOCAL_GUARD_POLL_*；若心跳超时或消息未达先修复消息链路；不得手工创建 chat_heartbeat*.jsonl、额外 handled 回执文件或非 tmp 新脚本；仅在 A/B 都到终态或我明确下达“停止监控”时结束。

短版（默认推荐）：
从现在起，会话内代理进入 event-only 事件驱动监控模式，不要结束会话；通过 tools/test/poll_agent_tickets.ps1 -StartFile "<start-file>" -AsJson 主动拉取事件票，按 business_command -> continue_watch_command -> mark_processed_command -> post_check_command 执行并补偿到 no_pending_rows；主动发送 chat heartbeat；任务定义修复必须先做故障 op 目标检查，再做全部受影响 D 轮整轮检查，运行时吸收态不得改成 noop；检查通过后只通过标准 stage window 重启票据对应阶段；不得手工创建心跳/回执文件、非 tmp 新脚本或执行未授权 commit/push；仅在 A/B 都到终态或我明确下达“停止监控”时结束。

强约束版（高风险轮次推荐）：
从现在起，会话内代理按 event-only 事件票持续监控，不要结束会话；修改 start-file 用 UTF-8 with BOM 编码 + LF 行尾；监控范围为 artifacts、guard_log、compile-step；不再使用旧时间窗判挂口径；允许按预算闭环修复（默认每个 D 轮最多 3 次）；通过 tools/test/poll_agent_tickets.ps1 -StartFile "<start-file>" -AsJson 取票并严格按 next_command_order 执行，补偿到 no_pending_rows；任务定义故障只改允许边界内 operations，先运行故障 op 的 -OperationIndex 目标检查，再运行所有受影响 D 轮的整轮严格检查；设计时空轮才可用最小 noop，吸收/幂等态必须保持 regex-patch；两层检查与修复证据通过后仅用标准 stage window 重启票据对应阶段；会话内主动发送 heartbeat，严禁 poll 代写；strict 违规、心跳超时或消息未达时先修复监控/消息链路；重启前必须采证；运行期不得手工创建心跳/回执文件、非 tmp 新脚本或执行未授权 commit/push；仅在 A/B 终态或我明确停止时结束。

## 强绑定句（建议原样保留）
进入 event-only 事件驱动监控，后续动作由事件票指令触发，并仅执行既有仓库命令（禁止自建额外脚本或循环）；显式切换到其他模式时才恢复定时状态票链路。

## 触发文本模板（复制后按需替换）
请执行 A/B 无人值守串行重跑（前台可见模式，单参提速入口）：

- A 任务定义：`testdata/<A_TASK_DEFINITION>.json`
- B 任务定义：`testdata/<B_TASK_DEFINITION>.json`
- 目标时间窗：`<YYYY-MM-DD ~ YYYY-MM-DD>`

工作要求：
1. 执行前必须完成无人值守运行环境检查（本地与远端无残留相关进程、SSH 连通、任务定义文件存在且无 TODO、记录当前工作区状态）；检查未通过不得启动 A/B；并确认入口脚本与运行模式字段已按模板指定。预检结果必须写入本轮任务启动文件中的 `PRECHECK_*` 字段，并在实际启动 A/B 前逐项回显 PASS/FAIL。
   - 当前 `open_unattended_ab_stage_window.ps1` / `open_unattended_ab_resume_window.ps1` 已对 `PRECHECK_REQUIRED=true` 场景执行硬闸：若 `PRECHECK_STATUS!=PASS`、`PRECHECK_START_GATE!=READY` 或 `PRECHECK_REMOTE_LOCK` 不是 `absent|held-by-self`，将直接阻断启动并回填 `PRECHECK_START_GATE=BLOCKED`。
   - 当前 `open_unattended_ab_stage_window.ps1` 与 `open_unattended_ab_resume_window.ps1` 均支持 `LAUNCH_READY_GATE_ENABLED=true`（默认）时自动执行 `tools/test/check_unattended_ab_launch_ready.ps1` 作为启动前统一门禁；该脚本内部已包含字段同步检查（`check_unattended_start_field_sync.ps1`），无需再额外前置一次字段同步检查。
   - `tools/test/check_unattended_ab_launch_ready.ps1` 常用参数：`-StartFile`（必填）、`-Stage A|B`（默认 A）、`-DryRun`（不写回预检字段）、`-DetailedOutput`（输出完整明细）、`-AsJson`（机器可读输出）、`-RequireCleanWorkspace`（要求 clean 工作区）。
   - 阶段化静态体检策略：`Stage=A` 时仅对 `A_TASK_DEFINITION` 执行 `D1:op1` 基线静态检查；`Stage=B` 时跳过启动前静态检查，改由运行期 fail-fast 静态门禁处理。
   - 当前 `start_dev_verify_fastmode_A.ps1` / `start_dev_verify_fastmode_B.ps1` 与 `open_unattended_ab_stage_window.ps1` 均已执行网络硬闸（`tools/dev/check_dualstack_whois_connectivity.ps1`）：本机+远端、IPv4+IPv6 按 `NETWORK_PRECHECK_*` 的 check/require 组合评估，任一 required 项失败即阻断启动。
   - 人工/AI 标准操作入口仅允许使用 `open_unattended_ab_stage_window.ps1`；takeover brief、ticket business_command、人工操作口径都不得为 B 生成 `open_unattended_ab_resume_window.ps1`；`open_unattended_ab_resume_window.ps1` 仅保留给 A 范围低层恢复/调试，不作为标准无人值守恢复入口。
   - 当前推荐优先使用 `tools/test/check_unattended_ab_launch_ready.ps1` 统一完成 start-file 校验、A/B 静态体检、字段同步与 `PRECHECK_*` 回填；默认只看最后一行 `AB_LAUNCH_READY_RESULT=PASS|FAIL`，排障时再加 `-DetailedOutput`。
2. 严格串行：先 A 后 B。
3. A 阶段重启时，主进程自动以项目基线回滚；B 阶段重启时，主进程自动以 A 成功快照为基线回滚。
4. 全程按事件驱动与定时状态票节奏监控并报告状态；在高风险轮次（尤其编译失败修复、任务定义变更后）Copilot 会话必须保持在线响应与按节奏轮询，不能仅依赖 monitor 脚本，也不要求单终端阻塞式实时输出窗口。
5. 运行期处置采用票据驱动策略：
   - 以定时状态票/事件票与 route guard 结果作为动作触发。
   - 不再使用旧的时间窗判挂规则。
   - 需要重启前必须先留证，再执行恢复动作。
6. 发生卡滞或需要重启时：
   - 先保留快照证据（进程快照、产物目录快照、summary_partial 若存在）。
   - 再关闭本地和远端相关进程。
   - 最后重启无人值守进程。
7. 会话中禁止提前结束，直到 A/B 都有最终结论。
8. 归档口径：只有 A/B 运行成功后，运行结果统一回填到 RFC 文档，不回填本模板。
9. A -> B 切换前必须获取 A 成功快照（至少包含：A 的 `final_status.json` 路径、`summary.csv` 路径、A 结束时源码状态摘要），并记录在本轮任务启动文件中。
10. 若 A 任一轮次失败，或 A 最终状态不是成功：
   - 禁止启动 B。
   - 必须先定位并修复 A 的失败原因，再从 A-D1 重新执行 A。
   - 若继续复用同一份任务启动文件执行“A 修复 -> A 重跑”，必须先将该启动文件恢复到未运行基线，再重新执行预检并从 A-D1 启动。
   - 仅当 A 重跑成功且重新固化 A 成功快照后，才允许进入 B。
11. 若 B 任一轮次出现编译失败：
   - 优先仅重启 B（不回到 A），但必须先将源码恢复到 A 成功快照状态，再应用修订后的 B 任务定义并从 B-D1 重新执行。
   - 若无法可靠恢复到 A 成功快照，则按保守策略从 A 重新执行，再串行进入 B。
12. 每次进入 remote strict 编译前，必须先通过 remote lock 检查：
   - 若同一 remote base 已被其他构建会话占用，则当前轮次不得进入编译。
   - 必须先确认前序构建完成，或明确清理失效锁后，才能继续本轮执行。
13. 事件驱动票与定时状态票中的既定工作内容视为预授权动作：AI 在无人值守运行期间直接执行 `business_command -> continue_watch_command -> handled_receipt_command -> validate_receipt_command -> mark_processed_command`，不再逐项向用户确认；`handled_at` 为强制回执字段。
14. 代码自愈修复不允许直接修改源码；只能修改当前阶段任务定义文件。若改动了任务定义，必须先让 `tools/test/check_task_definition_static.ps1` 静态体检通过，才允许重启或 resume；重启时只能启动当前票据对应阶段的主进程，A 问题只重启 A，B 问题只重启 B。
15. 如确需临时脚本，只能放在 `tmp/` 目录，用完删除。
16. 对 healthy 的 `running-status-report`，根因默认写“无活动故障/常规定时状态票”，修复路径默认写“continue_watch only”；不得仅凭历史失败证据推断需要重启 B。运行期不得手工创建 `chat_heartbeat*.jsonl`、额外 handled 回执文件，也不得在未获同意时创建非 `tmp/` 新脚本。
17. 无人值守运行期间禁止执行提交与推送操作（如 `git commit` / `git push`）；仅在用户明确同轮授权后，才可进入提交/推送流程。
18. 下次开工清单固定写在 `docs/RFC-whois-client-split.md` 与 `docs/RFC-address-space-preclassifier.md`；任务结束后如需回填这两份 RFC，必须先汇报结果并等待用户明确授权，再执行回填。

建议执行命令（标准窗口包装器入口）：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "<start-file>" -StartMonitors
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage B -StartFile "<start-file>" -StartMonitors
```
说明：默认固定使用以上 stage window 入口脚本；A 范围恢复才使用 `open_unattended_ab_resume_window.ps1`，B 重启不使用 resume。

## 三层治理硬门禁矩阵

| 层级 | 固定载体 | 允许 | 禁止 |
| --- | --- | --- | --- |
| L1 运行时硬门禁 | `open_unattended_ab_stage_window.ps1` | 统一用 `-Stage A` 或 `-Stage B`，并显式带 `-StartMonitors` 启动；B 仅在 A 成功快照真实存在且门禁通过时启动 | A 未 PASS/无快照时启动 B；启动失败前先清 restart/shutdown 证据 |
| L2 命令生成硬门禁 | ticket / takeover / poll 输出 | 只生成 stage window 命令 | 为 B 生成 resume window、fastmode 直跑或第二套人工入口 |
| L3 授权硬门禁 | 本模板 + 运行文档 | 统一检查 PASS 后只提一次启动授权；运行期票据按预授权执行 | 把 `READY` 当作启动授权；把聊天建议替代脚本/产物事实 |

执行含义：
- 若 L1 失败，脚本必须直接阻断。
- 若 L2 失败，必须先修脚本发令链，不得靠聊天口头纠偏。
- 若 L3 失败，必须先修正文档/模板/口径，再继续下一轮无人值守。

建议在实际启动前先执行统一检查：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "<start-file>"
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "<start-file>" -Stage B -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "<start-file>" -Stage A -AsJson
```
说明：
- 干跑可加 `-DryRun`；排障可再加 `-DetailedOutput`。
- 日常只看最后一行 `AB_LAUNCH_READY_RESULT=PASS|FAIL`。
- 只有当统一检查脚本返回 `AB_LAUNCH_READY_RESULT=PASS` 后，AI/操作员才应向用户提一次“启动 A（带 `-StartMonitors`）”授权。

## 轮次检查点方案（规划记录，尚未启用）

目标：减少“某轮失败后必须从 D1 复跑”的时间浪费，在不破坏当前 A->B 契约的前提下，逐步引入“每轮成功后可恢复检查点”。

当前生效状态：
- 本节仅用于实施记录与口径统一，当前仓库默认流程仍按既有策略运行。
- 尚未引入自动“每轮快照回滚 + 自动续跑”。

Phase 1（先实施，低风险）：
- 计划开工时间：2026-04-24（本地时区）。
- 目标范围：只增加“每轮成功检查点元数据”与“失败后续跑建议”，不自动改源码。
- 交付要点：
   - 在 `out/artifacts/dev_verify_multiround/<RUN>/` 生成轮次检查点清单（例如 `round_checkpoints/`）。
   - 每轮 PASS 记录：`round_tag`、时间戳、源码状态摘要、关键产物路径（`summary_partial.csv`、`final_status.json` 等）。
   - 某轮 FAIL 时给出标准化续跑建议（`StartRound/EndRound` + `state-only`），用于“就地继续”而非强制回到 D1。
- 明确不做：
   - 不做自动 git 回滚。
   - 不改 authority 判定、重定向语义与现有输出契约。
   - 不改变 A 失败阻断 B 的主策略。

后续阶段（待 Phase 1 稳定后）：
- Phase 2：增加“显式恢复到上一轮 PASS 检查点”的手动恢复入口。
- Phase 3：在预算与熔断保护下，评估自动回滚并自动续跑。

若本轮要求“主运行终端 / guard 终端在结束后保留窗口，便于人工查看结束前状态”，或已观察到 VS Code 集成终端整批消失，建议优先使用外部 `NoExit` 窗口启动：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "<start-file>" -StartMonitors
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage B -StartFile "<start-file>" -StartMonitors
```
说明：
- `open_unattended_ab_stage_window.ps1` 用于直接在独立 PowerShell 窗口启动 A 或 B 主运行，窗口默认 `NoExit`，并可同步拉起 guard + trigger 监控链。
- `open_unattended_ab_resume_window.ps1` 只负责 A 范围恢复；若 A PASS 后监控链仍在线，后续 B 由 guard 按既有串行契约接续，不需要再手工切到 resume for B。
- guard 已合并 supervisor/companion 功能，不再需要独立的 supervisor/companion 窗口。
- 若希望阶段结束后保留 A/B 主运行窗口用于复盘，请在任务启动文件中设置 `KEEP_WINDOW_ON_EXIT=true`（由 `open_unattended_ab_stage_window.ps1` 透传到 fastmode 入口）。
- 外部 `NoExit` 窗口与 VS Code 集成终端生命周期解耦，VS Code 更新/重启后窗口仍可保留，便于事后排查。
- 但在重新执行统一检查脚本前，若这些外部 PowerShell 窗口已不再需要，应先真正关闭窗口；否则窗口背后的 `powershell.exe` 进程可能继续存活，并导致 `PRECHECK_LOCAL_RELATED_PROCESSES=FAIL`。

## 本轮默认示例
- A：`autopilot_code_step_tasks_20260613_20260620.json`
- B：`autopilot_code_step_tasks_20260621_20260628.json`

## 任务启动文件（推荐每轮同时生成）
为避免发布任务时手填错误，建议每次在起草“下次开工清单 + 任务定义文件”后，同时生成一个可直接触发执行的任务启动文件（纯文本即可，建议放在 `testdata/unattended_start/active/` 目录）。

建议文件名：
- `testdata/unattended_start/active/unattended_ab_start_<YYYYMMDD-HHMM>.md`

建议自动化脚本：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/create_unattended_ab_start_file.ps1 -ATaskDefinition autopilot_code_step_tasks_20260715_20260722.json -BTaskDefinition autopilot_code_step_tasks_20260723_20260730.json -Window "2026-07-15 ~ 2026-07-30"
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20260504-1123.md -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20260504-1123.md
```
说明：
- `create_unattended_ab_start_file.ps1` 会从模板代码块提取 `key=value` 并生成新启动文件，支持用参数覆盖 A/B 任务定义、窗口与 remote 字段，模板扩展字段会自动保留。
- `create_unattended_ab_start_file.ps1` 默认生成 `event-only` 模式启动文件；如需 `normal`、`anti-missent` 或 `low-disturb`，必须显式加 `-Mode <mode>`。
- `create_unattended_ab_start_file.ps1 -Mode all-modes` 可一次性生成四种模式文件：`normal` 保持基名，另外三种模式自动附加 `_anti_missent`、`_low_disturb`、`_event_only` 后缀。
- `create_unattended_ab_start_file.ps1` 生成的启动文件会强制写为 UTF-8 with BOM + LF，便于中文字段与 PowerShell 5.1 稳定解析。
- `create_unattended_ab_start_file.ps1` 默认输出到 `testdata/unattended_start/active/`；如需生成 smoke 启动文件可加 `-OutputCategory smoke`。
- `reset_unattended_ab_start_file.ps1` 默认会把运行态字段恢复到未运行基线（保留当前模式），优先遵循 `RERUN_FROM_A_STARTFILE_RESET_FIELDS`，并提供 `-DryRun` 用于先查看变更。
- `reset_unattended_ab_start_file.ps1 -UseTemplateBaseline` 会委托 `create_unattended_ab_start_file.ps1` 按“当前 start-file 文件名 + 当前模式（`AI_CHAT_POLICY_WORK_MODE`，缺失或无效则回退 `event-only`）”重建并覆盖当前 start-file；可与 `-DryRun` 联合使用，仅打印 delegate 命令不写文件。

### 任务启动文件（从模板生成）

若你记得的“从模板生成新任务启动文件”脚本，就是：
- `tools/test/create_unattended_ab_start_file.ps1`

推荐用法（先生成，再按需 reset）：

```powershell
# 方式 A：最简生成（默认输出 active 目录，模式为 event-only）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/create_unattended_ab_start_file.ps1 -ATaskDefinition autopilot_code_step_tasks_20260715_20260722.json -BTaskDefinition autopilot_code_step_tasks_20260723_20260730.json -Window "2026-07-15 ~ 2026-07-30"

# 方式 A2：显式生成指定模式（normal / anti-missent / low-disturb / event-only）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/create_unattended_ab_start_file.ps1 -Mode low-disturb -ATaskDefinition autopilot_code_step_tasks_20260715_20260722.json -BTaskDefinition autopilot_code_step_tasks_20260723_20260730.json -Window "2026-07-15 ~ 2026-07-30"

# 方式 A3：一次性生成四种模式（normal 基名 + 3 个带后缀副本）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/create_unattended_ab_start_file.ps1 -Mode all-modes -ATaskDefinition autopilot_code_step_tasks_20260715_20260722.json -BTaskDefinition autopilot_code_step_tasks_20260723_20260730.json -Window "2026-07-15 ~ 2026-07-30" -OutputFile testdata/unattended_start/active/unattended_ab_start_20260715-20260730.md -Force

# 方式 B：明确输出路径（适合固定文件名）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/create_unattended_ab_start_file.ps1 -ATaskDefinition autopilot_code_step_tasks_20260715_20260722.json -BTaskDefinition autopilot_code_step_tasks_20260723_20260730.json -Window "2026-07-15 ~ 2026-07-30" -OutputFile testdata/unattended_start/active/unattended_ab_start_20260715-20260730.md -Force

# 方式 C：生成 smoke 启动文件
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/create_unattended_ab_start_file.ps1 -ATaskDefinition autopilot_code_step_tasks_20260715_20260722.json -BTaskDefinition autopilot_code_step_tasks_20260723_20260730.json -Window "2026-07-15 ~ 2026-07-30" -OutputCategory smoke

# 运行前需要复用同一 start-file 时，先做 reset 预演/执行
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20260715-20260730.md -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20260715-20260730.md

# 若需按当前模式回到模板基线（委托 create 重建覆盖）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20260715-20260730.md -UseTemplateBaseline -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile testdata/unattended_start/active/unattended_ab_start_20260715-20260730.md -UseTemplateBaseline
```

补充约束：
- 生成后建议立即执行 `tools/test/check_unattended_start_field_sync.ps1`，确认模板、active/smoke 与 reset 规则仍一致。
- 若 `A_TASK_DEFINITION` / `B_TASK_DEFINITION` 被覆盖为新文件，启动前仍需通过 `tools/test/check_task_definition_static.ps1` 做静态体检。

### 四种工作模式差异（状态票据视角）

以下口径用于解释 `AI_CHAT_POLICY_WORK_MODE` 对状态票据链路的影响，便于在生成 start-file 时按场景选模。

| 模式 | 状态票是否生成/派发 | 交互与发送特征 | running-status-report 默认处置 |
| --- | --- | --- | --- |
| `normal` | 生成并派发（`LOCAL_GUARD_STATUS_TICKET_ENABLED=true`，`AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS=true`） | `AI_CHAT_DISPATCH_DELIVERY_PROFILE=interactive-smoke`，`AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY=false`，状态消息模式 `alternate` | 按标准状态票口径：优先执行 `business_command`，随后 `continue_watch_command`，并回传 `handled_at` |
| `anti-missent` | 生成并派发 | 与 `normal` 基本一致，但 `AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY=true`，同时 `AI_CHAT_DISPATCH_STATUS_REPORT_ALLOW_INCONCLUSIVE_SUBMIT=false` | 与 `normal` 相同，重点是减少误投窗口（active-window-only） |
| `low-disturb` | 生成并派发 | `AI_CHAT_DISPATCH_DELIVERY_PROFILE=low-disturb`，状态消息模式 `short`，首条不强制 full（`AI_CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST=false`） | 状态票按“健康检查专用”执行：仅最小健康检查 + `continue_watch_command`，禁止从状态票直接发起阶段重启 |
| `event-only` | 不生成、不派发状态票（`LOCAL_GUARD_STATUS_TICKET_ENABLED=false`，`AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS=false`） | 状态票交互关闭（`AI_CHAT_DISPATCH_STATUS_REPORT_INTERACTIVE=false`） | 不走定时状态票链路，仅处理事件驱动票据 |

状态票据强约束（四种模式通用，`event-only` 除外）：
- 接管时先执行 brief 中的 `route_guard_command`，按 `AB_TAKEOVER_ROUTE_GUARD_V1.route.classification` 决定分支，再执行后续动作。
- 当分类为 `status-health-check-only` 时，只允许 `business_command -> continue_watch_command -> handled_at`，禁止 `business_resume`、`stage_restart`、`source_edit`、非 `tmp/` 新脚本。
- 若 `running-status-report` 已被更新屏障票覆盖（`superseded-status-ticket`），按只读监控（票据驱动）处理，不在旧状态票上执行恢复动作。

自愈修复四类分支（brief 必须显式写清）：
- `incident-auto-resume-script-fix` / `incident-manual-script-fix`：只修 guard/trigger/dispatch/poll 脚本链路，禁止把业务源码改动混进来。
- `incident-auto-resume-code-fix` / `incident-manual-code-fix`：修改对应阶段任务定义文件中对应轮次的定义内容；例如当前 B D4，就在 B 任务定义文件里修 D4 或追加该轮次补丁，然后静态体检并按阶段重启。
   - 若故障发生在 V1-V4 轮次，优先把增量修改补丁追加到 D4 轮次的现有定义后面，尽量不要回改已经编译/验证通过的 D1-D4 轮次定义。
   - 若改动了任务定义，先用 `-RoundTag <Dn> -OperationIndex <n>` 对故障 op 做目标检查，再对全部受影响 D 轮分别运行不带 `-OperationIndex` 的整轮严格检查；两层检查都通过后才允许 `stage_restart` / `business_resume`，并且只能重启该票据对应阶段。
   - 只有设计阶段确认整轮无代码变更目标时才允许最小 `type=noop`；运行时发现前置轮已吸收、replacement 已存在或 pattern 不再命中时，必须保持 `regex-patch` 并以逐 op 自有 marker 表达 `absorbed-by-prior-round` / `idempotent-replay`，禁止改成 noop 绕过门禁。
- `incident-auto-resume-noncode` / `incident-manual-noncode`：只做环境/监控链/瞬态稳定化，不改源码也不改任务定义。
- `notice-manual-wait` / `notice-budget-exhausted` / `notice-known-infra-transient`：只报告阻塞、预算或基础设施状态并回执，不进入自愈重启。

补充约束：
- 接管 brief 中如果已经知道是 code-fix 场景，要把目标 stage / round / task-definition 文件名写出来，不要只写“修 scripts and code”。

`low-disturb` 的额外执行口径：
- poll 侧默认强制状态票健康检查模式：`LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MAIN_PROCESS_SELF_HEAL=true`（保留有界主进程自愈）、`LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_TICKET_CHAIN_CHECK=false`、`LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_MAIN_PROCESS_HEALTH_CHECK=true`。
- 若未显式配置 `LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MONITOR_CHAIN_DEGRADED_ESCALATION`，默认开启 monitor-chain degraded 升级；阈值键为 `LOCAL_GUARD_POLL_STATUS_REPORT_MONITOR_CHAIN_DEGRADED_ESCALATION_THRESHOLD`（默认 3）。
- 对 low-disturb 状态票：检查正常且未触发处置时，按两行最小回执（`运行正常` + `handled_at`）；若检查异常或触发故障处理，立即切换 normal 状态票口径，并先执行 `continue_watch_command` 恢复 guard/事件链，再报告根因与修复动作。
- 这里“禁止从状态票直接发起阶段重启”的边界是：不能把 `running-status-report` 当作 `stage_restart` 指令直接执行；若确认脚本/代码故障且需重启，应先走事件升级与自愈闭环（如 `incident-captured` / `main-process-exit-review` -> `business_resume`），再由事件分支在证据、预算、冷却约束下执行重启。

运行中建议每轮关注 `tools/test/poll_agent_tickets.ps1` 输出中的这些字段：
- `event_policy_strict_mode`
- `event_policy_adjustments`
- `status_report_monitor_chain_degraded_escalation_enabled`
- `status_report_monitor_chain_degraded_escalation_threshold`

### 任务定义文件（从模板生成）

若你记得的“从模板生成任务定义文件”流程，建议按下列命令执行（先生成，再静态体检）：

```powershell
# 方式 A：最简生成（固定本地文件名，复制后强制 UTF-8 with BOM + LF）
powershell -NoProfile -ExecutionPolicy Bypass -Command '$dst = "testdata/autopilot_code_step_tasks_local.json"; Copy-Item -LiteralPath "testdata/autopilot_code_step_tasks_template.json" -Destination $dst -Force; $text = [System.IO.File]::ReadAllText($dst); $text = ($text -replace "`r`n", "`n") -replace "`r", "`n"; [System.IO.File]::WriteAllText($dst, $text, (New-Object System.Text.UTF8Encoding $true)); Write-Output ("[TASK-TEMPLATE] created=" + $dst + " encoding=utf8-bom eol=lf")'

# 方式 B：按窗口生成（推荐，避免覆盖历史文件，复制后强制 UTF-8 with BOM + LF）
powershell -NoProfile -ExecutionPolicy Bypass -Command '$window = "20261015_20261030"; $dst = ("testdata/autopilot_code_step_tasks_{0}.json" -f $window); Copy-Item -LiteralPath "testdata/autopilot_code_step_tasks_template.json" -Destination $dst -Force; $text = [System.IO.File]::ReadAllText($dst); $text = ($text -replace "`r`n", "`n") -replace "`r", "`n"; [System.IO.File]::WriteAllText($dst, $text, (New-Object System.Text.UTF8Encoding $true)); Write-Output ("[TASK-TEMPLATE] created=" + $dst + " encoding=utf8-bom eol=lf")'

# 生成后必做静态体检（禁止 TODO_* 残留再进入无人值守）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_local.json -Policy enforce -FailOnWarnings

# 按轮次与 operation 缩小检查范围（例如 A 启动前基线）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_local.json -Policy enforce -FailOnWarnings -RoundTag D1 -OperationIndex 1
```

补充约束：
- `check_task_definition_static.ps1` 参数说明：
   - `-TaskDefinitionFile` 必填；`-RepoRoot` 可选（默认仓库根）。
   - `-Policy off|warn|enforce` 默认 `enforce`。
   - `-FailOnWarnings` 开启后 warning 也按失败返回。
   - `-RoundTag D1..D4|V1..V4` 可只检查单轮。
   - `-OperationIndex <n>` 必须配合 `-RoundTag` 使用，用于只检查该轮第 n 个 operation。
- 生成后请先填写 D1~D4（至少 D1~D3）任务内容，再用于 `A_TASK_DEFINITION` / `B_TASK_DEFINITION`。
- 任务定义 JSON 允许出现中文 `description` / `notes`，因此模板与新生成文件固定使用 UTF-8 with BOM + LF。
- 若体检报错或 warning（启用 `-FailOnWarnings` 时），应先修复任务定义再启动 A/B。

建议内容模板（复制后替换尖括号）：
```text
AB_UNATTENDED_START_V1
BINDING_SENTENCE=进入 event-only 事件驱动监控，后续动作由事件票指令触发，并仅执行既有仓库命令（禁止自建额外脚本或循环）；显式切换到其他模式时才恢复定时状态票链路。
PRECHECK_REQUIRED=true
LAUNCH_READY_GATE_ENABLED=true
RETRY_BUDGET_MINI_REGRESSION_ENABLED=true
PRECHECK_STATUS=NOT_RUN
PRECHECK_OPERATOR=<Copilot|operator>
PRECHECK_AT=<YYYY-MM-DD HH:MM:SS>
PRECHECK_LOCAL_RELATED_PROCESSES=NOT_RUN
PRECHECK_REMOTE_RELATED_PROCESSES=NOT_RUN
PRECHECK_SSH_CONNECTIVITY=NOT_RUN
PRECHECK_TASK_A_EXISTS=NOT_RUN
PRECHECK_TASK_B_EXISTS=NOT_RUN
PRECHECK_TASK_A_TODO_FREE=NOT_RUN
PRECHECK_TASK_B_TODO_FREE=NOT_RUN
PRECHECK_WORKSPACE_STATUS=NOT_RUN
PRECHECK_WORKSPACE_STATUS_DETAIL=<CLEAN_OR_GIT_STATUS_SHORT_SUMMARY>
PRECHECK_ENTRY_SCRIPT_A_EXISTS=NOT_RUN
PRECHECK_ENTRY_SCRIPT_B_EXISTS=NOT_RUN
PRECHECK_RUN_MODE_CONFIRMED=NOT_RUN
PRECHECK_ENTRY_MODE_CONFIRMED=NOT_RUN
PRECHECK_REMOTE_LOCK=NOT_RUN
PRECHECK_START_GATE=NOT_RUN
PRECHECK_START_BLOCKER=
PRECHECK_FAILURE_REASON=
PRECHECK_NOTES=
NETWORK_PRECHECK_REQUIRED=true
NETWORK_PRECHECK_LOCAL_REQUIRED=true
NETWORK_PRECHECK_REMOTE_REQUIRED=true
NETWORK_PRECHECK_CHECK_IPV4=true
NETWORK_PRECHECK_CHECK_IPV6=true
NETWORK_PRECHECK_REQUIRE_IPV4=false
NETWORK_PRECHECK_REQUIRE_IPV6=true
NETWORK_PRECHECK_TARGETS=whois.iana.org;whois.arin.net
NETWORK_PRECHECK_TIMEOUT_SEC=8
NETWORK_PRECHECK_LAST_RESULT=NOT_RUN
NETWORK_PRECHECK_LAST_AT=
NETWORK_PRECHECK_LAST_REASON=
ROUND_RUNTIME_GATE_ENABLED=true
ROUND_RUNTIME_GATE_START_ROUND=2
ROUND_RUNTIME_GATE_MAX_ATTEMPTS=2
ROUND_RUNTIME_GATE_RETRY_DELAY_SEC=2
ROUND_RUNTIME_GATE_MIN_FREE_DISK_MB=256
ROUND_RUNTIME_GATE_CHECK_REMOTE_LOCK=true
ROUND_RUNTIME_GATE_CHECK_NETWORK=true
ROUND_RUNTIME_GATE_CHECK_PROCESS_CONFLICT=true
START_PARAMETER_ECHO_REQUIRED=true
STATUS_REPORT_REQUIRED=true
AI_SESSION_BLOCKING_WATCH_REQUIRED=true
AI_SESSION_BLOCKING_WATCH_REPORT_INTERVAL_MIN=10
AI_SESSION_BLOCKING_WATCH_SCOPES=artifacts;guard_log;compile-step
AI_SESSION_BLOCKING_WATCH_NOTES=
AI_CHAT_HEARTBEAT_ENABLED=true
AI_CHAT_HEARTBEAT_PATH=
AI_CHAT_HEARTBEAT_WRITE_ON_POLL=false
AI_CHAT_HEARTBEAT_TTL_MINUTES=12
AI_CHAT_HEARTBEAT_MISSING_GRACE_MINUTES=20
AI_CHAT_AUTO_RECOVER_ENABLED=true
AI_CHAT_AUTO_RECOVER_COOLDOWN_MINUTES=10
AI_CHAT_AUTO_RECOVER_FAST_RETRY_ENABLED=true
AI_CHAT_AUTO_RECOVER_FAST_RETRY_SECONDS=90
AI_CHAT_AUTO_RECOVER_EVENT=chat-session-heartbeat-timeout
AI_CHAT_FINAL_TRIGGER_VERIFY_MS=1200
AI_CHAT_FINAL_TRIGGER_MAX_ATTEMPTS=2
AI_CHAT_POLICY_VERSION=1
AI_CHAT_POLICY_WORK_MODE=event-only
AI_CHAT_POLICY_DELIVERY_PRIMARY=ipc
AI_CHAT_POLICY_DELIVERY_FALLBACK=on
AI_CHAT_POLICY_FINAL_STOP_GATE=trigger-started
AI_CHAT_TRIGGER_FINAL_STOP_GATE=trigger-started
AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS=false
AI_CHAT_TRIGGER_EVENT_DRIVEN_QUEUE=true
AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START=true
AI_CHAT_DISPATCH_USE_IPC=true
AI_CHAT_DISPATCH_USE_PY_SENDER=false
AI_CHAT_DISPATCH_USE_AHK=false
AI_CHAT_DISPATCH_IPC_MODE=visible
AI_CHAT_DISPATCH_PYTHON_EXE=C:\Program Files\Python313\python.exe
AI_CHAT_DISPATCH_DELIVERY_PROFILE=interactive-smoke
AI_CHAT_DISPATCH_SENDER_PRIMARY=ipc
AI_CHAT_DISPATCH_SENDER_FALLBACK_ENABLED=true
AI_CHAT_DISPATCH_INTERACTIVE_PRE_ACTIONS_ENABLED=false
AI_CHAT_DISPATCH_AHK_EVENT_ALLOWLIST=incident-captured;recovery-await-confirmation;auto-fix-await-confirmation;task-definition-fix-required;main-process-exit-review;manual-wait-paused;budget-exhausted-stop;known-infra-transient-stop;a-pass-conclusion-b-started;chat-session-final-status;running-status-report
AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_SEND_ENABLED=false
AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_REQUIRE_CODE_FOCUS=true
AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY=false
AI_CHAT_DISPATCH_STATUS_REPORT_INTERACTIVE=false
AI_CHAT_DISPATCH_STATUS_REPORT_MESSAGE_MODE=alternate
AI_CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST=true
AI_CHAT_DISPATCH_STATUS_REPORT_ALLOW_INCONCLUSIVE_SUBMIT=true
AI_CHAT_DISPATCH_STATUS_REPORT_PY_CIRCUIT_BREAKER_THRESHOLD=5
AI_CHAT_DISPATCH_STATUS_REPORT_PY_CIRCUIT_BREAKER_COOLDOWN_SEC=900
AI_CHAT_DISPATCH_MESSAGE_LOCALE=zh-cn
AI_CHAT_DISPATCH_ALLOW_RUNNING_STATUS_MESSAGE_OVERRIDE=true
AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_FULL=[FULL-RUNBOOK] 保持事件驱动+主动心跳；先报根因与修复路径；若本票健康，则根因写“无活动故障/常规定时状态票”，修复路径写“continue_watch only”；任务定义修复必须先做故障 op 目标检查，再做全部受影响 D 轮整轮检查；吸收/幂等态保持 regex-patch，禁止改成 noop；两层检查通过后仅重启票据对应阶段；可自愈且未触发预算/冷却耗尽且非不可恢复环境时，立即按 next_command_order 执行；处置后进入只读监控；不要仅凭旧 exit 证据建议重启 B；不得手工创建 chat_heartbeat/handled 回执文件或非 tmp 新脚本；运行期禁止 git commit/git push（除非用户同轮明确授权）；仅在A/B终态或我明确下达stop monitoring时停止；最终收尾显式上报会话结束日期时间。
AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_SHORT=[SHORT-CARD] 先报根因+修复路径；健康状态票固定为"无活动故障/常规定时状态票 + continue_watch only"；任务定义修复按目标 op -> 受影响整轮检查，吸收/幂等态不得改 noop，检查通过后仅同阶段重启；随后按 next_command_order 执行并回到事件驱动+心跳只读监控；本票完成后立即回传 handled_at，仅在stop monitoring或A/B终态时回传 session_closed_at；不要仅凭旧 exit 证据建议重启 B；运行期禁止 git commit/git push（除非用户同轮明确授权）；回传chat_heartbeat关键字段（SESSION/A/B、run_dir、main_round、guard、B exit digest）。
AI_CHAT_DISPATCH_CLEAR_INPUT_ON_FAILURE=true
AI_CHAT_DISPATCH_AHK_EXE=C:\Users\妙妙呜\AppData\Local\Programs\AutoHotkey\v2\AutoHotkey64.exe
AI_CHAT_DISPATCH_OPEN_EDITOR=false
AI_CHAT_DISPATCH_USE_CLIPBOARD=false
AI_CHAT_DISPATCH_RESET_ZOOM_BEFORE_SEND=true
AI_CHAT_DISPATCH_RESTORE_PREVIOUS_WINDOW_AFTER_SEND=true
AI_CHAT_DISPATCH_RESTORE_PREVIOUS_WINDOW_COUNT=12
AI_CHAT_DISPATCH_AUTO_RECONNECT_RESEND=true
AI_CHAT_DISPATCH_RECONNECT_DELAY_MS=1800
AI_CHAT_DISPATCH_RECONNECT_WINDOW_SEC=300
AI_CHAT_DISPATCH_MAXIMIZE_WINDOW=true
AI_CHAT_DISPATCH_ESC_PREFLIGHT=false
AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT_ENABLED=false
AI_CHAT_DISPATCH_CHAT_TOGGLE_SHORTCUT=^!b
AI_CHAT_DISPATCH_X_MODE=right-offset
AI_CHAT_DISPATCH_RIGHT_OFFSET_PX=300
AI_CHAT_DISPATCH_BOTTOM_AVOID_PX=170
AI_CHAT_DISPATCH_PRESEND_DELAY_MS=700
AI_CHAT_DISPATCH_ADAPTIVE_LOAD_ENABLED=true
AI_CHAT_DISPATCH_ADAPTIVE_HIGH_LOAD_MEMORY_PERCENT=88
AI_CHAT_DISPATCH_ADAPTIVE_HIGH_LOAD_AVAILABLE_MB=768
AI_CHAT_DISPATCH_ADAPTIVE_LOW_LOAD_MEMORY_PERCENT=72
AI_CHAT_DISPATCH_ADAPTIVE_LOW_LOAD_AVAILABLE_MB=1536
LOCAL_GUARD_WAIT_FOR_MANUAL_RESTART=false
LOCAL_GUARD_MANUAL_NOTICE_REPEAT=2
LOCAL_GUARD_AUTO_RECOVER_B=true
LOCAL_GUARD_RESTART_REQUIRES_CONFIRM=false
LOCAL_GUARD_RESTART_APPROVED=true
LOCAL_GUARD_SUPPRESS_KNOWN_INFRA_TICKETS=true
LOCAL_GUARD_EXIT_ON_KNOWN_INFRA_TRANSIENT=true
LOCAL_GUARD_AUTO_FIX_D_COMPILE=true
LOCAL_GUARD_AUTO_FIX_MAX_PER_D_ROUND=3
LOCAL_GUARD_AUTO_FIX_COOLDOWN_MINUTES=1
LOCAL_GUARD_AGENT_QUEUE_ENABLED=true
LOCAL_GUARD_AGENT_QUEUE_PATH=out/artifacts/ab_agent_queue/agent_tickets.jsonl
LOCAL_GUARD_WRITE_HANDLED_ARTIFACTS=false
LOCAL_GUARD_STATUS_TICKET_ENABLED=false
LOCAL_GUARD_STATUS_TICKET_INTERVAL_MINUTES=10
LOCAL_GUARD_B_RUNNING_NO_PROCESS_GRACE_SEC=
LOCAL_GUARD_POLL_STATUS_REPORT_EVENTS=running-status-report
LOCAL_GUARD_POLL_DRAIN_SAFE_EVENTS=running-status-report;manual-wait-paused;budget-exhausted-stop;known-infra-transient-stop
LOCAL_GUARD_POLL_BARRIER_EVENTS=incident-captured;recovery-await-confirmation;auto-fix-await-confirmation;task-definition-fix-required;main-process-exit-review;manual-wait-paused;budget-exhausted-stop;known-infra-transient-stop
LOCAL_GUARD_POLL_RESTART_SENSITIVE_EVENTS=incident-captured;recovery-await-confirmation;auto-fix-await-confirmation;task-definition-fix-required;main-process-exit-review
LOCAL_GUARD_POLL_CONTRACT_GATE_EVENTS=task-definition-fix-required
LOCAL_GUARD_POLL_EVENT_POLICY_STRICT=false
LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_TICKET_CHAIN_CHECK=false
LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_MAIN_PROCESS_HEALTH_CHECK=true
LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MAIN_PROCESS_SELF_HEAL=true
LOCAL_GUARD_STATUS_ONLY_AUTOFLOW_EXEC_TOKEN=
EXTERNAL_TRIGGER_EXECUTE=true
EXTERNAL_TRIGGER_COMMAND=powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/dispatch_takeover_to_chat.ps1 -TicketId "%TICKET_ID%" -TicketEvent "%EVENT%" -StartFile "%START_FILE%" -QueuePath "%QUEUE_PATH%" -BriefPath "%BRIEF_PATH%" -NoOpenEditor -SkipClipboard
RESTART_EVIDENCE_REQUIRED=true
RESTART_EVIDENCE_MINIMUM=process-snapshot;artifact-dir-snapshot;summary_partial-if-exists
RESTART_SEQUENCE=evidence-then-cleanup-then-restart
MAX_STAGE_RESTARTS=2
A_MAX_STAGE_RESTARTS=
B_MAX_STAGE_RESTARTS=
RESTART_EVIDENCE_NOTES=
SESSION_INITIAL_LAUNCH_AT=
SESSION_END_CONDITION=a-and-b-final
A_FINAL_STATUS=NOT_RUN
B_FINAL_STATUS=NOT_RUN
SESSION_FINAL_STATUS=NOT_RUN
SESSION_FINAL_NOTES=
RERUN_FROM_A_REQUIRES_STARTFILE_RESET=true
RERUN_FROM_A_STARTFILE_BASELINE=not-run
RERUN_FROM_A_STARTFILE_RESET_FIELDS=PRECHECK_*;A_SUCCESS_SNAPSHOT_FINAL_STATUS;A_SUCCESS_SNAPSHOT_SUMMARY;A_SUCCESS_SNAPSHOT_SOURCE_STATE;A_FINAL_STATUS;B_FINAL_STATUS;SESSION_FINAL_STATUS;LOCAL_GUARD_WAIT_FOR_MANUAL_RESTART;LOCAL_GUARD_AUTO_RECOVER_B;LOCAL_GUARD_RESTART_REQUIRES_CONFIRM;LOCAL_GUARD_RESTART_APPROVED;LOCAL_GUARD_SUPPRESS_KNOWN_INFRA_TICKETS;LOCAL_GUARD_EXIT_ON_KNOWN_INFRA_TRANSIENT;LOCAL_GUARD_WRITE_HANDLED_ARTIFACTS;AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START;AI_CHAT_DISPATCH_ALLOW_RUNNING_STATUS_MESSAGE_OVERRIDE;LOCAL_GUARD_POLL_STATUS_REPORT_EVENTS;LOCAL_GUARD_POLL_DRAIN_SAFE_EVENTS;LOCAL_GUARD_POLL_BARRIER_EVENTS;LOCAL_GUARD_POLL_RESTART_SENSITIVE_EVENTS;LOCAL_GUARD_POLL_CONTRACT_GATE_EVENTS;LOCAL_GUARD_POLL_EVENT_POLICY_STRICT;LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_TICKET_CHAIN_CHECK;LOCAL_GUARD_POLL_STATUS_REPORT_INCLUDE_MAIN_PROCESS_HEALTH_CHECK;LOCAL_GUARD_POLL_STATUS_REPORT_ENABLE_MAIN_PROCESS_SELF_HEAL;LOCAL_GUARD_STATUS_ONLY_AUTOFLOW_EXEC_TOKEN;TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS;TASK_STATIC_PRECHECK_MAX_FAILS;TASK_STATIC_PRECHECK_BLOCK_EVENT;EXTERNAL_TRIGGER_EXECUTE;EXTERNAL_TRIGGER_COMMAND
RUN_MODE=foreground-visible
KEEP_WINDOW_ON_EXIT=true
ENTRY_MODE=single-param-fastmode
ENTRY_SCRIPT_A=tools/test/start_dev_verify_fastmode_A.ps1
ENTRY_SCRIPT_B=tools/test/start_dev_verify_fastmode_B.ps1
AUTO_START_MONITORS=true
RESTART_MONITORS_ON_STAGE_RESTART=true
MONITOR_ENTRY_SCRIPT_GUARD=tools/test/open_unattended_ab_session_guard_window.ps1
MONITOR_CHAIN_GRACE_MINUTES=40
GUARD_STARTUP_WARMUP_MINUTES=5
AUTO_START_TAKEOVER_TRIGGER=true
MONITOR_ENTRY_SCRIPT_TRIGGER=tools/test/open_unattended_ab_takeover_trigger_window.ps1
A_TASK_DEFINITION=testdata/<A_TASK_DEFINITION>.json
B_TASK_DEFINITION=testdata/<B_TASK_DEFINITION>.json
WINDOW=<YYYY-MM-DD ~ YYYY-MM-DD>
RESET_POLICY_A=restore-source
RESET_POLICY_B=state-only
START_ROUND=1
END_ROUND=8
RESUME_FAILED_ROUND=
DEV_VERIFY_STRIDE_A=2
DEV_VERIFY_STRIDE_B=2
VERIFY_EXECUTION_PROFILE=d6-only
ENABLE_GUARDED_FAST_MODE=true
ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP=true
TERMINAL_WATCHDOG_MODE=safe
TERMINAL_WATCHDOG_INTERVAL_SEC=120
TERMINAL_WATCHDOG_MIN_AGE_SEC=600
TASK_DESIGN_QUALITY_POLICY=enforce
TASK_STATIC_PRECHECK_POLICY=enforce
TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS=false
TASK_STATIC_PRECHECK_MAX_FAILS=3
TASK_STATIC_PRECHECK_BLOCK_EVENT=manual-wait-paused
UNKNOWN_NOOP_BUDGET=1
UNKNOWN_NOOP_CONSECUTIVE_LIMIT=2
DISABLE_UNKNOWN_NOOP_BUDGET_GATE=false
RB_PREFLIGHT=1
RB_PRECLASS_TABLE_GUARD=1
REMOTE_IP=10.0.0.199
REMOTE_USER=larson
REMOTE_KEYPATH=/c/Users/妙妙呜/.ssh/id_rsa
REMOTE_BUILD_LOCK_REQUIRED=true
REMOTE_BUILD_LOCK_SCOPE=remote-base
REMOTE_BUILD_LOCK_CONFLICT_ACTION=stop-before-build
QUERIES=8.8.8.8 1.1.1.1 10.0.0.8
MONITOR_POLICY_D1=ticket-driven-default-10m
A_SUCCESS_SNAPSHOT_REQUIRED=true
A_SUCCESS_SNAPSHOT_FINAL_STATUS=<out/artifacts/dev_verify_multiround/<A_RUN>/final_status.json>
A_SUCCESS_SNAPSHOT_SUMMARY=<out/artifacts/dev_verify_multiround/<A_RUN>/summary.csv>
A_SUCCESS_SNAPSHOT_SOURCE_STATE=<CLEAN_OR_GIT_STATUS_SHORT_SUMMARY_AT_A_PASS>
A_FAILURE_BLOCKS_B=true
A_FAILURE_RECOVERY=fix-a-then-rerun-a-before-b
B_START_REQUIRES_A_PASS_WITH_SNAPSHOT=true
B_FAILURE_RECOVERY=prefer-restart-b-from-a-snapshot
B_FAILURE_FALLBACK=rerun-a-then-b-if-snapshot-unreliable
A_LAUNCH_PID=0
B_LAUNCH_PID=0
WATCH_PARENT_PID=0
WATCH_LAUNCH_PID=0
WATCH_LAST_START_AT=
WATCH_LAST_EXIT_PID=0
WATCH_LAST_EXIT_AT=
SESSION_CLOSED_REASON=
SESSION_CLOSED=false
SESSION_CLOSED_AT=
B_RUNTIME_LOG=
MONITOR_CHAIN_SHUTDOWN_REASON=
MONITOR_CHAIN_SHUTDOWN_REQUESTED=false
MONITOR_CHAIN_SHUTDOWN_KEEP_WINDOW=true
MONITOR_CHAIN_SHUTDOWN_DETAIL=
MONITOR_CHAIN_SHUTDOWN_AT=
MONITOR_CHAIN_SHUTDOWN_SOURCE=
```

## 新增字段后的同步自检（建议）

当你在模板中新增 `LOCAL_GUARD_*` 字段后，建议立即执行：

powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_start_field_sync.ps1

该检查会同时验证以下同步面是否完整：
- 模板文件 `docs/UNATTENDED_AB_START_TEMPLATE_CN.md`。
- 启动文件目录 `testdata/unattended_start/active` 与 `testdata/unattended_start/smoke`。
- reset 选择器脚本 `tools/test/reset_unattended_ab_start_file.ps1`。
- status-only 执行模板 `tools/test/check_unattended_routine_status.ps1`（是否带 `-ExecutionToken "<token>"`）。
- `AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_FULL` 与 `AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_SHORT` 在模板与所有 start-file 中均为非空值（硬门禁）。
- 可选 strict 门禁：启用 `-EnforceRunningStatusMessageTemplateMatch` 时，要求上述两键在所有 start-file 中与模板文案完全一致。

通过标准：`result=pass` 且 `missing_field_files=0`、`missing_reset_files=0`、`empty_value_files=0`。

strict 模式（可选）示例：

powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_start_field_sync.ps1 -EnforceRunningStatusMessageTemplateMatch

## 编码格式约定（避免遗忘）

为兼容无人值守链路中中文消息、PowerShell 5.1 读取与跨脚本调用，以下关键脚本建议固定使用 **UTF-8 with BOM + LF**：
- `tools/test/create_unattended_ab_start_file.ps1`
- `tools/test/reset_unattended_ab_start_file.ps1`
- `tools/test/dispatch_takeover_to_chat.ps1`
- `tools/test/unattended_ab_takeover_trigger.ps1`
- `tools/test/update_chat_session_heartbeat.ps1`
- `tools/test/unattended_ab_session_guard.ps1`
- `tools/test/unattended_ab_session_guard.ps1`
- `tools/test/send_chat_message_ahk.ps1`

维护约束：
- 新增或重构聊天接管/心跳链路脚本时，若涉及中文文本或跨进程文本传递，评估后同步加入以上清单。
- 发布前建议对上述清单做一次字节级复检（BOM=true 且 EOL=LF），避免格式漂移。

强制规范执行（建议纳入每轮预检）：
```powershell
# 仅检查（建议 gate 使用）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dev/enforce_utf8_bom_lf.ps1 -Mode check -Policy enforce -Scope tracked

# 一键修复后再复检（建议本地整理时使用）
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dev/enforce_utf8_bom_lf.ps1 -Mode fix -Policy warn -Scope tracked
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dev/enforce_utf8_bom_lf.ps1 -Mode check -Policy enforce -Scope tracked
```

脚本说明：
- 默认作用范围是 Git 受管的 `.ps1/.json/.md` 文件（`-Scope tracked`）。
- 对生成目录可用 `-ExcludePaths` 做排除（例如：`out/generated/`）。
- 若仅需提示不阻断，可用 `-Policy warn`；需要硬门禁时使用 `-Policy enforce`。

## 源码编码格式约定与增量门禁

C 源码（`src/**/*.c`、`src/**/*.h`）编码要求：
- 字符编码：**UTF-8（无 BOM）**
- 行尾格式：**LF（Unix 风格）**
- 不可含 CR（`\r`），不可含 BOM 头（`0xEF 0xBB 0xBF`）

此规则与 start-file 的 UTF-8 with BOM + LF 规则不同，注意区分。

检查/修复脚本：`tools/dev/enforce_utf8_lf_src_changed.ps1`

仅检查增量变更：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dev/enforce_utf8_lf_src_changed.ps1 -Mode check -Policy enforce
```

增量自动修复 + 强校验（推荐无人值守使用）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/dev/enforce_utf8_lf_src_changed.ps1 -Mode fix -Policy enforce -IncludeUntracked
```

该脚本特性：
- 基于 `git diff --name-only` 仅扫描 `src/` 下新增或改动的 `.c`/`.h` 文件，不做全量扫描。
- 内置仓库级互斥锁，与全量编码脚本 `enforce_utf8_bom_lf.ps1` / `enforce_utf8_bom_lf_changed.ps1` 隔离。
- 锁忙时默认 `action=skip` 以保证无人值守连续性；关键阶段可传 `-FailIfLocked` 做强一致阻断。

在门禁链路中的位置（接在现有 BOM/LF 门禁之后）：

```
incremental encoding fix（enforce_utf8_bom_lf_changed.ps1）
  → tracked file full check（enforce_utf8_bom_lf.ps1）
  → src C encoding fix/check（enforce_utf8_lf_src_changed.ps1） ← 本门禁
```

当前 `tools/test/check_unattended_ab_launch_ready.ps1`（非 `-DryRun`）和 `start_dev_verify_fastmode_A.ps1` / `start_dev_verify_fastmode_B.ps1` 已自动执行此门禁。

运行中常见回填片段（新增监控/接管锚点示例）：
```text
RESTART_EVIDENCE_NOTES=stage=A reason=d1-stall evidence=out/artifacts/dev_verify_multiround/<CURRENT_RUN>/restart_evidence/<YYYYMMDD-HHMMSS>
SESSION_FINAL_NOTES=A started at <YYYY-MM-DD HH:MM:SS> via fastmode A; current_round=D1; run_dir=out/artifacts/dev_verify_multiround/<CURRENT_RUN>; B pending A PASS and snapshot; guard_log=out/artifacts/ab_session_guard/<YYYYMMDD-HHMMSS>/guard.log; live_status=out/artifacts/ab_session_guard/<YYYYMMDD-HHMMSS>/live_status.json
SESSION_FINAL_NOTES=A PASS; a_snapshot_dir=out/artifacts/dev_verify_multiround/<A_RUN>/a_success_snapshot; launching B; guard_log=out/artifacts/ab_session_guard/<YYYYMMDD-HHMMSS>/guard.log; live_status=out/artifacts/ab_session_guard/<YYYYMMDD-HHMMSS>/live_status.json
SESSION_FINAL_NOTES=B started at <YYYY-MM-DD HH:MM:SS>; run_dir=out/artifacts/dev_verify_multiround/<B_RUN>; guard_log=out/artifacts/ab_session_guard/<YYYYMMDD-HHMMSS>/guard.log; live_status=out/artifacts/ab_session_guard/<YYYYMMDD-HHMMSS>/live_status.json
SESSION_FINAL_NOTES=<previous-notes>; evidence=out/artifacts/ab_session_guard/<YYYYMMDD-HHMMSS>/blocked_package_<YYYYMMDD-HHMMSS>
SESSION_FINAL_NOTES=<previous-notes>; guard_blocked reason=<stage-stall> evidence=out/artifacts/ab_session_guard/<YYYYMMDD-HHMMSS>/blocked_package_<YYYYMMDD-HHMMSS>
```

预检字段约定：
- 可复用的任务触发文件在真正执行前，预检相关字段默认统一填写为 `NOT_RUN`。
- `NOT_RECORDED` 仅用于事后补记历史启动文件、且当时确实未留下显式预检记录的特殊场景；不建议用于后续还要继续复用的触发文件。
- `PRECHECK_STATUS` 仅当全部必需子项通过后才能写为 `PASS`；任一子项失败则写为 `FAIL`，并填写 `PRECHECK_FAILURE_REASON`。
- 除 `PRECHECK_WORKSPACE_STATUS_DETAIL`、`PRECHECK_REMOTE_LOCK`、`PRECHECK_START_GATE`、`PRECHECK_START_BLOCKER`、`PRECHECK_FAILURE_REASON`、`PRECHECK_NOTES` 外，其余 `PRECHECK_*` 子项在实际预检后建议统一填写为 `PASS` 或 `FAIL`；`NOT_RUN` 仅用于尚未执行预检前。
- `PRECHECK_WORKSPACE_STATUS_DETAIL` 建议填写启动前 `git status --short` 的单行摘要；工作区干净可写 `CLEAN`。
- `PRECHECK_REMOTE_LOCK` 建议写为 `absent`、`held-by-self`、`blocked` 或 `unknown` 之一；若为 `blocked`，不得启动 A/B。
- `PRECHECK_START_GATE` 建议写为 `READY`、`BLOCKED` 或 `NOT_RUN`；仅当 `PRECHECK_STATUS=PASS` 且 `PRECHECK_REMOTE_LOCK` 为 `absent` 或 `held-by-self` 时，才能写为 `READY`。若为 `BLOCKED`，应在 `PRECHECK_START_BLOCKER` 中写明首要阻断原因。
- 若本轮预检主要由人工或 Copilot 在脚本启动前手工完成，应将实际执行者记录到 `PRECHECK_OPERATOR`，避免只在对话中口头确认。
- 当前更推荐由 `tools/test/check_unattended_ab_launch_ready.ps1` 统一驱动预检与写回；AI 不必逐项申请检查授权，只需在脚本整体 PASS 后向用户提一次最终启动授权。

运行字段约定：
- `START_PARAMETER_ECHO_REQUIRED` 与 `STATUS_REPORT_REQUIRED` 用于固定本轮执行纪律；默认建议保持为 `true`，避免仅靠口头提醒。
- `AI_SESSION_BLOCKING_WATCH_REQUIRED` 建议保持为 `true`；当该值为 `true` 时，执行者应在会话内保持事件驱动响应与定时轮询节奏，不得仅依赖 guard 脚本。该约束强调“会话持续在线与按节奏回报”，不要求持续占用单个终端的阻塞式实时输出窗口。`AI_SESSION_BLOCKING_WATCH_REPORT_INTERVAL_MIN` 建议保持 `10`，`AI_SESSION_BLOCKING_WATCH_SCOPES` 建议至少包含 `artifacts;guard_log;compile-step`。
- 当 `AI_SESSION_BLOCKING_WATCH_REQUIRED=true` 时，`unattended_ab_session_guard.ps1` 会按 `AI_SESSION_BLOCKING_WATCH_REPORT_INTERVAL_MIN` 输出结构化 `watch_heartbeat`，并将当前 watch 策略写入 `AI_SESSION_BLOCKING_WATCH_NOTES`，用于接管与复盘。
- `poll_agent_tickets.ps1` 默认只读取会话心跳文件（`AI_CHAT_HEARTBEAT_*`）并回显心跳摘要（文本标签为 `chat_heartbeat`，JSON 键为 `chat_session_heartbeat`）；仅当 `AI_CHAT_HEARTBEAT_WRITE_ON_POLL=true` 时才代写心跳。推荐保持 `AI_CHAT_HEARTBEAT_WRITE_ON_POLL=false`，并由会话内定时执行 `tools/test/update_chat_session_heartbeat.ps1 -StartFile "<start-file>" -Source "chat-session-active" -AsJson` 主动发送心跳。默认心跳路径现为 `out/artifacts/ab_agent_queue/chat_session_heartbeat_<start-file-stable-token>.json`，该 stable token 基于 start-file 完整路径生成；若升级过渡期默认新命名文件不存在而旧命名文件仍存在，脚本会自动回读并沿用旧命名文件，避免长会话中途断点。
- `unattended_ab_takeover_trigger.ps1` 可在 `AI_CHAT_AUTO_RECOVER_ENABLED=true` 且心跳超时时自动触发接管投送；模板默认开启，建议保留并结合 `AI_CHAT_AUTO_RECOVER_COOLDOWN_MINUTES`。为缩短“会话回合意外结束”恢复时延，启用自动恢复后建议同时启用短间隔补发：`AI_CHAT_AUTO_RECOVER_FAST_RETRY_ENABLED=true`、`AI_CHAT_AUTO_RECOVER_FAST_RETRY_SECONDS=90`。trigger/dispatch/status-report/poll 的默认状态文件同样按 start-file 完整路径 stable token 隔离，并在默认新路径缺失且旧路径存在时自动 fallback 到 legacy 命名。
- `AI_CHAT_FINAL_TRIGGER_VERIFY_MS`（默认 `1200`）与 `AI_CHAT_FINAL_TRIGGER_MAX_ATTEMPTS`（默认 `2`）用于终态总结票（`chat-session-final-status`）分发存活保障：trigger 在拉起 `dispatch_takeover_to_chat.ps1` 后会等待并校验分发进程存活；若校验失败按尝试次数快速重试，未确认成功前会延迟 auto-stop（日志 `auto_stop_deferred`）并继续驻留。
- 统一策略源键（建议只改这 5 个）：`AI_CHAT_POLICY_WORK_MODE`（`normal`/`anti-missent`/`low-disturb`/`event-only`）、`AI_CHAT_POLICY_DELIVERY_PRIMARY`（`ipc`/`pywinauto`/`ahk`）、`AI_CHAT_POLICY_DELIVERY_FALLBACK`（`on`/`off`）、`AI_CHAT_POLICY_FINAL_STOP_GATE`（`trigger-started`/`sender-sent`）、`AI_CHAT_POLICY_VERSION`（当前 `1`）。
- `AI_CHAT_POLICY_WORK_MODE=normal`：保持交互分发（含 `running-status-report`）；`anti-missent`：保持交互分发并启用严格前台窗口约束（`AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY=true`）；`low-disturb`：保留状态票交互发送，但将 `running-status-report` 收敛为低扰短报文与最小健康检查，只保留运行状态与主进程/监控链真实存活检查；若结果正常，仅回报“运行正常”与 `handled_at`，若结果异常或触发自愈/故障处理，则切回 normal 口径回复完整状态；`event-only`：仅保留事件驱动票据，关闭 guard 定时状态票生成（`LOCAL_GUARD_STATUS_TICKET_ENABLED=false`）并同步关闭状态票外部分发（`AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS=false`、`AI_CHAT_DISPATCH_STATUS_REPORT_INTERACTIVE=false`）。

模式速查：

| 模式 | 定时状态票生成 | 状态票外部分发 | 推荐场景 | 现成 smoke 样例 |
| --- | --- | --- | --- | --- |
| `normal` | 开 | 交互发送 | 常规无人值守主流程 | [normal smoke 样例](../testdata/unattended_start/smoke/unattended_ab_start_status_ticket_smoke.md) |
| `anti-missent` | 开 | 交互发送，且仅限前台激活窗口 | 误投风险高、需要严格前台约束 | 基于 `normal` 样例改 `AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY=true` |
| `low-disturb` | 开 | 交互发送，但仅低扰短报文 | 想保留状态票与工单流，但把“正常运行”回报压缩到最小 | [low-disturb smoke 样例](../testdata/unattended_start/smoke/unattended_ab_start_status_ticket_low_disturb_smoke.md) |
| `event-only`（默认） | 关 | 关 | 常规无人值守主流程，仅在真实事件发生时投送 | [event-only smoke 样例](../testdata/unattended_start/smoke/unattended_ab_start_event_only_smoke.md) |
- `AI_CHAT_POLICY_DELIVERY_PRIMARY` + `AI_CHAT_POLICY_DELIVERY_FALLBACK` 组合决定主/收底链路：`ipc+on/off`=IPC 投送（默认 `AI_CHAT_DISPATCH_IPC_MODE=visible`，当前不跨 sender 收底）；`pywinauto+on`=Pywinauto 主投送+AHK 收底，`ahk+on`=AHK 主投送+Pywinauto 收底，`off` 表示仅主链路发送。
- `AI_CHAT_POLICY_FINAL_STOP_GATE=sender-sent` 时，trigger 在 `chat-session-final-status` 场景会等待 dispatch `latest_relay_*.json` 出现 `sender_sent=true` 后才允许 auto-stop；`trigger-started` 保持旧行为（仅确认触发已拉起）。
- 默认 `event-only` 下 `AI_CHAT_TRIGGER_DISPATCH_STATUS_REPORTS=false`，trigger 仅派发事件票；显式切换为 `normal`、`anti-missent` 或 `low-disturb` 时，模式归一化脚本会恢复状态票生成、派发与交互字段。
- `AI_CHAT_TRIGGER_EVENT_DRIVEN_QUEUE` 默认建议 `true`：启用事件驱动队列读取，减少轮询路径对分发时序的扰动。
- `AI_CHAT_TRIGGER_SKIP_EXISTING_QUEUE_ON_START` 默认建议 `true`：trigger 首次启动时跳过队列中的历史存量票，仅消费启动后新增票；若需要重放历史票可显式改为 `false`。
- 默认模板已预置：`AUTO_START_TAKEOVER_TRIGGER=true`、`EXTERNAL_TRIGGER_EXECUTE=true`，且 `EXTERNAL_TRIGGER_COMMAND` 指向 `tools/test/dispatch_takeover_to_chat.ps1`。
- `open_unattended_ab_stage_window.ps1` / `open_unattended_ab_resume_window.ps1` 会依据上述 `AI_CHAT_POLICY_*` 自动回写 `AI_CHAT_DISPATCH_*` 派生键；日常切模式优先改源键，避免手工改一组派生键造成漂移。
- 若需在运行中对单个 start-file 做模式热切换，建议使用 `tools/test/switch_unattended_start_file_mode.ps1 -StartFile <path> -Mode <normal|anti-missent|low-disturb|event-only>`：脚本会先检查模式相关关键字段是否完整，缺失项自动补齐后再切换，并回显 `final_mode`。
- 为防止工单高频时堆积编辑区或拉起额外 VS Code 实例，模板默认关闭编辑器与系统剪贴板路径：`AI_CHAT_DISPATCH_OPEN_EDITOR=false`、`AI_CHAT_DISPATCH_USE_CLIPBOARD=false`；分发默认走 IPC Visible（`AI_CHAT_DISPATCH_USE_IPC=true`、`AI_CHAT_DISPATCH_IPC_MODE=visible`），并禁用窗口前后动作（`AI_CHAT_DISPATCH_INTERACTIVE_PRE_ACTIONS_ENABLED=false`）。
- 若需要按场景微调，可在启动文件中覆盖 `AI_CHAT_DISPATCH_*` 键：`USE_IPC`、`IPC_MODE`、`INTERACTIVE_PRE_ACTIONS_ENABLED`、`USE_PY_SENDER`、`USE_AHK`、`OPEN_EDITOR`、`USE_CLIPBOARD`、`AUTO_RECONNECT_RESEND`、`RECONNECT_DELAY_MS`、`RECONNECT_WINDOW_SEC`、`MAXIMIZE_WINDOW`、`AHK_EVENT_ALLOWLIST`、`HEARTBEAT_TIMEOUT_SEND_ENABLED`、`HEARTBEAT_TIMEOUT_REQUIRE_CODE_FOCUS`、`ACTIVE_WINDOW_ONLY`、`STATUS_REPORT_INTERACTIVE`、`STATUS_REPORT_MESSAGE_MODE`、`STATUS_REPORT_SEND_FULL_ON_FIRST`、`CLEAR_INPUT_ON_FAILURE`、`ESC_PREFLIGHT`、`CHAT_TOGGLE_SHORTCUT_ENABLED`、`CHAT_TOGGLE_SHORTCUT`、`X_MODE`、`RIGHT_OFFSET_PX`、`BOTTOM_AVOID_PX`、`PRESEND_DELAY_MS`。
- `AI_CHAT_DISPATCH_CLEAR_INPUT_ON_FAILURE=true`（默认）表示发送失败后先清空聊天输入框，再执行跨 sender 收底；设为 `false` 时保留失败遗留输入，便于人工观察失败并手动重发。
- `AI_CHAT_DISPATCH_ACTIVE_WINDOW_ONLY=false`（默认）表示允许 dispatch 在需要时激活/切换 VS Code 窗口完成投送；若需严格限制为“仅当前前台已激活的 VS Code 窗口”可改为 `true`。
- `AI_CHAT_DISPATCH_STATUS_REPORT_MESSAGE_MODE=alternate`（默认）表示状态票在 `full/full-first` 与 `short` 间交替发送；可改为 `short`（始终短消息）或 `full`（始终完整提示词）。`AI_CHAT_DISPATCH_STATUS_REPORT_SEND_FULL_ON_FIRST=true`（默认）表示每个 start-file 首次状态票优先发送一次完整提示词。
- `AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_FULL` 与 `AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_SHORT` 在默认 `event-only` 模式下不会被投送，但仍必须保持非空，作为显式切换到 `normal`、`anti-missent` 或 `low-disturb` 后的状态票兜底模板。建议保留 `[FULL-RUNBOOK]` / `[SHORT-CARD]` 前缀，并让内容与当前自愈门禁一致。
- 推荐最小示例（单行；可直接粘贴到 start-file）：
```text
AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_FULL=[FULL-RUNBOOK] 保持事件驱动+主动心跳；先报根因与修复路径；若本票健康，则根因写“无活动故障/常规定时状态票”，修复路径写“continue_watch only”；任务定义修复必须先做故障 op 目标检查，再做全部受影响 D 轮整轮检查；吸收/幂等态保持 regex-patch，禁止改成 noop；两层检查通过后仅重启票据对应阶段；可自愈且未触发预算/冷却耗尽且非不可恢复环境时，立即按 next_command_order 执行；处置后进入只读监控；不要仅凭旧 exit 证据建议重启 B；不得手工创建 chat_heartbeat/handled 回执文件或非 tmp 新脚本；运行期禁止 git commit/git push（除非用户同轮明确授权）；仅在A/B终态或我明确下达stop monitoring时停止；最终收尾显式上报会话结束日期时间。
AI_CHAT_DISPATCH_MESSAGE_RUNNING_STATUS_SHORT=[SHORT-CARD] 先报根因+修复路径；健康状态票固定为"无活动故障/常规定时状态票 + continue_watch only"；任务定义修复按目标 op -> 受影响整轮检查，吸收/幂等态不得改 noop，检查通过后仅同阶段重启；随后按 next_command_order 执行并回到事件驱动+心跳只读监控；本票完成后立即回传 handled_at，仅在stop monitoring或A/B终态时回传 session_closed_at；不要仅凭旧 exit 证据建议重启 B；运行期禁止 git commit/git push（除非用户同轮明确授权）；回传chat_heartbeat关键字段（SESSION/A/B、run_dir、main_round、guard、B exit digest）。
```
- 若设置了上述覆盖键，且 `AI_CHAT_DISPATCH_ALLOW_RUNNING_STATUS_MESSAGE_OVERRIDE=true`，dispatch 会优先采用覆盖文本；当前模板默认即走覆盖文本，脚本内默认文案仅作为兜底。
- 无人值守运行前提硬约束：应在目标聊天会话中发出启动指令，且启动前人工确认聊天输入框可见并可输入。
- 运行中策略：不做“每条消息发送前的聊天面板开关态预检”；仅在出现 `ahk_exit_code=38/41` 这类焦点保护失败时执行一次聊天面板恢复后重发（`dispatch_takeover_to_chat.ps1` 已内置一次自动恢复重发）。
- 为降低误触发风险，`AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_SEND_ENABLED` 默认建议保持 `false`；即使 allowlist 含 `chat-session-heartbeat-timeout`，也不会执行 AHK 文本发送（仅落盘 relay/brief）。
- 当确需启用 heartbeat 超时发送时，建议保持 `AI_CHAT_DISPATCH_HEARTBEAT_TIMEOUT_REQUIRE_CODE_FOCUS=true`（默认值）：发送前必须通过 VS Code 命令聚焦聊天输入框，否则直接拒绝发送，避免误投到终端或其他输入框。
- `LOCAL_GUARD_AUTO_FIX_D_COMPILE`、`LOCAL_GUARD_AUTO_FIX_MAX_PER_D_ROUND`、`LOCAL_GUARD_AUTO_FIX_COOLDOWN_MINUTES` 用于控制 guard 的 D 轮编译失败自动修复编排；默认建议开启，且每个 D 轮最多 3 次。
- `LOCAL_GUARD_AGENT_QUEUE_ENABLED` 与 `LOCAL_GUARD_AGENT_QUEUE_PATH` 用于启用 guard 工单队列（JSONL 追加写入）；建议保持开启，便于会话中断后快速接管。
- `LOCAL_GUARD_STATUS_TICKET_ENABLED` 与 `LOCAL_GUARD_STATUS_TICKET_INTERVAL_MINUTES` 控制定时状态票；模板默认 `event-only`，因此前者为 `false`，不生成 `running-status-report`。显式切换到其他模式后才按间隔生成状态票。
- 模式切换后可直接复用现成 smoke 样例：`normal` 见 [normal smoke 样例](../testdata/unattended_start/smoke/unattended_ab_start_status_ticket_smoke.md)，`low-disturb` 见 [low-disturb smoke 样例](../testdata/unattended_start/smoke/unattended_ab_start_status_ticket_low_disturb_smoke.md)，`event-only` 见 [event-only smoke 样例](../testdata/unattended_start/smoke/unattended_ab_start_event_only_smoke.md)。
- 若需要直接对照当前 active 窗口配置：`normal` 见 [active normal 样例](../testdata/unattended_start/active/unattended_ab_start_20261031-20261115.md)，`event-only` 见 [active event-only 样例](../testdata/unattended_start/active/unattended_ab_start_20261031-20261115_event_only.md)。
- `event-only` 的低成本联调建议优先做静态/半静态检查，再决定是否真正拉起 A/B：先执行 `tools/test/check_unattended_start_field_sync.ps1` 确认模板与 start-file 同步；再用 `tools/test/check_unattended_routine_status.ps1 -StartFile "testdata/unattended_start/smoke/unattended_ab_start_event_only_smoke.md" -AsJson` 查看 routine 摘要；最后用 `tools/test/poll_agent_tickets.ps1 -StartFile "testdata/unattended_start/smoke/unattended_ab_start_event_only_smoke.md" -IncludeStatusReports -Last 20 -AsJson` 检查当前是否只有事件票而没有新生成的定时状态票。若返回 `rows=[]` 或 `no_pending_rows`，在无事件入队的前提下属于正常现象。
- 模板默认推荐“自动恢复 + IPC Visible 投送”模式：`EXTERNAL_TRIGGER_EXECUTE=true` 且 `AUTO_START_TAKEOVER_TRIGGER=true`。若需回退到“仅工单队列 + 会话内事件驱动轮询监控”，可手工改为 `false/false`。
- 会话内主动拉取建议使用 `tools/test/poll_agent_tickets.ps1`（按定时状态票节奏执行）。脚本会返回待处理工单，并为每张工单生成两段执行指令：`business_command`（业务恢复动作）与 `continue_watch_command`（继续监控并保持会话在线节奏）；若返回 `mark_processed_command`，应在前两段执行成功后立即执行以回写完成标记，避免跨轮次重复拉取。这里要区分两套策略：`running-status-report` 仍按“最新一张优先、旧票覆盖”的状态票规则处理，而事件驱动票采用幂等排空策略：仅处理“本期执行启动基线（`event_queue_floor_at`）之后”的事件票，先按 `created_at` 找本期最早未处理票；事件仍存在则处理，不存在则直接标记已处理并继续下一张，直到本期事件票全部排空。排空完成后，执行链自动回到之前工作模式（`normal/anti-missent/low-disturb/event-only`）。当前脚本会把 `handled_at` 作为 ledger 一等字段回写，并在 JSON 输出中返回 `handled_receipts`；额外的 `handled_tickets/*.md` 默认关闭，仅在 `LOCAL_GUARD_WRITE_HANDLED_ARTIFACTS=true` 时才启用。
- 在无人值守运行期间，以上工单流属于预授权既定工作，AI 不应为这些标准步骤反复询问用户是否执行。
- 对 `running-status-report`（定时状态票），`poll_agent_tickets.ps1` 默认会填充状态检查型 `business_command`。在 `normal/anti-missent` 下，默认仍包含主进程健康检查与轻量巡检；在 `low-disturb` 下，会收敛为最小健康检查，但保留有界自愈能力（尤其是主进程缺失与监控链缺失），并在必要时升级事件票（`incident-captured` / `main-process-exit-review`），避免模式切换削弱故障闭环。若检查结果正常且未触发自愈/故障处理，聊天回报仅保留“运行正常”与 `handled_at`，且根因应明确写成“无活动故障/常规定时状态票”，不得据历史 exit 证据建议重启 B；若检查结果异常，或触发了自愈/故障处理，则按 normal 口径回复完整状态。
- 主动心跳与 handled 回执都应走正式脚本链路：心跳只用 `tools/test/update_chat_session_heartbeat.ps1`，handled 只用 `poll_agent_tickets.ps1 -AcknowledgeTicketIds ...` / `mark_processed_command`；不要手工写 `chat_heartbeat*.jsonl`、`chat_heartbeat_reports_additional_*.jsonl` 或额外 handled 文件。
- `poll_agent_tickets.ps1` 支持事件族策略键（逗号/分号分隔）：`LOCAL_GUARD_POLL_STATUS_REPORT_EVENTS`、`LOCAL_GUARD_POLL_DRAIN_SAFE_EVENTS`、`LOCAL_GUARD_POLL_BARRIER_EVENTS`、`LOCAL_GUARD_POLL_RESTART_SENSITIVE_EVENTS`、`LOCAL_GUARD_POLL_CONTRACT_GATE_EVENTS`。未填写时使用内置默认集合。
- 安全约束（脚本内置强制）：无论如何配置，`running-status-report` 会被补齐到 `LOCAL_GUARD_POLL_STATUS_REPORT_EVENTS`，并同步补齐到 `LOCAL_GUARD_POLL_DRAIN_SAFE_EVENTS`。
- 安全约束（脚本内置强制）：若 `LOCAL_GUARD_POLL_BARRIER_EVENTS` 或 `LOCAL_GUARD_POLL_RESTART_SENSITIVE_EVENTS` 未包含核心事件（`incident-captured`、`recovery-await-confirmation`、`auto-fix-await-confirmation`），脚本会自动补齐，并在 `event_policy.adjustments` 中给出本轮规范化记录。
- 安全约束（脚本内置强制）：`LOCAL_GUARD_POLL_CONTRACT_GATE_EVENTS` 至少包含 `task-definition-fix-required`，用于脚本契约修复工单的强锚点门禁命令下发。
- 可选严格模式：设置 `LOCAL_GUARD_POLL_EVENT_POLICY_STRICT=true` 时，若脚本检测到上述自动补齐需求，将直接失败退出并提示修正 `LOCAL_GUARD_POLL_*` 配置。
- V2 语义冻结文档见 `docs/RFC-unattended-ticket-polling-v2.md`；涉及状态机、重启屏障、drain、重试与归档策略时，以该文档为实现与评审基准。会话驻留与定时动作边界请参见该文档第 4.1 节。
- 模型与思考档位分层建议见 [RFC-unattended-model-tiering.md](RFC-unattended-model-tiering.md)；涉及 `GPT-5 mini` 的默认档位、适用范围、升级条件，以及哪些工作必须升级到 `GPT-5.4` 级模型时，以该文档为长期参考。
- 若需要从“任务定义模板 -> 启动文件 -> 预检 -> A/B 启动 -> 监控 -> 回填”的完整顺序查阅，请直接看 [UNATTENDED_AB_OPERATION_FLOW_CN.md](UNATTENDED_AB_OPERATION_FLOW_CN.md)。
- `EXTERNAL_TRIGGER_COMMAND` 为自动恢复默认链路入口：当 `EXTERNAL_TRIGGER_EXECUTE=true` 时，触发器会按模板执行 `tools/test/dispatch_takeover_to_chat.ps1`。
- 若后续需要关闭触发器，可手工设置 `AUTO_START_TAKEOVER_TRIGGER=false`；再次启用时恢复为 `true` 并保留 `MONITOR_ENTRY_SCRIPT_TRIGGER` 指向默认启动脚本。
- 模板默认 `LOCAL_GUARD_WAIT_FOR_MANUAL_RESTART=false`：统一事件驱动、事件全投送、三类故障自动处理的默认策略优先走自动恢复，不再先落入 manual-wait 暂停态；若需要切回人工等待，再显式改为 `true`。`LOCAL_GUARD_MANUAL_NOTICE_REPEAT` 仅在启用 manual-wait 时生效。
- 常态无人值守推荐 `LOCAL_GUARD_RESTART_REQUIRES_CONFIRM=false` 与 `LOCAL_GUARD_RESTART_APPROVED=true`，避免重启链路卡在人工批准。
- 临时调试可切换为 `LOCAL_GUARD_RESTART_REQUIRES_CONFIRM=true` 与 `LOCAL_GUARD_RESTART_APPROVED=false`，仅在人工确认后临时置 `LOCAL_GUARD_RESTART_APPROVED=true` 放行一次重启，随后建议回写为 `false`。
- `LOCAL_GUARD_SUPPRESS_KNOWN_INFRA_TICKETS=true` 用于在 D 轮识别到已知基础设施瞬态失败（如 network precheck/SSH 超时）时抑制 guard 工单入队，避免无效触发外部接管链路。
- `LOCAL_GUARD_EXIT_ON_KNOWN_INFRA_TRANSIENT=true` 表示命中上述已知基础设施瞬态失败后，guard 直接写入停止态并退出，不进入后续自动恢复/人工确认等待分支。
- `TASK_STATIC_PRECHECK_POLICY` 用于控制开跑前一次性任务定义静态体检（`tools/test/check_task_definition_static.ps1`），默认建议 `enforce`；任务定义同时保持 `qualityPolicy.operationSafetyPolicy=enforce`。严格检查覆盖 replacement 双转义、pattern 唯一匹配、每 op marker 所有权、替换收敛、整轮二次应用稳定、孤儿函数体风险与 `postApplyAssertions` 精确计数。开跑或自愈重启前还应运行 `tools/test/task_definition_safety_regression.ps1`，避免运行中才暴露已知事故形态。
- `TASK_STATIC_PRECHECK_FAIL_ON_WARNINGS` 用于控制静态体检是否将 warning 视为失败（传递 `-FailOnWarnings`）；默认建议 `true`，用于无人值守前置拦截“可疑但高风险”的任务定义漂移。
- `MAX_STAGE_RESTARTS`、`A_MAX_STAGE_RESTARTS`、`B_MAX_STAGE_RESTARTS` 用于配置阶段重启预算；`unattended_ab_session_guard.ps1` 会优先读取启动文件字段，缺省时才回退到脚本参数。
- `RESTART_EVIDENCE_REQUIRED`、`RESTART_EVIDENCE_MINIMUM` 与 `RESTART_SEQUENCE` 用于固定“先留证、再清场、最后重启”的顺序；若本轮发生卡滞重启，应将证据位置或摘要写入 `RESTART_EVIDENCE_NOTES`。
- `REMOTE_KEYPATH` 建议始终保留模板中的 MSYS 路径字面量，并以 UTF-8 with BOM + LF 保存启动文件；若出现用户名乱码，应先修正路径文本后再继续复用该文件，避免 guard 误读 SSH key 路径。
- `NETWORK_PRECHECK_*` 建议保持“check 与 require 解耦”：`*_CHECK_*` 决定是否探测该维度，`*_REQUIRE_*` 决定该维度失败是否阻断；默认建议 `NETWORK_PRECHECK_REQUIRE_IPV6=true`、`NETWORK_PRECHECK_REQUIRE_IPV4=false`。`*_LAST_*` 由启动脚本回填最近一次预检结果。
- `ROUND_RUNTIME_GATE_*` 用于控制 D 轮次运行前硬门禁（默认 D2 起生效）。required 项包括目录可写/磁盘余量、remote lock、网络 required 连通；optional 项包括并发进程冲突告警。required 失败会在当前轮次提前退出，避免继续执行明知无法通过的验证。
- `A_SUCCESS_SNAPSHOT_SOURCE_STATE` 用于记录 A 成功快照固化时的源码状态摘要；建议填写 `CLEAN` 或当时 `git status --short` 的单行摘要。
- `A_FINAL_STATUS`、`B_FINAL_STATUS` 建议使用 `NOT_RUN`、`RUNNING`、`PASS`、`FAIL`、`BLOCKED`；若 A 失败导致 B 未启动，B 建议写为 `BLOCKED`。
- `SESSION_END_CONDITION` 默认固定为 `a-and-b-final`；`SESSION_FINAL_STATUS` 在 A/B 都形成最终结论前不应写为完成态，建议使用 `NOT_RUN`、`RUNNING`、`PASS`、`FAIL`、`BLOCKED`。必要补充可写入 `SESSION_FINAL_NOTES`。
- `SESSION_FINAL_NOTES` 在运行中不应被当作纯自由文本覆盖；若已启用本地监控层，建议保留以 `;` 分隔的 `key=value` 锚点，至少不要删除 `run_dir=...`、`guard_log=...`、`live_status=...`、`a_snapshot_dir=...`、`evidence=...` 这类片段，便于 guard 与后续人工接管继续定位状态。
- `AUTO_START_MONITORS=true` 时，`open_unattended_ab_stage_window.ps1`（Stage A）与 `open_unattended_ab_resume_window.ps1` 会在拉起 A 后自动拉起 guard + trigger。 supervisor/companion 功能已合并到 guard。`AUTO_START_TAKEOVER_TRIGGER` 未显式填写时，会回退使用 `EXTERNAL_TRIGGER_EXECUTE` 作为 trigger 自动拉起开关；`RESTART_MONITORS_ON_STAGE_RESTART=true` 时会先终止同一 start file 的旧监控进程再重启，避免异常退出后遗留旧监控。
- 对 Stage B，标准操作仍建议显式使用 `open_unattended_ab_stage_window.ps1 -Stage B -StartMonitors`。当前实现会按“是否偏离 A 快照”自动选择监控附着或重绑；`-EnableBMonitorRestart` 仅作为兼容开关，不应再作为日常必填参数。
- `MONITOR_ENTRY_SCRIPT_GUARD` 与 `MONITOR_ENTRY_SCRIPT_TRIGGER` 可显式指定监控/触发器启动脚本路径；留空时默认分别使用 `tools/test/open_unattended_ab_session_guard_window.ps1` 与 `tools/test/open_unattended_ab_takeover_trigger_window.ps1`。
- `RERUN_FROM_A_REQUIRES_STARTFILE_RESET=true` 表示若继续复用同一份启动文件执行“A 修复 -> A 重跑”，必须先把该文件恢复到未运行基线；`RERUN_FROM_A_STARTFILE_RESET_FIELDS` 列出最低需要复位的字段范围。通常 `PRECHECK_*` 相关状态位回到 `NOT_RUN`，详情/备注类字段回到空值或 `TO_BE_FILLED`，`A_SUCCESS_SNAPSHOT_*` 回到待重新捕获状态，`A_FINAL_STATUS`、`B_FINAL_STATUS`、`SESSION_FINAL_STATUS` 回到 `NOT_RUN`。
- `start_dev_verify_fastmode_A.ps1` 与 `start_dev_verify_fastmode_B.ps1` 现已默认执行 remote lock 硬检查（`tools/dev/check_remote_lock.ps1`）：远端锁被占用、状态异常或 SSH 检查失败会直接阻断本轮启动，避免进入长跑后才失败。
- `start_dev_verify_fastmode_A.ps1` 与 `start_dev_verify_fastmode_B.ps1` 现已默认执行网络硬检查（`tools/dev/check_dualstack_whois_connectivity.ps1`）：required 失败即阻断；optional 失败仅记录日志，不阻断。
- 触发文件完成基线复位后，一旦重新执行预检并正式启动，同一文件应立即回填为 `PASS/READY/RUNNING` 等运行态值；因此“正在运行中的启动文件”不应再期待保持初始 `NOT_RUN` 基线外观。
- `TERMINAL_WATCHDOG_MODE` 建议使用 `off` 或 `safe`；`safe` 仅定时记录心跳并清理活动运行树之外、达到最小存活时间的 shellIntegration PowerShell/bash 空壳及其直接关联 headless conhost，默认不清理通用 conhost。

### V1 自动修复闭环（会话内代理 + guard 串联）
1. 触发条件：会话内按事件驱动/定时状态票轮询监控期间，guard 检测到 A 阶段 D1-D4 失败，且证据判定为编译失败。
2. guard 自动动作：抓取该轮最后一次编译证据，执行“任务定义补丁修复 + 静态检查 + A 重启”编排；每个 D 轮最多 3 次，支持冷却时间。
3. 成功后串联：guard 重启主流程后继续按事件驱动与 10 分钟状态票节奏监控并播报状态，持续回填 `SESSION_FINAL_NOTES` 锚点。
4. 三次失败或非已知签名：guard 写明失败原因并退出自动修复流程，避免无限循环，转入会话内人工/代理接管修复。
5. 职责边界：guard 不具备通用代码修复能力；通用代码修改由会话内 Copilot 根据日志执行，guard 负责检测、编排与重启串联。

### 与 Copilot 协作触发方式
你可直接下达：
- 按 `testdata/unattended_start/active/unattended_ab_start_<YYYYMMDD-HHMM>.md` 启动 A/B 无人值守任务。

执行约定：
1. 我先做预检并回显解析参数，逐项确认或回填 `PRECHECK_*` 字段后，再按 A -> B 严格串行启动。
2. 我按 票据驱动监控策略、结合事件驱动与定时状态票节奏监控并处理卡滞重启（先留证再清场再重启）。
3. 仅在 A/B 运行成功后，运行结果统一回填 RFC，不回填本模板。
4. 若 A 失败，我会立即停止 A -> B 串行链，不启动 B，并先进入“A 修复 -> A 重跑”的路径。
   - 若继续复用原任务启动文件，我会先将其恢复到未运行基线，再重新执行预检并从 A-D1 启动。
5. A 成功后我会先固化 A 成功快照，再启动 B；若 B 编译失败，将优先按“A 快照恢复 -> B 重启”路径执行。
6. 仅当 A 快照无法可靠恢复时，我才会建议并执行“从 A 重新开始”的保守路径。
7. 每次 remote strict 编译前，我会先检查 remote build lock；若 lock 已被占用，则立即停止本轮编译并先处理占用问题。
8. guard 会把 `guard_log`、`live_status`、`evidence` 等定位锚点持续写回 `SESSION_FINAL_NOTES`；在任务结束前不应手工删改这些锚点。
9. 若观察到主运行终端与 guard 终端近似同时消失，应优先怀疑 VS Code 集成终端 / extension host 层异常，而不是直接假定 A/B 业务脚本自身失败；此时先检查 `renderer.log`、`terminal.log`、`ptyhost.log` 与 `guard_log` 尾部时间，再决定是否按 `BLOCKED` 接管。
