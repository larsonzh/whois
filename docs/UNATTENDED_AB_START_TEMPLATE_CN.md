# A/B 无人值守启动文本模板（CN）

## 会话内阻塞盯盘复制语句（建议）

极简一行版（聊天框速贴）：
从现在起，会话内代理阻塞式持续盯盘并每 10 分钟汇报，不要结束会话；修改 start-file 用 UTF-8 编码；发现脚本故障可直接修复脚本；允许在预算内闭环自动修复代码（修复->重启->复核->记录）；仅在 A/B 都到终态或我明确下达“停止盯盘”时结束。

短版（默认推荐）：
从现在起，会话内代理进入阻塞式持续盯盘模式，不要结束会话，以监控与汇报为主；修改 start-file 用 UTF-8 编码；发现脚本故障可直接修复脚本，并可在预算内执行闭环自动修复代码（修复->重启->复核->记录）；每 10 分钟汇报一次；仅在 A/B 都到终态或我明确下达“停止盯盘”时结束。

强约束版（高风险轮次推荐）：
从现在起，会话内代理阻塞式持续盯盘，不要结束会话；修改 start-file 用 UTF-8 编码；监控范围为 artifacts、supervisor_log、companion_log、compile-step；按 D1 的 90/30/10/20 规则判挂；前 30 分钟只观察；之后每 10 分钟检查；连续满足挂起条件 20 分钟才判挂；发现脚本故障可直接修复脚本；允许按预算执行闭环自动修复代码（默认每个 D 轮最多 3 次，修复->重启->复核->记录）；判挂前必须先采证（进程快照、产物目录快照、summary_partial 如存在）；未获我确认不得重启。

## 强绑定句（建议原样保留）
进入实时监控，按 D1 固定容忍窗口策略判挂（90/30/10/20，重启前先留证）。

## 触发文本模板（复制后按需替换）
请执行 A/B 无人值守串行重跑（前台可见模式，单参提速入口）：

- A 任务定义：`testdata/<A_TASK_DEFINITION>.json`
- B 任务定义：`testdata/<B_TASK_DEFINITION>.json`
- 目标时间窗：`<YYYY-MM-DD ~ YYYY-MM-DD>`

工作要求：
1. 执行前必须完成无人值守运行环境检查（本地与远端无残留相关进程、SSH 连通、任务定义文件存在且无 TODO、记录当前工作区状态）；检查未通过不得启动 A/B；并确认入口脚本与运行模式字段已按模板指定。预检结果必须写入本轮任务启动文件中的 `PRECHECK_*` 字段，并在实际启动 A/B 前逐项回显 PASS/FAIL。
   - 当前 `open_unattended_ab_stage_window.ps1` / `open_unattended_ab_resume_window.ps1` 已对 `PRECHECK_REQUIRED=true` 场景执行硬闸：若 `PRECHECK_STATUS!=PASS`、`PRECHECK_START_GATE!=READY` 或 `PRECHECK_REMOTE_LOCK` 不是 `absent|held-by-self`，将直接阻断启动并回填 `PRECHECK_START_GATE=BLOCKED`。
   - 当前 `start_dev_verify_fastmode_A.ps1` / `start_dev_verify_fastmode_B.ps1` 与 `open_unattended_ab_stage_window.ps1` 均已执行网络硬闸（`tools/dev/check_dualstack_whois_connectivity.ps1`）：本机+远端、IPv4+IPv6 按 `NETWORK_PRECHECK_*` 的 check/require 组合评估，任一 required 项失败即阻断启动。
2. 严格串行：先 A 后 B。
3. B 启动时不得回滚 A 基线（state-only）。
4. 全程持续实时监控并报告状态；在高风险轮次（尤其编译失败修复、任务定义变更后）Copilot 会话必须保持阻塞盯盘，不能仅依赖 monitor 脚本。
5. D1 判挂必须按固定运行策略：
   - 90 分钟窗口。
   - 前 30 分钟仅观测。
   - 30~90 分钟每 10 分钟做进展判定。
   - 仅当三条件连续 20 分钟同时成立才判挂并重跑。
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

建议执行命令（单参提速入口）：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_A.ps1 <A_TASK_DEFINITION>.json
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_B.ps1 <B_TASK_DEFINITION>.json
```
说明：默认固定使用以上两个 fastmode 入口脚本（前台可见、单参提速），除非本轮任务明确批准变更入口。

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

若本轮要求“主运行终端 / supervisor / companion 终端在结束后保留窗口，便于人工查看结束前状态”，或已观察到 VS Code 集成终端整批消失，建议优先使用外部 `NoExit` 窗口启动：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage B -EnableBMonitorRestart
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_supervisor_window.ps1 -CurrentARunDir out/artifacts/dev_verify_multiround/<CURRENT_RUN> -CurrentAStartRound <1|6>
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_companion_window.ps1 -SupervisorLog out/artifacts/ab_supervisor/<YYYYMMDD-HHMMSS>/supervisor.log
```
说明：
- `open_unattended_ab_stage_window.ps1` 用于直接在独立 PowerShell 窗口启动 A 或 B 主运行，窗口默认 `NoExit`。
- `open_unattended_ab_supervisor_window.ps1` 与 `open_unattended_ab_companion_window.ps1` 用于把两层监控从 VS Code 集成终端中剥离，降低因 terminal host / extension host 异常导致的整批丢窗风险。
- 当 `RUN_MODE=foreground-visible` 时，supervisor 后续拉起的阶段进程也会使用可见且 `NoExit` 的窗口，避免阶段结束后自动关窗。
- 若希望阶段结束后保留 A/B 主运行窗口用于复盘，请在任务启动文件中设置 `KEEP_WINDOW_ON_EXIT=true`（由 `open_unattended_ab_stage_window.ps1` / supervisor 透传到 fastmode 入口）。
- 外部 `NoExit` 窗口与 VS Code 集成终端生命周期解耦，VS Code 更新/重启后窗口仍可保留，便于事后排查。

## 本轮默认示例
- A：`autopilot_code_step_tasks_20260613_20260620.json`
- B：`autopilot_code_step_tasks_20260621_20260628.json`

## 任务启动文件（推荐每轮同时生成）
为避免发布任务时手填错误，建议每次在起草“下次开工清单 + 任务定义文件”后，同时生成一个可直接触发执行的任务启动文件（纯文本即可，建议放在 `tmp/` 目录）。

建议文件名：
- `tmp/unattended_ab_start_<YYYYMMDD-HHMM>.md`

建议自动化脚本：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/create_unattended_ab_start_file.ps1 -ATaskDefinition autopilot_code_step_tasks_20260715_20260722.json -BTaskDefinition autopilot_code_step_tasks_20260723_20260730.json -Window "2026-07-15 ~ 2026-07-30"
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile tmp/unattended_ab_start_20260422-2300.md -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/reset_unattended_ab_start_file.ps1 -StartFile tmp/unattended_ab_start_20260422-2300.md
```
说明：
- `create_unattended_ab_start_file.ps1` 会从模板代码块提取 `key=value` 并生成新启动文件，支持用参数覆盖 A/B 任务定义、窗口与 remote 字段，模板扩展字段会自动保留。
- `reset_unattended_ab_start_file.ps1` 会把运行态字段恢复到未运行基线，优先遵循 `RERUN_FROM_A_STARTFILE_RESET_FIELDS`，并提供 `-DryRun` 用于先查看变更。

建议内容模板（复制后替换尖括号）：
```text
AB_UNATTENDED_START_V1
BINDING_SENTENCE=进入实时监控，按 D1 固定容忍窗口策略判挂（90/30/10/20，重启前先留证）。
PRECHECK_REQUIRED=true
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
AI_SESSION_BLOCKING_WATCH_SCOPES=artifacts;supervisor_log;companion_log;compile-step
AI_SESSION_BLOCKING_WATCH_NOTES=
LOCAL_GUARD_WAIT_FOR_MANUAL_RESTART=true
LOCAL_GUARD_MANUAL_NOTICE_REPEAT=2
LOCAL_GUARD_AUTO_RECOVER_B=false
LOCAL_GUARD_RESTART_REQUIRES_CONFIRM=true
LOCAL_GUARD_RESTART_APPROVED=false
LOCAL_GUARD_AUTO_FIX_D_COMPILE=true
LOCAL_GUARD_AUTO_FIX_MAX_PER_D_ROUND=3
LOCAL_GUARD_AUTO_FIX_COOLDOWN_MINUTES=1
LOCAL_GUARD_AGENT_QUEUE_ENABLED=true
LOCAL_GUARD_AGENT_QUEUE_PATH=out/artifacts/ab_agent_queue/agent_tickets.jsonl
LOCAL_GUARD_STATUS_TICKET_ENABLED=true
LOCAL_GUARD_STATUS_TICKET_INTERVAL_MINUTES=15
EXTERNAL_TRIGGER_EXECUTE=true
EXTERNAL_TRIGGER_COMMAND=powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/dispatch_takeover_to_chat.ps1 -TicketId "%TICKET_ID%" -TicketEvent "%EVENT%" -StartFile "%START_FILE%" -QueuePath "%QUEUE_PATH%" -BriefPath "%BRIEF_PATH%" -NoOpenEditor -SkipClipboard
RESTART_EVIDENCE_REQUIRED=true
RESTART_EVIDENCE_MINIMUM=process-snapshot;artifact-dir-snapshot;summary_partial-if-exists
RESTART_SEQUENCE=evidence-then-cleanup-then-restart
MAX_STAGE_RESTARTS=2
A_MAX_STAGE_RESTARTS=
B_MAX_STAGE_RESTARTS=
RESTART_EVIDENCE_NOTES=
SESSION_END_CONDITION=a-and-b-final
A_FINAL_STATUS=NOT_RUN
B_FINAL_STATUS=NOT_RUN
SESSION_FINAL_STATUS=NOT_RUN
SESSION_FINAL_NOTES=
RERUN_FROM_A_REQUIRES_STARTFILE_RESET=true
RERUN_FROM_A_STARTFILE_BASELINE=not-run
RERUN_FROM_A_STARTFILE_RESET_FIELDS=PRECHECK_*;A_SUCCESS_SNAPSHOT_FINAL_STATUS;A_SUCCESS_SNAPSHOT_SUMMARY;A_SUCCESS_SNAPSHOT_SOURCE_STATE;A_FINAL_STATUS;B_FINAL_STATUS;SESSION_FINAL_STATUS
RUN_MODE=foreground-visible
KEEP_WINDOW_ON_EXIT=true
ENTRY_MODE=single-param-fastmode
ENTRY_SCRIPT_A=tools/test/start_dev_verify_fastmode_A.ps1
ENTRY_SCRIPT_B=tools/test/start_dev_verify_fastmode_B.ps1
AUTO_START_MONITORS=true
RESTART_MONITORS_ON_STAGE_RESTART=true
MONITOR_ENTRY_SCRIPT_SUPERVISOR=tools/test/open_unattended_ab_supervisor_window.ps1
MONITOR_ENTRY_SCRIPT_COMPANION=tools/test/open_unattended_ab_companion_window.ps1
A_TASK_DEFINITION=testdata/<A_TASK_DEFINITION>.json
B_TASK_DEFINITION=testdata/<B_TASK_DEFINITION>.json
WINDOW=<YYYY-MM-DD ~ YYYY-MM-DD>
RESET_POLICY_A=restore-source
RESET_POLICY_B=state-only
START_ROUND=1
END_ROUND=8
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
MONITOR_POLICY_D1=90/30/10/20
A_SUCCESS_SNAPSHOT_REQUIRED=true
A_SUCCESS_SNAPSHOT_FINAL_STATUS=<out/artifacts/dev_verify_multiround/<A_RUN>/final_status.json>
A_SUCCESS_SNAPSHOT_SUMMARY=<out/artifacts/dev_verify_multiround/<A_RUN>/summary.csv>
A_SUCCESS_SNAPSHOT_SOURCE_STATE=<CLEAN_OR_GIT_STATUS_SHORT_SUMMARY_AT_A_PASS>
A_FAILURE_BLOCKS_B=true
A_FAILURE_RECOVERY=fix-a-then-rerun-a-before-b
B_START_REQUIRES_A_PASS_WITH_SNAPSHOT=true
B_FAILURE_RECOVERY=prefer-restart-b-from-a-snapshot
B_FAILURE_FALLBACK=rerun-a-then-b-if-snapshot-unreliable
```

运行中常见回填片段（新增监控/接管锚点示例）：
```text
RESTART_EVIDENCE_NOTES=stage=A reason=d1-stall evidence=out/artifacts/dev_verify_multiround/<CURRENT_RUN>/restart_evidence/<YYYYMMDD-HHMMSS>
SESSION_FINAL_NOTES=A started at <YYYY-MM-DD HH:MM:SS> via fastmode A; current_round=D1; run_dir=out/artifacts/dev_verify_multiround/<CURRENT_RUN>; B pending A PASS and snapshot; supervisor_log=out/artifacts/ab_supervisor/<YYYYMMDD-HHMMSS>/supervisor.log; live_status=out/artifacts/ab_supervisor/<YYYYMMDD-HHMMSS>/live_status.json; companion_log=out/artifacts/ab_companion/<YYYYMMDD-HHMMSS>/companion.log
SESSION_FINAL_NOTES=A PASS; a_snapshot_dir=out/artifacts/dev_verify_multiround/<A_RUN>/a_success_snapshot; launching B; supervisor_log=out/artifacts/ab_supervisor/<YYYYMMDD-HHMMSS>/supervisor.log; live_status=out/artifacts/ab_supervisor/<YYYYMMDD-HHMMSS>/live_status.json
SESSION_FINAL_NOTES=B started at <YYYY-MM-DD HH:MM:SS>; run_dir=out/artifacts/dev_verify_multiround/<B_RUN>; supervisor_log=out/artifacts/ab_supervisor/<YYYYMMDD-HHMMSS>/supervisor.log; live_status=out/artifacts/ab_supervisor/<YYYYMMDD-HHMMSS>/live_status.json
SESSION_FINAL_NOTES=<previous-notes>; evidence=out/artifacts/ab_supervisor/<YYYYMMDD-HHMMSS>/blocked_package_<YYYYMMDD-HHMMSS>
SESSION_FINAL_NOTES=<previous-notes>; companion_blocked reason=<supervisor-quiet|unknown-stage-stall> evidence=out/artifacts/ab_companion/<YYYYMMDD-HHMMSS>/blocked_package_<YYYYMMDD-HHMMSS>
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

运行字段约定：
- `START_PARAMETER_ECHO_REQUIRED` 与 `STATUS_REPORT_REQUIRED` 用于固定本轮执行纪律；默认建议保持为 `true`，避免仅靠口头提醒。
- `AI_SESSION_BLOCKING_WATCH_REQUIRED` 建议保持为 `true`；当该值为 `true` 时，执行者应在会话内持续阻塞盯盘，不得仅依赖 supervisor/companion 脚本。`AI_SESSION_BLOCKING_WATCH_REPORT_INTERVAL_MIN` 建议保持 `10`，`AI_SESSION_BLOCKING_WATCH_SCOPES` 建议至少包含 `artifacts;supervisor_log;companion_log;compile-step`。
- 当 `AI_SESSION_BLOCKING_WATCH_REQUIRED=true` 时，`unattended_ab_supervisor.ps1` 会按 `AI_SESSION_BLOCKING_WATCH_REPORT_INTERVAL_MIN` 输出结构化 `watch_heartbeat`，并将当前 watch 策略写入 `AI_SESSION_BLOCKING_WATCH_NOTES`，用于接管与复盘。
- `LOCAL_GUARD_AUTO_FIX_D_COMPILE`、`LOCAL_GUARD_AUTO_FIX_MAX_PER_D_ROUND`、`LOCAL_GUARD_AUTO_FIX_COOLDOWN_MINUTES` 用于控制 guard 的 D 轮编译失败自动修复编排；默认建议开启，且每个 D 轮最多 3 次。
- `LOCAL_GUARD_AGENT_QUEUE_ENABLED` 与 `LOCAL_GUARD_AGENT_QUEUE_PATH` 用于启用 guard 工单队列（JSONL 追加写入）；建议保持开启，便于会话中断后快速接管。
- `LOCAL_GUARD_STATUS_TICKET_ENABLED` 与 `LOCAL_GUARD_STATUS_TICKET_INTERVAL_MINUTES` 用于定时上报运行状态工单（event=`running-status-report`）；模板默认开启轻提示，建议保持 15 分钟或更长间隔以避免刷屏。该事件默认只落盘 relay/状态文件，不自动拉起 VS Code 与 Chat 窗口，防止窗口风暴。
- `EXTERNAL_TRIGGER_COMMAND` 与 `EXTERNAL_TRIGGER_EXECUTE` 用于配置会话外触发器动作：触发器会在新工单到达时生成 takeover brief，并执行外部命令。命令模板支持占位符 `%TICKET_ID%`、`%EVENT%`、`%START_FILE%`、`%QUEUE_PATH%`、`%BRIEF_PATH%`；模板默认命令包含 `-NoOpenEditor -SkipClipboard` 以保持静默转发。
- 推荐桥接命令可直接使用 `tools/test/dispatch_takeover_to_chat.ps1`：该脚本会生成 chat relay 文件、刷新 latest relay 状态，并把首条接管指令写入剪贴板；若本机 `code` CLI 可用，还会尝试打开 VS Code 与 Chat 面板。
- 若希望全事件静默转发（不自动打开 VS Code/Chat，也不写剪贴板），可在 `EXTERNAL_TRIGGER_COMMAND` 末尾追加 `-NoOpenEditor -SkipClipboard`。
- 推荐常驻触发器入口：`powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_takeover_trigger_window.ps1 -StartFile tmp/unattended_ab_start_<YYYYMMDD-HHMM>.md`。
- `LOCAL_GUARD_WAIT_FOR_MANUAL_RESTART=true` 表示 guard 在需要人工介入时进入低噪声暂停态并持续盯盘，而不是快速刷屏；`LOCAL_GUARD_MANUAL_NOTICE_REPEAT` 控制进入暂停前的提示次数。
- `LOCAL_GUARD_RESTART_REQUIRES_CONFIRM=true` 与 `LOCAL_GUARD_RESTART_APPROVED=false` 组合表示“默认不自动放行重启”；仅当人工确认后临时把 `LOCAL_GUARD_RESTART_APPROVED` 置为 `true` 才允许 guard 继续重启流程，恢复后建议回写为 `false`。
- `TASK_STATIC_PRECHECK_POLICY` 用于控制开跑前一次性任务定义静态体检（`tools/test/check_task_definition_static.ps1`），默认建议 `enforce`；该检查会覆盖 replacement 双转义风险、pattern 唯一匹配与目标锚点可达性，避免运行中才失败。
- `MAX_STAGE_RESTARTS`、`A_MAX_STAGE_RESTARTS`、`B_MAX_STAGE_RESTARTS` 用于配置阶段重启预算；`unattended_ab_supervisor.ps1` 会优先读取启动文件字段，缺省时才回退到脚本参数。
- `RESTART_EVIDENCE_REQUIRED`、`RESTART_EVIDENCE_MINIMUM` 与 `RESTART_SEQUENCE` 用于固定“先留证、再清场、最后重启”的顺序；若本轮发生卡滞重启，应将证据位置或摘要写入 `RESTART_EVIDENCE_NOTES`。
- `REMOTE_KEYPATH` 建议始终保留模板中的 MSYS 路径字面量，并以 UTF-8 编码保存启动文件；若出现用户名乱码，应先修正路径文本后再继续复用该文件，避免 supervisor/companion 误读 SSH key 路径。
- `NETWORK_PRECHECK_*` 建议保持“check 与 require 解耦”：`*_CHECK_*` 决定是否探测该维度，`*_REQUIRE_*` 决定该维度失败是否阻断；默认建议 `NETWORK_PRECHECK_REQUIRE_IPV6=true`、`NETWORK_PRECHECK_REQUIRE_IPV4=false`。`*_LAST_*` 由启动脚本回填最近一次预检结果。
- `ROUND_RUNTIME_GATE_*` 用于控制 D 轮次运行前硬门禁（默认 D2 起生效）。required 项包括目录可写/磁盘余量、remote lock、网络 required 连通；optional 项包括并发进程冲突告警。required 失败会在当前轮次提前退出，避免继续执行明知无法通过的验证。
- `A_SUCCESS_SNAPSHOT_SOURCE_STATE` 用于记录 A 成功快照固化时的源码状态摘要；建议填写 `CLEAN` 或当时 `git status --short` 的单行摘要。
- `A_FINAL_STATUS`、`B_FINAL_STATUS` 建议使用 `NOT_RUN`、`RUNNING`、`PASS`、`FAIL`、`BLOCKED`；若 A 失败导致 B 未启动，B 建议写为 `BLOCKED`。
- `SESSION_END_CONDITION` 默认固定为 `a-and-b-final`；`SESSION_FINAL_STATUS` 在 A/B 都形成最终结论前不应写为完成态，建议使用 `NOT_RUN`、`RUNNING`、`PASS`、`FAIL`、`BLOCKED`。必要补充可写入 `SESSION_FINAL_NOTES`。
- `SESSION_FINAL_NOTES` 在运行中不应被当作纯自由文本覆盖；若已启用本地监控层，建议保留以 `;` 分隔的 `key=value` 锚点，至少不要删除 `run_dir=...`、`supervisor_log=...`、`live_status=...`、`companion_log=...`、`a_snapshot_dir=...`、`evidence=...` 这类片段，便于 supervisor/companion 与后续人工接管继续定位状态。
- `AUTO_START_MONITORS=true` 时，`open_unattended_ab_stage_window.ps1`（Stage A）与 `open_unattended_ab_resume_window.ps1` 会在拉起 A 后自动拉起 supervisor/companion；`RESTART_MONITORS_ON_STAGE_RESTART=true` 时会先终止同一 start file 的旧监控进程再重启，避免异常退出后遗留旧监控。Stage B 默认保持不自动重启监控，只有显式传入 `-EnableBMonitorRestart` 才会执行同样的监控重启流程。
- `MONITOR_ENTRY_SCRIPT_SUPERVISOR` 与 `MONITOR_ENTRY_SCRIPT_COMPANION` 可显式指定监控启动脚本路径；留空时默认分别使用 `tools/test/open_unattended_ab_supervisor_window.ps1` 与 `tools/test/open_unattended_ab_companion_window.ps1`。
- `RERUN_FROM_A_REQUIRES_STARTFILE_RESET=true` 表示若继续复用同一份启动文件执行“A 修复 -> A 重跑”，必须先把该文件恢复到未运行基线；`RERUN_FROM_A_STARTFILE_RESET_FIELDS` 列出最低需要复位的字段范围。通常 `PRECHECK_*` 相关状态位回到 `NOT_RUN`，详情/备注类字段回到空值或 `TO_BE_FILLED`，`A_SUCCESS_SNAPSHOT_*` 回到待重新捕获状态，`A_FINAL_STATUS`、`B_FINAL_STATUS`、`SESSION_FINAL_STATUS` 回到 `NOT_RUN`。
- `start_dev_verify_fastmode_A.ps1` 与 `start_dev_verify_fastmode_B.ps1` 现已默认执行 remote lock 硬检查（`tools/dev/check_remote_lock.ps1`）：远端锁被占用、状态异常或 SSH 检查失败会直接阻断本轮启动，避免进入长跑后才失败。
- `start_dev_verify_fastmode_A.ps1` 与 `start_dev_verify_fastmode_B.ps1` 现已默认执行网络硬检查（`tools/dev/check_dualstack_whois_connectivity.ps1`）：required 失败即阻断；optional 失败仅记录日志，不阻断。
- 触发文件完成基线复位后，一旦重新执行预检并正式启动，同一文件应立即回填为 `PASS/READY/RUNNING` 等运行态值；因此“正在运行中的启动文件”不应再期待保持初始 `NOT_RUN` 基线外观。
- `TERMINAL_WATCHDOG_MODE` 建议使用 `off` 或 `safe`；`safe` 仅定时记录心跳并清理活动运行树之外、达到最小存活时间的 shellIntegration PowerShell/bash 空壳及其直接关联 headless conhost，默认不清理通用 conhost。

### V1 自动修复闭环（会话内代理 + guard 串联）
1. 触发条件：会话内阻塞盯盘期间，guard 检测到 A 阶段 D1-D4 失败，且证据判定为编译失败。
2. guard 自动动作：抓取该轮最后一次编译证据，执行“任务定义补丁修复 + 静态检查 + A 重启”编排；每个 D 轮最多 3 次，支持冷却时间。
3. 成功后串联：guard 重启主流程后继续阻塞盯盘，并按 10 分钟节奏播报状态，持续回填 `SESSION_FINAL_NOTES` 锚点。
4. 三次失败或非已知签名：guard 写明失败原因并退出自动修复流程，避免无限循环，转入会话内人工/代理接管修复。
5. 职责边界：guard 不具备通用代码修复能力；通用代码修改由会话内 Copilot 根据日志执行，guard 负责检测、编排与重启串联。

### 与 Copilot 协作触发方式
你可直接下达：
- 按 `tmp/unattended_ab_start_<YYYYMMDD-HHMM>.md` 启动 A/B 无人值守任务。

执行约定：
1. 我先做预检并回显解析参数，逐项确认或回填 `PRECHECK_*` 字段后，再按 A -> B 严格串行启动。
2. 我按 D1 固定容忍窗口策略实时监控并处理卡滞重启（先留证再清场再重启）。
3. 仅在 A/B 运行成功后，运行结果统一回填 RFC，不回填本模板。
4. 若 A 失败，我会立即停止 A -> B 串行链，不启动 B，并先进入“A 修复 -> A 重跑”的路径。
   - 若继续复用原任务启动文件，我会先将其恢复到未运行基线，再重新执行预检并从 A-D1 启动。
5. A 成功后我会先固化 A 成功快照，再启动 B；若 B 编译失败，将优先按“A 快照恢复 -> B 重启”路径执行。
6. 仅当 A 快照无法可靠恢复时，我才会建议并执行“从 A 重新开始”的保守路径。
7. 每次 remote strict 编译前，我会先检查 remote build lock；若 lock 已被占用，则立即停止本轮编译并先处理占用问题。
8. 若本轮启用了本地 `unattended_ab_supervisor.ps1` 或 `unattended_ab_companion.ps1`，我会把 `supervisor_log`、`live_status`、`companion_log`、`evidence` 等定位锚点持续写回 `SESSION_FINAL_NOTES`；在任务结束前不应手工删改这些锚点。
9. 若观察到“主运行终端、第一层监控、第二层监控终端近似同时消失”，应优先怀疑 VS Code 集成终端 / extension host 层异常，而不是直接假定 A/B 业务脚本自身失败；此时先检查 `renderer.log`、`terminal.log`、`ptyhost.log` 与 `supervisor_log`/`companion_log` 尾部时间，再决定是否按 `BLOCKED` 接管。
