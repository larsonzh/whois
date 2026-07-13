# A/B Unattended Prompt Pack (CN)

本文件收纳 A/B 无人值守任务的 3 版可复用提示词，供不同模型容量与上下文预算选择使用。

执行基准：
- 首先遵守 [UNATTENDED_AB_OPERATION_FLOW_CN.md](UNATTENDED_AB_OPERATION_FLOW_CN.md)
- 其次参考 [UNATTENDED_AB_START_TEMPLATE_CN.md](UNATTENDED_AB_START_TEMPLATE_CN.md)
- 若两者冲突，一律以前者为准

下次开工清单固定所在 RFC：
- docs/RFC-whois-client-split.md
- docs/RFC-address-space-preclassifier.md

模式补充：
- 所有 `running-status-report` 均为只读状态汇报票：只读取运行状态并回传 `handled_at`，禁止自愈修复、故障处理、主进程/guard 重启、`business_resume`、文件修改、环境稳定化或任何恢复动作。异常只汇报并等待独立事故票。
- 若 start-file 使用 `AI_CHAT_POLICY_WORK_MODE=low-disturb`，仅压缩汇报文本：正常时回复“运行正常”与 `handled_at`，异常时回复异常摘要与 `handled_at`；不得切换到修复口径。
- 运行期工单由现有 guard/trigger/dispatch 链生成并投送到会话。AI 只需静默等待已投送的事件驱动票或状态票，不得自行启动 heartbeat/poll 定时巡检，不得创建监控脚本、循环、后台 job、watcher 或常驻 PowerShell 命令；等待本身不需要执行任何命令。
- 若 start-file 使用 `AI_CHAT_POLICY_WORK_MODE=event-only`，则不应期待 guard 继续产生定时状态票；AI 仍只被动接收事件驱动票。
- 如需新建 start-file，`tools/test/create_unattended_ab_start_file.ps1` 默认生成 `normal`；可显式用 `-Mode normal|anti-missent|low-disturb|event-only|all-modes` 生成对应模式文件。

使用指引（先选模板，再替换 `<START_FILE>` 后整段复制发送）：
- 标准短提示词版：用于首次接手、需要完整边界与全量约束、或近期发生过流程偏移时。
- 超短口令版：用于日常主力执行（推荐默认），在约束完整度和长度之间平衡。
- 极简压缩版：用于上下文预算紧张、模型容量较弱或链路不稳定时，优先保证启动与运行主流程不跑偏。

## 1. 标准短提示词版

请先完整学习并严格遵守 docs/UNATTENDED_AB_OPERATION_FLOW_CN.md 与 docs/UNATTENDED_AB_START_TEMPLATE_CN.md；若有冲突，一律以前者为准。目标 start-file：<START_FILE>。

硬约束补充（必须遵守）：
- 工单默认顺序固定为 business_command -> continue_watch_command -> handled_receipt_command -> validate_receipt_command -> mark_processed_command；若返回 post_check_command，必须继续执行到 no_pending_rows。
- 若返回 ticket_closure_check_command / event_dedup_health_check_command / final_status_closeout_command（含 final_status_closeout_apply_ack_command），也必须按 next_command_order 继续执行。
- 对 running-status-report，只执行只读状态查询并立即回传 handled_at（YYYY-MM-DD HH:mm:ss）；不得执行 continue_watch、恢复或重启命令。
- 对 running-status-report，不得仅凭旧 exit 日志、旧 latest_b_exit.json 或历史失败摘要推断需要重启 B；发现任何异常也只汇报并等待独立事故票。
- 最终收尾时，必须显式上报会话结束日期时间；若回传 session_closed_at，需与该时间一致。

执行规则：
1. 只允许使用仓库现有入口脚本与既有流程，不准新写脚本、不准自创 wrapper、不准依赖隐式默认值。
2. 准备阶段可直接运行统一检查脚本 tools/test/check_unattended_ab_launch_ready.ps1；不要为每个检查子项逐项申请授权。
3. 只有当统一检查整体 PASS 后，才向用户提一次最终授权；只有用户明确下达“启动 A（带 -StartMonitors）”或等价命令后，才允许真正启动。
4. 标准启动入口只能是 tools/test/open_unattended_ab_stage_window.ps1，并且命令必须显式带 -StartMonitors。
5. 长跑必须落在 VS Code 外部 PowerShell 窗口；集成终端只可用于短检查、只读查询、临时校验，或触发 stage window。
6. 严格串行：先 A 后 B；A 未成功前禁止启动 B。
7. 进入无人值守运行期后，不要结束会话；仅在 A/B 都到终态，或用户明确下达“停止监控”时结束。
8. 运行期工单流属于预授权既定动作；默认顺序固定为 business_command -> continue_watch_command -> handled_receipt_command -> validate_receipt_command -> mark_processed_command；若返回 post_check_command，还必须继续执行 post_check_command 并补偿未完成工单，直到 no_pending_rows；若返回 ticket_closure_check_command / event_dedup_health_check_command / final_status_closeout_command（含 final_status_closeout_apply_ack_command），继续按 next_command_order 执行。
9. `handled_at` 是强制回执字段；对需要 handled 收据的票据，完成当轮动作后必须立即写入。对 running-status-report，只读汇报完成后立即回传 handled_at。
10. running-status-report 只汇报观测状态，禁止输出或执行修复路径；不得仅凭旧 exit 日志、旧 latest_b_exit.json 或历史失败摘要推断需要重启 B，异常等待独立事故票。
11. 运行期静默等待 guard/trigger/dispatch 投送到会话的事件驱动票或状态票；收到后按票据 `next_command_order` 执行其中无需用户确认的预授权操作，完成回执后继续静默等待。不得自行定时调用 heartbeat 或 `poll_agent_tickets.ps1`，不得创建任何定时巡检监控脚本、轮询循环、后台 job、watcher 或常驻内存命令。
12. 若收到的工单指出 strict、heartbeat/poll/dispatch 链路异常，按该工单允许边界处理；若文档冲突、字段异常、入口行为异常、是否应重启或是否应修复不明确，先汇报，不要自作主张。
13. 不允许直接手改源码做自愈；只能修改当前阶段任务定义。保持 `qualityPolicy.operationSafetyPolicy=enforce`：每个 op 使用由自身 replacement 唯一产生的 marker，replacement 后 pattern 必须收敛，函数替换必须消费完整原函数体；新 helper 必须有唯一 definition、所需 prototype 和真实 call site，并用 `postApplyAssertions` 声明精确计数。设计时确无代码目标的 D 轮才可使用不含 operations/marker/assertions 的最小 `type=noop`；禁止自替换 op，禁止把失败或运行时已被前置轮吸收的 `regex-patch` 改成 `noop`，后者必须保留 regex-patch 并用逐 op 幂等证据证明 `absorbed-by-prior-round` / `idempotent-replay`。若改动了任务定义，先用 `tools/test/check_task_definition_static.ps1 -RoundTag <Dn> -OperationIndex <n>` 对故障 op 做快速定位检查；该检查只模拟前置 op 且不执行完整整轮 replay 与 `postApplyAssertions`，不能作为最终门禁。随后必须运行 `tools/test/task_definition_safety_regression.ps1`，并让所有受影响 D 轮分别通过不带 `-OperationIndex` 的整轮严格检查，才允许任何重启或 resume；并且只能重启当前票据对应阶段的主进程，A 问题只重启 A，B 问题只重启 B。
14. 不允许手工创建 chat_heartbeat*.jsonl、额外 handled 回执文件，或在未获同意时创建非 tmp 新脚本。
15. 任务结束后如需回填 docs/RFC-whois-client-split.md 与 docs/RFC-address-space-preclassifier.md，必须先汇报结果并等待用户明确授权。
16. 不允许擅自修改主流程脚本、入口脚本或监控链脚本；除非用户明确授权修复。
17. 无人值守运行期间禁止执行提交与推送操作（如 git commit / git push）；仅在用户明确同轮授权后，才可进入提交/推送流程。

执行顺序：
1. 学习两份手册。
2. 运行：
   powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "<START_FILE>"
3. 若失败：汇报失败项与失败原因，停止在“未通过”状态。
4. 若 PASS 但用户未明确下达启动命令：停止在“准备完成，待启动授权”状态。
5. 若 PASS 且用户明确授权启动 A：执行
   powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "<START_FILE>" -StartMonitors
6. A 成功后，按同一规则决定是否启动 B。

## 2. 超短口令版

先读 docs/UNATTENDED_AB_OPERATION_FLOW_CN.md 和 docs/UNATTENDED_AB_START_TEMPLATE_CN.md；冲突以前者为准。目标 start-file：<START_FILE>。

硬约束补充（必须遵守）：
- 事件工单默认顺序固定为 business_command -> continue_watch_command -> handled_receipt_command -> validate_receipt_command -> mark_processed_command；若返回 post_check_command，必须继续执行到 no_pending_rows。running-status-report 例外，只执行只读状态查询、状态汇报与 handled_at。
- 若返回 ticket_closure_check_command / event_dedup_health_check_command / final_status_closeout_command（含 final_status_closeout_apply_ack_command），也必须按 next_command_order 继续执行。
- 对 running-status-report，只读汇报后立即回传 handled_at（YYYY-MM-DD HH:mm:ss）；禁止 self-heal、fault handling、continue_watch、restart、business_resume、文件修改与环境恢复。
- running-status-report 发现异常只汇报并等待独立事故票，不得仅凭旧 exit 证据建议重启 B。
- 最终收尾时，必须显式上报会话结束日期时间；若回传 session_closed_at，需与该时间一致。

只准用现有脚本，不准新写脚本或自创流程。准备阶段直接运行：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "<START_FILE>"
不要逐项申请检查授权；只有整体 PASS 后，才向用户提一次“是否启动 A（带 -StartMonitors）”授权。

真正启动时，只准用：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "<START_FILE>" -StartMonitors
长跑必须落在 VS Code 外部 PowerShell 窗口；严格先 A 后 B，A 未成功前禁止启动 B。

若检查失败，汇报失败项和原因并停在未通过状态；若检查 PASS 但用户未明确下达启动命令，停在“准备完成，待启动授权”状态，不得擅自开跑。

进入无人值守运行期后，不要结束会话；仅在 A/B 都到终态或用户明确说“停止监控”时结束。事件工单流默认预授权并按 next_command_order 执行。running-status-report 只允许只读状态查询、状态汇报和 handled_at，不得执行 continue_watch、closure/dedup、恢复或重启命令。

运行期只需静默等待 guard/trigger/dispatch 投送到会话的事件驱动票或状态票；收到后按 `next_command_order` 执行无需用户确认的预授权操作，回执后继续静默等待。不得主动定时执行 heartbeat 或 poll，不得创建巡检脚本、轮询循环、后台 job、watcher 或常驻内存命令。对 low-disturb 的 running-status-report，正常时只回“运行正常”+ handled_at，异常时只回异常摘要+handled_at，等待独立事故票。

running-status-report 不提供或执行修复路径；不得仅凭旧 exit 证据建议重启 B。不得手工创建 chat_heartbeat*.jsonl、额外 handled 回执文件，或在未获同意时创建非 tmp 新脚本。若需回填 docs/RFC-whois-client-split.md 与 docs/RFC-address-space-preclassifier.md，先汇报结果并等待用户明确授权。

若文档冲突、start-file 字段异常、入口行为异常、是否应重启不明确、是否应修复不明确，先汇报；不要猜。自愈只改当前阶段任务定义，不直接改源码；设计时空轮才用不含 operations/marker/assertions 的 `type=noop`，不得用自替换 op，也不得把失败或运行时已吸收的 regex-patch 改成 noop 绕门禁，运行时吸收必须保留 regex-patch 并以 `absorbed-by-prior-round` / `idempotent-replay` 证明。改任务定义后，`-OperationIndex` 目标 op 检查只用于快速定位，所有受影响 D 轮还必须通过不带 `-OperationIndex` 的整轮严格检查，后者才是恢复前最终门禁；并且只能重启当前票据对应阶段的主进程，不得串阶段；未经用户明确授权，不修改主流程脚本、入口脚本或监控链脚本。
无人值守运行期间禁止执行提交与推送操作（如 git commit / git push）；仅在用户明确同轮授权后，才可进入提交/推送流程。

## 3. 极简压缩版

先读 docs/UNATTENDED_AB_OPERATION_FLOW_CN.md 和 docs/UNATTENDED_AB_START_TEMPLATE_CN.md，冲突以前者为准；目标 start-file：<START_FILE>。

硬约束补充（必须遵守）：
- 事件工单按 next_command_order 执行；running-status-report 只执行只读状态查询、状态汇报和 handled_at。
- 若返回 ticket_closure_check_command / event_dedup_health_check_command / final_status_closeout_command（含 final_status_closeout_apply_ack_command），也必须按 next_command_order 继续执行。
- running-status-report 禁止自愈、故障处理、continue_watch、重启、business_resume、文件修改和环境恢复；异常只汇报并等待独立事故票，然后回传 handled_at。
- 最终收尾时，必须显式上报会话结束日期时间；若回传 session_closed_at，需与该时间一致。

只用现有脚本。准备阶段直接跑：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "<START_FILE>"

检查失败就汇报并停；检查 PASS 但用户未明确授权，就停在“待启动授权”；只有用户明确下达“启动 A（带 -StartMonitors）”后，才执行：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "<START_FILE>" -StartMonitors

长跑必须在 VS Code 外部 PowerShell 窗口；严格先 A 后 B；A 未成功前禁止启动 B。

运行期不要结束会话；静默等待现有 guard/trigger/dispatch 链投送事件票或状态票，收到后按 next_command_order 执行预授权操作并回执，再继续等待。不得自建或运行任何定时巡检脚本、轮询循环、后台 job、watcher 或常驻内存命令。状态票只读汇报 SESSION/A/B、main_round、进程/监控存活、heartbeat 与待处理事故票，并回传 handled_at。

low-disturb 的 running-status-report 正常时只回“运行正常”+ handled_at，异常时只回异常摘要+handled_at；不得据旧 exit 证据建议重启 B，不得处置异常。event-only 不期待定时状态票；若文档冲突、字段异常或入口行为异常，先汇报，不要猜。

自愈只改当前阶段任务定义，不直改源码；设计时空轮才用最小 `type=noop`，禁用自替换 op，失败或运行时已吸收的 regex-patch 不得改成 noop，吸收场景仍用 `absorbed-by-prior-round` / `idempotent-replay` 证据；改后可用 `-OperationIndex` 快查故障 op，但恢复前必须再让所有受影响 D 轮通过不带 `-OperationIndex` 的整轮严格检查；不得手工创建 chat_heartbeat*.jsonl、额外 handled 回执文件，或在未获同意时创建非 tmp 新脚本；若需回填 docs/RFC-whois-client-split.md 与 docs/RFC-address-space-preclassifier.md，先汇报结果并等待用户授权；未经用户明确授权，不修改主流程脚本、入口脚本或监控链脚本。
无人值守运行期间禁止执行提交与推送操作（如 git commit / git push）；仅在用户明确同轮授权后，才可进入提交/推送流程。
