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
- 若 start-file 使用 `AI_CHAT_POLICY_WORK_MODE=low-disturb`，则 `running-status-report` 应按低扰口径执行：优先运行最小健康检查；若结果正常且未触发自愈/故障处理，回复仅保留“运行正常”与 `handled_at`；若结果异常或触发了自愈/故障处理，则切回 normal 口径回复完整状态。
- 若 start-file 使用 `AI_CHAT_POLICY_WORK_MODE=event-only`，则不应期待 guard 继续产生定时状态票；运行期以事件驱动票据、主动 heartbeat 与 poll 为主。
- 如需新建 start-file，`tools/test/create_unattended_ab_start_file.ps1` 默认生成 `normal`；可显式用 `-Mode normal|anti-missent|low-disturb|event-only|all-modes` 生成对应模式文件。

使用指引（先选模板，再替换 `<START_FILE>` 后整段复制发送）：
- 标准短提示词版：用于首次接手、需要完整边界与全量约束、或近期发生过流程偏移时。
- 超短口令版：用于日常主力执行（推荐默认），在约束完整度和长度之间平衡。
- 极简压缩版：用于上下文预算紧张、模型容量较弱或链路不稳定时，优先保证启动与运行主流程不跑偏。

## 1. 标准短提示词版

请先完整学习并严格遵守 docs/UNATTENDED_AB_OPERATION_FLOW_CN.md 与 docs/UNATTENDED_AB_START_TEMPLATE_CN.md；若有冲突，一律以前者为准。目标 start-file：<START_FILE>。

硬约束补充（必须遵守）：
- 工单默认顺序固定为 business_command -> continue_watch_command -> handled_receipt_command -> validate_receipt_command -> mark_processed_command；若返回 post_check_command，必须继续执行到 no_pending_rows。
- 对 running-status-report，执行完 business_command 与 continue_watch_command 后，必须立即回传 handled_at（YYYY-MM-DD HH:mm:ss）。
- 对 healthy 的 running-status-report，不得仅凭旧 exit 日志、旧 latest_b_exit.json 或历史失败摘要推断需要重启 B。
- 最终收尾时，必须显式上报会话结束日期时间；若回传 session_closed_at，需与该时间一致。

执行规则：
1. 只允许使用仓库现有入口脚本与既有流程，不准新写脚本、不准自创 wrapper、不准依赖隐式默认值。
2. 准备阶段可直接运行统一检查脚本 tools/test/check_unattended_ab_launch_ready.ps1；不要为每个检查子项逐项申请授权。
3. 只有当统一检查整体 PASS 后，才向用户提一次最终授权；只有用户明确下达“启动 A（带 -StartMonitors）”或等价命令后，才允许真正启动。
4. 标准启动入口只能是 tools/test/open_unattended_ab_stage_window.ps1，并且命令必须显式带 -StartMonitors。
5. 长跑必须落在 VS Code 外部 PowerShell 窗口；集成终端只可用于短检查、只读查询、临时校验，或触发 stage window。
6. 严格串行：先 A 后 B；A 未成功前禁止启动 B。
7. 进入无人值守运行期后，不要结束会话；仅在 A/B 都到终态，或用户明确下达“停止监控”时结束。
8. 运行期工单流属于预授权既定动作；默认顺序固定为 business_command -> continue_watch_command -> handled_receipt_command -> validate_receipt_command -> mark_processed_command；若返回 post_check_command，还必须继续执行 post_check_command 并补偿未完成工单，直到 no_pending_rows。
9. `handled_at` 是强制回执字段；对需要 handled 收据的票据，完成当轮动作后必须立即写入，不可省略。对 running-status-report，执行完 business/continue 后就要立即回传 handled_at。
10. 对 healthy 的 running-status-report，根因固定写“无活动故障/常规定时状态票”，修复路径固定写“continue_watch only”；不得仅凭旧 exit 日志、旧 latest_b_exit.json 或历史失败摘要推断需要重启 B。
11. 按定时状态票节奏主动发送 heartbeat，并主动轮询 poll_agent_tickets.ps1；按同一节奏汇报当前阶段、A/B 状态、心跳摘要、strict mode、adjustments、待处理工单、恢复动作。
12. 若 strict 违规先修 LOCAL_GUARD_POLL_*；若消息链路异常先修 heartbeat/poll/dispatch；若文档冲突、字段异常、入口行为异常、是否应重启或是否应修复不明确，先汇报，不要自作主张。
13. 不允许直接手改源码做自愈；只能修改当前阶段任务定义。若改动了任务定义，必须先让 `tools/test/check_task_definition_static.ps1` 体检通过，才允许任何重启或 resume；并且只能重启当前票据对应阶段的主进程，A 问题只重启 A，B 问题只重启 B。
14. 不允许手工创建 chat_heartbeat*.jsonl、额外 handled 回执文件，或在未获同意时创建非 tmp 新脚本。
15. 任务结束后如需回填 docs/RFC-whois-client-split.md 与 docs/RFC-address-space-preclassifier.md，必须先汇报结果并等待用户明确授权。
16. 不允许擅自修改主流程脚本、入口脚本或监控链脚本；除非用户明确授权修复。

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
- 工单默认顺序固定为 business_command -> continue_watch_command -> handled_receipt_command -> validate_receipt_command -> mark_processed_command；若返回 post_check_command，必须继续执行到 no_pending_rows。
- 对 running-status-report，执行完 business_command 与 continue_watch_command 后，必须立即回传 handled_at（YYYY-MM-DD HH:mm:ss）。
- 对 healthy 的 running-status-report，不得仅凭旧 exit 证据建议重启 B。
- 最终收尾时，必须显式上报会话结束日期时间；若回传 session_closed_at，需与该时间一致。

只准用现有脚本，不准新写脚本或自创流程。准备阶段直接运行：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "<START_FILE>"
不要逐项申请检查授权；只有整体 PASS 后，才向用户提一次“是否启动 A（带 -StartMonitors）”授权。

真正启动时，只准用：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "<START_FILE>" -StartMonitors
长跑必须落在 VS Code 外部 PowerShell 窗口；严格先 A 后 B，A 未成功前禁止启动 B。

若检查失败，汇报失败项和原因并停在未通过状态；若检查 PASS 但用户未明确下达启动命令，停在“准备完成，待启动授权”状态，不得擅自开跑。

进入无人值守运行期后，不要结束会话；仅在 A/B 都到终态或用户明确说“停止监控”时结束。运行期工单流默认预授权，按 business_command -> continue_watch_command -> handled_receipt_command -> validate_receipt_command -> mark_processed_command 顺序执行；若返回 post_check_command，继续执行并补偿未完成工单；不要逐项再问用户。

按定时状态票节奏主动 heartbeat + poll_agent_tickets.ps1，并按同一节奏汇报：当前阶段、A/B 状态、心跳摘要、strict mode、adjustments、待处理工单、恢复动作。对强制收据票立即写 handled_at；对 low-disturb 的 running-status-report，正常时只回“运行正常”+ handled_at，异常或触发自愈时切回 normal 口径。若 strict 违规先修 LOCAL_GUARD_POLL_*；若消息链路异常先修 heartbeat/poll/dispatch。

对 healthy 的 running-status-report，根因固定写“无活动故障/常规定时状态票”，修复路径固定写“continue_watch only”；不得仅凭旧 exit 证据建议重启 B。不得手工创建 chat_heartbeat*.jsonl、额外 handled 回执文件，或在未获同意时创建非 tmp 新脚本。若需回填 docs/RFC-whois-client-split.md 与 docs/RFC-address-space-preclassifier.md，先汇报结果并等待用户明确授权。

若文档冲突、start-file 字段异常、入口行为异常、是否应重启不明确、是否应修复不明确，先汇报；不要猜。自愈只改当前阶段任务定义，不直接改源码；若改动了任务定义，必须先静态体检通过再恢复；并且只能重启当前票据对应阶段的主进程，不得串阶段；未经用户明确授权，不修改主流程脚本、入口脚本或监控链脚本。

## 3. 极简压缩版

先读 docs/UNATTENDED_AB_OPERATION_FLOW_CN.md 和 docs/UNATTENDED_AB_START_TEMPLATE_CN.md，冲突以前者为准；目标 start-file：<START_FILE>。

硬约束补充（必须遵守）：
- 工单默认顺序固定为 business_command -> continue_watch_command -> handled_receipt_command -> validate_receipt_command -> mark_processed_command；若返回 post_check_command，必须继续执行到 no_pending_rows。
- 对 running-status-report，执行完 business_command 与 continue_watch_command 后，必须立即回传 handled_at（YYYY-MM-DD HH:mm:ss）。
- 对 healthy 的 running-status-report，不得仅凭旧 exit 证据建议重启 B。
- 最终收尾时，必须显式上报会话结束日期时间；若回传 session_closed_at，需与该时间一致。

只用现有脚本。准备阶段直接跑：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "<START_FILE>"

检查失败就汇报并停；检查 PASS 但用户未明确授权，就停在“待启动授权”；只有用户明确下达“启动 A（带 -StartMonitors）”后，才执行：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "<START_FILE>" -StartMonitors

长跑必须在 VS Code 外部 PowerShell 窗口；严格先 A 后 B；A 未成功前禁止启动 B。

运行期不要结束会话；按定时状态票节奏 heartbeat + poll，并按同一节奏汇报。工单流默认预授权，按 business_command -> continue_watch_command -> handled_receipt_command -> validate_receipt_command -> mark_processed_command 执行；有 post_check_command 就继续补偿；对强制收据票立即写 handled_at，不逐项再问。

若 strict 违规先修 LOCAL_GUARD_POLL_*；若消息链路异常先修 heartbeat/poll/dispatch；low-disturb 的 running-status-report 正常时只回“运行正常”+ handled_at，且 healthy 的 running-status-report 不得据旧 exit 证据建议重启 B；event-only 不期待定时状态票；若文档冲突、字段异常、入口行为异常、是否应重启或修复不明确，先汇报，不要猜。

自愈只改当前阶段任务定义，不直改源码；不得手工创建 chat_heartbeat*.jsonl、额外 handled 回执文件，或在未获同意时创建非 tmp 新脚本；若需回填 docs/RFC-whois-client-split.md 与 docs/RFC-address-space-preclassifier.md，先汇报结果并等待用户授权；未经用户明确授权，不修改主流程脚本、入口脚本或监控链脚本。
