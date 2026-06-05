# A/B Unattended Prompt Pack (CN)

本文件收纳 A/B 无人值守任务的 3 版可复用提示词，供不同模型容量与上下文预算选择使用。

执行基准：
- 首先遵守 [UNATTENDED_AB_OPERATION_FLOW_CN.md](UNATTENDED_AB_OPERATION_FLOW_CN.md)
- 其次参考 [UNATTENDED_AB_START_TEMPLATE_CN.md](UNATTENDED_AB_START_TEMPLATE_CN.md)
- 若两者冲突，一律以前者为准

模式补充：
- 若 start-file 使用 `AI_CHAT_POLICY_WORK_MODE=low-disturb`，则 `running-status-report` 应按低扰口径执行：优先运行最小健康检查；若结果正常且未触发自愈/故障处理，回复仅保留“运行正常”与 `handled_at`；若结果异常或触发了自愈/故障处理，则切回 normal 口径回复完整状态。
- 若 start-file 使用 `AI_CHAT_POLICY_WORK_MODE=event-only`，则不应期待 guard 继续产生定时状态票；运行期以事件驱动票据、主动 heartbeat 与 poll 为主。
- 如需新建 start-file，`tools/test/create_unattended_ab_start_file.ps1` 默认生成 `normal`；可显式用 `-Mode normal|anti-missent|low-disturb|event-only|all-modes` 生成对应模式文件。

## 1. 标准短提示词版

请先完整学习并严格遵守 docs/UNATTENDED_AB_OPERATION_FLOW_CN.md 与 docs/UNATTENDED_AB_START_TEMPLATE_CN.md；若有冲突，一律以前者为准。目标 start-file：<START_FILE>。

执行规则：
1. 只允许使用仓库现有入口脚本与既有流程，不准新写脚本、不准自创 wrapper、不准依赖隐式默认值。
2. 准备阶段可直接运行统一检查脚本 tools/test/check_unattended_ab_launch_ready.ps1；不要为每个检查子项逐项申请授权。
3. 只有当统一检查整体 PASS 后，才向用户提一次最终授权；只有用户明确下达“启动 A（带 -StartMonitors）”或等价命令后，才允许真正启动。
4. 标准启动入口只能是 tools/test/open_unattended_ab_stage_window.ps1，并且命令必须显式带 -StartMonitors。
5. 长跑必须落在 VS Code 外部 PowerShell 窗口；集成终端只可用于短检查、只读查询、临时校验，或触发 stage window。
6. 严格串行：先 A 后 B；A 未成功前禁止启动 B。
7. 进入无人值守运行期后，不要结束会话；仅在 A/B 都到终态，或用户明确下达“停止监控”时结束。
8. 运行期工单流属于预授权既定动作；默认顺序固定为 business_command -> continue_watch_command -> mark_processed_command -> handled_receipt_command；若返回 post_check_command，还必须继续执行 post_check_command 并补偿未完成工单，直到 no_pending_rows。
9. `handled_at` 是强制回执字段；对需要 handled 收据的票据，完成当轮动作后必须立即写入，不可省略。对 running-status-report，执行完 business/continue 后就要立即回传 handled_at。
10. 每 5 到 10 分钟主动发送一次 heartbeat，并主动轮询 poll_agent_tickets.ps1；每 10 分钟汇报一次当前阶段、A/B 状态、心跳摘要、strict mode、adjustments、待处理工单、恢复动作。
11. 若 strict 违规先修 LOCAL_GUARD_POLL_*；若消息链路异常先修 heartbeat/poll/dispatch；若文档冲突、字段异常、入口行为异常、是否应重启或是否应修复不明确，先汇报，不要自作主张。
12. 不允许直接手改源码做自愈；只能修改当前阶段任务定义，体检通过后再重启本阶段。
13. 不允许擅自修改主流程脚本、入口脚本或监控链脚本；除非用户明确授权修复。

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

只准用现有脚本，不准新写脚本或自创流程。准备阶段直接运行：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "<START_FILE>"
不要逐项申请检查授权；只有整体 PASS 后，才向用户提一次“是否启动 A（带 -StartMonitors）”授权。

真正启动时，只准用：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "<START_FILE>" -StartMonitors
长跑必须落在 VS Code 外部 PowerShell 窗口；严格先 A 后 B，A 未成功前禁止启动 B。

若检查失败，汇报失败项和原因并停在未通过状态；若检查 PASS 但用户未明确下达启动命令，停在“准备完成，待启动授权”状态，不得擅自开跑。

进入无人值守运行期后，不要结束会话；仅在 A/B 都到终态或用户明确说“停止监控”时结束。运行期工单流默认预授权，按 business_command -> continue_watch_command -> mark_processed_command -> handled_receipt_command 顺序执行；若返回 post_check_command，继续执行并补偿未完成工单；不要逐项再问用户。

每 5 到 10 分钟主动 heartbeat + poll_agent_tickets.ps1，每 10 分钟汇报一次：当前阶段、A/B 状态、心跳摘要、strict mode、adjustments、待处理工单、恢复动作。对强制收据票立即写 handled_at；对 low-disturb 的 running-status-report，正常时只回“运行正常”+ handled_at，异常或触发自愈时切回 normal 口径。若 strict 违规先修 LOCAL_GUARD_POLL_*；若消息链路异常先修 heartbeat/poll/dispatch。

若文档冲突、start-file 字段异常、入口行为异常、是否应重启不明确、是否应修复不明确，先汇报；不要猜。自愈只改当前阶段任务定义，不直接改源码；未经用户明确授权，不修改主流程脚本、入口脚本或监控链脚本。

## 3. 极简压缩版

先读 docs/UNATTENDED_AB_OPERATION_FLOW_CN.md 和 docs/UNATTENDED_AB_START_TEMPLATE_CN.md，冲突以前者为准；目标 start-file：<START_FILE>。

只用现有脚本。准备阶段直接跑：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "<START_FILE>"

检查失败就汇报并停；检查 PASS 但用户未明确授权，就停在“待启动授权”；只有用户明确下达“启动 A（带 -StartMonitors）”后，才执行：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "<START_FILE>" -StartMonitors

长跑必须在 VS Code 外部 PowerShell 窗口；严格先 A 后 B；A 未成功前禁止启动 B。

运行期不要结束会话；每 5 到 10 分钟 heartbeat + poll，每 10 分钟汇报一次。工单流默认预授权，按 business_command -> continue_watch_command -> mark_processed_command -> handled_receipt_command 执行；有 post_check_command 就继续补偿；对强制收据票立即写 handled_at，不逐项再问。

若 strict 违规先修 LOCAL_GUARD_POLL_*；若消息链路异常先修 heartbeat/poll/dispatch；low-disturb 的 running-status-report 正常时只回“运行正常”+ handled_at，event-only 不期待定时状态票；若文档冲突、字段异常、入口行为异常、是否应重启或修复不明确，先汇报，不要猜。

自愈只改当前阶段任务定义，不直改源码；未经用户明确授权，不修改主流程脚本、入口脚本或监控链脚本。