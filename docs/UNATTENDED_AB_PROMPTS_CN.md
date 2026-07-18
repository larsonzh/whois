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
- `manual-wait-paused`、`budget-exhausted-stop`、`known-infra-transient-stop` 只允许报告、对应决策和唯一原子收尾，按 `route_guard_command -> atomic_closeout_command` 执行；不得修改文件或环境，不得执行 `business_resume`、`continue_watch_command` 或 guard/stage 重启。实际修复等待独立的已授权事故票或用户明确授权；budget 通告不取消此前事故票已授予的待办修复权限。
- 若 start-file 使用 `AI_CHAT_POLICY_WORK_MODE=low-disturb`，仅压缩汇报文本：正常时回复“运行正常”与 `handled_at`，异常时回复异常摘要与 `handled_at`；不得切换到修复口径。
- 运行期工单由现有 guard/trigger/dispatch 链生成并投送到会话。AI 只需静默等待已投送的事件驱动票或状态票；收到后严格按 `next_command_order` 执行，不遗漏操作。事件票若提供 `recovery_transaction_command`，优先只执行一次该“恢复+闭环事务”；否则最终只执行一次 `atomic_closeout_command`。仅在对应机器事实门禁全部通过后声称闭环。不得自行启动 heartbeat/poll 定时巡检，不得创建监控脚本、循环、后台 job、watcher、常驻 PowerShell 命令或长时间跨轮次巡检命令；等待本身不需要执行任何命令。通过标准 stage window 重启主进程后，必须在 3 分钟内完成事务/原子收尾并通过全部机器事实门禁，然后静默等待；3 分钟不是巡检窗口。
- 若 start-file 使用 `AI_CHAT_POLICY_WORK_MODE=event-only`，则不应期待 guard 继续产生定时状态票；AI 仍只被动接收事件驱动票。
- 脚本故障必须先读取 `LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED`。字段缺失、非法或为 `false` 时进入 `incident-script-diagnose-only`：只读排查并在聊天中输出根因、证据、影响、最小修复建议、验证命令、风险与回滚方案；禁止改文件、创建脚本、控制或重启进程、resume、改变环境。仅显式为 `true` 时才允许脚本自愈。
- 在代码修复、非代码恢复、事件评审或其他非脚本工单中发现新的 guard/trigger/dispatch/poll 脚本故障时，必须停止原流程并按 `LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED` 重新路由；不得在原工单车道内直接修脚本。
- 如需新建 start-file，`tools/test/create_unattended_ab_start_file.ps1` 默认生成 `normal`；可显式用 `-Mode normal|anti-missent|low-disturb|event-only|all-modes` 生成对应模式文件。

使用指引（先选模板，再替换 `<START_FILE>` 后整段复制发送）：
- 标准短提示词版：用于首次接手、需要完整边界与全量约束、或近期发生过流程偏移时。
- 超短口令版：用于日常主力执行（推荐默认），在约束完整度和长度之间平衡。
- 极简压缩版：用于上下文预算紧张、模型容量较弱或链路不稳定时，优先保证启动与运行主流程不跑偏。

## 1. 标准短提示词版

请先完整学习并严格遵守 docs/UNATTENDED_AB_OPERATION_FLOW_CN.md 与 docs/UNATTENDED_AB_START_TEMPLATE_CN.md；若有冲突，一律以前者为准。目标 start-file：<START_FILE>。

硬约束补充（必须遵守）：
- 事件工单按 `next_command_order` 执行业务动作；若提供 `recovery_transaction_command`，只执行一次该事务命令，它会按当前工单字段执行授权的 business/continue/closeout 路径并校验内部原子收尾；否则最终只执行一次 `atomic_closeout_command`。旧的 handled_receipt/validate_receipt/mark_processed/post_check 字段仅作审计兼容，不得逐条重复执行。事务/原子命令必须返回 exit code 0，且 JSON 机器事实满足对应门禁，否则 fail-close。
- ticket_closure_check_command / event_dedup_health_check_command / final_status_closeout_command / final_status_closeout_apply_ack_command 仅作审计兼容，不得逐条执行；其职责已由 recovery_transaction_command 或 atomic_closeout_command 统一覆盖。
- 对 running-status-report，只执行只读状态查询并立即回传 handled_at（YYYY-MM-DD HH:mm:ss）；不得执行 continue_watch、恢复或重启命令。
- 对 running-status-report，不得仅凭旧 exit 日志、旧 latest_b_exit.json 或历史失败摘要推断需要重启 B；发现任何异常也只汇报并等待独立事故票。
- 最终收尾时，必须显式上报会话结束日期时间；若回传 session_closed_at，需与该时间一致。

执行规则：
1. 只允许使用仓库现有入口脚本与既有流程，不准新写脚本、不准自创 wrapper、不准依赖隐式默认值。任务定义 JSON 的语义修改必须使用 VS Code `apply_patch` 编辑工具；禁止用终端内联 Python、多层 `powershell -Command`、here-string、重定向、通用字符串替换或格式化器修改任务定义。格式化器仅可做不改变 JSON 值、数组顺序或 operation 结构的机械格式化。编辑后依次执行 SyntaxOnly 装载检查、故障目标 op 快检（可定位时）、当前故障 D 轮递进严格检查；后续轮检查范围服从 start-file 的 `TASK_STATIC_CROSS_ROUND_REPAIR_ENABLED`，默认关闭时不得预演后续轮，开启时当前轮通过后按顺序逐轮检查到 D4。
2. 准备阶段可直接运行统一检查脚本 tools/test/check_unattended_ab_launch_ready.ps1；不要为每个检查子项逐项申请授权。
3. 只有当统一检查整体 PASS 后，才向用户提一次最终授权；只有用户明确下达“启动 A（带 -StartMonitors）”或等价命令后，才允许真正启动。
4. 标准启动入口只能是 tools/test/open_unattended_ab_stage_window.ps1，并且命令必须显式带 -StartMonitors。
5. 长跑必须落在 VS Code 外部 PowerShell 窗口；集成终端只可用于短检查、只读查询、临时校验，或触发 stage window。
6. 严格串行：先 A 后 B；A 未成功前禁止启动 B。
7. 进入无人值守运行期后，不要结束会话；仅在 A/B 都到终态，或用户明确下达“停止监控”时结束。
8. 运行期工单流属于预授权既定动作；严格按 `next_command_order` 执行业务动作，并以唯一的 `atomic_closeout_command` 收尾。只有该命令的退出码与 JSON 机器事实全部通过后才可回传其中的 handled_at 并声称闭环；命令缺失、锁忙、JSON 无效或任一事实失败时只报告阻塞。旧的分步回执字段只用于审计兼容，不再逐条执行。
9. `handled_at` 是强制回执字段；对需要 handled 收据的票据，完成当轮动作后必须立即写入。对 running-status-report，只读汇报完成后立即回传 handled_at。
10. running-status-report 只汇报观测状态，禁止输出或执行修复路径；不得仅凭旧 exit 日志、旧 latest_b_exit.json 或历史失败摘要推断需要重启 B，异常等待独立事故票。
11. 运行期静默等待 guard/trigger/dispatch 投送到会话的事件驱动票或状态票；收到后严格按票据 `next_command_order` 执行其中所有无需用户确认的预授权操作，不得遗漏。事件票最终只执行一次 `atomic_closeout_command`，仅当其退出码和全部 JSON 机器事实门禁通过后才继续静默等待；旧分步回执字段不得逐条执行。不得自行定时调用 heartbeat 或 `poll_agent_tickets.ps1`，不得创建任何定时巡检监控脚本、轮询循环、后台 job、watcher、常驻内存命令或长时间跨轮次巡检命令。通过标准 stage window 重启主进程后，必须在 3 分钟内执行原子收尾并通过全部机器事实门禁；无法完成则立即如实报告阻塞，不得转为主动巡检。
12. 若收到的工单指出 strict、heartbeat/poll/dispatch 链路异常，按该工单允许边界处理；若文档冲突、字段异常、入口行为异常、是否应重启或是否应修复不明确，先汇报，不要自作主张。
13. 只有 task-static 故障，以及编译/验证阶段经证据分类确认为代码故障的事故，才允许进入代码自愈；编译/验证阶段的权限、磁盘、网络、远程锁、工具链不可用或测试基础设施故障必须进入 noncode。code-step 仅执行“读绑定产物 -> 验证 -> 原子写 -> 写后验证”，任何 code-step 故障均属于 noncode，禁止修改源码或任务定义。不允许直接手改源码做自愈；只能在被允许的代码修复票中修改当前阶段任务定义。保持 `qualityPolicy.operationSafetyPolicy=enforce`：每个 op 使用由自身 replacement 唯一产生的 marker，replacement 后 pattern 必须收敛，函数替换必须消费完整原函数体；新 helper 必须有唯一 definition、所需 prototype 和真实 call site，并用 `postApplyAssertions` 声明精确计数。设计时确无代码目标的 D 轮才可使用不含 operations/marker/assertions 的最小 `type=noop`；禁止自替换 op，禁止把失败或运行时已被前置轮吸收的 `regex-patch` 改成 `noop`，后者必须保留 regex-patch 并用逐 op 幂等证据证明 `absorbed-by-prior-round` / `idempotent-replay`。若改动了任务定义，先运行 `-SyntaxOnly`，可定位时用 `-RoundTag <Dn> -OperationIndex <n>` 快检故障 op，再让当前故障轮通过不带 `-OperationIndex` 的递进严格检查。独立 task-static checker 首错即停，全部通过后生成哈希绑定产物；code-step 不重复 checker，只校验并原子应用该产物。工单内可根据首错诊断反复调用 checker，不消耗默认 3 次的相同指纹主进程重启预算。只有当前故障轮通过才允许同阶段重启或 resume；`single_instance_conflict`、正则 timeout 或 worker timeout 均为硬失败。
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
- 事件工单严格按 next_command_order 执行业务动作；若存在 recovery_transaction_command，则只执行一次该事务命令并从其成功 JSON 回传 handled_at；否则最终只执行一次 atomic_closeout_command，并仅在 exit code 0 且 JSON 机器事实全部通过后回传其 handled_at。旧分步回执字段仅作审计兼容。running-status-report 例外，只执行只读状态查询、状态汇报与 handled_at。
- 旧 closure/dedup/final-status 分步字段仅作审计兼容，不得逐条执行；事件票只执行一次 atomic_closeout_command。
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

运行期只需静默等待 guard/trigger/dispatch 投送到会话的事件驱动票或状态票；收到后严格按 `next_command_order` 执行全部预授权操作，不遗漏任务。事件票最终只执行一次 `atomic_closeout_command`，以其机器输出完成 handled_at、processed、receipt 与 closure 的统一校验后再继续静默等待；旧分步回执字段不得逐条执行。不得主动定时执行 heartbeat 或 poll，不得创建巡检脚本、轮询循环、后台 job、watcher、常驻内存命令或长时间跨轮次巡检命令。重启主进程后 3 分钟内必须完成原子收尾并通过全部机器事实门禁；该期限不是巡检窗口。对 low-disturb 的 running-status-report，正常时只回“运行正常”+ handled_at，异常时只回异常摘要+handled_at，等待独立事故票。

若 route guard 分类为 `incident-script-diagnose-only`，本票只允许只读取证、根因分析、修复方案、聊天汇报和原子收尾。不得修改脚本/源码/任务定义，不得创建脚本，不得停止或重启进程，不得执行 `business_resume`、`continue_watch_command` 或环境恢复；报告完成后执行唯一 `atomic_closeout_command` 并等待用户决定。

running-status-report 不提供或执行修复路径；不得仅凭旧 exit 证据建议重启 B。不得手工创建 chat_heartbeat*.jsonl、额外 handled 回执文件，或在未获同意时创建非 tmp 新脚本。若需回填 docs/RFC-whois-client-split.md 与 docs/RFC-address-space-preclassifier.md，先汇报结果并等待用户明确授权。

若文档冲突、start-file 字段异常、入口行为异常、是否应重启不明确、是否应修复不明确，先汇报；不要猜。自愈只改当前阶段任务定义，不直接改源码；设计时空轮才用不含 operations/marker/assertions 的 `type=noop`，不得用自替换 op，也不得把失败或运行时已吸收的 regex-patch 改成 noop 绕门禁，运行时吸收必须保留 regex-patch 并以 `absorbed-by-prior-round` / `idempotent-replay` 证明。改任务定义后先通过 SyntaxOnly，可用 `-OperationIndex` 快检目标 op，恢复前只要求当前故障 D 轮通过递进严格检查；后续轮由实际 code-step 检查。只能重启当前票据对应阶段的主进程，不得串阶段；未经用户明确授权，不修改主流程脚本、入口脚本或监控链脚本。
任务定义 JSON 的语义修改只允许使用 VS Code `apply_patch`；禁止通过终端内联 Python、PowerShell 多层命令、重定向、通用字符串替换或格式化器修改。修改后先做 SyntaxOnly，再做目标 op 快检（可定位时），最后做当前故障 D 轮递进严格检查。
无人值守运行期间禁止执行提交与推送操作（如 git commit / git push）；仅在用户明确同轮授权后，才可进入提交/推送流程。

## 3. 极简压缩版

先读 docs/UNATTENDED_AB_OPERATION_FLOW_CN.md 和 docs/UNATTENDED_AB_START_TEMPLATE_CN.md，冲突以前者为准；目标 start-file：<START_FILE>。

硬约束补充（必须遵守）：
- 事件工单按 next_command_order 执行；running-status-report 只执行只读状态查询、状态汇报和 handled_at。
- 旧 closure/dedup/final-status 分步字段仅作审计兼容，不得逐条执行；事件票只执行一次 atomic_closeout_command。
- running-status-report 禁止自愈、故障处理、continue_watch、重启、business_resume、文件修改和环境恢复；异常只汇报并等待独立事故票，然后回传 handled_at。
- 最终收尾时，必须显式上报会话结束日期时间；若回传 session_closed_at，需与该时间一致。

只用现有脚本。准备阶段直接跑：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_unattended_ab_launch_ready.ps1 -StartFile "<START_FILE>"

检查失败就汇报并停；检查 PASS 但用户未明确授权，就停在“待启动授权”；只有用户明确下达“启动 A（带 -StartMonitors）”后，才执行：
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/open_unattended_ab_stage_window.ps1 -Stage A -StartFile "<START_FILE>" -StartMonitors

长跑必须在 VS Code 外部 PowerShell 窗口；严格先 A 后 B；A 未成功前禁止启动 B。

运行期不要结束会话；静默等待现有 guard/trigger/dispatch 链投送事件票或状态票，收到后严格按 next_command_order 执行全部预授权操作，不遗漏任务。事件票最终只执行一次 atomic_closeout_command，并以其成功机器事实完成 handled_at、processed、receipt 与 closure 的统一校验后再继续等待。不得自建或运行任何定时巡检脚本、轮询循环、后台 job、watcher、常驻内存命令或长时间跨轮次巡检命令。重启主进程后 3 分钟内执行原子收尾并通过全部机器事实门禁，不把该期限用于巡检。状态票只读汇报 SESSION/A/B、main_round、进程/监控存活、heartbeat 与待处理事故票，并回传 handled_at。

low-disturb 的 running-status-report 正常时只回“运行正常”+ handled_at，异常时只回异常摘要+handled_at；不得据旧 exit 证据建议重启 B，不得处置异常。event-only 不期待定时状态票；若文档冲突、字段异常或入口行为异常，先汇报，不要猜。

自愈只改当前阶段任务定义，不直改源码；设计时空轮才用最小 `type=noop`，禁用自替换 op，失败或运行时已吸收的 regex-patch 不得改成 noop，吸收场景仍用 `absorbed-by-prior-round` / `idempotent-replay` 证据；改后先过 SyntaxOnly，可用 `-OperationIndex` 快查故障 op，但恢复前只检查当前故障 D 轮，后续轮在实际 code-step 到达时检查；不得手工创建 chat_heartbeat*.jsonl、额外 handled 回执文件，或在未获同意时创建非 tmp 新脚本；若需回填 docs/RFC-whois-client-split.md 与 docs/RFC-address-space-preclassifier.md，先汇报结果并等待用户授权；未经用户明确授权，不修改主流程脚本、入口脚本或监控链脚本。
任务定义 JSON 的语义修改只允许使用 VS Code `apply_patch`，禁止终端内联 Python/PowerShell、重定向、通用字符串替换或格式化器代改；修改后按 SyntaxOnly -> 目标 op 快检（可定位时）-> 当前故障轮递进严格检查的顺序验证。
无人值守运行期间禁止执行提交与推送操作（如 git commit / git push）；仅在用户明确同轮授权后，才可进入提交/推送流程。
