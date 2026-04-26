# RFC：无人值守工单轮询 V2（冻结草案）

## 1. 目的

本文用于冻结无 trigger 模式下无人值守工单轮询的 V2 语义。
目标是让执行过程具备可预测性、可审计性和重启安全性。

状态：可实施草案（语义冻结，分阶段落地）。

## 2. 范围

包含范围：
- 会话内阻塞盯盘 + 周期性队列轮询。
- 工单生命周期状态机与账本持久化。
- 重启屏障规则，以及 stale/deferred 分类。
- 结束阶段 drain 与重启后 recovery-drain。
- 压缩归档与保留策略。

不包含范围：
- 移除 stage/resume 执行器。
- 在本阶段物理删除 trigger/dispatch 脚本。

## 3. 角色模型

保留：
- 队列生产者：`unattended_ab_session_guard.ps1`。
- 队列消费者：`poll_agent_tickets.ps1`。
- 业务执行器：stage/resume 脚本。

默认禁用：
- 外部 trigger/dispatch 自动投递链路。

设计原则：
- 一次可拉多条，但必须逐条串行执行。
- 队列文件保持 append-only；运行时不删除原始工单行。

## 4. 轮询节奏

### 4.1 会话驻留与定时动作边界

边界定义：
- AI 会话本身不是操作系统后台定时器；“阻塞盯盘”表示会话保持活跃并持续执行轮询动作。
- 定时节拍由常驻监控脚本提供（例如 guard/supervisor 的循环 + sleep），并通过工单队列向会话暴露待执行动作。
- `poll_agent_tickets.ps1` 为单次轮询消费器：每次执行读取当前队列快照，并输出 `business_command` 与 `continue_watch_command`；若返回 `mark_processed_command`，应在业务动作成功后执行该命令回写完成标记。
- 默认推荐闭环是“guard 产票 + 会话内 AI 周期取票并串行执行”。
- 若会话终止，会话内周期取票会停止；guard 可以继续产票，但不会自动完成业务动作闭环。
- 如需完全脱离会话的人值守，可在外层增加独立调度器；该模式不属于本文默认路径。

默认频率：
- 常态：每 10 分钟。
- 事件态（`FAIL`/`BLOCKED` 或高严重级）：每 5 分钟。

单轮执行预算：
- 每轮最多执行 1 条会改变系统状态的动作类工单。
- `running-status-report` 视为信息类，可合并或覆盖。

## 5. 工单状态机

主路径：
- `new -> claimed -> executed -> watch-resumed -> done`

失败路径：
- `new -> claimed -> executed -> failed`

补充终态分类：
- `deferred`（屏障后的延后工单，后续重新轮询）。
- `stale_by_restart`（重启前上下文生成，重启后不安全执行）。
- `stale_status_superseded`（旧状态上报被最新状态上报覆盖）。

每条工单必须记录的账本字段：
- `ticket_id`
- `status`
- `event`
- `severity`
- `created_at`
- `claimed_at`
- `executed_at`
- `watch_resumed_at`
- `done_at`
- `failed_at`
- `retry_count`
- `next_retry_at`
- `failure_reason`
- `batch_id`
- `restart_generation`
- `notes`

## 6. 重启屏障语义

屏障事件是会改变运行上下文的工单（例如 resume/restart 动作）。

规则：
1. 屏障工单执行成功后，立即停止处理同批剩余工单。
2. 同批剩余工单统一标记为 `deferred`，原因为 `restart_barrier`。
3. 立刻执行 continue-watch/watch-resume 动作。
4. 在新上下文下立即触发一次重新轮询。

安全规则：
- 屏障前生成的工单，如依赖旧上下文，可重分类为 `stale_by_restart`。
- `stale_by_restart` 建议按事件族启发式判定：仅对“重启敏感事件”生效（如 `incident-captured`、`recovery-await-confirmation`、`auto-fix-await-confirmation` 及带 `restart/resume/recovery/blocked/incident` 语义的事件）。
- 判定建议优先级：先看 `restart_generation` 是否与最近屏障代际不一致（不一致即 stale），再看同批次且 `created_at <= last_barrier_at`（命中即 stale）。

## 7. 状态上报覆盖规则

针对 `running-status-report`：
1. 每轮仅保留最新一条为有效状态工单。
2. 旧状态工单标记为 `stale_status_superseded`。
3. 原始队列行不删除，只更新账本状态。

## 8. 结束阶段排空（Drain）

触发条件：
- `live_status` 表示 shutdown/complete，或 supervisor 判定会话闭合。

Drain 行为：
1. 执行一次立即、无等待轮询（`drain pass`）。
2. 仅执行安全的收尾类工单。
3. 非安全或依赖旧上下文的工单标记为 `deferred` 或 `stale_by_restart`。

建议初始白名单（可按业务扩展）：
- `running-status-report`
- `manual-wait-paused`
- `budget-exhausted-stop`
- `known-infra-transient-stop`

白名单事件在 drain/recovery-drain 中建议按“信息类工单”处理：
- 允许被认领并输出继续盯盘动作。
- 不触发业务恢复命令（`business_command` 留空）。

建议支持 start-file 可选配置键（逗号/分号分隔）：
- `LOCAL_GUARD_POLL_STATUS_REPORT_EVENTS`
- `LOCAL_GUARD_POLL_DRAIN_SAFE_EVENTS`
- `LOCAL_GUARD_POLL_BARRIER_EVENTS`
- `LOCAL_GUARD_POLL_RESTART_SENSITIVE_EVENTS`
- `LOCAL_GUARD_POLL_EVENT_POLICY_STRICT`（默认 `false`）

默认约束（实现强制）：
- 无论如何配置，`running-status-report` 视为状态上报事件，并保持在 drain-safe 集合内（脚本会自动补齐）。
- 若 barrier/restart-sensitive 集合未覆盖核心重启敏感事件（`incident-captured`、`recovery-await-confirmation`、`auto-fix-await-confirmation`），脚本会自动补齐并输出规范化记录。
- 当 `LOCAL_GUARD_POLL_EVENT_POLICY_STRICT=true` 时，若存在自动补齐需求则直接失败退出，要求先修正策略配置。
- 代际 stale 启发式优先作用于“重启敏感事件”集合，避免对普通动作事件过度 stale 化。

恢复行为：
- 下次会话启动时，在进入常规轮询前先执行一次 `recovery-drain`。

## 9. 重试与退避

针对可重试失败：
- 递增 `retry_count`。
- 按有界退避写入 `next_retry_at`。

建议退避（分钟）：
- 第 1 次重试：5
- 第 2 次重试：15
- 第 3 次重试：30
- 超过 3 次后保持 `failed`，并要求人工确认。

## 10. 存储与保留

队列文件：
- append-only JSONL。

账本文件：
- 建议路径：`out/artifacts/ab_agent_queue/ai_ticket_ledger_<start-token>.json`
- 建议 schema：`AB_AI_TICKET_LEDGER_V2`

保留策略：
- 活跃账本窗口：7 天。
- 已完成/过期归档：30 天。
- 失败/人工确认类：60 天。

压缩归档：
- 每日一次或会话结束后执行。
- 活跃账本保留未决和近期关键记录。
- 已解决历史记录迁移到按日期分片的归档文件。

## 11. 与 V1 的兼容关系

V1 当前已提供：
- triggerless 轮询输出。
- `processed_ids` 跟踪。
- fallback 动作（`watch_once`、业务恢复、继续盯盘）。

V2 必须保持：
- 现有队列生产者格式兼容。
- 现有业务动作命令形态兼容。

V2 增量：
- 完整状态机和账本元数据。
- 屏障/stale/deferred 语义。
- drain 与 recovery-drain 机制。

## 12. 分阶段落地计划

阶段 A（语义核心）：
- 增加 V2 账本 schema 与状态迁移。
- 除屏障命中外，运行行为与现状保持等价。

阶段 B（屏障 + stale + 重试）：
- 实现重启屏障分类。
- 增加 retry_count/next_retry_at。

阶段 C（drain + 压缩归档）：
- 增加结束阶段 drain 与 recovery-drain。
- 增加保留期压缩归档任务。

阶段 D（清理候选评审）：
- 经过稳定观察窗口后，再评估是否物理删除 trigger/dispatch 脚本。

## 13. 验收标准

1. 运行时不物理删除任何原始工单行。
2. 每条已处理工单在账本中都有确定终态。
3. 屏障工单不会放行同批尾部的非安全执行。
4. 结束阶段排空（drain）只执行一次且可幂等重入。
5. recovery-drain 在下一次会话启动仅执行一次。
6. 重试行为有界且可观测。
7. 压缩归档后仍保持审计与回放可追溯。

## 14. 待定项

1. 屏障事件的精确分类清单（初始可基于现有业务命令映射）。
2. 各事件族的 stale-by-restart 精确判定启发式。
3. 账本是否拆分为 `state` + `history` 双文件，或维持单文件 + 压缩归档。
