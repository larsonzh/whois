# 门禁加锁优先级清单（CN）

目的：在不牺牲吞吐的前提下，优先保护“并发写冲突风险高”的门禁步骤。

## 分级规则

| 风险级别 | 判定标准 | 默认策略 |
| --- | --- | --- |
| 高 | 会改写共享文件、共享状态、共享索引，且可能被多进程同时触发 | 必须加锁 |
| 中 | 主要读操作，但下游可能触发写；或写入是局部文件且冲突概率中等 | 可选加锁，按场景启用 |
| 低 | 纯只读检查，不改状态文件 | 通常不加锁 |

## 高风险（建议必须加锁）

1. 编码修复链路
   - scripts: tools/dev/enforce_utf8_bom_lf_changed.ps1, tools/dev/enforce_utf8_bom_lf.ps1
   - 原因: 会改写同一批 tracked 文件，存在并发写覆盖风险
   - 建议: 共享同一把仓库级互斥锁；锁占用时默认 skip，关键流程可切换 fail

2. 启动文件重写与状态回填
   - scripts: tools/test/precheck_unattended_ab_start_file.ps1, tools/test/reset_unattended_ab_start_file.ps1
   - 原因: 会写 start-file 键值，多个流程并发易互相覆盖
   - 建议: 按 start-file 维度加锁（已有 start-file 写锁思路可复用）

3. 票据状态回写
   - scripts: tools/test/poll_agent_tickets.ps1（ack/mark_processed/ledger 写入路径）
   - 原因: 同一 ticket/ledger 的并发 claim+done 可能导致重复处理或状态抖动
   - 建议: 按 queue+start-file 维度加锁或原子写策略

## 中风险（建议按场景加锁）

1. 统一启动前检查
   - script: tools/test/check_unattended_ab_launch_ready.ps1
   - 原因: 包含外部脚本调用链，其中含写动作（非 DryRun）
   - 建议: 不在顶层脚本额外全局加锁；依赖下游写脚本各自锁，避免串行化过度

2. A/B fastmode 启动门禁
   - scripts: tools/test/start_dev_verify_fastmode_A.ps1, tools/test/start_dev_verify_fastmode_B.ps1
   - 原因: 启动前会触发编码修复、字段门禁等组合动作
   - 建议: 维持“单实例互斥 + 下游写脚本锁”组合，不额外套全局大锁

## 低风险（通常不加锁）

1. 纯静态体检
   - script: tools/test/check_task_definition_static.ps1
   - 原因: 只读

2. 字段同步只读检查
   - script: tools/test/check_unattended_start_field_sync.ps1（检查模式）
   - 原因: 只读

3. 迷你回归检查
   - script: tools/test/status_ticket_mini_regression.ps1
   - 原因: 只读

## 实施建议

1. 优先保证“写路径有锁，读路径无锁”。
2. 锁粒度优先按资源维度，不用全局单锁。
3. 默认策略优先 skip-on-lock，关键阶段可切 fail-on-lock。
4. 对 lock=busy 统一打印结构化日志，便于排障与观测。
5. 每次新增会写文件的门禁时，评审项中强制回答“锁策略是什么”。
