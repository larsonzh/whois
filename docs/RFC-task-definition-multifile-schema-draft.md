# 任务定义多文件 Schema 草案（兼容 V1）

> 说明：本文中的 Vx 为暂定方案代号，用于避免与既有历史 V2 命名混淆。

## 1. 目标

- 支持在同一份任务定义文件中，在一个 D 轮次内修改多个源码文件。
- 保持现有 V1 单文件任务定义无需改动即可继续运行。
- 保持包装器入口用法不变（`-TaskDefinitionFile` 仍只接收一个 JSON 文件）。

## 2. 当前限制概述

当前实现本质上是“单目标文件”模型：

- 根字段只有一个 `targetFile`。
- code-step 执行器每轮只读取一个文件、应用全部 operation、再写回同一个文件。
- baseline reset 只维护一个 baseline 文件（`target_baseline.c`）。
- 包装器的 no-op/source-delta 分类仅跟踪一个目标相对路径。

## 3. 方案提议（Vx）

### 3.1 兼容性规则

- `schemaVersion=1`：保持现有行为完全不变。
- `schemaVersion=vx-draft`：允许多文件定义，同时保留 V1 字段语义。
- 若 Vx 文件仅使用 V1 字段（`targetFile` + operation 不含 `target`/`file`），运行行为必须与 V1 一致。

### 3.2 新增/扩展字段

- 根级字段：
  - `targetFile`（可选，历史默认目标）
  - `targetFiles`（可选，Vx）：命名目标数组
  - `defaultTarget`（可选，Vx）：当 operation 未显式指定目标时使用的目标 id

- 轮次级字段（`D1`~`D4`）：
  - 保留 `type`、`description`、`idempotentContains`、`operations`
  - 新增可选 `idempotentContainsByTarget`，用于多目标 marker 检查

- operation 级字段（`regex-patch`）：
  - 保留 `pattern`、`replacement`
  - 新增可选 `target`（来自 `targetFiles` 的目标 id）
  - 新增可选 `file`（直接路径，支持绝对或仓库相对路径）

### 3.3 Vx JSON 草案

```json
{
  "schemaVersion": "vx-draft",
  "name": "next-phase-multi-file-draft",
  "targetFile": "src/core/preclass.c",
  "targetFiles": [
    { "id": "preclass", "path": "src/core/preclass.c" },
    { "id": "query_exec", "path": "src/core/whois_query_exec.c" }
  ],
  "defaultTarget": "preclass",
  "qualityPolicy": {
    "unknownNoOpBudget": 1,
    "unknownNoOpConsecutiveLimit": 2,
    "disableUnknownNoOpBudgetGate": false,
    "taskDesignQualityPolicy": "enforce"
  },
  "rounds": {
    "D1": {
      "type": "regex-patch",
      "description": "单轮同时修改 preclass 与 query_exec",
      "idempotentContains": [
        "wc_preclass_default_action_literal("
      ],
      "idempotentContainsByTarget": {
        "query_exec": [
          "wc_preclass_resolve_decision_fields("
        ]
      },
      "operations": [
        {
          "target": "preclass",
          "pattern": "TODO_D1_PRECLASS_PATTERN",
          "replacement": "TODO_D1_PRECLASS_REPLACEMENT"
        },
        {
          "target": "query_exec",
          "pattern": "TODO_D1_QUERY_EXEC_PATTERN",
          "replacement": "TODO_D1_QUERY_EXEC_REPLACEMENT"
        }
      ]
    },
    "D2": {
      "type": "regex-patch",
      "description": "operation 直接指定文件路径",
      "operations": [
        {
          "file": "src/core/preclass.c",
          "pattern": "TODO_D2_PRECLASS_PATTERN",
          "replacement": "TODO_D2_PRECLASS_REPLACEMENT"
        }
      ]
    },
    "D3": {
      "type": "builtin",
      "builtin": "D3"
    },
    "D4": {
      "type": "noop",
      "description": "可选冻结轮"
    }
  }
}
```

## 4. 目标文件解析规则

每个 operation 的目标解析顺序如下：

1. 若 `operation.file` 存在，直接使用该路径。
2. 否则若 `operation.target` 存在，按 `targetFiles[id]` 映射。
3. 否则若根字段 `defaultTarget` 存在，按 id 映射。
4. 否则若根字段 `targetFile` 存在，使用历史单目标。
5. 否则若 `targetFiles` 仅有一项，使用该唯一目标。
6. 以上都不满足时，抛出明确的 schema 错误。

## 5. 运行时行为规则

- 每轮对“涉及到的每个目标文件”各读取一次，放入内存文本映射。
- 按 operation 声明顺序执行替换（跨文件顺序由 operation 列表顺序保证）。
- 仅回写发生变更的文件。
- 日志保持向后兼容，并补充多文件摘要：
  - 保留现有逐文件日志：`action=applied target=<path>`
  - 新增一行汇总，例如：`targets_changed=<n> targets_touched=<m>`

## 6. Reset/Baseline 兼容策略

- V1 继续使用现有 `_code_step_state/target_baseline.c` 逻辑。
- Vx 增加按目标存储 baseline 的目录，例如：
  - `_code_step_state/target_baseline/<target-id>.baseline`
- `-Reset`（restore-source）在 Vx 下应恢复所有被跟踪目标。
- `-ResetStateOnly` 继续仅清状态，不恢复源码。

## 7. 必要代码改造

### 7.1 执行器（高）

- 文件：`tools/test/autopilot_code_step_rounds.ps1`
- 范围：
  - 解析 Vx 字段（`targetFiles`、`defaultTarget`、operation 的 `target`/`file`）
  - 实现按目标文件的文本映射执行引擎
  - 增加多目标 baseline 存储/恢复
  - 输出向后兼容日志

### 7.2 包装器质量闸/no-op 逻辑（高）

- 文件：`tools/test/start_dev_verify_8round_multiround.ps1`
- 范围：
  - 将单一 `taskTargetRelativePath` 替换为“目标路径集合”
  - no-op 分类从“单文件变化”升级为“多目标任一/全部变化”语义
  - 增加未知 target id、无法解析目标的 operation 校验

### 7.3 可选执行器更新（低）

- 文件：`tools/test/autopilot_dev_recheck_8round.ps1`
- 范围：
  - 主体逻辑基本不变，仅需补充可选日志字段兼容检查

### 7.4 模板与文档（低）

- 文件：`testdata/autopilot_code_step_tasks_template.json`
- 在保留 V1 模板的同时，新增 Vx 示例模板。

- 文档更新：
  - `docs/OPERATIONS_CN.md`
  - `docs/OPERATIONS_EN.md`
  - `docs/RFC-address-space-preclassifier.md`
  - `docs/RFC-whois-client-split.md`

## 8. 改造成本评估（工程）

前提：
- 保持现有包装器命令接口不变。
- 包含一轮基于现有无人值守 golden 流程的完整验证。

预计工作量：

- 执行器 Vx 支持 + 向后兼容：1.5 ~ 2.0 天
- baseline/reset 多目标迁移逻辑：0.5 ~ 1.0 天
- 包装器 no-op/质量策略适配：1.0 ~ 1.5 天
- 模板/文档更新 + 迁移说明：0.5 天
- 验证执行 + 缺陷缓冲：1.0 ~ 1.5 天

总计：4.5 ~ 6.5 工程日

## 9. 风险点

- 最高风险：单轮同时修改多个文件时，no-op 分类可能出现“部分变化/部分无变化”导致判定漂移。
- 高风险：Vx 下 restore-source 语义在“仅部分目标 baseline 与 HEAD 不一致”时可能出现恢复语义不一致。
- 中风险：日志形态变化可能影响现有基于 grep 的监控脚本。

## 10. 建议分阶段上线

Phase 1：
- 仅在 Vx 路径实现解析器 + 执行器支持。
- V1 路径保持完全不动。

Phase 2：
- 开启包装器多目标质量闸/no-op 感知。
- 增加一份真实 Vx 任务定义用于 dry-run 验证。

Phase 3：
- 完成上线文档与迁移说明。
- 在新的 A/B 清单中推广 Vx 模板。

## 11. 双轨实施建议（V1 保留 + Vx 复制）

为降低改造风险，建议采用双轨并行：

- V1 轨道：冻结现有行为，不做语义改动，仅接收必要 bugfix。
- Vx 轨道：从 V1 复制生成独立脚本与模板，在副本上实现多文件能力。

### 11.1 文件命名建议

建议保留以下 V1 文件不动：

- `tools/test/autopilot_code_step_rounds.ps1`
- `tools/test/start_dev_verify_8round_multiround.ps1`
- `tools/test/start_autopilot_8round_code_change.ps1`
- `testdata/autopilot_code_step_tasks_template.json`

建议新增以下 Vx 副本：

- `tools/test/autopilot_code_step_rounds_vx.ps1`
- `tools/test/start_dev_verify_8round_multiround_vx.ps1`
- `tools/test/start_autopilot_8round_code_change_vx.ps1`
- `testdata/autopilot_code_step_tasks_template_vx.json`

### 11.2 入口分流建议

- V1 入口维持默认，继续服务既有任务定义（`schemaVersion=1`）。
- Vx 入口默认读取 Vx 模板（`schemaVersion=vx-draft`），仅用于多文件任务。
- 在 VS Code 任务层增加明确命名（例如 `... (V1)` / `... (Vx)`），避免误跑。

### 11.3 回退策略

- 若 Vx 任一阶段出现稳定性问题，直接切回 V1 入口继续执行。
- Vx 问题修复后重新 dry-run，不影响 V1 交付节奏。

## 12. 落地执行清单（按双轨方案）

### 12.1 第 0 步：复制与冻结

1. 复制 V1 脚本/模板生成 Vx 文件。
2. 在 RFC 中记录“V1 冻结基线提交哈希”。
3. 约定：V1 仅允许兼容性 bugfix，不引入 Vx 功能。

### 12.2 第 1 步：Vx 执行器能力

1. 在 `autopilot_code_step_rounds_vx.ps1` 实现 `targetFiles/defaultTarget/operation.target|file`。
2. 增加 Vx 多目标 baseline 与 reset 恢复。
3. 保持 V1 日志兼容，同时新增多文件汇总行。

### 12.3 第 2 步：Vx 包装器质量闸

1. 在 `start_dev_verify_8round_multiround_vx.ps1` 改造多目标 no-op/source-delta 判定。
2. 增加 target 解析失败、未知 target id 的 fail-fast。
3. 与现有 D1 reset guard 保持一致口径。

### 12.4 第 3 步：验证与发布

1. 先跑 Vx dry-run（单轮 + 多轮）。
2. 再跑完整无人值守 golden 流程。
3. 验证通过后，将 Vx 模板纳入后续 A/B 清单；V1 继续保留。

## 13. 成本口径（双轨方案下）

采用“双轨复制”后，总体工作量仍维持在本 RFC 第 8 节范围（4.5 ~ 6.5 工程日），但风险分布更可控：

- 开发成本略增（多维护一套入口/文件）。
- 上线风险显著下降（V1 可随时兜底回退）。
