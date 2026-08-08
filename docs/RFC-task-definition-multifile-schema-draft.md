# 任务定义多文件 Schema 草案（兼容 V1）

> 说明：本文中的 Vx 为暂定方案代号，用于避免与既有历史 V2 命名混淆。
>
> 状态：设计草案，尚未授权现有无人值守入口执行多文件任务。落地时应为任务定义、task-static 绑定产物和事务收据分别分配稳定版本号，不能只靠脚本文件名区分协议。

## 1. 目标

- 支持在同一份任务定义文件中，在一个 D 轮次内修改多个源码文件。
- 保持现有 V1 单文件任务定义无需改动即可继续运行。
- 保持包装器入口用法不变（`-TaskDefinitionFile` 仍只接收一个 JSON 文件）。
- 同时覆盖初始编制、无人值守 task-static/code-step 和运行期代理自愈三条路径。
- 多文件任一目标失败时整轮 fail-close，不留下不可证明的部分写入。

非目标：

- 允许通过显式 `lifecycle=create` 和专用 `create-file` operation 创建缺失文件；不允许隐式创建，也暂不允许删除或重命名源码文件。
- 不允许一个 operation 跨两个文件做一次正则匹配；每个 operation 只作用于一个目标。
- 不改变 D1-D4 与 V1-V4 的既有含义，也不放宽现有代码自愈编辑边界。

## 2. 当前限制概述

当前实现本质上是“单目标文件”模型：

- 根字段只有一个 `targetFile`。
- task-static checker 只维护一个 `workingText`，并只输出一个有效源码文件。
- `TASK_STATIC_VALIDATED_ARTIFACT_V1` 只绑定一个目标、一个基线 SHA-256 和一个有效源码 SHA-256。
- code-step 每轮只校验并原子写回一个文件，且不再自行执行 operation。
- baseline reset 只维护一个 baseline 文件（`target_baseline.c`）。
- 包装器的 no-op/source-delta 分类仅跟踪一个目标相对路径。
- prerequisite chain 要求前置定义与当前定义指向同一个目标。
- repair transaction 的 operation preview 只模拟一个目标文本。

## 3. 方案提议（Vx）

### 3.1 兼容性规则

- `schemaVersion=1`：保持现有行为完全不变。
- `schemaVersion=vx-draft`：允许多文件定义，同时保留 V1 字段语义。
- 若 Vx 注册表只有一个目标，operation 省略 `target` 时，其正则、marker、首错、replay 和断言行为必须与等价 V1 定义一致。
- Vx 解析、产物或提交失败不得自动降级为 V1；未知 schema 与不完整证据一律 fail-close。
- V1 继续使用现有参数、状态文件、baseline 文件名、关键日志标签和 `TASK_STATIC_VALIDATED_ARTIFACT_V1`。

### 3.2 新增/扩展字段

- 根级字段：
  - `targetFile`（可选，历史默认目标）
  - `targetFiles`（Vx 必填）：命名目标数组
  - `defaultTarget`（可选，Vx）：当 operation 未显式指定目标时使用的目标 id

- 轮次级字段（`D1`~`D4`）：
  - 保留 `type`、`description`、`idempotentContains`、`operations`
  - 新增 `idempotentContainsByTarget`，用于多目标轮次 marker 检查
  - `postApplyAssertions` 的每一项新增 `target`，将断言绑定到一个目标

- operation 级字段（`regex-patch`）：
  - 保留 `pattern`、`replacement`
  - 新增可选 `target`（来自 `targetFiles` 的目标 id）
  - 不把 `file` 作为正式能力；直接路径会绕过稳定 target id、目标注册表、自愈预览和收据绑定
- operation 级字段（`create-file`）：
  - `type` 固定为 `create-file`
  - `target` 必须引用 `lifecycle=create` 的目标
  - `content` 是待创建文件的完整文本内容
  - `contentSha256` 是按 UTF-8 无 BOM 编码后的预期内容 SHA-256；实现必须复算，禁止信任声明值
  - `existingPolicy` 当前只允许 `skip`，表示目标已存在时不覆盖

Vx 目标条目统一使用以下字段：

- `id`：匹配 `^[a-z][a-z0-9_]{0,63}$`，在任务定义内唯一。
- `file`：仓库相对路径，在规范化后唯一；禁止绝对路径、`..`、目录和仓库逃逸。
- `kind`：可选，取值 `c-source`、`c-header` 或 `text`，省略时为 `text`。
- `lifecycle`：可选，取值 `existing` 或 `create`，省略时为 `existing`。

目标身份由 `id + 规范完整路径 + kind + lifecycle` 共同绑定，不以 basename 判重。因此 `src/core/preclass.c` 与 `include/wc/preclass.h` 是两个合法且独立的目标，即使 basename 相同；应分别使用清晰 id，例如 `preclass_source` 与 `preclass_header`。Windows 上路径按大小写不敏感规则归一化，`Foo.h` 与 `foo.h` 视为同一路径冲突。`id` 不得由文件名自动推导。

`targetFiles[].path` 不进入正式 schema。当前草案与个别试探代码曾混用 `path`/`file`，应在实现前统一为 `file`。

### 3.3 Vx JSON 草案

```json
{
  "schemaVersion": "vx-draft",
  "name": "next-phase-multi-file-draft",
  "targetFile": "src/core/preclass.c",
  "targetFiles": [
    { "id": "preclass_source", "file": "src/core/preclass.c", "kind": "c-source", "lifecycle": "existing" },
    { "id": "preclass_header", "file": "include/wc/preclass.h", "kind": "c-header", "lifecycle": "create" },
    { "id": "query_exec", "file": "src/core/whois_query_exec.c", "kind": "c-source", "lifecycle": "existing" }
  ],
  "defaultTarget": "preclass_source",
  "qualityPolicy": {
    "unknownNoOpBudget": 1,
    "unknownNoOpConsecutiveLimit": 2,
    "disableUnknownNoOpBudgetGate": false,
    "taskDesignQualityPolicy": "enforce",
    "operationSafetyPolicy": "enforce"
  },
  "rounds": {
    "D1": {
      "type": "regex-patch",
      "description": "单轮同时修改 preclass 与 query_exec",
      "idempotentContainsByTarget": {
        "preclass_source": [
          "TODO_D1_PRECLASS_ROUND_MARKER"
        ],
        "query_exec": [
          "TODO_D1_QUERY_EXEC_ROUND_MARKER"
        ]
      },
      "operations": [
        {
          "target": "preclass_source",
          "pattern": "TODO_D1_PRECLASS_PATTERN",
          "replacement": "TODO_D1_PRECLASS_REPLACEMENT",
          "idempotentContains": [
            "TODO_D1_PRECLASS_OP_MARKER"
          ]
        },
        {
          "type": "create-file",
          "target": "preclass_header",
          "content": "TODO_D1_PRECLASS_HEADER_CONTENT",
          "contentSha256": "TODO_D1_PRECLASS_HEADER_UTF8_NO_BOM_SHA256",
          "existingPolicy": "skip",
          "idempotentContains": [
            "TODO_D1_PRECLASS_HEADER_MARKER"
          ]
        },
        {
          "target": "query_exec",
          "pattern": "TODO_D1_QUERY_EXEC_PATTERN",
          "replacement": "TODO_D1_QUERY_EXEC_REPLACEMENT",
          "idempotentContains": [
            "TODO_D1_QUERY_EXEC_OP_MARKER"
          ]
        }
      ],
      "postApplyAssertions": [
        {
          "name": "preclass-definition",
          "target": "preclass_source",
          "pattern": "TODO_D1_PRECLASS_ASSERTION",
          "expectedCount": 1
        },
        {
          "name": "preclass-header-declaration",
          "target": "preclass_header",
          "pattern": "TODO_D1_PRECLASS_HEADER_ASSERTION",
          "expectedCount": 1
        },
        {
          "name": "query-exec-call",
          "target": "query_exec",
          "pattern": "TODO_D1_QUERY_EXEC_ASSERTION",
          "expectedCount": 1
        }
      ]
    },
    "D2": {
      "type": "regex-patch",
      "description": "继续通过稳定 target id 指定文件",
      "operations": [
        {
          "target": "preclass_source",
          "pattern": "TODO_D2_PRECLASS_PATTERN",
          "replacement": "TODO_D2_PRECLASS_REPLACEMENT",
          "idempotentContains": [
            "TODO_D2_PRECLASS_OP_MARKER"
          ]
        }
      ],
      "idempotentContainsByTarget": {
        "preclass_source": [
          "TODO_D2_PRECLASS_ROUND_MARKER"
        ]
      },
      "postApplyAssertions": [
        {
          "name": "d2-preclass-result",
          "target": "preclass_source",
          "pattern": "TODO_D2_PRECLASS_ASSERTION",
          "expectedCount": 1
        }
      ]
    },
    "D3": {
      "type": "noop",
      "description": "No source change is designed for D3."
    },
    "D4": {
      "type": "noop",
      "description": "可选冻结轮"
    }
  }
}
```

示例中的 TODO 只解释结构；正式任务定义在生成 start-file 前必须清零全部 TODO。多目标初始编制应使用 `idempotentContainsByTarget` 和显式 assertion target；轮次级旧 `idempotentContains` 仅作为单目标/defaultTarget 兼容形式。

## 4. 目标文件解析规则

Vx 每个 operation 的目标解析顺序如下：

1. 若 `operation.target` 存在，按 `targetFiles[id]` 映射；未知 id 立即失败。
2. 否则若根字段 `defaultTarget` 存在，按 id 映射。
3. 否则若 `targetFiles` 仅有一项，使用该唯一目标。
4. 以上都不满足时，抛出明确的 schema 错误。

根字段 `targetFile` 仅用于兼容现有读取方，不参与优先级竞争。它存在时必须与 `defaultTarget` 对应条目的 `file` 完全一致。Vx 初始编制应为每个 operation 和 assertion 显式填写 `target`。

共享解析器必须先把所有目标规范化为仓库相对 `/` 路径，再拒绝 id 重复、路径重复、目录、符号链接逃逸和大小写归一化后的重复路径。存在性规则由 lifecycle 决定：

- `lifecycle=existing`：目标必须已存在且是普通文件，否则立即以 task-definition/schema 故障退出，禁止自动创建。
- `lifecycle=create`：目标可以不存在；若存在则必须是普通文件。其父目录必须已存在且位于仓库内，不自动创建目录。
- `lifecycle=create` 目标必须恰好由一个 `create-file` operation 首次引入；不得先对不存在目标执行 regex operation。
- 未声明 `lifecycle=create` 时，任何缺失目标均不得根据 operation 内容猜测为“需要创建”。

目标按规范路径排序只用于 manifest、哈希和提交锁顺序；operation 执行顺序仍以 JSON 数组为准。

### 4.1 `create-file` 幂等语义

`create-file` 采用 create-if-absent 语义：

1. 目标不存在：在内存映射中创建 `content`，状态为 `created`。
2. 目标已存在：不覆盖、不截断、不改编码，状态为 `already-exists`，即 operation 层面的幂等跳过。
3. `already-exists` 不是无条件成功：现有内容仍必须满足该 op 的 `idempotentContains`、声明的 `contentSha256` 或等价的精确内容绑定，以及本轮 target-bound assertions。任一不符按 task-definition mismatch 失败，禁止把错误文件静默视为已创建。
4. `create-file` replay 时目标已存在，必须得到 `already-exists` 且完整文本映射字节不变。
5. `create-file` 不允许 `overwrite`；需要修改已存在文件时，后续 operation 必须使用普通 regex-patch，并服从全局 operation 顺序。

这里“已存在则跳过”只表示不执行写覆盖，不表示跳过安全校验。

## 5. 运行时行为规则

- 每轮对“涉及到的每个目标文件”各读取一次，放入内存文本映射。
- `lifecycle=create` 且磁盘目标缺失时，以 `exists=false` 的空槽进入映射；只有其 `create-file` operation 可以把该槽转换为存在状态。
- 按 operation 声明顺序执行替换（跨文件顺序由 operation 列表顺序保证）。
- 首个 operation 失败立即停止；失败 replacement、后续 op、replay、断言和后续轮均不执行。
- task-static 全部通过后生成一个 manifest 和多个 effective payload；code-step 不重新解释 operation。
- code-step 在写入任何文件前校验全部目标与 payload，只提交发生变更的文件。
- 日志保持向后兼容，并补充多文件摘要：
  - 保留现有逐文件日志：`action=applied target=<path>`
  - 新增一行汇总，例如：`targets_changed=<n> targets_touched=<m>`

多文件“整轮原子”不能简单理解为多个 `File.Replace` 天然原子。正式实现必须采用“全量预验证 + journal + 每文件原子替换 + 整组回滚 + 写后哈希”的可恢复事务，详见第 16 节。

## 6. Reset/Baseline 兼容策略

- V1 继续使用现有 `_code_step_state/target_baseline.c` 逻辑。
- Vx 使用 `baseline-manifest.json` 和按目标保存原始字节的 `baseline/<target-id>.bin`。
- `-Reset`（restore-source）在 Vx 下应恢复所有被跟踪目标。
- `-ResetStateOnly` 继续仅清状态，不恢复源码。
- A 阶段 baseline 来自项目基线；B 阶段 baseline 来自完整性验证后的 A 成功快照。
- 同一次 reset 不允许某些目标恢复 baseline、另一些目标回退 HEAD，从而形成混合代际。
- baseline 捕获与恢复均按原始字节执行，保留 BOM、CRLF/LF 和末尾换行。
- `lifecycle=create` 且 baseline 不存在时只记录不存在事实；restore-source 删除本阶段创建的文件，不生成或恢复空占位文件。

## 7. 必要代码改造

### 7.1 执行器（高）

- 文件：`tools/test/autopilot_code_step_rounds.ps1`
- 范围：
  - 消费多目标绑定 manifest 与 payload，不在 code-step 重跑 regex
  - 增加 journal、backup、整组回滚和写后验证
  - 增加多目标 baseline 存储/恢复与 crash recovery
  - 保持向后兼容日志

### 7.1.1 独立 checker（最高）

- 文件：`tools/test/check_task_definition_static.ps1`
- 范围：
  - 共享目标解析器和多文件文本映射
  - target-bound marker/assertion、全映射 replay、逐 C 源文件 syntax gate
  - 多文件 prerequisite chain
  - 生成 Vx manifest 与 payload 目录

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
- 保留 V1 模板，另增 Vx 示例模板；正式定义仍需 TODO-free。

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

以上估算未覆盖当前已经生效的绑定产物、自愈候选事务、A 快照/B 恢复和多文件提交故障恢复，已不再适合作为正式排期。深化后的估算见第 24 节。

## 9. 风险点

- 最高风险：单轮同时修改多个文件时，no-op 分类可能出现“部分变化/部分无变化”导致判定漂移。
- 最高风险：第二个文件提交失败时，第一个文件已经落盘，形成混合源码。
- 高风险：checker、snapshot、wrapper 与 repair transaction 各自解析出不同目标集合。
- 高风险：Vx 下 restore-source 在“仅部分目标 baseline 与 HEAD 不一致”时出现混合恢复。
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

## 11. 双轨实施建议（V1 冻结分支 + Vx 共享核心）

结合当前 guard、ticket、snapshot、repair transaction 与绑定产物链，不建议复制整套 `_vx.ps1` 脚本。完整复制会形成两套命令生成、故障分类和恢复协议，长期漂移风险高于收益。

- V1 轨道：同一入口内进入冻结的 V1 adapter，只接收必要兼容性 bugfix。
- Vx 轨道：同一入口内进入 Vx adapter，复用日志、故障分类、worker timeout、mutex、票据和恢复编排。
- 共享核心：目标解析、manifest 校验、文件事务与 snapshot target set 必须只有一个实现。

### 11.1 文件组织建议

- 保持 `autopilot_code_step_rounds.ps1`、`start_dev_verify_8round_multiround.ps1` 和 stage window 命令入口不变。
- 增加小型共享模块承载 schema/target resolver 与多文件事务，不在各入口内复制解析逻辑。
- 保留 `testdata/autopilot_code_step_tasks_template.json` 作为 V1 模板，可新增一个 Vx 模板。
- 不默认新增 VS Code task；先通过现有入口的显式 Vx fixture/dry-run 验证。

### 11.2 入口分流建议

- V1 入口维持默认，继续服务既有任务定义（`schemaVersion=1`）。
- 同一入口读取 `schemaVersion=vx-draft` 时进入 Vx 分支，仅用于多文件任务。
- Vx 分支不完整或失败时禁止静默回退 V1。

### 11.3 回退策略

- 若 Vx 任一阶段出现稳定性问题，直接切回 V1 入口继续执行。
- Vx 问题修复后重新 dry-run，不影响 V1 交付节奏。

## 12. 落地执行清单（按双轨方案）

### 12.1 第 0 步：复制与冻结

1. 记录 V1 行为基线并建立 V1/Vx 对照 fixture。
2. 在 RFC 中记录“V1 冻结基线提交哈希”。
3. 约定：V1 仅允许兼容性 bugfix，不引入 Vx 功能。

### 12.2 第 1 步：Vx 执行器能力

1. 先在 checker 实现多目标解析、内存映射与绑定产物。
2. 再在 code-step 实现 journal、提交/回滚、baseline 与 reset。
3. 保持 V1 日志兼容，同时新增多文件汇总行。

### 12.3 第 2 步：Vx 包装器质量闸

1. 在现有 wrapper 的 Vx 分支改造多目标 no-op/source-delta 判定。
2. 增加 target 解析失败、未知 target id 的 fail-fast。
3. 接入 A snapshot/B restore 与 repair transaction。

### 12.4 第 3 步：验证与发布

1. 先跑 Vx dry-run（单轮 + 多轮）。
2. 再跑完整无人值守 golden 流程。
3. 验证通过后，将 Vx 模板纳入后续 A/B 清单；V1 继续保留。

## 13. 成本口径（双轨方案下）

采用“同入口、双 adapter、共享核心”后：

- V1 行为可通过 adapter 和回归冻结。
- Vx 可分阶段启用，不需要维护两套 guard/ticket/recovery 协议。
- V1 可作为后续独立会话的回退入口，但 Vx 运行中不得静默切换。

## 14. 单一权威解析器与目标集合冻结

目标解析、路径规范化和 target set 摘要必须由共享模块实现，并被 SyntaxOnly、checker、code-step、wrapper、A snapshot/B restore、repair transaction 与 launch-ready 共同调用。禁止各脚本保留略有差异的本地解析器。

生成 start-file 并通过 launch-ready 后，本次 A/B 会话的目标注册表冻结：

- 运行期自愈不得新增、删除、重命名 target id，也不得修改 target file/kind/defaultTarget/schemaVersion。
- task-static 故障可从故障 op 起修改其 `target`，但只能改为注册表中已有目标。
- compile/verify 代码故障的追加 op 可选择注册表中的其他目标，但不得扩展注册表。
- 若修复确实需要未声明文件，当前事务 fail-close，由人工重建本阶段任务定义并重新完成完整启动前验收。

这使 baseline、A snapshot、B restore、operation preview 与 code-step 收据始终覆盖同一闭包。

稳定 target set 按规范路径排序，并以 `id + NUL + path + NUL + kind + NUL + lifecycle + LF` 的序列计算 SHA-256。数组重排不得改变 operation 的目标，但会在 id/path/kind/lifecycle 对应关系变化时改变摘要。

## 15. task-static 多文件语义

### 15.1 内存模型与首错停止

checker 为目标注册表建立：

```text
target id -> normalized path -> lifecycle -> baseline exists/bytes/hash -> working exists/text
```

每轮按全局 operations 顺序执行。每个 op 只读写其 target 的 `working text`；首错立即停止，失败 replacement 不进入映射，后续 op、replay、assertions 和后续轮不执行。

`-OperationIndex n` 继续表示轮次数组中的全局第 n 项。focused check 必须在同一文本映射上顺序模拟前 `n-1` 个跨文件 op，并输出 `round`、`operation_index`、`target_id`、`target_path` 和首错分类。不能只模拟与目标 op 同文件的前置项。

### 15.2 marker、replay 与 assertions

- op marker 只在该 op 的目标文本中检查。
- marker 所有权在整个任务定义的 `(round, operation)` 范围内唯一，不能因 target 不同而复用。
- `create-file` 对缺失槽写入完整 content；对已存在槽只执行内容绑定、marker 和 assertion 校验，不替换文本。
- replacement 后原 pattern 必须在同一目标文本中零命中。
- 整轮 replay 从第一次应用后的完整文本映射开始，按同一全局顺序再执行一次；所有目标均字节不变才算通过。
- `absorbed-by-prior-round` / `idempotent-replay` 必须由当前 op 在当前 target 的自有 marker 证明。
- Vx `postApplyAssertions[].target` 必填；只在该 target 的整轮有效文本上精确计数，不提供“拼接所有文件后计数”。
- 跨文件 declaration/definition/caller 关系由多条 target-bound assertions 分别证明。

### 15.3 文件类型门禁

- 每个本轮 touched 的 `kind=c-source` 目标运行现有 C syntax gate。
- `kind=c-header` 不单独作为翻译单元编译，至少通过结构断言，并由后续完整编译验证 include 关系。
- `kind=text` 不运行 C syntax gate。
- 单文件 syntax PASS 不替代完整构建、链接、黄金、Step47 或业务验证。

### 15.4 ChainRounds 与 prerequisite

`-ChainRounds` 携带同一文本映射从故障轮推进到 D4；任一 target 首错停止整条链，后续轮不得拿原始磁盘文件单独检查。

`-PrerequisiteTaskDefinitionFiles` 升级为目标映射叠加：

- prerequisite 按命令行顺序执行。
- 相同规范路径共享一个文本槽，后置定义读取前置定义的有效结果。
- 新目标可加入映射，但必须通过仓库边界与 lifecycle 存在性门禁。
- prerequisite 创建的文件在后置定义中视为存在；若两个定义都对同一路径执行 `create-file`，后一个只能以 `already-exists` 幂等通过，且内容绑定必须一致。
- 不再要求 prerequisite 与当前任务只有一个完全相同的 target。
- manifest 记录前置定义路径、定义 SHA-256、应用顺序和目标集合摘要。
- A+B 链式验收最终对目标并集执行 replay、适用 syntax gate 与完整编译。

## 16. Vx 绑定产物与 code-step 提交协议

### 16.1 产物布局与 manifest

Vx 不传递单个 `ValidatedEffectiveSourceFile`，而传递一个 manifest 与 payload 目录：

```text
<round-artifact>/
  manifest.json
  payload/
    preclass.bin
    query_exec.bin
```

建议 manifest schema 为 `TASK_STATIC_VALIDATED_ARTIFACT_VX1`，至少包含：

- stage、round、task definition 绝对路径与 SHA-256；
- target set SHA-256、operation count、checker policy、生成时间；
- prerequisite 定义及顺序；
- 每个 target 的 id/path/kind/lifecycle/touched/changed；
- 每个 target 的 `baseline_exists`、`effective_exists`、baseline/effective length 与 SHA-256；
- changed target 的 payload 相对路径与 payload SHA-256。

`targets` 按规范路径排序。只有 changed target 必须有 payload；未变化目标可省略 payload，但仍必须绑定存在性与 baseline/effective hash。`baseline_exists=false` 时 length/hash 为 `null`；`effective_exists=true` 且目标发生创建或变化时必须有完整 payload。payload 以原始字节写出并按字节哈希。manifest 只有在 payload 全部完成后才原子发布。

### 16.2 code-step 写前门禁

写入任何目标前必须一次性通过：

- manifest schema、stage、round、任务定义路径与任务定义 SHA-256 匹配；
- 当前解析 target set 与 manifest 摘要匹配；
- 每个目标当前存在性及 length/hash 与 baseline 绑定匹配；`create` 目标若 checker 基线时不存在、提交前却突然出现，应判为 stale 并阻断；
- 每个 payload 存在、位于 artifact 目录内且 length/hash 匹配；
- 所有目标仍位于仓库内，无重复或符号链接逃逸；
- state dir 不存在未解决的提交 journal。

任一项失败不得写盘，沿用 `validated-artifact-*` noncode 分类，并增加 target id/path 诊断。code-step 不执行 regex、不补 prototype、不判断业务语义；任何 code-step 故障仍不授权修改源码或任务定义。

### 16.3 可恢复整轮提交

普通文件系统不提供跨多个路径的真正原子替换。Vx 必须实现以下可恢复事务：

1. 按规范路径排序提交目标。
2. 在各目标同目录写临时文件并验证 effective hash；父目录必须已经存在。
3. 在 state dir 原子写 `commit-journal.json`，记录 transaction id、全部目标、baseline/effective exists/hash、temp、backup 与 `prepared` 状态。
4. 再次验证全部磁盘 baseline 存在性与 hash。
5. 按稳定顺序执行：existing 目标使用每文件 `Replace/Move`；create 目标在仍不存在时使用不覆盖既有文件的原子 Move。若 create 目标此时已出现，提交失败并进入回滚，不得覆盖。每完成一项即原子更新 journal。
6. 全部替换后逐文件验证 effective hash。
7. 写 `commit-receipt.json`，再推进 invocationCount/lastRound。
8. 最后删除 backup、temp 与 journal。

若第 5-6 步失败，必须逆序恢复：existing 目标从 backup 恢复；本事务创建且 baseline 不存在的目标删除。随后验证全部回到 baseline 存在性与 hash；state 不推进。回滚验证失败时标记 `rollback-incomplete`，硬阻断后续 code-step/reset/restart，等待 noncode/script 专用处置。

进程启动发现未完成 journal 时，必须先恢复判定。这里的 baseline/effective 同时包含 exists 与 hash；只有“全部符合 baseline exists/hash”或“全部符合 effective exists/hash 且存在完整成功 receipt”可自动收敛。任何存在性或内容混合状态必须按 journal 恢复或 fail-close。

### 16.4 日志与状态

逐文件日志保留既有标签与 action，并追加 target id：

```text
[CODE-STEP] round=D1 action=applied target=<absolute-path> target_id=preclass
[CODE-STEP] round=D1 action=already-applied target=<absolute-path> target_id=query_exec
[CODE-STEP] round=D1 action=created target=<absolute-path> target_id=preclass_header
[CODE-STEP] round=D1 action=already-exists target=<absolute-path> target_id=preclass_header
[CODE-STEP] round=D1 transaction=<id> targets_declared=2 targets_touched=2 targets_changed=1 commit=success
```

Vx state 至少记录 schema、invocationCount、lastRound、lastTransactionId、lastManifestSha256、targetSetSha256 和 lastTimestamp。只有完整 receipt 后才能推进轮次。

## 17. Baseline、Reset 与 A/B 快照

Vx state 目录建议为：

```text
_code_step_state/
  baseline-manifest.json
  baseline/
    preclass.bin
    query_exec.bin
```

baseline manifest 绑定任务定义 hash、target set hash、每个目标的规范路径、lifecycle、exists、length、SHA-256 和来源。`lifecycle=create` 且 baseline 时不存在的目标记录 `exists=false`、`length=null`、`sha256=null`，不得生成伪造的空文件 baseline。

- `-Reset -ResetStateOnly` 只清状态和已确认安全的运行产物，不恢复业务文件；存在不可证明安全的 journal 时仍阻断。
- `-Reset` restore-source 先验证完整 baseline 集合，再复用第 16.3 节事务恢复所有目标。
- restore-source 对 `baseline exists=false` 目标的正确结果是文件不存在；若本阶段创建过该文件，事务必须删除并验证路径消失。
- 任一目标无法恢复时 reset 整体失败并保留证据；不得只删状态掩盖混合源码。

现有 `A_SUCCESS_SNAPSHOT_MANIFEST_V1` 已有多文件列表与 hash，可作为基础，但必须改用共享 resolver：

- A snapshot 覆盖 A target set 全部目标，而不只复制 changed targets；缺失目标以 `exists=false` manifest 条目表示，不创建占位文件。
- B 恢复允许集合来自冻结的 A target set。
- B 可声明不同 target set；与 A 有交集的文件必须先匹配 A snapshot hash。
- 若 A 创建了文件，B snapshot restore 必须恢复该文件及其 hash；若 A 快照声明目标不存在，B 恢复必须保证该路径不存在。
- snapshot 外文件、未 manifest 文件、目标集合摘要不一致全部阻断。

## 18. wrapper 的 source-delta 与 no-op 真值表

wrapper 在 code-step 前后为冻结 target set 计算 `id -> path -> length -> sha256` 向量。全局 git patch hash 可保留为环境证据，但不能作为 Vx no-op 的唯一依据。

逐目标状态：

- `changed`：前后 hash 不同且等于 manifest effective hash。
- `created`：前不存在、后存在且等于 manifest effective hash，计入 source changed。
- `unchanged-idempotent`：前后相同，checker 已证明对应 ops 通过 marker/replay 收敛。
- `already-exists`：`create-file` 前后均存在且字节不变，并已通过内容绑定、marker 与 assertions；属于幂等状态。
- `untouched`：本轮无 op 指向该目标，baseline/effective 相同。
- `mismatch`：任一事实与 manifest 不一致，硬失败。

聚合规则：

- 至少一个 `changed` 或 `created`：`source_delta_after_code_step=changed`，不得分类为 D-NOP。
- 零个 changed/created 且所有 touched 均为 `unchanged-idempotent` 或经完整验证的 `already-exists`：按既有 allowed no-op class 判定 safe no-op。
- 零个 changed 但证据不完整：`unknown-no-op`，继续受预算和连续次数门禁约束。
- 出现 mismatch：code-step/noncode 失败，不进入 no-op 分类。

“部分 changed、部分 already-applied”是合法 applied round，但不是 no-op，也不能触发全局 early stop。

## 19. 运行期代理代码自愈

### 19.1 编辑与轮次边界

既有硬规则保持不变：正式定义只读，只用 `apply_patch` 修改 candidate；固定执行 `Prepare -> Inspect（推荐）-> Validate -> Promote`；task-static 故障从故障 op 起可编辑；compile/verify 代码故障只在故障轮末尾追加；V1-V4 只在 D4 末尾追加；跨轮模式仍从故障轮 ChainRounds 到 D4；code-step 故障全部 noncode。

跨文件追加修复的规则：

- 一个 op 仍只修改一个 target。
- declaration、definition、caller 需要连续追加多个 op，并为每个 target 增加精确 assertion。
- 追加 op 可选择冻结注册表中的其他目标，但不得新增目标。
- 某个 target 的问题仍属于当前故障轮，不能把修复转移到其他轮。

### 19.2 operation preview

Vx `operation-preview.json` 至少增加：

- target id、规范 path、kind、lifecycle、baseline exists/SHA-256 与 target set SHA-256；
- 前置 op 模拟中每项的 target id/path、match count 和状态；
- 目标 op 执行前后该 target 文本 SHA-256；
- pattern/replacement 解码、匹配位置、替换后剩余命中和 marker 状态。
- 对 `create-file` 记录 `exists_before`、`exists_after`、声明/实算 content SHA-256，以及 `created|already-exists|content-mismatch` 判定。

`operation-preview.txt` 和 `apply-patch-context.txt` 必须显式标注前一/当前/后一 op 的 target。Inspect 在同一个跨文件文本映射上模拟全部前置 op，不能只模拟当前文件。

### 19.3 repair manifest、Promote 与恢复门禁

任务定义 Promote 仍只替换一个 JSON 文件，但 Prepare/Validate/receipt 必须绑定 schemaVersion、target set SHA-256、id/path/kind/lifecycle 列表、Validate 时各目标 baseline exists/hash，以及 focused/full/chain 日志。

Validate 与 Promote 前重新解析 candidate target set，并与 Prepare 冻结集合比较；任何注册表漂移失败。恢复事务除既有 promoted 状态、task hash、receipt 和 validated_rounds 外，还必须核对 receipt target set 与当前正式定义一致。

ticket/brief 应携带 `operation_index`、`target_id`、`target_path` 和 `target_set_sha256`，使代理可以在不猜文件的情况下执行现有命令链。

### 19.4 代理操作提示模板

现有 `dispatch_takeover_to_chat.ps1`、`unattended_ab_takeover_trigger.ps1` 及中英文无人值守提示文档需要按 schema 条件化扩展，但不得复制一套 Vx dispatch/trigger：

- V1 票据继续输出现有提示，不增加无关多文件噪声。
- Vx code-fix 提示必须给出首错的 target id/path/kind/lifecycle、全局 operation index 和 target set SHA-256。
- 明确 operation index 是跨文件全局顺序；Inspect 必须模拟所有前置 op，而不只是同文件 op。
- 明确正式任务定义与冻结 target registry 只读，只能编辑 candidate，且只能引用已注册 target。
- `create-file` 故障提示必须说明：不得直接创建/覆盖业务文件；只能修 candidate 中的 operation；`already-exists` 仍需内容绑定、marker 与 assertions 通过。
- 跨文件 declaration/definition/caller 修复必须拆成多个单目标 op，并逐 target 添加 assertions。
- code-step 创建、提交、journal 或回滚故障仍走 noncode，不得误导代理修改源码或任务定义。
- event-review、running-status-report 和 script-diagnose-only 不注入完整 code-fix 教程，仍严格服从 route guard。

### 19.5 工单 brief 与命令格式

Vx brief 在既有字段上增加机器可解析事实：

```text
task_definition_schema_version=vx-draft
target_set_sha256=<sha256>
failure_target_id=preclass_header
failure_target_path=include/wc/preclass.h
failure_target_kind=c-header
failure_target_lifecycle=create
failure_target_baseline_exists=false
validated_artifact_manifest=<repo-relative-path>
commit_transaction_id=<id-or-empty>
commit_journal=<repo-relative-path-or-empty>
rollback_status=<not-required|complete|incomplete>
affected_targets_artifact=<repo-relative-json-path>
affected_targets_sha256=<sha256>
```

复杂多目标数组不得展开为不受限的单行 brief；写入独立 JSON artifact，并由路径和 SHA-256 绑定。failure fingerprint 应纳入 target id/path/lifecycle、target set SHA-256 和结构化失败类别。

以下外部命令名、参数主形态和顺序协议保持兼容：`route_guard_command`、`task_definition_repair_transaction.ps1`、`complete_recovery_ticket_transaction.ps1`、`complete_agent_ticket_closeout.ps1`、`next_command_order`。通常不向 repair 命令重复增加 `-TargetId`；它必须由任务定义、RoundTag 和 OperationIndex 经共享 resolver 得出，并与 brief 事实互验。命令生成与执行脚本内部新增以下门禁：

- route guard 校验 schema、target set 和当前故障 target 事实是否一致。
- Prepare/Inspect/Validate/Promote 全程绑定 target set SHA-256。
- recovery transaction 校验 promotion receipt、validated artifact/code-step receipt 的 target set。
- code-step noncode brief 携带 journal/rollback 证据；`rollback_status=incomplete` 必须硬阻断 resume/restart。
- 旧 V1 brief 字段和命令保持可读；Vx 缺少必需 target 事实时 fail-close，不从路径或日志文本猜测。

## 20. 初始编制任务定义

### 20.1 编制顺序

1. 列出本阶段可能修改的完整文件闭包，包括运行期修复可能需要的 header/source。
2. 为每个目标分配稳定 id/kind/lifecycle；禁止同一路径重复声明。同 basename 的 `.c`/`.h` 使用不同 id。
3. 每轮先编写 target-bound assertions，再设计 operations。
4. 按真实依赖排列跨文件 op，例如 declaration -> definition -> caller。
5. 每个 op 使用自身 replacement 产生的唯一 marker。
6. 删除全部 TODO，保持 `operationSafetyPolicy=enforce`。
7. JSON 语义修改使用 `apply_patch`；编码/EOL 规范化只能做不改变值、数组顺序和 operation 结构的机械处理。
8. 对 `lifecycle=create` 目标确认父目录存在，计算 create content SHA-256，并验证“初始不存在创建、初始已存在幂等跳过但内容不匹配失败”两条路径。

### 20.2 生成 start-file 前的固定验收

Vx 初始编制至少依次通过：

1. TODO-free 与 UTF-8 BOM + LF 门禁。
2. `-SyntaxOnly`：schema、目标注册表、target 引用、仓库边界和 D1-D4 基础结构。
3. 多文件专项安全回归：未知 target、重复 path、路径逃逸、跨 target marker 复用、assertion 漏 target、payload stale、提交中途失败与回滚。
4. A 不带 `-RoundTag/-OperationIndex` 的全定义严格检查。
5. B 使用 A 作为 prerequisite 的链式全定义严格检查。
6. A effective target set 的完整编译与适用黄金/Step47。
7. A+B effective target set 的完整编译与适用黄金/Step47。
8. 隔离 worktree 中的 Vx code-step、reset 和字节保真测试。
9. launch-ready 完整检查。

局部 RoundTag/OperationIndex 只用于诊断，不能作为最终验收。A/B 均通过后才允许生成 start-file。

start-file 生成前尚无事故票，可直接用 `apply_patch` 编制新正式定义；生成后进入运行期治理，正式定义只读，所有语义修改走候选事务。launcher 仍只做 SyntaxOnly，每个实际 D 轮由独立 checker 依据当时权威多文件基线生成绑定产物。

## 21. 故障分类与机器证据

- task-static 中未知 target、pattern/marker/replay/assertion/syntax 失败：`task-definition-mismatch`，可进入 code-fix。
- checker mutex、regex timeout、worker timeout、资源不足：noncode，硬阻断重启。
- code-step manifest/payload stale、I/O、权限、journal/rollback：noncode；内部状态机无结构化结果异常才是 script fault。
- compile/link/业务验证失败：继续按现有结构化证据区分 code 与 noncode。

所有失败证据应增加 target id/path；多目标失败只报告按 operation 顺序遇到的首错，不能同时猜测后续目标状态。`rollback-incomplete` 是最高优先级硬阻断，不能被普通 retry 或任务定义 Promote 清除。

## 22. 分阶段实施与退出条件

### Phase 0：协议与 fixture

- 冻结字段名、路径规则、manifest schema 和提交状态机。
- 建立最小双文件 fixture 与共享 resolver table-driven 回归。

退出条件：V1 fixture 零行为差异；Vx schema 正反例稳定。

### Phase 1：只读 checker

- 实现多文件映射、assertion、replay、ChainRounds、prerequisite union 和 Vx artifact。
- 暂不允许真实业务 code-step 消费。

退出条件：A+B effective payload 可重复生成且 hash 稳定，安全回归全通过。

### Phase 2：隔离 code-step

- 在 fixture/worktree 实现 journal、故障注入、回滚、reset 和字节保真。

退出条件：成功时全部符合 effective exists/hash，失败时全部符合 baseline exists/hash；任何存在性或内容混合状态被检测并阻断。

### Phase 3：wrapper 与自愈事务

- 接入 no-op、snapshot/B restore、preview、Validate/Promote、ticket 与 recovery receipt。

退出条件：跨文件首错能生成正确 preview，并完成同票据自愈闭环。

### Phase 4：真实无人值守试运行

- 先低密度双文件 A/B，再运行高密度任务。
- V1 保留为后续独立会话回退路径，Vx 运行中不得静默切换。

退出条件：完整 A/B、snapshot/B restore、故障注入、最终 reset 与日志 grep 契约通过。

## 23. 必测矩阵

Schema/解析：

- V1 原样通过；Vx 单目标兼容写法与显式 target 结果一致。
- 重复 id/path、未知 target、缺 default、绝对路径、`..`、目录与仓库逃逸失败。
- `targetFile` 与 `defaultTarget` 路径冲突失败。
- 相同 basename 的 `.c`/`.h` 以不同 id 和完整路径共存；Windows 路径大小写折叠后的重复项失败。
- `existing` 目标缺失失败；`create` 目标缺失允许、父目录缺失失败；未声明 create lifecycle 时禁止隐式创建。

task-static：

- 同轮跨文件 op 按全局顺序生效；focused op 模拟全部跨文件前置项。
- 任一目标首错后不检查后续 op/assertion/round。
- marker 跨 target 复用失败；target-bound assertion 精确计数；任一 target replay 变化失败。
- ChainRounds 保持同一映射；prerequisite 目标交集与并集正确叠加。
- `create-file` 对缺失目标生成预期 content；对已存在且内容一致目标返回 `already-exists` 且字节不变。
- 已存在目标的 content/hash/marker/assertion 不一致失败；create-file replay 收敛；create 后的 regex op 可按全局顺序继续修改。

artifact/code-step：

- task、任一 baseline、任一 payload、target set 或 manifest stale 均在写前阻断。
- 一个 changed + 一个 already-applied 聚合为 changed。
- 第二个文件提交失败时第一个回滚；写后 hash 失败触发整组回滚。
- create 目标提交前被外部创建时按 stale 阻断且不覆盖；本事务创建后其他目标提交失败时删除新文件。
- 未完成 journal 可恢复，不可恢复混合状态阻断；state 只在完整 receipt 后推进。

baseline/snapshot：

- BOM、CRLF/LF 与末尾换行字节保真。
- reset 不混用 baseline/HEAD；A snapshot 覆盖完整 target set；B 交集 hash 不一致失败。
- `baseline exists=false` 不产生占位文件；reset/rollback 恢复为路径不存在；A/B snapshot 正确传递 exists 状态。

自愈：

- preview 正确绑定 target；Prepare 后 target registry 漂移被 Validate 拒绝。
- task-static 故障 op 前项跨文件只读；compile/verify 可合规追加多个跨文件 op。
- receipt target set 或 validated rounds 不完整时 recovery fail-close。
- create-file preview 包含 lifecycle、exists-before/after 和声明/实算内容 hash；Vx brief 缺少 target-set/target lifecycle 事实时 fail-close。

## 24. 工作量重估

纳入当前已生效的绑定产物、自愈事务、A snapshot/B restore 和多文件提交恢复后，建议按以下范围规划：

- 共享 resolver + schema/fixture：1.0~1.5 日。
- checker 映射、assertion、artifact、prerequisite：2.0~3.0 日。
- code-step journal、rollback、baseline/reset：2.0~3.0 日。
- wrapper no-op、snapshot、B restore：1.5~2.0 日。
- repair preview/Validate/receipt/ticket：1.5~2.5 日。
- 回归、故障注入、文档与真实 A/B 缓冲：2.0~3.0 日。

总计建议：10~15 工程日。只实现“正常路径能改两个文件”虽然更快，但不满足无人值守与自愈 fail-close 契约，不应进入真实 A/B。

## 25. 开工前待决策项

1. 正式 Vx `schemaVersion` 名称。
2. `TASK_STATIC_VALIDATED_ARTIFACT_VX1` 与 code-step receipt 的最终字段。
3. payload 只保存 changed targets，还是保存全部 targets；本文建议前者，但全部目标都绑定 hash。
4. journal 崩溃恢复状态机与失败收据保留位置。
5. header 的 task-static 检查方式和完整编译入口。
6. A/B prerequisite 目标并集与 snapshot 交集门禁的实现位置。
7. target 数量、单文件大小与整轮 payload 总量上限，防止 worker 资源耗尽。
8. V1 冻结基线提交哈希及 V1/Vx 对照样例。
9. `create-file.content` 的正式编码字段是否固定为 UTF-8 无 BOM；本文示例及 `contentSha256` 暂按 UTF-8 无 BOM。若需 BOM 或二进制文件，应另增显式 encoding/content artifact 协议，禁止隐式猜测。

这些决策与 Phase 0 回归完成前，不应让 `schemaVersion=vx-draft` 进入真实无人值守 code-step。
