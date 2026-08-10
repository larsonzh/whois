# 无人值守 A/B 下次开工清单模板

> 用途：统一任一功能/优化任务在其权威 RFC/设计文档集合中起草 Checklist A / Checklist B 和执行回填的结构，不绑定具体文档名。
>
> 本文件只提供模板，不是某次运行的权威清单或执行证据。使用时应先按需求归属确定至少一份主归属文档及必要协同文档，再把下方模板复制到集合内每份文档的“下次开工清单”落点，替换全部 `<...>` 占位符，并删除不适用的说明行。
>
> 当前 Address-Space 前置分类器（IPv4/IPv6）场景通常以 `docs/RFC-address-space-preclassifier.md` 为主归属文档；涉及客户端拆分架构或整体进度时，可同时选择 `docs/RFC-whois-client-split.md`。其他任务应选择其自身领域文档，不强制使用这两个示例。
>
> 新任务定义默认使用 `schemaVersion=vx-draft`。既有 `schemaVersion=1` 任务仅在兼容重跑或既有会话修复时使用，不因套用本模板而迁移 schema。

## 使用规则

1. Checklist A 与 Checklist B 必须同时起草，但分段描述各自目标、命令、验收和回填；不得把两阶段事实合并成一个模糊结论。
2. 权威文档集合至少包含一份主归属文档；只有任务确实影响其他文档拥有的契约时才增加协同文档，不得无依据扩散回填范围。
3. 集合内各文档的窗口、串行序号、任务定义路径、schema、target set、启动文件、状态和证据路径必须一致；领域设计说明可分别补充。
4. 起草时只填写计划、门禁和编制期验收；实际运行结果只能在执行后写入“执行回填”，不得预填 PASS、运行目录、事故结论或完成时间。
5. B 仅在 A 最终 PASS、A 成功快照完整性通过且 B 启动门禁通过后启动。A 未收口时，B 保持 `blocked-by-a`。
6. Vx 清单必须列出冻结 target registry 与 `target_set_sha256`；初始起草时摘要尚未生成可写 `pending-validation`，但在生成 start-file 前必须回填真实值。V1 清单填写 `targetFile`，Vx 专属项写 `N/A (V1)`。
7. 清单草案、正式任务定义和 start-file 三类产物须一并交用户确认；未获得明确启动授权时，状态保持“准备完成，待启动授权”。
8. 所有 `<...>` 占位符必须在生成 start-file 前清零。没有内容的可选段写明 `N/A`，不得保留猜测性事实。

## 可复制模板

````markdown
### 下次开工清单（无人值守 A/B，<WINDOW_START> ~ <WINDOW_END>，草案，串行第 <A_SEQUENCE>/<B_SEQUENCE> 份）

#### 共享身份与串行约束

| 字段 | 值 |
|---|---|
| 清单状态 | 草案 / 准备完成，待启动授权 / 运行中 / 已完成待回填 / 已回填 |
| 运行窗口 | `<WINDOW_START> ~ <WINDOW_END>` |
| 运行模式 | `<MODE，例如 code-change / gate-only>` |
| 质量策略 | `<QUALITY_POLICY，例如 strict-enforce>` |
| Checklist A 任务定义 | `testdata/<A_TASK_DEFINITION>.json` |
| Checklist B 任务定义 | `testdata/<B_TASK_DEFINITION>.json` |
| active start-file | `testdata/unattended_start/active/<START_FILE>.md` |
| A schema | `<vx-draft 或 1>` |
| B schema | `<vx-draft 或 1>` |
| A target set SHA-256 | `<SHA256 / pending-validation / N/A (V1)>` |
| B target set SHA-256 | `<SHA256 / pending-validation / N/A (V1)>` |
| 主归属文档 | `<docs/...md>` |
| 协同文档 | `<docs/...md / N/A>` |
| 用户启动授权 | `<pending / 已授权，时间>` |

**权威文档落点（按实际数量增删行）**

| 角色 | 文档路径 | 章节号或稳定标题 | 纳入原因 |
|---|---|---|---|
| 主归属 | `<docs/PRIMARY_RFC_OR_DESIGN.md>` | `<ANCHOR>` | `<直接拥有的需求/契约/设计>` |
| 协同 | `<docs/RELATED_RFC_OR_DESIGN.md / N/A>` | `<ANCHOR / N/A>` | `<跨架构或跨模块影响 / N/A>` |

- [ ] A/B 严格串行，不并发运行。
- [ ] B 仅在 A 最终 PASS、A 成功快照完整性通过且 B 启动门禁通过后启动。
- [ ] A FAIL、BLOCKED、快照缺失或快照不一致时，B 保持 `blocked-by-a`。
- [ ] 启动前不执行 `git commit`、`git push`，也不预填运行结果。
- [ ] 权威文档集合已按需求归属冻结，且集合内各落点的共享身份字段与证据路径已逐项核对一致。

#### Checklist A：<A_SHORT_TITLE>

**目标与边界**

- 目标：<A_GOAL>
- 非目标：<A_NON_GOALS>
- 设计依据：<A_RFC_SECTION_OR_REQUIREMENTS>
- 任务定义：`testdata/<A_TASK_DEFINITION>.json`
- schema：`<vx-draft 或 1>`
- 轮次范围：`D1-D4 + V1-V4`
- 前置条件：<A_PREREQUISITES>
- 完成后交付给 B：A 成功快照、final result、运行目录与绑定证据。

**目标注册表**

Vx 按下表列出完整冻结闭包；V1 删除该表并填写 `targetFile: <PATH>`。

| target id | file | kind | lifecycle | 计划涉及轮次 |
|---|---|---|---|---|
| `<A_TARGET_ID>` | `<REPO_RELATIVE_PATH>` | `<c-source / c-header / text>` | `<existing / create>` | `<D1...D4>` |

- `defaultTarget`: `<A_DEFAULT_TARGET / N/A (V1)>`
- `target_set_sha256`: `<A_TARGET_SET_SHA256 / pending-validation / N/A (V1)>`

**推荐命令**

```powershell
# SyntaxOnly 装载检查
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/<A_TASK_DEFINITION>.json -Policy enforce -SyntaxOnly

# A 编制期全定义严格检查
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/<A_TASK_DEFINITION>.json -Policy enforce -FailOnWarnings

# <A 适用的完整编译、黄金、Step47 或专项回归命令>
<A_VALIDATION_COMMANDS>

# <经用户授权后使用的 A 启动命令；优先引用 start-file 中的权威命令>
<A_START_COMMAND>
```

**预期验证范围**

- [ ] D1-D4 各轮目标、operation 顺序、marker 与 assertions 已明确。
- [ ] V1-V4 的编译、黄金、Step47 或业务验证范围已明确。
- [ ] TODO-free、`operationSafetyPolicy=enforce`、完整编译及适用专项回归通过。
- [ ] 预期 stdout/stderr 契约与禁止变更项已记录：<A_OUTPUT_CONTRACT>。
- [ ] A PASS 后生成并验证覆盖完整 A target set 的成功快照。

**编制期验收证据（生成 start-file 前填写）**

| 门禁 | 状态 | 证据或摘要 |
|---|---|---|
| TODO-free / 编码 | `<PASS/FAIL>` | `<COMMAND_OR_ARTIFACT>` |
| SyntaxOnly | `<PASS/FAIL>` | `<COMMAND_OR_ARTIFACT>` |
| A 全定义静态检查 | `<PASS/FAIL>` | `<COMMAND_OR_ARTIFACT>` |
| Vx 专项安全回归 | `<PASS/FAIL/N/A (V1)>` | `<COMMAND_OR_ARTIFACT>` |
| 完整编译 | `<PASS/FAIL>` | `<COMMAND_OR_ARTIFACT>` |
| 黄金 / Step47 | `<PASS/FAIL/N/A>` | `<COMMAND_OR_ARTIFACT>` |
| launch-ready | `<PASS/FAIL/PENDING>` | `<COMMAND_OR_ARTIFACT>` |

#### Checklist B：<B_SHORT_TITLE>

> 硬门禁：仅在 Checklist A 最终 PASS、A 成功快照完整性通过且 B 启动门禁通过后启动；否则保持 `blocked-by-a`。

**目标与边界**

- 目标：<B_GOAL>
- 非目标：<B_NON_GOALS>
- 设计依据：<B_RFC_SECTION_OR_REQUIREMENTS>
- 任务定义：`testdata/<B_TASK_DEFINITION>.json`
- schema：`<vx-draft 或 1>`
- 轮次范围：`D1-D4 + V1-V4`
- 设计期前置：Checklist A 全定义有效结果。
- 运行期前置：Checklist A 成功快照及其完整性门禁。

**目标注册表**

Vx 按下表列出完整冻结闭包；V1 删除该表并填写 `targetFile: <PATH>`。

| target id | file | kind | lifecycle | 计划涉及轮次 |
|---|---|---|---|---|
| `<B_TARGET_ID>` | `<REPO_RELATIVE_PATH>` | `<c-source / c-header / text>` | `<existing / create>` | `<D1...D4>` |

- `defaultTarget`: `<B_DEFAULT_TARGET / N/A (V1)>`
- `target_set_sha256`: `<B_TARGET_SET_SHA256 / pending-validation / N/A (V1)>`
- 与 A 的 target set 关系：<相同 / 相交 / 并集说明>。

**推荐命令**

```powershell
# SyntaxOnly 装载检查
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/<B_TASK_DEFINITION>.json -Policy enforce -SyntaxOnly

# B 以 A 为 prerequisite 的编制期链式全定义检查
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/check_task_definition_static.ps1 -TaskDefinitionFile testdata/<B_TASK_DEFINITION>.json -PrerequisiteTaskDefinitionFiles testdata/<A_TASK_DEFINITION>.json -Policy enforce -FailOnWarnings

# <A+B effective target set 的完整编译、黄金、Step47 或专项回归命令>
<B_VALIDATION_COMMANDS>

# <经用户授权且 A PASS 后使用的 B 启动命令；优先引用 start-file 中的权威命令>
<B_START_COMMAND>
```

**预期验证范围**

- [ ] D1-D4 各轮目标、operation 顺序、marker 与 assertions 已明确。
- [ ] V1-V4 的编译、黄金、Step47 或业务验证范围已明确。
- [ ] B 使用 A 作为 prerequisite 的链式全定义检查通过。
- [ ] A+B effective target set 的完整编译及适用专项回归通过。
- [ ] B 启动前重新核对 A snapshot、target set 交集与 B baseline。
- [ ] 预期 stdout/stderr 契约与禁止变更项已记录：<B_OUTPUT_CONTRACT>。

**编制期验收证据（生成 start-file 前填写）**

| 门禁 | 状态 | 证据或摘要 |
|---|---|---|
| TODO-free / 编码 | `<PASS/FAIL>` | `<COMMAND_OR_ARTIFACT>` |
| SyntaxOnly | `<PASS/FAIL>` | `<COMMAND_OR_ARTIFACT>` |
| B 使用 A prerequisite 的链式全定义检查 | `<PASS/FAIL>` | `<COMMAND_OR_ARTIFACT>` |
| Vx 专项安全回归 | `<PASS/FAIL/N/A (V1)>` | `<COMMAND_OR_ARTIFACT>` |
| A+B effective target set 完整编译 | `<PASS/FAIL>` | `<COMMAND_OR_ARTIFACT>` |
| 黄金 / Step47 | `<PASS/FAIL/N/A>` | `<COMMAND_OR_ARTIFACT>` |
| launch-ready | `<PASS/FAIL/PENDING>` | `<COMMAND_OR_ARTIFACT>` |

#### 启动前联合确认

- [ ] 两份任务定义均已通过初始编制完整验收，且没有残留占位符或 TODO。
- [ ] active start-file 已生成并通过字段同步、编码和 launch-ready 检查。
- [ ] 权威文档集合内每份文档均已包含本组 Checklist A/B，身份字段和证据一致。
- [ ] 用户已检查任务定义、权威文档集合中的清单和 start-file。
- [ ] 当前状态为“准备完成，待启动授权”；未获得明确授权前不启动 A。

#### 执行回填（运行后填写，起草时不得预填 PASS）

**Checklist A 回填**

| 字段 | 实际值 |
|---|---|
| final status | `<PASS/FAIL/BLOCKED>` |
| started_at / completed_at / elapsed | `<TIMESTAMPS>` |
| run_dir | `<A_RUN_DIR>` |
| final result / summary | `<A_RESULT_PATHS>` |
| task-static / code-step artifact | `<A_ARTIFACT_PATHS>` |
| snapshot manifest / target set SHA-256 | `<A_SNAPSHOT_EVIDENCE>` |
| 事故、自愈、重启摘要 | `<NONE 或结构化摘要与 ticket 路径>` |
| RFC 回填日期 | `<YYYY-MM-DD>` |

**Checklist B 回填**

| 字段 | 实际值 |
|---|---|
| A PASS 与 snapshot 门禁 | `<PASS/FAIL + EVIDENCE>` |
| final status | `<PASS/FAIL/BLOCKED>` |
| started_at / completed_at / elapsed | `<TIMESTAMPS>` |
| run_dir | `<B_RUN_DIR>` |
| final result / summary | `<B_RESULT_PATHS>` |
| task-static / code-step artifact | `<B_ARTIFACT_PATHS>` |
| 事故、自愈、重启摘要 | `<NONE 或结构化摘要与 ticket 路径>` |
| RFC 回填日期 | `<YYYY-MM-DD>` |

**最终收口**

- A/B 总结：<FINAL_SUMMARY>。
- 未完成项与后续动作：<FOLLOW_UP_OR_NONE>。
- 权威文档集合内各落点的回填内容已核对一致：`<YES/NO>`。
- 未经用户明确授权，不执行提交或推送。
````

## 起草完成判定

只有同时满足以下条件，才可从阶段 3 进入 start-file 生成阶段：

- 至少一份主归属文档已登记；所有已选主归属/协同文档均已有 Checklist A / Checklist B 的明确落点。
- 模板中的全部占位符已替换或以 `N/A` 明确关闭。
- A/B 身份、schema、目标闭包、串行门禁、命令和预期验证均可独立执行与核对。
- 编制期证据与运行期回填区域已分离，没有预填运行 PASS。
- 权威文档集合内各落点的共享字段逐项一致。
