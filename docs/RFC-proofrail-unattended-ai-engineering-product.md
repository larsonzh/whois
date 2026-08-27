# RFC：ProofRail（证轨）—— AI 无人值守工程通用产品抽取方案

> 状态：提案（Proposal）。本文将 whois 项目中沉淀的 AI 无人值守工程最佳实践与应用经验，
> 规划为一个独立的通用产品项目，并给出命名、定位、架构与实施路线建议。
>
> 来源：基于对本仓库 `tools/test/`（约 125 个无人值守脚本）、`testdata/`（V1/Vx 任务定义体系）
> 与 `docs/`（RFC 与操作流程文档）的实战资产盘点。

## 0. 项目命名

### 0.1 正式名称（推荐）

**ProofRail**（紧凑标识：**PrfRail**；工程名称：`prfrail`；中文名：**证轨**）

- 标语（Tagline）：*Provable rails for unattended AI engineering* —— 为 AI 无人值守编程铺设可证明的轨道。
- 命名解读：
  - **Proof（证明）**：直指本体系最核心的差异化能力——哈希绑定产物、幂等 marker、
    精确断言、promotion receipt 构成的"可证明写入"模型。AI 的每一次代码变更都有
    机器可验证的证据链，而非"跑完即信"。
  - **Rail（轨道/护栏）**：双关语义。既是 *guardrail*（护栏）——编辑边界矩阵、停机门禁、
    fail-close 状态机对 AI 权限的最小化约束；也是 *rail*（轨道）——first-fail-stop 的
    顺序执行语义让 AI 只能沿预定义轨道推进，不能自由发挥。
  - 正式名称完整表达产品定位；工程名称短小，适合作为仓库名、CLI、包名和模块前缀。
  - 中文名"证轨"两字对应 Proof/Rail，紧凑且技术气质鲜明。

### 0.2 名称分层与使用规范

采用 **ProofRail / PrfRail / `prfrail`** 的三级命名组合：

| 使用场景 | 写法 | 说明 |
|----------|------|------|
| 正式品牌、标题、对外文档 | **ProofRail** | 保留 Proof + Rail 的完整语义与品牌辨识度 |
| 紧凑视觉标识、空间受限界面 | **PrfRail** | 由 ProofRail 压缩而来，不将 `PR` 突出为独立缩写 |
| 仓库、CLI、可执行文件、包名和模块前缀 | `prfrail` | 全小写、无连字符，便于跨平台使用与检索 |
| 中文文档与传播 | **证轨** | 对应“证明/证据链 + 轨道/护栏” |

推荐示例：

```text
正式名称：ProofRail
紧凑标识：PrfRail
仓库名称：prfrail
CLI：prfrail
Go 模块：github.com/<org>/prfrail
中文名称：证轨
```

CLI 命令示例：

```bash
prfrail check
prfrail apply
prfrail verify
prfrail guard
prfrail inspect
prfrail promote
```

不建议将 **PRail** 作为正式名称或主要简称：在软件工程语境中，`PR` 通常首先被理解为
*Pull Request*，容易让产品被误认为仅面向 PR 检查或 PR 流水线。`PrfRail` 保留了
Proof 的来源提示，同时通过工程名称 `prfrail` 降低重名与语义歧义风险。

命名一致性规则：

1. README、RFC、官网和发布说明首次出现时使用 **ProofRail**。
2. 紧凑界面可使用 **PrfRail**，但首次出现时应注明其为 ProofRail 的紧凑标识。
3. 代码、命令、目录、制品和配置键统一使用小写 `prfrail`，避免混用 `prail`、`proofrail`
   或不同大小写变体。
4. 名称可用性会随时间变化；正式创建独立项目或商业发布前，应再次检查 GitHub、域名、
   语言包注册表及目标市场商标。

### 0.3 备选名称

| 备选 | 解读 | 未选为首选的原因 |
|------|------|------------------|
| **Veritask**（真验任务） | veritas（真理）+ task，强调任务执行的可验证性 | 侧重"任务"层，未覆盖护栏/边界语义 |
| **AegisPilot**（神盾领航） | Aegis（宙斯之盾）+ Pilot（领航/autopilot） | "Pilot" 在 AI 编码领域已被高度占用（Copilot 等），易混淆 |
| **SentinelForge**（哨兵工坊） | 哨兵（guard/watchdog）+ 锻造（代码变更） | 偏向监控语义，弱化了"可证明"这一核心卖点 |
| **FailClose** | 直接取自体系的核心安全原则 | 作为原则名极佳，但作为产品名偏负面 |

### 0.4 子模块命名建议

沿用铁路隐喻，并统一使用 `prfrail` 工程前缀：

- `prfrail-switch`（taskdef）：任务定义 schema 与静态 checker——"道岔"决定轨道走向。
- `prfrail-track`（applier）：原子执行引擎——列车只能沿轨道行驶。
- `prfrail-signal`（tickets）：票据生命周期与状态机——"信号灯"控制放行与阻断。
- `prfrail-guard`（guard）：进程监控与停机门禁。
- `prfrail-depot`（repair）：Prepare/Inspect/Validate/Promote 候选事务——"检修库"。
- `prfrail-gates`（gates）：可插拔验证门禁。

## 1. 总体结论：可行，且价值明确

whois 项目中的无人值守工程已经沉淀了一套完整、经过实战验证的体系，其核心思想与
whois 业务本身高度解耦，具备抽取为通用产品的条件。它解决的是一个通用问题：
**如何让 AI 代理在无人值守条件下安全、可审计、可恢复地执行代码变更任务**。
目前市面上的 AI 编码代理普遍缺乏这一层"工程化护栏"，这正是 ProofRail 的差异化定位。

## 2. 可抽取的核心资产盘点

从仓库现状看，与 whois 业务无关、可通用化的资产包括：

1. **任务定义 Schema 与静态检查体系**
   - V1 单文件 / Vx 多文件任务定义模型（target registry、稳定 target id、lifecycle、
     operation 全局排序）。
   - 独立 checker 的顺序内存文本语义、first-fail-stop、幂等 marker、pattern 收敛、
     replay 稳定性、精确 postApplyAssertions。
   - 哈希绑定产物（manifest/payload/target_set_sha256）。

2. **原子执行引擎（code-step）**
   - "读 → 全量预验证 → journal → 逐文件原子写入 → 写后验证 → 失败整组回滚"的事务模型。
   - journal/receipt/state 协议（可恢复提交）。

3. **票据驱动的故障处理与自愈框架**
   - guard/trigger/dispatch 的事件产票、结构化 category（task-static / code-fix / noncode）、
     fail-close 门禁。
   - 相同指纹预算三段状态机（pending_review → override_window → hard_block）、
     有效修复证据判定、防无限循环保护。
   - Prepare → Inspect → Validate → Promote 的隔离候选事务（candidate + 哈希绑定 +
     原子提升 + promotion receipt）。

4. **权限与边界模型**
   - 停机后才允许故障动作、只读状态票、跨轮次修改边界矩阵、轮次归属不可转移、
     编辑工具白名单/黑名单。
   - 自愈开关（self-heal enabled、cross-round repair enabled）与人工解锁规则。

5. **运行编排与可观测性**
   - stage window / supervisor / companion / session guard / watchdog 的进程编排。
   - 工单轮询 V2 的生命周期状态机、账本持久化、重启屏障、drain/recovery-drain。
   - start-file 身份绑定、快照完整性校验、心跳与健康检查。

6. **方法论文档**
   - 操作流程、授权边界（用户确认门禁）、任务切片设计与合并原则、低成本模型操作
     清单——这些是产品"最佳实践手册"的雏形。

## 3. 需要剥离的 whois 耦合点

- D1–D4/V1–V4 轮次语义中与 whois 编译/黄金/Step47 验证绑定的部分 → 抽象为可插拔的
  "验证阶段"接口，由使用方注入自己的构建/测试命令。
- C 语法门禁、`src/core/.task-static-*.c` 等语言特定检查 → 抽象为按语言可扩展的
  syntax gate 插件。
- VS Code 聊天投递（IPC chat sender、AHK 发送等）→ 抽象为"代理通道适配器"，
  支持不同 AI 代理接入方式（IDE 扩展、CLI 代理、API）。
- Windows/PowerShell 强绑定 → 见语言选择。

## 4. 语言与技术选型建议

当前实现以 PowerShell 5.1 为主，存在跨平台、可测试性、类型安全的天花板。建议：

- **核心引擎：Go**。理由：单二进制分发（与 whois 项目自身的 BusyBox 兼容哲学一致）、
  跨平台（Windows/Linux/macOS）、强并发原语适合进程编排与 watchdog、标准库覆盖文件
  原子操作与哈希、生态中已有成熟的正则/JSON Schema 工具。Rust 也可行，但 Go 的开发
  迭代速度更适合这个以流程编排为主的领域。
- **任务定义格式：保留 JSON（JSON Schema 正式化）**，同时评估提供 YAML/TOML 前端以
  改善人工可读性，内部统一规范化为 canonical JSON 后再做哈希绑定。
- **代理接口：定义协议而非绑定实现**。以本地文件队列 + 结构化 JSON 票据为基础协议
  （继承现有账本模型），提供 MCP server、CLI、HTTP 三种适配器，使任何 AI 代理
  （Copilot、Claude、本地模型）都能接入。
- **保留 PowerShell 兼容层（过渡期）**：为现有 whois 流程提供薄封装，使 whois 成为
  ProofRail 的第一个 dogfooding 用户，验证等价性后逐步切换。

## 5. 产品形态与模块划分

建议建立名为 `prfrail` 的独立仓库，模块划分（括号内为 0.4 节的品牌化命名）：

1. `taskdef`（switch）：任务定义 schema、解析、target registry、静态 checker。
2. `applier`（track）：原子执行引擎（journal、原子写、回滚、receipt）。
3. `tickets`（signal）：票据生命周期、账本、去重、状态机、指纹预算。
4. `guard`（guard）：进程监控、健康检查、停机门禁、watchdog。
5. `repair`（depot）：Prepare/Inspect/Validate/Promote 候选事务。
6. `gates`（gates）：可插拔验证门禁（syntax gate、构建、测试、黄金对比）。
7. `adapters`：代理通道（MCP/CLI/HTTP）与 IDE 集成。
8. `docs`：最佳实践手册（从现有中文 RFC 提炼，中英双语）。

## 6. 实施路线（分四个阶段）

1. **阶段一：规范固化**。将现有硬规则从 copilot-instructions 与各 RFC 中提炼为形式化
   规范文档（票据协议、任务定义 schema、编辑边界矩阵、事务状态机），补齐英文版。
   这一步不写代码，产出即有独立价值。
2. **阶段二：核心引擎重写**。用 Go 实现 taskdef checker 与 applier，以现有 PowerShell
   实现为参照做双跑等价性验证（同一任务定义、同一源码，比对 manifest 哈希与写入结果）。
   现有的 regression 脚本群可转化为新引擎的验收测试集。
3. **阶段三：编排与票据层迁移**。实现 guard/tickets/repair 模块，在 whois 仓库中并行
   试运行（影子模式：新引擎观察、旧引擎执行），确认票据判定一致后切换。
4. **阶段四：通用化与开放**。剥离最后的 whois 特定假设，提供示例项目（不同语言的
   目标仓库）、MCP 适配器与文档站，作为独立开源产品发布。

## 7. 关键风险与对策

- **规则复杂度过高吓退新用户**：现有体系为 whois 场景全量启用；产品化时应设计
  "分级模式"（基础原子应用 → 加票据自愈 → 加全套门禁），默认最小化配置。
- **双实现漂移**：阶段二/三必须以等价性测试为门禁，任何语义差异 fail-close，
  禁止"差不多就行"。
- **中文文档的国际化成本**：核心规范优先英文化，操作经验类文档可后置。
- **代理生态变化快**：把代理接口做成薄协议层，核心引擎不感知具体代理，降低生态
  变动冲击。
- **whois 自身演进冲突**：抽取期间 whois 的 Vx schema 处于冻结/慢改状态是有利窗口；
  建议在抽取仓库建立后，whois 侧新增无人值守能力一律先在 ProofRail 中实现再回灌。

## 8. 最有价值的独特卖点（产品定位参考）

- 首错即停 + 哈希绑定产物 + 原子提交回滚的"可证明写入"模型。
- 相同指纹预算与有效修复证据判定的"防 AI 无限循环"机制。
- 编辑边界矩阵与停机门禁的"AI 权限最小化"模型。
- 隔离候选事务（candidate 不污染正式定义）的自愈安全模型。

这四点在现有 AI 编码工具生态中均属稀缺，是 ProofRail 的核心竞争力所在，
也是"Proof + Rail"命名所直接指向的产品灵魂。
