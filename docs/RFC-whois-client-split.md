# whois_client 拆分主线备忘（Refactor / Split Roadmap）

> 目的：
> - 记录 `whois_client.c` 拆分主线的设计思路、阶段计划与每日进度，避免仅依赖 IDE / 聊天上下文；
> - 明确“已完成的历史拆分”和“后续阶段待做事项”，便于长期维护和断点续作；
> - 保证在任何时刻，都能回答：当前 master 上 `whois_client.c` 的形态与目标状态之间还差多少。

**当前状态（截至 2025-11-20）**：
- DNS 相关工作已在 v3.2.9 收尾，并以 `docs/RFC-dns-phase2.md` / `docs/RFC-dns-phase4-ip-health.md` 为主进行记录；
- v3.2.9 被视为 DNS 行为与调试可观测性的“黄金基线”；
- 接下来主线重点转回 `whois_client.c` 本体拆分与核心逻辑整理。

---

## 1. 背景与目标

### 1.1 现状简述

- `src/whois_client.c` 目前仍然承担了过多职责，包括但不限于：
  - CLI 解析与配置初始化（部分已在 `wc_opts` 中，但仍有 glue 和默认值逻辑停留在 client 层）；
  - 主控流程：查询循环、批量/单次模式判断、stdin/argv 路径分发；
  - pipeline glue：与 `wc_title` / `wc_grep` / `wc_fold` / `wc_output` / `wc_seclog` 等模块的粘合逻辑；
  - DNS / lookup / 重试策略的接口层（与 `wc_dns`、`lookup.c`、`wc_net` 交互）；
  - 日志与调试开关的一部分（例如 debug/metrics/security-log 相关的入口打印）；
  - 信号处理与进程级资源清理（`signal_handler`、`atexit` glue 等）。
- 随着 DNS Phase 2/3、条件输出引擎等陆续下沉到 `src/core/`、`src/cond/`，`whois_client.c` 越来越像一个“时间线长、上下文密集”的大杂烩文件，阅读和修改成本持续走高。

### 1.2 拆分后的目标状态（理想图）

- `whois_client.c` 收敛为一个**薄 CLI 壳层**：
  - 主要负责：
    - 命令行参数解析入口（调用 `wc_opts_parse_*`）；
    - 进程级初始化与资源注册（日志、signal/atexit 等）；
    - 简单的“查询循环”调度（将每个 query 委托给下沉后的 core/pipeline 层处理）；
  - 不再直接承载：
    - 复杂的 pipeline 细节（条件输出、grep/fold 等）；
    - DNS 行为细节和重试策略；
    - 具体的 socket/文件描述符操作（由更低层模块封装）。
- 相关逻辑按职责拆到：
  - `src/core/`：
    - `pipeline.c`：查询生命周期与输出 pipeline 的编排；
    - 其他 core 模块：与网络、DNS、重定向、安全日志的“接口级” glue；
  - `src/cond/`：条件输出相关模块（title/grep/fold/output/seclog），保持已有形态或逐步简化接口；
- 从阅读体验上，希望做到：
  - 看完 `whois_client.c` + 一两个 core 文件，就能快速理解“用户输入 → 查询执行 → 输出”的主路径，不必在 client 文件里翻找所有细节。

---

## 2. 既往拆分工作回顾（约 4 批次）

> 注：这里以“功能大块”为维度做归纳，具体 commit/PR 可通过 git log 追溯。数字 4 为近似记忆，主要代表“多次体系性拆分”，而非精确批次数。

### 2.1 条件输出引擎下沉（wc_title / wc_grep / wc_fold / wc_output / wc_seclog）

- 目的：
  - 将原本散落在 `whois_client.c` 中的“标题投影 + 正则筛查 + 折叠输出 + 安全日志”逻辑集中封装，形成可独立演进的条件输出引擎。
- 主要动作：
  - 提取与 `-g/--title`、`--grep*`、`--fold*`、`--security-log` 相关的处理代码，迁移到 `src/cond/` 下对应模块；
  - 新增 `src/core/pipeline.c` 作为输出 pipeline 的编排入口；
  - `whois_client.c` 保留“准备好 query + raw whois 响应”后调用 pipeline 的简单 glue。
- 当前效果：
  - 条件输出逻辑基本已从 client 层抽离，便于独立维护；
  - client 文件仍然保留部分与 pipeline 强耦合的 helper（例如某些结构体填充、错误路径处理），后续拆分可进一步清理这些 glue。

### 2.2 DNS 与 lookup glue 的分离（wc_dns + lookup.c）

- 目的：
  - 把 DNS 候选生成、缓存与 fallback 策略从 client 中下沉，形成 `wc_dns` 和 `lookup.c` 的清晰分工；
- 主要动作：
  - 引入 `wc_dns` 模块，统一 IP 字面量检测、RIR canonical host 映射、`getaddrinfo` 策略以及 IPv4/IPv6 交错排序；
  - `lookup.c` 内负责遍历 DNS 候选并执行 connect，承接重试与 fallback，再通过 `wc_net` 输出现有的 retry metrics；
  - `whois_client.c` 缩减为：配置 DNS 相关选项、调用 lookup 执行查询、处理返回值。
- 当前效果：
  - DNS/lookup 行为基本从 client 拆出；
  - signal/重试/metrics 的 glue 仍在 client 中，后续可以考虑集中封装在 `wc_net` 或新的 core 模块中。

### 2.3 重试节奏与环境变量剥离（CLI-only pacing）

- 目的：
  - 把原先依赖 `WHOIS_*` 环境变量的重试/节流配置统一迁移到 CLI 层，使行为更可预测、日志更易解释。
- 主要动作：
  - 在 `wc_opts` 中新增重试与 pacing 相关选项解析（`--pacing-*`、`--retry-metrics` 等）；
  - 清理 `whois_client.c` 与 net 层中对 `getenv/setenv/putenv` 的直接调用；
  - 保证所有 pacing/metrics 逻辑都通过 CLI 和配置结构体驱动。
- 当前效果：
  - `whois_client.c` 在节流与重试配置上已经瘦身不少；
  - 仍有部分“配置默认值 + 参数验证”逻辑存留在 client 层，可以在后续拆分中迁移到 `wc_opts` 或专用 config 模块。

### 2.4 安全与自测钩子的模块化

- 目的：
  - 将安全日志、自测（grep/selftest/dns-selftest 等）相关逻辑封装成可控入口，避免 `whois_client.c` 直接充斥各种编译开关判断。
- 主要动作：
  - 将安全日志输出移至 `wc_seclog`，`whois_client.c` 仅保留开关控制与初始化调用；
  - 把部分自测路径（如 GREP、自测 lookup）拆到 `src/core/selftest_*.c`，由 client 通过 CLI 开关触发；
- 当前效果：
  - client 文件中与 `#ifdef ..._TEST` 相关的噪声有所减少；
  - 仍有一定数量的自测入口及 debug 日志控制停留在 client 层，需要在后续阶段统一归档。

> 小结：
> - 以上 4 大方向的拆分让 `whois_client.c` 不再直接承担所有职责，但文件依然偏大、上下文交叉密集；
> - 后续工作应在“保持行为与 v3.2.9 golden 基线一致”的前提下，继续把 glue/控制流理顺，并逐步下沉到更合适的 core 模块中。

---

## 3. 接下来要开始的拆分阶段（Phase 1）

> 目标：在 **不改变行为** 的前提下，对 `whois_client.c` 做一次“结构梳理 + 职责边界拉直”，为后续更细粒度拆分打基础。

### 3.1 Phase 1 范围（仅结构调整，不改策略）

1. **主控流程梳理**：
   - 在 `whois_client.c` 中明确划分：
     - 进程级启动/清理（main、init、signal/atexit 注册）；
     - 单次查询处理（"do_one_query" 之类的 helper）；
     - 批量模式控制（stdin / `-B` vs argv 列表）。
   - 如有必要，为这些部分提取静态函数，使主控路径更易阅读。

2. **配置与状态收拢**：
   - 核对 `g_config` / 其他全局或静态状态的散落使用点：
     - 能下沉到 `wc_opts` / core 模块的尽量下沉；
     - client 层只保留必须的高层视角（例如“是否开启 debug/metrics/security-log”）的读取；
   - 尝试把“配置默认值填充 + 校验”集中放在一个初始化函数中，而不是分散在流程各处。

3. **日志入口归一化**：
   - 梳理 `log_message` / `log_security_event` 等在 client 内的直接调用：
     - 统一入口形式（例如所有启动/结束消息放在一起）；
     - 减少在深层逻辑中直接打印的情况，鼓励下沉到更合适模块。

4. **信号与退出路径整理**：
   - 现有 `signal_handler` 与 cleanup 逻辑已经为 DNS/metrics 做了一些 glue；
   - Phase 1 重点是：确认所有退出路径（正常结束、信号终止、错误短路）都能妥善调用 pipeline/net/DNS 的清理钩子；
   - 适当提取一个“统一退出入口”，避免到处 `exit()`。

### 3.2 Phase 1 执行顺序（建议）

1. **加注释 + 逻辑分段而不搬文件**：
   - 先在 `whois_client.c` 中通过注释和局部重排，把主流程划出清晰的“章节”；
   - 暂不新增 core 文件，确保 diff 尽可能易读。

2. **提取 helper 函数**：
   - 对于明显独立的块（例如“单条 query 处理”“批量模式循环”），提取为静态函数；
   - 保证函数签名只用已有类型/结构，不额外引入新抽象。

3. **梳理配置与状态传递**：
   - 对 `g_config` / 其他全局的读写进行集中梳理，必要时通过参数传递方式替代直接访问；
   - 这一阶段可以先做“readonly 下沉”（只读访问通过参数传递），写操作仍暂留在 client 层。

4. **记录每日进度与风险**：
   - 每完成一小块（例如“主流程重排完成”“批量模式 helper 提取完成”），在本 RFC 中对应章节追加简短笔记：
     - 变更范围；
     - 与 v3.2.9 golden 行为的对比结论（预期等价 / 有意微调）；
     - 如有必要，记录需要特别关注的回归点（如某些自测或脚本）。

---

## 4. 风险与回滚策略

- **风险 1：不慎引入行为差异**
  - 尤其是与信号处理、批量模式、错误路径（非 0 退出码）相关；
  - 缓解：
    - 拆分期间频繁对照 golden 样例与远程冒烟日志（特别是 `[RETRY-*]` 与 DNS 相关标签）；
    - 尽量保持“函数内逻辑不改，只是搬运/封装”的粒度。

- **风险 2：拆分粒度过细导致阅读成本反而上升**
  - 如果过早拆成太多小文件/小模块，会让导航成本上升；
  - 缓解：
    - Phase 1 只在 `whois_client.c` 内做结构化与局部提取，不急于新建大量文件；
    - Phase 2 再根据需要将已经形成的 helper/子模块下沉到 `src/core/`。

- **风险 3：与并行工作冲突**
  - 大规模重排文件容易与其他功能修改产生 merge 冲突；
  - 缓解：
    - 在开始较大改动前，尽量让 DNS / 文档 / release 相关工作进入稳定状态（当前已完成 v3.2.9 发布，有利于这一点）；
    - 优先完成结构性重排，然后在新结构上迭代功能。

---

## 5. 状态与 TODO 草稿（待补）

> 此节用于后续记录具体拆分进度。当前仅给出占位结构，后续在每次会话/提交后补充简要条目。

- **2025-11-20**（起点）
  - v3.2.9 已发布，DNS Phase 2/3 收尾，DNS 相关 RFC/备忘已整理完毕；
  - 新增本文件 `docs/RFC-whois-client-split.md`，作为 `whois_client.c` 拆分主线的备忘录；
  - 拆分 Phase 1 尚未正式动手，处于“规划与范围界定”阶段。

- **后续每日可追加示例（格式建议）**：
  - `2025-11-2X`：重排 main/初始化路径，提取 `run_single_query()` / `run_batch_mode()` helper，行为对照 v3.2.9 一致；
  - `2025-11-2Y`：收拢 `g_config` 只读访问，query 执行路径改为通过 context 结构传参；
  - ...

---

> 后续如需细化 Phase 2/3（例如真正把 pipeline glue、net/DNS glue 下沉到 `src/core/`）或增加新的自测矩阵，可在本文件后续章节中继续扩展，保持“背景 → 目标 → 改动 → 风险 → 进度”这一结构统一。
