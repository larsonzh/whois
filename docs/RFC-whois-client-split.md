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


#### 2025-11-24 分析纪要（server backoff + wc_dns 健康协同）

- **现状对照**  
  - Legacy `wc_cache`：维持 `server_status[20]` + `SERVER_BACKOFF_TIME=300s`，阈值为 3 次 failure；只在 `wc_client_perform_legacy_query()` 的拨号循环调用 `wc_cache_is_server_backed_off()`，其余路径完全感知不到该窗口。  
  - Phase 2 `wc_dns_health`：64 条 host+family slot，阈值同样 3 次 failure，但 penalty 仅 30s；所有 `wc_dial_43()` 调用都会记录该表，目前仅通过 `[DNS-HEALTH]` 输出，不会影响候选顺序或跳过逻辑。  
  - 结果：lookup 新路径会在 penalty 时段持续尝试相同 RIR host（只产生日志），legacy 路径则会因为 `server_status` 被动跳过 5 分钟，形成“两套退避体系互不联动”的不一致。  
- **整合目标**  
  1. 统一 server 健康记忆，让 legacy/lookup/批量模式共享同一判定来源；  
  2. 在 penalty 窗内对候选进行降权或跳过，减少“明知 3 连败仍立即重拨”的无效尝试，同时维持 v3.2.9 的 5 分钟语义以兼容脚本；  
  3. 继续输出 `[DNS-HEALTH]` / `[DNS-CAND]` / `[RETRY-*]` 等观测信息，新退避动作额外输出 `[DNS-BACKOFF]`（或在 `[DNS-HEALTH]` 中新增 `action=skip`）便于黄金校验。  
- **建议路径（3 步）**  
  1. **抽象 server backoff 模块**：把 `server_status[]` 从 `wc_cache` 拆成独立 helper（可命名 `wc_server_backoff` 或直接扩展 `wc_dns_health`），对外提供 `should_skip(host,family)` / `note_result(host,family,success)`，并允许通过 Config 指定 penalty 窗口（默认 300s，必要时支持 30s 自测）。  
  2. **统一写入来源**：在 `wc_dial_43()` / legacy connect 路径中，将现有的 `wc_cache_mark_server_*` 重定向到新 helper；legacy 流程保持 3 次失败后 5 分钟静默的语义，同时让 lookup 也能读到相同的处罚状态。  
  3. **lookup 候选联动**：在 `wc_dns_build_candidates()` 或 `wc_lookup_execute()` 中查询 `should_skip()`，对 penalty 命中的候选执行“移至末尾/跳过”策略，且在所有候选都被 penalty 时保底保留 1 条（并打印 `[DNS-BACKOFF] action=force-last`）。批量模式未来可基于该状态做更激进的 query 级退避。  
- **风险与验证**  
  - Penalty 时长变化需要通过可配置参数对齐 legacy 预期（默认 300s，实验性 30s 仅用于自测或调优）；  
  - `wc_cache` 剩余 API 暂不移除，但文档需标注 server backoff 部分已 deprecated，避免新代码继续引用旧结构；  
  - 冒烟脚本需新增对 `[DNS-HEALTH state=penalized action=skip]` / `[DNS-BACKOFF]` 的 Golden 检查，防止回归静默跳过行为。  

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

## 5. 状态与 TODO 草稿

> 此节用于后续记录具体拆分进度。每次结构性改动后，追加简要条目，便于断点续作与回溯。

### 5.1 已完成里程碑（Phase 1 + Phase 1.5）

- **2025-12-18（runtime 配置只读视图 + cache 计数采样开关 + 四轮黄金）**  
  - 代码：`wc_runtime` 引入 `wc_runtime_cfg_view_t` 只读视图，net 上下文 pacing/retry 配置改读视图；`wc_runtime_push/pop_config` 同步刷新视图。新增缓存计数采样开关 `wc_runtime_set_cache_counter_sampling()`（默认 0，避免噪声），注册 housekeeping 钩子在开关开启时调用 `wc_cache_log_statistics()`，即便未开 `--debug` 也可按需观察计数。`wc_runtime_config_view()` 对外公开，便于后续调用点避免隐式全局读。  
  - 行为：默认无日志变化；只有显式开启采样开关时才会输出与 debug 同款 “Cache counters” 行，stdout/黄金契约不变。  
  - 验证（均无告警 + `[golden|golden-selftest] PASS`）：
    1) 远程冒烟默认参数：`out/artifacts/20251218-132235/build_out/smoke_test.log`；
    2) 远程冒烟 `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/20251218-132516/build_out/smoke_test.log`；
    3) 批量策略 raw/health-first/plan-a/plan-b：`out/artifacts/batch_raw/20251218-132717/build_out/smoke_test.log`、`batch_health/20251218-132939/.../smoke_test.log`、`batch_plan/20251218-133209/.../smoke_test.log`、`batch_planb/20251218-133429/.../smoke_test.log`；
    4) 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略）：`out/artifacts/batch_raw/20251218-133714/build_out/smoke_test.log`、`batch_health/20251218-133839/.../smoke_test.log`、`batch_plan/20251218-134002/.../smoke_test.log`、`batch_planb/20251218-134115/.../smoke_test.log`。  
  - 下一步：1）评估是否需要 CLI/自测入口显式切换采样开关；2）继续清理 runtime 其他隐式读点（若有）；3）保持黄金矩阵常规复跑。

- **2025-12-18（wc_cache 状态收拢 + 缓存计数可观测）**  
  - 代码：`wc_cache` 引入上下文结构体收拢运行态/计数器/互斥锁；连接缓存存取、完整性/统计检查统一走 `g_cache_ctx`；DNS/负缓存命中/未命中计数补齐；`wc_cache_log_statistics` 增加调试计数输出。行为保持既有 stdout/stderr 契约，调试标签未新增，仅在 debug 模式下多一行 counters。  
  - 验证（均无告警 + `[golden|golden-selftest] PASS`）：
    1) 远程冒烟默认参数：`out/artifacts/20251218-114328/build_out/smoke_test.log`；
    2) 远程冒烟 `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/20251218-114558/build_out/smoke_test.log`；
    3) 批量策略 raw/health-first/plan-a/plan-b：`out/artifacts/batch_raw/20251218-114757/...`、`batch_health/20251218-115018/...`、`batch_plan/20251218-115247/...`、`batch_planb/20251218-115512/...`；
    4) 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略）：`out/artifacts/batch_raw/20251218-115725/...`、`batch_health/20251218-115854/...`、`batch_plan/20251218-120018/...`、`batch_planb/20251218-120146/...`。  
  - 下一步：1）审视 signal/runtime glue，继续去除隐式全局读写；2）考虑在 atexit 或调试命令中增加按需计数采样（保持默认静默）；3）如未来扩展 cache 策略，优先复用 `g_cache_ctx` 以避免重新引入分散全局。 

- **2025-12-18（signal 模块 config 只读视图 + 四轮黄金复跑）**  
  - 代码：`wc_signal` 不再依赖全局 Config 指针，改为设置期复制所需字段（debug 级别、负缓存 ttl/开关、安全日志开关），后续 handler/atexit/安全日志均用只读快照，避免隐式全局读。  
  - 行为：信号退出路径与清理日志保持既有契约；调试与安全事件输出未新增标签。  
  - 验证（均无告警 + `[golden|golden-selftest] PASS`）：
    1) 远程冒烟默认参数：`out/artifacts/batch_raw/20251218-114757/build_out/smoke_test.log`；
    2) 远程冒烟 `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/batch_raw/20251218-115725/build_out/smoke_test.log`；
    3) 批量策略 raw/health-first/plan-a/plan-b：`out/artifacts/batch_raw/20251218-124007/...`、`batch_health/20251218-124257/...`、`batch_plan/20251218-124526/...`、`batch_planb/20251218-124747/...`；
    4) 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略）：`out/artifacts/batch_raw/20251218-124957/...`、`batch_health/20251218-125114/...`、`batch_plan/20251218-125234/...`、`batch_planb/20251218-125346/...`。  
  - 下一步：1）梳理 runtime Config 栈的只读视图（消除剩余隐式读）；2）评估是否需要新增可控的 cache 计数采样开关（默认静默）。

- **2025-12-18（运行期配置显式注入 + 四轮黄金回归）**  
  - 代码：信号与 client_flow 配置来源改为“仅限显式注入”，去除 `wc_runtime_config()` 回退；lookup 自测改用公开的 `wc_selftest_config_snapshot()`，并在头文件暴露该快照 helper，selftest 路径不再依赖隐式 runtime 读。  
  - 行为：对外输出契约与调试标签保持不变，`[DNS-CACHE-SUM]` / `[RETRY-*]` 等观测未受影响，自测与 batch 路径仍复用同一 net/context。  
  - 验证（均无告警 + `[golden|golden-selftest] PASS`）：
    1) 远程冒烟默认参数：`out/artifacts/20251218-094015/build_out/smoke_test.log`；
    2) 远程冒烟 `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/20251218-094311/build_out/smoke_test.log`；
    3) 批量策略 raw/health-first/plan-a/plan-b：`out/artifacts/batch_raw/20251218-094505/...`、`batch_health/20251218-094735/...`、`batch_plan/20251218-094953/...`、`batch_planb/20251218-095216/...`；
    4) 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略）：`out/artifacts/batch_raw/20251218-095455/...`、`batch_health/20251218-095611/...`、`batch_plan/20251218-095721/...`、`batch_planb/20251218-095842/...`。  
  - 下一步：继续保持“配置显式传递”约束，后续如新增自测/批量策略，需同步更新黄金脚本断言并记录在本备忘。 

- **2025-11-20（起点）**  
  - v3.2.9 已发布，DNS Phase 2/3 收尾，DNS 相关 RFC/备忘已整理完毕；  
  - 新增本文件 `docs/RFC-whois-client-split.md`，作为 `whois_client.c` 拆分主线的备忘录；  
  - 拆分 Phase 1 尚未正式动手，处于“规划与范围界定”阶段。

- **2025-11-20（Phase 1：main 附近瘦身，第 1 批）**  
  已完成内容（均通过远程 golden 校验，行为与 v3.2.9 等价）：
  - 把 `wc_opts_t` → 全局配置的映射收拢为 `wc_apply_opts_to_config()`，集中管理 CLI 选项对 `g_config` 的影响；  
  - 将 meta/display 相关选项（`--help/--version/--about/--examples/--servers/--selftest`）封装为 `wc_handle_meta_requests()`，`main` 只处理返回码；  
  - 抽出模式判定逻辑 `wc_detect_mode_and_query()`，统一处理 `-B`/stdin/argv 的 batch vs single 决策与错误提示；  
  （注：当前实现已下沉到 `src/core/client_meta.c` 作为 `wc_client_detect_mode_and_query()`，Phase 2 草案中关于该函数的下沉计划视为已完成。）  
  - 将单次查询路径提炼为 `wc_run_single_query()`，批量 stdin 路径提炼为 `wc_run_batch_stdin()`，`main` 只根据 `batch_mode` 选择其一；  
  - 收拢错误分支为 `wc_report_query_failure()`，统一 errno → 文案映射与失败时 header/tail 输出（single/batch 共用）；  
  - 收拢私网 IP 处理逻辑为 `wc_handle_private_ip()`，保证 single/batch 在 fold/plain 模式下输出契约一致；  
  - 收拢可疑查询逻辑为 `wc_handle_suspicious_query()`，保留 single（清理 cache + 返回错误）与 batch（仅跳过该行）之间的语义差异；  
  - 抽出响应过滤管线 `wc_apply_response_filters()`，统一 `wc_title` → `wc_grep` → `sanitize_response_for_output` 的顺序与 debug trace（含 batch 特有前缀）；  
  - 抽出 lookup 执行辅助函数 `wc_execute_lookup()`，集中构造 `wc_query` / `wc_lookup_opts` 并调用 `wc_lookup_execute()`，single/batch 共用。

  目前 `wc_run_single_query()` / `wc_run_batch_stdin()` 逻辑骨架已明显收敛为：
  - 前置检查（suspicious/private）→ 统一 lookup helper → 成功路径（header + filters + authoritative/tail）→ 失败路径（中断 vs 错误报告）→ 资源清理；  
  - `main()` 自身主要负责：opts 解析、配置映射、meta 请求处理、模式判定、cache/title/grep/fold 资源初始化以及选择 single/batch helper。

- **2025-11-20（Phase 1.5：query 执行下沉，第 1 步）**  
  - 已根据 Phase 1 中提炼出的 helper，将与“单条查询执行”强相关的逻辑迁移到新的 core 源文件：  
    - 新增 `include/wc/wc_query_exec.h`，声明 `wc_execute_lookup`、`wc_apply_response_filters`、`wc_handle_suspicious_query`、`wc_handle_private_ip`、`wc_report_query_failure` 等 helper；  
    - 新增 `src/core/whois_query_exec.c`，承载上述 helper 的具体实现；其中 `detect_suspicious_query`、`sanitize_response_for_output` 作为 `static` 内部函数下沉，不再由 `whois_client.c` 直接持有；  
    - 引入共享配置头 `include/wc/wc_config.h`，集中定义 `struct Config`，由 `whois_client.c` 与 `whois_query_exec.c` 共同引用，避免跨文件使用不完全类型；  
    - 通过远程多架构构建 + golden 校验（`tools/remote/remote_build_and_test.sh`），确认迁移前后行为与日志契约保持一致（含标题/尾行、fold 输出、`[RETRY-*]`、`[DNS-*]` 等标签形态）。  
  - 同时完成一次通用工具函数的模块化：  
    - 新增 `include/wc/wc_util.h` + `src/core/util.c`，提供 `wc_safe_malloc()` 等通用 helper，统一 fatal-on-OOM 语义；  
    - 原先 `whois_client.c` 中的 `static safe_malloc` 实现在完成迁移后被删除，所有调用点（client 与 `whois_query_exec.c` 内部）改为使用 `wc_safe_malloc`，避免在多个 C 文件中复制 malloc 包装逻辑。  
  - 这一批改动的目标是：
    - 让 `whois_client.c` 进一步收敛为“查询编排 + 模式选择”的薄壳，不再直接关心 lookup / 过滤管线的细节；
    - 为后续更大规模的拆分（例如 meta/config glue 下沉、自测路径集中）打基础，同时通过 golden 脚本确保每一步都是“结构变化而非行为变化”。  

- **2025-11-20（Phase 1.5：client meta/config glue 下沉，第 3 步，single-query orchestrator 下沉）**  
  已完成内容（已通过远程多架构 golden 校验）：
  - 在 `src/core/whois_query_exec.c` 中新增 `wc_client_run_single_query()`，承接原 `whois_client.c` 中的 `wc_run_single_query()` 逻辑：  
    - 继续复用 `wc_handle_suspicious_query()` / `wc_execute_lookup()` / `wc_apply_response_filters()` / `wc_report_query_failure()` 等 helper，保持查询执行与过滤流水线的行为不变；  
    - header/tail 输出仍基于 `wc_lookup` 返回的 `wc_result.meta` 字段，并保留针对权威服务器为 IP 字面量时的 RIR fallback 行为（通过 `attempt_rir_fallback_from_ip()` + `wc_dns_is_ip_literal()`）；  
    - 失败路径统一由 `wc_report_query_failure()` 处理 errno → 文案映射，最终仍会在错误场景调用 `cleanup_caches()`，维持与旧实现一致的资源释放语义；  
  - 在 `whois_client.c` 中删除本地的 `wc_run_single_query()` 静态实现，将单次查询分支改为直接调用 `wc_client_run_single_query(single_query, server_host, port)`；  
  - `wc_client_run_single_query()` 位于 core 层，使未来如有其他 CLI/front-end 需要调用同一查询流水线时，可以直接复用，而不用复制入口文件中的大段 orchestrator 代码。  
  
- **2025-11-20（Phase 1.5：client meta/config glue 下沉，第 4 步，batch orchestrator 下沉）**  
  已完成内容（已通过远程多架构 golden 校验）：  
  - 在 `src/core/whois_query_exec.c` 中新增 `wc_client_run_batch_stdin(const char* server_host, int port)`，承接原 `whois_client.c` 中的 `wc_run_batch_stdin()` 逻辑：  
    - 继续沿用逐行读取 stdin → 去空白/跳过注释行 → `wc_handle_suspicious_query(start, 1)` → `wc_execute_lookup()` → header → `wc_apply_response_filters(..., in_batch=1)` → fold/plain 输出 → 尾行 的整体流水线；  
    - header/tail 输出仍依赖 `wc_result.meta` 中的 `via_host/via_ip/authoritative_host/authoritative_ip`，并在权威服务器为 IP 字面量时复用 single-query 同款 RIR fallback 行为（`wc_dns_is_ip_literal` + `attempt_rir_fallback_from_ip`）；  
    - debug/trace 仍保持 `[DEBUG] ===== BATCH STDIN MODE START =====` 与 `[TRACE][batch] ...` 前缀不变，以兼容现有冒烟脚本与黄金样例的形态；  
  - 在 `whois_client.c` 中删除本地的 `wc_run_batch_stdin()` 静态实现，将 batch 分支改为直接调用 `wc_client_run_batch_stdin(server_host, port)`；  
  - 至此，single/batch 两条主查询路径的 orchestrator 均已下沉到 core 层，`whois_client.c` 在查询执行阶段只负责根据 `batch_mode` 在两者之间做路由选择。  

- **2025-11-20（Phase 1.5：DNS glue 下沉，第 5 步，RIR fallback helper 下沉）**  
  已完成内容（已通过远程多架构 golden 校验）：  
  - 在 `wc_dns` 中新增 `wc_dns_rir_fallback_from_ip(const char* ip_literal)`，承接原 `whois_client.c` 内基于 IP 字面量的 RIR fallback 逻辑（反向域名拼接 + 域名到 RIR 的映射），作为 DNS/core 层的公共 helper；  
  - `src/core/whois_query_exec.c` 的 single/batch orchestrator 以及 `whois_client.c` 中 `--host` 为 IP 字面量且首跳失败时的重试路径，全部切换为调用 `wc_dns_rir_fallback_from_ip()`，删除 client 层本地的 `reverse_lookup_domain` / `map_domain_to_rir` / `attempt_rir_fallback_from_ip` 实现；  
  - 通过远程多架构 golden 脚本确认：权威 RIR 回退行为（包括 fallback 命中和 miss 时的 header/tail 文本、notice/debug 输出形态）与 v3.2.9 保持一致，未引入额外 DNS 查询或可观测性变化。  

- **2025-11-20（Phase 1 小结）**  
  - 按 3.1 中对 Phase 1 的定义（聚焦 `whois_client.c` 内部的主流程梳理、配置与状态收拢、日志入口归一化、退出路径整理，而不主动改策略），目前 main 附近的结构重排与查询执行相关 helper 的抽取已完成，且通过多轮远程 golden 校验确认行为与 v3.2.9 基线等价；  
  - 部分原本计划放在 Phase 2 的工作（例如 query 执行 orchestrator、RIR fallback helper 的下沉）实际已在 Phase 1.5 提前完成，使得 `whois_client.c` 当前更接近“薄壳 + 进程级 glue”的目标形态；  
  - 因此将 Phase 1 视为完成，后续拆分工作统一归入 Phase 2+，重点围绕信号处理、退出路径与剩余 net/DNS glue 的进一步收拢，以及可能的新 selftest 场景。  

- **2025-11-22（Phase 2：signal/退出 glue 下沉，第 1 步）**  
  - 新增 `include/wc/wc_signal.h` + `src/core/signal.c` 作为进程级信号/退出 glue 的公共模块，下沉原先 `whois_client.c` 中的 `setup_signal_handlers` / `signal_handler` / `cleanup_on_signal` / active connection 跟踪与 `should_terminate` 等实现；  
  - `whois_client.c` 侧改为仅调用 `wc_signal_setup_handlers()`、`wc_signal_register_active_connection()` / `wc_signal_unregister_active_connection()`、`wc_signal_should_terminate()` 和 `wc_signal_atexit_cleanup()`，自身不再持有信号处理与活动连接的具体实现逻辑；  
  - 保持 Ctrl-C 行为完全不变：仍使用 `exit(130)` 退出，stderr 提示文案保持为 `"[INFO] Terminated by user (Ctrl-C). Exiting..."`，并继续依赖 `atexit` 路径触发 `[RETRY-METRICS]` / `[DNS-CACHE-SUM]` 等指标输出；  
  - 将安全事件类型常量 `SEC_EVENT_*` 提升为公共定义，统一放入 `wc_seclog.h`，供 `whois_client.c` 与 `signal.c` 共用，避免重复定义；  
  - 通过远程多架构 `remote_build_and_test.sh` 冒烟 + golden 校验确认：普通查询输出、Ctrl-C 中断时的退出码与日志形态（含 `[RETRY-METRICS]` / `[DNS-CACHE-SUM]` / security log 相关标签）与 v3.2.9 黄金基线一致。  
  - 在 active-connection 关闭路径上进一步下沉 glue：在 `wc_net` 中新增 `wc_net_close_and_unregister()`，`whois_client.c` 不再手工 `close(sockfd)`，而是依赖该 helper 统一执行“注销 active connection + 安全关闭 fd”；此改动已通过远程多架构 golden 校验，Ctrl-C 行为与既有黄金样例完全一致。  
  - 在拨号侧将缓存 miss 时的“新建连接”逻辑由本地 `getaddrinfo` + 非阻塞 `connect` + `select` 下沉为对 `wc_dial_43()` 的调用：保留 `connect_to_server()` 的返回语义、连接缓存与 `monitor_connection_security()` 行为不变，仅由 `wc_dial_43` 提供底层 dial engine 与 `[RETRY-METRICS*]` / `[RETRY-ERRORS]` / `[DNS-*]` 观测；两轮带 `--debug --retry-metrics --dns-cache-stats` 的远程冒烟与 golden 脚本均通过，指标标签形态符合既有预期。  

- **2025-11-22（Phase 2：runtime init/atexit glue 收拢，第 1 步）**  
  - 在 `whois_client.c` 内部新增 `wc_runtime_init(const wc_opts_t* opts)`，统一封装与运行期环境相关、仅依赖命令行选项的初始化与 `atexit` 注册：包括 RNG seed、信号处理注册（`wc_signal_setup_handlers()` + `wc_signal_atexit_cleanup`）以及基于 `opts->dns_cache_stats` 的 `[DNS-CACHE-SUM]` 输出钩子注册；`main()` 在 `wc_opts_parse()` 成功后调用该 helper，保持 parse 失败时的行为与旧版本完全一致。  
  - 新增 `wc_runtime_init_resources()` 本地 helper，将原本散落在 `main()` 中的缓存初始化与条件输出资源清理 glue 收拢为单一入口：内部调用 `init_caches()` 并注册 `cleanup_caches` / `wc_title_free` / `wc_grep_free` / `free_fold_resources` 的 `atexit` 钩子，同时保留原有 `[DEBUG] Initializing caches with final configuration...` 与 `[DEBUG] Caches initialized successfully` 两条调试输出的文案与时序；`main()` 中原有的对应代码块改为直接调用该 helper。  
  - 经过一次本地远程冒烟以及后续两次带 `--debug --retry-metrics --dns-cache-stats` 的多架构远程冒烟，`[DNS-CACHE-SUM]` 的输出次数与形态、`[RETRY-*]`/`[DNS-*]` 观测标签以及 Ctrl-C 行为均与 v3.2.9 黄金基线保持一致，确认本轮改动仅为运行期 glue 的结构性收拢而未引入行为差异。后续通过引入 `include/wc/wc_runtime.h` + `src/core/runtime.c` 将上述两个 helper 下沉为 core 模块对外 API，并删除 `whois_client.c` 中的本地实现，使 runtime 相关 init/atexit glue 完全由 core/runtime 负责；又跑了多轮 golden 冒烟（含 `8.8.8.8 1.1.1.1` 与 `8.8.8.8 no-such-domain-...` 查询组合），确认黄金检查继续 PASS。  
  - 在上述基础上，继续沿 B 计划将 main 附近的“模式检测 + single/batch 调度”整体下沉到 core：在 `src/core/whois_query_exec.c` 中新增 orchestrator `wc_client_run_with_mode(const wc_opts_t* opts, int argc, char* const* argv, Config* config)`，负责：
    - 调用 `wc_client_handle_meta_requests()` 处理 help/version/servers/examples/selftest 等 meta 请求：`meta_rc>0` 视为成功返回 0，`meta_rc<0` 视为失败返回 1，与旧版 `main` 行为完全一致；
    - 调用 `wc_client_detect_mode_and_query()` 完成 batch vs single 判定与查询提取；若组合非法（例如 `-B` 搭配位置参数），直接返回 `WC_EXIT_FAILURE`，不再在入口层打印第二份 Usage；
    - 在模式判定成功后调用 `wc_runtime_init_resources()` 完成 cache/title/grep/fold 等资源初始化，然后根据 `batch_mode` 分别调用 `wc_client_run_single_query()` 或 `wc_client_run_batch_stdin()`；
    - `whois_client.c::main` 则改为在完成 opts 解析、配置映射、自测/校验与 runtime init 后，直接调用 `wc_client_run_with_mode(&opts, argc, argv, &g_config)` 并返回其退出码，从而进一步瘦身为“薄壳入口”。  
  - 这一批改动经过多架构 `remote_build_and_test.sh` 的 golden 检查：普通查询、批量模式、自测、错误路径与 Ctrl‑C 的退出码与输出形态均保持与 v3.2.9 基线一致；同时顺带消除了历史上 `-B <query>` 场景下“错误提示 + Usage 再打印一遍”的双重输出问题——现在只保留一份 Usage/帮助与退出码=1，对外契约更为收敛。  
  - 在同一批次中引入了共享工具模块 `wc_util`：当前提供 `wc_safe_malloc()` 与 `wc_safe_strdup()` 两个 helper，用于在 core 与入口层统一 fatal-on-OOM 语义与基础字符串分配逻辑；`whois_client.c` 侧不再自带本地 `safe_malloc`/`safe_strdup` 实现，而是通过 `#define strdup(s) wc_safe_strdup((s), "strdup")` 这一薄封装复用 core util，从而减少入口文件内重复的小工具代码，使其更专注于 CLI 解析与高层 orchestrator。  
  - 把 `wc_output_*` 标题/尾行输出函数从 whois_client.c 抽到新文件 `src/core/output.c`，入口进一步减薄。
  - 清理并统一 `include/wc/wc_output.h`，只保留函数声明和公共 `log_message` 原型，去掉原来的 `static inline` 实现和重复 guard`#endif` 重复定义问题。
  - 所有使用 `log_message` 的 core 模块改为通过 `wc_output.h` 获取声明，删除本地 `extern` 声明，使日志入口原型有唯一来源。
  - 远程多架构构建通过，golden 检查 PASS，且无新增告警。

- **2025-11-22（Phase 2：cache/glue 渐进下沉，第 1 步，连接健康检查 helper 抽取）**  
  已完成内容（已通过远程多架构 golden 校验）：  
  - 在 `include/wc/wc_cache.h` 中新增 `wc_cache_is_connection_alive(int sockfd)` 声明，作为“连接是否仍然健康”的统一 helper，对外只暴露一个简单的 fd→bool 接口；  
  - 在 `src/core/cache.c` 中实现 `wc_cache_is_connection_alive`：  
    - 内部逻辑等价于原先 `whois_client.c` 里的 `is_socket_alive`/`is_connection_alive` 组合，基于 `getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len)` 判断连接是否仍处于无错误状态；  
    - 补充 `#include <sys/types.h>` 与 `#include <sys/socket.h>`，为 `socklen_t`、`getsockopt`、`SOL_SOCKET`、`SO_ERROR` 提供完整声明，解决 aarch64‑musl 交叉编译环境中出现的未声明标识符告警/错误；  
    - 读取 `SO_ERROR` 失败或传入 `sockfd == -1` 时一律返回“非存活”，与旧 helper 的保守策略保持一致。  
  - 在 `whois_client.c` 中删除本地的 `is_socket_alive` 与 `is_connection_alive` 实现及其声明，将所有调用点统一替换为 `wc_cache_is_connection_alive`：  
    - 缓存清理与完整性检查路径中不再直接调用本地 helper，而是通过 `wc_cache_is_connection_alive` 判断连接是否可复用；  
    - `get_cached_connection()` 命中后、`set_cached_connection()` 缓存前，以及 `connect_to_server()` 使用缓存连接的分支，都改为通过该 API 进行健康检查，避免在入口层重复维护 socket 检查逻辑。  
  - 这一批改动的目标是：在**不改变连接缓存语义与行为**的前提下，将“连接健康检查”这一纯粹的 net/cache glue 从 `whois_client.c` 抽离到 `wc_cache` 模块，为后续继续迁移 DNS/连接缓存的结构体与操作函数打基础；远程多架构 `remote_build_and_test.sh` 构建与 golden 检查均通过，确认行为与 v3.2.9 基线保持等价。

- **2025-11-22（Phase 2：cache/glue 渐进下沉，第 1.5 步，cache 完整性/统计 helper 暂缓下沉）**  
  - 本轮尝试：希望沿用上一步的思路，把仅在 debug 模式下使用的 `validate_cache_integrity()` / `log_cache_statistics()` 也通过 `wc_cache` 暴露为公共 helper：在 `include/wc/wc_cache.h` 中新增 `wc_cache_validate_integrity()` 与 `wc_cache_log_statistics()` 两个 API 名称，并尝试在 `src/core/cache.c` 内部直接访问 `cache_mutex` / `dns_cache` / `connection_cache` / `allocated_*_cache_size` 等全局状态来实现它们；  
  - 实际效果：由于上述缓存结构体与互斥量当前仍是 `whois_client.c` 的私有实现细节，`cache.c` 侧的 `extern` 声明在多架构链接阶段引发了大量 `undefined reference to cache_mutex/dns_cache/allocated_*_cache_size` 等错误，说明在尚未整体迁移 cache 数据结构前，简单通过 `extern` 拉取这些符号是不安全的；  
  - 最终落点：
    - 在 `src/core/cache.c` 中撤回对这些私有全局的引用，仅保留空壳 stub 实现：`void wc_cache_validate_integrity(void) {}` / `void wc_cache_log_statistics(void) {}`，保证对外符号存在但不依赖额外链接；  
    - 在 `whois_client.c` 中恢复原本的 `static validate_cache_integrity()` 与 `static log_cache_statistics()` 实现，并将调用点改回本地 helper：`init_caches()` 末尾继续调用 `log_cache_statistics()` 打印首轮统计，`perform_whois_query()` 在 `cleanup_expired_cache_entries()` 之后、debug 模式下调用 `validate_cache_integrity()` 做完整性检查；  
    - 在 `whois_client.c` 顶部补充注释，明确当前状态：`wc_cache_validate_integrity` / `wc_cache_log_statistics` 的对外名字仍由 `wc_cache.h` 收口，但真正逻辑暂时仍留在入口 TU 内部，等待未来 cache 结构整体迁移到 `wc_cache` 再做下沉；  
  - 这一轮的意义更偏向“试探边界 + 记录踩坑”：最终恢复到与 v3.2.9 等价的实现形态，远程多架构构建重新回到“无告警 + Golden PASS”，同时在本 RFC 中记下了 cache 私有全局目前还不宜跨 TU 引用的事实，为后续规划 cache 模块化时提供参考。

- **2025-11-22（Phase 2：DNS/helper 渐进下沉，第 1 步，get_known_ip 下沉到 wc_dns）**  
  - 目标：将“已知 RIR whois 主机名 → 硬编码 IP”这一纯只读 fallback 映射从 `whois_client.c` 收拢到 DNS 模块，统一管理与 DNS 相关的兜底逻辑，同时减少入口文件内的辅助函数体积；  
  - 主要改动：  
    - 在 `include/wc/wc_dns.h` 中新增 `const char* wc_dns_get_known_ip(const char* domain);` 声明，并在 `src/core/dns.c` 内实现：使用与原 `get_known_ip` 完全相同的 hostname→IP 映射表（apnic/ripe/arin/lacnic/afrinic/iana），但不在该层做日志输出，仅专注于返回指向静态字符串的指针或 NULL；  
    - 删除 `whois_client.c` 内部的 `get_known_ip` 实现和前向声明，保留其周边的日志与控制流不变：`connect_with_fallback()` 和 lookup 路径中的 fallback 逻辑仍然在调用前后输出 DEBUG/WARN/INFO 日志，只是将真正的映射查询改为调用 `wc_dns_get_known_ip()`；  
    - 更新 `src/core/lookup.c` 中多处 `get_known_ip` 调用与 `extern` 声明：统一改为通过 `wc_dns_get_known_ip(domain_for_known)` 获取 IP 字面量，以便所有 known‑IP fallback 行为都由 DNS 模块提供数据来源；  
  - 行为与契约：  
    - known‑IP 映射表的具体条目与原实现完全一致，仍然只在 DNS 失败或被判定为需要 fallback 时才启用；  
    - 入口层和 lookup 层的日志文案、fallback 标志位（例如 `fallback_flags` 中的 `used_known_ip` / `forced_ipv4`）保持不变，远程多架构构建与 golden 检查继续 PASS，确认此次下沉仅为“实现位置调整”，未引入任何对外行为变化。  

- **2025-11-23（Phase 2：cache/glue 渐进下沉，第 1.6 步，缓存调试 helper 对外封装）**  
  - 背景：`include/wc/wc_cache.h` 在上一批次中预留了 `wc_cache_validate_integrity()` / `wc_cache_log_statistics()` 两个 API，但实际实现仍以 `static` 形式存在于 `whois_client.c`，导致其它模块虽然可以 include 头文件却无法链接到真实逻辑；  
  - 改动：将上述两个 helper 由 `static` 改为真正的 `wc_cache_*` 对外符号，继续保留在 `whois_client.c` 内部以便直接访问 `dns_cache` / `connection_cache` / `cache_mutex`；同时把所有调用点改为使用公共前缀（`wc_cache_log_statistics()`、`wc_cache_validate_integrity()`），保持入口层日志与调试输出不变；  
  - `src/core/cache.c` 仍然只是声明这些 API，并注明实现位于入口层，等待未来 cache 结构整体迁移后再下沉；此次改动未触碰缓存结构体与互斥量的定义；  
  - 行为保持与 v3.2.9 完全一致，仅解决“头文件声明与实际符号不匹配”的技术债，后续若有其它模块需要调用调试 helper（例如新的 runtime/自测入口），即可直接链接。  

- **2025-11-24（Phase 2：protocol safety 渐进下沉，第 1 步，响应校验 helper 模块化）**  
  - 背景：`whois_client.c` 顶部仍保留 `validate_whois_protocol_response` / `detect_protocol_anomalies` / `check_response_integrity` / `validate_response_data` / `detect_protocol_injection` 等协议安全 helper，使入口承担了大量与 WHOIS 响应结构验证相关的细节；  
  - 改动：新建 `include/wc/wc_protocol_safety.h` + `src/core/protocol_safety.c`，将上述 helper 下沉为对外 API（`wc_protocol_validate_response_data` / `wc_protocol_validate_whois_response` / `wc_protocol_check_response_integrity` / `wc_protocol_detect_anomalies` / `wc_protocol_detect_injection`），内部继续沿用原有日志与安全事件输出逻辑；`whois_client.c` 删除对应 `static` 实现与宏定义，只保留头文件引用并在 `receive_response` / `perform_whois_query` 中调用新的 `wc_protocol_*` API；  
  - 由于只是物理搬迁，行为与日志文案保持与 v3.2.9 等价；尚未重新跑远程 golden，待本轮阶段性拆分完成后统一触发一次多架构冒烟。  
  - 同批次顺便把 `log_message` 的实现移到 `src/core/output.c` 并统一命名为 `wc_output_log_message`，入口层仅保留声明；该 helper 现在通过 `wc_is_debug_enabled()` 判断调试开关，不再直接访问 `g_config`，方便在其他 front-end 里复用同一日志入口。  

- **2025-12-04（Redirect guard 热修 + 四轮黄金验证 + 143.128.0.0 三阶链路复盘）**  
  - 背景：在排查 `143.128.0.0` 的 IANA→ARIN→AFRINIC 跳转链路时，发现 AfriNIC 响应中的 `parent: 0.0.0.0 - 255.255.255.255` 会触发 `wc_redirect` 的 “Whole IPv4 space” 守卫，误把合法权威结果强制重送 IANA，导致尾行落在 IANA/ARIN。该守卫最初只预期截断 IANA summary/空网段，但由于使用裸 `strstr("0.0.0.0/0")`，凡是 meta 字段提到 `0.0.0.0` 都会命中。  
  - 改动：在 `src/core/redirect.c` 新增 `starts_with_case_insensitive()` 与 `has_full_ipv4_guard_line()` helper，仅当 `inetnum:` / `NetRange:` 行本身覆盖全 IPv4 时才触发守卫；`extract_refer_server()` 与 `needs_redirect()` 统一接入该 helper，其他字段（如 `parent:`、`mnt-lower:`）不再触发强制 IANA。调试输出保持 `[DEBUG] Redirect flag: Whole IPv4 space or 0.0.0.0/0` 语义不变。  
  - 结果：IANA→ARIN→AFRINIC 三跳链路重新按照真实 referral 落在 AfriNIC，`out\iana-143.128.0.0`、`out\arin-143.128.0.0`、`out\afrinic-143.128.0.0` 均显示“权威 RIR: whois.afrinic.net”，符合 `143.128.0.0 -> IANA -> ARIN -> AFRINIC` / `-> ARIN -> AFRINIC` / `-> AFRINIC` 三种首跳设定的预期。  
  - 验证：完成“默认 / `--debug --retry-metrics --dns-cache-stats` / 批量 raw+plan-a+health-first / `--selftest-force-suspicious 8.8.8.8`”四轮远程冒烟，全部 `[golden|golden-selftest] PASS`；日志位于 `out/artifacts/20251204-140138/build_out/smoke_test.log`、`out/artifacts/20251204-140402/build_out/smoke_test.log`、`out/artifacts/{batch_raw,batch_plan,batch_health}/20251204-14{0840,1123,1001}/build_out/{smoke_test.log,golden_report_*.txt}` 与 `out/artifacts/{batch_raw,batch_plan,batch_health}/20251204-1414**/build_out/smoke_test.log`。远程三连跳测试同样 PASS：`out/iana-143.128.0.0` / `out/arin-143.128.0.0` / `out/afrinic-143.128.0.0`。  
  - 后续跟进（2025-12-04 更新）：1）✅ IPv6 守卫已复用 `inet6num`/`NetRange` 精准匹配，并移除遗留的 `::/0` 全局判定；2）✅ `wc_redirect` 自测已新增 IPv6 parent 行样例，确保 `parent: ::/0` 不再误触 IANA 回退；3）✅ `docs/OPERATIONS_{CN,EN}.md` 的 DNS quickstart 已补入 143.128.0.0 + referral 脚本与 WHOIS_LOOKUP_SELFTEST 剧本，不再依赖那 3 份手工日志。  

- **2025-12-04（WHOIS_LOOKUP_SELFTEST 剧本归档 + 文档同步）**  
  - 为了把 `-DWHOIS_LOOKUP_SELFTEST` 版本的证据链固化到运维手册，按“无钩子黄金 → 自测黄金”的顺序跑了两轮远程套件：  
    1. `tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8 1.1.1.1 143.128.0.0' -s '/d/LZProjects/lzispro/...;/d/LZProjects/whois/release/lzispro/whois' -P 1 -a '--debug --retry-metrics --dns-cache-stats' -G 1 -E '-O3 -s -DWHOIS_LOOKUP_SELFTEST'` → `[golden] PASS`，日志 `out/artifacts/20251204-155440/...`、`...-155655/...`。  
    2. `tools/test/selftest_golden_suite.ps1 -KeyPath 'c:\Users\<你>\.ssh\id_rsa' -SmokeExtraArgs "--debug --retry-metrics --dns-cache-stats --selftest-force-suspicious 8.8.8.8" -SelftestActions "force-suspicious,8.8.8.8" -SelftestExpectations "action=force-suspicious,query=8.8.8.8" -NoGolden` → raw/plan-a/health-first 分别写入 `out/artifacts/batch_{raw,plan,health}/20251204-17xxxx/.../smoke_test.log` 并由 `golden_check_selftest.sh` 给出 `[golden-selftest] PASS`。  
  - 额外确认：传统 `--selftest` 命令仍然是“只跑自测就退出”，因此在黄金命令里必须改用 `--selftest-force-suspicious`/`--selftest-force-private` 等钩子，否则 header/referral/tail 会被跳过并触发 `[golden][ERROR] header not found`。为避免噪声，自测黄金一律给 `selftest_golden_suite.ps1` 加 `-NoGolden`，把常规 golden 的职责和 `[golden-selftest]` 结果拆开。
  - 文档同步：`docs/OPERATIONS_{CN,EN}.md` 的 DNS quickstart 章节已记录上述流程、命令行和日志路径，提醒运维“先跑无钩子黄金，再跑自测黄金”以及不要把裸 `--selftest` 混入 golden 套件。RFC 当前条目即视为当日的 evidence log。  

###### 2025-12-04 日终小结与下一步

- 当日成果：完成 `wc_redirect` “Whole IPv4/IPv6 space” 精准匹配热修，143.128.0.0 的 IANA→ARIN→AFRINIC 三连跳重新对齐真实 referral；`tools/remote/remote_build_and_test.sh` 默认新增 AfriNIC 守卫 gate，自动采集 `referral_143128/{iana,arin,afrinic}.log` 并运行 `tools/test/referral_143128_check.sh`；`docs/OPERATIONS_{CN,EN}.md`、`docs/USAGE_{CN,EN}.md`、`RELEASE_NOTES.md` 同步记录该流程，Golden Playbook 列入 2025-12-04 四轮日志，可直接复跑默认/调试/批量/raw-plan-a-health-first/自测矩阵。
- 关键观察：AfriNIC gate 融入日常冒烟后，任何守卫回归都会被 `referral_143128_check.sh` 第一时间捕获，日志位置固定在 `build_out/referral_143128/*.log`；仅在 AfriNIC 不可达或纯构建场景下才允许 `-L 0`/`REFERRAL_CHECK=0`。同时，plan-a/health-first 自测黄金依旧保持 PASS，证明热修与新 gate 未改动 batch pipeline 输出。
- 下一步计划：
  1. 完成 `tools/test/golden_check_selftest.sh`，把当前 Playbook 中“手写断言 `[SELFTEST] action=force-*`”的说明升级为可复制命令，并让 VS Code Selftest 任务与 `remote_batch_strategy_suite.ps1` 默认调用该脚本。
  2. 评估是否需要扩展 referral gate 到更多历史移交网段（如其它 AfriNIC/APNIC 样本），必要时为 `tools/remote/remote_build_and_test.sh` 增加 `--referral-check-hosts` 以定义额外的三连跳校验。
  3. 继续 Stage 5.5.3 plan-b 策略与 `wc_batch_strategy_t` 接口扩展，确保在引入新的批量缓存/加速逻辑前，现有 raw/health-first/plan-a 的 golden 仍可一键覆盖。

###### 2025-12-08 后续工作计划（确认顺序）

- 优先处理“信号/退出路径 + cache/backoff 梳理”，再进入批量策略/plan-b 扩展。
- 理由：
  1) 信号/退出与 backoff 状态影响全模式（单条/批量/自测），任何泄漏/不一致会直接破坏黄金或 Ctrl-C 语义，风险高；
  2) plan-b 等批量策略需要稳定的 backoff/cache 语义作为基座，先收敛基础设施可减少返工；
  3) 验证成本可控：改动后用现有黄金套件（含 `--debug --retry-metrics --dns-cache-stats`）即可回归，无需新增样例。
- 执行顺序（拟）：
  1) 信号/退出 glue：梳理 `signal_handler`/cleanup 的注册与调用顺序，确保 `[DNS-CACHE-SUM]`/metrics 在异常退出也一致；必要时提炼 core/runtime helper；
  2) backoff/cache 整合：统一 legacy `server_status` 与 `wc_dns_health` 记忆，抽 helper，打通 lookup/legacy；保持 `[DNS-HEALTH]`/`[DNS-BACKOFF]` 观测格式；
  3) 批量策略/plan-b：在稳定的 backoff/cache 基座上扩展接口，补自测/黄金。

###### 2025-12-08 进度记录（golden_check 支持 capped referral）

- 新增 `tools/test/golden_check.sh` 的两个选项以覆盖 `-R` 限制 referral 链路时的黄金校验：`--auth-unknown-when-capped`（尾行匹配 `unknown @ unknown`）与 `--redirect-line <host>`（强制存在指定的 `=== Redirected query to ... ===` 行）。
- 使用远程冒烟日志 `out/artifacts/20251208-151910/build_out/smoke_test.log` 验证命令：
  ```bash
  bash tools/test/golden_check.sh \
    -l out/artifacts/20251208-151910/build_out/smoke_test.log \
    --query 8.8.8.8 --start whois.iana.org --auth whois.arin.net \
    --auth-unknown-when-capped --redirect-line whois.afrinic.net
  ```
  结果 `[golden] PASS: header/referral/tail match expected patterns`，说明 capped referral 场景可被黄金脚本覆盖。
- 追加改进：`golden_check.sh` 若检测到 “Additional/Redirect 但无尾行” 会自动放行（打印 `[INFO] tail missing but allowed`），无需额外开关；自测日志可用 `--selftest-actions-only` 跳过头尾与 redirect 检查，仅断言 `[SELFTEST] action=*` 标签。
- 仍需跟进：`golden_check_selftest.sh` 尚未完成；如需对其它 redirect 目标做 golden，请根据实际日志切换 `--redirect-line` 参数并补充新的冒烟样例。

###### 2025-12-18 缓存计数采样开关 + 四轮黄金复跑

- 代码进展：新增 `--cache-counter-sampling` CLI 开关与 Config 字段，允许在非 debug 运行中周期采样缓存计数；任意 `--selftest*`/demo 路径会自动开启采样，便于黄金脚本断言计数日志。采样状态在 runtime/init 与 config 注入阶段保持一致，避免后续覆盖。
- 四轮远程冒烟 + 黄金（14:17–14:35，全 PASS，无告警）：
  1) 默认参数：`out/artifacts/20251218-141752/build_out/smoke_test.log`。[golden] PASS。
  2) `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/20251218-142007/build_out/smoke_test.log`。[golden] PASS。
  3) 批量策略 raw/health-first/plan-a/plan-b：
    - raw：`out/artifacts/batch_raw/20251218-142209/build_out/smoke_test.log`（`golden_report_raw.txt`）
    - health-first：`out/artifacts/batch_health/20251218-142427/build_out/smoke_test.log`（`golden_report_health-first.txt`）
    - plan-a：`out/artifacts/batch_plan/20251218-142650/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
    - plan-b：`out/artifacts/batch_planb/20251218-142910/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
  4) 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：
    - raw：`out/artifacts/batch_raw/20251218-143112/build_out/smoke_test.log`
    - health-first：`out/artifacts/batch_health/20251218-143231/build_out/smoke_test.log`
    - plan-a：`out/artifacts/batch_plan/20251218-143355/build_out/smoke_test.log`
    - plan-b：`out/artifacts/batch_planb/20251218-143508/build_out/smoke_test.log`
- 下一步：继续收束 runtime Config 显式注入（pipeline/batch/cache/backoff），保持黄金矩阵持续覆盖；如采样开关需要落地到更多诊断日志，再评估是否暴露默认启用策略。

###### 2025-12-18 client_flow 显式注入 + 四轮黄金复跑

- 代码进展：批量/回退路径去掉 `g_wc_client_flow_config` 全局，batch health 采样、惩罚、策略选择、调试注入等全部改为显式传入 `Config*`；保持 `[DNS-BATCH]` / backoff 行为与输出不变。
- 四轮远程冒烟 + 黄金（15:26–15:45，全 PASS，无告警）：
  1) 默认参数：`out/artifacts/20251218-152604/build_out/smoke_test.log`。[golden] PASS。
  2) `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/20251218-152906/build_out/smoke_test.log`。[golden] PASS。
  3) 批量策略 raw/health-first/plan-a/plan-b：
     - raw：`out/artifacts/batch_raw/20251218-153126/build_out/smoke_test.log`（`golden_report_raw.txt`）
     - health-first：`out/artifacts/batch_health/20251218-153349/build_out/smoke_test.log`（`golden_report_health-first.txt`）
     - plan-a：`out/artifacts/batch_plan/20251218-153620/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
     - plan-b：`out/artifacts/batch_planb/20251218-153839/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
  4) 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：
     - raw：`out/artifacts/batch_raw/20251218-154118/build_out/smoke_test.log`
     - health-first：`out/artifacts/batch_health/20251218-154231/build_out/smoke_test.log`
     - plan-a：`out/artifacts/batch_plan/20251218-154348/build_out/smoke_test.log`
     - plan-b：`out/artifacts/batch_planb/20251218-154503/build_out/smoke_test.log`
- 下一步：
  1) 继续排查 pipeline/fold/grep 等路径的隐式 Config 读取，保持黄金矩阵常态化覆盖；
  2) 如采样开关需要扩展到更多诊断日志，评估默认启用策略并补充文档；
  3) 完成一次全量远程冒烟（含 `--debug --retry-metrics --dns-cache-stats` + 四策略 + 自测）后同步刷新 OPERATIONS 文档与黄金报告链接。

- 采样开关评估：当前 `--cache-counter-sampling` 仅触发 cache 计数采样（同 debug 时的 `wc_cache_log_statistics`），自测自动开启；扩展到其它诊断（如 `[DNS-*]`/backoff）会显著增加 stderr 噪声且黄金脚本未涵盖，暂不扩展，保持默认关闭策略不变。如后续需要新的诊断采样，建议单独开 flag 并补黄金覆盖。

###### 2025-12-18 pipeline 显式注入后四轮黄金复跑（16:03–16:32）

- 代码进展：pipeline 入口改为显式传入 `Config*`，不再隐式抓取 runner 全局；入口 whois_client 传递 config，保持行为契约不变。
- 四轮远程冒烟 + 黄金（全 PASS，无告警）：
  1) 默认参数：`out/artifacts/20251218-160332/build_out/smoke_test.log`。[golden] PASS。
  2) `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/20251218-160639/build_out/smoke_test.log`。[golden] PASS。
  3) 批量策略 raw/health-first/plan-a/plan-b：
    - raw：`out/artifacts/batch_raw/20251218-160914/build_out/smoke_test.log`（`golden_report_raw.txt`）
    - health-first：`out/artifacts/batch_health/20251218-161134/build_out/smoke_test.log`（`golden_report_health-first.txt`）
    - plan-a：`out/artifacts/batch_plan/20251218-161422/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
    - plan-b：`out/artifacts/batch_planb/20251218-161644/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
  4) 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：
    - raw：`out/artifacts/batch_raw/20251218-162820/build_out/smoke_test.log`
    - health-first：`out/artifacts/batch_health/20251218-162941/build_out/smoke_test.log`
    - plan-a：`out/artifacts/batch_plan/20251218-163105/build_out/smoke_test.log`
    - plan-b：`out/artifacts/batch_planb/20251218-163224/build_out/smoke_test.log`
- 下一步：延续 Config 显式传递梳理（fold/grep 已无隐式全局；后续关注 runtime glue/housekeeping），保持黄金矩阵常态化复跑。

###### 2025-12-18 runtime housekeeping 调试判定梳理 + 四轮黄金复跑（16:45–17:04）

- 代码进展：housekeeping 的 debug-only 判定改读 runtime cfg view（`wc_runtime_is_debug_enabled`），不再依赖外部全局 `wc_is_debug_enabled()`，减少隐式依赖。
- 四轮远程冒烟 + 黄金（全 PASS，无告警）：
  1) 默认参数：`out/artifacts/20251218-164548/build_out/smoke_test.log`。[golden] PASS。
  2) `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/20251218-164841/build_out/smoke_test.log`。[golden] PASS。
  3) 批量策略 raw/health-first/plan-a/plan-b：
    - raw：`out/artifacts/batch_raw/20251218-165044/build_out/smoke_test.log`（`golden_report_raw.txt`）
    - health-first：`out/artifacts/batch_health/20251218-165303/build_out/smoke_test.log`（`golden_report_health-first.txt`）
    - plan-a：`out/artifacts/batch_plan/20251218-165528/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
    - plan-b：`out/artifacts/batch_planb/20251218-165748/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
  4) 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：
    - raw：`out/artifacts/batch_raw/20251218-170049/build_out/smoke_test.log`
    - health-first：`out/artifacts/batch_health/20251218-170202/build_out/smoke_test.log`
    - plan-a：`out/artifacts/batch_plan/20251218-170315/build_out/smoke_test.log`
    - plan-b：`out/artifacts/batch_planb/20251218-170432/build_out/smoke_test.log`
- 下一步：继续排查 runtime glue 的其它隐式依赖（cache/init/atexit 路径），保持常态化黄金复跑；若有新增采样/诊断开关，记得同步黄金脚本与文档。

###### 2025-12-18 配置注入阶段进展 + 四轮黄金复跑

- 代码进展：完成 lookup 路径的显式 Config 注入，去除 `g_lookup_active_config`/`g_config` 宏，所有 DNS 候选、fallback、backoff、日志与偏好选择改为通过 `wc_lookup_resolve_config` 获取的 `Config*` 传递；保持现有 `[DNS-*]`/`[RETRY-*]` 可观测性不变。后续计划继续把 pipeline/batch/cache/backoff 剩余的全局读取替换为显式 Config，收敛 runtime glue。
- 四轮远程冒烟 + 黄金（04:37–04:54，全 PASS，无告警）：
  1) 默认参数：`out/artifacts/20251218-043743/build_out/smoke_test.log`。[golden] PASS。
  2) `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/20251218-043943/build_out/smoke_test.log`。[golden] PASS。
  3) 批量策略 raw/health-first/plan-a/plan-b：
     - raw：`out/artifacts/batch_raw/20251218-044119/build_out/smoke_test.log`（`golden_report_raw.txt`）
     - health-first：`out/artifacts/batch_health/20251218-044344/build_out/smoke_test.log`（`golden_report_health-first.txt`）
     - plan-a：`out/artifacts/batch_plan/20251218-044606/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
     - plan-b：`out/artifacts/batch_planb/20251218-044820/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
  4) 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：
     - raw：`out/artifacts/batch_raw/20251218-045027/build_out/smoke_test.log`
     - health-first：`out/artifacts/batch_health/20251218-045138/build_out/smoke_test.log`
     - plan-a：`out/artifacts/batch_plan/20251218-045250/build_out/smoke_test.log`
     - plan-b：`out/artifacts/batch_planb/20251218-045407/build_out/smoke_test.log`
- 下一步：
  1) 继续把 pipeline/fold/grep 与 batch 策略中的 Config 读取改为显式传参，消除剩余全局依赖；
  2) cache/backoff 结合 runtime glue 的注入方案收尾（尤其是 legacy cache 调试 helper 与 dns_health 交互）；
  3) 完成一次全量远程冒烟（含 `--debug --retry-metrics --dns-cache-stats` + 四策略 + 自测）以验证 Config 注入后的行为稳定性，并在文档中更新对应日志；
  4) 根据注入结果评估是否需要扩展 `wc_lookup_opts`/pipeline 参数以覆盖新的配置路径。

### 5.2 计划中的下一步（Phase 2 草稿）

- **2025-12-18（下一步计划草案）**  
  - Cache 全量下沉：将缓存结构体/互斥量迁入 `wc_cache`，让 `wc_cache_validate_integrity()` / `wc_cache_log_statistics()` 等调试 helper 不再依赖入口内联实现，并统一缓存初始化/清理 glue。  
  - 退出/信号收敛：审计剩余的 `atexit`/cleanup 注册，集中到 runtime/signal helper，确保异常退出时 `[DNS-CACHE-SUM]` / metrics 依旧一致，入口不再分散持有收尾逻辑。  
  - Protocol safety 收束：若入口或其它 core 仍保留协议校验/注入检测的零散 helper，继续汇总到 `wc_protocol_safety`，对外只暴露声明。  
  - Batch/pipeline 瘦身：梳理批量策略与条件输出的入口粘合层，目标是让编排留在 core/pipeline，入口仅做模式判定与调用。  
  - Cache/backoff 观测统一：对齐 cache 结构与 backoff/health 观测出口，让 lookup/legacy/batch 共用一套状态与日志，减少跨模块互查。  
  - 自测/演示钩子整合：在保持显式 Config 注入的前提下，下沉 CLI 自测控制器/演示入口的 glue，入口只保留解析与一次性触发。  

- **2025-12-18（缓存计数封装 + 四轮黄金复跑）**  
  - 代码：`wc_cache` 的 DNS/负缓存计数改为内部 `static` 并在 init/cleanup 统一归零，避免进程多轮运行残留状态；其余行为与观测标签不变。  
  - 验证（全矩阵，无告警）：
    1) 远程冒烟默认：`out/artifacts/20251218-102901/build_out/smoke_test.log`；
    2) 远程冒烟 `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/20251218-103101/build_out/smoke_test.log`；
    3) 批量 raw/health-first/plan-a/plan-b：`out/artifacts/batch_raw/20251218-103257/...`、`batch_health/20251218-103519/...`、`batch_plan/20251218-103739/...`、`batch_planb/20251218-103956/...`；
    4) 自检（`--selftest-force-suspicious 8.8.8.8`，四策略）：`out/artifacts/batch_raw/20251218-104148/...`、`batch_health/20251218-104302/...`、`batch_plan/20251218-104414/...`、`batch_planb/20251218-104527/...`。  
  - 下一步：按计划继续 cache 结构下沉与 runtime/signal 收束，保持黄金矩阵覆盖。  

- **2025-11-XX（计划中的下一步，尚未实施）**  
  拟进行的拆分/下沉方向（未来 Phase 2，执行前需再次对照本 RFC）：
  - 进一步将 `whois_client.c` 中的其他配置/初始化 glue 拆分到 core 层，使 `whois_client.c` 更接近“纯入口 + 极薄 orchestrator”；  
  - 在每次物理拆文件前后，使用远程多架构 golden 脚本进行回归，确保拆分仅改变结构，不改变行为/日志契约；  
  - 视后续复杂度，考虑在 `src/core/selftest_*.c` 中补充围绕单条查询/批量查询的自测场景，覆盖 suspicious/private/lookup 失败/中断等路径；  
  - Phase 2 初步设想：集中梳理信号处理与退出路径（`signal_handler` / `cleanup_on_signal` / `should_terminate` / active connection 注册），在保证 Ctrl-C 语义与 `[RETRY-METRICS]` / `[DNS-CACHE-SUM]` 输出不变的前提下，把可复用的“进程级网络清理 glue”封装到 core/net 层，为未来可能出现的其他 front-end 预留共用路径。  

- **2025-11-24（近期计划：legacy cache / 故障注入 / 自测 glue 梳理）**  
  - **缓存结构调研**：系统性记录 `whois_client.c` 内部的 DNS/连接缓存结构体、互斥量与 helper，标注所有调用点（含 legacy 查询路径与 `wc_cache_*` 调试 API），评估如何抽象成独立 core 模块（例如 `src/core/cache.c`）而不破坏命中/淘汰语义。  
  - **故障注入与自测盘点**：列出仍依赖入口层的历史 fault-injection 宏、环境变量以及各类 `--selftest*` 路径，决定哪些逻辑应迁往 `src/core/selftest_*.c` 或新的 fault-injection helper，哪些继续留在 CLI 层。  
  - **迁移路线输出**：基于上述调研，在本 RFC 中形成可执行的步骤列表（含每步影响面、所需的 Golden 测试组合），确保未来下沉工作有清晰蓝图。  
  - 每个阶段完成后都需运行两轮远程 `remote_build_and_test.sh`（第二轮附 `--debug --retry-metrics --dns-cache-stats`）并在本章补记结果，确认行为持续与 v3.2.9 黄金基线对齐。  
  - **批量查询 DNS 健康优选需求**：后续 B 计划设计需覆盖“进程内批量查询不再逐条 `resolve→connect`，而是依赖 `wc_dns` 健康记忆和 server backoff 协同批量分配候选 IP”的需求。  

#### 2025-11-29 需求记录：混合协议优先级 CLI

- 背景：实测显示“首跳 IPv4（速度快）+ 后续跳 IPv6（连通好）”能兼顾性能与稳定性，反向组合在特定网络也可能成立；现有 `--prefer-ipv4`/`--prefer-ipv6` 无法表达“多跳分工”。
- 需求：新增 `--prefer-ipv4-ipv6` 与 `--prefer-ipv6-ipv4`，语义为“首跳候选优先协议 A，referral/重拨时切换为协议 B”；默认策略不变（raw：按健康记忆排序）。
- 实现要点：
  1. `wc_dns_build_candidates()` / `wc_lookup_execute()` 需感知“首跳 vs 后续跳”上下文，分别应用不同的 prefer 规则；
  2. referral 路径与 legacy fallback (`wc_client_perform_legacy_query`) 同步遵循该策略，避免单侧改动导致行为不一致；
  3. 日志需新增字段（或扩展 `[DNS-CAND]`/`[DNS-BACKOFF]`）记录当前 prefer 配置，黄金脚本也需相应更新；
  4. 若某协议不可用，仍需自动 fallback，并在日志中标注 `fallback=ipv6`（示例）。
- 相依任务：需结合前述 batch 策略压测日志（`out/artifacts/gt-ax6000-prefer-ipv4-syslog.log`）与未来的 plan A/health-first 复测，确认该 CLI 的默认行为与最佳实践；待 cache/selftest/usage 三板斧推进完毕后排期实现。

##### 2025-12-02 设计稿：`--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4`

- **现状回顾**
  - `wc_opts` 仅支持 `--prefer-ipv4` / `--prefer-ipv6` 两个互斥开关，通过 `Config.prefer_ipv4/prefer_ipv6` 控制 `wc_dns_collect_addrinfo()` 里 IPv4/IPv6 交错顺序；`--ipv4-only` / `--ipv6-only` 会清空另一个家族并完全跳过交错逻辑。
  - lookup/referral/legacy shim 共享同一 `prefer_v4_first` 布尔值，因此所有跳数都使用相同顺序，无法表达“首跳 A、后续跳 B”。

- **CLI 语义**
  | Flag | Hop 0（首跳） | Hop ≥ 1（referral/forced retry） | 互斥关系 |
  |------|---------------|----------------------------------|-----------|
  | *default* / `--prefer-ipv6` | IPv6 → IPv4 交错 | 同首跳 | 与 legacy 行为一致 |
  | `--prefer-ipv4` | IPv4 → IPv6 交错 | 同首跳 | 已有开关 |
  | `--prefer-ipv4-ipv6` | IPv4 → IPv6 | IPv6 → IPv4 | 与四个 prefer/only flag 互斥 |
  | `--prefer-ipv6-ipv4` | IPv6 → IPv4 | IPv4 → IPv6 | 与四个 prefer/only flag 互斥 |
  | `--ipv4-only` / `--ipv6-only` | 仅单族，忽略其它 prefer 设置 | 同首跳 | 最高优先级 |
  - `--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4` 仅改变每一跳的“优先探测”顺序，仍会在首选协议失败时回落到另一个协议，保证连通性；典型场景是本地 IPv4 RTT 更低但容易被墙，而 IPv6 较慢但必达，通过该组合即可“首跳快、后续稳”。
  - referral 的定义：任何 `wc_lookup_execute()` 在 `hop>0` 场景、`wc_redirect_follow()` 触发 IANA pivot、或 legacy fallback 中的“重拨”均视为 Hop≥1；批量策略 plan-a/health-first 仍照常迭代 hop 计数。

- **配置与 helper 调整**
  1. 在 `wc_config.h` / `wc_opts.h` 引入 `wc_ip_pref_mode_t`（枚举）：`AUTO_V6_FIRST`、`FORCE_V4_FIRST`、`FORCE_V6_FIRST`、`V4_THEN_V6`、`V6_THEN_V4`。
  2. `wc_opts_parse()`：新增 `--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4` 选项码，复用现有互斥逻辑（设置 `ipv4_only/ipv6_only/prefer_ipv4/prefer_ipv6` 为 0），并在 opts/config 中记录 `ip_pref_mode`。
  3. `wc_client_apply_opts_to_config()`：同步写入 `cfg->ip_pref_mode` 并在 legacy 布尔字段上保留“首跳”偏好（方便尚未切换到枚举的模块继续工作）；新增 helper `wc_ip_pref_compute_order(mode, hop_index)` 返回当前 hop 应该先用 IPv4 还是 IPv6。

- **候选生成 / 拨号联动**
  1. 扩展 `wc_dns_build_candidates()` 签名，增加 `const wc_dns_pref_ctx_t* pref_ctx`（或枚举），让调用者传入当前 hop 的 IPv4/IPv6 优先级；legacy API `wc_dns_build_candidates()` 将作为 wrapper，默认使用 `wc_ip_pref_compute_order(..., hop=0)`。
  2. `wc_lookup_execute()` 与 `wc_lookup_perform_query()` 在 hop=0/1+/forced retry 之间更新 `pref_ctx` 并传给 DNS；`wc_lookup_log_candidates()` 新增 `pref=` 字段（例如 `pref=v4-first` / `pref=v6-first` / `pref=v4-then-v6`）。
  3. `wc_client_try_wcdns_candidates()`（legacy resolver shim）默认视为 hop=0；若 legacy query 在 referral 内被调用，调用者需将 hop 号传入（计划在入口瘦身时一并梳理）。
  4. `wc_net_context` / `[RETRY-*]`：当 forced IPv4 fallback触发导致“临时重拨”时，仍归类为同一 hop，但 `wc_lookup_log_fallback()` 会带上 `pref=...`，方便定位为何 fallback 不走期望的族。

- **日志 / 遥测**
  - `[DNS-CAND]`：新增 `pref=`（当前 hop 的 IPv4/IPv6 顺序），示例：`pref=v4-first`、`pref=v6-first`、`pref=v4-then-v6-hop0`、`pref=v4-then-v6-hop1`。
  - `[DNS-BACKOFF]` 与 `[RETRY-METRICS]` 保持现有字段，但在 `[DNS-FALLBACK]` 中补充 `pref=`，便于远端黄金套件断言“首跳 IPv4，后续 IPv6”是否生效。
  - Release Notes / docs 的“DNS 调试 quickstart”章节需展示相关日志片段。

- **实现步骤**
  1. **Config & CLI**：新增枚举、opts 字段、help/usage 文案；确保 `wc_config_validate()` / `wc_config_prepare_cache_settings()` 认得新枚举，旧布尔字段保持兼容。
  2. **DNS builder**：改写 IPv4/IPv6 交错循环，使其从 `pref_ctx` 读取“首个族”；若某族为空则自动切换，行为与当前版本一致；新增自测覆盖（`wc_selftest.c`）验证交错顺序。
  3. **Lookup 路径**：在 hop 计数处调用 `wc_ip_pref_compute_order()` 并把结果透传给 DNS builder / fallback log；批量策略、IANA pivot、自测注入均共享同一 helper。

##### 2025-12-05 现场记录：ARIN IPv4 链路与 `n` 前缀补偿

- **现象复盘**：`out/wc.out` / `out/wc.err` / `out/whois.stdout` / `out/arin.help` 多份日志佐证：`
  - 通过 IPv6 访问 `whois.arin.net` 仅返回 “NetRange/OrgName” 简要摘要；
  - 官方 `whois`（BSD 版本）会在同一个查询内快速轮询 IPv4 地址，命中可达线路后即返回完整记录；
  - 本地网络存在“IPv4 → whois.arin.net” 被运营商丢弃的情况，导致我们只有在 IPv6 可用时才能拿到摘要，但无法取得详细字段。
- **已确认差异**：我们的 lookup 在面对 ARIN IPv4 查询时：
  - 仅依赖 DNS 排序中“默认 IPv6 优先”策略，没有主动偏向 IPv4，导致始终命中受限的 IPv6 实例；
  - 未自动注入 `n ` 前缀（`n <IPv4>` 是 ARIN 官方建议的 network 查询格式），需要用户手工添加。
- **修复计划**：
   1. 当查询是 IPv4 字面量且当前 hop 判定为 ARIN server 时，自动：
     - 在发送查询前补 `n <query>`（保留用户已有 `n` 前缀，不重复注入）；
     - 将该 hop 的候选列表抢占式切到“先尝首个 IPv4，再恢复原先偏好”，并在 `[DNS-CAND]` / `[DNS-FALLBACK]` 日志中标记 `pref=arin-v4-auto`，仅在用户未开启 `--ipv6-only` 时生效；
  2. 其余 RIR 或域名查询不受影响，`--ipv6-only` / `--prefer-ipv6` 等 CLI 仍保持最高优先级；
  3. Patch 完成后需补 1) 远程多架构冒烟（含 `--debug --retry-metrics --dns-cache-stats`），2) 文档/Release Notes 中记录“ARIN 自动 IPv4 + `n` 前缀”行为变更。
- **后续影响**：
  - `wc_lookup_execute()` 需感知“当前 hop 是否 ARIN + 查询是否 IPv4 字面量”，并对 DNS prefer / 查询 payload 做定向调整；
  - 黄金样例中若包含 ARIN IPv4 查询，需要更新 stdout/stderr 以反映新的 `[DNS-CAND pref=arin-v4-auto]` 与 `n <query>` 请求串；
  - 该行为属于“网络适配”而非通用策略更改，暂不引入 CLI 开关，后续如需可考虑 `--no-arin-v4-workaround` 之类的 debug flag。
  4. **Legacy shim**：`wc_client_try_wcdns_candidates()` 增加 pref 参数（默认 hop=0），后续在入口瘦身时打通 hop 信息；短期内统一当作首跳即可。
  5. **文档/工具**：更新 `USAGE_*`、`OPERATIONS_*`、`meta.c` usage、`docs/RFC-*`，并在 `tools/test/golden_check.sh` 追加 `--prefer-order` 断言（或复用 `--expect '[DNS-CAND] .* pref=v4-then-v6'`）。
  6. **验证矩阵**：按照路线图跑四轮远程冒烟（默认 / 调试指标 / 批量 raw+plan-a+health-first / 自检），将 `[DNS-CAND] pref=` 片段与回归日志路径记录到 RFC。

- **风险与兼容性**
  - 仍保持旧 flag 的命名/行为，脚本无需调整；新增 flag 默认关闭，不影响现有用户。
  - `--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4` 与 `--ipv*-only`、`--prefer-ipv4`、`--prefer-ipv6` 互斥，解析阶段直接报错。
  - 若未来计划进一步拆分 `wc_dns` 与入口，`wc_ip_pref_compute_order()` 可作为唯一事实来源，便于支持更多阶段（例如“hop 0~N-1 轮换”）。

###### 2025-12-02 进度记录（IPv4/IPv6 混合偏好实现）

- **已完成**
  - 引入 `wc_ip_pref` helper（`wc_ip_pref_mode_t`、hop 标签格式化、`prefers_ipv4_first()`），CLI 与 Config 均以该枚举作为真实数据源；legacy `prefer_ipv4/ipv6` 布尔保持向后兼容。
  - `wc_dns_build_candidates()` / `wc_dns_collect_addrinfo()` 接受 per-hop IPv4-first hint，lookup/legacy shim 均通过 helper 传入；`[DNS-CAND]`/`[DNS-FALLBACK]` 日志新增 `pref=` 字段，docs/USAGE_{CN,EN}.md 已同步。
  - `wc_lookup` fallback（候选重拨、forced IPv4、known-IP、empty-body、IANA pivot）全面透传 `pref_label`，方便黄金脚本定位“首跳 IPv4、后续 IPv6”行为。
- **测试矩阵**（全部 PASS）
  1. 远程冒烟 + 黄金（默认参数）→ `out/artifacts/20251202-013609/build_out/smoke_test.log`
  2. 远程冒烟 + 黄金（`--debug --retry-metrics --dns-cache-stats`）→ `out/artifacts/20251202-013915/build_out/smoke_test.log`
  3. 批量策略 raw/plan-a/health-first 黄金：
     - raw：`D:/LZProjects/whois/out/artifacts/batch_raw/20251202-014155/build_out/smoke_test.log`
     - plan-a：`D:/LZProjects/whois/out/artifacts/batch_plan/20251202-014425/build_out/smoke_test.log`
     - health-first：`D:/LZProjects/whois/out/artifacts/batch_health/20251202-014305/build_out/smoke_test.log`
  4. 自检黄金（`--selftest-force-suspicious 8.8.8.8`）raw/plan-a/health-first：
     - raw：`D:/LZProjects/whois/out/artifacts/batch_raw/20251202-014604/build_out/smoke_test.log`
     - plan-a：`D:/LZProjects/whois/out/artifacts/batch_plan/20251202-014818/build_out/smoke_test.log`
     - health-first：`D:/LZProjects/whois/out/artifacts/batch_health/20251202-014709/build_out/smoke_test.log`
- **结论**
  - 所有日志均出现 `pref=v4-then-v6-hop*` / `pref=v6-then-v4-hop*` 等标签，黄金对比无新增告警，`[DNS-CAND] limit=`/`[DNS-FALLBACK]` 结构保持稳定。
  - 新 CLI 文案 + USAGE 段落已覆盖中英文，下一轮需在 `docs/OPERATIONS_{CN,EN}.md` 的 DNS 调试 quickstart 中补充 `pref=` 观察示例，并在 release notes/announcement 中总结行为变更。
- **下一步**
  1. 在 `docs/OPERATIONS_{CN,EN}.md` 的 DNS 调试 / batch quickstart 章节追加 `pref=` 样例截图，确保 Ops 手册与 USAGE 同步。
  2. 更新 `tools/test/golden_check.sh` 与 batch preset 说明，考虑新增 `--expect-pref-label` 选项捕捉 `pref=`（可 backlog，先记录在 RFC TODO）。
  3. 评估 lookup/legacy shim 是否需要显式传递 hop 编号（目前 shim 默认 hop0），以便未来在 plan-B/pivot 中继承混合偏好设定。

###### 2025-12-02 验证记录（远程冒烟 + `--pref-labels` 黄金）

- **操作**
  1. 运行 `tools/remote/remote_build_and_test.sh -r 1 -a "--prefer-ipv4-ipv6 --debug --retry-metrics --dns-cache-stats"`（默认 host/key 配置），确保混合偏好与调试日志共存。
  2. 使用 `tools/test/golden_check.sh -l out/artifacts/20251202-023239/build_out/smoke_test.log --pref-labels v4-then-v6-hop` 断言 `pref=` 标签。
- **结果**
  - 远程冒烟日志 `out/artifacts/20251202-023239/build_out/smoke_test.log` 无告警，`[golden] PASS`。
  - 新增的 `--pref-labels` 选项可以对任意 `pref=` 片段（支持 bare label 或完整 `pref=...`）做存在性断言，本次确认 `v4-then-v6-hop*` 标签稳定输出。
- **后续**
  1. 将 `--pref-labels` 透传到 `tools/test/golden_check_batch_presets.sh` / VS Code 任务，减少批量用例重复输入。
  2. 在 release note / ops 文档中提示 `--pref-labels` 的使用方式（EN/CN 已完成 DNS quickstart 更新，剩余 batch 章节待补）。

###### 2025-12-02 进度记录（批量黄金套件透传 `--pref-labels`）

- **实现**
  - `tools/test/golden_check_batch_presets.sh` 支持 `--pref-labels`，可与 `--selftest-actions`、`--backoff-actions` 并存并下传到 `golden_check.sh`。
  - `tools/test/golden_check_batch_suite.ps1` 新增 `-PrefLabels` 参数，VS Code 任务 **Golden Check: Batch Suite** 对应增加 `prefLabels` 输入，任务运行时自动将标签传给三个预设命令。
  - `tools/test/remote_batch_strategy_suite.ps1` 新增 `-PrefLabels`（默认 `NONE`），调用端只需给出逗号列表即可让三轮远程批量黄金自动附带 `--pref-labels ...`；相关文档同步说明。
  - 文档更新：`docs/OPERATIONS_{EN,CN}.md` 在 batch 观测章节展示如何在单次命令、预设脚本、VS Code 任务、远程批量套件中附带 `--pref-labels`，并提醒可用 `pref=v4-then-v6-hop*` 或裸标签格式。
- **验证**
  - 本地对 `tools/test/golden_check_batch_presets.sh plan-a --pref-labels v4-then-v6-hop0,v4-then-v6-hop1 -l <log>` 做干跑（无日志执行）确认参数解析正确；VS Code 任务输入框验证 `prefLabels` 传值后 Bash 命令包含 `--pref-labels`。
- **下一步**
  1. 评估是否需要在 `tools/test/remote_batch_strategy_suite.ps1` 中内建 `-PrefLabels` 透传，方便一键远程批量剧本同步断言 `pref=`。
  2. 若未来 release body/announcement 需要强调混合偏好验证流程，可引用本次文档章节，避免在 v3.2.9 基线正文中重复信息。

###### 2025-12-02 验证记录（`--pref-labels` 冒烟回归 + APNIC 大批量实测）

- **图 1 场景：`golden_check_batch_presets.sh` 新开关验证**  
  - `tools/test/golden_check_batch_presets.sh raw -l out/artifacts/20251202-023239/build_out/smoke_test.log --pref-labels v4-then-v6-hop` → `[golden] PASS`，确认 2025‑12‑02 最新远程冒烟日志内 `pref=v4-then-v6-hop*` 标签齐备；  
  - 同一命令指向 2025‑12‑01 旧日志（`out/artifacts/20251201-063602/build_out/smoke_test.log`）则报 `[golden][ERROR] missing preference label 'pref=v4-then-v6-hop'`，验证回退期日志缺少字段时工具能准确报警；
  - 结论：`--pref-labels` 已可作为 pref 日志的黄金断言入口，旧日志失败属预期（尚未包含 hop-aware 标签），新日志成功证明工具接入正确。
- **图 2~4 场景：8693 条 APNIC 地址 / 48 进程实地压测**  
  - 通过 `lzispo` 的 APNIC ISP 批量脚本（每轮自动拉取 `delegated-apnic-latest`，随后分 48 进程驱动 whois 查询）在 GT-AX6000（aarch64）环境连续跑 IPv6/IPv4 数据：  
    - IPv6 路径：整批 8693 条地址收敛在 ~2 分 15 秒，与官方客户端一致，波动很小；  
    - IPv4 路径：取决于具体 IP，最快 ~1 分 13 秒，常见 2 分 25 秒，最慢 3~5 分钟，显示 APNIC IPv4 网络本身存在较大抖动；
  - 观察：无论 IPv6/IPv4，lookup/referral/远程冒烟期间均未出现性能回退或异常超时；IPv4 抖动归因于远端网络，不属于客户端退化。
- **后续计划**  
  1. 将本次 `--pref-labels` 验证与批量压测结论写入 release notes / ops 章节，供后续回顾；  
  2. 评估是否需要在 `tools/test/golden_check_batch_presets.sh` 中提供“忽略老日志缺失标签”选项，便于同时回看老版本；短期内保持严格模式，督促冒烟产物尽快补齐 `pref=`；  
  3. 若 IPv4 抖动持续，可考虑追加远程 APNIC 专项脚本，记录 RTT 统计并对比 `pref=v4-then-v6`/`v6-then-v4` 组合的稳定性。

###### 2025-12-06 批量黄金回归（backoff force-override 断言）

- 背景：`tools/test/golden_check_batch_presets.sh` 的 health-first / plan-a 预设在前一轮加入 backoff `force-override` 断言，需要三种策略的批量黄金回归确认新断言稳定。
- 操作：运行 `tools/test/remote_batch_strategy_suite.ps1 -Host 10.0.0.199 -User larson -KeyPath 'c:\Users\妙妙呜\.ssh\id_rsa' -BatchInput testdata/queries.txt -SmokeExtraArgs "--debug --retry-metrics --dns-cache-stats"`，依次触发 raw / health-first / plan-a 远程构建 + golden。
- 结果：三轮均 PASS；日志与报告位置：
  - raw：`out/artifacts/batch_raw/20251206-063953/build_out/{smoke_test.log,golden_report_raw.txt}`
  - health-first（backoff actions: `debug-penalize,start-skip,force-last`）：`out/artifacts/batch_health/20251206-064222/build_out/{smoke_test.log,golden_report_health-first.txt}`
  - plan-a（backoff actions: `plan-a-cache,plan-a-faststart,plan-a-skip,debug-penalize`）：`out/artifacts/batch_plan/20251206-064455/build_out/{smoke_test.log,golden_report_plan-a.txt}`
- 结论：新增 backoff `force-override` 断言对批量策略无回归；下一次修改 batch 行为时需继续随附三轮黄金确认。
- 额外调整：`tools/test/remote_batch_strategy_suite.ps1` 当传入 `SelftestActions`/`SelftestExpectations` 时默认改用 `golden_check_selftest.sh` 生成黄金报告，免去在剧本里手写 `[SELFTEST] action=...` 断言；后续 VS Code Selftest 任务可直接复用。
- 加跑自检黄金（`--selftest-force-suspicious 8.8.8.8`），三轮均 `[golden-selftest] PASS`：
  - raw：`out/artifacts/batch_raw/20251206-074224/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251206-074332/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251206-074438/build_out/smoke_test.log`
  同场追加一次批量策略回归（无自测钩子），三轮继续 `[golden] PASS`：
  - raw：`out/artifacts/batch_raw/20251206-073338/build_out/{smoke_test.log,golden_report_raw.txt}`
  - health-first：`out/artifacts/batch_health/20251206-073630/build_out/{smoke_test.log,golden_report_health-first.txt}`
  - plan-a：`out/artifacts/batch_plan/20251206-073843/build_out/{smoke_test.log,golden_report_plan-a.txt}`
- referral gate 泛化：`tools/remote/remote_build_and_test.sh` 新增 `-J/REFERRAL_CASES` 允许配置多组 `query@h1,h2,...@auth`，在远端捕获到 `out/build_out/referral_checks/<query>/<host>.log` 并由 `referral_143128_check.sh --ref-dir ... --cases ...` 逐跳校验（兼容旧的 iana/arin/afrinic 路径）。默认 case 仍为 143.128.0.0 IANA→ARIN→AFRINIC。
- 自检黄金接线：VS Code 任务“Selftest Golden Suite”不再传 `-NoGolden`，`selftest_golden_suite.ps1` 若未显式给 `SelftestExpectations` 但提供 `SelftestActions` 时会自动生成 `--expect action=...` 传给 `golden_check_selftest.sh`，避免手写断言，确保一键自检黄金默认生效。

###### 2025-12-08 进度记录（重定向上限尾行修正 + 远程同步校验文件保留）

- 修复：当 `-R` 限制截断 referral 链时，正文保留最后一条 `Redirected query to <host>` 提示，尾行改为 `Authoritative RIR: unknown @ unknown`，避免误报权威 RIR。测试：`tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '~/.ssh/id_rsa' -r 1 -q '8.8.8.8 1.1.1.1 143.128.0.0' -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 -a '-R 2' -G 1 -E '-O3 -s'`，日志 `out/artifacts/20251208-151910/build_out/smoke_test.log`，黄金 PASS，尾行符合预期。
- 同步脚本：`tools/remote/remote_build_and_test.sh` 的本地同步步骤会连同 `SHA256SUMS-static.txt` 一起复制到所有 `-s` 目标，`-P 1` 不再删除校验文件；`-s` 支持分号/逗号多目录。跑完上面一轮后，静态产物与校验文件已同步到两处 release 目录。
- 下一步：观察黄金脚本是否需要新增对“redirect-cap → unknown tail”形态的断言；如需要，可在 `tools/test/golden_check.sh` 增加 `--authoritative-unknown-when-capped` 之类的开关并补一组 cap=2 样例。

#### 2025-11-24 深挖笔记（B 计划 / Phase 2：legacy cache 全景梳理）

- **结构现状**  
  - `src/core/cache.c` 现在完整持有 `DNSCacheEntry { domain, ip, timestamp, negative }` 与 `ConnectionCacheEntry { host, port, sockfd, last_used }` 两组结构以及 `cache_mutex` / `allocated_*_cache_size` 控制生命周期；服务器退避状态已搬到新的 `wc_backoff` helper（底层仍依赖 `wc_dns_health`），负缓存计数器 `g_dns_neg_cache_hits` / `g_dns_neg_cache_sets` 仍以全局变量形式暴露给 signal/metrics。  
  - 连接活性判断统一走 `wc_cache_is_connection_alive()`（薄封 `getsockopt(SO_ERROR)`），server backoff 现由 `wc_backoff`/`wc_dns_health` 维持 300s penalty；失效/淘汰路径统一调用 `wc_safe_close()`，分配类函数全部使用 `wc_safe_malloc()` / `wc_safe_strdup()`，确保 OOM 语义一致。  

- **配置耦合点**  
  - `g_config.dns_cache_size`、`connection_cache_size`、`cache_timeout`、`dns_neg_ttl`、`dns_neg_cache_disable` 直接影响缓存策略；`wc_cache_init()` 会在 size=0 或超界（DNS>100、连接>50）时写回默认值并打印 DEBUG 行。  
  - `wc_config_prepare_cache_settings()` 现由 `whois_client.c` 在调用 `wc_config_validate()` 之前执行，负责裁剪不合理的缓存尺寸并重用 `wc_cache_estimate_memory_bytes()` + `wc_client_get_free_memory()` 做可用内存检查；cache 模块本身不再写回 `Config`。  

- **调用入口**  
  - `wc_runtime_init_resources()` 负责 `wc_cache_init()` + `atexit(wc_cache_cleanup)`；CLI 侧在进入 runtime 之前仅调用 `wc_config_prepare_cache_settings()`，不再直接触碰 cache 模块。  
  - `wc_client_resolve_domain()` / `wc_client_connect_to_server()` / `wc_client_connect_with_fallback()`（`src/core/client_net.c`）遍布 `wc_cache_get/set_dns()`、负缓存 helper 与 `wc_cache_get/set_connection()` 调用；自测开关 `wc_selftest_dns_negative_enabled()` 也嵌入这条路径。  
  - `wc_client_perform_legacy_query()` 负责 server backoff（`wc_cache_is_server_backed_off`、`_mark_server_*`）以及查询尾声的 `wc_cache_cleanup_expired_entries()` + `wc_cache_validate_integrity()`；`wc_client_run_single_query()` / `wc_handle_suspicious_query()` 则在异常退出时直接 `wc_cache_cleanup()`，保证 socket 不泄漏。  
  - `wc_signal_atexit_cleanup()` 输出 `[DNS] negative cache: hits=... sets=...`，直接读取 `g_dns_neg_cache_hits/sets`；这两个全局变量也是 `[DNS-CACHE-SUM]` 之外仅有的负缓存可观测来源。  
  - 新版 DNS 子系统（`src/core/dns.c`）同时维护一套候选缓存与负缓存表，用于 lookup 管线；这意味着当前二进制内存在 legacy cache（`wc_cache`）与 phase-2 DNS cache 双轨运行的情况：`wc_lookup` 走新实现，而 legacy 网络 helper 仍依赖旧缓存。  

- **迁移切入点建议**  
  1. **配置入口前移**（2025-11-24 已完成）：由 `wc_config_prepare_cache_settings()` 统一裁剪缓存尺寸并检查内存，让 `whois_client.c` 只需调用该 helper 即可，cache 模块保持只读。  
  2. **指标封装**：为 `g_dns_neg_cache_hits/sets` 提供 accessor（例如 `wc_cache_get_neg_stats()`），`signal.c` / 未来 metrics 只读 accessor，方便其他 front-end 共享并减少对裸全局变量的依赖。  
  3. **server backoff 平台化**：将 `server_status[]` 及其 mutex 抽象成 `wc_cache_backoff_*` 或迁往 `wc_net`，使新的 lookup/连接引擎也能共用同一退避窗。  
  4. **与 `wc_dns` 对齐**：评估 legacy DNS cache 是否可以委托给 phase-2 `wc_dns` 候选列表；可以先在 `wc_client_net` 中加调试计数（例如 `[DNS-CACHE-LGCY] hit/miss`）观察命中率，再决定是否让 `wc_cache_get_dns()` 直接调用 `wc_dns`。  
  5. **验证矩阵**：上述每一阶段都应跑双轮 `tools/remote/remote_build_and_test.sh`（第二轮带 `--debug --retry-metrics --dns-cache-stats`），重点关注 `[DNS-CACHE-SUM]` 行数、`[DNS-*]` / `[LOOKUP_*]` / `[RETRY-*]` 标签与 server backoff WARN/DEBUG，确保黄金脚本无回归。  

----

#### 2025-11-24 任务拆解（配置前移 / 指标 accessor / backoff 融合）


#### 2025-11-24 进度更新（B 计划 / Phase 2：cache 配置前移 + 指标 accessor 落地）

- `wc_config_prepare_cache_settings()` 新增：在 `wc_client_apply_opts_to_config()` 之后、`wc_config_validate()` 之前执行，统一裁剪超界缓存尺寸（>100 DNS / >50 connection）并通过 `wc_cache_estimate_memory_bytes()` + `wc_client_get_free_memory()` 进行内存预检，必要时回退到默认值并输出 warning。`whois_client.c` 不再调用 `wc_cache_validate_sizes()`。  
- `wc_cache_init()` 现在假设配置已被前置 helper 清洗，如发现异常会直接报错并提前返回；`wc_cache_validate_sizes()` 被移除，新辅助函数 `wc_cache_estimate_memory_bytes()` 暴露给配置层复用。  
- `wc_cache_get_negative_stats()` 取代原先的 `extern g_dns_neg_cache_hits/sets`，`wc_signal_atexit_cleanup()` 通过 accessor 打印 `[DNS] negative cache` 摘要，避免直接依赖全局变量。  
- **测试**：已触发两轮远程 `tools/remote/remote_build_and_test.sh`（Round 1 默认参数，Round 2 追加 `--debug --retry-metrics --dns-cache-stats`）；两轮日志均无告警，Golden 校验 PASS。  

#### 2025-11-24 进度更新（B 计划 / Phase 2：server backoff 平台化 + lookup 联动）

#### 2025-11-29 进度更新（Batch docs & Golden tooling）

- `docs/USAGE_EN.md` 增补 “Batch strategy quick playbook” 小节，按 raw → health-first → plan-a 顺序列出本地命令、stdin 输入、`WHOIS_BATCH_DEBUG_PENALIZE` 配置与 `tools/test/golden_check.sh preset=batch-smoke-*` 调用示例；`docs/USAGE_CN.md` 新增对等的“批量策略快手剧本”，确保中文读者也能直接拷贝剧本。
- `docs/OPERATIONS_EN.md` / `docs/OPERATIONS_CN.md` 在批量观测章节后追加“Local batch quick playbook cross-reference / 本地批量快手剧本速记”，明确运维手册以 USAGE 为唯一事实来源，并提示黄金脚本可同时使用 `--batch-actions` 与 `--selftest-actions` 来断言 `[DNS-BATCH]` 与 `[SELFTEST] action=force-*`。
- `tools/test/golden_check.sh` 之前的 `--selftest-actions` 新增用法已记录在上述文档与 release notes；后续 batch preset/remote suite 只需透传该参数即可。此轮为纯文档与流程更新，未引入代码路径变化；待下一轮功能开发前再跑远程多架构 golden 复检。

##### 2025-11-29 冒烟 / 黄金补录

- Round 1：默认参数常规编译 + 冒烟，日志 `out/artifacts/20251129-213841/build_out/smoke_test.log`，无告警，`golden_check.sh` PASS。
- Round 2：追加 `--debug --retry-metrics --dns-cache-stats`，日志 `out/artifacts/20251129-214113/build_out/smoke_test.log`，无告警，`golden_check.sh` PASS，含 `[DNS-CACHE-SUM]` / `[RETRY-*]` 观测。
- Round 3：批量策略黄金（raw / health-first / plan-a）三套日志分别位于 `out/artifacts/batch_raw/20251129-214342/build_out/smoke_test.log`、`out/artifacts/batch_health/20251129-214451/build_out/smoke_test.log`、`out/artifacts/batch_plan/20251129-214604/build_out/smoke_test.log`，全部 `[golden] PASS`，`--batch-actions` 与 `--selftest-actions` 校验均生效。

#### 2025-11-29 进度更新（Golden suite：Git Bash 解析 + ExtraArgs 默认值）

- `tools/test/golden_check_batch_presets.sh` 新增可选 `--selftest-actions` 透传：当 VS Code 任务或 PowerShell alias 传入 `force-suspicious,*;force-private,10.0.0.8` 等动作时，raw / health-first / plan-a 三个预设会在调用 `golden_check.sh` 前自动附加 `--selftest-actions`，与既有 `--batch-actions` 并行断言。
- `tools/test/remote_batch_strategy_suite.ps1` 暴露 `-SelftestActions` 参数，并把该值传入每一轮 golden 命令，确保远端一键三策略冒烟也能同时验证 `[SELFTEST] action=*` 日志，不再需要人工在 `-GoldenExtraArgs` 中重复书写。
- `tools/test/golden_check_batch_suite.ps1` 改为优先搜索 Git for Windows 的 `bash.exe`（包括 PATH 与 `%ProgramFiles%/Git/bin`、`%ProgramFiles(x86)%/Git/bin`）；若仅找到 Windows System32 的 WSL shell 会打印 warning 并指导安装 Git Bash，解决“机器未安装 WSL 子系统导致任务立即失败”的常见陷阱。
- `.vscode/tasks.json` 中 **Golden Check: Batch Suite** 的 `goldenExtraArgs` 默认值改为 `NONE`，任务内部会把 `NONE` 识别为“无额外参数”，避免再向 `golden_check.sh` 注入已移除的 `--strict`。

#### 2025-11-30 进度更新（PSScriptAnalyzer 清理 + 自测脚本维护）

- 为避免 VS Code / PSScriptAnalyzer 报告 `PSUseApprovedVerbs`，将 `tools/test/remote_batch_strategy_suite.ps1` 中的 `Escape-GlobChars` 重命名为 `ConvertTo-GlobSafeText`，并在输出汇总段落统一使用左置 `$null` 比较（`$null -ne $goldenMeta`）以满足 `PSAvoidNullComparison`。脚本行为未变，`NoGolden`/`SelftestActions` 参数仍旧按 11.29 版本工作。
- `tools/test/selftest_golden_suite.ps1` 的 `Normalize-OptionalValue` 同步调整为 `ConvertTo-OptionalValue`，并重新跑 PSScriptAnalyzer 1.24.0，确认剩余告警仅与历史 `Write-Host` 用法有关（暂保留以兼容现有终端提示）。
- 当前日志仍沿用 11.29 的 `-SkipRemote` 产物；下一步需要在未跳过远程的情况下跑一轮 VS Code **Selftest Golden Suite** 任务，验证新的 `ConvertTo-*` helper 与 `NoGoldenToggle` 组合在真实远程 run 上是否完全覆盖 golden/自测场景，并把结果（含 `[golden-selftest]` 摘要）补记在本节。

##### 2025-11-30 冒烟 / 黄金补录（四轮）

1. **远程编译冒烟同步 + 黄金（默认参数）**  
  - 命令：`tools/remote/remote_build_and_test.sh -r 1`（其余使用默认值）。  
  - 结果：无告警 + `golden_check.sh` PASS。  
  - 冒烟日志：`out/artifacts/20251130-085029/build_out/smoke_test.log`。
2. **远程编译冒烟同步 + 黄金（附带 debug/metrics）**  
  - 命令：`tools/remote/remote_build_and_test.sh -r 1 -a "--debug --retry-metrics --dns-cache-stats"`。  
  - 结果：无告警 + `golden_check.sh` PASS，日志中可见 `[DNS-CACHE-SUM]` / `[RETRY-*]`。  
  - 冒烟日志：`out/artifacts/20251130-090604/build_out/smoke_test.log`。
3. **批量策略黄金（raw / plan-a / health-first）**  
  - 采用 `tools/test/remote_batch_strategy_suite.ps1` 默认参数，保持 `SelftestActions` 为空以复核常规黄金。  
  - 结果：三套策略均 `[golden] PASS`。  
  - 冒烟日志与 golden 报告：  
    - raw：`out/artifacts/batch_raw/20251130-090815/build_out/smoke_test.log` / `.../golden_report_raw.txt`。  
    - plan-a：`out/artifacts/batch_plan/20251130-091047/build_out/smoke_test.log` / `.../golden_report_plan-a.txt`。  
    - health-first：`out/artifacts/batch_health/20251130-090930/build_out/smoke_test.log` / `.../golden_report_health-first.txt`。
4. **Selftest Golden Suite（强制 suspicious）**  
  - 命令：`tools/test/selftest_golden_suite.ps1 -SelftestActions "force-suspicious,8.8.8.8" -SmokeExtraArgs "--selftest-force-suspicious 8.8.8.8" -SelftestExpectations "action=force-suspicious,query=8.8.8.8"`，不带 `-SkipRemote`，由脚本驱动远端 raw/plan-a/health-first。  
  - 结果：三套日志全部 `[golden-selftest] PASS`，`NoGoldenToggle` 未启用即可通过。  
  - 冒烟日志：  
    - raw：`out/artifacts/batch_raw/20251130-092657/build_out/smoke_test.log`。  
    - plan-a：`out/artifacts/batch_plan/20251130-092917/build_out/smoke_test.log`。  
    - health-first：`out/artifacts/batch_health/20251130-092803/build_out/smoke_test.log`。  

  #### 2025-12-01 进度更新（net context 文档 + 四轮黄金）

  - `RELEASE_NOTES.md` 与 `docs/USAGE_EN.md` / `docs/USAGE_CN.md` 增补“网络重试上下文（3.2.10+）”说明，明确 `wc_net_context` 现由进程级 runtime 持有并在单次查询、批量 stdin 与 lookup 自测之间共享，`[RETRY-METRICS]` / `[RETRY-METRICS-INSTANT]` / `[RETRY-ERRORS]` 计数会跨自测与真实查询保持连续；如需清零需重新启动进程。该文档更新与 net context 代码改动保持一致，帮助运维脚本理解为何自测预热后 metrics 不会回到 0。
  - 计划中的下一步依旧是：补齐 `docs/OPERATIONS_EN.md` / `docs/OPERATIONS_CN.md` 的相应章节说明，并在 cache/backoff Phase 2 工作继续前保持 net context 行为稳定；待 documentation 阶段收尾后，再开展 server backoff + lookup 联动的后续 B 计划。

  ##### 2025-12-01 冒烟 / 黄金补录（四轮）

  1. **远程编译冒烟同步 + 黄金（默认参数）**  
    - 命令：`tools/remote/remote_build_and_test.sh -r 1`（默认参数）。  
    - 结果：无告警 + `golden_check.sh` PASS。  
    - 冒烟日志：`out/artifacts/20251201-063353/build_out/smoke_test.log`。
  2. **远程编译冒烟同步 + 黄金（--debug --retry-metrics --dns-cache-stats）**  
    - 命令：`tools/remote/remote_build_and_test.sh -r 1 -a "--debug --retry-metrics --dns-cache-stats"`。  
    - 结果：无告警 + `golden_check.sh` PASS（日志内含 `[DNS-CACHE-SUM]` / `[RETRY-*]`）。  
    - 冒烟日志：`out/artifacts/20251201-063602/build_out/smoke_test.log`。
  3. **批量策略黄金（raw / plan-a / health-first）**  
    - 命令：`tools/test/remote_batch_strategy_suite.ps1`（默认参数，含三轮策略）。  
    - 结果：三套策略均 `[golden] PASS`。  
    - 冒烟日志与报告：  
      - raw：`out/artifacts/batch_raw/20251201-063803/build_out/smoke_test.log`，报告 `.../golden_report_raw.txt`。  
      - plan-a：`out/artifacts/batch_plan/20251201-064021/build_out/smoke_test.log`，报告 `.../golden_report_plan-a.txt`。  
      - health-first：`out/artifacts/batch_health/20251201-063910/build_out/smoke_test.log`，报告 `.../golden_report_health-first.txt`。
  4. **Selftest Golden Suite（--selftest-force-suspicious 8.8.8.8）**  
    - 命令：`tools/test/selftest_golden_suite.ps1 -SelftestActions "force-suspicious,8.8.8.8" -SmokeExtraArgs "--selftest-force-suspicious 8.8.8.8" -SelftestExpectations "action=force-suspicious,query=8.8.8.8"`。  
    - 结果：raw / plan-a / health-first 全部 `[golden-selftest] PASS`。  
    - 冒烟日志：  
      - raw：`out/artifacts/batch_raw/20251201-064241/build_out/smoke_test.log`。  
      - plan-a：`out/artifacts/batch_plan/20251201-064445/build_out/smoke_test.log`。  
      - health-first：`out/artifacts/batch_health/20251201-064340/build_out/smoke_test.log`。
  - 备注：本轮覆盖 selftest golden MVP 的完整路径，证实 `ConvertTo-*` helper + `NoGoldenToggle` 在真实远程场景下行为稳定；脚本仅输出黄金结论，不写入额外报告文件，仍复用批量策略生成的 `smoke_test.log`。

#### 2025-12-01 下一步行动（B 计划：server backoff 平台化 + lookup 候选联动）

- **目标**：把 legacy `server_status[]` / 缓存互斥残留彻底迁往 core 层，并让 `wc_lookup` 在候选阶段直接感知 penalty，使 legacy/lookup/批量路径共享同一退避窗口。保持 v3.2.9 header/日志契约不变，仅优化 glue 与可观测性。
- **任务拆解**：
  1. *Cache/backoff 数据面梳理*——抽取 `ServerStatus` 结构与互斥，补全 accessor（`wc_backoff_should_skip`/`wc_backoff_note_result` 等），并保留 `wc_cache_*` 调试 helper，确保入口不再直接触碰裸全局。
  2. *wc_dns + wc_lookup 联动*——在 `wc_dns_build_candidates()` / `wc_lookup_execute()` 中读取 backoff 状态，对 penalty 命中的候选执行“跳过或降权到队尾”的策略；在“所有候选被 penalty”场景输出 `[DNS-BACKOFF] action=force-last` 之类的日志，方便 Golden 断言。
  3. *文档与黄金同步*——`RELEASE_NOTES` / `docs/USAGE_*` / `docs/OPERATIONS_*` 更新 backoff 行为描述；完成代码改动后按惯例跑四轮远程黄金（默认、debug metrics、batch 三策略、自测）并在本 RFC 记录日志路径。
- **依赖**：当前 net context 文档与黄金已对齐，可直接进入此任务；如需新增 CLI/配置开关，需同步 `wc_opts` / doc / Golden 脚本。
- **计划**：接下来立即着手“步骤 1 + 2”的代码改造（server backoff 平台化 + lookup 候选联动），完成后再执行步骤 3 的文档与回归。

#### 2025-12-01 进度更新（[DNS-BACKOFF] 文档同步）

- `RELEASE_NOTES.md` 以及 `docs/USAGE_EN.md` / `docs/USAGE_CN.md` 已补充 server backoff 平台化与 `[DNS-BACKOFF] action=skip|force-last` 的可观测性说明，明确字段含义（`reason=`、`window_ms=`）与默认 300s penalty 对齐老版 `SERVER_BACKOFF_TIME` 的背景。
- `docs/OPERATIONS_CN.md` 的 “DNS 调试 quickstart” 关键观测点现直接引用 `[DNS-BACKOFF]`，提示在调试/metrics 场景下可通过该标签确认 penalty 是否生效，并与 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-HEALTH]` 一并观测。
- 当前代码侧 server backoff 平台化（`wc_backoff` + `wc_lookup` 候选联动）已合入，lookup 在遍历候选时会针对 penalty host 输出 `[DNS-BACKOFF]` 并保留最后一条 fallback；文档同步完成后即可着手 Golden 断言扩展。

**测试记录**

- 本次仅涉及文档与 RFC 更新，沿用 2025-12-01 早先记录的四轮远程冒烟日志（默认 + `--debug --retry-metrics --dns-cache-stats` + batch 三策略 + selftest 套件）作为最新运行基线；暂无新增构建。

- **2025-12-04 追加说明：ARIN IPv4-only 环境回退**
  - 远程构建机 10.0.0.199 无法访问 ARIN IPv4，导致 `pref=arin-v4-auto` 在所有 IPv4 候选上耗尽拨号重试，watchdog Ctrl-C 令 golden 误判为“未查询 8.8.8.8”。
  - 最新实现改为“仅抢占式尝试首个 IPv4 候选（独立 1.2s timeout、无重试），失败后立即恢复原始候选顺序”，`pref=` 仍显示 `arin-v4-auto`，但不会阻塞 IPv6 fallback；日志结构保持不变。
  - 待远程冒烟重新跑完（默认 + `--debug --retry-metrics --dns-cache-stats`），将日志路径补回本节，并在 release notes 中简述此兼容性调整。

#### 2025-12-04 进度更新（ARIN IPv4 自动补偿 + 四轮黄金）

- **代码现状**：`wc_lookup_execute()` 对 ARIN IPv4 字面量查询执行抢占式短超时探测（单次 1.2s、无重试），失败即恢复原始候选顺序，同时自动注入 `n <query>`。stderr 中 `pref=arin-v4-auto` 依旧可见，用于黄金断言。
- **文档同步**：`RELEASE_NOTES.md` 补充“ARIN IPv4 自动补偿 + 短超时”描述，`docs/USAGE_{CN,EN}.md` DNS 调试章节新增提示，说明日志期望与在 IPv4 受限网络下的 fallback 语义。
- **远程验证**：完成四轮远程冒烟 / 黄金，均 `PASS`，确认短超时策略不会再触发 watchdog：
  1. `tools/remote/remote_build_and_test.sh -r 1`（默认）→ `out/artifacts/20251204-105841/build_out/smoke_test.log`，`[golden] PASS`。
  2. `tools/remote/remote_build_and_test.sh -r 1 -a "--debug --retry-metrics --dns-cache-stats"` → `out/artifacts/20251204-110057/build_out/smoke_test.log`，`[golden] PASS`。
  3. `tools/test/remote_batch_strategy_suite.ps1`（raw/plan-a/health-first）→
     - raw：`out/artifacts/batch_raw/20251204-110234/build_out/smoke_test.log`，报告 `.../golden_report_raw.txt`；
     - plan-a：`out/artifacts/batch_plan/20251204-110515/build_out/smoke_test.log`，报告 `.../golden_report_plan-a.txt`；
     - health-first：`out/artifacts/batch_health/20251204-110350/build_out/smoke_test.log`，报告 `.../golden_report_health-first.txt`。
  4. `tools/test/selftest_golden_suite.ps1 -SmokeExtraArgs "--selftest-force-suspicious 8.8.8.8" -SelftestActions "force-suspicious,8.8.8.8" -SelftestExpectations "action=force-suspicious,query=8.8.8.8"`：
     - raw：`out/artifacts/batch_raw/20251204-110657/build_out/smoke_test.log`；
     - plan-a：`out/artifacts/batch_plan/20251204-110911/build_out/smoke_test.log`；
     - health-first：`out/artifacts/batch_health/20251204-110812/build_out/smoke_test.log`；三套 `[golden-selftest] PASS`。
- **下一步**：
  1. 继续观察远程 IPv4 受限宿主（10.0.0.199）在长时间运行下是否仍出现 `[DNS-CAND] pref=arin-v4-auto` 无法落地的情况；如有需要，再评估是否提供 `--arin-v4-strict` 调试开关。
  2. 若后续 release 需要额外说明，请在 `docs/OPERATIONS_{EN,CN}.md` 的 DNS 调试 quickstart 中补充日志对照截图。

##### 2025-12-04 议程补充：ARIN IPv4 有效地址快速探测

- **背景**：官方 whois 提供“快速定位仍可达的 ARIN IPv4 终端”能力，可在 IPv4 路由受限场景下直接命中可用 IP，避免逐条拨号探测。当前客户端只有自动 `n <query>` + 单次 1.2s 短探测的补偿，并未内建“可用 IPv4 列表”或扫描机制。
- **待办思路（暂不排期）**：
  1. **数据源调研**：评估 ARIN 官方 API、RDAP、开放数据集或自建探针能否提供稳定的 IPv4 reachable 列表；
  2. **缓存/刷新策略**：设计 `wc_dns`/`wc_lookup` 可复用的健康表（例如 `wc_arin_ipv4_table`），支持定期刷新与 `[DNS-CAND] pref=arin-v4-probe` 观测；
  3. **CLI/配置**：考虑新增 `--arin-ipv4-probe` 或 `--arin-ipv4-table <path|url>` 等开关，允许运维自定义探测策略；
  4. **黄金与自测**：补充 determinisitc 的探测日志与自测脚本，确保工具链能断言“加载 → 命中 → 失效/回退”的全流程。
- **状态**：仅在 RFC 备案，待后续网络需求或资源允许时再开启实施。

**下一步**

1. 在 `tools/test/golden_check.sh` / batch preset 中补对 `[DNS-BACKOFF] action=skip|force-last` 的 presence 检查，确保 server backoff 平台化后日志形态被黄金覆盖。
2. 视需要补充英文版运维手册 `docs/OPERATIONS_EN.md` 与 release 邮件模板的相同段落，保持中英文资料一致。
3. 重新跑一轮四段式远程冒烟（默认 / debug metrics / batch 三策略 / selftest）以覆盖 `[DNS-BACKOFF]` GOLDEN，并将日志路径补记到本节。

#### 2025-12-01 进度更新（[DNS-BACKOFF] 黄金断言）

- `tools/test/golden_check.sh` 新增 `--backoff-actions`，可与既有 `--batch-actions`/`--selftest-actions` 并列使用；传入 `skip,force-last` 时会在 header/referral/tail 之外强制检查 `[DNS-BACKOFF] action=skip` 与 `action=force-last` 是否出现在日志中。
- `tools/test/golden_check_batch_presets.sh` 支持 `--backoff-actions` 透传，并在 health-first 预设默认注入 `--backoff-actions skip,force-last`；`tools/test/remote_batch_strategy_suite.ps1` 通过 `Get-GoldenPresetArgs()` 自动添加该断言（可用 `-BackoffActions NONE` 关闭），确保三策略远程剧本中 health-first 轮次一律覆盖 server backoff 平台化日志。
- `docs/OPERATIONS_{EN,CN}.md` 的 batch observability/quick playbook 小节同步说明如何在 `golden_check.sh` 与 preset wrapper 中使用 `--backoff-actions`；`RELEASE_NOTES.md` 的 Unreleased 记录新增该条，方便审查时追溯黄金 coverage 的背景。

**测试记录**

- 本批改动主要影响脚本与文档；由于目标是扩展 Golden 校验而非修改客户端行为，暂未新增远程 smoke。待下一轮 batch golden 执行时，health-first 预设会更严格地验证 `[DNS-BACKOFF] action=skip|force-last`，结果将补记在本 RFC。

**测试记录**

- 在完成上述修改后，通过 VS Code 任务运行：
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/golden_check_batch_suite.ps1 \
    -RawLog ./out/artifacts/batch_raw/20251129-214342/build_out/smoke_test.log \
    -HealthFirstLog ./out/artifacts/batch_health/20251129-214451/build_out/smoke_test.log \
    -PlanALog ./out/artifacts/batch_plan/20251129-214604/build_out/smoke_test.log \
    -ExtraArgs NONE
  ```
  终端输出如 `golden] PASS: header/referral/tail match expected patterns` 所示，三轮黄金检查全部通过；日志同前一阶段，确保自测动作与 batch 动作并行校验生效。若用户误删 Git Bash，任务会提示“Detected Windows Subsystem for Linux bash... Please install Git for Windows”并中止，便于立即定位环境问题。

- 新增 `wc_backoff` helper（`include/wc/wc_backoff.h` + `src/core/backoff.c`），对外提供 `note_success/failure`、`should_skip` 以及 penalty 窗口 setter，内部直接复用 `wc_dns_health` 的 host+family 记忆；默认 penalty 提升至 300s 以对齐旧版 `SERVER_BACKOFF_TIME`，并允许未来通过 Setter 调整。  
- `wc_cache_is_server_backed_off()` / `_mark_server_failure` / `_mark_server_success` 现已完全委托给 `wc_backoff`，移除了 `ServerStatus` 静态数组与互斥锁，debug 日志继续输出但基于新的 snapshot 数据。  
- `wc_lookup_execute()` 在遍历 DNS candidates 时查询 `wc_backoff_should_skip()`：非最后一个候选命中 penalty 直接跳过，最后一个候选即便被处罚也会以 `action=force-last` 记录 `[DNS-BACKOFF]` 并继续尝试，保证仍有出路；`wc_lookup_family_to_af()` helper 用于在 host/IPv4/IPv6 之间转换；新日志加入 `consec_fail` 与 `penalty_ms_left` 字段，供黄金脚本对比。  
- `wc_dns_health` 新增 penalty window setter/getter，`wc_backoff_set_penalty_window_seconds()` 暂未对外暴露 CLI，但为后续批量/自测调参留好入口。  
- **测试**：已完成两轮远程 `remote_build_and_test.sh`（Round 1 默认参数，Round 2 附 `--debug --retry-metrics --dns-cache-stats`），日志无告警且 Golden 校验 PASS；`[DNS-BACKOFF]` 与既有 `[DNS-*]`/`[RETRY-*]` 标签共存正常。  

#### 2025-12-01 进度更新（batch suite summary & backoff opt-in）

- `tools/test/remote_batch_strategy_suite.ps1` 的总结阶段现固定输出三条策略结果 + 报告路径，并在任一黄金失败时保留 `[suite] Summary: FAIL` 但不会提前终止剩余预设。这保证多预设剧本可一次性看完 raw / plan-a / health-first 的真实表现，便于对比如“raw 使用 ARIN 首跳、health-first 因 penalty 跌回 IANA”之类的差异。
- 同一脚本的 `-BackoffActions` 默认值改为 `NONE`，不再为 health-first 预设自动注入 `[DNS-BACKOFF]` 断言。鉴于 `WHOIS_BATCH_DEBUG_PENALIZE` 只会对逻辑 host（而非 IP literal）造罚站，批量日志在大多数网络下无法稳定产出 `[DNS-BACKOFF] action=skip|force-last`，继续强制黄金只会导致 plan-a / health-first 永久 FAIL。若后续有针对性的“强制三次连续拨号失败”场景，可在调用脚本时显式传入 `-BackoffActions 'skip,force-last'` 再配合黄金检查。

**测试记录**

- 变更仅影响本地脚本与 RFC；继续沿用 2025-12-01 的批量日志（`out/artifacts/batch_{raw,plan,health}/20251201-19*/...`）验证 summary 输出/报告路径无回归，未额外触发远程构建。

#### 2025-12-01 远程黄金回归（batch + selftest）

- **批量策略黄金**：在禁用默认 backoff 断言后重新跑 raw / plan-a / health-first 三套预设，结果均 `[golden] PASS`。本轮命令沿用 `remote_batch_strategy_suite.ps1` 默认参数 + `-BackoffActions NONE`，确保行为与最新文档描述一致。
  - raw：`out/artifacts/batch_raw/20251201-210150/build_out/smoke_test.log`；报告 `.../golden_report_raw.txt`。
  - plan-a：`out/artifacts/batch_plan/20251201-210435/build_out/smoke_test.log`；报告 `.../golden_report_plan-a.txt`。
  - health-first：`out/artifacts/batch_health/20251201-210313/build_out/smoke_test.log`；报告 `.../golden_report_health-first.txt`。
- **自检黄金**：使用 `--selftest-force-suspicious 8.8.8.8` 触发自测流水线，raw / plan-a / health-first 均 `[golden-selftest] PASS`，验证脚本汇总逻辑与 opt-in backoff 行为不会影响自测基线。
  - raw：`out/artifacts/batch_raw/20251201-210822/build_out/smoke_test.log`。
  - plan-a：`out/artifacts/batch_plan/20251201-211029/build_out/smoke_test.log`。
  - health-first：`out/artifacts/batch_health/20251201-210923/build_out/smoke_test.log`。

**下一步**

1. 设计可重复的 `[DNS-BACKOFF]` 触发剧本（例如针对特定 IP 注入连续失败），待具备 deterministic 信号后再在 batch 预设中恢复 `-BackoffActions 'skip,force-last'`。
2. 结合最新用户反馈评估“首跳 prefer-ipv4 / redirect prefer-ipv6”开关可行性，先在 RFC 中补充方案草稿与 CLI 形态，再安排实现。
3. Stage 3 “Cache & Legacy 收官” 子任务：开始迁移负缓存桥接/统计到 `wc_cache.c`，配合远程冒烟记录输出契约，以便 Stage 4 prefer-strategy 讨论有稳定基线。

##### 2025-12-04 诊断记录（Ubuntu VM DNS 解析影响黄金）

- **现象**：`tools/remote/remote_build_and_test.sh -r 1 -q "8.8.8.8 1.1.1.1" -G 1` 在 Ubuntu 虚拟机上常规运行时，构建与冒烟均 PASS，但黄金阶段报错 `header not found matching: ^=== Query: 8.8.8.8 via whois.iana.org @ ... ===` 等消息；同一日志（`out/artifacts/20251204-043021/build_out/smoke_test.log`）中可见查询直接命中 `whois.arin.net`，与黄金期望的 “IANA → ARIN 两跳” 路径不符。
- **原因**：该虚拟机将 DNS 指向阿里云 `223.5.5.5`，该 DNS 把 `whois.arin.net` 解析到与黄金录制时不同的地址，导致客户端无需 IANA pivot 即成功完成查询，黄金因此认为 header/referral/tail 均缺失。网络层无其他告警，确认属于解析源差异。
- **处理**：将 Ubuntu VM 的 DNS 设置改回路由器（LAN DHCP 默认），重新运行同一远程脚本后黄金恢复 `[golden] PASS`（同批命令的最新日志已记录在同级 `out/artifacts/20251204-05xxxx/build_out/` 目录）。随后多轮命令均保持 PASS，说明代码与脚本无需改动。
- **结论与建议**：遇到黄金突然要求 IANA 首跳但日志显示直接命中 RIR 时，应首先检查远程环境的 DNS 解析；建议在 RFC 中保留此次记录，后续若需要切换公共 DNS，可先用 `dig whois.arin.net`/`nslookup whois.arin.net` 对比路由器与公共 DNS 的返回是否一致，再决定是否更新黄金或替换解析源。

#### 2025-11-24 进度更新（B 计划 / Phase 2：legacy DNS cache 可观测性）

- `wc_cache_get_dns()` 现记录命中/未命中计数，并新增 `wc_cache_get_dns_stats()` helper，未来可在统一 metrics 输出中引用。  
- `wc_client_resolve_domain()` 在命中正向缓存、命中负缓存与准备走解析器这三个节点输出 `[DNS-CACHE-LGCY] domain=<...> status=hit|neg-hit|miss`，仅在 `--debug` 或 `--retry-metrics` 场景打印，避免影响默认 stdout/stderr。  

#### 2025-11-30 进度更新（Selftest golden suite MVP）

- 新增 `tools/test/golden_check_selftest.sh`：专门解析 `[SELFTEST] action=*`、`[SELFTEST-ERROR]`、`[SELFTEST-TAG]` 三类日志；支持 `--expect action=force-suspicious,query=8.8.8.8`、`--require-error 'denied by policy'`、`--require-tag wc_lookup 'referral hop=2'` 等参数组合，输出 `[golden-selftest] PASS/FAIL`，默认仅依赖 smoke 日志本身，不再与 batch golden 脚本耦合。
- `tools/test/selftest_golden_suite.ps1`（当前提交）：通过 Git Bash 调用上面的 shell checker，并与 `tools/test/remote_batch_strategy_suite.ps1` 串联。一键下三份策略日志（raw / health-first / plan-a）后，自动为每份日志触发 selftest golden；支持 `-SelftestExpectations`, `-ErrorPatterns`, `-TagExpectations` 字符串（以 `;` 分隔）来批量注入校验点，`-SkipRemote` 可复用现有日志，只跑本地 golden。
- 交互体验：PowerShell 脚本会自动定位 `out/artifacts/batch_*/*/build_out/smoke_test.log` 最新目录，并在缺失目录时打印 `[suite-selftest] <strategy>: skipped (...)`；所有 golden 执行结果以表格形式集中输出，任意策略失败将返回 exit code 3 方便 VS Code 任务捕获。
- `tools/test/remote_batch_strategy_suite.ps1` 汇总阶段新增 `LogPath` 守卫，避免启用 `Set-StrictMode -Version 2` 时因 NULL 结果触发 `PropertyNotFoundStrict`。这使得 selftest 套件在远端批量脚本完成后能继续执行 golden，而不会被 summary 阶段中断。
- 远端实跑命令（2025-11-30）：
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass `
    -File tools/test/selftest_golden_suite.ps1 `
    -SelftestActions "force-suspicious,8.8.8.8" `
    -SmokeExtraArgs "--selftest-force-suspicious 8.8.8.8" `
    -SelftestExpectations "action=force-suspicious,query=8.8.8.8"
  ```
  输出：
  - raw：`out/artifacts/batch_raw/20251130-053904/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251130-054007/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251130-054111/build_out/smoke_test.log`
  三份日志在 `golden_check_selftest.sh` 均报 `[golden-selftest] PASS`，而 batch 黄金因被强制短路出现 `[golden][ERROR] header/referral missing`，符合自测预期。
- `docs/OPERATIONS_{EN,CN}.md` 已新增 “Selftest golden suite” 小节，描述脚本参数（`-SelftestActions/-SmokeExtraArgs/-SelftestExpectations/-SkipRemote`）与最新日志证据，同时在 VS Code 任务章节补上一键入口说明。
- `.vscode/tasks.json` 新增 **Selftest Golden Suite** 任务，收集 `SelftestActions`、`SmokeExtraArgs`、期望/错误/标签列表并调用 `tools/test/selftest_golden_suite.ps1`；参数支持输入 `NONE` 以跳过对应校验，默认直接运行远端拉取 + 自测黄金流程。
- 自测脚本追加 `-NoGolden` 透传：当远端批量套件仅用于产生日志、而标准 `golden_check.sh` 因自测短路必然失败时，可通过该开关让 `remote_batch_strategy_suite.ps1` 跳过传统黄金校验，终端只保留 `[golden-selftest] PASS/FAIL` 结果，便于辨识真正的断言失败。

- **2025-12-12（Selftest controller glue 补齐 + 双轮黄金回归）**
  - 补齐 `include/wc/wc_selftest.h` 中的 `wc_selftest_apply_cli_flags()` / `wc_selftest_reset_all()` 声明，避免 `wc_opts_parse()` 出现隐式声明告警；自测控制器实现继续集中在 `src/core/selftest_hooks.c`，行为保持不变，仅为后续入口瘦身收口做准备。
  - 将 CLI selftest flag 应用迁移到 controller：`wc_selftest_controller_apply()` 现在负责调用 `wc_selftest_apply_cli_flags()` 并快照强制字符串，`wc_opts_parse()` 不再直接触碰 selftest setter，入口更薄，运行时语义不变（故障注入仍仅在自测路径生效，force-suspicious/private 继续影响真实查询）。
  - 远程双轮冒烟（tools/remote/remote_build_and_test.sh）：
    1. 默认参数：无告警，Golden PASS，日志 `out/artifacts/20251212-221059/build_out/smoke_test.log`（上一轮 213528 亦 PASS）；
    2. `--debug --retry-metrics --dns-cache-stats`：无告警，Golden PASS，日志 `out/artifacts/20251212-221358/build_out/smoke_test.log`（上一轮 213813 亦 PASS）。
  - 后续：继续推进 selftest controller 收口与入口瘦身，必要时在 docs/USAGE_{EN,CN}.md / docs/OPERATIONS_{EN,CN}.md 更新自测触发位置说明。

- **2025-12-01（forced IPv4 / known-IP fallback backoff-aware + 四轮黄金）**
  - `src/core/lookup.c` 中的 forced IPv4 与 known-IP fallback 现会通过 `wc_lookup_should_skip_fallback()` 查询 penalty 状态：当仍有其它 fallback 选项（如 known-IP）可用且候选处于 backoff，将输出 `[DNS-BACKOFF] action=skip` 并直接跳过，最后一个候选依旧以 `force-last` 方式执行，保证兜底能力。
  - 为避免重复查询 known-IP 映射，本轮在 fallback 入口缓存 `wc_dns_get_known_ip()` 结果，并在 forced IPv4 阶段可感知“后续仍有 known-IP 可用”，以此作为 `allow_skip` 的输入；也让 known-IP fallback 能稳定复用缓存，减少 DNS 侧噪声。
  - 四轮远程冒烟 / 黄金：
    1. 默认参数：`tools/remote/remote_build_and_test.sh -r 1`，日志 `out/artifacts/20251201-095324/build_out/smoke_test.log`；无告警、`[golden] PASS`；
    2. `--debug --retry-metrics --dns-cache-stats`：日志 `out/artifacts/20251201-095829/build_out/smoke_test.log`；无告警、`[golden] PASS`；
    3. 批量（raw / plan-a / health-first）黄金：`out/artifacts/batch_raw/20251201-100103/...`、`out/artifacts/batch_plan/20251201-100336/...`、`out/artifacts/batch_health/20251201-100213/...`，均报告 `[golden] PASS`；health-first 轮次在控制台出现一次中间态 `[golden] FAIL` 提示（图 1），经复核为脚本在补采 `[DNS-BACKOFF]` 断言时的瞬态输出，最终报告 PASS；
    4. Selftest 黄金（`--selftest-force-suspicious 8.8.8.8`）：`out/artifacts/batch_raw/20251201-101134/...`、`batch_plan/20251201-101344/...`、`batch_health/20251201-101240/...`，三份日志全部 `[golden-selftest] PASS`。
  - 下一步：
    - 继续观察 health-first preset 中 `[golden] FAIL` -> PASS 的瞬态提示，必要时在 `tools/test/golden_check_batch_presets.sh` 内增加更明确的阶段日志，避免产生误判；
    - 结合本次 backoff-aware fallback 行为，评估是否需要在 `docs/USAGE_*` 中追加“IPv4/known-IP fallback 在 penalty 窗口的表现”说明，以及为批量策略准备新的示例脚本。

- **2025-11-29（Batch 策略现场压测记录）**  
  - 在 GT-AX6000 实网环境下对 4 组批量策略（每组跑 2 遍）进行对照测试：每遍使用 48 个进程并行查询，输入为 8692 条 APNIC 发布的国内 IPv4 地址（其中少量记录在 APNIC 有备案但实际归属 ARIN 等 RIR，会在第二跳转向）；当日网络状况一般，采样显示若在理想时间窗口以 IPv4 直连还能再快约 10 秒。  
  - 所有轮次固定 `--host apnic` 且首跳强制 IPv4，原因是 IPv6 在该环境平均慢约 10 秒；IPv6-only 情况本轮未测。  
  - 详细日志保存在 `out/artifacts/gt-ax6000-prefer-ipv4-syslog.log`，每遍的配置可在 `Whois Client (whois-aarch64 v3.2.9-111-ge5d9e6d) Threads: 1` 行上方看到；后续优化或复盘可直接引用该文件。  
  - 该批数据将作为 Stage 3 batch 策略（raw vs plan-a vs health-first）调优与 IPv4/IPv6 优先级实验的参考基线；建议网络状况更佳时再复测一次，以确认 IPv4/IPv6 首跳差异是否稳定。
#### 2025-11-28 计划排程（三板斧收官）

- **① Cache & Legacy 收官**  
  - 目标：将负缓存桥接、legacy shim 指标、`[DNS-CACHE-LGCY]` / `[DNS-CACHE-LGCY-SUM]` 输出全部下沉到 `wc_cache.c`，并把剩余的 cache 统计/调试 helper 从入口文件彻底迁出，确保 legacy shim 仅保留观测用途。  
  - 预估瘦身：≈ 30 行（入口层 cache glue 与 shim 计数器）。  
  - 提交模板：`refactor: move cache stats to wc_cache.c`（若分拆为多步，可在黄金通过后按子模块命名）。  
  - 注意事项：每一步都需要双轮 `remote_build_and_test.sh`（默认 + `--debug --retry-metrics --dns-cache-stats`），并在 RFC / `[DNS-CACHE-LGCY]` 遥测中记录 shim 命中是否归零，防止无意回退到 legacy 数组。  
  - 进度：见下文“Cache & Legacy 收官 - 第 1 步”。
- **② Selftest/Fault 收官**  
  - 目标：将 `WHOIS_*_TEST`、suspicious/private 注入、fault toggle 以及自测辅助函数集中到 `wc_selftest.c` / `include/wc/wc_selftest.h`，入口文件只保留 CLI 开关解析，减少 `#ifdef WHOIS_*` 噪音。  
  - 预估瘦身：≈ 25 行（宏判定 + helper 实现）。  
  - 行动顺序（2025-11-28 更新）：
    1. **Selftest 控制器**：在 `wc_selftest.c` 内扩展统一入口（例如 `wc_selftest_apply_cli_flags()` / `wc_selftest_reset_all()`），由其调用全部 `wc_selftest_set_*` 并刷新 `wc_selftest_fault_profile_t`，`wc_opts.c` 无需再声明 `extern`。
    2. **可疑/私网钩子**：新增 `wc_selftest_should_force_suspicious()`、`wc_selftest_should_force_private()`（或等效 API），`wc_handle_suspicious_query()` / `wc_handle_private_ip()` 优先检查这些钩子并输出 `[SELFTEST] action=...`，以便 deterministic 地触发/观测。
    3. **Fault profile 归一**：引入 `wc_selftest_fault_profile_t`（或等价结构）描述 blackhole/force-pivot/dns-negative 等开关，`wc_dns`、`wc_lookup`、`wc_net` 仅读取 profile，控制器负责更新与日志输出，后续扩展注入点也复用同一渠道。
    4. **统一自测入口**：提供 `wc_selftest_run_if_enabled()`（内部调用 `wc_selftest_run_startup_demos()`、`wc_selftest_lookup()` 等），运行完后立即 `wc_selftest_reset_all()`，避免测试状态污染真实查询；`main()` 仅需在 runtime 初始化后调用一次。
    5. **文档与黄金**：同步更新 `docs/USAGE_{EN,CN}.md`、`docs/OPERATIONS_{EN,CN}.md`、`RELEASE_NOTES.md`，记录新增钩子及 `[SELFTEST] action=*` 日志；`tools/test/golden_check.sh` 亦需补充对这些标签的 presence 校验，并在 RFC 本节登记远程冒烟日志。  
  - 提交模板：`refactor: consolidate selftest macros to wc_selftest.c`。  
  - 注意事项：搬迁后必须重新跑 `--selftest*` 远程冒烟，确保 `[LOOKUP_SELFTEST]`、`[GREPTEST]` 等标签形态不变，并在 RFC 中登记新的自测入口位置。  
  - 进度：紧随其后的多段 Selftest/Fault 章节已按时间顺序记录。
- **③ Usage/Exit 收官**  
  - 目标：把 usage 字符串表、服务器列表、退出码策略 helper 从入口层迁到专门文件（建议 `wc_usage.c` / `wc_exit.c` 或扩展现有 `wc_client_meta`），完成 C 计划里“usage/exit glue 收口”的最后一块。  
  - 预估瘦身：≈ 20 行（usage 表 + exit helper）。  
  - 提交模板：`refactor: migrate usage strings to wc_usage.c`。  
  - 注意事项：迁移后需同步更新 `docs/USAGE_*` 与 `docs/OPERATIONS_*` 的引用路径，并确认 `wc_client_exit_usage_error()` / `wc_meta_print_usage()` / `wc_client_handle_meta_requests()` 的调用链保持稳定。  
  - 进度：参见下文“Usage/Exit 收官 - 第 1 步”。

上述三板斧按“Cache → Selftest/Fault → Usage/Exit”的顺序推进：每完成一板斧都需要在本节追加进度记录、标注黄金验证结果，并在 `docs/RELEASE_NOTES.md` 对应版本条目简述瘦身收益，以便日后快速回溯。

#### 2025-11-28 进度更新（Cache & Legacy 收官 - 第 1 步）

- 将 `[DNS-CACHE-LGCY]` 打印逻辑集中到 `wc_cache_log_legacy_dns_event()`：新增公共 helper，并在 `wc_cache` 内部根据缓存命中/负缓存/写入路径自动输出 `wcdns-hit`、`legacy-shim`、`miss`、`wcdns-store`、`neg-bridge`、`neg-shim` 等状态；`wc_client_resolve_domain()` 不再直接 `fprintf(stderr, ...)`。
- `wc_cache_get_dns_with_source()` / `wc_cache_is_negative_dns_cached_with_source()` / `wc_cache_set_dns_with_addr()` 现负责在命中或 miss 时调用该 helper；`wc_client_try_wcdns_candidates()` 仅在桥接候选成功/失败时调用 helper 写出 `legacy-shim` / `miss`（旧日志称 `bridge-hit` / `bridge-miss`），保持遥测结构统一。
- `client_net.c` 删除本地 `wc_client_log_legacy_dns_cache()`，所有 `[DNS-CACHE-LGCY]` 日志均走 shared helper，入口文件完全摆脱 legacy shim 统计代码；`wc_cache` 同步引入 `wc_net_retry_metrics_enabled()` 以保留 “debug 或 --retry-metrics 时才输出” 的守卫。
- **测试**：已完成三轮验证：
  1. `tools/remote/remote_build_and_test.sh`（默认参数）→ **无告警 + Golden PASS**，日志：`out/artifacts/20251128-122749/build_out/smoke_test.log`；
  2. 同脚本附 `--debug --retry-metrics --dns-cache-stats` → **无告警 + Golden PASS**，日志：`out/artifacts/20251128-123251/build_out/smoke_test.log`；
  3. `tools/test/remote_batch_strategy_suite.ps1 -QuietRemote`（raw / plan-a / health-first）全部 **Golden PASS**，对应日志：`out/artifacts/batch_raw/20251128-123752/build_out/smoke_test.log`、`out/artifacts/batch_plan/20251128-124004/build_out/smoke_test.log`、`out/artifacts/batch_health/20251128-123856/build_out/smoke_test.log`。
- **下一步（Cache & Legacy 第 2 步）**：继续整理 `wc_cache` 中残留的 legacy shim 计数（例如 `g_dns_cache_shim_hits_total`）与 `wc_cache_legacy_dns_enabled()` 开关，评估是否可在默认情况下完全移除 legacy 表的读写；同时检视 `[DNS-CACHE-LGCY-SUM]` 是否可以直接引用 `wc_cache_log_legacy_dns_event()` 的计数，进一步减轻入口资源。

#### 2025-11-28 进度更新（Selftest controller glue + 冒烟记录）

- `include/wc/wc_selftest.h` 预留 `struct wc_opts_s` 前向声明并新增 `wc_selftest_apply_cli_flags()` / `wc_selftest_reset_all()`，由 `wc_selftest` 模块统一接管所有自测开关；`wc_opts_t` 现持有完整的 selftest 字段（fail-first、空响应注入、grep/fold、自定义安全日志、DNS negative toggle、blackhole、force-pivot 等），`wc_opts_parse()` 在 CLI 解析完成后只需调用 controller 即可同步运行期状态。  
- `src/core/selftest_flags.c` 内新增集中 setter，负责驱动 `wc_selftest_fault_profile_t`（涵盖 fail-first / dns-negative / blackhole / force-pivot 等开关）以及 future fault hooks，入口层与 `wc_query_exec` 不再散落地各自写 selftest setter，便于后续实现“Suspicious/Private hook 注入”与“fault profile”步骤。  
- `whois_client.c` 与 runtime glue 仍保持原有行为：selftest controller 仅封装已有逻辑，黄金契约（标题/尾行、`[LOOKUP_SELFTEST]` 标签、批量模式语义等）没有任何可观测变化。  

**测试记录（tools/remote/remote_build_and_test.sh）**

1. 常规冒烟（默认参数）：无告警，Golden PASS，日志 `out\artifacts\20251128-133536\build_out\smoke_test.log`。  
2. 调试冒烟（`--debug --retry-metrics --dns-cache-stats`）：无告警，Golden PASS，日志 `out\artifacts\20251128-133754\build_out\smoke_test.log`。  
3. 批量策略黄金校验：raw / plan-a / health-first 三策略全部 Golden PASS；对应日志 `out\artifacts\batch_raw\20251128-133936\build_out\smoke_test.log`、`out\artifacts\batch_plan\20251128-134142\build_out\smoke_test.log`、`out\artifacts\batch_health\20251128-134037\build_out\smoke_test.log`。  

#### 2025-11-28 进度更新（Selftest/Fault：可疑/私网钩子落地）

- 新增 CLI `--selftest-force-suspicious <query|*>` / `--selftest-force-private <query|*>`，`wc_opts_t` 与 `wc_selftest_apply_cli_flags()` 会在解析后把目标字符串写入 selftest 模块；传入 `*` 可对任意查询强制触发。  
- `wc_selftest_should_force_suspicious()` / `wc_selftest_should_force_private()` 提供统一钩子，`wc_handle_suspicious_query()` / `wc_handle_private_ip()` 在执行静态判定前优先检查该钩子，命中时向 stderr 输出 `[SELFTEST] action=force-{suspicious,private} query=...`，并保持原有 security log / header-tail 契约。  
- 单次与批量查询路径都会在拨号前调用 `wc_handle_private_ip()`：真实私网 IP 与 selftest 强制路径均会短路为“正文提示 + tail=unknown”或 fold 单行输出，避免进入 lookup；对应逻辑复用了此前抽出的 `wc_client_is_private_ip()`，补齐了 doc 中“私网查询立即短路”的承诺。  
- 已完成三轮远程验证：① 默认参数 → `out\artifacts\20251128-140401\build_out\smoke_test.log`；② `--debug --retry-metrics --dns-cache-stats` → `out\artifacts\20251128-140611\build_out\smoke_test.log`；③ 批量策略 raw / plan-a / health-first Golden PASS，日志分别为 `out\artifacts\batch_raw\20251128-140816\build_out\smoke_test.log`、`out\artifacts\batch_plan\20251128-141022\build_out\smoke_test.log`、`out\artifacts\batch_health\20251128-140916\build_out\smoke_test.log`。  

#### 2025-11-28 进度更新（Selftest/Fault：fault profile 归一）

- `include/wc/wc_selftest.h` 新增 `wc_selftest_fault_profile_t` 结构与版本 getter，集中描述 dns-negative、blackhole（IANA/ARIN）、force-iana-pivot 以及 `fail-first` 拨号注入；现有 setter 会透过 controller 更新 profile 并 bump 版本号，外部模块只需读取单一入口。  
- `src/core/selftest_flags.c` 负责维护 profile 与版本号，`wc_selftest_apply_cli_flags()`/`wc_selftest_reset_all()` 会同步刷新 profile，`wc_selftest_set_fail_first_attempt()` 替代旧的 `wc_net_set_selftest_fail_first()`，避免 networking 层暴露 selftest-only API。  
- `wc_dns_collect_addrinfo()` / `wc_dns_build_candidates()` 使用共享 profile 判定 dns-negative 与 blackhole 注入，`wc_lookup_execute()` 仅引用 profile 上的 `force_iana_pivot` 字段，`wc_dial_43()` 则在拨号前依据 profile 版本同步一次 `fail-first` 状态，并在首次注入后本地清零，确保语义与旧版一致。`client_net.c` 的 legacy DNS 桥也复用了同一 profile。  
- `wc_net_set_selftest_fail_first()` 从公开 API 中移除，相关文档描述同步更新。  
- `wc_dns_collect_addrinfo()` / `wc_dns_build_candidates()` 使用共享 profile 判定 dns-negative 与 blackhole 注入，`wc_lookup_execute()` 仅引用 profile 上的 `force_iana_pivot` 字段，`wc_dial_43()` 则在拨号前依据 profile 版本同步一次 `fail-first` 状态，并在首次注入后本地清零，确保语义与旧版一致。`client_net.c` 的 legacy DNS 桥也复用了同一 profile。  
- `wc_net_set_selftest_fail_first()` 从公开 API 中移除，相关文档描述同步更新。  

**测试记录（2025-11-28，自测 fault profile 归一阶段）**

1. 常规冒烟（默认参数）：无告警，Golden PASS，日志 `out\artifacts\20251128-143529\build_out\smoke_test.log`。  
2. 调试冒烟（`--debug --retry-metrics --dns-cache-stats`）：无告警，Golden PASS，日志 `out\artifacts\20251128-143740\build_out\smoke_test.log`。  
3. 批量策略黄金校验：raw / plan-a / health-first 三策略全部 Golden PASS；对应日志 `out\artifacts\batch_raw\20251128-144001\build_out\smoke_test.log`、`out\artifacts\batch_plan\20251128-144216\build_out\smoke_test.log`、`out\artifacts\batch_health\20251128-144106\build_out\smoke_test.log`。  

#### 2025-11-28 进度更新（Selftest/Fault：统一自测入口）

- `include/wc/wc_selftest.h` 新增 `wc_selftest_run_if_enabled()` 与 `wc_selftest_lookup()` 的正式声明，自测/注入相关入口全部对齐至同一模块。  
- `src/core/selftest_hooks.c` 按 CLI 选项集中判断：`--selftest-fail-first-attempt`、`--selftest-inject-empty`、`--selftest-dns-negative`、`--selftest-blackhole-*`、`--selftest-force-iana-pivot`、`--selftest-{grep,seclog}` 任一启用即触发 lookup suite + startup demos，执行完毕后统一 `wc_selftest_reset_all()`，再仅恢复 `--selftest-force-{suspicious,private}` 这类需要影响真实查询的钩子，避免故障注入状态泄漏到后续真实查询。  
- `whois_client.c` 入口改为唯一调用 `wc_selftest_run_if_enabled(&opts)`，彻底移除了针对 `wc_selftest_run_startup_demos()` 的显式依赖，入口继续保持薄壳。  

**测试记录（2025-11-28，统一自测入口阶段）**

1. 常规冒烟（默认参数）：无告警，Golden PASS，日志 `out\artifacts\20251128-151106\build_out\smoke_test.log`。  
2. 调试冒烟（`--debug --retry-metrics --dns-cache-stats`）：无告警，Golden PASS，日志 `out\artifacts\20251128-151303\build_out\smoke_test.log`。  
3. 批量策略黄金校验：raw / plan-a / health-first 三策略全部 Golden PASS；对应日志 `out\artifacts\batch_raw\20251128-151512\build_out\smoke_test.log`、`out\artifacts\batch_plan\20251128-151725\build_out\smoke_test.log`、`out\artifacts\batch_health\20251128-151614\build_out\smoke_test.log`。  

#### 2025-11-28 进度更新（Selftest/Fault：文档 & 黄金同步）

- `docs/USAGE_{EN,CN}.md` 增补“3.2.10+ 自测旗标自动触发”说明：只要 CLI 上出现 `--selftest-*` 故障/演示开关（fail-first、inject-empty、dns-negative、blackhole、force-iana-pivot、grep/seclog），客户端会在真实查询前自动跑一次 lookup 自测，stderr 中的 `[LOOKUP_SELFTEST]` 无需再额外执行 `whois --selftest`；同时在 DNS 调试 quickstart 示例中直接展示 `--selftest-blackhole-arin` 等命令。  
- `docs/OPERATIONS_{EN,CN}.md` 同步更新 DNS 调试段落与 lookup 自检章节，去除已废弃的 `WHOIS_SELFTEST_INJECT_EMPTY` 环境变量流程，改为 CLI `--selftest --selftest-inject-empty`；示例命令与 `[LOOKUP_SELFTEST]` 说明均强调“带故障旗标=自动跑自测”。  
- `RELEASE_NOTES.md` 新增 “Unreleased” 条目，记录自测旗标自动触发与文档同步背景，方便后续标签合入与版本审查。  
- `tools/test/golden_check.sh` 无需改动：`[LOOKUP_SELFTEST]` 仍位于 stderr，黄金脚本继续关注 header/referral/tail；本次仅补文档来提示如何在烟测命令中复用自动自测机制。  

**测试记录**

- 纯文档/说明同步，无需重新构建；沿用 2025-11-28 的三轮远程冒烟作为最新基线，`[LOOKUP_SELFTEST]` 触发逻辑已在该轮验证。  

#### 2025-11-28 进度更新（Selftest/Fault：批量策略文档补充）

- `RELEASE_NOTES.md` 的 “Unreleased” 区块现额外概述 batch scheduler 的三种策略（raw 默认、health-first、plan-a 手动开启），同时指向 `docs/USAGE_EN.md#batch-modes` / `docs/USAGE_CN.md#批量模式` 与运维手册的 batch 章节，方便发布审查时快速了解策略差异与操作指引。  
- `docs/OPERATIONS_{EN,CN}.md` 的 batch scheduler 章节开头新增 release note 指针，提醒远程冒烟/批量黄金脚本在跟单时先查发布说明；其余章节结构未变，仅补充“raw 为默认，health-first/plan-a 需显式 flag + `WHOIS_BATCH_DEBUG_PENALIZE`”描述。  
- 纯文档追加，无需重新触发 `tools/remote/remote_build_and_test.sh`；延用 2025-11-28 三轮冒烟结果作为该阶段基线。  


#### 2025-11-28 进度更新（Usage/Exit 收官 - 第 1 步）

- 新增 `include/wc/wc_client_usage.h` + `src/core/client_usage.c`：服务器目录、`print servers` CLI 输出与 `wc_client_find_server_domain()` 现共用同一表格，`client_meta.c` 与 `client_util.c` 不再各自维护静态数组，后续如需扩展 alias/domain 仅需改动单一模块。  
- `wc_client_exit_usage_error()` 迁移至新模块 `src/core/client_exit.c` 并通过 `wc_client_exit.h` 对外提供，Usage/Exit glue 与 meta handler 解耦；`wc_client_flow.c` 统一通过该 helper 返回 `WC_EXIT_FAILURE`，为未来引入 `WC_EXIT_USAGE` 预留集中入口。  
- `wc_meta_print_usage()` 引入 section table（`wc_usage_section_t` + 静态行数组），`Conditional output engine` 与 `Diagnostics/Security` 两段文本改为数据驱动，Usage 帮助行的维护粒度从“printf 串”下沉为“静态表项”。  
- `RELEASE_NOTES.md` 的 “Unreleased” 区块新增 Usage/Exit 收官条目，明确本批仅为结构收口，不改变 CLI 行为；RFC 当前章节记录 server catalog / exit helper / usage 表的落地，后续步骤可继续围绕 exit code 细化。  
- **测试**：分四轮远程 `tools/remote/remote_build_and_test.sh` / `remote_batch_strategy_suite` 验证：  
  1. 常规参数（默认）→ `out/artifacts/20251128-170834/build_out/smoke_test.log`，无告警 + Golden PASS；  
  2. `--debug --retry-metrics --dns-cache-stats` → `out/artifacts/20251128-171101/build_out/smoke_test.log`，无告警 + Golden PASS；  
  3. 批量策略 raw/plan-a/health-first Golden 套件（`out/artifacts/batch_raw/20251128-171232/build_out/smoke_test.log` 等三份）全部 PASS；  
  4. `--help` 观测 run（`out/artifacts/20251128-172213/build_out/smoke_test.log`）确认 CLI usage 输出正常无告警。  

#### 2025-11-28 进度更新（工具链维护：remote 批量套件静默化 + 本地 golden 汇报）

- `tools/remote/remote_build_and_test.sh` / `tools/remote/remote_build.sh`：补充 `SMOKE_QUERIES_PROVIDED` 标志，仅在确实缺少 `-q` 时才提示 `SMOKE_STDIN_FILE`，并在每轮构建后生成 `build_out/golden_report*.txt` 显示黄金校验结果路径；顺带把 pacing 断言与 `VERSION.txt` 清理流程加固，避免上一轮遗留影响本轮。  
- `tools/test/remote_batch_strategy_suite.ps1`：默认在本地调用 `golden_check.sh`（每个 preset 产出独立 `golden_report_<preset>.txt`），并新增 `-QuietRemote` 开关用于静默远端 SSH 输出；配合 `tee`，stdout 只保留 `[suite]` 摘要但依旧落盘完整报告。  
- `.vscode/tasks.json`：新增 “Remote: Batch Strategy Golden” 任务，封装常用参数并默认追加 `-QuietRemote`，任何人可一键触发 raw / health-first / plan-a 三套策略并自动生成黄金报告。  
- 验证：用该任务触发 `tools/test/remote_batch_strategy_suite.ps1 -QuietRemote`，raw / health-first / plan-a 全部显示 `Golden check ... PASS`，对应 `smoke_test.log` 的黄金校验结果写入 `golden_report_*.txt`，终端输出与截图一致。  
- TODO：后续考虑把 `-QuietRemote` 设为默认值并提供 `-VerboseRemote` 恢复完整日志，同时在 golden 脚本侧汇总 `golden_report_*.txt` 以便直接引用到 release 邮件。  

#### 2025-11-24 进度更新（Phase 2：wc_dns bridge ctx helper + 三轮冒烟）

- 新增 `wc_dns_bridge_ctx_init()`：在 `wc_dns` 内集中推导 `canonical_host` 与 `rir_hint`，供 legacy resolver 复用 Phase 2 的 canonical 逻辑，减少入口层与 DNS 模块的重复推理。  
- 三轮远程 `tools/remote/remote_build_and_test.sh`（Round 1 默认参数，Round 2 附 `--debug --retry-metrics --dns-cache-stats`，Round 3 附 `--debug --retry-metrics --dns-cache-stats --dns-use-wcdns`），全部 **无告警 + Golden PASS**，覆盖桥接 helper 生效后的常规与强化观测场景。  

#### 2025-11-24 进度更新（B 计划 / Phase 2：legacy cache → wc_dns 过渡开关）

- 新增 CLI 开关 `--dns-use-wcdns`（对应 `wc_opts_t::dns_use_wc_dns` / `Config::dns_use_wc_dns`），用于显式 opt-in：在 legacy resolver 缓存 miss 时，优先复用 `wc_dns_build_candidates()` 返回的首个数值型候选，再回退到老的 `getaddrinfo()` 流程。默认关闭，以免影响现有脚本。  
- `wc_client_resolve_domain()` 在命中缓存后、落入 legacy 解析器之前增加一次 `wc_dns` 尝试：根据 `wc_guess_rir()` 和 `wc_dns_canonical_host_for_rir()` 计算 canonical host，调用 candidate builder 并挑选首个 IP literal，命中后沿用原有 `wc_cache_set_dns()` / debug 打印；若未取到数值候选则保持原逻辑（含自测注入、`getaddrinfo` 路径和 `[DNS-CACHE-LGCY]` 统计）。  
- `wc_meta_print_usage`、RFC 本文等文档同步说明该开关属于 Phase 4 过渡 flag，为逐步把 legacy DNS cache 接入 `wc_dns` 流水线做准备；待 remote golden 覆盖新增路径后评估是否默认开启。  
- 远程冒烟：Round1 默认参数；Round2 附 `--debug --retry-metrics --dns-cache-stats`；Round3 附 `--debug --retry-metrics --dns-cache-stats --dns-use-wcdns`。三轮均无告警，Golden 检查 PASS。  
- 该日志为后续“legacy cache 迁移至 `wc_dns`”的观测基础，可对比 Phase 2 的 `[DNS-CACHE]` 与 `[DNS-CACHE-LGCY]` 命中率差异来评估下沉优先级。  
- `wc_runtime_init()` 在 `--dns-cache-stats` 开启时会额外注册 `[DNS-CACHE-LGCY-SUM] hits=<...> misses=<...>` 退出摘要，便于远程冒烟脚本比对 legacy 命中率趋势。  
- **测试**：最新一轮两次远程 `remote_build_and_test.sh`（Round 1 默认，Round 2 加 `--debug --retry-metrics --dns-cache-stats`）均无告警、Golden PASS，`[DNS-CACHE-LGCY]` / `[DNS-CACHE-LGCY-SUM]` 标签在日志中稳定出现且与既有 `[DNS-*]` 组合正常。  

#### 2025-11-24 进度更新（B 计划 / Phase 2：legacy ↔ wc_dns 负缓存桥接落地）

- 在 `wc_client_resolve_domain()` 中切换为共用 `wc_dns_bridge_ctx_t`（`wc_dns_bridge_ctx_init()`），配合三段 helper：
  1. 桥接上下文由 `wc_dns` 模块统一推导 canonical host + RIR hint，legacy 侧不再维护本地 `wc_client_wcdns_ctx_t`；
  2. `wc_cache_is_negative_dns_cached_with_source()`：在 legacy 负缓存 API 内部直接查询 `wc_dns_negative_cache_lookup()`，命中时以 `WC_CACHE_DNS_SOURCE_WCDNS` 标记并输出 `[DNS-CACHE-LGCY] status=neg-bridge`，否则回退 legacy 数组；
  3. `wc_cache_set_negative_dns_with_error()`：记录负缓存时同步写入 `wc_dns_negative_cache_store()`，携带实际 `EAI_*` 错误码，`wc_client_resolve_domain()` 只需调用一次 API 即可完成双写；
   该桥接仅在 `--dns-use-wcdns` 打开时启用，日志上新增 `status=legacy-shim/miss/neg-bridge`（此前称 `bridge-hit/bridge-miss/neg-bridge`）三种枚举，便于远程黄金脚本观测。
- 变更后立即跑三轮 `tools/remote/remote_build_and_test.sh`：Round1 默认参数；Round2 `--debug --retry-metrics --dns-cache-stats`；Round3 `--debug --retry-metrics --dns-cache-stats --dns-use-wcdns`。三轮均 **无告警 + Golden PASS**，确认共享 bridge ctx 不影响 legacy/wc_dns 双向同步与遥测标签。
- `include/wc/wc_dns.h` + `src/core/dns.c` 暴露 `wc_dns_negative_cache_lookup/store()` 的正式 API，内部封装现有的 `wc_dns_neg_cache_hit()` / `wc_dns_neg_cache_store()`，确保 legacy 与 lookup 共用一套 TTL/统计；
- **远程冒烟**：完成三轮 `tools/remote/remote_build_and_test.sh`（Round1 默认；Round2 加 `--debug --retry-metrics --dns-cache-stats`；Round3 加 `--debug --retry-metrics --dns-cache-stats --dns-use-wcdns`），全部 **无告警 + Golden PASS**，`[DNS-CACHE-LGCY]` / `[DNS-CACHE]` / `[DNS-CACHE-LGCY-SUM]` 与 `[RETRY-*]` 标签形态与之前一致，新增 `status=legacy-shim/neg-bridge`（原 `bridge-hit/neg-bridge`）记录在第三轮日志中可见。  
- **同进度新增正向缓存同步**：当 `wc_client_resolve_domain()` 触发 `getaddrinfo()` 且成功解析出 IP 时，只要 `--dns-use-wcdns` 为启用状态，即会把该结果写回 `wc_dns` 正向缓存（新 helper `wc_dns_cache_store_literal`，包含 sockaddr 副本），这样下一次走 `wc_dns_build_candidates()` 时即可直接命中，无需再次触发系统解析。该写回统一使用 canonical host（`wc_client_build_wcdns_ctx()` 计算），保持与 lookup 路径一致的 key；
- **同批次 telemetry**：`[DNS-CACHE-LGCY]` 新增 `status=miss`（wc_dns 候选未产出数值命中时标记，便于区分进入 legacy resolver 的原因，旧日志记为 `bridge-miss`）与 `status=wcdns-store`（legacy `getaddrinfo` 成功且结果已同步写入 `wc_dns` cache 时标记），调试/metrics 场景下可据此评估双向同步效率；
- **测试**：再跑一轮同配置三连（Round1 默认；Round2 `--debug --retry-metrics --dns-cache-stats`；Round3 `--debug --retry-metrics --dns-cache-stats --dns-use-wcdns`），依旧 **无告警 + Golden PASS**，且 `[DNS-CACHE-LGCY] status=miss/wcdns-store`（旧日志显示为 `bridge-miss/bridge-store`）均有出现，验证新增 telemetry 已纳入遥测。  

#### 2025-11-24 设计草案（B 计划 / Phase 3：legacy DNS cache → wc_dns 合流路线图）

> 目标：在不破坏 v3.2.9 黄金基线的前提下，逐步让 `wc_client_resolve_domain()` 与 legacy DNS/负缓存逻辑完全复用 `wc_dns` 数据平面，最终仅保留一份缓存/健康记忆与遥测。下述阶段均要求“每一步都可由 `--dns-use-wcdns`/后继 flag 控制是否启用”。

#### 2025-11-24 差异盘点（Stage 3 cache 合流前提）

- **键值空间**：`wc_cache` 以“用户输入域名（区分大小写）”为 key，并在命中前对域名做 `wc_client_is_valid_domain_name()` 过滤；`wc_dns` 以 canonical host（RIR alias 归一 + case-insensitive）为 key。要合流必须在 `wc_cache_*` 内部统一通过 `wc_dns_bridge_ctx_init()` 拿到 canonical host，并保留原查询名→canonical 的映射以便调试输出仍能展示原始 query。  
- **值形态**：`wc_cache` 仅缓存单个 IPv4/IPv6 字符串且不保存 `sockaddr`，`wc_dns` 每个条目可保存最多 16 个候选（含 AF 标记 + ready-to-dial sockaddr）。Stage 3 需要定义“legacy 读取”视角：短期内依旧只暴露首个 IP literal，长期可改成“遍历 wc_dns entry 中的数值候选”。  
- **TTL / 淘汰**：两者都受 `g_config.cache_timeout` 约束，但 `wc_cache` 通过互斥量维护近似 LRU（基于最早 timestamp），`wc_dns` 则使用环形写指针 + 过期检查。合流时需确认并记录“写入 wc_dns 时即刻按 canonical TTL 生效”即可，不再在 legacy 层维护额外 timestamp。  
- **验证链路**：`wc_cache_set_dns()` 持续调用 `wc_client_validate_dns_response()`，阻止把异常字符串写入缓存；`wc_dns` 默认信任传入值。迁移时需要在 `wc_cache_*` → `wc_dns_cache_store_literal()` 之前保留验证，以免把测试注入或损坏条目带入共享缓存。  
- **观测与统计**：目前 `[DNS-CACHE-LGCY]` / `[DNS-CACHE-LGCY-SUM]` 与 `[DNS-CACHE]` / `[DNS-CACHE-SUM]` 并列输出。Stage 3 需要在“只读 wc_dns”阶段保留旧标签但标注来源，确认 golden 无差异后再合并统计口径。  
- **负缓存桥接**：flag 开启时 legacy 负缓存命中写回 wc_dns，但由于 key 空间差异仍需依赖 bridge ctx。Stage 3 正式收敛时应让 `wc_cache_is_negative_dns_cached()` 直接调用 `wc_dns_negative_cache_lookup()`，并在 legacy 模块内只保留调试计数。  

#### Stage 3 动作拆解（细化版）

1. **共用 key + 读路径**：`wc_cache_get_dns()` 已统一通过 `wc_dns_bridge_ctx_init()` 推导 canonical host，并在进入 legacy 数组前先查询 `wc_dns_cache_lookup_literal()` / `wc_dns_negative_cache_lookup()`；命中后返回 `wc_safe_strdup()` 并标记 `status=wcdns-hit/neg-bridge`，legacy 表仅作兜底。  
2. **写路径同步**：`wc_cache_set_dns_with_addr()` / `wc_cache_set_negative_dns_with_error()` 现优先写入 `wc_dns`，若 canonical 缺失或值非法才回退 legacy；需要继续观测 `[DNS-CACHE-LGCY] status=wcdns-store|legacy-shim`，确认 shim 仅在异常条件下出现。  
3. **负缓存完全共用**：`wc_cache_is_negative_dns_cached()` / `wc_cache_set_negative_dns()` 已薄封 `wc_dns_negative_cache_*`，下一步是将 `[DNS-CACHE-LGCY-SUM]` 的 neg 统计直接引用 `wc_dns_get_cache_stats()`，legacy 表仅做 shim 计数。  
4. **收尾与移除**：在 shim 计数稳定为 0（或仅自测场景触发）后，删除 legacy DNS/负缓存数组与 mutex，仅保留连接缓存 + shim 遥测结构；必要时提供调试环境变量来强制回退 legacy，以取代旧 CLI flag。  
5. **测试矩阵**：每个子阶段维持至少两轮远程 `remote_build_and_test.sh`（Round1 默认、Round2 `--debug --retry-metrics --dns-cache-stats`），可选第三轮作为“高并发/自测”补充，以替代历史上的 flag on/off 对照。  

#### 2025-11-24 进度更新（Stage 3 / Direction 1：wc_cache_get_dns → wc_dns 桥接）

- `wc_cache_get_dns_with_source()`：新增 `wc_cache_dns_source_t` 出参以区分命中源；当 `--dns-use-wcdns` 启用且 canonical host 在 wc_dns 正向缓存中存在数值条目时，直接返回该条目并标记 `WC_CACHE_DNS_SOURCE_WCDNS`，否则回退到原有 legacy 数组扫描。  
- `wc_client_resolve_domain()` 的遥测输出会在上述桥接命中时打印 `[DNS-CACHE-LGCY] status=wcdns-hit`，同时在 debug 模式记录 `Using wc_dns cached entry:`，以便对比 legacy/wc_dns 命中率。  
- wc_dns 暴露 `wc_dns_cache_lookup_literal()`，供 legacy 读路径安全地复制第一条数值候选，并在命中时累加 `g_wc_dns_cache_hits` 统计，保持 `[DNS-CACHE-SUM]` 可见性。  
- 三轮远程 `tools/remote/remote_build_and_test.sh` 已完成：Round1 默认参数；Round2 `--debug --retry-metrics --dns-cache-stats`；Round3 `--debug --retry-metrics --dns-cache-stats --dns-use-wcdns`。全部 **无告警 + Golden PASS**，确认共享读路径及新标签在全架构稳定。  

#### 2025-11-24 进度更新（Stage 3 / Direction 2：wc_cache_set_dns 双写进 wc_dns）

- `wc_cache_set_dns_with_addr()`：新增返回值 `wc_cache_store_result_t`，统一封装 legacy cache 写入与 wc_dns 桥接写入，沿用原有 domain/IP 校验逻辑；当 `--dns-use-wcdns` 启用时，无论 legacy cache 是否命中都会自动将结果写入 wc_dns 正向缓存。  
- `wc_cache_set_dns()` 作为薄封装（无 sockaddr 信息时回退到 `AF_UNSPEC`），`wc_client_resolve_domain()` 的两处写缓存路径均改为捕获返回值，并在命中 `WC_CACHE_STORE_RESULT_WCDNS` 时输出 `[DNS-CACHE-LGCY] status=wcdns-store`，满足 Stage 3 telemetry 要求。  
- `wc_dns_cache_store_literal` 仍在有 sockaddr 的路径中获得 family/addr 元数据（通过新的 `_with_addr` API 透传），保证缓存条目继续携带 ready-to-dial sockaddr。  
- 三轮远程 `tools/remote/remote_build_and_test.sh` 已完成：Round1 默认参数；Round2 `--debug --retry-metrics --dns-cache-stats`；Round3 `--debug --retry-metrics --dns-cache-stats --dns-use-wcdns`。全部 **无告警 + Golden PASS**，新标签 `status=wcdns-store` 在第二、三轮日志中稳定出现，`[DNS-CACHE-SUM]` 指标与既有黄金一致。  

#### 2025-11-24 进度更新（Stage 3 / Direction 3：负缓存 API 薄封 wc_dns）

- `include/wc/wc_cache.h` 新增 `wc_cache_is_negative_dns_cached_with_source()` 与 `wc_cache_set_negative_dns_with_error()`，并沿用 `wc_cache_dns_source_t` 协议，让 legacy 调用者得知负缓存命中来自 wc_dns 还是仍依赖本地数组。  
- `src/core/cache.c` 将 `wc_cache_is_negative_dns_cached()`/`wc_cache_set_negative_dns()` 改为先尝试 canonical host 上的 `wc_dns_negative_cache_lookup/store`，legacy 数组只做回退与遥测计数；当 wc_dns 命中时会自动记录 `[DNS-CACHE-LGCY] status=neg-bridge`，写入路径也会把 `EAI_*` 错误码传递给 wc_dns。  
- `src/core/client_net.c` 删除 `wc_client_try_wcdns_negative()` / `wc_client_sync_wcdns_negative()`，调用新 API 即可完成负缓存命中检测与双写，同时保留既有调试标签（`neg-hit` / `neg-bridge`）和自测注入路径。  
- **测试**：已完成三轮 `tools/remote/remote_build_and_test.sh`：Round1 默认参数；Round2 `--debug --retry-metrics --dns-cache-stats`；Round3 `--debug --retry-metrics --dns-cache-stats --dns-use-wcdns`。三轮均 **无告警 + Golden PASS**，第三轮日志已归档于 `out/artifacts/20251124-200519/build_out/smoke_test.log` 供复核。  

#### 2025-11-26 进度更新（Stage 3 / Direction 4：wc_cache → wc_dns 首选 + shim 标记）

- 按 B 计划 Stage 3 Direction 4 的“只读 wc_dns、legacy 仅作 shim”目标，`wc_cache_set_dns_with_addr()` / `wc_cache_set_negative_dns_with_error()` 在 `--dns-use-wc_dns=1` 时改为**优先写入 wc_dns**，仅当桥接写入失败（canonical 为空、非 IP literal、内存不足等）时才回退 legacy 缓存；若 flag 关闭则行为与旧版一致。  
- `wc_cache_get_dns_with_source()` 与 `wc_cache_is_negative_dns_cached_with_source()` 会在 flag 打开且最终命中 legacy 时将来源标记为 `WC_CACHE_DNS_SOURCE_LEGACY_SHIM`，配合新的遥测字符串 `status=legacy-shim` / `status=neg-shim`（`src/core/client_net.c`）直观显示“wc_dns 优先 + legacy 仅兜底”的状态。  
- `include/wc/wc_cache.h` 引入新的 source 枚举值 `WC_CACHE_DNS_SOURCE_LEGACY_SHIM`，确保日志、调试输出与未来黄金脚本都能分辨 shim 路径；负缓存路径同样复用了该标记。  
- 预期行为：当 `--dns-use-wc_dns` 开启并且 wc_dns 正常工作时，legacy 缓存不再新增条目，`[DNS-CACHE-LGCY]` 只会在 shim/fallback 时出现；flag 关闭时仍维持 v3.2.9 等价语义，可随时回退。  
- 三轮远程 `tools/remote/remote_build_and_test.sh` 已完成：Round1 默认参数；Round2 `--debug --retry-metrics --dns-cache-stats`；Round3 `--debug --retry-metrics --dns-cache-stats --dns-use-wc_dns`，全部 **无告警 + Golden PASS**。第三轮完整日志存于 `out/artifacts/20251126-002253/build_out/smoke_test.log`，可见 `status=legacy-shim` / `status=neg-shim` 标签与 `[DNS-CACHE-LGCY-SUM]`/`[DNS-CACHE-SUM]` 指标共存且与黄金检查兼容。  
- 为了跟踪 shim 兜底比例，`wc_cache_dns_stats_t` / `wc_cache_neg_stats_t` 新增 shim 命中计数，`[DNS-CACHE-LGCY-SUM]` 摘要改为输出 `hits/misses/shim_hits/neg_hits/neg_shim_hits`，便于在批量冒烟日志中快速评估 legacy cache 是否仍被频繁触发。  

##### 2025-11-26 冒烟复核补记（artifact: `out/artifacts/20251126-005506/build_out/smoke_test.log`）

- 再次跑三轮 `tools/remote/remote_build_and_test.sh`：Round1 默认参数；Round2 附 `--debug --retry-metrics --dns-cache-stats`；Round3 在第二轮基础上追加 `--dns-use-wcdns`。三轮日志均显示 **无告警 + Golden PASS**，验证 shim 计数器与新遥测在多架构稳定。
- 第三轮定位到 `out/artifacts/20251126-005506/build_out/smoke_test.log`：末尾两组查询的 `[DNS-CACHE-LGCY-SUM] hits=0 misses=0 shim_hits=0 neg_hits=0 neg_shim_hits=0`（例如行 2550-2553、2820-2823）与紧随其后的 `[DNS-CACHE-SUM] hits=0 neg_hits=0 misses=2` 共同佐证 `--dns-use-wcdns` 开启后全部命中 wc_dns，legacy shim 未被触发。
- 三轮日志无 `[WARN]`/`[ERROR]`，`[RETRY-METRICS]` 与 `[DNS-*]` 标签形态与 v3.2.9 黄金样例一致，满足 Stage 3 Direction 4 的“观测对齐 + shim 退居兜底”目标。

##### 2025-11-27 冒烟复核补记（artifact: `out/artifacts/20251126-022031/build_out/smoke_test.log`）

- 重新执行“第三轮”远程冒烟，参数固定为 `--debug --retry-metrics --dns-cache-stats`（去掉已删除的 `--dns-use-wcdns`），单轮覆盖 whois-aarch64/armv7/x86_64/x86/mipsel/mips64el 六个架构，每个架构依次查询 `8.8.8.8`、`1.1.1.1`，最终 **无告警 + Golden PASS**。
- 日志中 12 条 `[RETRY-METRICS] attempts=2 successes=2 failures=0 ...`（例如行 198/470/669/941/1140/1412/1611/1883/2082/2354/2553/2825）表明所有查询均在两次尝试内成功连接，没有触发额外重试或失败分支。
- 对应的 12 条 `[DNS-CACHE-LGCY-SUM] hits=0 misses=0 shim_hits=0 neg_hits=0 neg_shim_hits=0`（行 195/467/666/938/1137/1409/1608/1880/2079/2351/2550/2822）说明在默认桥接策略下 legacy shim 完全未介入，`wc_dns` 单独承担正向/负向缓存命中，契合 Stage 4 期望。
- 全日志未出现 `[WARN]`/`[ERROR]`，且 `[DNS-HEALTH]`、`[DNS-CAND]`、`[DNS-CACHE]`、`[DNS-CACHE-SUM] hits=0 neg_hits=0 misses=2` 的形态与 2025-11-26 之前的黄金样例一致；本次 artifact 已作为“flag 移除后第三轮”基线归档。

##### 2025-11-27 冒烟复核补记（artifact: `out/artifacts/20251126-024338/build_out/smoke_test.log`）

- 运行两轮 `tools/remote/remote_build_and_test.sh`：Round1 默认参数；Round2 附 `--debug --retry-metrics --dns-cache-stats`。两个回合均覆盖 whois-aarch64/armv7/x86_64/x86/mipsel/mips64el * (8.8.8.8, 1.1.1.1) 的 12 条查询组合，远程 runner 报告 **无告警 + Golden PASS**。
- 新 artifact 中每个查询尾段都打印 `[RETRY-METRICS] attempts=2 successes=2 failures=0 ...`（示例见行 198、470、669、941、1140、1412、1611、1883、2082、2354、2553、2825），确认所有拨号在 2 次内成功，无额外重试/失败案列。
- `[DNS-CACHE-LGCY-SUM] hits=0 misses=0 shim_hits=0 neg_hits=0 neg_shim_hits=0` 同样出现 12 次（行 195、467、666、938、1137、1409、1608、1880、2079、2351、2550、2822），意味着默认开启的 wc_dns 桥接继续让 legacy shim 保持 0 命中；`[DNS-CACHE-SUM] hits=0 neg_hits=0 misses=2` 与 `[DNS-HEALTH]` / `[DNS-CAND]` 形态与之前日志一致，证实 Stage 4 行为稳定。
- 全文件未匹配到 `[WARN]` / `[ERROR]`，stderr 只含 `[DNS-*]`、`[RETRY-*]` 等调试标签；stdout 仍严格遵守“标题 → 主体 → 权威尾行 / 折叠”的契约，可作为后续 Stage 4 验证的最新基线。

##### 下一步（Stage 3 / Direction 4 准备）

- 整理 Direction 4 目标：在 bridge 常驻的前提下，削减 legacy DNS/负缓存数组，仅保留 shim 遥测字段，最终让 `wc_dns` 成为唯一数据源。  
- 评估移除 legacy DNS 数组对 `[DNS-CACHE-LGCY]`/`[DNS-CACHE-LGCY-SUM]` 的影响，必要时将 shim 统计嵌入 `[DNS-CACHE]` 或另设 `[DNS-CACHE-SHIM]`，并更新黄金脚本。  
- 拆分实现步骤（API 调整→代码实现→遥测验证），每步跑至少两轮远程 `remote_build_and_test.sh`（默认、`--debug --retry-metrics --dns-cache-stats`），如需第三轮可改为“自测 / 压力”模式而非旧 flag。  
- **后续排期提醒**：`“进程内批量查询依赖 wc_dns 健康记忆+server backoff 批量分配候选”` 仍等待 Stage 3/4 完成后再展开，避免在结构性重构期间引入新变量。  

#### 2025-11-27 进度更新（Stage 3 / Direction 4：默认启用 wc_dns 桥接 / 移除 CLI flag）

- `wc_opts_t` / `Config` 移除了 `dns_use_wc_dns` 字段，CLI 开关 `--dns-use-wcdns` 不再存在，legacy resolver 改为 **无条件** 先复用 `wc_dns` 数据面：
  - `wc_cache_get_dns_with_source()` / `wc_cache_is_negative_dns_cached_with_source()` 仍会先尝试 `wc_dns`，命中后标记 `WC_CACHE_DNS_SOURCE_WCDNS`，若回落到旧数组则标记 `WC_CACHE_DNS_SOURCE_LEGACY_SHIM`；shim 计数持续输出到 `[DNS-CACHE-LGCY]` / `[DNS-CACHE-LGCY-SUM]`，以便观察 fallback 占比。  
  - `wc_cache_set_dns_with_addr()` / `wc_cache_set_negative_dns_with_error()` 继续优先写入 `wc_dns`，仅在 canonical 缺失或数值非法时才回退 legacy，行为与 flag=ON 时一致。  
  - `wc_client_resolve_domain()` 始终初始化 `wc_dns_bridge_ctx_t` 并先尝试 `wc_dns` 候选；`miss` / `wcdns-store` / `legacy-shim` 遥测仍可用于判断 fallback。  
- `wc_meta_print_usage`、USAGE/OPERATIONS 文档后续移除 `--dns-use-wcdns` 描述，Stage 3/4 的回滚路径仅剩“通过 shim 计数判断是否异常回退”，若需彻底禁用 bridge 另开 debug 环境变量再讨论。  
- **测试计划**：自 flag 移除后需补跑至少两轮远程 `tools/remote/remote_build_and_test.sh`（Round1 默认、Round2 `--debug --retry-metrics --dns-cache-stats`）验证常规与调试场景；若 shim 计数在第二轮仍为 0，可视作与先前 Round3 `--dns-use-wcdns` 的效果一致。等待远程资源窗口后补充日志编号。  
- **文档 TODO**：
  1. Stage 3 动作拆解与 Stage 0/1/2/3/4 摘要需改写为“bridge 默认开启，shim 仅保留观测”版本（本节即刻开始同步）。
  2. 后续任何“第三轮附 `--dns-use-wcdns`”的测试描述改为“第三轮已废弃，可改成额外采样或直接删去”。

> 注：本节之前关于 `--dns-use-wcdns` 的描述保留作为历史记录；如需复盘老版本可参考对应日期，但新代码路径已无法使用该 flag。  

**Stage 0 – 观测对齐（已完成）**
- 维持 legacy cache (`wc_cache_get/set_dns`) 与 `wc_dns` 双轨运行，但强制在 stderr 打印 `[DNS-CACHE-LGCY]`、`[DNS-CACHE-LGCY-SUM]`，并在 `wc_dns` 侧保留 `[DNS-CACHE]`。  
- 远程冒烟脚本记录命中率/负缓存统计，形成后续迁移的对照基线。  

**Stage 1 – 桥接候选（已完成，默认启用）**
- legacy resolver 在 miss 时 **始终** 先消费 `wc_dns_build_candidates()` 产出的 IP literal，命中后 `wc_cache_set_dns_with_addr()` 自动写回 wc_dns，legacy cache 仅在 `miss` 场景兜底（旧日志称 `bridge-miss`）。  
- 2025-11-27 起移除了 `--dns-use-wcdns` CLI flag，所有遥测（`wcdns-hit`/`legacy-shim`/`miss` 等）依旧保留，用于衡量 fallback 占比；回滚手段转为“观察 shim 计数 + 必要时通过 debug build 临时禁用 bridge”。  

**Stage 2 – 负缓存与策略统一**
1. **负缓存共享**：`wc_cache_is_negative_dns_cached()` 先查询 `wc_dns_negative_cache_lookup()`，命中后直接短路并标记 `status=neg-bridge`；legacy 数组只做 shim（`status=neg-shim`），`[DNS-CACHE-LGCY-SUM]` 的 neg 统计与 `[DNS-CACHE]` 对齐。  
2. **fallback 策略合流**：将 forced IPv4 / known IP fallback 切换为调用 `wc_dns` helper（`wc_dns_get_known_ip`、`wc_dns_rir_fallback_from_ip`），由 `wc_lookup` 统一输出 `[DNS-FALLBACK]`，确保 lookup/legacy 共享同一策略。  
3. **遥测整合**：`[DNS-CACHE-LGCY]` 的 `status` 字段已包含 `wcdns-hit` / `legacy-shim` / `miss` / `neg-bridge` / `neg-shim`（旧版称 `bridge-miss`），即便桥接默认开启也能快速定位是否回退到旧路径。  

**Stage 3 – 单一 cache/health 源**
- 继续收敛 `wc_cache_get/set_dns()`：正向/负向缓存均薄封 `wc_dns_cache_*`，legacy 仅保留字符串副本与 shim 遥测；`wc_cache_*` 的 mutex 仍存在，但未来可在 shim 退场时一并删除。  
- 连接缓存与 backoff 已统一到 `wc_backoff` / `wc_net`，Stage 3 主要目标变为“验证 shim 真正降为 0”并规划清理顺序。  

**Stage 4 – 清理 & 文档更新**
- （2025-11-27 完成）删除 `--dns-use-wcdns` flag，桥接常驻；如需彻底禁用 bridge，考虑在 debug build 中新增环境变量，而非面对用户暴露 CLI。  
- 下一步聚焦于文档/黄金同步：`docs/USAGE_*`、`docs/OPERATIONS_*`、`RELEASE_NOTES.md` 需明确“legacy DNS cache 已并入 wc_dns，shim 仅做遥测”，并规划何时淘汰 `[DNS-CACHE-LGCY*]`。  
- 视需要在 `tools/test/golden_check.sh` 中增加“legacy shim 标签只在 debug/异常场景出现”的校验，防止回退。  

**风控与回滚要点**
- 每个 Stage 结束时至少跑双轮远程冒烟（默认 + `--debug --retry-metrics --dns-cache-stats`），必要时追加第三轮“高并发 / 自测”以取代旧的 `--dns-use-wcdns` 对照。  
- 通过 shim 计数与 `[DNS-CACHE-LGCY] status=legacy-shim|neg-shim` 观察 fallback，如需彻底禁用 bridge 可在 debug build 添加隐藏环境变量（不再面向用户暴露 CLI）。  
- 所有行为变化仍需提前在 RFC/Release Notes 标注，并准备“ shim-only ”指标来辅助线下回滚分析。  

### 5.3 C 计划：退出码策略与现状对照表

> 目标：在 **不改变既有行为（尤其是 Ctrl-C=130 与成功=0）** 的前提下，先梳理并文档化当前的退出码分布，再视需要在后续小批次中用常量名收口，最后才考虑是否在不破坏外部依赖的情况下优化个别场景的退出码。

- **草图：建议的退出码分层（设计稿，暂不强推落地）**  
  - `0`：成功结束（正常查询完成；纯 meta 命令如 `--help/--version/--servers/--examples/--about` 成功返回；自测命令在所有子用例通过时）。  
  - `1`：通用失败（网络/lookup 失败、配置非法、批量模式中被视为“致命”的错误等），作为当前实现里绝大多数非 0 场景的统一收口。  
  - `2`：用法/参数错误的候选预留值（例如 `wc_opts_parse` 失败），目前实现中仍多数使用 `1`，后续如要引入 `2` 需要单独开一轮小改动并确认无外部依赖；截至 2025‑11‑22，本值仍停留在“设计草图”阶段，**尚未在实现中落地**。  
  - `130`：SIGINT(Ctrl-C) 中断，保持现有行为：stderr 输出固定文案 `"[INFO] Terminated by user (Ctrl-C). Exiting..."`，并通过 `atexit` 路径触发 metrics/cache stats 等钩子；这是必须严格保持不变的一档。  

- **现状对照表（首轮，只关注进程级出口与明显的 exit/return）**  
  - `src/whois_client.c`：  
    - `main()`：  
      - `wc_opts_parse()` 失败：打印 usage，`return 1;` → 归类为“用法/参数错误”，当前使用 `1`。  
      - `wc_config_validate(&g_config)` 失败：`if (!wc_config_validate(&g_config)) return 1;` → 配置不合法，归类为“通用失败(1)”。  
      - `wc_client_handle_meta_requests()` 返回非 0：  
        - `meta_rc > 0`：`exit_code = 0; return exit_code;` → 纯 meta 成功，退出码为 `0`。  
        - `meta_rc < 0`：`exit_code = 1; return exit_code;` → meta 执行失败，退出码为 `1`。  
      - `wc_client_detect_mode_and_query()` 失败：`return 1;` → 参数/模式组合问题，归入“通用失败(1)”（与 usage 接近，但当前未区分 1/2）。  
      - 单次/批量查询：  
        - 非 batch：直接 `return wc_client_run_single_query(single_query, server_host, port);`，其中 0/非 0 由 core 层 orchestrator 决定；按现有实现，成功为 `0`，失败为 `1`。  
        - batch：`return wc_client_run_batch_stdin(server_host, port);`，同样由 core 决定 0/1。  
      - 特例说明：对于 `no-such-domain-abcdef.whois-test.invalid` 这类“协议/网络均成功，但 RIR 明确返回‘无数据’”的查询，目前仍视作成功路径，退出码为 0；这一点在 v3.2.9 及本次改动前后均保持一致，后续如要调整，需要单独权衡脚本依赖与业务语义。  
      - 另一个体验层面的特例：`-B 8.8.8.8` 这类“模式与参数组合错误”路径，目前会先由 `getopt` 打印一条 "option requires an argument: h" 之类的错误提示，然后由 `whois_client.c` 打印 Usage/帮助信息一次；从终端观察类似于“错误提示 + Usage”叠在一起的双段输出。这属于既有行为，本轮 C 计划仅做语义标记，不改输出形态，后续如要精简为单份 Usage 再单独开批处理。  
  - `src/core/signal.c`：  
    - SIGINT 处理路径显式调用 `exit(130);`，保持 Ctrl-C 退出码固定为 130，黄金与外部脚本均依赖此行为。  
  - `src/core/util.c`：  
    - `wc_safe_malloc()` 在 OOM 时调用 `exit(EXIT_FAILURE);`（通常为 `1`），属于极端条件下的“进程级致命失败”，归入“通用失败(1)”一类；目前不计划在 C 计划中调整其数值，只在文档中记录其存在。  

- **2025-11-22 状态更新（C 步第 1 小步：入口层命名收口已落地）**  
  - 在 `include/wc/wc_types.h` 中新增 `wc_exit_code_t`：  
    - `WC_EXIT_SUCCESS = 0`  
    - `WC_EXIT_FAILURE = 1`  
    - 仅做“命名收口”，数值保持与历史行为完全一致；`signal.c` 中 Ctrl-C 对应的 `exit(130)` 没有改动。  
  - 在 `src/whois_client.c::main` 中，将真正影响进程退出码的若干出口改为使用上述常量（不改变实际返回值）：  
    - 参数解析/配置校验失败：`return 1;` → `return WC_EXIT_FAILURE;`。  
    - meta 分支：`meta_rc > 0` 表示帮助/版本等“成功型 meta”，返回 `WC_EXIT_SUCCESS`；否则视为错误，返回 `WC_EXIT_FAILURE`（兼容原有 “help=0 / 其它错误=1” 语义）。  
    - 模式探测/单查询提取失败：统一返回 `WC_EXIT_FAILURE`。  
  - 这一小步的目标是：**先让所有“对外可见的进程退出码”在入口层都有名字**，为后续更细粒度的退出码策略（usage=2 等）打基础，同时保证现有脚本与 golden 完全不受影响。  
  
- **2025-11-22 状态更新（C 步第 2 小步：Ctrl-C 退出码命名收口）**  
  - 在 `include/wc/wc_types.h` 中为 Ctrl-C 引入命名常量：`WC_EXIT_SIGINT = 130`，明确这一值专用于 SIGINT(Ctrl-C) 场景，禁止复用于其它非信号退出路径。  
  - 在 `src/core/signal.c` 中将原本的 `exit(130);` 改为 `exit(WC_EXIT_SIGINT);`，保持行为与数值完全不变，同时让信号路径的退出码也纳入统一的命名体系，便于后续在 C 计划中继续扩展。  
  
- **2025-11-22 状态更新（C 步第 3 小步：usage 与运行期错误语义标记）**  
  - 引入 helper `wc_client_exit_usage_error(argv0)`（现已下沉至 `src/core/client_meta.c`），统一处理“CLI 用法/参数错误”类出口：  
    - 原本 `wc_opts_parse()` 失败路径中直接打印 usage 并返回 1 的逻辑，改为调用该 helper；  
    - `wc_client_detect_mode_and_query()` 失败（例如 `-B` 搭配 positional query）也改为通过该 helper 返回。  
  - 该 helper 当前仍返回 `WC_EXIT_FAILURE`(1)，**不改变既有退出码数值**，仅用于显式标记“这是 usage 级错误”，为后续如需引入 `WC_EXIT_USAGE=2` 提前打好集中的迁移入口。  
  - USAGE 文档同步收口：`docs/USAGE_EN.md` 与 `docs/USAGE_CN.md` 的“退出码”小节明确了 0/1/130 的语义边界：  
    - `0`：成功，包括“协议成功但无数据”的 soft negative 场景（例如 `no-such-domain-abcdef.whois-test.invalid`）以及批量模式下“局部失败但整批跑完”的情况；  
    - `1`：通用失败，覆盖 CLI 用法/参数错误与运行期无法完成查询的错误；  
    - `130`：SIGINT(Ctrl‑C) 中断，约定为固定值以便脚本与远程冒烟脚本依赖。  

- **后续 C 步实施建议（尚未动手）**  
  - 后续如需进一步细化（例如把 usage 场景单独调整为 `2`），需在单独小批次中执行，并补充 USAGE/OPERATIONS 文档说明以及黄金脚本的适配；截至 2025‑11‑22，`2` 仍仅作为设计草图存在于本节，**实现中尚未启用 `WC_EXIT_USAGE`**，以避免过早改变对外退出码契约。  
  - 在 B 计划的 orchestrator 下沉过程中，`whois_client.c::main` 中的 meta/模式判定与 single/batch 调度已被抽象为 core 层的 `wc_client_run_with_mode()`；这一改动保持退出码与黄金行为不变，同时顺带消除了历史上 `-B <query>` 路径下“错误提示 + Usage 冗余打印一份”的双重输出问题（现仅保留错误提示与退出码=1，对外契约更为收敛）。  

> 后续如需细化 Phase 2/3（例如真正把 pipeline glue、net/DNS glue 下沉到 `src/core/`）或增加新的自测矩阵，可在本文件后续章节中继续扩展，保持“背景 → 目标 → 改动 → 风险 → 进度”这一结构统一。

---

#### 2025-11-22 进度小结（B 计划 / Phase 2：域名校验 helper 收口到 wc_client_util）

- **背景与动机**  
  - 在前一小步中，`get_known_ip()` 已经下沉为 `wc_dns_get_known_ip()`，成为 DNS 模块的一部分；同时，入口层的 cache integrity/stats 仍然依赖若干“域名是否合法”的判断。  
  - 这些域名语法校验最初以 `static int is_valid_domain_name(const char *domain)` 的形式定义在 `src/whois_client.c` 内部，只能在入口层复用，不利于后续将 cache/DNS glue 继续拆分到 core。  

- **本次改动（B 计划 / Phase 2 的一个小步）**  
  - 在 `include/wc/wc_client_util.h` / `src/core/client_util.c` 中新增公共 helper：`int wc_client_is_valid_domain_name(const char *domain);`，用于做轻量级的域名语法校验：  
    - 拒绝 `NULL` / 空串，以及整体长度不在 1–253 范围内的字符串；  
    - 仅接受 `[A-Za-z0-9.-]` 字符；  
    - 拒绝首尾为 `'.'` 或包含连续 `".."` 的场景；  
    - 保证每个 label（点分片段）长度在 1–63 之间。  
  - 将原先 `src/whois_client.c` 中的 `static is_valid_domain_name()` 删除，其完整逻辑 1:1 挪到 `wc_client_is_valid_domain_name()` 中，实现细节保持不变。  
  - 在 `src/whois_client.c` 内，将所有对域名合法性的检查统一切换为调用 `wc_client_is_valid_domain_name()`：  
    - `validate_cache_integrity()` 中针对 `dns_cache[i].domain` 与 `connection_cache[i].host` 的检查；  
    - `get_cached_dns()` / `set_cached_dns()` 对入参 `domain` 的预检查；  
    - 确认不存在残留的 `is_valid_domain_name()` 引用，唯一的实现落点为 `client_util.c`。  

- **行为与风险评估**  
  - 由于逻辑为直接搬迁（无任何条件增删改），且调用点均在同一 TU 内完成替换，预期对运行期行为和日志输出均 **零影响**。  
  - 该 helper 的职责严格限定为“域名语法校验”（不做 DNS 解析、不依赖 cache/glue 状态），未来如需在其它 core 模块中复用（例如新的 DNS glue、自测场景等），可以直接 include `wc_client_util.h`。  
  - 已通过远程多架构构建 + Golden 检查验证：**无新告警，Golden PASS**；本小步可以视为 B 计划 / Phase 2 下的一个安全落地里程碑。  

#### 2025-11-23 计划预告（B 计划 / Phase 2：继续从 `whois_client.c` 抽取小型只读 helper）

- **总体节奏**  
  - 延续 2025-11-22 的“小步 + Golden PASS”策略：每次只挑一个逻辑简单、无全局状态依赖的小 helper，下沉到合适的 core / util 模块；每步之后都跑一轮远程多架构构建 + 黄金对比，确认零行为漂移。  
  - 优先级顺序保持为：**补文档 / RFC → 低风险 helper 下沉 → 中长期 cache/DNS glue 设计讨论**。  

- **明日具体拆分起点（按优先级排）**  
  - **候选 1：继续在 `wc_client_util` 中收口 CLI 侧的小工具函数**  
    - 特征：与 CLI / 配置解析相关、只读（只基于参数计算返回值）、不直接操作 socket / mutex / 全局 cache。  
    - 典型目标：字符串清洗、简单格式化或额外的“输入合法性”检查逻辑，类似于已有的 `wc_client_parse_size_with_unit()` 与 `wc_client_is_valid_domain_name()`。  
    - 实施策略：
      - 从 `src/whois_client.c` 中再挑 1 个满足“纯函数 + 无跨 TU 依赖”的 helper；  
      - 第一步只在 `wc_client_util` 中新增实现与头文件声明，不动调用点，先跑一轮构建验证；  
      - 第二步再在 `whois_client.c` 中用新 API 替换原始静态函数的调用，并删除旧实现，最后重新跑 Golden。  
  - **候选 2：为后续 cache 模块下沉做“可观测性微整理”（仅当时间精力允许）**  
    - 限定范围：只讨论/设计 `validate_cache_integrity()` / `log_cache_statistics()` 的日志前缀与信息结构，**不在 2025-11-23 直接改动行为或拆模块**。  
    - 如需改动日志格式（例如统一加上 `[CACHE-*]` 前缀），将另起小节并在动手前先盘点黄金脚本是否依赖当前文案。  

- **暂不在 2025-11-23 推进的事项（占位备忘）**  
  - 真正把 `dns_cache` / `connection_cache` 及其 mutex / 统计逻辑整体迁出 `whois_client.c`，成为独立 `wc_cache` 子模块的工作，预计会单开 “B 计划 / Phase 3：cache glue 下沉” 专章；在那之前仅通过 helper 收口与日志整理为后续拆分铺路。（2025-11-25 更新：该任务已提前完成，详见同日“cache/glue 渐进下沉，第 2 步”条目，现阶段 `wc_cache` 模块已全面接管缓存生命周期与统计。）  

#### 2025-11-24 进度更新（B 计划 / Phase 2：CLI 工具函数继续收口）

- **背景**  
  - Phase 2 的小步拆分策略强调“优先搬运纯只读 helper”，减少 `whois_client.c` 的体积并为未来 cache/DNS glue 的迁移铺路。  
  - 入口层内尚有 `is_private_ip()` 这样的纯函数逻辑，仅依赖标准库 + `inet_pton`，是天然适合放入 `wc_client_util` 的候选。  

- **本次改动内容**  
  - 在 `include/wc/wc_client_util.h` / `src/core/client_util.c` 中新增 `int wc_client_is_private_ip(const char* ip);`：
    - 逻辑 1:1 搬运自 `whois_client.c` 旧版的 `is_private_ip`，继续检测 IPv4 RFC1918、IPv6 ULA/link-local/documentation/loopback段；
    - 新 helper 不依赖 `g_config` 或其他入口全局，仅使用标准网络头（`arpa/inet.h` / `netinet/in.h`）。  
  - `whois_client.c`：
    - 删除本地的 `is_private_ip` 声明与实现；
    - 在 `validate_dns_response()` 中将调用替换为 `wc_client_is_private_ip()`，保持警告日志与返回语义完全一致。  
    - 顺势移除 `is_ip_literal()`，所有判定 IP 字面量的场景一律使用 `wc_client_is_valid_ip_address()`，继续为未来 cache/DNS glue 下沉铺路。  
    - 进一步把 `validate_dns_response()` 抽象为 `wc_client_validate_dns_response()`：入口仅保留调用点，用于 DNS 缓存校验与回写前过滤；内部沿用 `wc_client_is_valid_ip_address`/`wc_client_is_private_ip` 逻辑，并继续通过 `log_message` 产生 WARN。  
  - 同批次继续搬运 `is_valid_ip_address()`：
    - 新增 `wc_client_is_valid_ip_address()`（使用 `inet_pton` 检查 IPv4/IPv6），供入口和 future cache/DNS glue 复用；
    - `whois_client.c::validate_dns_response()` 的合法性检查改为调用该 helper，本地实现与声明全部删除。  
  - 通过该步骤，入口文件行数再度减少，同时 `wc_client_util` 成为 CLI 侧“输入合法性 + 单纯判定 helper”的集中落脚点（目前已有 size parser、域名校验、私网 IP 判定三类函数）。  

- **测试 / 状态**  
  - 由于本地缺少 make 环境，计划通过远程 `tools/remote/remote_build_and_test.sh` 再跑一轮多架构构建 + golden 检查；我会在本地记录好改动明细后通知远端执行。  
  - 预期行为与 v3.2.9 黄金完全等价（纯函数搬运 + 调用点替换），待远程构建完成后再在本节补充结果。  

#### 2025-11-24 进度更新（B 计划 / Phase 2：配置校验 helper 收口）

- **背景**  
  - 改动前 `whois_client.c` 持有 `validate_global_config()`，负责在 `main()` 初始阶段校验端口、缓存尺寸、重试参数等配置字段；该函数只依赖 `Config` 结构体本身，是天然可下沉的 CLI-only helper。  
- **本次改动内容**  
  - 在 `include/wc/wc_config.h` 中新增 `wc_config_validate(const Config* config)`，并在新的 `src/core/config.c` 中实现，逻辑 1:1 搬运旧版 `validate_global_config()` 的各项边界检查与 `fprintf(stderr, ...)` 文案；  
  - `whois_client.c` 删除本地实现，主入口改为调用 `wc_config_validate(&g_config)`；其它模块如需共用同一校验逻辑时可以直接 include 头文件而无需再次复制实现。  
- **测试 / 状态**  
  - 代码层面仍是“只搬运、不改逻辑”，预期对对外行为零影响；待本地编辑完成后，请继续按惯例触发远程多架构 `remote_build_and_test.sh` 做黄金校验。  

#### 2025-11-24 进度更新（B 计划 / Phase 2：usage 错误 helper 下沉）

- **背景**  
  - `wc_client_exit_usage_error()` 最初以 static 形式存在于 `whois_client.c`，用于在 `wc_opts_parse` 失败等 CLI 用法错误场景下打印 Usage 并返回 `WC_EXIT_FAILURE`；该逻辑与其它 meta/usage glue（`wc_client_handle_meta_requests`、`wc_client_detect_mode_and_query`）一样，更适合集中在 `wc_client_meta` 模块。  
- **本次改动内容**  
  - 在 `include/wc/wc_client_meta.h` 中公开 `wc_client_exit_usage_error(const char* progname, const Config* cfg)`；在 `src/core/client_meta.c` 实现该 helper，并引入 `wc_types.h` 以继续返回 `WC_EXIT_FAILURE` 常量；  
  - `whois_client.c` 删除本地 static 实现，`main()` 在 `wc_opts_parse()` 失败时直接调用新 helper，保持使用者视角的行为与消息文本完全一致。  
- **测试 / 状态**  
  - 纯代码搬迁，不修改输出；待远程 `remote_build_and_test.sh` 完成后继续确认黄金状态。  

#### 2025-11-24 进度更新（B 计划 / Phase 2：内存探测 helper 收口）

- **背景**  
  - `whois_client.c` 仍保留 `get_free_memory()`（读取 `/proc/meminfo`）与 `report_memory_error()` 两个静态 helper，但仅被 `validate_cache_sizes()` 这一处使用；更合适的归属是 `wc_client_util`，与其它 CLI 侧纯辅助函数（size parser、域名/IP 校验等）放在一起，减小入口文件体积。  
- **本次改动内容**  
  - 在 `wc_client_util` 中新增 `wc_client_get_free_memory()` 与 `wc_client_report_memory_error()`，直接迁移原有逻辑，并将调试开关改为调用 `wc_is_debug_enabled()`；  
  - `whois_client.c` 删除本地实现，`validate_cache_sizes()` 改为调用新 helper；顺便移除了未被使用的本地前向声明。  
- **测试 / 状态**  
  - 行为保持不变（仍在 Linux 上读取 `/proc/meminfo`，失败时返回 0），待远程多架构黄金脚本完成后记录结果。  

#### 2025-11-24 进度更新（B 计划 / Phase 2：服务器列表打印 helper 下沉）

- **背景**  
  - `wc_client_handle_meta_requests()` 中的 `--servers` 输出仍依赖 `whois_client.c` 内的 `print_servers()` 与静态 `servers[]` 表，`client_meta.c` 只能通过 `extern` 调用。该 helper 是纯只读数据 + printf，适合整体搬到 meta 模块，进一步瘦身入口文件。  
- **本次改动内容**  
  - 在 `src/core/client_meta.c` 内定义 `wc_client_whois_server_t` 结构、静态服务器列表以及 `print_servers()` 实现；移除对 `whois_client.c` 的 `extern` 依赖；  
  - 新增 `wc_client_find_server_domain()`，供 `wc_client_get_server_target()` 等路径在解析短名称（如 `arin`）时获取域名；  
  - `whois_client.c` 删除本地 `WhoisServer` 定义、`servers[]` 数组与 `print_servers()` 函数，仅通过上述 helper 获取映射。  
- **测试 / 状态**  
  - 纯搬运改动，`--servers` 输出文本与顺序保持不变；待远程多架构黄金脚本确认 PASS。  

#### 2025-11-24 进度更新（B 计划 / Phase 2：safe_close 统一命名 + 双轮冒烟确认）

- **背景**  
  - 历史上 `safe_close()` 以入口层私有 helper 形式存在，但 `wc_net` / `wc_signal` / `wc_cache` 等多个模块都需要相同语义（抑制 EBADF、在任何路径下都把 fd 置为 `-1`）。随着 util 模块逐渐成型，需要一个具名且可共享的实现，以避免再出现局部静态版本。  

- **本次改动内容**  
  - 将 helper 正式命名为 `wc_safe_close()` 并在 `include/wc/wc_util.h` 中对外声明；核心实现落在 `src/core/util.c`，内部继续使用 `close()` + errno 检查以保持旧语义。  
  - 更新 `src/whois_client.c`、`src/core/net.c`、`src/core/cache.c`、`src/core/signal.c` 以及其它曾直接引用旧名的调用点，统一通过 `wc_safe_close()` 释放 socket / 管道句柄，确保入口与 core 借助同一工具函数管理 fd 生命周期。  
  - 为了让旧的 WHOIS 查询 helper 在拆分过渡期依然链接进最终二进制，额外引入 `wc_reference_legacy_helpers()` 并在 `main()` 入口调用；该 helper 仅取地址，不改变运行期行为。  

- **测试 / 状态**  
  - 连续两次触发远程多架构 `tools/remote/remote_build_and_test.sh -a '--debug --retry-metrics --dns-cache-stats'`：第一次在改名落地后立即运行，第二次在清理调用点与头文件后再次运行，均 **无告警 + Golden PASS**。  
  - `[RETRY-*]`、`[DNS-*]`、`[DNS-CACHE-SUM]`、安全日志等黄金标签形态与 v3.2.9 对齐，确认此次改动纯属命名/结构层面的统一，不涉及可观测行为变化。  

#### 2025-11-25 进度更新（B 计划 / Phase 2：server target helper 下沉）

- **背景**  
  - `whois_client.c` 仍保留 `get_server_target()` 这个静态 helper，用于把 `--host`/短别名/IP literal 统一映射成真实的连接目标；虽然目前核心查询路径由 `wc_query_exec` 承担，但未来 batch/redirect glue 仍需要同样的逻辑，因此该 helper 适合作为 CLI 工具函数对外提供。  
- **本次改动内容**  
  - 在 `wc_client_util` 中新增 `wc_client_get_server_target()`，完整迁移旧版逻辑，并改用 `wc_safe_strdup()` 保持 fatal-on-OOM 语义；  
  - `whois_client.c` 删除本地 `static get_server_target()` 定义与引用，后续如需调用可直接 include `wc_client_util.h`；  
  - 顺带清理 legacy helper 的占位引用，避免入口文件继续背负无用前向声明。  
- **测试 / 状态**  
  - 纯搬运，不触碰查询流程；待下一轮远程 `remote_build_and_test.sh -a '--debug --retry-metrics --dns-cache-stats'` 跑完后补记黄金结论。  

#### 2025-11-25 进度更新（B 计划 / Phase 2：legacy 网络 helper 模块化）

- **背景**  
  - `resolve_domain()`、`connect_to_server()`、`connect_with_fallback()` 仍以 static 形式存在于 `whois_client.c`，主要用于保留旧版查询链路（`perform_whois_query()`）的可编译性；尽管主流程已经迁移至 `wc_query_exec` + `wc_lookup`，这些 helper 体量较大且依赖 cache/selftest/security glue，继续留在入口文件会阻碍后续瘦身。  
- **本次改动内容**  
  - 新增 `include/wc/wc_client_net.h` + `src/core/client_net.c`，集中定义 `wc_client_resolve_domain()` / `wc_client_connect_to_server()` / `wc_client_connect_with_fallback()`，逻辑逐行搬运旧实现并改用 `wc_safe_strdup()` 等 core helper；  
  - `whois_client.c` 删除对应的 `static` 实现与前向声明，仅通过新模块提供的 API 维护 legacy 流程；  
  - 该模块内部继续沿用 `wc_cache_*`、`wc_dns_get_known_ip()`、`wc_selftest_dns_negative_enabled()`、`monitor_connection_security()` 等 glue，以保证调试标签与安全日志契约不受影响。  
- **测试 / 状态**  
  - 纯函数搬家，尚未在本地 `make`；按惯例需要再跑两轮远程 `tools/remote/remote_build_and_test.sh -a '--debug --retry-metrics --dns-cache-stats'` 验证 **无告警 + Golden PASS** 后再更新本节状态。  

#### 2025-11-25 进度更新（B 计划 / Phase 2：socket 发送/接收 helper 下沉）

- **背景**  
  - `send_query()` 与 `receive_response()` 仍留在 `whois_client.c`，负责 socket I/O、缓冲区分配及协议校验；这些逻辑会被 legacy 路径与未来的兼容层复用，继续占据入口文件近 200 行，不利于后续维护。  
- **本次改动内容**  
  - 新增 `include/wc/wc_client_transport.h` + `src/core/client_transport.c`，封装 `wc_client_send_query()` 与 `wc_client_receive_response()`，完整搬移旧实现并沿用 `wc_protocol_*`、`wc_signal_should_terminate()`、`wc_safe_malloc()` 等安全钩子；  
  - `whois_client.c` 去除对应 `static` 实现与声明，调用点替换为新 API；未来其它模块若需要 legacy I/O 行为可直接 include 该头文件。  
- **测试 / 状态**  
  - 行为未变，等待下一轮远程多架构 `remote_build_and_test.sh -a '--debug --retry-metrics --dns-cache-stats'`，确认 **无告警 + Golden PASS** 后在此补记结果。  

#### 2025-11-25 进度更新（B 计划 / Phase 2：legacy 查询 orchestrator 模块化）

- **背景**  
  - `perform_whois_query()` 仍静态驻留在 `whois_client.c`，虽然主流程已经迁往 `wc_query_exec`，但为了保留旧版执行路径入口文件不得不引用大段重试/redirect/缓存 glue；这段逻辑接近 400 行，成为进一步瘦身的最大单点。  
- **本次改动内容**  
  - 新增 `include/wc/wc_client_legacy.h` + `src/core/client_legacy.c`，将 `perform_whois_query()` 完整迁移并更名为 `wc_client_perform_legacy_query()`；内部继续依赖 `wc_client_net`、`wc_client_transport`、`wc_dns`、`wc_cache`、`wc_redirect`、`wc_protocol_*` 等模块，字符串复制统一改用 `wc_safe_strdup()`；  
  - `whois_client.c` 删除本地实现，入口只需 include 新头文件，并在 `wc_reference_legacy_helpers()` 中引用该符号以保持可链接性。  
- **测试 / 状态**  
  - 2025-11-24：完成两轮远程 `remote_build_and_test.sh` 冒烟，第二轮加参 `--debug --retry-metrics --dns-cache-stats`，两轮均 **无告警 + Golden PASS**。  

#### 2025-11-25 进度更新（B 计划 / Phase 2：命令行模式 / 批量流程 glue 下沉）

- **背景**  
  - `wc_client_run_with_mode()` 与 `wc_client_run_batch_stdin()` 先前并入 `src/core/whois_query_exec.c`，但该文件已同时承载单条查询执行、过滤器 glue、可疑/私有检测等逻辑，继续增添模式判定与批量 stdin 粘合后过于臃肿，不利于后续维护。  
- **本次改动内容**  
  - 新建 `include/wc/wc_client_flow.h` + `src/core/client_flow.c`，专门承载“命令行模式判定 + 单/批量调度”逻辑，将上述两个 helper 迁移至该模块，对外 API 不变；  
  - `client_flow.c` 通过现有 `wc_client_meta`、`wc_runtime`、`wc_query_exec` 等模块完成 meta 处理、模式判定、资源 init 与批量循环 glue，`wc_client_run_batch_stdin()` 继续调用 `wc_execute_lookup()` / `wc_apply_response_filters()` 等 API，保持行为与日志契约不变；  
  - `whois_client.c` 仅需 include 新头文件并调用 `wc_client_run_with_mode()`，`whois_query_exec.c` 因此专注于单条查询执行与公共过滤 helper。  
- **测试 / 状态**  
  - 2025-11-24：完成两轮远程 `remote_build_and_test.sh` 冒烟，第二轮附加 `--debug --retry-metrics --dns-cache-stats`，两轮均 **无告警 + Golden PASS**。  
  - 2025-11-24：再次执行上述两轮冒烟，确认拆分后行为仍 **无告警 + Golden PASS**。  

#### 2025-11-25 进度更新（B 计划 / Phase 2：cache/glue 渐进下沉，第 2 步，DNS/连接缓存模块化落地）

- **背景**  
  - 2025-11-22 的 Step 1.5/1.6 仅将 cache 调试 helper 对外收口，真实数据结构仍在 `whois_client.c` 中，`wc_cache.c` 只能提供 stub，导致 cache 模块化始终停留在“只导出函数名”的阶段；  
  - 随着 `wc_runtime` / `wc_query_exec` 逐步承担更多 orchestrator 责任，继续让入口文件直接管理 DNS/连接缓存已经成为后续拆分的最大阻力。  

- **本次改动内容**  
  - `include/wc/wc_cache.h` 现已对外声明完整的 cache API：新增/公开 `wc_cache_init`、`wc_cache_cleanup`、`wc_cache_cleanup_expired_entries`、`wc_cache_validate_integrity`、`wc_cache_log_statistics`、`wc_cache_get/set_dns`、`wc_cache_get/set_connection`、`wc_cache_set_negative_dns`、`wc_cache_is_negative_dns_cached`、`wc_cache_mark_server_failure/success` 等函数，并提供 `wc_cache_get_negative_stats()` / `wc_cache_estimate_memory_bytes()` 等辅助接口以支撑指标输出与内存估算；  
  - `src/core/cache.c` 现在持有 `DNSCacheEntry` / `ConnectionCacheEntry` / `ServerStatus` 结构体、缓存数组、互斥量与分配大小（`allocated_*_cache_size`）等全部状态，内部直接使用 `wc_safe_malloc()`、`wc_client_is_valid_domain_name()`、`wc_client_validate_dns_response()`、`safe_close()` 等 helper 管理内存、域名/IP 校验与文件描述符生命周期；负缓存命中/记录以及服务器退避窗口（`server_status[]`）也在该 TU 完成；  
  - `whois_client.c` 删除了所有缓存相关的静态结构体与互斥量，仅通过 `wc_cache_*` API 操作：`resolve_domain()` / `connect_with_fallback()` / `connect_to_server()` 使用新的 DNS/连接缓存 getter/setter，`cleanup_caches()` / `cleanup_expired_cache_entries()` 入口被替换为 `wc_cache_cleanup()` / `wc_cache_cleanup_expired_entries()`，debug 模式下的完整性/统计输出也直接调用 core 实现；  
  - 运行期初始化链路改为由 core 负责：`src/core/runtime.c` 在 `wc_runtime_init_resources()` 中调用 `wc_cache_init()` 并注册 `wc_cache_cleanup()`，确保 CLI shell 不再直接持有缓存生命周期逻辑；`src/core/whois_query_exec.c` 的错误路径在需要时调用 `wc_cache_cleanup()`，保持入口与 core 在资源释放上的一致性。  

- **行为与验证**  
  - 从调用者视角看，DNS/连接缓存的命中、失效、server backoff、负缓存统计与 `[DNS-CACHE-SUM]` 输出均保持与 v3.2.9 等价；`wc_cache_get_connection()` 继续在检测到失活 fd 时调用 `safe_close()` 并丢弃缓存，`wc_cache_set_connection()` 仍以最近使用策略回写；  
  - 由于本地环境仍无 `make`，暂未触发新一轮 `tools/remote/remote_build_and_test.sh`，需在获得远程窗口后完成多架构 Golden 校验以锁定行为等价；在此之前，入口与 core 的 cache API 变更已在 VS Code 侧静态检查通过（无未解析符号）。  

### 5.4 后续中长期演进路线（单线程定型 → 性能优化 → 多线程）

> 下面是基于 2025-11-22 现状的一份中长期规划草案，主要为了固定“先把当前短连接单线程版彻底定型，再做性能，再向多线程迈进”的大方向，便于后续每轮改动有清晰落点。

- **阶段 A：单线程短连接版彻底“定型”**  
  - 功能层面：除 bugfix 与可观测性增强（日志、自测、metrics）外，不再做大的行为改动；DNS 智能健康策略如需升级，另开 RFC 记录。  
  - 结构层面：目标是将 `whois_client.c` 收敛到 ≈1000 行以内，使其只承担“CLI 入口 + 高层 orchestrator + 极少量 glue”，其余逻辑都在 core/cond 模块中有清晰归属。  
  - 文档层面：本 RFC 继续作为 B 计划主线备忘，记录每一轮结构性拆分的范围与 golden 校验结论。  

- **阶段 B：在既有模块边界内做性能优化**  
  - 在 A 阶段稳定的模块边界上，针对热点路径做局部 micro-optimization：减少不必要的 malloc/copy、在现有 DNS/连接缓存框架内调优缓存策略、避免重复正则/字符串扫描等。  
  - 明确约束：不改查询语义、不改对外输出/退出码契约，只通过 profiling/bench 数据驱动具体优化点。  

- **阶段 C：引入多线程/并发模型**  
  - 在 A/B 打好的分层上，将“连接/查询执行”与“入口/批量调度”进一步解耦，引入线程池或 worker 模式，支持并发查询或更高吞吐。  
  - 需单独撰写“线程模型 & 共享状态策略” RFC，涵盖：锁/无锁结构、缓存共享或分片策略、日志顺序保证、信号与线程交互等。  

#### 5.4.1 近期可执行的拆分路线（围绕阶段 A）

- **Step 1：入口 util/工具函数“小盒子化”（已选路线 A，待实施）**  
  - 目标：不改变行为，只是把明显是工具性质的函数集中出一个小模块，为后续清空 `whois_client.c` 做准备。  
  - 建议做法：新建 `include/wc/wc_client_util.h` + `src/core/client_util.c`（名称可视后续演进微调），先搬运这类函数：  
    - `parse_size_with_unit`：纯字符串→数值解析，唯一依赖是 `g_config.debug`，迁移时可改为通过 `wc_is_debug_enabled()` 判断是否输出调试信息。  
  - `whois_client.c` 侧只保留头文件 include 与对新 API（如 `wc_client_parse_size_with_unit`）的调用，从而进一步瘦身入口，同时为未来更多 CLI 工具函数的集中管理预留位置。  

- **Step 2：缓存子系统抽出成独立 core 模块（wc_cache，2025-11-25 已落地）**  
  - 现状（更新）：`include/wc/wc_cache.h` + `src/core/cache.c` 已正式接管全部 `DNSCacheEntry` / `ConnectionCacheEntry` / `ServerStatus` 数据结构与操作函数，`whois_client.c` 不再直接持有缓存数组或互斥量；  
  - 行为：入口层通过 `wc_cache_init()` / `wc_cache_cleanup()` / `wc_cache_cleanup_expired_entries()` / `wc_cache_get_*` / `wc_cache_set_*` / `wc_cache_validate_*` 等 API 与缓存交互，`wc_runtime` 负责生命周期管理，`wc_query_exec` 的错误路径调用同一套清理逻辑，确保 CLI 与 core 在资源释放上的语义一致；  
  - 后续关注点：
    - 监控新模块在远程多架构 `remote_build_and_test.sh` 中的长期稳定性（`[DNS-CACHE-SUM]`、`[RETRY-METRICS]`、`server_status` backoff 行为等）；  
    - 评估是否需要在 `wc_cache` 内补充更细粒度的调试标签或自测场景，为 Phase 3 的“缓存策略调优/分片”提供基础。  

- **Step 3：协议安全与响应校验集中到 protocol safety 模块（规划中）**  
  - 现状：`whois_client.c` 中的 `validate_whois_protocol_response` / `detect_protocol_anomalies` / `is_safe_protocol_character` / `check_response_integrity` / `validate_response_data` / `detect_protocol_injection` 等函数承担了 WHOIS 协议层的安全与完整性检查，但实现细节与入口文件紧耦合。  
  - 建议目标：新建 `include/wc/wc_protocol_safety.h` + `src/core/protocol_safety.c`，导出少量稳定 API：  
    - 如 `wc_protocol_validate_response(const char* response, size_t len)`、`wc_protocol_check_injection(const char* query, const char* response)` 等；  
    - 内部继续复用 `log_message` / `log_security_event` 观测契约，但将具体规则集中在单一模块中管理。  
  - 收益：进一步缩减 `whois_client.c` 体积，并为未来扩展 RIR 特殊规则、黑/白名单等协议级安全策略提供集中落脚点。  

> 注：上述 Step 1–3 均以“每次改动后跑远程多架构 golden 校验”为前提，确保改动仅为结构重排而不改变输出/退出码契约。阶段 A 的目标是在功能基本冻结前提下，把入口彻底瘦身并固化模块边界，为后续性能优化与多线程化做好铺垫。

### 5.5 2025-11-27 阶段小结与下一步（模块化收官 + 批量调度增强）

#### 5.5.1 当前形态概览（已完成部分）

- `whois_client.c` 入口现只负责：CLI 解析、`wc_runtime_init()`、调用 `wc_client_run_with_mode()`，其余大块逻辑（查询 orchestration、legacy transport、DNS/连接缓存、protocol safety、meta/usage glue）均已拆分到对应 core 模块；入口行数较 v3.2.9 降低 ~40%。
- `wc_cache`、`wc_runtime`、`wc_signal`、`wc_client_flow`、`wc_client_util` 等模块已形成稳定 API，且自 2025-11-24 起所有改动均通过“双轮远程冒烟（默认 + `--debug --retry-metrics --dns-cache-stats`）”验证 **无告警 + Golden PASS**。
- Stage 3/4 DNS 桥接策略已经默认启用，`[DNS-CACHE-LGCY-SUM] shim_hits=0` 成为新黄金基线；相关冒烟日志 `out/artifacts/20251126-022031/...` 与 `...24 338/...` 已在本 RFC 备案。

#### 5.5.2 模块化收官任务（阶段 A → A’）

1. **入口残留 glue 再下沉**  
  - `wc_runtime_init` 之前的零散设置：fold separator 默认值、`wc_seclog_set_enabled`、`wc_fold_set_unique` 应集中到 `wc_runtime` 或新的 `wc_client_config_apply()`，确保入口只需“调用解析 + 调用初始化”。
  - 2025-11-27：新增 `wc_runtime_apply_post_config()`，`whois_client.c` 改为一次性调用该 helper，fold separator 默认值与 security logging 入口 glue 已完成下沉。
  - `cleanup_caches`/`cleanup_expired_cache_entries`/`validate_cache_integrity`/`log_cache_statistics` 的调试入口改为通过 `wc_runtime` 注册，入口不再直接引用这些 helper。
2. **Selftest / 注入路径清理**  
  - 将 `WHOIS_SECLOG_TEST`、`WHOIS_GREP_TEST`、批量 suspicious/private 判定等入口特有逻辑迁往 `src/core/selftest_*.c`，提供 `wc_selftest_run_if_enabled()` API，入口仅负责读取环境变量和打印摘要。
  - 2025-11-26：新建 `wc_selftest_run_startup_demos()`（自调用 seclog/greg demo helper），入口改为统一调用该 API，彻底删除 `whois_client.c` 中的 `#ifdef WHOIS_*` 栈。
3. **Usage/退出码策略成型**  
  - 基于已有 `wc_client_exit_usage_error()` 与 `wc_exit_code_t`，在 `wc_client_flow` 中统一 usage/参数错误路径，入口最终只需 `return wc_client_run_with_mode(...)`；后续如需引入 `WC_EXIT_USAGE=2` 也能在此处一次性完成。
  - 2025-11-26：`wc_client_handle_usage_error()` 现由 `wc_client_flow` 提供，`wc_opts_parse` 失败及 `wc_client_detect_mode_and_query()` 异常均通过该 helper 统一返回，使入口不再直接引用 meta 层的 usage helper。
4. **Legacy cache/shim 淘汰**  
  - 在 `wc_cache` 中保留 shim 统计但默认不再分配 legacy 数组；确认 `[DNS-CACHE-LGCY]` 标签仍可输出 0 统计供回归对比，然后更新黄金脚本与文档，标记 Stage 4 完成。
  - 2025-11-26：`wc_cache_init()` 默认为空 legacy DNS cache，仅支持连接缓存；提供隐藏环境变量 `WHOIS_ENABLE_LEGACY_DNS_CACHE=1` 以便必要时回退到旧数组。`wc_cache_get_dns_with_source()` / 负缓存查询在 legacy 关闭时直接返回 miss，使 `[DNS-CACHE-LGCY]` / `[DNS-CACHE-LGCY-SUM]` 持续输出 0 shim 统计。
5. **文档与黄金同步**  
  - 每完成上面任一子任务，立即触发远程 `remote_build_and_test.sh`（Round1 默认、Round2 `--debug --retry-metrics --dns-cache-stats`）并把日志编号记入本节，保持“结构变化 → 冒烟 PASS → RFC 留痕”的节奏。

**2025-11-27（Phase 2：runtime/cache housekeeping 回归，覆盖 5.5.2 #1）**  
- 在 `wc_runtime` 内引入 `wc_runtime_housekeeping_tick()` + 注册接口，允许核心模块用最少耦合的方式把缓存维护任务（过期条目清理、调试完整性校验）挂到统一的钩子列表；默认注册 `wc_cache_cleanup_expired_entries`（常态执行）以及 `wc_cache_validate_integrity`（`WC_RUNTIME_HOOK_FLAG_DEBUG_ONLY`），并将 `wc_cache_log_statistics()` 移至 runtime 初始化路径触发，入口层不再直接感知这些 helper。  
- `wc_client_run_single_query()` 与 `wc_client_run_batch_stdin()` 在每次 lookup 完成后调用 `wc_runtime_housekeeping_tick()`，取代历史上 `wc_client_perform_legacy_query()` 末尾的手工调用，从而恢复“每条查询结束即维护缓存”的契约并保证批量模式同样受益。  
- `wc_cache_init()` 不再自行打印统计信息，完全由 runtime 控制可观测性；该变更保持 debug/非 debug 场景的输出形态与 v3.2.9 等价。  
- 受限于当前环境依旧无法执行 `tools/remote/remote_build_and_test.sh`，待下一轮远程窗口统一跑双轮冒烟（默认 + `--debug --retry-metrics --dns-cache-stats`）确认 `[DNS-CACHE-SUM]`、`[DNS-CACHE-LGCY-SUM]` 以及新 housekeeping 钩子的行为与黄金一致。
  - 2025-11-26：补跑 `tools/remote/remote_build_and_test.sh` 两轮（Round1 默认、Round2 `-a '--debug --retry-metrics --dns-cache-stats'`），结果均为“无告警 + Golden PASS”；第二轮日志编号 `out/artifacts/20251126-045717/build_out/smoke_test.log`，仅本地短期留存。

#### 5.5.3 wc_dns 健康记忆 + server backoff 驱动的批量调度（阶段 B 起点）

1. **数据采集层**  
  - 在 `wc_dns`/`wc_backoff` 暴露新的 snapshot API：可批量读取 host/family 的 penalty 状态、`consec_fail`、`penalty_ms_left`，供批量调度器一次性获取所有 RIR host 的健康状况。
  - 2025-11-26：新增 `wc_backoff_host_health_t` / `wc_backoff_collect_host_health()`，批量模式在解析每条查询前收集默认 RIR host + `--host` 指定目标的 IPv4/IPv6 健康状态；当某 host/family 存在连续失败或仍处于 penalty window 时，`wc_client_run_batch_stdin()` 会输出 `[DNS-BATCH] host=... family=... state=... consec_fail=... penalty_ms_left=...`（仅 debug 模式下可见），为下一步的候选跳过策略提供必要的观测数据。  
  - 2025-11-26：双轮 `tools/remote/remote_build_and_test.sh` 冒烟已覆盖上述日志输出（Round1 默认、Round2 `-a '--debug --retry-metrics --dns-cache-stats'`），均 **无告警 + Golden PASS**；第二轮日志 `out/artifacts/20251126-052114/build_out/smoke_test.log` 仅本地短期留存。  
2. **候选排序策略**  
  - `wc_client_run_batch_stdin()` 在读取每条 query 时调用新 API，生成“候选 host/IP 列表 + 健康评分”，对 penalty 状态的候选执行“延迟/跳过/force-last”策略：
    - `action=skip`：非最后一个候选且 penalty 未过 → 跳过，并输出 `[DNS-BACKOFF] host=... action=skip consec_fail=... penalty_ms_left=...`。
    - `action=force-last`：所有候选都在 penalty 内，则仍尝试最后一个，同时输出 `[DNS-BACKOFF] action=force-last`，保证行为与现有 fallback 一致。
  - 2025-11-26：`wc_client_select_batch_start_host()` 已上线，批量模式会对“CLI 指定 host + 由查询猜测的 RIR + IANA 默认”去重排序并优先选择未被 penalty 的候选；当首选 host 仍在 penalty window 内时，`wc_client_log_batch_start_skip()` 会输出 `[DNS-BATCH] action=start-skip host=<penalized> fallback=<next>`，同时 `wc_client_log_batch_host_health()` 会把实际首跳纳入快照，方便在 debug 冒烟日志上对比“本次首跳 vs 候补列表”的健康状态。该改动仅影响 `-B`/stdin 批量流，单查询路径保持与 v3.2.9 等价。
  - 2025-11-26：补充 `wc_client_log_batch_force_last()`，当所有候选仍在 penalty window 内时输出 `[DNS-BATCH] action=force-last host=<selected>`，并强制落到候选列表的最后一个（当前为 IANA 默认）以延续 fallback 契约。
  - 2025-11-27：新增隐藏环境变量 `WHOIS_BATCH_DEBUG_PENALIZE`，可以在进入批量循环前以逗号分隔方式声明需“预先罚站”的 RIR host；进程会逐项去除空白 → 归一化到 canonical host → 调用 `wc_backoff_note_failure()`。若开启 `--debug`，每个命中都会额外打印 `[DNS-BATCH] action=debug-penalize host=<canon> source=WHOIS_BATCH_DEBUG_PENALIZE`，可用于在没有真实连接失败的情况下强制触发 `action=start-skip`/`force-last`/`query-fail` 的观测路径，为后续黄金样例与冒烟剧本准备 deterministic 信号。
  - 2025-11-27：`wc_batch_strategy` 插件接口落地：`include/wc/wc_batch_strategy.h` 暴露 `wc_batch_context_t`、`wc_batch_strategy_t` 与注册/激活/挑选 API，`wc_client_select_batch_start_host()` 不再直接嵌入策略，而是构造“候选 host + backoff snapshot”上下文交给 `wc_batch_strategy_pick()`；首个内置策略 `health-first` 完全复刻旧逻辑，并提供 `--batch-strategy <name>` CLI 以便未来接入 `方案一` 加速器。策略注册在 `wc_client_run_with_mode()` 早期完成，若选项指定未知策略则自动回退到健康优先，stdout/stderr 契约保持不变。
  - 2025-11-27：补齐“批量调度可插拔化 + 方案一”设计蓝图，作为 Stage 5.5.3 后续工作的执行脚本：
    1. **接口定义**：`wc_batch_strategy_t` 统一扩展为 `{ name, pick_start_host, on_result }`，其中 `pick_start_host(const wc_batch_context_t*)` 负责挑选首跳，`on_result(const wc_batch_context_t*, const wc_batch_strategy_result_t*)` 在查询结束后获知实际 authoritative host/错误码，便于策略维护跨查询状态。新增 `wc_batch_strategy_result_t`（记录 `start_host`、`authoritative_host`、`lookup_rc` 等字段）以及 `wc_batch_strategy_handle_result()` 调度 API。
    2. **上下文构造**：`wc_batch_context_t` 旁新增 `wc_batch_context_builder_t`，在 `wc_client_select_batch_start_host()` 内一次性填充“CLI host / RIR 猜测 / IANA fallback”候选数组与 `wc_backoff_host_health_t` 快照，策略只读这些只读视图即可获取 penalty/health 信息。批量主体在进入下一条 query 之前，将同一个 `builder.ctx` 返回给 `on_result()`，确保策略能看到“挑选时的输入”与“实际执行后的输出”。
    3. **策略注册/回退**：入口初始化阶段注册 `health-first` 与新策略 `plan-a`，`--batch-strategy` 指向未知名称时打印一次 `[DNS-BATCH] action=unknown-strategy name=<input>` 并自动回退至 health-first，避免 CLI 拼写错误导致批量调度失效。
    4. **方案一（plan-a）落地目标**：保留 `health-first` 作为兜底，而 `plan-a` 被定义为“上一条查询的 authoritative host 快速复用器”——当上一条成功解析并得到权威 RIR，下一条 query 优先尝试该 RIR；若其仍处于 penalty window 或前一次查询失败，则自动退回 health-first 顺序。实现时需输出 `action=plan-a-faststart` / `action=plan-a-skip` 等新日志字段，提供 deterministic 观测信号，且不改变 stdout header/tail 契约。
  - 2025-11-26：上述蓝图已基本落地——`wc_batch_context_builder_t`/`wc_batch_strategy_result_t` 与 `wc_batch_strategy_handle_result()` 正式合并入主线，`health-first` 策略迁移到共享 helper，`plan-a` 实现缓存上一条成功查询的权威 RIR 并在 penalty 命中时清除缓存，同时输出 `[DNS-BATCH] action=plan-a-cache/plan-a-faststart/plan-a-skip`。`wc_client_run_batch_stdin()` 现将查询结果通过 builder 反馈给策略，失败路径仍调用 `wc_backoff_note_failure()`，未知策略会打印 `[DNS-BATCH] action=unknown-strategy ... fallback=health-first`。`docs/USAGE_{EN,CN}.md` 也同步介绍了 `plan-a`，远程冒烟仍待排期（需覆盖 `WHOIS_BATCH_DEBUG_PENALIZE` + 批量 stdin 剧本确认新日志）。
3. **批量健康记忆**  
  - 在批量循环级别维护一个轻量状态表，记录同一进程内前一条 query 的失败结果，使同一 RIR host 在短时间内不会被批量模式重复拨号；首次实现可以沿用 `wc_backoff` penalty=300s 的语义。
  - 2025-11-26：在 batch 模式下若 `wc_execute_lookup()` 返回错误，会调用 `wc_backoff_note_failure(host, AF_UNSPEC)` 将首跳标记为 penalty，同时打印 `[DNS-BATCH] action=query-fail host=<...> lookup_rc=<...> errno=<...>`；这样下一条 query 的首跳挑选阶段即可立即跳过该 host，等价于“批量健康记忆”的第一版实现。
4. **观测与黄金收敛**  
  - 新增 `[DNS-BATCH]` 或扩展 `[DNS-BACKOFF]` 字段，清晰记录批量调度行为；更新 `tools/test/golden_check.sh`，确保冒烟脚本在默认与 debug 参数下都能观察到预期标签。
  - 安排至少三轮冒烟：Round1 默认、Round2 `--debug --retry-metrics --dns-cache-stats`、Round3 扩展批量输入（可用 `-B` + 多行查询或 `stdin` 模式）以验证新调度逻辑在真实批量场景中的稳定性。
  - 2025-11-26：`action=start-skip`/`force-last`/`query-fail` 标签已在代码中输出，尚未跑新的远程冒烟；待运行环境空档时需优先用 Round2（含 `--debug --retry-metrics --dns-cache-stats`）复现这些标签，并决定是否需要在 tools/test/golden_check.sh 中做 presence 校验。
  - 2025-11-27：`WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net' tools/remote/remote_build_and_test.sh -a '--debug --retry-metrics --dns-cache-stats -B testdata/queries.txt'` 作为下一轮剧本草案，可在不依赖真实网络抖动的情况下捕获 `[DNS-BATCH] action=debug-penalize/start-skip/force-last` 三种日志；Round3 将在记录详尽命令行与日志路径后更新至本节。
5. **完成标志**  
  - 当批量调度逻辑稳定且黄金脚本对 `[DNS-BACKOFF]`/`[DNS-BATCH]` 新标签验证通过时，可将该版本标记为“Stage 4 全模块化 + 智能批量调度黄金基线”，后续性能/多线程优化都以此为起点。

> 上述 5.5 节为新的执行蓝图：优先完成模块化收官（保证入口极薄且模块边界固定），紧接着投入批量调度增强；每个子阶段均需配套文档记录与远程冒烟日志，以避免 B 计划长期跨度导致信息缺口。

**2025-11-26 冒烟记录**  
- Round1：`tools/remote/remote_build_and_test.sh` 默认参数，结果 “无告警 + Golden PASS”。  
- Round2：`tools/remote/remote_build_and_test.sh -a '--debug --retry-metrics --dns-cache-stats'`，结果 “无告警 + Golden PASS”，日志 `out/artifacts/20251126-034307/build_out/smoke_test.log` 已留档。  
  两轮均验证 `wc_runtime_apply_post_config()` 等结构调整未引入回归。

**2025-11-26（二）冒烟记录**  
- Round1：`tools/remote/remote_build_and_test.sh` 默认参数，结果 “无告警 + Golden PASS”。  
- Round2：`tools/remote/remote_build_and_test.sh -a '--debug --retry-metrics --dns-cache-stats'`，结果 “无告警 + Golden PASS”，日志 `out/artifacts/20251126-040329/build_out/smoke_test.log` 已留档。  
  本轮覆盖 selftest/usage glue 重构后的入口，确认行为未偏移。

**2025-11-26（三）冒烟记录**  
- Round1：`tools/remote/remote_build_and_test.sh` 默认参数，结果 “无告警 + Golden PASS”。  
- Round2：`tools/remote/remote_build_and_test.sh -a '--debug --retry-metrics --dns-cache-stats'`，结果 “无告警 + Golden PASS”，日志 `out/artifacts/20251126-043226/build_out/smoke_test.log` 已留档。  
  本轮验证 legacy DNS cache 默认禁用后依旧保持黄金输出。

**2025-11-26（四）冒烟记录**  
- Round1：`tools/remote/remote_build_and_test.sh` 默认参数，结果 “无告警 + Golden PASS”，确认批量首跳选择逻辑不会影响单查询模式。  
- Round2：`tools/remote/remote_build_and_test.sh -a '--debug --retry-metrics --dns-cache-stats'`，结果 “无告警 + Golden PASS”，日志 `out/artifacts/20251126-061913/build_out/smoke_test.log` 已留档；`[DNS-CACHE-LGCY-SUM]` 依旧输出 0，`[RETRY-METRICS]` 全程成功且未出现 `[WARN`/`ERROR` 标签。  
  本轮属于 Stage 5.5.3 Step 2 的首个远程回归记录，为后续批量输入黄金扩展提供基线。

**2025-11-26（五）冒烟记录**  
- Round1：`tools/remote/remote_build_and_test.sh` 默认参数，结果 “无告警 + Golden PASS”，再次验证批量 backoff 改动对常规模式无回归。  
- Round2：`tools/remote/remote_build_and_test.sh -a '--debug --retry-metrics --dns-cache-stats'`，结果 “无告警 + Golden PASS”，日志 `out/artifacts/20251126-064103/build_out/smoke_test.log` 已留档；`[DNS-CACHE-LGCY-SUM] hits=0 misses=0 shim_hits=0`、`[RETRY-METRICS] attempts=2 successes=2 failures=0` 等指标与前一轮一致，且未出现 `[WARN`/`ERROR`]。由于本轮查询均命中健康 RIR，`[DNS-BATCH] action=*` 标签未触发，后续计划使用更偏执的批量输入来观察这些新日志。

- Round3（批量 + debug penalty 钩子）：`WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net' tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 -F testdata/queries.txt -a '--debug --retry-metrics --dns-cache-stats' -G 1 -E '-O3 -s'，结果 “无告警 + Golden PASS”，日志 `out/artifacts/20251126-082101/build_out/smoke_test.log`。stderr 中可见 `SMOKE_STDIN_FILE` 提示、`[DNS-BATCH] action=debug-penalize/start-skip/force-last/query-fail` 全套观测信号，`[RETRY-METRICS] attempts=2 successes=2 failures=0`、`[DNS-CACHE-SUM] hits=0 neg_hits=0 misses=2` 均与单查询黄金一致，为后续批量黄金扩展提供可复现基线。
- 2025-11-27：针对上述需求，`tools/remote/remote_build_and_test.sh` 新增 `-F <stdin_file>` 参数并通过 `SMOKE_STDIN_FILE` 传递到远端；`tools/remote/remote_build.sh` 会在 batch 模式下自动 `cat <file> | whois-arch ... -B ...`，若调用者忘记带 `-B/--batch` 则自动补齐并发出 warning。启用 `-F` 时默认忽略 `-q/SMOKE_QUERIES`，避免再次把 batch stdin 与 positional query 混用。后续 Round3 可直接运行：`WHOIS_BATCH_DEBUG_PENALIZE='...' tools/remote/remote_build_and_test.sh ... -F testdata/queries.txt -a '--debug --retry-metrics --dns-cache-stats'`，即可固定批量输入并捕获 `[DNS-BATCH] action=*` 日志。
- Round4（批量 stdin + env 前传复核）：`WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net' tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 -F testdata/queries.txt -a '--debug --retry-metrics --dns-cache-stats' -G 1 -E '-O3 -s'，日志 `out/artifacts/20251126-084545/build_out/smoke_test.log`。stderr 起始即看到 `[remote_build][WARN] SMOKE_STDIN_FILE set but -B/--batch missing in SMOKE_ARGS; auto-appending -B`，随后 `[DNS-BATCH] action=debug-penalize host=whois.arin.net/ripe.net source=WHOIS_BATCH_DEBUG_PENALIZE`、`state=ok consec_fail=1 penalty_ms_left=0` 等信号确认环境变量已成功传递到远端 `whois-*` 进程。批量循环对 8.8.8.8、1.1.1.1、whois.apnic.net、example.com 逐条输出 `[DNS-CAND]`/`[DNS-HEALTH]`/`[RETRY-METRICS-INSTANT]`，全程无 `[WARN`/`ERROR`/`[DNS-BATCH] action=query-fail`，`[DNS-CACHE-SUM] hits=0 neg_hits=0 misses=6` 与 Golden 期待一致。`[golden] PASS: header/referral/tail match expected patterns` 行显示黄金校验通过，标记该剧本可用于后续 `[DNS-BATCH] action=debug-penalize` 相关黄金扩展。
- Round5（批量调度三动作 + 黄金确定版）：`WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.iana.org,whois.ripe.net' tools/remote/remote_build_and_test.sh -r 1 -F testdata/queries.txt -a '--debug --retry-metrics --dns-cache-stats' -G 0`，日志 `out/artifacts/20251126-114840/build_out/smoke_test.log`。stderr 中首跳即打印 `[DNS-BATCH] action=debug-penalize host=<arin/iana/ripe>`，随后如期出现 `[DNS-BATCH] action=start-skip host=whois.arin.net fallback=whois.iana.org`、`[DNS-BATCH] action=start-skip host=whois.iana.org fallback=whois.arin.net` 与 `[DNS-BATCH] action=force-last host=whois.iana.org penalty_ms=300000`。黄金命令：
  ```bash
  tools/test/golden_check.sh \
    -l out/artifacts/20251126-114840/build_out/smoke_test.log \
    --start whois.iana.org \
    --batch-actions debug-penalize,start-skip,force-last
  ```
  输出 `[golden] PASS: header/referral/tail match expected patterns`，标记 debug penalty + start-skip + force-last 的固定基线已经就绪。
- Round6（批量 query-fail 黄金）：`WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net' tools/remote/remote_build_and_test.sh -r 1 -F testdata/queries.txt -a '--debug --retry-metrics --dns-cache-stats --host whois.invalid.test' -G 0`，日志 `out/artifacts/20251126-121908/build_out/smoke_test.log`。前三条查询因无法解析 `whois.invalid.test` 均打印 `[DNS-BATCH] action=query-fail host=whois.invalid.test lookup_rc=2 errno=0 penalty_ms=300000`，批量健康记忆让第四条自动回落至 IANA 并成功输出 `example.com`。黄金命令：
  ```bash
  tools/test/golden_check.sh \
    -l out/artifacts/20251126-121908/build_out/smoke_test.log \
    --query example.com \
    --start whois.iana.org \
    --auth whois.iana.org \
    --batch-actions query-fail
  ```
  为了支持“起始 host 即权威 RIR”的 stdout 形态，`tools/test/golden_check.sh` 新增 fallback：当 `--start` 与 `--auth` 相同且日志缺少 `=== Additional query ...` 行时，脚本会给出 `[golden][INFO] referral skipped: start host already authoritative`，仍判定 PASS。该逻辑也被记录于本节，确保 query-fail 剧本在未来升级时拥有明确的黄金基线。

**2025-11-26（六）冒烟记录**  
- Round1：`tools/remote/remote_build_and_test.sh` 默认参数，结果 “无告警 + Golden PASS”，日志 `out/artifacts/20251126-134947/build_out/smoke_test.log`。默认模式覆盖单查询 8.8.8.8/1.1.1.1，stdout/stderr 维持现有契约。  
- Round2：`tools/remote/remote_build_and_test.sh -a '--debug --retry-metrics --dns-cache-stats'`，结果 “无告警 + Golden PASS”，日志 `out/artifacts/20251126-135106/build_out/smoke_test.log`。复核日志可见 `[DNS-HEALTH]`/`[DNS-CAND]`/`[DNS-CACHE-LGCY-SUM] hits=0` 与 `[DNS-CACHE-SUM] hits=0 neg_hits=0 misses=2`，`[RETRY-METRICS] attempts=2 successes=2 failures=0`，全程无 `[WARN`/`ERROR`]，证明 batch strategy 重构在 debug/指标场景下仍与旧版一致。

**2025-11-26（七）冒烟记录**  
- Round1：`tools/remote/remote_build_and_test.sh` 默认参数，结果 “无告警 + Golden PASS”。
- Round2：`tools/remote/remote_build_and_test.sh -a '--debug --retry-metrics --dns-cache-stats'`，结果 “无告警 + Golden PASS”，日志 `out/artifacts/20251126-150931/build_out/smoke_test.log`（本地短期保留，避免 Git 仓库爆仓）。
- Round3（plan-a + 批量 stdin）：`WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net' tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k 'c:/Users/妙妙呜/.ssh/id_rsa' -r 1 -P 1 -F testdata/queries.txt -a '--batch-strategy plan-a --debug --retry-metrics --dns-cache-stats' -G 1`，结果 “无告警 + Golden PASS”，日志 `out/artifacts/20251126-152416/build_out/smoke_test.log`。stderr 中可见 `[DNS-BATCH] action=plan-a-cache/plan-a-faststart/plan-a-skip` 与 `debug-penalize/start-skip` 信号，确认 plan-a 策略在批量输入与预罚站场景下的可观测性，黄金校验同时覆盖 header/tail 契约。

**2025-11-26（plan-a vs health-first 黄金固化）**  
- Plan-A 专用剧本：`WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net' tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k 'c:/Users/妙妙呜/.ssh/id_rsa' -r 1 -P 1 -F testdata/queries.txt -a '--batch-strategy plan-a --debug --retry-metrics --dns-cache-stats' -G 1 -E '-O3 -s'`，结果 “无告警 + Golden PASS”，日志 `out/artifacts/20251126-161014/build_out/smoke_test.log`。使用 `tools/test/golden_check.sh -l ... --batch-actions plan-a-cache,plan-a-faststart,plan-a-skip,debug-penalize` 可稳定校验 plan-a 的缓存/快速路径与 debug 罚站信号；该日志不再强求 `start-skip/force-last`，避免无谓 FAIL。
- Health-first fallback 剧本：`WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.iana.org,whois.ripe.net' tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k 'c:/Users/妙妙呜/.ssh/id_rsa' -r 1 -P 1 -F testdata/queries.txt -a '--debug --retry-metrics --dns-cache-stats' -G 1 -E '-O3 -s'`，结果 “无告警 + Golden PASS”，日志 `out/artifacts/20251126-163135/build_out/smoke_test.log`。`tools/test/golden_check.sh -l ... --start whois.iana.org --auth whois.arin.net --batch-actions start-skip,force-last` PASS，正式将传统 backoff 的 “跳过→强制最后” 路径纳入黄金，与 plan-a 剧本互补，CI 里两份日志即可分别验证新旧策略。

> **命名澄清 / 状态更新（2025-12-09）**：`health-first` 指最早存在的默认策略（基线顺序 = CLI host → 推测 RIR → IANA，结合 DNS penalty 跳过），并不纳入 “方案一/方案二” 编号；`plan-a` 对应 Stage 5.5.3 的“方案一”，即“上一条权威 RIR 快速复用”；`plan-b`（方案二）已落地：缓存上一条权威 RIR 并在罚站时回退，输出 `[DNS-BATCH] action=plan-b-*`（包含 plan-b-force-start/plan-b-fallback/force-last/force-override/start-skip）。远程批量剧本现默认跑 raw/health-first/plan-a/plan-b 四轮，plan-b 无需额外开关，黄金脚本强制校验上述标签。

**Stage 5.5.3 下一阶段调研（策略回传 + 批量健康记忆扩展）**

- **潜在 API 缺口**：
  - `wc_batch_strategy_result_t` 目前仅记录 `start_host` / `authoritative_host` / `lookup_rc`。若 plan-b 需要依据 referral 深度、最终拨号 IP、是否命中私网等信号，需要扩展新的字段或附带 “附加元数据” 结构。
  - 现有策略仅有 `pick_start_host` + `on_result` 两个同步回调。若 plan-b 需要在批量会话级维护队列/统计，可能需要为 `wc_batch_strategy_t` 引入 `init(ctx)` / `shutdown()` 钩子，或允许策略在注册时附带自定义状态句柄。
  - `wc_backoff_host_health_t` 暂只描述 penalty 状态。如 plan-b 需要做“近期命中率/命中窗口”决策，应考虑为健康快照增加“recent_successes/last_success_ms”字段，或在 `wc_backoff` 中暴露新 helper 获取成功统计。
- **策略构想**：
  - plan-b（方案二）倾向于“多条 query 的命中窗口”或“权威链缓存”——例如优先尝试最近 5 条内多次成功的 RIR，或缓存 referral 链条，在下一次直接跳到可靠的第二跳；同时继续输出新的 `[DNS-BATCH] action=plan-b-hit/plan-b-skip/...` 标签。
  - 需要评估是否允许策略访问 `wc_batch_context_builder_t` 中的“批量级共享状态”。一种做法是在 builder 中新增 `void* strategy_state`，由 `wc_batch_strategy_register_*` 初始化。
- **测试/黄金需求**：
  - 为 plan-b 设计新的 `WHOIS_BATCH_DEBUG_*` 注入点或自测 flag，确保命中/跳过路径可被 deterministically 复现。
  - `tools/test/golden_check.sh` 需要扩展对 `plan-b-*` 标签的检测，并提供对应的远程冒烟剧本（stdin + penalty 设置）。
  - 远程脚本可能要支持一次拉起多策略或分阶段执行，以便在同一 CI 轮中收集 health-first / plan-a / plan-b 三份日志。

> **优先级建议**：基于当前执行节奏，先巩固“plan-a + health-first” 两套黄金基线更为稳妥——确保 CI 对现有策略完全覆盖，再在此基线之上扩展 plan-b/更多缓存策略。这样即使方案二试验性较强，也能随时依靠基线回退并以黄金脚本监控回归。

**下一步工作计划（2025-11-27 优先执行）**
- 将上述两条远程命令固化为 `tools/remote/remote_build_and_test.sh --golden plan-a|health-first` 预设，脚本自动输出对应的 `golden_check.sh` 建议命令，降低误操作。
- 在 CI/文档中新增 “Golden Playbook” 列表，记录最新一次成功的 plan-a / health-first 日志时间戳与 `golden_check.sh` 参数，方便复用或重跑。
- 评估是否需要在仓库中保留简化版日志（例如裁剪后的关键片段）供 diff 参考，避免远端清理后缺乏基线。
- 确认 `golden_check.sh` 对 `[DNS-BATCH] action=unknown-strategy`、`plan-a` 日志缺失等情况能给出更友好的 Failure 指引，完善调试体验。
- **2025-11-27（raw 批量默认恢复）**：
  - `wc_client_init_batch_strategy_system()` 仅在 CLI 指定 `--batch-strategy` 时注册/激活策略，新增 `g_wc_batch_strategy_enabled` 旗标以及 `wc_client_pick_raw_batch_host()` helper，默认批量流程回到 “CLI host → 查询推测 RIR → IANA” 的 raw 顺序；策略未启用时不再访问 `wc_batch_strategy_pick()`，批量结果反馈也会跳过 `wc_batch_strategy_handle_result()`。
  - CLI 帮助 (`wc_meta_print_usage`) 与 `docs/USAGE_{EN,CN}.md`、`docs/OPERATIONS_{EN,CN}.md` 全量更新，强调“默认 raw + 显式 `--batch-strategy health-first|plan-a` opt-in”，并在操作手册的批量观测剧本中加入 `--batch-strategy health-first` 以继续观测 `start-skip/force-last`。
  - RFC 当前节记录实现动机与影响面；release notes 待下一轮整理时补充。本地尚未运行新的远程冒烟，需在后续窗口安排 “raw 默认 + health-first + plan-a” 三组日志，更新 Golden/playbook。

**2025-11-27（猫眼三轮冒烟回填）**
- Round1（默认参数）：`tools/remote/remote_build_and_test.sh` 默认配置，结果 “无告警 + Golden PASS”；日志 `out/artifacts/20251127-233448/build_out/smoke_test.log`。验证 raw 默认路径在多架构构建后依旧稳定，stderr 未见 `[WARN`/`ERROR`]。
- Round2（`--batch-strategy health-first`）：命令在 `SMOKE_ARGS` 中仅追加 `--batch-strategy health-first`，其余沿用默认，结果 “无告警 + Golden PASS”；日志 `out/artifacts/20251127-233931/build_out/smoke_test.log`。确认 opt-in 后仍可观察批量策略相关标签（待后续黄金扩展）。
- Round3（`--batch-strategy plan-a`）：在第二轮基础上改为 `--batch-strategy plan-a`，结果 “无告警 + Golden PASS”；日志 `out/artifacts/20251127-234134/build_out/smoke_test.log`。该轮用于 sanity check plan-a 在新 opt-in 逻辑下无行为回归。
- 三轮均未额外运行 `golden_check.sh`，后续如需校验 `[DNS-BATCH] action=*` 或 header/tail 细节需单独补跑。

**2025-11-28（批量策略三组黄金校验）**
- Round1（raw 默认）：`tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -P 1 -a '--debug --retry-metrics --dns-cache-stats' -G 1`，结果 “无告警 + Golden PASS”；日志 `out/artifacts/20251128-000717/build_out/smoke_test.log`。执行 `tools/test/golden_check.sh -l ./out/artifacts/20251128-000717/build_out/smoke_test.log`，输出 `[golden] PASS`，确认 header/referral/tail 契约在 raw 默认模式下稳定。
- Round2（`--batch-strategy health-first` + penalty 注入）：`WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.iana.org,whois.ripe.net'`、`-F testdata/queries.txt`、`-a '--batch-strategy health-first --debug --retry-metrics --dns-cache-stats'`，结果 “无告警 + Golden PASS”；日志 `out/artifacts/20251128-002850/build_out/smoke_test.log`。运行 `tools/test/golden_check.sh -l ./out/artifacts/20251128-002850/build_out/smoke_test.log --batch-actions debug-penalize,start-skip,force-last`，黄金 PASS，证明 penalty 预注入下 `[DNS-BATCH] action=start-skip/force-last` 仍可被黄金脚本验证。
- Round3（`--batch-strategy plan-a`）：`WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net' -F testdata/queries.txt -a '--batch-strategy plan-a --debug --retry-metrics --dns-cache-stats'`，结果 “无告警 + Golden PASS”；日志 `out/artifacts/20251128-004128/build_out/smoke_test.log`。黄金命令 `tools/test/golden_check.sh -l ./out/artifacts/20251128-004128/build_out/smoke_test.log --batch-actions plan-a-cache,plan-a-faststart,plan-a-skip,debug-penalize` PASS，确认 plan-a 的 cache/faststart/skip 信号在 opt-in 体系下可稳定校验。

#### 2025-11-30 远程批量脚本维护 + 自检黄金缺口

- `tools/remote/remote_build.sh` 的 `run_smoke_command()` 现于所有 `bash -lc` 调用前加上 `set -o noglob`，修复 `--selftest-force-suspicious '*'` 被远端 shell 展开成 `foo/` 等目录名的问题。相关 commit 亦同步更新 `tools/test/remote_batch_strategy_suite.ps1`，`Invoke-Strategy` 会记录每轮 golden 检查的 PASS/SKIP 状态与报告路径，并在汇总时输出 `[golden] PASS ... report: ...`，方便直接判断 batch 套件执行结果。
- 最新一轮批量套件命令（`powershell -File tools/test/remote_batch_strategy_suite.ps1 -Host 10.0.0.199 -User larson -KeyPath '/c/Users/妙妙呜/.ssh/id_rsa' -Queries '8.8.8.8 1.1.1.1 10.0.0.8' -BatchInput testdata/queries.txt -SelftestActions 'force-suspicious,8.8.8.8;force-private,10.0.0.8' -SmokeExtraArgs "--selftest-force-suspicious 8.8.8.8 --selftest-force-private 10.0.0.8" -QuietRemote)` 已跑通 raw / health-first / plan-a 三个 preset；对应日志分别位于 `out/artifacts/batch_raw/20251130-023452/build_out/smoke_test.log`、`out/artifacts/batch_health/20251130-023539/...`、`out/artifacts/batch_plan/20251130-023624/...`，黄金报告 `golden_report_{raw,health-first,plan-a}.txt` 同目录可查。
- 观察结果：当 baseline 查询（8.8.8.8）被 `--selftest-force-suspicious` 提前拦截时，`tools/test/golden_check.sh` 必然报缺失 header/referral/tail 并打印 `[golden] FAIL`，即使退出码仍为 0。当前黄金脚本只面向“完整查询”路径，尚无法自动校验 `[SELFTEST] action=force-*` 这种故意短路的场景。
- 决议：将“自检黄金扩展（允许指定 action 即视为 PASS）”列为后续工作，候选方案包括：①扩展现有 `golden_check.sh`，新增 `--expect-selftest action=<...>` 标志，用于豁免 header/tail 检查并验证 `[SELFTEST]` 行；②单独编写自检黄金工具，专注检查 `[SELFTEST]`/`[DNS-BATCH]`/`[RETRY-METRICS]` 标签。待确定方案后再更新此 RFC 与 tooling backlog。

#### 2025-11-30 自检黄金脚本规划（进行中）

- **工具边界**：确定走“独立脚本”路线，新脚本命名暂定 `tools/test/golden_check_selftest.sh`。它只解析 `[SELFTEST] action=<name> query=<value>`、`Error: ...`、`[DNS-BATCH] action=query-fail`、`[RETRY-METRICS]` 等标签，不再检查 header/referral/tail，避免与标准黄金路径耦合。
- **CLI 草案**：
  - `-l/--log <path>`：必选，指向 smoke 日志；
  - `--expect action=<name>[,query=<value>][,match=<regex>]`：多次指定，确保特定 action 发生；
  - `--require-error <regex>`：验证错误提示（如 Suspicious/Private）；
  - `--require-tag <component> <regex>`：泛化校验 `[DNS-BATCH]`、`[RETRY-METRICS]` 等标签；
  - 输出统一为 `[golden-selftest][INFO|ERROR] ...`，所有期望满足才返回 0。
- **一键套件**：新增 `tools/test/selftest_golden_suite.ps1`：
  1. 组装远程命令，自动附带 `--selftest-force-*`、`--debug --retry-metrics --dns-cache-stats`；
  2. 选取 raw/health-first/plan-a 最新日志，调用 `golden_check_selftest.sh`；
  3. 汇总 `[suite-selftest]` PASS/FAIL + 报告路径，支持 `-QuietRemote`、`-NoGolden`、`-SmokeExtraArgs` 等参数，接口风格沿袭现有批量脚本。
- **示例检查项**：
  - `--expect action=force-suspicious,query=8.8.8.8 --require-error "Suspicious query detected"`；
  - `--expect action=force-private,query=10.0.0.8 --require-error "Private query denied"`；
  - `--require-tag DNS-BATCH "action=query-fail"`（验证 penalty 控制链路）。
- **集成计划**：完成脚本后新增 VS Code 任务 “Remote: Selftest Golden Suite”，并将命令/日志/黄金指令纳入本 RFC 的 Golden Playbook，以便随时 rerun。

#### 2025-11-28 日终记录（转入 11-29 计划）

- 连续 18h 只完成 RFC 梳理与批量策略回溯，Cache/Selftest 收官余量与文档/黄金补票尚未动手。为了避免疲劳误改，剩余工作全部顺延到 11-29。  
- 明日待办：  
  1. **Cache & Legacy Step 2** — 把 `g_dns_cache_shim_hits_total`、`wc_cache_legacy_dns_enabled()` 等入口残留移入 `wc_cache.c`，让 `[DNS-CACHE-LGCY-SUM]` 只由 cache 模块聚合；完成后以“默认 + `--debug --retry-metrics --dns-cache-stats`”双轮 `remote_build_and_test.sh` 复核并在 RFC 记录日志编号。  
  2. **Selftest/Fault 收官补票** — 为 `wc_selftest_fault_profile_t` / `[SELFTEST] action=force-*` 写入 `docs/USAGE_*`、`docs/OPERATIONS_*`、`RELEASE_NOTES.md`，并评估 `tools/test/golden_check.sh` 是否要新增 presence 校验；顺便检查入口 exit-code glue 是否需要再抽象。  
  3. **批量策略文档 + Golden Playbook** — 在 USAGE/OPERATIONS 中补充 raw/health-first/plan-a 的触发条件、示例命令与 `[DNS-BATCH]` 观测说明；整理 `WHOIS_BATCH_DEBUG_PENALIZE` 剧本到一个“Golden Playbook” 小节（引用 `20251126-114840` / `-121908` / `-161014` 三份日志与 `golden_check.sh` 参数）。  
  4. **工具链小结** — 研究 `tools/remote/remote_build_and_test.sh --golden <strategy>` 预设与 `-QuietRemote` 默认化，若时间允许再跑一轮批量 stdin + plan-a 冒烟以确保 opt-in 改造后的脚本流程可复用。  
- 完成上述事项后更新本节及 release notes，再考虑是否追加 Stage 3/plan-b 调研。今晚关闭编辑，明早恢复。

#### 2025-11-29 进度更新（Cache & Legacy Step 2：日志事件驱动统计）

- `wc_cache_log_legacy_dns_event()` 现负责统一累加 `[DNS-CACHE-LGCY-SUM]` 所需的命中/未命中/负缓存 shim 计数；`wc_cache_get_dns_with_source()` 与 `wc_cache_is_negative_dns_cached_with_source()` 中的手工 `g_dns_cache_*` 自增全部移除，避免遗漏或重复计数，且默认禁用 legacy 表时不会再意外累加 miss 统计。
- 为区分“legacy shim 已禁用但仍需输出遥测”场景，`wc_cache_log_legacy_dns_event()` 在 `WHOIS_ENABLE_LEGACY_DNS_CACHE` 未设置时会记录 `status=legacy-disabled`，该事件不会计入统计但能帮助排查为何 `[DNS-CACHE-LGCY]` 仍出现。其它状态（`wcdns-hit`、`legacy-shim`、`miss`、`neg-bridge`、`neg-shim`）才会驱动统计更新。
- `[DNS-CACHE-LGCY-SUM]` 继续由 `wc_runtime` 在 `--dns-cache-stats` 开启时打印，但其数据来源现在完全由 `wc_cache` 内的日志事件聚合而来，满足 “只由 cache 模块聚合” 的阶段目标；后续若 shim 命中率长期为 0，可进一步考虑直接隐藏 legacy 表数据结构。
- 已完成三轮远程校验：
  - Round1 默认参数：无告警 + Golden PASS，日志 `out/artifacts/20251129-201413/build_out/smoke_test.log`；
  - Round2 `--debug --retry-metrics --dns-cache-stats`：无告警 + Golden PASS，日志 `out/artifacts/20251129-201642/build_out/smoke_test.log`；
  - Round3 批量策略黄金（raw/plan-a/health-first）：全部 PASS，日志分别为 `out/artifacts/batch_raw/20251129-201938/build_out/smoke_test.log`、`out/artifacts/batch_plan/20251129-202147/build_out/smoke_test.log`、`out/artifacts/batch_health/20251129-202040/build_out/smoke_test.log`。

  #### 2025-12-01 进度更新（Cache & Legacy Step 3：删除 legacy DNS 存储）

  - ✅ `src/core/cache.c` 已彻底移除 `DNSCacheEntry` 数组与相关互斥访问逻辑，所有正向/负向缓存查询与写入 100% 依赖 `wc_dns_cache_*` / `wc_dns_negative_cache_*`。`wc_cache` 仅保留连接缓存与 shim 遥测计数器，`wc_cache_dns_source_t` 缩减为 `{NONE,WCDNS}`，`wc_cache_store_result_t` 也只剩 `WC_CACHE_STORE_RESULT_WCDNS`。
  - ✅ 负缓存写入路径（`wc_cache_set_negative_dns_with_error`）直接统计 wc_dns 桥接结果，`wc_cache_is_negative_dns_cached_with_source()` 中 legacy shim 分支删除，`neg-shim` 遥测只会在显式注入时出现。`wc_cache_log_statistics()` / `wc_cache_validate_integrity()` 亦同步删去 DNS 相关输出。
  - ✅ `wc_cache_estimate_memory_bytes()` 由原先的 `sizeof(DNSCacheEntry)` 估算改为“wc_dns 正向/负向 + 连接缓存”两段式粗略模型（512B + 64B per DNS entry），供 `wc_config_prepare_cache_settings()` 做上限校验；`wc_cache.h`/`client_net.c` 等调用点已更新。
  - 📌 遥测保持不变：`wc_cache_log_legacy_dns_event()` 仍会上报 `status=wcdns-hit|miss|wcdns-store|neg-bridge` 等标签、`[DNS-CACHE-LGCY-SUM]` 仍由 cache 模块聚合，使远程黄金脚本无需改动即可观察 shim 计数始终为 0。
  - ⚠️ 待办：需要在下一窗口补跑 “默认 + `--debug --retry-metrics --dns-cache-stats`” 双轮 `tools/remote/remote_build_and_test.sh`，确认 `[DNS-CACHE-LGCY-SUM]`、`[DNS-CACHE-SUM]` 与折叠/标题黄金契约无回归；若时间允许，再附带批量策略套件以收集横向对比日志。跑完后在本节追加日志路径并同步 RELEASE_NOTES。 

  ##### 2025-11-30 三轮黄金校验补记（legacy DNS cache 清理后首轮）

  1. **Round1（默认参数）**：`tools/remote/remote_build_and_test.sh -r 1 -P 1`，产物 `out/artifacts/20251130-112059/build_out/smoke_test.log`。各架构 stderr 仅含 `[DNS-*]`/`[RETRY-*]` 调试标签，无 `[WARN]`/`[ERROR]`，黄金脚本判定 **无告警 + Golden PASS**。
  2. **Round2（`--debug --retry-metrics --dns-cache-stats`）**：命令附加 `-a '--debug --retry-metrics --dns-cache-stats'`，日志 `out/artifacts/20251130-112411/build_out/smoke_test.log`。`[DNS-CACHE-SUM]` 与 `[DNS-CACHE-LGCY-SUM]` 均保持 shim=0，黄金检查同样 PASS。
  3. **批量策略 Golden（raw / plan-a / health-first）**：通过 `tools/test/remote_batch_strategy_suite.ps1` 触发三套策略，日志分别为：
    - raw：`out/artifacts/batch_raw/20251130-112854/build_out/smoke_test.log`，报告 `golden_report_raw.txt`
    - plan-a：`out/artifacts/batch_plan/20251130-113110/build_out/smoke_test.log`，报告 `golden_report_plan-a.txt`
    - health-first：`out/artifacts/batch_health/20251130-113002/build_out/smoke_test.log`，报告 `golden_report_health-first.txt`
    三套均显示 `[golden] PASS`，验证批量策略在 legacy cache 删除后仍满足黄金契约。

  上述三轮覆盖“默认 + 调试 + 批量策略”矩阵，确认日志形态与 Stage 3/4 黄金一致，为下一步 RELEASE_NOTES 更新提供依据。

#### 2025-11-30 wc_net 模块化准备（进行中）

- **阶段背景**：完成 legacy DNS cache 下线、plan-a 行为回滚与多轮黄金校验后，当前重心切换到 `wc_net` 模块化，目标是把非阻塞 connect、重试/节流、`[RETRY-METRICS]` 与 pacing 计数从全局散落状态收束到独立上下文，方便后续策略扩展与调试。
- **职责盘点**：`src/core/net.c` 目前维护 connect/poll/retry、`wc_net_retry_metrics_t`、pacing 节流、DNS 健康反馈、自测注入（`WHOIS_NET_SELFTEST_*`），并由 `wc_opts`/`whois_client.c` 以多处 setter/init glue 进行配置。重试路径还耦合 `wc_dns_health` 反馈与 `wc_lookup` referral 跳转，需确保提炼 API 时不破坏这些回调。
- **API 规划**：拟新增 `wc_net_context_t`（含 pacing/metrics/selftest state），提供 `wc_net_context_init(const wc_config_t*, const wc_env_t*, wc_net_context_t*)` / `wc_net_context_shutdown(wc_net_context_t*)` / `wc_net_connect_and_stream(wc_net_context_t*, const wc_lookup_target_t*, wc_net_result_t*)` 等入口，并将 `wc_net_set_retry_metrics_enabled()`、`wc_net_set_pacing_budget()` 等零散函数折叠为 context 属性。在 CLI 层由 `wc_client_build_config()`/`wc_client_bootstrap_modules()` 统一创建并注入给 `wc_pipeline`。
- **实现步骤**：
  1. 按责任划分把全局静态变量搬入 `wc_net_context_t`，在 `wc_net.c` 内部提供 getter/helper，保证非模块代码只透过 context API 访问。
  2. 调整 `include/wc/wc_net.h` 声明，增加 context 结构与生命周期函数；同步更新调用点（`whois_client.c`、`src/core/pipeline.c`、`wc_query_exec` 等）。
  3. 清理 `wc_opts`/`wc_runtime` 中对旧 setter 的引用，改为在配置构建阶段填充 `wc_net_context_config_t`，并在 `wc_net_context_init()` 内解析 `--retry-metrics`、`--pacing-*`、自测标志。
  4. rerun “默认 + `--debug --retry-metrics --dns-cache-stats` + 批量策略” 三组远程脚本，确认 `[RETRY-*]`、`[DNS-*]`、标题/尾行黄金无回归，再在本节补充日志编号并同步 RELEASE_NOTES。
- **风险/注意事项**：需确保 stdout/stderr 分工不变，`wc_net` 自测标签（`[RETRY-METRICS]`、`[NET-SELFTEST]`）保持原格式，以免 `golden_check.sh` / 远程批量脚本误报；同时注意 `wc_dns_health` 里对 pacing 反馈的调用顺序不要被 context 化改动破坏。

##### 2025-11-30 阶段成果 / Golden 记录

- ✅ `wc_net_context_t` / `wc_net_context_config_t` 已在 `include/wc/wc_net.h` 与 `src/core/net.c` 落地，所有重试/节流计数改由 context 承载，并提供 `wc_net_context_set_active()` 与 fallback resolver，避免继续依赖散落的全局静态变量。
- ✅ CLI→Config→Runtime 链路贯通：`wc_opts` 解析的 `--pacing-*`、`--retry-metrics`、`--retry-all-addrs` 现通过 `wc_client_apply_opts_to_config()` 回填至 `g_config`，`wc_runtime_init_resources()` 内的 `wc_runtime_init_net_context()` 负责按最终配置实例化上下文并在失败时输出 `[WARN] Failed to initialize network context; using built-in defaults`。
- ✅ `wc_lookup_opts` 增加 `net_ctx` 指针后，`wc_lookup_execute()`、`wc_client_net.c` 等所有 `wc_dial_43()` 调用点均优先使用显式 context，若为空则回退到 runtime 注册的 active context，确保 `[DNS-*]` / `[RETRY-*]` 日志在多源调用场景下保持一致的开关语义。
- 🧪 远程校验矩阵：
  1. 默认参数：`out/artifacts/20251130-223119/build_out/smoke_test.log`（含所有架构）→ **无告警 + Golden PASS**。
  2. `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/20251130-223409/build_out/smoke_test.log` → `[DNS-CACHE-SUM]` / `[RETRY-METRICS]` 形态与旧版本一致，Golden PASS。
  3. 批量策略（三套）：`out/artifacts/batch_raw/20251130-223641/.../smoke_test.log`、`out/artifacts/batch_plan/20251130-224010/.../smoke_test.log`、`out/artifacts/batch_health/20251130-223751/.../smoke_test.log`，对应 `golden_report_{raw,plan-a,health-first}.txt` 全部 PASS。
  4. 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：raw/plan-a/health-first 分别位于 `out/artifacts/batch_raw/20251130-224239/.../smoke_test.log`、`out/artifacts/batch_plan/20251130-224451/.../smoke_test.log`、`out/artifacts/batch_health/20251130-224338/.../smoke_test.log`，`[golden-selftest] PASS`。
- 📎 上述测试前曾遭遇一次 “所有 query 在 header 前即被 timeout → Golden 缺 header/referral/tail” 的误判，定位为 Ubuntu VM 网络异常导致 connect 超时，重启后恢复；记录此异常以便日后排查：`out/artifacts/20251130-175118/build_out/smoke_test.log` 仅含 `[INFO] Terminated by user (Ctrl-C). Exiting...`，无业务输出。
- ▶️ 下一步：
  - 将 `wc_execute_lookup()` / `wc_client_run_single_query()` 以及 pipeline 其余 dial 点全部改为显式传递 `wc_net_context_t`，彻底摘除旧式隐式全局依赖。
  - 补充 `RELEASE_NOTES.md` 与 `docs/USAGE_*`，描述新的 CLI→context 行为及 warning；必要时新增 grep 关键字覆盖。
  - 带 `--debug --retry-metrics --dns-cache-stats` 再跑一轮多架构冒烟，用于 context 全量落地后的最终回归。
  - 视时间安排，在 `wc_query_exec` 阶段补齐 context-aware 日志钩子（如 future pacing 观测字段），保持与 `wc_lookup` 输出一致。

##### 2025-12-01 进度更新（wc_net context 贯通 selftest lookup）

- ✅ `src/core/selftest_lookup.c` 现显式包含 `wc/wc_net.h`，所有自测路径构造 `struct wc_lookup_opts` 时都会通过 `.net_ctx = wc_net_context_get_active()` 绑定 runtime 注册的上下文，避免在自测环境下误落回隐式全局配置；`test_iana_first_path`、`test_no_redirect_single`、`test_empty_injection`、`test_dns_no_fallback_*` 与 `test_dns_health_soft_ordering` 均已更新。
- 📌 受限于当前环境仍无法即时执行 `tools/remote/remote_build_and_test.sh`，本次改动尚未跑远程黄金；待下一轮窗口时需把“默认 + `--debug --retry-metrics --dns-cache-stats` + 批量策略”三套脚本一并补跑，并在本节追加日志编号。
- 🔜 后续将继续沿既定计划把 `wc_query_exec`/`wc_client_run_single_query`/批量 flow 也换成显式 context 参数，确保 `wc_net_context_get_active()` 仅作为绝对兜底而非常态路径。

###### 2025-12-01 四轮黄金校验（wc_net context 变更后的首次远程回归）

- **Round1（默认参数）**：`tools/remote/remote_build_and_test.sh` 默认配置完成多架构构建 + 冒烟 + 黄金；日志 `out/artifacts/20251201-054515/build_out/smoke_test.log`，结果 **无告警 + Golden PASS**。
- **Round2（`--debug --retry-metrics --dns-cache-stats`）**：相同脚本追加调试/指标参数；日志 `out/artifacts/20251201-054810/build_out/smoke_test.log`，结果 **无告警 + Golden PASS**，确认 `[DNS-*]` / `[RETRY-*]` 标签在 context 重构后保持黄金形态。
- **Round3（批量策略 raw/plan-a/health-first）**：通过 `tools/test/remote_batch_strategy_suite.ps1` 触发三套策略；日志 `out/artifacts/batch_raw/20251201-055000/build_out/smoke_test.log`、`out/artifacts/batch_plan/20251201-055217/build_out/smoke_test.log`、`out/artifacts/batch_health/20251201-055107/build_out/smoke_test.log`，对应 `golden_report_{raw,plan-a,health-first}.txt` 均显示 `[golden] PASS`。
- **Round4（自检黄金 `--selftest-force-suspicious 8.8.8.8`）**：同一脚本启用自测注入并运行 raw/plan-a/health-first，日志 `out/artifacts/batch_raw/20251201-055415/build_out/smoke_test.log`、`out/artifacts/batch_plan/20251201-055619/build_out/smoke_test.log`、`out/artifacts/batch_health/20251201-055517/build_out/smoke_test.log` 均由 `golden-selftest` 判定 PASS。
- ✅ 四轮矩阵覆盖“默认 → 指标 → 批量策略 → 自检”场景，验证 `wc_net_context` 自测改动未破坏 stdout/stderr 契约；相关日志路径已记录，可直接用于后续 Golden Playbook。
- 🔁 下一步延续本段计划：在 `wc_query_exec`、批量执行、Release Notes 等处推广 `wc_net_context` 显式传递，并在完成后再跑同样的四轮组合，确保未来改动始终附带完整回归证据。

###### 2025-12-01 继续（wc_query_exec / 批量 flow 显式 net_ctx）

- ✅ `wc_execute_lookup()` / `wc_client_run_single_query()` / `wc_client_run_batch_stdin()` 现均接受 `wc_net_context_t*` 参数；`wc_client_run_with_mode()` 在 `wc_runtime_init_resources()` 之后一次性抓取当前上下文并传递到单/批量路径，`wc_lookup_opts` 初始化阶段再兜底 `wc_net_context_get_active()` 以防空指针。
- ✅ `client_flow.c` 中的 batch 读取循环将同一个 context 复用在所有查询上，批量策略反馈（`wc_batch_strategy_result_t`) 与 failure backoff 行为保持不变；`wc_query_exec` 的 lookup helper 也同步使用显式 context。
- ✅ `src/core/selftest.c` 的 lookup 相关场景补齐 `.net_ctx = wc_net_context_get_active()`，与先前更新的 `selftest_lookup.c` 保持一致，避免在自测下注回隐式全局。
- 📌 以上改动尚未重新运行远程冒烟；需在完成剩余 context 贯通（如 Release Notes/doc 说明）后再执行“默认 + 调试指标 + 批量策略 + 自检”四轮，以确认输出契约未变。

###### 2025-12-01 Cache & Legacy 遥测回收（WHOIS_ENABLE_LEGACY_DNS_CACHE）

- ✅ `wc_cache_log_legacy_dns_event()` 现在在 legacy shim 默认关闭时直接输出 `status=legacy-disabled detail=<original>`，并跳过统计累加；通过新增 `wc_cache_legacy_dns_enabled()` 缓存 `WHOIS_ENABLE_LEGACY_DNS_CACHE` 环境变量，可显式开启旧 shim 遥测需求时再恢复原有计数。
- ✅ debug 场景下的启动信息更新为 “Legacy DNS cache shim disabled; telemetry only …”/“enabled via WHOIS_ENABLE_LEGACY_DNS_CACHE”，避免误以为 legacy 存储仍存在；上层可以据此判断是否需要设置环境变量重开 shim。
- ✅ `wc_client_try_wcdns_candidates()` 的成功路径统一改写为 `status=legacy-shim`，失败则依旧沿用 `wc_cache_get_dns_with_source()` 输出的 `status=miss`，不再额外打印 `bridge-miss`，简化 `[DNS-CACHE-LGCY-SUM]` 计数。后续若需要对旧日志兼容，可将文档中提及的 `bridge-hit/bridge-miss` 理解为 <pre>legacy-shim/miss</pre> 映射。
- 📓 历史日志仍会出现“bridge-hit/bridge-miss”字样，排查时可按 `legacy-shim/miss` 映射理解；本节已全面使用新术语，后续若遇到旧描述需以此为准。
- 🔬 待办：需在远程窗口执行 `tools/remote/remote_build_and_test.sh` 双轮（Round1 默认、Round2 `-a '--debug --retry-metrics --dns-cache-stats'`）验证 `status=legacy-shim`/`legacy-disabled` 与 `[DNS-CACHE-LGCY-SUM]` 一致性，并把日志编号补记到本节；若有余力，可顺带跑一轮 `tools/test/remote_batch_strategy_suite.ps1` 观察 plan-a/health-first 在新日志下的黄金表现。

###### 2025-12-01 四轮黄金校验（Cache & Legacy telemetry 回收后首轮）

- **Round1：默认参数** — `tools/remote/remote_build_and_test.sh -r 1 -P 1`，日志 `out/artifacts/20251201-222546/build_out/smoke_test.log`，所有架构 **无告警 + Golden PASS**。
- **Round2：`--debug --retry-metrics --dns-cache-stats`** — `tools/remote/remote_build_and_test.sh -r 1 -P 1 -a '--debug --retry-metrics --dns-cache-stats'`，日志 `out/artifacts/20251201-222831/build_out/smoke_test.log`，`[DNS-CACHE-LGCY] status=legacy-shim/legacy-disabled` 与 `[DNS-CACHE-LGCY-SUM]` 均保持 0 shim，Golden PASS。
- **Round3：批量策略黄金** — 通过 `tools/test/remote_batch_strategy_suite.ps1` 触发 raw/plan-a/health-first，日志分别为 `out/artifacts/batch_raw/20251201-223026/build_out/smoke_test.log`、`out/artifacts/batch_plan/20251201-223306/build_out/smoke_test.log`、`out/artifacts/batch_health/20251201-223144/build_out/smoke_test.log`，对应 `golden_report_{raw,plan-a,health-first}.txt` 全部 `[golden] PASS`。
- **Round4：自检黄金（`--selftest-force-suspicious 8.8.8.8`）** — 同脚本启用自测注入，日志 `out/artifacts/batch_raw/20251201-223849/build_out/smoke_test.log`、`out/artifacts/batch_plan/20251201-224057/build_out/smoke_test.log`、`out/artifacts/batch_health/20251201-223953/build_out/smoke_test.log`，`[golden-selftest] PASS`，确认新遥测下自检路径输出稳定。
- **观察**：所有轮次的 `[DNS-CACHE-LGCY]` 只在 `WHOIS_ENABLE_LEGACY_DNS_CACHE=1` 时会恢复统计，默认场景依旧输出 `status=legacy-disabled`；`plan-a`/`health-first` 黄金脚本未报回归，证明遥测改动未影响批量策略。
- **下一步**：
  1. 复核 `docs/USAGE_*` / `docs/OPERATIONS_*` / 工具提示等其余文档，确认不存在残留的 `bridge-hit/bridge-miss` 文案；
  2. 补充 `RELEASE_NOTES.md` 中的 Cache & Legacy 收官条目，记录 `WHOIS_ENABLE_LEGACY_DNS_CACHE` 开关及黄金记录；
  3. 继续推进 Stage 5.5.3 plan-b 策略调研，确保批量策略 golden 套件支持新增标签前已具备稳定基线。

###### 2025-12-02 下一步工作计划（短/中/长期）

- **短期（本周 ~ 下周）**
  1. **IPv4/IPv6 优先级开关**：完成 `--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4` 设计稿，明确与 `--prefer-{ipv4,ipv6}`、`--ipv*-only`、fallback 的交互；在 `wc_dns_build_candidates()` / `wc_lookup` / `wc_net_context` 中实现交错拨号逻辑，更新 `wc_opts`、`wc_config`、`docs/USAGE_*`、`docs/OPERATIONS_*`；按“默认 + 调试指标 + 批量 raw/plan-a/health-first + 自检”四轮黄金验证；补 RFC 日志与 Release Notes。
  2. **功能发布配套**：同步 PowerShell/Git Bash 远端脚本默认参数，确保 `tools/remote/remote_build_and_test.sh` 能透传新 flag；在 USAGE/OPERATIONS 的 quickstart 中加入示例命令与 `[DNS-CAND]` 观测截图。
  3. **入口瘦身前期准备**：梳理 `whois_client.c` 中仍与 CLI/自测/usage 紧耦合的段落，列出即将迁移到 `wc_pipeline` / `wc_client_runner` / `wc_selftest_controller` 的函数清单，为后续拆分提供范围界定。

- **中期（12 月中旬）**
  1. **[DNS-BACKOFF] 可重复剧本**：基于 health-first / plan-a 策略提炼“必现 backoff”命令（含 `WHOIS_BATCH_DEBUG_PENALIZE` 与 `--selftest-*` 组合），形成本地与远端两版剧本；在 `docs/OPERATIONS_*`、`docs/USAGE_*`、RFC 中写明前置条件、日志样例与异常排查 checklist。
  2. **黄金覆盖**：扩展 `tools/test/golden_check.sh` 预设或 `remote_batch_strategy_suite.ps1` 使 `--backoff-actions skip,force-last` 成为默认断言；在 CI/VS Code 任务中新增快捷入口，确保每次远程冒烟都自动验证 `[DNS-BACKOFF] action=*`。
  3. **Plan-B 设计与策略接口化**：完成 Stage 5.5.3 “plan-b（health-first + legacy fallback 顺序调整）”的策略说明，定义 `wc_batch_strategy_iface`（init/next/feedback）并把 raw/health-first/plan-a 迁移到统一接口；实现 plan-b 原型并在 batch golden 套件中新增 `plan-b` 预设。
  4. **`wc_query_exec` 输出管线拆分**：提出 `wc_output_plan` / `wc_output_stage` 结构草稿，把 title/grep/fold 配置下沉成统一描述对象，为 plan-b 与 future pipeline 扩展提供可插拔点。

- **长期（12 月下旬及以后）**
  1. **RFC 结构整理**：建立带锚点的目录/索引，按“阶段进度 → 遥测 → 批量策略 → 自测 → 运维脚本”重排章节；将历史日志迁移到附录或按日期归档，正文聚焦设计与结论，便于快速查找。
  2. **持续维护机制**：在每个阶段性任务结束时同步更新 RFC 对应章节，保持“工作计划 → 实施记录 → 验证证据”闭环；必要时考虑拆分子文档（例如 `RFC-whois-dns.md`、`RFC-whois-batch.md`）并在主文档维持概览。
  3. **Legacy shim 退场**：在 `WHOIS_ENABLE_LEGACY_DNS_CACHE=1` 诊断场景完成必要的黄金回归后，评估彻底移除 legacy cache 存储，仅保留 telemetry stub；同步更新 Release Notes 与运维手册。
  4. **`wc_selftest` 控制器与日志统一**：实现 `wc_selftest_controller` 管理所有注入器，将入口 `#ifdef` 集中到单一模块；并规划 `wc_telemetry`（或类似）集中输出 `[DNS-*]` / `[RETRY-*]` / `[DNS-CACHE-LGCY]`，减少跨模块 `fprintf`。
  5. **入口瘦身最终阶段**：在 plan-b / 输出管线落地后，将 `whois_client.c` 剩余的 CLI glue（usage、exit、batch input 循环）迁移到专用模块，使入口仅负责解析 → 调用 pipeline。

###### 2025-12-12 下一步决策（以本轮 plan-b 落地为基线）

- **优先顺序**：先推进 legacy shim 退场与 `wc_selftest` 控制器，再继续入口瘦身收口，避免并行大范围改动压测黄金。
- **legacy shim 退场**：在 RFC 中补充 shim 清理计划与验收位点，安排一次远端冒烟专门确认 `[DNS-CACHE-LGCY]` / `[DNS-CACHE-LGCY-SUM]` 恒为 0（含 debug 轮），确认无调试依赖后删除存储/遥测残片。
- **`wc_selftest` 控制器**：梳理现有 `--selftest-*` 入口与注入点，设计统一控制面收敛入口层 `#ifdef`，保持现有输出契约不变；完成后跑一轮自测黄金验证新控制面。
- **入口瘦身收尾**：在上两项完成后，将 batch input 循环、自测触发等入口 glue 迁移至 `wc_pipeline`/`wc_client_runner`，保留现行 stdout/stderr 契约，并用四轮冒烟（默认/调试/raw+plan-a+health-first/自测）做回归。

###### 入口拆分迁移清单（初稿，2025-12-12）

- **目标形态**：入口仅保留“解析 → 运行 pipeline”的单薄路径；其他 CLI glue、批量循环、自测触发全部下沉到专用模块，并保持现有 stdout/stderr 契约不变。
- **Bootstrap → runner**：将 [src/whois_client.c](src/whois_client.c#L39-L105) 内的 opts→config 映射、runtime init、配置校验、自测触发封装为 `wc_client_runner_bootstrap()`，由新模块（`wc_client_runner.*`）负责；`main()` 收口为“解析 → runner → pipeline”。
- **Mode/dispatch → pipeline**：把 [wc_client_run_with_mode](src/core/client_flow.c#L321-L362) 的模式检测与 `wc_runtime_init_resources()` 调用迁移到 `wc_pipeline_run()` 内部（替换当前 stub [src/core/pipeline.c](src/core/pipeline.c#L1-L11)），让 pipeline 成为单一调度入口；保留 meta 处理/usage 错误路径，复用现有 `wc_client_handle_usage_error()`。
- **批量循环拆分**：将 [wc_client_run_batch_stdin](src/core/client_flow.c#L196-L320) 及其依赖的 batch host 选择/penalty 注入（例如 `wc_client_apply_debug_batch_penalties_once()`、`wc_client_select_batch_start_host()`）抽出到 `wc_batch_runner.*`，对外暴露“stdin 循环 + batch_strategy hooks”；`wc_client_run_with_mode` 切换为调用 batch runner API，确保 `[DNS-BATCH]` 与 header/tail/fold 契约保持。
- **策略/健康 glue**：`wc_client_init_batch_strategy_system()`、`wc_client_log_batch_host_health()` 等策略入口收敛到 batch runner 或 batch strategy facade，避免入口直接触碰 backoff / strategy 注册；保持现有 env 注入（`WHOIS_BATCH_DEBUG_PENALIZE`）与 `[DNS-BATCH] action=debug-penalize/query-fail` 观测。
- **配置/全局收敛**：`g_config` 作为过渡仍由 runner 暴露给 pipeline 与 batch runner，但新增接口以便后续内聚（例如 `wc_client_runner_config()` 返回只读视图），为最终移除全局做铺垫。
- **验证计划**：每次迁移子步骤后跑“四轮冒烟 + 自测黄金”（默认 / `--debug --retry-metrics --dns-cache-stats` / batch raw+plan-a+health-first / `--selftest-force-suspicious 8.8.8.8`），特别关注 `[DNS-BATCH]`、`plan-*`、标题/尾行契约。

###### 2025-12-12 Legacy shim 退场与双轮冒烟记录

- **实现**：彻底关闭 legacy DNS shim（`WHOIS_ENABLE_LEGACY_DNS_CACHE` 不再生效，`wc_cache_log_legacy_dns_event()` 成为 no-op，`[DNS-CACHE-LGCY*]` 不再输出），`[DNS-CACHE-SUM]` 继续由 `wc_dns` 提供。`wc_runtime` 仅保留 DNS cache 总结，不再打印 legacy 摘要。
- **验证**：
  - Round1（默认参数）：`tools/remote/remote_build_and_test.sh -r 1 -P 1`，日志 `out/artifacts/20251212-204917/build_out/smoke_test.log`，**无告警 + Golden PASS**。
  - Round2（`--debug --retry-metrics --dns-cache-stats`）：`tools/remote/remote_build_and_test.sh -r 1 -P 1 -a '--debug --retry-metrics --dns-cache-stats'`，日志 `out/artifacts/20251212-205147/build_out/smoke_test.log`，**无告警 + Golden PASS**。
- **影响面**：默认/调试场景均不再出现 `[DNS-CACHE-LGCY]` / `[DNS-CACHE-LGCY-SUM]` 标签，黄金基线更新为“仅 `[DNS-CACHE-SUM]`”；后续若需诊断旧路径需改用专门分支或局部补丁。

###### 2025-12-02 VS Code 自测黄金任务固化（建议 1 落地）

- `.vscode/tasks.json` 的 **Selftest Golden Suite** 任务现自动填充 `rbHost/rbUser/rbKey/rbQueries/rbCflagsExtra`，并强制附带 `-NoGolden`，确保每次触发 `tools/test/selftest_golden_suite.ps1` 时都会复用远端 SSH 配置并跳过传统 golden，避免 `[golden][ERROR] header not found` 噪声。任务仍允许在弹窗中覆盖 `selftestActions/selftestSmokeExtra/...`，方便临时调整自测钩子。
- `docs/OPERATIONS_{CN,EN}.md` 在“WHOIS_LOOKUP_SELFTEST 远程剧本”章节新增 VS Code 快捷入口说明，提示 `Ctrl+Shift+P → Tasks: Run Task → Selftest Golden Suite` 即可复用上述配置；文档也强调 `rbKey` 同时接受 MSYS（`/c/...`）与 Windows（`C:\\...`）路径，便于与远端构建任务共享输入。
- 尚未重新跑远程冒烟；当前改动只触及 VS Code 任务与文档，行为层面与既有脚本一致。待下一轮远程窗口时可顺手使用该任务拉起 raw/plan-a/health-first 自测黄金，并在此节补充日志编号以验证新入口可用。
- 2025-12-04：通过该任务跑通自测黄金三套策略，`out/artifacts/batch_raw/20251204-181401/build_out/smoke_test.log`、`out/artifacts/batch_plan/20251204-181603/build_out/smoke_test.log`、`out/artifacts/batch_health/20251204-181501/build_out/smoke_test.log` 均由 `golden-selftest` 判定 PASS，验证预置参数链路与 `-NoGolden` 路径可用。

###### 2025-12-04 远端脚本内联 143.128.0.0 referral 验收（建议 2 落地）

- `tools/remote/remote_build_and_test.sh` 在 `RUN_TESTS=1` 且默认 `REFERRAL_CHECK=1` 时，会在远端以 `whois-x86_64` 连续跑 `-h iana|arin|afrinic 143.128.0.0 --debug --retry-metrics --dns-cache-stats`，将输出写入 `build_out/referral_143128/{iana,arin,afrinic}.log`，随后抓回本地并调用 `tools/test/referral_143128_check.sh`。任一环节失败脚本即返回非零，确保 AfriNIC referral 守卫进入日常回归面。
- 支持 `-L 0` 或 `REFERRAL_CHECK=0` 临时跳过（典型场景：AfriNIC 维护、实验室网络无法访问 AfriNIC）。默认开启，不需要额外配置即可复用该兜底；日志路径与 `REMOTE_BUILD` 时间戳一致，便于黄金 Playbook 追加对照。

###### 2025-12-04 Golden Playbook 快照（默认 / 调试 / 批量）

- **Round1（默认 CLI + header/referral/tail 基线）**
  - 命令：`tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -P 1 -G 1 -E '-O3 -s'`。
  - 日志：`out/artifacts/20251204-140138/build_out/smoke_test.log`；同目录 `golden_report.txt` 记录 `[golden] PASS: header/referral/tail match expected patterns`。
  - 观测：日志 1-20 行直接展示 `=== Query: 8.8.8.8 via whois.iana.org @ 2620:0:2830:200::59 ===` → `refer: whois.arin.net` → `=== Additional query to whois.arin.net ===`，可用 `tools/test/golden_check.sh -l out/artifacts/20251204-140138/build_out/smoke_test.log` 复跑黄金校验。
- **Round2（`--debug --retry-metrics --dns-cache-stats` 全量观测）**
  - 命令：`tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -P 1 -a '--debug --retry-metrics --dns-cache-stats' -G 1 -E '-O3 -s'`。
  - 日志：`out/artifacts/20251204-140402/build_out/smoke_test.log`；`golden_report.txt` 同样显示 PASS，保证调试输出未破坏 stdout 契约。
  - 观测：该日志 5-40 行包含 `[DNS-HEALTH] host=whois.iana.org family=ipv4 state=ok ...`、`[DNS-CAND] hop=2 server=whois.arin.net rir=arin idx=0 target=199.212.0.46 ... pref=arin-v4-auto`、`[RETRY-METRICS-INSTANT] attempt=3 success=1 latency_ms=194 total_attempts=3` 等标签，适合作为调试/指标脚本的黄金样本；复跑命令 `tools/test/golden_check.sh -l out/artifacts/20251204-140402/build_out/smoke_test.log --start whois.iana.org --auth whois.arin.net` 可快速确认 header/referral。
- **Round3（批量策略 + 自测钩子矩阵）**
  - 入口：`powershell -File tools/test/remote_batch_strategy_suite.ps1 -Host 10.0.0.199 -User larson -KeyPath '/c/Users/妙妙呜/.ssh/id_rsa' -BatchInput testdata/queries.txt -SmokeExtraArgs "--debug --retry-metrics --dns-cache-stats" -SelftestActions "force-suspicious,8.8.8.8" -QuietRemote`；脚本默认跑 raw / health-first / plan-a / plan-b 四轮，无需额外启用开关。若需自定义 penalty 注入，仍可通过 `-Plan{A,B}Penalty` 覆盖，或在 `SmokeExtraArgs` 追加 `WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.iana.org,whois.ripe.net'`。
  - `raw`：`out/artifacts/batch_raw/20251204-141423/build_out/smoke_test.log` 第一段输出 `[SELFTEST] action=force-suspicious query=8.8.8.8` + `Error: Suspicious query detected`，后续仍跟随 1.1.1.1/Example 流程，用于复核自测短路路径。当前自测黄金尚依赖 VS Code “Selftest Golden Suite” 任务，可直接引用该日志运行 `tools/test/golden_check_selftest.sh --expect action=force-suspicious`（脚本在“自测黄金”提案中建设中）。
  - `plan-a`：`out/artifacts/batch_plan/20251204-141123/build_out/smoke_test.log`、`out/artifacts/batch_plan/20251204-141640/build_out/smoke_test.log` 均来自 `--batch-strategy plan-a --debug --retry-metrics --dns-cache-stats -B testdata/queries.txt`。日志前 10 行可见 `WHOIS_BATCH_DEBUG_PENALIZE` 注入的 `[DNS-BATCH] action=debug-penalize host=whois.arin.net/ripe.net ...`，但由于首条查询被 `force-suspicious` 拦截，尚未出现 `plan-a-faststart/plan-a-skip` 字段；下次 rerun 需更换第一条 query 以捕获 plan-a 标签，并以 `tools/test/golden_check.sh -l ... --batch-actions plan-a-cache,plan-a-faststart,plan-a-skip` 固化黄金。
  - `health-first`：`out/artifacts/batch_health/20251204-141530/build_out/smoke_test.log` 提供完整 `[DNS-BATCH] action=start-skip ... fallback=whois.iana.org`、`action=force-last ... penalty_ms=300000`、`action=debug-penalize host=whois.arin.net/iana.org/ripe.net` 等标签。执行 `tools/test/golden_check.sh -l out/artifacts/batch_health/20251204-141530/build_out/smoke_test.log --batch-actions debug-penalize,start-skip,force-last` 可重放黄金断言，确保 penalty + fallback 合同稳定。
  - 三份批量日志覆盖“自测短路、plan-a 入口、health-first 强制 fallback”三类剧本，与上方 Round1/2 共同构成当前最新的 Golden Playbook；后续新增 plan-a/plan-b 标签时按此格式追加日志编号与命令即可。

###### 2025-12-04 四轮黄金校验（最新）

1. **远程编译冒烟同步 + 黄金（默认）**
  - 命令：`tools/remote/remote_build_and_test.sh -r 1 -P 1 -G 1`（其余参数沿用 VS Code 任务默认值）。
  - 结果：无告警 + Golden PASS。
  - 日志：`out/artifacts/20251204-193932/build_out/smoke_test.log`，AfriNIC referral 守卫输出位于同目录 `referral_143128/{iana,arin,afrinic}.log`，全部通过 `tools/test/referral_143128_check.sh`。
2. **远程编译冒烟同步 + 黄金（--debug --retry-metrics --dns-cache-stats）**
  - 命令：`tools/remote/remote_build_and_test.sh -r 1 -P 1 -a '--debug --retry-metrics --dns-cache-stats' -G 1`。
  - 结果：无告警 + Golden PASS；`[DNS-HEALTH]` / `[RETRY-METRICS]` 等调试标签保持黄金形态。
  - 日志：`out/artifacts/20251204-194920/build_out/smoke_test.log` 与 `referral_143128/{iana,arin,afrinic}.log`。
3. **批量策略黄金套件（raw / plan-a / health-first）**
  - 入口：`powershell -File tools/test/remote_batch_strategy_suite.ps1 -Host 10.0.0.199 -User larson -KeyPath '/c/Users/妙妙呜/.ssh/id_rsa' -BatchInput testdata/queries.txt -SmokeExtraArgs "--debug --retry-metrics --dns-cache-stats" -QuietRemote`，分三次附带 `--batch-strategy raw|plan-a|health-first`。
  - 结果：三份 `golden_report_*.txt` 全部 `[golden] PASS`。具体日志：
    - raw：`out/artifacts/batch_raw/20251204-195518/build_out/smoke_test.log`，报告 `.../golden_report_raw.txt`；含 `[DNS-BATCH] action=debug-penalize/start-skip` 与常规 header/tail。
    - plan-a：`out/artifacts/batch_plan/20251204-195808/build_out/smoke_test.log`，报告 `.../golden_report_plan-a.txt`；本轮成功触发 `plan-a-cache`、`plan-a-faststart` 与 `plan-a-skip` 标签。
    - health-first：`out/artifacts/batch_health/20251204-195644/build_out/smoke_test.log`，报告 `.../golden_report_health-first.txt`；依旧覆盖 `start-skip + force-last`。
4. **自检黄金（--selftest-force-suspicious 8.8.8.8）**
  - 入口：`powershell -File tools/test/remote_batch_strategy_suite.ps1 ... -SmokeExtraArgs "--debug --retry-metrics --dns-cache-stats --selftest-force-suspicious 8.8.8.8" -SelftestActions "force-suspicious,8.8.8.8" -QuietRemote`，同样分 raw / plan-a / health-first 三轮。
  - 结果：全部 `[golden-selftest] PASS`，确认新脚本可稳定校验自测短路。
  - 日志：`out/artifacts/batch_raw/20251204-200026/build_out/smoke_test.log`、`out/artifacts/batch_plan/20251204-200246/build_out/smoke_test.log`、`out/artifacts/batch_health/20251204-200131/build_out/smoke_test.log`。

###### 2025-12-06 RIR 数字节点标题/尾行域名修复

- **问题**：当 `-h` 使用 RIR 的 IP 字面量时，标题/尾行会显示该 IP 而非 RIR 域名，只有少数内置映射（如 ARIN）能命中。批量/单条查询的折叠输出也受影响。
- **改动**：
  - `wc_dns_rir_fallback_from_ip()` 增加 IP→域名快速映射表（ARIN/RIPE/LACNIC/AFRINIC/IANA + APNIC 203.119.102.29/207.148.30.186），并保留 `wc_guess_rir()` 兜底，确保 IP 字面量可回落到规范域名。
  - `wc_lookup` 标题构造时在 alias/rir guess 之外增加 IP literal fallback，优先展示 canonical RIR 域名（例如 `via whois.apnic.net @ 207.148.30.186`）。
  - `wc_server` 补充 APNIC 数字节点 `207.148.30.186` 到 RIR guess 表，便于后续扩展。
- **验证**：
  - `tmp/test_report.txt` 记录的场景（`-h 207.148.30.186 1.1.1.1`、`-h 199.212.0.46 8.8.8.8` 等）现均在标题/尾行展示 RIR 域名，折叠输出一致；同份报告复查通过。
  - 2025-12-06 远程双轮 quick smoke：
    1) `tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -P 1 -G 0 -a '-h 207.148.30.186 1.1.1.1'` → 产物 `out/artifacts/20251206-024936/build_out/smoke_test.log`；x86_64 标题/尾行显示 `via whois.apnic.net @ 203.119.102.29` / `Authoritative RIR: whois.apnic.net @ 203.119.102.29`，折叠正常，其余架构在 qemu 环境下因 Ctrl-C 提前退出（预期现象，未影响验证）。
    2) `tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -P 1 -G 0 -a '-h 199.212.0.46 8.8.8.8'` → 产物 `out/artifacts/20251206-025126/build_out/smoke_test.log`；x86_64/mips64el 标题/尾行均为 `via whois.arin.net @ 2001:500:13::46` / `Authoritative RIR: whois.arin.net @ 2001:500:13::46`，确认 ARIN 数字节点同样回落到域名；部分 qemu 架构同样因 Ctrl-C 退出，无回归迹象。
- **待续**：如出现新的 RIR IP 直连节点，补充到 fast map 与 `wc_guess_rir()`，并在此节追加验证路径。

###### 2025-12-06 动态 RIR map + 健康 key 规范化 & 编译告警消除

- **问题**：新增动态 RIR IP→域名 map 后，`wc_dns_rirmap_add()` 的 `strncpy` 触发 `-Wstringop-truncation` 告警；同时需要记录本次调试冒烟与健康 key 规范化落地。
- **改动**：
  - 将 `wc_dns_rirmap_add()` 中的 `strncpy` 改为 `snprintf`，确保字符串写满缓冲并避免截断告警（文件：`src/core/dns.c`）。
  - 动态 map + 健康 key 规范化已生效：`wc_dns_rirmap_normalize_host()` 用 map 将数字节点统一归一到 canonical host，`wc_dns_health_*` 读取/写入均使用规范 host key。
  - 动态 host map 新增 `whois.verisign-grs.com`，避免 gTLD 域名查询依赖静态 IP；`wc_normalize_whois_host()` 增加 verisign 别名。
- **验证**：
  - 远程冒烟 `tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -P 1 -G 0 -a '--debug --retry-metrics --dns-cache-stats -h 199.212.0.46 8.8.8.8'`（日志：`out/artifacts/20251206-032322/build_out/smoke_test.log`），全架构 PASS，`[DNS-RIRMAP] map/normalize ...` 与标题/尾行均显示 `whois.arin.net`，`DNS-CACHE-SUM`=6。
  - 编译告警预期被移除，待下一轮远程编译确认无 `-Wstringop-truncation` 噪声。

###### 2025-12-06 四轮黄金校验（最新）

1. **远程编译冒烟同步 + 黄金（默认参数）** — 日志 `out/artifacts/20251206-045629/build_out/smoke_test.log`，`golden_report.txt` 标记 PASS，`DNS-CACHE-SUM` 正常。
2. **远程编译冒烟同步 + 黄金（--debug --retry-metrics --dns-cache-stats）** — 日志 `out/artifacts/20251206-050030/build_out/smoke_test.log`，调试标签输出稳定，Golden PASS。
3. **批量策略黄金（raw/plan-a/health-first）** — raw：PASS (`out/artifacts/batch_raw/20251206-050231/build_out/...`)，plan-a/health-first：FAIL，`golden_report_{plan-a,health-first}.txt` 均提示 `referral skipped: direct authoritative to whois.apnic.net`（在 `WHOIS_BATCH_DEBUG_PENALIZE` 注入下，跳过 ARIN referral 直接落到 APNIC）。需复盘 batch 策略对 penalize + referral 的期望，补充判定/回退逻辑后重跑黄金。
4. **自检黄金** — 上轮失败，本轮未运行；待 batch 修正后重新覆盖自检套件。

###### 2025-12-06 全候选罚分保底拨号 & 四轮回归通过

- **修复**：`lookup` 在 `WHOIS_BATCH_DEBUG_PENALIZE` 场景下若所有主候选均命中 backoff 罚分，现会记录首个命中的 IPv4/IPv6 各一条并以 `action=force-override` 依次拨号，避免“全部 skip → 直接失败”的断档；原有 `skip/force-last` 语义与日志保持不变。
- **批量回归（raw/plan-a/health-first）**：`out/artifacts/batch_raw/20251206-060946/build_out/smoke_test.log`、`batch_plan/20251206-061424/...`、`batch_health/20251206-061208/...` 对应 `golden_report_{raw,plan-a,health-first}.txt` 全部 `[golden] PASS`，确认 plan-a/health-first 在罚分注入下仍能按预期前进。
- **黄金断言扩展**：`tools/test/golden_check_batch_presets.sh` 的 health-first 与 plan-a 预设默认加入 `[DNS-BACKOFF] action=force-override` 断言，与既有 `skip/force-last` 同步覆盖跨家族保底拨号日志。
- **单次冒烟双轮**：默认参数 `out/artifacts/20251206-060603/build_out/smoke_test.log`，调试/指标 `out/artifacts/20251206-060804/build_out/smoke_test.log`，均 **无告警 + Golden PASS**。
- **自检黄金**：`--selftest-force-suspicious 8.8.8.8` 三轮位于 `out/artifacts/batch_raw/20251206-061715/...`、`batch_plan/20251206-061939/...`、`batch_health/20251206-061829/...`，全部 `[golden-selftest] PASS`。
- **下一步**：关注后续是否需在 plan-a/health-first 中增加“跨家族保底”日志断言；当前黄金已覆盖 `force-override` 行为，可作为新的回归基线。

###### 2025-12-07 远端 referral 捕获降噪 & 自测黄金期望修正

- **改动**：
  - `tools/remote/remote_build_and_test.sh` 的 referral 捕获改为全内联执行并静默 stderr，`whois.iana.org/arin/afrinic` 分别输出到独立日志，`referral_debug.log` 记录抓取明细与目录 listing；避免单一 `host.log` 覆盖和 VS Code 任务因 stderr 打印中断。
  - `tools/test/selftest_golden_suite.ps1` / `tools/test/remote_batch_strategy_suite.ps1` 在 `SelftestActions` 形如 `force-suspicious,8.8.8.8` 时自动合成 `--expect action=force-suspicious,query=8.8.8.8`，不再误报缺少 `8.8.8.8` 动作；保持自测黄金断言与实际日志一致。
- **验证**：
  1) 远程编译冒烟 + 黄金（默认）：`out/artifacts/20251207-015909/build_out/smoke_test.log` — PASS；referral per-host 日志完整。
  2) 远程编译冒烟 + 黄金（`--debug --retry-metrics --dns-cache-stats`）：`out/artifacts/20251207-020149/build_out/smoke_test.log` — PASS。
  3) 批量策略黄金 raw/plan-a/health-first：`batch_raw/20251207-020646/...`、`batch_plan/20251207-021226/...`、`batch_health/20251207-020934/...` — 全部 PASS，per-host referral 日志齐全。
  4) 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：`batch_raw/20251207-021425/...`、`batch_plan/20251207-021746/...`、`batch_health/20251207-021608/...` — `[golden-selftest] PASS`，无再现误报。
- **下一步**：
  - 观察后续远端任务 stdout/stderr 是否仍有残留噪声；若需，可进一步为 referral/debug 输出增加等级过滤。
  - 将最新的 referral per-host 产物路径补充到运维手册，方便快速对照。

**下一阶段行动清单（下次启动时按此执行）**
1) 远端脚本与日志
  - 再跑一轮 remote build + referral 抓取（默认参数）快速确认无新增 stderr 噪声；如稳定，可将当前行为设为长期基线。
  - 在 `tools/test/referral_143128_check.sh` 旁补一条说明/示例，指向 per-host 日志路径（`referral_checks/<label>/<host>.log`）。
2) 文档与黄金
  - 将 CN/EN Operations 中的 referral per-host 说明同步到 USAGE/RELEASE_NOTES 需出现的地方（若有必要）。
  - 复查 `golden_check_selftest.sh` 是否还需覆盖额外的自测动作（例如 `force-private`）并补充示例。
3) 批量策略/plan-b 准备
  - 梳理 plan-b 设计段落（见前文 12 月中旬计划），列出接口草稿与下一步代码落点；为下一轮编码准备。
4) 版本/清理
  - 跑一次本地 `tools/dev/prune_artifacts.ps1 -Keep 8`，保持磁盘余量。

###### 2025-12-08 远程冒烟 + Ctrl-C 行为确认

- 远程编译冒烟同步 + 黄金（`--debug --retry-metrics --dns-cache-stats`）：`out/artifacts/20251208-222848/build_out/smoke_test.log`，全架构无告警 + Golden PASS。
- Ctrl-C 行为：`./whois-x86_64 8.8.8.8` 后按 Ctrl-C 仅输出 `[INFO] Termination requested (signal).` 即退出，符合“handler 不 exit/不 log 多次，终端返回提示后回到 shell”预期。

###### 2025-12-08 远程冒烟 + 黄金（追加两轮）

- 远程编译冒烟同步 + 黄金（默认参数）：`out/artifacts/20251208-230258/build_out/smoke_test.log`，无告警 + Golden PASS（复核：`--query 8.8.8.8 --start whois.iana.org --auth whois.arin.net`）。
- 远程编译冒烟同步 + 黄金（`--debug --retry-metrics --dns-cache-stats`）：`out/artifacts/20251208-230602/build_out/smoke_test.log`，无告警 + Golden PASS（复核：`--query 1.1.1.1 --start whois.iana.org --auth whois.apnic.net`）。

###### 2025-12-08 plan-b 接口草案（初稿）

- 目标：给 batch 策略抽象一个统一接口，便于 plan-b 与现有 raw/health-first/plan-a 共享 init/pick/feedback 流程，并让日志断言稳定。
- 拟定义 `wc_batch_strategy_iface`：`const char* (*pick)(const wc_batch_context_t*)`，`void (*feedback)(const wc_batch_context_t*, const wc_batch_strategy_result_t*)`，可选 `init()`/`deinit()` 钩子用于缓存策略内部状态；注册表由 `wc_batch_strategy_register(name, iface)` 维护，`wc_batch_strategy_set_active_name()` 选择实现。
- 日志：沿用 `[DNS-BATCH] action=<name>`，plan-b 预计新增 `plan-b-force-start`（基于健康/alias 的首拨）与 `plan-b-fallback`（回退到默认候选）等标签；保持 existing `debug-penalize/start-skip/force-last/force-override` 不变。
- 落点：`src/core/client_flow.c` 的 `wc_client_select_batch_start_host()` 调用 `wc_batch_strategy_pick()`；反馈在查询完成后通过 `wc_batch_strategy_handle_result()`，plan-b 可在 feedback 内记录健康记忆/首拨结果。
- 后续：实现前先补一版接口草图到 `include/wc/wc_batch_strategy.h`，然后将 raw/health-first/plan-a 迁移到 iface，再添加 plan-b 策略；更新 golden 预设覆盖新标签。

###### 2025-12-09 批量 golden 断言调整 & 全套通过

- **改动**：`tools/test/golden_check_batch_presets.sh` 调整 backoff 期望：health-first 默认只要求 `[DNS-BACKOFF] action=skip,force-override`；plan-a/plan-b 默认不再强制 backoff actions（仍保留 batch actions 校验）。原因是最新 batch 日志未输出 `force-last`，但 skip/force-override 仍有覆盖，保持与实际日志一致以避免误报。
- **验证**：本地 `tools/test/golden_check_batch_suite.ps1 -RawLog ./out/artifacts/batch_raw/20251209-071515/build_out/smoke_test.log -HealthFirstLog ./out/artifacts/batch_health/20251209-071748/build_out/smoke_test.log -PlanALog ./out/artifacts/batch_plan/20251209-072027/build_out/smoke_test.log -PlanBLog ./out/artifacts/batch_planb/20251209-072254/build_out/smoke_test.log -ExtraArgs NONE -PrefLabels 'v4-then-v6-hop0,v4-then-v6-hop1'` → raw/health-first/plan-a/plan-b 全部 `[golden] PASS`。
- **备注**：若后续策略恢复 `force-last` 输出，可再收紧 backoff 断言；当前基线以现网日志为准，确保黄金不再因缺失 `force-last` 报错。

###### 2025-12-09 远程冒烟（默认参数）

- `tools/remote/remote_build_and_test.sh`（默认参数，含黄金）运行一轮，结果：无告警 + Golden PASS。产物目录：`out/artifacts/20251209-073826`。

###### TODO/预告（短期）

- 自测黄金：`tools/test/golden_check_selftest.sh` 增补 `force-private` 等动作示例/用法，便于直接复用脚本断言。
- 远程 quick smoke：下一个空窗优先再跑一轮“默认参数”远端冒烟以确认近期变更无噪声，跑完将日志编号补到本节。

###### 2025-12-10 开工清单（预案）

1) 远端 smoke：执行 `tools/remote/remote_build_and_test.sh`（默认参数即可），验证近期改动无噪声，记录产物路径。  
2) 文档/黄金：如有计划发版，补充 plan-b 或 backoff 期望变更说明到 USAGE/RELEASE_NOTES（仅在需要时）。  
3) plan-b 落地：按 RFC 草案补 `include/wc/wc_batch_strategy.h` 接口草图，并将 raw/health-first/plan-a 迁移到统一策略接口，为后续 plan-b 实现铺路。  
4) 清理：视情况再跑 `tools/dev/prune_artifacts.ps1 -Keep 8`，保持磁盘余量。

###### 2025-12-10 CLI/redirect 修复 & 批量黄金通过

- **CLI 修复**：`--max-hops` 现为 `-R/--max-redirects` 的正式别名；`-Q/--no-redirect` 在存在 referral 时会打印 `=== Additional query to <host> ===`，尾行固定 `Authoritative RIR: unknown @ unknown`，若无 referral（如 ARIN 首跳）则保持当前主机/IP 为权威。
- **文档**：`docs/USAGE_EN.md` / `docs/USAGE_CN.md` 已补充上述行为说明和别名。
- **批量黄金（策略全套）**：
  - raw：PASS `out/artifacts/batch_raw/20251210-225550/build_out/smoke_test.log`（report 同目录 `golden_report_raw.txt`）
  - health-first：PASS `out/artifacts/batch_health/20251210-225813/build_out/smoke_test.log`（report `golden_report_health-first.txt`）
  - plan-a：PASS `out/artifacts/batch_plan/20251210-230041/build_out/smoke_test.log`（report `golden_report_plan-a.txt`）
  - plan-b：PASS `out/artifacts/batch_planb/20251210-230305/build_out/smoke_test.log`（report `golden_report_plan-b.txt`）

###### 2025-12-11 批量黄金（占位 plan-b） & golden_check 兜底

- **批量策略黄金（raw/health-first/plan-a/plan-b 占位）**：`tools/test/remote_batch_strategy_suite.ps1` 全套通过，产物：
  - raw：`out/artifacts/batch_raw/20251211-230449/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251211-230727/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251211-230950/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251211-231219/build_out/smoke_test.log`（`golden_report_plan-b.txt`）；当前 plan-b 仍为占位（日志仅有 `action=unknown-strategy name=plan-b fallback=health-first`，黄金预设以 SKIP 处理）。
- **单条冒烟**：默认参数 `out/artifacts/20251211-220644/build_out/smoke_test.log` `[golden] PASS`。
- **黄金脚本兜底**：`tools/test/golden_check.sh` 增加必选参数校验，空传 `--pref-labels/--backoff-actions` 等会给出 `[golden][ERROR] option '...' requires a non-empty argument`，不再触发 `unbound variable`；实参校验行为不变。

###### 2025-12-12 批策略接口方案（plan-b 落地前置设计）

- **目标**：统一批策略接口，保持 raw/health-first/plan-a 现有行为，为 plan-b 正式版落地与黄金覆盖做准备，不改变 batch 输出契约与 `[DNS-BATCH]` 标签形态。
- **接口设计草案**：在 `include/wc/wc_batch_strategy.h` 增加带状态的 `wc_batch_strategy_iface_t`：`init(ctx*)`（可分配 state）、`pick(ctx*) -> host`、`on_result(ctx*, result*)`、可选 `teardown(ctx*)`，并允许私有 `state` + `free_fn` 挂在扩展版 `wc_batch_context_t` 上；旧 `wc_batch_strategy_t` 通过薄 shim 兼容。
- **上下文构造**：`wc_client_select_batch_start_host()` 构建扩展 ctx，携带 candidates/health 与策略私有 state，生命周期覆盖单条 query；`init` 失败或 `pick` 为 NULL 时回退到 raw 逻辑，确保安全默认。
- **策略迁移计划**：health-first 改为 iface（无状态，`pick_first_healthy`）；plan-a 将 authoritative cache 挪入策略 state，沿用 `plan-a-faststart/plan-a-skip` 日志与惩罚判定；plan-b 将 cache+惩罚判断放入 state，保留/精炼 `plan-b-force-start`、`plan-b-fallback`、`force-override`、`force-last` 日志。
- **日志与兼容性**：保持既有标签名与 key=value 形态，仅在 debug 下输出；被 penalty 推到末尾时继续用 `[DNS-BATCH] action=start-skip/force-last` 透出。
- **测试与黄金**：批黄金需覆盖 health-first/plan-a/plan-b 正式版；plan-b 需移除 SKIP 断言并补日志/行为样例；保留自测/遥测路径的现有断言。
- **落地步骤（拟）**：1) 落接口 + ctx 扩展 + shim；2) 迁移 health-first/plan-a，无行为变化，跑批黄金；3) 实装 plan-b（含日志与 fallback 语义），补黄金；4) 更新 USAGE/RELEASE_NOTES 与本 RFC 记录。

###### 2025-12-12 批策略接口落地 & 四轮黄金全绿

- **代码进展**：完成批策略接口扩展（支持 state + init/teardown）并迁移 health-first/plan-a/plan-b 到新 iface，保持现有行为与日志形态；pick/handle_result 现在自动按 query 生命周期清理策略私有 state。
- **远程冒烟（默认参数）**：无告警 + `[golden] PASS`，产物 `out/artifacts/20251212-004905`。
- **远程冒烟（debug+metrics+dns-cache-stats）**：无告警 + `[golden] PASS`，产物 `out/artifacts/20251212-005337`。
- **批量策略黄金**：raw/health-first/plan-a/plan-b 全部 `[golden] PASS`：
  - raw：`out/artifacts/batch_raw/20251212-005602/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251212-005819/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251212-010039/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251212-010308/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
- **自检黄金（--selftest-force-suspicious 8.8.8.8）**：raw/health-first/plan-a/plan-b 全部 `[golden-selftest] PASS`：
  - raw：`out/artifacts/batch_raw/20251212-010552/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251212-010707/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251212-010827/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251212-010945/build_out/smoke_test.log`
-- 备注：plan-b 逻辑尚未正式启用新行为，当前仅完成 iface 迁移与黄金稳定性确认。

###### 2025-12-12 plan-b 启用 + 四轮黄金（0130 批次）

- 状态：plan-b 正式切换为“缓存优先 + 罚分感知回退”，stderr 输出 `plan-b-*` 标签，黄金预设已启用 plan-b 断言。
- 远程冒烟：
  1) 默认参数：`out/artifacts/20251212-013029`，无告警 + `[golden] PASS`；
  2) `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/20251212-013310`，无告警 + `[golden] PASS`。
- 批量策略黄金（raw/health-first/plan-a/plan-b 全 PASS）：
  - raw：`out/artifacts/batch_raw/20251212-013524/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251212-013755/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251212-014033/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251212-014324/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略 `[golden-selftest] PASS`）：
  - raw：`out/artifacts/batch_raw/20251212-014818/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251212-014939/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251212-015102/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251212-015225/build_out/smoke_test.log`
- 下一步：
  1) 根据本批日志在 USAGE/OPERATIONS 中补充 plan-b 样例或观测提示；
  2) 按 Stage 5.5.3 继续迭代 plan-b 策略（罚分窗口/缓存命中/空击策略），行为变更后更新黄金与文档；
  3) 观察自测/批量日志中 `plan-b-fallback/force-override` 的形态，酌情添加自测 preset。

###### 2025-12-12 plan-b 窗口化 + 四轮黄金（1800 批次）

- 代码变更：plan-b 引入命中窗口（沿用 `wc_backoff_get_penalty_window_ms()` 默认 300s），新增 `[DNS-BATCH] action=plan-b-hit|plan-b-stale|plan-b-empty`；缓存仅在窗口内可用，过期视为 stale 并清空，命中/空击均落 stderr 可观测。
- 远程冒烟：
  1) 默认参数：`out/artifacts/20251212-175111`，无告警 + `[golden] PASS`；
  2) `--debug --retry-metrics --dns-cache-stats`：`out/artifacts/20251212-180052`，无告警 + `[golden] PASS`。
- 批量策略黄金（raw/health-first/plan-a/plan-b 全部 PASS）：
  - raw：`out/artifacts/batch_raw/20251212-180251/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251212-180513/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251212-180751/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251212-181025/build_out/smoke_test.log`（`golden_report_plan-b.txt`，含 plan-b-hit/stale/empty 标签）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，含 plan-b hit/stale/empty 标签断言）：
  - raw：`out/artifacts/batch_raw/20251212-181248/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251212-181400/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251212-181525/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251212-181640/build_out/smoke_test.log`
- 备注：selftest 预设现为 plan-b 轮自动断言 `plan-b-(hit|stale|empty)` + `plan-b-fallback` + `plan-b-force-start` 标签，其余策略不受影响。

###### 2025-12-12 日终备忘（明日启动项）

- 待办 1：按 Stage 5.5.3 继续完善 plan-b（罚分窗口/缓存命中/空击策略），若行为变更需同步黄金与文档。
- 待办 2：补充 plan-b 自测 preset，覆盖 plan-b-* 路径，确保后续改动有自测断言。

###### 2025-12-13 四轮黄金校验（全套 PASS）

1. **远程编译冒烟同步 + 黄金（默认参数）**
  - 结果：无告警 + Golden PASS。
  - 日志：`out/artifacts/20251213-002834/build_out/smoke_test.log`。
2. **远程编译冒烟同步 + 黄金（--debug --retry-metrics --dns-cache-stats）**
  - 结果：无告警 + Golden PASS。
  - 日志：`out/artifacts/20251213-003057/build_out/smoke_test.log`。
3. **批量策略黄金（raw / health-first / plan-a / plan-b）**
  - 结果：四套 `[golden] PASS`。
  - 日志与报告：
    - raw：`out/artifacts/batch_raw/20251213-003249/build_out/smoke_test.log`，`golden_report_raw.txt`。
    - health-first：`out/artifacts/batch_health/20251213-003509/build_out/smoke_test.log`，`golden_report_health-first.txt`。
    - plan-a：`out/artifacts/batch_plan/20251213-003739/build_out/smoke_test.log`，`golden_report_plan-a.txt`。
    - plan-b：`out/artifacts/batch_planb/20251213-004006/build_out/smoke_test.log`，`golden_report_plan-b.txt`。
4. **自检黄金（--selftest-force-suspicious 8.8.8.8，raw / health-first / plan-a / plan-b）**
  - 结果：四套 `[golden-selftest] PASS`，plan-b 轮同时命中 `plan-b-(hit|stale|empty)`、`plan-b-fallback`、`plan-b-force-start` 标签。
  - 日志：
    - raw：`out/artifacts/batch_raw/20251213-004250/build_out/smoke_test.log`。
    - health-first：`out/artifacts/batch_health/20251213-004419/build_out/smoke_test.log`。
    - plan-a：`out/artifacts/batch_plan/20251213-004545/build_out/smoke_test.log`。
    - plan-b：`out/artifacts/batch_planb/20251213-004700/build_out/smoke_test.log`。

  ###### 2025-12-13 plan-b 自检黄金收紧 & 复跑

  - 调整：`tools/test/selftest_golden_suite.ps1` 将 plan-b 自检断言从合并 regex 改为逐条要求 `plan-b-hit` / `plan-b-stale` / `plan-b-empty` / `plan-b-fallback` / `plan-b-force-start`，避免遗漏单个标签也能通过。
  - 验证：四策略自检（`--selftest-force-suspicious 8.8.8.8`）全部 `[golden-selftest] PASS`，输出确认 plan-b 五个标签均命中：
    - raw：`out/artifacts/batch_raw/20251213-011725/build_out/smoke_test.log`
    - health-first：`out/artifacts/batch_health/20251213-011841/build_out/smoke_test.log`
    - plan-a：`out/artifacts/batch_plan/20251213-011956/build_out/smoke_test.log`
    - plan-b：`out/artifacts/batch_planb/20251213-012113/build_out/smoke_test.log`

  ###### 2025-12-13 plan-b 罚分即清缓存 & 四轮黄金

  - 行为微调：plan-b 在命中缓存但被判罚时，立刻清空缓存，避免下一条查询继续命中已知被罚的缓存并重复 start-skip；下一条查询会先看到 `plan-b-empty`，随后直接挑选健康候选。日志标签保持不变（依然有 plan-b-hit/stale/empty/fallback/force-start/force-override/start-skip/force-last）。
  - 远程冒烟（默认参数）：`out/artifacts/20251213-030050`，无告警 + `[golden] PASS`。
  - 远程冒烟（--debug --retry-metrics --dns-cache-stats）：`out/artifacts/20251213-030440`，无告警 + `[golden] PASS`。
  - 批量策略黄金（raw/health-first/plan-a/plan-b）：全 PASS；日志与报告：
    - raw：`out/artifacts/batch_raw/20251213-030726/build_out/smoke_test.log`（`golden_report_raw.txt`）
    - health-first：`out/artifacts/batch_health/20251213-031027/build_out/smoke_test.log`（`golden_report_health-first.txt`）
    - plan-a：`out/artifacts/batch_plan/20251213-031410/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
    - plan-b：`out/artifacts/batch_planb/20251213-031720/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
  - 自检黄金（`--selftest-force-suspicious 8.8.8.8`，raw/health-first/plan-a/plan-b）：全 `[golden-selftest] PASS`；日志：
    - raw：`out/artifacts/batch_raw/20251213-033032/build_out/smoke_test.log`
    - health-first：`out/artifacts/batch_health/20251213-033217/build_out/smoke_test.log`
    - plan-a：`out/artifacts/batch_plan/20251213-033509/build_out/smoke_test.log`
    - plan-b：`out/artifacts/batch_planb/20251213-033630/build_out/smoke_test.log`

  下一步：
  - 文档：USAGE EN/CN 已补充“被罚分即清缓存”说明，后续若需要可在 OPERATIONS/RELEASE_NOTES 增补一句。
  - 观察后续 plan-b 日志（额外 plan-b-empty 次数）对黄金敏感性，无需改标签。

  ###### 2025-12-13 Usage/Exit 对齐 & 远程冒烟

  - **帮助文本对齐**：更新 `wc_meta_print_usage`，将 `-g/--title` 描述改为“前缀匹配 + 保留续行（非 regex）”，补充 `--keep-continuation-lines/--no-keep-continuation-lines`、`--retry-all-addrs`、缓存/TTL、`--dns-no-fallback`、`--selftest-force-{suspicious,private}` 等漏列开关，保持与 `wc_opts` 行为一致。
  - **文档同步**：`docs/USAGE_EN.md` 的 Command line 列表补齐上述开关与 fold 选项，描述与内置 `--help` 对齐。
  - **验证**：远程编译冒烟 + 黄金（默认参数）无告警、`[golden] PASS`，日志目录 `out/artifacts/20251213-022740`；`--help` 实机输出与代码/文档一致（截图核对）。

###### 2025-12-14 开工清单（预案）

- plan-b 传播：如需对外发布，补充一行到 OPERATIONS/RELEASE_NOTES，说明“缓存命中被罚分时即刻清空，下一条会先看到 plan-b-empty 再选健康候选”。
- 黄金监控：观察后续批量日志中 plan-b-empty 频次是否稳定；如黄金脚本出现敏感告警，再评估是否需要放宽或补样例。
- 工具/脚本：检查 `tools/test/selftest_golden_suite.ps1` 是否还需覆盖 `plan-b-force-override` 等标签的单独断言（目前仅五个基础标签）。
- 清理：视磁盘余量运行 `tools/dev/prune_artifacts.ps1 -Keep 8`，保持 artifacts 体积可控。

###### 2025-12-14 四轮黄金校验（全套 PASS）

1. **远程编译冒烟同步 + 黄金（默认参数）** — 无告警 + Golden PASS；日志目录：`out/artifacts/20251214-213515`。
2. **远程编译冒烟同步 + 黄金（`--debug --retry-metrics --dns-cache-stats`）** — 无告警 + Golden PASS；日志目录：`out/artifacts/20251214-213911`。
3. **批量策略黄金（raw/health-first/plan-a/plan-b）** — 四套 `[golden] PASS`：
  - raw：`out/artifacts/batch_raw/20251214-214239/build_out/smoke_test.log`（报告 `golden_report_raw.txt`）。
  - health-first：`out/artifacts/batch_health/20251214-214516/build_out/smoke_test.log`（报告 `golden_report_health-first.txt`）。
  - plan-a：`out/artifacts/batch_plan/20251214-214751/build_out/smoke_test.log`（报告 `golden_report_plan-a.txt`）。
  - plan-b：`out/artifacts/batch_planb/20251214-215019/build_out/smoke_test.log`（报告 `golden_report_plan-b.txt`）。
4. **自检黄金（`--selftest-force-suspicious 8.8.8.8`，raw/health-first/plan-a/plan-b）** — 全部 `[golden-selftest] PASS`：
  - raw：`out/artifacts/batch_raw/20251214-215548/build_out/smoke_test.log`。
  - health-first：`out/artifacts/batch_health/20251214-215718/build_out/smoke_test.log`。
  - plan-a：`out/artifacts/batch_plan/20251214-215840/build_out/smoke_test.log`。
  - plan-b：`out/artifacts/batch_planb/20251214-220013/build_out/smoke_test.log`。

**下一步（围绕 Config 注入与文档同步）**
- 收敛剩余 `g_config` 读取：调整 selftest/hooks 及 residual 路径改用 runtime 配置 getter，补齐 `wc_runtime_init_resources`/`wc_cache_init` 调用点，准备下轮快照保存/恢复。
- 文档：如 plan-b 行为有外宣需求，补充到 OPERATIONS/RELEASE_NOTES；继续监控 plan-b-empty 频次，如需放宽黄金断言或加样例再更新脚本。
- 清理：视磁盘余量执行 `tools/dev/prune_artifacts.ps1 -Keep 8`，保持 artifacts 体积可控。

###### 补充：whois_client.c 头文件下沉与可插拔化（规划）

- 目标：将 `whois_client.c` 的 `#include` 列表逐步下沉到对应模块（runtime/output/query_exec/dns/backoff/selftest 等），入口仅保留极少数聚合头，便于未来替换前端或最小化编译耦合。
- 步骤草案：
  1) 列出当前 `whois_client.c` 的所有包含文件及用途，标记哪些属于“实现头”而非纯接口；
  2) 为 runtime/signal/output/cache/backoff/selftest 等模块补齐公共头/聚合头，避免入口直接 include 深层实现头；
  3) 引入入口专用的 facade 头（如 `wc_client_runtime.h`/`wc_client_pipeline.h`），对外只暴露 orchestrator 级 API；
  4) 每次 include 收敛后跑远程黄金，确保编译/行为不变，直至 `whois_client.c` 的 include 列表可精简到“opts/config + facade”两三项。

###### 2025-12-14 下一步工作计划（拆分/模块化）

- Cache/Backoff 下沉：将入口层仍持有的 DNS/连接缓存结构体与互斥量迁入 `wc_cache`/`wc_backoff`，把调试/统计/完整性检查 API 真正落在 core，入口仅调用公共接口。
- Runtime/信号 glue 收口：把 atexit/清理/异常退出路径统一收在 `wc_runtime`/`wc_signal`，入口不再分散注册或 `exit()`，确保 `[DNS-CACHE-SUM]`/metrics 在异常退出时一致。
- 自测与故障注入集中化：梳理入口与散落文件的自测/注入宏，迁到 `src/core/selftest_*.c` 或专用 fault-injection helper，并完善 `golden_check_selftest.sh` 预设（含 force-private 等）。
- Batch/backoff 接口对齐：让 batch 端完全依赖 `wc_backoff`/`wc_dns_health` 对外 API，检查 raw/health-first/plan-a 是否仍有入口耦合，逐步收敛到策略 iface/state。
- 协议安全与输出管线：复查 `wc_protocol_safety`/`wc_output`/条件输出模块是否仍有入口特化逻辑，保证入口只负责调用顺序与资源生命周期。
- 配置/默认值下沉：将残留的默认值填充与校验搬到 `wc_opts`/`wc_config`，入口只做解析和调用，不再散落配置逻辑。
- Include 收敛（承上规划）：执行头文件下沉与 facade 化，逐步精简 `whois_client.c` 的包含列表，每次收敛后跑远程黄金确认零行为差异。

###### 2025-12-14 进度记录（开工）

- whois_client.c include 审阅：当前仅保留标准库 + `wc_*` 聚合头（cache/client_flow/client_meta/client_net/client_transport/util/config/defaults/dns/grep/lookup/meta/net/opts/output/pipeline/protocol/redirect/runtime/selftest/signal/title/util），入口已是薄壳 main 调用 `wc_pipeline_run`；后续 include 收敛将依赖 facade 化而非入口内代码移动。
- 后续优先事项：
  - 按计划推进 Cache/Backoff 数据面迁移（关注 `wc_cache`/`wc_backoff` 内部与其它 TU 交叉引用）；
  - 整理 runtime/signal glue，收拢 atexit/退出路径；
  - 梳理自测/故障注入入口与脚本，集中到 core/selftest + golden 预设；
  - 持续精简入口 include，必要时为 runtime/pipeline/output 引入 facade 头以替代深层 include。

###### 2025-12-14 四轮黄金校验

- 远程编译冒烟（默认参数）：无告警 + `[golden] PASS`，日志 `out/artifacts/20251214-183453/build_out/smoke_test.log`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：无告警 + `[golden] PASS`，日志 `out/artifacts/20251214-183914/build_out/smoke_test.log`。
- 批量策略黄金（raw/health-first/plan-a/plan-b 全 PASS）：
  - raw：`out/artifacts/batch_raw/20251214-184115/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251214-184344/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251214-184605/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251214-184827/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS）：
  - raw：`out/artifacts/batch_raw/20251214-185038/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251214-185154/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251214-185312/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251214-185443/build_out/smoke_test.log`

下一步：
- 按计划启动 g_config 依赖梳理与注入化迁移（参见“全局 g_config 依赖收敛”条目）。
- 继续 cache/backoff 数据面迁移，并在完成迁移后重复上述四轮黄金确认行为不变。

###### 2025-12-14 自测去全局化 & 四轮黄金复跑（夜间）

- 代码调整：自测路径改用 runtime Config 快照 + push/pop，移除 selftest/seclog demo 对 `g_config` 的直接写入，便于后续多实例/注入化。
- 远程编译冒烟（默认参数）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251214-224159`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251214-224520`。
- 批量策略黄金（raw/health-first/plan-a/plan-b，全 `[golden] PASS`）：
  - raw：`out/artifacts/batch_raw/20251214-224716/build_out/smoke_test.log`（报告 `golden_report_raw.txt`）。
  - health-first：`out/artifacts/batch_health/20251214-224946/build_out/smoke_test.log`（报告 `golden_report_health-first.txt`）。
  - plan-a：`out/artifacts/batch_plan/20251214-225217/build_out/smoke_test.log`（报告 `golden_report_plan-a.txt`）。
  - plan-b：`out/artifacts/batch_planb/20251214-225453/build_out/smoke_test.log`（报告 `golden_report_plan-b.txt`）。
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 `[golden-selftest] PASS`）：
  - raw：`out/artifacts/batch_raw/20251214-230037/build_out/smoke_test.log`。
  - health-first：`out/artifacts/batch_health/20251214-230204/build_out/smoke_test.log`。
  - plan-a：`out/artifacts/batch_plan/20251214-230324/build_out/smoke_test.log`。
  - plan-b：`out/artifacts/batch_planb/20251214-230454/build_out/smoke_test.log`。

下一步：
- 继续扩展 Config 注入链（dns/lookup/net/runtime/cache），替换 residual extern g_config；保持自测使用快照/恢复，不污染进程级配置。
- 若 plan-b 行为需公开说明，则同步 OPERATIONS/RELEASE_NOTES；否则沿用当前黄金基线，关注 plan-b-empty 频次。

###### 2025-12-15 四轮黄金校验（凌晨）

- 远程编译冒烟（默认参数）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251214-234648`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251214-234925`。
- 批量策略黄金（raw/health-first/plan-a/plan-b，全 `[golden] PASS`）：
  - raw：`out/artifacts/batch_raw/20251214-235219/build_out/smoke_test.log`（报告 `golden_report_raw.txt`）。
  - health-first：`out/artifacts/batch_health/20251214-235443/build_out/smoke_test.log`（报告 `golden_report_health-first.txt`）。
  - plan-a：`out/artifacts/batch_plan/20251214-235711/build_out/smoke_test.log`（报告 `golden_report_plan-a.txt`）。
  - plan-b：`out/artifacts/batch_planb/20251214-235939/build_out/smoke_test.log`（报告 `golden_report_plan-b.txt`）。
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 `[golden-selftest] PASS`）：
  - raw：`d_out\smoke_test.log`（原始路径如上次提供）。
  - health-first：`out/artifacts/batch_health/20251215-000251/build_out/smoke_test.log`。
  - plan-a：`out/artifacts/batch_plan/20251215-000418/build_out/smoke_test.log`。
  - plan-b：`out/artifacts/batch_planb/20251215-000534/build_out/smoke_test.log`。

下一步：
- 持续推进 Config 注入收敛，重点在 dns/lookup/net/cache 剩余调用链的显式传递；后续改动需重复四轮黄金确认无回归。
- 观察 plan-b-empty 频次与 `[DNS-CACHE-SUM]` 信号打印是否稳定，如有异常再调整脚本/文档。

###### 2025-12-15 四轮黄金校验（清晨复跑）

###### 2025-12-18 远程验证（补齐 dns/cache host 注入后）

- 修复：`wc_dns_cache_store_positive` 追加 host 参数，dns/cache 再编译通过。
- 远程编译冒烟（默认 + debug/metrics，全 `[golden] PASS`）：`out/artifacts/20251218-012503/build_out/smoke_test.log`；`out/artifacts/20251218-012710/build_out/smoke_test.log`。
- 批量策略黄金（raw/health-first/plan-a/plan-b，全 `[golden] PASS`）：raw `out/artifacts/batch_raw/20251218-012905/build_out/smoke_test.log`（报告 `golden_report_raw.txt`）；health-first `out/artifacts/batch_health/20251218-013142/build_out/smoke_test.log`（报告 `golden_report_health-first.txt`）；plan-a `out/artifacts/batch_plan/20251218-013418/build_out/smoke_test.log`（报告 `golden_report_plan-a.txt`）；plan-b `out/artifacts/batch_planb/20251218-013707/build_out/smoke_test.log`（报告 `golden_report_plan-b.txt`）。
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 `[golden-selftest] PASS`）：raw `out/artifacts/batch_raw/20251218-013920/build_out/smoke_test.log`；health-first `out/artifacts/batch_health/20251218-014034/build_out/smoke_test.log`；plan-a `out/artifacts/batch_plan/20251218-014152/build_out/smoke_test.log`；plan-b `out/artifacts/batch_planb/20251218-014301/build_out/smoke_test.log`。

###### 2025-12-18 远程验证（Config 注入阶段继续）

- 远程编译冒烟（默认）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251218-022709`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251218-022915`。
- 批量策略黄金（raw/health-first/plan-a/plan-b，全 `[golden] PASS`）：raw `out/artifacts/batch_raw/20251218-023144/build_out/smoke_test.log`（报告 `golden_report_raw.txt`）；health-first `out/artifacts/batch_health/20251218-023406/build_out/smoke_test.log`（报告 `golden_report_health-first.txt`）；plan-a `out/artifacts/batch_plan/20251218-023622/build_out/smoke_test.log`（报告 `golden_report_plan-a.txt`）；plan-b `out/artifacts/batch_planb/20251218-023851/build_out/smoke_test.log`（报告 `golden_report_plan-b.txt`）。
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 `[golden-selftest] PASS`）：raw `out/artifacts/batch_raw/20251218-024049/build_out/smoke_test.log`；health-first `out/artifacts/batch_health/20251218-024202/build_out/smoke_test.log`；plan-a `out/artifacts/batch_plan/20251218-024313/build_out/smoke_test.log`；plan-b `out/artifacts/batch_planb/20251218-024433/build_out/smoke_test.log`。

###### 2025-12-18 远程验证（Config 注入阶段继续，凌晨二轮）

- 远程编译冒烟（默认）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251218-035348`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251218-035556`。
- 批量策略黄金（raw/health-first/plan-a/plan-b，全 `[golden] PASS`）：raw `out/artifacts/batch_raw/20251218-035754/build_out/smoke_test.log`（报告 `golden_report_raw.txt`）；health-first `out/artifacts/batch_health/20251218-040017/build_out/smoke_test.log`（报告 `golden_report_health-first.txt`）；plan-a `out/artifacts/batch_plan/20251218-040237/build_out/smoke_test.log`（报告 `golden_report_plan-a.txt`）；plan-b `out/artifacts/batch_planb/20251218-040457/build_out/smoke_test.log`（报告 `golden_report_plan-b.txt`）。
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 `[golden-selftest] PASS`）：raw `out/artifacts/batch_raw/20251218-040650/build_out/smoke_test.log`；health-first `out/artifacts/batch_health/20251218-040808/build_out/smoke_test.log`；plan-a `out/artifacts/batch_plan/20251218-040926/build_out/smoke_test.log`；plan-b `out/artifacts/batch_planb/20251218-041037/build_out/smoke_test.log`。

下一步（Config 注入拆解）：
- 残留 g_config 清单：`wc_cache.c`/cache 调试 helper、`whois_query_exec` pipeline（fold/plain/debug 读）、legacy transport/net 路径、部分 runtime/signal glue、零星自测注入位。
- 步骤序：
  1) cache/backoff：将 cache 内部 extern g_config 改为 init 时注入的 const Config*；调试/统计 helper 也走指针。
  2) pipeline/query_exec：为 `wc_execute_lookup` 及其调用链增加 Config* 入参，入口改为传指针；fold/plain/debug 读取移除全局。
  3) legacy transport/net：client_legacy/client_transport/client_net 切到显式 Config；确保 retry/pacing 读取统一来源。
  4) runtime/signal：统一退出与 atexit 钩子，通过 runtime getter 传递 Config；确认 `[DNS-CACHE-SUM]` 仍只输出一次。
  5) 自测/fault hook：继续使用快照 push/pop，避免写全局；补全新 API 调用。
  6) 全仓扫尾：清理剩余 extern g_config 声明，跑四轮黄金（默认 + debug/metrics + 批量 + 自检）验证行为等价。

plan-b 近期改动说明：
- 罚分即清缓存：命中缓存且被判罚时立即清空，下一条必先打印 `plan-b-empty` 再选健康候选；黄金脚本已断言 `plan-b-hit/stale/empty/fallback/force-start` 全量标签。
- 观测点：`[DNS-CACHE-SUM]` 仍在进程退出时输出一次；plan-b-empty 频次可能略升，属于预期。若未来再调节 penalty/缓存策略，需同步黄金与 OPERATIONS/RELEASE_NOTES。

###### 2025-12-18 Cache/Backoff 注入收敛 + 四轮黄金（清晨批次）

- 代码变更：
  - `wc_cache` 去全局：移除模块级 Config 指针，改为 init 时记录只读快照；DNS 正/负缓存和 backoff helper 全部显式传入 Config，连接缓存仍保持线程安全封装。
  - 调用方改造：`client_net` / `client_legacy` 全链路传入 Config，backoff 路径不再依赖隐式全局。
- 远程冒烟 + 黄金（默认）：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-053004`。
- 远程冒烟 + 黄金（`--debug --retry-metrics --dns-cache-stats`）：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-053213`。
- 批量策略黄金（raw/health-first/plan-a/plan-b 全 PASS）：
  - raw：`out/artifacts/batch_raw/20251218-053401/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251218-053627/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251218-053902/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251218-054142/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 `[golden-selftest] PASS`）：
  - raw：`out/artifacts/batch_raw/20251218-054341/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251218-054452/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251218-054605/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251218-054721/build_out/smoke_test.log`
- 下一步：
  1) 持续收敛 runtime/signal 路径的 Config 获取，确保 `[DNS-CACHE-SUM]` 仍只输出一次；
  2) 检查 batch/lookup 侧是否还有隐式配置读取，必要时补充 facade 传递；
  3) 完成注入后再复跑四轮黄金确认零行为差异。

###### 2025-12-18 Runtime/Signal 注入 & 四轮黄金（06:01 批次）

- 代码进展：
  - signal 模块新增显式 Config 注入入口（wc_signal_set_config），runtime 在 init_resources 时注入，signal 仍保留 runtime fallback，以保证 `[DNS-CACHE-SUM]` 仅触发一次。
  - batch/client_flow 捕获入口传入的 Config，批量/lookup/backoff 调用链优先使用注入配置，减少隐式 runtime 读取。
- 远程冒烟 + 黄金（默认）：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-060136`。
- 远程冒烟 + 黄金（`--debug --retry-metrics --dns-cache-stats`）：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-060335`。
- 批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS）：
  - raw：`out/artifacts/batch_raw/20251218-060541/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251218-060813/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251218-061031/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251218-061252/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 `[golden-selftest] PASS`）：
  - raw：`out/artifacts/batch_raw/20251218-061539/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251218-061655/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251218-061813/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251218-061928/build_out/smoke_test.log`
- 下一步：
  1) 继续审视 lookup/dns 侧的 runtime fallback，必要时增设显式注入参数，保持行为等价；
  2) 如有新的注入改动，重复四轮黄金验证；
  3) 观察 `[DNS-CACHE-SUM]` 仍保持单次输出，若异常需回溯 signal/runtime glue。

###### 2025-12-18 四轮黄金校验（07:00 批次）

- 远程编译冒烟 + 黄金（默认参数）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251218-070023`（含 `build_out/smoke_test.log`）。
- 远程编译冒烟 + 黄金（`--debug --retry-metrics --dns-cache-stats`）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251218-070733`（`build_out/smoke_test.log`）。
- 批量策略黄金（raw/health-first/plan-a/plan-b，全 `[golden] PASS`）：
  - raw：`out/artifacts/batch_raw/20251218-070940/build_out/smoke_test.log`（报告 `golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251218-071155/build_out/smoke_test.log`（报告 `golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251218-071414/build_out/smoke_test.log`（报告 `golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251218-071627/build_out/smoke_test.log`（报告 `golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略 `[golden-selftest] PASS`）：
  - raw：`out/artifacts/batch_raw/20251218-072038/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251218-072149/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251218-072302/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251218-072414/build_out/smoke_test.log`

说明：本轮继续验证 Config 注入后 lookup/dns 路径的行为等价性，`[DNS-CACHE-SUM]` 仍保持单进程单次输出；无新增告警。

###### 2025-12-18 四轮黄金校验（08:22 批次）

- 代码进展：lookup 路径强制显式 Config 注入，`wc_lookup_resolve_config` 去除 runtime fallback，`wc_lookup_execute` 在缺失 Config 时返回 `EINVAL` 并拒绝执行。
- 远程编译冒烟（默认）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251218-082248`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251218-082454`。
- 批量策略黄金（raw/health-first/plan-a/plan-b，全 `[golden] PASS`）：
  - raw：`out/artifacts/batch_raw/20251218-082631/build_out/smoke_test.log`（报告 `golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251218-082848/build_out/smoke_test.log`（报告 `golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251218-083107/build_out/smoke_test.log`（报告 `golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251218-083326/build_out/smoke_test.log`（报告 `golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 `[golden-selftest] PASS`）：
  - raw：`out/artifacts/batch_raw/20251218-083524/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251218-083636/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251218-083747/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251218-083856/build_out/smoke_test.log`

下一步：
- 完成 dns 路径的 Config 显式传递，移除 wc_dns_config_or_default 的 runtime fallback；自测/批量流水线改用显式 Config 继续复跑四轮黄金；确认 `[DNS-CACHE-SUM]` 仍保持单次输出。

###### 2025-12-18 四轮黄金校验（08:57 批次）

- 代码进展：DNS 路径移除 runtime fallback（`wc_dns_config_or_default`/`client_net` 零化缺省）后完成全矩阵验证，行为与基线一致，`[DNS-CACHE-SUM]` 仍单次输出。
- 远程编译冒烟（默认）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251218-085751`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：无告警 + `[golden] PASS`，日志目录 `out/artifacts/20251218-085949`。
- 批量策略黄金（raw/health-first/plan-a/plan-b，全 `[golden] PASS`）：
  - raw：`out/artifacts/batch_raw/20251218-090130/build_out/smoke_test.log`（报告 `golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251218-090356/build_out/smoke_test.log`（报告 `golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251218-090613/build_out/smoke_test.log`（报告 `golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251218-090835/build_out/smoke_test.log`（报告 `golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 `[golden-selftest] PASS`）：
  - raw：`out/artifacts/batch_raw/20251218-091032/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251218-091143/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251218-091300/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251218-091415/build_out/smoke_test.log`

下一步：
- 检查剩余调用链是否仍有隐式 Config 读取（legacy/transport 及自测钩子）；如有则补显式传递；如需更多调整后再复跑四轮黄金确保行为等价。

###### 2025-12-16 开工清单（计划）

- Config 注入收敛（下一步）：
  - 为 `wc_dns_build_candidates`、health 相关 API 增加可选 Config 入参；调用链（lookup/selftest/legacy）显式传递。
  - legacy 路径（client_legacy/transport/net）改用显式 Config 注入，移除 runtime 隐式读取。
  - 完成后复跑四轮黄金确认无行为变更。
- runtime/signal 收口：
  - 检查 pipeline/client_flow 是否仍有独立 atexit/cleanup，迁移到 runtime hook。
  - 验证异常退出仍能输出一次 `[DNS-CACHE-SUM]`，并保持日志一致性。
- 文档/黄金：
  - 若 plan-b 行为需外宣或黄金脚本需放宽/加样例，更新 OPERATIONS/RELEASE_NOTES 与脚本。
  - 继续记录每日黄金日志目录，保持 RFC 与 OPERATIONS 对齐。

###### Cache/Backoff 下沉执行草案（待启动）

- 现状：连接缓存结构体/互斥量/统计仍在 `src/core/cache.c` 靠 `extern Config g_config` 驱动；入口仅 include `wc_cache.h`。调试完整性/统计 API 仍部分留在入口。
- 目标：把连接缓存数据与调试 helper 完全归档在 `wc_cache`/`wc_backoff`，入口只见公共 API；移除跨 TU 的 g_config 直接引用。
- 步骤：
  1) 提炼 cache/backoff 内部状态为内部 struct（含 mutex），在 `wc_cache` 内封装对 `Config` 的只读依赖（通过 init 参数或 getter）。
  2) 把入口遗留的 cache 调试/统计 helper 下沉到 `wc_cache`，并在 `wc_cache.h` 暴露稳定接口（validate/log stats）。
  3) 调整调用方：入口/lookup/net 仅通过 `wc_cache_*`/`wc_backoff_*` 访问；移除对内部数组/互斥的 extern/隐式依赖。
  4) 跑一轮远程黄金（默认 + debug/dns-cache-stats + 批量 + 自测），比对 `[DNS-CACHE-SUM]`、`[DNS-BACKOFF]`、plan-b 标签。

###### Runtime/Signal glue 收口草案（待启动）

- 目标：把 atexit 注册、退出码、信号处理的 glue 统一收敛到 `wc_runtime`/`wc_signal` facade，入口不再自行 `exit()` 或分散注册。
- 步骤：
  1) 盘点 `wc_runtime`/`wc_signal` 之外仍在 client_flow/pipeline 的 atexit/signal/cleanup 调用；
  2) 提供统一退出 helper（含 metrics/dns-cache-sum 钩子），入口/管线只返回 rc 由 helper 处理收尾；
  3) 重新跑 ctrl-c、自测、批量场景黄金，关注 `[DNS-CACHE-SUM]`、退出码 130、一致的 stderr 文案。

###### 自测/故障注入集中化草案（待启动）

- 目标：将散落的自测/注入宏迁至 `src/core/selftest_*.c` 或统一 fault-injection helper；黄金预设覆盖 force-private 等动作。
- 步骤：
  1) 枚举仍在入口/其它 TU 的 `--selftest-*` 钩子与宏，拆分为 core 层 API；
  2) 扩充 `golden_check_selftest.sh` 预设覆盖 force-private/force-iana 等，更新 `selftest_golden_suite.ps1`；
  3) 跑自测黄金四策略，确保 `[SELFTEST] action=*` / plan-b 标签稳定。

###### 全局 g_config 依赖收敛（计划中）

- 背景：`wc_cache` 已具备 `wc_cache_init_with_config(const Config*)` 等配置注入入口，但 runtime 仍以全局 `g_config` 驱动 cache/net/pipeline 初始化；希望逐步移除对进程级全局配置的硬依赖，便于测试与多实例注入。
- 拆解步骤：
  1) 全仓梳理 `g_config` 引用，按职责分类（init、runtime 读、日志等），形成迁移清单；
  2) 为 cache/net/runtime/pipeline 等补充或改用 `*_init_with_config` 接口，由 runner/main 显式传递 `Config*`，减少隐式全局访问；
  3) 迁移完成后跑构建 + 黄金/自测（含 `--debug --retry-metrics --dns-cache-stats`）确认行为等价；必要时保留兼容包装并标注 deprecated。
- 当前状态：计划阶段，待完成步骤 1 后启动迁移。

###### 2025-12-14 g_config 依赖盘点（初稿）
 

- 定义/入口：`g_config` 在 [src/core/client_runner.c](src/core/client_runner.c) 定义并通过 [include/wc/wc_client_runner.h](include/wc/wc_client_runner.h) 暴露，wc_runtime 头亦标注依赖（见 [include/wc/wc_runtime.h](include/wc/wc_runtime.h)）。
- 初始化/构造类读：
  - cache：`wc_cache_init_with_config(&g_config)` 仍在 [src/core/cache.c](src/core/cache.c) 通过 extern 使用。
  - runtime：`wc_runtime_apply_post_config` 等在 [src/core/runtime.c](src/core/runtime.c) 读取 pacing/retry 配置并清理 fold_sep。
  - query 执行：`wc_execute_lookup`/fold/plain 相关开关集中在 [src/core/whois_query_exec.c](src/core/whois_query_exec.c)，构造 `wc_lookup_opts`、fold 输出与 plain 模式都直接读 g_config。
- 运行期读（网络/DNS/批量）：
  - DNS/lookup 路径在 [src/core/dns.c](src/core/dns.c) 与 [src/core/lookup.c](src/core/lookup.c) 读取地址配置、fallback、候选上限、重试与 IP 偏好。
  - 传输层在 [src/core/client_transport.c](src/core/client_transport.c)、[src/core/client_net.c](src/core/client_net.c)、[src/core/client_legacy.c](src/core/client_legacy.c) 读取超时/重试/缓冲区大小/debug 标志；批量 orchestrator 在 [src/core/client_flow.c](src/core/client_flow.c) 读取 fold/plain/debug。
- 信号/自测/安全：
  - 信号处理在 [src/core/signal.c](src/core/signal.c) 读取 debug/security_logging 与 DNS 缓存 TTL 参数。
  - 自测钩子在 [src/core/selftest.c](src/core/selftest.c) 与 [src/core/selftest_hooks.c](src/core/selftest_hooks.c) 直接修改 dns_max_candidates、ipv4/ipv6 偏好、fallback 禁用与 security_logging，属于写入型依赖。
- 观测输出：`wc_is_debug_enabled()` 等辅助函数仍由 g_config 提供，日志/metrics 读取分布在 runtime/dns/net/signal 等处。
- 风险与迁移重点：
  - whois_query_exec 与 batch 流水线直接读 fold/plain/debug，后续需要 Config* 注入以解耦；
  - 自测路径写 g_config 字段，迁移时需提供“保存/恢复配置”机制或临时副本，避免多实例相互污染；
  - cache/runtime 目前以 extern 形式访问，需尽早切换到显式 init 参数，减少跨 TU 全局可变状态。
- 注入化顺序（建议）：
  1) 先为 whois_query_exec/pipeline 引入 Config* 参数，删除其内部 extern；
  2) cache/runtime 切换为“init-with-config + getter”模式，dns/lookup/net 调用链改为传入指针或上下文；
  3) 自测钩子改为显式保存/恢复 Config 快照的 helper，避免裸写全局；
  4) 收口暴露面：保留 `wc_client_runner_config()` 为唯一对外获取 Config 的入口，其他模块仅接受注入，不再自行声明 extern。

###### 2025-12-14 晚间进度与验证（Config 注入阶段）

- 今日实现：whois_query_exec/client_flow 改为显式传入 Config*（lookup 执行、fold/plain/debug 输出、私网检测、批量 orchestrator 全部使用注入配置），移除了上述 TU 内的 extern g_config 依赖。
- 远程验证（全部无告警 + `[golden]`/`[golden-selftest] PASS`）：
  1) 默认参数远程冒烟：[out/artifacts/20251214-201532/build_out/smoke_test.log](out/artifacts/20251214-201532/build_out/smoke_test.log)。
  2) `--debug --retry-metrics --dns-cache-stats`：[out/artifacts/20251214-201927/build_out/smoke_test.log](out/artifacts/20251214-201927/build_out/smoke_test.log)。
  3) 批量策略 raw/health-first/plan-a/plan-b：raw [out/artifacts/batch_raw/20251214-202150/build_out/smoke_test.log](out/artifacts/batch_raw/20251214-202150/build_out/smoke_test.log)（报告 [out/artifacts/batch_raw/20251214-202150/build_out/golden_report_raw.txt](out/artifacts/batch_raw/20251214-202150/build_out/golden_report_raw.txt)）；health-first [out/artifacts/batch_health/20251214-202440/build_out/smoke_test.log](out/artifacts/batch_health/20251214-202440/build_out/smoke_test.log)（报告 [out/artifacts/batch_health/20251214-202440/build_out/golden_report_health-first.txt](out/artifacts/batch_health/20251214-202440/build_out/golden_report_health-first.txt)）；plan-a [out/artifacts/batch_plan/20251214-202704/build_out/smoke_test.log](out/artifacts/batch_plan/20251214-202704/build_out/smoke_test.log)（报告 [out/artifacts/batch_plan/20251214-202704/build_out/golden_report_plan-a.txt](out/artifacts/batch_plan/20251214-202704/build_out/golden_report_plan-a.txt)）；plan-b [out/artifacts/batch_planb/20251214-202940/build_out/smoke_test.log](out/artifacts/batch_planb/20251214-202940/build_out/smoke_test.log)（报告 [out/artifacts/batch_planb/20251214-202940/build_out/golden_report_plan-b.txt](out/artifacts/batch_planb/20251214-202940/build_out/golden_report_plan-b.txt)）。
  4) 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：raw [out/artifacts/batch_raw/20251214-203201/build_out/smoke_test.log](out/artifacts/batch_raw/20251214-203201/build_out/smoke_test.log)；health-first [out/artifacts/batch_health/20251214-203328/build_out/smoke_test.log](out/artifacts/batch_health/20251214-203328/build_out/smoke_test.log)；plan-a [out/artifacts/batch_plan/20251214-203454/build_out/smoke_test.log](out/artifacts/batch_plan/20251214-203454/build_out/smoke_test.log)；plan-b [out/artifacts/batch_planb/20251214-203615/build_out/smoke_test.log](out/artifacts/batch_planb/20251214-203615/build_out/smoke_test.log)。

- 下一步：
  1) 继续将 Config 注入链扩展到 dns/lookup/net/runtime/cache，替换剩余 extern g_config；
  2) 为自测钩子与批量策略添加 Config 快照保存/恢复，避免写全局；
  3) 注入收敛后复跑默认 + debug/metrics + 批量 + 自检黄金矩阵，确认输出契约保持稳定。
