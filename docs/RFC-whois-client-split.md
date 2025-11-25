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

### 5.2 计划中的下一步（Phase 2 草稿）

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

- 新增 `wc_backoff` helper（`include/wc/wc_backoff.h` + `src/core/backoff.c`），对外提供 `note_success/failure`、`should_skip` 以及 penalty 窗口 setter，内部直接复用 `wc_dns_health` 的 host+family 记忆；默认 penalty 提升至 300s 以对齐旧版 `SERVER_BACKOFF_TIME`，并允许未来通过 Setter 调整。  
- `wc_cache_is_server_backed_off()` / `_mark_server_failure` / `_mark_server_success` 现已完全委托给 `wc_backoff`，移除了 `ServerStatus` 静态数组与互斥锁，debug 日志继续输出但基于新的 snapshot 数据。  
- `wc_lookup_execute()` 在遍历 DNS candidates 时查询 `wc_backoff_should_skip()`：非最后一个候选命中 penalty 直接跳过，最后一个候选即便被处罚也会以 `action=force-last` 记录 `[DNS-BACKOFF]` 并继续尝试，保证仍有出路；`wc_lookup_family_to_af()` helper 用于在 host/IPv4/IPv6 之间转换；新日志加入 `consec_fail` 与 `penalty_ms_left` 字段，供黄金脚本对比。  
- `wc_dns_health` 新增 penalty window setter/getter，`wc_backoff_set_penalty_window_seconds()` 暂未对外暴露 CLI，但为后续批量/自测调参留好入口。  
- **测试**：已完成两轮远程 `remote_build_and_test.sh`（Round 1 默认参数，Round 2 附 `--debug --retry-metrics --dns-cache-stats`），日志无告警且 Golden 校验 PASS；`[DNS-BACKOFF]` 与既有 `[DNS-*]`/`[RETRY-*]` 标签共存正常。  

#### 2025-11-24 进度更新（B 计划 / Phase 2：legacy DNS cache 可观测性）

- `wc_cache_get_dns()` 现记录命中/未命中计数，并新增 `wc_cache_get_dns_stats()` helper，未来可在统一 metrics 输出中引用。  
- `wc_client_resolve_domain()` 在命中正向缓存、命中负缓存与准备走解析器这三个节点输出 `[DNS-CACHE-LGCY] domain=<...> status=hit|neg-hit|miss`，仅在 `--debug` 或 `--retry-metrics` 场景打印，避免影响默认 stdout/stderr。  

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
  该桥接仅在 `--dns-use-wcdns` 打开时启用，日志上新增 `status=bridge-hit/bridge-miss/neg-bridge` 三个枚举，便于远程黄金脚本观测。
- 变更后立即跑三轮 `tools/remote/remote_build_and_test.sh`：Round1 默认参数；Round2 `--debug --retry-metrics --dns-cache-stats`；Round3 `--debug --retry-metrics --dns-cache-stats --dns-use-wcdns`。三轮均 **无告警 + Golden PASS**，确认共享 bridge ctx 不影响 legacy/wc_dns 双向同步与遥测标签。
- `include/wc/wc_dns.h` + `src/core/dns.c` 暴露 `wc_dns_negative_cache_lookup/store()` 的正式 API，内部封装现有的 `wc_dns_neg_cache_hit()` / `wc_dns_neg_cache_store()`，确保 legacy 与 lookup 共用一套 TTL/统计；
- **远程冒烟**：完成三轮 `tools/remote/remote_build_and_test.sh`（Round1 默认；Round2 加 `--debug --retry-metrics --dns-cache-stats`；Round3 加 `--debug --retry-metrics --dns-cache-stats --dns-use-wcdns`），全部 **无告警 + Golden PASS**，`[DNS-CACHE-LGCY]` / `[DNS-CACHE]` / `[DNS-CACHE-LGCY-SUM]` 与 `[RETRY-*]` 标签形态与之前一致，新增 `status=bridge-hit/neg-bridge` 记录在第三轮日志中可见。  
- **同进度新增正向缓存同步**：当 `wc_client_resolve_domain()` 触发 `getaddrinfo()` 且成功解析出 IP 时，只要 `--dns-use-wcdns` 为启用状态，即会把该结果写回 `wc_dns` 正向缓存（新 helper `wc_dns_cache_store_literal`，包含 sockaddr 副本），这样下一次走 `wc_dns_build_candidates()` 时即可直接命中，无需再次触发系统解析。该写回统一使用 canonical host（`wc_client_build_wcdns_ctx()` 计算），保持与 lookup 路径一致的 key；
- **同批次 telemetry**：`[DNS-CACHE-LGCY]` 新增 `status=bridge-miss`（wc_dns 候选未产出数值命中时标记，便于区分进入 legacy resolver 的原因）与 `status=wcdns-store`（legacy `getaddrinfo` 成功且结果已同步写入 `wc_dns` cache 时标记），调试/metrics 场景下可据此评估双向同步效率；
- **测试**：再跑一轮同配置三连（Round1 默认；Round2 `--debug --retry-metrics --dns-cache-stats`；Round3 `--debug --retry-metrics --dns-cache-stats --dns-use-wcdns`），依旧 **无告警 + Golden PASS**，且 `[DNS-CACHE-LGCY] status=bridge-miss/bridge-store` 均有出现，验证新增 telemetry 已纳入遥测。  

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
  - `wc_client_resolve_domain()` 始终初始化 `wc_dns_bridge_ctx_t` 并先尝试 `wc_dns` 候选；`bridge-miss` / `wcdns-store` / `legacy-shim` 遥测仍可用于判断 fallback。  
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
- legacy resolver 在 miss 时 **始终** 先消费 `wc_dns_build_candidates()` 产出的 IP literal，命中后 `wc_cache_set_dns_with_addr()` 自动写回 wc_dns，legacy cache 仅在 `bridge-miss` 场景兜底。  
- 2025-11-27 起移除了 `--dns-use-wcdns` CLI flag，所有遥测（`wcdns-hit`/`legacy-shim`/`bridge-miss` 等）依旧保留，用于衡量 fallback 占比；回滚手段转为“观察 shim 计数 + 必要时通过 debug build 临时禁用 bridge”。  

**Stage 2 – 负缓存与策略统一**
1. **负缓存共享**：`wc_cache_is_negative_dns_cached()` 先查询 `wc_dns_negative_cache_lookup()`，命中后直接短路并标记 `status=neg-bridge`；legacy 数组只做 shim（`status=neg-shim`），`[DNS-CACHE-LGCY-SUM]` 的 neg 统计与 `[DNS-CACHE]` 对齐。  
2. **fallback 策略合流**：将 forced IPv4 / known IP fallback 切换为调用 `wc_dns` helper（`wc_dns_get_known_ip`、`wc_dns_rir_fallback_from_ip`），由 `wc_lookup` 统一输出 `[DNS-FALLBACK]`，确保 lookup/legacy 共享同一策略。  
3. **遥测整合**：`[DNS-CACHE-LGCY]` 的 `status` 字段已包含 `wcdns-hit` / `legacy-shim` / `bridge-miss` / `neg-bridge` / `neg-shim`，即便桥接默认开启也能快速定位是否回退到旧路径。  

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
3. **批量健康记忆**  
  - 在批量循环级别维护一个轻量状态表，记录同一进程内前一条 query 的失败结果，使同一 RIR host 在短时间内不会被批量模式重复拨号；首次实现可以沿用 `wc_backoff` penalty=300s 的语义。
4. **观测与黄金收敛**  
  - 新增 `[DNS-BATCH]` 或扩展 `[DNS-BACKOFF]` 字段，清晰记录批量调度行为；更新 `tools/test/golden_check.sh`，确保冒烟脚本在默认与 debug 参数下都能观察到预期标签。
  - 安排至少三轮冒烟：Round1 默认、Round2 `--debug --retry-metrics --dns-cache-stats`、Round3 扩展批量输入（可用 `-B` + 多行查询或 `stdin` 模式）以验证新调度逻辑在真实批量场景中的稳定性。
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
