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

### 5.2 计划中的下一步（Phase 2 草稿）

- **2025-11-XX（计划中的下一步，尚未实施）**  
  拟进行的拆分/下沉方向（未来 Phase 2，执行前需再次对照本 RFC）：
  - 进一步将 `whois_client.c` 中的其他配置/初始化 glue 拆分到 core 层，使 `whois_client.c` 更接近“纯入口 + 极薄 orchestrator”；  
  - 在每次物理拆文件前后，使用远程多架构 golden 脚本进行回归，确保拆分仅改变结构，不改变行为/日志契约；  
  - 视后续复杂度，考虑在 `src/core/selftest_*.c` 中补充围绕单条查询/批量查询的自测场景，覆盖 suspicious/private/lookup 失败/中断等路径；  
  - Phase 2 初步设想：集中梳理信号处理与退出路径（`signal_handler` / `cleanup_on_signal` / `should_terminate` / active connection 注册），在保证 Ctrl-C 语义与 `[RETRY-METRICS]` / `[DNS-CACHE-SUM]` 输出不变的前提下，把可复用的“进程级网络清理 glue”封装到 core/net 层，为未来可能出现的其他 front-end 预留共用路径。  

---

### 5.3 C 计划：退出码策略与现状对照表

> 目标：在 **不改变既有行为（尤其是 Ctrl-C=130 与成功=0）** 的前提下，先梳理并文档化当前的退出码分布，再视需要在后续小批次中用常量名收口，最后才考虑是否在不破坏外部依赖的情况下优化个别场景的退出码。

- **草图：建议的退出码分层（设计稿，暂不强推落地）**  
  - `0`：成功结束（正常查询完成；纯 meta 命令如 `--help/--version/--servers/--examples/--about` 成功返回；自测命令在所有子用例通过时）。  
  - `1`：通用失败（网络/lookup 失败、配置非法、批量模式中被视为“致命”的错误等），作为当前实现里绝大多数非 0 场景的统一收口。  
  - `2`：用法/参数错误的候选预留值（例如 `wc_opts_parse` 失败），目前实现中仍多数使用 `1`，后续如要引入 `2` 需要单独开一轮小改动并确认无外部依赖。  
  - `130`：SIGINT(Ctrl-C) 中断，保持现有行为：stderr 输出固定文案 `"[INFO] Terminated by user (Ctrl-C). Exiting..."`，并通过 `atexit` 路径触发 metrics/cache stats 等钩子；这是必须严格保持不变的一档。  

- **现状对照表（首轮，只关注进程级出口与明显的 exit/return）**  
  - `src/whois_client.c`：  
    - `main()`：  
      - `wc_opts_parse()` 失败：打印 usage，`return 1;` → 归类为“用法/参数错误”，当前使用 `1`。  
      - `validate_global_config()` 失败：`if (!validate_global_config()) return 1;` → 配置不合法，归类为“通用失败(1)”。  
      - `wc_client_handle_meta_requests()` 返回非 0：  
        - `meta_rc > 0`：`exit_code = 0; return exit_code;` → 纯 meta 成功，退出码为 `0`。  
        - `meta_rc < 0`：`exit_code = 1; return exit_code;` → meta 执行失败，退出码为 `1`。  
      - `wc_client_detect_mode_and_query()` 失败：`return 1;` → 参数/模式组合问题，归入“通用失败(1)”（与 usage 接近，但当前未区分 1/2）。  
      - 单次/批量查询：  
        - 非 batch：直接 `return wc_client_run_single_query(single_query, server_host, port);`，其中 0/非 0 由 core 层 orchestrator 决定；按现有实现，成功为 `0`，失败为 `1`。  
        - batch：`return wc_client_run_batch_stdin(server_host, port);`，同样由 core 决定 0/1。  
      - 特例说明：对于 `no-such-domain-abcdef.whois-test.invalid` 这类“协议/网络均成功，但 RIR 明确返回‘无数据’”的查询，目前仍视作成功路径，退出码为 0；这一点在 v3.2.9 及本次改动前后均保持一致，后续如要调整，需要单独权衡脚本依赖与业务语义。  
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

- **后续 C 步实施建议（尚未动手）**  
  - 后续如需进一步细化（例如把 usage 场景单独调整为 `2`），需在单独小批次中执行，并补充 USAGE/OPERATIONS 文档说明以及黄金脚本的适配。  

> 后续如需细化 Phase 2/3（例如真正把 pipeline glue、net/DNS glue 下沉到 `src/core/`）或增加新的自测矩阵，可在本文件后续章节中继续扩展，保持“背景 → 目标 → 改动 → 风险 → 进度”这一结构统一。
