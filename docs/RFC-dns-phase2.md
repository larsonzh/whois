# DNS Phase 2 方案备忘

> 目的：固化当前讨论成果，避免 IDE/聊天上下文意外丢失；供后续迭代或文档扩展复用。

## 1. 背景
- 3.2.6~3.2.8 引入 `wc_dns` 模块，承担候选生成与 IPv4/IPv6 调度，但设计细节此前仅存在于会话记忆。
- `lookup.c` 仍负责大部分 fallback 逻辑，尚未与 DNS 缓存、指标输出等部件彻底解耦。
- 需要明确 Phase 2 的实施边界与后续阶段路线，以便他人介入或断点续作。

## 2. 目标
1. **候选集中管理**：所有 `--dns-*`、家族偏好、fallback 开关均在 `wc_dns` 层统一生效。
2. **回退复用**：空响应重试、强制 IPv4、已知 IPv4、黑洞自测等路径共享同一候选列表/限制，保持观测一致性。
3. **可观测性**：在 `--debug` / `--retry-metrics` 下输出候选顺序与拨号结果，便于排障。
4. **后续扩展接口**：为 Phase 3（DNS cache/负向 TTL）预留 metadata/统计埋点。

## 3. 当前实现速记
- `wc_dns_is_ip_literal`、`wc_dns_canonical_host_for_rir`、`wc_dns_build_candidates` 已落地，支持 `AI_ADDRCONFIG`、`dns_retry*`、候选上限、IPv6/IPv4 交错。
- `lookup.c`：
  - 构建候选列表后遍历拨号；首个候选失败时记录 `first_conn_rc`。
  - 失败后尝试“强制 IPv4”与“已知 IPv4”路径（可由 `--no-force-ipv4-fallback`/`--no-known-ip-fallback` 禁用）。
  - 空响应检测会复用 `wc_dns_build_candidates` 重新挑选备用主机。
- CLI (`wc_opts`) 已暴露 `dns_retry`、`dns_max_candidates`、`no_dns_addrconfig`、家族偏好、fallback 禁用项等配置。

## 4. 待解决事项（滚动状态）
1. **缓存对接**（✅ 已完成）：`wc_dns` 现已托管正向/负向缓存与 TTL，候选 metadata 附带来源、族、缓存命中标记，`lookup.c` 透出 `[DNS-CAND]`/`[DNS-ERROR]` 便于排障。
2. **错误提示统一**（✅ 已完成）：`wc_dns_build_candidates` 记录最后一次 `getaddrinfo`，`lookup.c` 在调试/指标模式下输出 `[DNS-ERROR] gai=... host=...`。
3. **调试日志**（✅ 已完成）：`wc_lookup_log_dns_candidates` 与 `[DNS-FALLBACK]` 已与 retry metrics 对齐。
4. **自测矩阵**（✅ 阶段完成）：已新增 `selftest_dns_candidate_limit`、`selftest_dns_negative_flag` 及 lookup 层 `dns-smoke` / `dns-no-fallback-counters`，覆盖候选上限、负缓存注入以及回退开关（含 `--dns-no-fallback`）的行为观察。后续如有需要可在 Phase 3 中进一步扩展 IPv6-only / 组合场景，但不再作为当前 Phase 2 必选项。
5. **文档**（✅ 已完成）：`USAGE_CN/EN` 与本备忘已补充 DNS 调试示例、缓存说明以及 `--dns-cache-stats` / `--dns-no-fallback` 等选项说明；`--help` 中亦补齐 DNS 相关开关简要说明。

## 5. 建议执行顺序
1. **候选生成增强**
   - 在 `wc_dns_build_candidates` 内部接入 DNS cache（命中/负向 TTL），并在 `wc_dns_candidate_list_t` 中附加来源标记。
   - 预留 `struct sockaddr_storage`，避免重复 `getaddrinfo`。
2. **调试 & 指标**
   - `lookup.c` 遍历候选时，若 `g_config.debug` 或 `wc_net` 的 retry metrics 开启，打印候选顺序、family、来源。
   - 新增 `wc_dns` 自测（可 mock `getaddrinfo`）验证 IPv4/IPv6 交错和上限裁剪。
3. **错误提示**
   - `wc_dns_collect_addrinfo` 返回结构化错误；`lookup.c` 根据错误类型输出提示（DNS 失败 vs TCP 失败）。
4. **文档同步**
   - 在 USAGE 中新增“DNS 调试”段落：示例命令 `whois-x86_64 --debug --retry-metrics --dns-max-candidates 2 ...`。
   - RELEASE_NOTES/README 更新 Phase 2 示例与回退策略说明。
5. **路线图占位**
   - Phase 3：以现有缓存实现为基线，补齐命中率/负缓存指标、可配置 TTL 与逐 RIR 统计；推导出 CLI 级别的 `--dns-cache-stats` 输出，并记录在 release note。
   - Phase 4：评估并行拨号或异步解析（需与 pacing/metrics 兼容）。

## 6. 风险与缓解
- **上下文丢失**：本文件即为落地备忘，建议提交版本控制并在 PR 描述中引用。
- **功能回归**：在启用新增日志或缓存前，务必扩展自测与远程冒烟脚本（含 `--selftest-inject-empty`、`--retry-metrics`、`--dns-*` 组合）。
- **指标噪声**：调试输出应受 `--debug` 或专用开关控制，避免影响批量管道。

> 若需扩展本备忘，请在同文件追加章节，保持“背景→目标→改进→风险”的结构，方便快速恢复上下文。

## 7. DNS 调试日志设计（[DNS-CAND]/[DNS-FALLBACK]）

### 7.1 触发与输出约束
- **开关**：只要 `g_config.debug` 或 `wc_net` 的 retry metrics 处于启用状态就打印；新增 `wc_net_retry_metrics_enabled()` 供 `lookup.c` 查询，避免重复维护状态。
- **介质**：全部输出写入 `stderr`，单行文本，ASCII，便于与现有 `[RETRY-*]` 同步收集；stdout 继续保留查询正文。
- **速率**：每个 hop 最多打印一次候选序列；fallback 事件按实际触发次数打印，以便对照 `fallback_flags` 与自测日志。

### 7.2 `[DNS-CAND]` 规格
- **触发点**：每次 `wc_dns_build_candidates()` 生成列表后立即遍历日志（在拨号前），记录该 hop 的候选顺序与来源。
- **格式**：`[DNS-CAND] hop=<n> server=<logical_host> rir=<rir|unknown> idx=<i> target=<token> type=<ipv4|ipv6|host> origin=<input|resolver|canonical>`。
   - `type` 由 `wc_dns_is_ip_literal()` 判定；`host` 表示尚未解析的主机名。
   - `origin`：`input`=用户直接传入的 IP，`resolver`=`getaddrinfo` 产物，`canonical`=为保证回退而补入的标准域名。
   - 额外字段：当 `g_config.dns_max_candidates` 发生裁剪时追加 `limit=<value>`，便于对照 CLI。
- **复用字段**：`hop`/`server` 直接复用 `lookup.c` 现有变量；`rir` 来自 `wc_guess_rir()`，无需新缓存。

### 7.3 `[DNS-FALLBACK]` 规格
- **触发点**：所有非主路径的重拨都打印，包括：
   1. 候选全部失败后进入“强制 IPv4”路径；
   2. 进入“已知 IPv4”映射；
   3. 空正文检测触发的再次拨号（含重新挑选候选、强制 IPv4、已知 IP）；
   4. IANA pivot（当前 hop 无 referral 但需要跳回 IANA）。
- **格式**：`[DNS-FALLBACK] hop=<n> cause=<connect-fail|empty-body|manual> action=<forced-ipv4|known-ip|candidate|iana-pivot> domain=<logical_host> target=<dial_target> status=<success|fail> flags=<bitset>`。
   - `cause` 描述触发原因；`action` 描述采用的回退策略；`target` 为实际拨号对象（IP 或 host）。
   - `flags` 复用 `wc_result.meta.fallback_flags` 现有含义，按 `known-ip|empty-retry|forced-ipv4|iana-pivot` 拼接，无新位。
- **补充信息**：当 fallback 失败且 `ni.last_errno` 可用时追加 `errno=<value>`；若来自空正文重试，还需附带 `empty_retry=<n>` 以便同自测脚本核对。

### 7.4 实现注意事项
- `lookup.c` 内新增 `static int wc_lookup_should_trace_dns(void)` 以统一判断调试开关；`wc_dns_candidate_list_t` 仍保持字符串数组，不引入结构体变更。
- 日志函数应尽量复用现有栈变量，避免额外堆分配；对 `target` 使用安全的 `snprintf`/`fprintf`。
- 与 `wc_net` 指标配合：在 `--retry-metrics` 仅开启（即 `--debug` 关闭）时，这些日志提供连接尝试上下文，供远程冒烟脚本把 `[DNS-CAND]` / `[DNS-FALLBACK]` 与 `[RETRY-METRICS]` 对齐。

## 8. DNS 自测用例与观测点

| 场景 | 命令 | 关键观测 |
| --- | --- | --- |
| IPv6-only 纯候选 | `./whois-x86_64 --selftest --selftest-blackhole-arin --selftest-inject-empty --ipv6-only --retry-metrics --debug` | `[DNS-CAND]` 仅有 IPv6 字面量，`dns-ipv6-only-candidates PASS`；黑洞触发后 `fallback counters: forced>0 known>0`，验证 instrumentation 仍然记录强制/已知 IPv4。 |
| Prefer-IPv6 + 回退开启 | 同上但将 `--ipv6-only` 换成 `--prefer-ipv6` | `canonical` 重新出现，`dns-canonical-fallback PASS`；`known-ip fallback found-known-ip` 与 `forced-ipv4 fallback warning` 证明回退策略被实际触发。 |
| Prefer-IPv6 + 回退禁用 | 在上一条基础上追加 `--no-force-ipv4-fallback --no-known-ip-fallback` | `[DNS-FALLBACK]` 输出 `not selected`，结尾 `dns-fallback-disabled PASS` 且计数器为零，说明禁用开关生效。 |

> 以上命令均在仓库根目录执行，配合远程黑洞环境可复现截图中的日志。冒烟脚本需要记录 `[DNS-CAND]` / `[DNS-FALLBACK]` 摘要，把自测结果写入 `build_report.txt`，以免后续迭代遗忘这些路径。

## 9. Phase 3 预备：DNS 缓存统计与观测

> 说明：本节仅为下一阶段的轻量规划，尚未实施；用于在 IDE/会话丢失时快速恢复思路。

### 9.1 目标（Phase 3 的第一小步）

1. 在 `wc_dns` 内部增加缓存命中计数器（正向/负向/未命中），不改变现有候选生成行为。
2. 为 CLI 预留 `--dns-cache-stats`（或复用 `--retry-metrics`）的输出格式，用于打印当前进程内统计摘要。
3. 在 `lookup.c` 的 DNS 调试日志附近，追加一行 `[DNS-CACHE]`，与 `[DNS-CAND]` / `[DNS-FALLBACK]` 一起，形成排障三件套。

### 9.2 粗略设计草案 + 已实现行为说明

- `wc_dns`：
    - 在现有缓存结构上增加三个计数：`hits`、`neg_hits`、`misses`；由 `wc_dns_build_candidates` 在查询缓存前/后更新。
    - 暴露一个轻量查询接口，例如 `wc_dns_get_cache_stats(struct wc_dns_cache_stats *out)`，供 `lookup.c` 和 `--dns-cache-stats` 使用（当前实现已存在该接口，并在 lookup 日志中使用）。
- `lookup.c`：
    - 在已经决定打印 `[DNS-CAND]` 的分支中，调用 `wc_dns_get_cache_stats`，输出：
         - `[DNS-CACHE] hits=<n> neg_hits=<n> misses=<n>`，全部写入 `stderr`（当前实现已采用该格式）。
    - 注意不在正常路径增加额外 `getaddrinfo` 调用，只消费现有统计。
- CLI / 文档：
    - `--dns-cache-stats`：
             - 启用时在程序退出前通过 `atexit` 打印一次全局统计摘要，前缀为 `[DNS-CACHE-SUM]`，形如：
                - `[DNS-CACHE-SUM] hits=10 neg_hits=0 misses=3`
             - 在 `docs/USAGE_EN.md` / `docs/USAGE_CN.md` 中提供示例命令和样例输出，并解释各字段含义：
                  - `hits`：本进程内 DNS **正向缓存命中次数**。当某个域名/主机名的解析结果已存在于缓存中并被成功复用（无需再次调用 `getaddrinfo`）时，计数加 1。
                  - `neg_hits`：本进程内 DNS **负缓存命中次数**。当某个域名之前解析失败（例如 NXDOMAIN）且该“失败结果”被写入负缓存，后续对同一域名的查询直接命中这条负缓存记录时，计数加 1。
                  - `misses`：本进程内 DNS **缓存未命中次数**。当缓存中既没有正向命中、也没有负向命中，客户端只能发起一次真正的 DNS 解析（`getaddrinfo`）时，计数加 1。
             - 直观理解：`hits` 越多说明重复查询有效利用了缓存；`neg_hits` 多通常意味着“同一个不存在/有问题的域名”被重复查询较多次；`misses` 偏大则意味着缓存命中率较低（查询集合高度分散，或进程刚启动、缓存尚未“预热”）。

### 9.3 自测与验证思路占位

- 在 `selftest_dns_*` 系列中新增一个轻量用例：
    - 构造一个会命中缓存的查询序列，例如相同 RIR 的重复查询，观察 `hits`/`misses` 计数是否符合预期（只要保证不影响现有网络自测即可）。
    - 若网络环境不稳定，自测可以只验证计数是否“单调非负且能被重置”，不强行依赖外部 DNS 行为。
- 远程冒烟脚本可在后续版本中择机加入 `--dns-cache-stats`，把 `[DNS-CACHE-SUM]` 摘要收入 `build_report.txt`，以辅助分析缓存策略的收益。

### 9.4 调整 DNS 策略与开关（D）：`--dns-no-fallback`（调试向）

本小节聚焦于**调试/自测场景下的 DNS 策略类开关**，默认不建议普通用户长期开启。目标是：在不破坏默认行为的前提下，允许开发者/维护者在需要时“锁死”某些 resolver 策略，以便复现和定位问题。

#### 9.4.1 语义（最小可用版本）

- 仅影响 **DNS 层面的“附加 fallback”策略**，不改变“正常解析失败 → 返回错误”这一基本流程；
- 禁止以下两类**额外尝试**：
   - 已知 IPv4 fallback：即在首轮解析全部失败后尝试内建的 `whois.<rir>.net` 等已知 IPv4 地址；
   - 强制 IPv4 fallback：在 `--prefer-ipv4` 场景下，首轮 IPv4/IPv6 都失败后，强行追加一次“只用 IPv4 地址”的重试；
- 对以下行为**不做改动**：
   - 初始的 `wc_dns_build_candidates()` 生成的候选列表（含 IPv4/IPv6/host）；
   - 基于候选列表的正常 connect 尝试和基于 `--prefer-ipv4/--prefer-ipv6` 的排序策略；
   - DNS 负缓存策略本身（是否写入负缓存/如何命中负缓存）。

#### 9.4.2 生效条件与 CLI 形态

- 开关名：`--dns-no-fallback`（仅 CLI，暂不提供环境变量别名）；
- **所有模式下均可指定**，但推荐仅在 `--debug`、自测或开发阶段使用；
- 当该开关开启且触发“本应进行 fallback 的分支”时：
   - 不再执行真正的 fallback 逻辑；
   - 仍然输出一条 `[DNS-FALLBACK]` 日志行，`action=no-op`、`status=skipped`，明确说明是由于 `dns-no-fallback` 被启用而跳过：
      - 示例：
         - `[DNS-FALLBACK] hop=1 cause=force-ipv4 action=no-op domain=whois.arin.net target=203.0.113.1 status=skipped flags=dns-no-fallback`
         - `[DNS-FALLBACK] hop=1 cause=known-ip action=no-op domain=whois.ripe.net target=193.0.6.135 status=skipped flags=dns-no-fallback`

#### 9.4.3 与现有选项的组合

- 与 `--prefer-ipv4/--prefer-ipv6`：
   - 仍按照偏好顺序构建和尝试候选（例如 prefer-ipv4 时优先试 IPv4，再试 IPv6），只是当**所有候选都失败且原本会触发“强制 IPv4 fallback”**时，不再进行该强制重试，而是停在失败状态；
- 与 `--ipv4-only/--ipv6-only`：
   - 这些选项本身就会限制候选族别，`--dns-no-fallback` 在这类场景下通常不会额外改变结果，但仍可能阻止“已知 IPv4 fallback”一类附加尝试；
- 与 DNS 缓存/统计：
   - `--dns-no-fallback` 不改变 hits/neg_hits/misses 的计数逻辑，只是减少了一些本应发生的“额外解析/连接尝试”；
   - 在分析 `[DNS-CACHE-SUM]` 时可以结合 `[DNS-FALLBACK] status=skipped flags=dns-no-fallback` 判断当前统计是在“无 fallback”模式下收集的。

#### 9.4.4 实现落点与注意事项

- 配置层：
   - 在 `wc_opts` 配置结构中新增一个 `dns_no_fallback` 布尔字段，由 CLI 解析层在看到 `--dns-no-fallback` 时置位；
- 查找/连接层（`lookup.c`）：
   - 在触发“已知 IPv4 fallback”和“强制 IPv4 fallback”的地方，增加 `if (config->dns_no_fallback)` 分支：
      - 只写一条 `wc_lookup_log_fallback(..., action=no-op, status=skipped, flags|=DNS_FALLBACK_FLAG_DNS_NO_FALLBACK)` 日志；
      - 不再对候选列表进行扩展，也不发起新的 connect；
   - 其他 fallback 类型（例如将 canonical host 重新入队）暂不受该开关控制，保持简单可控；
- 使用建议：
   - Usage 文档中会强调：该开关主要用于“调试 fallback 行为差异”或“收窄问题空间”，普通用户无需关注。

#### 9.4.5 调试命令与日志示例

在真实网络环境下，可以通过两组命令直观对比 `--dns-no-fallback` 的行为差异（示例以 ARIN 为例）：

- 基线（允许 fallback）：

   ```bash
   ./whois-x86_64 \
      -h arin \
      --debug --retry-metrics \
      8.8.8.8
   ```

   当运营商对 ARIN IPv4 有限制或偶发故障时，典型日志片段可能是：

   - `[DNS-FALLBACK] hop=1 cause=connect-fail action=forced-ipv4 ... status=success|fail ...`
   - `[DNS-FALLBACK] hop=1 cause=connect-fail action=known-ip ...`

- 禁用 fallback：

   ```bash
   ./whois-x86_64 \
      -h arin \
      --debug --retry-metrics \
      --dns-no-fallback \
      8.8.8.8
   ```

   在相同环境下，如果触发了原本会进入 fallback 的分支，则日志会变为：

   - `[DNS-FALLBACK] hop=1 cause=connect-fail action=no-op domain=... target=(none) status=skipped flags=dns-no-fallback`

远程冒烟脚本中可在 `SMOKE_ARGS` 中追加 `--dns-no-fallback`，同时配合黑洞/自测环境，集中观察 fallback 在“启用/禁用”这两种模式下的差异。

## 10. Phase 3 设计草案：RIR IPv4/IPv6 健康记忆策略

> 目标：在 **单进程范围内** 为每个 RIR/host 维护一个轻量级的 IPv4/IPv6 健康状态，在不破坏现有行为契约的前提下，减少重复撞墙（尤其是被屏蔽的 ARIN IPv4）。本节仅为设计草案，逐步落地。

### 10.1 数据模型与生命周期

- 观察粒度：`host + family` 级别，例如：
   - `whois.arin.net + AF_INET`（IPv4）
   - `whois.arin.net + AF_INET6`（IPv6）
- 建议结构（伪代码）：

   ```c
   struct wc_dns_health_entry {
         char host[WC_DNS_HOST_MAX];   // canonical host (e.g., whois.arin.net)
         int  family;                  // AF_INET / AF_INET6
         int  consecutive_failures;    // 连续失败次数
         uint64_t last_success_ts_ms;  // 最近一次成功时间戳（毫秒）
         uint64_t last_fail_ts_ms;     // 最近一次失败时间戳（毫秒）
         uint64_t penalty_until_ms;    // 若处于 penalty，则在该时间前视为“不健康”
   };
   ```

- 存储方式：
   - 仅在进程内维护的静态表（例如定长数组 + 简单 LRU 或环形淘汰），**不落盘**；
   - 限制最大条目数（例如 64）和全局 TTL（例如 5 分钟），避免无限增长。
- 生命周期规则：
   - 每次 `connect` 结束后调用 `wc_dns_health_note_result(host, family, success)` 更新；
   - 当 `now_ms >= penalty_until_ms` 时，即便过去有失败记录，也重新视为“可尝试”。

### 10.2 健康状态机与判定规则

初版建议使用一个简单的“软 penalty” 状态机，避免过度复杂：

- 失败路径：
   - 当同一 `host+family` 在短时间内连续失败 `N` 次（例如 N=3，窗口 `W_fail` 秒）时：
      - 计算 `penalty_until_ms = now_ms + P_ms`（例如 P_ms=30000，30 秒）；
      - 期间 `wc_dns_health_is_healthy(host,family)` 返回“penalized”。
- 恢复路径：
   - 若在 penalty 期间仍然尝试该 family 且成功：
      - 清零 `consecutive_failures`，并将 `penalty_until_ms` 置为 0。
   - 若 penalty 过期后重新失败：
      - 按普通失败重新计数，不做指数回退（避免状态机复杂化）。
- 判定函数示例：

   ```c
   enum wc_dns_health_state { HEALTH_OK, HEALTH_PENALIZED };

   enum wc_dns_health_state
   wc_dns_health_is_healthy(const char* host, int family, uint64_t now_ms);
   ```

此状态机只对“近期重复失败”做温和惩罚，不会永久屏蔽某个族类。

### 10.3 与候选生成的集成（软偏好）

在 `wc_dns_build_candidates` 完成候选列表后，在不改变“有哪些候选”的前提下引入“软排序/跳过”逻辑：

- 对每个候选条目（host/IP + family）查询健康状态：
   - 若 `HEALTH_OK`：保持原有顺序不变；
   - 若 `HEALTH_PENALIZED`：
      - 首选方案：将该候选 **推迟到同一 hop 列表的末尾**；
      - 替代方案：在同一 hop 内仍有其他 family 可用时，**暂时跳过**该候选，必要时在“兜底阶段”再考虑。
- 与家族偏好组合：
   - `--prefer-ipv6/--prefer-ipv4` 仍然决定初始排序，只是在有 penalty 的情况下做轻微调整：
      - 例如 prefer-ipv4 但 IPv4 被 penalty，且 IPv6 健康，则可以“优先尝试 IPv6，但保留一次 IPv4 兜底机会”。
- 可观测性：
   - 在 `--debug` 或 `--retry-metrics` 模式下新增 `[DNS-HEALTH]` 日志，例如：

      ```text
      [DNS-HEALTH] host=whois.arin.net family=ipv4 state=penalized consec_fail=3 penalty_ms_left=27845
      ```

   - 在 `[DNS-CAND]` 中追加简短 tag（可选）：`health=ok|penalized|skip`，便于肉眼对照。

### 10.4 与现有 fallback 策略的结合

目标是**减少重复撞墙**，而不是新增策略层：

- 初始拨号：
   - 使用 10.3 中的软偏好排序，尽量先尝试健康的族类/地址；
- 空正文重试：
   - 在为 ARIN 或其他 RIR 选择 fallback host 时，优先选择健康 family 的候选；
- 已知 IPv4 / 强制 IPv4 fallback：
   - 在准备进入这些 fallback 分支时先查询健康状态：
      - 若目标 `host+AF_INET` 处于 penalty 且仍有其他可用候选，则可以直接：
         - 记录一条 `[DNS-FALLBACK] ... action=no-op status=skipped flags=health-unhealthy`；
         - 不再对该 IPv4 发起实际 connect，减少浪费时间。
      - 若没有其他候选（例如纯 IPv4-only 环境）：仍允许尝试一次，以免因为状态机导致“必然失败”。
- 与现有开关的关系：
   - `--dns-no-fallback` / `--no-known-ip-fallback` / `--no-force-ipv4-fallback` / `--no-iana-pivot` 决定**哪些** fallback 类型可用；
   - 健康记忆只在“允许的策略集合”内做排序/跳过，不应绕过这些显式开关。

### 10.5 自测矩阵（Phase 3 版 H）

在现有自测框架基础上补充健康记忆相关的 instrumentation 测试：

- 纯状态机单元自测（不依赖公网）：
   - 构造伪 `host+family`，直接调用 `wc_dns_health_note_result()` / `wc_dns_health_is_healthy()`：
      - 验证连续失败触发 penalty；
      - 验证 penalty 期间成功会清零计数；
      - 验证 penalty 过期后状态恢复为 OK。
   - 所有测试以 `PASS/WARN` 报告，不影响整体退出码。
- 集成黑洞自测：
   - 结合 `--selftest-blackhole-arin` 与 `--selftest-inject-empty`，在 lookup 自测中观察：
      - 多次针对 ARIN IPv4 的失败是否导致 `[DNS-HEALTH]` 进入 penalized 状态；
      - 随后查询是否更偏向 IPv6 候选（结合 `[DNS-CAND] health=...` 标签验证）。
- 仍遵循现有原则：网络相关的自测只作为“信息性/建议性”，不应让 `--selftest` 因网络环境差异频繁失败。

### 10.6 文档与远程脚本配合

- 文档：
   - 在 USAGE_CN/EN 的 DNS 调试小节中追加一段“DNS 健康记忆”说明，解释 `[DNS-HEALTH]` 日志格式和简单解读方法；
   - 在本 RFC Phase 3 章节中保持设计与实现同步更新。
- 远程脚本：
   - 在当前 DNS 抽样的基础上（`[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]`），如果日志中存在 `[DNS-HEALTH]` 行，则额外抽取 1~3 行样例，方便在 CI/远程环境下快速 eyeball 行为是否符合预期。

> 落地顺序建议：
> 1）先实现 10.1~10.2 的健康记忆基础结构，只记录统计 + 打印 `[DNS-HEALTH]`，**不改变候选排序/策略**；
> 2）在确认统计与日志无误后，按 10.3 引入软排序（仅轻量调节顺序，不做硬性屏蔽）；
> 3）最后再考虑 10.4 中与 fallback 的结合，始终保持“可观测优先、行为保守”的原则，必要时提供调试开关以完全禁用健康记忆策略。

**当前实现进度（2025-11-18）**：

- 已完成 10.1~10.3 的基础实现：
   - `dns.c` 中引入 per-host/per-family 健康记忆表与状态机；
   - `net.c` 在每次 connect 尝试后上报健康结果；
   - `lookup.c` 在 DNS 候选构建时输出 `[DNS-HEALTH]` 日志；
   - `wc_dns_build_candidates` 中对 resolver 候选应用“健康优先”的稳定软排序（不丢弃候选）。
- 已通过多架构远程冒烟与 golden 校验，`[DNS-HEALTH]` 输出稳定，行为与现有 golden 基线保持一致。

### 10.7 DNS 调试 quickstart 示例

在启用 DNS 调试与 lookup 自测宏的构建下（例如 `-DWHOIS_LOOKUP_SELFTEST`），可以在远程冒烟日志中观察到 `[LOOKUP_SELFTEST]` 与 `[DNS-HEALTH]` 的组合输出，用于快速 eyeball DNS 候选与健康记忆的行为是否符合预期。

典型片段示例（节选）：

```text
[DEBUG] Analyzing line: Comment:        The Google Team
[DEBUG] Analyzing line: [LOOKUP_SELFTEST] iana-first: PASS (via=whois.iana.org auth=whois.arin.net)
[DNS-HEALTH] host=whois.iana.org family=ipv4 state=ok consec_fail=0 penalty_ms_left=0
[DNS-HEALTH] host=whois.iana.org family=ipv6 state=ok consec_fail=0 penalty_ms_left=0
[DNS-CAND] hop=1 server=whois.iana.org rir=iana idx=0 target=2620:0:2830:200::59 type=ipv6 origin=cache
...
[LOOKUP_SELFTEST] dns-health-soft-ordering: INFO (host=whois.iana.org v4=ok fail=0 pen_ms=0; v6=ok fail=0 pen_ms=0)
[DNS-HEALTH] host=whois.arin.net family=ipv4 state=ok consec_fail=0 penalty_ms_left=0
[DNS-HEALTH] host=whois.arin.net family=ipv6 state=ok consec_fail=0 penalty_ms_left=0
```

说明与注意事项：

- `[LOOKUP_SELFTEST]`：来自 `wc_selftest_lookup` 的可选自测输出，仅在以 `-DWHOIS_LOOKUP_SELFTEST` 编译并带 `--selftest` 运行时出现，用于观测 lookup 路径与健康记忆策略；
- `[DNS-HEALTH]`：来自 Phase 3 健康记忆模块的核心日志，表示当前 host 在 IPv4/IPv6 族别下的健康状态与 penalty 剩余时间；
- 由于当前实现是单进程内多处代码同时向 `stderr` 直接写入，**在部分 libc/qemu 组合下可能出现行级别 interleave/覆盖现象**（例如 `[LOOKUP_SELFTEST]` 前缀插入或截断前一条 `[DEBUG]` 的内容）；
- 这些日志主要面向人眼调试与 CI eyeball，不依赖严格的行/字段对齐；若未来引入多线程或将这些输出用于机器解析，可能需要额外的同步与结构化日志机制，在设计上应预留这一演进空间。

### 10.8 后续思路与工作计划备忘

> 本节作为 Phase 3 初版落地后的备忘录，用于记录下一步可能的演进方向和当前整理出的运维/实现侧 TODO，具体实现将视后续需求与时间再择机推进。

- **阶段性结论（2025-11-18）**：
   - Phase 2 + Phase 3 已完成从设计到实现再到观测、文档的闭环：
      - Phase 2：DNS cache 统计、`[DNS-CACHE-SUM]`、基础 DNS 调试开关；
      - Phase 3：per-host/per-family 健康记忆表、`[DNS-HEALTH]` 日志、候选软排序，以及 lookup 自测与 RFC/OPERATIONS 文档补充；
   - 现有实现对成功路径保持 **golden 行为一致**，对“被屏蔽 IPv4 等长期失败族类”提供了保守的性能优化（减少重复撞墙），适合作为稳定基线长期使用。

- **潜在 Phase 4 方向：RIR 级别 IP 健康记忆 / 短时间内跳过解析**：
   - 在当前 per-host/per-family 健康表的基础上，增加一层“最近成功 IP + 过期时间”的轻量缓存，例如：
      - 为 `whois.arin.net + AF_INET6` 维护最近一次成功的 IP 及一个短 TTL（如 30~120 秒）；
      - 在 TTL 内的新查询优先直接尝试该 IP，必要时才重新走 DNS 解析；
   - 目标：在大批量查询场景下，进一步减少重复 DNS 解析和握手开销，不仅对“被屏蔽 IPv4”有效，也对“正常可达、但 DNS/连接抖动明显”的环境有正面效果；
   - 风险与约束：
      - 需要谨慎处理 IP 级别的健康状态（per-host/per-family/per-IP），避免“记住坏 IP”带来长尾失败；
      - 必须在 RFC 级别重新定义 golden 行为与回退策略（例如提供开关以完全禁用该策略）。

- **运维侧小事（后续可分批完成）**：
   - 在 `OPERATIONS_CN.md` / `USAGE_CN.md` 中增加“DNS 调试 quickstart”小节，集中给出：
      - 推荐命令组合：`--debug --retry-metrics --dns-cache-stats [--selftest]`；
      - 精简版日志示例（`[DNS-HEALTH]` + `[DNS-CACHE-SUM]` + 1~2 条 `[LOOKUP_SELFTEST]`）；
      - 对行级 interleave/覆盖现象的简单说明，以及 grep 建议。
   - 在远程脚本 `tools/remote/remote_build_and_test.sh` 的文档附近补一句：当 `CFLAGS_EXTRA` 含 `-DWHOIS_LOOKUP_SELFTEST` 且 `SMOKE_ARGS` 含 `--selftest` 时，会额外输出 `[LOOKUP_SELFTEST]` 行，适合用于 DNS 行为 eyeball 调试，不建议作为日常发布配置。

- **代码层下一步（与 DNS 无关的大拆分主线）**：
   - 当前 DNS 相关重构告一段落，后续开发计划将回到 `src/whois_client.c` 的拆分与核心逻辑下沉：
      - 继续将 pipeline/输出/条件引擎等逻辑拆解至 `src/core/` 与 `src/cond/`，使 `whois_client.c` 逐步收敛为一个更薄的 CLI 壳层；
      - 在拆分过程中保持与现有 DNS 行为的解耦，避免引入与 Phase 2/3 逻辑交叉的隐性耦合；
   - 具体拆分计划与里程碑将记录在后续的专门 RFC/备忘录中（不再扩展本 DNS Phase 2 文档）。

#### 10.9 次日工作顺序备忘（计划用于 v3.2.9 基线前置）

> 目的：在 IDE/会话上下文丢失的情况下，仍能快速恢复“DNS 线收尾 + v3.2.9 发布 + 回归大拆分主线”的具体操作顺序。

1. **运维侧 DNS 文档与脚本补完（收尾 Phase 2/3 运维部分）**
    - `docs/OPERATIONS_CN.md`：
       - 新增“DNS 调试 quickstart”小节，内容参考本 RFC 10.7/10.8：
          - 推荐命令：
             - 单次调试：`whois-x86_64 --debug --retry-metrics --dns-cache-stats 8.8.8.8`
             - 带自测：`whois-x86_64 --debug --retry-metrics --dns-cache-stats --selftest 8.8.8.8`
          - 简短说明 `--dns-cache-stats` / `[DNS-CACHE-SUM]` / `[DNS-HEALTH]` 的含义与典型输出；
          - 提醒在调试版二进制（包含 `-DWHOIS_LOOKUP_SELFTEST`）时会出现 `[LOOKUP_SELFTEST]` 行，且在某些 libc/qemu 组合下可能与 `[DEBUG]` 输出发生行级 interleave/覆盖，适合 grep/eyeball，不适合做机器严格解析。
    - `docs/USAGE_CN.md`（可选，时间足够时）：
       - 在已有 DNS 调试段落里补一小句，指向新的“DNS 调试 quickstart”小节或给出单行示例命令。
    - `tools/remote/remote_build_and_test.sh` 相关文档（例如 README/注释）：
       - 补充说明：当 `CFLAGS_EXTRA` 包含 `-DWHOIS_LOOKUP_SELFTEST` 且 `SMOKE_ARGS` 含 `--selftest` 时，smoke 日志中会出现 `[LOOKUP_SELFTEST]` 行，仅用于 DNS 行为调试，不建议纳入正式 release 配置。

2. **准备并发布 v3.2.9（以当前 DNS 状态为新的 golden 基线）**
    - 文档与版本说明：
       - 在 `RELEASE_NOTES.md` 中新增 v3.2.9 条目，概述：
          - Phase 2：DNS cache 统计、`--dns-cache-stats`、`[DNS-CACHE]` / `[DNS-CACHE-SUM]` 日志；
          - Phase 3：DNS 健康记忆（`[DNS-HEALTH]`）、候选软排序、`--dns-no-fallback` 调试开关与相关自测；
          - 对行为的保证：在默认配置下保持与既有 golden 输出兼容，在部分 RIR IPv4 受限场景下减少重复失败尝试。
       - 如需对外发布说明，可在 `docs/release_bodies/v3.2.9.md` 新建/补充对应版本的发布正文，沿用现有版本的风格。
    - 构建与冒烟（推荐使用 VS Code 任务或直接调用脚本）：
       - 使用“release 习惯用配置”进行一次完整远程构建与多架构冒烟，例如：
          - `CFLAGS_EXTRA`：`-O3 -s`（不再带 `-DWHOIS_LOOKUP_SELFTEST`）；
          - `SMOKE_ARGS`：根据需要选择 `NONE` 或仅 `--dns-cache-stats`，确保 golden 校验通过；
       - 检查 `build_report` 与 `smoke_test.log`：
          - golden check: PASS；
          - 至少一条 `[DNS-CACHE-SUM]` 与若干 `[DNS-HEALTH]` 行存在、格式正确。
    - 打 tag / 发布：
       - 确认工作区干净后，通过已有 VS Code 任务：
          - `Git: Quick Push` 提交本地变更；
          - `Git: Tag Release` 或 `One-Click Release` 生成 `v3.2.9` tag 与 GitHub/Gitee 发布记录，引用上述 release body。

3. **v3.2.9 之后的主线：回归 `whois_client.c` 大拆分**
    - 以 v3.2.9 为新基线，后续工作重点不再扩展 DNS Phase 2/3，而是：
       - 盘点当前 `src/whois_client.c` 中仍然耦合的业务逻辑（pipeline、输出、条件引擎等）；
       - 拟定拆分顺序，将这些逻辑逐步迁移至 `src/core/` / `src/cond/` 模块；
       - 在拆分过程中如发现新的优化点或功能想法，优先记录在单独的拆分/RFC 备忘录中，按轻重缓急择机实现，避免在一个迭代中塞入过多策略变化。

> 注：以上顺序仅作为次日/近期工作的执行建议；若临时有更高优先级事项（例如紧急 bugfix），可按需调整顺序，但建议仍以 v3.2.9 作为“DNS 线收尾 + 拆分前基线”的里程碑版本。
