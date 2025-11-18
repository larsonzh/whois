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
4. **自测矩阵**（⏳ 进行中）：新增 `selftest_dns_candidate_limit`、`selftest_dns_negative_flag`，覆盖候选上限与负缓存注入；仍需扩展 IPv6-only / fallback 禁用组合。
5. **文档**（TODO）：`USAGE`/`RELEASE_NOTES` 需补充 DNS 调试示例与缓存说明。

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

### 9.2 粗略设计草案

- `wc_dns`：
   - 在现有缓存结构上增加三个计数：`hits`、`neg_hits`、`misses`；由 `wc_dns_build_candidates` 在查询缓存前/后更新。
   - 暴露一个轻量查询接口，例如 `wc_dns_get_cache_stats(struct wc_dns_cache_stats *out)`，供 `lookup.c` 和未来的 `--dns-cache-stats` 使用。
- `lookup.c`：
   - 在已经决定打印 `[DNS-CAND]` 的分支中，调用 `wc_dns_get_cache_stats`，输出：
      - `[DNS-CACHE] hit=<n> neg=<n> miss=<n>`，全部写入 `stderr`。
   - 注意不在正常路径增加额外 `getaddrinfo` 调用，只消费现有统计。
- CLI / 文档：
   - 若新增 `--dns-cache-stats`：
      - 启用时在程序退出前打印一次全局统计摘要；可复用 `[DNS-CACHE]` 前缀或使用更高层的 `[DNS-STATS]`。
      - 在 `docs/USAGE_EN.md` / `docs/USAGE_CN.md` 新增简短示例命令和样例输出，标记为 Phase 3 试验特性。

### 9.3 自测与验证思路占位

- 在 `selftest_dns_*` 系列中新增一个轻量用例：
   - 构造一个会命中缓存的查询序列，例如相同 RIR 的重复查询，观察 `hits`/`misses` 计数是否符合预期（只要保证不影响现有网络自测即可）。
   - 若网络环境不稳定，自测可以只验证计数是否“单调非负且能被重置”，不强行依赖外部 DNS 行为。
- 远程冒烟脚本可在后续版本中择机加入 `--dns-cache-stats`，把 `[DNS-CACHE]` 摘要收入 `build_report.txt`，以辅助分析缓存策略的收益。
