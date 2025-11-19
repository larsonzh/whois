# DNS Phase 4 设计草案：RIR 级 IP 健康记忆（IP-level health memory）

> 目的：在 v3.2.9 之后，将更激进的“RIR 级 IP 健康记忆 / 短时间内跳过解析”单独挂在 Phase 4 下，避免干扰当前已落地且相对保守的 Phase 2/3 黄金基线。**本 RFC 为设计草案，当前实现状态为：尚未启动 / NOT STARTED。**

## 1. 背景与现状

- v3.2.9 已完成 DNS Phase 2/3：
  - `wc_dns` 负责候选生成、DNS 缓存（含正/负缓存计数）、IPv4/IPv6 家族调度；
  - `lookup.c` 通过 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` / `[DNS-CACHE-SUM]` / `[DNS-HEALTH]` / `[LOOKUP_SELFTEST]` 替 DNS 行为提供完整的可观测性；
  - 引入 per-host/per-family 健康记忆（例如 `whois.arin.net + AF_INET` / `AF_INET6`），并在候选排序时做“健康优先”的**软排序**，不丢弃候选，只改变尝试顺序。
- 现有健康记忆的“粒度”是 host+family：
  - 仅统计“某个 RIR host 在 IPv4/IPv6 家族上的近期成功/失败情况”，用于决定候选排序与 `[DNS-HEALTH]` 日志；
  - **不会记住具体某个 IP 地址**，也不会基于单个 IP 决定是否跳过 DNS 解析。
- 在 `docs/RFC-dns-phase2.md` 第 10.6/10.8/10.9 节中，曾提到一个潜在方向：
  - “RIR 级别 IP 健康记忆 / 短时间内跳过解析”：希望在单进程范围内、为每个 RIR host 记住“最近成功的 IP”，在短时间窗口内优先使用这个 IP，从而减少重复 DNS 解析与握手。
  - 该方向在 Phase 2/3 中仅停留在文字草案，并未实际实现。

> 总结：v3.2.9 把 **host+family 级健康记忆 + DNS 缓存统计 + 观测标签** 固化为黄金基线，而“IP-level health memory” 被刻意留在后续阶段，以避免在同一版本中引入过多策略变化。

## 2. Phase 4 的目标与非目标

### 2.1 目标

1. **减少重复 DNS 解析与握手开销**：
   - 在高频、大批量查询场景（例如持续针对同一 RIR 的 addr space 聚合查询）中，优先复用“最近成功的 IP”，避免每次都重新 DNS 解析 + 从头试遍所有候选。

2. **维持与现有 Phase 2/3 行为的大体一致性**：
   - 对成功路径，尽量做到“只优化性能，不改变终态”；
   - 对失败路径，做到“最多少尝试几次明显坏 IP，不引入新的不可解释失败”。

3. **保持完整可观测性**：
   - 所有 IP 级决策必须通过新的/扩展的日志标签表达清楚（例如在 `[DNS-CAND]` / `[DNS-HEALTH]` / 新的 `[DNS-IP-HEALTH]` 中）；
   - 便于与现有的 `[RETRY-METRICS]`、`[DNS-CAND]`、`[DNS-FALLBACK]` 组合分析。

### 2.2 非目标

1. **不追求“全局最优路由”**：
   - 不试图在客户端侧做复杂的负载均衡或 multi-path 选择，只做“本进程内的轻量记忆 + 短期偏好”。

2. **不替代 RIR 的 DNS 策略**：
   - 不绕过上游在 DNS 层做的健康切换或流量分层策略，避免与服务端策略打架。

3. **不引入不可控的行为分叉**：
   - 不在默认路径下让“同一命令在同一环境中但在不同时间运行”产生过于难以解释的差异行为；
   - 实验性逻辑应有清晰开关控制，并可以一键关闭。

## 3. 粗略设计草案

### 3.1 数据模型（IP-level health memory）

在现有 `host + family` 级健康表之上，再增加一层“最近成功 IP 记忆”的轻量结构。例如：

```c
struct wc_dns_ip_health_entry {
    char host[WC_DNS_HOST_MAX];   // canonical host, e.g. "whois.arin.net"
    int  family;                  // AF_INET / AF_INET6
    struct sockaddr_storage ip;   // last known-good IP
    uint64_t last_success_ms;     // last successful connect timestamp
    uint64_t last_fail_ms;        // last failed connect timestamp for this IP
    uint64_t ttl_ms;              // how long we consider this IP as a shortcut candidate
};
```

- 存储方式：
  - 固定大小的数组或小型 LRU，限制条目数（例如 64）与过期时间（数十秒到数分钟）；
  - 仅为进程内结构，不落盘、不跨进程。

### 3.2 快路径使用原则（候选构建前/中）

1. 在构建候选列表前，查询 `host + family` 是否存在未过期的“最近成功 IP”：
   - 若存在：
     - 将该 IP 作为**第一候选**加入候选列表或作为“预插入目标”；
     - 仍可选择是否调用 `getaddrinfo` 补充其余候选：
       - 保守方案：**仍调用 DNS**，但优先尝试记忆 IP（保证行为接近当前版本，只是排序不同）；
       - 激进方案：在 IP 记忆未过期且无明显失败信号时直接跳过 DNS（风险更高，下文单独评估）。
   - 若不存在：
     - 回退到现有 Phase 2/3 行为（DNS cache + health + soft ordering）。

2. 在 connect 成功后更新记忆：
   - 将该 `host + family + IP` 写入 IP 健康表，记录 `last_success_ms` 与新的 `ttl_ms`；

3. 在 connect 失败后更新记忆：
   - 如果失败 IP 恰好是“记忆 IP”，可以：
     - 降低其 TTL，或立即使之过期；
     - 增加其 `last_fail_ms` 与失败计数，与 host+family 健康表联动。

### 3.3 与现有 DNS cache / host+family 健康记忆的关系

- DNS cache：记录“域名 → IP 列表 + TTL”，控制是否需要重新 `getaddrinfo`；
- host+family 健康记忆：记录“此 host 在某个族别上是否近期频繁失败”，控制候选排序与 `[DNS-HEALTH]`；
- IP-level health memory：记录“此 host+family 的**某个 IP**在最近是否成功”，作为短期的“首选候选”。

三者之间需要一个清晰的优先级关系，例如：

1. **DNS TTL 优先于 IP TTL**：
   - 如果 DNS TTL 已经过期，需要重新 `getaddrinfo`，同时更新 IP 记忆；
   - 避免在 DNS 已切换 IP 的情况下继续使用过期 IP。

2. **host+family 不健康时，IP 记忆只做参考**：
   - 如果 host+family 已经被判定为 `penalized`，即使有“最近成功 IP”，也应谨慎对待：
     - 可以作为候选之一，但不强制排在首位；
     - 或仅在“兜底阶段”尝试一次。

3. **日志要求**：
   - 引入新标签或扩展现有标签，说明当前候选是否来自 IP 记忆：

```text
[DNS-CAND] hop=1 server=whois.arin.net rir=arin idx=0 target=2001:db8::43 type=ipv6 origin=ip-memory
[DNS-IP-HEALTH] host=whois.arin.net family=ipv6 ip=2001:db8::43 state=ok last_success_ms=... ttl_ms_left=...
```

## 4. 复杂度与风险评估

> 本节归纳的是当前分析结论，旨在解释“为什么本设计暂不落地在 v3.2.9，而是单独挂在 Phase 4 中等待后续时机再评估”。

### 4.1 主要复杂度来源

1. **状态维度扩展**：
   - 从 host+family 扩展到 host+family+IP，状态空间翻倍甚至翻数倍；
   - 需要处理多 IP 记录（多 A/AAAA）、IP 切换、老 IP 作废等情况。

2. **策略交互**：
   - 需要与 DNS cache、host+family 健康记忆、fallback 策略（known-ip / forced-ipv4 / IANA pivot）、`--dns-no-fallback` 等现有机制协同：
     - 例如：DNS TTL 已过期但 IP TTL 未过期时，到底是谁说了算？
     - fallback 的目标 IP 是否也写入 IP 健康表？如果写入，坏 IP 会不会被长时间记住？

3. **行为可解释性**：
   - 现有 Phase 2/3 在 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-HEALTH]` 基础上已经可以较好解释“为什么拨号顺序是这样”；
   - 加上 IP-level health 后，需要更多日志才能解释“为什么这次直接连了某个 IP 而不是先查 DNS 或先试另一个 IP”，否则 golden 行为会变得难以比对与排障。

### 4.2 主要风险点

1. **记住坏 IP 的风险**：
   - 若某 IP 状态“时好时坏”，很容易在“刚记住就开始抖”的时刻触发连续失败；
   - 如果 IP 记忆优先于 DNS TTL，可能长期绕过 RIR 在 DNS 层做的健康切换，从而放大尾部失败概率。

2. **与上游策略的耦合**：
   - RIR 可能对不同 IP 做负载均衡或灰度，客户端在 IP 层做 aggressive 记忆容易和其策略冲突；
   - 这在公网环境中尤其敏感——“稍慢一点但稳定”往往优于“偶尔快很多但容易踩坑”。

3. **golden 行为的稳定性下降**：
   - 引入 IP 级记忆后，同一命令在不同时间运行可能因为“历史状态不同”而产生不同的候选顺序和时延；
   - golden 样例需要额外描述“前置历史”，否则难以复现。

4. **回滚成本上升**：
   - 一旦在默认路径中启用 IP 记忆并随版本发布，后续若发现问题，需要对行为回滚时，会面临大量“期望 vs 实际”的对比工作；
   - 对下游用户（特别是脚本化使用者）来说，行为轻微变化也可能引入新边缘 case。

### 4.3 当前结论

- 在已有 Phase 2/3 能力（DNS cache 统计 + host+family 健康记忆 + soft ordering + 完整日志）的前提下，**IP-level health memory 带来的边际收益相对有限，但实现和验证成本明显更高**。
- 出于稳定性和维护成本考虑，本 RFC 选择：
  - 将 IP 级健康记忆明确挂在 **Phase 4** 下；
  - 当前实现状态标记为 **NOT STARTED**；
  - 在未来确有性能/可用性需求驱动时，再专门立项实现，并配套完整的自测与文档。

## 5. 若未来推进，建议的分阶段路径

> 本节仅为“如果以后真的要做”的推进建议，现在不作为必须执行的计划。

### Phase 4.A：观测优先（只记不动）

- 实现：
  - 增加 IP 级统计与日志输出：
    - 在 connect 成功/失败后更新 IP 健康表；
    - 打印 `[DNS-IP-HEALTH]` 或扩展现有 `[DNS-HEALTH]`，但**不改变候选排序与解析行为**。
- 目的：
  - 在真实流量/远程冒烟中收集“是否存在明显可用的 IP-level 复用机会”；
  - 验证状态机是否稳定、不会导致内存/表大小问题。

### Phase 4.B：受限范围内的 IP 快路径（实验性开关）

- 新增显式开关（例如 `--dns-ip-health-experimental`），默认关闭：
  - 只在该开关开启时启用 IP 快路径；
  - 默认行为继续使用 Phase 2/3 的逻辑。
- 策略约束：
  - 仅对“DNS TTL 仍有效 + host+family 健康状态为 OK”的情况下，优先尝试最近成功 IP；
  - 失败后必须立即更新 IP 状态并按常规路径 fall back 到其余候选与 DNS cache 行为；
  - 全程输出清晰的日志，例如：

```text
[DNS-IP-HEALTH] shortcut=1 host=whois.arin.net family=ipv6 ip=2001:db8::43 state=ok ttl_ms_left=25000
[DNS-CAND] hop=1 server=whois.arin.net rir=arin idx=0 target=2001:db8::43 type=ipv6 origin=ip-memory
```

- 自测：
  - 单元测试验证状态机；
  - 黑洞/不稳定网络模拟测试验证“坏 IP 不会被长时间反复选择”。

### Phase 4.C：评估是否且如何并入默认路径

- 仅当 4.A/4.B 的验证结果足够正向、且运维/回归成本可控时，才考虑：
  - 将 IP-level 快路径以更保守的形式并入默认行为；
  - 或仅长期以“高级/调试开关”存在，不默认开启。

## 6. 状态与后续

- **当前状态（截至 2025-11-20）：**
  - 本 Phase 4 RFC 仅作为 DNS IP-level 健康记忆的设计备忘与风险评估；
  - **尚未编写任何实现代码，也未在 CLI/配置中暴露相关开关**；
  - 项目当前的工作重心回到 `whois_client.c` 拆分主线，DNS Phase 2/3 以 v3.2.9 为稳定黄金基线维持现状。

- **后续动作（如有）应包括：**
  - 单独的设计评审或 issue，把此 RFC 与具体性能/可靠性需求挂钩；
  - 若决定推进，按 5.1→5.2→5.3 的顺序逐步实现，每一步都保持可回滚、可观测、可通过自测与远程冒烟验证。

> TL;DR：IP-level health memory 是一个“有潜力但高复杂度/高耦合度”的优化方向，目前仅保留在 Phase 4 设计草案中，未实际落地。现阶段推荐继续围绕 v3.2.9 的 DNS 行为与既有自测矩阵进行演进，将主要精力回归到 `whois_client.c` 拆分与核心逻辑整理上。
