# whois Release Notes / 发布说明

发布流程（详版）：`docs/RELEASE_FLOW_CN.md` | English: `docs/RELEASE_FLOW_EN.md`
Detailed release flow: `docs/RELEASE_FLOW_EN.md` | Chinese: `docs/RELEASE_FLOW_CN.md`

## Unreleased

中文摘要 / Chinese summary
- 破坏性变更：移除 `--cidr-home-v4`/`--cidr-fast-v4`，IPv4 CIDR 查询回归标准重定向流程（不再强制 two-phase 与 no-redirect 二跳）。
- 新增开关：`--no-cidr-erx-recheck` 关闭 CIDR 的 ERX/IANA 基准复查，用于对比性能。
- 输出控制：默认仅保留权威正文；`--show-non-auth-body` 保留权威之前的非权威正文，`--show-post-marker-body` 保留权威之后的非权威正文；两者同时开启保留全部正文。
- 限流/拒绝正文：默认保留原文；新增 `--hide-failure-body` 可显式过滤限流/拒绝类正文行，便于批量比对降噪。
- 调试增强：`--show-post-marker-body` 可用于定位 ERX/IANA 标记后的正文路径。
- 输出与默认策略回归：`-P/--plain` 现在抑制重定向提示行（Additional/Redirected），仅保留正文；双栈默认恢复 IPv6 优先（首跳 `interleave-v6-first`、后续 `seq-v6-then-v4`，`ip_pref_mode` 固定为 `FORCE_V6_FIRST`）。
- 构建优化档补齐：新增 `OPT_PROFILE=small/lto`（由 Makefile 统一决定优化标志），远程构建/批量黄金/自检黄金脚本与 VS Code 任务均支持 `-O <profile>` 传入；空 `CFLAGS_EXTRA` 在套件中视为可选，不再强制占位。
- 构建档位扩展：`OPT_PROFILE` 新增 `lto-auto/lto-serial`，用于控制 LTO 并行度；远程构建脚本与 One-Click Release/批量/自检任务已同步。
- 构建日志增强：远程构建输出统一记录耗时（Elapsed）。
- 体积诊断：部分目标此前未 strip/带 debug_info 造成体积膨胀；统一 strip 后恢复正常。最新基线（lto-auto + UPX aarch64/x86_64）详见下表。
- 告警修复：`pipeline` 输出在过滤串为空时避免 `%s` 传 NULL 的编译告警。
- 构建告警修复：`lookup_exec_loop.c` 统一回 UTF-8 编码，避免 NULL 字节警告；`lookup_exec_connect.c`/`lookup_exec_empty.c` 的 `netdb.h` 限定为非 Windows 引入，补齐 `sys/socket.h`；`lookup_exec_connect.c` 补充 `<stdio.h>` 以消除 `snprintf` 隐式声明告警。
- 测试：远程编译冒烟同步 + 黄金校验（lto-auto 默认）PASS，日志 `out/artifacts/20260210-113135`。
- 测试：远程编译冒烟同步 + 黄金校验（lto-auto 默认）PASS，日志 `out/artifacts/20260210-120349`。
- 测试：远程编译冒烟同步 + 黄金校验（lto-auto 默认）PASS，日志 `out/artifacts/20260210-123718`。
- 测试：远程编译冒烟同步 + 黄金校验（Strict Version + lto-auto 默认）PASS，日志 `out/artifacts/20260210-133508`。
- 测试：远程编译冒烟同步 + 黄金校验（Strict Version + lto-auto + debug/metrics + dns-family-mode=interleave-v4-first）PASS，日志 `out/artifacts/20260210-134308`。
- 测试：远程编译冒烟同步 + 黄金校验（Strict Version + lto-auto 默认）PASS，日志 `out/artifacts/20260210-163305`。
- 测试：远程编译冒烟同步 + 黄金校验（Strict Version + lto-auto + debug/metrics + dns-family-mode=interleave-v4-first）PASS，日志 `out/artifacts/20260210-164007`。
- 测试：批量策略黄金（lto-auto）raw/health-first/plan-a/plan-b PASS，日志 `out/artifacts/batch_{raw,health,plan,planb}/20260210-13*`。
- 测试：自检黄金（lto-auto + `--selftest-force-suspicious 8.8.8.8`）raw/health-first/plan-a/plan-b PASS，日志 `out/artifacts/batch_{raw,health,plan,planb}/20260210-14*`。
- 测试：批量策略黄金（lto-auto）raw/health-first/plan-a/plan-b PASS，日志 `out/artifacts/batch_raw/20260210-165020`、`batch_health/20260210-165721`、`batch_plan/20260210-170754`、`batch_planb/20260210-171826`。
- 测试：自检黄金（lto-auto + `--selftest-force-suspicious 8.8.8.8`）raw/health-first/plan-a/plan-b PASS，日志 `out/artifacts/batch_raw/20260210-172643`、`batch_health/20260210-173432`、`batch_plan/20260210-174621`、`batch_planb/20260210-175714`。
- 测试：重定向矩阵 9x6 authority mismatches=0、errors=0，日志 `out/artifacts/redirect_matrix_9x6/20260210-175917`。
- 重定向修复：APNIC CIDR 查询不再被误导到 IANA/ARIN；允许在 CIDR referral 场景对 APNIC 进行一次回跳以完成正确权威判定（stdout 契约不变）。
- 重定向规则补齐：APNIC IANA-NETBLOCK 出现 “not allocated to APNIC / not fully allocated to APNIC” 时强制触发轮询，以校验最终权威（stdout/stderr 契约不变）。
- 重定向规则更新：首跳有 referral 直跟；首跳无 referral 且需跳转时强制 ARIN；第二跳起仅跟随未访问的 referral，缺失/重复时按 APNIC→ARIN→RIPE→AFRINIC→LACNIC 顺序挑选未访问 RIR；第二跳后不再插入 IANA；新增 `refer:` 行解析。
- 按 RIR 覆盖族偏好：新增 `--rir-ip-pref arin=v4,ripe=v6,...`，仅影响指定 RIR，优先级低于 `--ipv4-only/--ipv6-only`、高于全局 `--prefer-*`。
- ReferralServer 扩展：支持 `rwhois://host:port` 解析并按端口重定向。
- 启动优化：`--version/--help/--about/--examples/--servers` 走 meta-only 快路径，跳过 runtime init（无查询输出变化）。
- 退出清理补齐：进程退出显式释放 DNS 正/负缓存与连接缓存，避免长时间运行时被工具误判为泄漏；stdout/stderr 契约不变。
- 空响应回退收敛：ARIN 空响应重试预算降至 2，其它 RIR 保持 1；空响应回退之间加入轻量退让，降低高并发连接风暴风险（stdout/stderr 契约不变）。
- 权威尾行收敛：若已拿到正文但后续 referral 跳转失败，或限流/拒绝导致未收敛，尾行权威改为 `error`，用于区分“失败未收敛”与“真未知”；仅当尾行为 `error @ error` 时输出失败错误行。
- 失败错误行增强：统一错误行追加 `host/ip/time` 字段，便于定位远端拒绝/超时（仅在 `error @ error` 时输出）。
- 重定向健壮性：RIR 仅返回 banner 注释（无有效正文）时按空响应处理，先重试；若仍为空则触发重定向（非 ARIN 首跳直跳 ARIN，ARIN 首跳进入 RIR 轮询），避免过早收敛。
- 空响应告警：空响应重试改为 stderr 标签 `[EMPTY-RESP] action=...`，stdout 不再混入告警文本。
- APNIC ERX 轮询收敛：补齐 RIPE/AFRINIC/LACNIC 重定向提示行；权威回落 APNIC 并校准 IP 映射；清理冗余 hop 正文并消除提示行间空行。
English summary
- Breaking change: remove `--cidr-home-v4`/`--cidr-fast-v4`; IPv4 CIDR lookups now follow the standard redirect flow (no forced two-phase/no-redirect hop).
- New flag: `--no-cidr-erx-recheck` disables the ERX/IANA baseline recheck for CIDR to compare performance.
- Output control: keep only the authoritative body by default; `--show-non-auth-body` keeps pre-authoritative non-auth bodies, while `--show-post-marker-body` keeps post-authoritative non-auth bodies. Use both to keep all bodies.
- Failure bodies: keep rate-limit/denied text by default; add `--hide-failure-body` to filter those lines for batch diff noise reduction.
- Debug: `--show-post-marker-body` helps trace ERX/IANA marker paths.
- Output/defaults rollback: `-P/--plain` now suppresses referral hint lines (Additional/Redirected) and keeps only the body; dual‑stack defaults return to IPv6‑first (`interleave-v6-first` on hop 0, `seq-v6-then-v4` afterwards, `ip_pref_mode` pinned to `FORCE_V6_FIRST`).
- Build profile coverage: add `OPT_PROFILE=small/lto` (Makefile-owned optimization presets); remote build, batch golden, and selftest golden scripts/VS Code tasks accept `-O <profile>`. Empty `CFLAGS_EXTRA` is now optional in suites (no placeholder required).
- Build profile expansion: add `lto-auto/lto-serial` to control LTO parallelism; remote build scripts and One-Click Release/batch/selftest tasks are aligned.
- Build logs: remote build now prints an elapsed time summary.
- Size diagnostic: some targets were previously unstripped (debug_info), inflating size; unified strip brings sizes back to normal. Latest baseline (lto-auto + UPX on aarch64/x86_64) is listed below.

Build size baseline (lto-auto, UPX on aarch64/x86_64, stripped)

| Target | Size |
| --- | --- |
| whois-aarch64 | 149 KB |
| whois-armv7 | 340 KB |
| whois-mips64el | 506 KB |
| whois-mipsel | 483 KB |
| whois-loongarch64 | 262 KB |
| whois-x86_64 | 151 KB |
| whois-x86 | 404 KB |
| whois-win64.exe | 393 KB |
| whois-win32.exe | 422 KB |
- Warning fix: guard `pipeline` output to avoid `%s` with NULL filtered strings at compile time.
- Build warning fixes: normalize `lookup_exec_loop.c` to UTF-8 to remove NULL-byte warnings; guard `netdb.h` to non-Windows in `lookup_exec_connect.c`/`lookup_exec_empty.c` and add `sys/socket.h`; add `<stdio.h>` in `lookup_exec_connect.c` to fix implicit `snprintf` declarations.
- Test: remote build smoke sync + golden (lto-auto default) PASS, log `out/artifacts/20260210-113135`.
- Test: remote build smoke sync + golden (lto-auto default) PASS, log `out/artifacts/20260210-120349`.
- Test: remote build smoke sync + golden (lto-auto default) PASS, log `out/artifacts/20260210-123718`.
- Test: remote build smoke sync + golden (Strict Version + lto-auto default) PASS, log `out/artifacts/20260210-133508`.
- Test: remote build smoke sync + golden (Strict Version + lto-auto + debug/metrics + dns-family-mode=interleave-v4-first) PASS, log `out/artifacts/20260210-134308`.
- Test: batch strategy goldens (lto-auto) raw/health-first/plan-a/plan-b PASS, logs `out/artifacts/batch_{raw,health,plan,planb}/20260210-13*`.
- Test: selftest goldens (lto-auto + `--selftest-force-suspicious 8.8.8.8`) raw/health-first/plan-a/plan-b PASS, logs `out/artifacts/batch_{raw,health,plan,planb}/20260210-14*`.
- Test: redirect matrix 9x6 authority mismatches present, errors=0, log `out/artifacts/redirect_matrix_9x6/20260210-151915`.
- Redirect fix: APNIC CIDR queries no longer get misrouted to IANA/ARIN; allow one APNIC revisit for CIDR referrals to reach the correct authority (stdout contract unchanged).
- Redirect rule tightening: APNIC IANA-NETBLOCK banners with “not allocated to APNIC / not fully allocated to APNIC” now force RIR traversal to validate final authority (stdout/stderr contracts unchanged).
- Redirect traversal update: follow hop‑1 referrals when present; if hop 1 lacks a referral but needs redirect, force ARIN. From hop 2 onward, follow referrals only when unvisited; otherwise select the next unvisited RIR in APNIC→ARIN→RIPE→AFRINIC→LACNIC order. No IANA insertion after hop 2; add `refer:` line parsing.
- Per-RIR family overrides: add `--rir-ip-pref arin=v4,ripe=v6,...` to override IPv4/IPv6 preference per RIR; lower priority than `--ipv4-only/--ipv6-only`, higher than global `--prefer-*`.
- ReferralServer expansion: accept `rwhois://host:port` and redirect using the parsed port.
- Startup optimization: meta-only flags (`--version/--help/--about/--examples/--servers`) skip runtime init (no query output changes).
- Exit cleanup: explicitly free DNS positive/negative caches and connection caches on process exit, avoiding leak warnings in long-running or tool-instrumented runs; stdout/stderr contracts unchanged.
- Empty-body fallback tightening: ARIN retry budget reduced to 2 (others remain 1), with a small backoff between empty-response retries to reduce connection bursts under high concurrency (stdout/stderr contracts unchanged).
- Authoritative tail tightening: when a hop returns body data but a later referral fails, or rate-limit/denied prevents convergence, the tail now prints `error` to distinguish failure from a true unknown; failure lines are emitted only when the tail is `error @ error`.
- Failure line enhancement: append `host/ip/time` to the unified error line for faster triage (only when the tail is `error @ error`).
- Redirect robustness: comment-only (banner-only) RIR responses are treated as empty responses; retry first, then redirect (non-ARIN first hops pivot to ARIN, ARIN first hops enter the RIR cycle) to avoid premature authority.
- Empty-response warnings: retry notices now emit as stderr tags `[EMPTY-RESP] action=...`, keeping stdout free of diagnostics.
- APNIC ERX traversal tightening: restore RIPE/AFRINIC/LACNIC redirect hints, collapse authority to APNIC with correct IP mapping, and trim redundant hop bodies while removing blank lines between hop headers.

## 3.2.10

中文摘要 / Chinese summary
- ARIN 前缀剥离与自测（2026-01-15）：非 ARIN hop 遇到带前缀查询时自动剥离前缀并输出 `[DNS-ARIN] strip-prefix`（仅 stderr）；新增 lookup 自测 `arin-prefix-strip` 纯字符串校验；四轮黄金（默认 / debug+metrics / 批量四策略 / 自检四策略）均 PASS，日志 `out/artifacts/20260115-112537`、`20260115-113007`，以及 `batch_{raw,health,plan,planb}/20260115-11{3500,3857,4216,4510}/...` 与 `batch_{raw,health,plan,planb}/20260115-11{5135,5533,5808,0129}/...`。
- IPv4/IPv6 启动探测 + 默认偏好调整（2026-01-15）：进程启动即探测本机 IPv4/IPv6 是否可用，双栈且未显式指定 prefer/only 时默认改为 `--prefer-ipv4-ipv6` + `--dns-family-mode seq-v4-then-v6`；仅单栈时自动强制对应族并忽略冲突偏好（stderr 提示），两族都不可用直接 fatal 退出。`--debug` 下追加 `[NET-PROBE] ipv4=... ipv6=...`。

English summary
- ARIN prefix stripping + selftest (2026-01-15): non-ARIN hops now strip ARIN-style prefixes and emit `[DNS-ARIN] strip-prefix` to stderr; add a lookup selftest `arin-prefix-strip` (pure string check). Four-way golden runs all PASS with logs `out/artifacts/20260115-112537`, `20260115-113007`, plus `batch_{raw,health,plan,planb}/20260115-11{3500,3857,4216,4510}/...` and `batch_{raw,health,plan,planb}/20260115-11{5135,5533,5808,0129}/...`.
- IPv4/IPv6 startup probe + default flip (2026-01-15): on startup we probe local IPv4/IPv6 availability once; if both work and no prefer/only flags were set, the default becomes `--prefer-ipv4-ipv6` + `--dns-family-mode seq-v4-then-v6`. Single-stack hosts auto-force the matching family and ignore conflicting preferences with a notice; zero families is fatal. `[NET-PROBE] ipv4=... ipv6=...` appears under `--debug`.

Notes
- Stdout header/tail contracts remain unchanged; the extra `[LOOKUP_SELFTEST]` burst is stderr-only and still gated by the `-DWHOIS_LOOKUP_SELFTEST` build.

## 3.2.9

中文摘要 / Chinese summary
- DNS Phase 2/3 收尾：以当前 `wc_dns` + lookup 实现为基线，固化候选生成、负缓存、候选排序与回退层设计；三大调试标签 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` 与 Phase 3 新增的 `[DNS-HEALTH]` 共同构成 DNS 排障“观测三件套”，默认仅在 `--debug` 或 `--retry-metrics` 下输出。
- 进程级 DNS 缓存统计：`--dns-cache-stats` 通过 `atexit` 打印一次 `[DNS-CACHE-SUM] hits=<n> neg_hits=<n> misses=<n>`，用于粗略观察正向/负向缓存命中率与未命中情况；该选项只影响统计输出，不改变解析或回退策略。
- DNS 健康记忆（Phase 3）：在 `wc_dns` 内为每个 `host+family` 维护轻量健康状态（连续失败计数与 penalty 窗口），通过 `[DNS-HEALTH]` 日志暴露当前状态，并在候选排序中“健康优先、不中断候选”，以减少在明显不健康 IPv4/IPv6 族上的重复撞墙，同时保持黄金用例输出不变。
- 调试/自测集成：在以 `-DWHOIS_LOOKUP_SELFTEST` 编译并带 `--selftest` 运行时，新加入的 `[LOOKUP_SELFTEST]` 行会对 DNS 候选、健康记忆与回退路径做总结性报告，方便在远程冒烟日志中快速 eyeball 行为是否符合预期。
- 文档与运维补完：`USAGE_CN/EN` 与 `OPERATIONS_CN/EN` 均新增“DNS 调试 quickstart”/“DNS debug quickstart” 段落，给出推荐命令 `whois-x86_64 --debug --retry-metrics --dns-cache-stats [--selftest] 8.8.8.8`，并解释各类 DNS 标签含义及典型输出；`tools/remote/README_*.md` 补充了 `smoke_test.log` 中出现 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` / `[DNS-HEALTH]` / `[LOOKUP_SELFTEST]` 的预期说明。
- 版本与发布日期对齐：核心代码版本号升级为 `3.2.9`，README 顶部版本展示同步更新，为后续以 v3.2.9 作为 DNS 线“新 golden 基线”打好文档与实现的一致性基础。

English summary
- DNS Phase 2/3 wrap-up: solidifies the current `wc_dns` + lookup design as the new baseline for candidate generation, negative cache, candidate ordering and fallback layers. Together, `[DNS-CAND]`, `[DNS-FALLBACK]`, `[DNS-CACHE]` plus the Phase‑3 `[DNS-HEALTH]` tag form a DNS troubleshooting trio, emitted only when `--debug` or `--retry-metrics` is enabled.
- Process-level DNS cache stats: `--dns-cache-stats` prints a single `[DNS-CACHE-SUM] hits=<n> neg_hits=<n> misses=<n>` line via `atexit`, giving a rough view of positive/negative cache hit rate and misses. This flag is **observability-only** and does not alter resolution or fallback behavior.
- DNS health memory (Phase 3): `wc_dns` now tracks a lightweight health state per `host+family` (consecutive failures and a short penalty window). `[DNS-HEALTH]` logs expose this state, and candidate ordering applies a “healthy‑first, never dropping candidates” policy to avoid hammering obviously unhealthy IPv4/IPv6 families while keeping golden outputs unchanged.
- Debug/selftest integration: when built with `-DWHOIS_LOOKUP_SELFTEST` and run with `--selftest`, new `[LOOKUP_SELFTEST]` lines summarize DNS candidates, health memory and fallback paths so that remote smoke logs can be eyeballed quickly for expected behavior.
- Docs & operations closure: `USAGE_CN/EN` and `OPERATIONS_CN/EN` gained DNS debug quickstart sections recommending `whois-x86_64 --debug --retry-metrics --dns-cache-stats [--selftest] 8.8.8.8` and describing the meaning and sample output of `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` / `[DNS-HEALTH]` / `[LOOKUP_SELFTEST]`. `tools/remote/README_*.md` now calls out these tags as expected content in `smoke_test.log` when DNS debugging/selftests are enabled.
- Version alignment: bump the core code version to `3.2.9` and update the top-level README display so that v3.2.9 serves as the new “golden” baseline for DNS behavior and observability.

Notes
- No stdout contract changes (per‑query header and authoritative tail) compared to 3.2.8; all new DNS observability remains stderr‑only.
- DNS health memory is deliberately conservative: candidates are reordered but never dropped, and penalties are short‑lived to avoid surprising behavior in edge networks.
- Selftest and DNS debug flags are meant for development/ops; production usage can leave them off without affecting default DNS behavior.

## 3.2.8

中文摘要 / Chinese summary
- DNS 第一阶段（服务器解析）改进：使用 `AI_ADDRCONFIG` 与家族控制（仅/优先）提升解析与连通的确定性；对解析得到的多候选做去重与上限控制；在解析/连不通时回退到已知的 RIR IPv4；头/尾 `@` 段统一显示“实际连接 IP 或 unknown”。
- DNS 第二阶段（候选调度 + 回退层）：新增 `wc_dns` 模块统一处理 IP 字面量、RIR 映射、`getaddrinfo` 重试与 IPv4/IPv6 交错；`lookup.c` 通过该候选表拨号，并在空响应/连接失败/自测黑洞路径中复用同一集合，与 `--dns-*`/家族偏好配置保持一致。
- 三跳模拟增强：新增并验证稳定 `apnic → iana → arin` 链路；通过 `--selftest-force-iana-pivot` 保证仅首次强制 IANA 跳转，后续遵循真实 referral。
- 失败注入扩展：`--selftest-blackhole-arin`（最终跳超时）与 `--selftest-blackhole-iana`（中间跳超时）提供可重复的错误场景，便于脚本化回归与指标对比。
- 重试指标示例：使用 `--retry-metrics -t 3 -r 0` 观察连接级尝试分布与 p95；批量架构冒烟显示 attempts≈7、成功前置 2 次（起始+IANA），后续 ARIN 超时统计集中为 timeouts。
- 多目录同步：远程脚本 `-s '<dir1>;<dir2>'` 支持分号分隔的多个本地同步目标，提升多仓/镜像分发效率。
- 冒烟超时策略优化：含 `--retry-metrics` 的运行采用更宽松的 45s（SIGINT→5s→SIGKILL），避免截断最后的聚合行；常规运行保持默认 8s。
- 架构差异 errno 说明：连接超时在多数架构为 `errno=110 (ETIMEDOUT)`，在 MIPS/MIPS64 交叉产物下为 `errno=145`（同一符号常量的架构特定数值），逻辑以符号常量匹配，不依赖数值。
- 黄金样例汇总：本次冒烟日志（见 v3.2.8 release body）收录多架构 `[RETRY-METRICS-INSTANT]` + `[RETRY-METRICS]` + `[RETRY-ERRORS]` 模式，用作后续调优基线。
- DNS 调试输出：`--debug` 或 `--retry-metrics` 开启时新增 `[DNS-CAND]` / `[DNS-FALLBACK]` 行，完整记录候选列表、回退动作与 `fallback_flags` 映射，方便与 `[RETRY-*]` 对齐诊断。
- 文档同步：`docs/USAGE_EN.md` 与 `docs/USAGE_CN.md` 新增“DNS 调试日志与缓存可观测性”章节，全面说明 `[DNS-CAND]/[DNS-FALLBACK]/[DNS-ERROR]`、正/负向缓存命中提示以及 `--ipv4-only/--ipv6-only` 现在绕过规范域名预拨的行为。

English summary
- DNS phase‑1 (server resolution) improvements: `AI_ADDRCONFIG`-aware resolution with family controls (only/prefer) to increase determinism; de-duplicate and cap address candidates; fallback to known RIR IPv4 when resolution/connectivity fails; unify header/tail `@ <ip|unknown>` display of the connected endpoint.
- DNS phase‑2 (candidate orchestration + fallback): new `wc_dns` helper centralizes IP-literal detection, canonical RIR mapping, `getaddrinfo` retry cadence, and IPv4/IPv6 interleaving. `lookup.c` dials through the structured candidate list and reuses it for empty-response / connect-failure / selftest-blackhole paths so behavior aligns with the `--dns-*` knobs and family preferences.
- Three-hop simulation: stabilized `apnic → iana → arin` chain; `--selftest-force-iana-pivot` enforces only the first pivot via IANA, subsequent referrals follow real targets.
- Failure injection: `--selftest-blackhole-arin` (final hop timeout) and `--selftest-blackhole-iana` (middle hop timeout) yield reproducible error paths for scripted regression & metric baselines.
- Retry metrics showcase: with `--retry-metrics -t 3 -r 0` we observe ~7 attempts, first 2 successes (origin + IANA), remaining ARIN attempts timing out; p95 around 3s across arches.
- Multi-sync support: remote script accepts `-s '<dir1>;<dir2>'` (semicolon separated) to sync artifacts to multiple local destinations for mirrored distribution.
- Metrics-aware smoke timeout: runs containing `--retry-metrics` default to 45s (SIGINT then SIGKILL after 5s) to avoid truncating aggregate output; regular smokes remain at 8s.
- Errno differences: connect timeouts surface as `errno=110 (ETIMEDOUT)` on most arches; on MIPS/MIPS64 cross builds they appear as `errno=145` (architecture-specific numeric for the same symbol). Code logic switches on symbolic constants, not raw numbers.
- Golden sample: multi-arch smoke log excerpt (see v3.2.8 release body) now serves as a baseline for future performance tuning.
- DNS debug output: when `--debug` or `--retry-metrics` is active the client now emits `[DNS-CAND]` / `[DNS-FALLBACK]` lines to stderr, covering candidate ordering, fallback decisions, and the decoded `fallback_flags` bitset for easier correlation with `[RETRY-*]` metrics.
- Documentation: both `docs/USAGE_EN.md` and `docs/USAGE_CN.md` gained a “DNS debug logs & cache observability” section that explains `[DNS-CAND]/[DNS-FALLBACK]/[DNS-ERROR]`, how positive/negative caches show up in logs, and why `--ipv4-only/--ipv6-only` now skip the canonical-host pre-dial to keep the candidate list pure.

Notes
- No stdout contract changes (query header / authoritative tail remain intact in both success and injected failure cases).
- Failure injection flags remain non-fatal to existing success paths; they only alter specific hop behavior.
- Numeric errno variability (110 vs 145) does not affect classification; internal switch uses `ETIMEDOUT` symbol.


## 3.2.7

中文摘要 / Chinese summary
- DNS 第一阶段（服务器解析）奠基工作：引入解析策略与地址族控制参数、候选去重与上限；为 3.2.8 的三跳稳定化与 `@ <ip|unknown>` 观测铺路（本版以内部清理与脚本对齐为主，用户可见行为保持稳定）。
- 重试节流（连接级，默认开启，3.2.7）：转为纯 CLI 配置（移除全部运行时环境变量依赖），新增与精简相关标志：`--pacing-interval-ms`、`--pacing-jitter-ms`、`--pacing-backoff-factor`、`--pacing-max-ms`、`--pacing-disable`、`--retry-metrics`。
- 移除环境变量：源码彻底删除 `getenv/setenv/putenv`；原调试/自测环境变量统一改为 CLI：`--selftest-fail-first-attempt`、`--selftest-inject-empty`、`--selftest-grep`、`--selftest-seclog`。
- 文档精简：中英文 USAGE 将节流与自测章节压缩为单段 bullet；删除环境变量使用章节，仅保留 CLI 指南。
- 远程构建脚本更新：不再转发 WHOIS_*；构建日志提示“CLI-only for pacing/metrics/selftests”；保持多架构静态产物产出与哈希校验流程。
- 冒烟验证：使用 `-M nonzero` 与 `-M zero` 对默认节流与禁用节流进行断言，均 PASS；sleep_ms 呈现符合预期的非零/零差异。
- 行为兼容：标题/尾行、重定向、折叠输出、grep/title 投影均未改变；黄金用例与多架构 QEMU 冒烟继续通过。

English summary
- DNS phase‑1 groundwork: introduce resolution strategy and address‑family controls, candidate de‑dup/capping; sets the stage for 3.2.8’s stabilized three‑hop and unified `@ <ip|unknown>` observability (this release focuses on internal cleanup and script alignment with no user‑visible behavior changes).
- Connect-level retry pacing (default ON, 3.2.7): migrated to fully CLI-driven configuration (removed all runtime env dependencies). New/clean flags: `--pacing-interval-ms`, `--pacing-jitter-ms`, `--pacing-backoff-factor`, `--pacing-max-ms`, `--pacing-disable`, `--retry-metrics`.
- Environment variable removal: eliminated every `getenv/setenv/putenv`; former debug/selftest envs replaced by CLI flags: `--selftest-fail-first-attempt`, `--selftest-inject-empty`, `--selftest-grep`, `--selftest-seclog`.
- Documentation condensed: CN/EN USAGE pacing + selftest content reduced to a compact bullet section; removed legacy env usage guidance, retaining only CLI instructions.
- Remote build script: no longer forwards WHOIS_* variables; logs now state “CLI-only for pacing/metrics/selftests”; multi-arch static artifacts + hash verification unchanged.
- Smoke validation: assertions `-M nonzero` (default pacing) and `-M zero` (disabled pacing) both PASS; `sleep_ms` shows expected non-zero vs zero differentiation.
- Behavioral compatibility: output contract (header/tail), redirects, fold lines, grep/title projection unchanged; golden cases and multi-arch QEMU smokes remain green.

Notes
- No stdout format changes; pacing metrics remain stderr-only when `--retry-metrics` is specified.
- Selftest flags remain non-fatal: failures log diagnostics without altering exit codes.
- All prior env-based hooks are deprecated; attempting to set them has no effect in release binaries.

## 3.2.6

中文摘要 / Chinese summary
- 重构：将 WHOIS 重定向检测/解析逻辑抽离为独立模块（wc_redirect），统一大小写不敏感的重定向信号，移除 APNIC 特例分支；在实现上增加最小校验，避免可疑目标（如私网、localhost）。
- IANA 优先：当需要跨 RIR 跳转时强制先经 IANA 一跳（若尚未访问），稳定最终权威 RIR 的判定与尾行显示。
- 头尾契约一致性：标题行采用 “via <别名或域名> @ <实际连接 IP|unknown>”；尾行在权威服务器为 IP 字面量时，显示映射回的 RIR 域名，@ 段仍保留实际 IP/unknown。
- 自测增强：为重定向模块新增自测覆盖（needs_redirect/is_authoritative_response/extract_refer_server），与原有折叠自测共同执行。
- 警告清理：移除未使用的 legacy 校验函数；为严格 C11 环境提供本地 strdup 安全实现以消除隐式声明警告。

English summary
- Refactor: extract WHOIS redirect detection/parsing into wc_redirect; unify case-insensitive redirect flags; remove APNIC-only branch; add minimal redirect-target validation to avoid local/private endpoints.
- IANA-first policy: when redirecting across RIRs, ensure we hop via IANA once (if not already), improving authoritative resolution and tail-line stability.
- Output contracts: header prints “via <alias-or-host> @ <connected-ip|unknown>”; tail canonicalizes IP-literal authoritative hosts back to RIR domain while keeping the @ segment as IP/unknown.
- Selftests: add redirect tests (needs_redirect/is_authoritative_response/extract_refer_server) alongside existing fold tests.
- Warnings cleanup: remove unused legacy validator; provide local safe strdup for strict C11 builds to avoid implicit declarations.
- Simplified version scheme: default builds no longer append a `-dirty` suffix. Set environment variable `WHOIS_STRICT_VERSION=1` before invoking the remote build script to restore the previous strict behavior (adding `-dirty` when tracked changes exist). This keeps day‑to‑day iteration lightweight while still allowing release hygiene when needed.

Notes
- 用户可通过 `--selftest` 运行内置自测；远程构建脚本支持安静模式与多架构编译，golden 检查保持可用。
- 版本策略简化：默认不再附加 `-dirty`；若需要“严格”标记本地未提交改动，可在执行前导出 `WHOIS_STRICT_VERSION=1`。

## 3.2.5

中文摘要 / Chinese summary
- 取消双语显示与环境变量切换：移除 `--lang` 与 `WHOIS_LANG`，统一英文输出，避免在受限 SSH/串口终端出现乱码。
- 帮助内容精简与去重：合并/去重 usage 段落，新增/保留 `--debug-verbose`、`--selftest`、`--fold-unique` 说明。
- 文档同步：USAGE（中/英）与示例更新；远程构建脚本示例去除语言参数；保持对 BusyBox 管道输出契约的兼容。
- 行为兼容性：除帮助文本外，核心查询/重定向/条件输出引擎未改动；黄金用例保持通过。

English summary
- De-internationalization: remove `--lang` and `WHOIS_LANG`; switch to English-only output to avoid mojibake on constrained SSH/serial terminals.
- Help output simplified and deduplicated; document `--debug-verbose`, `--selftest`, and `--fold-unique`.
- Docs updated (CN/EN); remote helper script examples no longer pass language switches; BusyBox-friendly output contract preserved.
- Backward-compatible behavior (queries/redirects/conditional engine unchanged); golden tests continue to pass.

其他变更 / Other changes
- 小幅清理与注释同步；准备 3.2.5 标签与产物发布。
- 新增 `--host` 传入 IPv4/IPv6 字面量时的 RIR 反查回退：当直接连接失败，会调用 PTR 反查并自动切换到匹配的 RIR 主机；若不属于任何已知 RIR，则立即报错退出。
- Added RIR fallback when `--host` receives an IPv4/IPv6 literal: on connection failure the client performs a PTR lookup, retries with the canonical RIR hostname when matched, and aborts with an explicit error otherwise.

## 3.2.4

中文摘要 / Chinese summary
- 模块化第一步：抽离条件输出相关逻辑到 `wc_title` / `wc_grep` / `wc_fold` / `wc_output` / `wc_seclog`，引入 `src/core/pipeline.c` 做后续主流程承载；主行为保持兼容。
- 新增 grep 自测钩子（编译宏 `-DWHOIS_GREP_TEST` + 环境变量 `WHOIS_GREP_TEST=1`），三种模式（block / line / line+cont）启动时自动验证并输出 PASS/FAIL。文档新增启用示例。
- 修复与改进续行启发式：块模式仅保留首个“header-like”缩进行（如地址行），后续同类缩进行需匹配正则才保留，避免误输出无关字段（Foo 等）。
- 远程构建诊断增强：增加 LDFLAGS/LDFLAGS_EXTRA 打印、UPX 可用性与压缩结果提示、QEMU vs 原生 smoke runner 显示，便于排查跨架构差异。
- 文档更新：`OPERATIONS_CN/EN.md` 增添 grep 自测钩子章节；英文化残留注释；说明 wc 前缀含义（whois client modules）。
- 保持输出契约与 CLI 语义不变（header/tail、折叠行格式、参数集合）。

English summary
- First modularization step: extract conditional output logic into `wc_title`, `wc_grep`, `wc_fold`, `wc_output`, `wc_seclog`; introduce `src/core/pipeline.c` for future orchestration while preserving current behavior.
- Add grep self-test hook (build macro `-DWHOIS_GREP_TEST` + env `WHOIS_GREP_TEST=1`) validating block / line / line+cont modes at startup; docs include enable examples.
- Improve continuation heuristic in block mode: keep only the first header-like indented line (e.g. address), subsequent header-like continuation lines must match the regex, preventing unrelated field leakage.
- Enhance remote build diagnostics: print LDFLAGS/LDFLAGS_EXTRA, UPX availability & compression stats, and show QEMU vs native smoke runner to ease cross-arch troubleshooting.
- Docs updated: grep self-test section added (CN/EN), remaining comments anglified, explain wc prefix (whois client modules).
- External contracts unchanged (artifact names, CLI options, header/tail lines, folded output format).

其他变更 / Other changes
- 预留进一步拆分入口：后续计划抽取 CLI 解析 (wc_opts)、网络与缓存 (wc_net / wc_cache)、协议校验 (wc_proto) 等；本版仅奠定条件输出与诊断基础。
- 保持构建可重复性：远程脚本 `-X` 一键开启自测；多架构静态产物均通过 GREPTEST。 

Future (non-breaking roadmap)
- Next steps: publish this stable tag, then proceed with wc_opts extraction followed by wc_net and wc_cache; each step gated by remote multi-arch build + self-test PASS.


## 3.2.3

中文摘要 / Chinese summary
- 输出契约细化：标题行与尾行现在都会解析并显示所使用的服务器域名对应的 IP（解析失败显示 `unknown`），别名（如 `apnic`）被映射后再解析，避免“via apnic @ unknown”假阴性。
- 折叠输出（`--fold`）保持原格式不变：仍为 `<query> <UPPER_VALUE_...> <RIR>`，不追踪服务器 IP，确保下游管道兼容性。
- 新增 ARIN IPv6 连通性提示：在私网 IPv4 环境可能遭拒 (port 43)，建议启用 IPv6 或使用公网出口；相关说明已加入 USAGE（中/英）。

English summary
- Output contract refinement: header and tail lines now show the resolved IP of the starting server and authoritative RIR server (or `unknown` on DNS failure); aliases (e.g. `apnic`) are mapped before resolution to avoid false "@ unknown" cases.
- Folded output (`--fold`) remains unchanged: still `<query> <UPPER_VALUE_...> <RIR>` for pipeline stability; server IPs are intentionally excluded.
- Added ARIN IPv6 connectivity tip: private IPv4 LAN sources may be rejected on port 43; enabling IPv6 or using a public egress fixes access. Documentation updated (CN/EN).

其他变更 / Other changes
- 小幅代码清理与注释同步；为后续一键发布准备版本号提升。

Artifacts / 产物：同 3.2.2（一个动态 x86_64 + 七个全静态多架构二进制）。

---

## 3.2.2

中文摘要
- 安全性系统加固（九大方向），并新增可选安全日志：
  - 新增 `--security-log`（默认关闭）：将安全事件输出到 stderr（用于调试/审计），不改变 stdout 的“标题/尾行”契约。
  - 安全日志内置限频（约 20 条/秒）：在洪泛/攻击场景下自动抑制并输出汇总提示，避免刷屏。
  - 主要领域：
    1) 内存安全辅助：`safe_malloc/realloc/strdup` 等封装与检查；
    2) 信号处理与清理：SIGINT/TERM/HUP/PIPE 的稳态处理与活动连接清理；
    3) 输入校验：查询长度/字符集/可疑负载识别；
    4) 网络连接与重定向安全：目标校验、环路防护、注入与异常识别；
    5) 响应净化与校验：移除控制/ANSI 序列、结构一致性检查；
    6) 配置校验：不合法配置与越界检测；
    7) 线程安全与缓存一致性：加锁、失效策略与并发安全；
    8) 连接洪泛与速率监测：异常速率与限流告警；
    9) 协议级异常检测与日志：可疑字段与跨域响应识别。

English summary
- Security hardening across nine areas with optional diagnostics:
  - Add `--security-log` (off by default): emits SECURITY events to stderr for diagnostics/audit; stdout contract unchanged.
  - Security log output is rate-limited (~20 events/sec) with suppression summaries to prevent stderr flooding during attacks.
  - Areas covered:
    1) Memory safety helpers (safe malloc/realloc/strdup);
    2) Signal handling and cleanup (SIGINT/TERM/HUP/PIPE) with active-connection tracking;
    3) Input validation (query length/charset/suspicious payloads);
    4) Network/redirect security (target validation, loop guards, injection/anomaly detection);
    5) Response sanitization/validation (strip control/ANSI sequences, structural checks);
    6) Configuration validation (illegal/ out-of-range detection);
    7) Thread safety and cache integrity (locks, invalidation);
    8) Connection flood/rate monitoring;
    9) Protocol-level anomaly detection and logging.

其他变更
- 完全移除此前实验性的 RDAP 相关功能与开关，保持经典 WHOIS 纯文本流程，避免语义歧义与维护成本。
- 修复并清理若干编译警告（如 -Wsign-compare），`receive_response` 相关计数改为 `size_t`，并支持 `CFLAGS_EXTRA` 以便定制构建。 
- 文档（中/英）同步更新：补充安全日志与故障排查要点（含 ARIN:43 端口连通性提示），对齐“零 RDAP”状态。

Other changes
- Remove all experimental RDAP features and switches to keep classic WHOIS-only behavior and avoid semantic drift.
- Fix/clean compilation warnings (e.g., -Wsign-compare), switch some counters to `size_t`, and add `CFLAGS_EXTRA` for customized builds.
- Docs (CN/EN) updated accordingly, including security-log notes and troubleshooting (e.g., ARIN:43 connectivity), aligned with "no RDAP" state.

## 3.2.1

中文摘要
- 新增“折叠输出”开关 `--fold`：将经 `-g/--grep*` 筛选后的正文折叠为单行，格式为 `<query> <UPPER_VALUE_...> <RIR>`，便于在 BusyBox 管道中直接聚合与判定；默认关闭。
  - 新增 `--fold-sep <SEP>` 指定分隔符（默认空格，支持 `\t/\n/\r/\s`）；新增 `--no-fold-upper` 保留原大小写（默认转为大写）。

- 文档：新增“续行关键词命中技巧”一节，给出推荐策略 A（`-g` + 块模式 `--grep` + `--fold`）与可选策略 B（行模式 OR + `--keep-continuation-lines` + `--fold`），并说明行模式按“逐行”匹配（`\n` 不跨行）。
  - 参考：`docs/USAGE_CN.md#续行关键词命中技巧推荐策略与陷阱` | `docs/USAGE_EN.md#continuation-line-keyword-capture-tips-recommended`

English summary
- Add optional folded output via `--fold`: print a single folded line per query using the current selection (after `-g` and `--grep*`), formatted as `<query> <UPPER_VALUE_...> <RIR>`; disabled by default.
  - Add `--fold-sep <SEP>` to customize the separator (default space; supports `\t/\n/\r/\s`) and `--no-fold-upper` to preserve original case (default uppercases).

- Docs: add "Continuation-line keyword capture tips" with recommended Strategy A (`-g` + block `--grep` + `--fold`) and optional Strategy B (line-mode OR + `--keep-continuation-lines` + `--fold`); clarify that line mode matches per-line (`\n` does not span lines).
  - See: `docs/USAGE_EN.md#continuation-line-keyword-capture-tips-recommended` | `docs/USAGE_CN.md#续行关键词命中技巧推荐策略与陷阱`

## 3.2.0

中文摘要
- 新增基于正则的“行模式”过滤（`--grep-line`）与“块模式/行模式”切换（`--grep-block/--grep-line`），保持与 `-g/--title` 的投影语义兼容：先按标题前缀投影，再进行正则过滤。
- 行模式支持“续行展开”开关（`--keep-continuation-lines` 和 `--no-keep-continuation-lines`），用于在命中行时输出整个字段块（标题+续行）。
- 修复行模式在部分系统上可能跨行匹配的问题：现在对“当前行”做独立的正则匹配，兼容 musl；无需 `REG_STARTEND` 扩展。
- 连接缓存健壮性增强：使用 `getsockopt(SO_ERROR)` 校验连接可用性并在异常时清理缓存，替代脆弱的基于 `select` 的探测。
- 文档与集成：
  - USAGE（中/英）补充新选项与示例；跨链接至 lzispro，记录环境变量与集成方式。
  - lzispro 的 `lzispdata.sh` 默认切换为“行模式 + 不展开续行”，并提供环境变量回退到块模式或打开展开。

English summary
- Add regex-based line filtering mode (`--grep-line`) and explicit selection mode toggles (`--grep-block/--grep-line`); preserve `-g/--title` semantics by applying title projection first, then regex.
- Line mode supports an optional block expansion switch (`--keep-continuation-lines`/`--no-keep-continuation-lines`) to emit the whole field block when any line matches.
- Fix potential cross-line matching in line mode by matching against an isolated copy of the current line (portable on musl); no `REG_STARTEND` dependency.
- Improve cached-connection aliveness check using `getsockopt(SO_ERROR)` and clean up invalid sockets, replacing the earlier select-based probe.
- Docs and integration:
  - Update USAGE (CN/EN) with new options and examples; cross-link to lzispro with env var guidance.
  - lzispro `lzispdata.sh` defaults to line mode without block expansion; env switches allow reverting to block mode or enabling expansion.

Artifacts / 产物：与上一版一致（动态 x86_64 与七个全静态多架构二进制），详见下文 Artifacts 一节。

中文摘要
- 轻量高性能 C 语言 whois 客户端，专为 BusyBox 管道优化：
  - 批量标准输入（-B），无位置参数且 stdin 非 TTY 自动进入
  - 稳定输出契约：每条首行“=== Query: … ===”，末行“=== Authoritative RIR: … ===”
  - 非阻塞连接、I/O 超时、轻量重试（默认 2）、自动重定向（默认 5，支持禁用与上限）
  - 多架构静态二进制（aarch64/armv7/x86_64/x86/mipsel/mips64el/loongarch64）
- 新增/重要说明：
  - 文档全面更新（中英双语），补充 IPv4/IPv6 字面量作为 --host 的用法与示例
  - 远端交叉编译与冒烟测试脚本：默认“联网冒烟”，支持 SMOKE_QUERIES 自定义目标
  - 冒烟前增加 43/TCP 连通性预检（仅日志），失败将如实反映在 smoke_test.log 中

English summary
- Lightweight, high-performance whois client in C, optimized for BusyBox pipelines:
  - Batch stdin (-B), implicitly enabled when no positional arg and stdin is not a TTY
  - Stable output contract: per-query header and authoritative RIR tail line
  - Non-blocking connect, IO timeouts, light retries (default 2), referral redirects (default 6, configurable/disable)
  - Multi-arch static binaries (aarch64/armv7/x86_64/x86/mipsel/mips64el/loongarch64)
- New/important notes:
  - Docs revamped (CN/EN), add guidance for using IPv4/IPv6 literals with --host
  - Remote cross-compilation + smoke test scripts: default to networked smoke; support SMOKE_QUERIES
  - Add a log-only port-43 connectivity pre-check; real failures are reflected in smoke_test.log

## Artifacts / 产物
- whois-x86_64-gnu（CI 构建的 Linux x86_64 glibc 动态可执行）
- SHA256SUMS.txt（针对 whois-x86_64-gnu）

Additionally, remote toolchains produce seven fully static binaries (musl unless noted):
此外，远端交叉工具链会产出 7 个“全静态”二进制（除 loongarch64 特例外，一般为 musl 静态）：

- whois-x86_64-gnu - Linux x86_64，glibc 动态链接；体积小，适合常见桌面/服务器。
- whois-x86_64 — Linux x86_64，静态（musl）；与 whois-x86_64-gnu 的区别：无需依赖 glibc
- whois-x86 — Linux 32 位 x86 (i686)，静态
- whois-aarch64 — Linux aarch64/ARM64，静态；适合大多数发行版/容器
- whois-armv7 — Linux 32 位 ARMv7，静态
- whois-mipsel — Linux MIPS little-endian，静态
- whois-mips64el — Linux MIPS64 little-endian，静态
- whois-loongarch64 — Linux LoongArch64，静态（使用 GNU 工具链，已链接 libgcc/libstdc++）

使用提示 / Usage guidance：
- 在极简系统/容器中优先选择“静态”二进制（便携性最好）。
  - Prefer the static binary for maximum portability on minimal systems.
- 标准 x86_64 桌面/服务器（glibc）可直接使用 whois-x86_64-gnu（体积更小）。
  - Use whois-x86_64-gnu on standard x86_64 Linux with glibc for smaller size.

## 使用要点 / Usage highlights
- 禁止重定向：`--host <rir> -Q` 可固定服务器稳定输出。
  - Disable redirects: use `--host <rir> -Q` to fix the server for consistent output.
- 重试节奏默认：interval=300ms, jitter=300ms，可用 `-i/-J` 调整。
  - Retry pacing defaults: interval 300ms, jitter 300ms; adjustable via `-i/-J`.
- 私网 IP 输出正文为 "<ip> is a private IP address"，尾行为 `=== Authoritative RIR: unknown ===`。
  - For private IPs, the body prints "<ip> is a private IP address" and the tail shows `=== Authoritative RIR: unknown ===`.

更多细节 / More details:
- 使用说明 / Usage: CN docs/USAGE_CN.md | EN docs/USAGE_EN.md
