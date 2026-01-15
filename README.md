# whois (v3.2.10)

[![latest tag](https://img.shields.io/github/v/release/larsonzh/whois?display_name=tag&sort=semver)](https://github.com/larsonzh/whois/releases)
[![downloads](https://img.shields.io/github/downloads/larsonzh/whois/total)](https://github.com/larsonzh/whois/releases)
[![license](https://img.shields.io/github/license/larsonzh/whois)](LICENSE)
[![build](https://github.com/larsonzh/whois/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/larsonzh/whois/actions/workflows/build.yml)
[![release date](https://img.shields.io/github/release-date/larsonzh/whois)](https://github.com/larsonzh/whois/releases)
[![publish-gitee](https://github.com/larsonzh/whois/actions/workflows/publish-gitee.yml/badge.svg?branch=master)](https://github.com/larsonzh/whois/actions/workflows/publish-gitee.yml)

## 概览 / Overview

- 轻量高性能 C 语言 whois 客户端，支持：
	- 批量标准输入模式（`-B`），当 stdin 不是 TTY 时自动启用
	- 适合 BusyBox 管道的稳定输出契约：每条查询首行标题（含起始服务器与其 IP）与末行 Authoritative RIR（含其 IP）
	- 非阻塞连接、I/O 超时、轻量重试、跟随转发（带循环保护）
- Lightweight, high-performance whois client in C with:
	- Batch stdin mode (`-B`), implicitly enabled when stdin is not a TTY
	- Stable output contract for BusyBox pipelines: per-query header (includes starting server + its IP) and authoritative RIR tail (with its IP)
	- Non-blocking connect, IO timeouts, light retries, and referral redirect following with loop guard

亮点：折叠输出（`--fold`、`--fold-sep`、`--no-fold-upper`），续行关键词命中技巧（策略 A 与策略 B），以及 `--max-host-addrs` 可限制每个主机的拨号次数（配合 `--debug` 可见 `[DNS-LIMIT]` / `[NET-DEBUG]`）。均针对 BusyBox 管道做优化——详见使用文档。
	Highlight: folded output (`--fold`, `--fold-sep`, `--no-fold-upper`), continuation-line keyword capture tips (Strategy A vs B), and `--max-host-addrs` to cap per-host dial attempts (check `[DNS-LIMIT]` / `[NET-DEBUG]` under `--debug`). Tuned for BusyBox pipelines—see Usage.

### Why this whois client / 我们的亮点

- Smart redirects / 智能重定向：
	- Auto follow referrals with loop guard and max hops (`-R`, disable with `-Q`); non-blocking connect, timeouts, and light retries ensure responsive queries even on poor links.
	- 自动跟随转发（含循环保护与跳转上限 `-R`，可用 `-Q` 禁用）；非阻塞连接 + 超时 + 轻量重试，在弱网络下也能保持顺滑体验。
- Pipeline batch input / 管道化批量输入：
	- Read from stdin (`-B` or implicit when stdin isn’t a TTY), stable header/tail contract for BusyBox grep/awk pipelines; designed for large-scale classification and logging.
	- 读取标准输入（`-B` 或隐式触发），输出契约稳定，天然适配 BusyBox 的 grep/awk 管道，适合大批量归类与日志流处理。
- Conditional output engine / 条件输出引擎：
	- Title projection (`-g`, case-insensitive prefix) → POSIX ERE filters (`--grep/--grep-cs`, line/block, optional continuation expansion) → folded summarization (`--fold`).
	- 标题投影（`-g`，不区分大小写前缀）→ 正则筛查（`--grep/--grep-cs`，行/块 + 可选续行展开）→ 单行折叠（`--fold`）。

Tiny pipeline sketch / 处理流程一图流：

`query → resolve server → follow referrals → title projection (-g) → regex filter (--grep*) → fold (--fold)`

![Pipeline](docs/images/pipeline.svg)

## Try it / 试试手

```bash
# Linux / Git Bash：在 Linux 或 Git Bash 环境中运行
# Linux / Git Bash: run in Linux or Git Bash
whois-x86_64 8.8.8.8
whois-x86_64 --host apnic -Q 103.89.208.0
printf "8.8.8.8\n1.1.1.1\n" | whois-x86_64 -B -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold
```

```powershell
# Windows PowerShell：在 Windows PowerShell 中运行
# Windows PowerShell: run in Windows PowerShell
whois-x86_64.exe 8.8.8.8
whois-x86_64.exe --host apnic -Q 103.89.208.0
"8.8.8.8`n1.1.1.1" | .\whois-x86_64.exe -B -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold
```

### 文档 TOC / Docs TOC
- 使用说明 / Usage: `docs/USAGE_CN.md` | `docs/USAGE_EN.md`
- 操作与发布 / Operations: `docs/OPERATIONS_CN.md` | `docs/OPERATIONS_EN.md`
- 发布流程 / Release Flow: `docs/RELEASE_FLOW_CN.md` | `docs/RELEASE_FLOW_EN.md`
 - 链接风格转换 / Link style conversion: `docs/RELEASE_LINK_STYLE.md`

### CI 注记 / CI Note
- 仓库不再提供依赖远程 SSH 的工作流；如需在 CI 中访问私网，请改用自托管 Runner。
- 常规建议：在本机运行 `tools/remote/remote_build_and_test.sh` 完成立即可见的远程交叉编译与冒烟。
- 如需调试 SSH，可设置 `WHOIS_DEBUG_SSH=1` 以启用 `ssh -vvv` 详细日志。

快速导航 / Quick navigation:
- 发布与下载 / Releases:
	<!--
	Maintenance note / 维护说明:
	- Keep releases sorted by newest first (descending).
	- For Release notes anchor, use digits only (e.g., v3.2.5 -> `RELEASE_NOTES.md#325`).
	- Use the bilingual template below when adding a new version.
	- Also update the top title and shields badges to vX.Y.Z (first H1 line and any hard-coded version strings).
	- 同时将顶部标题与徽章版本更新为 vX.Y.Z（第一行 H1 标题及 README 中任何写死的版本号）。
	- Quick tip: copy the previous entry and replace version strings and anchor digits; verify both CN/EN lines.
	- 小贴士：可直接复制上一条，替换版本号与锚点数字，并检查中英文两行是否对应。
    
	Template / 模板：
	- vX.Y.Z：发布说明 `RELEASE_NOTES.md#XYZ` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/vX.Y.Z | Gitee Releases（查找 vX.Y.Z）: https://gitee.com/larsonzh/whois/releases
		- vX.Y.Z: Release notes `RELEASE_NOTES.md#XYZ` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/vX.Y.Z | Gitee Releases (find vX.Y.Z): https://gitee.com/larsonzh/whois/releases
	Example: v3.2.5 -> `#325`.
	-->
	- v3.2.10：发布说明 `RELEASE_NOTES.md#3210` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.10 | Gitee Releases（查找 v3.2.10）: https://gitee.com/larsonzh/whois/releases
		- v3.2.10: Release notes `RELEASE_NOTES.md#3210` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.10 | Gitee Releases (find v3.2.10): https://gitee.com/larsonzh/whois/releases
	- v3.2.9：发布说明 `RELEASE_NOTES.md#329` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.9 | Gitee Releases（查找 v3.2.9）: https://gitee.com/larsonzh/whois/releases
		- v3.2.9: Release notes `RELEASE_NOTES.md#329` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.9 | Gitee Releases (find v3.2.9): https://gitee.com/larsonzh/whois/releases
 	- v3.2.8：发布说明 `RELEASE_NOTES.md#328` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.8 | Gitee Releases（查找 v3.2.8）: https://gitee.com/larsonzh/whois/releases
		- v3.2.8: Release notes `RELEASE_NOTES.md#328` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.8 | Gitee Releases (find v3.2.8): https://gitee.com/larsonzh/whois/releases
	- v3.2.7：发布说明 `RELEASE_NOTES.md#327` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.7 | Gitee Releases（查找 v3.2.7）: https://gitee.com/larsonzh/whois/releases
		- v3.2.7: Release notes `RELEASE_NOTES.md#327` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.7 | Gitee Releases (find v3.2.7): https://gitee.com/larsonzh/whois/releases
	- v3.2.5：发布说明 `RELEASE_NOTES.md#325` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.5 | Gitee Releases（查找 v3.2.5）: https://gitee.com/larsonzh/whois/releases
		- v3.2.5: Release notes `RELEASE_NOTES.md#325` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.5 | Gitee Releases (find v3.2.5): https://gitee.com/larsonzh/whois/releases
	- v3.2.3：发布说明 `RELEASE_NOTES.md#323` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.3 | Gitee Releases（查找 v3.2.3）: https://gitee.com/larsonzh/whois/releases
		- v3.2.3: Release notes `RELEASE_NOTES.md#323` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.3 | Gitee Releases (find v3.2.3): https://gitee.com/larsonzh/whois/releases
	- v3.2.2：发布说明 `RELEASE_NOTES.md#322` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.2 | Gitee Releases（查找 v3.2.2）: https://gitee.com/larsonzh/whois/releases
		- v3.2.2: Release notes `RELEASE_NOTES.md#322` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.2 | Gitee Releases (find v3.2.2): https://gitee.com/larsonzh/whois/releases
	- v3.2.1：发布说明 `RELEASE_NOTES.md#321` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.1 | Gitee Releases（查找 v3.2.1）: https://gitee.com/larsonzh/whois/releases
		- v3.2.1: Release notes `RELEASE_NOTES.md#321` | GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.1 | Gitee Releases (find v3.2.1): https://gitee.com/larsonzh/whois/releases
  

## v3.2.10 速览 / What's new <a id="3210"></a>

- ARIN 前缀剥离与自测：非 ARIN hop 遇到带前缀查询时自动剥离前缀并输出 `[DNS-ARIN] strip-prefix`（仅 stderr）；新增 lookup 自测 `arin-prefix-strip`（纯字符串校验）。
	- ARIN prefix stripping + selftest: non-ARIN hops now strip ARIN-style prefixes and emit `[DNS-ARIN] strip-prefix` on stderr; added the `arin-prefix-strip` lookup selftest (pure string check).
- 四轮黄金验证（2026-01-15）：默认 / debug+metrics / 批量四策略 / 自检四策略全部 PASS（日志 `out/artifacts/20260115-112537`、`20260115-113007`，以及 `batch_{raw,health,plan,planb}/20260115-11{3500,3857,4216,4510}/...` 与 `batch_{raw,health,plan,planb}/20260115-11{5135,5533,5808,0129}/...`）。
	- Four-way golden matrix (2026-01-15): default, debug+metrics, batch four strategies, and selftest four strategies all PASS (logs as above).

参考与下载 / Links
- 发布说明 / Release notes: `RELEASE_NOTES.md#3210`
- 使用说明 / Usage: CN `docs/USAGE_CN.md` | EN `docs/USAGE_EN.md`
- GitHub 发布 / GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.10
- Gitee 发布 / Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.10）


## v3.2.9 速览 / What's new <a id="329"></a>

- DNS Phase 2/3 收尾：以 `wc_dns` + lookup 为基线，统一候选生成、负缓存、候选排序与回退层设计；通过 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` / `[DNS-HEALTH]` 将关键路径暴露到 stderr，仅在 `--debug` 或 `--retry-metrics` 下输出，保持 stdout 契约不变。
	- DNS Phase 2/3 completion: treat the current `wc_dns` + lookup stack as the new baseline for candidate generation, negative cache, ordering and layered fallbacks; key paths are exposed via `[DNS-CAND]`, `[DNS-FALLBACK]`, `[DNS-CACHE]` and `[DNS-HEALTH]` on stderr when `--debug` or `--retry-metrics` is enabled, without changing stdout contracts.
- 进程级 DNS 缓存统计：新增 `--dns-cache-stats`，在进程退出时输出单行 `[DNS-CACHE-SUM] hits=<n> neg_hits=<n> misses=<n>`，用于粗略观察正向/负向缓存命中率与未命中情况，仅影响可观测性，不改变解析/回退策略。
	- Process-level DNS cache stats: `--dns-cache-stats` prints a single `[DNS-CACHE-SUM] hits=<n> neg_hits=<n> misses=<n>` line at process exit, giving a rough view of positive/negative cache hit rates and misses while leaving resolution and fallback behavior unchanged.
- DNS 健康记忆（Phase 3）：为每个 `host+family` 维护轻量健康状态（连续失败计数、短期惩罚窗口），通过 `[DNS-HEALTH]` 展示当前健康度，并在候选排序中对“明显不健康”的族轻量降权，避免在被墙 IPv4/IPv6 段上的重复超时，同时不丢弃任何候选。
	- DNS health memory (Phase 3): maintain a lightweight health state per `host+family` (consecutive failures and a short penalty window). `[DNS-HEALTH]` exposes this state and candidate ordering applies a conservative "healthy‑first" bias so obviously broken families are tried less aggressively without dropping candidates.
- 自测与调试 quickstart：在以 `-DWHOIS_LOOKUP_SELFTEST` 编译并带 `--selftest` 运行时，新增 `[LOOKUP_SELFTEST]` 汇总当前自测中的 DNS 候选、健康记忆与回退路径；`USAGE_CN/EN` 与 `OPERATIONS_CN/EN` 新增 DNS 调试 quickstart 段落，推荐命令 `whois-x86_64 --debug --retry-metrics --dns-cache-stats [--selftest] 8.8.8.8` 并解释上述标签语义。
	- Selftests & DNS debug quickstart: builds with `-DWHOIS_LOOKUP_SELFTEST` and the `--selftest` flag now emit `[LOOKUP_SELFTEST]` summaries for DNS candidates, health memory and fallback paths. `USAGE_CN/EN` and `OPERATIONS_CN/EN` gained DNS debug quickstart sections recommending `whois-x86_64 --debug --retry-metrics --dns-cache-stats [--selftest] 8.8.8.8` and explaining the meaning of these stderr tags.
- 运维与文档对齐：远程脚本 `tools/remote/remote_build_and_test.sh` 的 README（中/英）补充了在启用 DNS 调试与自测时 `smoke_test.log` 中出现 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` / `[DNS-HEALTH]` / `[LOOKUP_SELFTEST]` 的预期说明；USAGE/OPERATIONS/RELEASE_NOTES 中的版本标注统一为具体版本号（去掉 `+`）。
	- Ops & docs alignment: `tools/remote/README_*.md` explain `[DNS-CAND]`, `[DNS-FALLBACK]`, `[DNS-CACHE]`, `[DNS-HEALTH]` and `[LOOKUP_SELFTEST]` as expected entries in `smoke_test.log` when DNS debugging or selftests are enabled, and USAGE/OPERATIONS/RELEASE_NOTES normalize version annotations to concrete versions (no trailing `+`).

参考与下载 / Links
- 发布说明 / Release notes: `RELEASE_NOTES.md#329`
- 使用说明 / Usage: CN `docs/USAGE_CN.md` | EN `docs/USAGE_EN.md`
- GitHub 发布 / GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.9
- Gitee 发布 / Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.9）


## v3.2.8 速览 / What's new <a id="328"></a>

- 三跳模拟：`--selftest-force-iana-pivot` 仅首次强制 IANA，后续遵循真实 referral，稳定 `apnic → iana → arin` 链路。
	- Three-hop chain: `--selftest-force-iana-pivot` enforces only the first IANA hop, then real referrals continue, stabilizing `apnic → iana → arin`.
- 失败注入：`--selftest-blackhole-arin`（最终跳）与 `--selftest-blackhole-iana`（中间跳）复现可控超时，辅助脚本化回归与指标采样。
	- Failure injection: `--selftest-blackhole-arin` (final hop) and `--selftest-blackhole-iana` (middle hop) provide deterministic timeout scenarios for regression & benchmarking.
- 重试指标：`--retry-metrics -t 3 -r 0` 展示前两次成功（起始+IANA）后续超时，attempts≈7、p95≈3s，利于观察连接级行为。
	- Retry metrics: with `--retry-metrics -t 3 -r 0` we see first two successes then timeouts; attempts≈7, p95≈3s across arches.
- DNS 第一阶段（服务器解析）改进：基于 `AI_ADDRCONFIG` 的解析策略；IPv4/IPv6 家族控制（仅/优先）；候选去重与上限；在解析失败时回退到已知 RIR IPv4；`@` 段统一显示已连接 IP/unknown，提升可观测性与确定性。
	- DNS phase‑1 (server resolution): `AI_ADDRCONFIG`-aware resolver strategy; IPv4/IPv6 family controls (only/prefer); candidate de‑dup and capping; fallback to known RIR IPv4 on resolution failures; unified `@ <ip|unknown>` display for observability and determinism.
- DNS 第二阶段（候选调度与回退层）：新增 `wc_dns` 模块集中处理 IP 字面量检测、RIR 映射、`getaddrinfo` 重试与 IPv4/IPv6 交错排序；`lookup.c` 依据该候选表拨号，并在空响应/失败回退时复用同一套候选与 `--dns-*` 上限，确保行为与 CLI 开关一致。
	- DNS phase‑2 (candidate scheduling + fallback stack): new `wc_dns` helper centralizes IP-literal detection, RIR canonical mapping, `getaddrinfo` retry policy, and IPv4/IPv6 interleaving. `lookup.c` now dials through this structured list and reuses it during empty-response/connection fallbacks, so the behavior honors `--dns-*` limits and family preferences exactly as configured.
- 多目录同步：远程脚本支持 `-s '<dir1>;<dir2>'` 同步产物到多个路径，简化镜像分发。
	- Multi-sync: remote build accepts multiple local sync targets via semicolon list.
- 冒烟超时策略：含指标运行默认 45s（SIGINT→5s→SIGKILL），常规仍 8s，避免截断尾部聚合行。
	- Metrics-aware timeout: 45s window (SIGINT then SIGKILL) for metric runs; regular smokes keep 8s.
- errno 差异：大多数架构超时显示 `errno=110 (ETIMEDOUT)`，MIPS/MIPS64 为数值 145（同一符号在该架构的定义）；逻辑按符号常量判断，不受数值差异影响。
	- Errno mapping: most arch use numeric 110 for ETIMEDOUT; MIPS/MIPS64 toolchains report 145 for the same symbolic constant; logic switches on `ETIMEDOUT`.
- 黄金样例：多架构 `[RETRY-METRICS-INSTANT]` + `[RETRY-METRICS]` + `[RETRY-ERRORS]` 已收录于 v3.2.8 Release body 供后续对比。
	- Golden sample: multi-arch metrics excerpt embedded in v3.2.8 release body for future comparisons.

参考与下载 / Links
- 发布说明 / Release notes: `RELEASE_NOTES.md#328`
- 使用说明 / Usage: CN `docs/USAGE_CN.md` | EN `docs/USAGE_EN.md`
- GitHub 发布 / GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.8
- Gitee 发布 / Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.8）

## v3.2.7 速览 / What's new <a id="327"></a>

- CLI-only 节流重试：连接级 pacing 默认开启；所有节流/指标配置迁移为命令行参数，新增并精简：`--pacing-interval-ms`、`--pacing-jitter-ms`、`--pacing-backoff-factor`、`--pacing-max-ms`、`--pacing-disable`、`--retry-metrics`。
	- CLI-only retry pacing: connect-level pacing default ON; fully migrated to flags listed above (no runtime env dependencies).
- 运行时环境变量剥离：删除全部 `getenv/setenv/putenv`；原调试/自测入口统一为 CLI：`--selftest-fail-first-attempt`、`--selftest-inject-empty`、`--selftest-grep`、`--selftest-seclog`。
	- Env removal: all previous debug/selftest env hooks replaced by explicit CLI flags.
- 文档与脚本统一：USAGE（中/英）精简为节流 + 自测合并段落；远程构建脚本打印“CLI-only”提示，不再转发 WHOIS_*；支持 `WHOIS_DEBUG_SSH=1` 开启 `ssh -vvv` 调试。
	- Docs & script: condensed CN/EN usage; remote build script stops forwarding WHOIS_*; `WHOIS_DEBUG_SSH=1` enables verbose SSH.
- 冒烟验证：新增 `-M nonzero` / `-M zero` 断言路径验证节流开启与禁用效果（sleep_ms 非零 vs 零），多架构均 PASS。
	- Smoke assertions: `-M nonzero` and `-M zero` validate pacing enabled/disabled across arches (PASS).
- 行为兼容：标题/尾行契约、重定向、折叠输出、grep/title 投影保持不变；黄金用例与 QEMU 冒烟继续通过。
	- Behavioral compatibility: output contracts, redirects, folding, grep/title unchanged; golden/QEMU tests remain green.
- CI 策略更新：移除依赖远程 SSH 的工作流；推荐本地脚本或自托管 Runner。
	- CI strategy: remote-SSH workflows removed; prefer local script or self-hosted runner.

参考与下载 / Links
- 发布说明 / Release notes: `RELEASE_NOTES.md#327`
- 使用说明 / Usage: CN `docs/USAGE_CN.md` | EN `docs/USAGE_EN.md`
- GitHub 发布 / GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.7
- Gitee 发布 / Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.7）

## v3.2.6 速览 / What's new <a id="326"></a>

- 重构与行为一致性：抽离 WHOIS 重定向检测/解析为独立模块（wc_redirect），统一大小写不敏感的重定向信号，移除 APNIC 特例；最小化重定向目标校验避免本地/私网目标。
	- Refactor & consistency: extract redirect logic into wc_redirect; unify case-insensitive redirect flags; remove APNIC-only branch; add minimal redirect-target validation.
- IANA 优先策略：跨 RIR 跳转时保证先经 IANA 一跳（若尚未访问），提升“权威 RIR”判定与尾行稳定性。
	- IANA-first policy to stabilize authoritative resolution and tail-line.
- 输出契约对齐：标题行采用“via <别名或域名> @ <连接 IP|unknown>”，尾行在权威为 IP 字面量时回映射为 RIR 域名，@ 段仍保留 IP/unknown。
	- Output contract alignment: header and tail as specified; literals canonicalized to RIR hostnames.
- 内置自测增强：新增重定向自测（needs_redirect/is_authoritative_response/extract_refer_server），与折叠自测一并执行；可编译开启 GREP/SECLOG 自测。
	- Selftests: redirect tests added; GREP/SECLOG tests available via compile-time switches.

参考与下载 / Links
- 发布说明 / Release notes: `RELEASE_NOTES.md#326`
- 使用说明 / Usage: CN `docs/USAGE_CN.md` | EN `docs/USAGE_EN.md`
- GitHub 发布 / GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.6
- Gitee 发布 / Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.6）

## v3.2.5 速览 / What's new <a id="325"></a>

- 稳定里程碑：在继续拆分（opts/net/cache）前冻结正确性与诊断，为下游提供安全基线。
	- Stability milestone: freeze correctness & diagnostics before further modular splits (opts/net/cache) to give downstream a safe baseline.
- 模块化第一步：抽离条件输出逻辑为 `wc_title`、`wc_grep`、`wc_fold`、`wc_output`、`wc_seclog`；新增 `src/core/pipeline.c` 预留后续编排；行为保持不变。
	- Modularization step 1: extract conditional output into `wc_title`, `wc_grep`, `wc_fold`, `wc_output`, `wc_seclog`; add `src/core/pipeline.c` for future orchestration; behavior preserved.
- GREP 自测钩子：编译加 `-DWHOIS_GREP_TEST`，运行设 `WHOIS_GREP_TEST=1`，自动验证 block / line / line+cont，输出 `[GREPTEST] ... PASS`；失败打印诊断。
	- GREP self-test hook: build with `-DWHOIS_GREP_TEST`; run with `WHOIS_GREP_TEST=1` to validate block/line/line+cont; emits `[GREPTEST] ... PASS` or diagnostics on failure.
- 续行启发式改进（块模式）：仅保留首个“类似标题缩进行”；后续同类缩进行需匹配正则才保留，避免引入无关字段。
	- Improved block-mode continuation heuristic: keep only first header-like indented line; later header-like indented lines must match regex to be kept.
- 远程构建诊断增强：打印 LDFLAGS_EXTRA、UPX 可用与压缩率、QEMU vs 原生 smoke runner。
	- Remote build diagnostics: include LDFLAGS_EXTRA, UPX availability/compression, and QEMU vs native smoke runner info.
- 文档更新：新增 grep 自测章节；解释 `wc` 前缀；清理遗留非英文注释。
	- Docs updated: add grep self-test section; clarify `wc` prefix; remove leftover non-English comments.

参考与下载 / Links
- 发布说明 / Release notes: `RELEASE_NOTES.md#324`
- 使用说明 / Usage: CN `docs/USAGE_CN.md` | EN `docs/USAGE_EN.md`
- GitHub 发布 / GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.5
- Gitee 发布 / Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.5）

## v3.2.3 速览 / What's new <a id="323"></a>

- 输出契约细化：标题与尾行显示服务器 IP（解析失败为 `unknown`），并对别名先映射再解析，避免 "via apnic @ unknown"。
	- Output contract refinement: header and tail now include server IPs (`unknown` on DNS failure); aliases mapped before resolution to avoid false "via apnic @ unknown" cases.
- 折叠输出（`--fold`）保持既有单行格式 `<query> <UPPER_VALUE_...> <RIR>`，不包含服务器 IP，确保下游管道稳定。
	- Folded output (`--fold`) retains the single-line form `<query> <UPPER_VALUE_...> <RIR>` without server IPs to keep downstream pipelines stable.
- 新增 ARIN IPv6 连通性提示：私网 IPv4 源可能被拒，建议启用 IPv6 或走公网出口（详见 USAGE）。
	- Add ARIN IPv6 connectivity tip: private IPv4 source may be rejected; enable IPv6 or use public egress (see Usage).

Links / 参考:
- 发布说明 / Release notes: `RELEASE_NOTES.md#323`
- 使用说明 / Usage: CN `docs/USAGE_CN.md` | EN `docs/USAGE_EN.md`
- GitHub 发布 / GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.3
- Gitee 发布 / Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.3）

## v3.2.2 速览 / What's new

- 安全加固（九大领域）与可选安全日志：
	- 新增 `--security-log`（默认关闭）：将安全事件输出到 stderr，便于调试与审计；不改变既有 stdout 输出契约。
		- Add `--security-log` (off by default): emits SECURITY events to stderr; stdout contract unchanged.
	- 安全日志已内置限频：避免在攻击/洪泛时刷屏（约 20 条/秒，超额抑制并定期汇总提示）。
		- Rate-limited output (~20 events/sec) with suppression summaries to avoid flooding.
	- 领域覆盖：内存安全辅助（safe_ 系列）、改进的信号处理与清理、输入/查询与长度/字符集校验、网络连接与重定向安全（含目标校验/环路/注入识别）、响应净化与校验（移除控制/ANSI 序列等）、配置校验、线程安全与缓存一致性（加锁/失效）、协议级异常检测与告警。
		- Coverage: safer memory helpers, improved signal handling/cleanup, strict input/query validation, secure redirects (target validation/loop/injection checks), response sanitization/validation (strip control/ANSI), configuration validation, thread-safety with cache integrity, protocol anomaly detection.
	- 版本命令与帮助已更新（`--version`、`--help`）。
		- `--version`/`--help` updated.

- 兼容性说明 / Compatibility:
	- 移除此前的 RDAP 实验功能与所有相关开关，保持经典 WHOIS 纯文本语义与工作流。
		- Remove previous experimental RDAP features/switches to keep classic WHOIS-only behavior.

参考与下载 / Links
- 发布说明 / Release notes: `RELEASE_NOTES.md#322`
- 使用说明 / Usage: CN `docs/USAGE_CN.md` | EN `docs/USAGE_EN.md`
- GitHub 发布 / GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.2
- Gitee 发布 / Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.2）

## v3.2.1 速览 / What's new

- 正则过滤与选择模式：新增 `--grep/--grep-cs`，支持行/块选择（`--grep-line`/`--grep-block`），并提供续行展开开关（`--keep-continuation-lines`）。
	- Regex filters and selection modes: add `--grep/--grep-cs`; support line/block selectors (`--grep-line`/`--grep-block`); optional block expansion in line mode (`--keep-continuation-lines`).
- 兼容原有 -g/--title 语义：`-g` 为不区分大小写的“前缀匹配”（非正则）；处理顺序保持为“先按标题投影，再做正则过滤”。
	- Preserve `-g/--title` semantics as case-insensitive prefix match (NOT regex); pipeline remains "title projection first, then regex filter".
- BusyBox 友好默认：输出契约不变；在 lzispro 中默认使用“行模式 + 不展开续行”，可通过环境变量回退或切换。
	- BusyBox-friendly defaults: output contract unchanged; lzispro defaults to "line mode + no continuation expansion", overridable via env vars.
- 稳定性增强：缓存连接存活性改用 `getsockopt(SO_ERROR)` 校验并在异常时清理。
	- Stability: cached-connection aliveness via `getsockopt(SO_ERROR)` with cleanup on error.
- 文档与流程：中英 USAGE 与操作手册更新；完善 Gitee Release 发布与“手动补发”工作流。
	- Docs & Ops updated (CN/EN); Gitee Release supports `target_commitish` and a manual backfill workflow.
- 产物：除 CI 动态 x86_64 外，提供 7 个全静态多架构二进制；附远程交叉编译与冒烟测试脚本。
	- Artifacts: CI x86_64-gnu plus seven fully static multi-arch binaries; remote cross-compile and QEMU smoke-test scripts.

参考与下载 / Links
- 发布说明 / Release notes: `RELEASE_NOTES.md#321`
- 使用说明 / Usage: CN `docs/USAGE_CN.md` | EN `docs/USAGE_EN.md`
- GitHub 发布 / GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.1
- Gitee 发布 / Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.1）

### 近期更新（v3.2.1 引入特性摘要） / Recent updates (introduced in v3.2.1)

- 可选折叠输出（--fold）：将筛选后的正文折叠为单行输出，格式为 `<query> <UPPER_VALUE_...> <RIR>`，便于 BusyBox 管道直接聚合与判定（默认关闭）。
	- Optional folded output (`--fold`): print a single folded line per query using the current selection, in the form `<query> <UPPER_VALUE_...> <RIR>`; handy for BusyBox pipelines (disabled by default).
- 支持 `--fold-sep <SEP>` 自定义分隔符（默认空格，支持 `\t/\n/\r/\s`），以及 `--no-fold-upper` 保留原大小写（默认转为大写）。
	- Supports `--fold-sep <SEP>` to customize the separator (default space; supports `\t/\n/\r/\s`) and `--no-fold-upper` to preserve original case (defaults to uppercase).

- 文档新增：续行关键词命中技巧（推荐策略 A：`-g` + 块模式 `--grep` + `--fold`；可选策略 B：行模式 OR + `--keep-continuation-lines` + `--fold`），并说明行模式为“逐行”匹配，`\n` 不跨行。
	- Docs addition: continuation-line keyword capture tips (recommended Strategy A: `-g` + block mode `--grep` + `--fold`; optional Strategy B: line-mode OR + `--keep-continuation-lines` + `--fold`), clarifying that line mode matches per line and `\n` does not span lines.
	- CN: `docs/USAGE_CN.md#续行关键词命中技巧推荐策略与陷阱` | EN: `docs/USAGE_EN.md#continuation-line-keyword-capture-tips-recommended`

## 示例图 / Example

折叠前后（示意）：

![Fold before/after](docs/images/fold-before-after.svg)

## 开发路线图 / Roadmap

- 条件输出（Phase 2.5）RFC（中文）：`docs/RFC-conditional-output-CN.md`

## 构建 / Build

- Linux / macOS / MSYS2(Windows) / WSL:
	- 默认构建：
		- Default build:
			- `make`
	- 静态链接（可选，取决于工具链是否支持 glibc/musl 静态）：
		- Static link (optional; depends on toolchain support for glibc/musl static):
			- `make static`

提示 / Notes:
- Windows 原生 MinGW 亦可，但推荐 MSYS2 或 WSL 以获得接近 Linux 的构建环境。
	- Windows native MinGW also works, but MSYS2 or WSL is recommended for a Linux-like environment.
- 若静态链接失败，属于平台库限制，建议继续使用动态链接目标。
	- If static linking fails, it's likely due to platform library limitations; continue using the dynamic target.

## 运行示例 / Run examples

- 单条查询
	- Single query
	- `./whois-client 8.8.8.8`
- 指定起始服务器查询
	- Query with specified starting server
	- `./whois-client --host apnic -Q 103.89.208.0`
- 管道批量查询
	- Pipeline batch query
	- `cat ip_list.txt | ./whois-client -B --host apnic`

## 打包 / Packaging (Windows PowerShell)

- 打包命令：
	- Packaging command:
		- `tools/package_artifacts.ps1 -Version 3.2.3`
- 产物布局：`dist/whois-<version>/{bin/<arch>, docs, src, licenses}`，并生成 `SHA256SUMS.txt` 与 ZIP。
	- Layout: `dist/whois-<version>/{bin/<arch>, docs, src, licenses}` with `SHA256SUMS.txt` and a ZIP archive.

## CI

- GitHub Actions（Ubuntu）自动构建：push 到 master/main 与 PR 会触发常规构建与产物归档。
	- GitHub Actions (Ubuntu) builds on push/PR and archives build artifacts.
- 推送形如 `vX.Y.Z` 的标签会触发发布：创建/更新 Release 并上传资产（支持覆盖）。
	- Pushing a tag like `vX.Y.Z` triggers release: creates/updates the Release and uploads assets (clobber enabled).
- 也支持从网页或 App 手动触发 `workflow_dispatch` 并输入 tag；另外提供 `publish-gitee.yml` 手动将 GitHub Release 镜像到 Gitee。
	- Manual `workflow_dispatch` is supported with an input tag; `publish-gitee.yml` mirrors the Release to Gitee on demand.

## Release pipeline / 发布流水线

- 主工作流：`.github/workflows/build.yml`
	- 收集仓库内 `release/lzispro/whois/` 下的 7 个静态二进制并生成合并的 `SHA256SUMS.txt`。
	- 创建/更新 GitHub Release，上传所有资产（允许覆盖同名文件）。
	- 可选：若配置了 Gitee Secrets，CI 会在日志中输出 Gitee 发布步骤；也可通过 `.github/workflows/publish-gitee.yml` 手动镜像到 Gitee。
	- 如需将 Release 正文中的直链改为仓库相对路径，使用 `docs/RELEASE_LINK_STYLE.md` 中的脚本。

## 默认重试节奏 / Retry pacing defaults

- 默认参数：timeout 5s、retries 2、retry-interval 300ms、retry-jitter 300ms
	- Defaults: timeout 5s, retries 2, retry-interval 300ms, retry-jitter 300ms
- 可通过参数调整，详见 USAGE 文档。
	- Adjustable via CLI options; see the USAGE docs for details.

## Errno 差异速查 / Errno quick reference

- 核心结论：请以“符号常量”为准（如 `ETIMEDOUT/ECONNREFUSED/ENETUNREACH/EHOSTUNREACH/EADDRNOTAVAIL/EINTR`），不同架构/工具链的“数值”可能不同。
- 错误来源：连接阶段错误通过 `getsockopt(fd, SO_ERROR, ...)` 返回，whois 仅按类别统计与原样打印 errno 数值，不进行自定义映射。
- 常见示例（观测自远程多架构冒烟）：
	- `ETIMEDOUT`（连接超时）：
		- x86_64/aarch64/armv7: 110
		- MIPS/MIPS64: 145（同一符号在该架构的编号）
	- `ECONNREFUSED`（连接被拒）：常见为 111；在 MIPS/MIPS64 上数值可能不同（以符号为准）。
	- `EHOSTUNREACH`（主机不可达）：常见为 113；在 MIPS/MIPS64 上数值可能不同（以符号为准）。
	- `ENETUNREACH`（网络不可达）与 `EADDRNOTAVAIL`（地址不可用）：数值亦可能随架构变化。

提示：本项目内部分类基于符号常量，数字差异不会影响统计与行为；若需精确比照某平台的数值，请在该平台运行一次可控失败用例并记录 stderr。

## 许可证 / License

- GPL-3.0-or-later
	- Licensed under GPL-3.0-or-later.

## 远程交叉编译 / Remote cross-compilation

- 推荐在 Ubuntu 虚拟机进行静态交叉编译，使用脚本：
	- 本地启动器：`tools/remote/remote_build_and_test.sh`
		- Local launcher: `tools/remote/remote_build_and_test.sh`
	- 远端构建器：`tools/remote/remote_build.sh`
		- Remote builder: `tools/remote/remote_build.sh`
- 目标架构：`aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64`
	- Targets: `aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64`
- 产物输出：`out/artifacts/<timestamp>/build_out/whois-*`
	- Artifacts: `out/artifacts/<timestamp>/build_out/whois-*`
- 存储与清理：
	- 自 v3.2.0 起，`out/artifacts/` 已加入 `.gitignore`，不再被版本库跟踪；如需本地清理旧运行，可使用 `tools/dev/prune_artifacts.ps1`（支持 `-DryRun`）。
		- Since v3.2.0, `out/artifacts/` is ignored by Git and no longer tracked; to clean up old local runs, use `tools/dev/prune_artifacts.ps1` (supports `-DryRun`).
- 可选同步：
	- 可以使用 `-s <dir>` 将 whois-* 同步到外部目录，例如：`D:/LZProjects/lzispro/release/lzispro/whois`
		- You can use `-s <dir>` to sync whois-* artifacts to an external directory, e.g., `D:/LZProjects/lzispro/release/lzispro/whois`.
	- 配合 `-P 1` 可在同步前清理该目录的非 whois-* 文件，从而实现“仅保留 7 个架构二进制”的要求。
		- With `-P 1`, clean non whois-* files in that directory before syncing to keep only the seven architecture binaries.
	- 多路径同步：`-s "/d/path/one;/d/path/two"`（或用逗号分隔）可同时同步到多个目录；脚本会自动规范 Windows 路径（如 `D:\path` → `/d/path`）。
		- Multi-target sync: `-s "/d/path/one;/d/path/two"` (or comma-separated) to sync to several folders at once; script auto-normalizes Windows paths (e.g. `D:\path` → `/d/path`).

- 冒烟测试：
	- 默认联网（`SMOKE_MODE=net`），不再将公网地址替换为私网地址；失败会如实反映超时/连不通场景。
		- By default (`SMOKE_MODE=net`), we no longer replace public addresses with private ones; failures accurately reflect timeouts/unreachable cases.
	- 自定义目标可用环境变量 `SMOKE_QUERIES` 或参数 `-q "8.8.8.8 example.com"` 指定（空格分隔）。
		- Customize targets via `SMOKE_QUERIES` env var or the `-q "8.8.8.8 example.com"` argument (space-separated).
