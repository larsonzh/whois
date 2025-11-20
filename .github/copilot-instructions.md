# Copilot Instructions for `whois`

面向：在 VS Code 中协助开发/维护本仓库的 AI 代理。

## 1. 架构总览与模块边界
- 单文件入口：`src/whois_client.c` 负责解析 CLI、驱动核心模块、串起整条流水线。
- 核心模块（`include/wc/*.h` + `src/core/*.c`）：
  - `wc_opts` + `src/core/opts.c`：命令行解析与配置归一化（含 DNS/重试/节流等开关）。
  - `wc_server` + `src/core/server.c`：起始 whois 服务器与别名解析（`--host`、RIR 选择）。
  - `wc_dns` + `src/core/dns.c`：DNS 候选生成、负缓存、IPv4/IPv6 健康记忆与 `[DNS-*]` 调试标签。
  - `wc_lookup` + `src/core/lookup.c`：按候选表拨号、跟随 referral、处理回退层（输出 `[LOOKUP_*]` / `[DNS-FALLBACK]` 等）。
  - `wc_net` + `src/core/net.c`：非阻塞 connect、I/O 超时、轻量重试与 `--retry-metrics` 指标输出。
  - 条件输出引擎：`src/cond/{title.c,grep.c,fold.c}` + `wc_title/wc_grep/wc_fold/wc_output`，实现“标题投影 → 正则过滤 → 折叠汇总”的三段式流水线。
  - 其他 glue：`src/core/pipeline.c`（整体流水线编排）、`src/core/meta.c`（usage/version）、`src/core/selftest*.c`（内置自测）。
- 数据流（核心心智模型）：
  - `query → resolve server (server+dns) → connect + follow referrals (lookup+net) → title projection (-g) → regex filter (--grep*) → fold (--fold)`。
  - stdout 只承载“业务输出”（标题/尾行/主体）；stderr 承载调试与指标（`[DNS-*]`、`[RETRY-*]`、`[LOOKUP_SELFTEST]` 等）。

## 2. 关键运行模式与输出契约
- 批量输入模式：
  - 当使用 `-B` 或 stdin 非 TTY 时自动启用，逐行读取 query，适配 BusyBox 管道。
- 每条查询的输出契约：
  - 头部标题行：`=== Query: <查询项> === via <host-or-alias> @ <ip|unknown>`（具体格式见 `RELEASE_NOTES.md` 与 `docs/USAGE_*`）。
  - 尾行：`=== Authoritative RIR: <rir-host> @ <ip|unknown> ===`。
  - `--fold` 模式下折叠行为固定为单行 `<query> <UPPER_VALUE_...> <RIR>`，不带 IP；任何改动需确保不破坏既有黄金样例与 BusyBox 管道。
  - 典型示例（非精确黄金，仅供形态参考）：
    - 标题：`=== Query: 8.8.8.8 === via apnic @ 203.119.x.x`
    - 尾行：`=== Authoritative RIR: whois.arin.net @ 192.0.x.x ===`
    - 折叠：`8.8.8.8 GOOGLE INC. ARIN`
- 条件输出引擎顺序：
  - 始终按 “`-g` 标题投影 → `--grep*` 正则筛查（行/块 + 续行策略）→ `--fold` 折叠输出” 顺序执行；修改时需保持该顺序不变。

## 3. DNS / 重试 / 指标相关惯例
- DNS 相关日志与统计：
  - 调试标签统一使用前缀：`[DNS-CAND]`、`[DNS-FALLBACK]`、`[DNS-CACHE]`、`[DNS-HEALTH]`，只在 `--debug` 或 `--retry-metrics` 等调试开关启用时输出到 stderr。
  - 进程级缓存统计开关 `--dns-cache-stats`：进程退出时通过 `atexit` 输出单行 `[DNS-CACHE-SUM] hits=<n> neg_hits=<n> misses=<n>`，每个进程只能输出一次。
- 重试/节流：
  - 所有重试/节流行为均由 CLI 控制（无环境变量配置），包括 `--pacing-*` 与 `--retry-metrics` 等；实现位于 `wc_net` + `src/core/net.c`。
  - `[RETRY-METRICS*]` 仅写入 stderr，且远程冒烟脚本会 grep 这些标签做黄金对比，修改时需保持字段名与基本结构稳定。

## 4. 自测与调试工作流
- 核心自测入口：
  - 编译阶段通过宏开启：例如 `-DWHOIS_LOOKUP_SELFTEST`、`-DWHOIS_GREP_TEST`；具体宏与行为见 `src/core/selftest*.c` 与 `include/wc_selftest.h`。
  - 运行期使用 `--selftest*` 开关触发不同场景（DNS 三跳链路、失败注入、grep/fold 自测等），输出 `[LOOKUP_SELFTEST]`、`[GREPTEST]` 等标签到 stderr。
- 日常调试推荐命令（示例）：
  - `whois-x86_64 --debug --retry-metrics --dns-cache-stats 8.8.8.8`
  - 带自测：`whois-x86_64 --debug --retry-metrics --dns-cache-stats --selftest 8.8.8.8`
  - 这些命令的标签含义与样例详见：`docs/USAGE_CN.md`、`docs/USAGE_EN.md`、`docs/OPERATIONS_CN.md`、`docs/OPERATIONS_EN.md`、`RELEASE_NOTES.md#329` 及相关 RFC 文档（例如 `docs/RFC-dns-phase2.md`）。

## 5. 构建、冒烟测试与发布流程
- 远程多架构构建 + 冒烟（推荐）：
  - 主脚本：`tools/remote/remote_build_and_test.sh`，在 Git Bash 或 WSL 中运行。
  - Windows 示例（PowerShell 调用 Git Bash）：
    ```powershell
    & 'C:\Program Files\Git\bin\bash.exe' -lc "cd /d/LZProjects/whois; tools/remote/remote_build_and_test.sh -r 1"
    ```
  - 常用参数：
    - `-r <rounds>`：冒烟轮数；`-P <n>`：限制并行架构数；`-s '<dir1>;<dir2>'`：同步产物到多个本地目录。
    - `-a '<SMOKE_ARGS>'`：透传给被测 `whois-*`，可用于开启 `--debug`、`--retry-metrics`、`--dns-cache-stats` 等。
  - 脚本会生成 `smoke_test.log`，并自动检查：
    - `[DNS-CACHE-SUM]` 行数（为 0 时告警）。
    - 各架构的 `[RETRY-METRICS]` / `[DNS-*]` / `[LOOKUP_SELFTEST]` 等标签是否存在并大致形态正确。
- 本地快速构建：
  - 使用 `Makefile` 构建主二进制（具体目标见 `Makefile`）。如需调试单一架构可直接本地 `make`。
- 产物清理与 Git 工作流：
  - 清理脚本：`tools/dev/prune_artifacts.ps1`、`tools/prune_lzispro_whois.ps1`。
  - 快速提交推送：VS Code 任务 `Git: Quick Push`（调用 `tools/dev/quick_push.ps1`）。

## 6. 修改代码时需要特别注意的约束
- 不破坏输出契约：
  - 任何更改标题行、尾行、折叠输出或 stderr 标签格式的改动，都应同步检查 `docs/USAGE_*`、`RELEASE_NOTES.md` 与 `tools/test/golden_check.sh`/黄金样例，必要时更新黄金。
- stdout/stderr 职责分离：
  - 新增的诊断/指标一律写入 stderr，并尽量复用现有标签风格（`[COMPONENT-TAG]`）。
- 模块前缀约定：
  - C 层公共 API 统一走 `wc_*` 前缀（见 `include/wc/*.h`）；新增模块时务必补齐头文件并保持命名一致。
- DNS 与重试逻辑：
  - 现有 DNS 候选/健康记忆/回退策略已在 v3.2.8–v3.2.9 冻结为“基线行为”；除非明确要改策略，否则只在可观测性和 bugfix 范围内改动。

---
如有不清楚或遗漏的部分（尤其是 DNS/自测/远程脚本相关习惯用法），欢迎在 PR 描述或 issue 中提出，再迭代补充本文件。
    - 确认 `[DNS-CACHE-SUM]` 行数 > 0 且每进程只输出一次。
