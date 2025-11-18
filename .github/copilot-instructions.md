# Copilot Instructions for `whois` Project

## 项目架构与核心组件
- 轻量级 C 语言实现的 whois 客户端，主文件：`src/whois_client.c`
- 支持多架构静态编译，产物如 `whois-x86_64`、`whois-aarch64`，无外部依赖
- 主要功能：批量标准输入、智能重定向、条件输出引擎（标题投影、正则筛查、折叠输出）
- 典型数据流：`query → resolve server → follow referrals → title projection (-g) → regex filter (--grep*) → fold (--fold)`

## 关键开发与运维流程
- **远程构建与冒烟测试**：
  - 推荐使用 Git Bash 执行 `tools/remote/remote_build_and_test.sh`，支持参数定制（详见 `docs/USAGE_CN.md`）
  - Windows 下可用 PowerShell 调用 Bash：
    ```powershell
    & 'C:\Program Files\Git\bin\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1"
    ```
  - 支持同步产物到外部目录（`-s <dir>`），并限制架构数量（`-P 1`）
- **本地构建**：
  - 使用 `Makefile`，但推荐远程脚本以保证多架构兼容性
- **产物清理**：
  - 使用 `tools/dev/prune_artifacts.ps1` 或 `tools/prune_lzispro_whois.ps1`

## 项目约定与模式
- **批量输入模式**：
  - 通过 `-B` 或 stdin 非 TTY 自动启用，输出头/尾契约适配 BusyBox 管道
- **输出契约**：
  - 每条查询首行 `=== Query: <查询项> ===`，尾行 `=== Authoritative RIR: <server> ===`
- **重定向与重试**：
  - 默认自动跟随 referral，最大跳数可控（`-R`），可用 `-Q` 禁用
  - 非阻塞连接、IO 超时、轻量重试（默认 2 次，间隔 300ms，抖动 300ms）
- **条件输出引擎**：
  - 标题投影（`-g`），POSIX ERE 正则筛查（`--grep*`），单行折叠（`--fold`）
  - 产物可选折叠分隔符（`--fold-sep`），默认大写（`--no-fold-upper` 保留原大小写）

## 重要文件与目录
- 主代码：`src/whois_client.c`
- 构建/测试脚本：`tools/remote/remote_build_and_test.sh`、`tools/dev/quick_push.ps1`、`tools/dev/tag_release.ps1`
- 文档：`docs/USAGE_CN.md`、`docs/USAGE_EN.md`、`docs/OPERATIONS_CN.md`、`docs/OPERATIONS_EN.md`

## 示例
- 批量查询并筛选：
  ```bash
  printf "8.8.8.8\n1.1.1.1\n" | whois-x86_64 -B -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold
  ```
- Windows 批量查询：
  ```powershell
  "8.8.8.8`n1.1.1.1" | .\whois-x86_64.exe -B -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold
  ```

---
如有不清楚或遗漏的部分，请反馈以便补充完善。

## DNS Phase 2 备忘录与工作流

- **当前已完成的 DNS 工作**：
  - 引入进程级 DNS 缓存统计 `--dns-cache-stats`，通过 `atexit` 钩子确保每个进程仅输出一行 `[DNS-CACHE-SUM]` 汇总。
  - 在 `meta`/usage 帮助中补全 `--dns-cache-stats` 文案，并在远程脚本中统计 `[DNS-CACHE-SUM]` 行数（仅在为 0 时告警）。
- **下一阶段（优先级较高）的改进项**：
  - **C. DNS 候选/回退日志统一**：在 `src/core/lookup.c` 中统一、结构化 `[DNS-CAND]` / `[DNS-FALLBACK]` 等调试输出，保证易 grep、易阅读，并控制日志量（默认仅在调试模式或特定开关下开启）。
  - **E/F. 文档与示例强化**：
    - 在 usage 中增加 "DNS Diagnostics" 小节，集中列出 `--dns-cache-stats` 及未来 DNS 调试相关选项。
    - 在 `docs/RFC-dns-phase2.md` 等文档中补充一段 DNS 调试 quickstart 示例，说明如何利用 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE-SUM]` 排查问题。
  - **G. 远程脚本提取 DNS 调试片段**：在 `tools/remote/remote_build_and_test.sh` 中，当 `SMOKE_ARGS` 含 DNS 调试开关（例如未来的 `--dns-debug`）时，从 `smoke_test.log` 中额外 grep/展示若干 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` 样例行，便于快速 eyeball 格式与行为。
- **后续（可选）改进项**：
  - **D. DNS 策略类开关**：考虑引入如 `--dns-no-fallback` 等选项，以便在调试时锁定某些 resolver 策略，但默认不暴露过多开关给普通用户，可先作为内部/高级开关设计。
  - **H. DNS 自测增强**：在 `src/core/selftest*.c` 中增加 DNS 缓存/回退相关自测场景，例如模拟第一个 resolver 失败、回退第二个成功，并验证日志输出与缓存计数。
- **未来重要方向（策略级优化）**：
  - **进程内智能记忆连接成功的 RIR IPv4/IPv6 地址策略**：
    - 背景：在 `-h <rir> --prefer-ipv4` 场景下，如果运营商屏蔽了该 RIR 的 IPv4，当前行为是每次查询都会先尝试 IPv4 失败，再退回 IPv6。
    - 目标：为每个 RIR/host 在进程内维护一次“健康记忆”，一旦确认某族类（如 IPv4）持续失败而 IPv6 可用，则在本进程后续查询中直接优先使用 IPv6，避免重复撞 IPv4 墙，大幅提升大批量查询效率。
    - 注意：这是超出 Phase 2 的策略型改进，预计改动点在 `lookup.c` 与 `dns.c` 之间的 glue 层，引入简单的 per-host/per-family 健康状态与短路逻辑，应在单独的 RFC 中设计细节后实施。

### 每日工作收尾流程（DNS Phase 2 相关）

- 当天有改动 DNS 相关代码/脚本/文档时：
  - 使用远程脚本运行至少一轮多架构 smoke（必要时附带 DNS 调试参数，如 `--dns-cache-stats`）。
  - 观察 `smoke_test.log`：
    - 确认 `[DNS-CACHE-SUM]` 行数 > 0 且每进程只输出一次。
    - 如当天改动了 `[DNS-CAND]` / `[DNS-FALLBACK]` 格式，确认输出符合预期样式、可被 grep。
  - 在本文件（`copilot-instructions.md`）或专门的 changelog/备忘录中简要记录：
    - 本日完成的 DNS Phase 2 子项（例如 C/E/F/G/D/H 的哪一部分）。
    - 发现的待办/问题（如果有），便于第二天继续推进。
  - 使用工作区内提供的 Git 工具或 `tools/dev/quick_push.ps1` 完成本日提交与推送，保持主干状态干净、可重现。
  