# whois (v3.2.1)

[![latest tag](https://img.shields.io/github/v/release/larsonzh/whois?display_name=tag&sort=semver)](https://github.com/larsonzh/whois/releases)
[![downloads](https://img.shields.io/github/downloads/larsonzh/whois/total)](https://github.com/larsonzh/whois/releases)
[![license](https://img.shields.io/github/license/larsonzh/whois)](LICENSE)
[![build](https://github.com/larsonzh/whois/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/larsonzh/whois/actions/workflows/build.yml)
[![release date](https://img.shields.io/github/release-date/larsonzh/whois)](https://github.com/larsonzh/whois/releases)

## 概览 / Overview

- 轻量高性能 C 语言 whois 客户端，支持：
	- 批量标准输入模式（`-B`），当 stdin 不是 TTY 时自动启用
	- 适合 BusyBox 管道的稳定输出契约：每条查询首行标题、末行 Authoritative RIR
	- 非阻塞连接、I/O 超时、轻量重试、跟随转发（带循环保护）
- Lightweight, high-performance whois client in C with:
	- Batch stdin mode (`-B`), implicitly enabled when stdin is not a TTY
	- Stable output contract for BusyBox pipelines: header per query and authoritative RIR tail
	- Non-blocking connect, IO timeouts, light retries, and referral redirect following with loop guard

Highlight: folded output (`--fold`, `--fold-sep`, `--no-fold-upper`) and continuation-line keyword capture tips (Strategy A vs B) designed for BusyBox pipelines — see Usage.

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
# Linux / Git Bash
whois-x86_64 8.8.8.8
whois-x86_64 --host apnic -Q 103.89.208.0
printf "8.8.8.8\n1.1.1.1\n" | whois-x86_64 -B -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold
```

```powershell
# Windows PowerShell
whois-x86_64.exe 8.8.8.8
whois-x86_64.exe --host apnic -Q 103.89.208.0
"8.8.8.8`n1.1.1.1" | .\whois-x86_64.exe -B -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold
```

文档 / Docs:
- 使用说明 / Usage (CN): `docs/USAGE_CN.md`
- Usage (EN): `docs/USAGE_EN.md`
- 操作与发布 / Operations (CN): `docs/OPERATIONS_CN.md`
- Operations (EN): `docs/OPERATIONS_EN.md`

快捷入口 / Quick links:
- 续行关键词命中技巧（推荐策略 A 与可选策略 B）：`docs/USAGE_CN.md#续行关键词命中技巧推荐策略与陷阱`
- Continuation-line keyword capture tips (Strategy A vs B): `docs/USAGE_EN.md#continuation-line-keyword-capture-tips-recommended`

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
- 发布说明 / Release notes: `RELEASE_NOTES.md#320`
- 使用说明：`docs/USAGE_CN.md` | `docs/USAGE_EN.md`
- GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.1
- Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.1）

## 近期更新 / Recent updates

- 可选折叠输出（--fold）：将筛选后的正文折叠为单行输出，格式为 `<query> <UPPER_VALUE_...> <RIR>`，便于 BusyBox 管道直接聚合与判定（默认关闭）。
	- 支持 `--fold-sep <SEP>` 自定义分隔符（默认空格，支持 `\t/\n/\r/\s`），以及 `--no-fold-upper` 保留原大小写（默认转为大写）。
	- Optional folded output (`--fold`): print a single folded line per query using the current selection, in the form `<query> <UPPER_VALUE_...> <RIR>`; handy for BusyBox pipelines (disabled by default).
	- Supports `--fold-sep <SEP>` to customize the separator (default space; supports `\t/\n/\r/\s`) and `--no-fold-upper` to preserve original case (defaults to uppercase).

- 文档新增：续行关键词命中技巧（推荐策略 A：`-g` + 块模式 `--grep` + `--fold`；可选策略 B：行模式 OR + `--keep-continuation-lines` + `--fold`），并说明行模式为“逐行”匹配，`\n` 不跨行。
	- CN: `docs/USAGE_CN.md#续行关键词命中技巧推荐策略与陷阱` | EN: `docs/USAGE_EN.md#continuation-line-keyword-capture-tips-recommended`

## 即将发布 / Unreleased (v3.2.2)

- 安全加固（九大领域）与可选安全日志：
	- 新增 `--security-log`（默认关闭）：将安全事件输出到 stderr，便于调试与审计；不改变既有 stdout 输出契约。
	- 安全日志已内置限频：避免在攻击/洪泛时刷屏（约 20 条/秒，超额抑制并定期汇总提示）。
	- 领域覆盖：内存安全辅助（safe_ 系列）、改进的信号处理与清理、输入/查询与长度/字符集校验、网络连接与重定向安全（含目标校验/环路/注入识别）、响应净化与校验（移除控制/ANSI 序列等）、配置校验、线程安全与缓存一致性（加锁/失效）、协议级异常检测与告警。
	- 版本命令与帮助已更新（`--version`、`--help`）。

English:
- Security hardening (nine areas) and optional diagnostics:
	- Add `--security-log` (off by default): emits SECURITY events to stderr for diagnostics; stdout output contract unchanged.
	- Security log output is rate-limited to avoid flooding (~20 events/sec with suppression summaries).
	- Coverage: safer memory helpers, improved signal handling/cleanup, strict input/query validation, secure redirects (target validation/loop/injection checks), response sanitization/validation (strip control/ANSI), configuration validation, thread-safety with cache integrity, and protocol anomaly detection.
	- Version/help text updated.

## 示例图 / Example

折叠前后（示意）：

![Fold before/after](docs/images/fold-before-after.svg)

## 开发路线图 / Roadmap

- 条件输出（Phase 2.5）RFC（中文）：`docs/RFC-conditional-output-CN.md`

## 构建 / Build

- Linux / macOS / MSYS2(Windows) / WSL:
	- 默认构建 / default build:
		- `make`
	- 静态链接（可选，取决于工具链是否支持 glibc/musl 静态）：
		- `make static`

提示 / Notes:
- Windows 原生 MinGW 亦可，但推荐 MSYS2 或 WSL 以获得接近 Linux 的构建环境。
- 若静态链接失败，属于平台库限制，建议继续使用动态链接目标。

## 运行示例 / Run examples

- `./whois-client 8.8.8.8`
- `./whois-client --host apnic -Q 103.89.208.0`
- `cat ip_list.txt | ./whois-client -B --host apnic`

## 打包 / Packaging (Windows PowerShell)

- `tools/package_artifacts.ps1 -Version 3.2.1`
- 产物布局 / Layout: `dist/whois-<version>/{bin/<arch>, docs, src, licenses}`，并生成 `SHA256SUMS.txt` 与 ZIP。

## CI

- GitHub Actions（Ubuntu）自动构建；推送形如 `vX.Y.Z` 的标签会自动创建 Release 并附带二进制与校验文件。

## 默认重试节奏 / Retry pacing defaults

- timeout: 5s, retries: 2, retry-interval: 300ms, retry-jitter: 300ms
- 可通过参数调整，详见 USAGE 文档。

## 许可证 / License

- GPL-3.0-or-later

## 远程交叉编译 / Remote cross-compilation

- 推荐在 Ubuntu 虚拟机进行静态交叉编译，使用脚本：
	- 本地启动器 / Local launcher: `tools/remote/remote_build_and_test.sh`
	- 远端构建器 / Remote builder: `tools/remote/remote_build.sh`
- 目标架构 / Targets: `aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64`
- 产物输出 / Artifacts: `out/artifacts/<timestamp>/build_out/whois-*`
 - 产物输出 / Artifacts: `out/artifacts/<timestamp>/build_out/whois-*`
 - 存储与清理 / Storage & cleanup:
	 - 自 v3.2.0 起，`out/artifacts/` 已加入 `.gitignore`，不再被版本库跟踪；如需本地清理旧运行，可使用 `tools/dev/prune_artifacts.ps1`（支持 `-DryRun`）。
	 - Since v3.2.0, `out/artifacts/` is ignored by Git and no longer tracked; to clean up old local runs, use `tools/dev/prune_artifacts.ps1` (supports `-DryRun`).
- 可选同步 / Optional sync:
	- 可以使用 `-s <dir>` 将 whois-* 同步到外部目录，例如：`D:/LZProjects/lzispro/release/lzispro/whois`
	- 配合 `-P 1` 可在同步前清理该目录的非 whois-* 文件，从而实现“仅保留 7 个架构二进制”的要求。

- 冒烟测试 / Smoke tests:
	- 默认联网（`SMOKE_MODE=net`），不再将公网地址替换为私网地址；失败会如实反映超时/连不通场景
	- 自定义目标可用环境变量 `SMOKE_QUERIES` 或参数 `-q "8.8.8.8 example.com"` 指定（空格分隔）
