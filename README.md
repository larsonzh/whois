# whois (v3.2.0)

## 概览 / Overview

- 轻量高性能 C 语言 whois 客户端，支持：
	- 批量标准输入模式（`-B`），当 stdin 不是 TTY 时自动启用
	- 适合 BusyBox 管道的稳定输出契约：每条查询首行标题、末行 Authoritative RIR
	- 非阻塞连接、I/O 超时、轻量重试、跟随转发（带循环保护）
- Lightweight, high-performance whois client in C with:
	- Batch stdin mode (`-B`), implicitly enabled when stdin is not a TTY
	- Stable output contract for BusyBox pipelines: header per query and authoritative RIR tail
	- Non-blocking connect, IO timeouts, light retries, and referral redirect following with loop guard

文档 / Docs:
- 中文 / Chinese: `docs/USAGE_CN.md`
- English: `docs/USAGE_EN.md`
 - 操作与发布手册 / Operations (CN): `docs/OPERATIONS_CN.md`
 - Operations (EN): `docs/OPERATIONS_EN.md`

## v3.2.0 速览 / What's new

- 正则过滤与选择模式：新增 `--grep/--grep-cs`，支持行/块选择（`--grep-line`/`--grep-block`），并提供续行展开开关（`--keep-continuation-lines`）。
- 兼容原有 -g/--title 语义：`-g` 为不区分大小写的“前缀匹配”（非正则）；处理顺序保持为“先按标题投影，再做正则过滤”。
- BusyBox 友好默认：输出契约不变；在 lzispro 中默认使用“行模式 + 不展开续行”，可通过环境变量回退或切换。
- 稳定性增强：缓存连接存活性改用 `getsockopt(SO_ERROR)` 校验并在异常时清理。
- 文档与流程：中英 USAGE 与操作手册更新；完善 Gitee Release 发布与“手动补发”工作流。
- 产物：除 CI 动态 x86_64 外，提供 7 个全静态多架构二进制；附远程交叉编译与冒烟测试脚本。

参考与下载
- 发布说明 / Release notes: `RELEASE_NOTES.md#320`
- 使用说明：`docs/USAGE_CN.md` | `docs/USAGE_EN.md`
- GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.2.0
- Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.2.0）

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

- `tools/package_artifacts.ps1 -Version 3.2.0`
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
- 可选同步 / Optional sync:
	- 可以使用 `-s <dir>` 将 whois-* 同步到外部目录，例如：`D:/LZProjects/lzispro/release/lzispro/whois`
	- 配合 `-P 1` 可在同步前清理该目录的非 whois-* 文件，从而实现“仅保留 7 个架构二进制”的要求。

- 冒烟测试 / Smoke tests:
	- 默认联网（`SMOKE_MODE=net`），不再将公网地址替换为私网地址；失败会如实反映超时/连不通场景
	- 自定义目标可用环境变量 `SMOKE_QUERIES` 或参数 `-q "8.8.8.8 example.com"` 指定（空格分隔）
