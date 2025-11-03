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