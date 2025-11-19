# Git Bash 远程静态交叉编译与测试（whois 独立仓库）

本工具在 Windows 的 Git Bash 中一键发起远程构建：上传代码（排除 .git 与 dist/out）→ 远端静态跨架构编译 → 可选 QEMU 冒烟测试 → 拉回产物 → 可选同步到 lzispro → 远端清理。

- 本地启动器：`whois/tools/remote/remote_build_and_test.sh`
- 远端构建器：`whois/tools/remote/remote_build.sh`

> 说明：PowerShell 启动器已不再维护，建议使用 Git Bash 版本。

## 前置条件

本地（Windows）
- Git Bash 可用（包含 ssh/scp/tar）
- 建议使用 ssh-agent，或准备好私钥（如 `/d/xxx/id_rsa`）

远端（Ubuntu 虚拟机）
- 已安装 musl 交叉编译器（脚本会优先识别下述绝对路径）：
  - aarch64: `~/.local/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc`
  - armv7: `~/.local/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-gcc`
  - x86_64: `~/.local/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc`
  - x86(i686): `~/.local/i686-linux-musl-cross/bin/i686-linux-musl-gcc`
  - mipsel: `~/.local/mipsel-linux-musl-cross/bin/mipsel-linux-musl-gcc`
  - mips64el: `~/.local/mips64el-linux-musl-cross/bin/mips64el-linux-musl-gcc`
  - loongarch64: `~/.local/loongson-gnu-toolchain-.../loongarch64-linux-gnu-gcc`
- 可选：`upx`（压缩 aarch64/x86_64）、`qemu-user-static`（冒烟测试）、`file`（产物信息）

## 快速开始

默认仅编译（不跑仿真），零参数即可：

```bash
cd /d/LZProjects/whois
./tools/remote/remote_build_and_test.sh
```

指定私钥（单一位置参数即可，等价于 -k；路径含空格请用引号）：

```bash
./tools/remote/remote_build_and_test.sh "/d/Larson/id_rsa"
```

开启 QEMU 冒烟测试（-r 1）：

```bash
./tools/remote/remote_build_and_test.sh -r 1
```

仅编译部分目标（更快）：

```bash
./tools/remote/remote_build_and_test.sh -t "aarch64 x86_64 loongarch64"
```

同步到 lzispro 中仅保存二进制的目录（例如 `D:/LZProjects/lzispro/release/lzispro/whois`），并可选清理非 whois-* 文件：

```bash
./tools/remote/remote_build_and_test.sh -s "/d/LZProjects/lzispro/release/lzispro/whois" -P 1
```

运行完成，产物将被拉回到：`out/artifacts/<时间戳>/build_out/`，包括：
- 各架构二进制：`whois-<arch>`（7 个架构：`aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64`）
- `file_report.txt`（file 命令输出汇总）
- `smoke_test.log`（启用 `-r 1` 时生成）

## 参数说明

- `-H <host>`：SSH 主机（默认 10.0.0.199）
- `-u <user>`：SSH 用户（默认 larson）
- `-p <port>`：SSH 端口（默认 22）
- `-k <key>`：SSH 私钥路径（可省略并使用 ssh-agent）
- `-R <remote_dir>`：远端工作根目录（默认 `$HOME/whois_remote`）
- `-t <targets>`：目标架构（默认 `"aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64"`）
- `-r <0|1>`：是否跑 QEMU 冒烟测试（默认 0）
- `-o <output_dir>`：远端产出目录（默认 `out/build_out`）
- `-f <fetch_to>`：本地拉取基目录（默认 `out/artifacts`）
- `-s <sync_to>`：本地同步目录（可指向 `lzispro/.../whois` 以只保留二进制）
- `-P <0|1>`：配合 `-s` 使用，是否在同步前清理目标目录中非 `whois-*` 文件（默认 0）
- `[keyfile]`：单一位置参数，等价于 `-k`

亦可通过环境变量覆盖相应默认值（如 `SSH_HOST` / `SSH_USER` 等）。

## 工作流程（简述）

- SSH 免交互：`StrictHostKeyChecking=accept-new`、`UserKnownHostsFile=/dev/null`、`BatchMode=yes`、`LogLevel=ERROR`
- 远端目录：默认 `$HOME/whois_remote/src`；通过 `-R` 可覆盖
- 上传：`tar` 流式传输（排除 `.git` 和 `out/artifacts`/`dist`）
- 远端构建：`tools/remote/remote_build.sh` 静态编译（`-O3 -s -pthread`），loongarch64 使用 `-static-libgcc -static-libstdc++`
- UPX：对 aarch64/x86_64 存在时压缩
- QEMU：可选逐个二进制冒烟（默认“联网测试”）
  - 默认查询：`8.8.8.8`
  - 可通过环境变量 `SMOKE_QUERIES` 覆盖（空格分隔，如 `SMOKE_QUERIES="8.8.8.8 example.com"`）
  - `SMOKE_MODE` 变量仅保留向后兼容，默认即为 `net`；不会再将公网地址替换为私网地址
  - 当 `CFLAGS_EXTRA` 含 `-DWHOIS_LOOKUP_SELFTEST` 且 `SMOKE_ARGS` 含 `--selftest` 时，smoke 日志中会额外出现 `[LOOKUP_SELFTEST]` 与 `[DNS-HEALTH]` 等行，用于 DNS/lookup 行为 eyeball 调试；这类输出主要面向人工阅读，不建议作为正式发布配置或机器解析输入。
- 回传：拉回 `out/build_out` 到 `out/artifacts/<时间戳>/build_out`
- 可选同步：如设置 `-s`，将 whois-* 同步到指定目录（可配 `-P 1` 只保留二进制）
- 清理：最后删除远端临时目录

## 常见问题与提示

- 私钥路径含空格：请使用引号包裹（Git Bash 路径用正斜杠）。
- 某架构 `not found`：该架构工具链未安装或不在固定路径；可先用 `-t` 构建已安装目标。
- `smoke_test.log` 为空：可能未加 `-r 1`，或远端缺少 `qemu-*-static`。
- `smoke_test.log` 中存在 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` / `[DNS-HEALTH]` / `[LOOKUP_SELFTEST]` 等行属于正常现象，分别对应 DNS 候选/回退路径、缓存计数与健康记忆、自测结果摘要，可在排查 DNS/连接问题时配合 grep 重点查看。
- 静态链接失败：属于平台/库限制；可先使用动态构建（本地 `make`），或调整工具链。

---

如需把默认目标缩减到常用的 `aarch64 x86_64` 以加速，或将同步目录改为其它路径，可直接使用命令行参数覆盖。
