# whois v3.4.0 公告 / Announcement

*紧凑主程序 + 完整 TLS companion：按需部署 HTTPS 能力 / Compact main binary + full TLS companion: deploy HTTPS capability only when needed*

v3.4.0 将官方九架构制品拆分为 9 个紧凑版与 9 个完整 TLS 版。默认 `whois-*` 不再携带 OpenSSL 3.5.8 和 121 张 Mozilla CA 证书；需要 HTTPS 代理时，将同架构、同版本的 `whois-*-tls` 放在同一目录，紧凑版会透明转交。TLS 版也可直接独立运行。

v3.4.0 splits the official nine-architecture delivery into nine compact and nine full TLS binaries. Default `whois-*` files no longer carry OpenSSL 3.5.8 or the 121-certificate Mozilla CA bundle. To use an HTTPS proxy, place the matching same-version `whois-*-tls` file in the same directory; the compact binary delegates transparently. The TLS binary can also run independently.

## 亮点 / Highlights

- 更小的默认制品：直连、HTTP CONNECT、SOCKS4/4a/5/5h 与全部非 HTTPS 功能只需紧凑版。
  - Smaller defaults: direct connections, HTTP CONNECT, SOCKS4/4a/5/5h, and every non-HTTPS path need only the compact binary.
- 完整 TLS 能力保留：`-tls` 版继续静态链接 OpenSSL 3.5.8，并嵌入 Mozilla CA `2026-08-13`（121 张证书）；`SSL_CERT_FILE` 私有 CA 覆盖与证书/主机名验证契约不变。
  - Full TLS capability remains available: `-tls` binaries retain static OpenSSL 3.5.8 and the Mozilla CA bundle dated 2026-08-13 (121 certificates); private-CA override through `SSL_CERT_FILE` and certificate/hostname verification are unchanged.
- 安全的同目录转交：紧凑版不搜索 `PATH`，只接受同目录、同版本 companion。缺失、版本不匹配、不可执行或非 TLS 文件均在联网前 fail-close，退出码为 37。
  - Safe same-directory delegation: the compact binary never searches `PATH` and accepts only a same-directory, same-version companion. Missing, mismatched, non-executable, or non-TLS files fail closed before network access with exit code 37.
- 批量管道保持兼容：转交发生在读取 stdin 前并且每个进程只发生一次；BusyBox 管道、自动批量、显式 `-B` 与所有 batch strategy 保持原有 stdout/stderr 和退出状态契约。
  - Batch pipelines remain compatible: delegation occurs before stdin is read and only once per process. BusyBox pipelines, automatic batch mode, explicit `-B`, and every batch strategy retain their stdout/stderr and exit-status contracts.
- 两种制品均可独立使用：紧凑版独立覆盖非 HTTPS 场景；TLS 版独立覆盖全部场景。
  - Both artifacts are independently useful: compact covers all non-HTTPS cases, while TLS covers every case.
- 完整发布集合为 18 个静态二进制：7 个 Linux 架构加 win32/win64，每个架构各有 compact 与 `-tls`。
  - The complete release set contains 18 static binaries: seven Linux architectures plus win32/win64, each with compact and `-tls` variants.
- 另提供 `whois-x86_64-gnu-tls` CI 兼容构建：它动态依赖 glibc、OpenSSL 3 的 `libssl` 与 `libcrypto`，只提供 TLS 完整版，不计入 18 个全静态制品。
  - An additional `whois-x86_64-gnu-tls` CI compatibility build dynamically depends on glibc plus OpenSSL 3 `libssl` and `libcrypto`. It is TLS-only and is not part of the 18 fully static artifacts.

## 快速使用 / Quick start

```bash
# 直连或非 HTTPS 代理：只部署紧凑版
whois-x86_64 8.8.8.8
whois-x86_64 --proxy socks5h://proxy.example.com:1080 example.com

# HTTPS 代理：两个同版本文件放在同一目录
#   whois-x86_64
#   whois-x86_64-tls
whois-x86_64 --proxy https://proxy.example.com:8443 8.8.8.8

# TLS 版也可直接运行
whois-x86_64-tls --proxy https://proxy.example.com:8443 8.8.8.8

# HTTPS 批量管道：只转交一次，stdin 保持不变
printf "8.8.8.8\n1.1.1.1\n" | whois-x86_64 -B --batch-strategy raw --proxy https://proxy.example.com:8443
```

Windows 对应文件为 `whois-win64.exe` + `whois-win64-tls.exe` 或 `whois-win32.exe` + `whois-win32-tls.exe`。

On Windows, use `whois-win64.exe` with `whois-win64-tls.exe`, or `whois-win32.exe` with `whois-win32-tls.exe`.

## 验证 / Verification

- 2026-09-04 聚焦构建已覆盖 x86_64、win32、win64 的 compact/TLS 六制品、SHA-256 一致性与 Windows full-static。
- v3.4.0 compact/TLS win64 均报告正确版本；两行 HTTPS 批量管道在两者上均完整处理 2 条查询。
- 删除 companion 后，紧凑版在消费 stdin 前以 37 退出，未产生查询输出。
- 最终强制 clean `v3.4.0` 的 Strict `lto-auto` 全矩阵轮 `out/artifacts/20260904-083712` 零编译/LTO 告警，18/18 哈希、Golden、三起点 referral 与同步全 PASS；24/24 冒烟查询头尾配对且异常 0。LoongArch64 已切换到 musl，所有 Linux compact/TLS 均为 static/static-pie，Windows 四制品均为 full-static。
- Focused builds on 2026-09-04 cover all six compact/TLS artifacts for x86_64, win32, and win64, SHA-256 consistency, and Windows full-static mode.
- Both v3.4.0 compact and TLS win64 binaries report the correct version and fully process a two-line HTTPS batch pipeline.
- Removing the companion makes the compact binary exit 37 before consuming stdin, with no query output.
- The final clean `v3.4.0` Strict `lto-auto` full-matrix run at `out/artifacts/20260904-083712` has zero compiler/LTO warnings and passes all 18 hashes, Golden, all three referral origins, and artifact sync; all 24 smoke query headers pair with authoritative tails with zero anomalies. LoongArch64 now uses musl, every Linux compact/TLS artifact is static/static PIE, and all four Windows artifacts are full-static.

## 兼容性 / Compatibility

默认直连、代理协议、RIR referral、DNS health、标题/尾行/折叠格式、stdout/stderr 分工、retry metrics 与 `NO_PROXY` 契约不变。TLS 拆分降低默认下载和存储成本，但实际执行 HTTPS 时仍会运行完整 TLS 程序。

Default direct connections, proxy protocols, RIR referrals, DNS health, header/tail/fold formats, stdout/stderr separation, retry metrics, and `NO_PROXY` contracts are unchanged. The split reduces default download and storage cost, but actual HTTPS execution still runs the full TLS program.

## 下载与文档 / Downloads and docs

- GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.4.0
- 发布正文 / Release body: `docs/release_bodies/v3.4.0.md`
- 使用说明 / Usage: `docs/USAGE_CN.md` | `docs/USAGE_EN.md`
- 操作手册 / Operations: `docs/OPERATIONS_CN.md` | `docs/OPERATIONS_EN.md`
- 代理 RFC / Proxy RFC: `docs/RFC-proxy-access.md`

---

可将以上内容直接用于发布公告或置顶 issue。
This content is ready for a release announcement or pinned issue.