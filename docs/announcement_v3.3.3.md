# whois v3.3.3 公告 / Announcement

*许可证迁移 MIT、代理访问 RIR、跨平台可移植性收口 / MIT license, proxy access to RIR, cross-platform portability closure*

v3.3.3 在保持默认直连与 BusyBox 管道输出契约不变的前提下，完成项目许可证由 GPL-3.0-or-later 迁移至 MIT（WP-12）、Windows/跨平台可移植性收口，并交付完整的代理访问 RIR 站点能力（WP-13A–WP-13D：HTTP/HTTPS CONNECT 与 SOCKS4/4a/5/5h，含静态 OpenSSL 3.5.8 的 HTTPS proxy TLS）。官方静态制品默认启用 TLS，`--help` 直接报告当前 HTTPS proxy TLS backend，终端用户无需了解内部构建开关。

## 亮点 / Highlights

- 许可证迁移（WP-12）：项目许可证由 GPL-3.0-or-later 改为 MIT，同步根 `LICENSE`、README 许可证说明及 23 个源/头文件的 SPDX/License 标识；第三方代码、数据、工具输出与依赖继续遵守各自许可证，不因根 LICENSE 变更自动重许可。
	- License migration (WP-12): the project license changes from GPL-3.0-or-later to MIT, synchronizing the root `LICENSE`, README license notice, and SPDX/License identifiers across 23 source/header files; third-party code, data, tool output, and dependencies remain under their respective licenses and are not automatically relicensed.
- 代理访问 RIR（WP-13）：新增 HTTP/HTTPS CONNECT 与 SOCKS4/4a/5/5h 代理协议；`--proxy-family` 仅控制代理端点，凭据来自专用环境变量或代理 URL userinfo，代理端与目标端 DNS、失败与指标完全分离。HTTPS 代理以静态 OpenSSL 3.5.8 建立经证书/主机名验证的 TLS（TLS 1.2 下限、CONNECT 前 TLS、peer/SNI/hostname/IP 验证），信任源为嵌入式 Mozilla CA `2026-08-13`（121 张证书，SHA-256 `f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9`，MPL-2.0）；`SSL_CERT_FILE` 可显式覆盖且读取失败 fail-close。`socks5h`/`socks4a` 由代理远程解析，`socks5`/`socks4` 保留本地解析；`socks5` 的候选级 general-failure/address-type-unsupported 会继续下一个本地地址，远程解析模式因目标 IP 不可观测而显示 `unknown`；A/B 阶段已并入共享 deadline、partial I/O 处理与 per-hop `NO_PROXY` 绕过。
	- Proxy access to RIR (WP-13): adds HTTP/HTTPS CONNECT and SOCKS4/4a/5/5h proxy schemes. `--proxy-family` selects only the proxy endpoint, credentials come from dedicated environment variables or proxy-URL userinfo, and proxy-side DNS/failures/metrics are fully separated from the target. HTTPS proxies use static OpenSSL 3.5.8 with verified TLS (TLS 1.2 minimum, TLS before CONNECT, peer/SNI/hostname/IP verification) trusting the embedded Mozilla CA of 2026-08-13 (121 certificates, SHA-256 `f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9`, MPL-2.0); `SSL_CERT_FILE` overrides explicitly and fails closed on read errors. `socks5h`/`socks4a` resolve remotely while `socks5`/`socks4` keep local resolution; candidate-level general-failure/address-type-unsupported advances `socks5` to the next local address, while remote-resolution modes show `unknown` because the target IP is unobservable; the A/B stages also deliver a shared deadline, partial-I/O handling, and per-hop `NO_PROXY` bypass.
- 产品交付收口：官方远程静态构建与 full/one-click release 默认或显式启用 `WHOIS_TLS=1`，`--help` 报告当前 HTTPS proxy TLS backend；普通本地 `make` 与显式 `WHOIS_TLS=0` 保留无 OpenSSL 兼容路径；中英文 USAGE 提供公网 CA 与私有 `SSL_CERT_FILE` 的 HTTPS 代理示例。
	- Product delivery closure: official remote statics and full/one-click releases default to or explicitly set `WHOIS_TLS=1`, and `--help` reports the current HTTPS proxy TLS backend; normal local `make` and explicit `WHOIS_TLS=0` retain an OpenSSL-free compatibility path; the bilingual usage guides provide public-CA and private `SSL_CERT_FILE` HTTPS-proxy examples.
- Windows/跨平台可移植性：集中 `wc_strings.h` 大小写比较映射，修正 `ssize_t`、平台头、sleep 与 64 位毫秒计时的条件编译，并补齐 `nanosleep` 的 POSIX feature-test macro、显式零初始化 retry metrics 的 `timespec` 起点。
	- Windows/cross-platform portability: centralizes case-insensitive comparison in `wc_strings.h` and fixes conditional handling for `ssize_t`, platform headers, sleeps, and 64-bit millisecond timing, plus the POSIX feature-test macro required by `nanosleep` and explicit zero-initialization of the retry-metrics `timespec` origin.
- 验证（2026-09-03）：WP-13B-1/2/3、WP-13C、WP-13D 的 Vx A/B 均 8/8 PASS；最终 Strict `lto-auto` 九架构构建/9 hash/Golden/referral、Batch 4/4、Selftest 5/5、12×6 redirect 72/72 与 CIDR body 4/4+draft 9/9 全 PASS；最终默认 TLS 同步轮零告警（`out/artifacts/20260903-045122`，360s），九制品 SHA-256 独立复算与清单一致、双 release 目录清单逐字一致、Windows 两目标均为 full-static。
	- Verification (2026-09-03): Vx A/B pass 8/8 for WP-13B-1/2/3, WP-13C, and WP-13D; the final Strict `lto-auto` nine-architecture build/9-hash/Golden/referral, Batch 4/4, Selftest 5/5, 12x6 redirect 72/72, and CIDR body 4/4 plus draft 9/9 all pass. The final default-TLS synchronized round is warning-free (`out/artifacts/20260903-045122`, 360s), all nine artifact SHA-256 hashes recompute to the manifest, both release directories match byte-for-byte, and both Windows targets are full-static.

## 兼容性 / Compatibility

- 默认行为零变化：默认直连、stdout/stderr 分工、RIR referral、DNS-health、batch strategy 与 retry metrics 契约保持不变；代理能力全部 opt-in。
- 官方制品体积显著增大（各架构约 2–6 MiB）：静态链接 OpenSSL 3.5.8 并嵌入 121 张 CA 证书，这是单文件零运行时依赖策略的固有代价；HTTPS 代理依赖嵌入式 CA，除非设置 `SSL_CERT_FILE`。
- 响应读取仍以 `--buffer-size`（默认 512 KiB）为实际接收上限，超限时静默截断且不标记截断状态（继承自 v3.3.2，本版未改变行为）。

English summary:
- License migration (WP-12): GPL-3.0-or-later → MIT, with root license, README notice, and 23 source/header SPDX identifiers synchronized.
- Proxy access to RIR (WP-13A–13D): HTTP/HTTPS CONNECT and SOCKS4/4a/5/5h; HTTPS proxies use static OpenSSL 3.5.8 TLS with the embedded Mozilla CA (2026-08-13, 121 certs) and fail-closed `SSL_CERT_FILE` override.
- Product delivery closure: official statics default to `WHOIS_TLS=1` and `--help` reports the TLS backend; local `make` and explicit `WHOIS_TLS=0` keep an OpenSSL-free path.
- Windows/cross-platform portability closure plus full Vx A/B and nine-architecture strict/9-hash/Golden/referral validation (2026-09-03).

## 获取与使用 / Get started

- 使用说明：`docs/USAGE_CN.md` | `docs/USAGE_EN.md`
- 快速体验：
```bash
# 经 HTTP 代理查询（CONNECT 隧道）
whois-x86_64 --proxy http://10.0.0.246:8080 8.8.8.8

# 经 HTTPS 代理查询（TLS 到代理，再 CONNECT；WHOIS 隧道内仍为明文）
whois-x86_64 --proxy https://proxy.example.com:8443 8.8.8.8

# 企业私有 CA：显式提供 SSL_CERT_FILE（读取失败 fail-close）
SSL_CERT_FILE=/path/to/private-ca.pem whois-x86_64 --proxy https://proxy.example.com:8443 8.8.8.8

# SOCKS5h：由代理远程解析目标域名
whois-x86_64 --proxy socks5h://proxy.example.com:1080 example.com

# 查看当前制品能力（HTTPS proxy TLS backend: enabled|disabled）
whois-x86_64 --help
```

## 下载 / Downloads

- GitHub Release: https://github.com/larsonzh/whois/releases/tag/v3.3.3
	- GitHub release page with nine static binaries and checksums
- Gitee Releases: https://gitee.com/larsonzh/whois/releases （查找 v3.3.3）
	- Gitee release page with mirrored links

## 文档 / Docs

- 使用说明 / Usage: `docs/USAGE_CN.md` | `docs/USAGE_EN.md`
- 发布说明 / Release notes: `RELEASE_NOTES.md#333`
- 操作与发布 / Operations: `docs/OPERATIONS_CN.md` | `docs/OPERATIONS_EN.md`

---

可将以上内容直接复制为置顶 issue 的正文；如需更精简版本，可仅保留“亮点”与“下载”两节。
You can copy the above as the pinned issue content; for a shorter version, keep only Highlights and Downloads.
