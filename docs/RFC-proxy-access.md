# RFC：RIR 代理访问 / RIR Proxy Access

状态 / Status：WP-13A、WP-13B-1/2/3、WP-13C 与 WP-13D 均已完成实施和生产验收；v3.4.0 起官方九架构交付拆分为不含 OpenSSL/CA 的紧凑主程序与可选 `-tls` 完整伴随程序 / WP-13A, WP-13B-1/2/3, WP-13C, and WP-13D have completed implementation and production acceptance; starting with v3.4.0, each official architecture ships a compact OpenSSL/CA-free main binary and an optional full `-tls` companion.

# 中文版

## 1. 目的

本文定义 WHOIS TCP 连接的代理访问方式，同时保持默认直连行为、referral 语义、DNS 健康记忆、权威 RIR 判定和 stdout 契约不变。

交付顺序如下：

1. WP-13A：冻结契约，并通过本地确定性探针验证协议与依赖假设。
2. WP-13B：基于 transport 抽象交付 HTTP CONNECT 与 SOCKS5/5h。
3. WP-13C：以兼容扩展形式增加 SOCKS4/4a。
4. WP-13D：仅在 TLS 后端通过九架构静态链接门禁后增加 HTTPS proxy。

WP-13A 不改变任何生产网络路径。

### 1.1 v3.4.0 双制品模型

- `whois-<arch>` 是默认紧凑版，可独立完成直连、HTTP CONNECT、SOCKS4/4a/5/5h 与全部非 HTTPS 功能。
- `whois-<arch>-tls`（Windows 为 `whois-winNN-tls.exe`）是嵌入 OpenSSL 与固定 CA 的完整版本，也可脱离紧凑版独立运行。
- 两者同目录部署时，紧凑版解析到 HTTPS 代理后以进程替换方式透明执行同版本 companion；argv、环境、stdin、stdout、stderr 与最终退出码保持不变。
- companion 仅从当前可执行文件所在位置派生，不搜索 `PATH`。缺失、版本不匹配、无法执行或实际不含 TLS 时，必须在代理网络访问前向 stderr 报错并 fail-close，禁止回退直连。
- `WHOIS_TLS=0` 仅生成紧凑版；官方 `WHOIS_TLS=1` 构建编排生成紧凑版与 TLS companion 两份产物。TLS 运行时峰值资源需求不因拆分而消失；拆分主要降低默认文件体积和非 HTTPS 部署成本。
- 最终生产验收（2026-09-04）：审计发现旧 LoongArch64 glibc 构建虽无动态 OpenSSL 依赖，但仍带 ELF interpreter，并在全静态 DNS/NSS 链接时产生运行时 glibc 兼容告警。构建现改用 `loongarch64-linux-musl`，OpenSSL 3.5.8 同步以该 triplet 重建；远程构建对所有 Linux compact/TLS 制品增加静态链接 fail-close 门禁。最终 Strict `lto-auto` 九架构双制品轮 `out/artifacts/20260904-073811` 无编译/LTO 告警，18/18 SHA-256、Golden 与三起点 referral 全 PASS；POSIX/win32/win64 smoke 为 `18/3/3`，24/24 查询标题与权威尾行配对且异常 0。七个 Linux 架构的 compact/TLS 均为 static/static-pie，win32/win64 均为 full-static。

The compact `whois-<arch>` binary independently handles every non-HTTPS path. The full `whois-<arch>-tls` companion embeds OpenSSL and the pinned CA and can also run on its own. When both files share a directory, a configured HTTPS proxy causes the compact process to replace itself with the version-matched companion while preserving argv, environment, standard streams, and the final exit status. Companion lookup never searches `PATH`; missing, mismatched, non-executable, or non-TLS companions fail closed before proxy network access. The split reduces default storage and deployment cost, not the peak resources required while TLS is active.

Final production acceptance (2026-09-04): review found that the former LoongArch64 glibc build had no dynamic OpenSSL dependency but still carried an ELF interpreter and emitted runtime-glibc compatibility warnings for fully static DNS/NSS calls. The application and OpenSSL 3.5.8 builds now use the `loongarch64-linux-musl` triplet, and the remote build fails closed unless every Linux compact/TLS artifact is static or static PIE. The final Strict `lto-auto` nine-architecture dual-artifact run at `out/artifacts/20260904-073811` has no compiler/LTO warnings and passes all 18 SHA-256 checks, Golden, and all three referral origins. POSIX/win32/win64 smoke counts are `18/3/3`, all 24 query headers pair with authoritative tails, and the anomaly count is zero. Both variants for all seven Linux architectures are static/static PIE; win32 and win64 remain full-static.

## 2. 不可破坏的约束

- 仅当用户显式提供 `--proxy`、设置 `WHOIS_PROXY`，或通过 `--proxy-env` 启用通用环境变量发现时才使用代理。
- 已配置但不可用的代理必须 fail-close；客户端不得静默回退到直连。
- 代理端点故障不得更新目标 RIR 的 DNS 健康、backoff、拒绝访问、限流、ERX/IANA 或权威状态。
- 逻辑 chain 仅包含 WHOIS 目标；代理端点和凭据不得进入 stdout。
- referral 必须为当前 hop 的 host 和 port 建立隧道，不得使用原始目标或固定端口 43。
- 单次目标尝试使用一个单调时钟 deadline，覆盖代理 DNS/TCP、可选 TLS、认证与隧道建立。
- 首版代理实现禁用连接缓存；重新启用须具备 transport-aware cache key 并另行评审。

## 3. 配置契约

### 3.1 CLI

| 选项 | 状态 | 契约 |
|---|---|---|
| `--proxy <url>` | 13B 已冻结 | 显式代理，优先级最高；13B 支持 `http`、`socks5` 和 `socks5h`。 |
| `--proxy-env` | 13B 已冻结 | 启用通用 `ALL_PROXY`/`all_proxy` 发现及 `NO_PROXY`/`no_proxy`；未指定时忽略通用代理环境变量。 |
| `--proxy-family auto\|v4\|v6` | 13B 已冻结 | 默认 `auto`；仅控制代理端点地址族，不得隐式复用目标地址族偏好。 |
| `--proxy-allow-insecure-auth` | 13B 已冻结 | 通过明文 `http` 代理发送 HTTP Basic 凭据前必须显式指定。 |
| `--proxy-pass` | 禁止 | 不得通过 argv 接收秘密。 |

`--proxy` 只接受不含 path、query 或 fragment 的绝对 URL。IPv6 代理字面量必须使用方括号。默认端口：`http` 为 8080，`socks5`/`socks5h`/`socks4`/`socks4a` 为 1080，`https` 为 443。未知 scheme 和非法 percent-encoding 必须在 lookup 前失败。

`--proxy` 只改变路由；`-p/--port` 仍指定初始 WHOIS 目标端口，referral 可独立替换后续目标端口。

### 3.2 环境变量优先级

冻结的优先级如下：

1. `--proxy`
2. `WHOIS_PROXY`
3. 仅在指定 `--proxy-env` 时依次读取 `ALL_PROXY`、`all_proxy`
4. 直连

13B 不读取 `HTTP_PROXY` 和 `HTTPS_PROXY`。原始 WHOIS 没有可用于二选一的 URL scheme，而且 POSIX 下大写 `HTTP_PROXY` 存在已知 CGI 注入歧义。

仅当 `--proxy-env` 启用通用环境变量处理时读取 `NO_PROXY`/`no_proxy`。每个 WHOIS hop 都重新计算匹配。首版支持 `*`、精确 host、前导点域名后缀、IPv4 字面量、方括号 IPv6 字面量以及可选精确端口；不支持 CIDR 和任意 glob。

13B 的认证来源冻结如下：

- 首选专用环境变量 `WHOIS_PROXY_USER` 与 `WHOIS_PROXY_PASSWORD`；必须同时存在且均为非空，否则在 lookup 前失败。
- CLI `--proxy` URL 禁止 userinfo，防止凭据进入 shell history 和进程列表。
- 仅来自 `WHOIS_PROXY`、`ALL_PROXY` 或 `all_proxy` 的代理 URL 可为兼容性携带 percent-encoded `username:password@`；username 与 password 必须均为非空。
- 专用凭据变量与环境 URL userinfo 同时存在属于歧义配置，必须 fail-fast，不得静默覆盖或拼接来源。
- 13B 不支持凭据文件、交互式提示或 OS 密钥链；后续增加任何来源均须单独评审。

环境继承仍可能暴露秘密，因此使用文档必须建议最小化子进程继承。测试可使用内存凭据，但报告只能包含 case 名称。

## 4. DNS 与地址族契约

- `http://` 和 `socks5://` 使用本地目标解析；现有目标候选顺序、地址族控制和健康记忆保持权威。
- `socks5://` 的 SOCKS5 `general-failure` 与 `address-type-unsupported` 是当前数值目标候选的失败，可继续下一个本地候选；认证、规则拒绝、命令/协议错误仍为 terminal。该放宽不适用于 `socks5h://`。
- `socks5h://` 将域名发送给代理。由于无法观测代理最终选择的目标地址族，13B 中它与 `--ipv4-only`、`--ipv6-only`、per-RIR family override 及 candidate fallback 控制不兼容；这些组合必须在 lookup 前失败。
- `--proxy-family=auto` 使用 `AF_UNSPEC` 独立解析代理端点；`v4`/`v6` 分别限制为 `AF_INET`/`AF_INET6`。数值代理字面量与显式 family 不匹配时必须在拨号前失败。
- HTTP CONNECT 使用数值目标候选；IPv6 authority 编码为 `[address]:port`。
- SOCKS5 对 IPv4 使用 ATYP 1、IPv6 使用 ATYP 4，仅 `socks5h` 远程 DNS 使用 ATYP 3。
- 远程 DNS 尝试因地址族未知，绝不更新目标 host+family 健康状态。

## 5. 协议契约

### 5.1 HTTP CONNECT

请求行与 Host header 使用相同 authority：

```text
CONNECT <authority> HTTP/1.1\r\n
Host: <authority>\r\n
Proxy-Connection: keep-alive\r\n
\r\n
```

任意 2xx 响应建立隧道。`407` 分类为 `proxy-auth-required`；其他 4xx 响应属于稳定代理拒绝分类；5xx 响应属于代理上游故障。响应 header 必须有上限，并在发送任何 WHOIS 字节前完成解析。

### 5.2 SOCKS5

客户端提供无认证方式，并仅在存在凭据时提供 username/password 认证。随后使用当前 WHOIS 目标和端口发送 CONNECT。REP 值在内部保持可区分，不得折叠为 RIR 拒绝或响应分类。

必须提供的分类为 `succeeded`、`general-failure`、`ruleset-denied`、`network-unreachable`、`host-unreachable`、`connection-refused`、`ttl-expired`、`command-unsupported`、`address-type-unsupported` 和 `unknown-reply`。

### 5.3 SOCKS4/4a 与 HTTPS

SOCKS4/4a 延后至 WP-13C。SOCKS4 仅支持 IPv4 目标；SOCKS4a 远程 DNS 不代表支持 IPv6。

SOCKS4 保留本地目标解析：严格 IPv6-only 控制与协议能力冲突，必须在查询前 fail-fast，不能静默忽略或降级为 IPv4。仍包含 IPv4 回退的 IPv6-first 偏好合法；IPv6 候选由协议能力过滤后继续 IPv4 候选。SOCKS5 支持 IPv4 与 IPv6 数值目标，目标 family 控制继续生效。SOCKS5h/SOCKS4a 的目标 family 由代理端解析决定，客户端无法强制或验证，因此显式目标 family 控制继续按配置冲突拒绝。`--proxy-family` 始终只控制代理端点，不参与目标 family 决策。

HTTPS proxy 延后至 WP-13D。其含义是客户端到 HTTP 代理之间使用 TLS，再执行 CONNECT；隧道内的 WHOIS 仍为明文 TCP。证书与主机名验证是强制要求，不计划提供不安全验证模式。

WP-13D 的默认信任源冻结为构建时固定并嵌入静态二进制的 Mozilla CA bundle；bundle 来源、版本日期、SHA-256 与许可证须进入构建清单和 release 审计。该设计保持九架构单文件分发，并避免交叉编译 OpenSSL 的 `OPENSSLDIR` 泄漏为运行时路径。非空 `SSL_CERT_FILE` 可显式覆盖嵌入 bundle，以支持企业代理私有 CA；覆盖文件无法读取、为空或不含可加载证书时必须在连接前 fail-close，不得回退到嵌入 bundle。未设置覆盖时只使用嵌入 bundle，不探测平台相关默认路径或 Windows 证书库。CA 更新至少每月检查一次；Mozilla CA 数据或适用安全公告变化时须更新固定摘要并重跑九架构 TLS、Golden/referral 与发布哈希门禁。

## 6. Transport 与超时边界

WP-13B 首先抽取无业务副作用的 endpoint dialer，以及具有 close、wait、read、write 操作的 transport 接口。现有直连适配器保留当前指标与 DNS 健康语义；代理适配器拥有代理端点尝试，且不得调用目标健康 hook。

所有操作消费同一个绝对单调 deadline；任一阶段不得重置完整 timeout。partial write、EOF、EINTR、非阻塞 readiness 和 TLS WANT_READ/WANT_WRITE 必须由 transport 层处理，而不是由代理协议 parser 处理。

既有 `attempts` 元数据统计实际 TCP 连接尝试：直连模式统计目标 socket，代理模式统计代理端点 socket。TLS 与协议消息不增加 attempts。代理阶段详情仅在启用 debug 或 retry metrics 时通过脱敏 stderr 诊断输出。

## 7. 错误与秘密处理

代理 TCP、TLS、认证、协议和目标连接回复均使用稳定内部分类。它们映射到既有 lookup failure 退出契约，但不得成为 WHOIS 响应正文，也不得参与权威 RIR 回退。

日志和产物可包含代理 scheme、脱敏 host、port、phase 与稳定分类；不得包含密码、完整 userinfo、`Proxy-Authorization` 或原始认证帧。由 URL 派生的错误文本必须先通过同一脱敏路径再输出。

认证失败、证书失败、协议格式错误和不支持组合不得重试。代理 TCP timeout 与瞬态 I/O 可消费既有有界连接重试预算；每次重试必须新建隧道。

## 8. WP-13A 可执行证据

运行确定性协议探针：

```powershell
python tools/test/proxy_protocol_spike.py
```

该探针仅使用 IPv4 loopback，验证精确 HTTP CONNECT authority、HTTP 状态保留、SOCKS5 IPv4/IPv6/domain 编码、username/password 协商、自定义端口和 REP 保留，以及 SOCKS4 IPv4/USERID、SOCKS4a domain 和响应码保留，并写入 `out/artifacts/proxy_protocol_spike/<timestamp>/report.json`。

为每个远程编译器提供目标 OpenSSL 参数后，分别运行 TLS 静态链接探针：

```bash
CC=aarch64-linux-musl-gcc \
OPENSSL_CFLAGS='-I/path/to/include' \
OPENSSL_LIBS='-L/path/to/lib -lssl -lcrypto -lz -ldl -pthread' \
tools/test/proxy_tls_dependency_spike.sh --target aarch64
```

探针要求全静态链接，并引用 TLS client setup、peer verification、SNI 和 hostname verification API。后端缺失或只能动态链接的结果为 `unavailable`，不得据此削弱验证或移除静态构建门禁。

## 9. Ready 门禁

本 RFC 与协议探针通过评审后，WP-13B-1 方可进入任务定义设计。代理端点 family 与 13B 凭据来源现已冻结；生产认证仍须由确定性配置测试覆盖后才可进入实现。仅当同一获批后端的 TLS 探针通过七个 POSIX 目标及 win32/win64，且其许可证、CVE 与更新策略均已记录后，WP-13D 才能解除 blocked。

### 9.1 WP-13D TLS 依赖门禁回填（2026-09-01）

- 获批后端为 OpenSSL 3.5.8 LTS，许可证 Apache-2.0；OpenSSL 3.5 LTS 官方支持至 2030-04-08。源码归档 SHA-256 为 `a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2`，发布签名验证链到固定 OpenSSL 主指纹 `B146647E45A7B33947AB226B2A2C87D161692D40`。
- `tools/remote/bootstrap_openssl_static.sh` 从同一已验证源码在隔离 prefix 下构建 `aarch64/armv7/x86_64/x86/mipsel/mips64el/loongarch64/win32/win64`，使用 `no-shared no-dso no-tests`；最终统一矩阵 9/9 PASS，证据为 `out/artifacts/proxy_tls_dependency_matrix/20260901-072331`。
- 七个 POSIX 探针均无 ELF interpreter 或 `NEEDED`；win32/win64 PE 探针均无 `libssl`/`libcrypto` DLL 依赖。每个目标保存编译器与 Configure manifest、`configdata.pm --dump`、静态库和探针 SHA-256、平台依赖审计及 SPDX 2.3 文档。
- 维护策略：每月复核 OpenSSL security advisories/CVE 与 3.5 LTS 最新补丁；出现影响所用 TLS client、X.509、证书/主机名验证或静态链接路径的安全发布时，升级固定版本并完整重跑九架构构建、探针、依赖审计、哈希和 SPDX 门禁。不得继续使用停止支持或存在未处置适用高严重度漏洞的版本。
- 生产 CA 快照固定为 curl CA Extract 发布的 Mozilla bundle `2026-08-13`（121 张证书，SHA-256 `f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9`，MPL-2.0）。`tools/dev/generate_ca_bundle.py` 在摘要和证书计数均匹配后确定性生成 `src/core/ca_bundle_data.c`；来源与 Mozilla/Firefox name-constraints 不随 PEM 转换保留的边界记录于 `docs/registry-snapshots/mozilla-ca-2026-08-13.md`。
- `WHOIS_TLS=1` 构建从每目标 OpenSSL 3.5.8 prefix 的隔离 pkg-config 元数据解析静态参数，默认构建继续无 OpenSSL 依赖。初始 TLS/LTO 九架构依赖矩阵 9/9 PASS（`out/artifacts/20260901-170601`）；2026-09-04 复核进一步将 LoongArch64 从 glibc 切换到 musl，消除 ELF interpreter、`libc.so.6` NEEDED 与静态 DNS/NSS 运行时兼容告警。最终 18 个 compact/TLS 制品均通过平台静态依赖门禁（`out/artifacts/20260904-073811`）。
- 因此 TLS 依赖门禁已解除，WP-13D 可进入独立 Vx 任务定义设计与 ready 评审；这不表示 HTTPS proxy 已实现，也不替代下述生产验收。

生产验收仍须通过 x86_64/win32/win64 聚焦合同、九架构 Strict 构建、Golden/referral、Batch/Selftest/CIDR/Redirect/Step47、默认直连输出冻结，并同步中英文使用文档。

## 10. WP-13B-1 下次开工清单

状态：**本轮已执行完成（SESSION=PASS / A=PASS / B=PASS）**。执行窗口 `2027-06-24 ~ 2027-07-07`（实际运行 2026-08-29），使用 `schemaVersion=vx-draft`、`strict-enforce`、event-only 串行 A/B；active start-file 为 `testdata/unattended_start/active/unattended_ab_start_20270624-20270707.md`。运行记录见下方“执行回填”。

### 10.1 Checklist A：endpoint dialer policy

- 任务定义：`testdata/autopilot_code_step_tasks_20270624_20270630.json`
- 目标：抽取 `wc_net_dial_endpoint` 及显式 endpoint-family/health policy，并用兼容 wrapper 保持 `wc_dial_43` 的直连行为。
- 非目标：不增加代理 CLI、协议握手、认证或 TLS；不改变 stdout、RIR referral、目标 DNS 健康和 retry metrics 契约。
- 冻结 target set：`net_header` = `include/wc/wc_net.h`（existing c-header）；`net_source` = `src/core/net.c`（existing c-source）；`defaultTarget=net_source`。
- `target_set_sha256=7918987e6f12e6cde433c258b93b30e3218819e48e2292a5693c096eecf94b08`。
- D1 声明 policy/API；D2 抽取实现并保留 legacy wrapper；D3 接入 family conflict 与 health gating；D4 为设计期确认的最小 noop。

编制期门禁：TODO-free/编码、SyntaxOnly、D1-D4、无 RoundTag 全定义严格检查、三项 Vx 专项安全回归均 PASS。A effective target set 已纳入聚焦编译；A+B effective target set 的最终九架构 `lto-auto` 构建、9/9 本地 hash、Linux/QEMU 与 win32/win64 smoke、Golden、三起点 referral、Step47 preflight 5/5 和 preclass table guard 均 PASS。归档证据：`out/artifacts/wp13b1_validation/20260829-120009`。

### 10.2 Checklist B：bare transport wiring

- 任务定义：`testdata/autopilot_code_step_tasks_20270701_20270707.json`
- 目标：创建裸字节 transport 合同与实现，并将 lookup send/recv/close 接到该适配器，保持 fd 所有权、timeout、buffer、signal、错误和 close reason 不变。
- 非目标：不实现 HTTP CONNECT、SOCKS、TLS、代理配置或连接复用。
- 冻结 target set：`net_header`、`net_source` 与 A 相交；新增 `transport_header` = `include/wc/wc_transport.h`（create c-header）、`transport_source` = `src/core/transport.c`（create c-source）；`lookup_send` = `src/core/lookup_exec_send.c`、`lookup_recv` = `src/core/lookup_exec_recv.c`（existing c-source）；`defaultTarget=lookup_send`。
- `target_set_sha256=1d22100e1bb2b1966509b93d5cbc3bacc383cd9833ef72a42c547e35e946a667`。
- D1/D2 创建 transport declaration/definition；D3/D4 分别迁移 lookup send/recv 路径。

编制期门禁：SyntaxOnly、D1-D4、以 A 为 prerequisite 的链式全定义严格检查及完整 effective payload hash 校验均 PASS；完整编译、Golden/referral、Step47 证据与 10.1 相同。运行期 B 必须保持 `blocked-by-a`，直到 A PASS、A snapshot 完整且 B 启动门禁通过。

**执行回填（2026-08-29 运行，2026-08-30 回填）**

**Checklist A 回填**

| 字段 | 实际值 |
|---|---|
| final status | PASS |
| started_at / completed_at / elapsed | `2026-08-29 12:59:42` → `2026-08-29 18:15:18` / `0d 05:15:37` |
| run_dir | `out/artifacts/dev_verify_multiround/20260829-130015` |
| final result / summary | `out/artifacts/dev_verify_multiround/20260829-130015/final_status.json`（Result=pass, ExitCode=0, 8/8 轮, FailedRoundTags=[]）、`summary.csv` |
| task-static / code-step artifact | 各 D 轮独立 checker 与 code-step 哈希绑定产物（run_dir 内）；无 task-definition repair transaction |
| snapshot manifest / target set SHA-256 | `target_set_sha256=7918987e6f12e6cde433c258b93b30e3218819e48e2292a5693c096eecf94b08`；A 成功快照完整性通过 |
| 事故、自愈、重启摘要 | NONE（无 incident、recovery_attempts=0、无重启） |
| RFC 回填日期 | 2026-08-30 |

**Checklist B 回填**

| 字段 | 实际值 |
|---|---|
| A PASS 与 snapshot 门禁 | PASS（A final_status.json Result=pass, ExitCode=0） |
| final status | PASS |
| started_at / completed_at / elapsed | `2026-08-29 18:14:36` → `2026-08-29 23:38:35` / `0d 05:24:00` |
| run_dir | `out/artifacts/dev_verify_multiround/20260829-181508` |
| final result / summary | `out/artifacts/dev_verify_multiround/20260829-181508/final_status.json`（Result=pass, ExitCode=0, 8/8 轮, FailedRoundTags=[], GeneratedAt=23:37:36）、`summary.csv` |
| task-static / code-step artifact | 各 D 轮独立 checker 与 code-step 哈希绑定产物（run_dir 内）；无 task-definition repair transaction |
| 事故、自愈、重启摘要 | NONE |
| RFC 回填日期 | 2026-08-30 |

**最终收口**

- A/B 总结：A、B 均为一次通过（8/8 轮），无卡滞、无重启、无自动修复；SESSION=PASS。事件票闭环：`a-pass-conclusion-b-started`（T20260829-181518844-f18488a6，handled_at 2026-08-29 18:17:25）、`chat-session-final-status`（chat-final-20260829-233835，handled_at 2026-08-29 23:39:40）；event-only 模式无常规状态票。
- A/B 合计用时：`0d 10:38:54`（session start `2026-08-29 12:59:42` → `2026-08-29 23:38:35`）。
- 运行后 Strict 验证（2026-08-30）：远程编译冒烟同步 + 黄金校验（Strict Version）——`WHOIS_STRICT_VERSION=1 tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -q '8.8.8.8 1.1.1.1 10.0.0.8' -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 -a '' -G 1 -E '' -O 'lto-auto' -K 0 -N 0` → 无告警 + lto 无告警 + Local hash verify: PASS + Golden PASS + referral check: PASS，退出码 0，用时 219s，日志目录 `out/artifacts/20260830-001936`。
- 完成后复核未发现当前直连路径、fd 所有权、close reason 或构建集成的高严重度回归；`src/core/transport.c` 已由 Makefile wildcard 纳入构建。
- 复核发现的 transport 扩展缺口已收敛：`wc_transport_t` 现通过可注入 ops/context 实际分派 `read/write/wait/close`，裸 socket 为默认 adapter；`wc_transport_send_all_until` 与 `wc_transport_wait_until` 共享绝对单调 deadline，lookup 现有高层调用和 response idle-timeout 语义保持不变。确定性 `tools/test/transport_contract_test.ps1` 已覆盖 adapter 分派、partial write、read、wait deadline、timeout、close 与无效 transport；现有 selftest 新增 policy 默认 health-off、非法 family、数值地址 family 冲突及 DNS-health hook 隔离。
- 复核后验证（2026-08-30）：本地 clang 严格聚焦语法检查与 transport contract PASS；九架构 `lto-auto` build/smoke/selftest、9/9 local hash、Golden 与三起点 referral PASS，用时 275s，证据目录 `out/artifacts/20260830-010926`，且未同步或改写 release 目录。
- DNS-health 隔离专项（2026-08-30）：通过自测计数器直接证明 `record_dns_health=0` 不调用目标 health hook，并以 `record_dns_health=1` 对照确认同一路径可观测；x86_64、win64、win32 smoke/selftest 与 local hash 均 PASS（143s，`out/artifacts/20260830-012006`）。WP-13B-2 可进入配置/CLI/env、HTTP CONNECT 与每 hop bypass 的 Vx 任务定义编制，仍须遵守第 9 节完整验收门禁。
- 最终同步产物审计（2026-08-30）：Strict Version `lto-auto` 九架构远程构建、默认查询 smoke、双目录同步与 Golden/referral 全部 PASS，无编译/LTO 告警，用时 241s（`out/artifacts/20260830-014939`）。归档九个二进制的 SHA-256 独立复算均与 `SHA256SUMS-static.txt` 匹配，仓库 release 清单与归档逐字一致；Linux/QEMU、win32、win64 默认 smoke 的 `8.8.8.8`/`1.1.1.1`/`10.0.0.8` 标题与权威尾行契约稳定。Golden 以 `8.8.8.8` 主 smoke 直接 PASS；IANA、ARIN、AFRINIC 三起点 referral 分别以 3/2/1 次成功连接、零失败收敛到 AFRINIC。该轮未启用 `--selftest`，专项 transport/policy/health-isolation 证据仍以上述 `010926`/`012006` 两轮为准；无需代码修复。
- 后续 WP-13C（SOCKS4/4a）与 WP-13D（HTTPS 代理 TLS）按第 9 节 Ready 门禁继续；WP-13D 的 TLS 依赖门禁现已通过，但仍不得在未经独立 ready 评审及生产门禁时开放。
- 权威文档集合内各落点的回填内容已核对一致：YES（本文件中文/英文两处）。
- 未经用户明确授权，不执行提交或推送。

## 11. WP-13B-2 下次开工清单

状态：**准备完成，待启动授权**。计划窗口 `2027-07-08 ~ 2027-07-21`，使用 `schemaVersion=vx-draft`、`strict-enforce`、event-only 串行 A/B；active start-file 为 `testdata/unattended_start/active/unattended_ab_start_20270708-20270721.md`。主归属文档为本 RFC，无协同文档。

共享门禁：A/B 严格串行；B 仅在 A 最终 PASS、A 成功快照完整且 B 启动门禁通过后启动，否则保持 `blocked-by-a`。启动前不提交、不推送、不预填执行结果。

### 11.1 Checklist A：配置、CLI 与环境预检

- 任务定义：`testdata/autopilot_code_step_tasks_20270708_20270714.json`；D1-D4 + V1-V4；`defaultTarget=opts_source`。
- 目标：冻结代理配置结构、CLI/env 优先级、authority-only URL、凭据与 family 冲突规则，并提供确定性 resolver/selftest；A 阶段配置代理时 fail closed，不路由代理流量。
- 非目标：不执行 HTTP CONNECT、SOCKS、TLS 或 per-hop `NO_PROXY` 路由；不改变默认直连、stdout、RIR referral、DNS-health、batch strategy 或 retry metrics 契约。
- 冻结 target set：`config_header`=`include/wc/wc_config.h`、`opts_header`=`include/wc/wc_opts.h`、`opts_source`=`src/core/opts.c`、`client_meta_source`=`src/core/client_meta.c`、`client_runner_source`=`src/core/client_runner.c`、`meta_source`=`src/core/meta.c`、`selftest_source`=`src/core/selftest.c`，均为 existing。
- `target_set_sha256=150b6f49ab217b65e2c048f407023d8d74dc69feaf670ccfeb5db71ad52a099b`；任务定义 SHA-256 `df34348b618e8f6a3c164c85dd1f0649ce2a0744a91a586d02026411d2b56f5b`。

编制期门禁：TODO-free/编码、SyntaxOnly、D1-D4、无 RoundTag 全定义严格检查、Vx 专项安全回归与 A effective payload hash 均 PASS。

**执行回填（2026-08-30 ~ 2026-08-31 运行，2026-08-31 回填）**

**Checklist A 回填**

| 字段 | 实际值 |
|---|---|
| final status | PASS |
| started_at / completed_at / elapsed | `2026-08-30 13:36:33` → `2026-08-30 18:46:02` / `0d 05:09:29` |
| run_dir | `out/artifacts/dev_verify_multiround/20260830-133709` |
| final result / summary | `out/artifacts/dev_verify_multiround/20260830-133709/final_status.json`（Result=pass, ExitCode=0, 8/8 轮, FailedRoundTags=[]）、`summary.csv` |
| task-static / code-step artifact | 各 D 轮独立 checker 与 code-step 哈希绑定产物（run_dir 内 `D*_validated_artifact/`）；无 task-definition repair transaction |
| snapshot manifest / target set SHA-256 | `target_set_sha256=150b6f49...`（A 成功快照 `a_success_snapshot/` 完整性通过） |
| 事故、自愈、重启摘要 | 无事故、无自愈、无重启（8/8 一轮通过） |
| RFC 回填日期 | 2026-08-31 |

### 11.2 Checklist B：HTTP CONNECT 与 per-hop bypass

- 任务定义：`testdata/autopilot_code_step_tasks_20270715_20270721.json`；D1-D4 + V1-V4；`defaultTarget=proxy_source`。
- 目标：实现 HTTP CONNECT、Basic auth 明文授权门禁、绝对单调 deadline、`NO_PROXY` per-hop 判断，以及 primary/override/fallback/empty-response 全连接路径接入；代理失败保持 terminal 且不污染目标 DNS-health 或 batch strategy。
- 非目标：不实现 SOCKS4/4a、SOCKS5/5h 数据面、HTTPS 代理 TLS、连接复用或静默直连回退。
- 冻结 target set：继承 A 的 7 个 target；新增 `net_header`=`include/wc/wc_net.h`、`net_source`=`src/core/net.c`、`proxy_header`=`include/wc/wc_proxy.h`（create）、`proxy_source`=`src/core/proxy.c`（create）、`lookup_header`=`include/wc/wc_lookup.h`、`lookup_connect`=`src/core/lookup_exec_connect.c`、`lookup_empty`=`src/core/lookup_exec_empty.c`、`lookup_loop`=`src/core/lookup_exec_loop.c`、`client_flow`=`src/core/client_flow.c`，其余均为 existing。
- `target_set_sha256=3808d4e86be49df0170add303e6acdf7e9fe7178cd526d0a445d73ac94c7d8e3`；任务定义 SHA-256 `4464717b6090f69a881c0abb3aa8f6afe6a30e6f4f91508a1ffaed3fbc594404`。

编制期门禁：SyntaxOnly、D1-D4、以 A 为 prerequisite 的链式全定义严格检查、Vx 专项安全回归均 PASS。A+B effective tree 的 16/16 target hash 与绑定 manifest 一致；九架构 `lto-auto` 编译、9/9 产物 hash、Linux/QEMU 与 win32/win64 smoke/selftest、Golden、三起点 referral 均 PASS（`tmp/wp13b2-b-effective-tree/out/artifacts/20260830-053710`）。Step47 preflight 5/5 PASS（`tmp/wp13b2-step47-script-validation/20260830-055709`），preclass table guard PASS（`tmp/wp13b2-b-effective-tree/out/artifacts/preclass_table_guard/20260830-061317`）。

**执行回填（2026-08-30 ~ 2026-08-31 运行，2026-08-31 回填）**

**Checklist B 回填**

| 字段 | 实际值 |
|---|---|
| A PASS 与 snapshot 门禁 | PASS（A final_status.json Result=pass, ExitCode=0；A snapshot manifest/hash 完整性通过） |
| final status | PASS |
| started_at / completed_at / elapsed | `2026-08-31 01:30:36` → `2026-08-31 08:27:32` / `0d 06:56:57` |
| run_dir | `out/artifacts/dev_verify_multiround/20260831-032025` |
| final result / summary | `out/artifacts/dev_verify_multiround/20260831-032025/final_status.json`（Result=pass, ExitCode=0, 8/8 轮, FailedRoundTags=[], GeneratedAt=08:26:50）、`summary.csv` |
| task-static / code-step artifact | 各 D 轮独立 checker 与 code-step 哈希绑定产物（run_dir 内 `D*_validated_artifact/`）；无 task-definition repair transaction |
| 事故、自愈、重启摘要 | B 首跑 runtime-fail（`.Count` 属性异常，`T20260831-024551167-8db236de`/`T20260831-024556280-6af52afe`）→ 脚本根因修复 3 处（multiround 单行输出数组化、Vx artifact 目录移动有限重试、guard A 快照锚点保护/重载）+ start-file `A_SUCCESS_SNAPSHOT_*` 恢复 → 标准 stop/reset/launch-ready 后经 stage-window 重启（B pid 13396、guard 15324、trigger 24908）从 D1 续跑 8/8 收敛 |
| RFC 回填日期 | 2026-08-31 |

**最终收口**

- A/B 总结：A 8/8 一轮通过；B 首跑 D1 后 runtime-fail，经 3 处编排脚本修复与 A 快照锚点恢复后重启，第二次 run 从 D1 续跑 8/8 通过；`A_FINAL_STATUS=PASS`、`B_FINAL_STATUS=PASS`、`SESSION_FINAL_STATUS=PASS`。
- A/B 合计用时：`0d 18:51:00`（session start `2026-08-30 13:36:33` → `2026-08-31 08:27:32`，含 launcher/preflight/A→B 交接与恢复间隔）。
- 事件票闭环：`T20260831-024551167-8db236de`（diagnose-only 评审）、`T20260831-024556280-6af52afe`（incident-captured，route guard 分类 `incident-auto-resume-noncode`；recovery transaction 因 A 快照锚点损坏 fail-close，未伪造回执，经用户授权修复后重启）、`chat-final-20260831-082732`（handled_at 2026-08-31 08:28:44）。
- 运行后 Strict 验证（2026-08-31）：`WHOIS_STRICT_VERSION=1 tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -q '8.8.8.8 1.1.1.1 10.0.0.8' -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 -a '' -G 1 -E '' -O 'lto-auto' -K 0 -N 0` → 无告警 + lto 无告警 + Local hash verify: PASS + Golden PASS + referral check: PASS，退出码 0，用时 254s，日志目录 `out/artifacts/20260831-091653`（build_out 九架构产物与 `SHA256SUMS-static.txt`）。
- 编辑器 IntelliSense 兼容性修正（2026-08-31）：`wc_proxy_selftest` 内的 `UINT64_MAX` 在 VS Code C/C++ IntelliSense（`windows-msvc-x64` + clang-cl，工作区仅有默认 includePath）下触发“编号的预期结尾后有多余文本”（code 19）误报，真实 GCC/Clang C11 编译与远程九架构构建均无此问题。现改为自测局部 `const uint64_t no_deadline = ~(uint64_t)0;` 并复用，语义与 `UINT64_MAX` 完全等价（全 1 无超时），不依赖实现特定的整数后缀；仅 `src/core/proxy.c` 自测路径改动，生产 CONNECT/NO_PROXY 逻辑与输出契约零变化。
- 修正后复核（2026-08-31）：Strict Version `lto-auto` 远程构建冒烟同步 + 黄金校验重跑无告警 + lto 无告警 + Local hash verify: PASS + Golden PASS + referral check: PASS，退出码 0，用时 270s，日志目录 `out/artifacts/20260831-095325`（build_out 九架构产物；本地重算 9/9 SHA-256 与 `SHA256SUMS-static.txt` 完全一致；referral 链路 IANA → ARIN → AFRINIC 正常收敛）。
- 复核结论：默认直连、stdout、RIR referral、DNS-health、batch strategy 与 retry metrics 契约保持不变；无需追加代码修复。
- 后续 WP-13C（SOCKS4/4a）与 WP-13D（HTTPS 代理 TLS）按第 9 节 Ready 门禁继续；WP-13D 的 TLS 依赖门禁现已通过，但仍不得在未经独立 ready 评审及生产门禁时开放。
- 权威文档集合内各落点的回填内容已核对一致：YES（本文件中文/英文两处 + RELEASE_NOTES + RFC-whois-client-split）。
- 未经用户明确授权，不执行提交或推送。

### 11.3 启动前联合确认

- [x] 两份任务定义已完成初始编制完整验收，无 TODO 或占位符。
- [x] A/B schema、target registry、target set hash 与 prerequisite 顺序已冻结。
- [x] A+B effective source 已完成编译、运行、Golden/referral、Step47 与 table guard 验证。
- [x] active start-file 已生成并通过字段同步、编码和 launch-ready dry-run 检查。
- [x] 用户已检查任务定义、清单和 start-file，并明确授权启动（2026-08-31 实际运行）。

执行回填：已完成，见 11.1/11.2 的 Checklist A/B 回填与最终收口（2026-08-31）。

## 12. WP-13B-3 SOCKS5/5h 实施记录

- 已实现 SOCKS5 method negotiation、RFC 1929 username/password、CONNECT 的 IPv4/IPv6/domain ATYP 编码、完整 REP 分类和统一 terminal failure policy。
- `socks5://` 保留本地目标 DNS 候选；单个候选返回 `general-failure` 或 `address-type-unsupported` 时继续后续候选。未被 per-hop `NO_PROXY` 绕过的 `socks5h://` 直接使用逻辑 hostname 候选，不调用本地目标 DNS、目标 DNS-health/backoff 或 empty-response IP fallback。被 host 规则绕过时仍走原本地 DNS/直连路径。
- SOCKS5H 成功后目标 IP 保持 unknown，不把代理端点或未观测的远端解析结果写入标题、权威尾行或目标健康状态。默认直连、stdout、RIR referral、batch strategy 与 retry metrics 契约不变。
- 确定性 fake transport 覆盖认证、ATYP、REP 与远程 DNS policy；loopback 协议/配置探针 21/21 PASS（`out/artifacts/proxy_protocol_spike/20260831-030507`）。严格 ISO C11 clang 检查零诊断；首轮远程检查发现并修复 loongarch64 下 `strdup` 隐式声明，改用标准 `malloc` + `memcpy`。
- 最终 Strict Version `lto-auto` 九架构构建无编译/LTO 告警，9/9 SHA-256、POSIX/QEMU 与 win32/win64 smoke、Golden 和 IANA/ARIN/AFRINIC 三起点 referral 全 PASS（`out/artifacts/20260831-112633`，436s）。未同步 release 目录。
- 带 release 同步的最终轮（2026-08-31）：Strict Version `lto-auto` 远程编译冒烟同步 + 黄金校验复核无告警 + lto 无告警 + Local hash verify/Golden/referral 全 PASS，用时 284s（`out/artifacts/20260831-114158`）；release 双目录（`lzispro/release/lzispro/whois` 与 `whois/release/lzispro/whois`）文件与 `SHA256SUMS-static.txt` 逐字一致，本地 `Get-FileHash` 复核 9/9 匹配。
- WP-13C（SOCKS4/4a）尚未实施；WP-13D（HTTPS proxy TLS）的 TLS 依赖门禁已通过，仍须独立 ready 评审及生产验收。

## 13. WP-13C SOCKS4/4a 开工评审

状态：**本期已完成执行回填（SESSION=PASS / A=PASS / B=PASS）**（2026-09-01）。不得与 WP-13D 合并；其 TLS 依赖门禁已通过，但仍须独立 ready 评审及生产验收。

- 确定性 loopback spike 已增加 SOCKS4 IPv4、自定义端口、USERID、SOCKS4a domain、CD=91 拒绝响应，以及 `socks4`/`socks4a` 配置门禁，原有 HTTP/SOCKS5 案例无回归；合计 27/27 PASS（`out/artifacts/proxy_protocol_spike/20260831-043917`）。
- 冻结语义：`socks4://` 只向代理发送本地解析的 IPv4 候选；`socks4a://` 发送逻辑 hostname，并与 `socks5h://` 共用远程 DNS、目标 family/fallback/RIR override 冲突门禁和健康隔离。SOCKS4a 不声明或推断代理最终使用 IPv6。
- USERID 使用已解析凭据中的 username；password 不进入 SOCKS4/4a 帧，且 USERID 不视为强认证。既有成对非空凭据来源与秘密清理规则保持不变，诊断和产物不得输出 USERID 或 password。
- 冻结生产 target closure：`include/wc/wc_config.h`、`src/core/opts.c`、`src/core/selftest.c`、`include/wc/wc_proxy.h`、`src/core/proxy.c`、`src/core/lookup_exec_connect.c`；`src/core/lookup_exec_empty.c` 作为远程 DNS/IPv4-only 继承路径纳入检查闭包但不预设源码改动。
- D1 增加 scheme/解析与配置自测；D2 增加 SOCKS4/4a transport handshake、CD 分类和 fake transport 字节合同；D3 接入 dial 分派、脱敏指标与 terminal policy；D4 在主候选构建中冻结 SOCKS4 IPv4-only 和 SOCKS4a hostname-only 路径，并验证默认直连、per-hop bypass 与目标健康隔离不变。
- 实施定义使用 `schemaVersion=vx-draft`，独立窗口从 `2027-07-22` 开始；生成 start-file 前仍须完成 TODO-free、SyntaxOnly、D1-D4、Vx 专项安全回归、全定义检查，以及完整 target set 的聚焦编译、Golden/referral、Step47 验证。

### 13.1 启动清单

- A 定义：`testdata/autopilot_code_step_tasks_20270722_20270728.json`；三目标 `config_header`、`opts_source`、`selftest_source`；`target_set_sha256=d60f26e6efbd732de60766306ec9d65a1a19cf2e32b9422c6514ace84ddd8eb7`；任务定义 SHA-256 `20382f3754b3b0a60f59572e75f547f5f04e1863a48c5922efa8fe7e818252cb`。
- B 定义：`testdata/autopilot_code_step_tasks_20270729_20270804.json`；继承 A 三目标并增加 `proxy_header`、`proxy_source`、`lookup_connect`、`lookup_empty`；`target_set_sha256=adc9aea696e8a74705a52b5cd37362b37b4913b9075a2ac11f4ffbac9f554361`；任务定义 SHA-256 `5fcb2254396fb8902b0e88aafc2aa013f21f4838aa7a9b76439bcedfe0394fad`。
- A/B 均通过 TODO-free、SyntaxOnly、D1-D4 链式检查、无 `RoundTag` 全定义检查及三项 Vx 基础设施安全回归；B 检查显式以 A 为 prerequisite，完整 target union 已冻结。
- 隔离 effective tree 已用正式 checker artifact 与 code-step 顺序落盘 A.D1-D4、B.D1-D4。Strict Version `lto-auto` 九架构构建、9/9 hash、Linux/QEMU 与 win32/win64 smoke/selftest、Golden 和三起点 referral 均 PASS（`tmp/wp13c-effective-tree/out/artifacts/20260831-132412`）。
- Windows Step47 preflight 显式使用 `release/lzispro/whois/whois-win64.exe`，5/5 PASS（`out/artifacts/step47_preclass_preflight/20260831-135424`）；`whois-x86_64` 仅供 Linux 环境使用。effective tree 的 preclass table guard 亦 PASS（`tmp/wp13c-effective-tree/out/artifacts/preclass_table_guard/20260831-141343`）。
- active start-file：`testdata/unattended_start/active/unattended_ab_start_20270722-20270804.md`；event-only、strict-enforce、A/B 串行，`LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED=false`。字段同步、A/B SyntaxOnly、增量编码及 A 阶段 launch-ready dry-run 均 PASS。未经用户明确授权，不启动、提交或推送。

**执行回填（2026-08-31 ~ 2026-09-01 运行，2026-09-01 回填）**

**Checklist A 回填**

| 字段 | 实际值 |
|---|---|
| final status | PASS |
| started_at / completed_at / elapsed | `2026-08-31 15:08:58` → `2026-08-31 20:51:29` / `0d 05:42:32` |
| run_dir | `out/artifacts/dev_verify_multiround/20260831-150933` |
| final result / summary | `out/artifacts/dev_verify_multiround/20260831-150933/final_status.json`（Result=pass, ExitCode=0, 8/8 轮, FailedRoundTags=[], GeneratedAt=20:49:36）、`summary.csv` |
| task-static / code-step artifact | 各 D 轮独立 checker 与 code-step 哈希绑定产物（run_dir 内 `D*_validated_artifact/`）；无 task-definition repair transaction |
| snapshot manifest / target set SHA-256 | `target_set_sha256=d60f26e6efbd732de60766306ec9d65a1a19cf2e32b9422c6514ace84ddd8eb7`；A 成功快照完整性通过 |
| 事故、自愈、重启摘要 | NONE（无 incident、recovery_attempts=0、无重启） |
| RFC 回填日期 | 2026-09-01 |

**Checklist B 回填**

| 字段 | 实际值 |
|---|---|
| A PASS 与 snapshot 门禁 | PASS（A final_status.json Result=pass, ExitCode=0） |
| final status | PASS |
| started_at / completed_at / elapsed | `2026-08-31 20:50:40` → `2026-09-01 03:10:37` / `0d 06:19:58` |
| run_dir | `out/artifacts/dev_verify_multiround/20260831-205121` |
| final result / summary | `out/artifacts/dev_verify_multiround/20260831-205121/final_status.json`（Result=pass, ExitCode=0, 8/8 轮, FailedRoundTags=[], GeneratedAt=03:09:28）、`summary.csv` |
| task-static / code-step artifact | 各 D 轮独立 checker 与 code-step 哈希绑定产物（run_dir 内 `D*_validated_artifact/`）；无 task-definition repair transaction |
| 事故、自愈、重启摘要 | NONE（无 incident、b_recovery_attempts=0、无重启） |
| RFC 回填日期 | 2026-09-01 |

**最终收口**

- A/B 总结：A、B 均为一次通过（8/8 轮），无卡滞、无重启、无自动修复；`A_FINAL_STATUS=PASS`、`B_FINAL_STATUS=PASS`、`SESSION_FINAL_STATUS=PASS`。事件票闭环：`T20260831-205129509-bb7b885e`（a-pass-conclusion-b-started，handled_at 2026-08-31 20:54:38）、`chat-final-20260901-031037`（chat-session-final-status，handled_at 2026-09-01 03:12:26）；event-only 模式无常规状态票。
- A/B 合计用时：`0d 12:01:40`（session start `2026-08-31 15:08:58` → `2026-09-01 03:10:37`，含 launcher/preflight、A→B 交接间隔）。
- 运行后 Strict 验证（2026-09-01）：`WHOIS_STRICT_VERSION=1 tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -q '8.8.8.8 1.1.1.1 10.0.0.8' -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 -a '' -G 1 -E '' -O 'lto-auto' -K 0 -N 0` → 无告警 + lto 无告警 + Local hash verify: PASS + Golden PASS + referral check: PASS，退出码 0，用时 755s，日志目录 `out/artifacts/20260901-121843`。
- 复核结论：默认直连、stdout、RIR referral、DNS-health、batch strategy 与 retry metrics 契约保持不变；无需追加代码修复。
- 后续 WP-13D（HTTPS 代理 TLS）的 TLS 依赖门禁已通过，仍按第 9 节完成独立 ready 评审及生产验收，不得提前开放。
- 权威文档集合内各落点的回填内容已核对一致：YES（本文件中文/英文两处 + RELEASE_NOTES + RFC-whois-client-split）。
- 未经用户明确授权，不执行提交或推送。

## 14. WP-13D HTTPS proxy TLS 开工清单

状态：**已完成执行与生产验收（SESSION=PASS / A=PASS / B=PASS）**。计划窗口 `2027-08-05 ~ 2027-08-18`，实际运行于 2026-09-02，使用 `schemaVersion=vx-draft`、`strict-enforce`、event-only 串行 A/B。active start-file 为 `testdata/unattended_start/active/unattended_ab_start_20270805-20270818.md`。

### 14.1 Checklist A：连接 transport 所有权

- 任务定义：`testdata/autopilot_code_step_tasks_20270805_20270811.json`；定义 SHA-256 `78f21ce56b111b00066f72d7502b4b73baff3118474bef64bc67adf23e442159`。
- 目标：让 `wc_net_info` 成为单 hop 连接唯一所有者，统一 `init/get/adopt/move/close`，并将 proxy、候选/empty-response fallback、send、recv 与 signal close 收敛到同一所有权路径。
- 冻结 target set：`net_header`、`net_source`、`proxy_source`、`lookup_connect`、`lookup_empty`、`lookup_send`、`lookup_recv`、`lookup_loop`、`selftest_source`，均为 existing；`target_set_sha256=8a3176bf267040b886b1cd7cbb48b545b228fa7c673094b223f5bfd4cad09957`。
- D1 声明并实现所有权 API；D2 迁移 proxy/connect/empty；D3 迁移 send/recv/loop；D4 增加 custom transport move 与幂等 close-once 自测。

### 14.2 Checklist B：HTTPS scheme 与 OpenSSL TLS transport

- 任务定义：`testdata/autopilot_code_step_tasks_20270812_20270818.json`；定义 SHA-256 `f2d45a5599b4fd39fff4995b06cb18abd25b140857bea3c8cf681320bfccd32a`；运行时必须以 A 为 prerequisite。
- 目标：增加 `https://` 配置与 443 默认端口；默认构建在 lookup 前稳定报 unsupported；`WHOIS_TLS=1` 使用 OpenSSL 3.5.8、强制 peer/hostname/IP 验证、SNI、TLS 1.2 下限、固定 CA 或 fail-close 的非空 `SSL_CERT_FILE` 覆盖，并在同一绝对单调 deadline 内完成 TLS handshake 与 HTTP CONNECT。
- 冻结 target set：继承 A 九目标；新增 `config_header`、`proxy_header`、`opts_source`（existing）及 `tls_header=include/wc/wc_tls.h`、`tls_source=src/core/tls.c`（create）；`target_set_sha256=4d171a4202c4c3bbec9d945aa884a44a0fcb72b3d619362eef590cb1d279af99`。
- D1/D2 分别创建完整 TLS header/source；D3 增加 scheme、build gate 与 parser selftest；D4 在代理 TCP 后、CONNECT 前接入 TLS，转交 A 的 owner，并增加稳定分类与确定性 TLS selftest。

### 14.3 编制期证据与执行回填

- A/B 均满足 UTF-8 BOM + LF、TODO-free、SyntaxOnly、D1-D4、三项 Vx 基础设施回归；B 带 A prerequisite 的全定义检查在官方 `WorkerTimeoutMs=120000` 预算下 `errors=0 warnings=0`，内部 regex timeout 与 operation safety policy 未放宽。
- 隔离 effective tree 的默认 stub 路径和 `WHOIS_TLS=1` OpenSSL 路径均通过 x86_64/win64 远程编译；TLS 路径 win64 保持 full-static，本地制品哈希复核 PASS。该证据仅为编制期快速编译，不替代第 9 节生产验收。
- A run=`out/artifacts/dev_verify_multiround/20260902-090840`，B run=`out/artifacts/dev_verify_multiround/20260902-160535`；两阶段均 `Result=pass`、`ExitCode=0`、8/8 完成且无失败轮。B 从 `2026-09-02 16:05:02` 至 `23:45:35`，用时 `0d 07:40:33`；A/B 会话从 `09:08:04` 至 `23:45:35`，合计 `0d 14:37:31`，最终于 `23:47:12` 关闭。
- 启动前一次远端网络预检因 SSH 超时被阻断，网络恢复后重新预检通过再启动 A。A D1 首次发布 Vx artifact 时遇短暂 `Move` 访问拒绝，脚本有限重试后成功，checker 最终 `errors=0 warnings=0`；未形成脚本故障、代码自愈或阶段重启。
- CA/构建准备已通过 `WHOIS_TLS=1` TLS/LTO 九架构、9/9 哈希、Windows full-static 与依赖审计（`out/artifacts/20260901-170601`）；A/B 编制期还通过默认 stub 与 TLS x86_64/win64 快编译、TLS loopback/证书/主机名/失败分类合同。普通构建继续以 `WHOIS_TLS=0` 生成无 OpenSSL 的 unsupported stub，不得将其描述为 HTTPS-enabled 制品。

### 14.4 最终回归与发布候选复核（2026-09-03）

- Strict Version `lto-auto` 默认轮与 debug/retry/DNS-stats/interleave-v4-first 轮均完成九架构构建，9/9 SHA-256、Golden 与 referral 全 PASS（`out/artifacts/20260903-003613`、`out/artifacts/20260903-004426`），未发现编译、LTO 或链接告警。归档阶段的 GnuPG socket `ignored` 只是 tar 跳过 Unix socket，不是构建告警。
- Batch Golden 的 raw/health-first/plan-a/plan-b 四策略全 PASS（`out/artifacts/batch_raw/20260903-005136` 至 `out/artifacts/batch_planb/20260903-011010`）；独立 core 与四策略 Selftest Golden 共 5/5 PASS（`out/artifacts/batch_raw/20260903-012001` 至 `out/artifacts/batch_planb/20260903-013853`）。负向合同中的 `Private query denied`、`Suspicious query detected` 等文本是预期断言，不是运行告警。
- 12×6 redirect matrix 生成 72/72 案例和 72/72 分析行，authority mismatch 为空且 `errors=(no errors found)`（`out/artifacts/redirect_matrix_10x6/20260903-014154`）。CIDR body `4/4`、draft matrix `9/9`，bundle `result=pass`、`exit_code=0`（`out/artifacts/cidr_bundle/cidr_bundle_summary_20260903-015526.txt`）。默认直连、stdout/stderr、权威判定、referral、CIDR 与 Step47 契约未发生回归，本轮无需代码修复。

### 14.5 产品交付收口

- 官方远程静态构建器默认 `WHOIS_TLS=1`，full release 与 one-click release 也显式固定该值；调用者仍可显式设置 `WHOIS_TLS=0` 生成无 OpenSSL 的兼容制品，本地普通 `make` 的默认值不变。
- `--help` 列出 HTTP/HTTPS/SOCKS4/4a/5/5h、默认端口、凭据与环境变量，并根据编译宏打印 `HTTPS proxy TLS backend: enabled|disabled`，因此用户可直接识别手中二进制能力。
- 中英文 USAGE 提供 HTTPS proxy、公网 CA、企业私有 `SSL_CERT_FILE` 及 Windows/POSIX 可执行示例；官方 release 不再要求终端用户自行理解或设置内部构建开关。
- 最终产品交付轮在不显式传入 `WHOIS_TLS` 时确认环境为 `WHOIS_TLS='1'`，Strict `lto-auto` 九架构、Windows full-static、网络冒烟、9/9 本地哈希、Golden 与三起点 referral 全 PASS，日志无 warning/error，并同步两个正式 release 目录（`out/artifacts/20260903-040906`，410s）。同步后的 win64 `--help` 实测显示 `HTTPS proxy TLS backend: enabled`，双目录清单逐字一致且制品独立复算 9/9 PASS。
- 用户可见文案收口后的最终复核轮再次通过 Strict `lto-auto` 九架构构建与同步（`out/artifacts/20260903-045122`，360s）：Linux/QEMU、win32、win64 冒烟分别完成 18/3/3 条查询，24/24 标题与权威尾行配对且硬告警为 0；Golden PASS，IANA/ARIN/AFRINIC 三起点 referral 均零错误并收敛至 AFRINIC。九个制品独立 SHA-256 复算与清单 9/9 一致，仓库内/外 release 清单逐字一致，Windows 两目标均为 full-static；同步 win64 的 `--help` 显示 TLS backend enabled，且 `--help`/`--about`/`--examples` 均无旧的 preflight-only 或内部构建开关文案。本轮无需代码修复。

# English Version

## 1. Purpose

This RFC defines proxy access for WHOIS TCP connections without changing the default direct-connect behavior, referral semantics, DNS health memory, authoritative-RIR selection, or stdout contracts.

The delivery order is:

1. WP-13A: freeze contracts and prove protocol/dependency assumptions with local deterministic probes.
2. WP-13B: deliver HTTP CONNECT and SOCKS5/5h over a transport abstraction.
3. WP-13C: add SOCKS4/4a as a compatibility extension.
4. WP-13D: add HTTPS proxy support only after the TLS backend passes the nine-architecture static-link gate.

WP-13A changes no production network path.

## 2. Non-negotiable invariants

- No proxy is used unless the user explicitly supplies `--proxy`, sets `WHOIS_PROXY`, or enables generic environment discovery with `--proxy-env`.
- A configured but unusable proxy fails closed. The client must never silently fall back to a direct connection.
- Proxy endpoint failures never update target RIR DNS health, backoff, denial, rate-limit, ERX/IANA, or authority state.
- The logical chain contains WHOIS targets only. Proxy endpoints and credentials never enter stdout.
- A referral opens a tunnel to that hop's current host and port, not the original target and not a fixed port 43.
- One monotonic deadline covers proxy DNS/TCP, optional TLS, authentication, and tunnel setup for a target attempt.
- The initial proxy implementation disables connection caching. Re-enabling it requires a transport-aware key and separate review.

## 3. Configuration contract

### 3.1 CLI

| Option | State | Contract |
|---|---|---|
| `--proxy <url>` | frozen for 13B | Explicit proxy; highest precedence. Supported 13B schemes are `http`, `socks5`, and `socks5h`. |
| `--proxy-env` | frozen for 13B | Enables generic `ALL_PROXY`/`all_proxy` discovery and `NO_PROXY`/`no_proxy`. Generic environment variables are ignored without this flag. |
| `--proxy-family auto\|v4\|v6` | frozen for 13B | Defaults to `auto`; controls only the proxy endpoint family. It must not reuse target-family preferences implicitly. |
| `--proxy-allow-insecure-auth` | frozen for 13B | Required before sending HTTP Basic credentials over a plain `http` proxy connection. |
| `--proxy-pass` | forbidden | Secrets must not be accepted in argv. |

`--proxy` accepts only an absolute URL with no path, query, or fragment. IPv6 proxy literals require brackets. Default ports are 8080 for `http`, 1080 for `socks5`/`socks5h`/`socks4`/`socks4a`, and 443 for `https`. Unknown schemes and malformed percent encoding fail before lookup.

`--proxy` changes routing only; `-p/--port` remains the initial WHOIS target port. A referral can replace that target port independently.

### 3.2 Environment precedence

The frozen precedence is:

1. `--proxy`
2. `WHOIS_PROXY`
3. `ALL_PROXY`, then `all_proxy`, only with `--proxy-env`
4. direct connection

`HTTP_PROXY` and `HTTPS_PROXY` are not read in 13B. Raw WHOIS has no URL scheme that can select between them, and uppercase `HTTP_PROXY` has known CGI-injection ambiguity on POSIX systems.

`NO_PROXY`/`no_proxy` are consulted only when `--proxy-env` enabled generic environment handling. Matching is recalculated for every WHOIS hop. The first implementation supports `*`, exact host, leading-dot domain suffix, IPv4 literal, bracketed IPv6 literal, and an optional exact port. CIDR and arbitrary glob syntax are not supported.

The 13B authentication sources are frozen as follows:

- Dedicated `WHOIS_PROXY_USER` and `WHOIS_PROXY_PASSWORD` environment variables are preferred. Both must be present and non-empty, or configuration fails before lookup.
- Userinfo is forbidden in a CLI `--proxy` URL so credentials cannot enter shell history or process listings.
- Only proxy URLs obtained from `WHOIS_PROXY`, `ALL_PROXY`, or `all_proxy` may carry percent-encoded `username:password@` userinfo for compatibility. Both username and password must be non-empty.
- Dedicated credential variables combined with environment-URL userinfo are ambiguous and fail fast; sources are never silently overridden or combined.
- Credential files, interactive prompts, and OS keychains are not supported in 13B. Any additional source requires separate review.

Environment inheritance can still expose secrets, so usage documentation must recommend minimizing child-process inheritance. Tests may use in-memory credentials and must report case names only.

## 4. DNS and address-family contract

- `http://` and `socks5://` use local target resolution. Existing target candidate ordering, family controls, and health memory remain authoritative.
- For `socks5://`, SOCKS5 `general-failure` and `address-type-unsupported` apply to the current numeric target candidate and advance to the next local candidate. Authentication, ruleset, command, and protocol failures remain terminal. This relaxation does not apply to `socks5h://`.
- `socks5h://` sends a domain name to the proxy. Because the selected target address family is unobservable, it is incompatible in 13B with `--ipv4-only`, `--ipv6-only`, per-RIR family overrides, and candidate fallback controls. These combinations fail before lookup.
- `--proxy-family=auto` resolves the proxy endpoint independently with `AF_UNSPEC`; `v4` and `v6` restrict it to `AF_INET` and `AF_INET6`, respectively. A numeric proxy literal that conflicts with an explicit family fails before dialing.
- HTTP CONNECT uses a numeric target candidate. IPv6 authorities are encoded as `[address]:port`.
- SOCKS5 uses ATYP 1 for IPv4, 4 for IPv6, and 3 only for `socks5h` remote DNS.
- Remote-DNS attempts never update target host+family health because the family is unknown.

## 5. Protocol contract

### 5.1 HTTP CONNECT

The request line and Host header use the same authority:

```text
CONNECT <authority> HTTP/1.1\r\n
Host: <authority>\r\n
Proxy-Connection: keep-alive\r\n
\r\n
```

Any 2xx response establishes the tunnel. `407` is `proxy-auth-required`; all other 4xx responses are stable proxy rejection classes; 5xx responses are proxy upstream failures. Response headers are bounded and parsed before any WHOIS bytes are sent.

### 5.2 SOCKS5

The client offers no-auth and, only when credentials exist, username/password authentication. It then sends CONNECT with the current WHOIS target and port. REP values remain distinguishable internally; they are not collapsed into RIR refusal or response classification.

The required classes are `succeeded`, `general-failure`, `ruleset-denied`, `network-unreachable`, `host-unreachable`, `connection-refused`, `ttl-expired`, `command-unsupported`, `address-type-unsupported`, and `unknown-reply`.

### 5.3 SOCKS4/4a and HTTPS

SOCKS4/4a are deferred to WP-13C. SOCKS4 supports IPv4 targets only; SOCKS4a remote DNS does not imply IPv6 support.

HTTPS proxy is deferred to WP-13D. It means TLS between this client and the HTTP proxy, followed by CONNECT; WHOIS inside the tunnel remains plain TCP. Certificate and hostname verification are mandatory. No insecure verification mode is planned.

WP-13D freezes its default trust source to a build-pinned Mozilla CA bundle embedded in each static binary. The bundle source, snapshot date, SHA-256, and license must be recorded in build manifests and release audits. This preserves single-file distribution on all nine targets and prevents a cross-compiled OpenSSL `OPENSSLDIR` from leaking into runtime behavior. A non-empty `SSL_CERT_FILE` explicitly overrides the embedded bundle for enterprise proxy private CAs. An unreadable, empty, or certificate-free override fails closed before connecting and never falls back to the embedded bundle. Without an override, only the embedded bundle is used; platform-specific default paths and the Windows certificate store are not probed. CA updates are reviewed at least monthly, and a Mozilla CA data change or applicable security advisory requires a pinned-digest update plus the full nine-target TLS, Golden/referral, and release-hash gates.

## 6. Transport and timeout boundary

WP-13B starts by extracting a side-effect-free endpoint dialer and a transport interface with close, wait, read, and write operations. The existing direct adapter preserves current metrics and DNS-health behavior. Proxy adapters own proxy endpoint attempts and cannot call target-health hooks.

All operations consume one absolute monotonic deadline. A phase cannot reset the full timeout. Partial writes, EOF, EINTR, nonblocking readiness, and TLS WANT_READ/WANT_WRITE must be handled by the transport layer rather than by proxy protocol parsers.

Existing `attempts` metadata counts actual TCP connection attempts: target sockets for direct mode and proxy endpoint sockets for proxy mode. TLS and protocol messages do not increment it. Proxy phase detail uses redacted stderr diagnostics only when debug or retry metrics are enabled.

## 7. Error and secret handling

Proxy TCP, TLS, authentication, protocol, and target-connect replies are internal stable classes. They map to the existing lookup failure exit contract but never become WHOIS response bodies and never participate in authoritative-RIR fallback.

Logs and artifacts may include the proxy scheme, redacted host, port, phase, and stable class. They must not include passwords, complete userinfo, `Proxy-Authorization`, or raw authentication frames. Error text derived from URLs must pass through the same redaction path before output.

Authentication failure, certificate failure, malformed protocol, and unsupported combinations are not retried. Proxy TCP timeout and transient I/O may consume the existing bounded connection retry budget. A retry always creates a new tunnel.

## 8. WP-13A executable evidence

Run the deterministic protocol spike:

```powershell
python tools/test/proxy_protocol_spike.py
```

It uses IPv4 loopback only and validates exact HTTP CONNECT authorities, HTTP status preservation, SOCKS5 IPv4/IPv6/domain encoding, username/password negotiation, custom ports, REP preservation, SOCKS4 IPv4/USERID framing, SOCKS4a domains, and SOCKS4 reply-code preservation. It writes `out/artifacts/proxy_protocol_spike/<timestamp>/report.json`.

Run the TLS static-link probe once per remote compiler after supplying that target's OpenSSL flags:

```bash
CC=aarch64-linux-musl-gcc \
OPENSSL_CFLAGS='-I/path/to/include' \
OPENSSL_LIBS='-L/path/to/lib -lssl -lcrypto -lz -ldl -pthread' \
tools/test/proxy_tls_dependency_spike.sh --target aarch64
```

The probe requires a fully static link and references TLS client setup, peer verification, SNI, and hostname verification APIs. A missing backend or dynamic-only result is `unavailable`, not permission to weaken verification or remove static-build gates.

## 9. Readiness gates

WP-13B-1 may enter task-definition design after this RFC and the protocol spike are reviewed. The proxy-endpoint family and 13B credential sources are now frozen; production authentication still requires deterministic configuration tests before implementation. WP-13D remains blocked until the TLS probe passes all seven POSIX targets plus win32 and win64 with one approved backend and its license/CVE/update policy documented.

### 9.1 WP-13D TLS dependency gate backfill (2026-09-01)

- The approved backend is OpenSSL 3.5.8 LTS under Apache-2.0; official support for OpenSSL 3.5 LTS ends on 2030-04-08. The source archive SHA-256 is `a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2`, and its release signature chains to the pinned OpenSSL primary fingerprint `B146647E45A7B33947AB226B2A2C87D161692D40`.
- `tools/remote/bootstrap_openssl_static.sh` builds `aarch64/armv7/x86_64/x86/mipsel/mips64el/loongarch64/win32/win64` from that single verified source into isolated prefixes with `no-shared no-dso no-tests`. The final unified matrix passes 9/9 at `out/artifacts/proxy_tls_dependency_matrix/20260901-072331`.
- All seven POSIX probes have no ELF interpreter or `NEEDED` entries. The win32/win64 PE probes have no `libssl` or `libcrypto` DLL dependency. Each target records its compiler and Configure manifest, `configdata.pm --dump`, static-library and probe SHA-256 values, platform dependency audit, and SPDX 2.3 document.
- Maintenance policy: review OpenSSL security advisories/CVEs and the latest 3.5 LTS patch monthly. A security release affecting the used TLS client, X.509, certificate/hostname verification, or static-link path triggers a pinned-version update and a complete nine-target rebuild, probe, dependency audit, hash, and SPDX gate. An unsupported release or one with an unresolved applicable high-severity vulnerability is not acceptable.
- The TLS dependency gate is therefore cleared and WP-13D may enter independent Vx task-definition design and readiness review. This does not mean that HTTPS proxy support is implemented and does not replace the production acceptance gates below.

Production acceptance still requires focused x86_64/win32/win64 contracts, nine-architecture Strict builds, Golden/referral, Batch/Selftest/CIDR/Redirect/Step47, default-direct output freezing, and synchronized Chinese/English usage documentation.

## 10. WP-13B-1 next-start checklist

Status: **this run is complete (SESSION=PASS / A=PASS / B=PASS)**. The `2027-06-24 ~ 2027-07-07` window (actually executed 2026-08-29) used `schemaVersion=vx-draft`, `strict-enforce`, and serial event-only A/B; the active start file is `testdata/unattended_start/active/unattended_ab_start_20270624-20270707.md`. Run records are in the `Execution backfill` block below.

### 10.1 Checklist A: endpoint dialer policy

- Definition: `testdata/autopilot_code_step_tasks_20270624_20270630.json`.
- Goal: extract `wc_net_dial_endpoint` with explicit endpoint-family and health policy while preserving direct behavior through the `wc_dial_43` compatibility wrapper.
- Excluded: proxy CLI, handshakes, authentication, and TLS; stdout, RIR referral, target DNS-health, and retry-metrics contracts remain unchanged.
- Frozen targets: `net_header` = `include/wc/wc_net.h` (existing c-header) and `net_source` = `src/core/net.c` (existing c-source), with `defaultTarget=net_source`.
- `target_set_sha256=7918987e6f12e6cde433c258b93b30e3218819e48e2292a5693c096eecf94b08`.
- D1 declares the policy/API, D2 extracts the implementation and legacy wrapper, D3 applies family conflicts and health gating, and D4 is a design-time minimal noop.

TODO/encoding, SyntaxOnly, D1-D4, full-definition checking without RoundTag, and all three Vx safety regressions pass. The final A+B effective set passes focused compilation, nine-architecture `lto-auto` builds, 9/9 local hashes, Linux/QEMU and win32/win64 smoke, Golden, three-origin referral, Step47 preflight 5/5, and the preclass table guard. Archived evidence: `out/artifacts/wp13b1_validation/20260829-120009`.

### 10.2 Checklist B: bare transport wiring

- Definition: `testdata/autopilot_code_step_tasks_20270701_20270707.json`.
- Goal: create the bare byte-transport contract and implementation, then route lookup send/receive/close through it without changing fd ownership, timeout, buffer, signal, error, or close-reason behavior.
- Excluded: HTTP CONNECT, SOCKS, TLS, proxy configuration, and connection reuse.
- Frozen targets: `net_header` and `net_source` overlap A; `transport_header` = `include/wc/wc_transport.h` (create c-header), `transport_source` = `src/core/transport.c` (create c-source), `lookup_send` = `src/core/lookup_exec_send.c`, and `lookup_recv` = `src/core/lookup_exec_recv.c` (existing c-source), with `defaultTarget=lookup_send`.
- `target_set_sha256=1d22100e1bb2b1966509b93d5cbc3bacc383cd9833ef72a42c547e35e946a667`.
- D1/D2 create the transport declaration/definition; D3/D4 migrate lookup send/receive respectively.

SyntaxOnly, D1-D4, B's prerequisite-chain full-definition check against A, and effective-payload hash validation pass. The complete build, Golden/referral, and Step47 evidence is shared with 10.1. At runtime B remains `blocked-by-a` until A passes, its snapshot is complete, and B's launch gate passes.

**Execution backfill (run 2026-08-29, filled 2026-08-30)**

**Checklist A backfill**

| Field | Actual value |
|---|---|
| Final status | PASS |
| started_at / completed_at / elapsed | `2026-08-29 12:59:42` → `2026-08-29 18:15:18` / `0d 05:15:37` |
| run_dir | `out/artifacts/dev_verify_multiround/20260829-130015` |
| Final result / summary | `out/artifacts/dev_verify_multiround/20260829-130015/final_status.json` (Result=pass, ExitCode=0, 8/8 rounds, FailedRoundTags=[]), `summary.csv` |
| task-static / code-step artifact | Per-D-round hash-bound checker and code-step artifacts inside run_dir; no task-definition repair transaction |
| Snapshot manifest / target set SHA-256 | `target_set_sha256=7918987e6f12e6cde433c258b93b30e3218819e48e2292a5693c096eecf94b08`; A success snapshot integrity passed |
| Incidents / self-heal / restart | NONE (no incidents, recovery_attempts=0, no restarts) |
| RFC backfill date | 2026-08-30 |

**Checklist B backfill**

| Field | Actual value |
|---|---|
| A PASS & snapshot gate | PASS (A final_status.json Result=pass, ExitCode=0) |
| Final status | PASS |
| started_at / completed_at / elapsed | `2026-08-29 18:14:36` → `2026-08-29 23:38:35` / `0d 05:24:00` |
| run_dir | `out/artifacts/dev_verify_multiround/20260829-181508` |
| Final result / summary | `out/artifacts/dev_verify_multiround/20260829-181508/final_status.json` (Result=pass, ExitCode=0, 8/8 rounds, FailedRoundTags=[], GeneratedAt=23:37:36), `summary.csv` |
| task-static / code-step artifact | Per-D-round hash-bound checker and code-step artifacts inside run_dir; no task-definition repair transaction |
| Incidents / self-heal / restart | NONE |
| RFC backfill date | 2026-08-30 |

**Final wrap-up**

- A/B summary: A and B both passed first try (8/8 rounds), no stalls, restarts, or auto-fixes; SESSION=PASS. Event tickets closed: `a-pass-conclusion-b-started` (T20260829-181518844-f18488a6, handled_at 2026-08-29 18:17:25) and `chat-session-final-status` (chat-final-20260829-233835, handled_at 2026-08-29 23:39:40); event-only mode emitted no routine status tickets.
- Combined A/B elapsed: `0d 10:38:54` (session start `2026-08-29 12:59:42` → `2026-08-29 23:38:35`).
- Post-run Strict validation (2026-08-30): remote build + smoke sync + Golden check (Strict Version) via `WHOIS_STRICT_VERSION=1 tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -q '8.8.8.8 1.1.1.1 10.0.0.8' -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 -a '' -G 1 -E '' -O 'lto-auto' -K 0 -N 0` → no warnings + no lto warnings + Local hash verify: PASS + Golden PASS + referral check: PASS, exit code 0, 219s, log dir `out/artifacts/20260830-001936`.
- The post-completion review found no high-severity regression in the current direct path, fd ownership, close reasons, or build integration; the Makefile wildcard includes `src/core/transport.c`.
- The transport extension gap found by that review is closed. `wc_transport_t` now dispatches `read/write/wait/close` through injectable ops/context, with the bare socket as the default adapter. `wc_transport_send_all_until` and `wc_transport_wait_until` share an absolute monotonic deadline while existing lookup-level calls and response idle-timeout semantics remain unchanged. Deterministic `tools/test/transport_contract_test.ps1` coverage includes adapter dispatch, partial writes, reads, wait deadlines, timeout, close, and invalid transports; existing selftests now cover policy defaults with health recording disabled, invalid families, numeric-literal family conflicts, and DNS-health hook isolation.
- Post-review validation (2026-08-30): focused strict clang syntax checks and the transport contract passed; nine-architecture `lto-auto` build/smoke/selftest, 9/9 local hashes, Golden, and three-origin referral checks passed in 275s. Evidence is under `out/artifacts/20260830-010926`; no release directory was synchronized or rewritten.
- DNS-health isolation contract (2026-08-30): a selftest counter directly proves that `record_dns_health=0` does not call the target health hook, with `record_dns_health=1` as the positive control. x86_64, win64, and win32 smoke/selftest and local hashes passed in 143s (`out/artifacts/20260830-012006`). WP-13B-2 may proceed to Vx task-definition design for configuration/CLI/environment parsing, HTTP CONNECT, and per-hop bypass, subject to the full section 9 acceptance gates.
- Final synchronized-artifact audit (2026-08-30): the Strict Version `lto-auto` nine-architecture remote build, default-query smoke, two-directory sync, Golden, and referral checks all passed with no compiler/LTO warnings in 241s (`out/artifacts/20260830-014939`). Independent SHA-256 recomputation for all nine archived binaries matches `SHA256SUMS-static.txt`, and the repository release manifest is byte-for-byte identical to the archive. Linux/QEMU, win32, and win64 default smoke preserves the query-header and authoritative-tail contracts for `8.8.8.8`, `1.1.1.1`, and `10.0.0.8`. Golden passed directly against the primary `8.8.8.8` smoke; IANA, ARIN, and AFRINIC referral origins converged to AFRINIC with 3/2/1 successful connection attempts and zero failures. This round did not enable `--selftest`; focused transport/policy/health-isolation evidence remains in the `010926`/`012006` rounds above. No code fix is required.
- WP-13C (SOCKS4/4a) and WP-13D (HTTPS proxy TLS) continue under section 9. WP-13D's TLS dependency gate is now cleared, but independent readiness review and production acceptance are still required.
- Backfill consistency across the authoritative document set: YES (CN/EN sections in this file).
- No commit or push without explicit user authorization.

## 11. WP-13B-2 next-start checklist

Status: **ready, awaiting launch authorization**. The planned window is `2027-07-08 ~ 2027-07-21`, using `schemaVersion=vx-draft`, `strict-enforce`, and serial event-only A/B. The active start file is `testdata/unattended_start/active/unattended_ab_start_20270708-20270721.md`. This RFC is the sole authoritative document.

Shared gates: A and B run serially. B remains `blocked-by-a` until A passes, its success snapshot is complete, and B's launch gate passes. No commit, push, or execution-result backfill occurs before launch.

### 11.1 Checklist A: configuration, CLI, and environment preflight

- Definition: `testdata/autopilot_code_step_tasks_20270708_20270714.json`; D1-D4 + V1-V4; `defaultTarget=opts_source`.
- Goal: freeze proxy configuration, CLI/environment precedence, authority-only URLs, credential and family conflicts, plus deterministic resolver/selftests. A fails closed when a proxy is configured and does not route proxy traffic.
- Excluded: HTTP CONNECT, SOCKS, TLS, and per-hop `NO_PROXY` routing. Default direct mode, stdout, RIR referrals, DNS health, batch strategy, and retry metrics remain unchanged.
- Frozen targets: `config_header`, `opts_header`, `opts_source`, `client_meta_source`, `client_runner_source`, `meta_source`, and `selftest_source`, all existing targets at the paths declared in the task definition.
- `target_set_sha256=150b6f49ab217b65e2c048f407023d8d74dc69feaf670ccfeb5db71ad52a099b`; task-definition SHA-256 `df34348b618e8f6a3c164c85dd1f0649ce2a0744a91a586d02026411d2b56f5b`.

TODO/encoding, SyntaxOnly, D1-D4, full-definition checking without RoundTag, Vx safety regressions, and the A effective-payload hash all pass.

**Execution backfill (run 2026-08-30 ~ 2026-08-31, filled 2026-08-31)**

**Checklist A backfill**

| Field | Actual value |
|---|---|
| Final status | PASS |
| started_at / completed_at / elapsed | `2026-08-30 13:36:33` → `2026-08-30 18:46:02` / `0d 05:09:29` |
| run_dir | `out/artifacts/dev_verify_multiround/20260830-133709` |
| Final result / summary | `out/artifacts/dev_verify_multiround/20260830-133709/final_status.json` (Result=pass, ExitCode=0, 8/8 rounds, FailedRoundTags=[]), `summary.csv` |
| task-static / code-step artifact | Per-D-round hash-bound checker and code-step artifacts inside run_dir (`D*_validated_artifact/`); no task-definition repair transaction |
| Snapshot manifest / target set SHA-256 | `target_set_sha256=150b6f49...`; A success snapshot integrity passed |
| Incidents / self-heal / restart | NONE (no incidents, no restarts) |
| RFC backfill date | 2026-08-31 |

### 11.2 Checklist B: HTTP CONNECT and per-hop bypass

- Definition: `testdata/autopilot_code_step_tasks_20270715_20270721.json`; D1-D4 + V1-V4; `defaultTarget=proxy_source`.
- Goal: implement HTTP CONNECT, the explicit cleartext Basic-auth gate, absolute monotonic deadlines, per-hop `NO_PROXY`, and all primary/override/fallback/empty-response connection paths. Proxy failures remain terminal and do not affect target DNS health or batch strategy.
- Excluded: SOCKS4/4a, the SOCKS5/5h data plane, HTTPS-proxy TLS, connection reuse, and silent direct fallback.
- Frozen targets: the seven A targets plus `net_header`, `net_source`, `proxy_header` (create), `proxy_source` (create), `lookup_header`, `lookup_connect`, `lookup_empty`, `lookup_loop`, and `client_flow`; all non-create targets are existing.
- `target_set_sha256=3808d4e86be49df0170add303e6acdf7e9fe7178cd526d0a445d73ac94c7d8e3`; task-definition SHA-256 `4464717b6090f69a881c0abb3aa8f6afe6a30e6f4f91508a1ffaed3fbc594404`.

SyntaxOnly, D1-D4, B's prerequisite-chain full-definition check against A, and Vx safety regressions pass. The A+B effective tree matches all 16 manifest-bound target hashes and passes nine-architecture `lto-auto` compilation, 9/9 artifact hashes, Linux/QEMU and win32/win64 smoke/selftests, Golden, and three-origin referral checks (`tmp/wp13b2-b-effective-tree/out/artifacts/20260830-053710`). Step47 preflight passes 5/5 (`tmp/wp13b2-step47-script-validation/20260830-055709`), and the preclass table guard passes (`tmp/wp13b2-b-effective-tree/out/artifacts/preclass_table_guard/20260830-061317`).

**Execution backfill (run 2026-08-30 ~ 2026-08-31, filled 2026-08-31)**

**Checklist B backfill**

| Field | Actual value |
|---|---|
| A PASS & snapshot gate | PASS (A final_status.json Result=pass, ExitCode=0; A snapshot manifest/hash integrity passed) |
| Final status | PASS |
| started_at / completed_at / elapsed | `2026-08-31 01:30:36` → `2026-08-31 08:27:32` / `0d 06:56:57` |
| run_dir | `out/artifacts/dev_verify_multiround/20260831-032025` |
| Final result / summary | `out/artifacts/dev_verify_multiround/20260831-032025/final_status.json` (Result=pass, ExitCode=0, 8/8 rounds, FailedRoundTags=[], GeneratedAt=08:26:50), `summary.csv` |
| task-static / code-step artifact | Per-D-round hash-bound checker and code-step artifacts inside run_dir (`D*_validated_artifact/`); no task-definition repair transaction |
| Incidents / self-heal / restart | B first run failed with `runtime-fail` (`.Count` property error, `T20260831-024551167-8db236de`/`T20260831-024556280-6af52afe`) → three orchestration-script root-cause fixes (multiround single-line array normalization, bounded Vx artifact directory-move retry, guard A-snapshot anchor protection/reload) plus start-file `A_SUCCESS_SNAPSHOT_*` recovery → standard stop/reset/launch-ready then stage-window restart (B pid 13396, guard 15324, trigger 24908) and D1..D4 to completion (8/8) |
| RFC backfill date | 2026-08-31 |

**Final wrap-up**

- A/B summary: A passed 8/8 on the first run. B's first run failed after D1 with `runtime-fail`; after three orchestration-script fixes and A-snapshot anchor recovery it was restarted and the second run passed 8/8 from D1. `A_FINAL_STATUS=PASS`, `B_FINAL_STATUS=PASS`, `SESSION_FINAL_STATUS=PASS`.
- Combined A/B elapsed: `0d 18:51:00` (session start `2026-08-30 13:36:33` → `2026-08-31 08:27:32`, including launcher/preflight, A→B handover, and recovery intervals).
- Event tickets closed: `T20260831-024551167-8db236de` (diagnose-only review), `T20260831-024556280-6af52afe` (incident-captured, route guard classified `incident-auto-resume-noncode`; recovery transaction fail-closed because the A snapshot anchor was corrupted, with no fabricated receipt; fixed after user authorization), and `chat-final-20260831-082732` (handled_at 2026-08-31 08:28:44).
- Post-run Strict validation (2026-08-31): `WHOIS_STRICT_VERSION=1 tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -q '8.8.8.8 1.1.1.1 10.0.0.8' -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 -a '' -G 1 -E '' -O 'lto-auto' -K 0 -N 0` → no warnings + no lto warnings + Local hash verify: PASS + Golden PASS + referral check: PASS, exit code 0, 254s, log dir `out/artifacts/20260831-091653` (nine-architecture artifacts with `SHA256SUMS-static.txt`).
- Editor IntelliSense compatibility fix (2026-08-31): `UINT64_MAX` inside `wc_proxy_selftest` produced a false positive “extra text after end of number” (code 19) under VS Code C/C++ IntelliSense (`windows-msvc-x64` with clang-cl and only the default workspace include path), while real GCC/Clang C11 builds and the remote nine-architecture build were unaffected. It is now replaced by a selftest-local `const uint64_t no_deadline = ~(uint64_t)0;` reused across all cases; the value is exactly equivalent to `UINT64_MAX` (all-ones, no timeout), does not depend on implementation-specific integer suffixes, and touches only the `src/core/proxy.c` selftest path. Production CONNECT/NO_PROXY logic and output contracts are unchanged.
- Post-fix revalidation (2026-08-31): Strict Version `lto-auto` remote build + smoke sync + Golden check re-run passed with no warnings, no LTO warnings, Local hash verify PASS, Golden PASS, and referral check PASS (exit 0, 270s, log dir `out/artifacts/20260831-095325`; local recomputation of all 9 SHA-256 hashes matches `SHA256SUMS-static.txt`, and the IANA → ARIN → AFRINIC referral chain converges correctly).
- Review conclusion: default direct connect, stdout, RIR referral, DNS health, batch strategy, and retry-metrics contracts remain unchanged; no further code fix is required.
- WP-13C (SOCKS4/4a) and WP-13D (HTTPS proxy TLS) continue under section 9. WP-13D's TLS dependency gate is now cleared, but independent readiness review and production acceptance are still required.
- Backfill consistency across the authoritative document set: YES (CN/EN sections in this file + RELEASE_NOTES + RFC-whois-client-split).
- No commit or push without explicit user authorization.

## 14. WP-13D HTTPS proxy TLS next-start checklist

Status: **execution and production acceptance complete (SESSION=PASS / A=PASS / B=PASS)**. The planned window was `2027-08-05 ~ 2027-08-18`; the actual run completed on 2026-09-02 with `schemaVersion=vx-draft`, `strict-enforce`, and serial event-only A/B. The active start file is `testdata/unattended_start/active/unattended_ab_start_20270805-20270818.md`.

### 14.1 Checklist A: connection transport ownership

- Definition: `testdata/autopilot_code_step_tasks_20270805_20270811.json`; definition SHA-256 `78f21ce56b111b00066f72d7502b4b73baff3118474bef64bc67adf23e442159`.
- Goal: make `wc_net_info` the sole owner of one hop connection, provide unified `init/get/adopt/move/close`, and move proxy, candidate/empty-response fallback, send, receive, and signal close paths onto that ownership contract.
- Frozen target set: `net_header`, `net_source`, `proxy_source`, `lookup_connect`, `lookup_empty`, `lookup_send`, `lookup_recv`, `lookup_loop`, and `selftest_source`, all existing; `target_set_sha256=8a3176bf267040b886b1cd7cbb48b545b228fa7c673094b223f5bfd4cad09957`.
- D1 declares and implements ownership APIs; D2 migrates proxy/connect/empty; D3 migrates send/receive/loop; D4 adds custom-transport move and idempotent close-once selftests.

### 14.2 Checklist B: HTTPS scheme and OpenSSL TLS transport

- Definition: `testdata/autopilot_code_step_tasks_20270812_20270818.json`; definition SHA-256 `f2d45a5599b4fd39fff4995b06cb18abd25b140857bea3c8cf681320bfccd32a`; runtime must use A as its prerequisite.
- Goal: add `https://` and default port 443; fail before lookup as unsupported in ordinary builds; with `WHOIS_TLS=1`, use OpenSSL 3.5.8 with mandatory peer/hostname/IP verification, SNI, TLS 1.2 minimum, the pinned CA bundle or a fail-closed non-empty `SSL_CERT_FILE` override, and one absolute monotonic deadline across TLS handshake and HTTP CONNECT.
- Frozen target set: A's nine targets plus existing `config_header`, `proxy_header`, and `opts_source`, and create targets `tls_header=include/wc/wc_tls.h` and `tls_source=src/core/tls.c`; `target_set_sha256=4d171a4202c4c3bbec9d945aa884a44a0fcb72b3d619362eef590cb1d279af99`.
- D1/D2 create the complete TLS header/source; D3 adds the scheme, build gate, and parser selftests; D4 inserts TLS after proxy TCP and before CONNECT, adopts it into A's owner, and adds stable classifications and deterministic TLS selftests.

### 14.3 Authoring evidence and execution backfill

- Both definitions are UTF-8 BOM + LF, TODO-free, and pass SyntaxOnly, D1-D4, and all three Vx infrastructure regressions. B's full-definition check with A as prerequisite passes with `errors=0 warnings=0` under the official `WorkerTimeoutMs=120000`; internal regex timeout and operation-safety enforcement remain unchanged.
- The isolated effective tree passes remote x86_64/win64 compilation for both the default stub and `WHOIS_TLS=1` OpenSSL paths. The TLS win64 artifact remains full-static and local artifact hashes pass. This is authoring-time quick-build evidence, not section 9 production acceptance.
- A run=`out/artifacts/dev_verify_multiround/20260902-090840` and B run=`out/artifacts/dev_verify_multiround/20260902-160535`; both report `Result=pass`, `ExitCode=0`, 8/8 rounds, and no failed tags. B ran from `2026-09-02 16:05:02` through `23:45:35` (`0d 07:40:33`); the combined A/B session ran from `09:08:04` through `23:45:35` (`0d 14:37:31`) and closed at `23:47:12`.
- One pre-launch remote network check was blocked by an SSH timeout; after network recovery, a clean precheck preceded Stage A. A D1 then saw a transient access denial while moving a Vx artifact, but bounded retry published it and the checker ended with `errors=0 warnings=0`; no script incident, code self-heal, or stage restart occurred.
- CA/build preparation passed `WHOIS_TLS=1` TLS/LTO across all nine architectures, 9/9 hashes, Windows full-static mode, and dependency audit (`out/artifacts/20260901-170601`). Authoring also passed default-stub and TLS x86_64/win64 quick builds plus deterministic TLS loopback certificate/hostname/failure-class contracts. Ordinary builds intentionally keep `WHOIS_TLS=0` and the OpenSSL-free unsupported stub; they must not be described as HTTPS-enabled artifacts.

### 14.4 Final regression and release-candidate review (2026-09-03)

- Default and debug/retry/DNS-stats/interleave-v4-first Strict Version `lto-auto` rounds completed all nine architectures with 9/9 SHA-256, Golden, and referral PASS (`out/artifacts/20260903-003613`, `out/artifacts/20260903-004426`) and no compiler, LTO, or linker warnings. GNU tar messages about ignored GnuPG Unix sockets are harmless archive notices, not build warnings.
- All four Batch Golden strategies (raw/health-first/plan-a/plan-b) pass (`out/artifacts/batch_raw/20260903-005136` through `out/artifacts/batch_planb/20260903-011010`); standalone core plus all four strategy Selftest Goldens pass 5/5 (`out/artifacts/batch_raw/20260903-012001` through `out/artifacts/batch_planb/20260903-013853`). Negative-contract text such as `Private query denied` and `Suspicious query detected` is expected assertion output.
- The 12x6 redirect matrix contains 72/72 case files and analysis rows, an empty authority-mismatch file, and `errors=(no errors found)` (`out/artifacts/redirect_matrix_10x6/20260903-014154`). CIDR body is 4/4, the draft matrix is 9/9, and the bundle reports `result=pass`, `exit_code=0` (`out/artifacts/cidr_bundle/cidr_bundle_summary_20260903-015526.txt`). Default direct, stdout/stderr, authority, referral, CIDR, and Step47 contracts remain unchanged; no code fix is required.

### 14.5 Product-delivery closure

- The official remote static builder defaults to `WHOIS_TLS=1`, and both full release and one-click release explicitly pin that value. Callers may still set `WHOIS_TLS=0` for an OpenSSL-free compatibility artifact; normal local `make` keeps its existing default.
- `--help` lists HTTP/HTTPS/SOCKS4/4a/5/5h, default ports, credentials, and environment variables, then reports `HTTPS proxy TLS backend: enabled|disabled` from the actual compile-time capability.
- The Chinese and English usage guides provide executable HTTPS-proxy, public-CA, private `SSL_CERT_FILE`, Windows, and POSIX examples. Users of official releases no longer need to understand or set the internal build flag.
- The final product-delivery run, without an explicit `WHOIS_TLS`, reports `WHOIS_TLS='1'` and passes Strict `lto-auto` across all nine architectures, Windows full-static mode, network smoke, 9/9 local hashes, Golden, and all three referral origins with no warning/error in the logs. It synchronizes both official release directories (`out/artifacts/20260903-040906`, 410s). The synchronized win64 `--help` reports `HTTPS proxy TLS backend: enabled`; both manifests are byte-identical and independent artifact hashes pass 9/9.
- The final post-copy-review run again passes the Strict `lto-auto` nine-architecture build and synchronization (`out/artifacts/20260903-045122`, 360s). Linux/QEMU, win32, and win64 smoke complete 18/3/3 queries; all 24 query headers have authoritative tails and hard-warning count is zero. Golden passes, and the IANA, ARIN, and AFRINIC referral origins have zero errors and all converge on AFRINIC. Independent SHA-256 recomputation matches all nine manifest entries, the repository and external release manifests are byte-identical, and both Windows targets are full-static. The synchronized win64 `--help` reports the TLS backend as enabled, while `--help`, `--about`, and `--examples` contain neither the obsolete preflight-only wording nor the internal build-switch terminology. No code fix is required.

### 11.3 Joint pre-launch confirmation

- [x] Both definitions passed complete initial-authoring validation with no TODOs or placeholders.
- [x] A/B schemas, target registries, target-set hashes, and prerequisite ordering are frozen.
- [x] A+B effective source passed compilation, runtime, Golden/referral, Step47, and table-guard validation.
- [x] The active start file is generated and passes field-sync, encoding, and launch-ready dry-run checks.
- [x] The user reviewed the definitions, checklist, and start file and explicitly authorized launch (actual run 2026-08-31).

Execution backfill: completed; see the Checklist A/B backfills and Final wrap-up in sections 11.1/11.2 (2026-08-31).

## 12. WP-13B-3 SOCKS5/5h implementation record

- Implements SOCKS5 method negotiation, RFC 1929 username/password authentication, CONNECT IPv4/IPv6/domain ATYP encoding, complete REP classification, and a shared terminal-failure policy.
- `socks5://` preserves local target-DNS candidates and advances after `general-failure` or `address-type-unsupported` for one candidate. An unbypassed `socks5h://` hop uses one logical hostname candidate and does not invoke local target DNS, target DNS-health/backoff, or empty-response IP fallback. A host-level per-hop `NO_PROXY` match preserves the existing local-DNS/direct path.
- After SOCKS5H succeeds, the target IP remains unknown; neither the proxy endpoint nor an unobserved remote resolution is written into titles, authoritative trailers, or target-health state. Default direct mode, stdout, RIR referrals, batch strategy, and retry-metrics contracts are unchanged.
- Deterministic fake transports cover authentication, ATYP, REP, and remote-DNS policy. The loopback protocol/configuration spike passes 21/21 cases (`out/artifacts/proxy_protocol_spike/20260831-030507`). Strict ISO C11 clang validation is clean; an initial remote run exposed and fixed an implicit `strdup` declaration on loongarch64 by using standard `malloc` plus `memcpy`.
- The final Strict Version `lto-auto` nine-architecture build has no compiler/LTO warnings. All 9 SHA-256 checks, POSIX/QEMU and win32/win64 smoke, Golden, and three-origin IANA/ARIN/AFRINIC referral checks pass (`out/artifacts/20260831-112633`, 436s). Release directories were not synchronized.
- Final run with release synchronization (2026-08-31): Strict Version `lto-auto` remote build + smoke sync + Golden re-check pass with no warnings, no LTO warnings, and Local hash verify/Golden/referral all PASS in 284s (`out/artifacts/20260831-114158`). Both release directories (`lzispro/release/lzispro/whois` and `whois/release/lzispro/whois`) match `SHA256SUMS-static.txt` byte-for-byte; local `Get-FileHash` recheck matches 9/9.
- At this WP-13B-3 checkpoint, WP-13C (SOCKS4/4a) was not yet implemented and WP-13D still awaited its independent readiness review and production acceptance. Both were completed later; see sections 13 and 14.

## 13. WP-13C SOCKS4/4a readiness review

Status: **this run is complete and backfilled (SESSION=PASS / A=PASS / B=PASS)** (2026-09-01). It must not be combined with WP-13D; the TLS dependency gate is cleared, but WP-13D still requires an independent readiness review and production acceptance.

- The deterministic loopback spike now covers SOCKS4 IPv4, custom ports, USERID, SOCKS4a domains, CD=91 rejection, and `socks4`/`socks4a` configuration gates without regressing the existing HTTP/SOCKS5 cases; all 27/27 cases pass (`out/artifacts/proxy_protocol_spike/20260831-043917`).
- Frozen semantics: `socks4://` sends only locally resolved IPv4 candidates. `socks4a://` sends the logical hostname and shares the `socks5h://` remote-DNS conflicts for target-family, fallback, and RIR overrides, plus its target-health isolation. SOCKS4a neither claims nor infers that the proxy selected IPv6.
- USERID is the resolved credential username. The password is never sent in a SOCKS4/4a frame, and USERID is not strong authentication. Existing paired non-empty credential-source and secret-clearing rules remain unchanged; diagnostics and artifacts must not print USERID or password.
- Frozen production target closure: `include/wc/wc_config.h`, `src/core/opts.c`, `src/core/selftest.c`, `include/wc/wc_proxy.h`, `src/core/proxy.c`, and `src/core/lookup_exec_connect.c`; `src/core/lookup_exec_empty.c` is included in the checked closure as the inherited remote-DNS/IPv4-only path without a presumed source edit.
- D1 adds schemes, parsing, and configuration selftests. D2 adds the SOCKS4/4a transport handshake, CD classification, and byte-exact fake-transport contracts. D3 wires dial dispatch, redacted metrics, and terminal policy. D4 freezes SOCKS4 IPv4-only and SOCKS4a hostname-only candidate construction while proving default direct routing, per-hop bypass, and target-health isolation remain unchanged.
- The implementation definition uses `schemaVersion=vx-draft` in an independent window beginning `2027-07-22`. Before start-file generation it must still pass TODO-free, SyntaxOnly, D1-D4, Vx safety regressions, full-definition checks, focused compilation for the complete target set, Golden/referral, and Step47 validation.

### 13.1 Launch checklist

- A definition: `testdata/autopilot_code_step_tasks_20270722_20270728.json`; targets `config_header`, `opts_source`, and `selftest_source`; `target_set_sha256=d60f26e6efbd732de60766306ec9d65a1a19cf2e32b9422c6514ace84ddd8eb7`; definition SHA-256 `20382f3754b3b0a60f59572e75f547f5f04e1863a48c5922efa8fe7e818252cb`.
- B definition: `testdata/autopilot_code_step_tasks_20270729_20270804.json`; the three A targets plus `proxy_header`, `proxy_source`, `lookup_connect`, and `lookup_empty`; `target_set_sha256=adc9aea696e8a74705a52b5cd37362b37b4913b9075a2ac11f4ffbac9f554361`; definition SHA-256 `5fcb2254396fb8902b0e88aafc2aa013f21f4838aa7a9b76439bcedfe0394fad`.
- Both definitions pass TODO-free, SyntaxOnly, chained D1-D4, full-definition checks without `RoundTag`, and all three Vx infrastructure safety regressions. B explicitly uses A as its prerequisite, and the complete target union is frozen.
- An isolated effective tree applied A.D1-D4 and B.D1-D4 through the production checker artifact and code-step flow. Strict Version `lto-auto` nine-architecture builds, 9/9 hashes, Linux/QEMU and win32/win64 smoke/selftests, Golden, and three-origin referral checks all pass (`tmp/wp13c-effective-tree/out/artifacts/20260831-132412`).
- Windows Step47 preflight explicitly uses `release/lzispro/whois/whois-win64.exe` and passes 5/5 (`out/artifacts/step47_preclass_preflight/20260831-135424`); `whois-x86_64` is Linux-only. The effective-tree preclass table guard also passes (`tmp/wp13c-effective-tree/out/artifacts/preclass_table_guard/20260831-141343`).
- Active start file: `testdata/unattended_start/active/unattended_ab_start_20270722-20270804.md`; event-only, strict-enforce, serial A/B, with `LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED=false`. Field sync, A/B SyntaxOnly, incremental encoding, and the stage-A launch-ready dry-run all pass. No launch, commit, or push occurs without explicit user authorization.

**Execution backfill (run 2026-08-31 ~ 2026-09-01, filled 2026-09-01)**

**Checklist A backfill**

| Field | Actual value |
|---|---|
| Final status | PASS |
| started_at / completed_at / elapsed | `2026-08-31 15:08:58` → `2026-08-31 20:51:29` / `0d 05:42:32` |
| run_dir | `out/artifacts/dev_verify_multiround/20260831-150933` |
| Final result / summary | `out/artifacts/dev_verify_multiround/20260831-150933/final_status.json` (Result=pass, ExitCode=0, 8/8 rounds, FailedRoundTags=[], GeneratedAt=20:49:36), `summary.csv` |
| task-static / code-step artifact | Per-D-round hash-bound checker and code-step artifacts inside run_dir (`D*_validated_artifact/`); no task-definition repair transaction |
| Snapshot manifest / target set SHA-256 | `target_set_sha256=d60f26e6efbd732de60766306ec9d65a1a19cf2e32b9422c6514ace84ddd8eb7`; A success snapshot integrity passed |
| Incidents / self-heal / restart | NONE (no incidents, recovery_attempts=0, no restarts) |
| RFC backfill date | 2026-09-01 |

**Checklist B backfill**

| Field | Actual value |
|---|---|
| A PASS & snapshot gate | PASS (A final_status.json Result=pass, ExitCode=0) |
| Final status | PASS |
| started_at / completed_at / elapsed | `2026-08-31 20:50:40` → `2026-09-01 03:10:37` / `0d 06:19:58` |
| run_dir | `out/artifacts/dev_verify_multiround/20260831-205121` |
| Final result / summary | `out/artifacts/dev_verify_multiround/20260831-205121/final_status.json` (Result=pass, ExitCode=0, 8/8 rounds, FailedRoundTags=[], GeneratedAt=03:09:28), `summary.csv` |
| task-static / code-step artifact | Per-D-round hash-bound checker and code-step artifacts inside run_dir (`D*_validated_artifact/`); no task-definition repair transaction |
| Incidents / self-heal / restart | NONE (no incidents, b_recovery_attempts=0, no restarts) |
| RFC backfill date | 2026-09-01 |

**Final wrap-up**

- A/B summary: A and B both passed first try (8/8 rounds), with no stalls, restarts, or auto-fixes. `A_FINAL_STATUS=PASS`, `B_FINAL_STATUS=PASS`, `SESSION_FINAL_STATUS=PASS`. Event tickets closed: `T20260831-205129509-bb7b885e` (a-pass-conclusion-b-started, handled_at 2026-08-31 20:54:38) and `chat-final-20260901-031037` (chat-session-final-status, handled_at 2026-09-01 03:12:26); event-only mode emitted no routine status tickets.
- Combined A/B elapsed: `0d 12:01:40` (session start `2026-08-31 15:08:58` → `2026-09-01 03:10:37`, including launcher/preflight and the A→B handover interval).
- Post-run Strict validation (2026-09-01): `WHOIS_STRICT_VERSION=1 tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -r 1 -q '8.8.8.8 1.1.1.1 10.0.0.8' -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 -a '' -G 1 -E '' -O 'lto-auto' -K 0 -N 0` → no warnings + no lto warnings + Local hash verify: PASS + Golden PASS + referral check: PASS, exit code 0, 755s, log dir `out/artifacts/20260901-121843`.
- Review conclusion: default direct connect, stdout, RIR referral, DNS health, batch strategy, and retry-metrics contracts remain unchanged; no further code fix is required.
- At this WP-13C checkpoint, WP-13D's TLS dependency gate was cleared while its independent readiness review and production acceptance remained pending. WP-13D later completed them; see section 14.
- Backfill consistency across the authoritative document set: YES (CN/EN sections in this file + RELEASE_NOTES + RFC-whois-client-split).
- No commit or push without explicit user authorization.