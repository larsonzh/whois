# RFC：RIR 代理访问 / RIR Proxy Access

状态 / Status：WP-13A 契约与依赖探针实施中 / active contract and dependency spike.

# 中文版

## 1. 目的

本文定义 WHOIS TCP 连接的代理访问方式，同时保持默认直连行为、referral 语义、DNS 健康记忆、权威 RIR 判定和 stdout 契约不变。

交付顺序如下：

1. WP-13A：冻结契约，并通过本地确定性探针验证协议与依赖假设。
2. WP-13B：基于 transport 抽象交付 HTTP CONNECT 与 SOCKS5/5h。
3. WP-13C：以兼容扩展形式增加 SOCKS4/4a。
4. WP-13D：仅在 TLS 后端通过九架构静态链接门禁后增加 HTTPS proxy。

WP-13A 不改变任何生产网络路径。

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

HTTPS proxy 延后至 WP-13D。其含义是客户端到 HTTP 代理之间使用 TLS，再执行 CONNECT；隧道内的 WHOIS 仍为明文 TCP。证书与主机名验证是强制要求，不计划提供不安全验证模式。

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

该探针仅使用 IPv4 loopback，验证精确 HTTP CONNECT authority、HTTP 状态保留、SOCKS5 IPv4/IPv6/domain 编码、username/password 协商、自定义端口和 REP 保留，并写入 `out/artifacts/proxy_protocol_spike/<timestamp>/report.json`。

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

生产验收仍须通过 x86_64/win32/win64 聚焦合同、九架构 Strict 构建、Golden/referral、Batch/Selftest/CIDR/Redirect/Step47、默认直连输出冻结，并同步中英文使用文档。

## 10. WP-13B-1 下次开工清单

状态：准备完成，待启动授权。运行窗口为 `2027-06-24 ~ 2027-07-07`，使用 `schemaVersion=vx-draft`、`strict-enforce`、event-only 串行 A/B；B 仅在 A 最终 PASS 且 A 成功快照完整性通过后启动。active start-file 为 `testdata/unattended_start/active/unattended_ab_start_20270624-20270707.md`。不得在用户明确授权前启动、提交或推送。

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

It uses IPv4 loopback only and validates exact HTTP CONNECT authorities, HTTP status preservation, SOCKS5 IPv4/IPv6/domain encoding, username/password negotiation, custom ports, and REP preservation. It writes `out/artifacts/proxy_protocol_spike/<timestamp>/report.json`.

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

Production acceptance still requires focused x86_64/win32/win64 contracts, nine-architecture Strict builds, Golden/referral, Batch/Selftest/CIDR/Redirect/Step47, default-direct output freezing, and synchronized Chinese/English usage documentation.

## 10. WP-13B-1 next-start checklist

Status: ready, awaiting launch authorization. The `2027-06-24 ~ 2027-07-07` window uses `schemaVersion=vx-draft`, `strict-enforce`, and serial event-only A/B execution. B starts only after A passes and its success snapshot passes integrity validation. The active start file is `testdata/unattended_start/active/unattended_ab_start_20270624-20270707.md`. No launch, commit, or push is authorized yet.

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