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
| `--proxy-family auto\|v4\|v6` | 待定 | 仅控制代理端点地址族，不得隐式复用目标地址族偏好。 |
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

凭据来源仍待安全评审冻结；冻结前不得开始生产认证实现。测试可使用内存凭据，但报告只能包含 case 名称。

## 4. DNS 与地址族契约

- `http://` 和 `socks5://` 使用本地目标解析；现有目标候选顺序、地址族控制和健康记忆保持权威。
- `socks5h://` 将域名发送给代理。由于无法观测代理最终选择的目标地址族，13B 中它与 `--ipv4-only`、`--ipv6-only`、per-RIR family override 及 candidate fallback 控制不兼容；这些组合必须在 lookup 前失败。
- 在 `--proxy-family` 冻结前，代理端点以 `AF_UNSPEC` 独立解析。
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

本 RFC 与协议探针通过评审后，WP-13B-1 方可进入任务定义设计。凭据来源冻结前，WP-13B 认证仍保持 blocked。仅当同一获批后端的 TLS 探针通过七个 POSIX 目标及 win32/win64，且其许可证、CVE 与更新策略均已记录后，WP-13D 才能解除 blocked。

生产验收仍须通过 x86_64/win32/win64 聚焦合同、九架构 Strict 构建、Golden/referral、Batch/Selftest/CIDR/Redirect/Step47、默认直连输出冻结，并同步中英文使用文档。

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
| `--proxy-family auto\|v4\|v6` | open | Controls only the proxy endpoint family. It must not reuse target-family preferences implicitly. |
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

The credential source remains open for security review. Until it is frozen, production authentication work must not begin. Tests may use in-memory credentials and must report case names only.

## 4. DNS and address-family contract

- `http://` and `socks5://` use local target resolution. Existing target candidate ordering, family controls, and health memory remain authoritative.
- `socks5h://` sends a domain name to the proxy. Because the selected target address family is unobservable, it is incompatible in 13B with `--ipv4-only`, `--ipv6-only`, per-RIR family overrides, and candidate fallback controls. These combinations fail before lookup.
- The proxy endpoint resolves independently with `AF_UNSPEC` until `--proxy-family` is frozen.
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

WP-13B-1 may enter task-definition design after this RFC and the protocol spike are reviewed. WP-13B authentication remains blocked until the credential source is frozen. WP-13D remains blocked until the TLS probe passes all seven POSIX targets plus win32 and win64 with one approved backend and its license/CVE/update policy documented.

Production acceptance still requires focused x86_64/win32/win64 contracts, nine-architecture Strict builds, Golden/referral, Batch/Selftest/CIDR/Redirect/Step47, default-direct output freezing, and synchronized Chinese/English usage documentation.