# whois 客户端使用说明（中文）

本说明适用于项目内置的轻量级 whois 客户端（C 语言实现，静态编译，零外部依赖）。二进制覆盖多架构，例如 `whois-x86_64`、`whois-aarch64` 等，以下示例以 `whois-x86_64` 为例。

提示：自 3.2.5 起，界面输出统一为英文（English-only），避免在不支持中文的 SSH 终端出现乱码；原 `--lang` 与 `WHOIS_LANG` 已移除。

## 目录

- [1. 快速开始](#1-快速开始)
- [2. 输出契约](#2-输出契约)
- [3. 命令行参数参考](#3-命令行参数参考)
- [4. 批量模式](#4-批量模式)
- [5. 常用示例](#5-常用示例)
- [6. 退出码](#6-退出码)
- [7. 提示与故障排查](#7-提示与故障排查)
- [8. 相关文档与集成](#8-相关文档与集成)

## 1. 快速开始

单条查询（自动跟随 referral 重定向，最多 `-R` 次，默认 6）：

```sh
whois-x86_64 8.8.8.8
whois-x86_64 example.com
```

指定起始服务器并禁止重定向：

```sh
whois-x86_64 --host apnic -Q 103.89.208.0
```

批量查询（`-B` 显式或 stdin 非 TTY 自动开启）：

```sh
cat ip_list.txt | whois-x86_64 -B --host apnic
```

主要特性：非阻塞连接、超时与轻量重试；自动跟随 referral（带循环保护）；稳定头/尾输出契约；批量 stdin 输入；条件输出引擎（`-g` → `--grep*` → `--fold`）；可选 HTTP CONNECT 代理；DNS/IP 家族偏好与负向缓存；诊断/安全日志。

权威判定、跳转顺序与 CIDR 语义以 `docs/RFC-ipv4-ipv6-whois-lookup-rules.md` 为最终基线；代理行为见 `docs/RFC-proxy-access.md`。

## 2. 输出契约

先看几个贯穿本文的术语（普通用户快速理解）：

- **WHOIS** — 一种用来回答“这个 IP/域名归谁”的协议/服务，传统上是明文 TCP 43 端口；本客户端就是去查这些服务器的。
- **RIR** — 五个地区性互联网注册机构：ARIN（北美）、APNIC（亚太）、RIPE NCC（欧洲/中东）、LACNIC（拉美）、AFRINIC（非洲）。它们负责分配 IP/AS 号并保存 WHOIS 记录。
- **IANA** — 互联网号码分配局，把大段地址分给各 RIR；很多查询会从 IANA 开始或被其提示。
- **referral（权威指引）** — 服务器回复“该地址由另一个 RIR 管理，请去问它”；客户端自动跟随（有跳数上限）。
- **权威（authoritative）** — 真正拥有该记录的服务器；尾行 `=== Authoritative RIR: ... ===` 就是最终判定。
- **跳（hop）** — 一次“连接某个服务器并查询”的过程；跟随 referral 就形成多跳链路。
- **CIDR** — `192.0.2.0/24` 表示一段地址范围（`/24` 是前缀长度）；IPv6 同理（如 `2001:db8::/32`）。
- **私网 IP** — RFC1918 的 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 等；客户端能识别，直接输出 `unknown` 且不联网。
- **标题行与续行** — WHOIS 正文形如 `NetName: Foo` 的字段行，其下以空格缩进直到下一个标题的行称为“块/续行”；`-g`/`--grep` 就是按这个结构过滤的。
- **折叠（fold）** — 把筛选后的正文压缩为一行（`<query> 值1 值2 ... RIR`），方便 awk/grep 聚合。
- **批量（batch）** — 每行一个查询，各自独立输出；适合 `cat 列表 | whois -B`。
- **预分类（preclass）** — 联网查询前，客户端先对照内置的“IANA 特殊/保留地址表”判断该地址属于哪一类（保留、特殊用途、普通公网等），从而决定：要不要真去查、优先连哪家 RIR、能否提前直接给出 `unknown`。
- **Phase A / B / C** — 内部实施阶段代号（普通用户无需关心）：A=**影子模式**（只打印分类诊断，不改变任何查询行为）；B=**默认首跳迁移**（让分类器决定先连哪家 RIR）；C=**保留/特殊地址早收敛**（对高置信的保留/特殊用途地址不再联网，直接输出 `Address Status:` 并收敛到 `unknown @ unknown`）。
- **P0 / P1 / P2** — 工程化步骤代号：P0=**观测**（先看分类结果）；P1=**受控动作**（在默认关闭的试验开关下，对少量候选执行“提前返回 unknown”等特殊行为，可用候选列表/等级治理）；P2=**放量门禁与回退**（发布前验证与一键回退）。普通用户一般不会用到，它们只影响部分“保留/特殊地址”是否提前返回。
- **Step 4.7** — 开发路线中的受控能力项（实施步骤 4.5/4.6/4.7 的第 4.7 步），与“reserved 早收敛”相关；`--enable-step47-trial` 等开关默认关闭，用于逐步放量验证。

### 头/尾与折叠契约

- 头行：`=== Query: <查询项> via <起始服务器标识> @ <实际连通IP或unknown> ===`
  - 查询项位于第 3 字段（`$3`）；标识保留用户输入的别名或映射后的 RIR 主机名；`@` 段恒为首次连通的真实 IP（DNS 失败时为 `unknown`）。
- 尾行：`=== Authoritative RIR: <权威RIR域名> @ <其IP|unknown|error> ===`
  - IP 字面量会映射回对应 RIR 域名；已知别名/子域（如 `whois-jp1.apnic.net`）会归一化为 canonical 域名。仅当尾行为 `error @ error` 时才在 stderr 输出 `Error: Query failed for ...`，否则不输出失败行。
- 折叠行：`<query> <UPPER_VALUE_1> <UPPER_VALUE_2> ... <RIR>`（无 IP），折叠后权威 RIR 为最后一个字段 `$(NF)`。
- 私网 IP：正文输出 `<ip> is a private IP address`，尾行 `=== Authoritative RIR: unknown ===`（隐式查询另见 `Address Status:` 行）。
- 附加跳：多跳中首个“无明确 referral 触发的附加跳”显示为 `=== Additional query to ... ===`（而非 `=== Redirected query to ... ===`），属预期行为。
- 空响应告警：`=== Warning: empty response from <host>, retrying ... ===`（stdout），不计入跳数。
- stdout 仅业务输出；stderr 仅诊断/指标（`[RETRY-*]`、`[DNS-*]`、`[SELFTEST]`、`[INFO]` 等）。

## 3. 命令行参数参考

```
Usage: whois-<arch> [OPTIONS] <IP or domain>
```

### 3.1 元信息

| 参数 | 说明 |
|------|------|
| `-H, --help` | 显示帮助并退出 |
| `-v, --version` | 显示版本并退出 |
| `-l, --list` | 列出内置 RIR 服务器别名 |
| `--about` | 显示功能与模块说明 |
| `--examples` | 显示扩展示例 |

说明：纯元信息选项直接返回，不触发运行期初始化（stdout/stderr 契约不变）。

### 3.2 核心查询

| 参数 | 说明 |
|------|------|
| `-h, --host HOST` | 指定起始 WHOIS 服务器（别名/域名/IP 字面量，如 `apnic`、`whois.apnic.net`、`202.12.29.220`） |
| `-p, --port PORT` | WHOIS 端口（默认 43）；不支持 `host:port` 语法 |
| `-B, --batch` | 从 stdin 逐行读取查询（禁止再写位置参数；stdin 非 TTY 时自动启用） |
| `-R, --max-redirects N` | 最大跟随 referral 跳数（默认 6）；别名 `--max-hops`。到达上限仍需跳转时立即结束，权威回落 `unknown` |
| `-Q, --no-redirect` | 等价 `-R 1`：只查首跳；若首跳返回 referral，立即结束并回落 `unknown @ unknown` |
| `-P, --plain` | 纯净输出：抑制头行、尾行与 referral 提示行 |
| `--show-non-auth-body` | 保留权威跳之前的非权威正文 |
| `--show-post-marker-body` | 保留权威跳之后的正文（与上项组合保留全部） |
| `--hide-failure-body` | 隐藏限流/拒绝类正文行（默认保留） |
| `--cidr-strip` | 查询项为 CIDR 时只发送 IP 基地址；标题行保留原始 CIDR |
| `-D, --debug` | 基础调试与 TRACE 到 stderr |

用例：

```sh
whois-x86_64 --host apnic -Q 103.89.208.0      # 固定起始 RIR 且不跟随 referral
whois-x86_64 -P 8.8.8.8                        # 纯净正文（无头/尾）
whois-x86_64 --cidr-strip -h arin 1.1.1.0/24   # CIDR 只发基地址
whois-x86_64 --show-non-auth-body --show-post-marker-body 1.1.1.1   # 保留全部跳转正文
```

### 3.3 代理（HTTP/HTTPS CONNECT / SOCKS）

代理是一台“中转服务器”：客户端把连接请求交给它，由它替你去连 WHOIS 服务器（端口 43）。当你的网络访问不了某些 RIR（例如运营商屏蔽 ARIN 的 43 端口）、或公司/校园要求走统一出口时，就可以通过代理查询。

#### 支持的代理类型（当前版本）

| 类型 | URL 示例 | 默认端口 | 用途说明 |
|------|----------|----------|----------|
| `http://` | `http://proxy.example:8080` | 8080 | HTTP CONNECT 代理：先向代理发 `CONNECT host:43`，成功后在其上跑 WHOIS 明文 TCP。最常见（公司/共享代理） |
| `https://` | `https://proxy.example:443` | 443 | HTTPS CONNECT 代理：客户端到代理先建立并验证 TLS，再发送 CONNECT；隧道内 WHOIS 仍为明文 TCP |
| `socks5://` | `socks5://proxy.example:1080` | 1080 | SOCKS5：**目标域名由本客户端本地解析**，再把解析出的 IP 交给代理（走的是你自己的 DNS） |
| `socks5h://` | `socks5h://proxy.example:1080` | 1080 | SOCKS5H 远程解析：**把域名直接发给代理**，由代理解析并连接。适合“本地 DNS 被污染/解析异常”或想隐藏目标域名 |
| `socks4://` | `socks4://proxy.example:1080` | 1080 | SOCKS4：仅支持 IPv4 目标（老式代理） |
| `socks4a://` | `socks4a://proxy.example:1080` | 1080 | SOCKS4A：支持域名（代理端解析），但仍不支持 IPv6 目标 |

选择建议：
- 公司/内网提供的一般是 `http://` 代理，端口常见 8080/3128。
- 只想要“能连上就行”且不介意本地解析：`socks5://`。
- 本地 DNS 有问题（如解析到错误地址）或不想暴露目标：`socks5h://`。
- `socks5://` 会按本地 DNS 候选顺序逐个尝试；某个地址收到 SOCKS5 general-failure 或 address-type-unsupported 时会继续下一个候选，因此不支持 IPv6 的代理仍可回退到 IPv4。`socks5h://` / `socks4a://` 无法观测代理最终选择的目标 IP，标题与权威尾行显示 `unknown` 属于预期行为。
- 注意：`socks5h://` / `socks4a://` 把域名交给代理，代理最终用的地址族无法预知，因此与 `--ipv4-only`/`--ipv6-only`、家族模式、回退开关或 `--rir-ip-pref` 等控制互斥，同时使用会在查询前直接报错。

#### 怎么指定代理（含 `ALL_PROXY` 是什么）

优先级从高到低：

1. 命令行 `--proxy <url>`
2. 环境变量 `WHOIS_PROXY`
3. 仅当加了 `--proxy-env` 时：`ALL_PROXY` → `all_proxy`
4. 都不存在 → 直连

关于 `ALL_PROXY` / `all_proxy`：它们是很常见的“通用代理环境变量”，很多程序（curl、git、apt 等）都认它，写法如 `http://proxy.example:8080` 或 `socks5h://proxy.example:1080`。`ALL_PROXY` 为大写（更常用），`all_proxy` 为小写；本客户端按“大写优先、小写次之”读取。**默认不读**——因为如果系统里恰好设置了 `ALL_PROXY`，而你不想走代理，会被“悄悄”强制走代理，所以必须显式加 `--proxy-env` 才启用。

`HTTP_PROXY` / `HTTPS_PROXY` 永远不会被读取：WHOIS 是明文 TCP（没有“HTTP 还是 HTTPS”之分），而且某些环境下大写 `HTTP_PROXY` 存在 CGI 注入隐患。

`NO_PROXY` / `no_proxy`（也需要 `--proxy-env` 才生效）：列出“不要走代理”的目标，多个用逗号分隔；对每一跳 WHOIS 服务器都会重新判断。支持：`*`（全部直连）、精确主机名、前导点域名后缀（如 `.internal` 匹配 `a.internal`）、IPv4 字面量、方括号 IPv6 字面量，以及“主机:端口”。不支持 CIDR（如 `10.0.0.0/8`）和任意通配符。

```sh
# 指定 NO_PROXY：本机、内网域名和不希望走代理的 RIR
NO_PROXY='localhost,.internal,whois.iana.org' whois-x86_64 --proxy-env 1.1.1.1
```

#### 用户名 / 密码怎么填（重要）

出于安全考虑：

- **不要在命令行 `--proxy http://user:pass@...` 里写账号密码**——URL 里的 userinfo 会被拒绝（凭据会留在 shell 历史与进程列表中）。
- 正确方式：使用专用环境变量 `WHOIS_PROXY_USER`（用户名）与 `WHOIS_PROXY_PASSWORD`（密码），两者**必须同时设置且非空**，否则启动时报错。
- 如果代理 URL 来自环境变量（`WHOIS_PROXY` / `ALL_PROXY` / `all_proxy`），该 URL 可以带 percent-encoded 的 `user:pass@`（如 `http://my%20user:p%40ss@proxy:8080`），方便与通用工具共用配置。
- 专用凭据变量与 URL 内嵌凭据**同时存在时直接报错**（避免歧义）。
- 走**明文 `http://` 代理**且带凭据时，还必须显式加 `--proxy-allow-insecure-auth`；否则报错。注意：明文代理上的账号密码是明文传输的，只应在可信内网代理使用。
- 不支持凭据文件、交互式输入或系统钥匙串；也请尽量不要把环境变量传给不必要的子进程（凭据可能被继承）。

示例：

```powershell
# PowerShell：先设凭据，再加 --proxy 与允许明文认证开关
$env:WHOIS_PROXY_USER = 'myuser'
$env:WHOIS_PROXY_PASSWORD = 'mypass'
whois-x86_64 --proxy http://10.0.0.246:8080 --proxy-allow-insecure-auth 8.8.8.8
```

```sh
# Git Bash / Linux：同样先设环境变量
export WHOIS_PROXY_USER='myuser'
export WHOIS_PROXY_PASSWORD='mypass'
whois-x86_64 --proxy http://10.0.0.246:8080 --proxy-allow-insecure-auth 8.8.8.8
```

#### 代理命令行参数（逐项）

| 参数 | 说明 |
|------|------|
| `--proxy URL` | 显式指定代理。URL 接受 `http://`/`https://`/`socks5://`/`socks5h://`/`socks4://`/`socks4a://` 的绝对地址（主机+端口，不含 path/query/fragment；IPv6 代理用方括号如 `[::1]:1080`；默认端口：http=8080、https=443、socks*=1080）。官方静态发布制品支持 `https://`；自行生成的无 TLS 兼容构建会在查询前报 unsupported。**URL 中禁止内嵌 `user:pass@`**（见下方凭据说明） |
| `--proxy-env` | 启用通用代理环境变量：按 `ALL_PROXY` → `all_proxy` 取代理，并读取 `NO_PROXY`/`no_proxy` 决定哪些目标直连。默认不启用（避免系统环境里的代理“悄悄”生效）；`HTTP_PROXY`/`HTTPS_PROXY` 永不读取 |
| `--proxy-allow-insecure-auth` | 允许在**明文 `http://` 代理**上发送凭据；不带它时，http 代理 + 凭据会在查询前报错（SOCKS 代理不受此限制） |
| `--proxy-family auto\|v4\|v6` | 只控制**代理服务器本身**的地址族（默认 `auto`）。例如代理只有 IPv6 地址时用 `--proxy-family v6`；与代理 URL 中的数值地址冲突会报错 |
| `-p, --port PORT` | 仍指 **WHOIS 目标端口**（默认 43），与代理无关；referral 可独立替换后续目标端口 |

优先级：`--proxy` > `WHOIS_PROXY` > （仅 `--proxy-env`）`ALL_PROXY` > `all_proxy` > 直连。

#### SOCKS 与 HTTPS 代理怎么操作

- **SOCKS**：直接指定即可，如 `whois-x86_64 --proxy socks5://10.0.0.246:1080 8.8.8.8`；带认证时按上面方式设 `WHOIS_PROXY_USER/PASSWORD`（SOCKS5 支持用户名/密码，SOCKS4 的 USERID 用用户名、不带密码）。
- **HTTPS 代理（`https://`）**：官方静态发布制品默认包含该能力。`https://host:443` 表示“客户端与代理之间走 TLS”，在 TLS 之上再发 `CONNECT`，隧道内 WHOIS 仍是明文。客户端强制校验证书与主机名/IP（无“跳过验证”选项），默认信任构建时内嵌的 Mozilla CA bundle；非空 `SSL_CERT_FILE` 可指向企业私有 CA 的 PEM（无法读取、为空或加载失败会 fail-close，不会回退内嵌 CA）。若自行构建了不含 HTTPS TLS 后端的兼容版本，客户端会在查询前稳定报 unsupported。设计细节见 `docs/RFC-proxy-access.md`。

先运行 `whois-x86_64 --help`（Windows 使用 `whois-win64.exe --help`）：出现 `HTTPS proxy TLS backend: enabled` 即可直接使用；出现 `disabled` 表示当前文件是不含 OpenSSL 的兼容构建。

```powershell
# 官方 Windows 静态制品：使用公网 CA 签发证书的 HTTPS 代理
.\whois-win64.exe --proxy https://proxy.example:443 8.8.8.8

# 企业私有 CA（PEM）
$env:SSL_CERT_FILE = 'C:\certs\corp-proxy-ca.pem'
.\whois-win64.exe --proxy https://proxy.corp.example:443 8.8.8.8
```

```sh
# 官方 POSIX 静态制品
./whois-x86_64 --proxy https://proxy.example:443 8.8.8.8

# 企业私有 CA（PEM）
SSL_CERT_FILE=/etc/company/proxy-ca.pem ./whois-x86_64 --proxy https://proxy.corp.example:443 8.8.8.8
```

### 3.4 超时与重试

| 参数 | 说明 |
|------|------|
| `--timeout SEC` | 套接字超时（默认 5s） |
| `--retries N` | 瞬时错误重试次数（默认 2） |
| `--retry-all-addrs` | 对每个解析出的 IP 都应用重试（默认仅第一个） |
| `--retry-interval-ms M` | 重试基础间隔 ms（默认 300） |
| `--retry-jitter-ms J` | 额外随机抖动 0..J ms（默认 300） |
| `--rate-limit-retries N` | 应用层限流/临时拒绝重试次数（默认 2，0..10）；`permanently denied` 不重试 |
| `--rate-limit-retry-interval-ms M` | 应用层重试间隔 ms（默认 2500） |

### 3.5 连接级重试节流（默认开启，仅 CLI）

| 参数 | 说明 |
|------|------|
| `--pacing-disable` | 关闭节流（不推荐） |
| `--pacing-interval-ms M` | 基础等待（默认 60） |
| `--pacing-jitter-ms J` | 随机抖动 0..J（默认 40） |
| `--pacing-backoff-factor N` | 每次重试放大倍数（默认 2） |
| `--pacing-max-ms C` | 单次等待上限（默认 400） |

说明：`[RETRY-METRICS] ... sleep_ms=` 反映节流累计睡眠；与通用重试 `-i/-J` 解耦。

### 3.6 缓冲与缓存

| 参数 | 说明 |
|------|------|
| `-b, --buffer-size BYTES` | 响应缓冲区大小（默认 512K，支持 1K/1M/1G 后缀） |
| `-d, --dns-cache N` | DNS 缓存条目数（默认 10） |
| `-c, --conn-cache N` | 连接缓存条目数（默认 5） |
| `-T, --cache-timeout SEC` | 缓存 TTL（默认 300） |
| `--cache-counter-sampling` | 非 debug 下也周期输出缓存计数采样；任一 `--selftest*` 自动开启 |

### 3.7 DNS / IP 家族偏好

通俗理解：WHOIS 服务器通常同时有 IPv4 与 IPv6 地址。`--ipv4-only`/`--ipv6-only` 是“只用一族”的强约束（如果该族不可达会失败）；`--prefer-*` 是“优先一族，失败自动换另一族”，更稳妥；`--rir-ip-pref` 则允许“不同 RIR 用不同策略”（比如某 RIR 仅 IPv4 畅通）。一般情况下不必特意设置，客户端会自动探测本机可用性并选择合理顺序。

| 参数 | 说明 |
|------|------|
| `--ipv4-only` / `--ipv6-only` | 强制单族解析与拨号（不再先拨规范域名） |
| `--prefer-ipv4` / `--prefer-ipv6` | 优先某族（另一族仍可回退） |
| `--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4` | 首跳偏好 + 后续 hop 向另一族倾斜 |
| `--rir-ip-pref SPEC` | 按 RIR 覆盖族偏好，如 `arin=v4,ripe=v6` |
| `--dns-family-mode MODE` | 全局候选交错顺序：`interleave-v4-first`/`interleave-v6-first`/`seq-v4-then-v6`/`seq-v6-then-v4`/`ipv4-only-block`/`ipv6-only-block` |
| `--dns-family-mode-first/next` | 首跳 / 第二跳及以上覆盖（同模式值） |
| `--dns-neg-ttl SEC` | 负向 DNS 缓存 TTL（默认 10） |
| `--no-dns-neg-cache` | 禁用负向缓存 |
| `--no-dns-addrconfig` | 关闭 OS `AI_ADDRCONFIG` 过滤（默认开启） |
| `--dns-retry N` | `EAI_AGAIN` 下 DNS 重试次数（默认 3，1..10） |
| `--dns-retry-interval-ms M` | DNS 重试间隔（默认 100，0..5000） |
| `--dns-max-candidates N` | 限制可拨号候选数（默认 12，1..64） |
| `--max-host-addrs N` | 每主机拨号上限（默认 0=不限，1..64） |
| `--dns-backoff-window-ms N` | DNS 失败滑动窗口（默认 10000，0=关闭） |
| `--dns-append-known-ips` | 追加内置 RIR 已知 IP 到候选 |
| `--no-known-ip-fallback` | 关闭已知 IPv4 兜底 |
| `--no-force-ipv4-fallback` | 关闭强制 IPv4 重拨回退 |
| `--no-iana-pivot` | 关闭缺失 referral 时的 IANA 中转 |
| `--dns-no-fallback` | 一次性关闭强制 IPv4/已知 IPv4 附加回退（调试用） |

优先级（族偏好）：`--ipv4-only/--ipv6-only` > `--rir-ip-pref` > `--dns-family-mode-*` > 全局 `--prefer-*`。

**什么是负向缓存（DNS 失败记忆）？**

当一次 DNS 解析失败（例如域名暂时不存在/解析出错）时，客户端会把这个“刚刚失败”的记忆短暂保存（默认 10 秒，`--dns-neg-ttl` 可调）。在这段时间里再次查询同一个名字，会直接按“已知失败”跳过，不再每次都等待 DNS 超时，从而加快批量/重复查询并减少无谓的解析请求。它是**只针对失败结果**的短缓存：成功解析走的是另一套正向缓存（`--dns-cache N` + `--cache-timeout`），且只要有一次成功解析就会覆盖负向记录。一般无需修改；若你发现某个域名的失败被反复快速跳过，可调大 TTL 观察，或用 `--no-dns-neg-cache` 关闭后重新验证真实解析结果。

用例：

```sh
whois-x86_64 --ipv4-only 1.1.1.1
whois-x86_64 --prefer-ipv6 --dns-neg-ttl 30 8.8.8.8
whois-x86_64 --rir-ip-pref arin=v4,ripe=v6 8.8.8.8
```

### 3.8 条件输出引擎

处理顺序固定：`-g`（标题投影）→ `--grep*`（行/块 + 可选续行展开）→ `--pick` → `--fold`/正文。

| 参数 | 说明 |
|------|------|
| `-g, --title PATTERN` | 标题前缀投影（不区分大小写；`|` 分隔多个前缀；匹配标题连带续行）。**不是正则** |
| `--grep REGEX` | POSIX ERE 过滤（不区分大小写） |
| `--grep-cs REGEX` | 区分大小写版本 |
| `--grep-line` | 行模式 |
| `--grep-block` | 块模式（默认） |
| `--keep-continuation-lines` | 行模式下保留续行（默认） |
| `--no-keep-continuation-lines` | 行模式下丢弃续行 |
| `--fold` | 折叠为单行：`<query> <UPPER_VALUE_...> <RIR>` |
| `--fold-sep STR` | 折叠分隔符（默认空格；支持 `\t`/`\n`/`\r`/`\s`） |
| `--no-fold-upper` | 保留原大小写（默认转大写） |
| `--fold-unique` | 折叠 token 去重（按首次出现保序） |
| `--no-body` | 抑制正文；保留查询头、`Address Status:` 与权威尾行（过滤仍执行） |
| `--print-meta` | 每条记录末尾追加 TAB 分隔 `k=v`：`query,rir,status,duration_ms,attempts,redirects` |
| `--print-chain` | 每条记录末尾追加 `chain=server1>server2>...`（最多 16 hop，溢出追加 `>truncated`） |
| `--pick KEYS` | 追加选定的 WHOIS 标题值（白名单：`netname,country,inetnum,inet6num,origin,route,descr`；缺失输出 `key=`） |
| `--pick-mode MODE` | `first`（默认）或 `join`（用 `|` 合并重复标题；续行先用 `; ` 合并） |
| `--stats` | 批量模式末尾追加一行 TAB 汇总（success/error、分类、RIR 分布、p50/p95 毫秒） |

互斥关系：`--no-body` 与 `--plain`、任何 `--fold*` 互斥（查询前报错）；`--print-meta`/`--print-chain`/`--pick` 与 `--plain` 互斥。

用例：

```sh
# 标题投影 + 块正则 + 折叠
whois-x86_64 -g 'Org|Net|Country' --grep 'Google|ARIN' --fold 8.8.8.8

# 行模式命中关键词并展开整块
whois-x86_64 -g 'netname|e-mail' --grep 'cmcc' --grep-line --keep-continuation-lines 1.2.3.4

# 记录边界 + 逻辑链 + 字段抽取（批量友好）
printf '8.8.8.8\n1.1.1.1\n' | whois-x86_64 -B --no-body --print-chain --pick netname,country --stats
```

### 3.9 诊断 / 安全 / 自测

| 参数 | 说明 |
|------|------|
| `--debug-verbose` | 更详细调试（缓存/重定向附加日志） |
| `--retry-metrics` | 打印重试统计到 stderr（`[RETRY-METRICS*]`，仅诊断，不改变行为） |
| `--dns-cache-stats` | 进程退出输出单行 `[DNS-CACHE-SUM] hits=<n> neg_hits=<n> misses=<n>` |
| `--security-log` | 安全事件日志到 stderr（默认关闭，限频约 20 条/秒） |
| `--selftest` | 运行内置自测并退出（折叠/重定向/lookup；非 0 退出即失败） |
| `--selftest-grep` / `--selftest-seclog` | 扩展自测（需编译宏 `-DWHOIS_GREP_TEST` / `-DWHOIS_SECLOG_TEST`） |
| `--selftest-inject-empty` | 触发空响应注入路径（需要网络） |
| `--selftest-dns-negative` | 模拟 DNS 负向缓存场景 |
| `--selftest-blackhole-iana` / `--selftest-blackhole-arin` | 黑洞化 IANA/ARIN 候选（模拟连接失败） |
| `--selftest-force-iana-pivot` | 强制一次 IANA 枢纽中转（构造三跳路径） |
| `--selftest-fail-first-attempt` | 强制首个尝试失败一次 |
| `--selftest-force-suspicious Q` | 将查询（或 `*`）标记为可疑用于管线测试 |
| `--selftest-force-private Q` | 将查询（或 `*`）标记为私网用于管线测试 |
| `--selftest-registry` | 批量策略注册表自测（不触网） |
| `--selftest-workbuf` | 长行/CRLF/高续行压力自测（`[WORKBUF]*`） |
| `--disable-address-preclass` | 一键关闭 Step 4.7 预分类（回退旧路径） |
| `--enable-preclass-actions` | 开启 P1 受控动作（默认关闭，需 `--enable-step47-trial`） |
| `--preclass-action-tier r0\|r1` | P1 候选分层（默认 `r0`） |
| `--preclass-action-list CSV` | 覆盖 P1 候选列表 |
| `--enable-step47-trial` | 开启 Step 4.7 试验门（默认关闭） |
| `--step47-trial-scope minimal\|reserved\|all` | 试验范围（默认 `minimal`） |
| `--enable-step47-early-unknown` | 开启 early-unknown 试验（默认关闭，仅 `reserved` 生效） |
| `--step47-early-unknown-list CSV` | early-unknown 候选列表 |
| `--enable-preclass-first-hop` | Phase B 分类器优先首跳（隐式查询默认开启；显式 `-h` 旁路） |
| `--enable-preclass-early-converge` | Phase C reserved/special 早收敛（默认开启；命中输出 `Address Status:` 并归一化 `unknown @ unknown`） |

说明：若你不熟悉 预分类/Phase/P0-P2/Step 4.7 等概念，请先看 §2 术语表——它们大多只影响“保留/特殊用途地址是否不联网直接返回 unknown”，普通公网/域名查询不受影响，保持默认配置即可。

开启任一 `--selftest-*` 故障旗标，会在真实查询前自动运行一次 lookup 自测（stderr 出现 `[LOOKUP_SELFTEST]`）。`[SELFTEST] action=force-*` 标签仅写 stderr，与 `--debug` 无关。调试收集推荐组合：

```sh
whois-x86_64 --debug --retry-metrics --dns-cache-stats --no-known-ip-fallback 8.8.8.8 2>debug.log
```

相关运维/构建/验证流程（远程冒烟、Golden、重定向矩阵、批量策略黄金、Step47 预发布门禁）见 `docs/OPERATIONS_CN.md`。

## 4. 批量模式

- 显式：`-B`；隐式：未给位置参数且 stdin 非 TTY 时自动启用。
- 输入逐行读取（行尾自动归一化为 LF）；每个查询记录保持独立头/尾与过滤链。
- `--batch-strategy raw|health-first|plan-a|plan-b`：可选起始主机调度策略（默认 `raw`）。
  - `raw`（默认）：CLI host → 推测 RIR → IANA，不跳过被惩罚主机、不复用缓存。
  - `health-first`：跳过近期失败主机；全部被罚则强制最后一个候选。
  - `plan-a`：复用上一条权威 RIR 作为快速起步；被罚则回落常规候选。
  - `plan-b`：缓存优先 + 罚站感知；被罚时回退首个健康候选（或强制 override/末尾）。
  - 未知名称自动回落 `health-first` 并输出一行 `[DNS-BATCH] action=unknown-strategy ...`。
- `--batch-interval-ms M` / `--batch-jitter-ms J`：批量间隔与抖动（默认 0）。
- `--stats`：最后追加一行汇总（适合聚合）。`WHOIS_BATCH_DEBUG_PENALIZE='host1,host2'` 可预注入惩罚窗口（仅调试）。

用例：

```sh
cat ip_list.txt | whois-x86_64 -B --host apnic
cat queries.txt | whois-x86_64 -B --batch-strategy plan-a --debug --retry-metrics
printf '8.8.8.8\n1.1.1.1\n' | whois-x86_64 -B --no-body --print-meta --stats
```

## 5. 常用示例

```sh
# 单条（自动重定向）
whois-x86_64 8.8.8.8

# 指定起始 RIR 并禁止重定向
whois-x86_64 --host apnic -Q 103.89.208.0

# 批量（显式）：
cat ip_list.txt | whois-x86_64 -B --host apnic

# 纯净输出（无标题/尾行）
whois-x86_64 -P 8.8.8.8

# 标题筛选（-g），仅输出匹配标题及续行
# 注意：-g 为不区分大小写的“前缀匹配”，不支持正则表达式（例如不支持 `|`、`[]` 等正则语法）。
whois-x86_64 -g "Org|Net|Country" 8.8.8.8

# 块模式正则（默认，不区分大小写），匹配 route/origin/descr 开头的标题
whois-x86_64 --grep '^(route|origin|descr):' 1.1.1.1

# 块模式正则（区分大小写）
whois-x86_64 --grep-cs '^(Net(Name|Range)):' 8.8.8.8

# 与 -g 叠加：先按标题前缀缩小范围，再做正则
whois-x86_64 -g "Org|Net" --grep 'Google|Mountain[[:space:]]+View' 8.8.8.8

# 行模式：仅输出命中的行（保留头尾标识行）
whois-x86_64 --grep 'Google' --grep-line 8.8.8.8

# 行模式 + 续行展开：块内任一行命中则输出整个该“标题块”（标题+续行）
whois-x86_64 -g 'netname|e-mail' --grep 'cmcc' --grep-line --keep-continuation-lines 1.2.3.4

# 折叠输出（一行汇总），结合前述筛选结果：格式为
#   <query> <UPPER_VALUE_1> <UPPER_VALUE_2> ... <RIR>
# 适合 BusyBox 环境直接做聚合与判定
whois-x86_64 -g 'netname|mnt-|e-mail' --grep 'CNC|UNICOM' --grep-line --fold 1.2.3.4
```

### 续行关键词命中技巧（推荐策略与陷阱）

管线顺序固定为：先按标题前缀投影（`-g`）→ 再做正则筛选（`--grep*`，行/块）→ 最后折叠（`--fold`）。其中：

- `-g` 是“标题前缀”的不区分大小写匹配，并非正则；匹配成功会连带输出其续行（以空白开头直到下一个标题）。
- `--grep/--grep-cs` 为 POSIX ERE，支持两种模式：
  - 默认“块模式”：对“标题块”（标题+续行）整体命中与否；
  - `--grep-line` 行模式：仅匹配的行被选中（可用 `--keep-continuation-lines` 将命中行扩展成其所在“标题块”）。
- `--fold` 使用当前选区（应用 `-g/--grep*` 后的结果）折叠为单行：`<query> <UPPER_VALUE_...> <RIR>`。
- `--no-body` 仍执行上述投影和筛选，但跳过最终正文写入；例如 `whois-x86_64 --no-body --grep 'NetName' 8.8.8.8` 只保留查询首行和权威尾行。批量模式下每个输入项各保留一组稳定边界。

推荐策略 A（稳定、易控）：

```sh
# 先用 -g 缩小到目标字段，再用块模式正则命中关键词，最后折叠
whois-x86_64 -g 'Org|Net|Country' \
  --grep 'Google|ARIN|Mountain[[:space:]]+View' \
  --fold 8.8.8.8
```

- 适合“关键词只出现在续行”的场景（例如地址、邮件在续行中），因为块模式只要块内任一行命中即可整块入选。
- 通过 `-g` 限定字段范围，避免把不相关块也带入，提升准确性。

可选策略 B（单正则合一，但存在过匹配风险）：

```sh
# 行模式使用 OR 正则，并用 --keep-continuation-lines 将命中行扩展为整个块
whois-x86_64 \
  --grep '^(Org|Net|Country)[^:]*:.*(Google|ARIN)|^[ \t]+.*(Google|ARIN)' \
  --grep-line --keep-continuation-lines --fold 8.8.8.8
```

- 优点：单个正则可同时覆盖“标题行”与“续行”关键词。
- 缺点：OR 正则容易命中通用续行从而把无关块“扩进来”，在数据较杂时需谨慎；若能先用 `-g` 缩小范围，建议优先用策略 A。

常见疑问与提示：

- 在行模式下，正则按“逐行”匹配，使用 `\n` 并不会跨行匹配；需要覆盖续行时请使用 `--keep-continuation-lines`。
- `--fold-sep` 可改分隔符（如 `,` 或 `\t`）：`--fold --fold-sep ,`、`--fold --fold-sep \t`；`--no-fold-upper` 可保留大小写。
- 折叠行首始终使用原始查询词 `<query>`（即便查询参数看起来像正则）。

## 6. 退出码
- `0`（`WC_EXIT_SUCCESS`）：成功  
  - 单条查询：查找流程完整结束；即使 RIR 明确返回“没有数据”（例如 `no-such-domain-abcdef.whois-test.invalid`），只要协议/网络链路成功，进程仍视为成功完成并返回 0。  
  - 批量模式：退出码只反映“整批是否跑完”，单行的网络/lookup 失败、可疑/私有 IP 等都会按行打印到 stderr，但不会把进程退出码从 0 改成 1。  
- `1`（`WC_EXIT_FAILURE`）：通用失败  
  - CLI 用法/参数错误（例如 `-B` 搭配位置参数、数值越界、缺少必需参数）——程序会先打印一条错误提示，再打印一份 Usage/帮助信息，然后以退出码 1 结束。  
  - 单条查询过程中发生的运行期失败：无法获得有效响应（多次重试后仍连接失败、DNS 解析硬错误、内部管线异常等）时，按“查询失败”处理并返回 1。  
- `130`（`WC_EXIT_SIGINT`）：被 SIGINT(Ctrl‑C) 中断  
  - 程序会在 stderr 打印 `[INFO] Terminated by user (Ctrl-C). Exiting...`，执行包括 DNS/重试统计在内的清理钩子，然后以 130 退出；远程冒烟脚本和外部自动化可能依赖这一固定值。  

## 7. 提示与故障排查
- 建议与 BusyBox 工具链配合：grep/awk/sed 排序、去重、聚合留给外层脚本处理
- 如需固定出口且避免跳转带来的不稳定，可使用 `--host <rir> -Q`
- 在自动重定向模式下，`-R` 过小可能拿不到权威信息；过大可能产生延迟，默认 6 足够
- 当无显式 referral 但输出提示“未由当前 RIR 管理”（如 ERX/IANA‑NETBLOCK 说明）时，客户端会按 APNIC → ARIN → RIPE → AFRINIC → LACNIC 的顺序尝试剩余 RIR，并跳过已访问的 RIR。
 - 重试节奏（连接级节流，3.2.7）：默认开启；仅保留命令行参数，Release 不依赖任何运行时环境变量（调试构建向后兼容但不推荐）。
  - 默认值：interval=60 / jitter=40 / backoff=2 / max=400（对 p95 影响极小）
  - CLI：`--pacing-interval-ms N`、`--pacing-jitter-ms N`、`--pacing-backoff-factor N`、`--pacing-max-ms N`、`--pacing-disable`
  - 调试：`--retry-metrics`（输出 [RETRY-METRICS*]）、`--selftest-fail-first-attempt`（强制首轮失败）、`--selftest-inject-empty`、`--selftest-grep`、`--selftest-seclog`
  - 通用重试 CLI (`-i/-J`) 与连接级节流已彻底解耦。

  快速对比（默认开启 vs 关闭）：
  ```text
  # 默认：sleep_ms 为非 0（示例）
  [RETRY-METRICS] ... sleep_ms=87
  # 关闭：sleep_ms 恒为 0
  [RETRY-METRICS] ... sleep_ms=0
  ```


  示例（本地批量 + 临时关闭节流）：
  ```bash
  printf "8.8.8.8\n1.1.1.1\n" | ./whois-x86_64 --pacing-disable -B -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold
  ```

  说明：`--retry-metrics` 输出 `[RETRY-METRICS]`（含 `sleep_ms`），可用于确认节流生效；`--pacing-disable` 后 `sleep_ms` 恒为 0。

  补充：`-i/-J`（通用重试间隔/抖动）与连接级节流已解耦；节流仅由 `--pacing-*` 控制。

### Errno 差异速查（连接阶段）

- 来源：连接失败的错误码来自 `getsockopt(..., SO_ERROR)`/`errno`；读取阶段超时不会计入 `[RETRY-ERRORS]`（但会影响 `[RETRY-METRICS]` 的成功/失败统计）。
- 架构差异：`ETIMEDOUT` 在多数架构数值为 `110`，在 MIPS/MIPS64 上为 `145`；逻辑按“符号常量”匹配，不依赖具体数值。
- 排查建议：优先查看 `strerror(errno)` 的文字描述（如 "Connection timed out"）。

| 符号        | 常见数值 | MIPS/MIPS64 | 含义                         |
|-------------|----------|-------------|------------------------------|
| ETIMEDOUT   | 110      | 145         | 连接超时（connect 超时）     |
| ECONNREFUSED| 111      | 111         | 连接被拒（端口关闭/防火墙）  |
| EHOSTUNREACH| 113      | 113         | 主机不可达（路由/ACL）       |

### 服务器参数为 IPv4/IPv6 字面量

- `--host` 可接受别名、主机名，或“IP 字面量”（包括 IPv4 与 IPv6）。
- IPv6 请直接使用不带方括号的字面量；不要写成 `[2001:db8::1]`。如需自定义端口，请使用 `-p` 选项，不支持 `host:port` 语法。
- 大多数 shell 下无需对 IPv6 加引号；若遇到解释器歧义，可用引号包裹。
- 若以 IPv4/IPv6 字面量连接失败，客户端会自动对该地址做 PTR 反查：
  - 若反查结果映射到已知 RIR 域名，将提示并自动切换到对应 RIR 的主机继续查询；
  - 若反查结果不属于任何已知 RIR，将直接报错（退出）并提示“该地址不属于任何 RIR”。

示例：

```sh
# 指定服务器为 IPv4 字面量
whois-x86_64 --host 202.12.29.220 8.8.8.8

# 指定服务器为 IPv6 字面量（默认端口 43）
whois-x86_64 --host 2001:dc3::35 8.8.8.8

# 指定 IPv6 服务器并自定义端口（用 -p 指定，而不是 [ip]:port）
whois-x86_64 --host 2001:67c:2e8:22::c100:68b -p 43 example.com
```

### 连通性提示：ARIN（IPv4 可能被运营商屏蔽）

- 在部分仅有 IPv4 私网出口（NAT，未启用 IPv6）的环境中，无法连上 `whois.arin.net:43` 的常见原因并非 ARIN 针对私网的 ACL 拒绝，而是宽带运营商对 ARIN 的 IPv4 whois 服务（A 记录所指向的 IPv4 地址的 43 端口）进行了屏蔽。
- 现象：IPv4 到 ARIN:43 无法建立连接；官方 whois 客户端同样受影响。改用 IPv6 后可立即恢复。
- 建议：优先启用 IPv6；或确保出口为公网 IPv4 未被屏蔽。必要时可直接指定 ARIN 的 IPv6 字面量作为 `--host`，或临时选择固定起始服务器/禁用重定向以便排查。若网络策略允许，也可改用代理（`--proxy http://...` 或 `--proxy socks5://...`，见 §3.3）让代理替你去连被运营商屏蔽的 whois 服务。

### 故障排查：偶发“空响应”重试/回退告警（3.2.7）

少见情况下，服务器端 TCP 连接已建立但返回体为空（或仅空白字符）。为避免出现“空正文 + 权威尾行”的误导性结果，客户端会检测这一异常并进行受控重试：

- 目标为 ARIN 时：基于 DNS 解析出的候选（优先 IPv6，再 IPv4）做最多 3 次回退重试；不增加跳数。
- 其他 RIR：基于 DNS 候选回退一次（若无可替换候选则重试同一主机）；不增加跳数。

在此过程中，会在合并输出中插入告警行以提示用户：

- `=== Warning: empty response from <host>, retrying via fallback host <host> ===`
- `=== Warning: empty response from <host>, retrying same host ===`
- 如所有回退均失败：`=== Warning: persistent empty response from <host> (giving up) ===`

说明：
- 告警属于标准输出（stdout），方便在批量管道中观察；重试不计入跳数，不影响既有“标题/尾行”契约。
- 可通过 `--selftest-inject-empty` 并运行 `--selftest` 复现该路径（需要网络）。

### 故障排查：限流 / 拒绝访问（rate-limit / denied）

另一种常见情况是服务器**明确拒绝或限流**，例如返回 `%ERROR:201: access denied`、`rate limit exceeded` 等。与“空响应”不同，它是有内容的拒绝，客户端会这样处理：

- **应用层受限重试**：对 `temporary denied / rate-limit` 响应，在同一跳内做受限重试，次数由 `--rate-limit-retries N` 控制（默认 2，范围 0..10），间隔由 `--rate-limit-retry-interval-ms M` 控制（默认 2500ms）；`permanently denied`（永久拒绝）不会重试。
- **重试仍失败 → 非权威重定向**：客户端把这次拒绝视为“非权威”并继续查找其它 RIR。若此前从未看到 ERX/IANA 标记且已查遍所有 RIR，权威回落到 `error`；否则权威为首个出现过 ERX/IANA 标记的 RIR。
- **错误行输出**：只有最终尾行为 `error @ error` 时才会在 stderr 输出 `Error: Query failed for ...`；否则不输出失败行。
- **调试观测**：`--debug` 下 stderr 会出现 `[RIR-RESP] action=denied|rate-limit ...`；应用层重试相关标签为 `[APP-RETRY]`（配合 `--retry-metrics` 使用）。
- **应对建议**：若某个 RIR 对当前出口持续拒绝（例如批量/矩阵中反复出现 access denied），可以：① 调大 `--rate-limit-retries`/间隔；② 用 `--rir-ip-pref <rir>=v6` 把该 RIR 切到 IPv6（若 IPv6 可达）；③ 通过 `--proxy` 换出口（见 §3.3）；④ 对单个目标先用 `--host <rir> -Q` 单独复测确认是否瞬时限流。

## 8. 相关文档与集成

### 版本注入

版本号会在构建时自动注入（优先读取仓库根目录 `VERSION.txt`；远程构建时由脚本写入该文件），默认回退为 `3.2.9`。
- 3.2.3：输出契约细化——标题与尾行附带服务器 IP（DNS 失败显示 `unknown`），别名先映射再解析；折叠输出保持 `<query> <UPPER_VALUE_...> <RIR>` 不含服务器 IP。新增 ARIN 连通性提示（修正）：部分网络环境下，运营商可能对 ARIN 的 IPv4 whois 服务（whois.arin.net:43 的 A 记录）做端口屏蔽，导致 IPv4 无法连通；IPv6 访问正常。建议启用 IPv6 或使用公网出口。
- 3.2.4：模块化基线（wc_* 模块：title/grep/fold/output/seclog）；新增 grep 自测钩子（编译宏 + 环境变量）；改进块模式续行启发式；新增 `--debug-verbose`、`--selftest`、`--fold-unique`。
- 3.2.2：九项安全性加固；新增 `--security-log` 调试日志开关（默认关闭，内置限频）。要点：内存安全包装、改进的信号处理、更严格的输入与服务器/重定向校验、连接洪泛监测、响应净化/校验、缓存加锁与一致性、协议异常检测等；同时彻底移除此前的 RDAP 实验功能与开关，保持经典 WHOIS 流程。
- 3.2.1：新增 `--fold` 单行折叠与 `--fold-sep`/`--no-fold-upper`；补充续行关键词命中技巧文档。
- 3.2.0：批量模式、标题/权威尾行、非阻塞连接与超时、重定向；默认重试节奏 interval=300ms/jitter=300ms。

### 构建与冒烟（运维向）

远程构建、冒烟、Golden、产物发布与清理流程详见 `docs/OPERATIONS_CN.md`；下载链接风格见 `docs/RELEASE_LINK_STYLE.md`。

### 与 lzispro 集成（交叉链接）

lzispro 的批量归类脚本 `release/lzispro/func/lzispdata.sh` 会直接调用本 whois 客户端并使用内置过滤，支持通过环境变量调整模式与关键词（有默认值，开箱即用）：

- WHOIS_TITLE_GREP：-g 标题前缀投影（例：`netname|mnt-|e-mail`）
- WHOIS_GREP_REGEXP：--grep 正则（POSIX ERE，例：`CNC|UNICOM|CHINANET|...`）
- WHOIS_GREP_MODE：`line` 或 `block`（whois 客户端默认 `block` 块模式；lzispro 脚本会显式设置为 `line` 以便 BusyBox 聚合）
- WHOIS_KEEP_CONT：行模式下是否展开续行到整个字段块（`1`/`0`，默认 `0`）

说明与示例请见 lzispro 项目 README“脚本环境变量（ISP 批量归类脚本）”一节：

- 本地（同工作区）：`../lzispro/README.md`
- GitHub：https://github.com/larsonzh/lzispro#%E8%84%9A%E6%9C%AC%E7%8E%AF%E5%A2%83%E5%8F%98%E9%87%8Fisp-%E6%89%B9%E9%87%8F%E5%BD%92%E7%B1%BB%E8%84%9A%E6%9C%AC

在 lzispro 调用路径中，脚本会默认设为“行模式 + 不展开续行”，便于 BusyBox awk 一行聚合；若需回退到客户端默认的“块模式”输出，可设置 `WHOIS_GREP_MODE=block`。

### 相关文档

- 操作与发布手册：`docs/OPERATIONS_CN.md`（English: `docs/OPERATIONS_EN.md`）
- IPv4/IPv6 查询规则契约：`docs/RFC-ipv4-ipv6-whois-lookup-rules.md`
- DNS 设计：`docs/RFC-dns-phase2.md`、`docs/RFC-dns-phase4-ip-health.md`
- 代理访问：`docs/RFC-proxy-access.md`
- 发布流程：`docs/RELEASE_FLOW_CN.md` | `docs/RELEASE_FLOW_EN.md`

### 当前功能状态

- 已开放（master 源码及官方静态制品）：直连、HTTP CONNECT（`http://`）、HTTPS CONNECT（`https://`）以及 SOCKS4/4a/5/5h；另含条件输出、批量策略、DNS/IP 家族控制、诊断/自测等（详见 §3）。
- 制品边界：官方静态 release 可直接使用 `https://`；自行生成的不含 HTTPS TLS 后端的兼容制品会稳定报 unsupported。用 `--help` 中的 `HTTPS proxy TLS backend` 行核验手中二进制。

