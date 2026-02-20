# whois 客户端使用说明（中文）

本说明适用于项目内置的轻量级 whois 客户端（C 语言实现，静态编译，零外部依赖）。二进制覆盖多架构，例如 `whois-x86_64`、`whois-aarch64` 等，以下示例以 `whois-x86_64` 为例。

提示：自 3.2.5 起，界面输出统一为英文（English-only），避免在不支持中文的 SSH 终端出现乱码；原 `--lang` 与 `WHOIS_LANG` 已移除。

亮点：
- 智能重定向：非阻塞连接、超时、轻量重试，自动跟随转发（`-R` 上限，`-Q` 可禁用），带循环保护。
  - 规则契约（2026-02-20）：IPv4/IPv6 地址查询流程（含非权威标记、CIDR 基准回查、RIR 轮询与收敛）以 `docs/RFC-ipv4-ipv6-whois-lookup-rules.md` 为准。
  - 顺序规则（2026-01-22）：首跳有 referral 则直跟；首跳无 referral 且需要跳转时强制以 ARIN 作为第二跳。第二跳起：有 referral 且未访问过则跟随，referral 已访问或无 referral 则按 APNIC→ARIN→RIPE→AFRINIC→LACNIC 顺序选择未访问 RIR；全部访问过即终止。第二跳后不再插入 IANA。
  - APNIC 的 IANA-NETBLOCK 提示中出现 “not allocated to APNIC” 或 “not fully allocated to APNIC” 时，即便返回了对象字段，也会触发重定向轮询以验证最终权威。
- 管道化批量输入：稳定头/尾输出契约；支持从标准输入读取（`-B`/隐式）；天然契合 BusyBox grep/awk。
- 行尾归一化：单条与批量 stdin 输入在处理前自动将 CR-only/CRLF 归一化为 LF，避免 title/grep/fold 被多余回车切段，适配 BusyBox 管道。
- 条件输出引擎：标题投影（`-g`）→ POSIX ERE 正则筛查（`--grep*`，行/块 + 可选续行展开）→ 单行折叠（`--fold`）。
- 批量起始策略插件：`--batch-strategy <name>` 现改为显式 opt-in（默认批量流程保持“CLI host → 推测 RIR → IANA”的 raw 顺序，不再自动按 penalty 重排）。`--batch-strategy health-first` 可恢复 penalty 感知排序，`--batch-strategy plan-a` 复用上一条权威 RIR。`--batch-strategy plan-b` 已启用：在健康时复用上一条权威 RIR，若被罚站则回退到首个健康候选（或强制末尾/override）；命中会输出 `[DNS-BATCH] plan-b-*` 标签（plan-b-force-start/plan-b-fallback/force-override/start-skip/force-last），并新增缓存窗口标签 `[DNS-BATCH] action=plan-b-hit|plan-b-stale|plan-b-empty`（默认窗口 300s，命中过期即视为 stale 并清空）；当缓存起始主机被罚分时会立刻丢弃缓存，下一条查询会直接走健康候选（可能先看到一次 `plan-b-empty`）。`WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net'` 仍可预注入惩罚窗口，方便验证上述加速器与黄金断言。
- 信号处理：Ctrl+C/TERM/HUP 会关闭缓存连接并在拨号/接收阶段快速中断，且仅输出一次终止提示；进程退出时显式释放 DNS/连接缓存；`[DNS-CACHE-SUM]` / `[RETRY-*]` 仍通过 atexit 刷出，保持黄金日志形态。
- 空响应回退：空响应触发的回退重试次数做了收敛（ARIN 上限 2、其他 1），并在回退间加入轻量退让，以降低高并发下的连接风暴；正常成功路径不受影响。
- 应用层限流重试（2026-02-17）：新增 `--rate-limit-retries N` 与 `--rate-limit-retry-interval-ms M`，仅对“temporary denied / rate-limit”响应在同 hop 内做受限重试；`permanently denied` 不重试。
- 权威尾行收敛：若已返回正文但后续 referral 跳转失败，或因限流/拒绝导致未收敛，尾行权威输出 `error`，用于区分“失败未收敛”与“真未知”。
- 入口复用：所有可执行入口统一通过 `wc_client_frontend_run` 执行；若未来新增入口，只需组装 `wc_opts` 后调用该 facade，不要在入口层重复自测/信号/atexit 逻辑。

批量策略速览（通俗版）：
- raw（默认）：按“CLI host → 推测 RIR → IANA”顺序，既不跳过“被惩罚”主机也不复用缓存。
- health-first：遇到“被惩罚/暂时屏蔽”的主机直接跳过，全部都被惩罚时强制用最后一个候选；关注 `[DNS-BATCH] start-skip/force-last`。
- plan-a：记住上一条权威 RIR，下一轮优先用它做快速起步；若该主机被惩罚则回落常规候选；关注 `[DNS-BATCH] plan-a-*` 与 `plan-a-skip`。
- plan-b：缓存优先且感知罚站。健康时复用上一条权威 RIR；若被罚站则回退到首个健康候选（若无则强制 override/末尾），在 `--debug` 下输出 `[DNS-BATCH] plan-b-force-start/plan-b-fallback/force-override/start-skip/force-last`，并新增缓存窗口相关标签 `[DNS-BATCH] action=plan-b-hit|plan-b-stale|plan-b-empty`（默认窗口 300s，stale 会清空缓存）便于观测命中/过期/空击。

补充：当缓存起始主机被罚分时，plan-b 会立即丢弃缓存，下一条查询可能先看到 `plan-b-empty`，随后直接选择健康候选。

## 导航（发布与运维扩展）

发布流程（详版）：`docs/RELEASE_FLOW_CN.md` | English: `docs/RELEASE_FLOW_EN.md`

查询规则契约（新增）：`docs/RFC-ipv4-ipv6-whois-lookup-rules.md`

若你需要“一键更新 Release（可选跳过打标签）”或“在普通远端主机用 Makefile 快速编译冒烟”能力，请查看《操作与发布手册》对应章节：

- VS Code 任务：One-Click Release（参数与令牌说明）
  - `docs/OPERATIONS_CN.md` → [One-Click Release 任务](./OPERATIONS_CN.md#vs-code-任务新增one-click-release)
- 新脚本：`one_click_release.ps1` 快速更新 GitHub/Gitee Release
  - `docs/OPERATIONS_CN.md` → 同上章节内脚本示例
- 简易远程 Makefile 快速编译与测试
  - `docs/OPERATIONS_CN.md` → [远程 Makefile 快速编译与测试](./OPERATIONS_CN.md#简易远程-makefile-快速编译与测试新增)

（如链接在某些渲染器中无法直接跳转，请打开 `OPERATIONS_CN.md` 手动滚动到对应标题。）

最新验证基线（2026-02-20，LTO）：
- CIDR 契约收敛（2026-02-20）：修复 APNIC `not allocated to APNIC` 场景中 ERX 标记被清零导致的回落偏差；使用发布产物复跑 `testdata/cidr_matrix_cases_draft.tsv` 达到 `pass=5 fail=0`，日志 `out/artifacts/redirect_matrix/20260220-111122`。
- 回归复核（2026-02-20）：远程快速构建与发布目录同步（`x86_64+win64`，`lto-auto`）`Local hash verify PASS + Golden PASS`，日志 `out/artifacts/20260220-110900`。
- 自检黄金（2026-02-20，prefilled）：raw/health-first/plan-a/plan-b 全 PASS，日志 `out/artifacts/batch_raw/20260220-111736`、`batch_health/20260220-112303`、`batch_plan/20260220-112658`、`batch_planb/20260220-113149`。
- invalid CIDR 收口（2026-02-19）：`-h iana --show-non-auth-body --show-post-marker-body 47.96.0.0/10` 首跳直接返回 IANA `Invalid query` 且尾行 `unknown @ unknown`，不再误走 IANA→ARIN→APNIC；`-h apnic` 同查询保持 `invalid search key -> unknown @ unknown`。
- 远程编译冒烟同步 + Golden（Strict Version + lto-auto 默认）：`Local hash verify PASS + Golden PASS + referral check PASS`，日志 `out/artifacts/20260219-045120`。
- 重定向矩阵（参数化 IPv4）：`pass=66 fail=0`，日志 `out/artifacts/redirect_matrix/20260219-045555`。
- 重定向矩阵（12x6，含 `47.96.0.0/10`）：`authMismatchFiles=0 errorFiles=0`，日志 `out/artifacts/redirect_matrix_10x6/20260219-051415`。
- 远程编译冒烟同步 + Golden（Strict Version + lto-auto 默认）：无告警 + lto 无告警 + Golden PASS + referral check: PASS，日志 `out/artifacts/20260214-075348`。
- 重定向矩阵 10x6：authority mismatches 空表、errors 空表，日志 `out/artifacts/redirect_matrix_10x6/20260214-081508`。
- 远程编译冒烟同步 + Golden（LTO 默认）：无告警 + lto 无告警 + Golden PASS + referral check: PASS，日志 `out/artifacts/20260209-122029`。
- 远程编译冒烟同步 + Golden（LTO + debug/metrics + dns-family-mode=interleave-v4-first）：无告警 + lto 无告警 + Golden PASS + referral check: PASS，日志 `out/artifacts/20260209-122818`。
- 批量策略黄金（LTO）：raw/health-first/plan-a/plan-b PASS，日志 `out/artifacts/batch_{raw,health,plan,planb}/20260209-11*`。
- 自检黄金（LTO + `--selftest-force-suspicious 8.8.8.8`）：raw/health-first/plan-a/plan-b PASS，日志 `out/artifacts/batch_{raw,health,plan,planb}/20260209-12*`。
- 重定向矩阵 10x6：无权威不匹配/错误，日志 `out/artifacts/redirect_matrix_10x6/20260209-133525`。
- 矩阵 authority 判定语义（2026-02-14）：若尾行为 `=== Authoritative RIR: error @ error ===`，该样例 authority 期望按 `error` 判定（失败未收敛）；仅非失败尾行按静态 RIR 期望表判定。
- CIDR 样例（APNIC/AFRINIC/RIPE/ARIN/LACNIC）：日志 `out/artifacts/cidr_samples/20260209-002242`。
- 48 进程批量对比（基准复查 + 轮询 vs 仅轮询）：日志 `out/artifacts/gt-ax6000_recheck_20260209_syslog.log`。
- 远程编译冒烟同步 + Golden（LTO 默认）：无告警 + lto 有告警 + Golden PASS + referral check: PASS，日志 `out/artifacts/20260201-214831`。
- 远程编译冒烟同步 + Golden（LTO 默认）：有告警 + lto 有告警 + Golden PASS + referral check: PASS，日志 `out/artifacts/20260130-213229`。
- 远程冒烟 + 黄金（默认参数）：`[golden] PASS`，日志 `out/artifacts/20260124-045307`。
- 远程冒烟 + 黄金（`--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`）：`[golden] PASS`，日志 `out/artifacts/20260124-045757`。
- 批量策略黄金（raw/health-first/plan-a/plan-b）：`[golden] PASS`，日志 `out/artifacts/batch_{raw,health,plan,planb}/20260124-050*`（报告同目录）。
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：`[golden-selftest] PASS`，日志 `out/artifacts/batch_{raw,health,plan,planb}/20260124-0519**/052***`。
- 远程编译冒烟同步 + 黄金（LTO 默认）：无告警 + lto 告警 + Golden PASS + referral check: PASS，日志 `out/artifacts/20260124-113056`。
- 远程编译冒烟同步 + 黄金（LTO 默认）：无告警 + lto 告警 + Golden PASS + referral check: PASS，日志 `out/artifacts/20260124-190255`。

### 重定向矩阵测试（IPv4）

该测试用于覆盖多 RIR 起始主机的重定向链路与权威判定，独立于编译/冒烟/黄金流程。

- 脚本：`tools/test/redirect_matrix_test.ps1`
- 任务：Test: Redirect Matrix (IPv4)、Test: Redirect Matrix (IPv4, Params)
- 产出：在输出目录生成 `redirect_matrix_report_<timestamp>.txt`（默认写入 `out/artifacts/redirect_matrix/<timestamp>`）。
- 逐条日志：默认写入 `out/artifacts/redirect_matrix/<timestamp>/cases/`，可用 `-SaveLogs false` 关闭。
- 退出码：任一用例失败返回 1，全部通过返回 0。

参数说明（可选）：
- `-BinaryPath`：二进制路径（默认 `release/lzispro/whois/whois-win64.exe`）
- `-OutDir`：报告输出目录（默认 `out/artifacts/redirect_matrix/<timestamp>`）
- `-RirIpPref`：传入 `--rir-ip-pref` 值，填 `NONE` 跳过
- `-PreferIpv4`：`true|false` 控制是否启用 `--prefer-ipv4`
- `-SaveLogs`：`true|false` 控制是否保存逐条日志（默认 `true`）

附加提示（Windows 跨平台产物）：
- `tools/remote/remote_build_and_test.sh` 默认追加 win32/win64 目标（无需手动 `-w 1`）。
- 本地 Windows 示例：
  - PowerShell 单条：`whois-win64.exe --debug --prefer-ipv4-ipv6 8.8.8.8`；IPv6-only：`whois-win64.exe --debug --ipv6-only 8.8.8.8`
  - PowerShell 管道：`"8.8.8.8" | whois-win64.exe --debug --ipv4-only`（stdin 非 TTY 自动批量）
  - CMD 管道：`echo 8.8.8.8 | whois-win64.exe --debug --ipv4-only`
- Linux wine 冒烟：`env WINEDEBUG=-all wine64 ./whois-win64.exe --debug --prefer-ipv6 8.8.8.8`（32 位对应 `wine`），可复用同一冒烟参数。

提示：
- 可选折叠输出 `--fold` 将筛选后的正文折叠为单行：`<query> <UPPER_VALUE_...> <RIR>`；
- `--fold-sep <SEP>` 指定折叠项分隔符（默认空格，支持 `\t`/`\n`/`\r`/`\s`）
- `--no-fold-upper` 保留原大小写（默认会转为大写）

## 一、核心特性（3.2.0）
  - 头：`=== Query: <查询项> via <起始服务器标识> @ <实际连通IP或unknown> ===`（例如 `via whois.apnic.net @ 203.119.102.24`），查询项位于标题行第 3 字段（`$3`）；标识会保留用户输入的别名或显示映射后的 RIR 主机名，`@` 段恒为首次连通的真实 IP
  - 尾：`=== Authoritative RIR: <权威RIR域名> @ <其IP|unknown|error> ===`，若最终服务器以 IP 字面量给出会映射回对应的 RIR 域名；若是已知的 RIR 别名/子域（如 `whois-jp1.apnic.net`），会先归一化为该 RIR 的 canonical 域名再输出；当尾行输出 `error @ error` 时才会在 stderr 输出 `Error: Query failed for ...`，否则不输出失败行；折叠后位于最后一个字段（`$(NF)`）
  - 链路判读：多跳场景中，首个“无明确 referral 触发的附加跳”可能显示为 `=== Additional query to ... ===`，而不是 `=== Redirected query to ... ===`；这是预期行为，不表示中间 RIR 跳丢失。


### 三跳仿真与重试指标（apnic→iana→arin）

为便于稳定模拟“第二/第三跳失败”并观察重试与错误统计，提供以下自测旗标（CLI 开关，不改变默认生产逻辑）：

| 旗标 | 作用 | 用途 |
|------|------|------|
| `--selftest-force-iana-pivot` | 首次可重定向链路出现时强制进行一次 IANA 枢纽中转（仅一次，后续真实 referral 正常跟随） | 构造确定的三跳路径 |
| `--selftest-blackhole-arin` | 将 ARIN 拨号候选替换为保留地址 `192.0.2.1` 制造可控连接超时 | 模拟“终端权威不可达” |
| `--selftest-blackhole-iana` | 黑洞化 IANA 拨号候选 | 模拟“中间跳失败” |

> 3.2.10+ 提醒：只要开启任意 `--selftest-*` 故障注入或 demo（`--selftest-fail-first-attempt`、`--selftest-inject-empty`、`--selftest-dns-negative`、`--selftest-blackhole-{arin,iana}`、`--selftest-force-iana-pivot`、`--selftest-{grep,seclog}`），客户端都会在执行真实查询前自动跑一次 lookup 自测，并在 stderr 输出 `[LOOKUP_SELFTEST] ...`，无需额外先执行 `whois --selftest`；`--selftest-force-{suspicious,private}` 等需要影响真实查询的钩子会在这次 dry-run 后立即恢复。

#### 故障档案与强制查询钩子（3.2.10+）

- 运行期的所有故障开关（黑洞、DNS negative、force-iana、fail-first 等）会统一写入 `wc_selftest_fault_profile_t`，DNS / lookup / net 仅需读取该结构与版本号即可保持注入行为一致，不再手动同步多个 `extern`。
- `--selftest-force-suspicious <query|*>` 可在静态检测前把某条（或全部 `*`）查询标记为“可疑”。命中时 stderr 会打印 `[SELFTEST] action=force-suspicious query=<值>`，并额外输出错误行供黄金校验，但在开启 force 时不再阻断；正常（非自测）可疑检测仍保持原有阻断行为。
- `--selftest-force-private <query|*>` 以同样方式强制触发“私网 IP”路径，stdout 仍输出标准私网提示/尾行并结束该查询；stderr 会输出 `[SELFTEST] action=force-private query=<值>`，并恒打印 `Error: Private query denied` 便于冒烟脚本断言。正常私网检测行为不变。
- `--selftest-registry` 运行本地批量策略注册表自测（不触网），验证默认激活、显式 override 与每次运行隔离，stderr 输出 `[SELFTEST] action=batch-registry-*` 标签；默认关闭，可在冒烟时显式开启。

提示：自 2025-12-25 起，以上 `[SELFTEST]` 标签统一带 `action=` 前缀，并在每个进程内最多输出一次（即便未显式执行 `--selftest` 套件，也会在首次命中强制钩子时落盘），便于 smoke/golden 统一 grep；同批次 DNS ipv6-only/fallback 自测已降级为 WARN，避免偶发网络导致自测中止。

示例（所有查询视为可疑，仅对 `10.0.0.8` 额外触发私网路径）：

```bash
printf "1.1.1.1\n10.0.0.8\n" | \
  whois-x86_64 -B --selftest-force-suspicious '*' --selftest-force-private 10.0.0.8
# stderr 片段：
# [SELFTEST] action=force-suspicious query=1.1.1.1
# [SELFTEST] action=force-private query=10.0.0.8
```

`[SELFTEST] action=force-*` 标签仅写 stderr，与 `-D/--debug` 是否开启无关；当测试/脚本依赖这些钩子时，请将其列为冒烟日志的预期输出。

示例（Windows PowerShell，通过 Git Bash 调用）：
```powershell
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && \
  ./tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8' -a '--host apnic --selftest-force-iana-pivot --selftest-blackhole-arin --retry-metrics -t 3 -r 0 --ipv4-only' -P 1"
```

自 2025-12-04 起，只要保持默认 `-L 1`（或省略该参数），`tools/remote/remote_build_and_test.sh` 就会在冒烟结束后自动抓取 `build_out/referral_143128/{iana,arin,afrinic}.log` 并在本地调用 `tools/test/referral_143128_check.sh`。仅当 AfriNIC 暂不可达或你只需要构建产物时，才建议传 `-L 0` 或设置 `REFERRAL_CHECK=0` 暂停该守卫，避免误报。

示例输出片段：
```text
[RETRY-METRICS-INSTANT] attempt=1 success=1 latency_ms=367 total_attempts=1
[RETRY-METRICS-INSTANT] attempt=2 success=1 latency_ms=227 total_attempts=2
Error: Query failed for 8.8.8.8 (connect timeout, errno=110, host=whois.apnic.net, ip=203.119.102.29, time=2026-01-30 03:11:29)
=== Query: 8.8.8.8 via whois.apnic.net @ 203.119.102.29 ===
[RETRY-METRICS] attempts=7 successes=2 failures=5 min_ms=227 max_ms=3017 avg_ms=2234.1 p95_ms=3017 sleep_ms=0
[RETRY-ERRORS] timeouts=5 refused=0 net_unreach=0 host_unreach=0 addr_na=0 interrupted=0 other=0
=== Authoritative RIR: whois.arin.net @ unknown ===
```

字段说明：
- `[RETRY-METRICS-INSTANT]`：每次拨号完成即刻输出；`success=1` 表示建立连接并收到正文；`latency_ms` 单次耗时；`total_attempts` 为累积尝试计数。
- `Error: ... errno=XXX`：统一的失败提示；包含 host/ip/time 便于定位；errno 区分超时 / 主机拒绝 / 网络不可达等场景。
- `[RETRY-METRICS]`：查询结束时聚合统计；`attempts=成功+失败`；`min/max/avg/p95_ms` 为各尝试耗时分布；`sleep_ms` 为连接级节流累计睡眠（禁用节流或无等待则为 0）。
- `[RETRY-ERRORS]`：错误分类计数（timeouts/refused/net_unreach/host_unreach/addr_na/interrupted/other）。

常见问题：
- `[RETRY-ERRORS]` 全 0？说明没有失败（或失败不在列出的分类之外）。
- `attempts` 为什么大于 `-r`？包含首拨（`-r 0` 仍有 attempt=1）。
- `sleep_ms` 是否含 DNS 重试等待？否，仅统计连接级节流等待。

远程冒烟脚本超时策略（`tools/remote/remote_build_and_test.sh`）：
- `SMOKE_TIMEOUT_DEFAULT_SECS`：普通冒烟（未加 `--retry-metrics`）保护超时，默认 8。
- `SMOKE_TIMEOUT_ON_METRICS_SECS`：包含 `--retry-metrics` 时的宽松超时，默认 45；脚本先 SIGINT（保留指标），超时后 5 秒再 SIGKILL。

自定义示例：
```powershell
$env:SMOKE_TIMEOUT_ON_METRICS_SECS='60'; \
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8' -a '--host apnic --selftest-force-iana-pivot --selftest-blackhole-arin --retry-metrics -t 3 -r 0 --ipv4-only'"
```

### 网络重试上下文（3.2.10+）

- 每个客户端进程在运行期初始化后都会构建一份 `wc_net_context`，之后所有入口（单条查询、批量 stdin 循环、自动触发的 lookup 自测）都会复用同一份上下文，因此 `[RETRY-METRICS]`、`[RETRY-METRICS-INSTANT]`、`[RETRY-ERRORS]` 计数会在自测预热与真实查询之间保持连续，不会在每条查询前自动清零。
- 若需要“干净”的重试计数或 pacing 状态，请直接重新启动进程；共享上下文的目的是让同一批次/同一流水线内的诊断输出更容易关联，也确保节流预算在批量模式下能够跨多条查询累积。

说明：黑洞化仅用于受控验证，不代表真实服务异常；标题/尾行契约保持不变，便于与真实结果做差异分析。

## 二、命令行用法

```
Usage: whois-<arch> [OPTIONS] <IP or domain>

元信息选项：
  -H, --help               显示帮助
  -v, --version            显示版本
  -l, --list               列出内置服务器别名
      --about              显示详细功能与模块说明
      --examples           显示更多示例

说明：纯元信息选项（help/version/about/examples/list）会直接返回结果，不再触发运行期初始化；stdout/stderr 契约保持不变。

运行期 / 查询选项（节选）：
  -B, --batch              从 stdin 逐行读取查询（禁止再写位置参数）；若未显式加 `-B` 且 stdin 非 TTY，则自动进入批量模式
      --batch-strategy 名称  仅批量模式可用；显式启用起始服务器调度策略/加速器（默认保持 raw 顺序）。可选 `health-first`、`plan-a`、`plan-b`，未知名称会打印一行 `[DNS-BATCH] action=unknown-strategy ... fallback=health-first` 并回落，避免影响旧脚本
      --batch-interval-ms M  批量模式下每条查询间隔 M 毫秒（默认 0=关闭）
      --batch-jitter-ms J    批量间隔追加随机抖动 0..J 毫秒（默认 0=关闭）
    -R, --max-redirects N   限制跟随的重定向跳数（默认 6）；到达上限仍需跳转则立即结束，权威未确定时回落为 `unknown`；别名：`--max-hops`
    -Q, --no-redirect       等同于 `-R 1`：仅查询首跳；若首跳返回 referral，则立即结束并回落 `Authoritative RIR: unknown @ unknown`
    -P, --plain             纯净输出（抑制标题/尾行与 referral 提示行）
        --show-non-auth-body 保留权威跳之前的非权威正文
        --show-post-marker-body 保留权威跳之后的正文（与 --show-non-auth-body 组合可保留全部）
        --hide-failure-body 隐藏限流/拒绝类正文行（默认保留）
      --ipv6-only            强制 IPv6；同时禁用 forced-ipv4/known-ip 回退，确保纯 IPv6 行为
      --ipv4-only            强制 IPv4（不涉及 IPv6 回退）
      --max-host-addrs N    限制单个主机的拨号尝试次数（默认 0=不限制，范围 1..64）。上限在 DNS 候选生成与 lookup 拨号层同时生效，超过 N 后不再尝试后续地址。开启 `--debug` 时可通过 `[DNS-LIMIT] host=<h> limit=<n> appended=<k> total=<m>` 与 `[NET-DEBUG] host=<h> max-host-addrs=<n> (ctx=<c> cfg=<g>)` 观测实际生效的上限。
      --dns-backoff-window-ms N  DNS 失败滑动窗口（毫秒，默认 10000，0=禁用窗口累计）
      --dns-append-known-ips  将内置 RIR 已知 IP 追加到 DNS 候选（显式开关，仅补足候选）
    -d, --dns-cache COUNT   DNS 缓存条目数（默认 10）
    -c, --conn-cache COUNT  连接缓存条目数（默认 5）
    -T, --cache-timeout SEC 缓存 TTL，秒（默认 300）
      --cache-counter-sampling  在非 debug 运行中也周期输出缓存计数采样（默认关闭；任意 `--selftest*` 开关会自动开启以便黄金断言）
```

### 新增：安全日志（可选）

- 重定向补充：当 RIR 返回限流/拒绝访问时会触发“非权威重定向”继续查找；若此前没有 ERX/IANA 标记且已查遍所有 RIR，则权威回落 `error`，否则权威为首个出现 ERX/IANA 标记的 RIR。失败出错行仅在最终尾行为 `error @ error` 时才会输出；否则不输出 `Error: Query failed for ...`。`--debug` 下，限流/拒绝会在 stderr 追加 `[RIR-RESP] action=denied|rate-limit ...` 标签。仅包含 banner 注释的 RIR 响应会按空响应处理：先重试，仍为空时触发重定向（非 ARIN 首跳直跳 ARIN，ARIN 首跳进入 RIR 轮询）。空响应重试会在 stderr 输出 `[EMPTY-RESP] action=...` 标签。若因限流/拒绝访问导致未能查询到某个 RIR，且出现过 ERX/IANA 标记但最终未收敛权威，则在遍历完所有 RIR 后，仅对首个 ERX/IANA 标记 RIR 执行一次“基准值回查”（去掉 CIDR 掩码的 IP 字面量查询）；若回查仍失败或仍含非权威标记，则权威保持 `error`。LACNIC 内部重定向到 ARIN 时因未加 ARIN 前置查询标志，常出现 `Query terms are ambiguous` 并触发非权威重定向，因此此时不会把 ARIN 记为已访问，下一跳会按 ARIN 规则补全前置标志再查询。

- `--security-log`：开启安全事件日志输出（stderr），默认关闭。用于调试/攻防校验，不改变标准输出（stdout）的既有“标题/尾行”契约。典型事件包含：输入校验拒绝、协议异常、重定向目标校验失败、响应净化与校验、连接洪泛检测等。
- 已内置限频防洪：安全日志在攻击/洪泛场景下会做限速（约 20 条/秒），超额条目会被抑制并在秒窗切换时汇总提示。
### 新增：调试 / 自检 / 折叠去重（3.2.4+）

- `-D, --debug`：开启“基础调试”与 TRACE（stderr）。默认关闭；推荐仅在排查问题时启用。
- `--debug-verbose`：开启“更详细的调试”（包含缓存/重定向等关键路径的附加日志），输出到 stderr。
- 当查询携带 ARIN 风格前缀（如 `n + =`）但跳转目标不是 ARIN 时，会自动剥离前缀并在 stderr 输出 `[DNS-ARIN] strip-prefix ...`（需 `--debug` 或重试指标开启时才会出现）。
- 说明：不再支持通过环境变量启用调试；请直接使用 `-D` 或 `--debug-verbose`。
- 调试日志采集提示：若查询命中内置已知 IP（例如 8.8.8.8 → whois.iana.org/arin），仅加 `--debug` 可能无 DNS/重试输出。可追加 `--retry-metrics --dns-cache-stats --no-known-ip-fallback` 强制经过 DNS/重试路径；需要仅 IPv4 则再加 `--ipv4-only`，示例：`./whois-x86_64 --title --debug --retry-metrics --dns-cache-stats --no-known-ip-fallback 8.8.8.8 2>debug.log`。
- `--selftest`：运行内置自检并退出；覆盖项包含折叠基础与折叠去重行为验证（非 0 退出代表失败）。自 3.2.10 起，任一 `--selftest-*` 故障旗标都会在真实查询前自动触发同一套 lookup 自测，因此该旗标仅在需要单独跑自测后立刻退出的场景使用。
  - 扩展（3.2.7）：默认自测包含折叠、重定向（redirect）与查找（lookup）检查；lookup 检查包含 IANA 首跳、单跳权威与“空响应注入”路径验证。可通过 `--selftest-inject-empty` 显式触发“空响应注入”路径（需要网络）。如需额外启用 grep 与安全日志（seclog）自测，请在构建时加入编译宏并使用 CLI：
    - 编译：`-DWHOIS_GREP_TEST`、`-DWHOIS_SECLOG_TEST`
    - 运行：`--selftest-grep`、`--selftest-seclog`
  - 远程脚本示例（启用全部自测并执行）：
    ```bash
    ./tools/remote/remote_build_and_test.sh -r 1 -a "--selftest" -E "-DWHOIS_GREP_TEST -DWHOIS_SECLOG_TEST"
    # 或在 PowerShell 中：
    & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -a '--selftest' -E '-DWHOIS_GREP_TEST -DWHOIS_SECLOG_TEST'"
    ```
  - 典型输出片段：
    ```
    [SELFTEST] fold-basic: PASS
    [SELFTEST] fold-unique: PASS
    [SELFTEST] redirect-detect-0: PASS
    [SELFTEST] redirect-detect-1: PASS
    [SELFTEST] auth-indicators: PASS
    [SELFTEST] extract-refer: PASS
    [SELFTEST] lookup-iana-first: PASS
    [SELFTEST] lookup-single-hop: PASS
    [SELFTEST] lookup-empty-inject: PASS
    [SELFTEST] grep: PASS
    [SELFTEST] seclog: PASS
    ```
  - 注意：grep 与 seclog 自测默认不开启；仅在需要验证正则引擎与安全日志速率/限频逻辑时使用，生产构建可不加这些宏以缩短构建时间。
  - 版本注入策略（简化）：默认不再附加 `-dirty` 后缀；如需恢复严格模式，可在构建或调用脚本前设置环境变量 `WHOIS_STRICT_VERSION=1`（暂不建议启用，待模块拆分完成后再使用严格标记，以降低日常迭代噪声）。
- `--fold-unique`：在 `--fold` 折叠模式下去除重复 token，按“首次出现”保序输出。

### 批量起始策略与调试（3.2.10+）

- `--batch-strategy <名称>`：仅在批量模式下启用可插拔策略；未指定时保持 raw 顺序（CLI host → 推测 RIR → IANA），不会触发 penalty 跳过或 plan-a 缓存日志。
  - `health-first`：沿用经典顺序并结合 DNS penalty 记忆跳过近期失败主机，是触发 `[DNS-BATCH] action=start-skip/force-last` 的必要前提。
  - `plan-a`：缓存上一条成功查询的权威 RIR，下一条查询若该 RIR 仍健康则直接作为首跳，并在 `--debug` 场景输出 `[DNS-BATCH] action=plan-a-cache`（缓存更新/清空）、`plan-a-faststart`（命中快速路径）、`plan-a-skip`（缓存 host 被 penalty，回退）等日志。
  - `plan-b`：缓存上一条权威 RIR，健康时优先使用；若被罚站则回退到首个健康候选（若无则强制 override/末尾），在 `--debug` 下输出 `[DNS-BATCH] plan-b-force-start/plan-b-fallback/force-override/start-skip/force-last`。
  未知名称会打印一行 `[DNS-BATCH] action=unknown-strategy name=<输入> fallback=health-first` 并自动启用 `health-first`，避免破坏旧脚本。
- `WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net'`：在进入批量循环前一次性将逗号分隔的主机标记为“已罚站”。通常需要配合 `--batch-strategy health-first`（观测 `start-skip/force-last`）或 `--batch-strategy plan-a`（观测 plan-a-* 日志），再搭配 `tools/remote/remote_build_and_test.sh -F testdata/queries.txt -a '--debug --retry-metrics --dns-cache-stats'`，即可在 remote smoke / Golden 剧本中稳定复现 `[DNS-BATCH] action=...` 信号。

#### 批量策略快手剧本

以下命令均默认在仓库根目录执行，示例二进制为 `whois-x86_64`，其余架构名称替换即可。脚本需要 BusyBox/Git Bash 环境，若要跨平台运行建议通过 `tools/remote/remote_build_and_test.sh`。

- **raw 顺序冒烟**：用于验证“无策略”路径仍能跑通、标题与尾行契约未被破坏。

  ```bash
  ./whois-x86_64 --debug --retry-metrics --dns-cache-stats \
    --batch-strategy raw < testdata/queries.txt
  ```

- **health-first + penalty 观察**：结合 `WHOIS_BATCH_DEBUG_PENALIZE` 提前将若干 RIR 标记为罚站，配合 `health-first` 观测 `[DNS-BATCH] action=start-skip/force-last`。

  ```bash
  WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net' \
    ./whois-x86_64 --debug --retry-metrics --dns-cache-stats \
    --batch-strategy health-first < testdata/queries.txt
  ```

- **plan-a 缓存路径**：先跑一轮 `health-first`，再复用 `plan-a` 确认 `[DNS-BATCH] action=plan-a-faststart/plan-a-cache/plan-a-skip`，并确保缓存失效时可回退。

  ```bash
  ./whois-x86_64 --debug --retry-metrics --dns-cache-stats \
    --batch-strategy health-first < testdata/queries.txt

  ./whois-x86_64 --debug --retry-metrics --dns-cache-stats \
    --batch-strategy plan-a < testdata/queries.txt
  ```

Golden 校验：推荐使用 `tools/test/golden_check_batch_presets.sh`（`raw` / `health-first` / `plan-a` / `plan-b`），现已对 plan-b 的 `[DNS-BATCH] plan-b-force-start/plan-b-fallback/force-override/start-skip/force-last` 等标签做断言。可在 `-l` 之前追加 `--selftest-actions 'force-suspicious,force-private'` 等列表，一次性断言 `[SELFTEST]` 与 `[DNS-BATCH]`。示例：

```bash
tools/test/golden_check_batch_presets.sh plan-a \
  --selftest-actions 'force-suspicious,force-private' \
  -l out/artifacts/<ts_pa>/build_out/smoke_test.log --strict
```

单条查询黄金脚本：`tools/test/golden_check.sh` 支持 capped referral 与自测日志：

- capped referral（例如 `-R 2`，尾行可能 `unknown @ unknown`）：
  ```bash
  tools/test/golden_check.sh -l out/artifacts/<ts>/build_out/smoke_test.log \
    --query 8.8.8.8 --start whois.iana.org --auth whois.arin.net \
    --auth-unknown-when-capped --redirect-line whois.afrinic.net
  ```
  若日志只有 `Additional`/`Redirect` 无尾行，脚本会自动放行并打印 `[INFO] tail missing but allowed`，无需额外开关。

- 自测日志（仅含 `[SELFTEST] action=*`，无头尾）：
  ```bash
  tools/test/golden_check.sh -l out/artifacts/<ts_selftest>/build_out/smoke_test.log \
    --selftest-actions force-suspicious --selftest-actions-only
  ```

当 golden 校验通过后，可将同一命令集透传给 `tools/remote/remote_build_and_test.sh -a '<命令>'` 做跨架构冒烟，使 `[DNS-BATCH]`、`[RETRY-METRICS]`、`[DNS-CACHE-SUM]` 等指标保持一致。

**Windows 一键四策略（raw + health-first + plan-a + plan-b）** – 通过 PowerShell 调用 `tools/test/remote_batch_strategy_suite.ps1`，一次性执行四轮远端冒烟，plan-b 轮次会校验 `[DNS-BATCH] plan-b-*` 标签：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/remote_batch_strategy_suite.ps1 `
  -Host 10.0.0.199 -User larson -KeyPath '/c/Users/你/.ssh/id_rsa' `
  -Queries '8.8.8.8 1.1.1.1' -BatchInput testdata/queries.txt `
  -SelftestActions 'force-suspicious,*;force-private,10.0.0.8' -EnablePlanB
```

`-SelftestActions '动作,目标;...'` 会为四组黄金命令统一追加 `--selftest-actions`，让 `[SELFTEST] action=*` 与 `[DNS-BATCH] action=*` 同时被断言。


### 新增：DNS 解析控制 / IP 家族偏好 / 负向缓存（3.2.7 & Phase1 扩展）

IP 家族偏好（解析与拨号顺序）：
- `--ipv4-only` 强制仅 IPv4（修复后不再先用域名按系统默认族顺序拨号）
- `--ipv6-only` 强制仅 IPv6
- `--prefer-ipv4` IPv4 优先，再 IPv6
- `--prefer-ipv6` IPv6 优先，再 IPv4
- `--prefer-ipv4-ipv6` 首跳（hop0）IPv4 优先，后续 referral/重试自动切换为 IPv6 优先；若首选失败仍会自动使用另一族
- `--prefer-ipv6-ipv4` 与上项镜像：首跳 IPv6 优先，后续 hop 改为 IPv4 优先（适合“本地 IPv6 更快，但多跳场景 IPv4 更稳”的拓扑）
- `--rir-ip-pref arin=v4,ripe=v6,...` 按 RIR 覆盖族偏好（可只设置部分 RIR）；优先级：`--ipv4-only/--ipv6-only` > RIR 覆盖 > `--dns-family-mode-*` > 全局 `--prefer-*`。RIR 覆盖会对应到 `ipv4-only-block`/`ipv6-only-block`。
- `--dns-family-mode <模式>` 控制 DNS 候选交错/顺序：`interleave-v4-first`/`interleave-v6-first`/`seq-v4-then-v6`/`seq-v6-then-v4`/`ipv4-only-block`/`ipv6-only-block`。可选 per-hop 覆盖：`--dns-family-mode-first`（首跳）与 `--dns-family-mode-next`（第二跳及以后）接受同样的模式。优先级：单栈强制（显式 only 或探测） > RIR 覆盖 > per-hop 覆盖 > 全局 family-mode > prefer 派生默认。`--debug` 下 `[DNS-CAND] mode=... start=ipv4|ipv6` 显示生效的跳次配置。
  启动时会做一次 IPv4/IPv6 可用性探测：IPv6 仅在本机存在公网地址（2000/4000::/3）时视为可用；两族都不可用直接 fatal 退出；仅单族可用时会自动强制对应 block 模式，忽略冲突偏好并打印 notice；双栈可用且未显式设定 prefer/only/family 时，默认生效 `--prefer-ipv6` + `--dns-family-mode-first interleave-v6-first` + `--dns-family-mode-next seq-v6-then-v4`（全局回落仍为 `seq-v6-then-v4`）。开启 `--debug` 会看到 `[NET-PROBE]` 打印探测结果。
用途简述：`--dns-family-mode`/`--dns-family-mode-first/next` 控制“候选表如何交错/切换”，而 `--prefer-*` 只决定首选族群。当首拨失败或被健康记忆判为坏时，family-mode 决定下一跳切换的族群与节奏；想直观看出差异，可在 `--debug` 下对比 `[DNS-CAND] mode/start`，或临时改成 `--prefer-ipv4-ipv6` 等降低单族偏好后再比较交错/顺序的表现。

CIDR 查询归一化：
- `--cidr-strip` 当查询项为 CIDR（例如 `1.1.1.0/24`）时，仅向服务器发送 IP 基地址，标题行仍保留原始 CIDR 字符串。
- `--no-cidr-erx-recheck` 关闭 CIDR 的 ERX/IANA 基准复查（默认开启复查）。

负向 DNS 缓存（短 TTL）：
- `--dns-neg-ttl <秒>` 设置负向缓存 TTL（默认 10 秒）
- `--no-dns-neg-cache` 禁用负向缓存

进程级汇总快照（`--dns-cache-stats`）：
- 当显式启用 `--dns-cache-stats` 时，客户端会在本次进程结束前额外打印一行 DNS 缓存统计：

  ```text
  [DNS-CACHE-SUM] hits=10 neg_hits=0 misses=3
  ```

- 该行只会在进程级别输出一次（单条/批量/自测均适用），统计来源于已有的 `[DNS-CACHE]` 计数器，仅用于诊断观察，不会改变解析/回退策略。
- 字段含义：
  - `hits`：本进程内 DNS **正向缓存命中次数**。当某个域名/主机名的解析结果已存在于缓存中并被成功复用（无需再次调用 `getaddrinfo`）时，计数加 1。
  - `neg_hits`：本进程内 DNS **负缓存命中次数**。当某个域名之前解析失败（例如 NXDOMAIN）且该“失败结果”被写入负缓存，后续对同一域名的查询直接命中这条负缓存记录时，计数加 1。
  - `misses`：本进程内 DNS **缓存未命中次数**。当缓存中既没有正向命中、也没有负向命中，客户端只能发起一次真正的 DNS 解析（`getaddrinfo`）时，计数加 1。
  - 直观理解：`hits` 越多说明重复查询有效利用了缓存；`neg_hits` 多通常意味着“同一个不存在/有问题的域名”被重复查询较多次；`misses` 偏大则意味着缓存命中率较低（查询集合高度分散，或进程刚启动、缓存尚未“预热”）。

> 2025-12 更新：legacy DNS cache 已彻底下线，`wc_dns` 成为唯一的解析与缓存数据面。`--dns-cache-stats` 输出仅保留 `[DNS-CACHE-SUM]`（源自 `wc_dns`），`[DNS-CACHE-LGCY]` / `[DNS-CACHE-LGCY-SUM]` 不再输出；若需诊断旧路径，请使用专门分支或本地补丁，而非运行时开关。

解析与候选控制（Phase1 新增，CLI-only）：
- `--no-dns-addrconfig` 关闭 `AI_ADDRCONFIG`（默认开启，避免在本机无 IPv6 时仍返回 IPv6 失败候选）
- `--dns-retry N` `getaddrinfo` 在 `EAI_AGAIN` 下的重试次数（默认 3，范围 1..10）
- `--dns-retry-interval-ms M` DNS 重试间隔毫秒（默认 100，范围 0..5000）
- `--rate-limit-retries N` 应用层限流/临时拒绝重试次数（默认 0，范围 0..10）
- `--rate-limit-retry-interval-ms M` 应用层限流重试间隔毫秒（默认 1500，范围 0..600000）
- `--dns-max-candidates N` 限制解析出的可拨号 IP 候选数量（默认 12，范围 1..64）
    - 白话：`--no-dns-addrconfig` 会关闭“与本机网络匹配”的系统过滤（例如：本机没有 IPv6 时默认会过滤掉 IPv6 结果），一般无需关闭；`--dns-retry*` 仅在临时 DNS 故障（EAI_AGAIN）时做快速重试。

Phase‑2 助手速记（`wc_dns` 模块）：
    - `wc_dns_build_candidates()` 会把用户指定的 IP 字面量保留为首个候选，再将 arin/apnic 等别名映射成规范域名，并按 `--prefer-*` / `--ipv*-only` / `--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4` 为当前 hop 交错 IPv6/IPv4 结果。
    - 解析阶段遵循 `--dns-retry*`、`--dns-max-candidates`，自动去重，并在仅提供字面量时回落到对应 RIR 的规范域名，保证拨号顺序可预测。
    - 空响应重试、强制 IPv4 重拨、已知 IPv4 fallback 以及自测黑洞路径都复用同一批候选；若加上 `--no-known-ip-fallback` / `--no-force-ipv4-fallback`，只会移除额外 fallback 层，不影响基础候选排序。
    - Phase 3 预览：在开启 `--debug` 或 `--retry-metrics` 时，`[DNS-CAND]` 之后会多一行 `[DNS-CACHE] hits=... neg_hits=... misses=...`，用于粗略观察 DNS 缓存/负缓存的使用情况，仅作诊断用途，不改变解析/回退行为。

#### DNS 自测操作指南（3.2.9）

以下示例默认在仓库根目录执行，使用 `whois-x86_64`，其他架构二进制同理。所有命令返回码为 0。

1. **IPv6-only 纯候选**
   ```bash
   ./whois-x86_64 --selftest --selftest-blackhole-arin --selftest-inject-empty \
     --ipv6-only --retry-metrics --debug
   ```
   观察 `[DNS-CAND]` 仅包含 IPv6 字面量且没有 `canonical`，`dns-ipv6-only-candidates PASS`。由于黑洞场景会诱发 IPv4 回退，结尾的 `fallback counters: forced>0 known>0` 证明 instrumentation 正常。

2. **Prefer-IPv6 + 回退开启**
   ```bash
   ./whois-x86_64 --selftest --selftest-blackhole-arin --selftest-inject-empty \
     --prefer-ipv6 --retry-metrics --debug
   ```
   `[DNS-CAND] canonical` 与 IPv4 候选重新出现，`dns-canonical-fallback PASS`。当 IPv6 候选被黑洞掉后，会看到 `known-ip fallback found-known-ip`、`forced-ipv4 fallback warning` 等日志，说明两层回退确实被触发。

3. **Prefer-IPv6 + 回退禁用**
   ```bash
   ./whois-x86_64 --selftest --selftest-blackhole-arin --selftest-inject-empty \
     --prefer-ipv6 --no-force-ipv4-fallback --no-known-ip-fallback \
     --retry-metrics --debug
   ```
   canonical 依旧被构建，但 `[DNS-FALLBACK]` 成对打印 `not selected`，`dns-fallback-disabled PASS` 且 `fallback counters` 为 0，可直观看到禁用了强制 IPv4 与已知 IPv4 回退。

回退行为开关（默认启用，不加开关即可使用）：
  - `--no-known-ip-fallback` 关闭“已知 IPv4”回退（针对特定 RIR 的固定 IPv4 兜底）
  - `--no-force-ipv4-fallback` 关闭“强制 IPv4”回退（空响应/异常场景再尝试纯 IPv4 重拨）
  - `--no-iana-pivot` 关闭“缺失 referral 时的 IANA 中转”策略（可能降低最终权威定位成功率）

调试统计（不改变行为）：
  - `--retry-metrics` 打印重试节奏统计（stderr），用于观察是否发生重试/等待；不会让程序“更慢”，仅输出统计数据。

说明：正向缓存保存“域名→IP”成功解析；负向缓存保存“解析失败”的临时记忆，用于在短时间内快速跳过重复失败的解析并降低阻塞时间。过期后自动清理，不影响后续成功解析。`--ipv4-only/--ipv6-only` 下已取消对原始域名的首拨，直接按单族枚举数值地址，避免系统默认族排序导致“仅 IPv4”仍先走 IPv6。
block 模式（`ipv4-only-block` / `ipv6-only-block`）不会再追加规范主机名 fallback，只保留允许族的数值候选；未显式设置 `--dns-family-mode-next` 时，全局 `--dns-family-mode` 会在第二跳及以后生效。

示例：
```powershell
# 优先 IPv4；设定负向缓存 TTL 为 30 秒
whois-x86_64 --prefer-ipv4 --dns-neg-ttl 30 8.8.8.8

# 自测：模拟负向缓存路径（域名 selftest.invalid 会被标记为负向缓存）
whois-x86_64 --selftest-dns-negative --host selftest.invalid 8.8.8.8

# 仅 IPv4，限制候选数为 4 并关闭已知 IPv4 回退
whois-x86_64 --ipv4-only --dns-max-candidates 4 --no-known-ip-fallback 1.1.1.1

# 仅 IPv6，关闭 IANA 枢纽中转（固定起始 RIR）
whois-x86_64 --ipv6-only --no-iana-pivot --host apnic 1.1.1.1
```

#### DNS 调试指引（Phase2）

- 推荐配方：`--debug --retry-metrics --dns-max-candidates <N>`；前两项让 stderr 带上连接级节奏/诊断，最后一项便于观察候选裁剪效果。
- 若要观测 IPv6→IPv4 或“首跳 IPv4、后续 IPv6”这类混合顺序，可组合 `--prefer-ipv6` / `--prefer-ipv4` / `--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4`，对比 `[RETRY-METRICS]` 的尝试顺序与 `=== Warning: empty response...` 中提示的回退主机。
- `[DNS-CAND]` 会列出每个 hop 的候选顺序，包含 `idx`、`type`（`ipv4` / `ipv6` / `host`）、`origin`（`input` / `resolver` / `canonical`）、本 hop 的 `pref=` 标签（如 `pref=v6-then-v4-hop1`），以及在触发上限时的 `limit=<N>`。
- `[DNS-FALLBACK]` 在强制 IPv4、已知 IPv4、空正文重试、IANA pivot 等非主路径运行时触发，除动作/结果/`fallback_flags` 外也会回显同一个 `pref=` 标签，使“操作员意图 vs 实际 fallback”一目了然。
- ARIN 查询：当目标是 `whois.arin.net` 且查询项不含空格（视为未带标志）时，自动注入常用 ARIN 前缀：IP/IPv6 用 `n + =`，CIDR 用 `r + =`，ASN 用 `a + =`（`AS...` 大小写皆可），NetHandle 用 `n + = !`。若查询项包含空格，则认为用户已带自定义标志，原样透传。若启用 `--cidr-strip`，CIDR 查询会按 IP 字面量处理并去除 CIDR 前缀长度。若 ARIN 输出出现 “No match found for” 且无 referral，则用原始查询（不带 ARIN 标志）转向 `whois.iana.org` 继续解析。
- 特殊说明：IPv4 `0.0.0.0` 结果固定为 `unknown`，与 `0.0.0.0/0` 保持一致。
- 需要验证 fallback 开关：
  - `--no-force-ipv4-fallback` + `--selftest-inject-empty` 可以确认“强制 IPv4”层关闭后的行为。
  - `--no-known-ip-fallback` 能阻止已知 IPv4 兜底，观察最终错误是否直接暴露。
  - `--dns-no-fallback` 一次性关闭“强制 IPv4/已知 IPv4”两层附加回退，只保留主路径，便于对比“有/无附加回退”时的差异（详见下方示例）。
- 建议在调试前阅读 `docs/RFC-dns-phase2.md`，掌握候选生成与回退栈的设计背景。

示例命令：
```powershell
# 观察候选裁剪 + IPv6→IPv4 顺序 + 空响应回退
whois-x86_64 --debug --retry-metrics --dns-max-candidates 2 --prefer-ipv6 --selftest-inject-empty example.com

# 对比关闭强制 IPv4 fallback 后的行为
whois-x86_64 --debug --retry-metrics --no-force-ipv4-fallback --selftest-inject-empty --host arin 8.8.8.8

# 结合自测黑洞，查看 stderr 中的 [DNS-CAND]/[DNS-FALLBACK]
whois-x86_64 --debug --retry-metrics --selftest-blackhole-arin --host arin 8.8.8.8 2> dns_trace.log
# 日志片段示例：
# [DNS-CAND] hop=1 server=whois.arin.net rir=arin idx=0 target=whois.arin.net type=host origin=canonical pref=v6-then-v4-hop1 limit=2
# [DNS-CAND] hop=1 server=whois.arin.net rir=arin idx=1 target=104.44.135.12 type=ipv4 origin=resolver pref=v6-then-v4-hop1 limit=2
# [DNS-FALLBACK] hop=1 cause=connect-fail action=forced-ipv4 domain=whois.arin.net target=104.44.135.12 status=success flags=forced-ipv4 pref=v6-then-v4-hop1
# [DNS-FALLBACK] hop=1 cause=manual action=iana-pivot domain=whois.arin.net target=whois.iana.org status=success flags=forced-ipv4|iana-pivot pref=v6-then-v4-hop1
 
# 对比有/无 dns-no-fallback 对 fallback 行为的影响（在真实 ARIN 环境下更易观察）：
# 1）允许附加回退（可能看到 action=forced-ipv4/known-ip）：
whois-x86_64 --debug --retry-metrics -h arin 8.8.8.8
# 2）禁用附加回退（fallback 分支仅打印 action=no-op status=skipped flags=dns-no-fallback）：
whois-x86_64 --debug --retry-metrics --dns-no-fallback -h arin 8.8.8.8
```

如需一站式查看候选/回退/缓存统计与健康记忆，推荐先阅读 `docs/OPERATIONS_CN.md` 中的“DNS 调试 quickstart”小节，并直接使用：

```bash
whois-x86_64 --debug --retry-metrics --dns-cache-stats 8.8.8.8
whois-x86_64 --debug --retry-metrics --dns-cache-stats --selftest 8.8.8.8
```

上述命令会在 stderr 中附带 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` / `[DNS-HEALTH]` 等日志，并在进程退出前打印单行 `[DNS-CACHE-SUM]` 汇总，适合配合 grep/日志查看器进行快速 eyeball 调试。

#### DNS 调试日志与缓存可观测性（3.2.9）

只要启用了 `--debug` 或 `--retry-metrics`，解析层就会输出结构化的 stderr 日志，并与 `[RETRY-METRICS*]` 共享同一节奏：每个 hop 先打印 `[DNS-CAND]` 列出候选，再在每次实际拨号后输出 `[RETRY-METRICS-INSTANT]`；若本次失败，则在下一次拨号前插入 `[DNS-FALLBACK]` 和/或 `[DNS-ERROR]`。因此即使你只关心重试节奏，也能同步看到 DNS 细节。

常见标签：
- `[DNS-CAND]`：逐条列出将要拨号的候选，包含 `type`（ipv4/ipv6/host）与 `origin`。`origin=input/canonical/resolver/cache/selftest` 分别表示用户字面量、映射 RIR 域名、实时解析、正向缓存复用、或自测注入。若末尾出现 `limit=<N>`，说明 `--dns-max-candidates` 已裁剪列表。`--ipv4-only` / `--ipv6-only` 现已跳过“先拨规范域名”这一步，整个列表会保持纯数值、且完全符合单族要求。
- `[DNS-FALLBACK]`：只要触发回退栈（强制 IPv4、已知 IPv4、空正文重试、IANA pivot 等）就会打印。`flags` 对应 `fallback_flags` 位掩码，`errno` / `empty_retry=` 进一步解释触发原因；`status=success` 表示该 fallback 生成了新的拨号尝试。
- `[DNS-BACKOFF]`：当候选被罚站时打印，字段包含 `server`（当前逻辑 whois host）、`target`（具体拨号目标，可能是 IP 或域名）、`family`、`action`（skip/force-last/force-override 等）、`consec_fail`、`penalty_ms_left`，便于与 `[DNS-HEALTH]` 或批量策略日志对齐。
- `[DNS-ERROR]`：报告解析失败。`source=resolver` 代表 `getaddrinfo` 直接出错，`source=negative-cache` 代表该域名仍在负向缓存有效期内而被跳过；`gai_err` 即原始错误码，方便与系统日志对齐。

缓存摘要：
- 正向缓存会连同 `sockaddr` 一起保存成功解析结果，后续命中会在 `[DNS-CAND]` 中看到 `origin=cache`，避免重复的 DNS/解析开销；容量由 `--dns-cache N` 决定（默认取构建配置值），有效期沿用全局 `cache_timeout`。
- 负向缓存只记录失败错误和到期时间，由 `--dns-neg-ttl` 控制（默认 10 秒）。命中时 `[DNS-ERROR]` 会显示 `source=negative-cache`，用于抑制同一无效域名的反复尝试。

与 `[RETRY-METRICS]` 的对照方式：
- `[DNS-CAND]` 总是在第一次拨号前全部打印完毕，因此可以直接用 `idx` 对照后续 `[RETRY-METRICS-INSTANT attempt=X]` 的顺序。
- 每当发生强制重试（timeout、空正文、自测黑洞等），会先输出 `[DNS-FALLBACK]` 说明原因，再继续遍历剩余候选；所以你可能看到 `[DNS-FALLBACK]` / `[DNS-ERROR]` 插在 `attempt=N` 与 `attempt=N+1` 之间，表明为何下一次会直接跳到另一族或备用 IP。
- 在 `--ipv4-only` / `--ipv6-only` 模式下，由于已取消规范域名的预拨号，`[RETRY-METRICS-INSTANT]` 中的每个 attempt 都可与一个纯数值候选一一对应，排查更直观。

### 新增：辅助脚本（Windows + Git Bash）

- `tools/remote/invoke_remote_plain.sh`：标准远程构建 + 冒烟 + Golden（不修改输出格式，验证契约）。
- `tools/remote/invoke_remote_demo.sh`：演示 `--fold --fold-unique -g ...` 的折叠输出（不跑 Golden）。
- `tools/remote/invoke_remote_selftest.sh`：仅运行 `--selftest`（不跑 Golden）。

> 以上脚本只是对 `tools/remote/remote_build_and_test.sh` 的参数封装，用于在 Windows 下可靠传递多词参数。

## 七、版本
版本号会在构建时自动注入（优先读取仓库根目录 `VERSION.txt`；远程构建时由脚本写入该文件），默认回退为 `3.2.9`。
- 3.2.3：输出契约细化——标题与尾行附带服务器 IP（DNS 失败显示 `unknown`），别名先映射再解析；折叠输出保持 `<query> <UPPER_VALUE_...> <RIR>` 不含服务器 IP。新增 ARIN 连通性提示（修正）：部分网络环境下，运营商可能对 ARIN 的 IPv4 whois 服务（whois.arin.net:43 的 A 记录）做端口屏蔽，导致 IPv4 无法连通；IPv6 访问正常。建议启用 IPv6 或使用公网出口。
- 3.2.4：模块化基线（wc_* 模块：title/grep/fold/output/seclog）；新增 grep 自测钩子（编译宏 + 环境变量）；改进块模式续行启发式（全局仅保留第一个 header-like 缩进行，后续同类需匹配正则）；远程构建诊断信息增强。新增 `--debug-verbose`、`--selftest`、`--fold-unique`。
- 3.2.2：九项安全性加固；新增 `--security-log` 调试日志开关（默认关闭，内置限频）。要点：内存安全包装、改进的信号处理、更严格的输入与服务器/重定向校验、连接洪泛监测、响应净化/校验、缓存加锁与一致性、协议异常检测等；同时彻底移除此前的 RDAP 实验功能与开关，保持经典 WHOIS 流程。
- 3.2.1：新增 `--fold` 单行折叠与 `--fold-sep`/`--no-fold-upper`；补充续行关键词命中技巧文档。
- 3.2.0：批量模式、标题/权威尾行、非阻塞连接与超时、重定向；默认重试节奏 interval=300ms/jitter=300ms。

- 3.2.6（版本号简化：默认不再附加 -dirty 后缀；保留 `WHOIS_STRICT_VERSION=1` 可回退严格行为）
- 3.2.0（Batch mode, headers+RIR tail, non-blocking connect, timeouts, redirects；默认重试节奏：interval=300ms, jitter=300ms）

## 八、远端构建与冒烟测试快速命令（Windows）

以下命令假设你已安装 Git Bash，并使用 Ubuntu 虚拟机作为交叉编译环境（详见 `tools/remote/README_CN.md`）。

- 在 Git Bash 中执行（默认联网冒烟测试，目标为 8.8.8.8）：

```bash
cd /d/LZProjects/whois
./tools/remote/remote_build_and_test.sh -r 1
```

- 同步产物到外部目录并仅保留 7 个架构二进制（将路径替换为你的目标目录）：

```bash
./tools/remote/remote_build_and_test.sh -r 1 -s "/d/Your/LZProjects/lzispro/release/lzispro/whois" -P 1
```

- 自定义冒烟目标（空格分隔）：

```bash
SMOKE_QUERIES="8.8.8.8 example.com 1.1.1.1" ./tools/remote/remote_build_and_test.sh -r 1
```

- 从 PowerShell 调用 Git Bash（注意路径与引号）：

```powershell
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -s /d/Your/LZProjects/lzispro/release/lzispro/whois -P 1"
```

### 产物存储与清理

下载链接风格（GitHub 直链 ↔ 仓库相对路径）的切换策略与脚本，见：`docs/RELEASE_LINK_STYLE.md`。

- 自 v3.2.0 起，`out/artifacts/` 已加入 `.gitignore`，不再纳入版本控制；CI 发布会在 GitHub Release 附带二进制资产。
- 如需清理本地历史产物，可使用 `tools/dev/prune_artifacts.ps1`（支持 `-DryRun`）。

## 九、与 lzispro 集成（交叉链接）

lzispro 的批量归类脚本 `release/lzispro/func/lzispdata.sh` 会直接调用本 whois 客户端并使用内置过滤，支持通过环境变量调整模式与关键词（有默认值，开箱即用）：

- WHOIS_TITLE_GREP：-g 标题前缀投影（例：`netname|mnt-|e-mail`）
- WHOIS_GREP_REGEXP：--grep 正则（POSIX ERE，例：`CNC|UNICOM|CHINANET|...`）
- WHOIS_GREP_MODE：`line` 或 `block`（whois 客户端默认 `block` 块模式；lzispro 脚本会显式设置为 `line` 以便 BusyBox 聚合）
- WHOIS_KEEP_CONT：行模式下是否展开续行到整个字段块（`1`/`0`，默认 `0`）

说明与示例请见 lzispro 项目 README“脚本环境变量（ISP 批量归类脚本）”一节：

- 本地（同工作区）：`../lzispro/README.md`
- GitHub：https://github.com/larsonzh/lzispro#%E8%84%9A%E6%9C%AC%E7%8E%AF%E5%A2%83%E5%8F%98%E9%87%8Fisp-%E6%89%B9%E9%87%8F%E5%BD%92%E7%B1%BB%E8%84%9A%E6%9C%AC

在 lzispro 调用路径中，脚本会默认设为“行模式 + 不展开续行”，便于 BusyBox awk 一行聚合；若需回退到客户端默认的“块模式”输出，可设置 `WHOIS_GREP_MODE=block`。
折叠示例（与脚本 `func/lzispdata.sh` 风格一致）：

```bash
whois-x86_64 --debug --retry-metrics --dns-cache-stats 8.8.8.8
whois-x86_64 --debug --retry-metrics --dns-cache-stats --selftest-blackhole-arin 8.8.8.8
```

上述命令保持 stdout 的头/尾契约不变，并在 stderr 输出 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` / `[DNS-HEALTH]`，进程结束前还会额外写出一次 `[DNS-CACHE-SUM] ...` 汇总。第二条命令追加任意 `--selftest-*` 旗标时，会在真实查询前自动跑 lookup 自测套件，因此 `[LOOKUP_SELFTEST]` 会自然出现，无需单独运行 `whois --selftest`。
```

## 四、常用示例

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

## 五、退出码
- `0`（`WC_EXIT_SUCCESS`）：成功  
  - 单条查询：查找流程完整结束；即使 RIR 明确返回“没有数据”（例如 `no-such-domain-abcdef.whois-test.invalid`），只要协议/网络链路成功，进程仍视为成功完成并返回 0。  
  - 批量模式：退出码只反映“整批是否跑完”，单行的网络/lookup 失败、可疑/私有 IP 等都会按行打印到 stderr，但不会把进程退出码从 0 改成 1。  
- `1`（`WC_EXIT_FAILURE`）：通用失败  
  - CLI 用法/参数错误（例如 `-B` 搭配位置参数、数值越界、缺少必需参数）——程序会先打印一条错误提示，再打印一份 Usage/帮助信息，然后以退出码 1 结束。  
  - 单条查询过程中发生的运行期失败：无法获得有效响应（多次重试后仍连接失败、DNS 解析硬错误、内部管线异常等）时，按“查询失败”处理并返回 1。  
- `130`（`WC_EXIT_SIGINT`）：被 SIGINT(Ctrl‑C) 中断  
  - 程序会在 stderr 打印 `[INFO] Terminated by user (Ctrl-C). Exiting...`，执行包括 DNS/重试统计在内的清理钩子，然后以 130 退出；远程冒烟脚本和外部自动化可能依赖这一固定值。  

## 六、提示
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

  示例（Windows PowerShell 远程冒烟 + 自定义节流）：
  ```powershell
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && \
    ./tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8 1.1.1.1' -a '--retry-metrics --selftest-fail-first-attempt --pacing-interval-ms 60 --pacing-jitter-ms 40 --pacing-backoff-factor 2 --pacing-max-ms 400' -P 1"
  ```

  示例（本地批量 + 临时关闭节流）：
  ```bash
  printf "8.8.8.8\n1.1.1.1\n" | ./whois-x86_64 --pacing-disable -B -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold
  ```

  可选自动断言（需要 `-r 1` 且 `--retry-metrics`）：`-M nonzero` / `-M zero`
  - 期望“禁用节流”为零睡眠：追加 `-M zero`
  示例：
  ```powershell
  # 默认节流应为非零
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8 1.1.1.1' -a '--retry-metrics --selftest-fail-first-attempt' -M nonzero"
  # 禁用节流应为零
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8 1.1.1.1' -a '--retry-metrics --selftest-fail-first-attempt --pacing-disable' -M zero"
  ```

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
- 建议：优先启用 IPv6；或确保出口为公网 IPv4 未被屏蔽。必要时可直接指定 ARIN 的 IPv6 字面量作为 `--host`，或临时选择固定起始服务器/禁用重定向以便排查。

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

