# RFC: whois 条件输出（Phase 2.5）

> 更新注记（2025-11-04）：本 RFC 聚焦“条件输出/筛选/折叠”等业务能力，与 3.2.2 引入的“安全加固与 `--security-log`”属于并行范畴，后者不改变 stdout 的既有输出契约，故不在本 RFC 的范围内。里程碑进度与本文的对照：
> - 已交付：`-g` 标题前缀筛选（Step 1）、`--grep/--grep-cs` 与行/块模式（Step 1.5）、`--fold` 单行折叠（在 3.2.1 提供）。
> - 待办/评估：本文中提到的 `--no-body`、链路/元信息打印与“命中即停/最大字节”优化等后续能力仍待按版本路线推进；当前 3.2.2 的改动主要为安全层面（与本 RFC 正交）。

目标（更新）：以“业务信息输出控制”为核心，优先支持按标题特征提取关键信息并折叠为单条记录，便于在 BusyBox 等精简环境中直接消费；在不改变默认输出的前提下，逐步补充过滤/统计等辅助能力。整体策略“小步快跑、可回退”。

## 背景与现状

- 现有特性：
  - 每条查询有固定首行 `=== Query: ... ===` 和尾行 `=== Authoritative RIR: <rir> ===`。
  - 已知元信息：query、最终权威 RIR、重定向次数、重试次数/是否、请求时长、是否私网 IP、错误码/原因（若失败）。
  - 批量模式（-B）与联网冒烟测试脚本，已在 CI/发布流程中验证。
- 痛点：
  - 外部脚本经常只需要“RIR、时长、是否成功”等元数据，却要消费整段 whois 文本。
  - 需要按条件过滤（只要 ARIN/仅成功/仅 IPv4 等），当前需二次处理文本，性能与复杂度较高。

## 业务优先与分工（核心）

- 核心业务流：
  1) 针对一个查询项（IP/域名/ASN），抓取 whois 原始文本；
  2) 根据“标题特征”（形如 `Key:` 的行首标签）选择所需字段；
  3) 将选取字段折叠为单条数据（单行），作为“本次查询的业务摘要”；
  4) 后续的“数据分类与存储”等由外部应用处理。
- 客户端职责（先做擅长的高效部分）：
  - 网络连接、超时/重试、重定向链处理；
  - 轻量级“标题行”筛选与值整形（合并多行值；去除冗余空白）；
  - 将选取字段折叠为一行的 k=v 对序列（BusyBox 友好）；
  - 追加必要的元信息（query/rir/status/duration），用于下游分类。
- 外部职责：
  - 业务侧分类、存储、落库、审计等；
  - 若需更复杂的跨 RIR 语义对齐，由外部脚本/应用处理。
- 接口约束：
  - 面向 BusyBox 精简环境与 ARM 架构优先；
  - 不以 JSON/CSV 作为首选接口；采用“行式 k=v 对 + 制表符分隔”的朴素文本协议；
  - 默认行为完全兼容旧版输出；新能力全部为可选开启。

## 设计原则

- 默认行为保持不变；新增能力全部为 opt-in。
- 仅围绕“现有可稳定获取的元信息”先提供过滤/投影；不引入重型语义解析。
- 输出友好：以行式 k=v 对为主（以 TAB 分隔对，以 `=` 连接键与值），BusyBox 可直接使用 awk/cut/grep 处理；JSON/CSV 延后。
- 性能优先：允许跳过大文本输出；提供早停匹配（可选）。

## CLI 拟新增能力（Step-by-step，更新）

第一步（Step 1：业务核心，建议 v3.2.0）：
- 标题字段选择：
  - `--pick <k1,k2,...>`：仅选择这些“标题键”对应的行，键名匹配规则：忽略大小写、匹配行首至冒号（如 `inetnum`, `inet6num`, `netname`, `country`, `descr`, `org`, `orgname`, `organization`, `cidr`, `route`, `origin`, `abuse-mailbox`）。
  - `--pick-mode <first|join>`：同名多次出现时的处理策略（默认 `first`；`join` 使用 `|` 拼接多值）。
  - 多行值折叠：相邻的同键多行会以 `; ` 拼接；首尾空白折叠为单空格。
- 单行折叠输出（BusyBox 友好）：
  - `--fold kv`：输出“单记录单行”的 k=v 对序列；对之间以 TAB 分隔，键值以 `=` 连接；默认附带：`query`、`rir`、`status`、`duration_ms`；示例：
    - `query=8.8.8.8	rir=arin	status=success	duration_ms=132	netname=GOOGLE	country=US`
  - 字符处理：值中的制表符与换行折叠为空格；连续空白归一为单空格；前后空白去除。
- 正文控制：
  - `--no-body`：抑制原始 whois 正文；与 `--fold kv` 搭配显著降 IO；默认仍保留首/尾标题行（保持契约），若同时指定 `--quiet-head-tail` 可完全仅输出折叠行。
- 轻量元过滤（可选）：
  - `--filter-rir <list>`、`--filter-status <success|error>`（便于外部侧先裁剪不必要的数据）；
  - 保持最小化，不引入 CSV/JSON。
- 统计（可选）：
  - `--stats`：汇总总数/成功数/RIR 分布/时延分位，用于批处理观测；输出在最后。

（修订补充）Step 1：标题 grep（首个管道，优先实现）
- 目标：仅在“信息标题行”上进行匹配筛选；用户以一个字符串参数提供多项前缀模式；未指定则完整透传。
- 标题行判定：取行首“第一个非空白字段”，若该字段以冒号 `:` 结尾，则视为标题行；仅对这类行进行匹配判断（其余行不参与匹配）。
- 匹配语义（简约化）：
  - 接口：`-g "pat1|pat2|..."`
  - 模式：前缀匹配（prefix-only），大小写不敏感（case-insensitive）。
  - 仅匹配“标题名”（即上述字段去掉末尾冒号后的内容），不包含值域。
  - 不提供额外模式开关（regex/contains/exact 等）于首版；后续如需，再增量引入。
  - 重要说明：`-g` 为“前缀匹配”，并非正则表达式；若需要正则，请使用 `--grep/--grep-cs`。
- 续行输出：当某个标题行被匹配选中时，输出该标题行及其“续行”（以空白字符开头的后续行），直到遇到下一标题行。
- 首/尾行：
  - 保留：每条查询的第一行 `=== Query: ... ===` 与最后一行 `=== Authoritative RIR: ... ===` 默认保留，用于分段；
  - 判定：这两行的识别为大小写敏感（严格匹配），以保证准确性；
  - 可选：若未来需要极简输出，可新增 `--quiet-head-tail` 开关（非首版）。
- 无条件：未提供 `-g` 时，不做筛选，完整输出原始文本（保持兼容）。
- 输入上限建议：
  - 整个 `-g` 字符串 ≤ 4096 字符；拆分项数 ≤ 64；单项长度 ≤ 128。

（新增）Step 1.5：正则过滤（块/行两种模式，已实现）
- 目标：不受“标题名”限制，直接用正则对“业务条目块”（标题+续行）匹配；块内任意行命中，则整块输出。
- 接口：
  - `--grep <REGEX>`（大小写不敏感）
  - `--grep-cs <REGEX>`（大小写敏感）
  - `--grep-line`：启用“行模式”，逐行选择；
  - `--grep-block`：切回“块模式”（默认），与 `--grep-line` 对称；
  - `--keep-continuation-lines`：与 `--grep-line` 联合使用，若匹配发生在某个“标题块”（标题+续行）之内，则输出整个该块（等价于对该块做一次块模式的展开输出）。
  - `--no-keep-continuation-lines`：关闭续行展开，与 `--keep-continuation-lines` 对称。
- 正则引擎：POSIX ERE（regcomp/regexec），不引入 PCRE/PCRE2；支持 `() | [] ^ $ . * + ?`，以及字符类 `[[:space:]]` 用于空白。
- 组合关系：若同时指定 `-g` 与 `--grep/--grep-cs`，按顺序执行（先标题前缀筛选，后块级正则），以便先粗筛再精筛。
- 模式/大小写的独立性与优先级：
  - “模式”由 `--grep-line/--grep-block` 控制（最后一次生效）；
  - “大小写”由 `--grep/--grep-cs` 控制（后者覆盖前者的编译设置）；
  - 多次提供 `--grep/--grep-cs` 时，建议把多个关键词合并为单个正则用 `|` 组合。
- 限制：REGEX 长度 ≤ 4096；编译错误立即报错退出。必要时可引入 `--max-scan-bytes` 作为极端防护（默认无需）。


第二步（Step 2：增强与审计，建议 v3.2.1）：
- 服务器链路：`--print chain` 或 `--fields server_chain`：输出重定向链（`server1>server2>...`），用于审计；
- RIR 同义键轻量归一（可选）：提供少量“别名→规范键”的内置映射（例如 ARIN 的 `NetRange` 归一到 `inetnum` 或 `range`），默认关闭，显式 `--normalize-keys` 开启；
- JSON/CSV 延后，默认不提供，避免破坏 BusyBox 场景的简洁性。

第三步（Step 3：早停与限流，建议 v3.2.2）：
- `--max-bytes N`：正文读取上限（防御超长输出）；
- （可选）“命中即停”的早停优化：与 `--grep/--grep-cs` 结合，在匹配足够信息后提前结束输出/拉取（实现需评估对重定向链和尾部契约的影响）。

第四步（Step 4：轻量解析增强，建议 v3.3.x）：
- 简单规则抽取通用字段（尽力而为）：`netname`、`country`、`inetnum/inet6num`、`descr`；
- 字段以 `parsed.*` 命名（如 `parsed.netname`）；默认关闭，显式开启。

退路与兼容：
- 任何一步若发现不稳定/代价过高，可保持在前一步设计；默认输出行为不变。

## 字段一览（初版，行式 kv 输出）

- query：原始查询值
- rir：最终权威 RIR（one of: apnic, arin, ripe, afrinic, lacnic, unknown）
- status：success|error
- error：若 error，给出简短原因代码（timeout|connect|parse|other）
- duration_ms：该查询总耗时
- bytes：正文字节数（若 `--no-body`，为 0 或捕获到的字节数）
- attempts：实际重试次数
- redirects：重定向跳转次数
- server：最终查询服务器
- server_chain：重定向链（server1>server2>...>final）
- is_private：布尔

（Step 4）
- parsed.netname / parsed.country / parsed.inetnum / parsed.inet6num / parsed.descr（尽力而为）

## 输出示例

0) 标题 grep（包含续行，默认大小写不敏感）：
```
$ ./whois-client 8.8.8.8 --title-grep inetnum,netname,country
=== Query: 8.8.8.8 ===
inetnum:        8.8.8.0 - 8.8.8.255
netname:        GOOGLE
country:        US
=== Authoritative RIR: arin ===
```
注：此处“title grep”基于 `-g` 的“大小写不敏感前缀匹配”，不是正则表达式。

1) 业务折叠（单行 kv，BusyBox 友好）：
```
$ ./whois-client 8.8.8.8 --pick netname,country,inetnum --fold kv --no-body
query=8.8.8.8	rir=arin	status=success	duration_ms=132	inetnum=8.8.8.0 - 8.8.8.255	netname=GOOGLE	country=US
```

2) 过滤 + 抑制正文（保留原有首/尾行）：
```
$ cat ips.txt | ./whois-client -B --filter-rir apnic,ripe --no-body
=== Query: 1.1.1.1 ===
=== Authoritative RIR: apnic ===
```

3) 多值处理：
```
$ ./whois-client 1.0.0.0/24 --pick route,origin --pick-mode join --fold kv --no-body
query=1.0.0.0/24	rir=apnic	status=success	duration_ms=95	route=1.0.0.0/24|1.0.0.0/16	origin=AS13335
```

## 性能与资源

- `--no-body` 可显著减少管道 IO 与下游处理开销。
- `--grep` + `--max-bytes` 支持“命中即停”，缩短端到端时延。
- 过滤发生在输出阶段，不影响连接与抓取；后续可考虑对某些条件（例如家族/私网）在连接前短路。

## 验收与测试

- 单元：
  - 标题匹配模式（contains/exact/prefix/regex）与大小写开关；
  - 续行包含逻辑（标题+续行，遇下一个标题停止）；
  - 无条件时的“完整输出”保证；
  - `--filter-rir`/`--filter-status` 的组合与顺序不敏感。
- 集成：
  - 对固定响应样本验证筛选前后内容（包含首/尾行）；
  - BusyBox 管道示例（grep/awk/cut）验证可直接处理。
- 性能：
  - 对长响应比较“全量输出 vs 标题筛选”字节数与耗时差异；
  - 与 `--max-bytes`/`--grep`（后续步骤）联动预期。

## 版本与里程碑

- v3.2.0：Step 1（标题 grep（首个管道）：标题筛选+续行，默认无条件等价全量输出；可选轻量元过滤/统计）
- v3.2.1：Step 2（重定向链输出 + 可选轻量键归一）
- v3.2.2：Step 3（grep/早停/最大字节）
- v3.3.x：Step 4（轻量字段抽取）

## 风险与边界

- RIR 文本千差万别；Step 4 仅做“尽力而为”的键值抽取，并提供清晰的关闭开关（默认关闭）。
- JSON/CSV 非核心，默认不提供，避免外部环境处理负担；如需，置于后续版本并保持独立开关。
- 严格兼容：默认运行不改变现有输出；所有能力需显式开启。
