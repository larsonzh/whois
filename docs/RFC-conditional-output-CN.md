# RFC: whois 条件输出（Phase 2.5）

> 状态：重定版契约生效（2026-08-24）；WP-03 `--no-body`、WP-04 `--print-meta`、WP-05A `--print-chain`、WP-05B `--pick` 与 WP-06 `--stats` 已实现并完成各自最终门禁。
> 权威顺序：本节“2026 重定版”高于下方历史路线；历史示例仅保留设计演进背景，不得作为新实现依据。
> 关联计划：`docs/RFC-post-3.3.0-development-plan.md`。

## 2026 重定版：能力分栏

| 分栏 | 能力 | 当前结论 |
|---|---|---|
| 已实现 | `-g`；`--grep/--grep-cs`；`--grep-line/--grep-block`；续行控制；`--fold`、`--fold-sep`、`--fold-unique`、`--no-fold-upper`；WP-03 `--no-body`；WP-04 `--print-meta`；WP-05A `--print-chain`；WP-05B `--pick`；WP-06 `--stats` | 保持 title -> grep -> pick -> fold/body 顺序，并按启用项追加 pick/chain/meta 观测行和批次末尾 stats 汇总 |
| 废弃/冲突设计 | `--fold kv`、`--title-grep`、`--print chain`、`--fields server_chain` | 不实现；分别由现有 `--fold`、`-g` 及后续独立选项取代 |
| 风险项（暂缓） | `--max-bytes`、网络读取早停/命中即停、并发批量、DNS/重试调整、JSON/CSV、`--normalize-keys` | 不属于 WP-03–WP-06；如需实施须另立工作包 |

## WP-03：`--no-body` 冻结契约

### 1. 作用域与数据流

- `--no-body` 是无参数、默认关闭的最终渲染开关；不新增短选项。
- 查询、DNS、连接、重试、完整响应读取、重定向、权威判定、title 投影和 grep 过滤全部照常执行。该选项不得提前停止网络读取，不得改变退出码、最终权威 RIR、诊断标签或 workbuf 统计。
- 固定处理顺序为：title 投影 -> grep -> fold 判定 -> body 渲染控制。`--no-body` 仅跳过最终正文写入 stdout，不释放或绕过前置过滤所需输入。

### 2. stdout/stderr 与记录边界

- 单条成功或失败查询均保留且只保留现有查询首行和权威尾行：
  - `=== Query: <item> === via <host-or-alias> @ <ip|unknown>`
  - `=== Authoritative RIR: <rir-host> @ <ip|unknown> ===`
- Phase C 早收敛产生的 `Address Status:` 是客户端生成的状态行，不属于原始 WHOIS 正文；若原路径会输出该行，`--no-body` 继续保留它，位置仍在首行与尾行之间。
- 原始 WHOIS 正文、续行、过滤后的正文以及正文型失败说明均不写 stdout。尾行仍按既有结果输出 `error @ error` 或 `unknown @ unknown`，进程退出码保持现有查询结果语义。
- 批量模式每个非空输入项独立形成上述记录，记录顺序与输入顺序一致；不得新增批次头、空分隔记录或汇总行。BusyBox 管道逐行输入语义不变。
- stderr 仅保留现有诊断/指标。`--no-body` 成功启用时不新增提示行；非法组合按现有 usage-error 路径向 stderr 输出单行错误并非零退出。

### 3. 组合与冲突

| 组合 | 规则 |
|---|---|
| `--no-body` + `-g/--grep*` | 合法；过滤链仍完整执行，但过滤后的正文不渲染。首行、可适用的 Address Status、尾行保持不变 |
| `--no-body` + `--show-non-auth-body/--show-post-marker-body/--hide-failure-body` | 合法；这些正文选择器先执行，最终正文仍由 `--no-body` 抑制 |
| `--no-body` + `-B` 或 stdin 非 TTY | 合法；逐查询输出首行/状态行/尾行 |
| `--no-body` + `--plain` | 非法；两者叠加会消除稳定记录边界，必须在查询开始前 fail-fast |
| `--no-body` + `--fold` | 非法；fold 的唯一业务输出来自正文，必须在查询开始前 fail-fast |
| `--no-body` + `--fold-sep/--fold-unique/--no-fold-upper` | 非法；不得静默接受无效 fold 配置 |

重复指定 `--no-body` 幂等。选项先后顺序不改变上述判定。

### 4. 转义、缺失值与资源上限

- WP-03 不新增字段协议或用户值，因此不新增 TAB、`=`、反斜杠或不可打印字节转义规则；首尾行继续使用既有输出净化与 `unknown/error` 表示。
- `--no-body` 不接受参数，不引入字段数、参数长度或累计输出长度上限。现有 query、grep、title、fold 和网络响应上限继续生效。
- 不得以 `--no-body` 为理由新增正文读取上限；`--max-bytes` 仍为暂缓项。

### 5. 验收矩阵

- 默认未启用：与当前 golden 逐字节一致。
- 单条：成功、`unknown`、`error` 各验证首尾行保留且正文为零；Phase C Address Status 路径验证状态行保留。
- 批量：显式 `-B` 与 stdin 非 TTY 各验证至少两条输入的记录边界和顺序。
- 组合：`-g`、`--grep`、正文选择器分别与 `--no-body` 组合；`--plain`、`--fold` 及所有 fold 修饰选项逐项验证 fail-fast。
- BusyBox：`printf '8.8.8.8\n1.1.1.1\n' | whois-client --no-body` 可按 `=== Query:` 与 `=== Authoritative RIR:` 稳定分段。

验收结果（2026-08-24）：独立合同 smoke `13/13` PASS；最终同步制品 Strict `lto-auto` 九架构 build/hash、Golden 与 IANA/ARIN/AFRINIC 三起点 referral 全 PASS且无编译/LTO 告警（`out/artifacts/20260824-115609`，248s）。Linux/QEMU、win32、win64 smoke 分别为 `18/3/3`，首尾行一一对应且零告警；仓库内、外部 lzispro 同步目录均与 artifact `9/9` SHA 一致；最终 win64 制品再次通过 `13/13` 合同 smoke（`out/artifacts/no_body_contract/20260824-120031`）。

## WP-04：`--print-meta` 冻结契约

### 1. 作用域与数据流

- `--print-meta` 是无参数、默认关闭的观测选项；不新增短选项；选项名固定为 `--print-meta`，不复用 `--fold` 名称。
- 查询、DNS、连接、重试、完整响应读取、重定向、权威判定、title 投影、grep 过滤与 fold 处理全部照常执行。该选项不得提前停止网络读取，不得改变退出码、最终权威 RIR、诊断标签或 workbuf 统计。
- 每条查询在记录末尾追加一行元信息（见第 2 节）；批量模式逐条输出，不新增批次汇总行（汇总属 WP-06 `--stats`）。

### 2. 输出格式与记录边界

- 一行一个记录；字段对之间以 TAB 分隔，键与值以 `=` 连接；解析规则为取第一个 `=` 作为键值分隔，值允许包含 `=`。
- 字段顺序固定为：`query`、`rir`、`status`、`duration_ms`、`attempts`、`redirects`。
- 行位置（固定排列）：
  - 非 fold/plain：`=== Query:` → `Address Status:`（如适用）→ 正文（`--no-body` 时省略）→ `=== Authoritative RIR:` → 元信息行
  - `--fold`：折叠行 → 元信息行
  - lookup 失败且启用 `--fold`：`<query> ERROR` → `rir=error status=error` 元信息行
  - 安全规则在 lookup 前拒绝输入：不回显业务边界，仅输出 `rir=error status=error` 元信息行；诊断仍写 stderr
  - `--plain`：见第 3 节（非法组合）
- 批量记录顺序与输入顺序一致；每个非空输入项恰好输出一行元信息。

### 3. 组合与冲突

| 组合 | 规则 |
|---|---|
| `--print-meta` + `-g/--grep*` | 合法；过滤只影响正文，元信息行与过滤结果无关 |
| `--print-meta` + `--no-body` | 合法；元信息行照常输出 |
| `--print-meta` + `--fold` | 合法；折叠行后输出元信息行 |
| `--print-meta` + `--fold-sep/--fold-unique/--no-fold-upper` | 合法；由 `--fold` 组合承载 |
| `--print-meta` + `--plain` | 非法；在查询开始前按 usage-error 输出单行错误并非零退出 |

重复指定 `--print-meta` 幂等；选项先后顺序不改变判定。冲突判定优先级：`--print-meta` 与 `--plain` 的冲突最先判定；现有 `--plain`/`--no-body`/`--fold` 互斥判定保持不变，`--print-meta` 不改变这些判定。

### 4. 字段语义与稳定表示

- `query`：本输入项（批量行归一后原样，含 CIDR/域名/ASN）。
- `rir`：最终权威显示 host，与尾行 host 完全一致（含 `unknown`/`error`；IP 字面量按尾行同一映射规则转换）。
- `status`：仅两值 `success`/`error`。`error` 当且仅当最终失败判定成立（即尾行 host 为 `error` 的未收敛/失败判定：限流/拒绝访问、传输失败、未消失败债权等）；其余情形（权威收敛、`unknown` 权威回落、Phase C 早收敛 Address Status）均为 `success`。
- lookup 前本地短路保持既有业务边界语义：非法 IP/CIDR 与显式私网拒绝已有 `unknown` 尾行，因此输出 `rir=unknown status=success`；安全规则拒绝没有业务尾行，稳定输出 `rir=error status=error`。这些路径未发生网络尝试，三个数值字段均为 0。
- `duration_ms`：查询生命周期单调时钟差值（毫秒，无符号整数；由执行器在查询前后采样单调时钟）。
- `attempts`：查询生命周期内连接尝试次数（本次 lookup 实际网络上下文计数的前后差值；无法取得差值时输出 0）。
- `redirects`：由既有 `hops` 推导，公式 `(hops > 0) ? (hops - 1) : 0`。
- 数值字段不可测量的稳定表示为 0；所有字段恒输出，不省略键。

### 5. 转义与资源上限

- 值中的 TAB、LF、CR、NUL 及其他控制字符归一为单个空格；连续空白折叠为单空格；首尾空白去除；反斜杠按字面输出，不引入转义层。
- 键名固定小写 ASCII（字母与下划线）；无转义前缀。
- 不新增资源上限：query 长度沿用现有上限（批量行缓冲、argv 参数）；元信息行由固定键和有界值组成，不新增累计输出长度上限。

### 6. 兼容与字段演进

- 字段名称与语义冻结；后续新增字段只允许追加到行尾并在本 RFC 登记，不改变既有字段顺序与含义；同步更新解析器与黄金测试。
- `--print-meta` 是观测选项：不掩盖查询失败，不改变权威判定，不改变退出码。

### 7. 验收矩阵

- 默认未启用：与当前 golden 逐字节一致。
- 单条：success、unknown、error 各输出一行元信息；字段数 6、顺序正确、数值字段非负。
- 批量：显式 `-B` 与 stdin 非 TTY 各验证每条记录一行元信息、顺序一致、无附加汇总行。
- 组合：`--no-body`、`--fold`、`-g`/`--grep*` 各组合验证行排列；`--plain` 组合验证查询前 fail-fast（usage-error 单行、非零退出）。
- 早返回：lookup 失败 + fold、非法 IP/CIDR（普通/fold）、显式私网拒绝和安全规则拒绝均验证恰好一行元信息及稳定状态。
- 归一化：argv 值的前导/尾随空白删除，内部空白和控制字符折叠为单空格。
- 数值语义：`duration_ms >= 0`、`attempts >= 0`、`redirects >= 0`；私网/无效输入样本下 `rir` 与 `status` 与尾行语义一致。
- BusyBox：`printf '8.8.8.8\n1.1.1.1\n' | whois-client --no-body --print-meta` 可由 awk/cut 按 TAB 提取 `query=`、`status=` 字段。

### 验收结果（2026-08-24）

- 独立复核后的合同 smoke 扩展为 `18/18` PASS（`out/artifacts/print_meta_contract/20260824-151824`）：在原 success/unknown/error/private、`--no-body`/`--fold`/显式批量、幂等与 `--plain` 基础上，新增 lookup 失败 + fold、非法 IP/CIDR（普通/fold）、显式私网、安全拒绝、前导/尾随空白归一化、stdin 自动批量、grep 组合及未启用 `--print-meta` 时 fold 失败 stdout 兼容性覆盖；最终同步 win64 制品 standalone selftest 及 parser/冲突断言继续 PASS。
- 最终同步制品 Strict `lto-auto` 九架构 build/hash、Golden 与 IANA/ARIN/AFRINIC 三起点 referral 全 PASS且无编译/LTO 告警（`out/artifacts/20260824-151759`，350s）；Linux/QEMU、win32、win64 smoke 首尾一一对应且零告警；两个 lzispro 同步目录与 artifact `9/9` SHA 一致。
- 实现与独立复核共修复：共享 workbuf 覆盖导致 `query=unknown`、普通失败路径缺元信息、失败 + fold 与 lookup 前短路漏行、前导空白未去除，以及 attempts 错读 active context 而非本次 lookup override context。值归一化改为无堆分配流式输出，避免内存分配失败静默丢失整条元信息。

## WP-05：链路输出与轻量字段抽取冻结契约

WP-05 按风险和数据所有权拆成两个独立验收切片：WP-05A `--print-chain` 负责查询执行器中的有序链路观测；WP-05B `--pick`/`--pick-mode` 负责条件输出管道中的精确标题字段抽取。两者可组合，但不得因合并开发而共享隐式状态或放宽各自门禁。

### 1. WP-05A `--print-chain`

- `--print-chain` 是无参数、默认关闭的观测选项；不新增短选项，也不复用历史草案中的 `--print chain` 或 `--fields server_chain`。
- 每条查询追加一行 `chain=<host1>><host2>>...`。键名固定为 `chain`；分隔符固定为 ASCII `>`；host 使用查询执行器实际选中的规范 server token，不附带 DNS IP、端口、重试次数或诊断原因。
- 链路是按时间排序的逻辑 hop 序列：一个 server 进入本次 hop 执行时登记一次；同一 hop 内的 DNS 候选、连接重试和应用层重试不得重复登记。策略确实离开后又回访同一 server 时保留非相邻重复项，避免丢失审计事实。
- 链路不得从现有 `visited[]` 反推。`visited[]` 是循环检测/轮询策略集合，会发生别名折叠、删除和重插入，不具备稳定的时间顺序；实现必须在 `wc_result_meta` 生命周期内单独保存有序链路。
- 未进入网络 hop（Phase C 早收敛、非法 IP/CIDR、显式私网拒绝、安全规则拒绝）以及无法取得链路时固定输出 `chain=unknown`。首 hop DNS/连接失败但已进入执行器时仍输出该 server。
- 最多登记 16 个 hop，与现有查询执行器的访问上限对齐；若未来内部上限扩大且实际链路超过 16，保留前 16 项并在末尾追加 `>truncated`。不得静默截断。

### 2. WP-05B `--pick` 与 `--pick-mode`

- `--pick <k1,k2,...>` 默认关闭，输出一行 TAB 分隔的 `k=v` 字段抽取结果；字段顺序严格保持用户首次指定顺序。重复键大小写不敏感地去重，不重复输出。
- 首版键白名单冻结为：`netname`、`country`、`inetnum`、`inet6num`、`origin`、`route`、`descr`。键匹配大小写不敏感且必须精确匹配冒号前完整标题名；不得复用 `-g` 的前缀匹配语义，以免 `route` 意外匹配其他键。
- 参数按逗号切分并删除键两侧 ASCII 空白；空项、白名单外键或最终无有效键均在查询开始前按 usage-error 失败。参数总长上限 4096 字节、字段数上限 64、单键上限 128 字节；这些通用解析上限与 `-g` 对齐，白名单会进一步限制实际唯一字段数。
- `--pick-mode first|join` 控制同名标题的多次出现，默认 `first`。`first` 取过滤后视图中的首次出现（即使值为空）；`join` 按出现顺序用 ASCII `|` 连接各次值。单次标题的续行先按原顺序使用 `; ` 拼入该次值，再参与 first/join。
- 仅显式提供 `--pick-mode` 而没有 `--pick` 属于 usage-error；重复 `--pick` 以最后一次参数为准，重复 `--pick-mode` 以最后一次合法值为准。
- 每个请求字段恒输出。缺失标题或值为空时输出空值（例如 `country=`），不得省略键、输出 `unknown` 或借用其他 RIR 的同义键。首版不做跨 RIR 语义归一，`--normalize-keys` 继续暂缓。
- 字段值沿用 WP-04 元信息归一化：删除首尾空白，把 TAB/LF/CR/NUL、其他控制字符和连续空白折叠为一个空格，反斜杠与 `=` 按字面输出。`join` 的 `|` 只表示展示层连接，消费者不得把它视为可逆转义格式。
- 每个请求字段的累计值上限为 64 KiB；达到上限时该字段截断并以字面量 `...` 收尾，同时继续抽取并输出其余请求键。该限制只作用于抽取行，不得截断原始响应或改变权威判定。

### 3. 固定处理顺序与记录排列

- 数据处理顺序冻结为：title 投影（`-g`）→ grep → pick 抽取 → fold/body 渲染。`--pick` 从 grep 后、fold 前的过滤视图抽取，不修改该视图，也不隐式抑制正文。
- 非 fold/plain 记录排列：`=== Query:` → `Address Status:`（如适用）→ 正文（`--no-body` 时省略）→ `=== Authoritative RIR:` → pick 行（如启用）→ chain 行（如启用）→ WP-04 meta 行（如启用）。
- fold 记录排列：折叠业务行 → pick 行 → chain 行 → meta 行。lookup 失败时仍先沿用 WP-04 的 `<query> ERROR` 规则，再按相同顺序追加启用的观测行。
- lookup 前本地短路沿用既有业务边界；启用的 pick 行仍输出全部空值，chain 行输出 `chain=unknown`，meta 行沿用 WP-04 状态。安全规则拒绝不新增查询首尾行。
- 批量模式每个非空输入项独立输出其 pick/chain/meta 行，顺序与输入一致；不得新增批次汇总行。

### 4. 组合、退出码与兼容性

| 组合 | 规则 |
|---|---|
| `--print-chain` + `--print-meta`/`--pick` | 合法；固定按 pick → chain → meta 排列 |
| `--print-chain` + `--no-body`/`--fold`/`-g`/`--grep*`/批量 | 合法；仅增加链路观测行 |
| `--pick` + `-g`/`--grep*` | 合法；按固定过滤顺序，过滤掉的标题表现为缺失空值 |
| `--pick` + `--no-body` | 合法；先完成抽取，再抑制正文 |
| `--pick` + `--fold` | 合法；折叠业务行后追加 pick 行 |
| `--print-chain` 或 `--pick` + `--plain` | 非法；缺少稳定记录边界，查询开始前 fail-fast |

- 两个切片均为输出/观测能力：不得改变查询、DNS、连接、重试、重定向、权威判定、退出码、stderr 标签或默认未启用时的 stdout。
- 字段名、行位置与语义冻结。后续增加链路属性或 pick 键须另行登记；不得改变 `chain` 分隔符、既有键顺序或缺失值表示。

### 4.1 命令用例

```sh
# 只保留记录边界并观察逻辑 WHOIS hop
./whois-x86_64 --no-body --print-chain 8.8.8.8

# 按请求顺序抽取字段；缺失字段仍输出 key=
./whois-x86_64 --no-body --pick netname,country,inetnum 8.8.8.8

# title 投影先于 pick；未保留在投影视图中的字段输出空值
./whois-x86_64 -g 'NetName|Country' --pick netname,country,descr 8.8.8.8

# fold 业务行后依次追加 pick 与 chain；此组合不使用 --no-body
./whois-x86_64 -g 'NetName|Country' --fold --pick netname,country --print-chain 8.8.8.8

# 合并重复 descr，并按 pick -> chain -> meta 输出观测行
./whois-x86_64 --no-body --pick descr,country --pick-mode join --print-chain --print-meta 1.1.1.1

# stdin 非 TTY 自动批量；每个输入项独立输出 pick/chain 行
printf '8.8.8.8\n1.1.1.1\n10.0.0.8\n' |
  ./whois-x86_64 --no-body --pick netname,country --print-chain
```

`--pick` 与 `--fold` 可组合，但 `--no-body` 与任何 fold 开关互斥；`--pick` 或 `--print-chain` 与 `--plain` 也会在查询开始前按 usage-error 失败。

### 5. 验收矩阵

- WP-05A：单 hop、IANA→ARIN→AFRINIC 多 hop、`-Q`、首 hop DNS/连接失败、Phase C/非法/私网/安全短路、回访重复和截断 sentinel；验证 retries 不制造重复 hop。
- WP-05B：白名单逐键、大小写精确匹配、缺失/空值、续行、重复标题的 first/join、重复请求键、非法键/空参数/超限，以及 `-g`/grep 后字段消失。
- 组合：默认、`--no-body`、`--fold`、`--print-meta`、三者同时启用、显式/自动批量和 `--plain` fail-fast；逐项验证固定行排列与默认关闭逐字节兼容。
- BusyBox：链路行可用 `cut -f1` 或 `sed 's/^chain=//'` 消费；pick 行可按 TAB 切分并以每项第一个 `=` 分离键值。

### 6. WP-05A 聚焦验收（2026-08-24）

- `--print-chain` 已完成 CLI/config/render 贯通，并在查询结果元数据中以独立固定容量数组记录有序逻辑 hop；登记点位于同 hop 重试入口之前，DNS 候选、连接重试和应用层重试不会重复登记，也未复用 `visited[]`。
- 专项合同 smoke `12/12` PASS（`out/artifacts/print_chain_contract/20260824-155911`），覆盖单 hop、首 hop DNS 失败、Phase C/非法/私网/安全短路、fold 失败、chain/meta 顺序、显式/自动批量、重复选项与 plain fail-fast。
- 聚焦 `lto-auto` 构建 x86_64/win32/win64、SHA、三平台 smoke 与 IANA/ARIN/AFRINIC referral 全 PASS（`out/artifacts/20260824-155726`，294s）；win64 standalone selftest 中 `opts-print-chain-parser` 与 `opts-print-chain-plain-conflict` 均 PASS且无 selftest FAIL。
- 本节仅记录 WP-05A 聚焦切片证据；WP-05 整体最终验收见下一节。

### 7. WP-05B 聚焦验收（2026-08-24）

- `--pick`/`--pick-mode` 已完成 parser、配置传递、过滤后抽取、成功/失败/本地短路渲染及 pick -> chain -> meta 排列接线；默认关闭时不改变既有 stdout。
- 独立合同 smoke `12/12` PASS（`out/artifacts/pick_contract/20260824-164050`），覆盖固定白名单空值、记录排列、大小写去重保序、重复 `--pick` 最后一次生效、显式/自动批量，以及非法键、空项、mode-without-pick、非法 mode 和 plain 冲突。
- 最终 win64 standalone selftest 退出 0；`opts-pick-parser`、`opts-pick-mode-without-pick`、`pick-extract-first-join`、`pick-truncation-boundary` 全 PASS，覆盖精确标题匹配（`route` 不匹配 `route6`）、first/join、空首次值、续行归一化及逐字段 64 KiB 截断后继续输出后续键。
- 三目标 build/hash 与三起点 referral PASS（`out/artifacts/20260824-164010`，233s）；该轮 win64 Wine 网络 smoke 对 `8.8.8.8` 返回环境性非零 WARN，前一轮同一产品修复的三目标 smoke 全 PASS（`out/artifacts/20260824-163234`，254s）。
- WP-05 最终重建复核 PASS（`out/artifacts/20260824-170256`，351s）：Strict 版本九架构 `lto-auto` 构建无编译/LTO 告警，artifact 与两个发布目录的 SHA-256 均 `9/9` 一致；Linux/QEMU/native smoke=`18`、win32=`3`、win64=`3`，每条查询首尾对应且无告警；Golden PASS，IANA/ARIN/AFRINIC 三起点 referral 均收敛至 AFRINIC。发布产物已同步到仓库内与外部 lzispro 目录。

## WP-06：批量统计冻结契约

### 1. 作用域与输出位置

- `--stats` 是无参数、默认关闭的批量业务汇总选项；不新增短选项。它只在显式 `-B` 或 stdin 非 TTY 自动批量模式合法，单条模式在查询开始前按 usage-error 失败。
- 汇总必须直接消费每条查询的结构化结果，不得解析或截获 stdout，也不得复用 WP-02 的 `[WORKBUF-STATS]` 诊断协议。查询、DNS、重试、重定向、权威判定和逐条渲染均保持不变。
- 完整批次正常读到 EOF 后，在所有逐查询记录之后向 stdout 追加且只追加一行统计。stderr 继续只承载诊断/内部指标；`--stats` 不新增 stderr 成功提示。
- 收到 SIGINT、统计内存分配失败或触发统计资源上限时不输出部分统计行，沿用非零退出路径。普通单项查询失败仍按现有批量语义继续后续输入，批次读到 EOF 后输出包含该失败项的完整统计。

### 2. 固定行协议

字段对以 TAB 分隔，键与十进制无符号整数以 `=` 连接，字段顺序固定为：

```text
stats_total=<n>\tstats_success=<n>\tstats_error=<n>\tstats_error_lookup=<n>\tstats_error_rejected=<n>\tstats_error_internal=<n>\tstats_rir_iana=<n>\tstats_rir_arin=<n>\tstats_rir_ripe=<n>\tstats_rir_apnic=<n>\tstats_rir_lacnic=<n>\tstats_rir_afrinic=<n>\tstats_rir_verisign=<n>\tstats_rir_unknown=<n>\tstats_rir_error=<n>\tstats_rir_other=<n>\tstats_duration_p50_ms=<n>\tstats_duration_p95_ms=<n>
```

- 所有键始终输出，禁止省略零值、改变顺序、输出浮点数或千位分隔符。
- 空输入，以及只有空白行或首个非空字符为 `#` 的注释行时，输出全部计数和两个分位数均为 `0` 的统计行，退出码为 0。
- `stats_total = stats_success + stats_error`。
- `stats_error = stats_error_lookup + stats_error_rejected + stats_error_internal`。
- 所有 `stats_rir_*` 桶之和等于 `stats_total`；一个输入项恰好进入一个状态桶、一个错误分类（仅 error 状态）和一个 RIR 桶。

### 3. 计数与分类口径

- `stats_total` 统计批量规范化后实际接收的非空、非注释输入项；lookup 前本地短路仍计一项。被忽略的空行和注释行不计数。
- success/error 必须与 WP-04 `status` 语义一致：正常 lookup、权威 unknown、非法 IP/CIDR 和既有私网/Phase C 成功短路计 success；安全规则拒绝、lookup 失败和内部资源失败计 error。不得根据正文内容或批次最终退出码重新推断状态。
- `stats_error_lookup` 包含已进入查询执行路径后的 DNS、连接、超时、协议和重定向失败；`stats_error_rejected` 包含安全规则在 lookup 前拒绝的输入；`stats_error_internal` 仅包含客户端自身资源或状态构造失败。新增错误来源必须先明确归入其中一类，不得静默增加字段。
- RIR 按 WP-04 最终展示语义分类：规范 IANA、ARIN、RIPE、APNIC、LACNIC、AFRINIC、Verisign 主机分别进入对应桶；success 且无规范权威 RIR 进入 `stats_rir_unknown`；所有 error 状态进入 `stats_rir_error`；success 且存在非规范权威主机进入 `stats_rir_other`。匹配大小写不敏感，但不得用子串猜测 RIR。

### 4. 时延分位与资源上限

- 时延样本覆盖 `stats_total` 的全部输入项，取与 WP-04 `duration_ms` 相同的查询生命周期值；lookup 前本地短路样本为 `0`。error 样本不排除。
- p50/p95 使用精确 nearest-rank：将 `N` 个无符号毫秒样本升序排列，百分位 `p` 取 1-based 索引 `ceil(p * N)` 的样本；这里 `p50=0.50`、`p95=0.95`。`N=0` 时两个结果均为 `0`，不做插值或平均。
- 为保持精确分位且限制内存，首版每批最多统计 1,000,000 个有效输入项，时长样本使用每项 32-bit 无符号整数。遇到第 1,000,001 项时必须在执行该项查询前向 stderr 报错、停止读取并以非零退出，且不得输出部分统计行。
- 时长数组分配或扩容失败时同样 fail-close；已完成查询的既有逐条 stdout 不回滚，但不得输出看似完整的统计行。

### 5. 组合、记录边界与退出码

| 组合 | 规则 |
|---|---|
| `--stats` + `--no-body`/`--fold`/`-g`/`--grep*` | 合法；逐条业务记录照常输出，统计行最后输出 |
| `--stats` + `--pick`/`--print-chain`/`--print-meta` | 合法；每项仍按 pick -> chain -> meta 排列，统计行只在整个批次末尾输出 |
| `--stats` + `--plain` | 非法；plain 缺少稳定记录边界，查询开始前 fail-fast |
| `--stats` + 单条位置参数 | 非法；统计只定义批量生命周期 |

- `--stats` 不改变普通单项失败时批量继续执行和最终退出码的既有语义；只有既有终止条件或统计自身 fail-close 条件产生新的非零退出。
- 重复指定 `--stats` 幂等。未启用时默认 stdout、stderr、退出码和资源使用保持逐字节兼容。
- 固定总排列为：每项 title/grep -> pick -> fold/body -> chain -> meta 的既有记录，全部输入项结束后再输出 stats。统计行不属于任何单项记录。

### 6. 验收矩阵与命令用例

- parser：显式批量、自动批量、重复选项、单条冲突、plain 冲突，以及冲突必须在首个查询前失败。
- 计数：空批次、空白/注释、全成功、全失败、混合 success/error、本地短路和普通失败后继续；验证三组求和不变量。
- RIR：六个 RIR、Verisign、unknown、error、other 各桶及大小写匹配。
- 分位：`N=0/1/2/20` 固定样本，验证 nearest-rank、error/零时长纳入、无插值和输入顺序不影响结果。
- 资源：恰好 1,000,000 项可完成，第 1,000,001 项执行前 fail-close；模拟分配失败时无部分统计行。
- 组合：`--no-body`、`--fold`、pick/chain/meta、显式/自动批量和默认关闭兼容性；验证统计行恒为 stdout 最后一行。

```sh
# 显式批量：所有逐条记录之后追加一行 stats_*= 汇总
printf '8.8.8.8\n1.1.1.1\n' |
  ./whois-x86_64 -B --no-body --print-meta --stats

# stdin 非 TTY 自动批量；fold 行完成后输出批次统计
printf '8.8.8.8\n1.1.1.1\n' |
  ./whois-x86_64 -g 'NetName|Country' --fold --stats
```

### 7. 聚焦验收（2026-08-24）

- x86_64/win64 `lto-auto` 完整编译、链接与 artifact SHA-256 校验 PASS（`out/artifacts/20260824-175509`，127s）。
- win64 专项合同 smoke `12/12` PASS（`out/artifacts/stats_contract/20260824-175550`），覆盖空/注释批次、success/rejected/lookup error、RIR 与错误求和、观测/fold 排列、单条/plain 冲突、重复选项、默认关闭和 stdin 自动批量。
- 真实联网复核发现 pipeline 渲染接管并清空 `res.body` 后，stats 才读取该指针判定成功，导致已正常输出 `status=success` 的查询被误计入 `stats_error_lookup`；现于渲染前冻结 lookup 成功状态，渲染与聚合共同使用该状态。`8.8.8.8` + `1.1.1.1` 的 meta/fold 两种组合均回归为 `total=2 success=2 error=0`，ARIN/APNIC 各 1、`rir_error=0`。
- 修复后最终 Strict 九架构 `lto-auto` 构建、Local hash、Golden 与 IANA/ARIN/AFRINIC 三起点 referral 全 PASS且无编译/LTO 告警（`out/artifacts/20260824-185823`，316s）；可运行 Linux/QEMU 目标、win32、win64 smoke 分别完成 `18/3/3` 条查询，首尾一一对应且零告警；artifact、仓库发布目录与外部 lzispro 发布目录 SHA-256 均 `9/9` 一致。
- 最终同步 win64 制品专项合同再次 `12/12` PASS（`out/artifacts/stats_contract/20260824-190108`），standalone selftest 退出 0；`opts-stats-parser`、`opts-stats-plain-conflict` 与 `stats-aggregate-percentiles` 均唯一 PASS。

> 更新注记（2025-11-16）：本 RFC 聚焦“条件输出/筛选/折叠”等业务能力；3.2.2 的安全加固、3.2.7 的 CLI-only 节流迁移与 3.2.8 的三跳/重试指标增强均保持默认 stdout 契约不变，故仅在此补充里程碑：
> - 已交付：`-g` 标题前缀筛选（Step 1）、`--grep/--grep-cs` + 行/块模式（Step 1.5）、`--fold` 单行折叠（3.2.1）、CLI-only 节流与重试指标（3.2.7）、三跳模拟与黑洞自测/指标基线（3.2.8）。
> - 待办/评估：`--no-body`、链路/元信息打印、早停/最大字节优化、轻量字段抽取（Step 4）等仍按路线推进；安全与网络增强保持与本 RFC 正交。

目标（更新）：以“业务信息输出控制”为核心，优先支持按标题特征提取关键信息并折叠为单条记录，便于在 BusyBox 等精简环境中直接消费；在不改变默认输出的前提下，逐步补充过滤/统计等辅助能力。整体策略“小步快跑、可回退”。

## 背景与现状

- 现有特性：
  - 每条查询有固定首行 `=== Query: <query> via <起始服务器标识> @ <实际连通IP或unknown> ===` 和尾行 `=== Authoritative RIR: <权威RIR域名> @ <其IP或unknown> ===`；即便权威服务器以 IP 字面量呈现，尾行也会映射回对应的 RIR 域名。
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

## 历史路线（仅供追溯，不作为实现契约）

以下内容保留 2025 年设计演进记录，其中 `--fold kv`、`--title-grep`、早停和 `--max-bytes` 等描述已被上方 2026 重定版取代或暂缓。

### CLI 拟新增能力（Step-by-step，历史记录）

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
  - 保留：每条查询的第一行 `=== Query: <query> via <...> @ <...> ===` 与最后一行 `=== Authoritative RIR: <...> @ <...> ===` 默认保留，用于分段；
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
- rir：最终权威 RIR 域名（例如 `whois.apnic.net`，缺省折叠时会输出大写；若无法判定则为 `unknown`）
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
=== Query: 8.8.8.8 via whois.iana.org @ 192.0.32.59 ===
inetnum:        8.8.8.0 - 8.8.8.255
netname:        GOOGLE
country:        US
=== Authoritative RIR: whois.arin.net @ 199.43.135.53 ===
```
注：此处“title grep”基于 `-g` 的“大小写不敏感前缀匹配”，不是正则表达式。

1) 业务折叠（单行 kv，BusyBox 友好）：
```
$ ./whois-client 8.8.8.8 --pick netname,country,inetnum --fold kv --no-body
query=8.8.8.8	rir=WHOIS.ARIN.NET	status=success	duration_ms=132	inetnum=8.8.8.0 - 8.8.8.255	netname=GOOGLE	country=US
```

2) 过滤 + 抑制正文（保留原有首/尾行）：
```
$ cat ips.txt | ./whois-client -B --filter-rir apnic,ripe --no-body
=== Query: 1.1.1.1 via whois.iana.org @ 192.0.32.59 ===
=== Authoritative RIR: whois.apnic.net @ 203.119.102.24 ===
```

3) 多值处理：
```
$ ./whois-client 1.0.0.0/24 --pick route,origin --pick-mode join --fold kv --no-body
query=1.0.0.0/24	rir=WHOIS.APNIC.NET	status=success	duration_ms=95	route=1.0.0.0/24|1.0.0.0/16	origin=AS13335
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
