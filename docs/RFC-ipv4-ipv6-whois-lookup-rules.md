# IPv4/IPv6 地址 WHOIS 查询规则契约（草案 v1）

> 状态：Draft（建议作为后续实现与重构的主契约）
>  
> 适用范围：本仓库 whois 客户端的 IPv4/IPv6 地址查询流程（含 CIDR）
>  
> 参考资料：
> - `docs/IPv4_&_IPv6_address_whois_lookup_rules.txt`
> - `docs/ipv4-address-space.txt`（IANA，Last Updated: 2025-10-10）
> - `docs/ipv6-address-space.txt`（IANA，Last Updated: 2025-10-23）

## 1. 目标与原则

本契约用于将“特例驱动”收敛为“规则驱动”，避免对 `IANA-NETBLOCK-*` 做逐条硬编码。

核心原则：

1. **统一状态机优先于特例分支**：所有 hop 仅按“权威/非权威/失败/空响应”状态转移。
2. **证据分级**：将“非权威线索”与“权威确认”分离，避免误收敛。
3. **IANA 地址空间用于首跳优化，不用于最终裁决**：首跳可快速命中，最终权威仍以响应证据为准。
4. **可回放、可断言**：每条规则都应映射到可测试断言（golden/selftest/matrix）。

---

## 2. 术语

- **权威响应（Authoritative）**：当前 hop 未触发任何非权威标记，且响应可用于最终归属确认。
- **非权威响应（Non-Authoritative）**：命中非权威标记，需要继续跳转。
- **显式 referral**：正文中明确给出下一跳主机（如 `refer:` / `ReferralServer:`）。
- **轮询跳转**：按固定 RIR 顺序选择下一个未访问 RIR：`APNIC -> ARIN -> RIPE -> AFRINIC -> LACNIC`。
- **基准查询项（Baseline Query）**：CIDR 去掩码后的 IP 字面量。
- **ERX/IANA 标记**：`ERX-NETBLOCK`、`IANA-NETBLOCK-*` 等线索，表示“可能非最终权威，需要继续求证”。

---

## 3. 响应分类（必须按优先级执行）

同一 hop 内，判定优先级必须固定：

1. **失败类（Failure）**：连接失败、超时、temporary denied、rate-limit、permanently denied。
2. **非权威类（Non-Authoritative）**：命中非权威标记或可解析 referral。
3. **语义空响应类（Semantic Empty）**：仅 banner/注释或正文缺失，且未命中前两类。
4. **权威类（Authoritative）**：以上均不命中。

说明：

- “非权威”优先级必须高于“空响应”，避免将 `Unallocated...` 等误判为空响应。
- 失败类若重试后仍失败，当前 hop 不应污染长期 visited 判定（防止错误收敛）。

---

## 4. RIR 识别与标记规则

### 4.1 当前 RIR 识别（header/body 证据）

沿用现有实现约定（IANA/APNIC/ARIN/RIPE/AFRINIC/LACNIC 及 LACNIC 内部重定向特征），并要求：

- 识别逻辑应容忍首行空行、缩进、前导空格。
- LACNIC 内部重定向场景必须保留“原始起点 + 内部目标”两层语义，供后续 visited 策略使用。

### 4.2 非权威标记（建议收敛为统一表驱动）

至少应覆盖：

- IANA: `refer:`
- APNIC: `ERX-NETBLOCK` / `IANA-NETBLOCK-*` / `inet6num: ::/0`
- ARIN: `ReferralServer:` / `No match found for ...`
- RIPE: `NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK` / `inet6num: ::/0`
- AFRINIC: `inetnum 0.0.0.0 - 255.255.255.255` / `inet6num 0::/0`
- LACNIC: `Unallocated and unassigned in LACNIC block`

补充约束：

- `Query terms are ambiguous.`（LACNIC 内部到 ARIN 的常见产物）在无有效 referral 时按非权威处理。
- `ERX/IANA` 仅是“继续求证信号”，不是直接“最终权威”信号。

---

## 5. 跳转与收敛规则

本章定义与查询类型无关的“总则”；非 CIDR / CIDR 的具体执行细则分别见第 6.1 / 6.2。

### 5.1 下一跳总则

1. 优先跟随“未访问的显式 referral”。
2. referral 缺失或 referral 已访问时，按轮询顺序选择未访问 RIR：`APNIC -> ARIN -> RIPE -> AFRINIC -> LACNIC`。
3. 当轮询序列无可用目标时，停止跳转并进入收敛判定。

### 5.2 visited 与异常总则

- 仅将“成功完成并产生可判定响应”的 hop 记入稳定 visited。
- 对失败类（Failure）hop（限速/拒绝/超时）不做强持久锁死，允许后续重访。
- 对 LACNIC 内部转 ARIN 且仅出现 ambiguous、无有效 referral 的场景，不得将 ARIN 视为稳定完成访问。

### 5.3 终止与输出总则

- 命中 `max-hops/max-redirects` 时必须立即停止。
- 若停止时仍未形成有效权威结论：
  - 常规未收敛输出 `unknown`；
  - 失败类（Failure）主导且未收敛时按现有失败语义输出 `error`。
- 第 6 章定义的非 CIDR/CIDR 收敛细则不得与本节总则冲突。

---

## 6. CIDR 与非 CIDR 统一规则

### 6.1 非 CIDR

非 CIDR 查询必须采用“分类驱动 + 跳转收敛”的统一流程，不得引入按单网段/单样例定制的特判路径。

处理步骤（MUST）：

1. **主循环执行**
   - 每个 hop 均按第 3 章固定优先级分类：`失败类（Failure） > 非权威类（Non-Authoritative） > 语义空响应类（Semantic Empty） > 权威类（Authoritative）`。
   - 在流程中持续维护 visited 集合、首个 `ERX/IANA` 标记上下文与失败上下文。

2. **非权威分流**
   - 命中非权威类（Non-Authoritative）时，优先跟随“未访问的显式 referral”。
   - 无 referral 或 referral 已访问时，按轮询序列选择首个未访问 RIR（见第 5.1）。
   - 命中 `ERX/IANA` 标记时必须记录“首个标记 RIR/host/ip/hop”，供末端回落使用。

3. **权威收敛**
   - 命中权威类（Authoritative）且不存在更高优先级冲突证据时，立即收敛结束。
   - 对非 CIDR，不要求基准回查，但要求当前 hop 结论可解释（来源于非冲突响应证据）。

收敛判定（MUST）：

- **优先收敛到明确权威**：任一 hop 形成稳定权威类（Authoritative）结论即结束。
- **全 RIR 遍历后仍无权威**：
  - 若出现过 `ERX/IANA` 标记，回落“首个 `ERX/IANA` 标记 RIR”；
  - 若未出现 `ERX/IANA` 标记，回落 `unknown`。
- **失败主导且未收敛**：按现有失败语义输出 `error`（与第 5.3 和 6.2 保持一致）。

异常与边界（SHOULD）：

- rate-limit/temporary denied/permanently denied/timeout 不应直接当作“权威否定证据”；应继续可行跳转。
- 失败 hop 不应强持久污染 visited，避免把“临时失败”误当作“已完成访问”。
- LACNIC 内部到 ARIN 且出现 ambiguous、无有效 referral 时，继续按非权威分流，不得提前收敛。

最小伪流程（Pseudo flow，非 CIDR）：

```text
state:
  visited = {}
  first_erx_marker = null
  failure_seen = false
  current = start_rir

loop while hop < max_hops:
  resp = query(current, original_query)
  cls  = classify(resp)  // Failure > Non-Authoritative > Semantic Empty > Authoritative

  if cls == Failure:
    failure_seen = true
    next = choose_next_by_ref_or_cycle(resp.referral, visited)
    if next == null: break
    current = next
    continue

  mark_visited_if_stable(resp, current, visited)

  if cls == Non-Authoritative:
    if has_erx_marker(resp) and first_erx_marker == null:
      first_erx_marker = current
    next = choose_next_by_ref_or_cycle(resp.referral, visited)
    if next == null: break
    current = next
    continue

  if cls == Authoritative:
    return authoritative(current)

  // Semantic Empty
  next = choose_next_by_ref_or_cycle(resp.referral, visited)
  if next == null: break
  current = next

if first_erx_marker != null: return fallback(first_erx_marker)
if failure_seen: return error
return unknown
```

### 6.2 CIDR

CIDR 必须采用“原始查询 + 基准回查 + 一致性验证”的闭环流程，禁止仅凭单跳或单标记直接定权威。

处理步骤（MUST）：

1. **原始 CIDR 主流程**
   - 用原始 CIDR 进入常规 hop 循环（遵循第 3、5 章）。
   - 若任一 hop 命中 `ERX/IANA` 标记，记录首个标记上下文（RIR/host/ip/hop）。
   - 若原始 CIDR 在未出现 `ERX/IANA` 标记时直接命中可确认权威，则应立即确定该 RIR 为权威并结束全部查询过程。

2. **首标记 RIR 内基准回查（仅一次）**
   - 基准查询项为 CIDR 去掩码后的 IP 字面量。
   - 基准回查只在首次出现 `ERX/IANA` 标记的 RIR 内执行一次，不得在其它 RIR 重复此步骤。
   - 若该次基准回查命中可确认权威，则立即确定该 RIR 为权威并结束全部查询。

3. **后续跳基准查询（仅在第 2 步失败时）**
   - 仅当第 2 步未命中时，才将基准查询项带到“首标记 RIR 之后的后续跳 RIR”继续查询。
   - 在后续跳中一旦命中可确认权威，进入第 4 步一致性验证。
   - 若后续所有可达 RIR 均未命中，则按收敛规则回落。

4. **原始查询项一致性验证（仅一次）**
   - 原始查询项一致性验证只允许执行一次。
   - 该验证不会发生在首次出现 `ERX/IANA` 标记的 RIR 内，只会发生在“第 3 步命中的后续跳 RIR”内。
   - 若一致性验证成功，则确定该后续跳 RIR 为权威并结束全部查询。
   - 若一致性验证失败，则确定权威 `unknown` 并结束全部查询。

正文输出约束（MUST）：

- CIDR 闭环中的“基准回查”（第 2 步）不输出响应内容正文。
- CIDR 闭环中的“后续跳基准查询”（第 3 步）即使命中，也不直接输出该次响应内容正文。
- CIDR 场景最终正文来源遵循“原始查询项一致性验证优先”原则：
  - 若进入第 4 步并完成验证，则正文输出使用第 4 步（原始查询项一致性验证）的响应内容。
  - 若在第 2 步命中并提前终止，或第 3 步后未进入/未通过第 4 步，则按既有规则仅输出结构化行（标题首行/重定向提示行/权威尾行），不输出基准回查正文。
- 非 CIDR 查询不受本约束影响，正文输出仍按现有规则与开关控制。

收敛判定（MUST）：

- **出现 `ERX/IANA` 标记时**：
  - 第 2 步命中：权威 = 首标记 RIR，结束。
  - 第 2 步未命中且第 3+4 步成功：权威 = 第 3 步命中的后续跳 RIR，结束。
  - 第 2 步未命中且第 3 步命中但第 4 步失败：权威 = `unknown`，结束。
  - 第 2 步未命中且第 3 步在后续全部跳均未命中：权威 = 首标记 RIR，结束。

- **全流程未出现 `ERX/IANA` 标记时**：
  - 若原始查询项直接命中某 RIR：权威 = 该 RIR，立即结束。
  - 若原始查询项在全部 RIR 均未命中：最后一跳结束时权威 = `unknown`。

执行边界（MUST）：

- “首标记 RIR 内基准回查”最多一次。
- “后续跳命中后的原始查询项一致性验证”最多一次。
- 任一分支命中上述终态后，必须立即结束全部查询过程。

异常与边界（SHOULD）：

- 发生 rate-limit/temporary denied/permanently denied 时，不应改变上述“只一次”的执行约束与终态判定顺序。
- LACNIC 内部到 ARIN 的 ambiguous 场景仍按“非权威”处理，不得破坏 CIDR 闭环顺序。
- 后续跳基准查询应只覆盖“首标记 RIR 之后”的可达 RIR，避免回到首标记 RIR重复求证。

最小伪流程（Pseudo flow，CIDR）：

```text
input:
  original = cidr_query
  baseline = strip_mask(cidr_query)

state:
  first_erx_marker = null
  baseline_recheck_done = false
  consistency_check_done = false

// Phase A: original CIDR flow to locate first ERX/IANA marker
for hop in original_flow:
  resp = query(next_rir, original)
  cls  = classify(resp)

  if cls == Authoritative and no_conflict(resp):
    return authoritative(next_rir)

  if cls == Non-Authoritative and has_erx_marker(resp):
    first_erx_marker = next_rir
    break

// no ERX/IANA marker and no authority hit in all RIR
if first_erx_marker == null:
  return unknown

// Phase B: one-time baseline recheck inside first marker RIR
if !baseline_recheck_done:
  baseline_recheck_done = true
  b1 = query(first_erx_marker, baseline)
  if classify(b1) == Authoritative and no_conflict(b1):
    return authoritative(first_erx_marker)

// Phase C: baseline query in subsequent RIR hops only
for rir in subsequent_rirs_after(first_erx_marker):
  b2 = query(rir, baseline)
  if classify(b2) == Authoritative and no_conflict(b2):
    // one-time original-query consistency check in this subsequent RIR
    if !consistency_check_done:
      consistency_check_done = true
      v = query(rir, original)
      if classify(v) == Authoritative and consistent(v, rir):
        return authoritative(rir)
      else:
        return unknown

// baseline miss on all subsequent RIR
return authoritative(first_erx_marker)
```

判定示例（用于测试对照）：

1. **原始 CIDR 未遇 `ERX/IANA` 标记并直接命中权威**
   - 路径：原始 CIDR 在某 RIR 直接命中权威，且此前未出现 `ERX/IANA` 标记。
   - 结果：权威 = 该 RIR；立即结束（不进入基准回查与一致性验证）。

2. **首标记 RIR 内基准回查命中**
   - 路径：原始 CIDR 命中首个 `ERX/IANA` 标记 -> 在该 RIR 内执行一次基准回查并命中。
   - 结果：权威 = 首标记 RIR；立即结束（不进入后续跳、不做一致性验证）。

3. **首标记 RIR 基准回查未命中，后续跳命中且一致性验证成功**
   - 路径：首标记 RIR 基准回查失败 -> 基准查询项在后续跳某 RIR 命中 -> 对该 RIR 做一次原始查询项一致性验证并成功。
   - 结果：权威 = 后续跳命中 RIR；立即结束。

4. **首标记 RIR 基准回查未命中，后续跳命中但一致性验证失败**
   - 路径：首标记 RIR 基准回查失败 -> 基准查询项在后续跳某 RIR 命中 -> 原始查询项一致性验证失败。
   - 结果：权威 = `unknown`；立即结束。

5. **首标记 RIR 基准回查未命中，后续跳全部未命中**
   - 路径：首标记 RIR 基准回查失败 -> 基准查询项在后续所有可达 RIR 均未命中。
   - 结果：权威 = 首标记 RIR；立即结束。

治理建议：

- 建议逐步淘汰 `--no-cidr-erx-recheck`（先标记 deprecated，再在下个主版本移除），避免“一条开关绕过核心收敛机制”。

---

## 7. IANA 地址空间文件的使用边界

### 7.1 可做（SHOULD）

- 用于**首跳候选优化**：
  - IPv4：按首字节 `/8` 前缀映射候选 RIR。
  - IPv6：按全局单播可分配区段（重点 `2000::/3`）决定候选优先级。
- 用于提示“保留/私有/特殊用途地址”的预判，减少无意义跳转。

### 7.2 不可做（MUST NOT）

- 不得将地址空间分配表作为“最终权威裁决”的唯一依据。
- 不得据此新增 `IANA-NETBLOCK-8`、`IANA-NETBLOCK-45` 之类硬编码分支。

### 7.3 数据更新建议

- 建议在仓库建立“快照更新时间 + 差异审查”流程：
  - 每次升级 `ipv4-address-space.txt` / `ipv6-address-space.txt` 时记录日期与变更摘要。
  - 回归矩阵至少覆盖：`8.8.0.0/16`、`45.113.52.0`、`45.71.8.0/22`、`1.1.1.1`、典型 IPv6 样例。

---

## 8. 输出与可观测性契约（保持不变）

保持现有 stdout/stderr 分工：

- stdout：业务结果（头行/正文/尾行/fold）。
- stderr：诊断与指标（`[DNS-*]`、`[RETRY-*]`、`[EMPTY-RESP]` 等）。

保持现有格式约束：

- 头行：`=== Query: <item> === via <host-or-alias> @ <ip|unknown>`
- 尾行：`=== Authoritative RIR: <rir-host> @ <ip|unknown|error> ===`
- fold：`<query> <UPPER_VALUE_...> <RIR>`

正文显示开关约束：

- `--show-non-auth-body` / `--show-post-marker-body` 仅控制允许显示的非权威或标记后正文范围。
- 对 CIDR 闭环而言，上述开关不改变“基准回查正文不输出”的规则；后续跳基准命中后，正文以“原始查询项一致性验证”响应为准。
- 标题首行、重定向提示行、权威尾行始终按既有契约输出，不受该 CIDR 正文来源约束影响。

---

## 9. 重构实施建议（低风险落地）

建议分阶段推进，避免一次性重构震荡：

1. **阶段 A（规则抽取）**：把“响应分类 + 非权威标记”抽为表驱动模块，不改行为。
2. **阶段 B（状态机收敛）**：统一 hop 状态转移和 next-hop 选择，减少互相覆盖的条件分支。
3. **阶段 C（开关收敛）**：将 `--no-cidr-erx-recheck` 标记 deprecated，并在完成回归后移除。
4. **阶段 D（IANA 优化接入）**：仅接入首跳优化，不触碰最终裁决语义。

每阶段闸门建议：

- `Remote: Build (Strict Version)` 通过。
- Redirect Matrix（含 10x6/参数化）`authMismatchFiles=0`。
- Selftest Golden Suite 通过。

---

## 10. 规则到代码实现映射（建议）

本节给出“规则章节 -> 现有代码落点”的建议映射，用于后续按模块分步改造。

| 规则域 | 主要文件（现状） | 建议动作 | 验证要点 |
| --- | --- | --- | --- |
| 第 3 章 响应分类优先级 | `src/core/lookup_exec_redirect.c`、`src/core/lookup_exec_empty.c`、`src/core/lookup_text.c` | 抽取统一分类入口（先判失败，再非权威，再语义空响应） | LACNIC `Unallocated...` 不再误入空响应路径 |
| 第 4 章 非权威标记 | `src/core/lookup_text.c`、`src/core/redirect.c` | 将 marker 检测表驱动化，减少散落 if-else | ERX/IANA/Referral 识别在各入口一致 |
| 第 5 章 下一跳与 visited 总则 | `src/core/lookup_exec_loop.c`、`src/core/lookup_exec_redirect.c` | 统一 `referral 优先 + 轮询兜底 + visited 约束` | 已访问 referral 不回访，轮询顺序稳定 |
| 第 6.1 非 CIDR 流程 | `src/core/lookup_exec_loop.c`、`src/core/lookup_exec_tail.c` | 以状态机替代分散分支，保留现有输出契约 | authority 收敛与 `unknown/error` 边界稳定 |
| 第 6.2 CIDR 闭环 | `src/core/lookup_exec_loop.c`、`src/core/lookup_policy.c`、`src/core/opts.c` | 固化“原始查询 + 单次首标记RIR基准回查 + 后续跳基准查询 + 单次一致性验证”流程 | `ERX/IANA` 场景下不再依赖特例硬编码；无 `ERX/IANA` 标记且原始 CIDR 直接命中权威时应立即停止 |
| 第 7 章 IANA 地址空间优化 | `src/core/server.c`、`src/core/dns.c`（必要时新增轻量映射模块） | 仅做首跳候选优化，不介入最终权威裁决 | `8.8.0.0/16` 等样例减少无效跳转且结论不漂移 |
| 第 8 章 输出契约 | `src/cond/title.c`、`src/cond/fold.c`、`src/core/pipeline.c` | 规则重构时锁定 stdout/stderr 边界不变 | 头行/尾行/fold 与现黄金格式一致 |
| 开关治理（`--no-cidr-erx-recheck`） | `src/core/opts.c`、`src/core/meta.c`、文档 | 先 deprecated，再移除；保留过渡期提示 | 回归通过后再执行破坏性下线 |

推荐落地顺序（与第 9 章阶段对应）：

1. 先做“分类入口 + marker 表驱动”（低行为风险）。
2. 再做“非 CIDR/CIDR 状态机收敛”（中风险，需矩阵门禁）。
3. 最后做“开关治理与 IANA 首跳优化”（策略层收口）。

### 10.1 测试用例命名建议（CIDR）

建议统一命名模板：

`cidr_<marker_state>_<baseline_path>_<consistency_or_stop>_<expected_authority>`

字段说明：

- `marker_state`：`with_marker` / `no_marker`
- `baseline_path`：`first_marker_hit` / `first_marker_miss_next_hit` / `first_marker_miss_all_miss` / `na`
- `consistency_or_stop`：`consistency_ok` / `consistency_fail` / `direct_stop`
- `expected_authority`：`first_marker_rir` / `next_hit_rir` / `unknown`

推荐最小样例集（与 6.2 收敛分支一一对应）：

- `cidr_no_marker_na_direct_stop_next_hit_rir`
  - 语义：无 `ERX/IANA` 标记，原始 CIDR 直接命中权威，立即停止。
- `cidr_with_marker_first_marker_hit_direct_stop_first_marker_rir`
  - 语义：首标记 RIR 内基准回查命中，立即停止。
- `cidr_with_marker_first_marker_miss_next_hit_consistency_ok_next_hit_rir`
  - 语义：首标记未命中，后续跳基准命中且一致性验证成功。
- `cidr_with_marker_first_marker_miss_next_hit_consistency_fail_unknown`
  - 语义：首标记未命中，后续跳基准命中但一致性验证失败。
- `cidr_with_marker_first_marker_miss_all_miss_direct_stop_first_marker_rir`
  - 语义：首标记未命中，后续跳基准全未命中，回落首标记 RIR。

### 10.2 矩阵输入草案（CIDR）

下表为“字段模板 + 样例值”草案，供 `redirect matrix` / 自测脚本落地时使用。示例查询项可在接入阶段按网络可达性替换，但分支语义与期望不变。

对应草案文件：`testdata/cidr_matrix_cases_draft.tsv`

| case_id | query | start_rir | expect_authority | expect_stop_reason | notes |
| --- | --- | --- | --- | --- | --- |
| `cidr_no_marker_na_direct_stop_next_hit_rir` | `203.0.113.0/24` | `arin` | `next_hit_rir` | `direct-authoritative-no-marker` | 无 `ERX/IANA` 标记，原始 CIDR 直接命中权威后立即停止 |
| `cidr_with_marker_first_marker_hit_direct_stop_first_marker_rir` | `8.8.0.0/16` | `apnic` | `first_marker_rir` | `baseline-hit-in-first-marker-rir` | 首标记 RIR 内基准回查一次命中即停止 |
| `cidr_with_marker_first_marker_miss_next_hit_consistency_ok_next_hit_rir` | `45.71.8.0/22` | `lacnic` | `next_hit_rir` | `consistency-validated` | 首标记未命中，后续跳基准命中且一次一致性验证成功 |
| `cidr_with_marker_first_marker_miss_next_hit_consistency_fail_unknown` | `1.1.1.0/24` | `apnic` | `unknown` | `consistency-check-failed` | 首标记未命中，后续跳命中但一次一致性验证失败 |
| `cidr_with_marker_first_marker_miss_all_miss_direct_stop_first_marker_rir` | `47.96.0.0/10` | `apnic` | `first_marker_rir` | `baseline-miss-on-all-subsequent-rirs` | 首标记未命中，后续跳基准全未命中，回落首标记 RIR |

字段约定建议：

- `expect_authority` 建议使用归一化值：`first_marker_rir` / `next_hit_rir` / `unknown`。
- `expect_host` 用于脚本可执行断言（例如 `whois.arin.net` / `unknown` / `invalid`）；未填写时可作为语义草案行保留。
- `expect_stop_reason` 建议脚本断言为离散枚举，避免自由文本导致误判。
- `start_rir` 建议覆盖至少 `apnic`、`lacnic`、`arin` 三类起点，验证跳转稳定性。
- 对公网环境易波动样例（限速/拒绝）建议在矩阵里增加 `allow_retry_window` 标记，避免环境噪声污染规则断言。

脚本接入提示：

- `tools/test/redirect_matrix_test.ps1` 已支持可选参数 `-CasesFile <tsv/csv>`。
- 当样例仅含语义期望（如 `first_marker_rir`/`next_hit_rir`）且未提供 `expect_host` 时，脚本会告警并跳过该行，不影响其他可执行用例。

---

## 11. 对原始 TXT 规则的审校意见（摘要）

你这版规则的方向非常对，尤其是“闭环收敛”和“反特例化”的思想；主要建议优化点如下：

1. **将“识别条件”和“流程条件”拆开写**：避免同一条规则既定义标记又定义跳转。
2. **CIDR 场景不要列举路径组合**：改成统一状态机，减少组合爆炸。
3. **失败类（Failure）与非权威类（Non-Authoritative）分开建模**：两者对 visited 和回访策略不同。
4. **IANA 地址空间定位为优化器而非裁决器**：既提速又不牺牲正确性。
5. **开关治理**：对会破坏主收敛逻辑的开关采用“先弃用、后移除”策略。

---

## 12. 后续维护约定

- 本文档作为后续开发评审的规则契约入口。
- 任何影响权威判定、跳转顺序、CIDR 回查语义的变更，必须先更新本文档再改代码。
- 建议在 `docs/RFC-whois-client-split.md` 中持续记录与本契约相关的实现进度与回归日志路径。
