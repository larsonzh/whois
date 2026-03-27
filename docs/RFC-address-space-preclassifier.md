# RFC：Address-Space 前置分类器（IPv4/IPv6）

状态：草案（仅讨论，不涉及代码变更）

## 1. 背景

当前实现在某些保留/特殊用途地址上，可能出现不合理收敛（例如 `255.0.0.0`），原因是运行时主要依赖各跳 WHOIS 正文中的 marker 文本来决定是否继续跳转。

典型问题链路：
- 输入地址本质上属于全局保留/特殊用途；
- 查询仍跨多个 RIR 轮询；
- 最后一跳因缺少已覆盖的“非权威触发词”，被误当作权威收口。

## 2. 目标

1. 引入基于官方地址空间注册表的**前置分类器（pre-classifier）**，优化首跳与收敛决策。
2. 对未显式指定 `-h` 的查询，不再默认 `IANA` 首跳，改为“分类器优先”策略。
3. 将 IPv6 地址空间文件纳入同一设计范围。
4. 在未明确宣布前，不破坏既有输出契约。

## 3. 非目标

- 不在本 RFC 中完全替代现有 WHOIS 正文规则。
- 不在本 RFC 中定义最终 CLI 文案细节。
- 不在运行时动态联网抓取 IANA 数据。

## 4. 数据来源与形态

- IPv4：`docs/ipv4-address-space.txt`
- IPv6：`docs/ipv6-address-space.txt`

建议运行模型：
- 文档文件作为“人类可读源快照”；
- 构建期（或预处理脚本）生成紧凑运行时表；
- 运行时不直接解析完整 txt 文本，降低复杂度与性能波动。

## 5. 前置分类器输出模型

每个输入 IP 统一输出：

- `ip_version`: `v4|v6`
- `class`: `allocated|legacy|reserved|special|unallocated|unknown`
- `rir_hint`: `apnic|arin|ripe|afrinic|lacnic|none`
- `reason_code`: 稳定符号码（用于诊断/观测）
- `confidence`: `high|medium|low`

示例 reason_code：
- `V4_FUTURE_USE_240_4`
- `V4_LIMITED_BROADCAST_255_255_255_255`
- `V4_PRIVATE_10_8`
- `V6_UNIQUE_LOCAL_FC00_7`
- `V6_LINK_LOCAL_FE80_10`
- `V6_GLOBAL_UNICAST_2000_3`

## 6. 决策策略（建议）

### 6.1 显式指定 `-h` 的查询

- 默认保持兼容：沿用现有行为。
- 前置分类器可运行并输出诊断，但不强制覆盖首跳（可通过后续开关讨论是否允许覆盖）。

### 6.2 未指定 `-h` 的查询（新默认）

将“默认 IANA 首跳”替换为“分类器优先”：

1. `class in {reserved, special}` 且 `rir_hint=none`
   - 直接收敛到 `unknown`（或未来引入 `reserved` 专用收敛语义）。
   - 默认跳过完整 RIR 轮询。

2. `class in {allocated, legacy}` 且 `rir_hint` 明确
   - 首跳直接使用该 RIR。
   - 保留现有 referral/redirect 逻辑做后续校验与纠偏。

3. `class=unknown` 或 `confidence` 较低
   - 回退到现有启动策略（兼容路径）。

### 6.3 运行时正文规则仍保留纠偏优先级

- failure 类信号（拒绝/限流/超时）仍按现有失败语义执行；
- strong non-authoritative marker 仍可驱动继续跳转；
- 前置分类器定位是“首跳与早收敛优化器”，不是硬替代。

## 7. IPv4 设计要点

依据 `IPv4 Address Space`：
- 大量前缀属于 `RESERVED` 或特殊用途，不应收敛为某个 RIR 权威。
- 对 `255.0.0.0` 这类地址，目标应是 `unknown`（或未来 `reserved`），而非“最后一跳 RIR”。

建议映射：
- `RESERVED` -> `class=reserved`, `rir_hint=none`
- `ALLOCATED|LEGACY` 且表中存在 RIR 归属 -> `class=allocated|legacy`, `rir_hint=<rir>`

## 8. IPv6 设计要点

依据 `IPv6 Address Space`：
- `2000::/3` 为当前 global unicast 主体范围；
- 大量区间属于 `Reserved by IETF` 或特殊作用域（`fc00::/7`、`fe80::/10`、`ff00::/8`）。

建议使用方式：
- `2000::/3` -> `class=allocated`（或 `global-unicast` 子类），走正常 WHOIS 流程；
- `fc00::/7`、`fe80::/10`、`ff00::/8` 及其他 reserved -> `class=special|reserved`, `rir_hint=none`；未指定 `-h` 时优先早收敛 `unknown`。

## 9. 观测与诊断

新增 stderr 标签（仅在 `--debug` 或 `--retry-metrics` 开启）：

- `[PRECLASS] ip=<q> ver=v4 class=reserved rir=none reason=V4_FUTURE_USE_240_4 confidence=high`
- `[PRECLASS-DECISION] start=unknown action=short-circuit-unknown`
- `[PRECLASS-DECISION] start=whois.arin.net action=classifier-rir-hint`

首轮不改 stdout 契约。

## 10. 分阶段落地

### Phase A（影子模式）
- 仅接入分类器与诊断标签，不改变路由/收敛行为。

### Phase B（默认首跳迁移）
- 对未指定 `-h` 的查询启用“分类器优先首跳”。
- 对未知/低置信场景保留旧策略回退。

### Phase C（reserved 早收敛）
- 对高置信保留/特殊用途地址启用早收敛 `unknown`。
- 保留临时禁用开关，便于应急回退。

## 11. 兼容与风险控制

- 增加临时特性开关（命名待定）：`--disable-address-preclass`。
- 默认不改变显式 `-h` 行为。
- 在矩阵中记录“启用前置分类后 hop 降幅与收敛差异”，通过观测后再放量。

## 12. 测试用例增量

必须新增确定性样例：

IPv4：
- `255.0.0.0` -> 期望非 RIR 收敛（`unknown`）
- `10.0.0.1` -> 私网/特殊用途处理
- `8.8.8.8` -> 正常 allocated 路径（保持既有正确收敛）

IPv6：
- `fc00::1` -> ULA 特殊用途处理
- `fe80::1` -> link-local 处理
- `2001:4860:4860::8888` -> 正常 global-unicast 路径

## 13. 待定问题

1. 保留/特殊用途的尾行是否持续使用 `unknown`，还是引入新状态（如 `reserved`）？
2. 显式 `-h` 是否永远旁路短路逻辑，还是允许用额外开关强制启用？
3. 地址空间快照的更新频率与发布流程如何绑定？

## 14. 建议结论

建议先执行 Phase A（影子模式），观察一段稳定窗口后再进入 Phase B。

理由：
- 风险低，不破坏现有契约；
- 可先验证分类器与真实 WHOIS 行为的一致性；
- 能以可控方式修复 `255.0.0.0` 这类误收敛问题。

## 15. 与 Step 4 的实施映射（建议）

为保持与当前主线一致，建议把本 RFC 映射为 Step 4 后续子阶段：

- **Step 4.5（观测接入）**
  - 仅接入 `[PRECLASS]` / `[PRECLASS-DECISION]` 诊断；
  - 不改查询路径和裁决；
  - 门禁目标：与当前 Step 4 一致（Strict + CIDR Bundle + Redirect Matrix）。

- **Step 4.6（默认首跳迁移）**
  - 仅在未指定 `-h` 时启用分类器优先首跳；
  - 显式 `-h` 保持兼容；
  - 保留全量回退开关。

- **Step 4.7（reserved 早收敛）**
  - 对高置信 reserved/special 前缀启用 `unknown` 早收敛；
  - 仅在连续观测稳定后打开。

该映射保持“先观测、后切流、再收敛”的节奏，符合当前 Step 4 的风险控制原则。

## 16. Step 4.7 候选白名单（Assessment Mode）

用于 pre-release 的“仅评估模式”白名单如下（不改变默认路由，仅记录差距）：

- `255.0.0.0`
  - 当前基线：`whois.iana.org`
  - Step 4.7 目标：`unknown`
  - 备注：reserved/special 早收敛的首要候选
- `10.0.0.1`
  - 当前基线：`unknown`
  - Step 4.7 目标：`unknown`
- `fc00::1`
  - 当前基线：`unknown`
  - Step 4.7 目标：`unknown`
- `fe80::1`
  - 当前基线：`unknown`
  - Step 4.7 目标：`unknown`
- `8.8.8.8`（allocated 基线锚点）
  - 当前基线：`whois.arin.net`
  - Step 4.7 目标：`whois.arin.net`

执行命令（评估模式）：

`powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\step47_readiness_matrix.ps1 -BinaryPath .\release\lzispro\whois\whois-win64.exe`

当前阶段门禁策略：

- 必须通过：`current_mismatch=0`、`decision_mismatch=0`
- 非阻断信号：`target_gap`（用于 Step 4.7 放量设计）

## 17. Step 4.7 放量设计 v1（草案）

### 17.1 启用条件（仅小流量试验）

- 特性范围：仅对白名单中高置信的 `reserved/special` 前缀应用 early-unknown。
- 默认状态：关闭（assessment mode 仍为默认）。
- 兼容约束：显式 `-h` 必须旁路 Step 4.7 逻辑。
- 安全约束：若分类结果为 `unknown/low-confidence`，回退到现有 Step 4.6 路径。
- 试验范围控制：新增 `--step47-trial-scope minimal|reserved|all`（默认 `minimal`）。

### 17.2 回退优先级

- 优先级 1（全局）：`--disable-address-preclass` 一键关闭 Step 4.5/4.6/4.7 全部行为。
- 优先级 2（模式）：当放量门禁未全绿时，保持 Step 4.7 在 assessment mode（不改路由/终态）。
- 优先级 3（运行时）：出现异常 mismatch 峰值时，无条件回退到 Step 4.6 语义，不改变输出契约。

### 17.3 语义不变约束（必须保持）

- failure debt 契约不变（包含最终 `error/unknown` 优先级与清偿规则）。
- 处理顺序不变：`title -> grep -> fold`。
- stdout/stderr 契约不变（业务输出在 stdout，诊断/指标在 stderr）。
- 显式 `-h` 行为不变。

### 17.4 验收断言（pre-release）

- Gate A（稳定性）：`step47_readiness_matrix.ps1` 中 `current_mismatch=0` 且 `decision_mismatch=0`。
- Gate B（回归）：Strict + CIDR Bundle + Redirect Matrix 10x6 在稳态参数下全绿。
- Gate C（兼容）：显式 `-h` 六组兼容专项持续 6/6 通过。
- 观测信号：设计阶段允许 `target_gap>0`，只追踪不阻断。

### 17.5 试验退出条件

- 仅当 pre-release 连续两轮在 Gate A/B/C 全绿时，才允许进入下一阶段。
- 放量后至少一个完整 release 周期内，在 release notes 中保留回退命令与检查清单。

## 18. Step 4.7 A/B 对照与范围验证（2026-03-16）

- 对照脚本：`tools/test/step47_ab_compare.ps1`
- 查询集：`255.0.0.0`、`10.0.0.1`、`fc00::1`、`fe80::1`、`8.8.8.8`
- 结果：
  - `minimal`：`eligible=1 auth_changed=0 route_changed=0`
  - `reserved`：`eligible=4 auth_changed=0 route_changed=0`
  - `all`：`eligible=5 auth_changed=0 route_changed=0`
- 结论：`step47-trial-scope` 仅影响观测动作覆盖范围，不改变当前收敛语义与路由稳定性。

## 19. 受控 early-unknown 试验入口（2026-03-16）

- 新增开关：`--enable-step47-early-unknown`（默认关闭）
- 生效门：
  - `--enable-step47-trial` 已开启
  - `--step47-trial-scope reserved`
  - 命中当前试验白名单中的 `255.0.0.0`
  - 未显式指定 `-h`
- 试验动作：`action=step47-short-circuit-unknown`

验证摘要：

- `reserved + early-unknown`：`short_circuit=1 auth_changed=1 route_changed=1`
- `minimal + early-unknown`：`short_circuit=0 auth_changed=0 route_changed=0`
- `all + early-unknown`：`short_circuit=0 auth_changed=0 route_changed=0`

结论：

- early-unknown 入口已被限定在 `reserved` scope 单点试验。
- 默认行为与显式 `-h` 兼容语义保持不变。

## 20. early-unknown 候选可配置化（2026-03-16）

- 新增参数：`--step47-early-unknown-list <csv>`，示例：`255.0.0.0,10.0.0.1`
- 兼容默认值：未设置或设置为 `default` 时，保持单点候选 `255.0.0.0`。
- 匹配规则：CSV 逐项精确匹配（忽略大小写，自动裁剪逗号两侧空白）。

### 20.1 A/B 对照（配置列表）

- 命令：
  - `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\step47_ab_compare.ps1 -BinaryPath .\release\lzispro\whois\whois-win64.exe -Scope reserved -EnableEarlyUnknown -EarlyUnknownList "255.0.0.0,10.0.0.1"`
- 结果：`eligible=4 short_circuit=2 auth_changed=1 route_changed=2 result=pass`
- 断言口径更新：
  - `route_changed` 由命中候选数决定。
  - `auth_changed` 由“命中候选且 baseline authoritative != unknown”决定。

### 20.2 回退演练（disable-address-preclass）

- 演练脚本：`tools/test/step47_rollback_drill.ps1`
- 命令：
  - `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\step47_rollback_drill.ps1 -BinaryPath .\release\lzispro\whois\whois-win64.exe -Scope reserved -EnableEarlyUnknown -EarlyUnknownList "255.0.0.0,10.0.0.1"`
- 结果：`auth_mismatch=0 via_mismatch=0 result=pass`
- 结论：`--disable-address-preclass` 可一键回退到 Step 4.6 基线语义。

### 20.3 门禁证据

- 远程 Strict（lto-auto）通过：`out/artifacts/20260316-024328`
- 关键信号：`Local hash verify PASS`、`Golden PASS`、`referral check PASS`

## 21. reserved 候选列表分级与预发布清单（2026-03-16）

### 21.1 预置列表（仓库内）

- 默认列表（R0）：`testdata/step47_reserved_list_default.txt`
  - 当前仅包含：`255.0.0.0`
  - 目的：保持“单点可控放量”，避免一次放开多个 route-change。
- 扩展列表（R1，评估用）：`testdata/step47_reserved_list_extended.txt`
  - 包含：`255.0.0.0`、`10.0.0.1`、`fc00::1`、`fe80::1`
  - 目的：用于 A/B 与 rollback 评估，不作为默认发布配置。

### 21.2 风险分级口径

- R0（低风险）：baseline authoritative 非 `unknown` 且单点候选（当前为 `255.0.0.0`）。
- R1（中风险）：baseline 已是 `unknown` 的 reserved/special 候选（如 `10.0.0.1`、`fc00::1`、`fe80::1`）；会增加 route_change 观测量，但不应改变最终 authoritative。
- R2（高风险）：任何 allocated/control 候选（如 `8.8.8.8`）禁止进入 early-unknown 列表。

### 21.3 pre-release 执行清单（建议顺序）

1. 远程 Strict（lto-auto）
2. Step47 PreRelease Check（一键，reserved + list file）
3. Step47 A/B（reserved + list file，按需拆分复核）
4. Step47 rollback drill（reserved + list file，按需拆分复核）
5. CIDR Bundle + Redirect Matrix 10x6（稳态参数）

推荐命令：

- `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\step47_prerelease_check.ps1 -BinaryPath .\release\lzispro\whois\whois-win64.exe -Scope reserved -EnableEarlyUnknown -ListFile testdata/step47_reserved_list_default.txt`
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\step47_ab_compare.ps1 -BinaryPath .\release\lzispro\whois\whois-win64.exe -Scope reserved -EnableEarlyUnknown -EarlyUnknownListFile testdata/step47_reserved_list_default.txt`
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\step47_rollback_drill.ps1 -BinaryPath .\release\lzispro\whois\whois-win64.exe -Scope reserved -EnableEarlyUnknown -EarlyUnknownListFile testdata/step47_reserved_list_default.txt`

### 21.4 一键门禁入口（新增）

- 新增脚本：`tools/test/step47_prerelease_check.ps1`
- 用途：串联执行 readiness、A/B、rollback 三项检查，并输出统一汇总（`summary.csv` / `summary.txt`）。
- VS Code 任务：`Test: Step47 PreRelease Check (reserved, list file)`（复用 `step47ListFile` 输入）
- 推荐命令：
  - `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\step47_prerelease_check.ps1 -BinaryPath .\release\lzispro\whois\whois-win64.exe -Scope reserved -EnableEarlyUnknown -ListFile testdata/step47_reserved_list_default.txt`

## 22. 下一阶段开发分解（P0/P1/P2，2026-03-28）

目标：在保持默认语义不变的前提下，推进 Address-Space 前置分类器（IPv4/IPv6）从“Step 4.7 工程化收口”进入“下一阶段可控开发”。

### 22.1 P0（观测字段与判定骨架）

- 范围：仅增强观测，不改变默认查询路径与终态。
- 交付物：
  - 在现有 `[PRECLASS]` / `[PRECLASS-DECISION]` 基础上补齐稳定字段（如动作来源、匹配层级、回退原因）。
  - 为 IPv4/IPv6 分类结果输出统一 `reason_code` 与 `confidence` 映射，便于后续矩阵聚合。
  - 明确显式 `-h` 旁路路径下的观测行为（允许观测、禁止切流）。
- 验证：
  - 最小样本集（IPv4+IPv6）只校验“观测字段稳定性”，不做 route/auth 变更断言。
  - 一键门禁需保持 PASS（Step47 PreRelease Check）。

### 22.2 P1（受控分类动作）

- 范围：在受控开关下引入分类动作，默认仍关闭。
- 交付物：
  - 对高置信 `reserved/special` 与明确 `rir_hint` 的动作路径做受控化实现。
  - 保持显式 `-h` 兼容优先，不参与短路动作。
  - 将动作覆盖范围与候选列表治理（R0/R1）绑定，禁止 allocated/control 进入 early-unknown 列表。
- 验证：
  - 先跑最小样本矩阵（关注 route_change/auth_changed 漂移），通过后再跑 A/B + rollback。
  - 失败时只记录最小阻塞项与日志路径，不做无差别扩表。

### 22.3 P2（放量门禁与回退策略）

- 范围：形成准发布门禁策略与回退预案，不直接扩大默认行为。
- 交付物：
  - 分层门禁：日常开发跑“定向矩阵 + 一键门禁”，准发布跑“Remote Strict → CIDR Bundle → Redirect Matrix 10x6”。
  - 回退优先级固化：`--disable-address-preclass` 作为全局兜底，确保一键回退到基线语义。
  - 明确进入下一阶段的条件：连续多轮无契约漂移且门禁全绿。
- 验证：
  - 准发布阶段三闸全绿（Strict/CIDR/10x6）且 Step47 一键门禁连续 PASS。

### 22.4 执行顺序与记录规则

1. 先 P0，再 P1，最后 P2；不得跳阶段直接放量。
2. 每轮仅回填新增证据（目录与结论），避免在 RFC 复制历史大段日志。
3. 若涉及判定语义或输出契约变化，必须同步：
   - `docs/RFC-ipv4-ipv6-whois-lookup-rules.md`
   - `docs/USAGE_CN.md`
   - `docs/USAGE_EN.md`

### 22.5 P0 最小样本矩阵（2026-03-28）

- 脚本：`tools/test/preclass_min_matrix.ps1`
- 样本集（6）：
  - IPv4：`255.0.0.0`、`10.0.0.1`、`8.8.8.8`
  - IPv6：`fc00::1`、`fe80::1`、`2001:4860:4860::8888`
- 执行模式：每个样本分别验证 implicit / explicit（`-h iana`）两条路径。
- 校验口径（仅观测稳定性，不改默认语义）：
  - `[PRECLASS]`：`family`、`class`、`rir`、`reason`、`confidence`、`host_mode`
  - `[PRECLASS-DECISION]`：`action`、`route_change`、`trial`、`scope`、`early_unknown`、`disabled`
- 结果：`pass=12 fail=0 result=pass`
- 证据目录：`out/artifacts/preclass_matrix/20260328-004613`
- Step47 一键门禁复跑：`result=pass`（`out/artifacts/step47_prerelease/20260328-005538`）
- 结论：满足 P0 验收目标（观测字段稳定，且未引入默认路由/终态语义漂移）。

### 22.6 P1 第一刀（受控动作骨架，2026-03-28）

- 新增受控开关：`--enable-preclass-actions`（默认关闭）。
- 实现口径（默认语义不变）：
  - 仅在 `implicit`（未显式 `-h`）且 `--enable-preclass-actions + --enable-step47-trial` 双门控开启时允许触发 P1 受控动作。
  - 仅对当前 Step47 试验范围内、且无明确 `rir_hint` 的样本触发 `preclass-short-circuit-unknown`。
  - 显式 `-h` 继续兼容旁路（`action=hint-bypassed route_change=0`）。
- 观测增强：`[PRECLASS-DECISION]` 新增字段 `p1_actions=<0|1>`，用于标记 P1 开关状态。
- 验证证据：
  - 远程 Strict（lto-auto）PASS：`out/artifacts/20260328-012039`（`Local hash verify PASS` + `Golden PASS` + `referral check PASS`）。
  - P1 门控矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-012105`（`pass=24 fail=0`；baseline/p1_only/p1_trial_reserved/p1_trial_reserved_explicit 全覆盖）。
  - 默认回归矩阵 PASS：`out/artifacts/preclass_matrix/20260328-012122`（`pass=12 fail=0`）。
  - Step47 一键门禁 PASS：`out/artifacts/step47_prerelease/20260328-012135`（readiness/ab/rollback 全 pass）。
- 结论：P1 第一刀已收敛为“双门控 + 显式 host 兼容优先”，且分层门禁全绿。

### 22.7 P1 第二刀（reason/confidence 枚举收敛，2026-03-28）

- 目标：仅增强观测语义一致性，不改变默认路由与终态。
- 实现要点（stderr 观测层）：
  - IPv4/IPv6 的 `class/reason/confidence` 映射改为稳定枚举（覆盖 reserved/special/private/global-unicast 等常见区间）。
  - 典型 reason_code 对齐：
    - `V4_FUTURE_USE_240_4`
    - `V4_LIMITED_BROADCAST_255_255_255_255`
    - `V4_PRIVATE_10_8`
    - `V6_UNIQUE_LOCAL_FC00_7`
    - `V6_LINK_LOCAL_FE80_10`
    - `V6_GLOBAL_UNICAST_2000_3`
  - 非 IP 输入继续使用 `NON_IP_INPUT`，保持兼容。
- 验证证据：
  - 远程 Strict（lto-auto）PASS：`out/artifacts/20260328-013219`（`Local hash verify PASS` + `Golden PASS` + `referral check PASS`）。
  - P0 默认矩阵 PASS：`out/artifacts/preclass_matrix/20260328-012808`（`pass=12 fail=0`）。
  - P1 门控矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-012820`（`pass=24 fail=0`）。
  - Step47 一键门禁 PASS：`out/artifacts/step47_prerelease/20260328-012837`（readiness/ab/rollback 全 pass）。
- 结论：P1 第二刀完成，当前可进入下一轮“动作范围细化与 candidate 治理（R0/R1）”。

### 22.8 P1 第三刀（R0/R1 candidate 治理，2026-03-28）

- 目标：在不改变默认语义的前提下，为 P1 动作范围提供可控分层治理。
- 新增开关：`--preclass-action-tier r0|r1`（默认 `r0`）。
- 行为约束：
  - `r0`：仅单点候选 `255.0.0.0` 可触发 P1 动作。
  - `r1`：扩展候选为 `255.0.0.0`、`10.0.0.1`、`fc00::1`、`fe80::1`。
  - 仍需满足 P1 双门控：`--enable-preclass-actions + --enable-step47-trial`；显式 `-h` 路径继续旁路。
- 观测增强：`[PRECLASS-DECISION]` 新增 `p1_tier=r0|r1` 字段。
- 验证证据：
  - 远程 Strict（lto-auto）PASS：`out/artifacts/20260328-015504`（`Local hash verify PASS` + `Golden PASS` + `referral check PASS`）。
  - P1 门控矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-015001`（`pass=30 fail=0`，新增 r0/r1 分层覆盖）。
  - 默认回归矩阵 PASS：`out/artifacts/preclass_matrix/20260328-015033`（`pass=12 fail=0`）。
  - Step47 一键门禁 PASS：`out/artifacts/step47_prerelease/20260328-015045`（readiness/ab/rollback 全 pass）。
- 结论：P1 candidate 治理已落地，满足“默认关闭、分层可控、门禁全绿”。

### 22.9 P1 第四刀（candidate 来源 CSV 治理，2026-03-28）

- 目标：在保留 `r0/r1` 分层语义的前提下，引入可配置候选来源，便于定向灰度验证。
- 新增开关：`--preclass-action-list <csv>`（默认 `NULL`，或显式 `default` 走 tier 默认候选）。
- 行为约束：
  - 当 `--preclass-action-list` 为非空且非 `default` 时，P1 候选来源优先使用 CSV 精确匹配（忽略大小写），覆盖 `r0/r1` 内置候选。
  - 仍需满足 P1 双门控：`--enable-preclass-actions + --enable-step47-trial`；显式 `-h` 路径继续旁路。
- 观测增强：`[PRECLASS-DECISION]` 新增 `p1_list=default|custom` 字段。
- 工程修复：补齐 `src/core/whois_query_exec.c` 的 `strcasecmp` 头文件声明（non-Windows 引入 `<strings.h>`），消除 Strict 构建告警。
- 验证证据：
  - 远程 Strict（lto-auto）PASS：`out/artifacts/20260328-021557`（`WARN_COUNT=0` + `Local hash verify PASS` + `Golden PASS` + `referral check PASS`）。
  - P1 门控矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-021759`（`pass=36 fail=0`，新增 `p1_trial_custom_r0` 与 `p1_list` 断言）。
  - 默认回归矩阵 PASS：`out/artifacts/preclass_matrix/20260328-021900`（`pass=12 fail=0`）。
  - Step47 一键门禁 PASS：`out/artifacts/step47_prerelease/20260328-021918`（readiness/ab/rollback 全 pass）。
- 结论：P1 candidate 来源治理完成，已形成“tier 默认 + CSV 覆盖 + 观测可判定”的闭环。

### 22.10 P1 第五刀（CSV default 归一化与矩阵扩表，2026-03-28）

- 目标：提升 CSV 候选治理的输入容错与观测稳定性，避免 `default` 标记因空白差异导致语义漂移。
- 实现要点：
  - `--preclass-action-list` 与 `--step47-early-unknown-list` 的 `default` 判定改为“单 token + 空白容忍”归一化逻辑（例如 `" default "` 视作默认）。
  - `[PRECLASS-DECISION]` 的 `p1_list` 判定同步使用归一化逻辑，保证 `default|custom` 与实际候选来源一致。
- 矩阵扩表：`tools/test/preclass_p1_gate_matrix.ps1` 新增两种模式：
  - `p1_trial_custom_multi_r0`：验证多候选 CSV（`10.0.0.1, fc00::1`）。
  - `p1_trial_custom_default_r1`：验证空白包裹 `default` 仍走 tier 默认（`p1_list=default`）。
  - 新增外部样本文件接入：`-CaseListFile`（默认尝试加载 `testdata/preclass_p1_real_samples.txt`），用于在不改断言逻辑的前提下扩展真实 IP 样本。
  - 新增样本分组标签与统计：支持 `group|ip` 样本行格式，输出 `summary_group.csv` / `summary_group.txt` 与 `[PRECLASS-P1-GROUP]` 分组通过率日志。
  - 新增分组阈值门禁：`-GroupPassThresholdSpec`（例如 `default=100,external_public_v4=95`）；支持按组阈值与默认阈值（`default=*`）混用，输出 `required_pct/gate_pass` 并以 `group_gate_fail` 计入退出码。
- 验证证据：
  - 远程 Strict（lto-auto）PASS：`out/artifacts/20260328-023116`（`WARN_COUNT=0` + `Local hash verify PASS` + `Golden PASS` + `referral check PASS`）。
  - P1 门控矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-023137`（`pass=48 fail=0`，`cases=6 modes=8`）。
  - P0 最小矩阵 PASS：`out/artifacts/preclass_matrix/20260328-024331`（`pass=12 fail=0`）。
  - Step47 一键门禁 PASS：`out/artifacts/step47_prerelease/20260328-024343`（readiness/ab/rollback 全 pass）。
  - P1 扩表矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-024852`（`pass=112 fail=0`，`cases=14 modes=8`，含 `testdata/preclass_p1_real_samples.txt` 追加样本）。
  - P1 分组扩表矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-025629`（`pass=112 fail=0`，新增分组汇总文件 `summary_group.*`）。
  - P1 标签化分组矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-030247`（`pass=112 fail=0`；新增分组 `external_public_v4/external_private_v4/external_cgnat_v4/external_public_v6`，分组通过率均为 100%）。
  - P1 分组阈值门禁矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-030802`（`pass=112 fail=0`，`group_gate_fail=0`，各组 `required_pct=100 gate_pass=True`）。
- 结论：P1 CSV 治理在“单点/多点/custom/default-blank”场景均稳定收敛，进入下一轮可按业务样本继续扩表。
