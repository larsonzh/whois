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
  - 新增阈值文件输入：`-GroupPassThresholdFile <path>`（示例：`testdata/preclass_p1_group_thresholds_default.txt`），支持按行或 `,`/`;` 分隔 token；与 `-GroupPassThresholdSpec` 同时指定时按“文件先加载，spec 后覆盖”合并。
  - 新增 VS Code 预填任务：`Test: Preclass P1 Gate Matrix (threshold file)`，默认指向 `testdata/preclass_p1_group_thresholds_default.txt`，用于一键执行按组阈值门禁。
  - 预发布串联增强：`tools/test/step47_prerelease_check.ps1` 新增 `-RunPreclassP1Gate`（默认关闭），开启后在 readiness/ab/rollback 后追加 `preclass-p1-gate` 步骤；支持透传 `-PreclassCaseListFile`、`-PreclassGroupThresholdFile`、`-PreclassGroupThresholdSpec`。
  - 参数预校验：当 `-RunPreclassP1Gate` 开启时，会先校验 preclass 脚本与可选文件路径存在性，并输出 `[STEP47-CHECK] preclass_gate=enabled|disabled ...` 诊断。
  - 新增预校验回归脚本：`tools/test/step47_preclass_preflight_check.ps1`，覆盖 `baseline-disabled`、`gate-enabled-valid-threshold`、`gate-enabled-missing-threshold`、`gate-enabled-missing-case-list` 四类用例；对应 VS Code 任务 `Test: Step47 Preclass Preflight Check`。
- 验证证据：
  - 远程 Strict（lto-auto）PASS：`out/artifacts/20260328-023116`（`WARN_COUNT=0` + `Local hash verify PASS` + `Golden PASS` + `referral check PASS`）。
  - P1 门控矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-023137`（`pass=48 fail=0`，`cases=6 modes=8`）。
  - P0 最小矩阵 PASS：`out/artifacts/preclass_matrix/20260328-024331`（`pass=12 fail=0`）。
  - Step47 一键门禁 PASS：`out/artifacts/step47_prerelease/20260328-024343`（readiness/ab/rollback 全 pass）。
  - P1 扩表矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-024852`（`pass=112 fail=0`，`cases=14 modes=8`，含 `testdata/preclass_p1_real_samples.txt` 追加样本）。
  - P1 分组扩表矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-025629`（`pass=112 fail=0`，新增分组汇总文件 `summary_group.*`）。
  - P1 标签化分组矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-030247`（`pass=112 fail=0`；新增分组 `external_public_v4/external_private_v4/external_cgnat_v4/external_public_v6`，分组通过率均为 100%）。
  - P1 分组阈值门禁矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-030802`（`pass=112 fail=0`，`group_gate_fail=0`，各组 `required_pct=100 gate_pass=True`）。
  - P1 阈值文件门禁矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-031626`（`pass=112 fail=0`，`group_gate=enabled source=file`，`group_gate_file=... status=loaded tokens=5`）。
  - P1 阈值文件+spec 合并矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-033525`（`pass=112 fail=0`，`group_gate=enabled source=file+spec`）。
  - Step47 + P1 串联门禁 PASS：`out/artifacts/step47_prerelease/20260328-034742`（`readiness/ab/rollback/preclass-p1-gate` 全 pass）。
  - Step47 + P1 串联（预校验版）PASS：`out/artifacts/step47_prerelease/20260328-035333`（新增 `preclass_gate=enabled` 诊断，四步全 pass）。
  - Step47 预校验回归 PASS：`out/artifacts/step47_preclass_preflight/20260328-040255`（`pass=4 fail=0`，四类预校验用例全通过）。
- 结论：P1 CSV 治理在“单点/多点/custom/default-blank”场景均稳定收敛，进入下一轮可按业务样本继续扩表。

### 22.11 Step47 preflight 接入远程 strict 链路（2026-03-28）

- 目标：把 Step47 preclass preflight 从“本地单测入口”接入到远程 strict 全链路，形成发布前默认可选门禁。
- 实现要点：
  - `tools/remote/remote_build_and_test.sh` 新增参数：
    - `-K <0|1>`：控制是否在远程拉取后执行本地 Step47 preflight。
    - `-C <list_file>`：透传 Step47 list file。
    - `-V <threshold_file>`：透传 preclass threshold file。
  - `tools/release/one_click_release.ps1` 新增 `-RbPreflight`（`0|1`），并在调用远程脚本时透传为 `-K`。
  - `.vscode/tasks.json` 新增输入 `rbPreflight`；`Remote: Build and Sync whois statics` 默认附加 `-K 1`；`One-Click Release` 支持 `-RbPreflight ${input:rbPreflight}`。
- 验证证据：
  - 远程 Strict + preflight PASS：`out/artifacts/20260328-041658`（`Local hash verify PASS` + `Golden PASS` + `referral check PASS` + `Step47 preclass preflight PASS`）。
  - Step47 preclass preflight 套件 PASS：`out/artifacts/step47_preclass_preflight/20260328-041704`（`pass=4 fail=0`）。
- 结论：Step47 preflight 已完成远程 strict 与 one-click release 参数链路打通；默认行为保持兼容（`-K 0` 时不执行 preflight）。

### 22.12 P2 收口进展（2026-03-28）

- 目标：按 22.3 的口径完成“准发布门禁 + 回退策略”收口，不扩大默认行为。
- 本轮准发布三闸结果（全绿）：
  - Remote Strict + preflight PASS：`out/artifacts/20260328-045150`
    - `Local hash verify PASS`
    - `Golden PASS`
    - `referral check PASS`
    - `Step47 preclass preflight PASS`（`out/artifacts/step47_preclass_preflight/20260328-045157`，`pass=4 fail=0`）
  - CIDR Contract Bundle PASS：`out/artifacts/cidr_bundle/cidr_bundle_summary_20260328-045439.txt`（body `pass=4 fail=0`，matrix `pass=9 fail=0`）
  - Redirect Matrix 10x6 PASS：`out/artifacts/redirect_matrix_10x6/20260328-045523`（`authMismatchFiles=0`，`errorFiles=0`）
- Step47 一键门禁（含 preclass-p1-gate）复跑 PASS：`out/artifacts/step47_prerelease/20260328-050426`。
- strict 任务透传人工验证（`Remote: Build (Strict Version)`）：
  - `-K 1`：出现 `[STEP47-PREFLIGHT]` 全套日志并 `result=pass`，目录 `out/artifacts/step47_preclass_preflight/20260328-051817`，总耗时 `318s`。
  - `-K 0`：日志中不出现 `[STEP47-PREFLIGHT]` 段，仅保留 strict 常规链路，耗时 `198s`。
- 回退策略状态：`--disable-address-preclass` 仍作为全局兜底开关，未发生默认语义漂移。

结论：P2 门禁收口条件已满足，可进入“发布侧回归清单固化与阶段完成标记”。

### 22.13 业务样本扩表进展（2026-03-28）

- 扩表文件：`testdata/preclass_p1_real_samples.txt`
  - 新增样本（按既有分组）：`external_public_v4`、`external_private_v4`、`external_cgnat_v4`、`external_public_v6`。
- 门禁复跑：`tools/test/preclass_p1_gate_matrix.ps1 -GroupPassThresholdFile testdata/preclass_p1_group_thresholds_default.txt`
  - 产物：`out/artifacts/preclass_p1_matrix/20260328-050157`
  - 结果：`pass=168 fail=0`，`group_gate_fail=0`，各分组 `gate_pass=True`。

结论：业务样本扩表后门禁仍稳定，全量分组阈值保持 100% 通过。

### 22.14 阶段完成标记（2026-03-28）

- 阶段：P2（preclass 接入与发布前门禁闭环）
- 完成判定（全部满足）：
  - 参数链路闭环：remote strict（`-K/-C/-V`）-> one-click（`-RbPreflight`）-> VS Code strict/sync 任务输入透传一致。
  - 准发布三闸全绿：Remote Strict + preflight、CIDR Contract Bundle、Redirect Matrix 10x6 全部 PASS。
  - Step47 双链路全绿：preflight regression 与 prerelease（含 `preclass-p1-gate`）均 PASS。
  - 人工透传验证完成：strict 任务 `-K 1` 触发 preflight；`-K 0` 不触发 preflight，行为与预期一致。
- 兼容性结论：默认行为未变（未启用 preclass 门禁时路径保持既有语义）；`--disable-address-preclass` 继续作为全局回退开关。
- 发布侧冻结项（进入下一阶段前不再变更）：
  - `testdata/preclass_p1_group_thresholds_default.txt` 作为默认阈值基线。
  - `testdata/preclass_p1_real_samples.txt` 作为业务样本基线（后续仅增量扩表，不改既有样本判定语义）。
  - `tools/test/step47_preclass_preflight_check.ps1` 四场景回归作为 preflight 入口基线。
- 发布侧清单入口：`docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 已固化“Release-Side Regression Checklist（2026-03-28）”作为发版前必跑顺序与通过标准。
- 下一阶段入口：在不改变默认语义前提下，执行“发布侧回归清单最终固化 + 小批量业务样本增量扩表”。

### 22.15 业务样本小批量增量扩表（2026-03-28）

- 扩表文件：`testdata/preclass_p1_real_samples.txt`
  - 本轮增量：
    - `external_public_v4`：新增 2 条。
    - `external_private_v4`：新增 2 条。
    - `external_cgnat_v4`：新增 2 条。
    - `external_public_v6`：新增 3 条。
- P1 分组阈值门禁复跑：
  - 命令：`tools/test/preclass_p1_gate_matrix.ps1 -GroupPassThresholdFile testdata/preclass_p1_group_thresholds_default.txt`
  - 产物：`out/artifacts/preclass_p1_matrix/20260328-054446`
  - 结果：`cases=29 modes=8`，`pass=232 fail=0`，`group_gate_fail=0`。
- Step47 串联门禁复跑（含 preclass-p1-gate）:
  - 命令：`tools/test/step47_prerelease_check.ps1 -RunPreclassP1Gate -PreclassGroupThresholdFile testdata/preclass_p1_group_thresholds_default.txt`
  - 产物：`out/artifacts/step47_prerelease/20260328-054950`
  - 结果：`readiness/ab/rollback/preclass-p1-gate` 全 pass，`result=pass`。

结论：小批量增量扩表后，P1 分组阈值门禁与 Step47 串联门禁保持稳定，未引入默认语义漂移。

### 23. 可执行设计骨架（2026-03-31）

目标：将“Address-Space 前置分类器”从规则草案推进到可落地实现，明确数据模型、生成脚本输入输出、查表 API、门禁断言与回退点。

#### 23.1 数据模型（运行时表）

建议生成统一前缀表（IPv4/IPv6 共用结构，按 family 区分）：

- `family`：`4|6`
- `prefix_len`：前缀长度（IPv4: 0~32，IPv6: 0~128）
- `addr_hi` / `addr_lo`：前缀起始地址（IPv4 固定写入 `addr_lo`，`addr_hi=0`）
- `class_id`：`allocated|legacy|reserved|special|unallocated|unknown`
- `rir_id`：`apnic|arin|ripe|afrinic|lacnic|none|unknown`
- `reason_id`：稳定整数编号（与 `reason_code` 一一映射）
- `confidence_id`：`high|medium|low`
- `flags`：保留扩展位（如“仅观测”“禁止 early-unknown”）

配套元数据：

- `schema_version`：表结构版本
- `source_ipv4_sha256` / `source_ipv6_sha256`：源快照哈希
- `generated_at`：生成时间戳
- `record_count_v4` / `record_count_v6`：记录数

#### 23.2 生成脚本输入/输出（构建期）

输入：

- `docs/ipv4-address-space.txt`
- `docs/ipv6-address-space.txt`
- `tools/preclass/reason_code_map.json`（新增，维护 `reason_code <-> reason_id`）

输出：

- `include/wc/wc_preclass_table.h`（自动生成，不手改）
- `src/core/preclass_table.c`（自动生成静态数组与元数据）
- `out/generated/preclass_manifest.json`（源文件哈希、记录数、生成版本）

构建流程：

1. 解析 IPv4/IPv6 快照并标准化为 CIDR 记录。
2. 归一化 `class/rir/reason/confidence` 到稳定枚举。
3. 做重叠检测与最长前缀优先排序。
4. 生成 C 表与 manifest。
5. 在构建中校验“生成结果可重复”（同输入同输出哈希）。

#### 23.3 查表 API（建议）

新增头文件：`include/wc/wc_preclass.h`

建议接口：

- `int wc_preclass_lookup_text(const char* query, wc_preclass_result_t* out);`
- `int wc_preclass_lookup_bin(const uint8_t* addr, int family, wc_preclass_result_t* out);`
- `int wc_preclass_decide_start(const wc_preclass_result_t* in, int has_explicit_host, const wc_preclass_policy_t* policy, wc_preclass_decision_t* out);`
- `const char* wc_preclass_reason_name(uint16_t reason_id);`

返回结构建议：

- `wc_preclass_result_t`：`family/class_id/rir_id/reason_id/confidence_id/matched_prefix_len`
- `wc_preclass_decision_t`：`action/start_host/route_change/auth_change/rollback_hint`

约束：

- 显式 `-h` 必须可旁路动作（兼容优先）。
- 未启用动作开关时仅输出观测，不改路由。

#### 23.4 落地顺序（执行序）

1. **D0（生成器打底）**：先落地脚本与生成产物，不改运行时行为。
2. **D1（查表接线）**：将现有 `wc_preclass_classify_ip` 切换为“查表优先 + 旧逻辑兜底”。
3. **D2（动作门控）**：仅在 `--enable-preclass-actions + --enable-step47-trial` 下启用动作。
4. **D3（发布门禁）**：按 Remote Strict -> CIDR Bundle -> Redirect Matrix 10x6 -> Step47 prerelease 复核。

#### 23.5 回退点（必须保留）

- **R0（运行时总回退）**：`--disable-address-preclass` 一键回退到基线语义。
- **R1（动作回退）**：关闭 `--enable-preclass-actions`，仅保留观测。
- **R2（试验回退）**：关闭 `--enable-step47-trial` 或限制 `scope=minimal`。
- **R3（构建回退）**：生成表失败时阻断发布构建，不允许带不完整表上线。

#### 23.6 门禁断言（可执行）

最小断言：

1. 生成器断言：`manifest` 中源哈希与输入文件哈希一致。
2. 数据断言：`reason_id` 全量可反查 `reason_code`，无孤儿枚举。
3. 查表断言：同一输入在相同表版本下输出稳定（family/class/rir/reason/confidence 不漂移）。
4. 兼容断言：显式 `-h` 路径 `route_change=0`（除已有显式 hint 逻辑）。
5. 发布断言：Remote Strict + preflight、CIDR Bundle、Redirect Matrix 10x6、Step47 prerelease 全 PASS。

发布阻断条件：

- 任一门禁 FAIL。
- `authMismatchFiles > 0`。
- 生成表与源快照哈希不一致。

#### 23.7 交付完成标准

- 已提交生成器与自动生成表文件。
- 已接线 `wc_preclass_lookup_*` API 并保留旧逻辑兜底。
- 已完成至少两轮全链路门禁且结果一致。
- 已在 `docs/RFC-whois-client-split.md` 与 `RELEASE_NOTES.md` 记录证据路径与回退口径。

#### 23.8 D0 首次落地（2026-04-01）

- 生成器已落地：`tools/preclass/gen_preclass_table.py`
- 映射文件已落地：`tools/preclass/reason_code_map.json`
- 使用说明已落地：`tools/preclass/README.md`
- 自动生成产物：
  - `include/wc/wc_preclass_table.h`
  - `src/core/preclass_table.c`
  - `out/generated/preclass_manifest.json`
- 本轮生成结果：`rows=276`（`v4=256`，`v6=20`），`schema_version=1`。
- 兼容性说明：本轮仅完成 D0 产物落地，运行时查表路径尚未接线，默认查询语义保持不变。

#### 23.9 D1 查表接线（2026-04-01）

- 运行时接线：`src/core/preclass.c` 已接入 `wc_preclass_table` 查表路径，并新增 `class/rir/reason/confidence` 的 ID→字符串映射。
- 兼容兜底：保留旧逻辑中的 private/special/global-unicast 判定分支，确保保留地址与显式场景观测字段稳定。
- 可观测性变化：普通公网地址可输出基于注册表的分类（如 `legacy/allocated` 与 `V4_*_REGISTRY`），用于后续动作门控评估。
- 本轮门禁：
  - Remote Strict PASS：`out/artifacts/20260401-014329`
  - Preclass 最小矩阵 PASS：`out/artifacts/preclass_matrix/20260401-014502`
  - Step47 readiness PASS：`out/artifacts/step47_matrix/20260401-014542`

#### 23.9A D2 动作门控补记（2026-04-01）

- 补记原因：D2 能力在 2026-03-28 的 P1 阶段已实现并长期运行（`--enable-preclass-actions + --enable-step47-trial` 双门控），但在第 23 节按 D0/D1/D3/D4 记录时遗漏了独立小节，导致序号观感上“跳过 D2”。
- D2 门控约束（保持不变）：
  - 仅在 `--enable-preclass-actions + --enable-step47-trial` 同时开启时允许 preclass 动作生效。
  - 显式 `-h` 路径保持旁路，避免破坏兼容语义。
  - `--preclass-action-tier` / `--preclass-action-list` 继续决定候选覆盖范围（默认不放量）。
- 本轮补证（2026-04-01）：
  - P1 门控矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260401-032155`（`pass=232 fail=0`，`group_gate_fail=0`）。
  - Step47 串联（含 `preclass-p1-gate`）PASS：`out/artifacts/step47_prerelease/20260401-032539`（`readiness/ab/rollback/preclass-p1-gate` 全 pass）。
- 结论：D2 并未缺失实现，本次已完成“编号补记 + 新证据闭环”，第 23 节执行序可按 D0 -> D1 -> D2 -> D3 -> D4 理解与追溯。

#### 23.10 D3 一致性收口（2026-04-01，双轮全链路）

- Round 1（固定顺序）PASS：
  - Remote Strict：`out/artifacts/20260401-023614`（`Local hash verify PASS` + `[golden] PASS` + `referral check PASS`）
  - CIDR Bundle：`out/artifacts/cidr_bundle/cidr_bundle_summary_20260401-023738.txt`（body `pass=4 fail=0`，matrix `pass=9 fail=0`）
  - Redirect Matrix 10x6：`out/artifacts/redirect_matrix_10x6/20260401-023834`（`authMismatchFiles=0`，`errorFiles=0`）
  - Step47 prerelease（含 preclass-p1-gate）：`out/artifacts/step47_prerelease/20260401-024532`（`readiness/ab/rollback/preclass-p1-gate` 全 pass）
- Round 2（同序复跑）PASS：
  - Remote Strict：`out/artifacts/20260401-025245`（`Local hash verify PASS` + `[golden] PASS` + `referral check PASS`）
  - CIDR Bundle：`out/artifacts/cidr_bundle/cidr_bundle_summary_20260401-025312.txt`（body `pass=4 fail=0`，matrix `pass=9 fail=0`）
  - Redirect Matrix 10x6：`out/artifacts/redirect_matrix_10x6/20260401-025346`（`authMismatchFiles=0`，`errorFiles=0`）
  - Step47 prerelease（含 preclass-p1-gate）：`out/artifacts/step47_prerelease/20260401-030103`（`readiness/ab/rollback/preclass-p1-gate` 全 pass）
- 收口判定：两轮四闸结果一致且全部通过，满足 23.7“至少两轮全链路门禁且结果一致”的完成标准。

#### 23.11 D4 可执行门禁断言自动化（2026-04-01）

- 新增可执行断言脚本：`tools/test/preclass_table_guard.ps1`
- 新增 VS Code 任务：`Test: Preclass Table Guard (RFC 23.6)`
- 断言覆盖：
  - 生成器断言：`manifest.source_ipv4_sha256/source_ipv6_sha256` 与输入快照哈希一致。
  - 数据断言：表内 `reason_id` 全量可回查 `reason_code_map.json`（`missing_reason_ids` 必须为空）。
  - 行数断言：`record_count_v4/v6/total` 与 `preclass_table.c` 解析计数一致。
- 本轮证据：`out/artifacts/preclass_table_guard/20260401-031509`
  - 执行摘要：`summary.txt`
  - 结构化结果：`summary.json`
  - 结果：`result=pass`
- 兼容说明：当前 `reason_code_map.json` 中的未命中枚举（本轮为 `2002`）按“非阻断诊断项”输出，不影响 23.6 的“表内 ID 可回查”强约束。

#### 23.12 D5 Step47 可选串联 table guard（2026-04-01）

- 目标：把 23.6 的 `preclass_table_guard` 从“独立任务”提升为 Step47 一键门禁中的可选步骤，便于同一轮预发布检查集中输出证据。
- 脚本接线：`tools/test/step47_prerelease_check.ps1` 新增参数
  - `-RunPreclassTableGuard`
  - `-PreclassTableGuardScript`
- 默认语义：保持关闭（不传 `-RunPreclassTableGuard` 时行为不变），仅在显式开启时追加 `preclass-table-guard` 步骤。
- 任务接线：`.vscode/tasks.json` 新增 `Test: Step47 PreRelease + Table Guard (reserved, list file)`，用于一键触发该可选步骤。
- 本轮验证：
  - Step47 + table guard PASS：`out/artifacts/step47_prerelease/20260401-033633`
  - 串联内 `preclass-table-guard` 步骤 PASS：`out/artifacts/preclass_table_guard/20260401-033643`
  - 总结：`[STEP47-CHECK] result=pass`，默认关闭语义未变。

#### 23.13 D6 Remote/Release 入口透传 table guard（2026-04-01）

- 目标：把 D5 的“Step47 内可选 table guard”扩展到 remote strict 与 one-click release 入口，避免发布侧与脚本侧参数能力不对称。
- 远程脚本接线：`tools/remote/remote_build_and_test.sh`
  - 新增 `-N <0|1>`：控制是否在拉取后执行 `preclass_table_guard`（默认 `0`，保持兼容）。
  - 新增 `-B <script_path>`：覆盖 table guard 脚本路径（默认 `tools/test/preclass_table_guard.ps1`）。
- 发布脚本接线：`tools/release/one_click_release.ps1`
  - 新增 `-RbPreclassTableGuard <0|1>`：透传到远程脚本 `-N`。
  - 新增 `-RbPreclassTableGuardScript <path>`：透传到远程脚本 `-B`。
  - 新增 `-DryRunIf <true|false>`：安全演练模式（默认 `false`）；开启后强制跳过 tag、GitHub/Gitee release 更新与 statics 自动 commit/push，保留可选 build/sync 验证路径。
- 任务入口接线：`.vscode/tasks.json`
  - 新增输入 `rbPreclassTableGuard/rbPreclassTableGuardScript`。
  - `Remote: Build (Strict Version)` 透传 `-N/-B`。
  - `One-Click Release` 透传 `-RbPreclassTableGuard/-RbPreclassTableGuardScript`。
  - 新增输入 `oneClickDryRun`，并在 `One-Click Release` 任务透传 `-DryRunIf`。
- 兼容说明：默认保持关闭；未显式开启时不新增执行步骤，不改变既有 release/strict 语义。
- 本轮验证（Remote Strict，`-K 0 -N 1`）：
  - 构建产物：`out/artifacts/20260401-035628`
  - `Local hash verify PASS` + `[golden] PASS` + `referral check PASS`
  - table guard PASS：`out/artifacts/preclass_table_guard/20260401-035634`
  - `STEP47-PREFLIGHT` 计数 `0`（符合 `-K 0` 预期）
- 本轮 dry-run 烟测（本地，无副作用路径）：
  - 命令：`powershell -NoProfile -ExecutionPolicy Bypass -File tools/release/one_click_release.ps1 -Version 3.2.12 -BuildAndSyncIf false -DryRunIf true -SkipTagIf false`
  - 结果：脚本输出 `one-click done: dry-run mode; tag=v3.2.12`，且工作区仅包含预期脚本/任务改动。

#### 23.14 D6 合流清单执行（2026-04-03，按 2026-04-02 清单）

- D6 合流验证（Remote Strict，`-K 1 -N 1`）PASS：
  - `STRICT_TS=20260403-021119`（`Local hash verify PASS` + `[golden] PASS` + `referral check PASS`）
  - `PREFLIGHT_TS=20260403-021128`（`pass=4 fail=0`）
  - `TABLE_GUARD_TS=20260403-021940`（`result=pass`）
- One-Click dry-run 全链路（`oneClickDryRun=true` + `rbPreflight=1` + `rbPreclassTableGuard=1`）复验：
  - 首轮出现 preflight 失败：`out/artifacts/step47_preclass_preflight/20260403-022527`（`pass=3 fail=1`，失败点为 rollback 子步骤）。
  - 复跑（`-RbCflagsExtra ''` 对齐 strict 口径）PASS：`out/artifacts/20260403-023609`、`out/artifacts/step47_preclass_preflight/20260403-023618`、`out/artifacts/preclass_table_guard/20260403-024219`。
  - dry-run 无副作用语义已命中：`statics changes detected but commit/push skipped`、`skipping GitHub release update`、`skipping Gitee release update`、`one-click done: dry-run mode; tag=v3.2.12`。
- 23.6 断言回归 PASS：`out/artifacts/preclass_table_guard/20260403-024312`（`missing_reason_ids=`，`orphan_reason_ids=2002` 仅诊断）。
- 预分类回归双闸 PASS：
  - P0 最小矩阵：`out/artifacts/preclass_matrix/20260403-024349`（`pass=12 fail=0`）
  - P1 门控矩阵（threshold file）：`out/artifacts/preclass_p1_matrix/20260403-024822`（`pass=232 fail=0`，`group_gate_fail=0`）

#### 23.15 D6 双轮一致性门禁任务化与首轮实跑（2026-04-03）

- 新增门禁脚本：`tools/test/d6_consistency_double_run.ps1`。
  - 单次执行固定覆盖两轮：Remote Strict（`-K 1 -N 1`）+ P0 最小矩阵 + P1 门控矩阵（threshold file）。
  - 统一输出：`out/artifacts/d6_consistency_double_round/<ts>`，并落盘 `summary.csv` / `summary.txt`。
- 新增任务入口：`.vscode/tasks.json` -> `Gate: D6 Double-Round Consistency`（复用既有 `rb*` 输入，便于与 strict 任务保持同口径参数）。
- 首轮实跑 PASS：`out/artifacts/d6_consistency_double_round/20260403-035824`（`[D6-CONSISTENCY] result=pass`）。
  - Round1：`STRICT/PREFLIGHT/TABLE_GUARD=20260403-040118/20260403-040126/20260403-040519`，P0=`out/artifacts/preclass_matrix/20260403-040525`，P1=`out/artifacts/preclass_p1_matrix/20260403-040536`。
  - Round2：`STRICT/PREFLIGHT/TABLE_GUARD=20260403-041423/20260403-041435/20260403-041845`，P0=`out/artifacts/preclass_matrix/20260403-041848`，P1=`out/artifacts/preclass_p1_matrix/20260403-041856`。
- 判定：两轮 `hash/golden/referral/preflight/table-guard/P0/P1` 均为 `True`，`RoundPass=True`。

- 第二次整轮复跑 PASS：`out/artifacts/d6_consistency_double_round/20260403-043011`。
  - Round1：`STRICT/PREFLIGHT/TABLE_GUARD=20260403-043313/20260403-043322/20260403-043700`，P0=`out/artifacts/preclass_matrix/20260403-043702`，P1=`out/artifacts/preclass_p1_matrix/20260403-043710`。
  - Round2：`STRICT/PREFLIGHT/TABLE_GUARD=20260403-044318/20260403-044326/20260403-044719`，P0=`out/artifacts/preclass_matrix/20260403-044721`，P1=`out/artifacts/preclass_p1_matrix/20260403-044729`。
  - 判定：与首次实跑一致，`RoundPass=True` 且关键闸项全部 `True`。

#### 23.16 2026-04-04 清单续跑补证（2026-04-03）

- D6 第 3 组双轮一致性证据 PASS：`out/artifacts/d6_consistency_double_round/20260403-054424`（`[D6-CONSISTENCY] result=pass`）。
  - Round1：`STRICT/PREFLIGHT/TABLE_GUARD=20260403-054716/20260403-054724/20260403-055127`。
  - Round2：`STRICT/PREFLIGHT/TABLE_GUARD=20260403-055938/20260403-055949/20260403-060419`。
  - 判定：两轮 `hash/golden/referral/preflight/table-guard/P0/P1` 继续全 `True`。
- dry-run 本地无副作用复验 PASS：`out/artifacts/oneclick_dryrun_guard/20260403-060902`（`require_git_state_unchanged=True`、`git_state_unchanged=True`、`result=pass`）。
- dry-run build+sync 受控断言复验 PASS：`out/artifacts/oneclick_dryrun_guard/20260403-060914`（`require_statics_detected_if_build_sync=True`、`statics_detected=true`、`statics_commit_pushed=false`、`result=pass`）。
- 说明：本轮已按脚本口径完成“D6 第 3 组 + dry-run 双模式复验”；VS Code 任务面板入口一致性校验留作下一轮补证。

#### 23.17 UI 入口无交互补丁（2026-04-03）

- `.vscode/tasks.json` 新增 3 个 prefilled 任务：
  - `Gate: D6 Double-Round Consistency (prefilled)`
  - `Test: One-Click DryRun Guard (local, prefilled)`
  - `Test: One-Click DryRun Guard (build+sync, prefilled)`
- 入口补证进展：`local` prefilled 任务入口 PASS：`out/artifacts/oneclick_dryrun_guard/20260403-062627`（`result=pass`）。
- 运行约束：`build+sync` 与 `d6` 属于远端构建任务，必须串行执行；并行触发会因共享远端工作目录导致构建互扰。

#### 23.18 UI 入口串行补证结果（2026-04-03）

- `build+sync prefilled`：`out/artifacts/oneclick_dryrun_guard/20260403-064550`
  - `exit_code=0`、`guard_result=pass`。
  - 在 `RequireStaticsDetectedIfBuildSync=true` 下，`statics_detected=false`，因此 `smoke_result=fail`（本轮无新 static delta 的可解释结果）。
- `d6 prefilled`：`out/artifacts/d6_consistency_double_round/20260403-065703`
  - Round1：`STRICT/PREFLIGHT/TABLE_GUARD=20260403-070232/20260403-070245/20260403-070725`。
  - Round2：`STRICT/PREFLIGHT/TABLE_GUARD=20260403-071708/20260403-071721/20260403-072140`。
  - `summary.csv` 判定：两轮 `RoundPass=True`，`hash/golden/referral/preflight/table-guard/P0/P1` 全 `True`。

#### 23.19 2026-04-05 清单续跑（Day2，2026-04-03）

- Pre-Release 严格串行预演完成：
  - local：`out/artifacts/oneclick_dryrun_guard/20260403-085449`（`result=pass`）。
  - build+sync strict：`out/artifacts/oneclick_dryrun_guard/20260403-085503`（`guard_result=pass`，但 `RequireStaticsDetectedIfBuildSync=true` 且 `statics_detected=false`，`smoke_result=fail`，可解释失败）。
  - build+sync no-delta-ok：`out/artifacts/oneclick_dryrun_guard/20260403-090357`（`result=pass`）。
  - D6：`out/artifacts/d6_consistency_double_round/20260403-091450`（`[D6-CONSISTENCY] result=pass`）。
- D6 稳定性抽检追加：`out/artifacts/d6_consistency_double_round/20260403-094125`，两轮 `RoundPass=True`，且 `PreflightPass/TableGuardPass=True`。
- 检索模板有效性复核：
  - PowerShell 模板已命中 `guard_result/statics_detected/smoke_result` 与 D6 `RoundPass/PreflightPass/TableGuardPass`。
  - Git Bash 侧因环境无 `rg`，采用 `"C:/Program Files/Git/bin/bash.exe" + grep` 等效验证并命中相同关键字段。

#### 23.20 2026-04-06 清单开工执行（2026-04-04 ~ 2026-04-05）

- UI 入口再确认（串行）：
  - local prefilled PASS：`out/artifacts/oneclick_dryrun_guard/20260404-222633`（`result=pass`）。
  - build+sync no-delta-ok PASS：`out/artifacts/oneclick_dryrun_guard/20260404-223713`（`result=pass`、`guard_result=pass`）。
  - D6 prefilled 首次出现“单轮异常”后按决策表串行重跑：
    - 首次：`out/artifacts/d6_consistency_double_round/20260404-224624`（Round1 异常、Round2 正常）。
    - 重跑：`out/artifacts/d6_consistency_double_round/20260404-231236`（两轮 `RoundPass=True`，`PreflightPass/TableGuardPass=True`）。
- strict/no-delta 并排留证（同轮）：
  - Pair-A：strict `20260404-233933` + no-delta `20260404-234956`。
  - Pair-B：strict `20260405-003113` + no-delta `20260405-004139`。
  - 本轮两个 strict 均 `statics_detected=true` 且 PASS；“可解释失败 vs 链路健康 PASS”语义对照继续沿用 Day2 证据（`20260403-085503` vs `20260403-090357`）。
- D6 非默认样本抽检 PASS：`out/artifacts/d6_consistency_double_round/20260405-000144`，查询样本 `8.8.4.4 1.0.0.1 45.113.52.0`，两轮 `RoundPass=True` 且关键闸项全 `True`。
- C5 模板可用性固化：已在 `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 增补“无 `rg` 环境使用 `bash.exe + grep` 等效命令”提示。
- 收尾状态：本轮 static delta 已统一提交推送（`86109a9`），工作区干净。

#### 23.21 Daily 链路续跑（2026-04-05）

- UI 入口 Daily 串行链路 PASS：
  - local：`out/artifacts/oneclick_dryrun_guard/20260405-013507`（`result=pass`）。
  - build+sync no-delta-ok：`out/artifacts/oneclick_dryrun_guard/20260405-013515`（`statics_detected=false` 且 `smoke_result=pass`）。
  - D6：`out/artifacts/d6_consistency_double_round/20260405-014305`（`[D6-CONSISTENCY] result=pass`）。
- D6 关键时间戳：
  - Round1 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-014607/20260405-014614/20260405-014956`。
  - Round2 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-015625/20260405-015631/20260405-020027`。
- 收尾状态：本轮再次出现 static delta（`release/lzispro/whois/*`），按既有口径统一提交收口。

#### 23.22 2026-04-07 清单预跑（2026-04-05）

- Daily 三任务（UI 串行）PASS：
  - local：`out/artifacts/oneclick_dryrun_guard/20260405-020758`（`result=pass`）。
  - build+sync no-delta-ok：`out/artifacts/oneclick_dryrun_guard/20260405-020804`（`statics_detected=false` 且 `smoke_result=pass`）。
  - D6：`out/artifacts/d6_consistency_double_round/20260405-021626`（`[D6-CONSISTENCY] result=pass`）。
- strict/no-delta 并排复验 PASS：`strict=20260405-024148`、`no-delta-ok=20260405-025109`（均 `result=pass`，strict 为 `statics_detected=true`）。
- D6 非默认样本（`8.8.4.4 1.1.1.0/24 2001:4860:4860::8888`）PASS：`out/artifacts/d6_consistency_double_round/20260405-025919`。
  - Round1 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-030257/20260405-030303/20260405-030640`。
  - Round2 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-031326/20260405-031332/20260405-031711`。
- 检索模板抽测 PASS（PowerShell + bash+grep）：已命中 one-click `statics_detected/guard_result/smoke_result` 与 D6 `RoundPass/PreflightPass/TableGuardPass`；并将模板正则统一为兼容 `key: value`/`key=value`。

#### 23.23 持续推进第二轮（2026-04-05）

- Daily 三任务（UI 串行）PASS：
  - local：`out/artifacts/oneclick_dryrun_guard/20260405-032635`。
  - build+sync no-delta-ok：`out/artifacts/oneclick_dryrun_guard/20260405-032642`（`statics_detected=false`、`smoke_result=pass`）。
  - D6：`out/artifacts/d6_consistency_double_round/20260405-033428`（两轮 `RoundPass=True`）。
- strict/no-delta 并排复验 PASS：`strict=20260405-035747`、`no-delta-ok=20260405-040554`（strict 为 `statics_detected=true`）。
- D6 非默认样本（`1.0.0.1 45.113.52.0/22 2404:6800:4008::200e`）首跑出现单轮异常：`out/artifacts/d6_consistency_double_round/20260405-041520`（Round2 `StrictExit=1`，`Preflight/TableGuard` 缺失）。
- 按分流规则立即重跑后收敛 PASS：`out/artifacts/d6_consistency_double_round/20260405-043523`。
  - Round1 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-043930/20260405-043937/20260405-044308`。
  - Round2 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-045013/20260405-045020/20260405-045340`。
- 模板抽测复核 PASS：
  - PowerShell 命中：`out/artifacts/oneclick_dryrun_guard/20260405-040554/{summary.txt,oneclick_dryrun.log}` 与 `out/artifacts/d6_consistency_double_round/20260405-043523/summary.csv`。
  - bash+grep 命中：同目录下 `key: value` / `key=value` 双格式均可检索。

#### 23.24 2026-04-08 清单执行（2026-04-05）

- Daily 三任务（UI 串行）PASS：
  - local：`out/artifacts/oneclick_dryrun_guard/20260405-050330`（`result=pass`）。
  - build+sync no-delta-ok：`out/artifacts/oneclick_dryrun_guard/20260405-050338`（`statics_detected=false`、`smoke_result=pass`）。
  - D6：`out/artifacts/d6_consistency_double_round/20260405-051137`（两轮 `RoundPass=True`）。
- strict/no-delta 并排复验 PASS：`strict=20260405-053514`、`no-delta-ok=20260405-054315`（strict 为 `statics_detected=true`）。
- D6 非默认样本（`9.9.9.9 43.227.220.0/22 2606:4700:4700::1111`）PASS：`out/artifacts/d6_consistency_double_round/20260405-055041`。
  - Round1 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-055404/20260405-055412/20260405-055854`。
  - Round2 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-060602/20260405-060610/20260405-061036`。
- 模板抽测 PASS（PowerShell + bash+grep）：
  - PowerShell 命中：`out/artifacts/oneclick_dryrun_guard/20260405-054315/{summary.txt,oneclick_dryrun.log}` 与 `out/artifacts/d6_consistency_double_round/20260405-055041/summary.csv`。
  - bash+grep 命中：同目录下 `key: value` / `key=value` 双格式字段持续可检索。

#### 23.25 2026-04-09 清单执行（2026-04-05）

- Daily 三任务（UI 串行）PASS：
  - local：`out/artifacts/oneclick_dryrun_guard/20260405-062047`（`result=pass`）。
  - build+sync no-delta-ok：`out/artifacts/oneclick_dryrun_guard/20260405-062056`（`statics_detected=false`、`smoke_result=pass`）。
  - D6：`out/artifacts/d6_consistency_double_round/20260405-062756`（两轮 `RoundPass=True`）。
- strict/no-delta 并排复验 PASS：`strict=20260405-064857`、`no-delta-ok=20260405-065628`（strict 为 `statics_detected=true`）。
- D6 非默认样本（`208.67.222.222 203.26.12.0/24 2620:119:35::35`）PASS：`out/artifacts/d6_consistency_double_round/20260405-070422`。
  - Round1 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-070803/20260405-070811/20260405-071140`。
  - Round2 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-071846/20260405-071854/20260405-072243`。
- 模板抽测 PASS（PowerShell + bash+grep）：
  - PowerShell 命中：`out/artifacts/oneclick_dryrun_guard/20260405-065628/{summary.txt,oneclick_dryrun.log}` 与 `out/artifacts/d6_consistency_double_round/20260405-070422/summary.csv`。
  - bash+grep 命中：同目录下 `key: value` / `key=value` 双格式字段持续可检索。

#### 23.26 2026-04-10 清单执行（2026-04-05）

- Daily 三任务（UI 串行）PASS：
  - local：`out/artifacts/oneclick_dryrun_guard/20260405-090255`（`result=pass`）。
  - build+sync no-delta-ok：`out/artifacts/oneclick_dryrun_guard/20260405-090304`（`statics_detected=false`、`smoke_result=pass`）。
  - D6：`out/artifacts/d6_consistency_double_round/20260405-091112`（两轮 `RoundPass=True`）。
- strict/no-delta 并排复验 PASS：`strict=20260405-093833`、`no-delta-ok=20260405-094715`（strict 为 `statics_detected=true`）。
- D6 非默认样本（`149.112.112.112 45.236.136.0/22 2001:4860:4860::8844`）首跑出现单轮异常：`out/artifacts/d6_consistency_double_round/20260405-095722`（Round2 `StrictExit=1`，`Preflight/TableGuard` 缺失）。
- 按分流规则立即重跑后收敛 PASS：`out/artifacts/d6_consistency_double_round/20260405-101930`。
  - Round1 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-102426/20260405-102435/20260405-103011`。
  - Round2 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-103853/20260405-103901/20260405-104306`。
- 模板抽测 PASS（PowerShell + bash+grep）：
  - PowerShell 命中：`out/artifacts/oneclick_dryrun_guard/20260405-094715/{summary.txt,oneclick_dryrun.log}` 与 `out/artifacts/d6_consistency_double_round/20260405-101930/summary.csv`。
  - bash+grep 命中：同目录下 `key: value` / `key=value` 双格式字段持续可检索。

#### 23.27 2026-04-11 清单执行（2026-04-05）

- Daily 三任务（UI 串行）PASS：
  - local：`out/artifacts/oneclick_dryrun_guard/20260405-132622`（`result=pass`）。
  - build+sync no-delta-ok：`out/artifacts/oneclick_dryrun_guard/20260405-132637`（`statics_detected=false`、`smoke_result=pass`）。
  - D6：`out/artifacts/d6_consistency_double_round/20260405-133529`（两轮 `RoundPass=True`）。
- strict/no-delta 并排复验 PASS：`strict=20260405-140407`、`no-delta-ok=20260405-141319`（strict 为 `statics_detected=true`）。
- D6 非默认样本（`64.6.64.6 103.53.144.0/22 2620:fe::fe`）PASS：`out/artifacts/d6_consistency_double_round/20260405-142232`。
  - Round1 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-142619/20260405-142628/20260405-143120`。
  - Round2 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-143854/20260405-143903/20260405-144528`。
- 模板抽测 PASS（PowerShell + bash+grep）：
  - PowerShell 命中：`out/artifacts/oneclick_dryrun_guard/20260405-141319/{summary.txt,oneclick_dryrun.log}` 与 `out/artifacts/d6_consistency_double_round/20260405-142232/summary.csv`。
  - bash+grep 命中：同目录下 `key: value` / `key=value` 双格式字段持续可检索。

#### 23.28 2026-04-12 清单执行（2026-04-05）

- Daily 三任务（UI 串行）PASS：
  - local：`out/artifacts/oneclick_dryrun_guard/20260405-181156`（`result=pass`）。
  - build+sync no-delta-ok：`out/artifacts/oneclick_dryrun_guard/20260405-181215`（`statics_detected=false`、`smoke_result=pass`）。
  - D6：`out/artifacts/d6_consistency_double_round/20260405-182152`（两轮 `RoundPass=True`）。
- strict/no-delta 并排复验 PASS（串行留证）：`strict=20260405-190338`、`no-delta-ok=20260405-191302`（strict 为 `statics_detected=true`）。
- D6 非默认样本（`208.67.220.220 43.227.220.0/22 2620:fe::9`）PASS：`out/artifacts/d6_consistency_double_round/20260405-192648`。
  - Round1 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-193055/20260405-193104/20260405-193526`。
  - Round2 `STRICT/PREFLIGHT/TABLE_GUARD=20260405-194326/20260405-194335/20260405-194926`。
- 模板抽测 PASS（PowerShell + Git Bash grep）：
  - PowerShell 命中：`out/artifacts/oneclick_dryrun_guard/20260405-191302/{summary.txt,oneclick_dryrun.log}`；`summary.csv` 校验 `rows=2 bad=0`。
  - `bash.exe + grep` 命中：同目录下 `key: value` / `key=value` 字段及 `summary.csv` 的 `True` 结果行。

#### 23.29 Autopilot 无人值守三轮验证（2026-04-05）

- 目标：按“首选方案”仅执行测试链路（无 commit/push），连续 3 轮串行验证稳定性。
- 汇总目录：`out/artifacts/autopilot_three_round/20260405-203521`（`summary.txt` / `summary.csv`）。
- 汇总结果：`rounds_total=3`、`rounds_pass=3`、`result=pass`。
- 每轮时间戳（均无需 D6 重跑）：
  - Round1：`local=20260405-203522`、`no-delta=20260405-203523`、`D6=20260405-204536`、`D6Retried=false`。
  - Round2：`local=20260405-211436`、`no-delta=20260405-211438`、`D6=20260405-212321`、`D6Retried=false`。
  - Round3：`local=20260405-215702`、`no-delta=20260405-215704`、`D6=20260405-220657`、`D6Retried=false`。

#### 23.30 2026-04-13 开发切片（P0 观测字段增强，2026-04-05）

- 变更范围（in-scope）：`wc_preclass_emit_observation()` 仅增强观测字段，新增 `action_src` / `match_layer` / `fallback`。
- 不变范围（out-of-scope）：不改默认路由与终态语义；不改 `route_change` 判定；不改输出链（title/grep/fold）契约。
- 代码落点：`src/core/whois_query_exec.c`。
- 门禁结果（采用 strict 超集验证）：
  - Remote Strict（lto + smoke + sync + golden）：`out/artifacts/20260405-234432`。
  - 本地 hash：`PASS`；golden：`PASS`；referral check：`PASS`。
  - Step47 preflight：`out/artifacts/step47_preclass_preflight/20260405-234441`（`pass=4 fail=0 result=pass`）。
  - Preclass table guard：`out/artifacts/preclass_table_guard/20260405-234915`（`result=pass`）。
- 运行时抽检：`out/artifacts/20260405-234432/build_out/preclass_observe_debug_20260405.log` 命中 `action_src`、`match_layer`、`fallback`（命中计数均为 1）。

#### 23.31 2026-04-14 开发切片（P0 聚合稳定化，2026-04-06）

- 变更范围（in-scope）：为 `[PRECLASS]` 增加聚合稳定字段 `reason_code` / `confidence_code`，并将最小矩阵断言同步到新字段。
- 不变范围（out-of-scope）：不改默认路由与终态语义；不改 `PRECLASS-DECISION` 路由判定。
- 代码落点：
  - `src/core/whois_query_exec.c`（新增 `wc_preclass_confidence_code()` + `[PRECLASS]` 新字段输出）。
  - `tools/test/preclass_min_matrix.ps1`（新增 `ReasonCodeOk/ConfidenceCodeOk` 校验列）。
- 门禁结果（strict 超集 + 专项）PASS：
  - Remote Strict：`out/artifacts/20260406-001614`（`Local hash verify PASS`、`[golden] PASS`、`referral check PASS`）。
  - Step47 preflight：`out/artifacts/step47_preclass_preflight/20260406-001624`（`pass=4 fail=0 result=pass`）。
  - Preclass table guard：`out/artifacts/preclass_table_guard/20260406-002301`（`result=pass`）。
  - Preclass 最小矩阵：`out/artifacts/preclass_matrix/20260406-002332`（`pass=12 fail=0 result=pass`）。
- 运行时抽检：`out/artifacts/20260406-001614/build_out/preclass_reason_confidence_debug_20260406.log` 命中 `reason_code` 与 `confidence_code`（命中计数均为 1）。

#### 23.32 2026-04-15~2026-04-18 多轮可执行版收口（实际执行：2026-04-06）

- 执行口径：按 Round1~Round4 串行完成，保持“仅观测增强，不改默认路由/终态”与显式 `-h` 兼容优先。
- 关键修复：`tools/release/one_click_release.ps1` 修复 `RbSyncDir` 多目录透传、root path 防呆与单路径标量化误判，消除 `-s '/'` 异常。
- Round2 最小回归 PASS：
  - local（修复后）：`out/artifacts/oneclick_dryrun_guard/20260406-043842`
  - no-delta：`out/artifacts/oneclick_dryrun_guard/20260406-042639`
  - D6：`out/artifacts/d6_consistency_double_round/20260406-043848`（双轮 `RoundPass=True`）
- Round3 P1 健壮化 PASS：
  - P1 gate matrix：`out/artifacts/preclass_p1_matrix/20260406-050306`（`pass=232 fail=0 group_gate_fail=0`）
  - Step47（含 preclass-p1-gate）：`out/artifacts/step47_prerelease/20260406-050626`
- Round4 准发布链路 PASS：
  - one-click strict：`out/artifacts/oneclick_dryrun_guard/20260406-051011`
  - strict 产物：`out/artifacts/20260406-051450`
  - CIDR Bundle：`out/artifacts/cidr_bundle/cidr_bundle_summary_20260406-051848.txt`（`body_status=pass`，`matrix_status=pass`）
  - Redirect 10x6：`out/artifacts/redirect_matrix_10x6/20260406-051916`（`authority_*.txt` 为空，`errors_*.txt` 为 `(no errors found)`）
  - Step47：`out/artifacts/step47_prerelease/20260406-052449`
- 结论：本 RFC 第 23 节相关执行项已完成闭环，默认语义与输出契约保持稳定。

#### 23.33 稳妥档无人值守四轮复验（2026-04-06）

- 执行口径：复用稳妥档巡检模式，连续 4 轮串行执行 `local -> build+sync no-delta-ok -> D6`，仅执行门禁与证据沉淀，不引入代码改动。
- 汇总证据：`out/artifacts/autopilot_four_round/20260406-070404`（包含 `summary.txt`、`summary.csv` 与每轮日志）。
- 轮次结果：
  - Round1：`20260406-070405/070406/071337`，`RoundPass=True`
  - Round2：`20260406-073731/073732/074705`，`RoundPass=True`
  - Round3：`20260406-081253/081255/082259`，`RoundPass=True`
  - Round4：`20260406-084932/084933/085705`，`RoundPass=True`
- 结论：复验 4/4 全绿，默认语义与输出契约稳定；本轮保留产物变化供人工决定是否提交。

#### 23.34 无人值守清单回填同步（2026-04-09）

- 同步背景：根据 `docs/RFC-whois-client-split.md` 的“无人值守稳妥档（2026-04-09 ~ 2026-04-16）”执行口径，新增 source-driven skip（`D-NOP/D-SKIP/V-SKIP`）后完成一轮实跑回填。
- 执行入口：`powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_autopilot_8round_code_change.ps1`
- 证据目录：`out/artifacts/dev_verify_multiround/20260409-035646`
- 本轮结果：
  - `D1/D2/D3 = D-NOP`，且 `CodeStepAction=already-applied`、`SourceDeltaAfterCodeStep=unchanged`。
  - `D4 = D-SKIP`（触发 `d1-d3-all-d-nop`）。
  - `V1~V4 = V-SKIP`（触发 `global-no-source-change`）。
  - 汇总结论：`result=pass`，全链路按规则收口为 `no-source-change`。
- 阶段状态同步：当前任务切片已收口；若继续无人值守开发轮，需先重定义 `D1~D3` 的目标源码差异（目标文件/符号/验收点），否则将稳定复现 `D-NOP -> D-SKIP -> V-SKIP`。

#### 23.35 下一阶段设计启动（2026-04-09）

- 启动前提：23.34 已确认当前切片进入 `no-source-change` 收口；后续必须先定义可落地的源码差异目标，再进入新一轮开发。
- 设计目标：在不改变默认语义与输出契约前提下，重定义 D1~D3 三刀，使每轮都有可验证的源码差异与门禁闭环。

##### 23.35.1 D1（API 收敛与观测层解耦）

- 目标文件：`include/wc/wc_preclass.h`、`src/core/preclass.c`、`src/core/whois_query_exec.c`。
- 设计要点：
  - 统一 preclass 观测字段导出面，明确 `reason/reason_code` 与 `confidence/confidence_code` 的生成责任边界。
  - 减少 `whois_query_exec.c` 内联判断分支，将可复用字段映射下沉到 preclass 模块。
- 验收口径：显式 `-h` 兼容优先保持不变，默认路径不发生 route/auth 语义漂移。

##### 23.35.2 D2（决策函数化与动作来源统一）

- 目标文件：`src/core/whois_query_exec.c`（必要时配套 `src/core/preclass.c`）。
- 设计要点：
  - 将 trial/action 判定抽为独立函数，统一 `action_src/match_layer/fallback` 的赋值与兜底。
  - 保持 `--disable-address-preclass` 与显式 `-h` 旁路优先级不变。
- 验收口径：默认配置下 `route_change=0` 的稳定性断言必须持续成立。

##### 23.35.3 D3（一致性门禁补强）

- 目标范围：preclass reason/confidence 映射一致性、日志字段完整性、Step47 串联可断言性。
- 设计要点：
  - 将“表内 reason_id 可反查”“关键字段不缺失”固化为可执行门禁。
  - 将该门禁接入 Step47 串联检查，形成与 D6 一致的证据链。
- 验收口径：`group_gate_fail=0` 且新增一致性断言全部通过。

##### 23.35.4 执行规则（与无人值守脚本对齐）

1. 每轮开跑前必须声明 `目标文件/符号/验收点`。
2. 若轮次结束后 `src/**` 与 `include/**` 无差异，按 `D-NOP` 收口，不执行重门禁。
3. 仅在存在源码差异时执行完整 `local -> no-delta -> D6`，并保留 strict/preflight/table-guard 证据。
4. 若 `D1~D3` 全 `D-NOP`，保持 `no-source-change` 结论，不再重复消耗复检轮次。

#### 23.36 D1 第一刀落地（2026-04-09）

- 目标对齐：落实 23.35.1 的“API 收敛与观测层解耦”，先完成最小可验证改动，不触发默认语义变化。
- 代码落点：
  - `include/wc/wc_preclass.h`：新增统一导出 API `wc_preclass_observation_codes(...)`。
  - `src/core/preclass.c`：新增并集中维护 observation 映射（`reason_code/reason_key/confidence_code/confidence_rank`）。
  - `src/core/whois_query_exec.c`：移除重复静态映射函数，改为调用 `wc_preclass_observation_codes(...)`。
- 行为约束：
  - 仅重构映射责任边界，`[PRECLASS]` / `[PRECLASS-DECISION]` 输出字段与默认路由判定口径保持不变。
  - 显式 `-h` 兼容优先级与 `--disable-address-preclass` 回退优先级保持不变。
- 本轮验证：编辑器静态诊断通过（新增/修改文件无错误）。
- 阶段判定：D1 首刀已完成；下一步进入 D2（trial/action 决策函数化与动作来源统一）。

#### 23.37 D2 第二刀落地（2026-04-09）

- 目标对齐：落实 23.35.2，将 trial/action 决策逻辑函数化并统一动作来源字段。
- 代码落点：
  - `include/wc/wc_preclass.h`：新增 `wc_preclass_decision_fields_t` 与 `wc_preclass_resolve_decision_fields(...)`。
  - `src/core/preclass.c`：实现 `action/action_src/match_layer/fallback/route_change/input` 统一决策。
  - `src/core/whois_query_exec.c`：改为调用统一 API，移除重复内联决策分支。
  - `tools/test/autopilot_code_step_rounds.ps1`：补齐新旧代码形态幂等兼容，避免 D1/D2 正则步骤失配。
- 行为约束：默认语义与输出契约保持不变；显式 `-h` 与 `--disable-address-preclass` 旁路优先级保持不变。
- 本轮验证：无人值守重跑 `out/artifacts/dev_verify_multiround/20260409-053305`，`result=pass`。

#### 23.38 D3 第三刀落地（2026-04-09，传统方式先实现后验证）

- 目标对齐：落实 23.35.3，补强 reason/confidence 一致性门禁并纳入 Step47 串联检查。
- 代码落点：
  - `tools/test/preclass_table_guard.ps1`：新增表内 `reason_id/confidence_id` 反查完整性断言。
  - `tools/test/step47_prerelease_check.ps1`：新增 `-RunPreclassMinMatrix` 可选串联步骤。
  - `tools/test/step47_preclass_preflight_check.ps1`：新增 `gate-enabled-consistency-chain` 用例（table-guard + min-matrix + p1-gate）。
- 证据目录：
  - `out/artifacts/preclass_table_guard/20260409-055758`（`result=pass`，反查缺失为空）。
  - `out/artifacts/preclass_matrix/20260409-055809`（`pass=12 fail=0`）。
  - `out/artifacts/step47_preclass_preflight/20260409-055816`（`pass=5 fail=0`，串联用例通过）。
- 阶段判定：D3 已完成，23.35 的 D1~D3 设计目标全部落地。

#### 23.39 Strict 刷新与后 D3 完整无人值守验证（2026-04-09）

- strict 远程链路（`lto-auto` + smoke + sync + golden，含 `-K 1 -N 1`）执行通过：
  - 产物目录：`out/artifacts/20260409-061205`
  - 结论：`golden=PASS`、`Step47 preflight=PASS`、`Preclass table guard=PASS`
- 后 D3 验证批任务定义：
  - `testdata/autopilot_code_step_tasks_post_d3_validation_20260409.json`（D1~D4 固定 `noop`，避免误改码）
- 完整无人值守 8 轮执行：
  - 入口：`start_autopilot_8round_code_change.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_post_d3_validation_20260409.json`
  - 证据目录：`out/artifacts/dev_verify_multiround/20260409-062134`
  - 结论：`result=pass`，`D1~D3=D-NOP`、`D4=D-SKIP`、`V1~V4=V-SKIP`，按规则收口 `no-source-change`。

#### 23.40 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，2026-04-10 ~ 2026-04-17）

> 注：本清单用于“有新增源码差异目标”时启动；若当轮 `src/**` 与 `include/**` 无差异，按 `D-NOP/D-SKIP/V-SKIP` 规则收口。

**八轮通用约束（开跑前确认）**：
1. [x] 已完成 strict 刷新（`-K 1 -N 1`）并确认测试二进制更新（证据见 `out/artifacts/20260409-075254` 及后续轮次 strict 目录）。
2. [x] 已填写并使用任务定义文件（`testdata/autopilot_code_step_tasks_20260410_20260417.json`），无 `TODO_*`。
3. [x] 已按严格串行执行：`local -> build+sync no-delta-ok -> D6`，全 8 轮无硬失败中断。
4. [x] D6 重试上限约束生效（本次未触发超限重跑）。
5. [x] 已附带并通过 `preclass_table_guard + preclass_min_matrix + step47_preclass_preflight`。
6. [x] 运行期间未自动提交/推送，保持人工决策口径。

**开发四轮（D1~D4，允许最小改码）**：

**D1（2026-04-10）**
1. [x] 已完成目标收敛并落地到统一输出路径。
2. [x] 已命中目标文件/符号（主要变更落在 `src/core/preclass.c`）。
3. [x] 已完成 `input_label` 相关一致性改造并移除重复映射分支。
4. [x] 验收通过：`summary.csv` 显示 D1 为 `EXECUTE + applied + changed`。
5. [x] 条件未触发（本轮存在源码差异，未走 `D1=D-NOP`）。
6. [x] 已执行 `local -> no-delta -> D6` 且本轮通过。

**D2（2026-04-11）**
1. [x] 已完成 `PRECLASS-DECISION` 字段规范化目标。
2. [x] 已命中目标文件/符号（主要变更持续集中在 `src/core/preclass.c`）。
3. [x] 已完成决策字段 guard/helper 收敛，减少调用侧重复判断。
4. [x] 验收通过：`summary.csv` 显示 D2 为 `EXECUTE + applied + changed`。
5. [x] 已执行完整门禁并附带 `preclass_table_guard`。
6. [x] 已完成关键字段完整性回填与证据记录。

**D3（2026-04-12）**
1. [x] 已完成 D3 一致性链目标并验证通过。
2. [x] 已命中目标文件/符号与对应门禁脚本路径。
3. [x] 已完成 D3 计划内改造并保持孤儿 ID 非阻断策略。
4. [x] 验收通过：门禁结果满足 `missing_reverse_*_ids` 为空与 `preclass_min_matrix fail=0`。
5. [x] 已执行完整门禁并附 `preclass_min_matrix + step47_preclass_preflight`。
6. [x] 串联断言通过并完成 D3 证据回填。

**D4（2026-04-13）**
1. [x] 已完成开发阶段收口并输出可复跑 D 阶段基线。
2. [x] 已固化任务定义文件并完成幂等标记策略验证。
3. [x] 目标文件已落地：`testdata/autopilot_code_step_tasks_20260410_20260417.json` + `src/core/preclass.c`。
4. [x] 条件满足且已执行准发布链路，D 阶段总表通过。
5. [x] 条件未触发（D1~D3 非全 `D-NOP`，未走 `D-SKIP`）。

**复检四轮（V1~V4，只跑门禁与取证）**：

**V1（2026-04-14）**
1. [x] 已完成基线复检并与 D4 关键字段一致。

**V2（2026-04-15）**
1. [x] 已完成噪声窗口复检（本次未触发需分流重验的阻断异常）。

**V3（2026-04-16）**
1. [x] 已完成非默认样本复检，D6 双轮一致通过。

**V4（2026-04-17）**
1. [x] 已完成发布前收口复检并汇总（`rounds_total=8`、`rounds_pass=8`、`result=pass`）。
2. [x] 已同步回填 `docs/RFC-address-space-preclassifier.md` 与 `docs/RFC-whois-client-split.md`（`RELEASE_NOTES.md` 留待发布提交流程统一更新）。

**执行回填（2026-04-09，按 2026-04-10 ~ 2026-04-17 清单无人值守实跑）**：
- 执行入口：`powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_autopilot_8round_code_change.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20260410_20260417.json -KeyPath /d/LZProjects/whois/tmp/autopilot_id_rsa`
- 汇总目录：`out/artifacts/dev_verify_multiround/20260409-073910`
- 汇总结论：`rounds_total=8`、`rounds_pass=8`、`result=pass`
- D1~D3 真实改码结论：
  - D1：`CodeStepAction=applied`，`SourceDeltaAfterCodeStep=changed`
  - D2：`CodeStepAction=applied`，`SourceDeltaAfterCodeStep=changed`
  - D3：`CodeStepAction=applied`，`SourceDeltaAfterCodeStep=changed`
- D4/V1~V4：全部 `EXECUTE` 且 `RoundPass=True`（详见 `summary.csv`）。
- 轮次 evidence（autopilot 目录）：`20260409-073911`（D1）、`20260409-082341`（D2）、`20260409-090902`（D3）、`20260409-095438`（D4）、`20260409-104523`（V1）、`20260409-113500`（V2）、`20260409-121626`（V3）、`20260409-130635`（V4）。
- 代码与产物现状：源码差异集中在 `src/core/preclass.c`；执行期间同步刷新了 `release/lzispro/whois/*` 与 `SHA256SUMS-static.txt`，未自动提交/推送。

#### 23.41 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，2026-04-18 ~ 2026-04-25，已完成回填）

> 注：本清单基于 `out/artifacts/dev_verify_multiround/20260409-154303` 的实跑结果回填；目标是在不改变输出契约前提下推进预分类第二阶段硬化。若 `Dn` 未产生 `src/**` 与 `include/**` 源码差异，按 `D-NOP` 规则处理并回填原因。

**八轮通用约束（开跑前确认）**：
1. [x] strict 刷新链路已覆盖（`-K 1 -N 1` 口径），各轮 `D6Pass=True` 且 `RoundPass=True`。
2. [x] 已填写并使用任务定义文件：`testdata/autopilot_code_step_tasks_20260418_20260425.json`（`TaskDefinitionFile` 全轮一致，无 `TODO_*`）。
3. [x] D1~D3 已逐轮校验 `CodeStepAction` 与 `SourceDeltaAfterCodeStep`，结果均为 `applied + changed`。
4. [x] 全 8 轮均按固定串行执行 `local -> build+sync no-delta-ok -> D6`，无硬失败中断。
5. [x] 长耗时轮次已按“进程树 + artifact 心跳”规则复核后继续执行，最终完成全轮。
6. [x] 全程未自动提交/推送（仅产物刷新，提交决策保持人工口径）。

**开发四轮（D1~D4，允许最小改码）**：

**D1（2026-04-18）**
1. [x] 已完成 `input_label/action_source` 映射收敛目标并产生源码差异。
2. [x] 目标文件命中 `src/core/preclass.c`（`wc_preclass_resolve_decision_fields` 相关段）。
3. [x] 同类映射分支已收敛到 helper 路径，默认输出语义保持不变。
4. [x] 验收通过：`summary.csv` 中 D1 为 `EXECUTE + applied + changed`，并且本轮门禁链路通过。

**D2（2026-04-19）**
1. [x] 已完成 fallback 归一化路径收敛，避免 `none/empty` 口径漂移。
2. [x] 目标文件命中 `src/core/preclass.c`（含决策日志调用路径关联）。
3. [x] fallback 与 route_change 边界处理已统一，调用层重复兜底减少。
4. [x] 验收通过：`summary.csv` 中 D2 为 `EXECUTE + applied + changed`，本轮门禁链路通过。

**D3（2026-04-20）**
1. [x] 已完成 route-change 允许集合收敛目标并维持默认行为不变。
2. [x] 目标文件命中 `src/core/preclass.c`（route_change 判定路径）。
3. [x] 允许集合判定与未知动作回退已统一到单点路径。
4. [x] 验收通过：`summary.csv` 中 D3 为 `EXECUTE + applied + changed`，本轮门禁链路通过。

**D4（2026-04-21）**
1. [x] 已完成 D 阶段收口并形成可复跑基线。
2. [x] 任务定义文件按幂等策略执行完成。
3. [x] 验收通过：D4 结果为 `EXECUTE + already-applied + unchanged`，符合“D 阶段冻结”预期。

**复检四轮（V1~V4，只跑门禁与取证）**：

**V1（2026-04-22）**
1. [x] 基线复检完成：V1 `RoundPass=True`，与 D4 关键字段一致。

**V2（2026-04-23）**
1. [x] 噪声窗口复检完成：本轮未触发阻断型 `%ERROR:201/timeout`，`RoundPass=True`。

**V3（2026-04-24）**
1. [x] 非默认样本复检已完成；V3 查询集为 `64.6.64.6 103.53.144.0/22 2620:fe::fe`（v4 + v4 CIDR + v6），`RoundPass=True`（证据：`out/artifacts/autopilot_dev_recheck_8round/20260409-203629/summary.csv`）。

**V4（2026-04-25）**
1. [x] 发布前收口复检完成并汇总：`rounds_total=8`、`rounds_pass=8`、`result=pass`。
2. [x] 已同步回填 `docs/RFC-address-space-preclassifier.md`、`docs/RFC-whois-client-split.md`、`RELEASE_NOTES.md`。

**执行回填（2026-04-09，按 2026-04-18 ~ 2026-04-25 清单无人值守实跑）**：
- 任务定义文件：`testdata/autopilot_code_step_tasks_20260418_20260425.json`
- 执行入口：`powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_autopilot_8round_code_change.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20260418_20260425.json -KeyPath /d/LZProjects/whois/tmp/autopilot_id_rsa`
- 汇总目录：`out/artifacts/dev_verify_multiround/20260409-154303`
- 汇总结论：`rounds_total=8`、`rounds_pass=8`、`result=pass`
- 轮次结果（来自 `summary.csv`）：
  - D1：`EXECUTE`，`CodeStepAction=applied`，`SourceDeltaAfterCodeStep=changed`，`RoundPass=True`，autopilot 目录 `out/artifacts/autopilot_dev_recheck_8round/20260409-154304`
  - D2：`EXECUTE`，`CodeStepAction=applied`，`SourceDeltaAfterCodeStep=changed`，`RoundPass=True`，autopilot 目录 `out/artifacts/autopilot_dev_recheck_8round/20260409-163028`
  - D3：`EXECUTE`，`CodeStepAction=applied`，`SourceDeltaAfterCodeStep=changed`，`RoundPass=True`，autopilot 目录 `out/artifacts/autopilot_dev_recheck_8round/20260409-172216`
  - D4：`EXECUTE`，`CodeStepAction=already-applied`，`SourceDeltaAfterCodeStep=unchanged`，`RoundPass=True`，autopilot 目录 `out/artifacts/autopilot_dev_recheck_8round/20260409-180544`
  - V1：`EXECUTE`，`RoundPass=True`，autopilot 目录 `out/artifacts/autopilot_dev_recheck_8round/20260409-185246`
  - V2：`EXECUTE`，`RoundPass=True`，autopilot 目录 `out/artifacts/autopilot_dev_recheck_8round/20260409-194202`
  - V3：`EXECUTE`，`RoundPass=True`，autopilot 目录 `out/artifacts/autopilot_dev_recheck_8round/20260409-203629`
  - V4：`EXECUTE`，`RoundPass=True`，autopilot 目录 `out/artifacts/autopilot_dev_recheck_8round/20260409-212908`
- 清单复核结论：
  - 已完成：通用约束 6/6，开发轮 D1~D4 4/4，复检轮 V1~V4 4/4。
- 代码与产物现状：源码差异仍集中在 `src/core/preclass.c`；执行期间同步刷新了 `release/lzispro/whois/*` 与 `SHA256SUMS-static.txt`，未自动提交/推送。

#### 23.42 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，2026-04-26 ~ 2026-05-03，草案）

> 注：本清单沿用上一轮执行器与门禁口径；开发轮允许最小改码但不自动提交/推送，复检轮仅做门禁与取证。若 D1~D3 未产生 `src/**` 或 `include/**` 源码差异，按 `D-NOP` 规则回填原因并在 V 轮补证。
> 回填状态：2026-04-10 已执行；首跑在 V2 失败后按既有分流补跑 V2~V4，最终收敛 PASS。

**八轮通用约束（开跑前确认）**：
1. [x] strict 刷新链路保持开启（`-K 1 -N 1`），目标为全轮 `D6Pass=True` 且 `RoundPass=True`。
2. [x] 已准备并锁定任务定义文件：`testdata/autopilot_code_step_tasks_20260426_20260503.json`（全轮 `TaskDefinitionFile` 一致）。
3. [x] 采用固定串行链路 `local -> build+sync no-delta-ok -> D6`，禁止并行执行。
4. [x] D1~D3 每轮均留证 `CodeStepAction` 与 `SourceDeltaAfterCodeStep`，要求可解释且可回放。
5. [x] 全程保持人工提交口径（`AUTO_COMMIT=0`、`AUTO_PUSH=0`），仅允许产物刷新。
6. [x] VERIFY 轮默认使用 `-VerifyExecutionProfile d6-only`；如需扩证可切 `full`，但 V3 仍需保留混合样本复检。

**开发四轮（D1~D4，允许最小改码）**：

**D1（2026-04-26）**
1. [x] 新增 `wc_preclass_normalize_decision_action()`，收敛 `decision_action` 的默认值回落与赋值入口。
2. [x] 目标文件命中 `src/core/preclass.c`（必要时附带头文件声明同步）。
3. [x] 将 `out_fields->action` 改为统一 helper 写入，保留 `action_source=decision` 的既有触发条件。
4. [x] 验收通过：D1 结果满足 `EXECUTE + applied + changed` 且门禁链路通过。

**D2（2026-04-27）**
1. [x] 新增 `wc_preclass_policy_action_source()`，统一 `preclass_disabled` 路径的 `action_source` 赋值。
2. [x] 目标文件命中 `src/core/preclass.c` 与必要调用点。
3. [x] 覆盖 `if (!query || !*query)` 与常规 `preclass_disabled` 两个分支，消除重复硬编码字符串。
4. [x] 验收通过：D2 结果满足 `EXECUTE + applied + changed` 且门禁链路通过。

**D3（2026-04-28）**
1. [x] 新增 `wc_preclass_route_change_fallback()`，统一 route-change 被归零时的 fallback 写回逻辑。
2. [x] 目标文件命中 `src/core/preclass.c`，避免新增跨模块散点分叉。
3. [x] 将 `route-change-normalized` 条件写回由分支改为 helper 单点处理，保持输出语义不变。
4. [x] 验收通过：D3 结果满足 `EXECUTE + applied + changed` 且门禁链路通过。

**D4（2026-04-29）**
1. [x] 完成 D 阶段收口并形成可复跑基线。
2. [x] 任务定义按幂等策略执行完成，允许 `already-applied + unchanged`。
3. [x] 验收通过：D4 与前三轮证据链一致，可直接进入 V 轮。

**复检四轮（V1~V4，只跑门禁与取证）**：

**V1（2026-04-30）**
1. [x] 完成基线复检，要求关键字段与 D4 对齐且 `RoundPass=True`。

**V2（2026-05-01）**
1. [x] 完成噪声窗口复检；若出现 `%ERROR:201/timeout`，按既有分流口径补跑并留证。

**V3（2026-05-02）**
1. [x] 完成非默认样本复检，查询集固定为 `64.6.64.6 103.53.144.0/22 2620:fe::fe`（v4 + v4 CIDR + v6），并记录 D6 双轮一致结果。

**V4（2026-05-03）**
1. [x] 完成发布前收口复检并汇总（目标 `rounds_total=8`、`rounds_pass=8`、`result=pass`）。
2. [x] 完成 RFC 回填（至少 `docs/RFC-address-space-preclassifier.md` 与相关证据路径），发布说明按提交流程补齐。

**执行回填（Checklist A，2026-04-10）**：
- 任务定义文件：`testdata/autopilot_code_step_tasks_20260426_20260503.json`
- 首次执行目录：`out/artifacts/dev_verify_multiround/20260410-025505`
- 补跑收敛目录：`out/artifacts/dev_verify_multiround/20260410-065857`
- 首次执行结果：D1~D4、V1 通过；V2 失败（`ExitCode=1`，`RoundPass=False`）。
- 补跑结果：V2/V3/V4 全部通过（`RoundPass=True`）。
- 清单复核结论：8 轮已完成并收敛通过（含 V2 失败后补跑闭环）。

#### 23.43 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，2026-05-04 ~ 2026-05-11，草案，串行第 2 份）

> 注：本清单用于与上一份（2026-04-26 ~ 2026-05-03）按 A -> B 串行执行；保持无人值守、严格串行、失败即停。D1~D3 任务类型必须为 `regex-patch` 或 `builtin`，不得为 `noop`。
> 回填状态：2026-04-10 已执行并一次性 8/8 通过。

**八轮通用约束（开跑前确认）**：
1. [x] 与 A 清单串行执行，不并行；A 完成后再启动 B。
2. [x] strict 刷新链路保持开启（`-K 1 -N 1`），目标为全轮 `D6Pass=True` 且 `RoundPass=True`。
3. [x] 已准备并锁定任务定义文件：`testdata/autopilot_code_step_tasks_20260504_20260511.json`。
4. [x] D1~D3 任务类型核对通过：仅允许 `regex-patch` 或 `builtin`，不能是 `noop`。
5. [x] 全程保持人工提交口径（`AUTO_COMMIT=0`、`AUTO_PUSH=0`），仅允许产物刷新。
6. [x] VERIFY 轮提速参数固定：`-VerifyExecutionProfile d6-only`。
7. [x] 安全 skip 参数固定：`-EnableGateOnlySourceDrivenSkip:$true`。
8. [x] 采用固定串行链路 `local -> build+sync no-delta-ok -> D6`，禁止并行执行。

**开发四轮（D1~D4，允许最小改码）**：

**D1（2026-05-04）**
1. [x] 新增 `wc_preclass_default_action()`，收敛初始 `action` 默认值入口。
2. [x] 将 `out_fields->action = "observe-only";` 替换为 helper 调用。
3. [x] 目标文件命中 `src/core/preclass.c`，不改变输出契约。
4. [x] 验收通过：D1 结果满足 `EXECUTE + applied + changed`。

**D2（2026-05-05）**
1. [x] 新增 `wc_preclass_default_fallback_reason()`，收敛初始 `fallback_reason` 默认值入口。
2. [x] 将 `out_fields->fallback_reason = "no-decision-action";` 替换为 helper 调用。
3. [x] 目标文件命中 `src/core/preclass.c`，日志键名不漂移。
4. [x] 验收通过：D2 结果满足 `EXECUTE + applied + changed`。

**D3（2026-05-06）**
1. [x] 新增 `wc_preclass_default_input_label()`，收敛初始 `input_label` 默认值入口。
2. [x] 将 `out_fields->input_label = "non-ip";` 替换为 helper 调用。
3. [x] 目标文件命中 `src/core/preclass.c`，保持 IPv4/IPv6 契约不变。
4. [x] 验收通过：D3 结果满足 `EXECUTE + applied + changed`。

**D4（2026-05-07）**
1. [x] 冻结轮，保持 `noop`。
2. [x] 验收通过：D4 为 `EXECUTE + already-applied + unchanged` 或 `EXECUTE + applied + changed` 且门禁通过。

**复检四轮（V1~V4，只跑门禁与取证）**：

**V1（2026-05-08）**
1. [x] 基线复检完成，关键字段与 D4 对齐。

**V2（2026-05-09）**
1. [x] 噪声窗口复检完成；若出现 `%ERROR:201/timeout`，按既有分流口径补跑并留证。

**V3（2026-05-10）**
1. [x] 非默认样本复检完成，查询集固定为 `64.6.64.6 103.53.144.0/22 2620:fe::fe`。

**V4（2026-05-11）**
1. [x] 发布前收口复检完成并汇总（目标 `rounds_total=8`、`rounds_pass=8`、`result=pass`）。
2. [x] 完成 RFC 回填与证据目录补齐。

**执行回填（Checklist B，2026-04-10）**：
- 任务定义文件：`testdata/autopilot_code_step_tasks_20260504_20260511.json`
- 执行目录：`out/artifacts/dev_verify_multiround/20260410-084332`
- 轮次结果：D1~D4、V1~V4 全部 `EXECUTE + RoundPass=True`。
- 关键佐证：V2 轮 D6 目录 `out/artifacts/autopilot_dev_recheck_8round/20260410-104948`。
- 清单复核结论：一次性 8 轮通过，无需补跑。

#### 23.44 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，2026-05-12 ~ 2026-05-19，草案，串行第 3 份）

> 注：本清单为新一轮 A 清单，目标是与 23.45 形成 A -> B 严格串行执行。D1~D3 任务类型必须为 `regex-patch` 或 `builtin`，不得为 `noop`。
> 回填状态：2026-04-10 已执行并一次性收敛（`rounds_total=8`、`rounds_pass=8`、`result=pass`）。

**八轮通用约束（开跑前确认）**：
1. [x] 与 23.45 串行执行，本清单先执行。
2. [x] strict 刷新链路保持开启（`-K 1 -N 1`），目标为全轮 `D6Pass=True` 且 `RoundPass=True`。
3. [x] 已准备并锁定任务定义文件：`testdata/autopilot_code_step_tasks_20260512_20260519.json`。
4. [x] D1~D3 任务类型核对通过：仅允许 `regex-patch` 或 `builtin`，不能是 `noop`。
5. [x] VERIFY 提速参数固定：`-VerifyExecutionProfile d6-only`。
6. [x] 安全 skip 参数固定：`-EnableGateOnlySourceDrivenSkip:$true`。
7. [x] 全程保持人工提交口径（`AUTO_COMMIT=0`、`AUTO_PUSH=0`）。
8. [x] 采用固定串行链路 `local -> build+sync no-delta-ok -> D6`，禁止并行执行。

**开发四轮（D1~D4，允许最小改码）**：

**D1（2026-05-12）**
1. [x] 新增 `wc_preclass_default_match_layer()`，统一初始 `match_layer` 默认值入口。
2. [x] 将 `out_fields->match_layer = "non-ip";` 替换为 helper 调用。
3. [x] 目标文件命中 `src/core/preclass.c`，保持输出契约不变。
4. [x] 验收通过：`EXECUTE + applied + changed`。

**D2（2026-05-13）**
1. [x] 新增 `wc_preclass_default_action_source()`，统一初始 `action_source` 默认值入口。
2. [x] 将 `out_fields->action_source = wc_preclass_normalize_action_source("default");` 替换为 helper 调用。
3. [x] 目标文件命中 `src/core/preclass.c`，日志键名不漂移。
4. [x] 验收通过：`EXECUTE + applied + changed`。

**D3（2026-05-14）**
1. [x] 新增 `wc_preclass_default_route_change()`，统一初始 `route_change` 默认值入口。
2. [x] 将默认块中的 `out_fields->route_change = 0;` 替换为 helper 调用。
3. [x] 目标文件命中 `src/core/preclass.c`，不改变 route-change 语义。
4. [x] 验收通过：`EXECUTE + applied + changed`。

**D4（2026-05-15）**
1. [x] 冻结轮，保持 `noop`。
2. [x] 验收通过：`EXECUTE + already-applied + unchanged`。

**复检四轮（V1~V4，只跑门禁与取证）**：

**V1（2026-05-16）**
1. [x] 基线复检完成，关键字段与 D4 对齐。

**V2（2026-05-17）**
1. [x] 噪声窗口复检按 fast-skip 执行，结果为 `V-SKIP + RoundPass=True`（`fast-skip-v2-d-nop-count-0-of-3`）。

**V3（2026-05-18）**
1. [x] 非默认样本复检完成，查询集固定为 `64.6.64.6 103.53.144.0/22 2620:fe::fe`。

**V4（2026-05-19）**
1. [x] 发布前收口复检完成并汇总（`rounds_total=8`、`rounds_pass=8`、`result=pass`）。
2. [x] 完成 RFC 回填与证据目录补齐。

**执行回填（Checklist A，2026-04-10）**：
- 任务定义文件：`testdata/autopilot_code_step_tasks_20260512_20260519.json`
- 执行目录：`out/artifacts/dev_verify_multiround/20260410-180931`
- 轮次结果：D1~D4、V1、V3、V4 均为 `EXECUTE + RoundPass=True`；V2 为 `V-SKIP + RoundPass=True`。
- 关键佐证：D1~D3 为 `CodeStepAction=applied + SourceDeltaAfterCodeStep=changed`，D4 为 `already-applied + unchanged`。
- 清单复核结论：一次性 8 轮通过，无需补跑。

#### 23.45 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，2026-05-20 ~ 2026-05-27，草案，串行第 4 份）

> 注：本清单为新一轮 B 清单，仅在 23.44 完成后启动。D1~D3 任务类型必须为 `regex-patch` 或 `builtin`，不得为 `noop`。
> 回填状态：2026-04-10 已执行并一次性收敛（`rounds_total=8`、`rounds_pass=8`、`result=pass`）。

**八轮通用约束（开跑前确认）**：
1. [x] 与 23.44 串行执行，不并行；23.44 完成后再执行本清单。
2. [x] strict 刷新链路保持开启（`-K 1 -N 1`），目标为全轮 `D6Pass=True` 且 `RoundPass=True`。
3. [x] 已准备并锁定任务定义文件：`testdata/autopilot_code_step_tasks_20260520_20260527.json`。
4. [x] D1~D3 任务类型核对通过：仅允许 `regex-patch` 或 `builtin`，不能是 `noop`。
5. [x] VERIFY 提速参数固定：`-VerifyExecutionProfile d6-only`。
6. [x] 安全 skip 参数固定：`-EnableGateOnlySourceDrivenSkip:$true`。
7. [x] 全程保持人工提交口径（`AUTO_COMMIT=0`、`AUTO_PUSH=0`）。
8. [x] 采用固定串行链路 `local -> build+sync no-delta-ok -> D6`，禁止并行执行。

**开发四轮（D1~D4，允许最小改码）**：

**D1（2026-05-20）**
1. [x] 新增 `wc_preclass_decision_action_source()`，封装 decision 分支 action_source 字面量。
2. [x] 将 `out_fields->action_source = "decision";` 替换为 helper 调用。
3. [x] 目标文件命中 `src/core/preclass.c`，保持输出语义不变。
4. [x] 验收通过：`EXECUTE + applied + changed`。

**D2（2026-05-21）**
1. [x] 新增 `wc_preclass_disabled_fallback_reason()`，统一 preclass-disabled fallback 写回。
2. [x] 将两个 preclass-disabled 分支中的 fallback 赋值替换为 helper 调用。
3. [x] 目标文件命中 `src/core/preclass.c`，日志键名不漂移。
4. [x] 验收通过：`EXECUTE + applied + changed`。

**D3（2026-05-22）**
1. [x] 新增 `wc_preclass_decision_none_fallback_reason()`，封装 decision 分支 `none` fallback 归一化。
2. [x] 将 `wc_preclass_normalize_fallback_reason("none")` 调用替换为 helper 调用。
3. [x] 目标文件命中 `src/core/preclass.c`，不改变 fallback 语义。
4. [x] 验收通过：`EXECUTE + applied + changed`。

**D4（2026-05-23）**
1. [x] 冻结轮，保持 `noop`。
2. [x] 验收通过：`EXECUTE + already-applied + unchanged`。

**复检四轮（V1~V4，只跑门禁与取证）**：

**V1（2026-05-24）**
1. [x] 基线复检完成，关键字段与 D4 对齐。

**V2（2026-05-25）**
1. [x] 噪声窗口复检按 fast-skip 执行，结果为 `V-SKIP + RoundPass=True`（`fast-skip-v2-d-nop-count-0-of-3`）。

**V3（2026-05-26）**
1. [x] 非默认样本复检完成，查询集固定为 `64.6.64.6 103.53.144.0/22 2620:fe::fe`。

**V4（2026-05-27）**
1. [x] 发布前收口复检完成并汇总（`rounds_total=8`、`rounds_pass=8`、`result=pass`）。
2. [x] 完成 RFC 回填与证据目录补齐。

**执行回填（Checklist B，2026-04-10）**：
- 任务定义文件：`testdata/autopilot_code_step_tasks_20260520_20260527.json`
- 执行目录：`out/artifacts/dev_verify_multiround/20260410-223605`
- 轮次结果：D1~D4、V1、V3、V4 均为 `EXECUTE + RoundPass=True`；V2 为 `V-SKIP + RoundPass=True`。
- 关键佐证：D1~D3 为 `CodeStepAction=applied + SourceDeltaAfterCodeStep=changed`，D4 为 `already-applied + unchanged`。
- 清单复核结论：一次性 8 轮通过，无需补跑。

#### 23.46 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，2026-05-28 ~ 2026-06-04，草案，串行第 5 份，Checklist A）

> 注：本清单为新一轮 A 清单，仅用于“提高任务设计质量”实战验证；与下一份 B 清单按 A -> B 严格串行执行。D1~D3 必须为 `regex-patch` 或 `builtin`，不得为 `noop`。

**八轮通用约束（开跑前确认）**：
1. [x] 串行约束：仅在上一批次收口后启动本清单，且全程失败即停（首轮在 D4 失败即停，已于 2026-04-15 完成完整收口）。
2. [x] 任务定义文件固定：`testdata/autopilot_code_step_tasks_20260528_20260604.json`。
3. [x] 任务设计质量策略固定：`-TaskDesignQualityPolicy enforce`。
4. [x] no-op 分级与预算固定：
  - 安全 no-op 类别：`absorbed-by-prior-round`、`idempotent-replay`。
  - 未知 no-op 类别：`unknown-unexplained`。
  - 预算参数：`-UnknownNoOpBudget 1`、`-UnknownNoOpConsecutiveLimit 2`、`-DisableUnknownNoOpBudgetGate:$false`。
5. [x] VERIFY 提速参数固定：`-VerifyExecutionProfile d6-only`。
6. [x] 安全 skip 参数固定：`-EnableGateOnlySourceDrivenSkip:$true`。
7. [x] 全程保持稳妥档 AUTO 口径：`AUTO_APPROVAL_ONCE=1`、`AUTO_CODE_CHANGE=1`、`AUTO_COMMIT=0`、`AUTO_PUSH=0`。
8. [x] 固定串行门禁链路：`local -> build+sync no-delta-ok -> D6`（D2/D3 受误判 D-NOP 影响未进入该链路）。

**开发四轮（D1~D4，允许最小改码）**：

**D1（2026-05-28）**
1. [x] 新增 `wc_preclass_match_layer_cidr_literal()`，封装 CIDR 的 `match_layer` 字面量。
2. [x] 将 `query_is_cidr ? "cidr" : "ip"` 的 CIDR 分支替换为 helper 调用。
3. [x] 验收目标：`EXECUTE + applied + changed`。

**D2（2026-05-29）**
1. [x] 新增 `wc_preclass_match_layer_ip_literal()`，封装 IP 的 `match_layer` 字面量。
2. [x] 将上一轮改造后的 IP 分支替换为 helper 调用。
3. [x] 验收目标：`EXECUTE + applied + changed`（外层记录达成；内层误判为 D-NOP）。

**D3（2026-05-30）**
1. [x] 新增 `wc_preclass_disabled_route_change_reset()`，统一 preclass-disabled 分支 route_change 清零。
2. [x] 将 disabled 分支中的 `route_change = 0` 替换为 helper 调用。
3. [x] 验收目标：`EXECUTE + applied + changed`（外层记录达成；内层误判为 D-NOP）。

**D4（2026-05-31）**
1. [x] 冻结轮，保持 `noop`。
2. [x] 验收目标：`EXECUTE + already-applied + unchanged`（轮次后续 D6 失败，按失败即停收口）。

**复检四轮（V1~V4，只跑门禁与取证）**：

**V1（2026-06-01）**
1. [x] 基线复检：关键字段与 D4 对齐，`RoundPass=True`（首轮未执行，2026-04-15 已补齐并通过）。

**V2（2026-06-02）**
1. [x] 噪声窗口复检：允许 fast-skip，但必须记录 skip reason 与 no-op 分类证据（首轮未执行，2026-04-15 已补齐并通过）。

**V3（2026-06-03）**
1. [x] 非默认样本复检：固定查询集 `64.6.64.6 103.53.144.0/22 2620:fe::fe`（首轮未执行，2026-04-15 已补齐并通过）。

**V4（2026-06-04）**
1. [x] 发布前收口复检：目标 `rounds_total=8`、`rounds_pass=8`、`result=pass`（2026-04-15 已完成并通过）。
2. [x] 回填 RFC：记录 evidence 目录与 no-op 分级统计字段（2026-04-15 已完成）。

**执行回填（2026-04-11，Checklist A 首次执行到 D4）**：
- 执行入口：`tools/test/start_autopilot_8round_code_change.ps1 -TaskDefinitionFile testdata/autopilot_code_step_tasks_20260528_20260604.json -VerifyExecutionProfile d6-only -EnableGateOnlySourceDrivenSkip:$true -TaskDesignQualityPolicy enforce -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2`。
- 汇总目录：`out/artifacts/dev_verify_multiround/20260411-073131`。
- D1：`EXECUTE`，`CodeStepAction=applied`，并执行完整门禁链路（`RoundPass=True`）。
- D2：外层 code-step 后存在源码增量（`SourceDeltaAfterCodeStep=changed`），但该轮内层 gate-only 复核被记为 `D-NOP`，未触发 `local/no-delta/D6`（见 `out/artifacts/autopilot_dev_recheck_8round/20260411-081937/summary.csv`）。
- D3：同 D2，外层记录有源码增量，但内层 gate-only 复核被记为 `D-NOP`，未触发 `local/no-delta/D6`（见 `out/artifacts/autopilot_dev_recheck_8round/20260411-081939/summary.csv`）。
- D4：执行并失败停止（`out/artifacts/autopilot_dev_recheck_8round/20260411-081941/summary.csv`，`RoundPass=False`）。
- V1~V4：未执行（受 D4 失败即停约束）。
- 口径说明：D2/D3 的 `applied/EXECUTE` 与 `D-NOP` 冲突已定位为编排层“外层 code-step 与内层 gate-only 跳过判定重复生效”导致。

**执行回填（2026-04-15，Checklist A 完整收口）**：
- 任务定义文件：`testdata/autopilot_code_step_tasks_20260528_20260604.json`。
- 完整执行目录：`out/artifacts/dev_verify_multiround/20260415-175235`。
- 最终结果：`final_status.json` 为 `Result=pass`、`CompletedRoundCount=8`。
- 轮次摘要：`summary.csv` 显示 D1~D3 为 `CodeStepAction=applied + SourceDeltaAfterCodeStep=changed`，D4 为 `already-applied + unchanged`，V1~V4 均为 `EXECUTE + RoundPass=True`。
- 收口结论：Checklist A 已完成“开发四轮 + 复检四轮”全量收口，可无缝衔接 Checklist B。

#### 23.47 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，2026-06-05 ~ 2026-06-12，草案，串行第 6 份，Checklist B）

> 注：本清单为新一轮 B 清单，仅在 Checklist A 完成后启动；保持同一 no-op 分级预算口径与提速参数，验证串行迭代稳定性。
> 状态更新（2026-04-16）：Checklist B 已完成回填；首次执行 D1 失败后，按 state-only 重启完成 8/8 收口。
> 连续累积模式说明：B 入口传 `-ResetCodeStepState -CodeStepResetPolicy state-only`，仅清 code-step 状态而不回退源码；因此可承接 A 的改动继续执行，A -> B 之间无需额外提交。
> 强制防误跑规则（2026-04-15）：当轮次覆盖 D1（`-StartRound <= 1`）时，A（`restore-source`）与 B（`state-only`）都必须显式传 `-ResetCodeStepState`；若遗漏且 `out/artifacts/autopilot_dev_recheck_8round/_code_step_state/state.json` 中检测到历史 `invocationCount > 0`，入口脚本会 fail-fast 终止。
> 提速护栏说明：当 `-EnableGuardedFastMode $true` 且 `-VerifyExecutionProfile d6-only` 时，`D2/D3` 执行 `strict-only` 轻量 gate，`D4` 与 `V1` 禁止快跳并强制执行 `full` gate，`V2~V4` 保持 `d6-only`。

> 轮次口径补充：`MAX_ROUNDS=4` 仅表示开发轮 D1~D4；A/B checklist 执行口径为 8 轮（D1~D4 + V1~V4，对应 `-StartRound 1 -EndRound 8`）。

**八轮通用约束（开跑前确认）**：
1. [x] 串行约束：仅在 Checklist A 完成后启动，不并行。
2. [x] 任务定义文件固定：`testdata/autopilot_code_step_tasks_20260605_20260612.json`。
3. [x] 任务设计质量策略固定：`-TaskDesignQualityPolicy enforce`。
4. [x] no-op 分级与预算固定：
  - 安全 no-op 类别：`absorbed-by-prior-round`、`idempotent-replay`。
  - 未知 no-op 类别：`unknown-unexplained`。
  - 预算参数：`-UnknownNoOpBudget 1`、`-UnknownNoOpConsecutiveLimit 2`、`-DisableUnknownNoOpBudgetGate:$false`。
5. [x] VERIFY 提速参数固定：`-VerifyExecutionProfile d6-only`。
6. [x] 安全 skip 参数固定：`-EnableGateOnlySourceDrivenSkip:$true`。
7. [x] 全程保持稳妥档 AUTO 口径：`AUTO_APPROVAL_ONCE=1`、`AUTO_CODE_CHANGE=1`、`AUTO_COMMIT=0`、`AUTO_PUSH=0`。
8. [x] 固定串行门禁链路：`D1/D4/V1=full gate`，`D2/D3=strict-only light gate`，`V2~V4=d6-only`。

**开发四轮（D1~D4，允许最小改码）**：

**D1（2026-06-05）**
1. [x] 新增 `wc_preclass_hint_disabled_action_literal()`，统一 hint-disabled action 字面量。
2. [x] 替换两个 preclass-disabled 分支中的 `out_fields->action = "hint-disabled"`。
3. [x] 新增 `wc_preclass_hint_disabled_action_source()`，并替换两处 disabled 分支 action_source 赋值为 helper 调用。
4. [x] 验收目标：`EXECUTE + applied + changed`。

**D2（2026-06-06）**
1. [x] 新增 `wc_preclass_route_change_block_reset()`，封装 route-change block 的清零值。
2. [x] 将 not-allowed 分支中的 `out_fields->route_change = 0` 替换为 helper 调用。
3. [x] 新增 `wc_preclass_route_change_fallback_apply()`，并将 route-change 归一化分支 fallback 写回替换为 helper 调用。
4. [x] 验收目标：`EXECUTE + applied + changed`。

**D3（2026-06-07）**
1. [x] 新增 `wc_preclass_fallback_none_literal()`，封装 fallback `none` 字面量。
2. [x] 将 `wc_preclass_route_change_fallback` 的 `strcmp(..., "none")` 判断替换为 helper 调用。
3. [x] 新增 `wc_preclass_decision_none_literal()`，并将 decision 分支 `none` fallback 归一化改为 helper 路由。
4. [x] 验收目标：`EXECUTE + applied + changed`。

**D4（2026-06-08）**
1. [x] 冻结轮，保持 `noop`。
2. [x] 验收目标：`EXECUTE + already-applied + unchanged`。

**复检四轮（V1~V4，只跑门禁与取证）**：

**V1（2026-06-09）**
1. [x] 基线复检：关键字段与 D4 对齐，`RoundPass=True`。

**V2（2026-06-10）**
1. [x] 噪声窗口复检：已执行并通过（见下方执行回填与 `summary.csv`）。

**V3（2026-06-11）**
1. [x] 非默认样本复检：固定查询集 `64.6.64.6 103.53.144.0/22 2620:fe::fe`。

**V4（2026-06-12）**
1. [x] 发布前收口复检：目标 `rounds_total=8`、`rounds_pass=8`、`result=pass`。
2. [x] 回填 RFC：记录 evidence 目录与 no-op 分级统计字段。

**执行回填（2026-04-15 ~ 2026-04-16，Checklist B）**：
- 任务定义文件：`testdata/autopilot_code_step_tasks_20260605_20260612.json`。
- 首次执行目录：`out/artifacts/dev_verify_multiround/20260415-232520`，`final_status.json` 为 `Result=fail`、`FailedRoundTags=["D1"]`。
- 重启执行口径：`-ResetCodeStepState -CodeStepResetPolicy state-only`（仅重置 code-step 状态，不回退源码）。
- 重启执行目录：`out/artifacts/dev_verify_multiround/20260416-003754`，`final_status.json` 为 `Result=pass`、`CompletedRoundCount=8`。
- 轮次摘要：`summary.csv` 显示 D1 为 `already-applied + unchanged`，D2~D3 为 `applied + changed`，D4 为 `already-applied + unchanged`，V1~V4 均为 `EXECUTE + RoundPass=True`。
- 收口结论：Checklist B 已完成“失败可恢复、恢复可收口”的 8 轮闭环。

**AUTO 会话预置模板（PowerShell，当前终端会话生效）**：

```powershell
# Core policy
$env:AUTO_APPROVAL_ONCE = "1"
$env:AUTO_CODE_CHANGE = "1"
$env:AUTO_COMMIT = "0"
$env:AUTO_PUSH = "0"
$env:AUTO_DEV_MAX_ROUNDS = "4"
$env:AUTO_TOTAL_ROUNDS = "8"
$env:AUTO_START_ROUND = "1"
$env:AUTO_END_ROUND = "8"

# A/B checklist + gate knobs
$env:AUTO_TASK_FILE_A = "testdata/autopilot_code_step_tasks_20260528_20260604.json"
$env:AUTO_TASK_FILE_B = "testdata/autopilot_code_step_tasks_20260605_20260612.json"
$env:AUTO_CODESTEP_RESET_POLICY_A = "restore-source"
$env:AUTO_CODESTEP_RESET_POLICY_B = "state-only"
$env:AUTO_DEV_VERIFY_STRIDE_A = "1"
$env:AUTO_DEV_VERIFY_STRIDE_B = "2"
$env:AUTO_VERIFY_EXECUTION_PROFILE = "d6-only"
$env:AUTO_ENABLE_GUARDED_FAST_MODE_A = "1"
$env:AUTO_ENABLE_GUARDED_FAST_MODE_B = "1"
$env:AUTO_ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP = "1"
$env:AUTO_TASK_DESIGN_QUALITY_POLICY = "enforce"
$env:AUTO_UNKNOWN_NOOP_BUDGET = "1"
$env:AUTO_UNKNOWN_NOOP_CONSECUTIVE_LIMIT = "2"
$env:AUTO_DISABLE_UNKNOWN_NOOP_BUDGET_GATE = "0"
$env:AUTO_RB_PREFLIGHT = "1"
$env:AUTO_RB_PRECLASS_TABLE_GUARD = "1"

# Remote + workload defaults
$env:AUTO_REMOTE_IP = "10.0.0.199"
$env:AUTO_REMOTE_USER = "larson"
$env:AUTO_REMOTE_KEYPATH = "/c/Users/妙妙呜/.ssh/id_rsa"
$env:AUTO_QUERIES = "8.8.8.8 1.1.1.1 10.0.0.8"

# Verify in-session variables
Get-ChildItem Env:AUTO_* | Sort-Object Name
```

**AUTO 会话预置模板（Bash，当前终端会话生效）**：

```bash
# Core policy
export AUTO_APPROVAL_ONCE=1
export AUTO_CODE_CHANGE=1
export AUTO_COMMIT=0
export AUTO_PUSH=0
export AUTO_DEV_MAX_ROUNDS=4
export AUTO_TOTAL_ROUNDS=8
export AUTO_START_ROUND=1
export AUTO_END_ROUND=8

# A/B checklist + gate knobs
export AUTO_TASK_FILE_A=testdata/autopilot_code_step_tasks_20260528_20260604.json
export AUTO_TASK_FILE_B=testdata/autopilot_code_step_tasks_20260605_20260612.json
export AUTO_CODESTEP_RESET_POLICY_A=restore-source
export AUTO_CODESTEP_RESET_POLICY_B=state-only
export AUTO_DEV_VERIFY_STRIDE_A=1
export AUTO_DEV_VERIFY_STRIDE_B=2
export AUTO_VERIFY_EXECUTION_PROFILE=d6-only
export AUTO_ENABLE_GUARDED_FAST_MODE_A=1
export AUTO_ENABLE_GUARDED_FAST_MODE_B=1
export AUTO_ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP=1
export AUTO_TASK_DESIGN_QUALITY_POLICY=enforce
export AUTO_UNKNOWN_NOOP_BUDGET=1
export AUTO_UNKNOWN_NOOP_CONSECUTIVE_LIMIT=2
export AUTO_DISABLE_UNKNOWN_NOOP_BUDGET_GATE=0
export AUTO_RB_PREFLIGHT=1
export AUTO_RB_PRECLASS_TABLE_GUARD=1

# Remote + workload defaults
export AUTO_REMOTE_IP=10.0.0.199
export AUTO_REMOTE_USER=larson
export AUTO_REMOTE_KEYPATH=/c/Users/妙妙呜/.ssh/id_rsa
export AUTO_QUERIES='8.8.8.8 1.1.1.1 10.0.0.8'

# Verify in-session variables
env | grep '^AUTO_'
```

**AUTO 映射口径（A/B 入口）**：
- 当前入口脚本不直接读取 `AUTO_*`；执行时需映射为显式参数传给 `tools/test/start_dev_verify_8round_multiround.ps1`。
- `AUTO_TASK_FILE_A/B` -> `-TaskDefinitionFile`
- `AUTO_CODESTEP_RESET_POLICY_A/B` -> `-CodeStepResetPolicy`
- `AUTO_START_ROUND/AUTO_END_ROUND` -> `-StartRound/-EndRound`
- `AUTO_DEV_VERIFY_STRIDE_A/B` -> `-DevVerifyStride`
- `AUTO_VERIFY_EXECUTION_PROFILE` -> `-VerifyExecutionProfile`
- `AUTO_ENABLE_GUARDED_FAST_MODE_A/B` -> `-EnableGuardedFastMode`
- `AUTO_ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP` -> `-EnableGateOnlySourceDrivenSkip`
- `AUTO_RB_PREFLIGHT` / `AUTO_RB_PRECLASS_TABLE_GUARD` -> `-RbPreflight` / `-RbPreclassTableGuard`（未显式设置时默认均为 `1`）
- `AUTO_TASK_DESIGN_QUALITY_POLICY` -> `-TaskDesignQualityPolicy`
- `AUTO_UNKNOWN_NOOP_BUDGET` / `AUTO_UNKNOWN_NOOP_CONSECUTIVE_LIMIT` / `AUTO_DISABLE_UNKNOWN_NOOP_BUDGET_GATE` -> 对应 no-op 预算参数
- `AUTO_REMOTE_IP/AUTO_REMOTE_USER/AUTO_REMOTE_KEYPATH` -> `-RemoteIp/-User/-KeyPath`

**工作前置清单（A/B 开跑前）**：
1. 工作区干净：`git status --short` 为空。
2. 两份任务文件存在且可解析：`testdata/autopilot_code_step_tasks_20260528_20260604.json`、`testdata/autopilot_code_step_tasks_20260605_20260612.json`。
3. 任务文件无 `TODO_*` 占位。
4. 远端连通可用（SSH 可达）且输出目录可写。
5. A/B 只要覆盖 D1，命令中都必须显式包含 `-ResetCodeStepState`（不得省略该开关）。

**两份清单串行入口（A 未启用“每轮更多改码内容”，B 启用该策略；d6-only + 安全 skip + no-op 预算门禁）**：

> 累积验证口径：A 使用 `-ResetCodeStepState -CodeStepResetPolicy restore-source`；B 使用 `-ResetCodeStepState -CodeStepResetPolicy state-only`。
> AUTO 变量口径：入口脚本不直接消费 `AUTO_*`，需在会话内先预置变量，再映射为显式参数传入。

```powershell
# Variable-driven template (PowerShell)
# Checklist A
& .\tools\test\start_dev_verify_8round_multiround.ps1 `
  -ResetCodeStepState `
  -CodeStepResetPolicy $env:AUTO_CODESTEP_RESET_POLICY_A `
  -TaskDefinitionFile $env:AUTO_TASK_FILE_A `
  -StartRound ([int]$env:AUTO_START_ROUND) -EndRound ([int]$env:AUTO_END_ROUND) `
  -DevVerifyStride ([int]$env:AUTO_DEV_VERIFY_STRIDE_A) `
  -VerifyExecutionProfile $env:AUTO_VERIFY_EXECUTION_PROFILE `
  -EnableGuardedFastMode:([int]$env:AUTO_ENABLE_GUARDED_FAST_MODE_A -eq 1) `
  -EnableGateOnlySourceDrivenSkip:([int]$env:AUTO_ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP -eq 1) `
  -TaskDesignQualityPolicy $env:AUTO_TASK_DESIGN_QUALITY_POLICY `
  -UnknownNoOpBudget ([int]$env:AUTO_UNKNOWN_NOOP_BUDGET) `
  -UnknownNoOpConsecutiveLimit ([int]$env:AUTO_UNKNOWN_NOOP_CONSECUTIVE_LIMIT) `
  -DisableUnknownNoOpBudgetGate:([int]$env:AUTO_DISABLE_UNKNOWN_NOOP_BUDGET_GATE -eq 1) `
  -RbPreflight $env:AUTO_RB_PREFLIGHT -RbPreclassTableGuard $env:AUTO_RB_PRECLASS_TABLE_GUARD `
  -QuietTerminalOutput "true" `
  -QuietRemoteBuildLogs "false" `
  -KeyPath $env:AUTO_REMOTE_KEYPATH -RemoteIp $env:AUTO_REMOTE_IP -User $env:AUTO_REMOTE_USER -Queries $env:AUTO_QUERIES

# Checklist B
& .\tools\test\start_dev_verify_8round_multiround.ps1 `
  -ResetCodeStepState `
  -CodeStepResetPolicy $env:AUTO_CODESTEP_RESET_POLICY_B `
  -TaskDefinitionFile $env:AUTO_TASK_FILE_B `
  -StartRound ([int]$env:AUTO_START_ROUND) -EndRound ([int]$env:AUTO_END_ROUND) `
  -DevVerifyStride ([int]$env:AUTO_DEV_VERIFY_STRIDE_B) `
  -VerifyExecutionProfile $env:AUTO_VERIFY_EXECUTION_PROFILE `
  -EnableGuardedFastMode:([int]$env:AUTO_ENABLE_GUARDED_FAST_MODE_B -eq 1) `
  -EnableGateOnlySourceDrivenSkip:([int]$env:AUTO_ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP -eq 1) `
  -TaskDesignQualityPolicy $env:AUTO_TASK_DESIGN_QUALITY_POLICY `
  -UnknownNoOpBudget ([int]$env:AUTO_UNKNOWN_NOOP_BUDGET) `
  -UnknownNoOpConsecutiveLimit ([int]$env:AUTO_UNKNOWN_NOOP_CONSECUTIVE_LIMIT) `
  -DisableUnknownNoOpBudgetGate:([int]$env:AUTO_DISABLE_UNKNOWN_NOOP_BUDGET_GATE -eq 1) `
  -RbPreflight $env:AUTO_RB_PREFLIGHT -RbPreclassTableGuard $env:AUTO_RB_PRECLASS_TABLE_GUARD `
  -QuietTerminalOutput "true" `
  -QuietRemoteBuildLogs "false" `
  -KeyPath $env:AUTO_REMOTE_KEYPATH -RemoteIp $env:AUTO_REMOTE_IP -User $env:AUTO_REMOTE_USER -Queries $env:AUTO_QUERIES
```

```bash
# Variable-driven template (Bash -> PowerShell)
cat <<'PS' | powershell.exe -NoProfile -ExecutionPolicy Bypass -
$ErrorActionPreference = 'Stop'

# Checklist A
& .\tools\test\start_dev_verify_8round_multiround.ps1 `
  -ResetCodeStepState `
  -CodeStepResetPolicy $env:AUTO_CODESTEP_RESET_POLICY_A `
  -TaskDefinitionFile $env:AUTO_TASK_FILE_A `
  -StartRound ([int]$env:AUTO_START_ROUND) -EndRound ([int]$env:AUTO_END_ROUND) `
  -DevVerifyStride ([int]$env:AUTO_DEV_VERIFY_STRIDE_A) `
  -VerifyExecutionProfile $env:AUTO_VERIFY_EXECUTION_PROFILE `
  -EnableGuardedFastMode:([int]$env:AUTO_ENABLE_GUARDED_FAST_MODE_A -eq 1) `
  -EnableGateOnlySourceDrivenSkip:([int]$env:AUTO_ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP -eq 1) `
  -TaskDesignQualityPolicy $env:AUTO_TASK_DESIGN_QUALITY_POLICY `
  -UnknownNoOpBudget ([int]$env:AUTO_UNKNOWN_NOOP_BUDGET) `
  -UnknownNoOpConsecutiveLimit ([int]$env:AUTO_UNKNOWN_NOOP_CONSECUTIVE_LIMIT) `
  -DisableUnknownNoOpBudgetGate:([int]$env:AUTO_DISABLE_UNKNOWN_NOOP_BUDGET_GATE -eq 1) `
  -RbPreflight $env:AUTO_RB_PREFLIGHT -RbPreclassTableGuard $env:AUTO_RB_PRECLASS_TABLE_GUARD `
  -QuietTerminalOutput "true" `
  -QuietRemoteBuildLogs "false" `
  -KeyPath $env:AUTO_REMOTE_KEYPATH -RemoteIp $env:AUTO_REMOTE_IP -User $env:AUTO_REMOTE_USER -Queries $env:AUTO_QUERIES

# Checklist B
& .\tools\test\start_dev_verify_8round_multiround.ps1 `
  -ResetCodeStepState `
  -CodeStepResetPolicy $env:AUTO_CODESTEP_RESET_POLICY_B `
  -TaskDefinitionFile $env:AUTO_TASK_FILE_B `
  -StartRound ([int]$env:AUTO_START_ROUND) -EndRound ([int]$env:AUTO_END_ROUND) `
  -DevVerifyStride ([int]$env:AUTO_DEV_VERIFY_STRIDE_B) `
  -VerifyExecutionProfile $env:AUTO_VERIFY_EXECUTION_PROFILE `
  -EnableGuardedFastMode:([int]$env:AUTO_ENABLE_GUARDED_FAST_MODE_B -eq 1) `
  -EnableGateOnlySourceDrivenSkip:([int]$env:AUTO_ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP -eq 1) `
  -TaskDesignQualityPolicy $env:AUTO_TASK_DESIGN_QUALITY_POLICY `
  -UnknownNoOpBudget ([int]$env:AUTO_UNKNOWN_NOOP_BUDGET) `
  -UnknownNoOpConsecutiveLimit ([int]$env:AUTO_UNKNOWN_NOOP_CONSECUTIVE_LIMIT) `
  -DisableUnknownNoOpBudgetGate:([int]$env:AUTO_DISABLE_UNKNOWN_NOOP_BUDGET_GATE -eq 1) `
  -RbPreflight $env:AUTO_RB_PREFLIGHT -RbPreclassTableGuard $env:AUTO_RB_PRECLASS_TABLE_GUARD `
  -QuietTerminalOutput "true" `
  -QuietRemoteBuildLogs "false" `
  -KeyPath $env:AUTO_REMOTE_KEYPATH -RemoteIp $env:AUTO_REMOTE_IP -User $env:AUTO_REMOTE_USER -Queries $env:AUTO_QUERIES
PS
```

```powershell
# Checklist A (2026-05-28 ~ 2026-06-04)
& .\tools\test\start_dev_verify_8round_multiround.ps1 `
  -ResetCodeStepState `
  -CodeStepResetPolicy restore-source `
  -TaskDefinitionFile testdata/autopilot_code_step_tasks_20260528_20260604.json `
  -StartRound 1 -EndRound 8 `
  -DevVerifyStride 1 `
  -VerifyExecutionProfile d6-only `
  -EnableGuardedFastMode $true `
  -EnableGateOnlySourceDrivenSkip $true `
  -RbPreflight 1 -RbPreclassTableGuard 1 `
  -QuietTerminalOutput true `
  -QuietRemoteBuildLogs false `
  -TaskDesignQualityPolicy enforce `
  -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 `
  -DisableUnknownNoOpBudgetGate:$false `
  -KeyPath /c/Users/妙妙呜/.ssh/id_rsa -RemoteIp 10.0.0.199 -User larson

# Checklist B (2026-06-05 ~ 2026-06-12)
& .\tools\test\start_dev_verify_8round_multiround.ps1 `
  -ResetCodeStepState `
  -CodeStepResetPolicy state-only `
  -TaskDefinitionFile testdata/autopilot_code_step_tasks_20260605_20260612.json `
  -StartRound 1 -EndRound 8 `
  -DevVerifyStride 2 `
  -VerifyExecutionProfile d6-only `
  -EnableGuardedFastMode $true `
  -EnableGateOnlySourceDrivenSkip $true `
  -RbPreflight 1 -RbPreclassTableGuard 1 `
  -QuietTerminalOutput true `
  -QuietRemoteBuildLogs false `
  -TaskDesignQualityPolicy enforce `
  -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 `
  -DisableUnknownNoOpBudgetGate:$false `
  -KeyPath /c/Users/妙妙呜/.ssh/id_rsa -RemoteIp 10.0.0.199 -User larson

# Single-arg fastmode wrappers (2026-04-16)
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_A.ps1 autopilot_code_step_tasks_20260528_20260604.json
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_B.ps1 autopilot_code_step_tasks_20260605_20260612.json

# Wrapper behavior:
# - Both wrappers fix DevVerifyStride=2 and full fastmode gate options.
# - A fixes CodeStepResetPolicy=restore-source; B fixes CodeStepResetPolicy=state-only.
# - Single required input is the task definition filename (testdata/ is auto-prefixed when omitted).

> 说明：A/B 当前建议显式传 `-EnableGuardedFastMode true`、`-QuietTerminalOutput true` 与 `-QuietRemoteBuildLogs false`。其中前者抑制终端噪音，后者保留远端编译关键日志用于实时监控与故障定位。
> 固定运行策略（D1 监控容忍窗口，2026-04-15）：
> 1) D1 默认容忍窗口为 90 分钟；前 30 分钟仅观测不做人工重启。
> 2) 在 30~90 分钟区间，每 10 分钟做一次“有进展”判定；满足任一即继续等待：
>    - D1 对应产物目录有新文件或更新时间推进；
>    - `step47_preclass_preflight/*` 或 `preclass_p1_matrix/*` 文件数量持续增长；
>    - 远端链路进程（`remote_build_and_test.sh` / `ssh` / `whois-*`）仍存活且 CPU 时间增长。
> 3) 仅当以下三项连续 20 分钟同时成立，才允许判定“挂起并重跑”：
>    - 无关键落盘推进（如 `D1.log`、`summary_partial.csv`、preflight/矩阵汇总文件）；
>    - 无远端链路活跃进程；
>    - 活跃目录文件数不再增长。
> 4) 触发重跑前，先固定留证：进程快照 + 当前产物目录快照 + 已有 `summary_partial.csv`。
> 说明（2026-04-14 补充）：若通过嵌套 `powershell -File` 方式调用，布尔参数建议显式传 `$true/$false`，或直接省略并使用默认值；不要依赖字符串 `"true"/"false"` 的隐式转换。
```

**执行复盘（2026-04-14，A -> B 串行接续）**：
- A 首次 D1 失败根因：`D1_no-delta_attempt1` 内 `Step47 preclass preflight` 出现 `pass=4 fail=1`，导致 one-click no-delta 退出码非零；同轮 build/hash/golden/referral 均通过，说明不是 `-EnableGuardedFastMode` 或 d6-only 参数本身导致。
- “未显式透传 preflight/table guard 仍然执行”的原因：内层 `autopilot_dev_recheck_8round.ps1` 在 no-delta 路径默认会开启 preflight/table guard；本 RFC 与脚本已同步新增显式参数 `-RbPreflight`、`-RbPreclassTableGuard`，并在日志打印有效值，减少误判。
- A 成功后 B 若使用 `-CodeStepResetPolicy restore-source`，会触发 reset 期源码恢复（baseline/HEAD 回写逻辑），从而破坏 A -> B 累积改码预期；串行累积验证必须使用 B=`state-only`。
- 经验教训：
  1. 串行 A/B 的“累积性”优先级高于单轮可复现性，B 固定 `state-only` 写入清单硬约束。
  2. 把关键门禁开关（preflight/table guard）从“隐式默认”提升为“显式参数 + 日志可观测”。
  3. 布尔参数在嵌套调用场景下统一采用稳健传参规范，避免 `ParameterArgumentTransformationError`。
  4. 会话模板中增加“失败归因先看 no-delta 的 preflight 行，再看 d6 两轮日志”的一键排障顺序。

**进展速记（2026-04-16，无人值守白名单自愈策略同步落地）**：
- 同步目标：与 `docs/RFC-whois-client-split.md` 对齐，仅启用 3 条白名单策略，不引入额外自动修复动作。
- 规则 1（任务定义 replacement 双转义修复）已落地：
  - 落地点：`tools/test/autopilot_code_step_rounds.ps1` 的 `regex-patch` 执行路径。
  - 动作：检测到“字面量 `\\n/\\t` 且疑似多行模板”时，先做一次受限归一化（`\\r\\n -> CRLF`、`\\n -> LF`、`\\t -> TAB`），并输出 `[CODE-STEP-AUTOHEAL] rule=taskdef-replacement-double-escape`。
  - 边界：归一化后仍判定为双转义风险则继续阻断，不放行不确定输入。
- 规则 2（已知 preflight 瞬时抖动重试）已扩展：
  - 落地点：`tools/test/autopilot_dev_recheck_8round.ps1` 的 `Test-Step47PreflightFlake`。
  - 已覆盖签名：保留既有 `pass=3 fail=1`；新增 `pass=4 fail=1 + gate-enabled-valid-threshold fail + rollback/mismatch` 的已观测瞬时抖动特征。
  - 边界：仅识别“已知签名”并沿用单次受限重试口径，不扩大为通配重试。
- 规则 3（strict 失败短路保护）维持生效：
  - 落地点：`tools/test/d6_consistency_double_run.ps1`。
  - 动作：strict 失败时输出 `short_circuit=skip-p0-p1`，并跳过当轮 P0/P1，避免污染后续判定。
  - 边界：短路只作用于 strict 失败轮次，不影响 strict 通过场景下的完整链路检查。
- 统一分流口径：白名单外异常默认 `stop-and-investigate`，先固化证据再人工处理。

**执行记录（2026-04-12，V2 A/B 对照简报，非 Checklist B 执行）**：
- 执行入口：`tools/test/start_dev_verify_8round_multiround.ps1`（`d6-only + enforce + source-driven skip + no-op budget gate` 口径）。
- A 组证据目录：`out/artifacts/autopilot_dev_recheck_8round/20260411-111746/V2_d6_attempt1/20260411-111746`。
- B 组证据目录：`out/artifacts/autopilot_dev_recheck_8round/20260411-113104/V2_d6_attempt1/20260411-113104`。
- 归属说明：该记录用于 V2 失败模式对照，不代表 Checklist B 已执行。

| 组别 | 轮次 | StrictExit | Strict耗时(s) | Round耗时(s) | RoundPass | 关键判定 |
| --- | --- | --- | --- | --- | --- | --- |
| A | R1 | -1 | n/a | 1028 | False | `table_guard_ts` 为空，`TableGuardPass=False`；`PreflightPass=True` 且 `P0/P1=True` |
| A | R2 | 0 | 751 | 857 | True | Hash/Golden/Referral/Preflight/TableGuard/P0/P1 全部通过 |
| B | R1 | 0 | 1192 | 1282 | True | Hash/Golden/Referral/Preflight/TableGuard/P0/P1 全部通过 |
| B | R2 | 2 | 25 | n/a | False | strict 链接失败（`undefined reference`：`log_security_event`、`monitor_connection_security`、`wc_seclog_set_enabled`） |

- A 组结论：R1 掉闸后 R2 恢复通过，失败特征集中在 `table_guard_ts` 缺失导致的 `TableGuardPass=False`。
- B 组结论：R1 通过、R2 在 strict 25s 内硬失败，属于链接期符号缺失，直接拉低本轮总判定。
- 下次动作：先修复 B-R2 的链接缺符号，再按同参数重跑 `V2_d6_attempt1` 做 A/B 复验。

#### 23.48 A/B 连续无人值守执行回填（2026-04-16）

- 里程碑：首次完成“A/B 串行 + B 中途故障处理后重启”的完整无人值守收口，链路稳定可复用。
- A（restore-source）结果：`out/artifacts/dev_verify_multiround/20260415-175235/final_status.json` 为 `Result=pass`、`CompletedRoundCount=8`。
- B 首次结果：`out/artifacts/dev_verify_multiround/20260415-232520/final_status.json` 为 `Result=fail`（`FailedRoundTags=["D1"]`）。
- B 重启策略：按既有规程执行“本地/远端进程清理 -> 证据快照 -> `-ResetCodeStepState -CodeStepResetPolicy state-only` 重启”。
- B 重启后结果：`out/artifacts/dev_verify_multiround/20260416-003754/final_status.json` 为 `Result=pass`、`CompletedRoundCount=8`。
- V4 双轮证据：`out/artifacts/autopilot_dev_recheck_8round/20260416-042520/V4_d6_attempt1/20260416-042520/summary.csv`（round1/round2 均 `RoundPass=True`）。
- 运行结论：A -> B 全链路在近 10 小时量级连续运行后完成收口（实际跨时段约 11 小时），满足“失败可恢复、恢复可收口”的预期目标。

#### 23.49 下次开工清单（A/B 串行，2026-04-17，已完成回填）

1. [x] 证据归档：将 `20260415-175235`（A PASS）、`20260415-232520`（B 首失败）、`20260416-003754`（B 重启 PASS）三组目录写入统一索引。
2. [x] 预检固定化：执行 SSH 连通、远端空间、任务文件存在性、`RbPreflight/RbPreclassTableGuard` 开关四项前置检查。
3. [x] 严格串行：A 固定 `restore-source`，B 固定 `state-only`，两者均显式传 `-ResetCodeStepState`，禁止并发执行。
4. [x] 故障处理准入：仅当“无进程活性 + 无关键落盘 + 无目录增长”满足挂起判据时才触发重启；重启前必须保留快照证据。
5. [x] 发布前复核：保留 V3 混合样本（v4 + CIDR + v6）验证位，不得被默认查询样本替代。
6. [x] 文档同步：收口后同步更新 `docs/RFC-whois-client-split.md`、`docs/OPERATIONS_CN.md`、`docs/OPERATIONS_EN.md` 的模板与执行记录。

#### 23.50 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，提速模式，2026-06-13 ~ 2026-06-20，串行第 7 份，Checklist A，已完成回填）

> 注：本轮基于上次 A/B 收口经验，继续 A -> B 串行；A 作为先行序列，D1~D4 均为实改码（不使用 noop）。

**八轮通用约束（开跑前确认）**：
1. [x] 串行约束：仅在上一个串行批次收口后启动，A 期间禁止并发跑 B。
2. [x] 任务定义文件固定：`testdata/autopilot_code_step_tasks_20260613_20260620.json`。
3. [x] Reset 策略固定：A 必须使用 `-ResetCodeStepState -CodeStepResetPolicy restore-source`。
4. [x] 提速模式固定：`-DevVerifyStride 2 -VerifyExecutionProfile d6-only -EnableGuardedFastMode $true -EnableGateOnlySourceDrivenSkip $true`。
5. [x] 质量闸固定：`-TaskDesignQualityPolicy enforce -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 -DisableUnknownNoOpBudgetGate:$false`。
6. [x] 轮次范围固定：`-StartRound 1 -EndRound 8`（D1~D4 + V1~V4）。

**开发四轮（D1~D4，较上一版提升改码密度）**：
1. [x] D1：新增默认 action/source/fallback 三组 literal helper，并替换 `wc_preclass_default_*` 相关返回路径。
2. [x] D2：新增 non-ip/cidr/ip compare helper，并替换 `wc_preclass_input_label_from_match_layer` 与 default input/match 返回路径。
3. [x] D3：新增 policy/decision/disabled 三组 helper，并替换 `wc_preclass_policy_action_source`、`wc_preclass_decision_action_source`、`wc_preclass_disabled_fallback_reason`。
4. [x] D4：新增 route-change/action 四组 helper，并替换 route-change allow/fallback 分支（D4 不再使用 noop）。

**复检四轮（V1~V4）**：
1. [x] V1 基线复检：强制 full gate，要求 `RoundPass=True`。
2. [x] V2 噪声窗口复检：允许 fast path，但保留 skip reason/no-op 分类证据。
3. [x] V3 混合样本复检：固定查询集 `64.6.64.6 103.53.144.0/22 2620:fe::fe`。
4. [x] V4 收口复检：`rounds_total=8`、`rounds_pass=8`、`result=pass`，并完成 RFC 回填。

**建议执行命令（单参提速入口）**：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_A.ps1 autopilot_code_step_tasks_20260613_20260620.json
```

#### 23.51 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，提速模式，2026-06-21 ~ 2026-06-28，串行第 8 份，Checklist B，已完成回填）

> 注：Checklist B 仅在 Checklist A 收口后启动；采用 state-only 承接 A 的源码增量，保持 A/B 串行累积。

**八轮通用约束（开跑前确认）**：
1. [x] 串行约束：仅在 Checklist A `result=pass` 后启动，禁止并发。
2. [x] 任务定义文件固定：`testdata/autopilot_code_step_tasks_20260621_20260628.json`。
3. [x] Reset 策略固定：B 使用 `-ResetCodeStepState -CodeStepResetPolicy state-only`。
4. [x] 提速模式固定：`-DevVerifyStride 2 -VerifyExecutionProfile d6-only -EnableGuardedFastMode $true -EnableGateOnlySourceDrivenSkip $true`。
5. [x] 质量闸固定：`-TaskDesignQualityPolicy enforce -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 -DisableUnknownNoOpBudgetGate:$false`。
6. [x] 轮次范围固定：`-StartRound 1 -EndRound 8`（D1~D4 + V1~V4）。

**开发四轮（D1~D4，较上一版提升改码密度）**：
1. [x] D1：新增 class-name literal helper 集合，并替换 `wc_preclass_set_allocated_hint` 与 `wc_preclass_class_name` 返回路径。
2. [x] D2：新增 RIR literal helper 集合，并替换 guessed-rir `unknown` 比较、`wc_preclass_set_allocated_hint` 与 `wc_preclass_rir_name` 返回路径。
3. [x] D3：新增 confidence literal helper 集合，并替换 `wc_preclass_set_allocated_hint` 与 `wc_preclass_confidence_name` 返回路径。
4. [x] D4：新增 reason literal helper 集合，并替换 `wc_preclass_set_allocated_hint` 与 `wc_preclass_reason_name` 的 default 返回路径。

**复检四轮（V1~V4）**：
1. [x] V1 基线复检：强制 full gate，`RoundPass=True`。
2. [x] V2 噪声窗口复检：采用 fast path，并保留 skip reason/no-op 分类证据。
3. [x] V3 混合样本复检：固定查询集 `64.6.64.6 103.53.144.0/22 2620:fe::fe`。
4. [x] V4 收口复检：`rounds_total=8`、`rounds_pass=8`、`result=pass`，并完成 RFC 回填。

**建议执行命令（单参提速入口）**：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_B.ps1 autopilot_code_step_tasks_20260621_20260628.json
```

**执行回填（2026-04-17，Checklist A/B 串行）**：
- Checklist A 执行目录：`out/artifacts/dev_verify_multiround/20260417-050528`，`final_status.json` 为 `Result=pass`、`ExitCode=0`、`CompletedRoundCount=8`；`summary.csv` 已逐轮记录 `TaskDefinitionFile=testdata/autopilot_code_step_tasks_20260613_20260620.json`。
- Checklist B 首次执行目录：`out/artifacts/dev_verify_multiround/20260417-095240`，`final_status.json` 为 `Result=fail`、`FailedRoundTags=["D4"]`。
- 首次失败根因链：`step47_preclass_preflight/20260417-121244/summary.txt` 中 `gate-enabled-consistency-chain` 失败；下钻到 `preclass_table_guard/20260417-121736/summary.txt`，命中 `missing_reverse_confidence_ids=0,1,2`。
- 修复与专项回归：`tools/test/preclass_table_guard.ps1` 放宽 switch-case 解析后，`preclass_table_guard/20260417-123618/summary.json` 为 `result=pass`（`confidence_reverse_lookup_complete=true`），`step47_preclass_preflight/20260417-123639/summary.txt` 全用例通过。
- Checklist B 重跑目录：`out/artifacts/dev_verify_multiround/20260417-130503`，`final_status.json` 为 `Result=pass`、`ExitCode=0`、`CompletedRoundCount=8`。
- B 轮次结论：D1~D4 均 `EXECUTE + RoundPass=True`，且 code-step 为 `already-applied`；V1/V3/V4 为 `EXECUTE + RoundPass=True`，V2 为 `V-SKIP`（`fast-skip-v2-d-nop-count-2-of-3`，证据写入 `summary.csv`）。
- 串行约束确认：A/B 均显式使用 `-ResetCodeStepState`；B 按要求保持 `-CodeStepResetPolicy state-only`；执行期间未触发自动提交/自动推送。

**模板对齐说明（供后续同类任务复用）**：

1. [x] 沿用：`AUTO 会话预置模板`、`AUTO 映射口径`、`工作前置清单`、`两份清单串行入口`、`D1 监控容忍窗口`。
2. [x] 差异：本轮 D4 为“实改码轮”，不再是冻结/noop 轮；D4 保持 regex 单一命中。
3. [x] 差异：本轮 A/B 均使用 `DevVerifyStride=2`；任务文件固定为：
  - `testdata/autopilot_code_step_tasks_20260613_20260620.json`
  - `testdata/autopilot_code_step_tasks_20260621_20260628.json`

#### 23.52 最新版 AUTO 预置模板（本次任务文件 + stride=2，独立节，执行优先）

```powershell
# Core policy
$env:AUTO_APPROVAL_ONCE = "1"
$env:AUTO_CODE_CHANGE = "1"
$env:AUTO_COMMIT = "0"
$env:AUTO_PUSH = "0"
$env:AUTO_DEV_MAX_ROUNDS = "4"
$env:AUTO_TOTAL_ROUNDS = "8"
$env:AUTO_START_ROUND = "1"
$env:AUTO_END_ROUND = "8"

# This cycle (2026-06-13 ~ 2026-06-28): A/B task files + stride=2
$env:AUTO_TASK_FILE_A = "testdata/autopilot_code_step_tasks_20260613_20260620.json"
$env:AUTO_TASK_FILE_B = "testdata/autopilot_code_step_tasks_20260621_20260628.json"
$env:AUTO_CODESTEP_RESET_POLICY_A = "restore-source"
$env:AUTO_CODESTEP_RESET_POLICY_B = "state-only"
$env:AUTO_DEV_VERIFY_STRIDE_A = "2"
$env:AUTO_DEV_VERIFY_STRIDE_B = "2"
$env:AUTO_VERIFY_EXECUTION_PROFILE = "d6-only"
$env:AUTO_ENABLE_GUARDED_FAST_MODE_A = "1"
$env:AUTO_ENABLE_GUARDED_FAST_MODE_B = "1"
$env:AUTO_ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP = "1"
$env:AUTO_TASK_DESIGN_QUALITY_POLICY = "enforce"
$env:AUTO_UNKNOWN_NOOP_BUDGET = "1"
$env:AUTO_UNKNOWN_NOOP_CONSECUTIVE_LIMIT = "2"
$env:AUTO_DISABLE_UNKNOWN_NOOP_BUDGET_GATE = "0"
$env:AUTO_RB_PREFLIGHT = "1"
$env:AUTO_RB_PRECLASS_TABLE_GUARD = "1"

# Remote defaults
$env:AUTO_REMOTE_IP = "10.0.0.199"
$env:AUTO_REMOTE_USER = "larson"
$env:AUTO_REMOTE_KEYPATH = "/c/Users/妙妙呜/.ssh/id_rsa"
$env:AUTO_QUERIES = "8.8.8.8 1.1.1.1 10.0.0.8"
```

**AUTO 映射口径（A/B 入口）**：
- `AUTO_TASK_FILE_A/B` -> `-TaskDefinitionFile`
- `AUTO_CODESTEP_RESET_POLICY_A/B` -> `-CodeStepResetPolicy`
- `AUTO_DEV_VERIFY_STRIDE_A/B` -> `-DevVerifyStride`
- `AUTO_VERIFY_EXECUTION_PROFILE` -> `-VerifyExecutionProfile`
- `AUTO_ENABLE_GUARDED_FAST_MODE_A/B` -> `-EnableGuardedFastMode`
- `AUTO_ENABLE_GATE_ONLY_SOURCE_DRIVEN_SKIP` -> `-EnableGateOnlySourceDrivenSkip`
- `AUTO_RB_PREFLIGHT` / `AUTO_RB_PRECLASS_TABLE_GUARD` -> `-RbPreflight` / `-RbPreclassTableGuard`

**工作前置清单（A/B 开跑前）**：
1. `git status --short` 为空（仅允许本次变更）。
2. 两份任务文件可解析：`autopilot_code_step_tasks_20260613_20260620.json`、`autopilot_code_step_tasks_20260621_20260628.json`。
3. 覆盖 D1 时，命令必须显式包含 `-ResetCodeStepState`。
4. A 固定 `restore-source`，B 固定 `state-only`，禁止并发。
5. D1 监控容忍窗口按固定策略执行（90 分钟窗口 / 30 分钟仅观测 / 30~90 分钟每 10 分钟活性判定 / 连续 20 分钟三条件才判挂起）。

**两份清单串行入口（推荐）**：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_A.ps1 autopilot_code_step_tasks_20260613_20260620.json
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_B.ps1 autopilot_code_step_tasks_20260621_20260628.json
```

> 说明：本轮 D4 明确为“实改码轮”，非冻结/noop 轮；任务定义 regex 必须保持单一命中。

#### 23.53 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，提速模式，2026-06-29 ~ 2026-07-06，串行第 9 份，Checklist A，已完成回填）

> 注：本清单为新一轮 A 清单，继续按 A -> B 严格串行执行。
> 密度约束：D1~D4 均为实改码轮，且每轮至少 4 个 `regex-patch` operation，禁止 `noop`。

**八轮通用约束（开跑前确认）**：
1. [x] 串行约束：仅在上一串行批次收口后启动，A 期间禁止并发跑 B。
2. [x] 任务定义文件固定：`testdata/autopilot_code_step_tasks_20260629_20260706.json`。
3. [x] Reset 策略固定：A 使用 `-ResetCodeStepState -CodeStepResetPolicy restore-source`。
4. [x] 提速模式固定：`-DevVerifyStride 2 -VerifyExecutionProfile d6-only -EnableGuardedFastMode $true -EnableGateOnlySourceDrivenSkip $true`。
5. [x] 质量闸固定：`-TaskDesignQualityPolicy enforce -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 -DisableUnknownNoOpBudgetGate:$false`。
6. [x] 轮次范围固定：`-StartRound 1 -EndRound 8`（D1~D4 + V1~V4）。

**开发四轮（D1~D4，提升改码密度）**：
1. [x] D1：抽取 action-source 与 fallback-none 字面量 helper，并替换 normalize/fallback 返回路径。
2. [x] D2：抽取 observe-only 与 hint-disabled 字面量 helper，并替换 default/decision action 返回路径。
3. [x] D3：新增 match-layer output helper 与 query-kind 路由 helper，并替换 `match_layer` 输出分支。
4. [x] D4：新增 route-change flag helper，统一 normalize/default/disabled/block reset 路径与判定条件。

**复检四轮（V1~V4）**：
1. [x] V1 基线复检：强制 full gate，`RoundPass=True`。
2. [x] V2 噪声窗口复检：允许 fast path，但保留 skip reason/no-op 分类证据。
3. [x] V3 混合样本复检：固定查询集 `64.6.64.6 103.53.144.0/22 2620:fe::fe`。
4. [x] V4 收口复检：目标 `rounds_total=8`、`rounds_pass=8`、`result=pass`，并完成 RFC 回填。

**任务定义文件（已执行并回填）**：
- `testdata/autopilot_code_step_tasks_20260629_20260706.json`

**建议执行命令（单参提速入口）**：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_A.ps1 autopilot_code_step_tasks_20260629_20260706.json
```

**执行结果回填（A 阶段，已完成）**：
1. [x] A 成功快照 run：`out/artifacts/dev_verify_multiround/20260420-030816`，`final_status.json` 为 `result=pass`、`CompletedRoundCount=3`（V2~V4 复检收口）。
2. [x] A 重启证据：`tmp/unattended_ab_start_20260418-2200.md` 中 `RESTART_EVIDENCE_NOTES=stage=A ... manual_blocked_20260419-045628.txt`。
3. [x] A 终态回写：启动文件已写入 `A_FINAL_STATUS=PASS`。


#### 23.54 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，提速模式，2026-07-07 ~ 2026-07-14，串行第 10 份，Checklist B，已完成回填）

> 注：Checklist B 仅在 Checklist A 收口后启动；采用 state-only 承接 A 的源码增量，保持串行累积。
> 密度约束：D1~D4 均为实改码轮，且每轮至少 4 个 `regex-patch` operation，禁止 `noop`。

**八轮通用约束（开跑前确认）**：
1. [x] 串行约束：仅在 Checklist A `result=pass` 后启动，禁止并发。
2. [x] 任务定义文件固定：`testdata/autopilot_code_step_tasks_20260707_20260714.json`。
3. [x] Reset 策略固定：B 使用 `-ResetCodeStepState -CodeStepResetPolicy state-only`。
4. [x] 提速模式固定：`-DevVerifyStride 2 -VerifyExecutionProfile d6-only -EnableGuardedFastMode $true -EnableGateOnlySourceDrivenSkip $true`。
5. [x] 质量闸固定：`-TaskDesignQualityPolicy enforce -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 -DisableUnknownNoOpBudgetGate:$false`。
6. [x] 轮次范围固定：`-StartRound 1 -EndRound 8`（D1~D4 + V1~V4）。

**开发四轮（D1~D4，提升改码密度）**：
1. [x] D1：引入 class-id 常量枚举并改造 `set_allocated_hint` 的 class 赋值路径。
2. [x] D2：引入 rir-id 常量枚举并改造 unknown-rir 对比与赋值路径。
3. [x] D3：引入 confidence-id 常量枚举并改造 confidence 赋值路径。
4. [x] D4：引入 reason-id 常量枚举并改造 reason 赋值路径与 default fallback 口径。

**复检四轮（V1~V4）**：
1. [x] V1 基线复检：强制 full gate，`RoundPass=True`。
2. [x] V2 噪声窗口复检：采用 fast path，并保留 skip reason/no-op 分类证据。
3. [x] V3 混合样本复检：固定查询集 `64.6.64.6 103.53.144.0/22 2620:fe::fe`。
4. [x] V4 收口复检：目标 `rounds_total=8`、`rounds_pass=8`、`result=pass`，并完成 RFC 回填。

**任务定义文件（已执行并回填）**：
- `testdata/autopilot_code_step_tasks_20260707_20260714.json`

**建议执行命令（单参提速入口）**：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_B.ps1 autopilot_code_step_tasks_20260707_20260714.json
```

**执行结果回填（B 阶段，已完成）**：
1. [x] B 阶段重启后收敛：`out/artifacts/dev_verify_multiround/20260420-204020` 与 `out/artifacts/dev_verify_multiround/20260420-204032` 均在 D1 停止（`result=fail`、`CompletedRoundCount=1`），随后重启到 `out/artifacts/dev_verify_multiround/20260420-220732`。
2. [x] B 最终 run：`out/artifacts/dev_verify_multiround/20260420-220732/final_status.json` 为 `result=pass`、`ExitCode=0`、`CompletedRoundCount=8`。
3. [x] V2 快速跳过口径：`summary_partial.csv` 的 V2 行为 `RoundDecision=V-SKIP`、`SkipReason=fast-skip-v2-d-nop-count-2-of-3`、`RoundElapsedSeconds=0.72`（策略命中，非失败）。
4. [x] supervisor 收口证据：`out/artifacts/ab_supervisor/20260420-220729/supervisor.log` 记录 `stage_final stage=B result=pass` 与 `complete result=pass`。


#### 23.55 对应任务启动文件（2026-04-18，已回填）

- 启动文件路径：`tmp/unattended_ab_start_20260418-2200.md`
- 绑定文件：
  - A：`testdata/autopilot_code_step_tasks_20260629_20260706.json`
  - B：`testdata/autopilot_code_step_tasks_20260707_20260714.json`
- 策略重点：`RUN_MODE=foreground-visible`、`ENTRY_MODE=single-param-fastmode`、`ENTRY_SCRIPT_A/B=tools/test/start_dev_verify_fastmode_A/B.ps1`。
- 终态字段：`A_FINAL_STATUS=PASS`、`B_FINAL_STATUS=PASS`、`SESSION_FINAL_STATUS=PASS`。

#### 23.56 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，提速模式，2026-07-15 ~ 2026-07-22，串行第 11 份，Checklist A，草案）

> 注：本清单基于上一轮 A/B 执行口径起草，继续按 A -> B 严格串行执行。
> 改码密度要求：D1~D4 每轮至少 6 个 `regex-patch` operation，禁止 `noop`。

**八轮通用约束（开跑前确认）**：
1. [ ] 串行约束：仅在上一串行批次收口后启动，A 期间禁止并发跑 B。
2. [ ] 任务定义文件固定：`testdata/autopilot_code_step_tasks_20260715_20260722.json`。
3. [ ] Reset 策略固定：A 使用 `-ResetCodeStepState -CodeStepResetPolicy restore-source`。
4. [ ] 提速模式固定：`-DevVerifyStride 2 -VerifyExecutionProfile d6-only -EnableGuardedFastMode $true -EnableGateOnlySourceDrivenSkip $true`。
5. [ ] 质量闸固定：`-TaskDesignQualityPolicy enforce -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 -DisableUnknownNoOpBudgetGate:$false`。
6. [ ] 轮次范围固定：`-StartRound 1 -EndRound 8`（D1~D4 + V1~V4）。

**开发四轮（D1~D4，进一步提升改码密度）**：
1. [ ] D1：观测码字面量集中化（reason/confidence/prefix），并改造观测映射函数调用路径。
2. [ ] D2：`input_label` 与 `action_source` 路由 helper 化，统一默认/决策字面量回收。
3. [ ] D3：决策分支应用函数拆分（disabled/decision/route-change），降低主流程重复分支。
4. [ ] D4：`classify_ip` 高频分支 helper 化，覆盖 v4/v6 热路径并扩大单轮源码差异面。

**复检四轮（V1~V4）**：
1. [ ] V1 基线复检：强制 full gate，`RoundPass=True`。
2. [ ] V2 噪声窗口复检：允许 fast path，但保留 skip reason/no-op 分类证据。
3. [ ] V3 混合样本复检：固定查询集 `64.6.64.6 103.53.144.0/22 2620:fe::fe`。
4. [ ] V4 收口复检：目标 `rounds_total=8`、`rounds_pass=8`、`result=pass`，并完成 RFC 回填。

**任务定义文件（草案，已生成）**：
- `testdata/autopilot_code_step_tasks_20260715_20260722.json`

**建议执行命令（单参提速入口）**：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_A.ps1 autopilot_code_step_tasks_20260715_20260722.json
```

#### 23.57 下次开工清单（无人值守稳妥档：开发四轮 + 复检四轮，提速模式，2026-07-23 ~ 2026-07-30，串行第 12 份，Checklist B，草案）

> 注：Checklist B 仅在 Checklist A 收口后启动；采用 state-only 承接 A 的源码增量。
> 改码密度要求：D1~D4 每轮至少 6 个 `regex-patch` operation，禁止 `noop`。

**八轮通用约束（开跑前确认）**：
1. [ ] 串行约束：仅在 Checklist A `result=pass` 后启动，禁止并发。
2. [ ] 任务定义文件固定：`testdata/autopilot_code_step_tasks_20260723_20260730.json`。
3. [ ] Reset 策略固定：B 使用 `-ResetCodeStepState -CodeStepResetPolicy state-only`。
4. [ ] 提速模式固定：`-DevVerifyStride 2 -VerifyExecutionProfile d6-only -EnableGuardedFastMode $true -EnableGateOnlySourceDrivenSkip $true`。
5. [ ] 质量闸固定：`-TaskDesignQualityPolicy enforce -UnknownNoOpBudget 1 -UnknownNoOpConsecutiveLimit 2 -DisableUnknownNoOpBudgetGate:$false`。
6. [ ] 轮次范围固定：`-StartRound 1 -EndRound 8`（D1~D4 + V1~V4）。

**开发四轮（D1~D4，进一步提升改码密度）**：
1. [ ] D1：family 字面量 helper 化，覆盖 lookup/classify 的 family 写入路径。
2. [ ] D2：IPv4 高频判定条件提取为 predicate helpers 并替换热分支条件。
3. [ ] D3：IPv6 高频判定条件提取为 predicate helpers 并替换热分支条件。
4. [ ] D4：unknown 与 guessed-rir 路径 helper 化，统一 v4/v6 unknown 收敛口径。

**复检四轮（V1~V4）**：
1. [ ] V1 基线复检：强制 full gate，`RoundPass=True`。
2. [ ] V2 噪声窗口复检：采用 fast path，并保留 skip reason/no-op 分类证据。
3. [ ] V3 混合样本复检：固定查询集 `64.6.64.6 103.53.144.0/22 2620:fe::fe`。
4. [ ] V4 收口复检：目标 `rounds_total=8`、`rounds_pass=8`、`result=pass`，并完成 RFC 回填。

**任务定义文件（草案，已生成）**：
- `testdata/autopilot_code_step_tasks_20260723_20260730.json`

**建议执行命令（单参提速入口）**：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/start_dev_verify_fastmode_B.ps1 autopilot_code_step_tasks_20260723_20260730.json
```

#### 23.58 对应任务启动文件（2026-04-22，草案，已生成）

- 启动文件路径：`tmp/unattended_ab_start_20260422-2300.md`
- 绑定文件：
  - A：`testdata/autopilot_code_step_tasks_20260715_20260722.json`
  - B：`testdata/autopilot_code_step_tasks_20260723_20260730.json`
- 策略重点：`RUN_MODE=foreground-visible`、`ENTRY_MODE=single-param-fastmode`、`A_FAILURE_BLOCKS_B=true`、`B_START_REQUIRES_A_PASS_WITH_SNAPSHOT=true`。
