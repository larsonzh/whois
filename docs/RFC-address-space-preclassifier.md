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
