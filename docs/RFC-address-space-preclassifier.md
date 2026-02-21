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
