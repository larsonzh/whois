# Copilot Instructions for whois

面向：在 VS Code 中协助维护本仓库的 AI 代理，需让新人快速上手并避免破坏既有契约。

## 架构与数据流（务必先掌握）
- 入口：命令行解析与主流程在 [../src/whois_client.c](../src/whois_client.c)，配置结构定义在 [../include/wc/wc_config.h](../include/wc/wc_config.h)。
- 核心模块：选项 [../src/core/opts.c](../src/core/opts.c)、起始服务器 [../src/core/server.c](../src/core/server.c)、DNS 候选与健康记忆 [../src/core/dns.c](../src/core/dns.c)、拨号/转发 [../src/core/lookup.c](../src/core/lookup.c)、非阻塞网络与重试 [../src/core/net.c](../src/core/net.c)、单条查询执行 [../src/core/whois_query_exec.c](../src/core/whois_query_exec.c)。
- 条件输出链：标题投影/正则/折叠分别在 [../src/cond/title.c](../src/cond/title.c)、[../src/cond/grep.c](../src/cond/grep.c)、[../src/cond/fold.c](../src/cond/fold.c)，编排 glue 在 [../src/core/pipeline.c](../src/core/pipeline.c)。
- 心智模型：query → server+dns 解析 → connect+referral → title (-g) → grep (--grep*) → fold (--fold)。stdout 仅业务输出；stderr 仅诊断/指标（保持分工）。

## 输出契约（不要破坏）
- IPv4/IPv6 规则契约（强约束）：任何查询链路、权威判定、CIDR 行为与输出语义改动，必须遵守 [../docs/RFC-ipv4-ipv6-whois-lookup-rules.md](../docs/RFC-ipv4-ipv6-whois-lookup-rules.md)。若与其他描述存在冲突，以该规则文档为准，并在变更中同步更新相关文档与测试样例。
- 标题行：`=== Query: <item> === via <host-or-alias> @ <ip|unknown>`；尾行：`=== Authoritative RIR: <rir-host> @ <ip|unknown> ===`；折叠行：`<query> <UPPER_VALUE_...> <RIR>`（无 IP）。
- 批量模式：`-B` 或 stdin 非 TTY 自动逐行读取；契约需兼容 BusyBox 管道。
- 处理顺序固定：title 投影 → grep（行/块+续行策略）→ fold，任何改动保持顺序与格式稳定，必要时同步黄金样例与文档。
- 重定向补充：RIR 限流/拒绝访问视为“非权威重定向”继续查找；若无 ERX/IANA 标记且已查遍所有 RIR，权威回落 unknown，否则为首个 ERX/IANA 标记 RIR；LACNIC 首跳内部重定向后遇拒绝访问与首跳直连 RIR 拒绝访问均按“不污染轮询序列”处理。
- 设计原则细节请查：[../docs/RFC-whois-client-split.md](../docs/RFC-whois-client-split.md)、[../docs/USAGE_CN.md](../docs/USAGE_CN.md)、[../docs/USAGE_EN.md](../docs/USAGE_EN.md)、[../docs/OPERATIONS_CN.md](../docs/OPERATIONS_CN.md)、[../docs/OPERATIONS_EN.md](../docs/OPERATIONS_EN.md)。

## 日志与指标习惯
- DNS 调试标签 `[DNS-CAND]/[DNS-FALLBACK]/[DNS-CACHE]/[DNS-HEALTH]` 仅在 `--debug` 或 `--retry-metrics` 打开，写 stderr。
- `--dns-cache-stats` 在进程退出时输出单行 `[DNS-CACHE-SUM] hits=<n> neg_hits=<n> misses=<n>`，每进程一次；保持字段名不变。
- 重试指标 `[RETRY-METRICS*]` 由 [../src/core/net.c](../src/core/net.c) 打印，远程冒烟会 grep 这些标签。

## 自测与调试
- 编译期开关：`-DWHOIS_LOOKUP_SELFTEST`、`-DWHOIS_GREP_TEST` 等，逻辑见 [../src/core/selftest*.c](../src/core) 与 [../include/wc/wc_selftest.h](../include/wc/wc_selftest.h)。
- 运行期开关：`--selftest*`、`--debug`、`--retry-metrics`、`--dns-cache-stats`，常用命令：`whois-x86_64 --debug --retry-metrics --dns-cache-stats [--selftest] 8.8.8.8`。
- 修改折叠/grep/title 逻辑后请跑相关自测或黄金检查，确保 stderr 标签与 stdout 契约未变。

## 构建与冒烟工作流
- 推荐远程多架构脚本 [../tools/remote/remote_build_and_test.sh](../tools/remote/remote_build_and_test.sh)，Windows 示例：`"C:\\Program Files\\Git\\bin\\bash.exe" -lc "cd /d/LZProjects/whois; tools/remote/remote_build_and_test.sh -r 1"`。
- VS Code 任务：Remote/Strict 版本、Git: Quick Push、Golden/Selftest suites 已预置，可直接用任务面板触发。
- 本地快速构建：`make`（见 [../Makefile](../Makefile)）；清理脚本 [../tools/dev/prune_artifacts.ps1](../tools/dev/prune_artifacts.ps1)。

## 代码与设计约定
- 公共 API 统一 `wc_*` 前缀，新增模块需补头文件并保持命名一致；共享小工具放 [../src/core/util.c](../src/core/util.c)。
- DNS 候选/健康/回退策略已在 v3.2.8–v3.2.9 冻结，仅做可观测性或 bugfix 级别改动。
- 新增诊断/指标一律写 stderr，沿用已有标签风格；避免更改标签名称，防止黄金与脚本失效。

## D/V 轮次任务定义设计指导（自愈修复专用）
- **D 轮执行前门禁与报票时序（硬规则）**：A/B 启动入口先做 D1-op1 静态预检；进入每个实际执行的 D 轮前，`round runtime static gate` 必须对该轮全部 `operations` 按顺序 dry-run（op2 基于 op1 replacement 后的内存文本，依次类推）。若任一 op 不是唯一命中或替换不可落地，门禁立即将该轮标记为 `TASK-STATIC-FAIL`，跳过该轮 code-step 并使主流程失败退出；运行中的 guard 再依据 `round_task_static_gate_fail` / `[TASK-STATIC-CHECK]` 证据归类为 `task-definition-mismatch`，生成 `incident-captured` 自愈修复票。因此正常情况下无需等到 code-step 再失败。仅当门禁未启用、该轮因 `pre-resume` 被跳过门禁，或存在门禁未覆盖的运行时差异时，才由 code-step 的逐 op 唯一匹配检查 fail-fast，随后由 guard 生成对应事故票。启动/重启入口静态预检失败则由 launcher 直接生成 `task-definition-fix-required` 票；两类票均必须包含 stage、round、op（可定位时）和 task-definition。
- **静态检查语义（硬规则）**：每轮前整轮检查与 code-step 均采用顺序内存文本语义，目标源码只在该轮全部 operations 通过后统一写入，禁止留下半轮源码状态。AI 修复 code-step 故障后，只对触发故障的当前 op 执行目标检查：`tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce -RoundTag <Dn> -OperationIndex <n>`；checker 会顺序模拟同轮 op1 至 op(n-1) 作为只读前提，只把 op(n) 作为目标检查。前置 op 被模拟不代表允许修改。
- **跨轮次修改边界（硬规则）**：D1 故障可改 D1-D4；D2 故障可改 D2-D4、不得改 D1；D3 故障可改 D3-D4、不得改 D1-D2；D4 故障仅可改 D4、不得改 D1-D3。V1-V4 是验证轮次而非 JSON 轮次键：不得改 D1-D3，也不得修改或删除 D4 既有内容，只能在 D4 `operations` 末尾连续追加一个或多个 op。静态门禁必须按上述前向范围验证，不得错误地限制为仅当前 D 轮。
- **D 轮次内操作边界（硬规则）**：code-step 阶段失败时，当前故障 op 之前的 op 为只读；仅允许从故障 op 位置起修改、删除、插入或追加 op。编译/验证阶段失败时，该轮原有 op 均为只读，只能在该轮末尾连续追加一个或多个 op。
- **改动量评估优先**：先评估代码改动量。改动量小，在当前 D 轮次末尾追加 op 补丁（追加模式）；改动量大，则重设计当前 D 轮次所有 ops（重构模式）。追加模式优先，重构模式仅当追加模式导致 ops 数量膨胀或语义混乱时选用。
- **低成本模型任务定义编辑最小操作清单（GPT-5 mini 等）**：
  - 只改 `rounds.<Dn>.operations`，不要改 `rounds` 键名、轮次编号、顶层 schema 字段。
  - 先定位“当前故障 op”在 operations 中的索引；前置轮次和该索引之前的 op 只读，禁止修改。
  - 允许动作仅限跨轮次矩阵允许的 D 轮，以及当前故障 op 及其后续：修改、删除、插入或追加 op。
  - 每次编辑后，保持 operations 内 op 顺序稳定；不要因为格式化或重排导致语义漂移。
  - 修改 pattern/replacement 时必须保证“唯一命中 + 可落地替换”；若无法唯一命中，优先追加新 op，不要强改前置 op。
  - 提交前必跑静态检查；若静态检查失败，继续在当前故障 op 及其后续修复，禁止回头改前置 op。
- 任何重启前必须运行静态检查（`tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce`）；若静态检查失败，必须根据诊断继续在允许修改边界内修复任务定义并重新检查，只有检查通过后才可重启。若无法合规通过检查，报告阻塞并停止重启，禁止绕过门禁。
- 修改 D 轮次任务定义后，务必检查该轮次中每个 op 是否在源码中遗留了**孤儿函数体**。当 op 的 pattern 只匹配函数签名而不匹配其函数体时，签名被替换后原函数体将残留为悬空代码块，导致编译错误。发现后应在该轮次末尾追加删除孤儿体的 op，或修改原 op 的 pattern 使其一并消耗原函数体。
- 修改 helper 前向声明时必须保留 helper 的函数定义；若首次 caller 调用之前没有 prototype，则在 caller 前添加，并删除 caller 之后或其他位置的重复 prototype。完成后同一 helper 必须恰好保留一个 prototype，且位于首次 caller 之前。“删除旧 prototype + 插入 caller 前 prototype”必须作为原子归一化操作，任一步失败都不得写入部分源码或持久化不完整 operations。
- D 轮次代码设计必须基于 whois 项目的整体方案，包括但不限于：
  - 项目架构文档与 RFC（`docs/` 目录下），当前代码改动涉及的具体方案见 [../docs/RFC-address-space-preclassifier.md](../docs/RFC-address-space-preclassifier.md)。
  - 输出契约（标题行、尾行、折叠行格式等），详见 [../docs/USAGE_CN.md](../docs/USAGE_CN.md) 与 [../docs/USAGE_EN.md](../docs/USAGE_EN.md)。
  - IPv4/IPv6 查询规则契约，详见 [../docs/RFC-ipv4-ipv6-whois-lookup-rules.md](../docs/RFC-ipv4-ipv6-whois-lookup-rules.md)。
  - DNS 与重试策略契约（v3.2.8–v3.2.9 冻结），详见 [../docs/RFC-dns-phase2.md](../docs/RFC-dns-phase2.md)、[../docs/RFC-dns-phase4-ip-health.md](../docs/RFC-dns-phase4-ip-health.md)。
- Step47 矩阵契约是不可逾越的红线，不得因代码变更改变其预期结果。
- **预算耗尽与待办修复的优先级（2026-07-05）**：当收到 `budget-exhausted-stop` 通告时，若此前同一会话中已有一张 `incident-captured`（或类似）票据允许了 `code-fix-workflow` / `script-fix-workflow` 但尚未执行对应的修复动作，则**先完成已有修复后再处理预算通告**。budget-exhausted 仅限制 guard 自动重启次数，不影响 task-definition 修复的手动执行。修复完成并静态检查通过后，再按 rerun-scope-decision 的结论重启对应阶段（A 或 B），不要等待额外的人工确认——budget-exhausted 的 `blocked_actions` 不影响 Agent 在修复后通过 launcher 手动重启。
- **防无限循环保护（2026-07-05）**：Agent 在每次重启对应阶段前，应将当前故障的 `main_round` + `failure_fingerprint` 写入 session memory（`/memories/session/last_failure.md`）。重启后若收到新的 `incident-captured` 票据，其 `main_round` 与 `failure_fingerprint` 均与 session memory 中记录的上一次一致，则判定为**同一故障点连续失败**。此时 Agent 应停止自动重启，向用户报告修复未生效，等待人工介入。session memory 中的记录应在以下任一条件满足时清除：(a) 新的故障指纹与上次不同（修复已改变故障表现），(b) 该阶段全部 8 轮完成且未再触发同一故障。
- **相同指纹门禁三段化（2026-07-08）**：D 轮次 `code-step` 的相同指纹门禁采用 `pending_review -> override_window -> hard_block` 状态机。默认预算 `CODESTEP_IDENTICAL_FP_MAX_RETRIES=3`（可按 stage 覆盖）。第 2/3 次重试必须有有效修复证据（任务定义哈希变化 / 轮次任务定义印记变化 / 轮次源码摘要变化），否则直接进入 `hard_block`。
- **人工修复后解锁规则（2026-07-08）**：`hard_block` 不是永久封禁。人工修复后仅在“有效修复证据 + 静态检查通过”时允许从 `hard_block` 自动回到 `pending_review` 并重置同指纹预算；证据不足时保持阻断，禁止重启。

## 协作与文档
- 交流用中文；代码/注释/提交信息用英文。
- 变更输出契约、DNS/重试策略或自测流程时，请同步更新 [../docs/USAGE_CN.md](../docs/USAGE_CN.md)、[../docs/USAGE_EN.md](../docs/USAGE_EN.md)、[../RELEASE_NOTES.md](../RELEASE_NOTES.md) 与相关 RFC/黄金脚本说明。
- 日终或重要改动请在 [../docs/RFC-whois-client-split.md](../docs/RFC-whois-client-split.md) 记录进展与待办，确保上下文可追溯。
