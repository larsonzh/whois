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

## D 轮次任务定义设计指导（自愈修复专用）
- 故障轮次未指定时，按以下规则判断修复方式：
  - **D1-D4 code-step 阶段失败（code-edit-failure / task-definition-mismatch）**：源码尚未变更，可修改/追加/删除该轮次中的 op。
  - **D1-D4 code-step 阶段已通过，但编译/验证阶段失败**：源码已被该轮次修改。在末尾追加新 op，不可修改或删除该轮次原有 op。
  - **V1-V4 验证阶段（不是 JSON 轮次键名——只有 D1-D4 是轮次条目）**：将修复作为新 op 追加到 D4 operations 数组末尾，不得创建 V1-V4 轮次条目。
- **改动量评估优先**：先评估代码改动量。改动量小，在当前 D 轮次末尾追加 op 补丁（追加模式）；改动量大，则重设计当前 D 轮次所有 ops（重构模式）。追加模式优先，重构模式仅当追加模式导致 ops 数量膨胀或语义混乱时选用。
- 任何重启前必须运行静态检查（`tools/test/check_task_definition_static.ps1 -TaskDefinitionFile <file> -Policy enforce`）；静态检查通过后才可重启。
- 修改 D 轮次任务定义后，务必检查该轮次中每个 op 是否在源码中遗留了**孤儿函数体**。当 op 的 pattern 只匹配函数签名而不匹配其函数体时，签名被替换后原函数体将残留为悬空代码块，导致编译错误。发现后应在该轮次末尾追加删除孤儿体的 op，或修改原 op 的 pattern 使其一并消耗原函数体。
- D 轮次代码设计必须基于 [../docs/RFC-address-space-preclassifier.md](../docs/RFC-address-space-preclassifier.md) 中的方案。Step47 矩阵契约是不可逾越的红线，不得因代码变更改变其预期结果。

## 协作与文档
- 交流用中文；代码/注释/提交信息用英文。
- 变更输出契约、DNS/重试策略或自测流程时，请同步更新 [../docs/USAGE_CN.md](../docs/USAGE_CN.md)、[../docs/USAGE_EN.md](../docs/USAGE_EN.md)、[../RELEASE_NOTES.md](../RELEASE_NOTES.md) 与相关 RFC/黄金脚本说明。
- 日终或重要改动请在 [../docs/RFC-whois-client-split.md](../docs/RFC-whois-client-split.md) 记录进展与待办，确保上下文可追溯。
