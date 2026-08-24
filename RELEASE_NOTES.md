# whois Release Notes / 发布说明

发布流程（详版）：`docs/RELEASE_FLOW_CN.md` | English: `docs/RELEASE_FLOW_EN.md`
Detailed release flow: `docs/RELEASE_FLOW_EN.md` | Chinese: `docs/RELEASE_FLOW_CN.md`

## Unreleased

中文摘要 / Chinese summary
- WP-01 `injection-view-fallback` 遗留自测修复（2026-08-24）：根因是 standalone selftest 自 2025-12-25 起把 `wc_handle_suspicious_query` 的既有返回契约读反；强制注入命中会输出诊断但返回 `0` 以继续自测查询，自然可疑输入才返回 `1` 表示阻断。测试现改用天然可疑的 `1.2.3.4;` 区分全局 injection view fallback 与普通阻断，并按 `rc == 0` 判定 PASS；生产查询逻辑未改。core golden 新增 PASS 必须出现、FAIL 禁止出现的双向门禁。Fast x86_64/win64 构建、Local hash、smoke 与 golden PASS（`out/artifacts/20260824-073602`）；win64 standalone `--selftest` 退出 0；core/raw/health-first/plan-a/plan-b selftest golden 全 PASS（`20260824-073602/074252/074814/075417/080035`）。最终 Strict `lto-auto` 默认轮无编译/LTO 告警，九架构 Local hash `9/9`、Golden 与三起点 referral 全 PASS（`out/artifacts/20260824-081341`，281s）；Linux/win32/win64 smoke 分别完成 `18/3/3` 条查询且标题/权威尾行一一对应、无硬错误，Strict win64 standalone selftest 再次退出 0；仓库内与外部 lzispro 同步目录的九架构哈希均与 artifact 一致。
- post-3.3.0 WP-01 发布工具首批收口（2026-08-24）：一键发布现按 build/verify、同步并提交静态产物、创建 tag、发布 release 的顺序执行；目标 tag 不存在时通过进程环境强制远程构建版本为 `v<Version>`，现有 tag 若不指向最终静态产物提交则 fail-close。GitHub/Gitee token 不再拼入或回显于 `bash -lc` 命令文本。dry-run smoke 新增发布顺序、强制版本、token 内联风险以及九架构加 checksum 集合断言，本地无构建路径 PASS（`out/artifacts/oneclick_dryrun_guard/20260824-071904`）。真实 one-click build+sync 与最终 tag 指向演练仍待预发布窗口完成，WP-01 保持 active。

English summary
- WP-01 `injection-view-fallback` legacy selftest fix (2026-08-24): the standalone selftest had interpreted the established `wc_handle_suspicious_query` return contract backwards since 2025-12-25. A forced injection emits diagnostics but returns `0` so the selftest query can continue, while a naturally suspicious query returns `1` when blocked. The test now uses the naturally suspicious `1.2.3.4;` input to distinguish the global injection-view fallback from normal blocking and expects `rc == 0`; production query logic is unchanged. The core golden gate now requires PASS and forbids FAIL. Fast x86_64/win64 build, local hashes, smoke, and golden pass (`out/artifacts/20260824-073602`); win64 standalone `--selftest` exits 0; core/raw/health-first/plan-a/plan-b selftest goldens all pass (`20260824-073602/074252/074814/075417/080035`). The final default Strict `lto-auto` round has no compile/LTO warnings; all nine local hashes, Golden, and all three referral starts pass (`out/artifacts/20260824-081341`, 281s). Linux/win32/win64 smoke logs complete `18/3/3` queries with matching query headers and authoritative tails and no hard errors; the Strict win64 standalone selftest exits 0 again. All nine hashes in both the repository and external lzispro sync directories match the artifact manifest.
- Post-3.3.0 WP-01 release-tooling closure, first slice (2026-08-24): one-click release now runs build/verify, syncs and commits statics, creates the tag, then publishes releases. When the target tag is absent, the remote build version is forced to `v<Version>` through the process environment; an existing tag that does not identify the final statics commit fails closed. GitHub/Gitee tokens no longer enter or appear in the echoed `bash -lc` command text. The dry-run smoke now asserts release ordering, forced-version wiring, absence of inline tokens, and the nine-architecture-plus-checksum artifact set; the local no-build path passes (`out/artifacts/oneclick_dryrun_guard/20260824-071904`). The real one-click build+sync and final tag-target rehearsal remains open for a prerelease window, so WP-01 stays active.

## 3.3.0

中文摘要 / Chinese summary
- 发布候选完整复核（2026-08-23）：响应分类修复后的 Strict `lto-auto` 默认/debug 两轮无编译/LTO 告警，九架构 SHA-256 实算均 `9/9` 匹配，Golden/referral 全 PASS（`out/artifacts/20260823-151731`，292s；`20260823-152347`，281s）；Batch 四策略全 `[golden] PASS`（`152928/153443/154054/154744`，1,356.781s）；Selftest 四策略与独立 core golden 全 PASS（`155355/155909/160500/161048`，1,298.199s），四条新增分类优先级断言均命中 PASS 且对应 FAIL 均被禁止。12x6 authority mismatch 空表、无 errors（`redirect_matrix_10x6/20260823-161855`）；CIDR body `4/4`、draft matrix `9/9`、bundle exit 0（`cidr_bundle_summary_20260823-163528.txt`）。完整 standalone core 原始日志仍保留既有网络 WARN/SKIP 与 `injection-view-fallback: FAIL`，不计入 golden 全绿且不是本轮回归。本轮无需代码修复；后续冻结语义，仅进行版本号、release body、tag 与 GitHub Release 收口。
- 确定性响应分类回归（2026-08-23）：新增冻结响应 selftest `redirect-denied-priority`、`redirect-rate-limit-priority` 与 `redirect-semantic-empty-priority`。前两项以同时包含 `inetnum` 权威字段和 denied/rate-limit 标记的正文驱动真实 redirect evaluator，锁定 `Failure > Authoritative`、首跳 RIR 轮询、failure debt 元数据及 visited 清理；semantic-empty 项冻结纯 banner/comment、comment 内非权威标记和权威字段三类边界，锁定 `Non-Authoritative > Semantic Empty > Authoritative`。Linux、win32、win64 三架构均 PASS；core selftest golden 对三项均要求 PASS 且禁止 FAIL。生产行为已符合契约，本切片未修改业务逻辑。
- 确定性 redirect 回归（2026-08-23）：新增冻结响应 selftest `redirect-invalid-key-priority`，以同时包含 `%ERROR:115 invalid search key` 与 referral 的正文直接驱动真实 redirect evaluator。首轮三架构日志一致暴露 invalid-key 分支清除 referral 后仍继续分类，导致 `need_redir_eval`/`force_stop_authoritative` 被覆盖；现于清理 referral 后直接进入统一写回，恢复“无效查询首跳终止、不得漂移跳转”契约。core selftest golden 新增 PASS 必须出现、FAIL 必须禁止的双断言；修复后三架构该 case 全 PASS。
- A/B 轮次检查点 Phase 1（2026-08-23）：范围收缩为观测元数据。`start_dev_verify_8round_multiround.ps1` 每轮原子写入 `round_checkpoints/<round>.json`，记录 PASS/FAIL、源码状态摘要和关键产物；失败元数据标记 `recommended_recovery_mode=fast-pass`、`recommended_reset_policy=stage-default`、`source_mutation_policy=task-definition-only` 并指向既有 A/B 入口。源码摘要只用于发现漂移，失败后所有代码修复必须进入任务定义并由 code-step/fast-pass 重放，禁止重启前直接编辑业务源码。未启用 direct resume，不增加 checkpoint 参数或环境分支；A repo baseline、B A-snapshot 与长期验证的 fast-pass 行为保持不变。原 Phase 2/3 路线正式关闭，不实施历史 PASS 源码快照、direct resume、失败后自动恢复或自动续跑；未来如有实证瓶颈须按全新提案重新立项。主脚本新增 advanced parameter binding，未知参数立即非零退出，避免策略探测拼写错误意外启动默认 8 轮。策略 JSON、未知参数 fail-fast、PASS/FAIL 落盘探测、PowerShell AST 与 `ContractGateOnly` 16/16 通过；完整 `status_ticket_mini_regression.ps1` 实跑 `72/72 PASS`（`failed_cases=0`，含 `round-checkpoint-phase1` 与 `fast-pass-resume-matrix`），证据 `out/artifacts/status_ticket_mini_regression/20260823-144058`。RFC 顶部状态治理同步收口，当前无主动开发事项。
- literal 收敛第 3 批（无人值守 A/B，vx55/vx56，窗口 `2027-06-10 ~ 2027-06-23`，2026-08-22~23）：`SESSION=PASS`（A run=`out/artifacts/dev_verify_multiround/20260822-160200`，A elapsed=0d 07:56:10；B run=`out/artifacts/dev_verify_multiround/20260822-235721`，B elapsed=0d 07:18:34；A/B 合计 `0d 15:13:58`），全程无事故/自愈/重启，A/B 各内联删除 15 个（共 30 个）单次使用 literal helper——**literal 收敛项目完结**（累计收敛 60 个，vx53~vx56）；剩余 6 个多调用/带 prototype helper（`class_unknown`/`class_special`/`rir_unknown`/`v6_unique_local_reason`/`v6_link_local_reason`/`v6_multicast_reason`）作为命名常量有意保留，不再续编；分类语义/输出契约/生成表零变化。最终四轮黄金校验 + 12x6 重定向矩阵全部 PASS：Strict `lto-auto` 默认/`--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first` 两轮无告警 + lto 无告警 + Local hash/Golden/referral 全 PASS（`out/artifacts/20260823-090004`，268s；`20260823-090701`，259s）；Batch 四策略黄金全 `[golden] PASS`（`20260823-091349/091840/092356/092948`，1,198.287s）；Selftest 四策略全 `[golden-selftest] PASS`（`20260823-093542/094029/094550/095134`，1,222.364s）；12x6 矩阵 authority 空表 + `(no errors found)`（`out/artifacts/redirect_matrix_10x6/20260823-100221`）。执行回填见 `docs/RFC-address-space-preclassifier.md` 24.29。
- literal 收敛第 1/2 批（无人值守 A/B，vx53/vx54，窗口 `2027-05-27 ~ 2027-06-09`，2026-08-21~22）：A/B 各 8/8 轮一次通过（A run=`out/artifacts/dev_verify_multiround/20260821-051747`，B run=`out/artifacts/dev_verify_multiround/20260821-121221`，A/B 合计 `0d 14:33:38`），各内联删除 15 个（共 30 个）单次使用 literal helper；分类语义/输出契约/生成表零变化；最终 Strict 远程构建冒烟同步 + 黄金校验（`lto-auto`）无告警 PASS（`out/artifacts/20260822-135204`，255s，Local hash/Golden/referral 全 PASS）。执行回填见 `docs/RFC-address-space-preclassifier.md` 24.28。
- 24.23.7 代码清理完成 + 一致性 selftest 冻结值修复（2026-08-21）：切片 A 消除 `whois_query_exec.c` observation 冗余分支；切片 B 删除 `client_flow.c` 重复 `wc_client_csv_is_default_marker`、改用公共 `wc_preclass_csv_is_default_marker`；切片 C 抽取 `wc_preclass_ipv4_to_u32`/`wc_preclass_ipv6_to_u64` 字节组装 helper（行为零变化）。修复内置一致性 selftest 两条表侧冻结期望（`ff00::1`/`2001:db9::1` 的 `V6_MULTICAST`/`V6_GLOBAL_UNICAST` 修正为与生成表/reason map 一致的 `V6_MULTICAST_FF00_8`/`V6_GLOBAL_UNICAST_2000_3`）；Selftest Golden 新增独立 core `--selftest` 门禁（`golden_check_selftest.sh` 新增 `--forbid-line`，断言 preclass 三条 PASS、禁止对应 FAIL 与 `[PRECLASS-CONSISTENCY]` 诊断）；`prune_artifacts_all.ps1` 纳入 `out/artifacts/core_selftest`（保留 8 份）。全门禁 PASS：编码门禁、Fast 构建（`20260820-192402`）、一键全门禁 8 项（CIDR `4/4+9/9` `20260820-220634`、12x6 authority 空表 `20260820-223125`）、Selftest Golden（core/raw/health/plan-a/plan-b 全 PASS，`20260821`）、Batch Golden 四策略全 PASS（`20260821`）、Strict 默认+debug 两轮无告警（`20260821-001350`/`002054`）、12x6 复核 authority 空表无 errors（`20260821-013117`）；release 已同步。执行回填见 `docs/RFC-address-space-preclassifier.md` 24.27。
- Step47 验证契约同步 Phase C（2026-08-19）：`tools/test/step47_ab_compare.ps1` 期望从
  `route_changed=1`（Phase C 默认翻转前 base=hint-bypassed/trial=step47-short-circuit）更新为
  `route_changed=0`（Phase C 正式收尾后 reserved/special 高置信隐式查询默认早收敛
  `preclass-early-converge-unknown`），并新增 `early_converge_mismatch` 强断言锁定 base/trial 收敛契约。
  该修复仅同步验证脚本与文档（RFC-address-space-preclassifier.md 第 16/19/20 节），业务行为零变化；
  `step47_ab_compare` 与 `step47_preclass_preflight_check` 全绿。
- 提交 `7e1f2fa7` 后的四轮 Golden + 12x6 复核（2026-08-18）：Strict lto-auto 默认/debug 两轮无编译与 LTO 告警，Local hash、Golden、referral 全 PASS（`out/artifacts/20260818-071217`，224s；`20260818-072952`，255s）；默认轮 9 架构 POSIX 哈希与真实 LTO 基准轮 `065540` 完全一致（Windows PE 因时间戳不同除外），确认 LTO 已真实启用且构建确定性同源。Batch 四策略 Golden 全 PASS（`073512/073943/074445/075120`，1185.080s）；Selftest 四策略全 `[golden-selftest] PASS`（`080108/080605/081113/081614`，1201.862s），报告均含 `output line matched: 10\.0\.0\.8 is a private IP address`，证明 `--require-line` 真实业务输出断言已生效、阻断 marker-only 假通过。12x6 矩阵 authority 表空（`redirect_matrix_10x6/20260818-083320`）；唯一 `afrinic_45.113.52.0_22` error 为 LACNIC 站点限流（`whois.lacnic.net ... rir=lacnic`，hop 4/5 连续 give-up），复测 `--prefer-ipv4 --rir-ip-pref arin=ipv6 "45.113.52.0/22" -h afrinic` 收敛 APNIC 正确，与历史同段限流模式一致，属外部瞬态而非代码或脚本回归。
- 单条路径 force-private 优先级补全（2026-08-18）：提交 `22e0247f` 后的四轮 Golden + 12x6 复核全部 PASS（Strict `20260817-090311`/`091109`，批量 `091732..093454`，自检 `094804..100557`，矩阵 `100855` 无 errors）。审计发现 raw 自检走单条查询时 `--selftest-force-private 10.0.0.8` 仍被 Phase C early-converge 短路绕过（golden 仅靠启动 marker 通过），批量循环已在此前修复而单条路径遗漏。最终将检查前移到单条 preclass 决策之前，按 `net_ctx->injection` 优先、全局 view 回退调用 `wc_query_exec_is_forced_private`，命中即转入真实私网分支且不输出虚假的 early-converge 观察；golden checker 新增 `--require-line`，默认精确要求 `10\.0\.0\.8 is a private IP address`，阻断 marker-only 假通过。最终真实 LTO 制品通过 Phase C review `26/26`（`preclass_phasec_review/20260818-070138`）；普通单条隐式私网查询仍早收敛，显式 `-h` 保持兼容。
- LTO 远程构建别名修复（2026-08-18）：审计发现 `remote_build_and_test.sh` 在 `getopts` 前归一化 profile，命令行 `-O lto-auto|lto-serial` 因此未进入 Makefile `lto` 分支；历史同名轮次的跨架构/hash/Golden/referral/行为证据仍有效，但不构成实际 LTO 告警证据。现将归一化移到参数解析后，并由 `remote_build.sh` 显式 export `LTO_MODE/LTO_SERIAL/LTO_PARALLEL` 给所有 POSIX/Windows make 调用。x86_64 判别轮 `20260818-064740` 明确含 `-flto=auto`；最终全架构轮 `20260818-065540` 9 架构编译/链接均含 `-flto=auto`，Local hash、Golden、三条 referral 全 PASS，release 已同步（455s）。
- 批量路径早收敛补全与自检黄金期望修复（2026-08-17）：四轮 Golden 与 12x6 复核发现 raw 自检 golden 实际 FAIL（`batch_raw/20260817-051757`）——Phase C 翻转后单条查询对 `10.0.0.8` 早收敛 `unknown @ unknown`，但批量流程仍走私网提示，且 `selftest_golden_suite.ps1` 的 `cmd | tee` 管道无 pipefail 把真实失败掩盖为 PASS、任务预填 `-ErrorPatterns 'private IP address'` 无法匹配早收敛形态。现修复：普通隐式批量 early-converge 候选进入 Phase C，显式 `-h` 与 `--selftest-force-private` 保持真实私网处理；两个 selftest golden 包装器统一 `set -o pipefail` + `2>&1 | tee`，缺失策略、非法标签与 checker 非零均 fail-close；tasks.json ErrorPatterns 改为 `Suspicious query detected;Private query denied`，以显式 SelftestExpectations 为权威并补回 WORKBUF 标签断言。C 内置 selftest 新增 `preclass-phasec-force-private-priority`。最终快速构建 `out/artifacts/20260817-081022`（163s，Local hash PASS），扩展 Phase C review `24/24 PASS`（`preclass_phasec_review/20260817-075434`），新增 C selftest 标签 PASS；负向 golden 注入确认非零退出码及 stderr 诊断落盘。12x6 本轮唯一 `lacnic_45.113.52.0_22` rate-limit（`out/artifacts/redirect_matrix_10x6/20260817-060124`）经同参数单例重测恢复 APNIC，判定为 LACNIC 外部限流，未改变规则或代码。
- Phase C 默认开启与前置分类器正式收尾（2026-08-17）：高置信 IANA `reserved|special + rir=none` 隐式查询默认早收敛 `unknown @ unknown`；显式 `-h` 保持兼容，`--disable-address-preclass` 保持全量回退。Phase C `20/20`、special-purpose `17/17`、P0 `12/12`、P1 `232/232`、CIDR `4/4 + 9/9`、Step47、12x6 全 PASS（`out/artifacts/redirect_matrix_10x6/20260817-033253`）；最终 9 架构 Strict hash/Golden/referral PASS（`out/artifacts/20260817-034423`，302s），发布制品已同步。
- 2026-08-17 四轮 Golden 与矩阵复核：Strict `lto-auto` 默认/debug 两轮无编译/LTO 告警，Local hash、Golden、referral 全 PASS（`out/artifacts/20260817-000833`，305s；`out/artifacts/20260817-001953`，290s）。Batch Golden 四策略全 PASS（`002627/003207/003826/004414`，1357.129s），Selftest Golden 四策略全 PASS（`010022/010604/011235/011843`，1410.913s）。12x6 authority mismatch 空表；唯一 `lacnic_45.113.52.0_22` rate-limit error（`out/artifacts/redirect_matrix_10x6/20260817-014619`）由同参数单例重测恢复 APNIC，属外部瞬态，未改代码或静态期望。
- 最终四轮 Golden 与重定向矩阵复核（2026-08-16）：Strict `lto-auto` 默认轮与 debug/metrics/DNS-family 轮均无编译/LTO 告警，9 架构 SHA-256 清单实算零不匹配，Local hash、Golden、三条 referral 全 PASS（`out/artifacts/20260816-203059`，276s；`out/artifacts/20260816-203903`，286s）。批量 raw/health-first/plan-a/plan-b 全 Golden PASS（`20260816-204504/205026/205622/210225`，1315.436s）；自检四策略全 `[golden-selftest] PASS`（`20260816-210950/211526/212129/212741`，1369.958s）。最终 12x6 矩阵 authority mismatch 空表、errors=`(no errors found)`（`out/artifacts/redirect_matrix_10x6/20260816-213231`）。本轮无需代码修复。
- 统一末端失败节点重查（2026-08-16）：新增可扩展的每 RIR 失败登记表与原因位掩码，首批承载 `denied`、`rate-limit`、`EMPTY-RESP give-up`。仅在 RIR 轮询耗尽、权威仍未决、未命中 hop cap 且不在嵌套重查 guard 中时，按首次失败顺序对每个节点执行一次 `no_redirect=1/max_hops=1` 单跳重查；权威响应才清偿 failure debt 并收敛，ERX/referral 等非权威响应只补充证据且保留债务，失败则维持原终态。新增 stderr `[TERMINAL-RETRY] action=attempt|result host=... reasons=0x... result=authoritative|non-authoritative|failed` 与 `terminal-retry-registry/policy` selftest。P0 `12/12`、special `17/17`、CIDR bundle `4/4 + 9/9`、12x6 `authMismatchFiles=0 errorFiles=0`（`out/artifacts/redirect_matrix_10x6/20260816-194455`）通过；全架构 Strict `lto-auto` Local hash/Golden/referral 全 PASS（`out/artifacts/20260816-201756`，325s）。
- 发布候选全链复核（2026-08-16）：Strict `lto-auto` 默认与 debug/metrics 两轮均无编译/LTO 告警，Local hash、Golden、referral 全 PASS（`out/artifacts/20260816-152132`，250s；`out/artifacts/20260816-152908`，278s）。批量策略 raw/health-first/plan-a/plan-b 全 Golden PASS（`20260816-153443/153930/154447/155008`，1167.514s）；自检四策略全 `[golden-selftest] PASS`（`20260816-155757/160310/160845/161433`，1272.104s）。首轮 12x6 矩阵 `errorFiles=0`，仅 `lacnic_158.60.0.0_16` 因 APNIC hop 连续空响应落 `unknown`，同轮其余五起点均收敛 APNIC；相同参数定向复测连续 2 次恢复 APNIC，判定为外部瞬态而非规则/代码回归。随后完整复跑 12x6 达到 `authMismatchFiles=0 errorFiles=0`（`out/artifacts/redirect_matrix_10x6/20260816-173702`）；原始瞬态证据保留于 `20260816-161935`。
- 批量策略 Golden 门禁修复（2026-08-16）：Phase B 默认首跳启用后，health-first/plan-a/plan-b 的 penalty 夹具仍会有意将 `8.8.8.8` 从 IANA 起跳，但 suite 错按 raw 的 ARIN 直达基准检查；同时 `Invoke-Strategy`/`Invoke-Golden` 的成功流文本污染结构化返回对象，导致三组 Golden FAIL 最终误汇总为 PASS。现按策略固定 raw=ARIN 直达、penalty 三策略=IANA→ARIN，plan-b 的 `force-last|force-override` 按二选一断言，stderr 纳入报告，并确保任一失败传播退出码 3。新增 `-SkipRemote` 复用最新日志的本地重放入口；原四份日志重放全 PASS，负向注入验证 `Summary: FAIL`/exit 3。
- Phase B 默认首跳修复（2026-08-16）：修复 `wc_opts_init_defaults()` 未初始化 `preclass_first_hop_enable`，导致解析后的零值覆盖 Config 默认开启值、普通 allocated/legacy 隐式查询仍从 IANA 起跳的问题。现在 `1.1.1.1` 默认首跳 APNIC、`8.8.8.8` 默认首跳 ARIN；显式 `-h` 继续旁路，`--disable-address-preclass` 继续回退 IANA。P0 矩阵同步接受正式决策动作 `classifier-rir-hint route_change=1`；`golden_check.sh` 默认基准同步从 IANA→ARIN referral 更新为 `8.8.8.8` 的 ARIN 直达，并保留显式 `--start/--auth` 历史链路校验。全架构 Strict `lto-auto` 复跑无编译/LTO 告警，Local hash、Golden、referral 全 PASS（`out/artifacts/20260816-134711`，336s）。
- IANA special-purpose 覆盖层（2026-08-16，默认仍关闭）：preclass 生成器升级为 schema v2，改用仓库固定的四份 IANA CSV 与 manifest，按最长前缀且同前缀 special 优先合并，生成 `covering_rir/registry/purpose/globally_reachable/reserved_by_protocol` 元数据。`--enable-preclass-early-converge` 下新增 Address Status，并将 special-purpose 成功响应的权威尾行统一为 `unknown @ unknown`；显式 `-h` 保留正文但不再造成权威漂移。专项矩阵离线 `10/10 PASS`、含 IANA/APNIC/ARIN/RIPE/AFRINIC/LACNIC/Verisign 七起点共 `17/17 PASS`；最终发布制品复跑仍为 `17/17 PASS`（`out/artifacts/preclass_special_registry/20260816-113551`）。schema v2 table guard PASS（`out/artifacts/preclass_table_guard/20260816-110940`）；全架构 Strict、hash、Golden、referral PASS（`out/artifacts/20260816-113503`）。
- 49/50 缺口验证回填（2026-08-16）：修复 Windows `getopt_long` shim 未排列位置参数、导致查询后的 `-h arin` 未解析的跨平台缺陷；新增 `opts-permuted-parser` 回归。win32/win64 对 `203.0.113.0/24 -h arin` 均恢复 ARIN 起始/权威；CIDR 正文契约 `4/4 PASS`、draft TSV `9/9 PASS`（`out/artifacts/cidr_bundle/cidr_bundle_summary_20260816-042354.txt`）。Redirect IPv4 首轮 `66/66 PASS`，修复后复跑出现 1 条 LACNIC rate-limit 环境瞬态（单例立即恢复 `unknown`）；Redirect 10x6 稳态 `authMismatchFiles=0`、`errorFiles=0`；Batch Strategy Golden 的 raw/health-first/plan-a/plan-b 全 PASS（总计 `1775.592s`）。
- Phase C selftest 实跑（2026-08-16）：`whois-win64.exe --selftest` 中新增的 `preclass-phasec-policy`、`preclass-phasec-route`、显式主机旁路及短/长选项 parser 断言全部 PASS；完整 standalone selftest 的既有 `injection-view-fallback` 仍 FAIL，并有网络相关 WARN/SKIP，已确认不是 49/50 引入，Phase C 默认仍关闭。
- 黄金脚本静态修复（2026-08-16）：`tools/test/golden_check_selftest.sh` 修复 ShellCheck `SC2016`，通过 Bash 语法、帮助入口和错误分支回归；提交 `c756e2cf` 已推送至 `origin/master`。
- 43/44 Vx A/B 无人值守复核修复（2026-08-11）：V1-V4 代码故障票现在显式写出实际故障轮次；V2 保持既有运行时裁剪语义，D1-D3 中出现 1 或 2 个安全 `D-NOP` 时允许快跳，`unknown-unexplained` 仍阻断快跳；终态总结默认门禁由 trigger/sender 动作升级为同票 ledger `status=done + handled_at` 回执，未确认时 trigger 保持驻留并按 90 秒冷却重投原 ticket/brief，不创建重复 final ticket。`status_ticket_mini_regression.ps1` 新增对应回归。
- 工单消息完整性修复（2026-07-23）：修复 `dispatch_takeover_to_chat.ps1` 将所有超过 4000 字符的正常业务消息误当作 transcript 噪声、按 65%/35% 从字符中间截断的问题。历史 dispatch 日志审计发现 1476 条 `incident-captured` 记录仅命中 `length_cap_chars=1`，且 `removed_lines=0`、`transcript_blocks_removed=0`；未发现行数截断。格式化器现在默认完整保留所有票据类型的业务正文，仅过滤已识别的命令面板/终端 transcript 噪声；显式传入 `MaxChars`/`MaxLines` 时仍保留有界截断能力。快速 contract gate 新增长业务正文、显式上限和 transcript 过滤动态回归。
- A/B 启动与恢复预检提速（2026-07-23）：`check_unattended_ab_launch_ready.ps1` 默认保留 task-definition SyntaxOnly、字段同步、changed-file 编码、进程、SSH 与远端锁门禁，将 status-ticket、retry-budget、route-guard 及全仓库格式/编码完整回归改为显式 opt-in；同时移除 fastmode A/B 内重复的 status-ticket 完整回归。Stage A dry-run 实测由约 8 分 35 秒降至约 31 秒；任务定义修复票的强锚点改用 `status_ticket_mini_regression.ps1 -ContractGateOnly`，墙钟由约 5 分钟降至约 5 秒，并固定在 launch-ready、主进程重启和 recovery transaction 之前执行。三分钟原子收尾保持目标窗口语义，恢复事务原有 240 秒 stage 进程验证与 120 秒 acknowledge 容错预算不收紧。Stage B 无 A PASS snapshot 时继续在后续检查前 fail-fast，但新增 baseline START/DONE 进度。完整套件继续由独立脚本与发布门禁覆盖。
- Retry-budget 专项回归提速（2026-07-23）：`retry_budget_minimal_regression.ps1` 改为一次共享 session-floor seed 后，通过 poll 的 ack-only 快路径依次验证 yes/missing/no 三种 receipt，不再为每个 case 重复 seed 与 ticket selection；PowerShell/poll 调用从 9 次降至 4 次，本机实测由 92.2 秒降至 46.9 秒，三种 ledger 终态保持不变。
- 恢复事务代理禁杀契约（2026-07-23）：修正“3 分钟收尾目标”可能被 Agent 误解为事务总墙钟上限的问题；`.github/copilot-instructions.md`、流程/提示词/启动模板、guard/stage-window/dispatch 运行时提示及 takeover brief 统一声明：`recovery_transaction_command` 只执行一次并等待同步命令自然退出，不得仅因超过 3 分钟或 240 秒而 kill、`Stop-Process`、终止终端或取消事务。240 秒仍仅用于事务内部 stage 启动验证，atomic closeout 保留 120 秒 acknowledge 超时；最终结果只按退出码和 JSON 机器事实判定。完整 status-ticket 回归新增跨层静态防回归。
- Stage-window launch-ready 诊断修复（2026-07-23）：修复 `open_unattended_ab_stage_window.ps1` 在 `$ErrorActionPreference=Stop` 下将 launch-ready 的 stderr 进度行误判为终止错误、导致仅显示 `status=START` 与空 `result=` 的问题。Launch-ready 子步骤改为 `Start-Process` 分离捕获 stdout/stderr 与非零退出码，stage-window 捕获期间局部使用 `Continue`，最终仍按退出码和 PASS marker fail-close；checker mutex 冲突现在明确输出 DONE exit 4、`single_instance_conflict` 和持久化 blocker detail。
- 脚本故障默认只排查（2026-07-16）：start-file 新增 `LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED=false`。字段缺失、非法或关闭时，guard/trigger/route guard/poll/dispatch 共同强制 `incident-script-diagnose-only`，只允许只读取证、根因分析、修复方案、聊天汇报与原子收尾；禁止文件修改、进程控制、重启/resume、环境修改和创建脚本。仅显式开启后保留原脚本自愈流程。
- 票据路由分类收敛（2026-06-12）：`tools/test/check_takeover_route_guard.ps1` 将 incident 分支细化为 `script-fix` / `code-fix` / `noncode` 三条专用流程，并新增通告类专用分类 `notice-manual-wait`、`notice-budget-exhausted`、`notice-known-infra-transient`，避免不同性质故障在执行层混流。
- trigger/dispatch 对齐新分类（2026-06-12）：`tools/test/unattended_ab_takeover_trigger.ps1` 生成细粒度 `route_guard_expected`；`tools/test/dispatch_takeover_to_chat.ps1` 按 route classification 分发专用处理模板（脚本修复/代码修复/非代码故障/通告类），不再将非状态票统一降级为 generic recovery 流。
- Trigger 路径 route guard 门控 smoke（2026-06-12）：新增 `tools/test/trigger_route_guard_gate_smoke.ps1`，并在 `.vscode/tasks.json` 增加可选任务入口 `Test: Trigger Route Guard Gate Smoke`；同步更新 `docs/UNATTENDED_AB_OPERATION_FLOW_CN.md`（阶段 4.10）说明执行命令、通过标准与证据路径。
- Trigger route guard gate smoke 验收（2026-06-12）：本地复验 `result=pass`，检查项 `status_allowed=True`、`incident_allowed=True`、`status_failed=True`、`incident_failed=True`；证据目录 `out/artifacts/trigger_route_guard_gate_smoke/20260612-030100`（`summary.json`、`evidence.log`）。
- 聊天分发策略源键收敛（2026-05-25）：新增 `tools/test/chat_dispatch_policy_compiler.ps1`，由 `tools/test/open_unattended_ab_stage_window.ps1` 与 `tools/test/open_unattended_ab_resume_window.ps1` 统一编译并回写 `AI_CHAT_DISPATCH_*` 派生键；新增策略备忘 `docs/RFC-unattended-chat-dispatch-policy-v1.md`，并在 `docs/README.md` 与 `docs/RFC-whois-client-split.md` 建立索引入口。
- sender-sent 终态门控与主备链路（2026-05-25）：`tools/test/unattended_ab_takeover_trigger.ps1` 新增 `AI_CHAT_POLICY_FINAL_STOP_GATE=sender-sent` 路径（以 `latest_relay_<start-token>.json` 的 `sender_sent=true` 为 auto-stop 前置）；`tools/test/dispatch_takeover_to_chat.ps1` 新增 sender primary/fallback 解析与跨 sender 回退开关，relay state 补充 `sender_fallback_enabled`；最小联调证据见 `out/artifacts/ab_agent_queue/takeover_trigger_unattended_ab_start_sender_gate_smoke.log`。
- PowerShell 告警缓存延迟排障补充（2026-04-23）：`docs/OPERATIONS_CN.md` / `docs/OPERATIONS_EN.md` 新增“旧函数名告警残留”处理建议；推荐先用 `Invoke-ScriptAnalyzer -Path <script.ps1>` 终端复核，再按“重开文件 -> Reload Window -> Restart Language Server”顺序清理编辑器缓存告警。
- A/B guard 低噪声与 V1 闭环口径补齐（2026-04-25）：`tools/test/unattended_ab_session_guard.ps1` 的 restart pasted block 改为 begin/end 与分隔线分行输出，降低日志噪声；`docs/UNATTENDED_AB_START_TEMPLATE_CN.md` 新增 `LOCAL_GUARD_AUTO_FIX_*`、`LOCAL_GUARD_MANUAL_WAIT_*` 字段与职责边界（guard 负责编排，代码修复由会话内代理执行）。
- 无人值守提速优化落地（2026-04-10）：`tools/test/autopilot_dev_recheck_8round.ps1` 新增 `-VerifyExecutionProfile full|d6-only` 与 `-EnableGateOnlySourceDrivenSkip`；在 `d6-only` 下 VERIFY 轮可跳过 `local/no-delta`，并保留 D6 双轮一致性门禁。
- 任务设计质量机制落地（2026-04-11）：`tools/test/start_dev_verify_8round_multiround.ps1` / `tools/test/start_autopilot_8round_code_change.ps1` 新增 `-TaskDesignQualityPolicy`、`-UnknownNoOpBudget`、`-UnknownNoOpConsecutiveLimit` 与 `-DisableUnknownNoOpBudgetGate`；开发轮 no-op 从“是否无差异”升级为“分级判定 + 预算约束 + 风险阻断”。
- 包装器默认口径更新（2026-04-10）：`tools/test/start_dev_verify_8round_multiround.ps1` 与 `tools/test/start_autopilot_8round_code_change.ps1` 默认启用 `VerifyExecutionProfile=d6-only`，并默认开启 gate-only 安全跳过（保留 D1 基线与 V3 混合样本复检）。
- A/B 串行清单回填完成（2026-04-25，串行第 11/12 份）：Checklist A 目录 `out/artifacts/dev_verify_multiround/20260423-122600` 与 Checklist B 目录 `out/artifacts/dev_verify_multiround/20260424-025440` 均 `rounds_pass=8/8`、`result=pass`；B 的 V2 为策略性 `V-SKIP`（`fast-skip-v2-d-nop-count-2-of-3`）且 `RoundPass=True`。
- A/B 无人值守串行回填完成（2026-04-21，串行第 9/10 份）：本次总计 3 次重启后收敛（A 阶段 1 次，B 阶段 2 次），最终 `A_FINAL_STATUS=PASS`、`B_FINAL_STATUS=PASS`、`SESSION_FINAL_STATUS=PASS`；A 成功快照目录 `out/artifacts/dev_verify_multiround/20260420-030816`，B 最终目录 `out/artifacts/dev_verify_multiround/20260420-220732`（`rounds_pass=8/8`），V2 为策略跳过 `fast-skip-v2-d-nop-count-2-of-3`。
- 无人值守白名单自愈（2026-04-16）：仅落地三条规则并保持边界收敛。`tools/test/autopilot_code_step_rounds.ps1` 在 `regex-patch` 场景新增 replacement 双转义受限归一化（输出 `[CODE-STEP-AUTOHEAL]`）；`tools/test/autopilot_dev_recheck_8round.ps1` 扩展 preflight 抖动签名识别（保留 `pass=3 fail=1`，新增 `pass=4 fail=1 + valid-threshold fail + rollback/mismatch`）；strict 失败短路（`short_circuit=skip-p0-p1`）继续由 `tools/test/d6_consistency_double_run.ps1` 执行。
- 无人值守稳妥档八轮（2026-04-18~2026-04-25）已完成回填（实际执行 2026-04-09）：`out/artifacts/dev_verify_multiround/20260409-154303`，`rounds_pass=8/8`；D1~D3 为 `CodeStepAction=applied + SourceDeltaAfterCodeStep=changed`，D4 为 `already-applied + unchanged`，V1~V4 全 `RoundPass=True`。
- A/B 串行清单回填完成（2026-04-10）：Checklist A 首跑目录 `out/artifacts/dev_verify_multiround/20260410-025505` 在 V2 失败后，于 `out/artifacts/dev_verify_multiround/20260410-065857` 补跑 V2~V4 收敛通过；Checklist B 目录 `out/artifacts/dev_verify_multiround/20260410-084332` 一次性 `rounds_pass=8/8`。
- A/B 串行清单回填完成（2026-04-10，2026-05-12~2026-05-27 草案对）：Checklist A 目录 `out/artifacts/dev_verify_multiround/20260410-180931`、Checklist B 目录 `out/artifacts/dev_verify_multiround/20260410-223605` 均为 `rounds_pass=8/8`；两份清单的 V2 均按 `V-SKIP`（`fast-skip-v2-d-nop-count-0-of-3`）通过，无需补跑。
- 复核补充：V3 非默认样本复检已完成，查询集为 `64.6.64.6 103.53.144.0/22 2620:fe::fe`（v4 + v4 CIDR + v6），证据见 `out/artifacts/autopilot_dev_recheck_8round/20260409-203629/summary.csv`。
- 稳妥档无人值守四轮复验完成（2026-04-06）：`out/artifacts/autopilot_four_round/20260406-070404` 汇总 `rounds_pass=4/4`，四轮 `RoundPass=True`，默认语义与输出契约保持稳定。
- 2026-04-15~2026-04-18 多轮可执行版已完成（实际执行 2026-04-06）：Round1~Round4 全部通过，统一验收达成（默认语义不变、门禁全绿、证据可追溯）。
- one-click 同步稳固修复（2026-04-06）：`tools/release/one_click_release.ps1` 修复 `RbSyncDir` 多目录透传与 root path 防呆，并修复单路径标量化误判，消除 `-s '/'` 异常。
- Round3 P1 健壮化门禁 PASS（2026-04-06）：`out/artifacts/preclass_p1_matrix/20260406-050306`（`pass=232 fail=0 group_gate_fail=0`）+ `out/artifacts/step47_prerelease/20260406-050626`。
- Round4 准发布链路 PASS（2026-04-06）：`out/artifacts/oneclick_dryrun_guard/20260406-051011`、`out/artifacts/20260406-051450`、`out/artifacts/cidr_bundle/cidr_bundle_summary_20260406-051848.txt`、`out/artifacts/redirect_matrix_10x6/20260406-051916`、`out/artifacts/step47_prerelease/20260406-052449`。
- 2026-04-14 开发切片（P0 聚合稳定化，2026-04-06）：`src/core/whois_query_exec.c` 的 `[PRECLASS]` 新增 `reason_code/confidence_code`，并在 `tools/test/preclass_min_matrix.ps1` 增加对应一致性断言；默认裁决语义保持不变。
- 门禁留证（strict 超集）：Remote Strict `out/artifacts/20260406-001614` 全绿（`Local hash verify PASS`、`[golden] PASS`、`referral check PASS`），并透传 preflight/table guard：`out/artifacts/step47_preclass_preflight/20260406-001624`（`pass=4 fail=0`）、`out/artifacts/preclass_table_guard/20260406-002301`（`result=pass`）。
- 最小矩阵与运行时抽检：`out/artifacts/preclass_matrix/20260406-002332`（`pass=12 fail=0`）；`out/artifacts/20260406-001614/build_out/preclass_reason_confidence_debug_20260406.log` 命中 `reason_code/confidence_code`。
- 2026-04-13 开发切片（P0 观测增强，2026-04-05）：`src/core/whois_query_exec.c` 的 `[PRECLASS-DECISION]` 新增稳定观测字段 `action_src/match_layer/fallback`，默认路由与终态语义保持不变。
- 门禁留证（strict 超集）：Remote Strict `out/artifacts/20260405-234432` 全绿（`Local hash verify PASS`、`[golden] PASS`、`referral check PASS`），并透传 preflight/table guard：`out/artifacts/step47_preclass_preflight/20260405-234441`（`pass=4 fail=0`）、`out/artifacts/preclass_table_guard/20260405-234915`（`result=pass`）。
- 运行时抽检：`out/artifacts/20260405-234432/build_out/preclass_observe_debug_20260405.log` 命中新增字段，确认观测链路生效。
- Autopilot 无人值守三轮验证（2026-04-05）：按“首选方案”仅执行测试链路并串行跑完 3 轮，汇总目录 `out/artifacts/autopilot_three_round/20260405-203521`，结果 `rounds_pass=3/3`、`result=pass`。
- 三轮明细：Round1 `local/no-delta/D6=20260405-203522/203523/204536`，Round2 `20260405-211436/211438/212321`，Round3 `20260405-215702/215704/220657`，`D6Retried=false`。
- 本次 Autopilot 口径保持“测试执行，不自动提交发布”；当前仅保留 build+sync 产生的 static delta 待人工确认后收尾。
- 2026-04-12 清单执行（2026-04-05）：Daily 三任务 UI 串行 PASS（`local=20260405-181156`、`build+sync no-delta-ok=20260405-181215`、`D6=20260405-182152`），D6 双轮 `RoundPass=True`。
- strict/no-delta 并排复验（2026-04-05 第七轮）：`strict=20260405-190338`、`no-delta-ok=20260405-191302`，均 PASS（strict 为 `statics_detected=true`）。
- D6 非默认样本抽检（2026-04-05 第七轮）：样本 `208.67.220.220 43.227.220.0/22 2620:fe::9`，证据 `out/artifacts/d6_consistency_double_round/20260405-192648`，两轮关键闸项全通过。
- 2026-04-11 清单执行（2026-04-05）：Daily 三任务 UI 串行 PASS（`local=20260405-132622`、`build+sync no-delta-ok=20260405-132637`、`D6=20260405-133529`），D6 双轮 `RoundPass=True`。
- strict/no-delta 并排复验（2026-04-05 第六轮）：`strict=20260405-140407`、`no-delta-ok=20260405-141319`，均 PASS（strict 为 `statics_detected=true`）。
- D6 非默认样本抽检（2026-04-05 第六轮）：样本 `64.6.64.6 103.53.144.0/22 2620:fe::fe`，证据 `out/artifacts/d6_consistency_double_round/20260405-142232`，两轮关键闸项全通过。
- 2026-04-10 清单执行（2026-04-05）：Daily 三任务 UI 串行 PASS（`local=20260405-090255`、`build+sync no-delta-ok=20260405-090304`、`D6=20260405-091112`），D6 双轮 `RoundPass=True`。
- strict/no-delta 并排复验（2026-04-05 第五轮）：`strict=20260405-093833`、`no-delta-ok=20260405-094715`，均 PASS。
- D6 单轮异常重跑收敛（2026-04-05 第二次）：样本 `149.112.112.112 45.236.136.0/22 2001:4860:4860::8844` 首跑 `20260405-095722` Round2 异常；按分流规则重跑 `20260405-101930` 恢复双轮 PASS。
- 2026-04-09 清单执行（2026-04-05）：Daily 三任务 UI 串行 PASS（`local=20260405-062047`、`build+sync no-delta-ok=20260405-062056`、`D6=20260405-062756`），D6 双轮 `RoundPass=True`。
- strict/no-delta 并排复验（2026-04-05 第四轮）：`strict=20260405-064857`、`no-delta-ok=20260405-065628`，均 PASS。
- D6 非默认样本抽检（2026-04-05 第四轮）：样本 `208.67.222.222 203.26.12.0/24 2620:119:35::35`，证据 `out/artifacts/d6_consistency_double_round/20260405-070422`，两轮关键闸项全通过。
- 2026-04-08 清单执行（2026-04-05）：Daily 三任务 UI 串行 PASS（`local=20260405-050330`、`build+sync no-delta-ok=20260405-050338`、`D6=20260405-051137`），D6 双轮 `RoundPass=True`。
- strict/no-delta 并排复验（2026-04-05 第三轮）：`strict=20260405-053514`、`no-delta-ok=20260405-054315`，均 PASS。
- D6 非默认样本抽检（2026-04-05 第三轮）：样本 `9.9.9.9 43.227.220.0/22 2606:4700:4700::1111`，证据 `out/artifacts/d6_consistency_double_round/20260405-055041`，两轮关键闸项全通过。
- 持续推进第二轮（2026-04-05）：Daily 三任务 UI 串行再次 PASS（`local=20260405-032635`、`build+sync no-delta-ok=20260405-032642`、`D6=20260405-033428`）。
- strict/no-delta 并排复验（2026-04-05 第二轮）：`strict=20260405-035747`、`no-delta-ok=20260405-040554`，均 PASS。
- D6 单轮异常重跑收敛（2026-04-05）：非默认样本 `1.0.0.1 45.113.52.0/22 2404:6800:4008::200e` 首跑 `20260405-041520` 出现 Round2 异常；按分流规则重跑 `20260405-043523` 恢复双轮 PASS。
- 2026-04-07 清单预跑（2026-04-05）：Daily 三任务 UI 串行 PASS（`local=20260405-020758`、`build+sync no-delta-ok=20260405-020804`、`D6=20260405-021626`）；D6 双轮 `RoundPass=True`。
- strict/no-delta 并排复验（2026-04-05）：`strict=20260405-024148`、`no-delta-ok=20260405-025109` 均 PASS；本轮 strict 为 `statics_detected=true`。
- D6 非默认样本抽检（2026-04-05）：样本 `8.8.4.4 1.1.1.0/24 2001:4860:4860::8888`，证据 `out/artifacts/d6_consistency_double_round/20260405-025919`，两轮关键闸项全通过。
- 检索模板兼容性修正（2026-04-05）：`docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` / `docs/RFC-whois-client-split.md` 的 one-click 模板已兼容 `key: value` 与 `key=value`，并覆盖 `summary.txt + oneclick_dryrun.log`，避免漏检。
- Daily 链路续跑（2026-04-05）：UI 串行三任务 PASS：`local=20260405-013507`、`build+sync no-delta-ok=20260405-013515`、`D6=20260405-014305`；D6 双轮 `RoundPass=True`，关键闸项全通过。
- no-delta 口径复验（2026-04-05）：本轮 `build+sync no-delta-ok` 检测 `statics_detected=false` 且 `smoke_result=pass`，链路健康判定维持稳定。
- 2026-04-06 清单开工执行（2026-04-04~2026-04-05）：UI 串行复核完成并留时间戳 `TASK_ONECLICK_TS=20260404-222633/20260404-223713`、`TASK_D6_TS=20260404-231236`；D6 首次单轮异常（`20260404-224624`）已按分流规则重跑收敛到双轮全 PASS（`20260404-231236`）。
- strict/no-delta 并排留证（2026-04-05）：同轮补齐两组对照 `20260404-233933/20260404-234956` 与 `20260405-003113/20260405-004139`，均 `guard_result=pass`；本轮 strict 均检测到 static delta（`statics_detected=true`）。
- D6 非默认样本抽检（2026-04-05）：新增查询样本 `8.8.4.4 1.0.0.1 45.113.52.0`，证据 `out/artifacts/d6_consistency_double_round/20260405-000144`，两轮 `RoundPass=True` 且 `PreflightPass/TableGuardPass=True`。
- C5 可用性固化（2026-04-05）：`docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 在 C5 新增“无 `rg` 时用 `bash.exe + grep` 等效命令”提示，减少 Windows 端检索歧义。
- 收尾清理完成（2026-04-05）：本轮 static delta 与文档证据已统一提交推送（`86109a9`），工作区恢复干净。
- D6 参数名收敛（2026-04-03）：`tools/test/d6_consistency_double_run.ps1` 远端地址参数统一为 `-RemoteIp`，并同步 `.vscode/tasks.json` 与 `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 示例，避免编辑器对 `Host` 自动变量的误判干扰。
- 下次开工清单起草（2026-04-03）：`docs/RFC-whois-client-split.md` 新增“下次开工清单（2026-04-06）”，覆盖 UI 入口再确认、strict/no-delta 并排留证、D6 非默认样本抽检、C5 无 `rg` 等效命令提示、三方文档对齐与收尾清理。
- 2026-04-05 清单 Day2 续跑（2026-04-03）：Pre-Release 严格串行预演完成并留双份 summary：`local` PASS（`20260403-085449`）、`build+sync strict` 可解释失败（`20260403-085503`，`statics_detected=false`）、`build+sync no-delta-ok` PASS（`20260403-090357`）、`D6` PASS（`20260403-091450`）。
- D6 稳定性抽检（2026-04-03）：新增第 2 组抽检证据 `out/artifacts/d6_consistency_double_round/20260403-094125`，两轮 `RoundPass=True` 且 `PreflightPass/TableGuardPass=True`。
- 检索模板复核与口径一致性（2026-04-03）：PowerShell 命令模板可直接命中 one-click/D6 关键字段；Git Bash 在无 `rg` 环境下改用 `bash.exe + grep` 完成等效检索；`docs/RELEASE_FLOW_CN.md` 与 `docs/RELEASE_FLOW_EN.md` 的 C1-C6 编号与顺序已核对一致。
- 2026-04-05 清单 Day1 收尾（2026-04-03）：D6 同步后 `release/lzispro/whois/*` 出现 static delta，已按清单口径统一提交推送并恢复工作区干净。
- 2026-04-05 清单 Day1 预跑（2026-04-03）：Daily 三任务链路已串行 PASS：`out/artifacts/oneclick_dryrun_guard/20260403-080703`（local）、`out/artifacts/oneclick_dryrun_guard/20260403-080718`（build+sync no-delta-ok）、`out/artifacts/d6_consistency_double_round/20260403-081805`（D6 双轮 `result=pass`）。
- 证据目录模式速查表（2026-04-03）：`docs/RFC-whois-client-split.md` 与 `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 新增“失败样例 -> 证据目录模式”映射表，覆盖 one-click、D6、preflight、P1 gate、网络噪声等常见场景，便于首跳定位证据路径与判定字段。
- 检索命令模板（2026-04-03）：`docs/RFC-whois-client-split.md` 与 `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 新增 PowerShell/Git Bash 可复制检索命令块（One-Click 摘要、D6 摘要、网络噪声线索）。
- 检索速查表（2026-04-03）：`docs/RFC-whois-client-split.md` 与 `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 新增“任务名 -> grep 关键字”表格，用于日志快速定位。
- 失败分流速查表（2026-04-03）：`docs/RFC-whois-client-split.md` 与 `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 新增“问题 -> 任务 -> 判定字段”表格，便于在失败场景直接定位下一步任务。
- 失败分流决策表（2026-04-03）：`docs/RFC-whois-client-split.md` 与 `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 新增“3 行失败分流”规则，覆盖 `statics_detected=false`、D6 单轮异常与网络噪声三类场景。
- 单行任务清单（2026-04-03）：`docs/RFC-whois-client-split.md` 与 `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 新增“任务面板单行版”，用于按场景（daily / pre-release 有无 static delta）直接串行执行任务。
- 快速检查卡（2026-04-03）：在 `docs/RFC-whois-client-split.md` 新增“早班 5 分钟检查卡（Daily）”与“发版前 20 分钟检查卡（Pre-Release）”，统一任务顺序、判定口径与证据回填动作。
- 命令块补齐（2026-04-03）：`docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 的一页式 Runbook 新增“最小命令块（可复制执行）”，覆盖日常快验与发布前全量复核两套串行命令。
- 门禁一页式 Runbook（2026-04-03）：`docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 新增“日常快验 vs 发布前全量复核”分层执行说明，并明确 `build+sync` 与 `D6` 必须串行的约束。
- 任务补齐（2026-04-03）：新增 `Test: One-Click DryRun Guard (build+sync, prefilled, no-delta-ok)`，用于在“本轮无 static delta”场景下做 build+sync 链路健康验证，避免把无差异当作失败。
- UI 入口串行补证（2026-04-03）：`Gate: D6 Double-Round Consistency (prefilled)` 任务入口 PASS，证据 `out/artifacts/d6_consistency_double_round/20260403-065703`（Round1 `STRICT/PREFLIGHT/TABLE_GUARD=20260403-070232/20260403-070245/20260403-070725`，Round2 `20260403-071708/20260403-071721/20260403-072140`，两轮关键闸项全通过）。
- UI 入口串行补证（2026-04-03）：`Test: One-Click DryRun Guard (build+sync, prefilled)` 证据 `out/artifacts/oneclick_dryrun_guard/20260403-064550`，`exit_code=0` 且 `guard_result=pass`；由于 `RequireStaticsDetectedIfBuildSync=true` 且本轮无新 static delta（`statics_detected=false`），最终 `smoke_result=fail`（可解释结果）。
- UI 入口无交互补丁（2026-04-03）：`.vscode/tasks.json` 新增 3 个 prefilled 任务（`Gate: D6 Double-Round Consistency (prefilled)`、`Test: One-Click DryRun Guard (local, prefilled)`、`Test: One-Click DryRun Guard (build+sync, prefilled)`），用于在任务通道中避免 input 交互阻断。
- 任务入口验证（2026-04-03）：`Test: One-Click DryRun Guard (local, prefilled)` 从任务入口执行 PASS，证据 `out/artifacts/oneclick_dryrun_guard/20260403-062627`。
- 运行约束补记（2026-04-03）：`build+sync` 与 `d6` 两类远程任务共享远端工作目录，需串行执行；并行会引发构建产物互扰。
- 2026-04-04 清单续跑补证（2026-04-03）：新增第 3 组 D6 双轮一致性证据 `out/artifacts/d6_consistency_double_round/20260403-054424`（Round1 `STRICT/PREFLIGHT/TABLE_GUARD=20260403-054716/20260403-054724/20260403-055127`，Round2 `20260403-055938/20260403-055949/20260403-060419`），两轮关键闸项继续全通过。
- dry-run 双模式复验（2026-04-03）：本地无副作用复验 PASS `out/artifacts/oneclick_dryrun_guard/20260403-060902`（`require_git_state_unchanged=True`、`git_state_unchanged=True`）；build+sync 受控断言复验 PASS `out/artifacts/oneclick_dryrun_guard/20260403-060914`（`require_statics_detected_if_build_sync=True`、`statics_detected=true`、`statics_commit_pushed=false`、`result=pass`）。
- dry-run 断言烟测扩展（2026-04-03）：`tools/test/oneclick_dryrun_guard_smoke.ps1` 新增 BuildAndSync 模式参数透传与 `-RequireStaticsDetectedIfBuildSync` 断言，并补齐参数透传空值兼容与 `statics_detected_check` 顺序修复；新增任务 `Test: One-Click DryRun Guard (build+sync)`，实跑 PASS：`out/artifacts/oneclick_dryrun_guard/20260403-051110`（`statics_detected=true`、`statics_commit_pushed=false`、`result=pass`）。
- dry-run 断言烟测增强（2026-04-03）：`tools/test/oneclick_dryrun_guard_smoke.ps1` 新增 git 工作区前后快照校验（`git_status_before.txt` / `git_status_after.txt`）；当 `BuildAndSyncIf=false` 时强制要求 `git_state_unchanged=true`。增强后烟测 PASS：`out/artifacts/oneclick_dryrun_guard/20260403-045829`。
- dry-run 断言烟测任务化（2026-04-03）：新增 `tools/test/oneclick_dryrun_guard_smoke.ps1` 与任务 `Test: One-Click DryRun Guard (local)`，用于自动校验 `[ONECLICK-DRYRUN-GUARD]` 关键字段（skip_tag/skip_github_release/skip_gitee_release/statics_commit_pushed/guard_result）；首次执行 PASS：`out/artifacts/oneclick_dryrun_guard/20260403-045451`。
- 双轮一致性门禁第二轮复跑（2026-04-03）：再次执行 `tools/test/d6_consistency_double_run.ps1`，证据目录 `out/artifacts/d6_consistency_double_round/20260403-043011`，Round1 `STRICT/PREFLIGHT/TABLE_GUARD=20260403-043313/20260403-043322/20260403-043700`，Round2 `20260403-044318/20260403-044326/20260403-044719`；两轮 P0/P1 继续全通过。
- 双轮一致性门禁首轮实跑（2026-04-03）：`tools/test/d6_consistency_double_run.ps1` 首次执行通过，证据目录 `out/artifacts/d6_consistency_double_round/20260403-035824`；Round1 `STRICT/PREFLIGHT/TABLE_GUARD` 时间戳为 `20260403-040118/20260403-040126/20260403-040519`，Round2 为 `20260403-041423/20260403-041435/20260403-041845`，且两轮 P0/P1 预分类回归均通过。
- 双轮一致性门禁任务化（2026-04-03）：新增 `tools/test/d6_consistency_double_run.ps1` 与 VS Code 任务 `Gate: D6 Double-Round Consistency`。该任务固定执行两轮 `Remote Strict(-K 1 -N 1)` 并串联 P0/P1 预分类回归，统一输出 `out/artifacts/d6_consistency_double_round/<ts>` 与 `[D6-CONSISTENCY]` 汇总（含 `summary.csv/summary.txt`）。
- dry-run 无副作用断言显式化（2026-04-03）：`tools/release/one_click_release.ps1` 新增结构化输出 `[ONECLICK-DRYRUN-GUARD]`，统一给出 `skip_tag/skip_github_release/skip_gitee_release/statics_detected/statics_commit_pushed/result`，便于发布侧脚本直接做语义校验；本地快验（`-BuildAndSyncIf false -DryRunIf true`）输出 `result=pass`。
- Preflight 稳定性收口（2026-04-03）：`tools/test/step47_preclass_preflight_check.ps1` 在 `gate-enabled-valid-threshold` 用例上新增“命中 rollback 失败特征时的条件单次重试”（最多 1 次），并保留每次尝试独立日志（含 `.retry1.log`）与 `action=retry` 诊断输出；回归 PASS：`out/artifacts/step47_preclass_preflight/20260403-032214`（`pass=4 fail=0`）。
- 清单执行（2026-04-03，按 2026-04-02）：D6 合流验证 PASS，Remote Strict（`-K 1 -N 1`）证据 `out/artifacts/20260403-021119`，preflight `out/artifacts/step47_preclass_preflight/20260403-021128`，table guard `out/artifacts/preclass_table_guard/20260403-021940`。One-Click dry-run 全链路首轮出现 preflight rollback 波动（`out/artifacts/step47_preclass_preflight/20260403-022527`）后复跑 PASS：`out/artifacts/20260403-023609`、`out/artifacts/step47_preclass_preflight/20260403-023618`、`out/artifacts/preclass_table_guard/20260403-024219`；并确认 dry-run 命中“跳过 statics commit/push + 跳过 GitHub/Gitee release 更新”。23.6 断言回归 PASS：`out/artifacts/preclass_table_guard/20260403-024312`；预分类双闸 PASS：`out/artifacts/preclass_matrix/20260403-024349`、`out/artifacts/preclass_p1_matrix/20260403-024822`。
- D6.1 One-Click 安全 dry-run（2026-04-01）：`tools/release/one_click_release.ps1` 新增 `-DryRunIf <true|false>`（默认 `false`），开启后强制跳过 tag、GitHub/Gitee release 更新与 statics 自动 commit/push，保留可选 build/sync 验证路径；`.vscode/tasks.json` 新增 `oneClickDryRun` 输入并在 `One-Click Release` 任务透传。烟测 PASS：`powershell -NoProfile -ExecutionPolicy Bypass -File tools/release/one_click_release.ps1 -Version 3.2.12 -BuildAndSyncIf false -DryRunIf true -SkipTagIf false`（输出 `one-click done: dry-run mode; tag=v3.2.12`）。
- D6 Remote/Release 入口透传 table guard（2026-04-01）：`tools/remote/remote_build_and_test.sh` 新增 `-N/-B`（可选执行 preclass table guard，默认关闭），`tools/release/one_click_release.ps1` 新增 `-RbPreclassTableGuard/-RbPreclassTableGuardScript` 并透传到远程脚本，`.vscode/tasks.json` 新增输入 `rbPreclassTableGuard/rbPreclassTableGuardScript` 且在 `Remote: Build (Strict Version)` 与 `One-Click Release` 中接线；默认语义保持不变。本轮实跑（`-K 0 -N 1`）PASS：`out/artifacts/20260401-035628`（hash/golden/referral 全通过），guard 证据 `out/artifacts/preclass_table_guard/20260401-035634`。
- D3 一致性收口（2026-04-01，双轮全链路）：连续两轮按固定顺序执行 Remote Strict（`-K 0`）-> CIDR Contract Bundle -> Redirect Matrix 10x6 -> Step47 prerelease（含 preclass-p1-gate）均 PASS；证据路径分别为 Round1 `out/artifacts/20260401-023614`、`out/artifacts/cidr_bundle/cidr_bundle_summary_20260401-023738.txt`、`out/artifacts/redirect_matrix_10x6/20260401-023834`、`out/artifacts/step47_prerelease/20260401-024532`，Round2 `out/artifacts/20260401-025245`、`out/artifacts/cidr_bundle/cidr_bundle_summary_20260401-025312.txt`、`out/artifacts/redirect_matrix_10x6/20260401-025346`、`out/artifacts/step47_prerelease/20260401-030103`。
- D2 动作门控补记（2026-04-01）：补齐第 23 节 D2 独立记录（实现并未缺失）；本轮补证为 P1 门控矩阵 PASS（`out/artifacts/preclass_p1_matrix/20260401-032155`）与 Step47 串联 preclass gate PASS（`out/artifacts/step47_prerelease/20260401-032539`）。
- D5 Step47 可选串联 table guard（2026-04-01）：`tools/test/step47_prerelease_check.ps1` 新增 `-RunPreclassTableGuard/-PreclassTableGuardScript`，并新增任务 `Test: Step47 PreRelease + Table Guard (reserved, list file)`；串联验证 PASS：`out/artifacts/step47_prerelease/20260401-033633`，`preclass-table-guard` 产物 `out/artifacts/preclass_table_guard/20260401-033643`。
- 23.6 可执行断言自动化（2026-04-01）：新增 `tools/test/preclass_table_guard.ps1` 与任务 `Test: Preclass Table Guard (RFC 23.6)`，覆盖 manifest 源哈希一致性、生成表行数一致性与表内 `reason_id` 可回查断言；执行 PASS：`out/artifacts/preclass_table_guard/20260401-031509`（`summary.json`/`summary.txt`）。
- 可见 golden 证据复跑（2026-04-01）：Remote Strict（`-K 0`）PASS，产物 `out/artifacts/20260401-022732`，`golden_report.txt` 已生成并显示 `[golden] PASS`，同时 `referral check PASS`，且日志内 `[STEP47-PREFLIGHT]` 计数为 0。
- Address-Space 前置分类器 D1 查表接线（2026-04-01）：`src/core/preclass.c` 已接入 `wc_preclass_table` 查表（含 `class/rir/reason/confidence` ID 映射），并保留 private/special/global-unicast 兼容分支；验证：Remote Strict PASS（`out/artifacts/20260401-014329`）+ preclass 最小矩阵 PASS（`out/artifacts/preclass_matrix/20260401-014502`）+ Step47 readiness PASS（`out/artifacts/step47_matrix/20260401-014542`）。
- Address-Space 前置分类器 D0 首次落地（2026-04-01）：新增生成器 `tools/preclass/gen_preclass_table.py` 与映射 `tools/preclass/reason_code_map.json`，并生成 `include/wc/wc_preclass_table.h`、`src/core/preclass_table.c`、`out/generated/preclass_manifest.json`；本轮生成 `rows=276`（`v4=256`，`v6=20`，`schema_version=1`）。
- 清单门禁复跑（2026-04-01）：Remote Strict（`-K 0`）+ CIDR Contract Bundle + Redirect Matrix 10x6 + Step47 prerelease（含 preclass-p1-gate）均 PASS；证据路径 `out/artifacts/20260401-001630`、`out/artifacts/cidr_bundle/cidr_bundle_summary_20260401-002629.txt`、`out/artifacts/redirect_matrix_10x6/20260401-002732`、`out/artifacts/step47_prerelease/20260401-003752`。
- 清单第 3 条执行（2026-04-01）：已补齐 PASS 单段快报与完整复盘块，落地于 `docs/release_bodies/next-major-compat-announcement-draft.md`（`-K 0` 口径，`PREFLIGHT_TS=N/A`）。
- 清单第 4 条执行（2026-04-01，条件未触发）：未出现 `%ERROR:201` 或持续拒绝噪声，参数化复验未触发；已在复盘模板补齐“not-triggered”记录样例。
- 清单开工门禁复跑（2026-03-31）：按固定顺序完成 Remote Strict（含 preflight）→ CIDR Contract Bundle → Redirect Matrix 10x6 → Step47 prerelease，结果全 PASS；证据路径 `out/artifacts/20260331-223717`、`out/artifacts/step47_preclass_preflight/20260331-223727`、`out/artifacts/cidr_bundle/cidr_bundle_summary_20260331-225134.txt`、`out/artifacts/redirect_matrix_10x6/20260331-225650`、`out/artifacts/step47_prerelease/20260331-230718`。
- 可执行设计骨架（2026-03-31）：`docs/RFC-address-space-preclassifier.md` 新增第 23 节，明确数据模型、生成脚本输入输出、查表 API、门禁断言以及落地顺序与回退点。
- P1 candidate 来源治理（2026-03-28）：新增 `--preclass-action-list <csv>`，用于覆盖 `--preclass-action-tier r0|r1` 的默认候选集合（CSV 精确匹配，忽略大小写）；默认行为不变（未设置或 `default` 仍走 tier 默认）。
- P1 CSV default 归一化（2026-03-28）：`--preclass-action-list` 与 `--step47-early-unknown-list` 对 `default` 标记支持前后空白（如 `" default "`），并保持“仅单 token 为 default 时走默认语义”。
- P1 真实样本扩表（2026-03-28）：`tools/test/preclass_p1_gate_matrix.ps1` 新增 `-CaseListFile`，默认追加 `testdata/preclass_p1_real_samples.txt` 中的 IP 样本。
- P1 样本分组统计（2026-03-28）：`tools/test/preclass_p1_gate_matrix.ps1` 支持 `group|ip` 样本行并输出 `summary_group.csv` / `summary_group.txt` 与 `[PRECLASS-P1-GROUP]` 分组通过率。
- P1 样本标签化（2026-03-28）：`testdata/preclass_p1_real_samples.txt` 升级为 `group|ip` 标签化样本（`external_public_v4/external_private_v4/external_cgnat_v4/external_public_v6`）。
- P1 分组阈值门禁（2026-03-28）：`tools/test/preclass_p1_gate_matrix.ps1` 新增 `-GroupPassThresholdSpec`（如 `default=100,external_public_v4=95`），输出 `required_pct/gate_pass` 并将分组门禁失败计入 `group_gate_fail` 退出码。
- P1 阈值文件输入（2026-03-28）：`tools/test/preclass_p1_gate_matrix.ps1` 新增 `-GroupPassThresholdFile <path>`（示例 `testdata/preclass_p1_group_thresholds_default.txt`）；支持按行或 `,`/`;` 分隔 token，并与 `-GroupPassThresholdSpec` 叠加（spec 后覆盖）。
- P1 预填任务（2026-03-28）：新增 VS Code 任务 `Test: Preclass P1 Gate Matrix (threshold file)`，默认载入 `testdata/preclass_p1_group_thresholds_default.txt` 以便一键门禁。
- Step47 串联可选 P1 门禁（2026-03-28）：`tools/test/step47_prerelease_check.ps1` 新增 `-RunPreclassP1Gate`（默认关闭）；开启时附加 `preclass-p1-gate` 步骤，并支持 `-PreclassCaseListFile/-PreclassGroupThresholdFile/-PreclassGroupThresholdSpec`。
- Step47 串联预校验（2026-03-28）：启用 `-RunPreclassP1Gate` 时会先校验 preclass 脚本与可选文件路径存在性，并输出 `preclass_gate=enabled|disabled` 诊断，提升失败可定位性。
- Step47 预校验回归（2026-03-28）：新增 `tools/test/step47_preclass_preflight_check.ps1`（任务：`Test: Step47 Preclass Preflight Check`），覆盖 baseline/enable/missing-threshold/missing-case 四类场景。
- 远程 strict 集成 preflight（2026-03-28）：`tools/remote/remote_build_and_test.sh` 新增 `-K/-C/-V`，可在远程构建拉取后本地执行 Step47 preclass preflight；`tools/release/one_click_release.ps1` 新增 `-RbPreflight` 并透传到远程脚本。
- 任务编排补齐（2026-03-28）：`.vscode/tasks.json` 新增输入 `rbPreflight`，`Remote: Build and Sync whois statics` 默认追加 `-K 1`；`One-Click Release` 增加 `-RbPreflight ${input:rbPreflight}` 参数透传。
- strict 任务透传补齐（2026-03-28）：`Remote: Build (Strict Version)` 已补齐 `-K ${input:rbPreflight}`，确保 strict 任务可按输入启用 preflight。
- 阶段完成标记（2026-03-28）：P2 收口判定已满足（参数透传闭环 + 三闸全绿 + Step47 双链路全绿 + strict `-K` 人工验证），默认语义保持不变，进入“发布侧回归清单最终固化”阶段。
- 发布侧回归清单固化（2026-03-28）：`docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 已补齐固定顺序门禁、通过标准、失败中止策略与证据留存要求。
- 业务样本小批量扩表（2026-03-28）：`testdata/preclass_p1_real_samples.txt` 新增 9 条分组样本（public_v4/private_v4/cgnat_v4/public_v6），用于发布侧增量回归。
- 发版复盘模板对齐（2026-03-28）：`docs/release_bodies/next-major-compat-announcement-draft.md` 已同步固定 4 门禁、通过标准与证据留存字段，可直接用于发版当日记录。
- 发版复盘样例预填（2026-03-28）：`docs/release_bodies/next-major-compat-announcement-draft.md` 新增“Release-day recap sample”，并采用“占位符+示例值”双写路径，已预填本轮 4 门禁 PASS 判定。
- 占位符映射说明（2026-03-28）：复盘样例补充 `<STRICT_TS>/<PREFLIGHT_TS>/<CIDR_TS>/<MATRIX_TS>/<STEP47_TS>` 映射，明确各时间戳对应门禁输出。
- 占位符命名规范（2026-03-28）：`docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 新增统一命名与填写规则，复盘样例同步增加双向引用。
- 快速填写块（2026-03-28）：复盘样例新增“键值对模板块 + 示例填充块”，可复制后仅替换右值，减少漏改。
- 复盘 snippet 抽取（2026-03-28）：新增 `docs/release_bodies/release-day-recap-snippet.md`，提供 issue/comment 直贴版本并与模板联动。
- docs 索引入口（2026-03-28）：`docs/README.md` 新增 `release-day-recap-snippet.md` 导航链接，支持从文档首页快速定位。
- 复盘复制顺序建议（2026-03-28）：`docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 在占位符规范中补充“先填键值块、再粘贴正文、后补备注”的操作顺序。
- 复盘发布当日检查清单（2026-03-28）：`docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 增加 3 行粘贴前检查（路径可达、时间戳一致、结论对齐）。
- 失败轮最小回填字段（2026-03-28）：`docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` 新增 FAIL 轮必填字段（`run_ts/failed_gate/evidence_path/cause_next`），确保失败轮也可审计。
- 复盘 snippet FAIL 字段对齐（2026-03-28）：`docs/release_bodies/release-day-recap-snippet.md` 的中英文直贴模板补齐 `run_ts/failed_gate/evidence_path/cause_next`，与发布流程规范保持一致。
- 复盘 snippet FAIL 示例（2026-03-28）：`docs/release_bodies/release-day-recap-snippet.md` 新增“Example-Failed Block”，用于失败轮次快速回填与直贴。
- 复盘 snippet FAIL 单段快报（2026-03-28）：`docs/release_bodies/release-day-recap-snippet.md` 新增“One-Paragraph Quick Comment (FAIL)”中英模板，适配 issue 时间线快速回报。
- 复盘 snippet PASS 单段快报（2026-03-28）：`docs/release_bodies/release-day-recap-snippet.md` 新增“One-Paragraph Quick Comment (PASS)”中英模板，形成 PASS/FAIL 对称快报。
- 观测增强（2026-03-28）：`[PRECLASS-DECISION]` 新增 `p1_list=default|custom` 字段，用于区分 P1 候选来源。
- 构建告警修复（2026-03-28）：`src/core/whois_query_exec.c` 补齐 non-Windows `<strings.h>` 引用，消除 `strcasecmp` 隐式声明告警。
- 验证基线（2026-03-28）：
  - Remote Strict PASS：`out/artifacts/20260328-021557`（`WARN_COUNT=0` + `Local hash verify PASS` + `Golden PASS` + `referral check PASS`）
  - P1 门控矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-021759`（`pass=36 fail=0`）
  - P0 最小矩阵 PASS：`out/artifacts/preclass_matrix/20260328-021900`（`pass=12 fail=0`）
  - Step47 一键门禁 PASS：`out/artifacts/step47_prerelease/20260328-021918`
  - Remote Strict PASS：`out/artifacts/20260328-023116`（`WARN_COUNT=0` + `Local hash verify PASS` + `Golden PASS` + `referral check PASS`）
  - P1 门控矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-023137`（`pass=48 fail=0`，`cases=6 modes=8`）
  - P0 最小矩阵 PASS：`out/artifacts/preclass_matrix/20260328-024331`（`pass=12 fail=0`）
  - Step47 一键门禁 PASS：`out/artifacts/step47_prerelease/20260328-024343`
  - P1 扩表矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-024852`（`pass=112 fail=0`，`cases=14 modes=8`）
  - P1 分组扩表矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-025629`（`pass=112 fail=0`，group summaries generated）
  - P1 标签化分组矩阵 PASS：`out/artifacts/preclass_p1_matrix/20260328-030247`（`pass=112 fail=0`，external_* group metrics all 100%）
  - P1 grouped-threshold gate matrix PASS：`out/artifacts/preclass_p1_matrix/20260328-030802`（`pass=112 fail=0`，`group_gate_fail=0`，all groups `required_pct=100 gate_pass=True`）
  - P1 grouped-threshold file gate matrix PASS：`out/artifacts/preclass_p1_matrix/20260328-031626`（`pass=112 fail=0`，`group_gate=enabled source=file`，`group_gate_file` loaded with 5 tokens）
  - P1 grouped-threshold file+spec merge matrix PASS：`out/artifacts/preclass_p1_matrix/20260328-033525`（`pass=112 fail=0`，`group_gate=enabled source=file+spec`）
  - Step47 + P1 chained gate PASS：`out/artifacts/step47_prerelease/20260328-034742`（`readiness/ab/rollback/preclass-p1-gate` all pass）
  - Step47 + P1 chained gate (preflight) PASS：`out/artifacts/step47_prerelease/20260328-035333`（adds `preclass_gate=enabled` diagnostics; all four steps pass）
  - Step47 preflight regression PASS：`out/artifacts/step47_preclass_preflight/20260328-040255`（`pass=4 fail=0` across baseline/enable/missing-threshold/missing-case cases）
  - Remote Strict + preflight PASS：`out/artifacts/20260328-041658`（`Local hash verify PASS` + `Golden PASS` + `referral check PASS` + `Step47 preclass preflight PASS`）
  - Step47 preclass preflight suite PASS：`out/artifacts/step47_preclass_preflight/20260328-041704`（`pass=4 fail=0`）
  - Expanded P1 gate matrix PASS：`out/artifacts/preclass_p1_matrix/20260328-050157`（`pass=168 fail=0`，`group_gate_fail=0`）
  - Step47 prerelease (with preclass-p1-gate) PASS：`out/artifacts/step47_prerelease/20260328-050426`
  - Remote Strict + preflight rerun PASS：`out/artifacts/20260328-045150`（`Local hash verify PASS` + `Golden PASS` + `referral check PASS` + `Step47 preclass preflight PASS`）
  - Step47 preclass preflight suite rerun PASS：`out/artifacts/step47_preclass_preflight/20260328-045157`（`pass=4 fail=0`）
  - Strict task passthrough manual check PASS (`-K 1`)：`out/artifacts/step47_preclass_preflight/20260328-051817`（`pass=4 fail=0`，`result=pass`，elapsed `318s`）
  - Strict task passthrough manual check PASS (`-K 0`)：no `[STEP47-PREFLIGHT]` segment in strict task log, elapsed `198s`
  - Expanded P1 gate matrix (small-batch) PASS：`out/artifacts/preclass_p1_matrix/20260328-054446`（`cases=29 modes=8`，`pass=232 fail=0`，`group_gate_fail=0`）
  - Step47 prerelease (with preclass-p1-gate) rerun PASS：`out/artifacts/step47_prerelease/20260328-054950`
  - CIDR Contract Bundle rerun PASS：`out/artifacts/cidr_bundle/cidr_bundle_summary_20260328-045439.txt`（body `pass=4 fail=0`，matrix `pass=9 fail=0`）
  - Redirect Matrix 10x6 rerun PASS：`out/artifacts/redirect_matrix_10x6/20260328-045523`（`authMismatchFiles=0`，`errorFiles=0`）

English summary
- Full release-candidate verification (2026-08-23): after the response-classification fix, the default/debug Strict `lto-auto` rounds have no compile/LTO warnings, both nine-architecture SHA-256 lists recalculate with `9/9` matches, and Golden/referral checks pass (`out/artifacts/20260823-151731`, 292s; `20260823-152347`, 281s). All four Batch goldens pass (`152928/153443/154054/154744`, 1,356.781s); all four Selftest strategies plus the standalone core golden gate pass (`155355/155909/160500/161048`, 1,298.199s), with all four new classification-priority PASS lines matched and their FAIL forms forbidden. The 12x6 authority-mismatch table is empty with no errors (`redirect_matrix_10x6/20260823-161855`); CIDR body is `4/4`, draft matrix is `9/9`, and the bundle exits 0 (`cidr_bundle_summary_20260823-163528.txt`). The complete standalone core raw log still contains pre-existing network WARN/SKIP results and `injection-view-fallback: FAIL`; these are outside the golden all-green claim and are not regressions from this change. No code fix is required; semantics are frozen while version, release body, tag, and GitHub Release metadata are closed out.
- Deterministic response-classification regressions (2026-08-23): add the frozen-response `redirect-denied-priority`, `redirect-rate-limit-priority`, and `redirect-semantic-empty-priority` selftests. The first two drive the real redirect evaluator with bodies combining an authoritative `inetnum` field with denied/rate-limit markers, locking `Failure > Authoritative`, first-hop RIR cycling, failure-debt metadata, and visited cleanup. The semantic-empty case freezes pure banner/comment, non-authoritative markers inside comments, and authoritative-field boundaries, locking `Non-Authoritative > Semantic Empty > Authoritative`. Linux, win32, and win64 all pass; the core selftest golden gate requires each PASS line and forbids each FAIL form. Production behavior already satisfies the contract, so this slice does not change business logic.
- Deterministic redirect regression (2026-08-23): adds the frozen-response `redirect-invalid-key-priority` selftest, driving the real redirect evaluator with a body that contains both `%ERROR:115 invalid search key` and a referral. The first three-architecture run exposed that the invalid-key branch cleared the referral but continued classification, allowing `need_redir_eval` and `force_stop_authoritative` to be overwritten. The evaluator now enters its unified writeback immediately after clearing the referral, restoring the first-hop terminal contract for invalid queries. The core selftest golden gate now requires the PASS line and forbids its FAIL form; all three architectures pass after the fix.
- A/B round checkpoint Phase 1 (2026-08-23) is reduced to observational metadata. `start_dev_verify_8round_multiround.ps1` atomically writes `round_checkpoints/<round>.json` after every round with PASS/FAIL status, source-state summary, and key artifact paths; failure metadata records `recommended_recovery_mode=fast-pass`, `recommended_reset_policy=stage-default`, `source_mutation_policy=task-definition-only`, and the existing A/B launcher. Source summaries detect drift only: every post-failure code fix must enter the task definition and be replayed by code-step/fast-pass; direct business-source edits before restart are prohibited. Direct resume is not enabled and no checkpoint parameter or environment branch is added; the A repository baseline, B A-snapshot, and long-validated fast-pass behavior remain unchanged. The former Phase 2/3 route is formally closed: historical PASS source snapshots, direct resume, automatic recovery, and automatic continuation will not be implemented; any future evidence-backed bottleneck requires a new proposal. Advanced parameter binding rejects unknown parameters immediately, preventing a misspelled policy probe from launching the default eight-round workflow. Policy JSON, unknown-parameter fail-fast, PASS/FAIL write probes, PowerShell AST checks, and `ContractGateOnly` 16/16 pass.
- literal converge batch 3 (unattended A/B, vx55/vx56, window `2027-06-10 ~ 2027-06-23`, 2026-08-22~23): `SESSION=PASS` (A run=`out/artifacts/dev_verify_multiround/20260822-160200`, A elapsed=0d 07:56:10; B run=`out/artifacts/dev_verify_multiround/20260822-235721`, B elapsed=0d 07:18:34; A/B total `0d 15:13:58`), zero incidents/self-heal/restarts, A/B each inlined 15 (30 total) single-use literal helpers — **literal convergence project complete** (60 total across vx53~vx56); the remaining 6 multi-call/prototype helpers (`class_unknown`/`class_special`/`rir_unknown`/`v6_unique_local_reason`/`v6_link_local_reason`/`v6_multicast_reason`) are intentionally kept as named constants, no further inlining; classification semantics/output contracts/generated table unchanged. Final four-round golden + 12x6 matrix all PASS: Strict `lto-auto` default / `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first` two rounds no warnings + no LTO warnings + Local hash/Golden/referral all PASS (`out/artifacts/20260823-090004`, 268s; `20260823-090701`, 259s); Batch four-strategy golden all `[golden] PASS` (`20260823-091349/091840/092356/092948`, 1,198.287s); Selftest four strategies all `[golden-selftest] PASS` (`20260823-093542/094029/094550/095134`, 1,222.364s); 12x6 matrix empty authority table + `(no errors found)` (`out/artifacts/redirect_matrix_10x6/20260823-100221`). See `docs/RFC-address-space-preclassifier.md` 24.29 for the execution backfill.
- literal converge batches 1/2 (unattended A/B, vx53/vx54, window `2027-05-27 ~ 2027-06-09`, 2026-08-21~22): A/B both 8/8 rounds passed first try (A run=`out/artifacts/dev_verify_multiround/20260821-051747`, B run=`out/artifacts/dev_verify_multiround/20260821-121221`, A/B total `0d 14:33:38`), each inlined 15 (30 total) single-use literal helpers; classification semantics/output contracts/generated table unchanged; final Strict remote build smoke + golden (`lto-auto`) no-warning PASS (`out/artifacts/20260822-135204`, 255s, Local hash/Golden/referral all PASS). See `docs/RFC-address-space-preclassifier.md` 24.28 for the execution backfill.
- 24.23.7 code cleanup complete + consistency selftest frozen-value fix (2026-08-21): Slice A removes the duplicated observation branch in `whois_query_exec.c`; Slice B deletes the duplicate `wc_client_csv_is_default_marker` in `client_flow.c` and routes both call sites through the public `wc_preclass_csv_is_default_marker`; Slice C extracts `wc_preclass_ipv4_to_u32`/`wc_preclass_ipv6_to_u64` byte-assembly static helpers in `preclass.c` (byte conversion only, zero behavior change). Fixes two table-side frozen expectations in the built-in consistency selftest (`ff00::1`/`2001:db9::1`: `V6_MULTICAST`/`V6_GLOBAL_UNICAST` corrected to `V6_MULTICAST_FF00_8`/`V6_GLOBAL_UNICAST_2000_3` to match the generated table and reason map); Selftest Golden gains a standalone core `--selftest` gate (`golden_check_selftest.sh` adds `--forbid-line`, asserting the three preclass PASS lines and rejecting their FAIL forms plus any `[PRECLASS-CONSISTENCY]` diagnostic); `prune_artifacts_all.ps1` now retains `out/artifacts/core_selftest` (keep 8). All gates PASS: encoding gate, Fast build (`20260820-192402`), one-click gate set of 8 items (CIDR `4/4+9/9` `20260820-220634`, 12x6 empty authority table `20260820-223125`), Selftest Golden (core/raw/health/plan-a/plan-b all PASS, `20260821`), Batch Golden all four strategies PASS (`20260821`), Strict default+debug two rounds without warnings (`20260821-001350`/`002054`), 12x6 recheck with empty authority table and no errors (`20260821-013117`); release artifacts synced. See `docs/RFC-address-space-preclassifier.md` 24.27 for the execution backfill.
- Step47 validation contract aligned with Phase C (2026-08-19): `tools/test/step47_ab_compare.ps1` expectations move from `route_changed=1` (pre-flip base=hint-bypassed/trial=step47-short-circuit) to `route_changed=0` (after Phase C closure, high-confidence reserved/special implicit queries early-converge to `preclass-early-converge-unknown`), adding an `early_converge_mismatch` strong assertion to lock base/trial convergence. This only aligns the validation script and docs (RFC-address-space-preclassifier.md sections 16/19/20); business behavior is unchanged; `step47_ab_compare` and `step47_preclass_preflight_check` are green.
- Four-round Golden + 12x6 recheck after commit `7e1f2fa7` (2026-08-18): Strict lto-auto default/debug two rounds show no compile/LTO warnings, Local hash/Golden/referral all PASS (`out/artifacts/20260818-071217`, 224s; `20260818-072952`, 255s); the default round's 9-arch POSIX hashes exactly match the real-LTO baseline round `065540` (Windows PE timestamps differ), confirming LTO is truly enabled and the build is deterministic. Batch four-strategy Golden all PASS (`073512/073943/074445/075120`, 1185.080s); Selftest four strategies all `[golden-selftest] PASS` (`080108/080605/081113/081614`, 1201.862s) with reports containing `output line matched: 10\.0\.0\.8 is a private IP address`, proving the `--require-line` real-output assertion is effective and blocks marker-only false passes. 12x6 authority table is empty (`redirect_matrix_10x6/20260818-083320`); the only `afrinic_45.113.52.0_22` error is a LACNIC site rate-limit (hop 4/5 give-up) that re-converges to APNIC with `--prefer-ipv4 --rir-ip-pref arin=ipv6 "45.113.52.0/22" -h afrinic`, matching the historical rate-limit pattern for the same prefix — an external transient, not a code/script regression.
- Single-path force-private priority completed (2026-08-18): four-round Golden + 12x6 recheck after `22e0247f` all PASS. Audit found that a single-query `--selftest-force-private 10.0.0.8` was still short-circuited by Phase C early-converge (golden passed only via startup marker), while the batch loop had already been fixed. The check now runs before the single-query preclass decision, consulting `wc_query_exec_is_forced_private` with `net_ctx->injection` first and a global-view fallback, entering the real private branch without emitting a false early-converge observation; the golden checker adds `--require-line` defaulting to `10\.0\.0\.8 is a private IP address` to block marker-only false passes. The real-LTO artifact passes Phase C review `26/26` (`preclass_phasec_review/20260818-070138`); ordinary single-query implicit private queries still early-converge and explicit `-h` stays compatible.
- LTO remote-build alias fix (2026-08-18): audit found `remote_build_and_test.sh` normalized the profile before `getopts`, so CLI `-O lto-auto|lto-serial` never entered the Makefile `lto` branch; historical same-name rounds kept valid cross-arch/hash/Golden/referral/behavior evidence but did not constitute actual LTO warning evidence. Normalization now happens after argument parsing, and `remote_build.sh` explicitly exports `LTO_MODE/LTO_SERIAL/LTO_PARALLEL` to all POSIX/Windows make invocations. The x86_64 discriminator round `20260818-064740` clearly contains `-flto=auto`; the final all-arch round `20260818-065540` compiles/links with `-flto=auto` on all 9 arches, Local hash/Golden/three referrals all PASS, release synced (455s).
- Batch-path early-converge completion and selftest-golden expectation fix (2026-08-17): the four-round Golden + 12x6 recheck found the raw selftest golden actually FAILed (`batch_raw/20260817-051757`) — after the Phase C flip, single-query `10.0.0.8` early-converges to `unknown @ unknown`, but the batch flow still prints the private hint, and the missing `pipefail` in `selftest_golden_suite.ps1` masked the real failure as PASS while the prefilled `-ErrorPatterns 'private IP address'` could not match the early-converge form. Fixed: normal implicit batch early-converge candidates enter Phase C; explicit `-h` and `--selftest-force-private` keep real private handling; both selftest golden wrappers use `set -o pipefail` + `2>&1 | tee` with fail-close on missing strategies, invalid tags, or nonzero checkers; tasks.json ErrorPatterns switched to `Suspicious query detected;Private query denied` with explicit SelftestExpectations as authoritative, plus restored WORKBUF tag assertion. C built-in selftest adds `preclass-phasec-force-private-priority`. Final fast build `out/artifacts/20260817-081022` (163s, Local hash PASS), extended Phase C review `24/24 PASS` (`preclass_phasec_review/20260817-075434`); the single 12x6 `lacnic_45.113.52.0_22` rate-limit (`redirect_matrix_10x6/20260817-060124`) recovered to APNIC on an identical single-case rerun — an external LACNIC transient, no rule/code change.
- Phase C default-on and Address-Space preclassifier closure (2026-08-17): high-confidence IANA `reserved|special + rir=none` implicit queries now early-converge to `unknown @ unknown` by default; explicit `-h` stays compatible and `--disable-address-preclass` keeps full fallback. Phase C `20/20`, special-purpose `17/17`, P0 `12/12`, P1 `232/232`, CIDR `4/4 + 9/9`, Step47, 12x6 all PASS (`out/artifacts/redirect_matrix_10x6/20260817-033253`); final 9-arch Strict hash/Golden/referral PASS (`out/artifacts/20260817-034423`, 302s); release artifacts synced.
- 2026-08-17 four-round Golden and matrix recheck: Strict lto-auto default/debug two rounds show no compile/LTO warnings, Local hash/Golden/referral all PASS (`out/artifacts/20260817-000833`, 305s; `20260817-001953`, 290s). Batch Golden all four strategies PASS (`002627/003207/003826/004414`, 1357.129s); Selftest Golden all four strategies PASS (`010022/010604/011235/011843`, 1410.913s). 12x6 authority-mismatch table empty; the only `lacnic_45.113.52.0_22` rate-limit error (`redirect_matrix_10x6/20260817-014619`) recovered to APNIC on an identical single-case rerun — external transient, no code or static-expectation change.
- Final four-round Golden and redirect-matrix recheck (2026-08-16): Strict lto-auto default and debug/metrics/DNS-family rounds both show no compile/LTO warnings, 9-arch SHA-256 list recalculated with zero mismatch, Local hash/Golden/three referrals all PASS (`out/artifacts/20260816-203059`, 276s; `20260816-203903`, 286s). Batch raw/health-first/plan-a/plan-b all Golden PASS (`20260816-204504/205026/205622/210225`, 1315.436s); selftest four strategies all `[golden-selftest] PASS` (`20260816-210950/211526/212129/212741`, 1369.958s). Final 12x6 authority-mismatch table empty, errors=`(no errors found)` (`redirect_matrix_10x6/20260816-213231`). No code fix needed this round.
- Unified terminal failure-node recheck (2026-08-16): adds an extensible per-RIR failure registry with reason bitmask, initially covering `denied`, `rate-limit`, and `EMPTY-RESP give-up`. Only when RIR polling is exhausted, authority is still undecided, the hop cap is not hit, and not inside a nested recheck guard, each node is re-queried once (`no_redirect=1/max_hops=1`) in first-failure order; authoritative responses settle the failure debt and converge, ERX/referral-style non-authoritative responses only add evidence and keep the debt, and failures keep the original terminal state. Adds stderr `[TERMINAL-RETRY] action=attempt|result host=... reasons=0x... result=authoritative|non-authoritative|failed` and `terminal-retry-registry/policy` selftests. P0 `12/12`, special `17/17`, CIDR bundle `4/4 + 9/9`, 12x6 `authMismatchFiles=0 errorFiles=0` (`redirect_matrix_10x6/20260816-194455`) pass; all-arch Strict lto-auto Local hash/Golden/referral all PASS (`20260816-201756`, 325s).
- Release-candidate full-chain recheck (2026-08-16): Strict lto-auto default and debug/metrics rounds show no compile/LTO warnings; Local hash/Golden/referral all PASS (`out/artifacts/20260816-152132`, 250s; `20260816-152908`, 278s). Batch raw/health-first/plan-a/plan-b all Golden PASS (`20260816-153443/153930/154447/155008`, 1167.514s); selftest four strategies all `[golden-selftest] PASS` (`20260816-155757/160310/160845/161433`, 1272.104s). First 12x6 run had `errorFiles=0`; only `lacnic_158.60.0.0_16` fell to `unknown` due to consecutive empty APNIC-hop responses while the other five starts converged to APNIC; two identical targeted reruns recovered APNIC — external transient, not a rule/code regression. A full 12x6 rerun then reached `authMismatchFiles=0 errorFiles=0` (`redirect_matrix_10x6/20260816-173702`); the original transient evidence stays at `20260816-161935`.
- Batch-strategy Golden gate fix (2026-08-16): after Phase B default first-hop, health-first/plan-a/plan-b penalty fixtures intentionally start `8.8.8.8` from IANA, but the suite checked them against raw's ARIN-direct baseline; meanwhile the success-stream text polluted the structured return objects of `Invoke-Strategy`/`Invoke-Golden`, so the three Golden FAILs were aggregated as PASS. Now raw=ARIN-direct, penalty strategies=IANA→ARIN are fixed per strategy, plan-b's `force-last|force-override` is asserted as either/or, stderr is captured into reports, and any failure propagates exit code 3. Adds a `-SkipRemote` local replay entry reusing the latest logs; the original four logs replay all PASS and a negative injection yields `Summary: FAIL`/exit 3.
- Phase B default first-hop fix (2026-08-16): fixes `wc_opts_init_defaults()` not initializing `preclass_first_hop_enable`, which let a parsed zero value override the Config default and keep ordinary allocated/legacy implicit queries starting from IANA. Now `1.1.1.1` defaults to APNIC and `8.8.8.8` to ARIN; explicit `-h` continues to bypass and `--disable-address-preclass` falls back to IANA. The P0 matrix accepts the formal decision action `classifier-rir-hint route_change=1`; `golden_check.sh` default baseline updates from the IANA→ARIN referral to ARIN-direct for `8.8.8.8` while keeping explicit `--start/--auth` historical-chain checks. All-arch Strict lto-auto rerun shows no compile/LTO warnings with Local hash/Golden/referral PASS (`20260816-134711`, 336s).
- IANA special-purpose overlay (2026-08-16, still off by default): the preclass generator upgrades to schema v2, consuming the repo-pinned four IANA CSVs plus a manifest, merging by longest prefix with special-first on equal prefixes, and producing `covering_rir/registry/purpose/globally_reachable/reserved_by_protocol` metadata. Under `--enable-preclass-early-converge` it adds Address Status and unifies the authoritative tail of special-purpose successes to `unknown @ unknown`; explicit `-h` keeps the body without causing authority drift. Dedicated offline matrix `10/10 PASS` plus `17/17 PASS` across seven starts (IANA/APNIC/ARIN/RIPE/AFRINIC/LACNIC/Verisign); the final release artifact reruns `17/17 PASS` (`out/artifacts/preclass_special_registry/20260816-113551`). Schema-v2 table guard PASS (`out/artifacts/preclass_table_guard/20260816-110940`); all-arch Strict, hash, Golden, referral PASS (`20260816-113503`).
- 49/50 gap validation backfill (2026-08-16): fixes the Windows `getopt_long` shim that stopped at positional args and failed to permute `-h arin` placed after a query; adds an `opts-permuted-parser` regression. win32/win64 both restore ARIN start/authority for `203.0.113.0/24 -h arin`; CIDR body contract `4/4 PASS`, draft TSV `9/9 PASS` (`cidr_bundle_summary_20260816-042354.txt`). Redirect IPv4 first round `66/66 PASS`; one LACNIC rate-limit environmental transient appeared on the post-fix rerun (single case immediately recovered to `unknown`); Redirect 10x6 stable `authMismatchFiles=0`, `errorFiles=0`; Batch Strategy Golden raw/health-first/plan-a/plan-b all PASS (total `1775.592s`).
- Phase C selftest live run (2026-08-16): the new `preclass-phasec-policy`, `preclass-phasec-route`, explicit-host bypass, and short/long option parser assertions in `whois-win64.exe --selftest` all PASS; the pre-existing `injection-view-fallback` still FAILs with network-related WARN/SKIP, confirmed not introduced by 49/50; Phase C remains off by default.
- Golden script static fix (2026-08-16): fixes ShellCheck `SC2016` in `tools/test/golden_check_selftest.sh`; passes Bash syntax, help entry, and error-branch regressions; commit `c756e2cf` pushed to `origin/master`.
- 43/44 Vx A/B unattended recheck fix (2026-08-11): V1-V4 code-fault tickets now explicitly record the actual failing round; V2 keeps the existing runtime-trim semantics (safe `D-NOP` count 1-2 among D1-D3 allows fast-skip, `unknown-unexplained` still blocks it); the terminal-summary default gate upgrades from trigger/sender action to a same-ticket ledger `status=done + handled_at` receipt, with the trigger staying resident and redelivering the original ticket/brief on a 90-second cooldown until confirmed, instead of creating a duplicate final ticket. `status_ticket_mini_regression.ps1` gains the corresponding regression.
- Ticket-message integrity fix (2026-07-23): fixes `dispatch_takeover_to_chat.ps1` truncating every normal business message over 4000 chars as transcript noise (65%/35% split mid-text). Historical dispatch-log audit found 1476 `incident-captured` records hitting only `length_cap_chars=1` with `removed_lines=0` and `transcript_blocks_removed=0`; no line-based truncation found. The formatter now keeps the full business body for all ticket types by default, filtering only recognized command-panel/terminal transcript noise; explicit `MaxChars`/`MaxLines` keep bounded truncation. The quick contract gate adds long-body, explicit-limit, and transcript-filter dynamic regressions.
- A/B launch and resume precheck speedup (2026-07-23): `check_unattended_ab_launch_ready.ps1` keeps the default gates for task-definition SyntaxOnly, field sync, changed-file encoding, processes, SSH, and remote lock, and moves status-ticket, retry-budget, route-guard, and full-repo format/encoding regressions behind explicit opt-in; the duplicate full status-ticket regression inside fastmode A/B is removed. Stage A dry-run drops from ~8m35s to ~31s; the strong anchor for task-definition-fix tickets switches to `status_ticket_mini_regression.ps1 -ContractGateOnly` (~5min to ~5s), pinned before launch-ready, main-process restart, and recovery transaction. The three-minute atomic-closeout target window semantics are kept; the original 240s stage-process and 120s acknowledge budgets are not tightened. Stage B still fail-fasts before later checks when no A PASS snapshot exists, but gains baseline START/DONE progress; the full suite remains covered by standalone scripts and release gates.
- Retry-budget focused-regression speedup (2026-07-23): `retry_budget_minimal_regression.ps1` now seeds one shared session floor and validates the yes/missing/no receipts via the poll ack-only fast path instead of re-seeding and re-selecting a ticket per case; PowerShell/poll calls drop from 9 to 4, locally measured from 92.2s to 46.9s, with all three ledger terminal states unchanged.
- Recovery-transaction no-kill contract (2026-07-23): clarifies that the "3-minute closeout target" could be misread as a transaction wall-clock ceiling; `.github/copilot-instructions.md`, flow/prompt/start templates, guard/stage-window/dispatch runtime hints, and takeover briefs uniformly state that `recovery_transaction_command` runs once and waits for the sync command to exit naturally, never killing, `Stop-Process`-ing, terminating the terminal, or cancelling the transaction merely for exceeding 3 minutes or 240s. 240s remains only the in-transaction stage-start validation budget; atomic closeout keeps its 120s acknowledge timeout; results are judged solely by exit code and JSON machine facts. The full status-ticket regression adds cross-layer static anti-regression.
- Stage-window launch-ready diagnostics fix (2026-07-23): fixes `open_unattended_ab_stage_window.ps1` treating launch-ready stderr progress lines as terminal errors under `$ErrorActionPreference=Stop`, showing only `status=START` with an empty `result=`. Launch-ready sub-steps now use `Start-Process` with separated stdout/stderr capture and nonzero exit codes; stage-window capture uses local `Continue` and still fail-closes on exit code and PASS marker; checker-mutex conflicts now clearly output DONE exit 4, `single_instance_conflict`, and a persisted blocker detail.
- Script faults diagnose-only by default (2026-07-16): start-file gains `LOCAL_GUARD_SCRIPT_SELF_HEAL_ENABLED=false`. When the field is missing, empty, or false, guard/trigger/route guard/poll/dispatch jointly force `incident-script-diagnose-only`, allowing only read-only evidence, root-cause analysis, a fix proposal, chat reporting, and atomic closeout; file changes, process control, restart/resume, environment modification, and script creation are forbidden. The original script self-heal flow only exists when explicitly enabled.
- Route-classification convergence (2026-06-12): `tools/test/check_takeover_route_guard.ps1` now splits incident handling into dedicated `script-fix` / `code-fix` / `noncode` lanes, and adds notice-specific classes (`notice-manual-wait`, `notice-budget-exhausted`, `notice-known-infra-transient`) to avoid mixed recovery flows.
- Trigger/dispatch alignment to detailed lanes (2026-06-12): `tools/test/unattended_ab_takeover_trigger.ps1` now emits detailed `route_guard_expected`; `tools/test/dispatch_takeover_to_chat.ps1` routes by classification into dedicated templates (script-fix, code-fix, noncode, notice), replacing the previous generic non-status recovery path.
- Trigger route-guard gate smoke on trigger path (2026-06-12): add `tools/test/trigger_route_guard_gate_smoke.ps1` and an optional VS Code task entry `Test: Trigger Route Guard Gate Smoke` in `.vscode/tasks.json`; update `docs/UNATTENDED_AB_OPERATION_FLOW_CN.md` (section 4.10) with command, pass criteria, and evidence paths.
- Trigger route-guard gate smoke validation (2026-06-12): local rerun returns `result=pass` with checks `status_allowed=True`, `incident_allowed=True`, `status_failed=True`, and `incident_failed=True`; evidence directory is `out/artifacts/trigger_route_guard_gate_smoke/20260612-030100` (`summary.json`, `evidence.log`).
- Chat-dispatch policy source-key consolidation (2026-05-25): added `tools/test/chat_dispatch_policy_compiler.ps1`; `tools/test/open_unattended_ab_stage_window.ps1` and `tools/test/open_unattended_ab_resume_window.ps1` now compile `AI_CHAT_POLICY_*` into derived `AI_CHAT_DISPATCH_*` keys at launch; added memo RFC `docs/RFC-unattended-chat-dispatch-policy-v1.md` and indexed it in `docs/README.md` and `docs/RFC-whois-client-split.md`.
- Sender-sent final-stop gate and cross-sender fallback (2026-05-25): `tools/test/unattended_ab_takeover_trigger.ps1` now supports `AI_CHAT_POLICY_FINAL_STOP_GATE=sender-sent` (requires `sender_sent=true` in `latest_relay_<start-token>.json` before auto-stop); `tools/test/dispatch_takeover_to_chat.ps1` adds sender primary/fallback resolution plus cross-sender fallback toggle and persists `sender_fallback_enabled` in relay state; minimal integration evidence is in `out/artifacts/ab_agent_queue/takeover_trigger_unattended_ab_start_sender_gate_smoke.log`.
- Stale PowerShell warning-cache troubleshooting added (2026-04-23): `docs/OPERATIONS_CN.md` and `docs/OPERATIONS_EN.md` now document how to handle lingering legacy-function diagnostics; recommended order is terminal verification via `Invoke-ScriptAnalyzer -Path <script.ps1>`, then reopen file -> Reload Window -> Restart Language Server.
- A/B guard low-noise logging + V1 loop policy alignment (2026-04-25): `tools/test/unattended_ab_session_guard.ps1` now prints restart pasted blocks as split begin/end + separator lines to reduce log noise; `docs/UNATTENDED_AB_START_TEMPLATE_CN.md` now documents `LOCAL_GUARD_AUTO_FIX_*` and `LOCAL_GUARD_MANUAL_WAIT_*` keys plus the responsibility boundary (guard orchestrates; in-session agent performs code fixes).
- Unattended runtime optimization landed (2026-04-10): `tools/test/autopilot_dev_recheck_8round.ps1` now supports `-VerifyExecutionProfile full|d6-only` and `-EnableGateOnlySourceDrivenSkip`; under `d6-only`, VERIFY rounds can skip `local/no-delta` while retaining D6 double-round consistency gates.
- Task-design quality controls landed (2026-04-11): `tools/test/start_dev_verify_8round_multiround.ps1` and `tools/test/start_autopilot_8round_code_change.ps1` now support `-TaskDesignQualityPolicy`, `-UnknownNoOpBudget`, `-UnknownNoOpConsecutiveLimit`, and `-DisableUnknownNoOpBudgetGate`; DEV no-op handling is upgraded from binary delta checks to classified no-op with budgeted risk blocking.
- Wrapper defaults updated (2026-04-10): `tools/test/start_dev_verify_8round_multiround.ps1` and `tools/test/start_autopilot_8round_code_change.ps1` now default to `VerifyExecutionProfile=d6-only` and enable safe gate-only skip by default (preserving D1 baseline and V3 mixed-sample verification).
- A/B serial checklist backfill completed (2026-04-25, serial batch 11/12): Checklist A at `out/artifacts/dev_verify_multiround/20260423-122600` and Checklist B at `out/artifacts/dev_verify_multiround/20260424-025440` both reached `rounds_pass=8/8` with `result=pass`; B V2 is policy `V-SKIP` (`fast-skip-v2-d-nop-count-2-of-3`) with `RoundPass=True`.
- Unattended whitelist auto-healing (2026-04-16): only three allowlisted actions are enabled. `tools/test/autopilot_code_step_rounds.ps1` now applies constrained replacement de-escaping for double-escaped `regex-patch` payloads and emits `[CODE-STEP-AUTOHEAL]`; `tools/test/autopilot_dev_recheck_8round.ps1` extends known preflight transient signatures (keeps `pass=3 fail=1`, adds `pass=4 fail=1 + valid-threshold fail + rollback/mismatch`); strict-failure short-circuit (`short_circuit=skip-p0-p1`) remains enforced by `tools/test/d6_consistency_double_run.ps1`.
- Autonomous conservative 8-round cycle for 2026-04-18~2026-04-25 has been backfilled (executed on 2026-04-09) at `out/artifacts/dev_verify_multiround/20260409-154303` with `rounds_pass=8/8`; D1~D3 are `CodeStepAction=applied + SourceDeltaAfterCodeStep=changed`, D4 is `already-applied + unchanged`, and V1~V4 are all `RoundPass=True`.
- A/B serial checklist backfill completed (2026-04-10): Checklist A first run at `out/artifacts/dev_verify_multiround/20260410-025505` failed at V2 and then converged after rerunning V2~V4 via `out/artifacts/dev_verify_multiround/20260410-065857`; Checklist B at `out/artifacts/dev_verify_multiround/20260410-084332` passed in one shot with `rounds_pass=8/8`.
- A/B serial checklist backfill completed (2026-04-10, 2026-05-12~2026-05-27 draft pair): Checklist A at `out/artifacts/dev_verify_multiround/20260410-180931` and Checklist B at `out/artifacts/dev_verify_multiround/20260410-223605` both reached `rounds_pass=8/8`; both V2 rounds passed via `V-SKIP` (`fast-skip-v2-d-nop-count-0-of-3`) with no rerun required.
- Review addendum: V3 non-default sample revalidation is complete; the query set is `64.6.64.6 103.53.144.0/22 2620:fe::fe` (`v4 + v4 CIDR + v6`), with evidence at `out/artifacts/autopilot_dev_recheck_8round/20260409-203629/summary.csv`.
- Autonomous conservative 4-round revalidation is complete (2026-04-06): `out/artifacts/autopilot_four_round/20260406-070404` reports `rounds_pass=4/4` with `RoundPass=True` in all four rounds, while default semantics and output contracts remain stable.
- Multi-round executable runbook (2026-04-15~2026-04-18) is now closed out, with actual execution completed on 2026-04-06 and all Round1~Round4 gates passing under unchanged default semantics.
- one-click sync hardening (2026-04-06): `tools/release/one_click_release.ps1` now correctly forwards multi-directory `RbSyncDir`, adds root-path guard rails, and fixes single-path scalarization mis-detection that previously produced `-s '/'`.
- Round3 P1 robustness gates PASS (2026-04-06): `out/artifacts/preclass_p1_matrix/20260406-050306` (`pass=232 fail=0 group_gate_fail=0`) plus `out/artifacts/step47_prerelease/20260406-050626`.
- Round4 pre-release chain PASS (2026-04-06): `out/artifacts/oneclick_dryrun_guard/20260406-051011`, `out/artifacts/20260406-051450`, `out/artifacts/cidr_bundle/cidr_bundle_summary_20260406-051848.txt`, `out/artifacts/redirect_matrix_10x6/20260406-051916`, and `out/artifacts/step47_prerelease/20260406-052449`.
- Dry-run guard smoke extension (2026-04-03): `tools/test/oneclick_dryrun_guard_smoke.ps1` now supports BuildAndSync passthrough parameters and `-RequireStaticsDetectedIfBuildSync` assertion, including empty-argument passthrough compatibility fixes and `statics_detected_check` ordering fix; add task `Test: One-Click DryRun Guard (build+sync)`. Controlled run PASS at `out/artifacts/oneclick_dryrun_guard/20260403-051110` (`statics_detected=true`, `statics_commit_pushed=false`, `result=pass`).
- Dry-run guard smoke enhancement (2026-04-03): `tools/test/oneclick_dryrun_guard_smoke.ps1` now records and compares git workspace snapshots (`git_status_before.txt` / `git_status_after.txt`); when `BuildAndSyncIf=false`, it requires `git_state_unchanged=true`. Enhanced smoke PASS at `out/artifacts/oneclick_dryrun_guard/20260403-045829`.
- Dry-run guard smoke taskization (2026-04-03): add `tools/test/oneclick_dryrun_guard_smoke.ps1` and task `Test: One-Click DryRun Guard (local)` to automatically validate key `[ONECLICK-DRYRUN-GUARD]` fields (skip_tag/skip_github_release/skip_gitee_release/statics_commit_pushed/guard_result); first run PASS at `out/artifacts/oneclick_dryrun_guard/20260403-045451`.
- Second rerun of the double-round consistency gate (2026-04-03): `tools/test/d6_consistency_double_run.ps1` was executed again with PASS evidence at `out/artifacts/d6_consistency_double_round/20260403-043011`; Round1 `STRICT/PREFLIGHT/TABLE_GUARD=20260403-043313/20260403-043322/20260403-043700`, Round2 `20260403-044318/20260403-044326/20260403-044719`, with P0/P1 regressions still fully passing in both rounds.
- First real run of the double-round consistency gate (2026-04-03): the initial execution of `tools/test/d6_consistency_double_run.ps1` is PASS with evidence at `out/artifacts/d6_consistency_double_round/20260403-035824`; Round1 `STRICT/PREFLIGHT/TABLE_GUARD` timestamps are `20260403-040118/20260403-040126/20260403-040519`, Round2 are `20260403-041423/20260403-041435/20260403-041845`, and both rounds pass P0/P1 preclassifier regressions.
- Double-round consistency gate taskization (2026-04-03): add `tools/test/d6_consistency_double_run.ps1` and VS Code task `Gate: D6 Double-Round Consistency`. The gate runs two fixed rounds of `Remote Strict(-K 1 -N 1)` plus preclassifier P0/P1 regressions and emits unified evidence under `out/artifacts/d6_consistency_double_round/<ts>` with `[D6-CONSISTENCY]` summary lines (`summary.csv/summary.txt`).
- Explicit dry-run side-effect assertions (2026-04-03): `tools/release/one_click_release.ps1` now emits a structured `[ONECLICK-DRYRUN-GUARD]` line exposing `skip_tag/skip_github_release/skip_gitee_release/statics_detected/statics_commit_pushed/result` so release automation can verify dry-run semantics directly; local quick check (`-BuildAndSyncIf false -DryRunIf true`) reports `result=pass`.
- Preflight stability hardening (2026-04-03): `tools/test/step47_preclass_preflight_check.ps1` now adds a conditional single retry (max 1) for the `gate-enabled-valid-threshold` case, triggered only when rollback-failure signatures are present; each attempt is persisted as an independent log (including `.retry1.log`) with an `action=retry` diagnostic line. Regression PASS: `out/artifacts/step47_preclass_preflight/20260403-032214` (`pass=4 fail=0`).
- Checklist execution (2026-04-03, for the 2026-04-02 plan): D6 merged-path validation is PASS. Remote Strict with `-K 1 -N 1` passed at `out/artifacts/20260403-021119`, with preflight `out/artifacts/step47_preclass_preflight/20260403-021128` and table guard `out/artifacts/preclass_table_guard/20260403-021940`. One-click dry-run full-chain had an initial preflight rollback fluctuation (`out/artifacts/step47_preclass_preflight/20260403-022527`) and converged on rerun: `out/artifacts/20260403-023609`, `out/artifacts/step47_preclass_preflight/20260403-023618`, `out/artifacts/preclass_table_guard/20260403-024219`; dry-run safeguards were confirmed (skip statics commit/push and skip GitHub/Gitee release updates). 23.6 table-guard regression is PASS at `out/artifacts/preclass_table_guard/20260403-024312`; preclassifier dual gates are PASS at `out/artifacts/preclass_matrix/20260403-024349` and `out/artifacts/preclass_p1_matrix/20260403-024822`.
- D6.1 one-click safe dry-run (2026-04-01): `tools/release/one_click_release.ps1` adds `-DryRunIf <true|false>` (default `false`). When enabled, it force-skips tag creation, GitHub/Gitee release updates, and statics auto commit/push while still allowing optional build/sync path validation. `.vscode/tasks.json` adds `oneClickDryRun` and wires it into the `One-Click Release` task. Smoke PASS: `powershell -NoProfile -ExecutionPolicy Bypass -File tools/release/one_click_release.ps1 -Version 3.2.12 -BuildAndSyncIf false -DryRunIf true -SkipTagIf false` (prints `one-click done: dry-run mode; tag=v3.2.12`).
- D6 remote/release table-guard pass-through (2026-04-01): `tools/remote/remote_build_and_test.sh` adds `-N/-B` (optional preclass table-guard execution, default OFF), `tools/release/one_click_release.ps1` adds `-RbPreclassTableGuard/-RbPreclassTableGuardScript`, and `.vscode/tasks.json` adds `rbPreclassTableGuard/rbPreclassTableGuardScript` inputs and wires both `Remote: Build (Strict Version)` and `One-Click Release`; default semantics remain unchanged. Validation run (`-K 0 -N 1`) PASS at `out/artifacts/20260401-035628` with guard evidence `out/artifacts/preclass_table_guard/20260401-035634`.
- D3 consistency closure (2026-04-01, dual full-chain rounds): two consecutive rounds in fixed order all PASS, Remote Strict (`-K 0`) -> CIDR Contract Bundle -> Redirect Matrix 10x6 -> Step47 prerelease (with preclass-p1-gate); evidence paths are Round1 `out/artifacts/20260401-023614`, `out/artifacts/cidr_bundle/cidr_bundle_summary_20260401-023738.txt`, `out/artifacts/redirect_matrix_10x6/20260401-023834`, `out/artifacts/step47_prerelease/20260401-024532`, and Round2 `out/artifacts/20260401-025245`, `out/artifacts/cidr_bundle/cidr_bundle_summary_20260401-025312.txt`, `out/artifacts/redirect_matrix_10x6/20260401-025346`, `out/artifacts/step47_prerelease/20260401-030103`.
- D2 action-gate backfill (2026-04-01): add the missing standalone D2 record in section 23 (implementation was already present); fresh evidence includes P1 gate matrix PASS (`out/artifacts/preclass_p1_matrix/20260401-032155`) and Step47 chained preclass gate PASS (`out/artifacts/step47_prerelease/20260401-032539`).
- D5 Step47 optional table-guard chaining (2026-04-01): `tools/test/step47_prerelease_check.ps1` now supports `-RunPreclassTableGuard/-PreclassTableGuardScript`, and task `Test: Step47 PreRelease + Table Guard (reserved, list file)` is added; chained validation PASS at `out/artifacts/step47_prerelease/20260401-033633` with `preclass-table-guard` evidence at `out/artifacts/preclass_table_guard/20260401-033643`.
- 23.6 executable assertions automation (2026-04-01): add `tools/test/preclass_table_guard.ps1` and task `Test: Preclass Table Guard (RFC 23.6)` to enforce manifest source-hash consistency, generated-table row-count consistency, and reverse mapping coverage for all in-table `reason_id` values; run PASS at `out/artifacts/preclass_table_guard/20260401-031509` (`summary.json`/`summary.txt`).
- Visible golden-evidence rerun (2026-04-01): Remote Strict (`-K 0`) PASS at `out/artifacts/20260401-022732`, with generated `golden_report.txt` showing `[golden] PASS`, `referral check PASS`, and zero `[STEP47-PREFLIGHT]` log entries.
- Address-space preclassifier D1 lookup wiring (2026-04-01): `src/core/preclass.c` now wires `wc_preclass_table` lookups with `class/rir/reason/confidence` ID mapping, while keeping compatibility branches for private/special/global-unicast handling; validation: Remote Strict PASS (`out/artifacts/20260401-014329`) + preclass minimal matrix PASS (`out/artifacts/preclass_matrix/20260401-014502`) + Step47 readiness PASS (`out/artifacts/step47_matrix/20260401-014542`).
- Address-space preclassifier D0 first landing (2026-04-01): add generator `tools/preclass/gen_preclass_table.py` with reason map `tools/preclass/reason_code_map.json`, and generate `include/wc/wc_preclass_table.h`, `src/core/preclass_table.c`, and `out/generated/preclass_manifest.json`; this run produced `rows=276` (`v4=256`, `v6=20`, `schema_version=1`).
- Checklist gates rerun (2026-04-01): Remote Strict (`-K 0`) + CIDR Contract Bundle + Redirect Matrix 10x6 + Step47 prerelease (with preclass-p1-gate) all PASS; evidence paths are `out/artifacts/20260401-001630`, `out/artifacts/cidr_bundle/cidr_bundle_summary_20260401-002629.txt`, `out/artifacts/redirect_matrix_10x6/20260401-002732`, `out/artifacts/step47_prerelease/20260401-003752`.
- Checklist item 3 completed (2026-04-01): PASS one-paragraph quick post and full recap block are now filled in `docs/release_bodies/next-major-compat-announcement-draft.md` (`-K 0` run, `PREFLIGHT_TS=N/A`).
- Checklist item 4 completed (2026-04-01, not triggered): no `%ERROR:201` or persistent denial noise was observed, so parameterized revalidation was not required; a not-triggered record sample is now added to the recap template.
- Checklist kickoff gates rerun (2026-03-31): completed Remote Strict (with preflight) -> CIDR Contract Bundle -> Redirect Matrix 10x6 -> Step47 prerelease in fixed order, all PASS; evidence paths are `out/artifacts/20260331-223717`, `out/artifacts/step47_preclass_preflight/20260331-223727`, `out/artifacts/cidr_bundle/cidr_bundle_summary_20260331-225134.txt`, `out/artifacts/redirect_matrix_10x6/20260331-225650`, `out/artifacts/step47_prerelease/20260331-230718`.
- Executable design skeleton drafted (2026-03-31): section 23 is added in `docs/RFC-address-space-preclassifier.md`, covering data model, generator script I/O, lookup APIs, gate assertions, rollout order, and rollback points.
- P1 candidate source governance (2026-03-28): add `--preclass-action-list <csv>` to override the default candidate set from `--preclass-action-tier r0|r1` (exact CSV match, case-insensitive); defaults remain unchanged (`unset/default` keeps tier defaults).
- P1 CSV default normalization (2026-03-28): `--preclass-action-list` and `--step47-early-unknown-list` now accept surrounding whitespace on the `default` marker (for example `" default "`), while keeping the single-token default semantics.
- P1 real-sample matrix expansion (2026-03-28): `tools/test/preclass_p1_gate_matrix.ps1` adds `-CaseListFile` and appends IP samples from `testdata/preclass_p1_real_samples.txt` by default.
- P1 grouped sample summaries (2026-03-28): `tools/test/preclass_p1_gate_matrix.ps1` supports `group|ip` case lines and emits `summary_group.csv` / `summary_group.txt` plus `[PRECLASS-P1-GROUP]` pass-rate logs.
- P1 labeled sample set (2026-03-28): `testdata/preclass_p1_real_samples.txt` is upgraded to `group|ip` labels (`external_public_v4/external_private_v4/external_cgnat_v4/external_public_v6`).
- P1 grouped threshold gate (2026-03-28): `tools/test/preclass_p1_gate_matrix.ps1` adds `-GroupPassThresholdSpec` (for example `default=100,external_public_v4=95`), emits `required_pct/gate_pass`, and includes grouped gate failures in `group_gate_fail` exit status.
- P1 threshold-file input (2026-03-28): `tools/test/preclass_p1_gate_matrix.ps1` adds `-GroupPassThresholdFile <path>` (for example `testdata/preclass_p1_group_thresholds_default.txt`), accepts line-based or `,`/`;` separated tokens, and merges with `-GroupPassThresholdSpec` (spec overrides).
- P1 prefilled task (2026-03-28): add VS Code task `Test: Preclass P1 Gate Matrix (threshold file)` to run grouped-threshold gating with the default threshold file in one click.
- Optional P1 gate in Step47 chain (2026-03-28): `tools/test/step47_prerelease_check.ps1` adds `-RunPreclassP1Gate` (off by default); when enabled it appends a `preclass-p1-gate` step and forwards `-PreclassCaseListFile/-PreclassGroupThresholdFile/-PreclassGroupThresholdSpec`.
- Step47 preflight checks (2026-03-28): with `-RunPreclassP1Gate`, the script now validates preclass script/path inputs up front and emits `preclass_gate=enabled|disabled` diagnostics for clearer failure attribution.
- Step47 preflight regression (2026-03-28): add `tools/test/step47_preclass_preflight_check.ps1` (task: `Test: Step47 Preclass Preflight Check`) to cover baseline, enabled, missing-threshold, and missing-case scenarios.
- Remote strict preflight integration (2026-03-28): add `-K/-C/-V` to `tools/remote/remote_build_and_test.sh` to run local Step47 preclass preflight after remote fetch; add `-RbPreflight` in `tools/release/one_click_release.ps1` and forward it to the remote script.
- Task wiring update (2026-03-28): add `rbPreflight` in `.vscode/tasks.json`; `Remote: Build and Sync whois statics` now appends `-K 1` by default; `One-Click Release` forwards `-RbPreflight ${input:rbPreflight}`.
- Strict task wiring update (2026-03-28): `Remote: Build (Strict Version)` now forwards `-K ${input:rbPreflight}` so preflight can be toggled directly in strict runs.
- Phase completion marker (2026-03-28): P2 closure criteria are now satisfied (parameter pass-through loop closed + all three release gates green + both Step47 chains green + manual strict `-K` verification), with default semantics unchanged; work moves to finalizing the release-side regression checklist.
- Release-side regression checklist finalized (2026-03-28): `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` now define the fixed gate order, pass criteria, fail-fast policy, and minimum evidence-retention requirements.
- Small-batch real-sample expansion (2026-03-28): add 9 grouped samples in `testdata/preclass_p1_real_samples.txt` (public_v4/private_v4/cgnat_v4/public_v6) for incremental release-side regression.
- Release-day recap template aligned (2026-03-28): `docs/release_bodies/next-major-compat-announcement-draft.md` now mirrors the fixed 4-gate checklist with pass-criteria and evidence-retention fields for day-of-release records.
- Release-day recap sample prefilled (2026-03-28): `docs/release_bodies/next-major-compat-announcement-draft.md` now uses placeholder+example dual paths and includes a concrete sample with this round's fixed 4-gate PASS verdict.
- Placeholder mapping notes (2026-03-28): the recap sample now documents `<STRICT_TS>/<PREFLIGHT_TS>/<CIDR_TS>/<MATRIX_TS>/<STEP47_TS>` mapping to their corresponding gate outputs.
- Placeholder naming convention (2026-03-28): `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` now define unified placeholder naming and fill rules, with bidirectional links from the recap sample.
- Quick-fill blocks (2026-03-28): the recap sample now includes a key-value template block and an example-filled block, so users only replace right-hand values with lower manual-error risk.
- Recap snippet extracted (2026-03-28): add `docs/release_bodies/release-day-recap-snippet.md` as a direct issue/comment paste target, linked with the recap template.
- Docs index entry (2026-03-28): `docs/README.md` now includes a direct navigation link to `release-day-recap-snippet.md` for homepage discovery.
- Recap copy-order guidance (2026-03-28): `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` now add an explicit sequence (fill key-value block first, paste recap body second, add notes/verdict last).
- Release-day recap checklist (2026-03-28): `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` now add a 3-line pre-paste check (path reachability, timestamp consistency, verdict alignment).
- FAIL-round minimum backfill fields (2026-03-28): `docs/RELEASE_FLOW_CN.md` / `docs/RELEASE_FLOW_EN.md` now require `run_ts/failed_gate/evidence_path/cause_next` for failed rounds to keep auditability.
- Recap snippet FAIL-field sync (2026-03-28): `docs/release_bodies/release-day-recap-snippet.md` now includes `run_ts/failed_gate/evidence_path/cause_next` in both CN/EN paste templates to match the release-flow requirements.
- Recap snippet FAIL example (2026-03-28): `docs/release_bodies/release-day-recap-snippet.md` now includes an “Example-Failed Block” for direct failed-run recap posting.
- Recap snippet FAIL one-paragraph quick post (2026-03-28): `docs/release_bodies/release-day-recap-snippet.md` now includes a bilingual “One-Paragraph Quick Comment (FAIL)” template for rapid issue timeline updates.
- Recap snippet PASS one-paragraph quick post (2026-03-28): `docs/release_bodies/release-day-recap-snippet.md` now includes a bilingual “One-Paragraph Quick Comment (PASS)” template for symmetric PASS/FAIL quick reporting.
- Observability upgrade (2026-03-28): `[PRECLASS-DECISION]` now emits `p1_list=default|custom` to expose P1 candidate source.
- Build-warning fix (2026-03-28): add non-Windows `<strings.h>` in `src/core/whois_query_exec.c` to remove the implicit `strcasecmp` declaration warning.
- Validation baseline (2026-03-28):
  - Remote Strict PASS: `out/artifacts/20260328-021557` (`WARN_COUNT=0` + `Local hash verify PASS` + `Golden PASS` + `referral check PASS`)
  - P1 gate matrix PASS: `out/artifacts/preclass_p1_matrix/20260328-021759` (`pass=36 fail=0`)
  - P0 minimal matrix PASS: `out/artifacts/preclass_matrix/20260328-021900` (`pass=12 fail=0`)
  - Step47 prerelease gate PASS: `out/artifacts/step47_prerelease/20260328-021918`
  - Remote Strict PASS: `out/artifacts/20260328-023116` (`WARN_COUNT=0` + `Local hash verify PASS` + `Golden PASS` + `referral check PASS`)
  - P1 gate matrix PASS: `out/artifacts/preclass_p1_matrix/20260328-023137` (`pass=48 fail=0`, `cases=6 modes=8`)
  - P0 minimal matrix PASS: `out/artifacts/preclass_matrix/20260328-024331` (`pass=12 fail=0`)
  - Step47 prerelease gate PASS: `out/artifacts/step47_prerelease/20260328-024343`
  - Expanded P1 matrix PASS: `out/artifacts/preclass_p1_matrix/20260328-024852` (`pass=112 fail=0`, `cases=14 modes=8`)
  - Grouped P1 matrix PASS: `out/artifacts/preclass_p1_matrix/20260328-025629` (`pass=112 fail=0`, group summaries generated)
  - Labeled grouped P1 matrix PASS: `out/artifacts/preclass_p1_matrix/20260328-030247` (`pass=112 fail=0`, external_* group metrics all 100%)
  - Remote Strict + preflight PASS: `out/artifacts/20260328-041658` (`Local hash verify PASS` + `Golden PASS` + `referral check PASS` + `Step47 preclass preflight PASS`)
  - Step47 preclass preflight suite PASS: `out/artifacts/step47_preclass_preflight/20260328-041704` (`pass=4 fail=0`)
  - Expanded P1 gate matrix PASS: `out/artifacts/preclass_p1_matrix/20260328-050157` (`pass=168 fail=0`, `group_gate_fail=0`)
  - Step47 prerelease (with preclass-p1-gate) PASS: `out/artifacts/step47_prerelease/20260328-050426`
  - Remote Strict + preflight rerun PASS: `out/artifacts/20260328-045150` (`Local hash verify PASS` + `Golden PASS` + `referral check PASS` + `Step47 preclass preflight PASS`)
  - Step47 preclass preflight suite rerun PASS: `out/artifacts/step47_preclass_preflight/20260328-045157` (`pass=4 fail=0`)
  - Strict task passthrough manual check PASS (`-K 1`): `out/artifacts/step47_preclass_preflight/20260328-051817` (`pass=4 fail=0`, `result=pass`, elapsed `318s`)
  - Strict task passthrough manual check PASS (`-K 0`): no `[STEP47-PREFLIGHT]` segment in strict task log, elapsed `198s`
  - Expanded P1 gate matrix (small-batch) PASS: `out/artifacts/preclass_p1_matrix/20260328-054446` (`cases=29 modes=8`, `pass=232 fail=0`, `group_gate_fail=0`)
  - Step47 prerelease (with preclass-p1-gate) rerun PASS: `out/artifacts/step47_prerelease/20260328-054950`
  - CIDR Contract Bundle rerun PASS: `out/artifacts/cidr_bundle/cidr_bundle_summary_20260328-045439.txt` (body `pass=4 fail=0`, matrix `pass=9 fail=0`)
  - Redirect Matrix 10x6 rerun PASS: `out/artifacts/redirect_matrix_10x6/20260328-045523` (`authMismatchFiles=0`, `errorFiles=0`)

## 3.2.12

中文摘要 / Chinese summary
- Step 4.7 工程化收口（2026-03-16）：完成受控 trial/early-unknown 能力链路，新增 `--step47-early-unknown-list <csv>`，并保持默认关闭（不改变默认查询语义）。
- 预发布门禁一键化（2026-03-16）：新增 `tools/test/step47_prerelease_check.ps1`，串联 readiness + A/B + rollback 并统一输出汇总；同步新增 VS Code 任务 `Test: Step47 PreRelease Check (reserved, list file)`，复用 `step47ListFile` 输入，降低手工参数漂移。
- 脚本维护性收敛（2026-03-16）：`tools/test/step47_rollback_drill.ps1` 函数命名统一为 approved verbs（`ConvertTo-*` / `Get-*`），清除 PowerShell 分析器告警，不改变断言语义。
- 发布前门禁复跑（2026-03-16）：
  - Step47 一键门禁 PASS：`out/artifacts/step47_prerelease/20260316-043150`
  - Remote Strict PASS：`out/artifacts/20260316-043644`（`Local hash verify PASS` + `Golden PASS` + `referral check PASS`）
  - CIDR Contract Bundle PASS：`out/artifacts/cidr_bundle/cidr_bundle_summary_20260316-043717.txt`（body `pass=4 fail=0`，matrix `pass=9 fail=0`）
  - Redirect Matrix 10x6 PASS：`out/artifacts/redirect_matrix_10x6/20260316-043753`（`authMismatchFiles=0`，`errorFiles=0`）

English summary
- Step 4.7 engineering closure (2026-03-16): complete the controlled trial/early-unknown capability chain with `--step47-early-unknown-list <csv>`, while keeping defaults OFF (no change to default query semantics).
- One-command prerelease gate (2026-03-16): add `tools/test/step47_prerelease_check.ps1` to run readiness + A/B + rollback in one shot with unified summaries; add VS Code task `Test: Step47 PreRelease Check (reserved, list file)` reusing `step47ListFile` to reduce manual parameter drift.
- Script maintainability convergence (2026-03-16): normalize function names in `tools/test/step47_rollback_drill.ps1` to approved verbs (`ConvertTo-*` / `Get-*`) and clear PowerShell analyzer warnings with no assertion semantic change.
- Pre-release gate rerun (2026-03-16):
  - Step47 prerelease gate PASS: `out/artifacts/step47_prerelease/20260316-043150`
  - Remote Strict PASS: `out/artifacts/20260316-043644` (`Local hash verify PASS` + `Golden PASS` + `referral check PASS`)
  - CIDR Contract Bundle PASS: `out/artifacts/cidr_bundle/cidr_bundle_summary_20260316-043717.txt` (body `pass=4 fail=0`, matrix `pass=9 fail=0`)
  - Redirect Matrix 10x6 PASS: `out/artifacts/redirect_matrix_10x6/20260316-043753` (`authMismatchFiles=0`, `errorFiles=0`)

## 3.2.11

中文摘要 / Chinese summary
- 默认值调整（2026-03-03）：应用层限流重试默认值调整为 `--rate-limit-retries=2`、`--rate-limit-retry-interval-ms=2500`，在保持失败语义不变的前提下，降低矩阵与批量场景下的窗口性限流噪声。
- 失败债务语义收敛（2026-03-03）：在规则契约中新增“失败债务与清偿”定义，明确同一 RIR 上原始查询项出现失败（含空响应重试耗尽）且未获可判定正文时记为未清偿债务；轮询耗尽仍有未清偿债务时终态优先 `error`。
- CIDR 证据同一性澄清（2026-03-03）：基准查询（CIDR 去掩码）结果仅作辅助证据，不得清偿原始 CIDR 查询的失败债务；因此 APNIC ERX 场景下，`unknown`/APNIC 回落仅在“无未清偿失败债务”时成立。
- 重大改进（规则契约基线，2026-02）：本版将《IPv4/IPv6 地址 WHOIS 查询规则契约》（`docs/RFC-ipv4-ipv6-whois-lookup-rules.md`）确立为实现与评审主入口；后续涉及权威判定/跳转顺序/CIDR 语义的变更以该契约为准。
- CIDR 契约收敛（2026-02）：明确并稳定“原始 CIDR 主流程 + 首标记 RIR 基准回查 + 后续跳一致性验证 + APNIC 前候选有限回查”闭环，避免因起始 RIR 顺序导致终态漂移。
- LACNIC→ARIN 规则细化（2026-02-22）：将“立即非权威跳转且不预标记 ARIN visited”触发条件从 CIDR 收敛到“非 IP 字面量查询”；IP 字面量保持既有路径，减少 ARIN 直连权威误伤风险。
- 开关治理进展（2026-02-20）：`--no-cidr-erx-recheck` 进入 deprecated 过渡阶段；当前版本保留运行语义，仅输出一次性告警并在文档中标注“下个主版本计划移除”。
- DNS 可观测性增强（Step 4）：新增 `[DNS-CAND-IANA]`、`[DNS-CAND-SUM]`、`[DNS-CAND-RATIO]`、`[DNS-CAND-UNIQ]` 四类候选诊断标签（仅 `--debug`/`--retry-metrics` 输出），不改变默认 stdout 契约。
- 验证基线（2026-02-25）：Strict 两轮（默认 / debug+metrics）全部 PASS；CIDR Contract Bundle（prefilled）PASS（`result=pass`、`body_status=pass`、`matrix_status=pass`）；Redirect Matrix 10x6 PASS（`authMismatchFiles=0`、`errorFiles=0`）。

English summary
- Default tuning (2026-03-03): app-layer rate-limit retry defaults are updated to `--rate-limit-retries=2` and `--rate-limit-retry-interval-ms=2500`, reducing transient rate-limit noise in matrix/batch runs without changing failure semantics.
- Failure-debt convergence (2026-03-03): the rules contract now defines failure debt and settlement: when the same RIR fails on the original query item (including empty-response retry exhaustion) without a determinable body, unresolved debt is recorded; if the RIR cycle is exhausted with unresolved debt, terminal authority converges to `error`.
- CIDR evidence-identity clarification (2026-03-03): baseline-query (mask-stripped CIDR) outcomes are auxiliary evidence only and must not settle failure debt for the original CIDR query; in APNIC-ERX paths, `unknown`/APNIC fallback applies only when no unresolved failure debt remains.
- Major improvement (contract baseline, 2026-02): this release establishes the “IPv4/IPv6 WHOIS lookup rules contract” (`docs/RFC-ipv4-ipv6-whois-lookup-rules.md`) as the primary implementation/review reference for authority decision, redirect ordering, and CIDR semantics.
- CIDR contract convergence (2026-02): stabilizes the closed loop of original CIDR flow + one-time baseline recheck in first-marker RIR + subsequent consistency validation + bounded pre-APNIC candidate lookback, preventing start-RIR order drift.
- LACNIC→ARIN refinement (2026-02-22): narrows the trigger for “immediate non-authoritative continuation without ARIN pre-visited mark” from CIDR-wide to non-IP-literal queries; IP literals keep existing authority paths.
- Flag governance progress (2026-02-20): `--no-cidr-erx-recheck` enters deprecation transition; runtime behavior remains compatible in this release with a one-time warning and docs marking planned removal in the next major release.
- DNS observability upgrades (Step 4): adds `[DNS-CAND-IANA]`, `[DNS-CAND-SUM]`, `[DNS-CAND-RATIO]`, and `[DNS-CAND-UNIQ]` candidate diagnostics (only under `--debug`/`--retry-metrics`), with no default stdout contract changes.
- Validation baseline (2026-02-25): both Strict runs (default / debug+metrics) are PASS; CIDR Contract Bundle (prefilled) is PASS (`result=pass`, `body_status=pass`, `matrix_status=pass`); Redirect Matrix 10x6 is PASS (`authMismatchFiles=0`, `errorFiles=0`).

中文摘要 / Chinese summary
- 验证追加（2026-02-23，本轮）：Strict Version 两轮（`lto-auto`，默认 / `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`）均通过：`无告警 + lto 无告警 + Local hash verify PASS + Golden PASS + referral check PASS`，日志 `out/artifacts/20260223-062933`（187s）、`out/artifacts/20260223-063512`（267s）。
- 验证追加（2026-02-23，本轮）：Batch Golden 四策略（raw/health-first/plan-a/plan-b）全 PASS，日志 `out/artifacts/batch_raw/20260223-064057`、`batch_health/20260223-064601`、`batch_plan/20260223-065003`、`batch_planb/20260223-065408`（总计 1039.830s）。
- 验证追加（2026-02-23，本轮）：Selftest Golden 四策略（raw/health-first/plan-a/plan-b，`--selftest-force-suspicious 8.8.8.8`）全 `[golden-selftest] PASS`，日志 `out/artifacts/batch_raw/20260223-070056`、`batch_health/20260223-070613`、`batch_plan/20260223-071033`、`batch_planb/20260223-071536`（总计 1155.471s）。
- 验证追加（2026-02-23，本轮）：Redirect Matrix 12x6 结果全绿（authority mismatch 空表，`errors=(no errors found)`），日志 `out/artifacts/redirect_matrix_10x6/20260223-072410`。
- 脚本兼容性复核（2026-02-23，本轮）：`golden_report*.txt` 与 `golden_selftest_report.txt` 全部 PASS，确认黄金脚本在当前输出格式下工作正常。
- 验证追加（2026-02-22 晚间）：Strict 两轮（默认参数 / `--debug --retry-metrics --dns-cache-stats`）均 `[golden] PASS`，日志 `out/artifacts/20260222-200857`、`out/artifacts/20260222-201419`。
- 验证追加（2026-02-22 晚间）：Batch Strategy Golden 四策略（raw/health-first/plan-a/plan-b）全 PASS，日志 `out/artifacts/batch_raw/20260222-201954`、`batch_health/20260222-202552`、`batch_plan/20260222-203003`、`batch_planb/20260222-203401`；Selftest Golden 四策略全 PASS，日志 `out/artifacts/batch_raw/20260222-204127`、`batch_health/20260222-204706`、`batch_plan/20260222-205139`、`batch_planb/20260222-205609`。
- 验证追加（2026-02-22 晚间）：Redirect Matrix 12x6 结果 `errors=(no errors found)`，authority 对照无不匹配，日志 `out/artifacts/redirect_matrix_10x6/20260222-210208`。
- LACNIC→ARIN 硬规则细化（2026-02-22）：将“立即非权威跳转且不预标记 ARIN visited”的触发条件从“CIDR”收敛为“非 IP 字面量查询”（例如 ASN/域名/句柄）；IP 字面量保持既有路径，避免误伤 ARIN 直连权威收敛。实现同步补齐 `query_is_ip_literal_effective` 从 loop→decision→redirect 的透传（`src/core/lookup_exec_loop.c`、`src/core/lookup_exec_decision.c/.h`、`src/core/lookup_exec_redirect.h/.c`）。
- 验证复核（2026-02-22）：`43.225.216.0/21` 八组对照（lacnic/apnic/arin/ripe/afrinic/iana，含 `--cidr-strip`/IP 字面量）全部收敛 APNIC；非 IP 字面量边界样例验证通过（结果 `tmp/final_acceptance_20260222.txt`）。
- 全架构 Strict 轮次（2026-02-22）：远程构建/冒烟/同步/Golden/referral 通过，`lto-auto` 默认参数，`无告警 + lto 无告警 + Local hash verify PASS + [golden] PASS + referral check PASS`，产物 `out/artifacts/20260222-193842`。
- CIDR 契约补充（2026-02-22）：明确 APNIC 前候选回查触发前置条件为“CIDR + APNIC 命中 ERX/IANA + 存在 APNIC 前候选 RIR（排除 IANA/APNIC）+ RIR 轮询耗尽”；命中即 `unknown`，全 miss 回落 APNIC。并补充 LACNIC 内部重定向到 ARIN 时，ARIN 正文 `Query terms are ambiguous.` 不能单独作为“确定非权威”关键词（文档：`docs/RFC-ipv4-ipv6-whois-lookup-rules.md`、`docs/USAGE_CN.md`、`docs/USAGE_EN.md`）。
- LACNIC 内部重定向语义补齐（2026-02-21）：将 LACNIC internal redirect 明确为非权威路径；当内部目标已访问（尤其已访问 ARIN）时，该内部重定向失效并回到标准 RIR 轮询；当内部目标为未访问且非 ARIN 的 RIR 时，按连续访问链路继续处理。同步修正 CIDR/非 CIDR 的 visited 语义差异，避免 APNIC ERX/IANA 链路在一致性验证阶段误收敛 `unknown`（实现：`src/core/lookup_exec_redirect.c`、`src/core/lookup_exec_loop.c`；契约：`docs/RFC-ipv4-ipv6-whois-lookup-rules.md`）。
- Step 3 开始（2026-02-20）：`--no-cidr-erx-recheck` 进入治理阶段第一步（deprecated）；当前版本保持行为不变，仅在 CLI help 与文档中标记“下个主版本计划移除”，用于过渡告知与脚本迁移窗口。
- Step 4 首轮（2026-02-20，观测性）：在 `src/core/dns.c` 为 IANA 首跳候选构建新增 stderr 诊断标签 `[DNS-CAND-IANA]`（仅在 `--debug` 或 `--retry-metrics` 开启时输出），字段包含候选总数与来源分解（input/cache/resolver/known/canonical）及 `cache_hit/neg_cache_hit/limit_hit`，不改变候选顺序与 authority 裁决语义。
- Step 4 第二轮（2026-02-20，观测性）：新增通用 stderr 标签 `[DNS-CAND-SUM]`（按 hop/host 输出 `mode/start/count` 与来源分解），用于跨跳观测 DNS 候选构建路径；仅在 `--debug` 或 `--retry-metrics` 输出，默认输出契约不变。
- Step 4 第三轮（2026-02-21，观测性）：新增 stderr 标签 `[DNS-CAND-RATIO]`，按 hop 输出候选来源占比（`input/cache/resolver/known/canonical`），用于快速识别候选来源漂移；仅在 `--debug` 或 `--retry-metrics` 输出，默认输出契约不变。
- Step 4 第四轮（2026-02-21，观测性）：新增 stderr 标签 `[DNS-CAND-UNIQ]`，按 hop 输出候选唯一性统计（`total/unique/duplicate`），用于识别候选池重复密度；仅在 `--debug` 或 `--retry-metrics` 输出，默认输出契约不变。
- 网络窗口复核（2026-02-21）：确认 RIPE 对当前 IPv4 出口存在稳定拒绝（`%ERROR:201 access denied`，非随机抖动）；将矩阵参数切换为 `-RirIpPref arin=ipv6,ripe=ipv6` 后复跑恢复全绿（`authMismatchFiles=0、errorFiles=0`），用于隔离环境拒绝噪声。
- Step 4 第四轮复验（2026-02-21）：远程快速构建与发布目录同步（`x86_64+win64`，`lto-auto`）通过，`Local hash verify PASS + Golden PASS`，日志 `out/artifacts/20260221-024636`。
- Step 4 第四轮矩阵复验（2026-02-21）：在稳定参数 `-InterCaseSleepMs 600 -RateLimitRetries 2 -RateLimitRetrySleepMs 2500` 与 `-RirIpPref arin=ipv6,ripe=ipv6` 下，12x6 两次同参复跑均为 `authMismatchFiles=0 errorFiles=1`，单条错误均为环境性 `connect timeout`（日志 `tmp/logs/redirect_matrix_12x6_step4r4_win64_ripe_ipv6/20260221-024940`、`tmp/logs/redirect_matrix_12x6_step4r4_win64_ripe_ipv6_rerun/20260221-031813`）。
- 环境恢复复验（2026-02-21）：VM 重启并完成更新后，按同一远程命令再次执行构建/冒烟/Golden 全流程恢复通过：`Local hash verify PASS + Golden PASS`（日志 `out/artifacts/20260221-053557`）；前一轮失败归因为 VM 外网异常窗口（`out/artifacts/20260221-052125`）。
- 输出契约修复（2026-02-21）：修复“首跳失败且默认正文折叠时重定向提示行可能缺失”问题；现在即使中间正文被裁剪，`=== Additional/Redirected query to ... ===` 仍会按链路保留（`src/core/lookup_exec_tail.c`）。
- 输出契约修复（2026-02-21）：修复“首跳连接失败时标题 `@` 段误显示失败候选 IP”问题；失败场景现统一输出 `@ unknown`，与“首个成功连通 IP 或 unknown”契约一致（`src/core/lookup_exec_loop.c`）。
- 诊断增强（2026-02-21）：`[EMPTY-RESP]` 全部动作新增 `time=<YYYY-MM-DD HH:MM:SS>` 字段；新增 `[LIMIT-RESP]` 诊断标签，记录“已连接但收到限流/拒绝”场景的 `retry/give-up` 事件与时间戳，便于还原异常先后顺序（仅 stderr，stdout 契约不变）。
- 矩阵观测补强（2026-02-21）：修复 `tools/test/redirect_matrix_10x6.ps1` 在限流重试时仅保留“最后一次尝试输出”导致证据丢失的问题；现在当检测到限流重试，会将每次重试的关键信息写入结果文件（`[MATRIX-RETRY] ...`），便于离线排障与回放。
- 失败输出可见性（2026-02-21）：在查询失败路径中保留已累积的中间正文/跳转内容，再输出失败尾行与错误行，避免“链路已发生跳转但失败样例中不可见”的排障盲区（`src/core/whois_query_exec.c`）；同日完成全架构远程构建与同步，`Local hash verify PASS`（`out/artifacts/20260221-072428`）。
- CIDR 契约收敛（2026-02-20）：修复 APNIC `not allocated to APNIC` 场景中 ERX 标记被清零导致的回落偏差（`src/core/lookup_exec_redirect.c`）；使用发布产物复跑 `testdata/cidr_matrix_cases_draft.tsv` 达到 `pass=5 fail=0`，日志 `out/artifacts/redirect_matrix/20260220-111122`。
- 回归复核（2026-02-20）：远程快速构建与发布目录同步（`x86_64+win64`，`lto-auto`）`Local hash verify PASS + Golden PASS`，日志 `out/artifacts/20260220-110900`；`Selftest Golden Suite (prefilled)` 四策略均 PASS（raw/health-first/plan-a/plan-b），日志 `out/artifacts/batch_raw/20260220-111736`、`batch_health/20260220-112303`、`batch_plan/20260220-112658`、`batch_planb/20260220-113149`。
- 文档契约化（2026-02-20）：新增 `docs/RFC-ipv4-ipv6-whois-lookup-rules.md` 作为 IPv4/IPv6 地址查询规则主契约，统一“响应分类优先级（failure > non-auth > semantic-empty > authoritative）”“CIDR 基准回查”“RIR 轮询收敛”与“IANA 地址空间仅用于首跳优化、不直接裁决权威”的规范边界。
- 文档入口同步（2026-02-20）：`docs/README.md`、`docs/USAGE_CN.md`、`docs/USAGE_EN.md` 已新增该契约入口；`docs/IPv4_&_IPv6_address_whois_lookup_rules.txt` 顶部增加迁移提示，后续评审与维护以新 RFC 文档为准。
- invalid CIDR 收口（2026-02-19）：修复 IANA `% Error: Invalid query` 被误判为空响应并触发误跳转的问题；`-h iana --show-non-auth-body --show-post-marker-body 47.96.0.0/10` 现首跳收敛 `unknown @ unknown`，不再走 IANA→ARIN→APNIC。
- 测试复核（2026-02-19）：远程 Strict（`x86_64+win64`，`lto-auto`）`Local hash verify PASS + Golden PASS + referral check PASS`，日志 `out/artifacts/20260219-045120`。
- 测试复跑（2026-02-19）：参数化 IPv4 矩阵 `pass=66 fail=0`（`out/artifacts/redirect_matrix/20260219-045555`）；12x6 矩阵（含 `47.96.0.0/10`）`authMismatchFiles=0、errorFiles=0`（`out/artifacts/redirect_matrix_10x6/20260219-051415`）。
- 文档同步（2026-02-19）：已将上述进度、验证结果与下一步计划同步到 `docs/RFC-whois-client-split.md`、`docs/USAGE_CN.md`、`docs/USAGE_EN.md`、`docs/OPERATIONS_CN.md`、`docs/OPERATIONS_EN.md`。
- 测试复核（2026-02-17，最新）：Strict Version（lto-auto 默认）全绿：无告警 + lto 无告警 + Golden PASS + referral check: PASS，日志 `out/artifacts/20260217-170956`。
- 测试复跑（2026-02-17，最新）：重定向矩阵 10x6 同参数再次复跑仍全绿（`authMismatchFiles=0、errorFiles=0`），日志 `out/artifacts/redirect_matrix_10x6/20260217-171711`。
- 验证路径（2026-02-17）：当前按“关键命令单点复测（`-h apnic 45.113.52.0`、`-h lacnic 1.1.1.1`）+ 10x6 全量矩阵”双层执行，作为 redirect 回归门禁。
- 文档补充（2026-02-17）：已将 Windows/PowerShell 下的“干净版 APP-RETRY 探测命令”（`cmd /c` 包装原生程序 + stderr 直落日志，避免 `NativeCommandError` 包装噪音）同步写入 `docs/RFC-whois-client-split.md`、`docs/OPERATIONS_CN.md` 与 `docs/OPERATIONS_EN.md`。
- 核心修复（2026-02-17）：重定向 referral 统一执行“已访问 RIR 不回访”策略（不限于 ARIN→APNIC），当 referral 指向已访问 RIR 时改走未访问 RIR 轮询；修复 APNIC ERX 非权威链在 LACNIC 收口时误落 LACNIC 权威的问题。
- 测试复跑（2026-02-17）：重定向矩阵 10x6 在增强节流参数 `-InterCaseSleepMs 500 -RateLimitRetries 2 -RateLimitRetrySleepMs 2500` 下全绿（authority mismatches=0、errors=0），日志 `out/artifacts/redirect_matrix_10x6/20260217-065457`。
- 测试复跑（2026-02-17，追加）：同参数再次复跑仍全绿（`authMismatchFiles=0、errorFiles=0`），日志 `out/artifacts/redirect_matrix_10x6/20260217-105213`。
- 测试复核（2026-02-16）：Strict Version 两轮（默认 / debug+metrics+dns-family-mode=interleave-v4-first）均为“无告警 + lto 无告警 + Golden PASS + referral check: PASS”，日志 `out/artifacts/20260216-152247`、`out/artifacts/20260216-152830`。
- 测试复核（2026-02-16）：批量策略黄金（raw/health-first/plan-a/plan-b）全 PASS，日志 `out/artifacts/batch_raw/20260216-153356`、`batch_health/20260216-153914`、`batch_plan/20260216-154751`、`batch_planb/20260216-155559`。
- 测试复核（2026-02-16）：自检黄金（raw/health-first/plan-a/plan-b，`--selftest-force-suspicious 8.8.8.8`）全 PASS，日志 `out/artifacts/batch_raw/20260216-160118`、`batch_health/20260216-160632`、`batch_plan/20260216-161448`、`batch_planb/20260216-162255`。
- 重定向矩阵（2026-02-16）：10x6 authority mismatches 空表，但出现 7 条环境性 `rate-limit` errors，日志 `out/artifacts/redirect_matrix_10x6/20260216-162426`。
- 工具修复（2026-02-17）：`tools/test/redirect_matrix_10x6.ps1` 新增矩阵抗限流参数 `-InterCaseSleepMs`、`-RateLimitRetries`、`-RateLimitRetrySleepMs`（默认 `250/1/1500`），在不改变 authority/error 判定语义前提下，降低高频矩阵触发限流概率。
- 核心增强（2026-02-17）：新增应用层限流重试参数 `--rate-limit-retries` 与 `--rate-limit-retry-interval-ms`，仅对 `temporary denied` / `rate-limit` 响应在同 hop 内做受限重试，`permanently denied` 保持不重试，避免与现有连接层 retry 语义混淆。
- 重定向收口（2026-02-14）：修复 `erx_fast_authoritative` 命中后 APNIC legacy 路径误将 `need_redir_eval` 重新置 1 的问题，避免 APNIC ERX 默认流程出现额外多跳。
- 重定向收口（2026-02-14）：收窄 `force_stop_authoritative` 作用域至 APNIC ERX root 的无 referral 终止条件，避免 ARIN/跨 RIR referral 被误截断。
- 重定向收口（2026-02-14）：补齐“LACNIC 起始但返回 APNIC ERX 页面”场景下 APNIC root 状态建立，避免 `lacnic_171.84.0.0/14` 收敛为 `unknown`。
- 重定向收口（2026-02-14）：将 APNIC `IANA-NETBLOCK` 统一视作非权威并继续 RIR 轮询，修复 `45.71.8.0/22` 在 APNIC/LACNIC 起始下的误收敛。
- 测试：远程编译冒烟同步 + 黄金校验（Strict Version + lto-auto）PASS，日志 `out/artifacts/20260214-061249`。
- 测试：重定向矩阵 10x6 authority mismatches=0、errors=0，日志 `out/artifacts/redirect_matrix_10x6/20260214-061443`。
- 测试判定语义（2026-02-14）：重定向矩阵 authority 校验遵循“失败优先”契约；若样例尾行为 `=== Authoritative RIR: error @ error ===`（限流/拒绝/连接故障导致未收敛），则该样例期望 authority 按 `error` 判定；仅非失败尾行按静态 RIR 期望表判定。
- 测试：远程编译冒烟同步 + 黄金校验（Strict Version + lto-auto 默认）PASS，日志 `out/artifacts/20260214-075348`（无告警 + lto 无告警 + Golden PASS + referral check: PASS）。
- 测试：重定向矩阵 10x6 authority mismatches 空表、errors 空表，日志 `out/artifacts/redirect_matrix_10x6/20260214-081508`。
- 破坏性变更：移除 `--cidr-home-v4`/`--cidr-fast-v4`，IPv4 CIDR 查询回归标准重定向流程（不再强制 two-phase 与 no-redirect 二跳）。
- 新增开关：`--no-cidr-erx-recheck` 关闭 CIDR 的 ERX/IANA 基准复查，用于对比性能。
- 输出控制：默认仅保留权威正文；`--show-non-auth-body` 保留权威之前的非权威正文，`--show-post-marker-body` 保留权威之后的非权威正文；两者同时开启保留全部正文。
- 限流/拒绝正文：默认保留原文；新增 `--hide-failure-body` 可显式过滤限流/拒绝类正文行，便于批量比对降噪。
- 调试增强：`--show-post-marker-body` 可用于定位 ERX/IANA 标记后的正文路径。
- 输出与默认策略回归：`-P/--plain` 现在抑制重定向提示行（Additional/Redirected），仅保留正文；双栈默认恢复 IPv6 优先（首跳 `interleave-v6-first`、后续 `seq-v6-then-v4`，`ip_pref_mode` 固定为 `FORCE_V6_FIRST`）。
- 构建优化档补齐：新增 `OPT_PROFILE=small/lto`（由 Makefile 统一决定优化标志），远程构建/批量黄金/自检黄金脚本与 VS Code 任务均支持 `-O <profile>` 传入；空 `CFLAGS_EXTRA` 在套件中视为可选，不再强制占位。
- 构建档位扩展：`OPT_PROFILE` 新增 `lto-auto/lto-serial`，用于控制 LTO 并行度；远程构建脚本与 One-Click Release/批量/自检任务已同步。
- 构建日志增强：远程构建输出统一记录耗时（Elapsed）。
- 体积诊断：部分目标此前未 strip/带 debug_info 造成体积膨胀；统一 strip 后恢复正常。最新基线（lto-auto + UPX aarch64/x86_64）详见下表。
- 告警修复：`pipeline` 输出在过滤串为空时避免 `%s` 传 NULL 的编译告警。
- 构建告警修复：`lookup_exec_loop.c` 统一回 UTF-8 编码，避免 NULL 字节警告；`lookup_exec_connect.c`/`lookup_exec_empty.c` 的 `netdb.h` 限定为非 Windows 引入，补齐 `sys/socket.h`；`lookup_exec_connect.c` 补充 `<stdio.h>` 以消除 `snprintf` 隐式声明告警。
- 测试：远程编译冒烟同步 + 黄金校验（lto-auto 默认）PASS，日志 `out/artifacts/20260210-113135`。
- 测试：远程编译冒烟同步 + 黄金校验（lto-auto 默认）PASS，日志 `out/artifacts/20260210-120349`。
- 测试：远程编译冒烟同步 + 黄金校验（lto-auto 默认）PASS，日志 `out/artifacts/20260210-123718`。
- 测试：远程编译冒烟同步 + 黄金校验（Strict Version + lto-auto 默认）PASS，日志 `out/artifacts/20260210-133508`。
- 测试：远程编译冒烟同步 + 黄金校验（Strict Version + lto-auto + debug/metrics + dns-family-mode=interleave-v4-first）PASS，日志 `out/artifacts/20260210-134308`。
- 测试：远程编译冒烟同步 + 黄金校验（Strict Version + lto-auto 默认）PASS，日志 `out/artifacts/20260210-163305`。
- 测试：远程编译冒烟同步 + 黄金校验（Strict Version + lto-auto + debug/metrics + dns-family-mode=interleave-v4-first）PASS，日志 `out/artifacts/20260210-164007`。
- 测试：批量策略黄金（lto-auto）raw/health-first/plan-a/plan-b PASS，日志 `out/artifacts/batch_{raw,health,plan,planb}/20260210-13*`。
- 测试：自检黄金（lto-auto + `--selftest-force-suspicious 8.8.8.8`）raw/health-first/plan-a/plan-b PASS，日志 `out/artifacts/batch_{raw,health,plan,planb}/20260210-14*`。
- 测试：批量策略黄金（lto-auto）raw/health-first/plan-a/plan-b PASS，日志 `out/artifacts/batch_raw/20260210-165020`、`batch_health/20260210-165721`、`batch_plan/20260210-170754`、`batch_planb/20260210-171826`。
- 测试：自检黄金（lto-auto + `--selftest-force-suspicious 8.8.8.8`）raw/health-first/plan-a/plan-b PASS，日志 `out/artifacts/batch_raw/20260210-172643`、`batch_health/20260210-173432`、`batch_plan/20260210-174621`、`batch_planb/20260210-175714`。
- 测试：重定向矩阵 10x6 authority mismatches=0、errors=0，日志 `out/artifacts/redirect_matrix_10x6/20260210-175917`。
- 重定向修复：APNIC CIDR 查询不再被误导到 IANA/ARIN；允许在 CIDR referral 场景对 APNIC 进行一次回跳以完成正确权威判定（stdout 契约不变）。
- 重定向规则补齐：APNIC IANA-NETBLOCK 出现 “not allocated to APNIC / not fully allocated to APNIC” 时强制触发轮询，以校验最终权威（stdout/stderr 契约不变）。
- 重定向规则更新：首跳有 referral 直跟；首跳无 referral 且需跳转时强制 ARIN；第二跳起仅跟随未访问的 referral，缺失/重复时按 APNIC→ARIN→RIPE→AFRINIC→LACNIC 顺序挑选未访问 RIR；第二跳后不再插入 IANA；新增 `refer:` 行解析。
- 重定向门控修复：修复 APNIC 非首跳在 `need_redir_eval=1` 时可能提前收敛的问题，保持固定 RIR 轮询顺序不变；并收敛 APNIC stop 与 `force_stop_authoritative` 作用域，避免误截断轮询。
- 重定向解析修复：`remarks:` 行不再参与 fallback host hint 提取，避免误提取 referral host。
- 测试：远程编译冒烟同步 + 黄金校验（Strict Version，全架构）PASS，日志 `out/artifacts/20260213-111557`（golden/referral/hash verify 均通过）。
- 按 RIR 覆盖族偏好：新增 `--rir-ip-pref arin=v4,ripe=v6,...`，仅影响指定 RIR，优先级低于 `--ipv4-only/--ipv6-only`、高于全局 `--prefer-*`。
- ReferralServer 扩展：支持 `rwhois://host:port` 解析并按端口重定向。
- 启动优化：`--version/--help/--about/--examples/--servers` 走 meta-only 快路径，跳过 runtime init（无查询输出变化）。
- 退出清理补齐：进程退出显式释放 DNS 正/负缓存与连接缓存，避免长时间运行时被工具误判为泄漏；stdout/stderr 契约不变。
- 空响应回退收敛：ARIN 空响应重试预算降至 2，其它 RIR 保持 1；空响应回退之间加入轻量退让，降低高并发连接风暴风险（stdout/stderr 契约不变）。
- 权威尾行收敛：若已拿到正文但后续 referral 跳转失败，或限流/拒绝导致未收敛，尾行权威改为 `error`，用于区分“失败未收敛”与“真未知”；仅当尾行为 `error @ error` 时输出失败错误行。
- 失败错误行增强：统一错误行追加 `host/ip/time` 字段，便于定位远端拒绝/超时（仅在 `error @ error` 时输出）。
- 重定向健壮性：RIR 仅返回 banner 注释（无有效正文）时按空响应处理，先重试；若仍为空则触发重定向（非 ARIN 首跳直跳 ARIN，ARIN 首跳进入 RIR 轮询），避免过早收敛。
- 空响应告警：空响应重试改为 stderr 标签 `[EMPTY-RESP] action=...`，stdout 不再混入告警文本。
- APNIC ERX 轮询收敛：补齐 RIPE/AFRINIC/LACNIC 重定向提示行；权威回落 APNIC 并校准 IP 映射；清理冗余 hop 正文并消除提示行间空行。
English summary
- Verification addendum (2026-02-23, current round): both Strict Version rounds (`lto-auto`, default / `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`) pass with `no warnings + no LTO warnings + Local hash verify PASS + Golden PASS + referral check PASS`, logs `out/artifacts/20260223-062933` (187s) and `out/artifacts/20260223-063512` (267s).
- Verification addendum (2026-02-23, current round): Batch Golden passes across all four strategies (raw/health-first/plan-a/plan-b), logs `out/artifacts/batch_raw/20260223-064057`, `batch_health/20260223-064601`, `batch_plan/20260223-065003`, `batch_planb/20260223-065408` (total 1039.830s).
- Verification addendum (2026-02-23, current round): Selftest Golden passes across all four strategies (raw/health-first/plan-a/plan-b, `--selftest-force-suspicious 8.8.8.8`) with `[golden-selftest] PASS`, logs `out/artifacts/batch_raw/20260223-070056`, `batch_health/20260223-070613`, `batch_plan/20260223-071033`, `batch_planb/20260223-071536` (total 1155.471s).
- Verification addendum (2026-02-23, current round): Redirect Matrix 12x6 is fully green (empty authority mismatch table and `errors=(no errors found)`), log `out/artifacts/redirect_matrix_10x6/20260223-072410`.
- Script compatibility recheck (2026-02-23, current round): all `golden_report*.txt` and `golden_selftest_report.txt` are PASS, confirming golden scripts remain healthy under the current output format.
- Verification addendum (2026-02-22 evening): both Strict rounds (default args / `--debug --retry-metrics --dns-cache-stats`) are `[golden] PASS`, logs `out/artifacts/20260222-200857` and `out/artifacts/20260222-201419`.
- Verification addendum (2026-02-22 evening): Batch Strategy Golden passes across all four strategies (raw/health-first/plan-a/plan-b), logs `out/artifacts/batch_raw/20260222-201954`, `batch_health/20260222-202552`, `batch_plan/20260222-203003`, `batch_planb/20260222-203401`; Selftest Golden also passes across all four strategies, logs `out/artifacts/batch_raw/20260222-204127`, `batch_health/20260222-204706`, `batch_plan/20260222-205139`, `batch_planb/20260222-205609`.
- Verification addendum (2026-02-22 evening): Redirect Matrix 12x6 reports `errors=(no errors found)` with no authority mismatches, log `out/artifacts/redirect_matrix_10x6/20260222-210208`.
- LACNIC→ARIN hard-rule refinement (2026-02-22): narrow the trigger for “immediate non-authoritative continuation + no ARIN pre-visited mark” from CIDR-only to non-IP-literal queries (e.g., ASN/domain/handle). IP literals stay on existing paths to avoid regressing ARIN direct-authority convergence. Also plumb `query_is_ip_literal_effective` end-to-end (loop→decision→redirect) in `src/core/lookup_exec_loop.c`, `src/core/lookup_exec_decision.c/.h`, and `src/core/lookup_exec_redirect.h/.c`.
- Verification rerun (2026-02-22): all eight `43.225.216.0/21` comparison runs (lacnic/apnic/arin/ripe/afrinic/iana, including `--cidr-strip` and IP-literal variants) converge to APNIC; non-IP-literal boundary checks also pass (summary: `tmp/final_acceptance_20260222.txt`).
- Full-architecture Strict round (2026-02-22): remote build/smoke/sync + Golden/referral all pass with default `lto-auto` (`no warnings + no LTO warnings + Local hash verify PASS + [golden] PASS + referral check PASS`), artifacts in `out/artifacts/20260222-193842`.
- LACNIC internal redirect semantics alignment (2026-02-21): treat LACNIC internal redirects as non-authoritative; invalidate the internal hint when the target RIR is already visited (especially visited ARIN) and continue standard RIR cycling; keep continuous-hop handling when the internal target is an unvisited non-ARIN RIR. Also align CIDR vs non-CIDR visited semantics to avoid false `unknown` convergence during APNIC ERX/IANA consistency checks (impl: `src/core/lookup_exec_redirect.c`, `src/core/lookup_exec_loop.c`; contract: `docs/RFC-ipv4-ipv6-whois-lookup-rules.md`).
- Step 3 kickoff (2026-02-20): `--no-cidr-erx-recheck` enters phase-1 governance (deprecated). Runtime behavior remains unchanged in this release; CLI help and docs now mark it as planned for removal in the next major version to provide a migration window.
- Step 4 round-1 (2026-02-20, observability): add stderr diagnostic tag `[DNS-CAND-IANA]` in `src/core/dns.c` for IANA first-hop candidate construction (emitted only when `--debug` or `--retry-metrics` is enabled). The tag reports total candidate count, source breakdown (`input/cache/resolver/known/canonical`), and `cache_hit/neg_cache_hit/limit_hit`; candidate ordering and authority semantics are unchanged.
- Step 4 round-2 (2026-02-20, observability): add generic stderr tag `[DNS-CAND-SUM]` to report per-hop/per-host candidate construction (`mode/start/count` and source breakdown) across referral hops. Emission remains gated by `--debug` or `--retry-metrics`; default output contract is unchanged.
- Step 4 round-3 (2026-02-21, observability): add stderr tag `[DNS-CAND-RATIO]` to report per-hop candidate-source percentages (`input/cache/resolver/known/canonical`) for quick source-drift detection. Emission remains gated by `--debug` or `--retry-metrics`; default output contract is unchanged.
- Step 4 round-4 (2026-02-21, observability): add stderr tag `[DNS-CAND-UNIQ]` to report per-hop candidate uniqueness (`total/unique/duplicate`) for duplicate-density visibility. Emission remains gated by `--debug` or `--retry-metrics`; default output contract is unchanged.
- Network-window revalidation (2026-02-21): RIPE shows stable IPv4 egress denial (`%ERROR:201 access denied`, not random jitter). Rerunning the matrix with `-RirIpPref arin=ipv6,ripe=ipv6` restores full green (`authMismatchFiles=0, errorFiles=0`), isolating environment-induced denial noise.
- Step 4 round-4 revalidation (2026-02-21): remote fast build + release sync (`x86_64+win64`, `lto-auto`) passes with `Local hash verify PASS + Golden PASS`, log `out/artifacts/20260221-024636`.
- Step 4 round-4 matrix reruns (2026-02-21): with stable pacing (`-InterCaseSleepMs 600 -RateLimitRetries 2 -RateLimitRetrySleepMs 2500`) and `-RirIpPref arin=ipv6,ripe=ipv6`, two 12x6 reruns both report `authMismatchFiles=0 errorFiles=1`; the single error is environmental `connect timeout` noise (`tmp/logs/redirect_matrix_12x6_step4r4_win64_ripe_ipv6/20260221-024940`, `tmp/logs/redirect_matrix_12x6_step4r4_win64_ripe_ipv6_rerun/20260221-031813`).
- Environment-recovery rerun (2026-02-21): after VM reboot and update completion, re-running the exact same remote build/smoke/golden command returns to full PASS (`Local hash verify PASS + Golden PASS`, log `out/artifacts/20260221-053557`); the previous failure is attributed to a temporary VM outbound-network anomaly window (`out/artifacts/20260221-052125`).
- Output contract fix (2026-02-21): preserve redirect hint headers (`=== Additional/Redirected query to ... ===`) even when non-authoritative bodies are stripped by default output shaping (`src/core/lookup_exec_tail.c`).
- Output contract fix (2026-02-21): when hop-0 connection fails, header now reports `@ unknown` instead of a failed candidate IP, aligning with the “first successful connected IP or unknown” contract (`src/core/lookup_exec_loop.c`).
- Matrix observability hardening (2026-02-21): fix `tools/test/redirect_matrix_10x6.ps1` so rate-limit retries no longer lose prior-attempt evidence. The script now persists per-retry diagnostics into each case log (`[MATRIX-RETRY] ...`) instead of writing only the final attempt output.
- Failure-path visibility (2026-02-21): keep accumulated intermediate body/redirect content on query-failure paths before printing failure tail/error lines, so failed samples still expose the traversed hop context (`src/core/whois_query_exec.c`). A full-architecture remote build+sync also passed on the same day with `Local hash verify PASS` (`out/artifacts/20260221-072428`).
- CIDR contract convergence (2026-02-20): fix the APNIC `not allocated to APNIC` path where ERX markers could be cleared and cause wrong fallback (`src/core/lookup_exec_redirect.c`); rerunning `testdata/cidr_matrix_cases_draft.tsv` on release artifacts now yields `pass=5 fail=0`, log `out/artifacts/redirect_matrix/20260220-111122`.
- Regression verification (2026-02-20): remote fast build + release sync (`x86_64+win64`, `lto-auto`) reports `Local hash verify PASS + Golden PASS`, log `out/artifacts/20260220-110900`; `Selftest Golden Suite (prefilled)` passes across all four strategies (raw/health-first/plan-a/plan-b), logs `out/artifacts/batch_raw/20260220-111736`, `batch_health/20260220-112303`, `batch_plan/20260220-112658`, `batch_planb/20260220-113149`.
- Docs contractization (2026-02-20): add `docs/RFC-ipv4-ipv6-whois-lookup-rules.md` as the primary contract for IPv4/IPv6 lookup behavior, standardizing response classification priority (`failure > non-auth > semantic-empty > authoritative`), CIDR baseline recheck flow, RIR cycle convergence, and the boundary that IANA address-space files are for first-hop optimization only (not final authority decisions).
- Docs entry sync (2026-02-20): add links to the new contract in `docs/README.md`, `docs/USAGE_CN.md`, and `docs/USAGE_EN.md`; add a migration note at the top of `docs/IPv4_&_IPv6_address_whois_lookup_rules.txt` so future reviews and maintenance anchor on the new RFC doc.
- Invalid CIDR closure (2026-02-19): fix the path where IANA `% Error: Invalid query` could be treated as semantic-empty and trigger drift hops; `-h iana --show-non-auth-body --show-post-marker-body 47.96.0.0/10` now converges on the first hop to `unknown @ unknown`.
- Verification (2026-02-19): remote Strict (`x86_64+win64`, `lto-auto`) reports `Local hash verify PASS + Golden PASS + referral check PASS`, log `out/artifacts/20260219-045120`.
- Matrix reruns (2026-02-19): parameterized IPv4 matrix `pass=66 fail=0` (`out/artifacts/redirect_matrix/20260219-045555`); 12x6 matrix (including `47.96.0.0/10`) `authMismatchFiles=0, errorFiles=0` (`out/artifacts/redirect_matrix_10x6/20260219-051415`).
- Docs sync (2026-02-19): progress, validation results, and next-step plan were synchronized to `docs/RFC-whois-client-split.md`, `docs/USAGE_CN.md`, `docs/USAGE_EN.md`, `docs/OPERATIONS_CN.md`, and `docs/OPERATIONS_EN.md`.
- Verification (2026-02-17, latest): Strict Version (lto-auto default) is clean: no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260217-170956`.
- Rerun verification (2026-02-17, latest): redirect matrix 10x6 is fully green again with the same stronger throttling (`authMismatchFiles=0, errorFiles=0`), log `out/artifacts/redirect_matrix_10x6/20260217-171711`.
- Validation path (2026-02-17): keep the two-layer redirect gate as focused command repro (`-h apnic 45.113.52.0`, `-h lacnic 1.1.1.1`) plus full 10x6 matrix rerun.
- Docs update (2026-02-17): added a clean Windows/PowerShell APP-RETRY probe command (`cmd /c` wrapped native run with direct stderr append, avoiding `NativeCommandError` wrapper noise) to `docs/RFC-whois-client-split.md`, `docs/OPERATIONS_CN.md`, and `docs/OPERATIONS_EN.md`.
- Core fix (2026-02-17): enforce a generic “no revisit for visited RIR” referral policy (not only ARIN→APNIC), so referrals to visited RIRs continue through unvisited RIR cycle; also fix APNIC ERX non-authoritative chain convergence so LACNIC terminal hops do not mislabel authority as LACNIC.
- Rerun verification (2026-02-17): redirect matrix 10x6 is fully green with stronger throttling (`-InterCaseSleepMs 500 -RateLimitRetries 2 -RateLimitRetrySleepMs 2500`): authority mismatches=0 and errors=0, log `out/artifacts/redirect_matrix_10x6/20260217-065457`.
- Rerun verification (2026-02-17, extra): same parameters are fully green again (`authMismatchFiles=0, errorFiles=0`), log `out/artifacts/redirect_matrix_10x6/20260217-105213`.
- Verification (2026-02-16): both Strict Version runs (default / debug+metrics+dns-family-mode=interleave-v4-first) are clean: no warnings + LTO no warnings + Golden PASS + referral check PASS, logs `out/artifacts/20260216-152247` and `out/artifacts/20260216-152830`.
- Verification (2026-02-16): batch strategy goldens (raw/health-first/plan-a/plan-b) all PASS, logs `out/artifacts/batch_raw/20260216-153356`, `batch_health/20260216-153914`, `batch_plan/20260216-154751`, `batch_planb/20260216-155559`.
- Verification (2026-02-16): selftest goldens (raw/health-first/plan-a/plan-b with `--selftest-force-suspicious 8.8.8.8`) all PASS, logs `out/artifacts/batch_raw/20260216-160118`, `batch_health/20260216-160632`, `batch_plan/20260216-161448`, `batch_planb/20260216-162255`.
- Redirect matrix (2026-02-16): 10x6 has empty authority mismatches, but 7 environmental `rate-limit` errors remain, log `out/artifacts/redirect_matrix_10x6/20260216-162426`.
- Tooling fix (2026-02-17): `tools/test/redirect_matrix_10x6.ps1` adds rate-limit mitigation knobs `-InterCaseSleepMs`, `-RateLimitRetries`, and `-RateLimitRetrySleepMs` (defaults `250/1/1500`) to reduce throttling-induced matrix failures without changing authority/error semantics.
- Core enhancement (2026-02-17): add app-layer throttling retry knobs `--rate-limit-retries` and `--rate-limit-retry-interval-ms`; they only retry temporary denied / rate-limit responses within the same hop, while permanently denied remains non-retriable.
- Breaking change: remove `--cidr-home-v4`/`--cidr-fast-v4`; IPv4 CIDR lookups now follow the standard redirect flow (no forced two-phase/no-redirect hop).
- New flag: `--no-cidr-erx-recheck` disables the ERX/IANA baseline recheck for CIDR to compare performance.
- Output control: keep only the authoritative body by default; `--show-non-auth-body` keeps pre-authoritative non-auth bodies, while `--show-post-marker-body` keeps post-authoritative non-auth bodies. Use both to keep all bodies.
- Failure bodies: keep rate-limit/denied text by default; add `--hide-failure-body` to filter those lines for batch diff noise reduction.
- Debug: `--show-post-marker-body` helps trace ERX/IANA marker paths.
- Output/defaults rollback: `-P/--plain` now suppresses referral hint lines (Additional/Redirected) and keeps only the body; dual‑stack defaults return to IPv6‑first (`interleave-v6-first` on hop 0, `seq-v6-then-v4` afterwards, `ip_pref_mode` pinned to `FORCE_V6_FIRST`).
- Build profile coverage: add `OPT_PROFILE=small/lto` (Makefile-owned optimization presets); remote build, batch golden, and selftest golden scripts/VS Code tasks accept `-O <profile>`. Empty `CFLAGS_EXTRA` is now optional in suites (no placeholder required).
- Build profile expansion: add `lto-auto/lto-serial` to control LTO parallelism; remote build scripts and One-Click Release/batch/selftest tasks are aligned.
- Build logs: remote build now prints an elapsed time summary.
- Size diagnostic: some targets were previously unstripped (debug_info), inflating size; unified strip brings sizes back to normal. Latest baseline (lto-auto + UPX on aarch64/x86_64) is listed below.

Build size baseline (lto-auto, UPX on aarch64/x86_64, stripped)

| Target | Size |
| --- | --- |
| whois-aarch64 | 149 KB |
| whois-armv7 | 340 KB |
| whois-mips64el | 506 KB |
| whois-mipsel | 483 KB |
| whois-loongarch64 | 262 KB |
| whois-x86_64 | 151 KB |
| whois-x86 | 404 KB |
| whois-win64.exe | 393 KB |
| whois-win32.exe | 422 KB |
- Warning fix: guard `pipeline` output to avoid `%s` with NULL filtered strings at compile time.
- Build warning fixes: normalize `lookup_exec_loop.c` to UTF-8 to remove NULL-byte warnings; guard `netdb.h` to non-Windows in `lookup_exec_connect.c`/`lookup_exec_empty.c` and add `sys/socket.h`; add `<stdio.h>` in `lookup_exec_connect.c` to fix implicit `snprintf` declarations.
- Test: remote build smoke sync + golden (lto-auto default) PASS, log `out/artifacts/20260210-113135`.
- Test: remote build smoke sync + golden (lto-auto default) PASS, log `out/artifacts/20260210-120349`.
- Test: remote build smoke sync + golden (lto-auto default) PASS, log `out/artifacts/20260210-123718`.
- Test: remote build smoke sync + golden (Strict Version + lto-auto default) PASS, log `out/artifacts/20260210-133508`.
- Test: remote build smoke sync + golden (Strict Version + lto-auto + debug/metrics + dns-family-mode=interleave-v4-first) PASS, log `out/artifacts/20260210-134308`.
- Test: batch strategy goldens (lto-auto) raw/health-first/plan-a/plan-b PASS, logs `out/artifacts/batch_{raw,health,plan,planb}/20260210-13*`.
- Test: selftest goldens (lto-auto + `--selftest-force-suspicious 8.8.8.8`) raw/health-first/plan-a/plan-b PASS, logs `out/artifacts/batch_{raw,health,plan,planb}/20260210-14*`.
- Test: redirect matrix 10x6 authority mismatches present, errors=0, log `out/artifacts/redirect_matrix_10x6/20260210-151915`.
- Redirect fix: APNIC CIDR queries no longer get misrouted to IANA/ARIN; allow one APNIC revisit for CIDR referrals to reach the correct authority (stdout contract unchanged).
- Redirect rule tightening: APNIC IANA-NETBLOCK banners with “not allocated to APNIC / not fully allocated to APNIC” now force RIR traversal to validate final authority (stdout/stderr contracts unchanged).
- Redirect traversal update: follow hop‑1 referrals when present; if hop 1 lacks a referral but needs redirect, force ARIN. From hop 2 onward, follow referrals only when unvisited; otherwise select the next unvisited RIR in APNIC→ARIN→RIPE→AFRINIC→LACNIC order. No IANA insertion after hop 2; add `refer:` line parsing.
- Redirect gating fix: resolve premature convergence on APNIC non-first-hop paths when `need_redir_eval=1`, while keeping the fixed RIR cycle order unchanged; tighten APNIC-stop / `force_stop_authoritative` scope so valid cycles are not truncated.
- Redirect parsing fix: ignore `remarks:` lines when extracting fallback host hints to prevent false referral-host extraction.
- Test: remote build smoke sync + golden (Strict Version, full-arch) PASS, log `out/artifacts/20260213-111557` (golden/referral/hash verify all PASS).
- Per-RIR family overrides: add `--rir-ip-pref arin=v4,ripe=v6,...` to override IPv4/IPv6 preference per RIR; lower priority than `--ipv4-only/--ipv6-only`, higher than global `--prefer-*`.
- ReferralServer expansion: accept `rwhois://host:port` and redirect using the parsed port.
- Startup optimization: meta-only flags (`--version/--help/--about/--examples/--servers`) skip runtime init (no query output changes).
- Exit cleanup: explicitly free DNS positive/negative caches and connection caches on process exit, avoiding leak warnings in long-running or tool-instrumented runs; stdout/stderr contracts unchanged.
- Empty-body fallback tightening: ARIN retry budget reduced to 2 (others remain 1), with a small backoff between empty-response retries to reduce connection bursts under high concurrency (stdout/stderr contracts unchanged).
- Authoritative tail tightening: when a hop returns body data but a later referral fails, or rate-limit/denied prevents convergence, the tail now prints `error` to distinguish failure from a true unknown; failure lines are emitted only when the tail is `error @ error`.
- Failure line enhancement: append `host/ip/time` to the unified error line for faster triage (only when the tail is `error @ error`).
- Redirect robustness: comment-only (banner-only) RIR responses are treated as empty responses; retry first, then redirect (non-ARIN first hops pivot to ARIN, ARIN first hops enter the RIR cycle) to avoid premature authority.
- Empty-response warnings: retry notices now emit as stderr tags `[EMPTY-RESP] action=...`, keeping stdout free of diagnostics.
- APNIC ERX traversal tightening: restore RIPE/AFRINIC/LACNIC redirect hints, collapse authority to APNIC with correct IP mapping, and trim redundant hop bodies while removing blank lines between hop headers.

## 3.2.10

中文摘要 / Chinese summary
- ARIN 前缀剥离与自测（2026-01-15）：非 ARIN hop 遇到带前缀查询时自动剥离前缀并输出 `[DNS-ARIN] strip-prefix`（仅 stderr）；新增 lookup 自测 `arin-prefix-strip` 纯字符串校验；四轮黄金（默认 / debug+metrics / 批量四策略 / 自检四策略）均 PASS，日志 `out/artifacts/20260115-112537`、`20260115-113007`，以及 `batch_{raw,health,plan,planb}/20260115-11{3500,3857,4216,4510}/...` 与 `batch_{raw,health,plan,planb}/20260115-11{5135,5533,5808,0129}/...`。
- IPv4/IPv6 启动探测 + 默认偏好调整（2026-01-15）：进程启动即探测本机 IPv4/IPv6 是否可用，双栈且未显式指定 prefer/only 时默认改为 `--prefer-ipv4-ipv6` + `--dns-family-mode seq-v4-then-v6`；仅单栈时自动强制对应族并忽略冲突偏好（stderr 提示），两族都不可用直接 fatal 退出。`--debug` 下追加 `[NET-PROBE] ipv4=... ipv6=...`。

English summary
- ARIN prefix stripping + selftest (2026-01-15): non-ARIN hops now strip ARIN-style prefixes and emit `[DNS-ARIN] strip-prefix` to stderr; add a lookup selftest `arin-prefix-strip` (pure string check). Four-way golden runs all PASS with logs `out/artifacts/20260115-112537`, `20260115-113007`, plus `batch_{raw,health,plan,planb}/20260115-11{3500,3857,4216,4510}/...` and `batch_{raw,health,plan,planb}/20260115-11{5135,5533,5808,0129}/...`.
- IPv4/IPv6 startup probe + default flip (2026-01-15): on startup we probe local IPv4/IPv6 availability once; if both work and no prefer/only flags were set, the default becomes `--prefer-ipv4-ipv6` + `--dns-family-mode seq-v4-then-v6`. Single-stack hosts auto-force the matching family and ignore conflicting preferences with a notice; zero families is fatal. `[NET-PROBE] ipv4=... ipv6=...` appears under `--debug`.

Notes
- Stdout header/tail contracts remain unchanged; the extra `[LOOKUP_SELFTEST]` burst is stderr-only and still gated by the `-DWHOIS_LOOKUP_SELFTEST` build.

## 3.2.9

中文摘要 / Chinese summary
- DNS Phase 2/3 收尾：以当前 `wc_dns` + lookup 实现为基线，固化候选生成、负缓存、候选排序与回退层设计；三大调试标签 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` 与 Phase 3 新增的 `[DNS-HEALTH]` 共同构成 DNS 排障“观测三件套”，默认仅在 `--debug` 或 `--retry-metrics` 下输出。
- 进程级 DNS 缓存统计：`--dns-cache-stats` 通过 `atexit` 打印一次 `[DNS-CACHE-SUM] hits=<n> neg_hits=<n> misses=<n>`，用于粗略观察正向/负向缓存命中率与未命中情况；该选项只影响统计输出，不改变解析或回退策略。
- DNS 健康记忆（Phase 3）：在 `wc_dns` 内为每个 `host+family` 维护轻量健康状态（连续失败计数与 penalty 窗口），通过 `[DNS-HEALTH]` 日志暴露当前状态，并在候选排序中“健康优先、不中断候选”，以减少在明显不健康 IPv4/IPv6 族上的重复撞墙，同时保持黄金用例输出不变。
- 调试/自测集成：在以 `-DWHOIS_LOOKUP_SELFTEST` 编译并带 `--selftest` 运行时，新加入的 `[LOOKUP_SELFTEST]` 行会对 DNS 候选、健康记忆与回退路径做总结性报告，方便在远程冒烟日志中快速 eyeball 行为是否符合预期。
- 文档与运维补完：`USAGE_CN/EN` 与 `OPERATIONS_CN/EN` 均新增“DNS 调试 quickstart”/“DNS debug quickstart” 段落，给出推荐命令 `whois-x86_64 --debug --retry-metrics --dns-cache-stats [--selftest] 8.8.8.8`，并解释各类 DNS 标签含义及典型输出；`tools/remote/README_*.md` 补充了 `smoke_test.log` 中出现 `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` / `[DNS-HEALTH]` / `[LOOKUP_SELFTEST]` 的预期说明。
- 版本与发布日期对齐：核心代码版本号升级为 `3.2.9`，README 顶部版本展示同步更新，为后续以 v3.2.9 作为 DNS 线“新 golden 基线”打好文档与实现的一致性基础。

English summary
- DNS Phase 2/3 wrap-up: solidifies the current `wc_dns` + lookup design as the new baseline for candidate generation, negative cache, candidate ordering and fallback layers. Together, `[DNS-CAND]`, `[DNS-FALLBACK]`, `[DNS-CACHE]` plus the Phase‑3 `[DNS-HEALTH]` tag form a DNS troubleshooting trio, emitted only when `--debug` or `--retry-metrics` is enabled.
- Process-level DNS cache stats: `--dns-cache-stats` prints a single `[DNS-CACHE-SUM] hits=<n> neg_hits=<n> misses=<n>` line via `atexit`, giving a rough view of positive/negative cache hit rate and misses. This flag is **observability-only** and does not alter resolution or fallback behavior.
- DNS health memory (Phase 3): `wc_dns` now tracks a lightweight health state per `host+family` (consecutive failures and a short penalty window). `[DNS-HEALTH]` logs expose this state, and candidate ordering applies a “healthy‑first, never dropping candidates” policy to avoid hammering obviously unhealthy IPv4/IPv6 families while keeping golden outputs unchanged.
- Debug/selftest integration: when built with `-DWHOIS_LOOKUP_SELFTEST` and run with `--selftest`, new `[LOOKUP_SELFTEST]` lines summarize DNS candidates, health memory and fallback paths so that remote smoke logs can be eyeballed quickly for expected behavior.
- Docs & operations closure: `USAGE_CN/EN` and `OPERATIONS_CN/EN` gained DNS debug quickstart sections recommending `whois-x86_64 --debug --retry-metrics --dns-cache-stats [--selftest] 8.8.8.8` and describing the meaning and sample output of `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` / `[DNS-HEALTH]` / `[LOOKUP_SELFTEST]`. `tools/remote/README_*.md` now calls out these tags as expected content in `smoke_test.log` when DNS debugging/selftests are enabled.
- Version alignment: bump the core code version to `3.2.9` and update the top-level README display so that v3.2.9 serves as the new “golden” baseline for DNS behavior and observability.

Notes
- No stdout contract changes (per‑query header and authoritative tail) compared to 3.2.8; all new DNS observability remains stderr‑only.
- DNS health memory is deliberately conservative: candidates are reordered but never dropped, and penalties are short‑lived to avoid surprising behavior in edge networks.
- Selftest and DNS debug flags are meant for development/ops; production usage can leave them off without affecting default DNS behavior.

## 3.2.8

中文摘要 / Chinese summary
- DNS 第一阶段（服务器解析）改进：使用 `AI_ADDRCONFIG` 与家族控制（仅/优先）提升解析与连通的确定性；对解析得到的多候选做去重与上限控制；在解析/连不通时回退到已知的 RIR IPv4；头/尾 `@` 段统一显示“实际连接 IP 或 unknown”。
- DNS 第二阶段（候选调度 + 回退层）：新增 `wc_dns` 模块统一处理 IP 字面量、RIR 映射、`getaddrinfo` 重试与 IPv4/IPv6 交错；`lookup.c` 通过该候选表拨号，并在空响应/连接失败/自测黑洞路径中复用同一集合，与 `--dns-*`/家族偏好配置保持一致。
- 三跳模拟增强：新增并验证稳定 `apnic → iana → arin` 链路；通过 `--selftest-force-iana-pivot` 保证仅首次强制 IANA 跳转，后续遵循真实 referral。
- 失败注入扩展：`--selftest-blackhole-arin`（最终跳超时）与 `--selftest-blackhole-iana`（中间跳超时）提供可重复的错误场景，便于脚本化回归与指标对比。
- 重试指标示例：使用 `--retry-metrics -t 3 -r 0` 观察连接级尝试分布与 p95；批量架构冒烟显示 attempts≈7、成功前置 2 次（起始+IANA），后续 ARIN 超时统计集中为 timeouts。
- 多目录同步：远程脚本 `-s '<dir1>;<dir2>'` 支持分号分隔的多个本地同步目标，提升多仓/镜像分发效率。
- 冒烟超时策略优化：含 `--retry-metrics` 的运行采用更宽松的 45s（SIGINT→5s→SIGKILL），避免截断最后的聚合行；常规运行保持默认 8s。
- 架构差异 errno 说明：连接超时在多数架构为 `errno=110 (ETIMEDOUT)`，在 MIPS/MIPS64 交叉产物下为 `errno=145`（同一符号常量的架构特定数值），逻辑以符号常量匹配，不依赖数值。
- 黄金样例汇总：本次冒烟日志（见 v3.2.8 release body）收录多架构 `[RETRY-METRICS-INSTANT]` + `[RETRY-METRICS]` + `[RETRY-ERRORS]` 模式，用作后续调优基线。
- DNS 调试输出：`--debug` 或 `--retry-metrics` 开启时新增 `[DNS-CAND]` / `[DNS-FALLBACK]` 行，完整记录候选列表、回退动作与 `fallback_flags` 映射，方便与 `[RETRY-*]` 对齐诊断。
- 文档同步：`docs/USAGE_EN.md` 与 `docs/USAGE_CN.md` 新增“DNS 调试日志与缓存可观测性”章节，全面说明 `[DNS-CAND]/[DNS-FALLBACK]/[DNS-ERROR]`、正/负向缓存命中提示以及 `--ipv4-only/--ipv6-only` 现在绕过规范域名预拨的行为。

English summary
- DNS phase‑1 (server resolution) improvements: `AI_ADDRCONFIG`-aware resolution with family controls (only/prefer) to increase determinism; de-duplicate and cap address candidates; fallback to known RIR IPv4 when resolution/connectivity fails; unify header/tail `@ <ip|unknown>` display of the connected endpoint.
- DNS phase‑2 (candidate orchestration + fallback): new `wc_dns` helper centralizes IP-literal detection, canonical RIR mapping, `getaddrinfo` retry cadence, and IPv4/IPv6 interleaving. `lookup.c` dials through the structured candidate list and reuses it for empty-response / connect-failure / selftest-blackhole paths so behavior aligns with the `--dns-*` knobs and family preferences.
- Three-hop simulation: stabilized `apnic → iana → arin` chain; `--selftest-force-iana-pivot` enforces only the first pivot via IANA, subsequent referrals follow real targets.
- Failure injection: `--selftest-blackhole-arin` (final hop timeout) and `--selftest-blackhole-iana` (middle hop timeout) yield reproducible error paths for scripted regression & metric baselines.
- Retry metrics showcase: with `--retry-metrics -t 3 -r 0` we observe ~7 attempts, first 2 successes (origin + IANA), remaining ARIN attempts timing out; p95 around 3s across arches.
- Multi-sync support: remote script accepts `-s '<dir1>;<dir2>'` (semicolon separated) to sync artifacts to multiple local destinations for mirrored distribution.
- Metrics-aware smoke timeout: runs containing `--retry-metrics` default to 45s (SIGINT then SIGKILL after 5s) to avoid truncating aggregate output; regular smokes remain at 8s.
- Errno differences: connect timeouts surface as `errno=110 (ETIMEDOUT)` on most arches; on MIPS/MIPS64 cross builds they appear as `errno=145` (architecture-specific numeric for the same symbol). Code logic switches on symbolic constants, not raw numbers.
- Golden sample: multi-arch smoke log excerpt (see v3.2.8 release body) now serves as a baseline for future performance tuning.
- DNS debug output: when `--debug` or `--retry-metrics` is active the client now emits `[DNS-CAND]` / `[DNS-FALLBACK]` lines to stderr, covering candidate ordering, fallback decisions, and the decoded `fallback_flags` bitset for easier correlation with `[RETRY-*]` metrics.
- Documentation: both `docs/USAGE_EN.md` and `docs/USAGE_CN.md` gained a “DNS debug logs & cache observability” section that explains `[DNS-CAND]/[DNS-FALLBACK]/[DNS-ERROR]`, how positive/negative caches show up in logs, and why `--ipv4-only/--ipv6-only` now skip the canonical-host pre-dial to keep the candidate list pure.

Notes
- No stdout contract changes (query header / authoritative tail remain intact in both success and injected failure cases).
- Failure injection flags remain non-fatal to existing success paths; they only alter specific hop behavior.
- Numeric errno variability (110 vs 145) does not affect classification; internal switch uses `ETIMEDOUT` symbol.


## 3.2.7

中文摘要 / Chinese summary
- DNS 第一阶段（服务器解析）奠基工作：引入解析策略与地址族控制参数、候选去重与上限；为 3.2.8 的三跳稳定化与 `@ <ip|unknown>` 观测铺路（本版以内部清理与脚本对齐为主，用户可见行为保持稳定）。
- 重试节流（连接级，默认开启，3.2.7）：转为纯 CLI 配置（移除全部运行时环境变量依赖），新增与精简相关标志：`--pacing-interval-ms`、`--pacing-jitter-ms`、`--pacing-backoff-factor`、`--pacing-max-ms`、`--pacing-disable`、`--retry-metrics`。
- 移除环境变量：源码彻底删除 `getenv/setenv/putenv`；原调试/自测环境变量统一改为 CLI：`--selftest-fail-first-attempt`、`--selftest-inject-empty`、`--selftest-grep`、`--selftest-seclog`。
- 文档精简：中英文 USAGE 将节流与自测章节压缩为单段 bullet；删除环境变量使用章节，仅保留 CLI 指南。
- 远程构建脚本更新：不再转发 WHOIS_*；构建日志提示“CLI-only for pacing/metrics/selftests”；保持多架构静态产物产出与哈希校验流程。
- 冒烟验证：使用 `-M nonzero` 与 `-M zero` 对默认节流与禁用节流进行断言，均 PASS；sleep_ms 呈现符合预期的非零/零差异。
- 行为兼容：标题/尾行、重定向、折叠输出、grep/title 投影均未改变；黄金用例与多架构 QEMU 冒烟继续通过。

English summary
- DNS phase‑1 groundwork: introduce resolution strategy and address‑family controls, candidate de‑dup/capping; sets the stage for 3.2.8’s stabilized three‑hop and unified `@ <ip|unknown>` observability (this release focuses on internal cleanup and script alignment with no user‑visible behavior changes).
- Connect-level retry pacing (default ON, 3.2.7): migrated to fully CLI-driven configuration (removed all runtime env dependencies). New/clean flags: `--pacing-interval-ms`, `--pacing-jitter-ms`, `--pacing-backoff-factor`, `--pacing-max-ms`, `--pacing-disable`, `--retry-metrics`.
- Environment variable removal: eliminated every `getenv/setenv/putenv`; former debug/selftest envs replaced by CLI flags: `--selftest-fail-first-attempt`, `--selftest-inject-empty`, `--selftest-grep`, `--selftest-seclog`.
- Documentation condensed: CN/EN USAGE pacing + selftest content reduced to a compact bullet section; removed legacy env usage guidance, retaining only CLI instructions.
- Remote build script: no longer forwards WHOIS_* variables; logs now state “CLI-only for pacing/metrics/selftests”; multi-arch static artifacts + hash verification unchanged.
- Smoke validation: assertions `-M nonzero` (default pacing) and `-M zero` (disabled pacing) both PASS; `sleep_ms` shows expected non-zero vs zero differentiation.
- Behavioral compatibility: output contract (header/tail), redirects, fold lines, grep/title projection unchanged; golden cases and multi-arch QEMU smokes remain green.

Notes
- No stdout format changes; pacing metrics remain stderr-only when `--retry-metrics` is specified.
- Selftest flags remain non-fatal: failures log diagnostics without altering exit codes.
- All prior env-based hooks are deprecated; attempting to set them has no effect in release binaries.

## 3.2.6

中文摘要 / Chinese summary
- 重构：将 WHOIS 重定向检测/解析逻辑抽离为独立模块（wc_redirect），统一大小写不敏感的重定向信号，移除 APNIC 特例分支；在实现上增加最小校验，避免可疑目标（如私网、localhost）。
- IANA 优先：当需要跨 RIR 跳转时强制先经 IANA 一跳（若尚未访问），稳定最终权威 RIR 的判定与尾行显示。
- 头尾契约一致性：标题行采用 “via <别名或域名> @ <实际连接 IP|unknown>”；尾行在权威服务器为 IP 字面量时，显示映射回的 RIR 域名，@ 段仍保留实际 IP/unknown。
- 自测增强：为重定向模块新增自测覆盖（needs_redirect/is_authoritative_response/extract_refer_server），与原有折叠自测共同执行。
- 警告清理：移除未使用的 legacy 校验函数；为严格 C11 环境提供本地 strdup 安全实现以消除隐式声明警告。

English summary
- Refactor: extract WHOIS redirect detection/parsing into wc_redirect; unify case-insensitive redirect flags; remove APNIC-only branch; add minimal redirect-target validation to avoid local/private endpoints.
- IANA-first policy: when redirecting across RIRs, ensure we hop via IANA once (if not already), improving authoritative resolution and tail-line stability.
- Output contracts: header prints “via <alias-or-host> @ <connected-ip|unknown>”; tail canonicalizes IP-literal authoritative hosts back to RIR domain while keeping the @ segment as IP/unknown.
- Selftests: add redirect tests (needs_redirect/is_authoritative_response/extract_refer_server) alongside existing fold tests.
- Warnings cleanup: remove unused legacy validator; provide local safe strdup for strict C11 builds to avoid implicit declarations.
- Simplified version scheme: default builds no longer append a `-dirty` suffix. Set environment variable `WHOIS_STRICT_VERSION=1` before invoking the remote build script to restore the previous strict behavior (adding `-dirty` when tracked changes exist). This keeps day‑to‑day iteration lightweight while still allowing release hygiene when needed.

Notes
- 用户可通过 `--selftest` 运行内置自测；远程构建脚本支持安静模式与多架构编译，golden 检查保持可用。
- 版本策略简化：默认不再附加 `-dirty`；若需要“严格”标记本地未提交改动，可在执行前导出 `WHOIS_STRICT_VERSION=1`。

## 3.2.5

中文摘要 / Chinese summary
- 取消双语显示与环境变量切换：移除 `--lang` 与 `WHOIS_LANG`，统一英文输出，避免在受限 SSH/串口终端出现乱码。
- 帮助内容精简与去重：合并/去重 usage 段落，新增/保留 `--debug-verbose`、`--selftest`、`--fold-unique` 说明。
- 文档同步：USAGE（中/英）与示例更新；远程构建脚本示例去除语言参数；保持对 BusyBox 管道输出契约的兼容。
- 行为兼容性：除帮助文本外，核心查询/重定向/条件输出引擎未改动；黄金用例保持通过。

English summary
- De-internationalization: remove `--lang` and `WHOIS_LANG`; switch to English-only output to avoid mojibake on constrained SSH/serial terminals.
- Help output simplified and deduplicated; document `--debug-verbose`, `--selftest`, and `--fold-unique`.
- Docs updated (CN/EN); remote helper script examples no longer pass language switches; BusyBox-friendly output contract preserved.
- Backward-compatible behavior (queries/redirects/conditional engine unchanged); golden tests continue to pass.

其他变更 / Other changes
- 小幅清理与注释同步；准备 3.2.5 标签与产物发布。
- 新增 `--host` 传入 IPv4/IPv6 字面量时的 RIR 反查回退：当直接连接失败，会调用 PTR 反查并自动切换到匹配的 RIR 主机；若不属于任何已知 RIR，则立即报错退出。
- Added RIR fallback when `--host` receives an IPv4/IPv6 literal: on connection failure the client performs a PTR lookup, retries with the canonical RIR hostname when matched, and aborts with an explicit error otherwise.

## 3.2.4

中文摘要 / Chinese summary
- 模块化第一步：抽离条件输出相关逻辑到 `wc_title` / `wc_grep` / `wc_fold` / `wc_output` / `wc_seclog`，引入 `src/core/pipeline.c` 做后续主流程承载；主行为保持兼容。
- 新增 grep 自测钩子（编译宏 `-DWHOIS_GREP_TEST` + 环境变量 `WHOIS_GREP_TEST=1`），三种模式（block / line / line+cont）启动时自动验证并输出 PASS/FAIL。文档新增启用示例。
- 修复与改进续行启发式：块模式仅保留首个“header-like”缩进行（如地址行），后续同类缩进行需匹配正则才保留，避免误输出无关字段（Foo 等）。
- 远程构建诊断增强：增加 LDFLAGS/LDFLAGS_EXTRA 打印、UPX 可用性与压缩结果提示、QEMU vs 原生 smoke runner 显示，便于排查跨架构差异。
- 文档更新：`OPERATIONS_CN/EN.md` 增添 grep 自测钩子章节；英文化残留注释；说明 wc 前缀含义（whois client modules）。
- 保持输出契约与 CLI 语义不变（header/tail、折叠行格式、参数集合）。

English summary
- First modularization step: extract conditional output logic into `wc_title`, `wc_grep`, `wc_fold`, `wc_output`, `wc_seclog`; introduce `src/core/pipeline.c` for future orchestration while preserving current behavior.
- Add grep self-test hook (build macro `-DWHOIS_GREP_TEST` + env `WHOIS_GREP_TEST=1`) validating block / line / line+cont modes at startup; docs include enable examples.
- Improve continuation heuristic in block mode: keep only the first header-like indented line (e.g. address), subsequent header-like continuation lines must match the regex, preventing unrelated field leakage.
- Enhance remote build diagnostics: print LDFLAGS/LDFLAGS_EXTRA, UPX availability & compression stats, and show QEMU vs native smoke runner to ease cross-arch troubleshooting.
- Docs updated: grep self-test section added (CN/EN), remaining comments anglified, explain wc prefix (whois client modules).
- External contracts unchanged (artifact names, CLI options, header/tail lines, folded output format).

其他变更 / Other changes
- 预留进一步拆分入口：后续计划抽取 CLI 解析 (wc_opts)、网络与缓存 (wc_net / wc_cache)、协议校验 (wc_proto) 等；本版仅奠定条件输出与诊断基础。
- 保持构建可重复性：远程脚本 `-X` 一键开启自测；多架构静态产物均通过 GREPTEST。 

Future (non-breaking roadmap)
- Next steps: publish this stable tag, then proceed with wc_opts extraction followed by wc_net and wc_cache; each step gated by remote multi-arch build + self-test PASS.


## 3.2.3

中文摘要 / Chinese summary
- 输出契约细化：标题行与尾行现在都会解析并显示所使用的服务器域名对应的 IP（解析失败显示 `unknown`），别名（如 `apnic`）被映射后再解析，避免“via apnic @ unknown”假阴性。
- 折叠输出（`--fold`）保持原格式不变：仍为 `<query> <UPPER_VALUE_...> <RIR>`，不追踪服务器 IP，确保下游管道兼容性。
- 新增 ARIN IPv6 连通性提示：在私网 IPv4 环境可能遭拒 (port 43)，建议启用 IPv6 或使用公网出口；相关说明已加入 USAGE（中/英）。

English summary
- Output contract refinement: header and tail lines now show the resolved IP of the starting server and authoritative RIR server (or `unknown` on DNS failure); aliases (e.g. `apnic`) are mapped before resolution to avoid false "@ unknown" cases.
- Folded output (`--fold`) remains unchanged: still `<query> <UPPER_VALUE_...> <RIR>` for pipeline stability; server IPs are intentionally excluded.
- Added ARIN IPv6 connectivity tip: private IPv4 LAN sources may be rejected on port 43; enabling IPv6 or using a public egress fixes access. Documentation updated (CN/EN).

其他变更 / Other changes
- 小幅代码清理与注释同步；为后续一键发布准备版本号提升。

Artifacts / 产物：同 3.2.2（一个动态 x86_64 + 七个全静态多架构二进制）。

---

## 3.2.2

中文摘要
- 安全性系统加固（九大方向），并新增可选安全日志：
  - 新增 `--security-log`（默认关闭）：将安全事件输出到 stderr（用于调试/审计），不改变 stdout 的“标题/尾行”契约。
  - 安全日志内置限频（约 20 条/秒）：在洪泛/攻击场景下自动抑制并输出汇总提示，避免刷屏。
  - 主要领域：
    1) 内存安全辅助：`safe_malloc/realloc/strdup` 等封装与检查；
    2) 信号处理与清理：SIGINT/TERM/HUP/PIPE 的稳态处理与活动连接清理；
    3) 输入校验：查询长度/字符集/可疑负载识别；
    4) 网络连接与重定向安全：目标校验、环路防护、注入与异常识别；
    5) 响应净化与校验：移除控制/ANSI 序列、结构一致性检查；
    6) 配置校验：不合法配置与越界检测；
    7) 线程安全与缓存一致性：加锁、失效策略与并发安全；
    8) 连接洪泛与速率监测：异常速率与限流告警；
    9) 协议级异常检测与日志：可疑字段与跨域响应识别。

English summary
- Security hardening across nine areas with optional diagnostics:
  - Add `--security-log` (off by default): emits SECURITY events to stderr for diagnostics/audit; stdout contract unchanged.
  - Security log output is rate-limited (~20 events/sec) with suppression summaries to prevent stderr flooding during attacks.
  - Areas covered:
    1) Memory safety helpers (safe malloc/realloc/strdup);
    2) Signal handling and cleanup (SIGINT/TERM/HUP/PIPE) with active-connection tracking;
    3) Input validation (query length/charset/suspicious payloads);
    4) Network/redirect security (target validation, loop guards, injection/anomaly detection);
    5) Response sanitization/validation (strip control/ANSI sequences, structural checks);
    6) Configuration validation (illegal/ out-of-range detection);
    7) Thread safety and cache integrity (locks, invalidation);
    8) Connection flood/rate monitoring;
    9) Protocol-level anomaly detection and logging.

其他变更
- 完全移除此前实验性的 RDAP 相关功能与开关，保持经典 WHOIS 纯文本流程，避免语义歧义与维护成本。
- 修复并清理若干编译警告（如 -Wsign-compare），`receive_response` 相关计数改为 `size_t`，并支持 `CFLAGS_EXTRA` 以便定制构建。 
- 文档（中/英）同步更新：补充安全日志与故障排查要点（含 ARIN:43 端口连通性提示），对齐“零 RDAP”状态。

Other changes
- Remove all experimental RDAP features and switches to keep classic WHOIS-only behavior and avoid semantic drift.
- Fix/clean compilation warnings (e.g., -Wsign-compare), switch some counters to `size_t`, and add `CFLAGS_EXTRA` for customized builds.
- Docs (CN/EN) updated accordingly, including security-log notes and troubleshooting (e.g., ARIN:43 connectivity), aligned with "no RDAP" state.

## 3.2.1

中文摘要
- 新增“折叠输出”开关 `--fold`：将经 `-g/--grep*` 筛选后的正文折叠为单行，格式为 `<query> <UPPER_VALUE_...> <RIR>`，便于在 BusyBox 管道中直接聚合与判定；默认关闭。
  - 新增 `--fold-sep <SEP>` 指定分隔符（默认空格，支持 `\t/\n/\r/\s`）；新增 `--no-fold-upper` 保留原大小写（默认转为大写）。

- 文档：新增“续行关键词命中技巧”一节，给出推荐策略 A（`-g` + 块模式 `--grep` + `--fold`）与可选策略 B（行模式 OR + `--keep-continuation-lines` + `--fold`），并说明行模式按“逐行”匹配（`\n` 不跨行）。
  - 参考：`docs/USAGE_CN.md#续行关键词命中技巧推荐策略与陷阱` | `docs/USAGE_EN.md#continuation-line-keyword-capture-tips-recommended`

English summary
- Add optional folded output via `--fold`: print a single folded line per query using the current selection (after `-g` and `--grep*`), formatted as `<query> <UPPER_VALUE_...> <RIR>`; disabled by default.
  - Add `--fold-sep <SEP>` to customize the separator (default space; supports `\t/\n/\r/\s`) and `--no-fold-upper` to preserve original case (default uppercases).

- Docs: add "Continuation-line keyword capture tips" with recommended Strategy A (`-g` + block `--grep` + `--fold`) and optional Strategy B (line-mode OR + `--keep-continuation-lines` + `--fold`); clarify that line mode matches per-line (`\n` does not span lines).
  - See: `docs/USAGE_EN.md#continuation-line-keyword-capture-tips-recommended` | `docs/USAGE_CN.md#续行关键词命中技巧推荐策略与陷阱`

## 3.2.0

中文摘要
- 新增基于正则的“行模式”过滤（`--grep-line`）与“块模式/行模式”切换（`--grep-block/--grep-line`），保持与 `-g/--title` 的投影语义兼容：先按标题前缀投影，再进行正则过滤。
- 行模式支持“续行展开”开关（`--keep-continuation-lines` 和 `--no-keep-continuation-lines`），用于在命中行时输出整个字段块（标题+续行）。
- 修复行模式在部分系统上可能跨行匹配的问题：现在对“当前行”做独立的正则匹配，兼容 musl；无需 `REG_STARTEND` 扩展。
- 连接缓存健壮性增强：使用 `getsockopt(SO_ERROR)` 校验连接可用性并在异常时清理缓存，替代脆弱的基于 `select` 的探测。
- 文档与集成：
  - USAGE（中/英）补充新选项与示例；跨链接至 lzispro，记录环境变量与集成方式。
  - lzispro 的 `lzispdata.sh` 默认切换为“行模式 + 不展开续行”，并提供环境变量回退到块模式或打开展开。

English summary
- Add regex-based line filtering mode (`--grep-line`) and explicit selection mode toggles (`--grep-block/--grep-line`); preserve `-g/--title` semantics by applying title projection first, then regex.
- Line mode supports an optional block expansion switch (`--keep-continuation-lines`/`--no-keep-continuation-lines`) to emit the whole field block when any line matches.
- Fix potential cross-line matching in line mode by matching against an isolated copy of the current line (portable on musl); no `REG_STARTEND` dependency.
- Improve cached-connection aliveness check using `getsockopt(SO_ERROR)` and clean up invalid sockets, replacing the earlier select-based probe.
- Docs and integration:
  - Update USAGE (CN/EN) with new options and examples; cross-link to lzispro with env var guidance.
  - lzispro `lzispdata.sh` defaults to line mode without block expansion; env switches allow reverting to block mode or enabling expansion.

Artifacts / 产物：与上一版一致（动态 x86_64 与七个全静态多架构二进制），详见下文 Artifacts 一节。

中文摘要
- 轻量高性能 C 语言 whois 客户端，专为 BusyBox 管道优化：
  - 批量标准输入（-B），无位置参数且 stdin 非 TTY 自动进入
  - 稳定输出契约：每条首行“=== Query: … ===”，末行“=== Authoritative RIR: … ===”
  - 非阻塞连接、I/O 超时、轻量重试（默认 2）、自动重定向（默认 5，支持禁用与上限）
  - 多架构静态二进制（aarch64/armv7/x86_64/x86/mipsel/mips64el/loongarch64）
- 新增/重要说明：
  - 文档全面更新（中英双语），补充 IPv4/IPv6 字面量作为 --host 的用法与示例
  - 远端交叉编译与冒烟测试脚本：默认“联网冒烟”，支持 SMOKE_QUERIES 自定义目标
  - 冒烟前增加 43/TCP 连通性预检（仅日志），失败将如实反映在 smoke_test.log 中

English summary
- Lightweight, high-performance whois client in C, optimized for BusyBox pipelines:
  - Batch stdin (-B), implicitly enabled when no positional arg and stdin is not a TTY
  - Stable output contract: per-query header and authoritative RIR tail line
  - Non-blocking connect, IO timeouts, light retries (default 2), referral redirects (default 6, configurable/disable)
  - Multi-arch static binaries (aarch64/armv7/x86_64/x86/mipsel/mips64el/loongarch64)
- New/important notes:
  - Docs revamped (CN/EN), add guidance for using IPv4/IPv6 literals with --host
  - Remote cross-compilation + smoke test scripts: default to networked smoke; support SMOKE_QUERIES
  - Add a log-only port-43 connectivity pre-check; real failures are reflected in smoke_test.log

## Artifacts / 产物
- whois-x86_64-gnu（CI 构建的 Linux x86_64 glibc 动态可执行）
- SHA256SUMS.txt（针对 whois-x86_64-gnu）

Additionally, remote toolchains produce seven fully static binaries (musl unless noted):
此外，远端交叉工具链会产出 7 个“全静态”二进制（除 loongarch64 特例外，一般为 musl 静态）：

- whois-x86_64-gnu - Linux x86_64，glibc 动态链接；体积小，适合常见桌面/服务器。
- whois-x86_64 — Linux x86_64，静态（musl）；与 whois-x86_64-gnu 的区别：无需依赖 glibc
- whois-x86 — Linux 32 位 x86 (i686)，静态
- whois-aarch64 — Linux aarch64/ARM64，静态；适合大多数发行版/容器
- whois-armv7 — Linux 32 位 ARMv7，静态
- whois-mipsel — Linux MIPS little-endian，静态
- whois-mips64el — Linux MIPS64 little-endian，静态
- whois-loongarch64 — Linux LoongArch64，静态（使用 GNU 工具链，已链接 libgcc/libstdc++）

使用提示 / Usage guidance：
- 在极简系统/容器中优先选择“静态”二进制（便携性最好）。
  - Prefer the static binary for maximum portability on minimal systems.
- 标准 x86_64 桌面/服务器（glibc）可直接使用 whois-x86_64-gnu（体积更小）。
  - Use whois-x86_64-gnu on standard x86_64 Linux with glibc for smaller size.

## 使用要点 / Usage highlights
- 禁止重定向：`--host <rir> -Q` 可固定服务器稳定输出。
  - Disable redirects: use `--host <rir> -Q` to fix the server for consistent output.
- 重试节奏默认：interval=300ms, jitter=300ms，可用 `-i/-J` 调整。
  - Retry pacing defaults: interval 300ms, jitter 300ms; adjustable via `-i/-J`.
- 私网 IP 输出正文为 "<ip> is a private IP address"，尾行为 `=== Authoritative RIR: unknown ===`。
  - For private IPs, the body prints "<ip> is a private IP address" and the tail shows `=== Authoritative RIR: unknown ===`.

更多细节 / More details:
- 使用说明 / Usage: CN docs/USAGE_CN.md | EN docs/USAGE_EN.md
