# whois 操作与发布手册（中文）

英文版见：`docs/OPERATIONS_EN.md`

本手册汇总日常“提交/发布/远端构建/镜像到 Gitee”相关的常用操作与注意事项，便于随时查阅。

信号处理提示（2025-12-21）：Ctrl+C/TERM/HUP 会关闭缓存连接并仅输出一次终止提示；`[DNS-CACHE-SUM]` / `[RETRY-*]` 仍会在 atexit 刷出，即便远程冒烟被中断也能留存缓存与指标行。
前端入口提示：所有可执行入口统一复用 `wc_client_frontend_run`；如需新增测试/多入口，仅在入口层组装 `wc_opts` 后调用该 facade，禁止在入口重复自测、信号或 atexit 逻辑，保持 stdout/stderr 契约一致。
自测标记提示（2025-12-25）：`[SELFTEST]` 标签统一带 `action=` 前缀，进程内最多输出一次，未显式执行 `--selftest` 套件也会在首次命中强制钩子时落盘；DNS ipv6-only/fallback 自测降级为 WARN，避免偶发网络中止套件。
响应过滤缓冲提示（2025-12-25）：响应过滤链路复用单次查询的工作缓冲，减少重复分配，行为与 CLI 不变；title/grep/fold 已提供 workbuf 版接口，旧接口兼容保留。fold unique 去重已改用 workbuf scratch 存储 token 视图，避免逐 token malloc（2025-12-25）。
注入视图提示（2025-12-27）：force-* 注入已集中在 selftest injection view；无 net_ctx 路径同样从该视图兜底读取，行为与带 net_ctx 一致。新增入口/封装需显式获取视图，避免回退旧全局；stdout/stderr 契约不变。
workbuf 统计提示（可选）：如需观察长行/多续行的扩容情况，可在编译时定义 `WC_WORKBUF_ENABLE_STATS`，运行后通过 `wc_workbuf_stats_snapshot()` 获取 `reserves/grow_events/max_request/max_cap/max_view_size`；默认构建未启用，不影响黄金。
注入视图验证示例：
```bash
# Linux/Git Bash：观察注入视图兜底 + 指标标签
whois-x86_64 --debug --retry-metrics --dns-cache-stats --selftest-force-suspicious 8.8.8.8
# 期待 stderr 出现：[SELFTEST] action=force-suspicious、[DNS-CACHE-SUM]、[RETRY-METRICS*]
```

快速测试指引：
- 本地最小验证：运行上面命令，确认无 net_ctx/有 net_ctx 路径输出一致（标题/尾行/折叠不变）。
- 远程冒烟：VS Code 任务“Remote: Build and Sync whois statics”或直接 `tools/remote/remote_build_and_test.sh -r 1 -a "--debug --retry-metrics --dns-cache-stats --selftest-force-suspicious 8.8.8.8"`，查看 smoke_test.log 是否包含 `[SELFTEST] action=force-suspicious`、`[DNS-CACHE-SUM]` 且黄金 PASS。

其它场景示例：
- 批量策略（raw，无折叠）：
  ```bash
  printf "8.8.8.8\n1.1.1.1\n" | whois-x86_64 -B --batch-strategy raw --debug --retry-metrics --dns-cache-stats --grep-line --no-fold
  # 关注 stderr: [RETRY-METRICS*]，stdout: 无折叠，保持标题/尾行契约
  ```
- 批量策略（plan-b，带折叠）：
  ```bash
  printf "8.8.8.8\n1.1.1.1\n" | whois-x86_64 -B --batch-strategy plan-b --fold --debug --retry-metrics --dns-cache-stats
  # 关注 stdout: 每行折叠 <query> <UPPER...> <RIR>；stderr: [DNS-CACHE-SUM] 仅一次
  ```
- 批量策略（health-first，块模式 + 续行保留）：
  ```bash
  printf "8.8.8.8\n1.1.1.1\n" | whois-x86_64 -B --batch-strategy health-first --grep "OrgName|Country" --grep-block --keep-continuation-lines --fold --debug --retry-metrics --dns-cache-stats
  # 关注 stdout: 折叠后的字段包含续行关键词；stderr: [DNS-CACHE-SUM] 单行 + [RETRY-METRICS*]
  ```
- 单次查询，无折叠对比：
  ```bash
  whois-x86_64 --debug --retry-metrics --dns-cache-stats --no-fold 8.8.8.8
  # 与默认折叠对比，确认正文/标题/尾行一致
  ```
- grep 组合（行模式 OR，多关键词）：
  ```bash
  whois-x86_64 -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --debug --retry-metrics --dns-cache-stats 8.8.8.8
  # 关注 stdout: 仅保留命中行；stderr: 指标标签存在，契约不变
  ```
- grep 组合（块模式 AND，保留续行）：
  ```bash
  whois-x86_64 --grep 'OrgName' --grep 'Country' --grep-block --keep-continuation-lines --fold --debug --retry-metrics --dns-cache-stats 8.8.8.8
  # 关注 stdout: 折叠行包含块内两个命中字段；stderr: 标签正常
  ```
- 节流参数验证（pacing on/off 对比）：
  ```bash
  whois-x86_64 --pacing-interval-ms 300 --pacing-jitter-ms 300 --retry-metrics 8.8.8.8
  whois-x86_64 --pacing-disable --retry-metrics 8.8.8.8
  # 对比 stderr 中 [RETRY-METRICS*] 的 sleep_ms/attempts，确认节流生效与禁用效果
  ```
- DNS 家族特例（强制 IPv6 优先）：
  ```bash
  whois-x86_64 --dns-family-mode prefer-v6 --debug --retry-metrics --dns-cache-stats 8.8.8.8
  # 关注 stderr: [DNS-CAND]/[DNS-HEALTH] 顺序偏向 v6，仍有 fallback；[DNS-CACHE-SUM] 单行
  ```
- DNS 家族特例（仅 IPv4）：
  ```bash
  whois-x86_64 --dns-family-mode v4-only --debug --retry-metrics --dns-cache-stats 8.8.8.8
  # 关注 stderr: 候选仅 v4，无 v6；尾行契约不变
  ```
- 节流参数（backoff + max cap）：
  ```bash
  whois-x86_64 --pacing-interval-ms 200 --pacing-jitter-ms 200 --pacing-backoff-factor 2.0 --pacing-max-ms 1200 --retry-metrics 8.8.8.8
  # 关注 [RETRY-METRICS*] 中 sleep_ms 逐步退避且封顶 1200ms，attempts/p95 与期望一致
  ```
- 关闭 dns-cache-stats 场景：
  ```bash
  whois-x86_64 --debug --retry-metrics 8.8.8.8
  # 预期 stderr 无 [DNS-CACHE-SUM]，其余标签仍在；stdout 契约不变
  ```
- 超时/重试组合（高 retries，低 timeout）：
  ```bash
  whois-x86_64 --timeout 2 --retries 4 --retry-interval 200 --retry-jitter 200 --retry-metrics 8.8.8.8
  # 关注 [RETRY-METRICS*] 的 attempts/p95，确认小超时+多重试路径；stderr 保持标签完整
  ```
- pacing-max-ms 极端值验证：
  ```bash
  whois-x86_64 --pacing-interval-ms 100 --pacing-jitter-ms 0 --pacing-backoff-factor 3.0 --pacing-max-ms 50 --retry-metrics 8.8.8.8
  # 预期 sleep_ms 被封顶在 50ms 左右，不会随 backoff 继续增长；attempts/p95 受限
  ```
- 无 IPv6 环境下的 v6-only 异常观测：
  ```bash
  whois-x86_64 --dns-family-mode v6-only --retry-metrics --debug 8.8.8.8
  # 预期 stderr: [DNS-CAND] 仅 v6，可能 ENETUNREACH/EHOSTUNREACH/ETIMEDOUT；[RETRY-METRICS*] 记录失败，stdout 仍保持契约（可能尾行 unknown）
  ```
- 自测注入组合（空包 + force-suspicious）：
  ```bash
  whois-x86_64 --selftest-inject-empty --selftest-force-suspicious 8.8.8.8 --debug --retry-metrics --dns-cache-stats
  # 预期 stderr 同时出现 [SELFTEST] action=inject-empty 与 action=force-suspicious；stdout 契约不变
  ```

链接风格转换说明请参考：`docs/RELEASE_LINK_STYLE.md`（绝对直链与相对路径的切换策略与脚本）。

发布流程（详版）：`docs/RELEASE_FLOW_CN.md` | English: `docs/RELEASE_FLOW_EN.md`

Windows 产物快速使用（本地冒烟示例）：
- PowerShell 单条：`whois-win64.exe --debug --prefer-ipv4-ipv6 8.8.8.8`；纯 IPv6：`whois-win64.exe --debug --ipv6-only 8.8.8.8`
- PowerShell 管道：`"8.8.8.8" | whois-win64.exe --debug --ipv4-only`（未显式 `-B` 但 stdin 非 TTY 时自动批量）
- CMD 管道：`echo 8.8.8.8 | whois-win64.exe --debug --ipv4-only`
- Linux 上用 wine：`env WINEDEBUG=-all wine64 ./whois-win64.exe --debug --prefer-ipv6 8.8.8.8`（32 位对应 `wine`）。

VS Code 任务/脚本提示：`tools/remote/remote_build_and_test.sh` 默认构建 win32/win64；远程冒烟输出的 Windows 日志位于 `out/artifacts/<ts>/build_out/smoke_test_win64.log` / `smoke_test_win32.log`，便于回溯。

---

## 一键发布（Windows PowerShell）

入口脚本：`tools/release/full_release.ps1`（内部调用 Bash 脚本 `tools/release/full_release.sh`）

常用用法：

- 默认发布（自动补丁位 + 联网冒烟）
  ```powershell
  .\tools\release\full_release.ps1
  ```
- 指定多查询目标（空格分隔）
  ```powershell
  .\tools\release\full_release.ps1 -Queries "8.8.8.8 1.1.1.1"
  ```
- 跳过冒烟测试（更快）
  ```powershell
  .\tools\release\full_release.ps1 -NoSmoke
  ```
- 手动指定 Tag（例如 v3.1.10）
  ```powershell
  .\tools\release\full_release.ps1 -Tag v3.1.10
  ```
- 指定 lzispro 路径（当不在 whois 同级目录时）
  ```powershell
  .\tools\release\full_release.ps1 -LzisproPath "D:\\LZProjects\\lzispro"
  ```
- 演练（不做变更）
  ```powershell
  .\tools\release\full_release.ps1 -DryRun -NoSmoke -Queries "8.8.8.8 1.1.1.1"
  ```

参数说明：
- `-Tag vX.Y.Z`：省略则自动把最新标签补丁位 +1
- `-Queries "..."`：供冒烟测试使用；当 `-NoSmoke` 时会被忽略（脚本会打印提醒）
- `-NoSmoke`：跳过联网冒烟测试
- `-LzisproPath`：可显式传入 lzispro 路径（自动转换为 MSYS `/d/...`）
- `-DryRun`：只打印步骤，不执行

产物与日志：
- 7 个静态二进制会同步到：`<lzispro>/release/lzispro/whois/`
- 详细日志：`whois/out/release_flow/<timestamp>/step1_remote.log`
- 严格模式：默认将 Warnings 视为失败并提前退出（STRICT_WARN=1）

---

## 远端交叉编译启动器（本地）

脚本：`tools/remote/remote_build_and_test.sh`

关键参数（可用 `-h` 查看完整帮助）：
- `-t`：目标架构（默认：`aarch64 armv7 x86_64 x86 mipsel mips64el loongarch64`）
- `-r 0|1`：是否跑冒烟测试
- `-q "8.8.8.8 example.com"`：冒烟测试查询目标（空格分隔）
- `-a` 追加冒烟参数（示例：`-a '-g Org|Net|Country'`）。更新：VS Code 任务现已统一为参数值加引号并安全引用，`rbSmokeArgs` 输入框直接填内容（如：`-g Domain|Registrar|Name Server|DNSSEC`）或留空表示无额外参数；不再推荐裸 `--` 作为占位。显式空值可留空或输入 `''`。`-g` 为不区分大小写的“前缀匹配”，不是正则；需正则过滤请用 `--grep/--grep-cs`。
- `-s <dir>`：把 whois-* 与 `SHA256SUMS-static.txt` 同步到本机目录；支持分号/逗号多目录；`-P 1` 仅清理非 whois-* / 非 SHA256SUMS 文件
- `-o/-f`：远端输出目录、本地拉取目录基准（默认 `out/artifacts/<ts>/build_out`）
- `-L 0|1`：默认 1，表示在抓回冒烟日志后自动生成 `referral_143128/iana|arin|afrinic.log` 并调用 `tools/test/referral_143128_check.sh`。如需临时跳过（例如 AfriNIC 维护窗口或仅做纯构建），可传 `-L 0`。

注意：自 2025-12-20 起，网络层不再提供隐式 fallback net context，需在入口调用 `wc_runtime_init_resources()` 后显式激活 net_ctx；缺失会返回 `WC_ERR_INVALID`。默认远程脚本/入口已覆盖，无需额外操作。

自检 registry 提示：`--selftest-registry` 即便未启用 lookup/startup demos 也会执行 registry harness；`tools/test/selftest_golden_suite.ps1` 仅在 `SmokeArgs`/`SmokeExtraArgs` 都不含该旗标时才自动追加，避免重复开关但保证 `[SELFTEST] action=batch-registry-*` 可见。

最新一次四轮冒烟（2025-12-31 08:34–09:40，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251231-083422`。
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251231-094006`。

上一轮四向参考（2025-12-31 06:59–07:02）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251231-065912`。
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251231-070240`。

更早一轮参考（2025-12-31 06:13–06:16）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251231-061307`。
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251231-061635`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-31 09:43–09:54）：
- raw：`out/artifacts/batch_raw/20251231-094301/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251231-094642/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251231-095108/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251231-095450/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

上一轮参考（2025-12-31 07:11–07:22）：
- raw：`out/artifacts/batch_raw/20251231-071143/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251231-071514/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251231-071907/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251231-072254/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

更早参考（2025-12-31 06:19–06:29）：
- raw：`out/artifacts/batch_raw/20251231-061925/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251231-062253/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251231-062624/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251231-062947/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-31 09:57–10:04）：
- raw：`out/artifacts/batch_raw/20251231-095753/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251231-100000/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251231-100207/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251231-100448/build_out/smoke_test.log`

上一轮参考（2025-12-31 07:25–07:32）：
- raw：`out/artifacts/batch_raw/20251231-072555/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251231-072804/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251231-073021/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251231-073225/build_out/smoke_test.log`

更早参考（2025-12-31 06:34–06:41）：
- raw：`out/artifacts/batch_raw/20251231-063416/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251231-063635/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251231-063902/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251231-064111/build_out/smoke_test.log`

最新一次双轮冒烟（2025-12-25 15:37–15:40，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-153747/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-154027/build_out/smoke_test.log`。

最新一次四轮冒烟（2025-12-25 12:34–12:37，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-123419/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-123745/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-25 12:39–12:46）：
- raw：`out/artifacts/batch_raw/20251225-123945/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251225-124205/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251225-124429/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251225-124648/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-25 12:48–12:52 批次）：
- raw：`out/artifacts/batch_raw/20251225-124840/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251225-124955/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251225-125111/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251225-125231/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-25 11:46–11:48，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-114602/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-114822/build_out/smoke_test.log`。

最新一次四轮冒烟（2025-12-25 10:59–11:02，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-105955/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-110224/build_out/smoke_test.log`。

最新一次四轮冒烟（2025-12-25 06:46–06:49，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-064648/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-064909/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-25 06:51–06:58）：
- raw：`out/artifacts/batch_raw/20251225-065101/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251225-065323/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251225-065539/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251225-065801/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-25 07:00–07:03 批次）：
- raw：`out/artifacts/batch_raw/20251225-070013/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251225-070125/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251225-070241/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251225-070358/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-22 23:37–23:56，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251222-233731/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251222-233938/build_out/smoke_test.log`。

最新一次四轮冒烟（2025-12-25 00:14–00:17，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-001454/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-001704/build_out/smoke_test.log`。

最新一次四轮冒烟（2025-12-25 00:48–00:50，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-004820/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251225-005049/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-25 00:52–00:59）：
- raw：`out/artifacts/batch_raw/20251225-005250/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251225-005508/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251225-005736/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251225-005953/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-25 01:01–01:05 批次）：
- raw：`out/artifacts/batch_raw/20251225-010144/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251225-010258/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251225-010412/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251225-010533/build_out/smoke_test.log`

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-25 00:18–00:25）：
- raw：`out/artifacts/batch_raw/20251225-001855/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251225-002111/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251225-002327/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251225-002544/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-25 00:28–00:32 批次）：
- raw：`out/artifacts/batch_raw/20251225-002843/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251225-002954/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251225-003113/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251225-003230/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-24 22:56–22:59，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251224-225648/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251224-225932/build_out/smoke_test.log`。

最新一次四轮冒烟（2025-12-24 23:45–23:47，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251224-234518/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251224-234746/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-24 23:49–23:56）：
- raw：`out/artifacts/batch_raw/20251224-234943/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251224-235158/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251224-235416/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251224-235632/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-24 23:58–2025-12-25 00:02 批次）：
- raw：`out/artifacts/batch_raw/20251224-235842/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251224-235959/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251225-000119/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251225-000232/build_out/smoke_test.log`

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-24 23:02–23:10）：
- raw：`out/artifacts/batch_raw/20251224-230253/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251224-230508/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251224-230748/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251224-231041/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-24 23:12–23:17 批次）：
- raw：`out/artifacts/batch_raw/20251224-231247/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251224-231445/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251224-231558/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251224-231707/build_out/smoke_test.log`

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-22 23:41–23:48）：
- raw：`out/artifacts/batch_raw/20251222-234143/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251222-234400/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251222-234617/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251222-234836/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-22 23:51–23:56 批次）：
- raw：`out/artifacts/batch_raw/20251222-235158/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251222-235324/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251222-235439/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251222-235606/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-22 20:50–20:53，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251222-205023/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251222-205302/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-22 20:55–21:03）：
- raw：`out/artifacts/batch_raw/20251222-205509/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251222-205731/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251222-210022/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251222-210302/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-22 21:11–21:14 批次）：
- raw：`out/artifacts/batch_raw/20251222-211109/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251222-211228/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251222-211340/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251222-211452/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-21 00:12 左右，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251221-001203/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251221-001409/build_out/smoke_test.log`。

最新一次远程冒烟（2025-12-21 01:24 左右，默认参数，含信号清理优化）：无告警 + `[golden] PASS`，日志 `out/artifacts/20251221-012403/build_out/smoke_test.log`。

最新一次四轮冒烟（2025-12-21 01:50 左右，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251221-015000/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251221-015221/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-21 01:54–02:01 批次）：
- raw：`out/artifacts/batch_raw/20251221-015424/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251221-015646/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251221-015920/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251221-020147/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-21 02:04–02:07 批次）：
- raw：`out/artifacts/batch_raw/20251221-020412/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251221-020523/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251221-020632/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251221-020741/build_out/smoke_test.log`

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-21 00:15–00:23 批次）：
- raw：`out/artifacts/batch_raw/20251221-001557/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251221-001825/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251221-002047/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251221-002311/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-21 00:25–00:29 批次）：
- raw：`out/artifacts/batch_raw/20251221-002544/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251221-002700/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251221-002818/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251221-002937/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-20 22:21 左右，net ctx 收束 + runtime flush hook 复跑，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251220-222145/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251220-222407/build_out/smoke_test.log`。

最新一次远程编译冒烟（2025-12-20 23:02，默认参数）：无告警 + `[golden] PASS`，日志 `out/artifacts/20251220-230243/build_out/smoke_test.log`。

最新一次四轮冒烟（2025-12-20 23:35 左右，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251220-233528/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251220-233802/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-20 23:40–23:47 批次）：
- raw：`out/artifacts/batch_raw/20251220-234006/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251220-234232/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251220-234454/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251220-234721/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-20 23:49–23:53 批次）：
- raw：`out/artifacts/batch_raw/20251220-234934/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251220-235101/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251220-235224/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251220-235342/build_out/smoke_test.log`

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-20 22:26–22:34 批次）：
- raw：`out/artifacts/batch_raw/20251220-222608/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251220-222900/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251220-223143/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251220-223431/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-20 22:36–22:40 批次）：
- raw：`out/artifacts/batch_raw/20251220-223635/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251220-223752/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251220-223906/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251220-224028/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-20 21:12 左右，net ctx 显式注入后复跑，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251220-211245/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251220-211508/build_out/smoke_test.log`；
- 批量策略 raw/health-first/plan-a/plan-b：
  - raw：`out/artifacts/batch_raw/20251220-211738/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251220-212022/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251220-212249/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251220-212513/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
- 自检（`--selftest-force-suspicious 8.8.8.8`，四策略）：
  - raw：`out/artifacts/batch_raw/20251220-212733/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251220-212900/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251220-213031/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251220-213156/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-18 14:17 左右，缓存计数采样开关落地后复跑，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-141752/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-142007/build_out/smoke_test.log`。

最新一次四轮冒烟（2025-12-18 15:26 左右，client_flow 显式 Config 注入后复跑，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-152604/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-152906/build_out/smoke_test.log`。

最新一次四轮冒烟（2025-12-18 16:03 左右，pipeline 显式 Config 传递复跑，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-160332/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-160639/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-18 16:09 批次）：
- raw：`out/artifacts/batch_raw/20251218-160914/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251218-161134/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251218-161422/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251218-161644/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-18 16:28 批次）：
- raw：`out/artifacts/batch_raw/20251218-162820/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251218-162941/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251218-163105/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251218-163224/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-18 16:45 左右，runtime housekeeping 调试判定梳理后复跑，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-164548/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-164841/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-18 16:50 批次）：
- raw：`out/artifacts/batch_raw/20251218-165044/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251218-165303/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251218-165528/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251218-165748/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-18 17:00 批次）：
- raw：`out/artifacts/batch_raw/20251218-170049/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251218-170202/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251218-170315/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251218-170432/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-18 17:35 左右，runtime Config 持久化去指针，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-173506/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-173742/build_out/smoke_test.log`。

注：本轮 referral 检查对 143.128.0.0 的 `whois.arin.net` 路径报 ERROR（缺少 `whois.afrinic.net` 尾行，日志 `out/artifacts/20251218-173742/build_out/referral_checks/143.128.0.0/whois.arin.net.log`），其余链路 PASS；后续需决定调整脚本基线或补尾行逻辑。

最新一次四轮冒烟（2025-12-18 17:45–18:07，复跑恢复 PASS，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-174543/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-174818/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-18 17:53–18:01 批次）：
- raw：`out/artifacts/batch_raw/20251218-175331/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251218-175604/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251218-175830/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251218-180051/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-18 18:03–18:07 批次）：
- raw：`out/artifacts/batch_raw/20251218-180308/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251218-180432/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251218-180554/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251218-180712/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-18 18:17–18:35，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-181758/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-182014/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-18 18:22–18:29 批次）：
- raw：`out/artifacts/batch_raw/20251218-182205/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251218-182427/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251218-182654/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251218-182916/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-18 18:31–18:35 批次）：
- raw：`out/artifacts/batch_raw/20251218-183125/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251218-183246/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251218-183401/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251218-183540/build_out/smoke_test.log`

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-18 15:31 批次）：
- raw：`out/artifacts/batch_raw/20251218-153126/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251218-153349/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251218-153620/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251218-153839/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-18 15:41 批次）：
- raw：`out/artifacts/batch_raw/20251218-154118/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251218-154231/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251218-154348/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251218-154503/build_out/smoke_test.log`

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-18 14:22 批次）：
- raw：`out/artifacts/batch_raw/20251218-142209/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251218-142427/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251218-142650/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251218-142910/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-18 14:31 批次）：
- raw：`out/artifacts/batch_raw/20251218-143112/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251218-143231/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251218-143355/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251218-143508/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-18 10:29 左右，缓存计数封装后复跑，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-102901/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-103101/build_out/smoke_test.log`。

最新一次四轮冒烟（2025-12-18 11:43 左右，wc_cache 计数补齐后复跑，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-114328/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-114558/build_out/smoke_test.log`。

最新一次四轮冒烟（2025-12-18 12:40 左右，signal 只读视图后复跑，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/batch_raw/20251218-114757/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/batch_raw/20251218-115725/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-18 12:45 批次）：
- raw：`out/artifacts/batch_raw/20251218-124007/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251218-124257/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251218-124526/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251218-124747/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-18 12:50 批次）：
- raw：`out/artifacts/batch_raw/20251218-124957/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251218-125114/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251218-125234/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251218-125346/build_out/smoke_test.log`

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-18 11:47 批次）：
- raw：`out/artifacts/batch_raw/20251218-114757/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251218-115018/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251218-115247/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251218-115512/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-18 11:57 批次）：
- raw：`out/artifacts/batch_raw/20251218-115725/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251218-115854/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251218-120018/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251218-120146/build_out/smoke_test.log`

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-18 10:32 批次）：
- raw：`out/artifacts/batch_raw/20251218-103257/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251218-103519/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251218-103739/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251218-103956/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-18 10:41 批次）：
- raw：`out/artifacts/batch_raw/20251218-104148/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251218-104302/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251218-104414/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251218-104527/build_out/smoke_test.log`

最新一次四轮冒烟（2025-12-18 09:40 左右，默认脚本参数）：
- 默认参数：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-094015/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + `[golden] PASS`，日志 `out/artifacts/20251218-094311/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-18 09:45 批次）：
- raw：`out/artifacts/batch_raw/20251218-094505/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251218-094735/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251218-094953/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251218-095216/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-18 09:55 批次）：
- raw：`out/artifacts/batch_raw/20251218-095455/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251218-095611/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251218-095721/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251218-095842/build_out/smoke_test.log`

最新一次双轮冒烟（2025-12-18 08:57 批次，默认脚本参数）：
- 默认参数：无告警 + Golden PASS，日志 `out/artifacts/20251218-085751/build_out/smoke_test.log`；
- `--debug --retry-metrics --dns-cache-stats`：无告警 + Golden PASS，日志 `out/artifacts/20251218-085949/build_out/smoke_test.log`。

批量策略黄金（raw/health-first/plan-a/plan-b，全 PASS，2025-12-18 09:01 批次）：
- raw：`out/artifacts/batch_raw/20251218-090130/build_out/smoke_test.log`（`golden_report_raw.txt`）
- health-first：`out/artifacts/batch_health/20251218-090356/build_out/smoke_test.log`（`golden_report_health-first.txt`）
- plan-a：`out/artifacts/batch_plan/20251218-090613/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
- plan-b：`out/artifacts/batch_planb/20251218-090835/build_out/smoke_test.log`（`golden_report_plan-b.txt`）

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-18 09:10 批次）：
- raw：`out/artifacts/batch_raw/20251218-091032/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251218-091143/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251218-091300/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251218-091415/build_out/smoke_test.log`

自检黄金（`--selftest-force-suspicious 8.8.8.8`，四策略全 PASS，2025-12-18 清晨）：
- raw：`out/artifacts/batch_raw/20251218-013920/build_out/smoke_test.log`
- health-first：`out/artifacts/batch_health/20251218-014034/build_out/smoke_test.log`
- plan-a：`out/artifacts/batch_plan/20251218-014152/build_out/smoke_test.log`
- plan-b：`out/artifacts/batch_planb/20251218-014301/build_out/smoke_test.log`

###### 2025-12-18 复跑（02:27–02:44）

- 远程编译冒烟（默认）：`out/artifacts/20251218-022709/build_out/smoke_test.log`，无告警，`[golden] PASS`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：`out/artifacts/20251218-022915/build_out/smoke_test.log`，无告警，`[golden] PASS`。
- 批量策略黄金（raw/health-first/plan-a/plan-b）：全 `[golden] PASS`。
  - raw：`out/artifacts/batch_raw/20251218-023144/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251218-023406/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251218-023622/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251218-023851/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：全 `[golden-selftest] PASS`。
  - raw：`out/artifacts/batch_raw/20251218-024049/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251218-024202/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251218-024313/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251218-024433/build_out/smoke_test.log`

###### 2025-12-18 复跑（03:53–04:10）

- 远程编译冒烟（默认）：`out/artifacts/20251218-035348/build_out/smoke_test.log`，无告警，`[golden] PASS`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：`out/artifacts/20251218-035556/build_out/smoke_test.log`，无告警，`[golden] PASS`。
- 批量策略黄金（raw/health-first/plan-a/plan-b）：全 `[golden] PASS`。
  - raw：`out/artifacts/batch_raw/20251218-035754/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251218-040017/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251218-040237/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251218-040457/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：全 `[golden-selftest] PASS`。
  - raw：`out/artifacts/batch_raw/20251218-040650/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251218-040808/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251218-040926/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251218-041037/build_out/smoke_test.log`

###### 2025-12-18 复跑（04:37–04:54）

- 远程编译冒烟（默认）：`out/artifacts/20251218-043743/build_out/smoke_test.log`，无告警，`[golden] PASS`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：`out/artifacts/20251218-043943/build_out/smoke_test.log`，无告警，`[golden] PASS`。
- 批量策略黄金（raw/health-first/plan-a/plan-b）：全 `[golden] PASS`。
  - raw：`out/artifacts/batch_raw/20251218-044119/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251218-044344/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251218-044606/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251218-044820/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：全 `[golden-selftest] PASS`。
  - raw：`out/artifacts/batch_raw/20251218-045027/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251218-045138/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251218-045250/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251218-045407/build_out/smoke_test.log`

###### 2025-12-18 复跑（07:00–07:24）

- 远程编译冒烟（默认）：`out/artifacts/20251218-070023/build_out/smoke_test.log`，无告警，`[golden] PASS`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：`out/artifacts/20251218-070733/build_out/smoke_test.log`，无告警，`[golden] PASS`。
- 批量策略黄金（raw/health-first/plan-a/plan-b）：全 `[golden] PASS`。
  - raw：`out/artifacts/batch_raw/20251218-070940/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251218-071155/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251218-071414/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251218-071627/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：四策略 `[golden-selftest] PASS`。
  - raw：`out/artifacts/batch_raw/20251218-072038/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251218-072149/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251218-072302/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251218-072414/build_out/smoke_test.log`

Plan-b 说明：当缓存命中但被罚分时会立即清空缓存，下一条查询先输出 `plan-b-empty` 再选择健康候选；黄金脚本已覆盖该行为。

###### 2025-12-18 复跑（08:22–08:38）

- 远程编译冒烟（默认）：`out/artifacts/20251218-082248/build_out/smoke_test.log`，无告警，`[golden] PASS`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：`out/artifacts/20251218-082454/build_out/smoke_test.log`，无告警，`[golden] PASS`。
- 批量策略黄金（raw/health-first/plan-a/plan-b）：全 `[golden] PASS`。
  - raw：`out/artifacts/batch_raw/20251218-082631/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251218-082848/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251218-083107/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251218-083326/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：全 `[golden-selftest] PASS`。
  - raw：`out/artifacts/batch_raw/20251218-083524/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251218-083636/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251218-083747/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251218-083856/build_out/smoke_test.log`

###### 2025-12-18 复跑（08:57–09:14）

- 远程编译冒烟（默认）：`out/artifacts/20251218-085751/build_out/smoke_test.log`，无告警，`[golden] PASS`。
- 远程编译冒烟（`--debug --retry-metrics --dns-cache-stats`）：`out/artifacts/20251218-085949/build_out/smoke_test.log`，无告警，`[golden] PASS`。
- 批量策略黄金（raw/health-first/plan-a/plan-b）：全 `[golden] PASS`。
  - raw：`out/artifacts/batch_raw/20251218-090130/build_out/smoke_test.log`（`golden_report_raw.txt`）
  - health-first：`out/artifacts/batch_health/20251218-090356/build_out/smoke_test.log`（`golden_report_health-first.txt`）
  - plan-a：`out/artifacts/batch_plan/20251218-090613/build_out/smoke_test.log`（`golden_report_plan-a.txt`）
  - plan-b：`out/artifacts/batch_planb/20251218-090835/build_out/smoke_test.log`（`golden_report_plan-b.txt`）
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`）：全 `[golden-selftest] PASS`。
  - raw：`out/artifacts/batch_raw/20251218-091032/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251218-091143/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251218-091300/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251218-091415/build_out/smoke_test.log`

### DNS 调试 quickstart（Phase 2/3）

- 单次 DNS 调试（stderr 带候选/回退/缓存统计）：
  ```bash
  whois-x86_64 --debug --retry-metrics --dns-cache-stats 8.8.8.8
  ```
- 带自测的 DNS 调试（附加故障注入并触发 lookup 自检）：
  ```bash
  whois-x86_64 --debug --retry-metrics --dns-cache-stats --selftest-blackhole-arin 8.8.8.8
  ```
- 混合家族偏好（首跳/后续跳分别优先 IPv4 或 IPv6）：
  ```bash
  whois-x86_64 --prefer-ipv4-ipv6 --debug --retry-metrics --dns-cache-stats 8.8.8.8
  whois-x86_64 --prefer-ipv6-ipv4 --debug --retry-metrics --dns-cache-stats --selftest-force-suspicious 8.8.8.8
  ```
  `--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4` 与 `--prefer-*` / `--ipv*-only` 互斥，启用后 lookup/referral/legacy 的每一跳都会单独计算家族顺序，并在所有 DNS 日志中追加 `pref=` 标签以方便确认：
  ```
  [DNS-CAND] hop=0 pref=v4-then-v6-hop0 ...
  [DNS-FALLBACK] hop=1 action=known-ip pref=v4-then-v6-hop1 ...
  ```
  即便未开启混合模式也会显示 `pref=v6-first` / `pref=v4-first`，便于黄金脚本断言。

  - 若需自动验收，可直接运行 `tools/test/golden_check.sh --pref-labels v4-then-v6-hop0,v4-then-v6-hop1`（标签既可写 `pref=...` 也可省略前缀），用来确保混合偏好场景的 `pref=` 标签稳定出现。
- 关键观测点：
  - `[DNS-CAND]`：每个 hop 的候选顺序与来源（host/IP/缓存/规范域名），2025-12-02 起固定携带 `pref=`（如 `pref=v4-then-v6-hop0`、`pref=v6-first`），用于对照 `--prefer-*` / `--ipv*-only`、混合偏好 flag 及 `--dns-max-candidates` 行为；配合上文的 `--pref-labels` 黄金命令可快速确认标签是否存在。
    - ARIN IPv4 字面量命中时会追加 `pref=arin-v4-auto`，表示客户端自动注入 `n <query>` 并对首个 IPv4 候选执行 1.2s（无重试）的短探测，例如：
      ```
      [DNS-CAND] hop=1 server=whois.arin.net rir=arin idx=0 target=104.44.135.12 type=ipv4 origin=resolver pref=arin-v4-auto
      [DNS-FALLBACK] hop=1 cause=connect-fail action=candidate domain=whois.arin.net target=104.44.135.12 status=fail errno=10060 pref=arin-v4-auto
      ```
      失败后会立即恢复原始候选顺序，让 IPv6 或其他 referral 继续推进，避免 IPv4 不可达时卡死；可参考 `out/artifacts/20251204-110057/build_out/smoke_test.log`。
  - `[DNS-FALLBACK]`：强制 IPv4、已知 IPv4、空正文重试、IANA pivot 等路径的动作与结果；在启用 `--dns-no-fallback` 时会以 `action=no-op status=skipped` 形式记录被跳过的回退。
  - `[DNS-CACHE]` / `[DNS-CACHE-SUM]`：前者为调试阶段的即时缓存计数，后者为 `--dns-cache-stats` 触发的进程级汇总行（形如 `[DNS-CACHE-SUM] hits=10 neg_hits=0 misses=3`），仅输出一次，便于快速 eyeball 缓存命中率。
  - `[DEBUG] Cache counters: ...`：开启 `--debug` 时 `wc_cache_log_statistics()` 会附带一行 cache 计数摘要（dns_hits/dns_misses/dns_shim_hits 与 neg_hits/neg_sets/neg_shim_hits），不新增标签，仅作现场排障参考，可与 `[DNS-CACHE-SUM]` 互补。
  - 若需在不启用 `--debug` 的情况下临时观察该行，可在自测/诊断入口调用 `wc_runtime_set_cache_counter_sampling(1)`，housekeeping tick 会输出同款摘要；默认保持 0 以避免 stderr 噪声。
  - `[DNS-CACHE-LGCY]`：**已移除**，legacy shim 退场后不再输出该标签；`[DNS-CACHE-SUM]` 继续由 `wc_dns` 提供。如需诊断旧路径，请使用专门分支或本地补丁，而非运行时开关。
  - `[DNS-HEALTH]`（Phase 3）：per-host/per-family 健康记忆快照，记录连续失败次数与 penalty 剩余时间，用于解释候选软排序行为（健康优先、不丢弃候选）。
  - `[DNS-BACKOFF]`：统一罚站平台输出的“跳过/排队末尾”提示，`action=skip|force-last` 表示当前 host 因最近失败被暂缓，`reason=` 对应最新的 errno/状态，`window_ms=` 为剩余冷却时间，供批量/单次排障快速确认 penalty 是否按预期触发。
- 调试版自测观测：当以 `-DWHOIS_LOOKUP_SELFTEST` 编译时，只要运行 `--selftest` **或** 在实际命令行附加任意 `--selftest-*` 故障旗标（fail-first / inject-empty / dns-negative / blackhole / force-iana-pivot / grep / seclog demo），都会在真实查询前自动打印一次 `[LOOKUP_SELFTEST]`，无需加独立的 `whois --selftest` 预跑。
  - 在部分 libc/QEMU 组合下，`[LOOKUP_SELFTEST]` 与 `[DEBUG]` 可能在行级发生 interleave/覆盖，此为预期限制；适合 grep/肉眼检查，不建议依赖为机器可解析格式。

###### 2025-12-07 补充记录

- 远端 referral 守卫：`tools/remote/remote_build_and_test.sh` 现将 `whois.iana.org/arin/afrinic` 各自输出到独立日志，并把抓取/目录 listing 写入 `referral_debug.log`（静默 stderr），避免单一 `host.log` 覆盖与任务误判。产物路径仍在 `out/artifacts/<ts>/build_out/referral_checks/` 下。
- 自测黄金期望：`tools/test/selftest_golden_suite.ps1` 与 `remote_batch_strategy_suite.ps1` 会将 `SelftestActions` 形如 `force-suspicious,8.8.8.8` 自动拼成 `--expect action=force-suspicious,query=8.8.8.8`，无需额外传 `SelftestExpectations` 即可覆盖动作+查询。

###### 2025-12-14 冒烟复跑快照

- 默认/调试两轮远程冒烟均 `[golden] PASS`：`out/artifacts/20251214-201532/build_out/smoke_test.log`（默认）与 `out/artifacts/20251214-201927/build_out/smoke_test.log`（`--debug --retry-metrics --dns-cache-stats`）。
- 批量策略 raw/health-first/plan-a/plan-b 黄金 PASS：`out/artifacts/batch_raw/20251214-202150/build_out/smoke_test.log`、`.../golden_report_raw.txt`；`out/artifacts/batch_health/20251214-202440/.../{smoke_test.log,golden_report_health-first.txt}`；`out/artifacts/batch_plan/20251214-202704/.../{smoke_test.log,golden_report_plan-a.txt}`；`out/artifacts/batch_planb/20251214-202940/.../{smoke_test.log,golden_report_plan-b.txt}`。
- 自检黄金（`--selftest-force-suspicious 8.8.8.8`）四策略全 PASS：`out/artifacts/batch_raw/20251214-203201/.../smoke_test.log`、`batch_health/20251214-203328/.../smoke_test.log`、`batch_plan/20251214-203454/.../smoke_test.log`、`batch_planb/20251214-203615/.../smoke_test.log`。

##### WHOIS_LOOKUP_SELFTEST 远程剧本（2025-12-04）

> 目标：在 AfriNIC IPv6 parent 守卫回归修复后，形成一套“先跑常规黄金 → 再跑自测黄金”的固定剧本，并记录“不要直接附 `--selftest`”的避坑经验。

1. **常规远程黄金（不开自测）**
   ```powershell
   & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois; \\
     tools/remote/remote_build_and_test.sh \\
       -H 10.0.0.199 -u larson -k '/c/Users/<你>/.ssh/id_rsa' \\
       -r 1 -q '8.8.8.8 1.1.1.1 143.128.0.0' \\
       -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 \\
       -a '--debug --retry-metrics --dns-cache-stats' \\
       -G 1 -E '-O3 -s -DWHOIS_LOOKUP_SELFTEST'"
   ```
   - 目的：同一构建开启 `-DWHOIS_LOOKUP_SELFTEST`，但不附任何 `--selftest-*`，保持头/尾契约完整，让 `golden_check.sh` 继续 `[golden] PASS`。
   - 参考日志：`out/artifacts/20251204-155440/build_out/smoke_test.log`（默认）与 `out/artifacts/20251204-155655/build_out/smoke_test.log`（带 `--debug --retry-metrics --dns-cache-stats`）。

2. **自测黄金（带钩子，但跳过常规 golden）**
   ```powershell
   tools/test/selftest_golden_suite.ps1 \
     -KeyPath "c:\\Users\\<你>\\.ssh\\id_rsa" \
     -SmokeExtraArgs "--debug --retry-metrics --dns-cache-stats --selftest-force-suspicious 8.8.8.8" \
     -SelftestActions "force-suspicious,8.8.8.8" \
     -SelftestExpectations "action=force-suspicious,query=8.8.8.8" \
     -NoGolden
   ```
  - `-NoGolden` 会把四轮远程 batch（raw / health-first / plan-a / plan-b）变成“只收集日志”，避免因头/尾缺失刷屏 `[golden][ERROR]`；真正的断言由 `golden_check_selftest.sh` 在脚本末尾完成。
  - 参考日志：
    - raw：`out/artifacts/batch_raw/20251204-171214/build_out/smoke_test.log`
    - health-first：`out/artifacts/batch_health/20251204-171334/build_out/smoke_test.log`
    - plan-a：`out/artifacts/batch_plan/20251204-171519/build_out/smoke_test.log`
    - plan-b：已输出 `[DNS-BATCH] plan-b-*`（plan-b-force-start/plan-b-fallback/force-override/start-skip/force-last），黄金预设现已对这些标签做断言。
    raw/health-first/plan-a 三份日志均输出 `[golden-selftest] PASS` + `action=force-suspicious,query=8.8.8.8`。
  - VS Code 任务入口：按 `Ctrl+Shift+P` → `Tasks: Run Task` → `Selftest Golden Suite`，会自动透传 `rbHost/rbUser/rbKey/rbQueries/rbCflagsExtra` 并强制附加 `-NoGolden`。首次运行会提示填写远程 SSH Host/User/Key，与 `Remote: Build and Sync whois statics` 共享同一组输入；`rbKey` 支持 MSYS 风格（`/c/Users/...`）或 Windows 风格（`C:\\Users\\...`）。如需额外钩子，可在任务弹窗里直接修改 `selftestActions/selftestSmokeExtra/...`。

3. **避坑提示**
   - **不要**在常规黄金命令中直接附 `--selftest`。该开关会让 CLI 在内部自测跑完后直接退出，导致 `=== Query … ===`/`=== Authoritative RIR … ===` 不再出现，`golden_check.sh` 必然报 `header not found`。
   - 需要调试 `[LOOKUP_SELFTEST]` 时，请改用 `--selftest-force-suspicious` / `--selftest-force-private` 等钩子，让自测只在 stderr 打标签，stdout 仍保留头/尾。
   - 若必须观察 `whois --selftest` 的 stdout，可单独运行 `whois-x86_64 --selftest` 或给脚本加 `-SkipRemote -SelftestExpectations ...`，但这一步不应和黄金校验混在一起。

##### 重定向链路验收（143.128.0.0）

碰到 AfriNIC 早期转移网段或怀疑 “Whole IPv4 space / 0.0.0.0/0” 守卫误触时，可按顺序运行：

```bash
whois-x86_64 -h iana 143.128.0.0 --debug --retry-metrics --dns-cache-stats
whois-x86_64 -h arin 143.128.0.0 --debug --retry-metrics --dns-cache-stats
whois-x86_64 -h afrinic 143.128.0.0 --debug --retry-metrics --dns-cache-stats
```

- 预期输出：第一条呈现 `143.128.0.0 → IANA → ARIN → AFRINIC`，第二条 `ARIN → AFRINIC`，第三条直接 `AFRINIC`，三条尾行都固定为 `=== Authoritative RIR: whois.afrinic.net @ <ip|unknown> ===`。
- 该组合可验证守卫只匹配 `inetnum:` / `NetRange:` 行，`parent: 0.0.0.0 - 255.255.255.255` 不再触发强制 IANA；若尾行重新落到 IANA/ARIN，则说明守卫仍被错误触发。
- 参考日志：`out/iana-143.128.0.0`、`out/arin-143.128.0.0`、`out/afrinic-143.128.0.0` 以及 2025-12-04 四轮远程冒烟（`out/artifacts/20251204-140138/...`、`-140402/...`、`batch_{raw,plan,health}/20251204-14{0840,1123,1001}/...`、`batch_{raw,plan,health}/20251204-1414**/...`），均验证该守卫补丁已经生效。
- 自动化验收：执行 `tools/test/referral_143128_check.sh`（可选 `--iana-log/--arin-log/--afrinic-log` 自定义路径）即可一次性校验三份日志仍然以 AfriNIC 为权威且保留预期的 `Additional query` 链路。
- 远端冒烟默认已包含上述验收：`tools/remote/remote_build_and_test.sh -r 1` 会在远端生成 `build_out/referral_143128/{iana,arin,afrinic}.log` 并在抓回产物后自动调用 `referral_143128_check.sh`。如果需要跳过（例如目标网络封锁 AfriNIC），请传 `-L 0` 或设置 `REFERRAL_CHECK=0`。

### 网络重试上下文（3.2.10+）

- 运行期只会创建一份 `wc_net_context`，并在单条查询、批量 stdin 循环以及自动触发的 lookup 自测之间复用。因此 `[RETRY-METRICS]`、`[RETRY-METRICS-INSTANT]`、`[RETRY-ERRORS]` 计数会在自测预热与真实查询之间保持连续，不会在每条查询前自动清零。
- 远端冒烟脚本（`tools/remote/remote_build_and_test.sh`）每次调用都会启动全新的进程与二进制，所以不同架构/不同轮之间的计数天然独立；本地排障若需要“干净”指标，请重新启动 `whois-<arch>`，而不是期望在同一进程内复位。
- 批量 stdin 与自动自测共享同一节流预算。如果启用了 `--selftest-force-suspicious` / `--selftest-force-private` 等开关，stdin 真正开始前就会看到 `total_attempts>=1` 的 `[RETRY-METRICS-INSTANT]`，这是预期行为，不应被视作回归。
- 黄金/脚本检查：`docs/USAGE_CN.md` 的“网络重试上下文（3.2.10+）”章节已是官方说明。编写 `tools/test/golden_check.sh` 断言时，请关注指标是否存在，而不要假设自测后 `attempts` 会重置为 1；如需隔离测试场景，请改为一轮一进程地执行冒烟。

#### 批量调度观测（WHOIS_BATCH_DEBUG_PENALIZE + golden_check 扩展）

> 版本提示：`RELEASE_NOTES.md` 的 *Unreleased* 段已记录“raw 默认 + health-first / plan-a 需显式启用”的批量策略说明，并指向本小节与 `docs/USAGE_CN.md` 的“批量起始策略”章节，便于在发布说明中直接定位到这些命令与黄金预设。

> 适用场景：需要在远程冒烟中稳定复现 `[DNS-BATCH] action=debug-penalize` 等日志，并立即用黄金脚本校验这些标签是否存在。

> 最新证据（2025-12-12）：plan-b 已正式启用（缓存优先 + 罚分感知回退），远程冒烟 `out/artifacts/20251212-013029`（默认）与 `out/artifacts/20251212-013310`（debug/metrics）均 PASS；批量黄金 `out/artifacts/batch_{raw,health,plan,planb}/20251212-013524..014324/...` 与自测黄金 `out/artifacts/batch_{raw,health,plan,planb}/20251212-014818..015225/...` 全部通过并输出 `plan-b-*` 标签。若缓存的起始 host 被罚分，plan-b 会立刻清空缓存，下一条查询会先看到 `plan-b-empty`，随后直接挑选健康候选。

1. 运行远端冒烟（示例命令）：
   ```bash
   WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net' \
   ./tools/remote/remote_build_and_test.sh \
     -H 10.0.0.199 -u larson -k '/c/Users/you/.ssh/id_rsa' \
     -r 1 -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' \
     -P 1 -a '--batch-strategy health-first --debug --retry-metrics --dns-cache-stats' \
     -F testdata/queries.txt -G 1 -E '-O3 -s'
   ```
   - `WHOIS_BATCH_DEBUG_PENALIZE`：在进入批量模式前对指定 RIR host 施加“调试罚站”，强制产生 `[DNS-BATCH] action=debug-penalize host=<...>`。
   - `-F testdata/queries.txt`：通过 stdin 固定批量输入，脚本会自动补 `-B` 并提示。
   - `-a '--batch-strategy health-first --debug --retry-metrics --dns-cache-stats'`：显式启用 health-first（默认 raw 模式已不再输出 `start-skip/force-last`），并打开全部调试标签以观察 `[DNS-BATCH]`、`[DNS-CAND]`、`[RETRY-*]`。
2. 远程脚本完成后，用黄金脚本检查批量标签：
   ```bash
   tools/test/golden_check.sh \
     -l out/artifacts/20251126-084545/build_out/smoke_test.log \
     --batch-actions debug-penalize
   ```
  - `--batch-actions` 支持逗号分隔（例如 `debug-penalize,start-skip`），脚本会逐项查找 `[DNS-BATCH] action=<name>`。
  - 新增 `--backoff-actions`，可用于断言 `[DNS-BACKOFF] action=skip|force-last` 等退避日志是否出现；`health-first` 预设默认会注入 `--backoff-actions skip,force-last`，其余策略可按需在命令末尾显式追加。
   - 仍会同步检查默认的 header/referral/tail 契约。若缺失会打印 `[golden][ERROR]` 并返回非零。
3. 以上命令不需要修改远端脚本即可复用；如需扩展到更多动作，只需更新 `WHOIS_BATCH_DEBUG_PENALIZE` 与 `--batch-actions` 列表，并把日志路径换成当轮时间戳即可。

#### Plan-A 批量加速器剧本（远程冒烟 + 黄金校验）

> 适用场景：验证 `--batch-strategy plan-a` 的缓存/快速复用路径与 `[DNS-BATCH] action=plan-a-*` 日志是否稳定输出。

1. 运行远程冒烟（保持 `plan-a` 策略）：
   ```powershell
   $env:WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net'; \
   & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && \\
     tools/remote/remote_build_and_test.sh \\
       -H 10.0.0.199 -u larson -k 'c:/Users/you/.ssh/id_rsa' \\
       -r 1 -P 1 \\
       -F testdata/queries.txt \\
       -a '--batch-strategy plan-a --debug --retry-metrics --dns-cache-stats' \\
       -G 1 -E '-O3 -s'"
   ```
   - `WHOIS_BATCH_DEBUG_PENALIZE` 只罚站 arin/ripe，让 plan-a 能够在“缓存命中”与“缓存被 penalty 清空”两种路径间切换。
   - `-F testdata/queries.txt` 固定 stdin 批量输入，脚本会自动追加 `-B` 并提示。
   - `--batch-strategy plan-a` 触发 plan-a 逻辑，其余调试开关保持一致以输出 `[DNS-BATCH]`/`[RETRY-*]`/`[DNS-CACHE-*]`。
2. 远程脚本完成后，黄金脚本只校验 plan-a 相关动作：
   ```bash
   tools/test/golden_check.sh \
     -l out/artifacts/20251126-161014/build_out/smoke_test.log \
     --batch-actions plan-a-cache,plan-a-faststart,plan-a-skip,debug-penalize \
     --pref-labels v4-then-v6-hop0,v4-then-v6-hop1
   ```
   - `plan-a-cache`：缓存命中/清空时的日志；
   - `plan-a-faststart`：缓存健康，直接复用上一条 authoritative host；
   - `plan-a-skip`：缓存 host 被 penalty 时 fallback 至健康候选；
   - `debug-penalize`：确保调试罚站环境变量确实生效。
  - `--pref-labels`：用于断言混合 IPv4/IPv6 偏好场景下的 `pref=` 标签（可写 `v4-then-v6-hop0` 或 `pref=v4-then-v6-hop0`），当命令行启用了 `--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4` 时建议同时开启该检查。
   - 仍会默认检查 header/referral/tail 契约。若缺失上述任意日志，`golden_check.sh` 会返回非零，CI 立即报警。
3. 如需同时在同一 CI 轮验证传统 health-first 的 `start-skip/force-last` 路径，可再运行“批量调度观测”小节中的第二条命令；两份日志互补覆盖即可。

##### 四组黄金校验的预设脚本

批量策略四组黄金检查常常只是在不同日志上重复填充 `--batch-actions`，现在可以用 `tools/test/golden_check_batch_presets.sh` 简化操作：

```bash
# raw：仅做 header/referral/tail 契约检查
./tools/test/golden_check_batch_presets.sh raw --pref-labels v4-then-v6-hop0,v4-then-v6-hop1 -l ./out/artifacts/<ts_raw>/build_out/smoke_test.log

# health-first：自动校验 debug-penalize/start-skip/force-last
./tools/test/golden_check_batch_presets.sh health-first --pref-labels v4-then-v6-hop0,v4-then-v6-hop1 -l ./out/artifacts/<ts_hf>/build_out/smoke_test.log

# plan-a：自动校验 plan-a-cache/faststart/skip + debug-penalize
./tools/test/golden_check_batch_presets.sh plan-a --pref-labels v4-then-v6-hop0,v4-then-v6-hop1 -l ./out/artifacts/<ts_pa>/build_out/smoke_test.log

# plan-b：自动校验 plan-b-* + debug-penalize（若预设已启用）
./tools/test/golden_check_batch_presets.sh plan-b --pref-labels v4-then-v6-hop0,v4-then-v6-hop1 -l ./out/artifacts/<ts_pb>/build_out/smoke_test.log
```

除 `-l` 以外的参数会原样透传给 `golden_check.sh`，因此仍可叠加 `--query`、`--backoff-actions`、`--pref-labels`、`--strict` 等选项。脚本仅负责注入对应预设的 `--batch-actions` 列表（以及 `health-first` 预设的 `--backoff-actions skip,force-last`），保持其余校验逻辑与手工命令一致；若无需校验混合偏好，可省略 `--pref-labels` 或显式传 `--pref-labels NONE`。

> **提示**：2025-12-02 之前的冒烟日志尚未带 `pref=` 字段，此时 `--pref-labels` 会报告“missing preference label”。如需回看旧版本，可暂时省略该参数；检查最新版日志时再重新启用，以确保 hop-aware 标签被黄金覆盖。

##### VS Code 任务：Golden Check Batch Suite

在 VS Code 中通过 Terminal → Run Task 选择 **Golden Check: Batch Suite**，即可一键串行跑 raw / health-first / plan-a / plan-b 四组校验。任务现新增“Preference labels” 输入框（逗号分隔，输入 `NONE` 或留空视为跳过），与原有 Extra Args（默认 `--strict`）共同传递给 `tools/test/golden_check_batch_suite.ps1`；四个日志路径依旧可单独留空跳过，对应的 `--pref-labels` 亦会自动透传到每个预设脚本。

##### PowerShell Alias：黄金四件套

若偏好终端操作，可先在当前 PowerShell 会话注册别名：

```powershell
./tools/dev/register_golden_alias.ps1 -AliasName golden-suite
```

随后即可使用：

```powershell
golden-suite `
  -RawLog ./out/artifacts/20251128-000717/build_out/smoke_test.log `
  -HealthFirstLog ./out/artifacts/20251128-002850/build_out/smoke_test.log `
  -PlanALog ./out/artifacts/20251128-004128/build_out/smoke_test.log `
  -PlanBLog ./out/artifacts/20251210-120101/build_out/smoke_test.log `
  -ExtraArgs --strict
```

如需自动生效，可把 `register_golden_alias.ps1` 加入 PowerShell Profile，在 VS Code 打开终端时即完成别名注册。

#### 自测黄金套件（raw / health-first / plan-a / plan-b）

`tools/test/selftest_golden_suite.ps1` 用于验证 `--selftest-force-*` 钩子会在查询进入常规流水线前就短路输出。脚本先调用 `remote_batch_strategy_suite.ps1`（若带 `-SkipRemote` 则跳过）生成最新 batch 日志，再对 raw / health-first / plan-a / plan-b 四份 `smoke_test.log` 逐个执行 `tools/test/golden_check_selftest.sh`。

1. 完整示例（远端抓取 + `[SELFTEST] action=*` 断言）：
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass `
     -File tools/test/selftest_golden_suite.ps1 `
     -SelftestActions "force-suspicious,8.8.8.8" `
     -SmokeExtraArgs "--selftest-force-suspicious 8.8.8.8" `
     -SelftestExpectations "action=force-suspicious,query=8.8.8.8"
   ```
   - `-SelftestActions` 让 `golden_check.sh` 与实际注入的 fault 一致，缺失时会直接报 `[golden][ERROR] missing [SELFTEST] action=...`。
   - `-SmokeExtraArgs` 把 `--selftest-force-*` 等开关附加到每轮远端 `-a '...'` 参数，确保 `[SELFTEST]` 行真实存在于 `smoke_test.log`。
   - `-SelftestExpectations` / `-ErrorPatterns` / `-TagExpectations` 为分号分隔列表，分别转换成 `--expect`、`--require-error`、`--require-tag 组件 正则`；留空或输入 `NONE` 即视为跳过。
  - `-SkipRemote` 仅做黄金复核，直接抓取 `out/artifacts/batch_{raw,health,plan,planb}` 下最新时间戳的日志。
  - `-NoGolden` 会在远端四策略执行时跳过 `golden_check.sh`（即 `remote_batch_strategy_suite.ps1` 的 `-NoGolden`），当自测钩子会让 header/referral/tail 合约必然失败时，可用来消除 `[golden][ERROR]` 噪声，只保留 `[golden-selftest]` 结果。
   推荐预设（同时断言 force-suspicious 与 force-private）：
   ```bash
   tools/test/golden_check_selftest.sh \
     -l out/artifacts/batch_raw/<ts>/build_out/smoke_test.log \
     --expect action=force-suspicious,query=8.8.8.8 \
     --expect action=force-private,query=10.0.0.8 \
     --require-error "Suspicious query detected" \
     --require-error "Private query denied" \
     --require-tag SELFTEST "action=force-(suspicious|private)"
   ```
   若使用 `selftest_golden_suite.ps1`，可将上述参数分别填入 `-SelftestExpectations` / `-ErrorPatterns` / `-TagExpectations`，确保四策略都断言两个强制钩子。
2. 脚本输出每个策略的 `[golden-selftest] PASS/FAIL`，如有任一失败会返回 rc=3，方便 VS Code 任务或 CI 捕捉。
3. 最新佐证（2025-12-12，plan-b 命中窗口标签已启用；所有远端命令均追加 `--selftest-force-suspicious 8.8.8.8`）：
  - raw：`out/artifacts/batch_raw/20251212-181248/build_out/smoke_test.log`
  - health-first：`out/artifacts/batch_health/20251212-181400/build_out/smoke_test.log`
  - plan-a：`out/artifacts/batch_plan/20251212-181525/build_out/smoke_test.log`
  - plan-b：`out/artifacts/batch_planb/20251212-181640/build_out/smoke_test.log`
  plan-b 轮除常规 `plan-b-*` 外，黄金已断言新增 `[DNS-BATCH] action=plan-b-hit|plan-b-stale|plan-b-empty`，其余策略不受影响。

##### VS Code 任务：Selftest Golden Suite

Terminal → Run Task → **Selftest Golden Suite** 可一键执行上述命令。任务会依次询问：

- `SelftestActions`（传给 batch 黄金预设，默认 `force-suspicious,8.8.8.8`）。
- `SmokeExtraArgs`（追加到每轮远程 smoke，默认 `--selftest-force-suspicious 8.8.8.8`）。
- 可选的期望 / 错误 / 标签列表（以分号分隔，支持 `NONE`）。

任务始终会跑远端流程；若只需复查日志，请手工调用脚本并加 `-SkipRemote`。

##### 远端一键四策略冒烟 + 黄金

脚本 `tools/test/remote_batch_strategy_suite.ps1` 会串行执行 raw / health-first / plan-a / plan-b 四组 `remote_build_and_test.sh`，并在本地对各自的 `smoke_test.log` 运行对应的黄金预设（默认夹带 `--strict`）。示例：

```powershell
./tools/test/remote_batch_strategy_suite.ps1 `
  -Host 10.0.0.199 -User larson -KeyPath "/c/Users/你/.ssh/id_rsa" `
  -Queries "8.8.8.8 1.1.1.1" `
  -SyncDirs "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois" `
  -BatchInput testdata/queries.txt -CflagsExtra "-O3 -s"
```

若需复用 `--selftest-actions` 黄金检查，可把 `-SelftestActions 'force-suspicious,*;force-private,10.0.0.8'`（用分号分隔多条 `动作,目标`）传给脚本，它会在四轮黄金校验时自动附加 `--selftest-actions`。

- Raw 轮：仅使用 `--debug --retry-metrics --dns-cache-stats`，保持默认 raw 批量模式。
- Health-first 轮：追加 `--batch-strategy health-first`、通过 `-F testdata/queries.txt` 固定 stdin 批量输入，并注入 `WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.iana.org,whois.ripe.net'`。
- Plan-A 轮：追加 `--batch-strategy plan-a`，沿用批量输入，罚站列表缩减为 `whois.arin.net,whois.ripe.net`。
- Plan-B 轮：追加 `--batch-strategy plan-b`，沿用批量输入，罚站列表与 plan-a 保持一致，用于覆盖 plan-b 缓存/回退分支。
- 产物归档：分别落在 `out/artifacts/batch_raw|batch_health|batch_plan|batch_planb/<timestamp>/build_out/`，脚本会自动抓取最新目录里的 `smoke_test.log` 做黄金校验。
- 可选开关：`-SkipRaw/-SkipHealthFirst/-SkipPlanA/-SkipPlanB`、`-RemoteGolden`（同时启用远端 `-G 1`）、`-NoGolden`（仅抓日志不跑本地黄金）、`-DryRun`（只打印命令），`-SelftestActions 'force-suspicious,*;force-private,10.0.0.8'`（批量透传到黄金脚本），以及 `-RemoteExtraArgs "-M nonzero"` / `-GoldenExtraArgs ''` 等。若需在四轮远程冒烟时统一追加额外客户端参数（例如 `--selftest-force-suspicious '*' --selftest-force-private 10.0.0.8`），可使用 `-SmokeExtraArgs "..."`，无需手动修改基础 `-a '--debug --retry-metrics ...'` 字符串。

该脚本等价于 RFC 章节中记录的 2025-11-28 三轮冒烟 + 黄金命令，并新增 plan-b 封装成 PowerShell 一键执行，省去多次复制命令。

#### 本地批量快手剧本速记（3.2.10+）

- “raw → health-first → plan-a → plan-b” 四组本地命令（含 stdin 数据与 golden 校验示例）现集中在 `docs/USAGE_CN.md` 的“批量起始策略”与“批量策略快手剧本”章节。优先参考该处内容，确保本地手动复现实验与远程剧本保持一致。
- `tools/test/golden_check.sh` 新增 `--selftest-actions`，可在执行批量剧本时与 `--batch-actions` 并用，一次性断言 `[SELFTEST] action=force-suspicious|force-private|...` 与 `[DNS-BATCH] action=...`。若在远程脚本中需要此校验，可直接把 `--selftest-actions` 追加到 golden 命令末尾，或在 `remote_batch_strategy_suite.ps1` 中使用 `-SelftestActions 'force-suspicious,*;...'`（各类预设/VS Code 任务会原样透传）。
- `tools/test/golden_check_batch_presets.sh`、`remote_batch_strategy_suite.ps1` 等封装脚本内部尚未硬编码剧本细节，因此保持 USAGE 文档为事实来源；若剧本更新，请同步在此小节标注时间点及参考章节，避免运维手册与使用手册产生分歧。若批量剧本需要同时断言混合 IPv4/IPv6 标签，可在远程套件中加入 `-PrefLabels "v4-then-v6-hop0,v4-then-v6-hop1"`（默认 `NONE`），脚本会把该值直接透传为 `--pref-labels ...`，与 `-SelftestActions`、`-BackoffActions` 类似。

### 自测故障档案与 `[SELFTEST] action=force-*` 日志（3.2.10+）

- `wc_selftest_fault_profile_t` 现负责汇总所有运行期注入开关（dns-negative、黑洞、force-iana、fail-first 等），DNS / lookup / net 仅需读取该结构与版本号即可保持行为一致，不再在多个模块中维护 `extern` 变量。
- `--selftest-force-suspicious <query|*>`、`--selftest-force-private <query|*>` 通过同一控制器注入，可指定具体查询或 `*`（表示整场运行）。命中时 stderr 会在既有安全日志/私网输出前打印 `[SELFTEST] action=force-suspicious|force-private query=<值>`，便于脚本断言钩子是否生效。
- 本地批量示例（推荐直接拷贝到 RFC/Release 中作为佐证）：

  ```bash
  printf '1.1.1.1\n10.0.0.8\n' | \
    ./out/build_out/whois-x86_64 -B \
      --selftest-force-suspicious '*' --selftest-force-private 10.0.0.8
  # stderr 片段：
  # [SELFTEST] action=force-suspicious query=1.1.1.1
  # [SELFTEST] action=force-private query=10.0.0.8
  ```

  （远程冒烟时请用 `-F testdata/queries.txt` 固定 stdin，并把上述两个开关附加到 `-a '...'`。）
- 黄金覆盖现状：`tools/test/golden_check.sh` 暂未校验 `[SELFTEST] action=force-*`；在补齐前，请在冒烟后追加 `grep '[SELFTEST] action=force-' out/artifacts/<ts>/build_out/smoke_test.log` 并将结果写入 `docs/RFC-whois-client-split.md` 或 release notes，方便后续追溯。

## Git 提交与推送（SSH）

```powershell
# 确认远程地址为 SSH（示例：git@github.com:larsonzh/whois.git）
git remote -v

git add -A
git commit -m "your change"

# 同步与推送（推荐先 rebase）
git pull --rebase origin master
git push origin master

# 打标签（发布现需手动触发工作流）
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
# 首次添加（按你的仓库改）
git remote add gitee git@gitee.com:larsonzh/whois.git
# 后续推送
git push gitee master
git push gitee --tags

### Windows 下指定 git 使用的 SSH 程序（避免 msys 路径问题）

- 背景：Git for Windows 自带的 msys-ssh 在含非 ASCII 用户目录时可能无法写入 `/c/Users/.../.ssh/known_hosts`，导致推送时报 `Permission denied (publickey)` 或反复询问 fingerprint。
- 建议：让 git 直接使用 Windows 自带 OpenSSH。

一次性全局设置（推荐）：

```powershell
git config --global core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"
```

仅当前仓库设置（脚本/任务内使用）：

```powershell
git config core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"
```

验证与推送：

```powershell
ssh -T git@github.com    # 首次输入 yes，看到 Hi <username>! 即正常
git push
```

恢复 msys-ssh：

```powershell
git config --unset core.sshCommand
git config --global --unset core.sshCommand
```

注意：如果需要 ssh-agent，Windows 自带的 OpenSSH 需在管理员 PowerShell 中启动/设为自动：

```powershell
Get-Service ssh-agent | Set-Service -StartupType Automatic
Start-Service ssh-agent
ssh-add "$env:USERPROFILE\.ssh\id_ed25519"
```
```

## 三跳模拟与重试指标（3.2.8）

目的：在不破坏“头/尾契约”的前提下，稳定复现 `apnic → iana → arin` 三跳链路，并通过连接级别的重试指标观测成功/失败与错误分类。

关键标志（组合使用）：
- `--selftest-force-iana-pivot`：仅首次强制从区域 RIR 透传至 IANA，后续按真实 referral 继续（解锁三跳链路）。
- `--selftest-blackhole-arin` / `--selftest-blackhole-iana`：模拟最终跳/中间跳“连接超时”。
- `--retry-metrics`：开启每次连接尝试与聚合统计输出。
- `-t 3 -r 0`：连接超时 3s，禁用通用重试（仅观察连接内部的多候选/多次尝试）。
- `--ipv4-only`：在特定网络环境下提升确定性（可选）。

示例 1（最终跳失败：arin 被黑洞）：
```powershell
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois; \
tools/remote/remote_build_and_test.sh -H <host> -u <user> -k '<key>' -r 1 -q '8.8.8.8' \
  -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 \
  -a '--host apnic --selftest-force-iana-pivot --selftest-blackhole-arin --retry-metrics -t 3 -r 0 --ipv4-only' -G 0 -E ''"
```
输出特征（节选）：
```
[RETRY-METRICS-INSTANT] attempt=1 success=1 ...
[RETRY-METRICS-INSTANT] attempt=2 success=1 ...
Error: Query failed for 8.8.8.8 (connect timeout, errno=110|145)
[RETRY-METRICS] attempts=7 successes=2 failures=5 ... p95_ms≈3000
[RETRY-ERRORS] timeouts=5 refused=0 net_unreach=0 host_unreach=0 addr_na=0 interrupted=0 other=0
=== Authoritative RIR: whois.arin.net @ unknown ===
```

示例 2（中间跳失败：iana 被黑洞）：
```powershell
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois; \
tools/remote/remote_build_and_test.sh -H <host> -u <user> -k '<key>' -r 1 -q '8.8.8.8' \
  -s '/d/LZProjects/lzispro/release/lzispro/whois' -P 1 \
  -a '--host apnic --selftest-force-iana-pivot --selftest-blackhole-iana --retry-metrics -t 3 -r 0 --ipv4-only' -G 0 -E ''"
```
输出特征（节选）：
```
[RETRY-METRICS-INSTANT] attempt=1 success=1 ...
Error: Query failed for 8.8.8.8 (connect timeout, errno=110|145)
[RETRY-METRICS] attempts≈5–8 successes≥1 failures≥1 p95_ms≈3000
[RETRY-ERRORS] timeouts>0 其余通常为 0
=== Authoritative RIR: whois.iana.org @ unknown ===
```

提示：
- 冒烟的超时策略对含 `--retry-metrics` 的运行更宽松：默认 `SMOKE_TIMEOUT_ON_METRICS_SECS=45`，先发送 SIGINT，5s 后必要时再 SIGKILL，避免丢失尾部聚合指标；常规运行默认 8s（`SMOKE_TIMEOUT_DEFAULT_SECS`）。
- 多同步目录：`-s` 支持以分号分隔的多个本地目标；脚本会归一化并逐一同步。
- 指标含义：
  - `[RETRY-METRICS-INSTANT]` 为“单次连接尝试”的即时报文。
  - `[RETRY-METRICS]` 为汇总统计（attempts/successes/failures/min/max/avg/p95/sleep_ms）。
  - `[RETRY-ERRORS]` 为“连接阶段 errno 分类统计”（仅统计 connect() 级别错误）：若连接成功但后续读取阶段超时，则可能出现“失败计入 [RETRY-METRICS]、而 [RETRY-ERRORS] 不增”的现象。
 - 架构差异：ETIMEDOUT 在常见架构数值为 110；MIPS/MIPS64 架构呈现为 145（同一符号常量），逻辑基于符号不受数值差异影响；如需排查请使用 `strerror(errno)` 输出的文字描述。

errno 快查（只需了解，不必强记）：
| 符号 | 常见数值 | MIPS/MIPS64 | 说明 |
|------|----------|-------------|------|
| ETIMEDOUT | 110 | 145 | 连接超时（非读取超时） |
| ECONNREFUSED | 111 | 111 | 连接被拒绝（端口关闭/防火墙） |
| EHOSTUNREACH | 113 | 113 | 主机不可达（路由或ACL） |

> 仅在本次冒烟中观察到 ETIMEDOUT 的数值差异；无需单独文档，随版本说明即可；后续如扩展将追加到 RELEASE_NOTES。

说明：Git 的 SSH 与远端构建机的 SSH（用于交叉编译）是两回事，互不影响。

---

## CI 简述（GitHub Actions）

工作流文件：`.github/workflows/build.yml`、`.github/workflows/publish-gitee.yml`

触发：
- push 到 main/master（常规构建与产物归档）
- PR（常规构建与产物归档）
- push 打标签 `vX.Y.Z`（触发 build.yml 的 `release` 任务，创建/更新 Release 并上传资产）
- 手动触发（workflow_dispatch）：可在 build.yml 的 `release` 任务中输入 tag 重跑；`publish-gitee.yml` 可手动补发到 Gitee

主要 Job：
- `build-linux`：构建 `whois-x86_64-gnu` 并保存为构建产物
- `release`（标签推送或手动触发）：
  - 收集 whois 仓库 `release/lzispro/whois/` 的 7 个静态二进制
  - 生成合并的 `SHA256SUMS.txt`
  - 创建/更新 GitHub Release，上传所有资产（支持覆盖同名资产）
  - 可选：若设置了 Secrets（见下），在 Gitee 创建同名 Release，正文附 GitHub 下载直链
  - 如需后续改为仓库相对路径以改善国内网络体验，可使用 `relativize_static_binary_links.sh`（详见 `docs/RELEASE_LINK_STYLE.md`）

  - `GITEE_OWNER`（如：`larsonzh`）
  - `GITEE_REPO`（如：`whois`）
  - `GITEE_TOKEN`（你的 Gitee PAT，具备发布权限）
- 验证：发布 Job 日志显示 `Gitee create release HTTP 200/201` 即成功；未配置将自动跳过

提示（远程 SSH）：
- 仓库不再提供依赖远程 SSH 的工作流。如需在 CI 中执行远程构建，请使用自托管 Runner；常规情况下建议在本机使用 `tools/remote/remote_build_and_test.sh` 完成交叉编译与冒烟。
- 如遇 SSH 连接问题，可设置环境变量 `WHOIS_DEBUG_SSH=1`，脚本会开启 `ssh -vvv` 详细日志以便排查。

---

###### LACNIC 透传提示

- 若显式 `-h lacnic` 查询非 LACNIC 辖区的 IP，LACNIC 服务器会直接透传权威 RIR 的正文（例如 1.1.1.1 显示 APNIC 内容，8.8.8.8/143.128.0.0 显示 ARIN 内容），但尾行仍会显示 `Authoritative RIR: whois.lacnic.net`。这是服务器自身行为，并非客户端回退导致。
- 若希望标题/尾行与正文归属保持一致，请用默认流程从 IANA 跟随 referral，或直接指定对应权威 RIR（如 `-h apnic` / `-h arin`），避免依赖 LACNIC 透传。

## 故障排查速查

- 第一步失败或有告警：查看 `whois/out/release_flow/<ts>/step1_remote.log`（默认严格模式，Warning 也会中止）
- `-NoSmoke` 与 `-Queries` 同时使用：Queries 会被忽略（脚本会打印提示）
- Windows 路径：PowerShell 包装器会自动把 `D:\...` 转为 `/d/...`
- 多查询参数：PowerShell 已修复自动引用，`-Queries "8.8.8.8 1.1.1.1"` 可直接使用
- Gitee 步骤失败：不阻断 GitHub 主发布；日志会打印返回码与响应体
- 自 v3.2.0 起，`out/artifacts/` 不再纳入版本控制；如需清理本地历史产物，使用 `tools/dev/prune_artifacts.ps1`（支持 `-DryRun`）。
- `out/`、`release_assets/`：已在 `.gitignore` 忽略，避免误提交

### Lookup 自检与“空响应”回退验证（3.2.7）

目的：在网络可用的前提下，快速验证“连接失败/空正文”统一回退策略是否生效，且不改变既有头/尾契约。

方法：
- 直接运行自测（含 lookup 覆盖）：
  ```powershell
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -a '--selftest'"
  ```
- 显式触发“空响应注入”路径（需要网络）：
  ```powershell
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./out/build_out/whois-x86_64 --selftest --selftest-inject-empty"
  ```

说明：lookup 自测为建议性检查（网络影响较大），失败会记录但不改变自测退出码；核心自测（折叠/重定向）仍决定 `--selftest` 的总体通过/失败。

---

## 术语

- CI（Continuous Integration，持续集成）：在服务器自动执行构建/测试/打包/检查，保证主干可构建、问题早发现
- CD（Continuous Delivery/Deployment）：在 CI 通过后自动交付/部署（发布版本、上线等）

---

## 快速清单（Cheat Sheet）

- 发布（自动补丁 + 冒烟）：`.\\tools\\release\\full_release.ps1`
- 跳过冒烟：`.\\tools\\release\\full_release.ps1 -NoSmoke`
- 多查询：`.\\tools\\release\\full_release.ps1 -Queries "8.8.8.8 1.1.1.1"`
- 指定 Tag：`.\\tools\\release\\full_release.ps1 -Tag vX.Y.Z`
- 日志：`whois/out/release_flow/<ts>/step1_remote.log`
- Gitee Secrets：`GITEE_OWNER / GITEE_REPO / GITEE_TOKEN`

---

## 快速提交（可选）

- 脚本：`tools/dev/quick_push.ps1`
- 用法示例：
  ```powershell
  # 推送到 origin master（自动 add/commit/pull --rebase/push）
  .\tools\dev\quick_push.ps1 -Message "fix: xxx"

  # 同时推送到 gitee 远程
  .\tools\dev\quick_push.ps1 -Message "docs: update" -PushGitee

  # 推送其它分支
  .\tools\dev\quick_push.ps1 -Message "feat: abc" -Branch develop

  # 同时推送标签（若已本地创建）
  .\tools\dev\quick_push.ps1 -Message "release" -PushTags
  ```
- 注意：
  - 若无改动且未加 `-AllowEmpty`，脚本会提示“不存在需要提交的变更”。
  - 使用 `-PushGitee` 前需先 `git remote add gitee git@gitee.com:<owner>/<repo>.git`。

### VS Code 任务

已内置任务（Terminal → Run Task）：
- Git: Quick Push
- Remote: Build and Sync whois statics（远端一键构建并同步 7 个静态二进制）

使用说明：
- 运行任务后会弹出参数输入框（可保留默认再按需修改）：
  - Remote build host (SSH)：远端主机（IP/域名）
  - Remote SSH user：默认 ubuntu
  - Private key path：私钥路径（Git Bash 风格，如 /c/Users/you/.ssh/id_rsa）
  - Run smoke tests?：1/0 是否在远端对产物做联网冒烟
  - Smoke queries：冒烟查询目标（空格分隔）
  - Local sync dir：本机同步目录（Git Bash 路径），默认 `/d/LZProjects/lzispro/release/lzispro/whois`
- 任务会在远端交叉编译完成后，把 7 个静态二进制拉回并同步到本机目录；同步前用 `-P 1` 清理非 `whois-*` 文件，保持目录整洁。

运行时会弹出输入框填写 commit message。

注意：根据当前策略，不建议自动向 Gitee 推送代码；如需同步，请在 Gitee 侧手动执行或单次使用命令行推送以避免双向冲突。

---

## 打标签发布（可选）

- 脚本：`tools/dev/tag_release.ps1`
- 用法：
  ```powershell
  .\tools\dev\tag_release.ps1 -Tag v3.1.10 -Message "Release v3.1.10"
  # 可选同步到 gitee：
  .\tools\dev\tag_release.ps1 -Tag v3.1.10 -PushGitee
  ```
- 说明：
  - 会校验格式 `vX.Y.Z`，并检查同名标签是否已存在；创建后自动推送到 origin。
  - 推送标签会触发 GitHub Actions 的发布流程，自动创建 Release 并上传产物。

### 重新生成同名版本的发布（删除并重建标签）

适用场景：需要替换已发布版本的资产（例如更新为最新静态二进制），且保持版本号不变（如 `v3.2.7`）。

步骤：
1) 若 GitHub 页面上仍存在同名 Release，请先删除该 Release 页面（不会影响代码）。
2) 删除本地与远端同名标签：
  ```powershell
  git tag -d vX.Y.Z
  git push origin :refs/tags/vX.Y.Z
  ```
3) 准备最新静态产物（任选其一）：
  - 运行 VS Code 任务“Remote: Build and Sync whois statics”
  - 或执行一键发布任务/脚本并开启构建同步：`One-Click Release`（`buildSync=true`），将 whois 仓库 `release/lzispro/whois/` 目录内的 7 个静态产物更新、提交并推送
4) 重建并推送同名标签：
  ```powershell
  git tag -a vX.Y.Z -m "Release vX.Y.Z"
  git push origin vX.Y.Z
  ```
5) 等待发布工作流重新运行并收集 whois 仓库 `release/lzispro/whois/` 的 7 个静态二进制与 `SHA256SUMS.txt`。
6) 仅需更新发布正文而不改标签时，可执行：
  ```powershell
  .\tools\release\one_click_release.ps1 -Version X.Y.Z -SkipTagIf true
  ```

提示：当前发布流程已与 lzispro 仓库解耦，资产来源为 whois 仓库内的 `release/lzispro/whois/`，非 lzispro 仓库路径。

---

  ## 开发者附注：安全日志自测钩子（可选，默认关闭）

  目的：快速验证 `--security-log` 的“限频防洪”是否生效，而无需构造复杂的网络场景。该钩子仅在你显式开启时运行，不改变正常行为。

  启用方式（需同时满足）：
  - 构建时：为 whois 加上编译宏 `-DWHOIS_SECLOG_TEST`
  - 运行时：设置环境变量 `WHOIS_SECLOG_TEST=1`

  运行效果：程序启动早期会向安全日志打出一小段高频事件，用于触发与观察限频；事件仅输出到 stderr，stdout 的“标题/尾行”契约不受影响。结束后自动恢复原先的 `security_logging` 设置。

  示例（本机 Linux）：
  ```bash
  make CFLAGS_EXTRA="-DWHOIS_SECLOG_TEST"
  WHOIS_SECLOG_TEST=1 ./whois-client --security-log --help
  ```

  示例（通过 SSH 在远端 Linux 主机执行）：
  ```bash
  ssh ubuntu@203.0.113.10 '
    cd ~/whois && \
    make CFLAGS_EXTRA="-DWHOIS_SECLOG_TEST" && \
    WHOIS_SECLOG_TEST=1 ./whois-client --security-log --help
  '
  ```

  示例（Windows PowerShell，远端自测，推荐）：
  ```powershell
  # 1) 准备远端工作目录（与旧目录隔离）
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@remote 'rm -rf ~/whois-wip; mkdir -p ~/whois-wip'

  # 2) 上传本地 whois 项目（请按需替换本地路径、远端账户与主机）
  scp -r -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "D:/LZProjects/whois/*" user@remote:~/whois-wip/

  # 3) 远端编译并运行自测（宏 + 环境变量 同时开启）
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@remote `
    'cd ~/whois-wip && make clean || true; make CFLAGS_EXTRA=-DWHOIS_SECLOG_TEST && WHOIS_SECLOG_TEST=1 ./whois-client --security-log --help'
  ```

  提示：
  - 可执行文件名为 `whois-client`（静态可选 `whois-client.static`）。
  - `--help` 仅用于快速退出流程，便于观察 stderr 的 SECURITY 行与“抑制汇总”。
  - Windows 需已安装 OpenSSH（PowerShell 可直接运行 `ssh/scp`）。

  说明：
  - `--help` 仅用于快速退出流程，便于你观察到 stderr 的 SECURITY 行与“抑制汇总”提示；也可以换成任意命令行，不影响自测。
  - 未加编译宏或未设置环境变量时，自测钩子不会运行。

  ---

  ## 开发者附注：grep 过滤自测钩子（可选）

  目的：在不依赖真实 WHOIS 响应的情况下，验证 wc_grep 在块模式与行模式下的匹配与续行保留逻辑是否正确。

  启用条件（需同时满足）：
  - 构建：加入编译宏 `-DWHOIS_GREP_TEST`
  - 运行：设置环境变量 `WHOIS_GREP_TEST=1`

  运行效果：程序启动时用内置的微型样本做三轮过滤测试，输出：
  ```
  [GREPTEST] block mode: PASS
  [GREPTEST] line mode (no-cont): PASS
  [GREPTEST] line mode (keep-cont): PASS
  ```
  若失败，会附带 `[GREPTEST-OUT]` 行列出产生的输出，便于快速定位。

  示例（本地 Linux）：
  ```bash
  make CFLAGS_EXTRA="-DWHOIS_GREP_TEST"
  WHOIS_GREP_TEST=1 ./whois-client --help 2>&1 | grep GREPTEST || true
  ```

  示例（Windows 远端脚本）：
  ```powershell
  # 使用远端构建脚本 -X 1 一次性开启编译宏与运行期环境变量
  & 'C:\Program Files\Git\bin\bash.exe' -lc "tools/remote/remote_build_and_test.sh -H <host> -u <user> -k '<key>' -r 1 -q '8.8.8.8 1.1.1.1' -s '<sync_dir>' -P 1 -a '' -G 0 -E '-O3 -s' -X 1"
  ```

  启发式（当前逻辑简述）：
  - Header 必须从第 0 列开始；任意前导空白的行视为续行。
  - 块模式：保留匹配块的续行，过滤无关续行。
  - 为避免把首个“看起来像 header 的”缩进行（如地址行）错误丢弃，允许全局保留第一个此类缩进行；后续若继续出现 header-like 缩进行则需匹配正则才保留。

  说明：
  - 行模式由 `--grep-line` 开启，`--grep-line-keep-cont` 控制是否保留续行。
  - 未同时满足编译宏与环境变量时，自测逻辑完全禁用，不影响正常输出。

  ---

## 后续规划（RFC）

- 条件输出（Phase 2.5）：通过参数化过滤/投影与轻量统计，降低外部脚本负担并提升性能；默认行为保持不变，全部能力为可选开启。
  - 设计文档（RFC）：`docs/RFC-conditional-output-CN.md`
  - 第一阶段（v3.2.0 目标）：基础过滤（RIR/家族/私网/状态）、`--no-body` 抑制正文、`--print meta` 元信息行与 `--fields` 字段选择、`--stats` 统计。

### VS Code 任务

- Git: Tag Release（会弹出输入框填写 tag 与 message）

---

## 手动补发 Gitee Release（publish-gitee-manual）

适用场景：历史标签发布时，CI 因缺少 target_commitish 导致“Publish release to Gitee”返回 400，或你想对已存在的 GitHub Release 进行“补发到 Gitee”。该流程不会把代码/标签推到 Gitee，仅创建 Gitee Release 页面并附上 GitHub 下载直链。

前置条件：在 GitHub 仓库 Settings → Secrets 配置以下项（与自动发布相同）：
- GITEE_OWNER：Gitee 用户/组织名
- GITEE_REPO：Gitee 仓库名
- GITEE_TOKEN：Gitee PAT（需具备创建发布的权限）
- 可选 GITEE_TARGET_COMMITISH：若不设，默认 `master`（用于在 Gitee 端创建 tag 时的指向）

操作步骤：
1) GitHub → Actions → 选择工作流 `publish-gitee-manual`
2) 右上角 Run workflow：
   - tag：如 `v3.2.0`
   - target_commitish：默认为 `master`（可改为具体分支/提交）
3) 运行完成后，在步骤“Publish release to Gitee (manual)”看到 `Gitee create release HTTP 201/200` 即成功。

说明：
- 本工作流仅创建 Gitee Release 页面，正文来自 `RELEASE_NOTES.md` 并追加 GitHub Releases 的下载直链。
- 不会向 Gitee 仓库推送代码/标签；若确需镜像 refs，请在 Gitee 账户添加 SSH 公钥后，手动执行：
  - `git push gitee master`
  - `git push gitee --tags`
- 自 v3.2.1（及之后新标签）起，CI 的自动发布已包含 `target_commitish`，通常无需再手动补发。

---

## VS Code 任务（新增：One-Click Release）

除了已有的“Git: Quick Push”和“Remote: Build and Sync whois statics”，现新增任务：

- One-Click Release（调用 `tools/release/one_click_release.ps1`，用于快速更新 GitHub/Gitee Release；可选择是否跳过创建/推送标签；支持可选的“远程编译+冒烟+同步并推送静态二进制”）

运行后会出现以下输入项：
- releaseVersion：纯版本号，不带 `v`（用于拼接 `docs/release_bodies/vX.Y.Z.md`）
- releaseName：发布显示名称（GitHub/Gitee 共用，默认 `whois v<version>`）
- skipTag：是否跳过创建/推送标签（`true`/`false`）
 - buildSync：是否执行“远程编译 + 冒烟 + 同步静态二进制并提交推送”（默认 `true`）
 - 远程构建参数：`rbHost/rbUser/rbKey/rbSmoke/rbQueries/rbSmokeArgs/rbGolden/rbCflagsExtra/rbSyncDir`
   - 同步目录默认包含 whois 仓库自身的 `release/lzispro/whois`，用于收集 7 个静态产物（已与 lzispro 解耦）。

底层等价命令（PowerShell）：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/release/one_click_release.ps1 `
  -Version <releaseVersion> -GithubName <releaseName> -GiteeName <releaseName> -SkipTagIf <skipTag> `
  -BuildAndSyncIf <buildSync> -RbHost <rbHost> -RbUser <rbUser> -RbKey '<rbKey>' `
  -RbSmoke <rbSmoke> -RbQueries '<rbQueries>' -RbSmokeArgs '<rbSmokeArgs>' -RbGolden <rbGolden> `
  -RbCflagsExtra '<rbCflagsExtra>' -RbSyncDir '<rbSyncDir>'
```

注意：
- 若 `skipTag=true`，脚本仅更新已有标签对应的 Release 正文/名称，不会创建/推送新标签。
- 若 `buildSync=false`，将跳过“远程编译/冒烟/同步并推送”阶段，直接进入打标签与更新发布正文。
- GitHub 需要 `GH_TOKEN` 或 `GITHUB_TOKEN`；Gitee 需要 `GITEE_TOKEN`。未设置的会被自动跳过并提示。
- 支持 `WHOIS_DEBUG_SSH=1` 在远程脚本中开启 `ssh -vvv` 诊断。
- 建议等到“下一个版本”发布时再实际联通两端更新，避免频繁改动当前稳定内容。

---

## 新增脚本：one_click_release.ps1 使用说明

脚本位置：`tools/release/one_click_release.ps1`

用途：一键更新 GitHub/Gitee Release 正文与显示名称；可通过参数选择是否跳过打标签（与 VS Code 任务一致）。

常用示例：
```powershell
# 正常创建标签 + 更新 Release（需要本地 git 与 Git Bash 可用）
./tools/release/one_click_release.ps1 -Version 3.2.5

# 仅更新已有标签对应的 Release，跳过打标签
./tools/release/one_click_release.ps1 -Version 3.2.5 -SkipTagIf true

# 自定义显示名称（GitHub/Gitee 共用或分别指定）
./tools/release/one_click_release.ps1 -Version 3.2.5 -GithubName "whois v3.2.5" -GiteeName "whois v3.2.5"
```

参数要点：
- `-Version X.Y.Z` 必填；正文文件固定读取 `docs/release_bodies/vX.Y.Z.md`
- `-SkipTag` 与 `-SkipTagIf 'true'` 二选一或同时指定均可，任意为真即跳过打标签
- `-PushGiteeTag` 可将标签同步到 gitee 远程（如无需要可忽略）
- GitHub 更新有重试机制（`-GithubRetry/-GithubRetrySec`），用于等待 Actions 创建 Release 占位

---

## 简易远程 Makefile 快速编译与测试（新增）

适用：需要在一台普通 Linux 主机上，直接用仓库自带 `Makefile` 做快速功能验证与冒烟，不依赖交叉编译脚本。

前置：远端可 `ssh` 登录，已安装 `gcc`，对外可访问 whois 端口 43。

步骤（Windows PowerShell 示例，按需替换路径/主机/账户）：
```powershell
# 1) 远端准备隔离目录
ssh user@host 'rm -rf ~/whois-fast && mkdir -p ~/whois-fast'

# 2) 仅同步最小必需文件（减少带宽与污染）
scp -r D:/LZProjects/whois/src D:/LZProjects/whois/Makefile user@host:~/whois-fast/

# 3) 远端编译（默认生成 whois-client）
ssh user@host 'cd ~/whois-fast && make -j$(nproc)'

# 4) 单条查询快速检视
ssh user@host 'cd ~/whois-fast && ./whois-client 8.8.8.8 | head -n 40'

# 5) 批量检视 + 过滤（利用 stdin）
ssh user@host "cd ~/whois-fast && printf '8.8.8.8\n1.1.1.1\n' | ./whois-client -B -g 'netname|country' --grep 'GOOGLE|CLOUDFLARE' --grep-line"

# 6) 可选静态链接（工具链支持时）
ssh user@host 'cd ~/whois-fast && make static'

# 7) 清理
ssh user@host 'rm -rf ~/whois-fast'
```

提示：
- `Makefile` 支持 `CFLAGS_EXTRA` 追加编译选项，例如 `make CFLAGS_EXTRA=-DWHOIS_SECLOG_TEST`。
- 批量模式输出遵循“头/尾契约”，便于人工快速审阅。
- 该方法仅用于快速验证，不会生成多架构静态产物；如需多架构或统一日志，请使用 `tools/remote/remote_build_and_test.sh`。
