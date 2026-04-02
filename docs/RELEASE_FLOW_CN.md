# 一键发布流程（whois）

本文档描述如何在本地一键完成完整发布：

- 远程交叉编译 7 个架构静态二进制 + 联网冒烟
- 同步静态产物到 lzispro，并自动提交/推送
- （可选）提交更新后的 `RELEASE_NOTES.md`
- 打标签触发 GitHub Release（自动附上 CI 的 `whois-x86_64-gnu` + 7 个静态二进制）

> CI 与远程 SSH 说明：
> - 与远程 SSH（跨机交叉编译/抓取产物）相关的 GitHub Actions 工作流现已改为“手动触发（workflow_dispatch）”，以避免托管 Runner 无法直连私网主机导致失败。
> - 建议：在本机通过 `tools/remote/remote_build_and_test.sh` 完成远端构建与冒烟；需要 CI 化时，优先考虑自托管 Runner。
> - 排错：设置 `WHOIS_DEBUG_SSH=1` 可开启 `ssh -vvv` 详细调试日志。

## 快速使用（PowerShell）

在 whois 仓库根目录执行：

```powershell
# 自动递增标签（基于当前最大 vX.Y.Z 的补丁号），默认联网冒烟，默认查询 8.8.8.8
# 自动探测同级目录的 lzispro，或用 --lzispro-path 指定
./tools/release/full_release.ps1

# 指定标签与查询目标
./tools/release/full_release.ps1 -Tag v3.1.9 -Queries '8.8.8.8 1.1.1.1'

# 关闭冒烟测试
./tools/release/full_release.ps1 -NoSmoke

# 指定 lzispro 路径（例如 D:\LZProjects\lzispro）
./tools/release/full_release.ps1 -LzisproPath 'D:\LZProjects\lzispro'
```

等效的 Git Bash（可用于 CI 宿主或 WSL）：

```bash
./tools/release/full_release.sh --tag v3.1.9 --queries '8.8.8.8 1.1.1.1'
```

## 版本号规则
- 未显式指定 `--tag/ -Tag` 时，脚本会读取 whois 仓库现有标签中最大的 `vX.Y.Z`，将 Z 自增 1 作为下一版。
- 若该标签已存在，脚本会报错退出，避免重复发布。
- 版本标记策略（自 3.2.6 起）：默认构建不再附加 `-dirty` 后缀以减少不必要的标签/提交操作；若需要严格检测并在存在已跟踪改动时附加 `-dirty`（用于审计或正式发布复核），可在调用远程构建脚本前设置环境变量 `WHOIS_STRICT_VERSION=1`。例如：
   ```powershell
   $env:WHOIS_STRICT_VERSION = 1
   & 'C:\Program Files\Git\bin\bash.exe' -lc "tools/remote/remote_build_and_test.sh -r 1"
   ```
   或在 VS Code 中使用新增的严格模式 Task（Remote: Build (Strict Version)）。

## 目录与同步说明
- 7 个静态二进制默认同步到：`<lzispro>/release/lzispro/whois/`。
- GitHub Actions 的发布工作流会在打标签后自动从 lzispro 的 master 分支读取该目录（或 `<lzispro>/release/lzispro/whois/whois`，两者兼容）收集附件并生成合并校验 `SHA256SUMS.txt`。

## 执行细节（full_release.sh）
1. 调用 `tools/remote/remote_build_and_test.sh`：
   - 参数：`-r 1`（可关闭）、`-q '<queries>'`、`-s '<lzispro>/release/lzispro/whois' -P 1`（先清理目标内非 whois-* 文件）
   - 默认将 Step1 的输出存入 `out/release_flow/<timestamp>/step1_remote.log`；若检测到任意警告/错误（包含 `warning:`、`[WARN]`、`[ERROR]`），脚本会立即终止。可用 `--strict-warn 0` 关闭此行为。
2. 在 lzispro 仓库执行 `git add release/lzispro/whois/whois-* && commit && push`（若无变更则跳过）
3. 在 whois 仓库执行 `git add RELEASE_NOTES.md && commit && push`（若无变更则跳过）
4. 在 whois 仓库创建并推送标签 `vX.Y.Z` 触发 Release

## 常见问题
- 标签不存在/已存在：未提供标签时自动递增，若目标标签已存在脚本会终止避免重复。
- 未找到 lzispro：脚本默认探测 whois 同级目录下的 `lzispro`。也可用 `--lzispro-path` 明确指定。
- 附件缺失：确认步骤 2 已提交并推送到 GitHub，且工作流日志里能看到已从 lzispro 正确复制 7 个静态二进制。

---

## 稳定发布最佳实践

- 关键原则：一次完成。所有代码与文档先提交推送后，再用 VS Code 任务 One-Click Release 完成“打标签 + 远程编译 + 冒烟 + 同步 + 提交推送 + 触发工作流 + 更新 GitHub/Gitee 发布正文”。不要拆成多步手工执行。
- 预检清单：
   - 工作区干净：没有未提交变更（含 `release/lzispro/whois/`、`docs/release_bodies/vX.Y.Z.md`）。
   - 文档一致：`README.md`、`RELEASE_NOTES.md`、`docs/release_bodies/vX.Y.Z.md` 已对齐；双语顺序统一为“中文在上，英文在下（或同行中文在前、英文在后）”。
   - 复盘入口：next-major 发版可直接使用 `docs/release_bodies/next-major-compat-announcement-draft.md` 中的 `Release-day recap template / 发版当日复盘模板` 填写三闸结果与 PASS/FAIL 判定。
   - 下载直链：发布正文内资产为 GitHub 绝对直链，并补充 `SHA256SUMS.txt`。
   - 版本确认：计划发布版本未被占用；若需复用必须先删除线上旧 Release 与旧标签。
   - 凭据就绪：GitHub `GITHUB_TOKEN/GH_TOKEN`，Gitee `GITEE_TOKEN`（如需同步）。
- One-Click Release 建议：
   - `skipTag=false`、`buildSync=true`；远程 `rbHost/rbUser/rbKey` 正确；`rbSmoke=1`、`rbQueries` 给出 1～2 个目标；`rbSmokeArgs` 留空或仅填必要参数；`rbSyncDir` 支持多目录用分号分隔。
   - 严格版本：使用任务内“严格构建”或设置 `WHOIS_STRICT_VERSION=1`，确保产物版本为干净的 `vX.Y.Z`。
- 常见误区：
   - 先手动推标签或先手动远程构建再调用任务，容易导致“标签与正文/资产不同步”。
   - 在任务表单里随手填了 `rbSmokeArgs` 等占位值（即便正确）也可能改变冒烟行为，建议为空即留空。
   - 频繁删除/重推同名标签可能让 Release 进入草稿或无资产状态。
- 发布后验证：
   - Actions 运行：release 工作流成功，7 个二进制 + `SHA256SUMS.txt` 已出现在 Release 附件中。
   - 产物版本：本地同步目录的二进制 `-v` 输出应为干净 `vX.Y.Z`。
   - 正文：GitHub/Gitee 发布正文名称与内容匹配当前版本。
- 修复策略：
   - 仅正文有误：One-Click Release（`skipTag=true`、`buildSync=false`）只刷新正文。
   - 资产缺失：删除本地+远端 Tag → 确认产物已提交推送 → 再完整执行 One-Click（不跳过 Tag）。
   - 版本带 `-dirty`：说明构建时工作区不干净，清理后重新完整执行。

### 发布侧回归清单（最终固化，2026-03-28）

- 适用范围：P2 收口后的常规发版前门禁复核（不改变默认语义）。
- 必跑门禁（顺序固定）：
  1. `Remote: Build (Strict Version)`（建议 `rbPreflight=1`）
     - 通过标准：`Local hash verify PASS`、`Golden PASS`、`referral check PASS`、`Step47 preclass preflight PASS`。
  2. `Test: CIDR Contract Bundle (prefilled)`
     - 通过标准：`body_status=pass`、`matrix_status=pass`。
  3. `Test: Redirect Matrix (10x6)`
     - 通过标准：`authMismatchFiles=0`、`errorFiles=0`。
  4. `Test: Step47 PreRelease Check (reserved, list file)`（启用 preclass gate）
     - 通过标准：`readiness`/`ab`/`rollback`/`preclass-p1-gate` 全 pass。
- 异常处理：任一门禁失败即中止发布，不允许“先打标签后补修”。
- 证据留存（最少项）：
  - `out/artifacts/<timestamp>` 主目录。
  - preflight 目录（若启用）：`out/artifacts/step47_preclass_preflight/<timestamp>`。
  - Step47 预发布目录：`out/artifacts/step47_prerelease/<timestamp>`。
  - 在 `RELEASE_NOTES.md` 与相关 RFC 记录本次路径与 PASS/FAIL 结论。

### 门禁执行一页式 Runbook（2026-04-03）

- 目标：把“日常快验”和“发布前全量复核”分层，减少重复全链路执行。

- A. 日常快验（开发中，建议每次改动后执行）
  1. `Test: One-Click DryRun Guard (local, prefilled)`
     - 通过标准：`result=pass`，且 `git_state_unchanged=True`。
  2. `Gate: D6 Double-Round Consistency (prefilled)`
     - 通过标准：`summary.csv` 两轮 `RoundPass=True`。
  3. 可选：`Test: One-Click DryRun Guard (build+sync, prefilled, no-delta-ok)`
     - 用途：验证任务入口链路可运行，不把“本轮无 static delta”当失败。

- B. 发布前全量复核（发版前）
  1. 串行执行（禁止并行）：
     - `Test: One-Click DryRun Guard (local, prefilled)`
     - `Test: One-Click DryRun Guard (build+sync, prefilled)`
     - `Gate: D6 Double-Round Consistency (prefilled)`
  2. 判定口径：
     - 若预计会有新静态产物，`build+sync, prefilled` 要求 `statics_detected=true`。
     - 若本轮预计无静态差异，可改跑 `build+sync, prefilled, no-delta-ok` 作为链路健康校验。

- C. 串行约束（必须遵守）
  - `build+sync` 与 `D6` 都会调用远程构建目录，不能并行触发；并行会导致远端产物互扰并引发误判。

- C1. 任务面板单行版（贴边即用）
   - Daily（无静态差异常态）：`Test: One-Click DryRun Guard (local, prefilled)` -> `Test: One-Click DryRun Guard (build+sync, prefilled, no-delta-ok)` -> `Gate: D6 Double-Round Consistency (prefilled)`。
   - Pre-Release（预计有静态变化）：`Test: One-Click DryRun Guard (local, prefilled)` -> `Test: One-Click DryRun Guard (build+sync, prefilled)` -> `Gate: D6 Double-Round Consistency (prefilled)`。
   - Pre-Release（预计无静态变化）：`Test: One-Click DryRun Guard (local, prefilled)` -> `Test: One-Click DryRun Guard (build+sync, prefilled, no-delta-ok)` -> `Gate: D6 Double-Round Consistency (prefilled)`。

- C2. 失败分流 3 行决策表
   - `build+sync` 仅因 `statics_detected=false` 失败且 `guard_result=pass`：切到 `build+sync, prefilled, no-delta-ok`。
   - `D6` 单轮异常：按串行口径立即重跑 `Gate: D6 Double-Round Consistency (prefilled)`，并对比 `summary.csv` 的 `RoundPass`。
   - 外部网络噪声（如 `%ERROR:201`/超时峰值）：先按网络窗口复验参数跑（`-RirIpPref arin=ipv6,ripe=ipv6`），再回默认参数补跑一轮。

- C3. 失败分流速查表（问题 -> 任务 -> 判定字段）

   | 问题特征 | 下一条任务 | 关键判定字段 |
   | --- | --- | --- |
   | `build+sync` 失败且 `guard_result=pass`、`statics_detected=false` | `Test: One-Click DryRun Guard (build+sync, prefilled, no-delta-ok)` | `summary.txt: smoke_result=pass` |
   | `D6` 失败且仅单轮异常 | `Gate: D6 Double-Round Consistency (prefilled)`（串行重跑 1 轮） | `summary.csv: RoundPass`（两轮均 `True`） |
   | `%ERROR:201` 或超时峰值 | 先按网络窗口复验参数跑，再回默认参数补跑同一任务 | `authMismatchFiles/errorFiles` 恢复基线 |

- C4. 检索速查表（任务名 -> grep 关键字）

   | 任务名 | grep 关键字（优先） | 用途 |
   | --- | --- | --- |
   | `Test: One-Click DryRun Guard (local, prefilled)` | `\[ONECLICK-DRYRUN-SMOKE\] result=\|git_state_unchanged=\|guard_result=` | 判断本地 dry-run 是否无副作用且 guard 生效 |
   | `Test: One-Click DryRun Guard (build+sync, prefilled)` | `\[ONECLICK-DRYRUN-SMOKE\] result=\|statics_detected=\|guard_result=` | 判断 build+sync 断言是否通过、是否检测到 static delta |
   | `Gate: D6 Double-Round Consistency (prefilled)` | `\[D6-CONSISTENCY\] result=\|RoundPass\|PreflightPass\|TableGuardPass` | 判断双轮一致性总结果与关键闸项 |
   | 网络窗口复验链路 | `%ERROR:201\|timeout\|authMismatchFiles\|errorFiles` | 判断外部网络噪声并验证回归 |

- C5. 检索命令模板（PowerShell / Git Bash）

   ```powershell
   # One-Click 摘要（local/build+sync）
   Select-String -Path .\out\artifacts\oneclick_dryrun_guard\*\summary.txt -Pattern 'smoke_result=|guard_result=|statics_detected=|git_state_unchanged='

   # D6 双轮摘要
   Select-String -Path .\out\artifacts\d6_consistency_double_round\*\summary.csv -Pattern 'RoundPass|PreflightPass|TableGuardPass'

   # 网络噪声线索（从日志中抓取）
   Get-ChildItem .\out\artifacts -Recurse -File -Include *.log,*.txt | Select-String -Pattern '%ERROR:201|timeout|authMismatchFiles|errorFiles'
   ```

   ```bash
   # One-Click 摘要（local/build+sync）
   rg -n -S "smoke_result=|guard_result=|statics_detected=|git_state_unchanged=" out/artifacts/oneclick_dryrun_guard/**/summary.txt

   # D6 双轮摘要
   rg -n -S "RoundPass|PreflightPass|TableGuardPass" out/artifacts/d6_consistency_double_round/**/summary.csv

   # 网络噪声线索（从日志中抓取）
   rg -n -S "%ERROR:201|timeout|authMismatchFiles|errorFiles" out/artifacts/**/*.log out/artifacts/**/*.txt
   ```

- D. 最小命令块（可复制执行）

   日常快验（推荐顺序）：

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\oneclick_dryrun_guard_smoke.ps1 -Version 3.2.12 -BuildAndSyncIf false

   powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\oneclick_dryrun_guard_smoke.ps1 -Version 3.2.12 -BuildAndSyncIf true -RbHost 10.0.0.199 -RbUser larson -RbKey /c/Users/妙妙呜/.ssh/id_rsa -RbSmoke 1 -RbQueries "8.8.8.8 1.1.1.1 10.0.0.8" -RbGolden 1 -RbOptProfile lto-auto -RbPreflight 1 -RbPreclassTableGuard 1 -RbSyncDir "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois" -RequireStaticsDetectedIfBuildSync false

   powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\d6_consistency_double_run.ps1 -BinaryPath .\release\lzispro\whois\whois-win64.exe -RemoteHost 10.0.0.199 -User larson -KeyPath /c/Users/妙妙呜/.ssh/id_rsa -Smoke 1 -Queries "8.8.8.8 1.1.1.1 10.0.0.8" -SyncDir "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois" -Golden 1 -OptProfile lto-auto -Step47ListFile .\testdata\step47_reserved_list_default.txt -PreclassThresholdFile .\testdata\preclass_p1_group_thresholds_default.txt -OutDirRoot .\out\artifacts\d6_consistency_double_round
   ```

   发布前全量复核（严格串行）：

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\oneclick_dryrun_guard_smoke.ps1 -Version 3.2.12 -BuildAndSyncIf false

   powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\oneclick_dryrun_guard_smoke.ps1 -Version 3.2.12 -BuildAndSyncIf true -RbHost 10.0.0.199 -RbUser larson -RbKey /c/Users/妙妙呜/.ssh/id_rsa -RbSmoke 1 -RbQueries "8.8.8.8 1.1.1.1 10.0.0.8" -RbGolden 1 -RbOptProfile lto-auto -RbPreflight 1 -RbPreclassTableGuard 1 -RbSyncDir "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois" -RequireStaticsDetectedIfBuildSync true

   powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\test\d6_consistency_double_run.ps1 -BinaryPath .\release\lzispro\whois\whois-win64.exe -RemoteHost 10.0.0.199 -User larson -KeyPath /c/Users/妙妙呜/.ssh/id_rsa -Smoke 1 -Queries "8.8.8.8 1.1.1.1 10.0.0.8" -SyncDir "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois" -Golden 1 -OptProfile lto-auto -Step47ListFile .\testdata\step47_reserved_list_default.txt -PreclassThresholdFile .\testdata\preclass_p1_group_thresholds_default.txt -OutDirRoot .\out\artifacts\d6_consistency_double_round
   ```

### 复盘占位符命名规范（2026-03-28）

- 适用范围：`docs/release_bodies/next-major-compat-announcement-draft.md` 的“Release-day recap sample / 发版当日复盘样例”。
- 统一占位符：
   - `<STRICT_TS>`：Remote strict 产物目录时间戳（`out/artifacts/<STRICT_TS>`）。
   - `<PREFLIGHT_TS>`：Step47 preclass preflight 时间戳（`out/artifacts/step47_preclass_preflight/<PREFLIGHT_TS>`）。
   - `<CIDR_TS>`：CIDR bundle summary 文件时间后缀（`cidr_bundle_summary_<CIDR_TS>.txt`）。
   - `<MATRIX_TS>`：Redirect Matrix 10x6 目录时间戳（`out/artifacts/redirect_matrix_10x6/<MATRIX_TS>`）。
   - `<STEP47_TS>`：Step47 prerelease 目录时间戳（`out/artifacts/step47_prerelease/<STEP47_TS>`）。
- 填写规则：
   - 统一使用真实产物路径中的 `yyyyMMdd-HHmmss`。
   - 若某轮未启用 preflight，可保留 `<PREFLIGHT_TS>` 占位并在备注中标注“未启用”。
   - 禁止跨轮混填（每一轮复盘应保持时间戳可追溯到同一批门禁执行）。
- 复制顺序建议：先在“键值对模板块”完成右值替换并核对路径，再粘贴到复盘正文/issue comment，最后补备注与结论。
- 发布当日粘贴检查清单（3 行版）：
   - 路径可达：4 个门禁证据路径存在且可打开。
   - 时间戳一致：同一轮复盘仅使用同批次 `yyyyMMdd-HHmmss`。
   - 结论对齐：门禁 verdict 与证据内容一致（PASS/FAIL 不冲突）。
- 失败时最小回填字段（FAIL 轮必填）：
   - `run_ts`：失败轮执行时间戳（`yyyyMMdd-HHmmss`）。
   - `failed_gate`：失败门禁/步骤名（如 `preclass-p1-gate`）。
   - `evidence_path`：至少 1 条失败证据路径（日志或 summary 文件）。
   - `cause_next`：一句话原因 + 下一步动作（重跑/回滚/网络复验）。
- 关联入口：复盘样例正文已内置“占位符说明 / Placeholder legend”，与本节保持同一口径。
- 快速粘贴片段：`docs/release_bodies/release-day-recap-snippet.md`（issue/comment 可直接粘贴）。

### 网络窗口异常复验（2026-02-21）

- 适用场景：门禁出现固定外部拒绝/限流（如 RIPE 对当前 IPv4 出口返回 `%ERROR:201: access denied`），且疑似与代码行为无关。
- 复验原则：不改 authority 语义与输出契约，仅在测试参数层隔离网络噪声。
- 建议参数：矩阵/复验命令增加 `-RirIpPref arin=ipv6,ripe=ipv6`（或仅对受影响 RIR 切 IPv6）。
- 记录要求：在发布说明或 RFC 中同时记录默认参数结果与复验结果（含 `authMismatchFiles`、`errorFiles` 与日志路径）。
- 回退条件：当出口策略恢复后，应回到默认参数再跑一轮门禁，确认无环境特化依赖。


English short note: See script headers; the PowerShell wrapper simply forwards arguments to the bash script. The release job will attach both CI-built glibc x86_64 binary and seven statically linked multi-arch binaries from the lzispro repository.
