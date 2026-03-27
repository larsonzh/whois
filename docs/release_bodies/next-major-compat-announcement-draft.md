# next-major compatibility announcement (draft) / next-major 兼容公告（草稿）

> 中文范围：下个主版本移除已弃用参数 `--no-cidr-erx-recheck` 的迁移公告草稿。当前状态：该参数在 v3.2.x 已进入 deprecated 过渡期，仍可使用，但会输出一次性告警。
>
> EN scope: migration notice draft for removing deprecated flag `--no-cidr-erx-recheck` in the next major release. Current status: deprecated in v3.2.x, still accepted with a one-time warning.

## TL;DR / 摘要

- 中文
  - `--no-cidr-erx-recheck` 将在下个主版本移除。
  - 默认行为（CIDR 启用 ERX/IANA 基准复查）保持不变，且仍是推荐路径。
  - 当前仍在使用该参数的脚本可立即移除，以获得前向兼容。

- EN
  - `--no-cidr-erx-recheck` will be removed in the next major version.
  - Default behavior (ERX/IANA baseline recheck enabled for CIDR) remains unchanged and is recommended.
  - Scripts currently using this flag can remove it now for forward compatibility.

## Impact surface / 影响范围

- 中文
  - 受影响：显式传入 `--no-cidr-erx-recheck` 的 CLI 脚本、封装器、CI 任务和 alias。
  - 不受影响：未传该参数的流程（默认行为与移除后行为一致）。

- EN
  - Affected: CLI scripts, wrappers, CI jobs, and aliases that explicitly include `--no-cidr-erx-recheck`.
  - Not affected: workflows that do not pass this flag (post-removal behavior matches current default behavior).

## Behavioral difference after removal / 移除后的行为差异

- 中文
  - 移除前（当前）
    - 传入参数：跳过 CIDR ERX/IANA 基准复查，按重定向策略继续。
    - 不传参数：执行基准复查（默认）。
  - 移除后（next-major）
    - 该参数将被识别为无效选项。
    - CIDR 路径统一走基准复查。

- EN
  - Before removal (current)
    - Flag present: skip CIDR ERX/IANA baseline recheck and continue by redirect policy.
    - Flag absent: perform baseline recheck (default).
  - After removal (next major)
    - The flag is rejected as an invalid option.
    - Baseline recheck path is always used for CIDR.

## Migration path (recommended) / 迁移路径（建议）

1. 中文：在脚本、任务定义与包装层中搜索并移除 `--no-cidr-erx-recheck`。
   EN: Search and remove `--no-cidr-erx-recheck` from scripts, task definitions, and wrappers.

2. 中文：复跑三闸验证。
   EN: Re-run strict gates.
   - `Remote: Build (Strict Version)`
   - `Test: CIDR Contract Bundle (prefilled)`
   - `Test: Redirect Matrix (10x6)`

3. 中文：确认 `authMismatchFiles=0`，并核对本地环境无新增回归。
   EN: Verify `authMismatchFiles=0` and confirm no new regressions in your environment.

## Suggested timeline / 建议时间线

- 中文
  - v3.2.x（当前）：保留 deprecated + 一次性告警（已生效）。
  - v3.2.x 后续 1 个 patch 窗口：持续在 release notes 与运维文档公告移除计划。
  - next-major（目标）：移除选项解析与 help 暴露，保留迁移说明。

- EN
  - v3.2.x (current): deprecation + one-time warning (already active).
  - next 1 patch window in v3.2.x: repeatedly announce planned removal in release notes and operations docs.
  - next major (target): remove flag parsing and help entry; keep migration notes in release body.

## Rollback guidance / 回滚建议

- 中文
  - 若迁移后出现环境相关回归：
    - 先用现有 retry metrics 与 matrix 日志区分网络/限流噪声。
    - 生产回滚可临时固定到最新 v3.2.x，同时收集可复现样例。
    - 提 issue 时建议附：查询集、起始服务器、完整命令行、stderr 诊断（`--debug --retry-metrics --dns-cache-stats`）、matrix 汇总。

- EN
  - If environment-specific regressions appear after migration:
    - First isolate network/rate-limit noise with existing retry metrics and matrix logs.
    - For production rollback, temporarily pin to the latest v3.2.x while collecting reproducible cases.
    - When opening an issue, include: query set, startup server, command line, stderr diagnostics (`--debug --retry-metrics --dns-cache-stats`), and matrix summary.

## Copy-ready short notice / 可直接复用的短公告

- 中文
  - `--no-cidr-erx-recheck` 已在 v3.2.x 进入 deprecated 过渡期，并计划在下个主版本移除。建议立即从脚本中移除该参数以保证前向兼容；默认 CIDR 路径（启用 ERX/IANA 基准复查）保持不变。

- EN
  - `--no-cidr-erx-recheck` is deprecated in v3.2.x and scheduled for removal in the next major version. Please remove this flag from scripts now for forward compatibility; the default CIDR path (ERX/IANA baseline recheck enabled) remains unchanged.

## Release-day recap template / 发版当日复盘模板

- 中文
  - 变更摘要（仅观测/是否切流）：
  - 代码位置：
  - 回退开关：
  - 固定门禁清单（顺序不可变）：
    1. `Remote: Build (Strict Version)`（建议 `rbPreflight=1`）
       - 结果：PASS / FAIL
       - 通过标准核对：`Local hash verify PASS` / `Golden PASS` / `referral check PASS` / `Step47 preclass preflight PASS`
       - 日志/产物路径：
    2. `Test: CIDR Contract Bundle (prefilled)`
       - 结果：PASS / FAIL
       - 通过标准核对：`body_status=pass` / `matrix_status=pass`
       - 日志/产物路径：
    3. `Test: Redirect Matrix (10x6)`
       - 结果：PASS / FAIL
       - 通过标准核对：`authMismatchFiles=0` / `errorFiles=0`
       - 日志/产物路径：
    4. `Test: Step47 PreRelease Check (reserved, list file)`（启用 preclass gate）
       - 结果：PASS / FAIL
       - 通过标准核对：`readiness` / `ab` / `rollback` / `preclass-p1-gate` 全 pass
       - 日志/产物路径：
  - 证据归档（最少项）：
    - 主目录：`out/artifacts/<timestamp>`
    - preflight 目录（若启用）：`out/artifacts/step47_preclass_preflight/<timestamp>`
    - Step47 目录：`out/artifacts/step47_prerelease/<timestamp>`
  - 判定：
    - 环境性噪声说明：
    - 结论：PASS / FAIL
  - 未决问题与下一步：

- EN
  - Change summary (observation-only / traffic switched):
  - Code locations:
  - Rollback switch:
  - Fixed gate checklist (order must not change):
    1. `Remote: Build (Strict Version)` (recommended with `rbPreflight=1`)
       - Result: PASS / FAIL
       - Pass criteria check: `Local hash verify PASS` / `Golden PASS` / `referral check PASS` / `Step47 preclass preflight PASS`
       - Log/artifact path:
    2. `Test: CIDR Contract Bundle (prefilled)`
       - Result: PASS / FAIL
       - Pass criteria check: `body_status=pass` / `matrix_status=pass`
       - Log/artifact path:
    3. `Test: Redirect Matrix (10x6)`
       - Result: PASS / FAIL
       - Pass criteria check: `authMismatchFiles=0` / `errorFiles=0`
       - Log/artifact path:
    4. `Test: Step47 PreRelease Check (reserved, list file)` (with preclass gate enabled)
       - Result: PASS / FAIL
       - Pass criteria check: all `readiness` / `ab` / `rollback` / `preclass-p1-gate` steps are pass
       - Log/artifact path:
  - Evidence retention (minimum):
    - Main root: `out/artifacts/<timestamp>`
    - Preflight folder (when enabled): `out/artifacts/step47_preclass_preflight/<timestamp>`
    - Step47 folder: `out/artifacts/step47_prerelease/<timestamp>`
  - Decision:
    - Environmental noise notes:
    - Verdict: PASS / FAIL
  - Open issues and next actions:
