# whois Operations & Release Guide

Chinese version: `docs/OPERATIONS_CN.md`

This guide summarizes common day-to-day tasks: commit/push, remote cross-compilation + smoke tests, and publishing releases to GitHub and Gitee.

For link style conversion (absolute GitHub asset URLs ↔ relative repo paths) see: `docs/RELEASE_LINK_STYLE.md`.

Detailed release flow: `docs/RELEASE_FLOW_EN.md` | Chinese: `docs/RELEASE_FLOW_CN.md`

---

## One-click release (Windows PowerShell)

Entry script: `tools/release/full_release.ps1` (wraps the Bash script `tools/release/full_release.sh`).

Common usage:

- Default release (auto-bump patch + networked smoke test)
  ```powershell
  .\tools\release\full_release.ps1
  ```
- Custom smoke queries (space separated)
  ```powershell
  .\tools\release\full_release.ps1 -Queries "8.8.8.8 1.1.1.1"
  ```
- Skip smoke tests (faster)
  ```powershell
  .\tools\release\full_release.ps1 -NoSmoke
  ```
- Specify tag explicitly (e.g., v3.2.0)
  ```powershell
  .\tools\release\full_release.ps1 -Tag v3.2.0
  ```
- Specify lzispro path (when not at the same level as whois)
  ```powershell
  .\tools\release\full_release.ps1 -LzisproPath "D:\\LZProjects\\lzispro"
  ```
- Dry run (print steps only)
  ```powershell
  .\tools\release\full_release.ps1 -DryRun -NoSmoke -Queries "8.8.8.8 1.1.1.1"
  ```

Artifacts and logs:
- Seven static binaries will be synced to: `<lzispro>/release/lzispro/whois/`
- Detailed log: `whois/out/release_flow/<timestamp>/step1_remote.log`
- Strict mode: warnings are treated as failures by default (STRICT_WARN=1)

---

## VS Code Tasks

- Git: Quick Push
- Remote: Build and Sync whois statics (one-click remote build and sync seven static binaries)
- One-Click Release (invokes `tools/release/one_click_release.ps1` to update GitHub/Gitee Release; optionally skip creating/pushing a tag; can optionally run remote build + smoke + sync and commit/push static binaries)

Prompts for One-Click Release:
- `releaseVersion`: plain version (no `v`), e.g., `3.2.5`. Reads `docs/release_bodies/vX.Y.Z.md` and computes tag name.
- `releaseName`: display name for both GitHub/Gitee (default `whois v<version>`).
- `skipTag`: whether to skip creating/pushing the tag (`true`/`false`).
- `buildSync`: whether to perform remote build + smoke + sync + commit/push (default `true`).
- Remote build args: `rbHost/rbUser/rbKey/rbSmoke/rbQueries/rbSmokeArgs/rbGolden/rbCflagsExtra/rbSyncDir`.

Underlying command (PowerShell):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/release/one_click_release.ps1 `
  -Version <releaseVersion> -GithubName <releaseName> -GiteeName <releaseName> -SkipTagIf <skipTag> `
  -BuildAndSyncIf <buildSync> -RbHost <rbHost> -RbUser <rbUser> -RbKey '<rbKey>' `
  -RbSmoke <rbSmoke> -RbQueries '<rbQueries>' -RbSmokeArgs '<rbSmokeArgs>' -RbGolden <rbGolden> `
  -RbCflagsExtra '<rbCflagsExtra>' -RbSyncDir '<rbSyncDir>'
```

## Three-hop simulation & retry metrics (3.2.8)

Goal: deterministically exercise the `apnic → iana → arin` referral chain without breaking the header/tail contract, and observe connection-level retry metrics and error categorization.

Key flags (combine as needed):
- `--selftest-force-iana-pivot`: force a one-time pivot to IANA from the regional RIR; follow real referrals afterwards (enables the three-hop path).
- `--selftest-blackhole-arin` / `--selftest-blackhole-iana`: simulate final-hop/middle-hop connection timeouts.
- `--retry-metrics`: emit per-attempt and aggregate retry metrics.
- `-t 3 -r 0`: 3s connect timeout, disable generic retries (focus on internal multi-candidate attempts).
- `--ipv4-only`: optional, to increase determinism in some networks.

Example 1 (final hop failure: ARIN blackholed):
```powershell
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois; \
tools/remote/remote_build_and_test.sh -H <host> -u <user> -k '<key>' -r 1 -q '8.8.8.8' \
  -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 \
  -a '--host apnic --selftest-force-iana-pivot --selftest-blackhole-arin --retry-metrics -t 3 -r 0 --ipv4-only' -G 0 -E ''"
```
Output traits (excerpt):
```
[RETRY-METRICS-INSTANT] attempt=1 success=1 ...
[RETRY-METRICS-INSTANT] attempt=2 success=1 ...
Error: Query failed for 8.8.8.8 (connect timeout, errno=110|145)
[RETRY-METRICS] attempts=7 successes=2 failures=5 ... p95_ms≈3000
[RETRY-ERRORS] timeouts=5 refused=0 net_unreach=0 host_unreach=0 addr_na=0 interrupted=0 other=0
=== Authoritative RIR: whois.arin.net @ unknown ===
```

Example 2 (middle hop failure: IANA blackholed):
```powershell
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois; \
tools/remote/remote_build_and_test.sh -H <host> -u <user> -k '<key>' -r 1 -q '8.8.8.8' \
  -s '/d/LZProjects/lzispro/release/lzispro/whois' -P 1 \
  -a '--host apnic --selftest-force-iana-pivot --selftest-blackhole-iana --retry-metrics -t 3 -r 0 --ipv4-only' -G 0 -E ''"
```
Output traits (excerpt):
```
[RETRY-METRICS-INSTANT] attempt=1 success=1 ...
Error: Query failed for 8.8.8.8 (connect timeout, errno=110|145)
[RETRY-METRICS] attempts≈5–8 successes≥1 failures≥1 p95_ms≈3000
[RETRY-ERRORS] timeouts>0 others typically 0
=== Authoritative RIR: whois.iana.org @ unknown ===
```

Notes:
- Smoke timeout policy is metrics-aware: by default `SMOKE_TIMEOUT_ON_METRICS_SECS=45` for runs containing `--retry-metrics`. The runner sends SIGINT first and SIGKILL 5s later if still needed to avoid truncating aggregate metrics. Regular runs default to 8s (`SMOKE_TIMEOUT_DEFAULT_SECS`).
- Multi-sync: `-s` accepts multiple local targets separated by semicolons; the script normalizes and syncs to each.
- Metrics meaning:
  - `[RETRY-METRICS-INSTANT]`: per-attempt connect events.
  - `[RETRY-METRICS]`: aggregates (attempts/successes/failures/min/max/avg/p95/sleep_ms).
  - `[RETRY-ERRORS]`: connect() errno categories only. If the TCP connection succeeds but a later read times out, failures appear in `[RETRY-METRICS]` but `[RETRY-ERRORS]` may remain unchanged.
 - Architecture variance: ETIMEDOUT numeric value is 110 on most arches but 145 on MIPS/MIPS64; logic matches the symbolic constant so behavior is uniform. Use `strerror(errno)` for human-readable cause.

Errno quick reference:
| Symbol | Common value | MIPS/MIPS64 | Meaning |
|--------|--------------|-------------|---------|
| ETIMEDOUT | 110 | 145 | connect timeout (not read timeout) |
| ECONNREFUSED | 111 | 111 | connection refused (closed port/firewall) |
| EHOSTUNREACH | 113 | 113 | host unreachable (routing/ACL) |

> Only ETIMEDOUT numeric divergence observed in this smoke; no separate doc required—release notes hold mapping context.

Notes:
- Tokens: GitHub requires `GH_TOKEN` or `GITHUB_TOKEN`; Gitee requires `GITEE_TOKEN`. Missing tokens are skipped with a warning.
- If `buildSync=false`, the script skips remote build/smoke/sync-and-push and only updates tag/release.
- For SSH diagnostics in the remote script, set `WHOIS_DEBUG_SSH=1`.

### DNS debug quickstart (Phase 2/3)

For a quick, all-in-one view of DNS candidates, fallbacks, cache and health stats on a single binary, you can run:

```bash
whois-x86_64 --debug --retry-metrics --dns-cache-stats 8.8.8.8
whois-x86_64 --debug --retry-metrics --dns-cache-stats --selftest-blackhole-arin 8.8.8.8
```

These commands keep stdout’s header/tail contract intact, and stream DNS diagnostics to stderr:

- `[DNS-CAND]` – per-hop candidate sequence (host/IP) with type (`ipv4`/`ipv6`/`host`) and origin (`input`/`resolver`/`canonical`); useful to verify `--prefer-*` / `--ipv*-only` and `--dns-max-candidates` behaviour.
- `[DNS-FALLBACK]` – all non-primary dial paths (forced IPv4, known IPv4, empty-body retry, IANA pivot). When `--dns-no-fallback` is enabled, the corresponding branches log `action=no-op status=skipped` so you can compare behaviour with/without extra fallbacks.
- `[DNS-CACHE]` / `[DNS-CACHE-SUM]` – point-in-time and process-level DNS cache counters. `[DNS-CACHE-SUM] hits=.. neg_hits=.. misses=..` is printed exactly once per process when `--dns-cache-stats` is set and is ideal for a quick cache hit/miss eyeball.
- `[DNS-HEALTH]` (Phase 3) – per-host/per-family health snapshots (consecutive failures, remaining penalty window) backing the soft candidate reordering logic (“healthy-first”, never dropping candidates).
- `[LOOKUP_SELFTEST]` – when built with `-DWHOIS_LOOKUP_SELFTEST` the client prints this summary once per process whenever `--selftest` runs **or** any `--selftest-*` runtime fault toggle (fail-first, inject-empty, dns-negative, blackhole, force-iana-pivot, grep/seclog demos) is present. No separate `whois --selftest` prologue is required.

Note: on some libc/QEMU combinations, `[LOOKUP_SELFTEST]` and `[DEBUG]` lines can interleave or partially overwrite each other at the line level. This is expected for now; the format is intended for grep/eyeball debugging, not strict machine parsing.

#### Batch scheduler observability (WHOIS_BATCH_DEBUG_PENALIZE + golden_check)

> Release note pointer: the *Unreleased* section in `RELEASE_NOTES.md` now summarizes the "raw by default, health-first / plan-a opt-in" behavior and links here plus `docs/USAGE_EN.md` → “Batch start strategy” so readers scanning the release notes can jump straight to these commands and golden presets.

> Use this when you need deterministic `[DNS-BATCH] action=debug-penalize` (or similar) logs from a remote smoke run and want the golden checker to assert their presence.

1. Run the remote smoke with stdin batch input and debug penalties:
   ```bash
   WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net' \
   ./tools/remote/remote_build_and_test.sh \
     -H 10.0.0.199 -u larson -k '/c/Users/you/.ssh/id_rsa' \
     -r 1 -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' \
     -P 1 -a '--batch-strategy health-first --debug --retry-metrics --dns-cache-stats' \
     -F testdata/queries.txt -G 1 -E '-O3 -s'
   ```
   - `WHOIS_BATCH_DEBUG_PENALIZE` pre-populates the backoff table so the batch loop immediately emits `[DNS-BATCH] action=debug-penalize host=<...>` for the listed RIR servers.
   - `--batch-strategy health-first` is now required for `[DNS-BATCH] action=start-skip/force-last` because raw mode is the default when the flag is omitted.
   - `-F testdata/queries.txt` feeds a stable set of queries through stdin; the script auto-appends `-B` if missing and logs a warning.
   - `--debug --retry-metrics --dns-cache-stats` keeps all diagnostic channels on (`[DNS-BATCH]`, `[DNS-CAND]`, `[RETRY-*]`, `[DNS-CACHE-*]`).
2. After the run completes, validate both the standard header contract and the batch actions:
   ```bash
   tools/test/golden_check.sh \
     -l out/artifacts/20251126-084545/build_out/smoke_test.log \
     --batch-actions debug-penalize
   ```
   - `--batch-actions` accepts a comma-separated list (e.g., `debug-penalize,start-skip`). The script searches for `[DNS-BATCH] action=<name>` lines and reports `[golden][ERROR]` if any are missing.
   - Standard header/referral/tail checks still run; the command returns non-zero on any mismatch.
3. Reuse the same flow whenever you need deterministic batch observability—update the timestamped log path and extend `--batch-actions` as new actions (such as `force-last` or `start-skip`) are added to your test scenario.

#### Plan-A batch accelerator playbook (remote smoke + golden validation)

> Purpose: exercise `--batch-strategy plan-a` with deterministic cache hits/misses, and assert `[DNS-BATCH] action=plan-a-*` logs via `golden_check.sh`.

1. Run the remote smoke with plan-a enabled:
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

    ##### Quick golden re-checks via presets

    To avoid retyping long `golden_check.sh` commands during the three batch strategy suites, use `tools/test/golden_check_batch_presets.sh`:

    ```bash
    # raw default: header/referral/tail only
    ./tools/test/golden_check_batch_presets.sh raw -l ./out/artifacts/<ts_raw>/build_out/smoke_test.log

    # health-first: asserts debug-penalize + start-skip + force-last
    ./tools/test/golden_check_batch_presets.sh health-first -l ./out/artifacts/<ts_hf>/build_out/smoke_test.log

    # plan-a: asserts plan-a-cache/faststart/skip + debug-penalize
    ./tools/test/golden_check_batch_presets.sh plan-a -l ./out/artifacts/<ts_pa>/build_out/smoke_test.log
    ```

    All remaining arguments are forwarded to `golden_check.sh`, so you can still add `--query` overrides or `--strict`. The helper only injects the preset `--batch-actions` list, keeping the rest of the validation identical to the manual commands.

    ##### VS Code task: Golden Check Batch Suite

    Use the VS Code task **Golden Check: Batch Suite** (Terminal → Run Task) to run the raw/health-first/plan-a validations in sequence. The task prompts for three log paths plus optional extra args (defaults to `--strict`). Leave any path blank to skip that preset. Internally it invokes `tools/test/golden_check_batch_suite.ps1`, so the results mirror the manual helper above but run in one click.

    ##### PowerShell alias helper

    If you prefer the terminal, register the alias once per session:

    ```powershell
    ./tools/dev/register_golden_alias.ps1 -AliasName golden-suite
    ```

    Then run multi-log checks via:

    ```powershell
    golden-suite `
      -RawLog ./out/artifacts/20251128-000717/build_out/smoke_test.log `
      -HealthFirstLog ./out/artifacts/20251128-002850/build_out/smoke_test.log `
      -PlanALog ./out/artifacts/20251128-004128/build_out/smoke_test.log `
      -ExtraArgs --strict
    ```

    Add the alias script to your PowerShell profile to auto-load it when VS Code opens an integrated terminal.

    ##### Remote smoke + golden (raw / health-first / plan-a)

    Use `tools/test/remote_batch_strategy_suite.ps1` when you want the remote cross-build, smoke, sync, and golden checks for all three batch strategies in one go. Example:

    ```powershell
    ./tools/test/remote_batch_strategy_suite.ps1 `
      -Host 10.0.0.199 -User larson -KeyPath "/c/Users/you/.ssh/id_rsa" `
      -Queries "8.8.8.8 1.1.1.1" `
      -SyncDirs "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois" `
      -BatchInput testdata/queries.txt -CflagsExtra "-O3 -s"
    ```

    - Raw run uses `--debug --retry-metrics --dns-cache-stats` with no batch strategy flag (default raw mode).
    - Health-first run appends `--batch-strategy health-first`, pipes `testdata/queries.txt` via `-F`, and preloads penalties (`WHOIS_BATCH_DEBUG_PENALIZE=whois.arin.net,whois.iana.org,whois.ripe.net`).
    - Plan-A run appends `--batch-strategy plan-a`, reuses the stdin batch file, and applies penalties for arin/ripe.
    - Artifacts land in `out/artifacts/batch_raw|batch_health|batch_plan/<timestamp>/build_out/`; each run automatically feeds the resulting `smoke_test.log` to `golden_check_batch_presets.sh` (with `--strict` by default).
    - Flags: `-SkipRaw/-SkipHealthFirst/-SkipPlanA`, `-RemoteGolden` (also run the built-in `-G 1` during remote smoke), `-NoGolden`, `-DryRun`, and `-RemoteExtraArgs "-M nonzero"` for pacing assertions. Pass `-GoldenExtraArgs ''` to drop the default `--strict`.

    This script is the batch counterpart to the manual triple-command flow recorded in `docs/RFC-whois-client-split.md` for the 2025-11-28 smoke runs.
   - Penalize ARIN/RIPE only so the cached host alternates between “healthy fast start” and “penalized → fallback”.
   - `-F testdata/queries.txt` feeds deterministic stdin input; the script auto-appends `-B` when missing.
   - Keeping `--debug --retry-metrics --dns-cache-stats` ensures `[DNS-BATCH]`, `[RETRY-*]`, and `[DNS-CACHE-*]` all appear for troubleshooting.
2. Validate plan-a specific actions with the golden checker:
   ```bash
   tools/test/golden_check.sh \
     -l out/artifacts/20251126-161014/build_out/smoke_test.log \
     --batch-actions plan-a-cache,plan-a-faststart,plan-a-skip,debug-penalize
   ```
   Expected signals:
   - `plan-a-cache` – cache update/clear events.
   - `plan-a-faststart` – previous authoritative host reused successfully.
   - `plan-a-skip` – cached host penalized; strategy falls back to the health-first order.
   - `debug-penalize` – confirms the environment variable propagated to the remote binary.
   Header/referral/tail checks still run; the command exits non-zero if any required log is missing.
3. For comprehensive coverage, pair this plan-a log with a health-first log (see previous subsection) that asserts `start-skip` / `force-last`. Together they cover both the new accelerator and the baseline “healthy-first” backoff logic in CI.

---

## CI overview (GitHub Actions)

Workflows: `.github/workflows/build.yml`, `.github/workflows/publish-gitee.yml`.

Triggers:
- Push to main/master (regular build and artifact archive).
- Pull request (regular build and artifact archive).
- Push tag `vX.Y.Z` (runs `release` job in `build.yml`: create/update GitHub Release and upload assets).
- Manual dispatch (`workflow_dispatch`): rerun `release` job with an input tag; `publish-gitee.yml` is manual for GH→Gitee mirroring.

Main jobs:
- `build-linux`: builds `whois-x86_64-gnu` and uploads it as a build artifact.
- `release` (on tag push or manual):
  - Collects the seven static binaries from this repo `release/lzispro/whois/`.
  - Generates a merged `SHA256SUMS.txt`.
  - Ensures the GitHub Release exists, uploads/overwrites assets.
  - Optional: if Gitee secrets are configured, creates a Gitee release with GitHub download links.
  - To later switch links to repository-relative paths, use `relativize_static_binary_links.sh` (see `docs/RELEASE_LINK_STYLE.md`).

Secrets for Gitee (optional):
- `GITEE_OWNER` / `GITEE_REPO` / `GITEE_TOKEN` (and optional `GITEE_TARGET_COMMITISH`, default `master`).

Remote SSH note:
- The repo no longer ships SSH-based CI workflows. Prefer running `tools/remote/remote_build_and_test.sh` locally, or use self-hosted runners if CI must reach private hosts.
- For debugging SSH, set `WHOIS_DEBUG_SSH=1`.

---

## Artifacts housekeeping
Use `tools/dev/prune_artifacts.ps1` to remove old local artifacts (supports `-DryRun`).

---
## Tag and publish (optional)

Script: `tools/dev/tag_release.ps1`

Usage:
```powershell
./tools/dev/tag_release.ps1 -Tag v3.2.0 -Message "Release v3.2.0"
```

If you later want to switch those asset links to repository-relative paths, use `relativize_static_binary_links.sh` (see `docs/RELEASE_LINK_STYLE.md`).

### Re-create the same tag to refresh assets
Use this when you need to replace release assets (for example, update to the latest static binaries) without changing the version (e.g., `v3.2.7`).

Steps:
1) Delete the GitHub Release page of the same tag if it still exists (optional, assets can be clobbered by CI as well).
2) Delete the local and remote tag:
```powershell
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z
```
3) Prepare the latest static artifacts (choose one):
- Run the VS Code task “Remote: Build and Sync whois statics”; or
- Run One-Click Release with buildSync=true to rebuild, sync, and commit/push the seven statics into `release/lzispro/whois/`.
4) Re-create and push the same tag:
```powershell
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```
5) Wait for the release workflow to re-run and collect the seven static binaries and `SHA256SUMS.txt` from this repo `release/lzispro/whois/`.
6) To only update the release body without changing the tag:
```powershell
./tools/release/one_click_release.ps1 -Version X.Y.Z -SkipTagIf true
```
Note: The release process is decoupled from the lzispro repository. Assets are sourced from this repo `release/lzispro/whois/`, not from lzispro.

### New script: one_click_release.ps1
Path: `tools/release/one_click_release.ps1`

Purpose: one-click update of GitHub/Gitee Release body and display name; can optionally skip tag creation/push (same behavior as the VS Code task).

Examples:
```powershell
# Create/push tag + update both releases
./tools/release/one_click_release.ps1 -Version 3.2.5

# Update release body only (skip tagging)
./tools/release/one_click_release.ps1 -Version 3.2.5 -SkipTagIf true
```

Key parameters:
- GitHub update has retries (`-GithubRetry/-GithubRetrySec`) to wait for GH Actions to create the initial release record.


Prerequisites: configure secrets in GitHub repository Settings → Secrets
- `GITEE_OWNER`: Your Gitee user/organization name
- `GITEE_REPO`: The repository name on Gitee
- `GITEE_TOKEN`: Your Gitee PAT with permission to create releases
- Optional `GITEE_TARGET_COMMITISH`: If omitted, defaults to `master` (the branch/commit for Gitee to attach the tag when it does not exist)

Steps:
1) GitHub → Actions → select workflow `publish-gitee-manual`
2) Run workflow with inputs:
   - `tag`: e.g., `v3.2.0`
   - `target_commitish`: `master` by default (or a specific branch/commit)
3) Success criteria: the step "Publish release to Gitee (manual)" ends with `Gitee create release HTTP 201/200`.

Script: `tools/dev/quick_push.ps1`
Function: Automatically add/commit/pull --rebase/push all changes to remote.
Usage:
```powershell
Parameters:
- `-Message "message"`: Commit message, required.
- `-PushTags`: Push local tags.

Function: Remote build, sync artifacts, push tag. For official releases.
Usage:
```powershell
.	ools\release\full_release.ps1
```
Parameters: See above "One-click release" section.
Function: Package binaries, docs, source, license into dist directory for distribution.
Usage:
```powershell
.	ools\package_artifacts.ps1 -Version v3.2.1
```

### 4. Remote cross-compilation and smoke test
Script: `tools/remote/remote_build_and_test.sh`
Function: Remote multi-arch cross-compilation, auto sync artifacts, optional smoke test.
Usage:
```bash
tools/remote/remote_build_and_test.sh -H remote_host -u user -k private_key -t arch -r 1 -q "8.8.8.8" -s local_sync_dir
```
Parameters: See above "VS Code Tasks" and script comments.

### 5. Helper scripts
- `tools/dev/prune_artifacts.ps1`: Clean up old artifacts, supports DryRun.
- `tools/dev/tag_release.ps1`: Create and push tag, trigger release.

### Lookup selftests and empty-response fallback verification (3.2.7)

Purpose: validate the unified fallback strategy for connection failures/empty bodies under a real network, without altering the standard header/tail contract.

How to:
- Run built-in selftests (lookup included):
  ```powershell
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -a '--selftest'"
  ```
- Explicitly trigger the empty-response injection path (network required) with the local binary and CLI flag:
  ```powershell
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./out/build_out/whois-x86_64 --selftest --selftest-inject-empty"
  ```

Notes: lookup selftests are network-influenced and advisory; failures are recorded but do not change the selftest exit code. Core selftests (fold/redirect) still determine the overall `--selftest` result.

For more script details or usage examples, refer to this guide or ask the developer assistant.

---

## Developer notes: security log self-test hook (optional, off by default)

Purpose: Quickly validate that `--security-log` rate limiting works without crafting complex network scenarios. The hook only runs when you explicitly enable it and does not alter normal behavior.

Enable (both required):
- Build-time: compile whois with `-DWHOIS_SECLOG_TEST`
- Runtime: set environment variable `WHOIS_SECLOG_TEST=1`

Effect: Early in startup, the program emits a short burst of SECURITY events to stderr to trigger/observe rate limiting; stdout’s header/tail contract remains unchanged. The original `security_logging` setting is restored afterwards.

Examples (local Linux):
```bash
make CFLAGS_EXTRA="-DWHOIS_SECLOG_TEST"
WHOIS_SECLOG_TEST=1 ./whois-client --security-log --help
```

Examples (run on a remote Linux host via SSH):
```bash
ssh ubuntu@203.0.113.10 '
  cd ~/whois && \
  make CFLAGS_EXTRA="-DWHOIS_SECLOG_TEST" && \
  WHOIS_SECLOG_TEST=1 ./whois-client --security-log --help
'
```

Examples (Windows PowerShell, remote self-test, recommended):
```powershell
# 1) Prepare an isolated directory on the remote host
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@remote 'rm -rf ~/whois-wip; mkdir -p ~/whois-wip'

# 2) Upload the local whois project (adjust path, user, and host as needed)
scp -r -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "D:/LZProjects/whois/*" user@remote:~/whois-wip/

# 3) Build with the self-test macro and run the hook
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@remote `
  'cd ~/whois-wip && make clean || true; make CFLAGS_EXTRA=-DWHOIS_SECLOG_TEST && WHOIS_SECLOG_TEST=1 ./whois-client --security-log --help'
```

Notes:
- The executable name is `whois-client` (optionally `whois-client.static` for static builds).
- `--help` is used for quick exit while still exercising the hook.
- Requires OpenSSH on Windows so that `ssh/scp` are available in PowerShell.

Notes:
- `--help` is used to exit quickly while still exercising the hook; any other command line works as well.
- If you omit the build macro or the environment variable, the self-test hook will not run.

---

## Simple remote Makefile build & test (new)

When you just need a quick functional check on a plain Linux box (no cross toolchains), use the bundled `Makefile` remotely.

Prereqs: SSH access, `gcc` installed, and outbound whois (TCP 43) connectivity on the host.

Steps (Windows PowerShell; adjust paths/host/user):
```powershell
# 1) Prepare a clean directory on the remote host
ssh user@host 'rm -rf ~/whois-fast && mkdir -p ~/whois-fast'

# 2) Copy the minimum set (Makefile + src)
scp -r D:/LZProjects/whois/src D:/LZProjects/whois/Makefile user@host:~/whois-fast/

# 3) Build (generates whois-client by default)
ssh user@host 'cd ~/whois-fast && make -j$(nproc)'

# 4) Quick single query check
ssh user@host 'cd ~/whois-fast && ./whois-client 8.8.8.8 | head -n 40'

# 5) Batch check with projection/filtering (via stdin)
ssh user@host "cd ~/whois-fast && printf '8.8.8.8\n1.1.1.1\n' | ./whois-client -B -g 'netname|country' --grep 'GOOGLE|CLOUDFLARE' --grep-line"

# 6) Optional: static link (if toolchain supports it)
ssh user@host 'cd ~/whois-fast && make static'

# 7) Cleanup
ssh user@host 'rm -rf ~/whois-fast'
```

Tips:
- Use `CFLAGS_EXTRA` to inject extra flags, e.g., `make CFLAGS_EXTRA=-DWHOIS_SECLOG_TEST`.
- Batch mode prints the header/tail contract lines to ease manual review.
- This method is for quick validation only and won’t produce multi-arch static artifacts; prefer `tools/remote/remote_build_and_test.sh` for full cross builds.

---

## Developer notes: grep filtering self-test hook (optional)

Purpose: Validate wc_grep’s matching and continuation handling in both block and line modes without relying on live WHOIS responses.

Enable (both required):
- Build-time: compile with `-DWHOIS_GREP_TEST` (e.g., via `CFLAGS_EXTRA` or the remote launcher’s `-E`)
- Runtime: set environment `WHOIS_GREP_TEST=1`

Effect: On startup, a tiny built-in sample is filtered; the program emits lines like:
```
[GREPTEST] block mode: PASS
[GREPTEST] line mode (no-cont): PASS
[GREPTEST] line mode (keep-cont): PASS
```
Failures will include a short dump prefixed with `[GREPTEST-OUT]` for quick diagnostics.

Examples (local Linux):
```bash
make CFLAGS_EXTRA="-DWHOIS_GREP_TEST"
WHOIS_GREP_TEST=1 ./whois-client --help 2>&1 | grep GREPTEST || true
```

Examples (Windows → remote, using the provided launcher):
```powershell
# Append -X 1 to enable both compile-time and runtime (adds -DWHOIS_GREP_TEST; exports WHOIS_GREP_TEST=1)
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "tools/remote/remote_build_and_test.sh -H <host> -u <user> -k '<key>' -r 1 -q '8.8.8.8 1.1.1.1' -s '<sync_dir>' -P 1 -a '' -G 0 -E '-O3 -s' -X 1"
```

Heuristics (current behavior):
- Headers must start at column 0; any indented line is treated as a continuation.
- Block mode keeps continuations of matched blocks and suppresses unrelated ones.
- To avoid dropping a meaningful first continuation that looks header-like, the filter allows keeping at most one such indented header-like line globally; subsequent header-like continuations must match the regex to be kept.

Notes:
- Line mode honors `--grep-line` and optionally `--grep-line-keep-cont`; block mode is the default when line mode is off.
- These hooks do not affect normal output when the macro and env var are not both enabled.
