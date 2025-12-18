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

Latest two-pass smoke (2025-12-18 06:01 batch, default remote script params):
- Default args: no warnings, Golden PASS, log `out/artifacts/20251218-060136/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, Golden PASS, log `out/artifacts/20251218-060335/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-18 06:05 batch):
- raw: `out/artifacts/batch_raw/20251218-060541/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251218-060813/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251218-061031/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251218-061252/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all four strategies PASS, 2025-12-18 06:15 batch):
- raw: `out/artifacts/batch_raw/20251218-061539/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251218-061655/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251218-061813/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251218-061928/build_out/smoke_test.log`

###### 2025-12-18 rerun (02:27–02:44)

- Remote smoke (default): `out/artifacts/20251218-022709/build_out/smoke_test.log`, no alerts, `[golden] PASS`.
- Remote smoke (`--debug --retry-metrics --dns-cache-stats`): `out/artifacts/20251218-022915/build_out/smoke_test.log`, no alerts, `[golden] PASS`.
- Batch goldens (raw/health-first/plan-a/plan-b): all `[golden] PASS`.
  - raw: `out/artifacts/batch_raw/20251218-023144/build_out/smoke_test.log` (`golden_report_raw.txt`)
  - health-first: `out/artifacts/batch_health/20251218-023406/build_out/smoke_test.log` (`golden_report_health-first.txt`)
  - plan-a: `out/artifacts/batch_plan/20251218-023622/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
  - plan-b: `out/artifacts/batch_planb/20251218-023851/build_out/smoke_test.log` (`golden_report_plan-b.txt`)
- Selftest goldens (`--selftest-force-suspicious 8.8.8.8`): all `[golden-selftest] PASS`.
  - raw: `out/artifacts/batch_raw/20251218-024049/build_out/smoke_test.log`
  - health-first: `out/artifacts/batch_health/20251218-024202/build_out/smoke_test.log`
  - plan-a: `out/artifacts/batch_plan/20251218-024313/build_out/smoke_test.log`
  - plan-b: `out/artifacts/batch_planb/20251218-024433/build_out/smoke_test.log`

###### 2025-12-18 rerun (03:53–04:10)

- Remote smoke (default): `out/artifacts/20251218-035348/build_out/smoke_test.log`, no alerts, `[golden] PASS`.
- Remote smoke (`--debug --retry-metrics --dns-cache-stats`): `out/artifacts/20251218-035556/build_out/smoke_test.log`, no alerts, `[golden] PASS`.
- Batch goldens (raw/health-first/plan-a/plan-b): all `[golden] PASS`.
  - raw: `out/artifacts/batch_raw/20251218-035754/build_out/smoke_test.log` (`golden_report_raw.txt`)
  - health-first: `out/artifacts/batch_health/20251218-040017/build_out/smoke_test.log` (`golden_report_health-first.txt`)
  - plan-a: `out/artifacts/batch_plan/20251218-040237/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
  - plan-b: `out/artifacts/batch_planb/20251218-040457/build_out/smoke_test.log` (`golden_report_plan-b.txt`)
- Selftest goldens (`--selftest-force-suspicious 8.8.8.8`): all `[golden-selftest] PASS`.
  - raw: `out/artifacts/batch_raw/20251218-040650/build_out/smoke_test.log`
  - health-first: `out/artifacts/batch_health/20251218-040808/build_out/smoke_test.log`
  - plan-a: `out/artifacts/batch_plan/20251218-040926/build_out/smoke_test.log`
  - plan-b: `out/artifacts/batch_planb/20251218-041037/build_out/smoke_test.log`

###### 2025-12-18 rerun (04:37–04:54)

- Remote smoke (default): `out/artifacts/20251218-043743/build_out/smoke_test.log`, no alerts, `[golden] PASS`.
- Remote smoke (`--debug --retry-metrics --dns-cache-stats`): `out/artifacts/20251218-043943/build_out/smoke_test.log`, no alerts, `[golden] PASS`.
- Batch goldens (raw/health-first/plan-a/plan-b): all `[golden] PASS`.
  - raw: `out/artifacts/batch_raw/20251218-044119/build_out/smoke_test.log` (`golden_report_raw.txt`)
  - health-first: `out/artifacts/batch_health/20251218-044344/build_out/smoke_test.log` (`golden_report_health-first.txt`)
  - plan-a: `out/artifacts/batch_plan/20251218-044606/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
  - plan-b: `out/artifacts/batch_planb/20251218-044820/build_out/smoke_test.log` (`golden_report_plan-b.txt`)
- Selftest goldens (`--selftest-force-suspicious 8.8.8.8`): all `[golden-selftest] PASS`.
  - raw: `out/artifacts/batch_raw/20251218-045027/build_out/smoke_test.log`
  - health-first: `out/artifacts/batch_health/20251218-045138/build_out/smoke_test.log`
  - plan-a: `out/artifacts/batch_plan/20251218-045250/build_out/smoke_test.log`
  - plan-b: `out/artifacts/batch_planb/20251218-045407/build_out/smoke_test.log`

###### 2025-12-18 rerun (07:00–07:24)

- Remote smoke (default): `out/artifacts/20251218-070023/build_out/smoke_test.log`, no alerts, `[golden] PASS`.
- Remote smoke (`--debug --retry-metrics --dns-cache-stats`): `out/artifacts/20251218-070733/build_out/smoke_test.log`, no alerts, `[golden] PASS`.
- Batch goldens (raw/health-first/plan-a/plan-b): all `[golden] PASS`.
  - raw: `out/artifacts/batch_raw/20251218-070940/build_out/smoke_test.log` (`golden_report_raw.txt`)
  - health-first: `out/artifacts/batch_health/20251218-071155/build_out/smoke_test.log` (`golden_report_health-first.txt`)
  - plan-a: `out/artifacts/batch_plan/20251218-071414/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
  - plan-b: `out/artifacts/batch_planb/20251218-071627/build_out/smoke_test.log` (`golden_report_plan-b.txt`)
- Selftest goldens (`--selftest-force-suspicious 8.8.8.8`): all four strategies `[golden-selftest] PASS`.
  - raw: `out/artifacts/batch_raw/20251218-072038/build_out/smoke_test.log`
  - health-first: `out/artifacts/batch_health/20251218-072149/build_out/smoke_test.log`
  - plan-a: `out/artifacts/batch_plan/20251218-072302/build_out/smoke_test.log`
  - plan-b: `out/artifacts/batch_planb/20251218-072414/build_out/smoke_test.log`

Plan-b note: when a cached entry is penalized, the cache is cleared immediately and the next query logs `plan-b-empty` before picking healthy candidates; golden scripts already cover this behavior.

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

### Network retry context (3.2.10+)

- Each process now instantiates **one** `wc_net_context` during runtime init and hands the pointer to every lookup entry point (single query, batch stdin loop, automatic lookup selftest warm-up). As a result all `[RETRY-METRICS]`, `[RETRY-METRICS-INSTANT]`, and `[RETRY-ERRORS]` counters are continuous within the process, even if a `--selftest-*` hook fires before the real workload.
- Remote smoke runs (`tools/remote/remote_build_and_test.sh`) naturally start a fresh process per architecture, so counters reset between smoke rounds. When reproducing an issue locally, restart the binary (or open a new terminal) before each scenario if you need a clean slate; there is no in-process “metrics reset”.
- Batch stdin and the autoselftest warm-up share the same pacing budget. If you enable `--selftest-force-suspicious` or `--selftest-force-private`, expect the very first `[RETRY-METRICS-INSTANT] total_attempts` to be `>=1` before your stdin queries start—this is by design and should not be treated as a regression.
- Golden expectations: the Usage guide (`docs/USAGE_EN.md` → “Network retry context (3.2.10+)”) documents the above behaviour. When writing `golden_check.sh` assertions for `[RETRY-*]`, assert the **presence** of metrics rather than assuming attempts start at 1 after the warm-up. If a scenario demands “fresh counters”, run a separate remote smoke or invoke `whois-x86_64` once per test vector.

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

These commands keep stdout’s header/tail contract intact, and stream DNS diagnostics to stderr. Combine them with the mixed preference flags when you need hop-aware IPv4/IPv6 sequencing:

```bash
whois-x86_64 --prefer-ipv4-ipv6 --debug --retry-metrics --dns-cache-stats 8.8.8.8
whois-x86_64 --prefer-ipv6-ipv4 --debug --retry-metrics --dns-cache-stats --selftest-force-suspicious 8.8.8.8
```

When either `--prefer-ipv4-ipv6` or `--prefer-ipv6-ipv4` is active (they are mutually exclusive with `--prefer-*` / `--ipv*-only`), lookup/referral hops switch priorities per hop and every DNS log line gains a `pref=` tag so you can confirm the execution order:

```
[DNS-CAND] hop=0 pref=v4-then-v6-hop0 ...
[DNS-FALLBACK] hop=1 action=known-ip pref=v4-then-v6-hop1 ...
```

These fields appear even when mixed flags are off (`pref=v6-first`, `pref=v4-first`) so golden checks can assert the expected family order.

To automate the assertion, run `tools/test/golden_check.sh --pref-labels v4-then-v6-hop0,v4-then-v6-hop1` (labels accept bare values or full `pref=...`), which now guarantees mixed-preference runs emit the expected tags.

DNS diagnostics reference:

- `[DNS-CAND]` – per-hop candidate sequence (host/IP) with type (`ipv4`/`ipv6`/`host`) and origin (`input`/`resolver`/`canonical`); from 2025-12-02 onward it always includes `pref=` labels (`pref=v4-then-v6-hop0`, `pref=v6-first`, etc.) so you can validate mixed preference flags and referral hops.
  - When the client auto-compensates for ARIN IPv4 literals you will see `pref=arin-v4-auto`, meaning `wc_lookup` prepended `n <query>` and fired a single 1.2s (no-retry) IPv4 probe before falling back to the normal order, e.g.:
    ```
    [DNS-CAND] hop=1 server=whois.arin.net rir=arin idx=0 target=104.44.135.12 type=ipv4 origin=resolver pref=arin-v4-auto
    [DNS-FALLBACK] hop=1 cause=connect-fail action=candidate domain=whois.arin.net target=104.44.135.12 status=fail errno=10060 pref=arin-v4-auto
    ```
    After the short probe the loop resumes IPv6/other referrals so watchdogs on IPv4-only failures are avoided. See `out/artifacts/20251204-110057/build_out/smoke_test.log` for a full trace.
- `[DNS-FALLBACK]` – all non-primary dial paths (forced IPv4, known IPv4, empty-body retry, IANA pivot). When `--dns-no-fallback` is enabled, the corresponding branches log `action=no-op status=skipped` so you can compare behaviour with/without extra fallbacks.
- `[DNS-CACHE]` / `[DNS-CACHE-SUM]` – point-in-time and process-level DNS cache counters. `[DNS-CACHE-SUM] hits=.. neg_hits=.. misses=..` is printed exactly once per process when `--dns-cache-stats` is set and is ideal for a quick cache hit/miss eyeball.
- `[DNS-CACHE-LGCY]` – **removed**; legacy shim is retired and no longer emits telemetry. `[DNS-CACHE-SUM]` remains sourced from `wc_dns`. To debug the old path, use a dedicated branch or local patch instead of runtime knobs.
- `[DNS-HEALTH]` (Phase 3) – per-host/per-family health snapshots (consecutive failures, remaining penalty window) backing the soft candidate reordering logic (“healthy-first”, never dropping candidates).
- `[LOOKUP_SELFTEST]` – when built with `-DWHOIS_LOOKUP_SELFTEST` the client prints this summary once per process whenever `--selftest` runs **or** any `--selftest-*` runtime fault toggle (fail-first, inject-empty, dns-negative, blackhole, force-iana-pivot, grep/seclog demos) is present. No separate `whois --selftest` prologue is required.

Note: on some libc/QEMU combinations, `[LOOKUP_SELFTEST]` and `[DEBUG]` lines can interleave or partially overwrite each other at the line level. This is expected for now; the format is intended for grep/eyeball debugging, not strict machine parsing.

###### 2025-12-07 addenda

- Remote referral guard: `tools/remote/remote_build_and_test.sh` now writes per-host referral logs (`whois.iana.org/arin/afrinic`) and records capture details plus directory listing in `referral_debug.log` while keeping stderr quiet. Outputs live under `out/artifacts/<ts>/build_out/referral_checks/`.
- Selftest golden expectations: `tools/test/selftest_golden_suite.ps1` and `remote_batch_strategy_suite.ps1` synthesize `--expect action=force-suspicious,query=8.8.8.8` automatically when `SelftestActions` is `force-suspicious,8.8.8.8`, so you no longer need to pass `SelftestExpectations` explicitly.

###### 2025-12-14 smoke rerun snapshot

- Regular and debug remote smokes both `[golden] PASS`: `out/artifacts/20251214-201532/build_out/smoke_test.log` (default) and `out/artifacts/20251214-201927/build_out/smoke_test.log` (`--debug --retry-metrics --dns-cache-stats`).
- Batch strategy goldens all PASS (raw/health-first/plan-a/plan-b): `out/artifacts/batch_raw/20251214-202150/.../{smoke_test.log,golden_report_raw.txt}`, `batch_health/20251214-202440/.../{smoke_test.log,golden_report_health-first.txt}`, `batch_plan/20251214-202704/.../{smoke_test.log,golden_report_plan-a.txt}`, `batch_planb/20251214-202940/.../{smoke_test.log,golden_report_plan-b.txt}`.
- Selftest golden with `--selftest-force-suspicious 8.8.8.8` (all four strategies) `[golden-selftest] PASS`: `out/artifacts/batch_raw/20251214-203201/.../smoke_test.log`, `batch_health/20251214-203328/.../smoke_test.log`, `batch_plan/20251214-203454/.../smoke_test.log`, `batch_planb/20251214-203615/.../smoke_test.log`.

##### WHOIS_LOOKUP_SELFTEST remote playbook (2025-12-04)

> Goal: bake the “regular golden first, selftest golden second” workflow into a repeatable recipe for the AfriNIC IPv6 parent guard fix, and document the pitfall where `--selftest` short-circuits headers.

1. **Regular remote golden (no selftest hook)**
  ```powershell
  & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois; \\
    tools/remote/remote_build_and_test.sh \\
     -H 10.0.0.199 -u larson -k '/c/Users/<you>/.ssh/id_rsa' \\
     -r 1 -q '8.8.8.8 1.1.1.1 143.128.0.0' \\
     -s '/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois' -P 1 \\
     -a '--debug --retry-metrics --dns-cache-stats' \\
     -G 1 -E '-O3 -s -DWHOIS_LOOKUP_SELFTEST'"
  ```
  - Same binary now ships with `-DWHOIS_LOOKUP_SELFTEST`, but we purposely skip any `--selftest-*` toggles so stdout still prints the canonical header/referral/tail contract and `golden_check.sh` stays green.
  - Evidence: `out/artifacts/20251204-155440/build_out/smoke_test.log` (default) and `out/artifacts/20251204-155655/build_out/smoke_test.log` (extra debug metrics).

2. **Selftest golden (hooks enabled, traditional golden skipped)**
  ```powershell
  tools/test/selftest_golden_suite.ps1 \
    -KeyPath "c:\\Users\\<you>\\.ssh\\id_rsa" \
    -SmokeExtraArgs "--debug --retry-metrics --dns-cache-stats --selftest-force-suspicious 8.8.8.8" \
    -SelftestActions "force-suspicious,8.8.8.8" \
    -SelftestExpectations "action=force-suspicious,query=8.8.8.8" \
    -NoGolden
  ```
  - `-NoGolden` tells `remote_batch_strategy_suite.ps1` (which the helper calls under the hood) to only grab logs; this removes the noisy `[golden][ERROR] header not found` spam caused by the forced selftest short-circuit. The tail-end `golden_check_selftest.sh` handles the real assertions.
  - Latest artefacts: raw `out/artifacts/batch_raw/20251204-171214/build_out/smoke_test.log`, plan-a `.../batch_plan/20251204-171519/...`, health-first `.../batch_health/20251204-171334/...`; plan-b now emits `[DNS-BATCH] plan-b-*` (force-start/fallback/force-override/start-skip/force-last) and is fully asserted by the preset.
  - VS Code shortcut: `Ctrl+Shift+P` → `Tasks: Run Task` → **Selftest Golden Suite**. The task now reuses the same `rbHost/rbUser/rbKey/rbQueries/rbCflagsExtra` inputs as the remote build tasks, auto-injects `-NoGolden`, and pipes whatever you enter for `selftestActions/selftestSmokeExtra/...` straight to the helper. `rbKey` accepts either MSYS (`/c/Users/...`) or Windows (`C:\\Users\\...`) paths, so you can paste whichever version you already use for remote builds.

3. **Pitfall call-outs**
  - Do **not** append plain `--selftest` to the regular golden command. The flag exits immediately after running the built-in selftests, so the usual `=== Query ... ===` / `=== Authoritative RIR ... ===` lines never print and the golden checker inevitably fails.
  - To emit `[LOOKUP_SELFTEST]` while keeping the header contract, prefer `--selftest-force-suspicious` / `--selftest-force-private` (or any other runtime hook) so only stderr carries the diagnostic tags.
  - If you must run `whois --selftest` for reference output, do it in a separate session (or run `selftest_golden_suite.ps1 -SkipRemote -SelftestExpectations ...`) instead of mixing it with header/tail validation.

##### Referral sanity check (143.128.0.0)

When you need to sanity-check multi-hop redirects (especially early AfriNIC transfers that still mention `parent: 0.0.0.0 - 255.255.255.255`), run the following trio on the same build:

```bash
whois-x86_64 -h iana 143.128.0.0 --debug --retry-metrics --dns-cache-stats
whois-x86_64 -h arin 143.128.0.0 --debug --retry-metrics --dns-cache-stats
whois-x86_64 -h afrinic 143.128.0.0 --debug --retry-metrics --dns-cache-stats
```

- Expected flow: `IANA → ARIN → AFRINIC`, `ARIN → AFRINIC`, `AFRINIC` respectively; each tail line should end with `=== Authoritative RIR: whois.afrinic.net @ <ip|unknown> ===`.
- These runs double-check that the “Whole IPv4 space/0.0.0.0/0” guard only fires when the literal appears on `inetnum:`/`NetRange:` lines. AfriNIC’s `parent:` metadata no longer causes extra IANA pivots.
- Reference logs live under `out/iana-143.128.0.0`, `out/arin-143.128.0.0`, and `out/afrinic-143.128.0.0`; they were captured alongside the 2025-12-04 smoke suite (`out/artifacts/20251204-140138/...`, `-140402/...`, `batch_{raw,plan,health}/20251204-14{0840,1123,1001}/...`, `batch_{raw,plan,health}/20251204-1414**/...`).
- Automation: run `tools/test/referral_143128_check.sh` (optional `--iana-log/--arin-log/--afrinic-log`) to assert that each captured log still lands on AfriNIC and keeps the expected Additional query chain.
- Remote runs now include this gate by default: whenever `tools/remote/remote_build_and_test.sh` runs with `-r 1` (and `-L` is left at the default), it records `build_out/referral_143128/{iana,arin,afrinic}.log` on the remote host and executes `referral_143128_check.sh` locally. Use `-L 0`/`REFERRAL_CHECK=0` to skip when AfriNIC is unreachable.

#### Batch scheduler observability (WHOIS_BATCH_DEBUG_PENALIZE + golden_check)

> Release note pointer: the *Unreleased* section in `RELEASE_NOTES.md` now summarizes the "raw by default, health-first / plan-a opt-in" behavior and links here plus `docs/USAGE_EN.md` → “Batch start strategy” so readers scanning the release notes can jump straight to these commands and golden presets.

> Use this when you need deterministic `[DNS-BATCH] action=debug-penalize` (or similar) logs from a remote smoke run and want the golden checker to assert their presence.

> Latest evidence (2025-12-12 18:00 batch): plan-b active with cache-window tags. Remote smokes at `out/artifacts/20251212-175111` (default) and `out/artifacts/20251212-180052` (debug/metrics) plus batch golden `out/artifacts/batch_{raw,health,plan,planb}/20251212-180251..181025/...` and selftest golden `out/artifacts/batch_{raw,health,plan,planb}/20251212-181248..181640/...` all PASS. Plan-b emits `plan-b-hit/plan-b-stale/plan-b-empty` in addition to existing `plan-b-*` actions; when the cached start host is penalized the cache is cleared immediately, so the next query will first log `plan-b-empty` before picking a healthy candidate.

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
     --batch-actions debug-penalize \
     --pref-labels v4-then-v6-hop0,v4-then-v6-hop1
   ```
  - `--batch-actions` accepts a comma-separated list (e.g., `debug-penalize,start-skip`). The script searches for `[DNS-BATCH] action=<name>` lines and reports `[golden][ERROR]` if any are missing.
  - `--backoff-actions` (new) enforces `[DNS-BACKOFF] action=<name>` presence—use it to assert `skip`/`force-last` penalties or any other backoff tag your scenario should emit.
  - `--pref-labels` asserts the hop-aware IPv4/IPv6 preference logs (accepts bare labels or `pref=...` strings). Use it whenever a run enables `--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4` so the mixed-order tags stay golden-protected.
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

    To avoid retyping long `golden_check.sh` commands during the four batch strategy suites, use `tools/test/golden_check_batch_presets.sh`:

    ```bash
    # raw default: header/referral/tail only
    ./tools/test/golden_check_batch_presets.sh raw --selftest-actions force-suspicious,force-private --pref-labels v4-then-v6-hop0,v4-then-v6-hop1 -l ./out/artifacts/<ts_raw>/build_out/smoke_test.log

    # health-first: asserts debug-penalize + start-skip + force-last + DNS backoff
    ./tools/test/golden_check_batch_presets.sh health-first --selftest-actions force-suspicious,force-private --pref-labels v4-then-v6-hop0,v4-then-v6-hop1 -l ./out/artifacts/<ts_hf>/build_out/smoke_test.log

    # plan-a: asserts plan-a-cache/faststart/skip + debug-penalize
    ./tools/test/golden_check_batch_presets.sh plan-a --selftest-actions force-suspicious,force-private --pref-labels v4-then-v6-hop0,v4-then-v6-hop1 -l ./out/artifacts/<ts_pa>/build_out/smoke_test.log

    # plan-b: asserts plan-b-* + debug-penalize (if the preset is enabled)
    ./tools/test/golden_check_batch_presets.sh plan-b --selftest-actions force-suspicious,force-private --pref-labels v4-then-v6-hop0,v4-then-v6-hop1 -l ./out/artifacts/<ts_pb>/build_out/smoke_test.log
    ```

    The helper now also accepts `--pref-labels list` (comma separated, same syntax as `golden_check.sh`) and forwards it downstream, so mixed preference runs no longer require editing every command. Leave the flag out (or pass `--pref-labels NONE`) if your batch suite sticks to the default IPv6-first behavior. Any additional arguments after `-l ...` continue to pass straight to `golden_check.sh`.

    > **Heads-up:** smoke logs generated before 2025-12-02 did not yet include the `pref=` field, so `--pref-labels` will intentionally raise “missing preference label”. Skip the flag when auditing pre-instrumentation artifacts; re-enable it for current runs to keep hop-aware tags under golden coverage.

    ##### VS Code task: Golden Check Batch Suite

    Use the VS Code task **Golden Check: Batch Suite** (Terminal → Run Task) to run the raw/health-first/plan-a/plan-b validations in sequence. The task now prompts for a dedicated “Preference labels” field (comma list, `NONE` to skip) and forwards it as `--pref-labels ...`; it also keeps the previous “Extra args” textbox (defaults to `--strict`). Leave any log path blank to skip that preset. Internally it invokes `tools/test/golden_check_batch_suite.ps1`, so the results mirror the manual helper above but run in one click.

    ##### PowerShell alias helper

    If you prefer the terminal, register the alias once per session:

    ```powershell
    ./tools/dev/register_golden_alias.ps1 -AliasName golden-suite
    ```

    #### Selftest golden suite (raw / health-first / plan-a / plan-b)

    Use `tools/test/selftest_golden_suite.ps1` when you need to prove that a forced selftest hook short-circuits the query _before_ the usual header/referral/tail contract. The wrapper first runs `remote_batch_strategy_suite.ps1` (unless `-SkipRemote` is supplied), then executes `tools/test/golden_check_selftest.sh` for each freshly fetched log.

    1. Full example (remote fetch + `[SELFTEST] action=*` assertions):
      ```powershell
      powershell -NoProfile -ExecutionPolicy Bypass `
        -File tools/test/selftest_golden_suite.ps1 `
        -SelftestActions "force-suspicious,8.8.8.8" `
        -SmokeExtraArgs "--selftest-force-suspicious 8.8.8.8" `
        -SelftestExpectations "action=force-suspicious,query=8.8.8.8"
      ```
      - `-SelftestActions` keeps `golden_check.sh` in sync with the fault you injected so the traditional batch presets know which `[SELFTEST] action=...` lines to expect.
      - `-SmokeExtraArgs` appends the actual CLI toggles (e.g., `--selftest-force-suspicious '*'`) to every remote smoke command, guaranteeing that the `[SELFTEST]` logs exist in `smoke_test.log`.
      - `-SelftestExpectations`, `-ErrorPatterns`, and `-TagExpectations` accept semicolon-separated lists that become `--expect`, `--require-error`, and `--require-tag component regex` arguments for `golden_check_selftest.sh`. Leave them blank or type `NONE` to skip a category.
      - `-SkipRemote` allows a “golden only” pass that simply picks the newest timestamped logs under `out/artifacts/batch_{raw,health,plan,planb}`.
      - `-NoGolden` forwards to `remote_batch_strategy_suite.ps1` so the upstream batch runs skip `golden_check.sh` (no `[golden][ERROR]` noise when a forced selftest short-circuits the query). Use this whenever only the selftest assertions matter.
    2. The script prints `[golden-selftest] PASS/FAIL` per strategy and exits with rc=3 whenever at least one expectation is missing, making it safe for automation.
    3. Evidence from 2025-12-12 (plan-b cache-window tags enabled; every run includes `--selftest-force-suspicious 8.8.8.8`):
      - raw: `out/artifacts/batch_raw/20251212-181248/build_out/smoke_test.log`
      - health-first: `out/artifacts/batch_health/20251212-181400/build_out/smoke_test.log`
      - plan-a: `out/artifacts/batch_plan/20251212-181525/build_out/smoke_test.log`
      - plan-b: `out/artifacts/batch_planb/20251212-181640/build_out/smoke_test.log`
      Plan-b selftest golden now asserts the new `[DNS-BATCH] action=plan-b-hit|plan-b-stale|plan-b-empty` tags in addition to existing `plan-b-*`; other strategies remain unchanged.

    ##### VS Code task: Selftest Golden Suite

    Terminal → Run Task → **Selftest Golden Suite** mirrors the command above. The task prompts for:

    - `SelftestActions` (forwarded to the batch golden presets; default `force-suspicious,8.8.8.8`).
    - `SmokeExtraArgs` (appended to each remote smoke run; default `--selftest-force-suspicious 8.8.8.8`).
    - Optional expectation/error/tag lists (semicolon separated, accepts `NONE`).

    The task always performs the remote fetch; rerun the script manually with `-SkipRemote` for quick local-only checks.

### Selftest fault profile & `[SELFTEST] action=force-*` logs (3.2.10+)

- `wc_selftest_fault_profile_t` now owns every runtime injection toggle (dns-negative, blackholes, force-iana, fail-first). DNS/lookup/net modules poll the shared version counter instead of duplicating `extern` globals, so CLI changes take effect atomically between referrals.
- `--selftest-force-suspicious <query|*>` and `--selftest-force-private <query|*>` feed through the same controller. Pass a literal to target one line or `*` to cover the entire run. Each forced hit prints a deterministic stderr tag (`[SELFTEST] action=force-suspicious|force-private query=<value>`) before the usual security log, making it safe for scripted assertions.
- Local repro example (stdin batch for reproducibility):

  ```bash
  printf '1.1.1.1\n10.0.0.8\n' | \
    ./out/build_out/whois-x86_64 -B \
      --selftest-force-suspicious '*' --selftest-force-private 10.0.0.8
  # stderr excerpt:
  # [SELFTEST] action=force-suspicious query=1.1.1.1
  # [SELFTEST] action=force-private query=10.0.0.8
  ```

  (For remote smoke, feed the same queries via `-F testdata/queries.txt` and append the two `--selftest-force-*` flags to `-a '...'`.)
- Golden coverage: `tools/test/golden_check.sh` does not yet assert `[SELFTEST] action=force-*`. Until a preset lands, add a post-run `grep '[SELFTEST] action=force-' out/artifacts/<ts>/build_out/smoke_test.log` step to your playbook and mention the result in `docs/RFC-whois-client-split.md` or the release notes when filing evidence.
    Then run multi-log checks via:

    ```powershell
    golden-suite `
      -RawLog ./out/artifacts/20251128-000717/build_out/smoke_test.log `
      -HealthFirstLog ./out/artifacts/20251128-002850/build_out/smoke_test.log `
      -PlanALog ./out/artifacts/20251128-004128/build_out/smoke_test.log `
      -PlanBLog ./out/artifacts/20251210-120101/build_out/smoke_test.log `
      -ExtraArgs --strict
    ```

    Add the alias script to your PowerShell profile to auto-load it when VS Code opens an integrated terminal.

    ##### Remote smoke + golden (raw / health-first / plan-a / plan-b)

    Use `tools/test/remote_batch_strategy_suite.ps1` when you want the remote cross-build, smoke, sync, and golden checks for all four batch strategies in one go. Example:

    ```powershell
    ./tools/test/remote_batch_strategy_suite.ps1 `
      -Host 10.0.0.199 -User larson -KeyPath "/c/Users/you/.ssh/id_rsa" `
      -Queries "8.8.8.8 1.1.1.1" `
      -SyncDirs "/d/LZProjects/lzispro/release/lzispro/whois;/d/LZProjects/whois/release/lzispro/whois" `
      -BatchInput testdata/queries.txt -CflagsExtra "-O3 -s" -SelftestActions "force-suspicious,force-private"
    ```

    - Raw run uses `--debug --retry-metrics --dns-cache-stats` with no batch strategy flag (default raw mode).
    - Health-first run appends `--batch-strategy health-first`, pipes `testdata/queries.txt` via `-F`, and preloads penalties (`WHOIS_BATCH_DEBUG_PENALIZE=whois.arin.net,whois.iana.org,whois.ripe.net`).
    - Plan-A run appends `--batch-strategy plan-a`, reuses the stdin batch file, and applies penalties for arin/ripe.
    - Plan-B run appends `--batch-strategy plan-b`, reuses the stdin batch file, and keeps the same penalties to exercise plan-b cache/fallback branches.
    - Artifacts land in `out/artifacts/batch_raw|batch_health|batch_plan|batch_planb/<timestamp>/build_out/`; each run automatically feeds the resulting `smoke_test.log` to `golden_check_batch_presets.sh` (with `--strict` by default).
    - Flags: `-SkipRaw/-SkipHealthFirst/-SkipPlanA/-SkipPlanB`, `-RemoteGolden` (also run the built-in `-G 1` during remote smoke), `-NoGolden`, `-DryRun`, `-RemoteExtraArgs "-M nonzero"` for pacing assertions, plus `-SelftestActions "force-suspicious,force-private"` (or any comma list) to auto-append `--selftest-actions ...` when invoking `golden_check_batch_presets.sh`. Pass `-GoldenExtraArgs ''` to drop the default `--strict`. Use `-SmokeExtraArgs "--selftest-force-suspicious '*' --selftest-force-private 10.0.0.8"` (or similar) when you want every remote smoke run to include additional client flags without rewriting the base `-a '...'` string. Use `-PrefLabels "v4-then-v6-hop0,v4-then-v6-hop1"` (default `NONE`) to forward `--pref-labels ...` to every downstream `golden_check.sh`, ensuring hop-aware IPv4/IPv6 tags stay asserted during remote batch suites.

    This script is the batch counterpart to the manual triple-command flow recorded in `docs/RFC-whois-client-split.md` for the 2025-11-28 smoke runs, with plan-b now wrapped as the fourth leg.
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

#### Local batch quick playbook cross-reference (3.2.10+)

- The day-to-day “raw → health-first → plan-a → plan-b” command snippets now live in `docs/USAGE_EN.md` → “Batch start strategy” + “Batch strategy quick playbook”. Reference those when you need a minimal local repro without the remote suite wrapper. Each entry shows the exact stdin + flag combo plus the recommended `golden_check.sh preset=batch-smoke-*` invocation.
- `tools/test/golden_check.sh` accepts `--selftest-actions` alongside `--batch-actions` and `--backoff-actions`. Use the latter when you need `[DNS-BACKOFF] action=skip|force-last` (or any other penalty tag) to be part of the golden assertions in addition to header/tail validation.
- Remote smoke wrappers (`remote_batch_strategy_suite.ps1`, `remote_build_and_test.sh`) simply forward any `--selftest-actions` tail args to `golden_check.sh`, so there is no extra wiring required—keep the presets in sync with the USAGE guide to avoid drift between local and remote playbooks.

###### LACNIC passthrough note

- When you force `-h lacnic` for non-LACNIC IPs, the server proxies the authoritative RIR body (e.g., 1.1.1.1 shows APNIC content, 8.8.8.8/143.128.0.0 shows ARIN) while the tail still reads `Authoritative RIR: whois.lacnic.net`. This comes from the server itself, not from our client fallbacks.
- If you need the tail to match the true authoritative RIR, let the default flow start at IANA and follow referrals, or query the target RIR directly (e.g., `-h apnic` / `-h arin`) instead of relying on LACNIC passthrough.

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
Parameters: See above "VS Code Tasks" and script comments. `-s` supports semicolon/comma multi-target lists and syncs both `whois-*` and `SHA256SUMS-static.txt`; with `-P 1` only non-whois/non-checksum files are pruned. When `-r 1` and `-L` is not overridden, the script also captures `referral_143128/iana|arin/afrinic.log` on the remote host and runs `tools/test/referral_143128_check.sh` locally. Pass `-L 0` (or export `REFERRAL_CHECK=0`) if you need to skip the AfriNIC regression gate.

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
