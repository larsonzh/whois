# whois Operations & Release Guide

Chinese version: `docs/OPERATIONS_CN.md`

This guide summarizes common day-to-day tasks: commit/push, remote cross-compilation + smoke tests, and publishing releases to GitHub and Gitee.

Signal handling note (2025-12-21): Ctrl+C/TERM/HUP now closes cached connections and emits a single termination notice; `[DNS-CACHE-SUM]`/`[RETRY-*]` still flush via atexit, so smoke/golden logs retain cache/metrics lines even on interrupted runs.
Frontend entry note: all executables reuse `wc_client_frontend_run`; if you add a test or alt entry, only assemble `wc_opts` and call the facade. Do not duplicate selftest, signal, or atexit logic in the new `main`; keep stdout/stderr contracts identical.
Selftest marker note (2025-12-25): `[SELFTEST]` tags now always include `action=` and emit at most once per process; even without running the `--selftest` suite, the first forced hook will still write the tag. DNS ipv6-only/fallback selftests are WARN-only to avoid aborting on flaky networks.
ARIN prefix strip note (2026-01-15): when a query contains spaces (ARIN-style prefixes) and the hop is non-ARIN, the client strips the prefix before re-querying and emits `[DNS-ARIN] action=strip-prefix host=<server> query=<raw> stripped=<no-prefix>` under debug/metrics.
RIR rate-limit/denied note (2026-02-06): when a RIR replies with rate-limit/denied, treat it as a non-authoritative redirect and keep searching; if no ERX/IANA marker was seen and all RIRs are exhausted, authority falls back to error, otherwise it uses the first ERX/IANA-marked RIR. Failure lines on stderr are emitted only when the final tail is `error @ error`; otherwise no `Error: Query failed for ...` line is produced. Under `--debug`, rate-limit/denied hops emit `[RIR-RESP] action=denied|rate-limit ...` to stderr. Comment-only (banner-only) RIR responses are treated as empty responses: the hop is retried, and if it remains empty the client redirects (non-ARIN hop pivots to ARIN; ARIN enters the RIR cycle). Empty-response retries emit `[EMPTY-RESP] action=...` tags on stderr. If rate-limit/denied prevents querying a RIR and an ERX/IANA marker was seen but no authority converged, perform one baseline IP recheck (CIDR mask stripped) against the first ERX/IANA-marked RIR after the RIR cycle; if the recheck still fails or remains non-authoritative, keep authority as error. The non-polluting sequence applies to LACNIC internal redirects that hit denial and to first-hop direct RIR denial. A LACNIC internal redirect to ARIN omits the ARIN query prefix and often yields `Query terms are ambiguous`, so ARIN should not be marked visited and the next hop must re-query ARIN with the proper prefix.
Invalid CIDR closure (2026-02-19): fixed the path where IANA `% Error: Invalid query` could be misclassified as semantic-empty; `-h iana --show-non-auth-body --show-post-marker-body 47.96.0.0/10` now converges immediately to `unknown @ unknown` without drifting into IANA→ARIN→APNIC.
CIDR contract convergence (2026-02-20): fixed the APNIC `not allocated to APNIC` path where ERX markers could be cleared and produce wrong fallback (`src/core/lookup_exec_redirect.c`); rerunning `testdata/cidr_matrix_cases_draft.tsv` on release artifacts now yields `pass=5 fail=0`, log `out/artifacts/redirect_matrix/20260220-111122`.
Remote fast build + release sync (2026-02-20, `x86_64+win64`, `lto-auto`): `Local hash verify PASS + Golden PASS`, log `out/artifacts/20260220-110900`.
Selftest goldens (2026-02-20, prefilled): raw/health-first/plan-a/plan-b all PASS, logs `out/artifacts/batch_raw/20260220-111736`, `batch_health/20260220-112303`, `batch_plan/20260220-112658`, `batch_planb/20260220-113149`.
CIDR body-contract smoke task (2026-02-20): VS Code now includes `Test: CIDR Body Contract` (parameterized) and `Test: CIDR Body Contract (prefilled)` (one-click preset), both mapped to `tools/test/cidr_body_contract_smoke.ps1`; coverage now includes 4 stable cases (first-marker suppression, post-marker consistency path, no-marker direct authoritative, and iana-chain tail presence), and the latest local run is `pass=4 fail=0` (log `out/artifacts/cidr_body_contract/20260220-124943`).
CIDR draft matrix expansion (2026-02-20): `testdata/cidr_matrix_cases_draft.tsv` now includes executable cases for no-marker cross-RIR convergence, all-space unknown, and invalid-input; targeted execution via `redirect_matrix_test.ps1 -CasesFile testdata/cidr_matrix_cases_draft.tsv` yields `pass=8 fail=0`, log `out/artifacts/redirect_matrix/20260220-125430`. VS Code now also provides one-click tasks `Test: Redirect Matrix (CIDR Draft TSV)` and `Test: Redirect Matrix (CIDR Draft TSV, prefilled)`, and a task-equivalent rerun also yields `pass=8 fail=0` (`out/artifacts/redirect_matrix/20260220-130044`).
Next plan (2026-02-20): treat the above logs as the active baseline, extend CIDR draft matrix coverage (marker/no-marker/consistency-fail/failure-driven error), and keep the three-gate validation path (`Strict + matrix + selftest`).
Remote build smoke sync + golden (2026-02-19, Strict Version + lto-auto default): `Local hash verify PASS + Golden PASS + referral check PASS`, log `out/artifacts/20260219-045120`.
Redirect matrix reruns (2026-02-19): parameterized IPv4 `pass=66 fail=0` (`out/artifacts/redirect_matrix/20260219-045555`); 12x6 (including `47.96.0.0/10`) `authMismatchFiles=0, errorFiles=0` (`out/artifacts/redirect_matrix_10x6/20260219-051415`).
Remote build smoke sync + golden (2026-02-09, LTO default): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260209-122029`.
Remote build smoke sync + golden (2026-02-09, LTO + debug/metrics + dns-family-mode=interleave-v4-first): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260209-122818`.
Remote build smoke sync + golden (2026-02-10, lto-auto default): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260210-110224`.
Remote build smoke sync + golden (2026-02-10, lto-auto default): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260210-113135`.
Remote build smoke sync + golden (2026-02-10, lto-auto default): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260210-120349`.
Remote build smoke sync + golden (2026-02-10, lto-auto default): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260210-123718`.
Remote build smoke sync + golden (2026-02-10, Strict Version + lto-auto default): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260210-133508`.
Remote build smoke sync + golden (2026-02-10, Strict Version + lto-auto + debug/metrics + dns-family-mode=interleave-v4-first): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260210-134308`.
Remote build smoke sync + golden (2026-02-10, Strict Version + lto-auto default): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260210-163305`.
Remote build smoke sync + golden (2026-02-14, Strict Version + lto-auto default): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260214-075348`.
Remote build smoke sync + golden (2026-02-16, Strict Version + lto-auto default): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260216-152247`.
Remote build smoke sync + golden (2026-02-16, Strict Version + lto-auto + debug/metrics + dns-family-mode=interleave-v4-first): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260216-152830`.
Remote build smoke sync + golden (2026-02-17, Strict Version + lto-auto default): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260217-170956`.
Remote build smoke sync + golden (2026-02-10, Strict Version + lto-auto + debug/metrics + dns-family-mode=interleave-v4-first): no warnings + LTO no warnings + Golden PASS + referral check PASS, log `out/artifacts/20260210-164007`.
Build size baseline (2026-02-10, lto-auto + UPX aarch64/x86_64 + full strip): aarch64 149KB, x86_64 151KB, armv7 340KB, x86 404KB, mipsel 483KB, mips64el 506KB, loongarch64 262KB, win64 393KB, win32 422KB; `upx_report.txt` shows aarch64/x86_64 compressed OK.
Batch strategy goldens (2026-02-10, lto-auto): raw/health-first/plan-a/plan-b PASS, logs `out/artifacts/batch_{raw,health,plan,planb}/20260210-13*`.
Selftest goldens (2026-02-10, lto-auto + `--selftest-force-suspicious 8.8.8.8`): raw/health-first/plan-a/plan-b PASS, logs `out/artifacts/batch_{raw,health,plan,planb}/20260210-14*`.
Selftest report: each strategy now writes `golden_selftest_report.txt` under its `build_out`.
Batch strategy goldens (2026-02-10, lto-auto): raw/health-first/plan-a/plan-b PASS, logs `out/artifacts/batch_raw/20260210-165020`, `batch_health/20260210-165721`, `batch_plan/20260210-170754`, `batch_planb/20260210-171826`.
Selftest goldens (2026-02-10, lto-auto + `--selftest-force-suspicious 8.8.8.8`): raw/health-first/plan-a/plan-b PASS, logs `out/artifacts/batch_raw/20260210-172643`, `batch_health/20260210-173432`, `batch_plan/20260210-174621`, `batch_planb/20260210-175714`.
Selftest report: each strategy now writes `golden_selftest_report.txt` under its `build_out`.
Redirect matrix 10x6 (2026-02-10): authority mismatches=0, errors=0, log `out/artifacts/redirect_matrix_10x6/20260210-175917`.
Redirect matrix assertion semantics (2026-02-14): authority checks follow the failure-first contract; when a case ends with `=== Authoritative RIR: error @ error ===` (for example, unresolved due to rate-limit/denied/connect failures), expected authority is `error`; static RIR expectations apply only to non-failure tails.
Redirect matrix 10x6 (2026-02-14): authority mismatches empty, errors empty, log `out/artifacts/redirect_matrix_10x6/20260214-081508`.
Redirect matrix 10x6 (2026-02-16): authority mismatches empty; errors contain 7 environmental `rate-limit` cases, log `out/artifacts/redirect_matrix_10x6/20260216-162426`.
Rate-limit mitigation knobs for matrix runs (2026-02-17): `tools/test/redirect_matrix_10x6.ps1` adds `-InterCaseSleepMs` (default 250), `-RateLimitRetries` (default 1), and `-RateLimitRetrySleepMs` (default 1500). Start with defaults; if needed, raise to `500/2/2500` for off-peak reruns.
Redirect matrix 10x6 (2026-02-17): rerun with stronger throttling (`-InterCaseSleepMs 500 -RateLimitRetries 2 -RateLimitRetrySleepMs 2500`) is fully green (authority mismatches=0, errors=0), log `out/artifacts/redirect_matrix_10x6/20260217-065457`.
Redirect matrix 10x6 (2026-02-17, extra rerun): same parameters, fully green again (`authMismatchFiles=0, errorFiles=0`), log `out/artifacts/redirect_matrix_10x6/20260217-105213`.
Redirect matrix 10x6 (2026-02-17, latest rerun): same parameters, fully green again (`authMismatchFiles=0, errorFiles=0`), log `out/artifacts/redirect_matrix_10x6/20260217-171711`.
Redirect revisit fix (2026-02-17): enforce a generic “do not revisit visited RIR” rule (not only ARIN→APNIC). When referral points to an already visited RIR, continue with unvisited RIR cycle. Recheck confirms `-h apnic 45.113.52.0` no longer revisits APNIC and still converges to APNIC authority; `-h lacnic 1.1.1.1` is also correct.
Current execution guidance (2026-02-17): use `out/artifacts/20260217-170956` (Strict) and `out/artifacts/redirect_matrix_10x6/20260217-171711` (matrix) as the active baseline; keep the two-layer validation path of focused command repro (`-h apnic 45.113.52.0`, `-h lacnic 1.1.1.1`) plus full 10x6 matrix rerun.
APP-RETRY clean probe (2026-02-17): to avoid PowerShell `NativeCommandError` wrapper noise, use `cmd /c` to run the native binary and append stderr directly to a log: `$bin="d:\LZProjects\whois\release\lzispro\whois\whois-win64.exe"; $outDir=".\out\artifacts\app_retry_probe_clean"; $log=Join-Path $outDir "stderr.log"; New-Item -ItemType Directory -Force $outDir | Out-Null; Remove-Item $log -ErrorAction SilentlyContinue; 1..80 | % { cmd /c "\`\"$bin\`\" --debug --retry-metrics --rate-limit-retries 2 --rate-limit-retry-interval-ms 1500 -h arin 45.121.52.0/22 1>nul 2>>\`\"$log\`\"" }; Select-String -Path $log -Pattern "\[APP-RETRY\]" | Select-Object -First 20`.
Batch strategy goldens (2026-02-09, LTO): raw/health-first/plan-a/plan-b PASS, logs `out/artifacts/batch_{raw,health,plan,planb}/20260209-11*`.
Selftest goldens (2026-02-09, LTO + `--selftest-force-suspicious 8.8.8.8`): raw/health-first/plan-a/plan-b PASS, logs `out/artifacts/batch_{raw,health,plan,planb}/20260209-12*`.
Redirect matrix 10x6 (2026-02-09): no authority mismatches/errors, log `out/artifacts/redirect_matrix_10x6/20260209-133525`.
CIDR sample coverage (2026-02-09): APNIC/AFRINIC/RIPE/ARIN/LACNIC, log `out/artifacts/cidr_samples/20260209-002242`.
48-process batch comparison (2026-02-09): recheck+cycle vs cycle-only, log `out/artifacts/gt-ax6000_recheck_20260209_syslog.log`.
Response filter buffer note (2025-12-25): response filters reuse a per-query work buffer; no behavior or CLI change. Title/grep/fold now support workbuf-backed APIs; legacy APIs unchanged. Fold unique token reuse now uses a workbuf scratch instead of per-token malloc (2025-12-25).
Injection view note (2025-12-27): force-* injections are centralized in the selftest injection view; NULL net_ctx paths also read from it, matching behavior with net_ctx. New entrypoints/wrappers must pull the view explicitly—do not reintroduce globals; stdout/stderr contracts stay unchanged.
Workbuf stats note (optional): to observe long-line/high-continuation expansion, build with `WC_WORKBUF_ENABLE_STATS` and read `wc_workbuf_stats_snapshot()` for `reserves/grow_events/max_request/max_cap/max_view_size`. Disabled by default, no impact on goldens.
WORKBUF tag fields: `action` names the case (long-crlf/dense-lf); `result` is PASS/FAIL; `len/max_view` is the largest visible slice; `max_request` is the largest requested read; `reserves` is the initial reserve; `grow` is the number of expansions; `max_cap` is the peak buffer capacity; `cases=a/b` summarizes executed cases.
Stress plan note (2025-12-31 → 2026-01-09): fold-unique body aliasing fix ships (token views now live in workbuf scratch), covering manual long-line/dense-continuation/CRLF scenarios with no truncation/crash. Latest remote smoke + golden logs: `out/artifacts/20260109-120735` (default, PASS) and `out/artifacts/20260109-124459` (`--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`, PASS); post-control-flow split rerun: `out/artifacts/20260109-145129` (default, PASS) and `out/artifacts/20260109-145610` (same debug/metrics family, PASS). Batch raw/health-first/plan-a/plan-b golden: `out/artifacts/batch_raw/20260109-124921/build_out/smoke_test.log`, `out/artifacts/batch_health/20260109-125305/build_out/smoke_test.log`, `out/artifacts/batch_plan/20260109-125524/build_out/smoke_test.log`, `out/artifacts/batch_planb/20260109-125751/build_out/smoke_test.log`; post-split rerun PASS at `out/artifacts/batch_raw/20260109-150005/...`, `batch_health/20260109-150359/...`, `batch_plan/20260109-150620/...`, `batch_planb/20260109-150841/...` (reports colocated). Selftest golden (`--selftest-force-suspicious 8.8.8.8`): `out/artifacts/batch_raw/20260109-130135/build_out/smoke_test.log`, `out/artifacts/batch_health/20260109-130353/build_out/smoke_test.log`, `out/artifacts/batch_plan/20260109-130611/build_out/smoke_test.log`, `out/artifacts/batch_planb/20260109-130839/build_out/smoke_test.log`; post-split rerun PASS at `out/artifacts/batch_raw/20260109-151205/...`, `batch_health/20260109-151420/...`, `batch_plan/20260109-151631/...`, `batch_planb/20260109-151848/...`. Selftest golden builds include `-DWC_WORKBUF_ENABLE_STATS`; with `--debug` you’ll see `[WORKBUF-STATS]` on stderr. For quick regressions, add `--selftest-workbuf` to trigger built-in long-line/CRLF/high-continuation coverage; stderr emits `[WORKBUF]`/`[WORKBUF-STATS]` markers for golden checks. Manual workbuf stress rerun (fold+unique, grep-block) PASS: `out/artifacts/workbuf_stress/20260109-133951` (exit 1 due to expected force-suspicious selftest). Post-crash batch rendering fix was validated by four-pass goldens: remote smoke+golden `out/artifacts/20260109-214157` (default) and `out/artifacts/20260109-214706` (debug/metrics/family), batch strategies `out/artifacts/batch_raw/20260109-215119/...`, `batch_health/20260109-215529/...`, `batch_plan/20260109-215904/...`, `batch_planb/20260109-220154/...` (reports colocated), and selftest goldens `out/artifacts/batch_raw/20260109-220449/...`, `batch_health/20260109-220718/...`, `batch_plan/20260109-220945/...`, `batch_planb/20260109-221213/...`, all PASS. Render-entry refactor rerun: remote smoke+golden `out/artifacts/20260109-225321` (default) and `out/artifacts/20260109-225816` (debug/metrics/family) PASS; batch strategies `out/artifacts/batch_raw/20260109-230239/...`, `batch_health/20260109-230638/...`, `batch_plan/20260109-230940/...`, `batch_planb/20260109-231213/...` PASS (reports colocated). Selftest golden plan-b failed referral check: `out/artifacts/batch_planb/20260109-232630/...` missing redirect/tail for whois.afrinic.net (143.128.0.0), investigate referral expectations vs output; other selftest modes pass. Selftest rerun after referral review: all four modes PASS at `out/artifacts/batch_raw/20260109-234646/...`, `batch_health/20260109-234931/...`, `batch_plan/20260109-235158/...`, `batch_planb/20260109-235420/...`. Tail render centralization rerun: remote smoke+golden `out/artifacts/20260110-000925` (default) and `out/artifacts/20260110-001503` (debug/metrics/family) PASS; batch strategies `out/artifacts/batch_raw/20260110-001916/...`, `batch_health/20260110-002318/...`, `batch_plan/20260110-002547/...`, `batch_planb/20260110-002819/...` PASS (reports colocated); selftest goldens `out/artifacts/batch_raw/20260110-003120/...`, `batch_health/20260110-003338/...`, `batch_plan/20260110-003556/...`, `batch_planb/20260110-003829/...` all PASS.
Log sink consolidation rerun: remote smoke+golden `out/artifacts/20260110-013330` (default) and `out/artifacts/20260110-013821` (`--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`) PASS.
Batch error-path consolidation rerun: remote smoke+golden `out/artifacts/20260110-020138` (default) and `out/artifacts/20260110-020851` (`--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`) PASS; batch strategies raw/health-first/plan-a/plan-b PASS (`out/artifacts/batch_raw/20260110-021336/...`, `batch_health/20260110-021724/...`, `batch_plan/20260110-021950/...`, `batch_planb/20260110-022212/...`); selftest raw/health-first/plan-a/plan-b PASS (`out/artifacts/batch_raw/20260110-022514/...`, `batch_health/20260110-022750/...`, `batch_plan/20260110-023009/...`, `batch_planb/20260110-023227/...`).
After the batch normalization/render split fix, the default remote smoke + golden run was clean (`[golden] PASS`), log `out/artifacts/20260109-154512`.

Latest batch/selftest goldens (2025-12-31):
- Batch raw/health-first/plan-a/plan-b: `out/artifacts/batch_raw/20251231-203950/build_out/smoke_test.log`, `out/artifacts/batch_health/20251231-204330/build_out/smoke_test.log`, `out/artifacts/batch_plan/20251231-204730/build_out/smoke_test.log`, `out/artifacts/batch_planb/20251231-205124/build_out/smoke_test.log` (golden_report_* in same dirs).
- Selftest raw/health-first/plan-a/plan-b (`--selftest-force-suspicious 8.8.8.8`, with `--selftest-workbuf` + `-DWC_WORKBUF_ENABLE_STATS`): `out/artifacts/batch_raw/20251231-205426/build_out/smoke_test.log`, `out/artifacts/batch_health/20251231-205630/build_out/smoke_test.log`, `out/artifacts/batch_plan/20251231-205841/build_out/smoke_test.log`, `out/artifacts/batch_planb/20251231-210058/build_out/smoke_test.log` (stderr includes `[WORKBUF]`/`[WORKBUF-STATS]`).
Injection view quick check:
```bash
# Linux / Git Bash: observe injection fallback + metrics tags
whois-x86_64 --debug --retry-metrics --dns-cache-stats --selftest-force-suspicious 8.8.8.8
# Expect on stderr: [SELFTEST] action=force-suspicious, [DNS-CACHE-SUM], [RETRY-METRICS*]
```

Quick testing guidance:
- Local sanity: run the command above, verify header/tail/fold unchanged and NULL-vs-present net_ctx paths behave identically.
- Remote smoke: use the VS Code task “Remote: Build and Sync whois statics” or run `tools/remote/remote_build_and_test.sh -r 1 -a "--debug --retry-metrics --dns-cache-stats --selftest-force-suspicious 8.8.8.8"`; in `smoke_test.log` check `[SELFTEST] action=force-suspicious`, `[DNS-CACHE-SUM]`, and golden PASS.

Other scenarios:
- Batch strategy (raw, no fold):
  ```bash
  printf "8.8.8.8\n1.1.1.1\n" | whois-x86_64 -B --batch-strategy raw --debug --retry-metrics --dns-cache-stats --grep-line --no-fold
  # Check stderr: [RETRY-METRICS*]; stdout: headers/tails only, no folding
  ```
- Batch strategy (plan-b, folded):
  ```bash
  printf "8.8.8.8\n1.1.1.1\n" | whois-x86_64 -B --batch-strategy plan-b --fold --debug --retry-metrics --dns-cache-stats
  # Check stdout: folded `<query> <UPPER...> <RIR>` per line; stderr: single [DNS-CACHE-SUM]
  ```
- Batch strategy (health-first, block mode + keep continuations):
  ```bash
  printf "8.8.8.8\n1.1.1.1\n" | whois-x86_64 -B --batch-strategy health-first --grep "OrgName|Country" --grep-block --keep-continuation-lines --fold --debug --retry-metrics --dns-cache-stats
  # Check stdout: folded line retains continuation hits; stderr: one [DNS-CACHE-SUM] + [RETRY-METRICS*]
  ```
- Single query, no-fold comparison:
  ```bash
  whois-x86_64 --debug --retry-metrics --dns-cache-stats --no-fold 8.8.8.8
  # Compare with folded run to ensure header/tail/body unchanged
  ```
- Grep combo (line mode OR, multi-keyword):
  ```bash
  whois-x86_64 -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --debug --retry-metrics --dns-cache-stats 8.8.8.8
  # Check stdout: only matched lines remain; stderr: metrics tags present, contracts unchanged
  ```
- Grep combo (block mode AND, keep continuations):
  ```bash
  whois-x86_64 --grep 'OrgName' --grep 'Country' --grep-block --keep-continuation-lines --fold --debug --retry-metrics --dns-cache-stats 8.8.8.8
  # Check stdout: folded line contains both hits from the block; stderr: tags intact
  ```
- Pacing params (on vs off):
  ```bash
  whois-x86_64 --pacing-interval-ms 300 --pacing-jitter-ms 300 --retry-metrics 8.8.8.8
  whois-x86_64 --pacing-disable --retry-metrics 8.8.8.8
  # Compare [RETRY-METRICS*] sleep_ms/attempts to confirm pacing enabled vs disabled
  ```
- DNS family mode (prefer v6):
  ```bash
  whois-x86_64 --dns-family-mode prefer-v6 --debug --retry-metrics --dns-cache-stats 8.8.8.8
  # Check stderr: [DNS-CAND]/[DNS-HEALTH] biased to v6 with fallback; single [DNS-CACHE-SUM]
  ```
- DNS family mode (v4-only):
  ```bash
  whois-x86_64 --dns-family-mode v4-only --debug --retry-metrics --dns-cache-stats 8.8.8.8
  # Check stderr: v4-only candidates, no v6; tail contract unchanged
  ```
- Pacing backoff + max cap:
  ```bash
  whois-x86_64 --pacing-interval-ms 200 --pacing-jitter-ms 200 --pacing-backoff-factor 2.0 --pacing-max-ms 1200 --retry-metrics 8.8.8.8
  # Expect [RETRY-METRICS*] sleep_ms to back off and cap at ~1200ms; attempts/p95 match expectation
  ```
- dns-cache-stats disabled scenario:
  ```bash
  whois-x86_64 --debug --retry-metrics 8.8.8.8
  # No [DNS-CACHE-SUM] on stderr; other tags remain; stdout contract unchanged
  ```
- Timeout/retry combo (low timeout, higher retries):
  ```bash
  whois-x86_64 --timeout 2 --retries 4 --retry-interval 200 --retry-jitter 200 --retry-metrics 8.8.8.8
  # Watch [RETRY-METRICS*] attempts/p95 to confirm short timeout + multiple retries path; tags intact
  ```
- Extreme pacing-max-ms cap:
  ```bash
  whois-x86_64 --pacing-interval-ms 100 --pacing-jitter-ms 0 --pacing-backoff-factor 3.0 --pacing-max-ms 50 --retry-metrics 8.8.8.8
  # Expect sleep_ms capped near 50ms despite backoff; attempts/p95 bounded
  ```
- v6-only on an IPv4-only network:
  ```bash
  whois-x86_64 --dns-family-mode v6-only --retry-metrics --debug 8.8.8.8
  # Expect stderr: v6-only [DNS-CAND], likely ENETUNREACH/EHOSTUNREACH/ETIMEDOUT; [RETRY-METRICS*] shows failures; stdout contract held (failure tail is error)
  ```
- Selftest injection combo (empty response + force-suspicious):
  ```bash
  whois-x86_64 --selftest-inject-empty --selftest-force-suspicious 8.8.8.8 --debug --retry-metrics --dns-cache-stats
  # Expect stderr to show both [SELFTEST] action=inject-empty and action=force-suspicious; stdout contract unchanged
  ```

For link style conversion (absolute GitHub asset URLs ↔ relative repo paths) see: `docs/RELEASE_LINK_STYLE.md`.

Detailed release flow: `docs/RELEASE_FLOW_EN.md` | Chinese: `docs/RELEASE_FLOW_CN.md`

Windows artifacts quick use (local smoke examples):
- PowerShell single query: `whois-win64.exe --debug --prefer-ipv4-ipv6 8.8.8.8`; IPv6-only: `whois-win64.exe --debug --ipv6-only 8.8.8.8`
- PowerShell pipeline: `"8.8.8.8" | whois-win64.exe --debug --ipv4-only` (batch mode triggers automatically when stdin is not a TTY, even without `-B`)
- CMD pipeline: `echo 8.8.8.8 | whois-win64.exe --debug --ipv4-only`
- Wine on Linux: `env WINEDEBUG=-all wine64 ./whois-win64.exe --debug --prefer-ipv6 8.8.8.8` (use `wine` for 32-bit).

VS Code task/script note: `tools/remote/remote_build_and_test.sh` now builds win32/win64 by default; remote smoke outputs live in `out/artifacts/<ts>/build_out/smoke_test_win64.log` / `smoke_test_win32.log` for later review.

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
- Test: Redirect Matrix (IPv4) (standalone redirect matrix test, not tied to build/smoke/golden)
- Test: Redirect Matrix (IPv4, Params) (custom binary path/output dir/flags)

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

Note: as of 2025-12-20 there is no implicit fallback net context; callers must activate a net_ctx after `wc_runtime_init_resources()`. Missing context returns `WC_ERR_INVALID`. The remote script / CLI entry already does this by default.

Redirect matrix test notes:
- Script: `tools/test/redirect_matrix_test.ps1`
- Output: `redirect_matrix_report_<timestamp>.txt` (default under `out/artifacts/redirect_matrix/<timestamp>`)
- Per-case logs: saved under `out/artifacts/redirect_matrix/<timestamp>/cases/` by default; disable with `-SaveLogs false`.
- Exit code: returns 1 when any case fails, 0 when all pass.
- Params: `-BinaryPath`, `-OutDir`, `-RirIpPref` (`NONE` to skip), `-PreferIpv4` (`true|false`)

Latest four-way smoke (2026-01-09 10:59–12:45, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20260109-105954`.
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`: no warnings, `[golden] PASS`, log `out/artifacts/20260109-124459`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 12:49–12:57 on 2026-01-09):
- raw: `out/artifacts/batch_raw/20260109-124921/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20260109-125305/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20260109-125524/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20260109-125751/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 13:01–13:08 on 2026-01-09):
- raw: `out/artifacts/batch_raw/20260109-130135/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20260109-130353/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20260109-130611/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251231-100448/build_out/smoke_test.log`

Previous run (07:25–07:32 on 2025-12-31):
- raw: `out/artifacts/batch_raw/20251231-072555/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251231-072804/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251231-073021/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251231-073225/build_out/smoke_test.log`

Earlier run (06:34–06:41 on 2025-12-31):
- raw: `out/artifacts/batch_raw/20251231-063416/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251231-063635/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251231-063902/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251231-064111/build_out/smoke_test.log`

Latest double smoke (2025-12-25 15:37–15:40, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251225-153747/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`: no warnings, `[golden] PASS`, log `out/artifacts/20251225-154027/build_out/smoke_test.log`.

Latest four-way smoke (2025-12-25 12:34–12:37, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251225-123419/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`: no warnings, `[golden] PASS`, log `out/artifacts/20251225-123745/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 12:39–12:46 on 2025-12-25):
- raw: `out/artifacts/batch_raw/20251225-123945/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251225-124205/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251225-124429/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251225-124648/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 12:48–12:52 on 2025-12-25):
- raw: `out/artifacts/batch_raw/20251225-124840/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251225-124955/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251225-125111/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251225-125231/build_out/smoke_test.log`

Latest four-way smoke (2025-12-25 11:46–11:48, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251225-114602/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`: no warnings, `[golden] PASS`, log `out/artifacts/20251225-114822/build_out/smoke_test.log`.

Latest four-way smoke (2025-12-25 10:59–11:02, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251225-105955/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`: no warnings, `[golden] PASS`, log `out/artifacts/20251225-110224/build_out/smoke_test.log`.

Latest four-way smoke (2025-12-25 06:46–06:49, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251225-064648/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`: no warnings, `[golden] PASS`, log `out/artifacts/20251225-064909/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 06:51–06:58 on 2025-12-25):
- raw: `out/artifacts/batch_raw/20251225-065101/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251225-065323/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251225-065539/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251225-065801/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 07:00–07:03 on 2025-12-25):
- raw: `out/artifacts/batch_raw/20251225-070013/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251225-070125/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251225-070241/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251225-070358/build_out/smoke_test.log`

Latest four-way smoke (2025-12-22 23:37–23:56, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251222-233731/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`: no warnings, `[golden] PASS`, log `out/artifacts/20251222-233938/build_out/smoke_test.log`.

Latest four-way smoke (2025-12-25 00:14–00:17, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251225-001454/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`: no warnings, `[golden] PASS`, log `out/artifacts/20251225-001704/build_out/smoke_test.log`.

Latest four-way smoke (2025-12-25 00:48–00:50, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251225-004820/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`: no warnings, `[golden] PASS`, log `out/artifacts/20251225-005049/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 00:52–00:59 on 2025-12-25):
- raw: `out/artifacts/batch_raw/20251225-005250/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251225-005508/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251225-005736/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251225-005953/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 01:01–01:05 on 2025-12-25):
- raw: `out/artifacts/batch_raw/20251225-010144/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251225-010258/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251225-010412/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251225-010533/build_out/smoke_test.log`

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 00:18–00:25 on 2025-12-25):
- raw: `out/artifacts/batch_raw/20251225-001855/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251225-002111/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251225-002327/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251225-002544/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 00:28–00:32 on 2025-12-25):
- raw: `out/artifacts/batch_raw/20251225-002843/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251225-002954/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251225-003113/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251225-003230/build_out/smoke_test.log`

Latest four-way smoke (2025-12-24 22:56–22:59, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251224-225648/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`: no warnings, `[golden] PASS`, log `out/artifacts/20251224-225932/build_out/smoke_test.log`.

Latest four-way smoke (2025-12-24 23:45–23:47, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251224-234518/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`: no warnings, `[golden] PASS`, log `out/artifacts/20251224-234746/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 23:49–23:56 on 2025-12-24):
- raw: `out/artifacts/batch_raw/20251224-234943/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251224-235158/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251224-235416/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251224-235632/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 23:58–00:02 on 2025-12-24/25):
- raw: `out/artifacts/batch_raw/20251224-235842/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251224-235959/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251225-000119/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251225-000232/build_out/smoke_test.log`

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 23:02–23:10 on 2025-12-24):
- raw: `out/artifacts/batch_raw/20251224-230253/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251224-230508/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251224-230748/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251224-231041/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 23:12–23:17 on 2025-12-24):
- raw: `out/artifacts/batch_raw/20251224-231247/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251224-231445/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251224-231558/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251224-231707/build_out/smoke_test.log`

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 23:41–23:48 on 2025-12-22):
- raw: `out/artifacts/batch_raw/20251222-234143/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251222-234400/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251222-234617/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251222-234836/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 23:51–23:56 on 2025-12-22):
- raw: `out/artifacts/batch_raw/20251222-235158/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251222-235324/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251222-235439/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251222-235606/build_out/smoke_test.log`

Latest four-way smoke (2025-12-22 20:50–20:53, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251222-205023/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`: no warnings, `[golden] PASS`, log `out/artifacts/20251222-205302/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 20:55–21:03 on 2025-12-22):
- raw: `out/artifacts/batch_raw/20251222-205509/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251222-205731/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251222-210022/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251222-210302/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 21:11–21:14 on 2025-12-22):
- raw: `out/artifacts/batch_raw/20251222-211109/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251222-211228/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251222-211340/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251222-211452/build_out/smoke_test.log`

Latest four-way smoke (around 00:12 on 2025-12-21, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251221-001203/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251221-001409/build_out/smoke_test.log`.

Latest remote smoke (around 01:24 on 2025-12-21, default params, with signal cleanup optimization): no warnings, `[golden] PASS`, log `out/artifacts/20251221-012403/build_out/smoke_test.log`.

Latest four-way smoke (around 01:50 on 2025-12-21, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251221-015000/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251221-015221/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 01:54–02:01 on 2025-12-21):
- raw: `out/artifacts/batch_raw/20251221-015424/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251221-015646/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251221-015920/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251221-020147/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 02:04–02:07 on 2025-12-21):
- raw: `out/artifacts/batch_raw/20251221-020412/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251221-020523/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251221-020632/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251221-020741/build_out/smoke_test.log`

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 00:15–00:23 on 2025-12-21):
- raw: `out/artifacts/batch_raw/20251221-001557/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251221-001825/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251221-002047/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251221-002311/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 00:25–00:29 on 2025-12-21):
- raw: `out/artifacts/batch_raw/20251221-002544/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251221-002700/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251221-002818/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251221-002937/build_out/smoke_test.log`

Latest four-way smoke (around 22:21 on 2025-12-20, net_ctx convergence + runtime flush hook re-smoke, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251220-222145/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251220-222407/build_out/smoke_test.log`.

Latest remote smoke (23:02 on 2025-12-20, default params): no warnings, `[golden] PASS`, log `out/artifacts/20251220-230243/build_out/smoke_test.log`.

Latest four-way smoke (around 23:35 on 2025-12-20, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251220-233528/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251220-233802/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-20 23:40–23:47 batches):
- raw: `out/artifacts/batch_raw/20251220-234006/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251220-234232/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251220-234454/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251220-234721/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 2025-12-20 23:49–23:53 batches):
- raw: `out/artifacts/batch_raw/20251220-234934/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251220-235101/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251220-235224/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251220-235342/build_out/smoke_test.log`

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-20 22:26–22:34 batches):
- raw: `out/artifacts/batch_raw/20251220-222608/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251220-222900/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251220-223143/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251220-223431/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 2025-12-20 22:36–22:40 batches):
- raw: `out/artifacts/batch_raw/20251220-223635/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251220-223752/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251220-223906/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251220-224028/build_out/smoke_test.log`

Latest four-way smoke (around 21:12 on 2025-12-20, after explicit net ctx requirement, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251220-211245/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251220-211508/build_out/smoke_test.log`.
- Batch strategy goldens (raw/health-first/plan-a/plan-b):
  - raw: `out/artifacts/batch_raw/20251220-211738/build_out/smoke_test.log` (`golden_report_raw.txt`)
  - health-first: `out/artifacts/batch_health/20251220-212022/build_out/smoke_test.log` (`golden_report_health-first.txt`)
  - plan-a: `out/artifacts/batch_plan/20251220-212249/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
  - plan-b: `out/artifacts/batch_planb/20251220-212513/build_out/smoke_test.log` (`golden_report_plan-b.txt`)
- Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies):
  - raw: `out/artifacts/batch_raw/20251220-212733/build_out/smoke_test.log`
  - health-first: `out/artifacts/batch_health/20251220-212900/build_out/smoke_test.log`
  - plan-a: `out/artifacts/batch_plan/20251220-213031/build_out/smoke_test.log`
  - plan-b: `out/artifacts/batch_planb/20251220-213156/build_out/smoke_test.log`

Latest four-way smoke (around 14:17 on 2025-12-18, cache-counter sampling flag rollout, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251218-141752/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251218-142007/build_out/smoke_test.log`.

Latest four-way smoke (around 15:26 on 2025-12-18, client_flow explicit Config injection, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251218-152604/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251218-152906/build_out/smoke_test.log`.

Latest four-way smoke (around 16:03 on 2025-12-18, pipeline explicit Config handoff, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251218-160332/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251218-160639/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-18 16:09 batch):
- raw: `out/artifacts/batch_raw/20251218-160914/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251218-161134/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251218-161422/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251218-161644/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 2025-12-18 16:28 batch):
- raw: `out/artifacts/batch_raw/20251218-162820/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251218-162941/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251218-163105/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251218-163224/build_out/smoke_test.log`

Latest four-way smoke (around 16:45 on 2025-12-18, runtime housekeeping debug gate tidy-up, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251218-164548/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251218-164841/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-18 16:50 batch):
- raw: `out/artifacts/batch_raw/20251218-165044/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251218-165303/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251218-165528/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251218-165748/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 2025-12-18 17:00 batch):
- raw: `out/artifacts/batch_raw/20251218-170049/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251218-170202/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251218-170315/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251218-170432/build_out/smoke_test.log`

Latest four-way smoke (around 17:35 on 2025-12-18, runtime Config stored by value, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251218-173506/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251218-173742/build_out/smoke_test.log`.

Note: referral check reported ERROR for 143.128.0.0 (`whois.arin.net` missing authoritative tail to `whois.afrinic.net`), log `out/artifacts/20251218-173742/build_out/referral_checks/143.128.0.0/whois.arin.net.log`; other referrals PASS. Decide whether to adjust the referral baseline or emit the tail in this path.

Latest four-way smoke (around 17:45–18:07 on 2025-12-18, rerun cleared referral anomaly, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251218-174543/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251218-174818/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-18 17:53–18:01 batch):
- raw: `out/artifacts/batch_raw/20251218-175331/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251218-175604/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251218-175830/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251218-180051/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 2025-12-18 18:03–18:07 batch):
- raw: `out/artifacts/batch_raw/20251218-180308/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251218-180432/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251218-180554/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251218-180712/build_out/smoke_test.log`

Latest four-way smoke (around 18:17–18:35 on 2025-12-18, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251218-181758/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251218-182014/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-18 18:22–18:29 batch):
- raw: `out/artifacts/batch_raw/20251218-182205/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251218-182427/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251218-182654/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251218-182916/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 2025-12-18 18:31–18:35 batch):
- raw: `out/artifacts/batch_raw/20251218-183125/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251218-183246/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251218-183401/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251218-183540/build_out/smoke_test.log`

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-18 15:31 batch):
- raw: `out/artifacts/batch_raw/20251218-153126/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251218-153349/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251218-153620/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251218-153839/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 2025-12-18 15:41 batch):
- raw: `out/artifacts/batch_raw/20251218-154118/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251218-154231/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251218-154348/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251218-154503/build_out/smoke_test.log`

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-18 14:22 batch):
- raw: `out/artifacts/batch_raw/20251218-142209/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251218-142427/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251218-142650/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251218-142910/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 2025-12-18 14:31 batch):
- raw: `out/artifacts/batch_raw/20251218-143112/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251218-143231/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251218-143355/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251218-143508/build_out/smoke_test.log`

Latest four-way smoke (around 10:29 on 2025-12-18, after cache-counter encapsulation, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251218-102901/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251218-103101/build_out/smoke_test.log`.

Latest four-way smoke (around 11:43 on 2025-12-18, cache counter updates re-smoked, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251218-114328/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251218-114558/build_out/smoke_test.log`.

Latest four-way smoke (around 12:40 on 2025-12-18, signal read-only view re-smoked, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/batch_raw/20251218-114757/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/batch_raw/20251218-115725/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-18 12:45 batch):
- raw: `out/artifacts/batch_raw/20251218-124007/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251218-124257/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251218-124526/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251218-124747/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 2025-12-18 12:50 batch):
- raw: `out/artifacts/batch_raw/20251218-124957/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251218-125114/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251218-125234/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251218-125346/build_out/smoke_test.log`

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-18 11:47 batch):
- raw: `out/artifacts/batch_raw/20251218-114757/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251218-115018/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251218-115247/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251218-115512/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 2025-12-18 11:57 batch):
- raw: `out/artifacts/batch_raw/20251218-115725/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251218-115854/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251218-120018/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251218-120146/build_out/smoke_test.log`

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-18 10:32 batch):
- raw: `out/artifacts/batch_raw/20251218-103257/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251218-103519/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251218-103739/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251218-103956/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 2025-12-18 10:41 batch):
- raw: `out/artifacts/batch_raw/20251218-104148/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251218-104302/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251218-104414/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251218-104527/build_out/smoke_test.log`

Latest four-way smoke (around 09:40 on 2025-12-18, default remote params):
- Default args: no warnings, `[golden] PASS`, log `out/artifacts/20251218-094015/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, `[golden] PASS`, log `out/artifacts/20251218-094311/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-18 09:45 batch):
- raw: `out/artifacts/batch_raw/20251218-094505/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251218-094735/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251218-094953/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251218-095216/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all strategies PASS, 2025-12-18 09:55 batch):
- raw: `out/artifacts/batch_raw/20251218-095455/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251218-095611/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251218-095721/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251218-095842/build_out/smoke_test.log`

Latest two-pass smoke (2025-12-18 08:57 batch, default remote script params):
- Default args: no warnings, Golden PASS, log `out/artifacts/20251218-085751/build_out/smoke_test.log`.
- `--debug --retry-metrics --dns-cache-stats`: no warnings, Golden PASS, log `out/artifacts/20251218-085949/build_out/smoke_test.log`.

Batch strategy goldens (raw/health-first/plan-a/plan-b, all PASS, 2025-12-18 09:01 batch):
- raw: `out/artifacts/batch_raw/20251218-090130/build_out/smoke_test.log` (`golden_report_raw.txt`)
- health-first: `out/artifacts/batch_health/20251218-090356/build_out/smoke_test.log` (`golden_report_health-first.txt`)
- plan-a: `out/artifacts/batch_plan/20251218-090613/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
- plan-b: `out/artifacts/batch_planb/20251218-090835/build_out/smoke_test.log` (`golden_report_plan-b.txt`)

Selftest goldens (`--selftest-force-suspicious 8.8.8.8`, all four strategies PASS, 2025-12-18 09:10 batch):
- raw: `out/artifacts/batch_raw/20251218-091032/build_out/smoke_test.log`
- health-first: `out/artifacts/batch_health/20251218-091143/build_out/smoke_test.log`
- plan-a: `out/artifacts/batch_plan/20251218-091300/build_out/smoke_test.log`
- plan-b: `out/artifacts/batch_planb/20251218-091415/build_out/smoke_test.log`

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

###### 2025-12-18 rerun (08:22–08:38)

- Remote smoke (default): `out/artifacts/20251218-082248/build_out/smoke_test.log`, no alerts, `[golden] PASS`.
- Remote smoke (`--debug --retry-metrics --dns-cache-stats`): `out/artifacts/20251218-082454/build_out/smoke_test.log`, no alerts, `[golden] PASS`.
- Batch goldens (raw/health-first/plan-a/plan-b): all `[golden] PASS`.
  - raw: `out/artifacts/batch_raw/20251218-082631/build_out/smoke_test.log` (`golden_report_raw.txt`)
  - health-first: `out/artifacts/batch_health/20251218-082848/build_out/smoke_test.log` (`golden_report_health-first.txt`)
  - plan-a: `out/artifacts/batch_plan/20251218-083107/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
  - plan-b: `out/artifacts/batch_planb/20251218-083326/build_out/smoke_test.log` (`golden_report_plan-b.txt`)
- Selftest goldens (`--selftest-force-suspicious 8.8.8.8`): all `[golden-selftest] PASS`.
  - raw: `out/artifacts/batch_raw/20251218-083524/build_out/smoke_test.log`
  - health-first: `out/artifacts/batch_health/20251218-083636/build_out/smoke_test.log`
  - plan-a: `out/artifacts/batch_plan/20251218-083747/build_out/smoke_test.log`
  - plan-b: `out/artifacts/batch_planb/20251218-083856/build_out/smoke_test.log`

###### 2025-12-18 rerun (08:57–09:14)

- Remote smoke (default): `out/artifacts/20251218-085751/build_out/smoke_test.log`, no alerts, `[golden] PASS`.
- Remote smoke (`--debug --retry-metrics --dns-cache-stats`): `out/artifacts/20251218-085949/build_out/smoke_test.log`, no alerts, `[golden] PASS`.
- Batch goldens (raw/health-first/plan-a/plan-b): all `[golden] PASS`.
  - raw: `out/artifacts/batch_raw/20251218-090130/build_out/smoke_test.log` (`golden_report_raw.txt`)
  - health-first: `out/artifacts/batch_health/20251218-090356/build_out/smoke_test.log` (`golden_report_health-first.txt`)
  - plan-a: `out/artifacts/batch_plan/20251218-090613/build_out/smoke_test.log` (`golden_report_plan-a.txt`)
  - plan-b: `out/artifacts/batch_planb/20251218-090835/build_out/smoke_test.log` (`golden_report_plan-b.txt`)
- Selftest goldens (`--selftest-force-suspicious 8.8.8.8`): all `[golden-selftest] PASS`.
  - raw: `out/artifacts/batch_raw/20251218-091032/build_out/smoke_test.log`
  - health-first: `out/artifacts/batch_health/20251218-091143/build_out/smoke_test.log`
  - plan-a: `out/artifacts/batch_plan/20251218-091300/build_out/smoke_test.log`
  - plan-b: `out/artifacts/batch_planb/20251218-091415/build_out/smoke_test.log`

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
Error: Query failed for 8.8.8.8 (connect timeout, errno=110|145, host=whois.apnic.net, ip=203.119.102.29, time=2026-01-30 03:11:29)
[RETRY-METRICS] attempts=7 successes=2 failures=5 ... p95_ms≈3000
[RETRY-ERRORS] timeouts=5 refused=0 net_unreach=0 host_unreach=0 addr_na=0 interrupted=0 other=0
=== Authoritative RIR: error @ error ===
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
Error: Query failed for 8.8.8.8 (connect timeout, errno=110|145, host=whois.apnic.net, ip=203.119.102.29, time=2026-01-30 03:11:29)
[RETRY-METRICS] attempts≈5–8 successes≥1 failures≥1 p95_ms≈3000
[RETRY-ERRORS] timeouts>0 others typically 0
=== Authoritative RIR: error @ error ===
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
- `[DEBUG] Cache counters: ...` – printed by `wc_cache_log_statistics()` only when `--debug` is set; dumps dns_hits/dns_misses/dns_shim_hits and neg_hits/neg_sets/neg_shim_hits for quick spot checks. This does not add new tags and complements `[DNS-CACHE-SUM]`.
- If you need the same counters without turning on `--debug`, flip `wc_runtime_set_cache_counter_sampling(1)` in your selftest/diagnostic entrypoint; the housekeeping tick will emit the same summary line. Default remains off to keep stderr quiet.
- `[DNS-CACHE-LGCY]` – **removed**; legacy shim is retired and no longer emits telemetry. `[DNS-CACHE-SUM]` remains sourced from `wc_dns`. To debug the old path, use a dedicated branch or local patch instead of runtime knobs.
- `[DNS-HEALTH]` (Phase 3) – per-host/per-family health snapshots (consecutive failures, remaining penalty window) backing the soft candidate reordering logic (“healthy-first”, never dropping candidates).
- `[LOOKUP_SELFTEST]` – when built with `-DWHOIS_LOOKUP_SELFTEST` the client prints this summary once per process whenever `--selftest` runs **or** any `--selftest-*` runtime fault toggle (fail-first, inject-empty, dns-negative, blackhole, force-iana-pivot, grep/seclog demos) is present. No separate `whois --selftest` prologue is required.

Note: on some libc/QEMU combinations, `[LOOKUP_SELFTEST]` and `[DEBUG]` lines can interleave or partially overwrite each other at the line level. This is expected for now; the format is intended for grep/eyeball debugging, not strict machine parsing.

###### 2025-12-07 addenda

- Remote referral guard: `tools/remote/remote_build_and_test.sh` now writes per-host referral logs (`whois.iana.org/arin/afrinic`) and records capture details plus directory listing in `referral_debug.log` while keeping stderr quiet. Outputs live under `out/artifacts/<ts>/build_out/referral_checks/`.
- Selftest golden expectations: `tools/test/selftest_golden_suite.ps1` and `remote_batch_strategy_suite.ps1` synthesize `--expect action=force-suspicious,query=8.8.8.8` automatically when `SelftestActions` is `force-suspicious,8.8.8.8`, so you no longer need to pass `SelftestExpectations` explicitly.
- Registry selftest: `--selftest-registry` now executes even without lookup/startup demos; `selftest_golden_suite.ps1` only auto-adds the flag if neither `SmokeArgs` nor `SmokeExtraArgs` already contains it, avoiding duplicate switches while keeping `[SELFTEST] action=batch-registry-*` visible for golden.

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
- Header reading tip: when troubleshooting chain order, `=== Additional query to ... ===` should be interpreted as a non-referral extra hop and is often expected; it does not imply a missing RIR hop.
- Windows quick filter for hop headers/tail: `Get-Content build_out/smoke_test.log | Select-String '^=== (Query|Additional query|Redirected query|Authoritative RIR):'`.

##### IPv6 root-object redirect sanity check (::/0)

When APNIC/RIPE/AFRINIC return the IPv6 root object (`inet6num: ::/0` or `0::/0`), treat it as non-authoritative and trigger the no-referral redirect flow. Validate with:

```bash
whois-x86_64 -h apnic 2c0f:fb50::1 --debug --retry-metrics --dns-cache-stats
whois-x86_64 -h ripe 2c0f:fb50::1 --debug --retry-metrics --dns-cache-stats
whois-x86_64 -h afrinic 2c0f:fb50::1 --debug --retry-metrics --dns-cache-stats

whois-x86_64 -h apnic 2001:dd8:8:701::2 --debug --retry-metrics --dns-cache-stats
whois-x86_64 -h ripe 2001:dd8:8:701::2 --debug --retry-metrics --dns-cache-stats
whois-x86_64 -h afrinic 2001:dd8:8:701::2 --debug --retry-metrics --dns-cache-stats
```

- Expected: `2c0f:fb50::1` converges to AfriNIC; `2001:dd8:8:701::2` converges to APNIC (RIPE/AFRINIC starts hit `::/0`/`0::/0`, then follow ARIN referral back to APNIC).

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

    # health-first: asserts debug-penalize + start-skip + force-last + DNS backoff (force-last or force-override)
    ./tools/test/golden_check_batch_presets.sh health-first --selftest-actions force-suspicious,force-private --pref-labels v4-then-v6-hop0,v4-then-v6-hop1 -l ./out/artifacts/<ts_hf>/build_out/smoke_test.log

    # plan-a: asserts plan-a-cache/faststart/skip + debug-penalize
    ./tools/test/golden_check_batch_presets.sh plan-a --selftest-actions force-suspicious,force-private --pref-labels v4-then-v6-hop0,v4-then-v6-hop1 -l ./out/artifacts/<ts_pa>/build_out/smoke_test.log

    # plan-b: asserts plan-b-* + debug-penalize (if the preset is enabled)
    ./tools/test/golden_check_batch_presets.sh plan-b --selftest-actions force-suspicious,force-private --pref-labels v4-then-v6-hop0,v4-then-v6-hop1 -l ./out/artifacts/<ts_pb>/build_out/smoke_test.log
    ```

    The helper now also accepts `--pref-labels list` (comma separated, same syntax as `golden_check.sh`) and forwards it downstream, so mixed preference runs no longer require editing every command. Leave the flag out (or pass `--pref-labels NONE`) if your batch suite sticks to the default IPv6-first behavior. Any additional arguments after `-l ...` continue to pass straight to `golden_check.sh`.

    > **Heads-up:** smoke logs generated before 2025-12-02 did not yet include the `pref=` field, so `--pref-labels` will intentionally raise “missing preference label”. Skip the flag when auditing pre-instrumentation artifacts; re-enable it for current runs to keep hop-aware tags under golden coverage.

    ##### VS Code task: Golden Check Batch Suite

    Use the VS Code task **Golden Check: Batch Suite** (Terminal → Run Task) to run the raw/health-first/plan-a/plan-b validations in sequence. The task prompts for a dedicated “Preference labels” field (comma list, `NONE` to skip) and forwards it as `--pref-labels ...`; the “Extra args” textbox now defaults to `NONE` (no extra flags). Each log input accepts `LATEST` (or `AUTO`) to auto-pick the newest `smoke_test.log` under the matching `out/artifacts/batch_*` folder; leave a log path blank (or set it to `NONE`) to skip that preset. Inputs may include leading/trailing spaces; the script trims them automatically. To avoid the historical “single-space gets dropped” issue in VS Code tasks, the task passes an internal `__WC_ARG__` prefix (transparent to users). Internally it invokes `tools/test/golden_check_batch_suite.ps1`, so the results mirror the manual helper above but run in one click.
    You can also paste absolute paths copied from the smoke output; the script accepts both absolute paths and workspace-relative paths (for example `./out/artifacts/...`).

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
    1.1 Recommended expectation bundle (force-suspicious + force-private):
      ```bash
      tools/test/golden_check_selftest.sh \
        -l out/artifacts/batch_raw/<ts>/build_out/smoke_test.log \
        --expect action=force-suspicious,query=8.8.8.8 \
        --expect action=force-private,query=10.0.0.8 \
        --require-error "Suspicious query detected" \
        --require-error "Private query denied" \
        --require-tag SELFTEST "action=force-(suspicious|private)"
      ```
      Use the same expectations in `-SelftestExpectations/-ErrorPatterns/-TagExpectations` when calling `selftest_golden_suite.ps1` so all four strategies assert both forced hooks.
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
    - Artifacts land in `out/artifacts/batch_raw|batch_health|batch_plan|batch_planb/<timestamp>/build_out/`; each run automatically feeds the resulting `smoke_test.log` to `golden_check.sh`.
    - The remote suite now passes `-BackoffActions skip,force-last|force-override` for health-first, so the backoff coverage matches the batch suite preset without a follow-up “Golden Check: Batch Suite” pass.
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
Parameters: See above "VS Code Tasks" and script comments. `-O <profile>` passes `OPT_PROFILE` to make (e.g., `small`/`lto`); when set, leave `-E '-O3 -s'` off so the Makefile can pick the profile defaults. `-s` supports semicolon/comma multi-target lists and syncs both `whois-*` and `SHA256SUMS-static.txt`; with `-P 1` only non-whois/non-checksum files are pruned. When `-r 1` and `-L` is not overridden, the script also captures `referral_143128/iana|arin/afrinic.log` on the remote host and runs `tools/test/referral_143128_check.sh` locally. Pass `-L 0` (or export `REFERRAL_CHECK=0`) if you need to skip the AfriNIC regression gate.

#### Trimmed fast regression (x86_64 + win64)

For “refactor-only / no behavior change” iterations: build only `x86_64 + win64` (two binaries), run the same baseline smoke + golden checks, and finish faster than a full multi-arch build (but it does not cover some extra suites, e.g. redirect matrix).

```powershell
& "C:\Program Files\Git\bin\bash.exe" -lc "cd /d/LZProjects/whois; tools/remote/remote_build_and_test.sh -H 10.0.0.199 -u larson -k '/c/Users/妙妙呜/.ssh/id_rsa' -t 'x86_64 win64' -w 0 -r 1 -q '8.8.8.8 1.1.1.1 10.0.0.8' -a '' -G 1 -E '' -O 'lto-auto' -L 0"
```

Companion quick push (add/commit/fetch-rebase/push):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev\quick_push.ps1 -Message "refactor: <your message>" -Branch master
```

Note: C11 forbids implicit function declarations. If you add new `static` helpers and call them before a visible prototype/definition, builds may fail under `-Werror`. Fix by placing a forward declaration above the first call or by reordering definitions.

For background and daily progress notes, see: `docs/RFC-whois-client-split.md`.

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
