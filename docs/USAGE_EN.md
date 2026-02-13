# whois client usage

Chinese version: `docs/USAGE_CN.md`

This document describes the built-in lightweight whois clients shipped with the project (C implementation, statically linked, zero external runtime deps). Binaries cover multiple architectures such as `whois-x86_64`, `whois-aarch64`, etc. Examples below use `whois-x86_64`.

NOTICE (v3.2.5+): Output is English-only; the previous `--lang` option and `WHOIS_LANG` env have been removed to avoid mojibake on limited SSH terminals.

Highlights:
- Smart redirects: non-blocking connect, timeouts, light retries, and referral following with loop guard (`-R`, disable with `-Q`).
  - Traversal rules (2026-01-22): follow a referral on hop 1 when present; if hop 1 has no referral but a redirect is needed, force ARIN as hop 2. From hop 2 onward, follow referrals only when they have not been visited; if the referral is already visited or missing, select the next unvisited RIR in APNIC→ARIN→RIPE→AFRINIC→LACNIC order. Stop when all RIRs are visited. No IANA insertion after hop 2.
- Pipeline batch input: stable header/tail contract; read from stdin (`-B`/implicit); great for BusyBox grep/awk flows.
- Line-ending normalization: single and batch stdin inputs normalize CR-only/CRLF to LF before title/grep/fold, preventing stray carriage returns from splitting tokens; friendly to BusyBox pipelines.
- Conditional output engine: title projection (`-g`) → POSIX ERE filters (`--grep*`, line/block, optional continuation expansion) → folded summary (`--fold`).
- Batch start-host accelerators: pluggable `--batch-strategy <name>` are opt-in (default batch flow sticks to the raw CLI-host → RIR-guess → IANA order without penalty skipping). Use `--batch-strategy health-first` to re-enable the penalty-aware ordering, `--batch-strategy plan-a` to reuse the last authoritative RIR. `--batch-strategy plan-b` is active: cache-first and penalty-aware; it reuses the last authoritative RIR when healthy, falls back on penalty, and emits `[DNS-BATCH] plan-b-*` tags (`plan-b-force-start/plan-b-fallback/force-override/start-skip/force-last`) plus cache-window signals `[DNS-BATCH] action=plan-b-hit|plan-b-stale|plan-b-empty` (default window 300s, stale clears the cache). `WHOIS_BATCH_DEBUG_PENALIZE='host1,host2'` still seeds penalty windows for deterministic accelerator smoke tests and golden assertions.
- Signal handling: Ctrl+C/TERM/HUP closes cached connections and short-circuits dial/recv loops for a faster exit; a single termination notice is emitted; process exit explicitly frees DNS/connection caches; `[DNS-CACHE-SUM]`/`[RETRY-*]` still flush via atexit so golden logs stay intact.
- Empty-response fallback: empty-body retry budgets are tightened (ARIN max 2, others 1) with a small backoff between retries to reduce connection bursts under high concurrency; normal success paths are unaffected.
- Authoritative tail tightening: if a hop returns body data but a later referral fails, or rate-limit/denied prevents convergence, the authoritative tail now prints `error` to distinguish failure from a true unknown.
- Entry reuse: all executables go through `wc_client_frontend_run`; when adding a new entry, just build `wc_opts` and call the facade—do not reimplement selftests, signal, or atexit logic in `main`.

Batch strategy quick guide (plain English):
- raw (default): Just follows CLI host → guessed RIR → IANA; no penalty-aware skipping, no cache reuse.
- health-first: Skips penalized hosts up front; if everything is penalized, forces the last candidate. Watch `[DNS-BATCH] start-skip/force-last`.
- plan-a: Remembers the last authoritative RIR and tries it first for a fast start; if that host is penalized, it falls back to the normal list. Watch `[DNS-BATCH] plan-a-*` and `plan-a-skip`.
- plan-b: Cache-first with penalty-aware fallback. Reuses the last authoritative RIR when healthy; if penalized, falls back to the first healthy candidate (or forces override when none). Logs `[DNS-BATCH] plan-b-force-start/plan-b-fallback/force-override/start-skip/force-last` plus cache-window signals `[DNS-BATCH] action=plan-b-hit|plan-b-stale|plan-b-empty` (default 300s window; stale flushes the cache) under `--debug`. When the cached start host becomes penalized, plan-b now drops the cache immediately so the next query goes straight to healthy candidates (you may see a `plan-b-empty` first).

## Navigation (Release & Ops Extras)

Detailed release flow: `docs/RELEASE_FLOW_EN.md` | Chinese: `docs/RELEASE_FLOW_CN.md`

Need one-click Release updating (optionally skip tagging) or a quick remote Makefile build smoke check? See the Operations guide:

- VS Code Task: One-Click Release (inputs & tokens)
  - `docs/OPERATIONS_EN.md` → [VS Code Tasks](./OPERATIONS_EN.md#vs-code-tasks)
- New script: `one_click_release.ps1` (fast GitHub/Gitee Release update)
  - `docs/OPERATIONS_EN.md` → section “New script: one_click_release.ps1”
- Simple remote Makefile build & test
  - `docs/OPERATIONS_EN.md` → [Simple remote Makefile build & test (new)](./OPERATIONS_EN.md#simple-remote-makefile-build--test-new)

(If anchors don’t jump in your viewer, open `OPERATIONS_EN.md` and scroll to the headings.)

Latest validated matrix (2026-02-09, LTO):
- Remote build smoke sync + golden (LTO default): no warnings + LTO no warnings + Golden PASS + referral check PASS, logs `out/artifacts/20260209-122029`.
- Remote build smoke sync + golden (LTO + debug/metrics + dns-family-mode=interleave-v4-first): no warnings + LTO no warnings + Golden PASS + referral check PASS, logs `out/artifacts/20260209-122818`.
- Batch strategy goldens (LTO): raw/health-first/plan-a/plan-b PASS, logs `out/artifacts/batch_{raw,health,plan,planb}/20260209-11*`.
- Selftest goldens (LTO + `--selftest-force-suspicious 8.8.8.8`): raw/health-first/plan-a/plan-b PASS, logs `out/artifacts/batch_{raw,health,plan,planb}/20260209-12*`.
- Redirect matrix 9x6: no authority mismatches/errors, logs `out/artifacts/redirect_matrix_9x6/20260209-133525`.
- CIDR samples (APNIC/AFRINIC/RIPE/ARIN/LACNIC): logs `out/artifacts/cidr_samples/20260209-002242`.
- 48-process batch comparison (recheck+cycle vs cycle-only): logs `out/artifacts/gt-ax6000_recheck_20260209_syslog.log`.
- Remote build smoke sync + golden (LTO default): no warnings + LTO warning + Golden PASS + referral check PASS, logs `out/artifacts/20260201-214831`.
- Remote build smoke sync + golden (LTO default): warnings + LTO warnings + Golden PASS + referral check PASS, logs `out/artifacts/20260130-213229`.
- Remote smoke + golden (default args): `[golden] PASS`, logs `out/artifacts/20260124-045307`.
- Remote smoke + golden (`--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first`): `[golden] PASS`, logs `out/artifacts/20260124-045757`.
- Batch strategy goldens (raw/health-first/plan-a/plan-b): `[golden] PASS`, logs `out/artifacts/batch_{raw,health,plan,planb}/20260124-050*` (reports colocated).
- Selftest goldens (`--selftest-force-suspicious 8.8.8.8`): `[golden-selftest] PASS`, logs `out/artifacts/batch_{raw,health,plan,planb}/20260124-0519**/052***`.
- Remote build smoke sync + golden (LTO default): no warnings + LTO warning + Golden PASS + referral check PASS, logs `out/artifacts/20260124-113056`.
- Remote build smoke sync + golden (LTO default): no warnings + LTO warning + Golden PASS + referral check PASS, logs `out/artifacts/20260124-190255`.

### Redirect matrix test (IPv4)

This test covers multi-RIR redirect chains and authoritative tail decisions. It is standalone and does not run inside build/smoke/golden scripts.

- Script: `tools/test/redirect_matrix_test.ps1`
- Tasks: Test: Redirect Matrix (IPv4), Test: Redirect Matrix (IPv4, Params)
- Output: `redirect_matrix_report_<timestamp>.txt` under the output directory (default: `out/artifacts/redirect_matrix/<timestamp>`).
- Per-case logs: saved under `out/artifacts/redirect_matrix/<timestamp>/cases/` by default; disable with `-SaveLogs false`.
- Exit code: returns 1 when any case fails, 0 when all pass.

Optional parameters:
- `-BinaryPath`: path to whois binary (default `release/lzispro/whois/whois-win64.exe`)
- `-OutDir`: report output directory (default `out/artifacts/redirect_matrix/<timestamp>`)
- `-RirIpPref`: value for `--rir-ip-pref` (`NONE` to skip)
- `-PreferIpv4`: `true|false` to control `--prefer-ipv4`
- `-SaveLogs`: `true|false` to save per-case logs (default `true`)

Notes for Windows artifacts:
- `tools/remote/remote_build_and_test.sh` now builds win32/win64 by default (no need to pass `-w 1`).
- Local Windows examples:
  - PowerShell single: `whois-win64.exe --debug --prefer-ipv4-ipv6 8.8.8.8`; IPv6-only: `whois-win64.exe --debug --ipv6-only 8.8.8.8`
  - PowerShell pipeline: `"8.8.8.8" | whois-win64.exe --debug --ipv4-only` (batch auto-enables when stdin is not a TTY)
  - CMD pipeline: `echo 8.8.8.8 | whois-win64.exe --debug --ipv4-only`
- Wine on Linux: `env WINEDEBUG=-all wine64 ./whois-win64.exe --debug --prefer-ipv6 8.8.8.8` (`wine` for 32-bit), reuse the same smoke args as native.

Notes:
- Optional folded output `--fold` prints a single-line summary per query: `<query> <UPPER_VALUE_...> <RIR>`.
  - `--fold-sep <SEP>` sets the separator between folded tokens (default space; supports `\t`/`\n`/`\r`/`\s`)
  - `--no-fold-upper` preserves original case (default uppercases values and RIR)

## 1. Key features (3.2.0)
- Batch stdin: `-B/--batch` (or implicit when no positional arg and stdin is not a TTY)
- Header + authoritative RIR tail (enabled by default; disable with `-P/--plain`)
  - Header: `=== Query: <query> via <starting-server-label> @ <connected-ip-or-unknown> ===` (e.g., `via whois.apnic.net @ 203.119.102.24`); the query token sits at field `$3`. The label keeps the user-supplied alias when possible, or shows the mapped RIR hostname, while the `@` segment always reflects the first successful connection IP.
  - Tail: `=== Authoritative RIR: <authoritative-server> @ <its-ip|unknown|error> ===`; when the authoritative endpoint is an IP literal, the client maps it back to the corresponding RIR hostname before printing; when it is a known RIR alias/subdomain (e.g., `whois-jp1.apnic.net`), it is normalized to the canonical RIR host. When the tail prints `error @ error`, a matching stderr `Error: Query failed for ...` line is emitted; otherwise no failure line is produced. After folding the tail becomes the last field `$(NF)`.
  - Chain reading tip: in multi-hop paths, the first extra hop that is not driven by an explicit referral can appear as `=== Additional query to ... ===` (instead of `=== Redirected query to ... ===`). This is expected and does not mean a missing intermediate RIR hop.
- Non-blocking connect + IO timeouts + light retry (default 2); automatic redirects (cap by `-R`, disable with `-Q`), loop guard

### Three-hop simulation & retry metrics (apnic→iana→arin)

To deterministically reproduce multi-hop behavior and controlled failures (middle or final hop) while inspecting retry statistics, use these self-test flags (they do NOT alter production defaults):

| Flag | Effect | Purpose |
|------|--------|---------|
| `--selftest-force-iana-pivot` | Forces exactly one early pivot via IANA when a redirect opportunity first appears; subsequent referrals follow the real chain | Ensure stable apnic→iana→arin path |
| `--selftest-blackhole-arin`   | Replaces ARIN dial candidates with documentation addr `192.0.2.1` to induce connect timeouts | Simulate authoritative endpoint unreachable |
| `--selftest-blackhole-iana`  | Blackholes IANA dial candidates | Simulate middle-hop failure |

> Startup note (3.2.10+): enabling any `--selftest-*` fault toggle or demo (`--selftest-fail-first-attempt`, `--selftest-inject-empty`, `--selftest-dns-negative`, `--selftest-blackhole-{arin,iana}`, `--selftest-force-iana-pivot`, `--selftest-{grep,seclog}`) automatically runs the lookup selftest suite once per process before your real queries. `[LOOKUP_SELFTEST]` now appears without a standalone `whois --selftest` prologue, and persistent knobs such as `--selftest-force-{suspicious,private}` are re-applied immediately after the dry run.

#### Fault profile & forced query hooks (3.2.10+)

- All runtime fault toggles (blackholes, DNS-negative, force-iana, fail-first) flow into the shared `wc_selftest_fault_profile_t`. DNS, lookup, and net modules read this snapshot plus its version counter to keep injected behavior consistent across referrals and retries.
- `--selftest-force-suspicious <query|*>` marks specific queries (or `*` for every query) as suspicious before the static detector runs. The pipeline emits `[SELFTEST] action=force-suspicious ...` plus an error line for golden checks, but does not abort when the force flag is set; normal (non-selftest) suspicious detection still blocks as before.
- `--selftest-force-private <query|*>` follows the same pattern for private-IP handling. Forced hits still render the standard private IP body/tail and exit for the affected query; stderr receives `[SELFTEST] action=force-private ...` and an explicit `Error: Private query denied` so smoketests can assert the hook fired. Normal private detection remains unchanged.
- `--selftest-registry` runs a local batch-strategy registry harness (no network) to assert default activation, explicit override, and per-run isolation via `[SELFTEST] action=batch-registry-*` tags. Defaults to off; safe to enable in smoke.

Note: as of 2025-12-25 the `[SELFTEST]` tags above always include an `action=` prefix and emit at most once per process—even if you never run the `--selftest` suite—so smoke/golden greps stay consistent. The DNS ipv6-only/fallback selftests are now WARN-only to avoid aborting on flaky networks.

Example (force suspicious globally, private only for 10.0.0.8):

```bash
printf "1.1.1.1\n10.0.0.8\n" | \
  whois-x86_64 -B --selftest-force-suspicious '*' --selftest-force-private 10.0.0.8
# stderr excerpts:
# [SELFTEST] action=force-suspicious query=1.1.1.1
# [SELFTEST] action=force-private query=10.0.0.8
```

The `[SELFTEST] action=force-*` tags are stderr-only and independent of `--debug`; include them in remote smoke expectations whenever you rely on these hooks.

Example (PowerShell invoking Git Bash):
```powershell
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && \
  ./tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8' -a '--host apnic --selftest-force-iana-pivot --selftest-blackhole-arin --retry-metrics -t 3 -r 0 --ipv4-only' -P 1"
```

Since 2025-12-04 the remote script automatically captures `build_out/referral_143128/{iana,arin,afrinic}.log` and runs `tools/test/referral_143128_check.sh` whenever you keep the default `-L 1` (or omit the flag entirely). Pass `-L 0` or export `REFERRAL_CHECK=0` only when AfriNIC is temporarily unreachable and you merely need the build artifacts.

Sample output snippet:
```text
[RETRY-METRICS-INSTANT] attempt=1 success=1 latency_ms=367 total_attempts=1
[RETRY-METRICS-INSTANT] attempt=2 success=1 latency_ms=227 total_attempts=2
Error: Query failed for 8.8.8.8 (connect timeout, errno=110, host=whois.apnic.net, ip=203.119.102.29, time=2026-01-30 03:11:29)
=== Query: 8.8.8.8 via whois.apnic.net @ 203.119.102.29 ===
[RETRY-METRICS] attempts=7 successes=2 failures=5 min_ms=227 max_ms=3017 avg_ms=2234.1 p95_ms=3017 sleep_ms=0
[RETRY-ERRORS] timeouts=5 refused=0 net_unreach=0 host_unreach=0 addr_na=0 interrupted=0 other=0
=== Authoritative RIR: whois.arin.net @ unknown ===
```

Fields:
- `[RETRY-METRICS-INSTANT]` – per-attempt immediate metrics; `success=1` means the attempt established a connection and produced body data; `latency_ms` is per-attempt elapsed time; `total_attempts` monotonically increases.
- `Error: ... errno=XXX` – unified failure line; includes host/ip/time for quicker triage. Errno differentiates timeout vs refusal vs reachability issues.
- `[RETRY-METRICS]` – aggregated stats for the whole query; `attempts = successes + failures`; latency distribution (`min/max/avg/p95_ms`) spans all attempts; `sleep_ms` is cumulative pacing wait (0 when pacing disabled or no waits occurred).
- `[RETRY-ERRORS]` – categorized failure counters (`timeouts/refused/net_unreach/host_unreach/addr_na/interrupted/other`).

FAQ:
- Why are all `[RETRY-ERRORS]` zero? – No failures occurred (or failures outside listed categories).
- Why can `attempts` exceed `-r`? – The first dial attempt counts; `-r 0` still yields attempt=1.
- Does `sleep_ms` include DNS retry intervals? – No; only connection-level pacing waits.

Remote smoke timeout policy (in `tools/remote/remote_build_and_test.sh`):
- `SMOKE_TIMEOUT_DEFAULT_SECS` – guard timeout for non-metrics runs (default 8s).
- `SMOKE_TIMEOUT_ON_METRICS_SECS` – generous timeout for runs containing `--retry-metrics` (default 45s). Script sends SIGINT first (allow graceful metric flush), then SIGKILL after 5s if still hanging.

Customization example:
```powershell
$env:SMOKE_TIMEOUT_ON_METRICS_SECS='60'; \
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8' -a '--host apnic --selftest-force-iana-pivot --selftest-blackhole-arin --retry-metrics -t 3 -r 0 --ipv4-only'"
```

### Network retry context (3.2.10+)

- Each client process now owns a single `wc_net_context` instance created during runtime init. That context is passed into every lookup entry point (single queries, batch stdin loops, auto lookup selftests), so all `[RETRY-METRICS]`, `[RETRY-METRICS-INSTANT]`, and `[RETRY-ERRORS]` counters remain continuous even when the selftest warm-up runs before your real queries.
- Restart the process if you require fresh counters; otherwise the shared context intentionally preserves pacing budgets and error tallies across multiple queries so you can correlate diagnostics inside the same batch session.

Note: Blackholing is a controlled simulation, not a real service outage; the header/tail contract remains intact for easy diffing against real queries.

## 2. Command line

```
Usage: whois-<arch> [OPTIONS] <IP or domain>

Core meta options:
  -H, --help               Show help
  -v, --version            Show version
  -l, --list               List built-in servers
      --about              Detailed feature/modules overview
      --examples           Extended usage examples

Note: pure meta options (help/version/about/examples/list) return immediately and skip runtime initialization; stdout/stderr contracts remain unchanged.

Runtime / query options:
  -h, --host HOST          Specify starting whois server (alias or domain, e.g. apnic / whois.apnic.net)
  -g, --title PATTERNS     Title filter (header lines only): case-insensitive prefix match on key names; use '|' to separate multiple prefixes (e.g., inet|netname). Not a regex; matching headers keep their continuation lines.
      --keep-continuation-lines  Keep continuation lines in line mode (default)
      --no-keep-continuation-lines  Drop continuation lines in line mode
  -p, --port PORT          Port number (default 43)
  -b, --buffer-size SIZE   Response buffer size, supports 1K/1M/1G suffixes (default 512K)
  -d, --dns-cache COUNT    DNS cache entries (default 10)
  -c, --conn-cache COUNT   Connection cache entries (default 5)
  -T, --cache-timeout SEC  Cache TTL seconds (default 300)
      --cache-counter-sampling  Emit cache counter samples periodically even without --debug (off by default; auto-enabled when any --selftest* toggle is used)
  -r, --retries COUNT      Max retry times per single request (default 2)
      --retry-all-addrs    Apply retries to every resolved IP (default: only first)
      --max-host-addrs N   Cap per-host dial attempts (default 0 = unbounded, range 1..64). Enforced in DNS candidate build and lookup; once N candidates are tried, remaining addresses are skipped. Under --debug you will see `[DNS-LIMIT] host=<h> limit=<n> appended=<k> total=<m>` plus `[NET-DEBUG] host=<h> max-host-addrs=<n> (ctx=<c> cfg=<g>)` for the resolved limit.
        --dns-backoff-window-ms N  DNS backoff failure window in ms (default 10000, 0=disable window)
      --dns-append-known-ips  Append built-in RIR known IPs to DNS candidates (opt-in, fill only)
  -t, --timeout SECONDS    Network timeout (default 5s)
  -i, --retry-interval-ms MS  Base sleep between retries in milliseconds (default 300)
  -J, --retry-jitter-ms MS    Extra random jitter in milliseconds (0..MS, default 300)
  -R, --max-redirects N    Max referral redirects to follow (default 6). If another redirect is required after the cap, stop immediately and fall back to `Authoritative RIR: unknown @ unknown`. Alias: --max-hops
  -Q, --no-redirect        Same as `-R 1`: only query the starting server; if a referral is present, stop immediately and fall back to `Authoritative RIR: unknown @ unknown`.
  -B, --batch              Read queries from stdin (one per line); forbids positional query
      --batch-strategy NAME  Opt-in batch start-host strategy/accelerator (default batching keeps raw ordering). Pass `health-first`, `plan-a`, or `plan-b`; unknown names log `[DNS-BATCH] action=unknown-strategy ...` once and fall back automatically
      --batch-interval-ms M  Sleep M ms between batch queries (default: 0)
      --batch-jitter-ms J    Add random 0..J ms to batch interval (default: 0)
      --ipv6-only            Force IPv6 only; disables forced-ipv4/known-ip fallbacks for strict IPv6 behavior
      --ipv4-only            Force IPv4 only (no IPv6 fallback involved)
  -P, --plain              Plain output (suppress header, RIR tail, and referral hint lines)
      --show-non-auth-body Keep non-authoritative bodies before the authoritative hop
      --show-post-marker-body Keep bodies after the authoritative hop (combine with --show-non-auth-body to keep all)
      --hide-failure-body Hide rate-limit/denied body lines (default: keep)
  -D, --debug              Debug logs to stderr
  --security-log           Enable security event logging to stderr (rate-limited)
  --debug-verbose          Extra verbose diagnostics (redirect/cache instrumentation)
  --selftest               Run internal self-tests (fold basics & unique) then exit; the same lookup suite now auto-runs once whenever you enable any `--selftest-*` runtime fault toggle, so keep this flag for standalone selftest runs only
      --selftest-force-suspicious Q  Mark a query (or '*' for all) as suspicious before lookup runs
      --selftest-force-private Q     Mark a query (or '*' for all) as private before lookup runs
  --fold                   Fold output to a single line per query
  --fold-sep STR           Separator for folded output (default space; \t/\n/\r/\s supported)
  --no-fold-upper          Preserve original case when folding (default uppercases values)
  --fold-unique            De-duplicate tokens when folding (preserve first occurrence order)
```

Notes:
- If no positional query is provided and stdin is not a TTY, batch mode is enabled implicitly; `-B` enables it explicitly.
- With `-Q` (no redirect), the tail RIR just shows the actual queried server and may NOT be authoritative.
- Redirect note: when a RIR replies with rate-limit/denied, the client treats it as a non-authoritative redirect and continues; if no ERX/IANA marker was seen and all RIRs are exhausted, authority falls back to `error`, otherwise it uses the first ERX/IANA-marked RIR. Failure lines on stderr are emitted only when the final tail is `error @ error`; otherwise no `Error: Query failed for ...` line is produced. Under `--debug`, rate-limit/denied hops emit `[RIR-RESP] action=denied|rate-limit ...` to stderr. Comment-only (banner-only) RIR responses are treated as empty responses: the hop is retried, and if it remains empty the client redirects (non-ARIN hop pivots to ARIN; ARIN enters the RIR cycle). Empty-response retries emit stderr tags `[EMPTY-RESP] action=...` for diagnostics. If rate-limit/denied prevents querying a RIR and an ERX/IANA marker was seen but no authority converged, the client performs a single baseline IP recheck (CIDR mask stripped) on the first ERX/IANA-marked RIR after the RIR cycle completes; if the recheck still fails or shows non-authoritative markers, authority remains `error`. A LACNIC internal redirect to ARIN omits the ARIN query prefix and often triggers `Query terms are ambiguous`, so ARIN is not marked visited in that case and the next hop re-queries ARIN with the proper prefix.
 - `-g` matches only on header lines whose first token ends with ':'; when a header matches, its continuation lines (starting with whitespace until the next header) are also included; without `-g`, the full body is passed through.
 - Important: `-g` uses case-insensitive prefix matching and is NOT a regular expression.

Debug control:
- Use `-D/--debug` to enable basic debug/TRACE logs to stderr (off by default).
- Use `--debug-verbose` to enable extra verbose diagnostics (redirect/cache instrumentation).
- When a query carried ARIN-style prefixes (e.g., `n + =`) but the hop is not ARIN, the lookup path strips the prefix and logs `[DNS-ARIN] strip-prefix ...` (emits under `--debug` or retry-metrics).
- Note: enabling debug via environment variables is not supported.
- Debug capture tip: queries that hit built-in known-IP shortcuts (e.g., 8.8.8.8 → whois.iana.org/arin) may produce little/no DNS/retry logs under `--debug`. Add `--retry-metrics --dns-cache-stats --no-known-ip-fallback` to force DNS/retry paths; append `--ipv4-only` if you need IPv4-only dialing. Example: `./whois-x86_64 --title --debug --retry-metrics --dns-cache-stats --no-known-ip-fallback 8.8.8.8 2>debug.log`.

Batch accelerator diagnostics:
- `--batch-strategy <name>` selects optional start-host accelerators for batch mode. When omitted the client keeps the raw order (CLI host → guessed RIR → IANA) without penalty-based skips or plan-a cache hits.
  - `health-first` mirrors the classic canonical-host ordering plus DNS penalty awareness; it is required for `[DNS-BATCH] action=start-skip/force-last` logs.
  - `plan-a` caches the authoritative RIR reported by the previous successful query and reuses it as the next starting point when the backoff snapshot shows no penalty, emitting `[DNS-BATCH] action=plan-a-faststart` (hit), `plan-a-skip` (penalized, so fall back), and `plan-a-cache` (cache update/clear) logs when debug is enabled. Unknown names emit a single `[DNS-BATCH] action=unknown-strategy name=<input> fallback=health-first` line and then enable `health-first` as a safe fallback.
  - `plan-b` reuses the last authoritative RIR when healthy; on penalty it falls back to the first healthy candidate (or forces override/last). Emits `[DNS-BATCH] plan-b-force-start/plan-b-fallback/force-override/start-skip/force-last` under `--debug`.
- `WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net'` (comma-separated list) preloads penalty windows before the batch loop starts. Pair it with `--batch-strategy health-first` (for `start-skip/force-last`) or `--batch-strategy plan-a` (for cache hits) plus `tools/remote/remote_build_and_test.sh -F <stdin_file>` to get deterministic `[DNS-BATCH] action=...` sequences without waiting for real network failures.

#### Batch strategy quick playbook (raw / health-first / plan-a / plan-b)

The commands below keep stdout contracts intact and focus on capturing stderr diagnostics for reproducible golden runs. Replace `<host>`, `<user>`, `<key>` with your remote runner information; omit `-s/--sync` arguments if you do not need artifacts copied back.

1. **Raw baseline (default ordering)**  
   ```bash
   tools/remote/remote_build_and_test.sh \
     -H <host> -u <user> -k '<key>' -r 1 -q '8.8.8.8 1.1.1.1' -P 1 \
     -a '--debug --retry-metrics --dns-cache-stats' -G 1 -E ''
   ```
  Use `tools/test/golden_check_batch_presets.sh raw --selftest-actions force-suspicious,force-private -l <log>` afterwards when you need `[SELFTEST] action=force-*` assertions (omit the option if the run stayed clean).

2. **health-first accelerator** (penalty-aware start host)  
   ```bash
   WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.iana.org,whois.ripe.net' \
   tools/remote/remote_build_and_test.sh \
     -H <host> -u <user> -k '<key>' -r 1 -P 1 -F testdata/queries.txt \
     -a '--batch-strategy health-first --debug --retry-metrics --dns-cache-stats' -G 1 -E ''
   ```
  Validate with `tools/test/golden_check_batch_presets.sh health-first --selftest-actions force-suspicious,force-private -l <log>` so that batch + selftest hooks are checked in a single pass.

3. **plan-a accelerator** (authoritative cache reuse)  
   ```bash
   WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net' \
   tools/remote/remote_build_and_test.sh \
     -H <host> -u <user> -k '<key>' -r 1 -P 1 -F testdata/queries.txt \
     -a '--batch-strategy plan-a --debug --retry-metrics --dns-cache-stats' -G 1 -E ''
   ```
  Validate with `tools/test/golden_check_batch_presets.sh plan-a --selftest-actions force-suspicious,force-private -l <log>` (adjust the list if you exercised different `--selftest-force-*` knobs).

4. **plan-b accelerator (cache-first, penalty-aware)**  
  ```bash
  tools/remote/remote_build_and_test.sh \
    -H <host> -u <user> -k '<key>' -r 1 -P 1 -F testdata/queries.txt \
    -a '--batch-strategy plan-b --debug --retry-metrics --dns-cache-stats' -G 1 -E ''
  ```
  Current builds emit `[DNS-BATCH] plan-b-force-start/plan-b-fallback/force-override/start-skip/force-last` when applicable; `tools/test/golden_check_batch_presets.sh plan-b ...` now asserts these tags alongside header/tail contracts.

`golden_check_batch_presets.sh` consumes `--selftest-actions list` itself (before `-l ...`) and forwards all other arguments (e.g., `--strict`, `--query`) verbatim to `golden_check.sh`. Keep the `WHOIS_BATCH_DEBUG_PENALIZE` list aligned with the scenario so the expected `[DNS-BATCH] action=*` lines appear deterministically.

  Single-query golden (`tools/test/golden_check.sh`) tips:

  - Capped referrals (e.g., `-R 2` where the tail can become `unknown @ unknown`):
    ```bash
    tools/test/golden_check.sh -l out/artifacts/<ts>/build_out/smoke_test.log \
      --query 8.8.8.8 --start whois.iana.org --auth whois.arin.net \
      --auth-unknown-when-capped --redirect-line whois.afrinic.net
    ```
    If the log only has `Additional`/`Redirect` without a tail, the script auto-allows it and prints `[INFO] tail missing but allowed`.

  - Selftest-only logs (contain `[SELFTEST] action=*` but no header/tail):
    ```bash
    tools/test/golden_check.sh -l out/artifacts/<ts_selftest>/build_out/smoke_test.log \
      --selftest-actions force-suspicious --selftest-actions-only
    ```

  **Windows one-click (raw + health-first + plan-a + plan-b)** – run all four rounds plus golden checks via PowerShell:

  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File tools/test/remote_batch_strategy_suite.ps1 `
    -Host 10.0.0.199 -User larson -KeyPath '/c/Users/you/.ssh/id_rsa' `
    -Queries '8.8.8.8 1.1.1.1' -BatchInput testdata/queries.txt `
    -SelftestActions 'force-suspicious,*;force-private,10.0.0.8' -EnablePlanB
  ```

  `-SelftestActions 'action,target;...'` appends `--selftest-actions` to every preset so `[SELFTEST] action=*` gets asserted alongside the usual `[DNS-BATCH]` checks.

## 3. Output contract (for BusyBox pipelines)
- Header: `=== Query: <query> via <starting-server-label> @ <connected-ip-or-unknown> ===`; the query remains `$3`
- Tail: `=== Authoritative RIR: <authoritative-server> @ <its-ip-or-unknown> ===`; literals are mapped back to canonical RIR hostnames, and the tail token is still `$(NF)` after folding
- Private IP: body prints `"<ip> is a private IP address"` and the tail stays `=== Authoritative RIR: unknown ===`

Folding example (aligned with `func/lzispdata.sh` style):

```sh
... | grep -Ei '^(=== Query:|netname|mnt-|e-mail|=== Authoritative RIR:)' \
  | awk -v count=0 '/^=== Query/ {if (count==0) printf "%s", $3; else printf "\n%s", $3; count++; next} \
      /^=== Authoritative RIR:/ {printf " %s", toupper($4)} \
      (!/^=== Query:/ && !/^=== Authoritative RIR:/) {printf " %s", toupper($2)} END {printf "\n"}'
# Tip: after folding, `$(NF)` is the authoritative RIR (uppercase); even if the query finished on an IP literal, the client emits the mapped hostname, so filtering still works
```

### Helper scripts (Windows + Git Bash)

To simplify multi-word argument passing under PowerShell, the following wrapper scripts are provided:

- `tools/remote/invoke_remote_plain.sh` – remote multi-arch build + smoke + golden (standard format).
- `tools/remote/invoke_remote_demo.sh` – demo folded output with `--fold --fold-unique -g 'netname|OrgName'` (no golden).
- `tools/remote/invoke_remote_selftest.sh` – run `--selftest` only.

Each wraps `tools/remote/remote_build_and_test.sh` with preset env variables.

## 4. Common examples

```sh
# Single (with auto redirects)
whois-x86_64 8.8.8.8

# Force starting RIR and disable redirects
whois-x86_64 --host apnic -Q 103.89.208.0

# Batch (explicit)
cat ip_list.txt | whois-x86_64 -B --host apnic

# Plain output (no header/tail)
whois-x86_64 -P 8.8.8.8
```

## 5. Exit codes
- `0` (`WC_EXIT_SUCCESS`): success  
  - Single query: lookup pipeline finished successfully; even if the RIR reports "no data" (e.g. `no-such-domain-abcdef.whois-test.invalid`), the client still treats the run as a successful completion and returns 0.  
  - Batch mode: the process exit code reflects whether the batch as a whole ran to completion; individual per-line failures (network/lookup errors, suspicious/private IPs, etc.) are printed to stderr on a per‑query basis, but do not change the process exit code from 0.  
- `1` (`WC_EXIT_FAILURE`): generic failure  
  - CLI usage / parameter errors (e.g. invalid combinations such as `-B` plus a positional query, out‑of‑range numeric flags, missing required arguments) – the client prints an error message and the Usage block once, then exits with 1.  
  - Runtime failures for a single query where the client cannot obtain a valid response (e.g. dial/connect errors after retries, hard DNS failures, internal pipeline errors).  
- `130` (`WC_EXIT_SIGINT`): interrupted by SIGINT (Ctrl‑C)  
  - The client prints `[INFO] Terminated by user (Ctrl-C). Exiting...` to stderr, flushes pending cleanup hooks (including DNS/metrics stats), and then exits with 130. Scripts and tests may rely on this exact value.  

## 6. Tips
- Prefer leaving sorting/dedup/aggregation to outer BusyBox scripts (grep/awk/sed)
- To stick to a fixed server and minimize instability from redirects, use `--host <rir> -Q`
- In automatic redirects mode, too small `-R` may lose authoritative info; too large may add latency; default 6 is typically enough
- When no explicit referral is present but the response indicates the address is not managed by the current RIR (e.g. ERX/IANA-netblock banners), the client will try remaining RIRs in order APNIC → ARIN → RIPE → AFRINIC → LACNIC, skipping already visited RIRs.
  - APNIC IANA-NETBLOCK banners containing “not allocated to APNIC” or “not fully allocated to APNIC” are treated as redirect hints even if the response contains object fields.
  - Retry pacing (connect-level, 3.2.7): default ON (CLI-only). Defaults: `interval=60`, `jitter=40`, `backoff=2`, `max=400`.
   Flags: `--pacing-disable` | `--pacing-interval-ms N` | `--pacing-jitter-ms N` | `--pacing-backoff-factor N` | `--pacing-max-ms N`.
   Metrics: `--retry-metrics` (stderr lines `[RETRY-METRICS] sleep_ms=...`).
   Selftest/Debug: `--selftest-fail-first-attempt` | `--selftest-inject-empty` | `--selftest-grep` | `--selftest-seclog` (last two need compile-time `-DWHOIS_GREP_TEST` / `-DWHOIS_SECLOG_TEST`).
   Generic (not pacing) retry knobs: `-i/--retry-interval-ms`, `-J/--retry-jitter-ms`.
   Quick A/B check (with `--retry-metrics`): default shows non-zero `sleep_ms`; adding `--pacing-disable` keeps `sleep_ms=0`.
   Remote smoke assertion examples (PowerShell):
   ```powershell
   # Expect non-zero sleeps
   & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8 1.1.1.1' -a '--retry-metrics --selftest-fail-first-attempt' -M nonzero"
   # Expect zero sleeps when disabled
   & 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -q '8.8.8.8 1.1.1.1' -a '--retry-metrics --selftest-fail-first-attempt --pacing-disable' -M zero"
   ```

### Errno quick reference (connect stage)

- Source: connect failures are obtained via `getsockopt(..., SO_ERROR)`/`errno`. Read-stage timeouts do not increment `[RETRY-ERRORS]` (but they do count as failures in `[RETRY-METRICS]`).
- Architecture variance: `ETIMEDOUT` is `110` on most arches and `145` on MIPS/MIPS64. Behavior matches symbolic constants, not numeric values.
- Tip: prefer `strerror(errno)` for human-readable diagnostics (e.g., "Connection timed out").

| Symbol       | Common value | MIPS/MIPS64 | Meaning                          |
|--------------|--------------|-------------|----------------------------------|
| ETIMEDOUT    | 110          | 145         | connect timeout                  |
| ECONNREFUSED | 111          | 111         | connection refused (closed/fw)   |
| EHOSTUNREACH | 113          | 113         | host unreachable (routing/ACL)   |

## 7. DNS resolver control / IP family preference / negative cache (3.2.7 & Phase1)

IP family preference (resolution + dialing order):
  - `--ipv4-only` force IPv4 only (FIX: no longer dials canonical hostname first which could yield IPv6 pre-filter)
  - `--ipv6-only` force IPv6 only
  - `--prefer-ipv4` prefer IPv4 then IPv6
  - `--prefer-ipv6` prefer IPv6 then IPv4
  - `--prefer-ipv4-ipv6` prefer IPv4 on the first hop, switch to IPv6-first for referrals/retries (still auto-fallback to the other family if the preferred one fails)
  - `--prefer-ipv6-ipv4` mirror of the above: IPv6-first on hop 0, IPv4-first afterwards (useful when IPv4 is faster locally but unstable across multiple redirects)
  - `--rir-ip-pref arin=v4,ripe=v6,...` per-RIR override (partial lists allowed). Priority: `--ipv4-only/--ipv6-only` > per-RIR > `--dns-family-mode-*` > global `--prefer-*`. Per-RIR overrides map to `ipv4-only-block`/`ipv6-only-block` for the matching RIR.
  - `--dns-family-mode <mode>` chooses the global fallback ordering: `interleave-v4-first` / `interleave-v6-first` / `seq-v4-then-v6` / `seq-v6-then-v4` / `ipv4-only-block` / `ipv6-only-block`. Per-hop overrides: `--dns-family-mode-first <mode>` (first hop) and `--dns-family-mode-next <mode>` (second+ hops) accept the same modes. Priority: single-stack (explicit or probed) > per-RIR override > per-hop overrides > global mode > prefer defaults. Under `--debug` you’ll see `[DNS-CAND] mode=<...> start=ipv4|ipv6` reflecting the effective hop.
  - Block modes (`ipv4-only-block` / `ipv6-only-block`) do not append canonical hostname fallbacks; only numeric results from the allowed family are kept. When `--dns-family-mode-next` is not set, the global `--dns-family-mode` also applies to second+ hops.

CIDR query normalization:
  - `--cidr-strip` when the query is CIDR (e.g. `1.1.1.0/24`), send only the base IP to the server while keeping the original CIDR string in the header line.
  - `--no-cidr-erx-recheck` disable ERX/IANA baseline recheck for CIDR (enabled by default).

  Startup probes IPv4/IPv6 availability once: IPv6 is treated as available only when a global address is present (2000/4000::/3). If both fail the process exits fatal; if only one works it auto-forces the matching block mode and ignores the opposite flags with a notice; if both work and no explicit prefer/only/family was set, the effective default becomes `--prefer-ipv6` + `--dns-family-mode-first interleave-v6-first` + `--dns-family-mode-next seq-v6-then-v4` (global fallback stays `seq-v6-then-v4`). `[NET-PROBE]` debug lines show the probed state when `--debug` is on.

Negative DNS cache (short TTL):
  - `--dns-neg-ttl <sec>` TTL for negative cache entries (default 10s)
  - `--no-dns-neg-cache` disable negative caching

Resolver & candidate controls (Phase1, CLI-only):
  - `--no-dns-addrconfig` disable `AI_ADDRCONFIG` (default ON; helps avoid unusable families on host lacking IPv6)
  - `--dns-retry N` retry count for transient `EAI_AGAIN` (default 3, range 1..10)
  - `--dns-retry-interval-ms M` sleep interval between DNS retries (default 100, range 0..5000 ms)
  - `--dns-max-candidates N` cap total resolved dial candidates (default 12, range 1..64)
  - `--dns-cache-stats` emit a single process-level DNS cache summary line on stderr at exit (diagnostics only, no behavior change). Example:

    ```text
    [DNS-CACHE-SUM] hits=10 neg_hits=0 misses=3
    ```

    where:
    - `hits` – number of **positive cache hits** in this process. Incremented when a domain/hostname resolution is served directly from the DNS cache (no new `getaddrinfo` call).
    - `neg_hits` – number of **negative cache hits** in this process. Incremented when a previous resolution failure (e.g., NXDOMAIN) was cached and a later query reuses that negative entry without performing a real DNS lookup.
    - `misses` – number of **cache misses** in this process. Incremented when neither a positive nor negative cache entry exists and the client must perform a fresh DNS resolution (`getaddrinfo`).

    Intuitively: more `hits` means better reuse of prior DNS work; high `neg_hits` usually indicates repeated queries for domains that don’t currently resolve; large `misses` suggests a low cache hit rate (highly diverse query set or a “cold” process).

> Dec 2025 update: the legacy DNS cache has been fully retired. `wc_dns` is now the sole resolver/cache data plane, `[DNS-CACHE-SUM]` already pulls stats from `wc_dns`, and `[DNS-CACHE-LGCY]` / `[DNS-CACHE-LGCY-SUM]` no longer emit (shim is removed). If you need to diagnose the old path, use a dedicated branch or local patch instead of runtime knobs.
  - Plain speak: `--no-dns-addrconfig` turns off the OS filter that hides address families your host can't use (e.g., IPv6 on IPv4-only hosts) — you usually want to keep it ON. `--dns-retry*` only applies to transient DNS errors (EAI_AGAIN).

Phase‑2 helper recap (`wc_dns` module):
  - `wc_dns_build_candidates()` keeps user-specified IP literals as the first entries, normalizes aliases (arin/apnic/...) via `wc_dns_canonical_host_for_rir()`, then interleaves IPv6/IPv4 results according to the active `--prefer-*` / `--ipv*-only` / `--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4` policy for the current hop.
  - The helper enforces `--dns-retry*`, respects `--dns-max-candidates`, de-duplicates addresses, and falls back to the canonical hostname when only literals are provided, so dialing order stays deterministic.
  - Empty-response recovery, forced-IPv4 retries, known IPv4 fallback, and selftest blackhole paths all re-use the same candidate list. Disabling `--no-known-ip-fallback`/`--no-force-ipv4-fallback` simply removes those extra layers while the base candidate ordering remains intact.

Fallback behavior toggles (ON by default; add flags to turn OFF):
  - `--no-known-ip-fallback` disable known IPv4 fallback set (RIR-specific fixed IPv4s)
  - `--no-force-ipv4-fallback` disable forced-IPv4 retry path (post empty/error scenarios)
  - `--no-iana-pivot` disable IANA pivot when referral chain is missing (may reduce authoritative resolution success)

Notes: Positive cache stores successful domain→IP resolutions. Negative cache remembers resolution failures briefly to skip repeated attempts and reduce latency. Entries expire automatically; any successful resolution overwrites a prior negative entry. Under `--ipv4-only/--ipv6-only` the client now omits the raw hostname pre-dial and directly enumerates numeric addresses of the requested family to prevent cross-family leakage.

### DNS debugging (Phase 2 helpers)

- Combine `--debug --retry-metrics --dns-max-candidates <N>` to stream both candidate ordering (`[DNS-CAND]`) and fallback actions (`[DNS-FALLBACK]`) to stderr while keeping stdout untouched.
- `[DNS-CAND]` lists each hop’s dial targets with `idx`, `type` (`ipv4`/`ipv6`/`host`), `origin` (`input`/`resolver`/`canonical`), the active `pref=` label (e.g. `v4-then-v6-hop1`) and shows `limit=<N>` when `--dns-max-candidates` trims results.
- `[DNS-FALLBACK]` fires when a non-primary path is used (forced IPv4, known IPv4, empty-body retries, IANA pivot, etc.), echoes both the bitset from `fallback_flags` and the same `pref=` label, making it easier to correlate operator intent with the actual fallback that ran.
- ARIN queries: when dialing `whois.arin.net` and the query does **not** contain a space (no user-supplied flags), the client auto-injects the common ARIN prefixes: IP/IPv6 `n + =`, CIDR `r + =`, ASN `a + =` (case-insensitive `AS...`), NetHandle `n + = !`. Any query containing a space is treated as already flagged and is sent verbatim. If `--cidr-strip` is enabled, CIDR input is treated as an IP literal and the CIDR prefix length is not sent. If an ARIN response contains "No match found for" without a referral, the client pivots to `whois.iana.org` with the original query (without ARIN flags) to continue resolution.
- Special note: IPv4 `0.0.0.0` now returns `unknown` to stay aligned with `0.0.0.0/0`.
- Recommended experiments:
  - `--no-force-ipv4-fallback --selftest-inject-empty` to prove that the extra IPv4 layer is disabled.
  - `--no-known-ip-fallback` to observe the raw error surface.
  - `--dns-no-fallback` to disable both forced/known IPv4 add-on fallbacks while keeping the primary candidate logic intact (see examples below).

If you prefer a single “batteries-included” command instead of wiring all flags manually, see `docs/OPERATIONS_EN.md` → “DNS debug quickstart (Phase 2/3)”, which uses:

```bash
whois-x86_64 --debug --retry-metrics --dns-cache-stats 8.8.8.8
whois-x86_64 --debug --retry-metrics --dns-cache-stats --selftest-blackhole-arin 8.8.8.8
```

Those runs emit `[DNS-CAND]` / `[DNS-FALLBACK]` / `[DNS-CACHE]` / `[DNS-HEALTH]` to stderr and a single `[DNS-CACHE-SUM] ...` line at process exit, giving you a compact view of resolver candidates, fallback decisions, cache behaviour and per-host health. Adding any `--selftest-*` knob (as in the second command) now triggers the lookup selftest block automatically before the real query, so `[LOOKUP_SELFTEST]` shows up without needing a separate `--selftest`-only invocation.

Example (capture stderr):

```powershell
whois-x86_64 --debug --retry-metrics --selftest-blackhole-arin --host arin 8.8.8.8 2> dns_trace.log
# [DNS-CAND] hop=1 server=whois.arin.net rir=arin idx=0 target=whois.arin.net type=host origin=canonical limit=2
# [DNS-CAND] hop=1 server=whois.arin.net rir=arin idx=1 target=104.44.135.12 type=ipv4 origin=resolver limit=2
# [DNS-FALLBACK] hop=1 cause=connect-fail action=forced-ipv4 domain=whois.arin.net target=104.44.135.12 status=success flags=forced-ipv4
# [DNS-FALLBACK] hop=1 cause=manual action=iana-pivot domain=whois.arin.net target=whois.iana.org status=success flags=forced-ipv4|iana-pivot
```

Diagnostics (no behavior change):
  - `--retry-metrics` print retry pacing stats to stderr to see if/when waits happen; it does not slow the client itself.

Examples:
```powershell
# Prefer IPv4; set negative cache TTL to 30 seconds
whois-x86_64 --prefer-ipv4 --dns-neg-ttl 30 8.8.8.8

# Selftest: simulate negative-cache path (domain selftest.invalid gets marked negative)
whois-x86_64 --selftest-dns-negative --host selftest.invalid 8.8.8.8

# IPv4-only; cap candidates to 4 and disable known IPv4 fallback
whois-x86_64 --ipv4-only --dns-max-candidates 4 --no-known-ip-fallback 1.1.1.1

# IPv6-only; disable IANA pivot (stick to fixed starting RIR)
whois-x86_64 --ipv6-only --no-iana-pivot --host apnic 1.1.1.1
```

#### DNS debugging tips (Phase2)

- Baseline recipe: `--debug --retry-metrics --dns-max-candidates <N>`. The first two flags emit connect-level pacing/diagnostics to stderr; the last one makes it obvious when the candidate list is being truncated.
- Toggle `--prefer-ipv6` / `--prefer-ipv4` to watch how IPv6-first vs IPv4-first ordering impacts retry attempts (check `[RETRY-METRICS]` lines and the warning banners such as `=== Warning: empty response ... ===`).
- Fallback validation:
  - Combine `--no-force-ipv4-fallback` with `--selftest-inject-empty` to confirm the forced-IPv4 layer is disabled.
  - Add `--no-known-ip-fallback` to ensure the known IPv4 safety net is skipped, so errors bubble up immediately.
  - Use `--dns-no-fallback` to turn off both forced-IPv4 and known-IPv4 *extra* fallback layers in one go, leaving only the primary path active. This is useful when comparing "with vs without extra fallback" behavior (see sample commands below).
- Read `docs/RFC-dns-phase2.md` beforehand for the rationale behind candidate generation and the fallback stack.

Sample commands:
```powershell
# Observe candidate capping + IPv6→IPv4 ordering + empty-response retry
whois-x86_64 --debug --retry-metrics --dns-max-candidates 2 --prefer-ipv6 --selftest-inject-empty example.com

# Compare behavior when forced-IPv4 fallback is disabled
whois-x86_64 --debug --retry-metrics --no-force-ipv4-fallback --selftest-inject-empty --host arin 8.8.8.8

# Compare behavior with and without dns-no-fallback in a real ARIN scenario:
# 1) Extra fallbacks enabled (you may see action=forced-ipv4/known-ip):
whois-x86_64 --debug --retry-metrics -h arin 8.8.8.8
# 2) Extra fallbacks disabled (fallback branch only logs action=no-op status=skipped flags=dns-no-fallback):
whois-x86_64 --debug --retry-metrics --dns-no-fallback -h arin 8.8.8.8
```

### DNS debug logs & cache observability (3.2.9)

When either `--debug` or `--retry-metrics` is active the resolver emits structured stderr lines that line up with the retry instrumentation. Typical order per hop is `[DNS-CAND]` (once per candidate), `[RETRY-METRICS-INSTANT]` (once per dial attempt), and, if the attempt fails, `[DNS-FALLBACK]`/`[DNS-ERROR]` before the next attempt. Because both toggles share the same gating hook you still get DNS insights even when you only care about pacing metrics.

Key tags and how to read them:
- `[DNS-CAND]` enumerates the dial list in the exact order it will be attempted. `type` reflects IPv4/IPv6/host, while `origin` reveals where the entry came from: `input` (user-supplied literal), `canonical` (mapped RIR name), `resolver` (fresh `getaddrinfo` data), `cache` (positive cache reuse with stored `sockaddr`), or `selftest`. A trailing `limit=<N>` confirms that `--dns-max-candidates` truncated the list. Under `--ipv4-only` or `--ipv6-only` the canonical host placeholder is no longer inserted, so the list stays pure numeric and mirrors the requested family without a leading host entry.
- `[DNS-FALLBACK]` fires whenever the fallback stack kicks in (forced IPv4, known IPv4, empty-body retry, IANA pivot). The `flags` field mirrors the `fallback_flags` bitset, and optional `errno` / `empty_retry=` annotations explain why a branch executed. Seeing `status=success` means the fallback produced a fresh `[RETRY-METRICS-INSTANT]` attempt.
- `[DNS-BACKOFF]` appears when a dial candidate is currently penalized by the shared server backoff window. Fields include `server` (logical whois host), `target` (dial token), `family`, `action` (skip/force-last/force-override), `consec_fail`, and `penalty_ms_left`, mirroring the underlying `wc_dns_health` snapshot so you can correlate with `[DNS-HEALTH]` and batch scheduler logs.
- `[DNS-ERROR]` reports resolver failures. `source=resolver` indicates a direct `getaddrinfo` error, whereas `source=negative-cache` tells you the request was skipped because the short-lived negative cache still holds the failure (`--dns-neg-ttl` controls its lifetime). The `gai_err` code is the raw `getaddrinfo` status for easy correlation with system logs.

Cache behavior summary:
- Positive cache entries reuse both the textual token and its captured `sockaddr`, so repeat queries avoid re-parsing IP literals or re-running DNS; you will see `origin=cache` on `[DNS-CAND]` lines when this occurs. The cache size is controlled by `--dns-cache N` (default matches the build configuration) and respects the global `cache_timeout`.
- Negative cache entries only store the failure code and expire according to `--dns-neg-ttl` (default 10s). They reduce noisy resolver spam on obviously bad hosts and surface via `[DNS-ERROR ... source=negative-cache ...]`.

Process-level snapshot (`--dns-cache-stats`):
- When `--dns-cache-stats` is set, the client prints a final one-line summary after all queries in the process have completed (or after `--selftest` finishes), for example:

  ```text
  [DNS-CACHE-SUM] hits=10 neg_hits=0 misses=3
  ```

- This is a read-only diagnostic view built on top of the existing per-hop `[DNS-CACHE]` counters and does not change DNS behavior.

Interleaving with retry metrics:
- The resolver prints all `[DNS-CAND]` lines before the first dial, so you can match candidate indices with `attempt=#` in `[RETRY-METRICS-INSTANT]`.
- Each forced retry (timeouts, empty body, injected selftests) logs a `[DNS-FALLBACK]` describing the cause, then restarts the connect loop with the remaining candidates. This means `[DNS-FALLBACK]`/`[DNS-ERROR]` may appear between `attempt=N` and `attempt=N+1`, clarifying why a later attempt might jump directly to a different IP family.
- Because `--ipv4-only`/`--ipv6-only` now bypass the canonical host pre-dial, all attempts in `[RETRY-METRICS-INSTANT]` for those modes map 1:1 to numeric entries, which makes cross-referencing log lines trivial.

### Security logging (optional)

- Use `--security-log` to emit SECURITY events to stderr for diagnostics and hardening validation. Examples of events: input validation rejects, protocol anomalies, redirect target validation failures, response sanitization, and connection flood detection. This does not change the normal stdout output contract and is off by default.
- Security logs are rate-limited to avoid stderr flooding during attacks (roughly 20 events/sec with suppression summaries).

### Using an IPv4/IPv6 literal as server

- `--host` accepts aliases, hostnames, or raw IP literals (both IPv4 and IPv6).
- For IPv6, pass the literal without brackets; do not use `[2001:db8::1]`. If you need a custom port, use `-p`; the `host:port` syntax is not supported.
- Most shells do not require quoting IPv6 literals; if your shell misinterprets them, wrap with quotes.
- When an IPv4/IPv6 literal fails to connect, the client automatically performs a PTR lookup on that address:
  - If the reverse name maps to a known RIR domain, the client prints a notice and retries using the canonical RIR hostname;
  - If the reverse lookup does not map to any known RIR, the client aborts immediately and reports that the literal does not belong to a recognized RIR.

Examples:

```sh
# Server as an IPv4 literal
whois-x86_64 --host 202.12.29.220 8.8.8.8

# Server as an IPv6 literal (default port 43)
whois-x86_64 --host 2001:dc3::35 8.8.8.8

# IPv6 server with custom port (use -p instead of [ip]:port)
whois-x86_64 --host 2001:67c:2e8:22::c100:68b -p 43 example.com
```

### Connectivity tip: ARIN (IPv4 port 43 may be ISP-blocked)

- In some IPv4-only environments (NAT, no IPv6), failure to reach `whois.arin.net:43` is typically caused not by ARIN rejecting private sources, but by the ISP blocking ARIN's IPv4 whois service (port 43 on the A record's IPv4).
- Symptoms: cannot establish IPv4 connections to ARIN:43; the official whois client is affected likewise. Switching to IPv6 works immediately.
- Recommendation: prefer IPv6; or ensure your egress is a public IPv4 path not subject to blocking. If needed, specify ARIN's IPv6 literal via `--host`, or temporarily pin a starting server / disable redirects to aid troubleshooting.

### Troubleshooting: transient empty response warnings (3.2.7)

In rare cases a server may accept a TCP connection but return an empty (or whitespace-only) body. To avoid a misleading authoritative tail with no data, the client detects this and performs a guarded retry:

- ARIN targets: dynamically derives fallback candidates from DNS (prefer IPv6 then IPv4) and may retry up to 3 distinct candidates; no extra hop counted.
- Other RIR targets: one DNS-derived fallback attempt (or same host if no alternate address); no extra hop counted.

During this, you'll see warning diagnostics inserted into the combined output:

- `=== Warning: empty response from <host>, retrying via fallback host <host> ===`
- `=== Warning: empty response from <host>, retrying same host ===`
- If all fallbacks fail: `=== Warning: persistent empty response from <host> (giving up) ===`

Notes:
- These warnings are part of stdout so they are visible in batch pipelines. They do not change the header/tail contract and do not increment hop counts during the retry.
- You can reproduce this path in selftests by using `--selftest-inject-empty` together with `--selftest` (network required).

### Selftests (3.2.7)

Use `--selftest` to run internal tests (fold basics & unique + redirect + lookup) and exit. Lookup checks cover IANA-first hop, single-hop authoritative, and the empty-response injection path. You can explicitly trigger the injection path by passing `--selftest-inject-empty` (network required). To additionally enable GREP and SECLOG selftests:

Build-time macros:
```bash
E="-DWHOIS_GREP_TEST -DWHOIS_SECLOG_TEST" ./tools/remote/remote_build_and_test.sh -r 1 -a "--selftest" -E "-DWHOIS_GREP_TEST -DWHOIS_SECLOG_TEST"
```
Or from PowerShell:
```powershell
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -a '--selftest' -E '-DWHOIS_GREP_TEST -DWHOIS_SECLOG_TEST'"
```

Runtime switches (CLI):
- `--selftest-grep` to run extended grep selftests (requires compile-time `-DWHOIS_GREP_TEST`)
- `--selftest-seclog` to run security log rate-limit tests (requires compile-time `-DWHOIS_SECLOG_TEST`)
- `--selftest-inject-empty` to exercise the empty-response path in lookup selftests

Sample output snippet:
```
[SELFTEST] fold-basic: PASS
[SELFTEST] fold-unique: PASS
[SELFTEST] redirect-detect-0: PASS
[SELFTEST] redirect-detect-1: PASS
[SELFTEST] auth-indicators: PASS
[SELFTEST] extract-refer: PASS
[SELFTEST] lookup-iana-first: PASS
[SELFTEST] lookup-single-hop: PASS
[SELFTEST] lookup-empty-inject: PASS
[SELFTEST] grep: PASS
[SELFTEST] seclog: PASS
```
Notes:
- GREP/SECLOG selftests are optional; omit macros for production builds to reduce build time.
- Non-zero exit indicates at least one failing check. Lookup selftests are network-influenced and treated as advisory; core selftests still determine the exit code.
- Version injection simplified: by default the build no longer appends a `-dirty` suffix. Avoid enabling strict mode for now; only set `WHOIS_STRICT_VERSION=1` once module split is complete to reduce day-to-day churn.
- DNS-specific coverage (3.2.9):
  - `dns-ipv6-only-candidates` proves that `--ipv6-only` (or `--ipv4-only`) skips canonical hostname fallback and keeps the candidate list purely numeric.
  - `dns-canonical-fallback` verifies that relaxing the family filter restores the canonical hostname entry so fallback warnings stay meaningful.
  - `dns-fallback-enabled` / `dns-fallback-disabled` combine `--selftest-blackhole-arin` with the runtime toggles to ensure forced-IPv4 and known-IPv4 layers both fire when enabled and remain silent when disabled. These use instrumentation counters instead of shelling out so they run quickly during `--selftest`.
  - DNS cache stats (Phase 3 preview): when `--debug` or `--retry-metrics` is enabled you will also see a `[DNS-CACHE] hits=... neg_hits=... misses=...` line after `[DNS-CAND]`, summarizing the resolver's cache/negative-cache usage. These counters are for diagnostics only and do not change lookup behavior.

#### DNS selftest playbook (3.2.9)

Use `whois-x86_64` (or any built target) from the repo root when running the following recipes. All of them exit with status 0 when the instrumentation sees the expected paths.

1. **Pure IPv6 candidate list**
   ```bash
   ./whois-x86_64 --selftest --selftest-blackhole-arin --selftest-inject-empty \
     --ipv6-only --retry-metrics --debug
   ```
   Expect `[DNS-CAND]` to list only IPv6 literals (no `canonical` entry) and the summary line `dns-ipv6-only-candidates PASS`. Because the ARIN blackhole scenario forces IPv4 retry attempts, you will also see `dns-fallback-enabled PASS` with `fallback counters: forced>0 known>0`, proving the backoff logic remains wired even though IPv6-only mode drops the canonical hostname.

2. **Prefer-IPv6 with fallback enabled**
   ```bash
   ./whois-x86_64 --selftest --selftest-blackhole-arin --selftest-inject-empty \
     --prefer-ipv6 --retry-metrics --debug
   ```
   Here `[DNS-CAND] canonical` reappears and `dns-canonical-fallback PASS` confirms that relaxing the family filter restores the hostname entry. After the injected IPv6 failures, instrumentation logs such as `known-ip fallback found-known-ip` or `forced-ipv4 fallback warning` should surface, and the counters reported at the end stay non-zero.

3. **Prefer-IPv6 with fallback disabled**
   ```bash
   ./whois-x86_64 --selftest --selftest-blackhole-arin --selftest-inject-empty \
     --prefer-ipv6 --no-force-ipv4-fallback --no-known-ip-fallback \
     --retry-metrics --debug
   ```
   Canonical entries are still constructed, but `[DNS-FALLBACK]` now prints `forced-ipv4 fallback not selected` / `known-ip fallback not selected`. The counters stay at zero and `dns-fallback-disabled PASS` documents that the CLI toggles successfully silenced the retries.

### Folded output

- Use `--fold` to print a single folded line per query using the current selection (after `-g` and `--grep*`):
  - Format: `<query> <UPPER_VALUE_1> <UPPER_VALUE_2> ... <RIR>`
  - Handy for BusyBox pipelines and simple classification

Example:

```sh
whois-x86_64 -g 'netname|mnt-|e-mail' --grep 'CNC|UNICOM' --grep-line --fold 1.2.3.4
```

### Continuation-line keyword capture tips (recommended)

The pipeline order is fixed: title projection first (`-g`) → regex filter (`--grep*`, line/block) → folded output (`--fold`).

- `-g` is a case-insensitive prefix match on header keys (NOT a regex). A matched header includes its continuation lines (indented until next header).
- `--grep/--grep-cs` use POSIX ERE and support two modes:
  - Default "block mode": match on full header blocks (header + continuation lines).
  - `--grep-line` line mode: match individual lines (use `--keep-continuation-lines` to expand a hit line to the entire block).
- `--fold` prints a single line using the current selection: `<query> <UPPER_VALUE_...> <RIR>`.

Recommended Strategy A (stable and precise):

```sh
# Narrow down with -g, then use block-mode regex to match keywords, then fold
whois-x86_64 -g 'Org|Net|Country' \
  --grep 'Google|ARIN|Mountain[[:space:]]+View' \
  --fold 8.8.8.8
```

- Works well when keywords only appear in continuation lines (e.g., address/email), since a block is selected if any line within it matches.
- `-g` restricts scope to relevant fields and reduces accidental matches.

Optional Strategy B (single-regex approach, beware overmatching):

```sh
# Line mode with an OR-regex; expand matched lines to full blocks
whois-x86_64 \
  --grep '^(Org|Net|Country)[^:]*:.*(Google|ARIN)|^[ \t]+.*(Google|ARIN)' \
  --grep-line --keep-continuation-lines --fold 8.8.8.8
```

- Pros: one regex covers both header and continuation lines.
- Cons: OR patterns may hit generic continuation lines and bring in irrelevant blocks; prefer Strategy A when possible.

Notes:

- In line mode, regex applies per-line. Using `\n` won't span lines; use `--keep-continuation-lines` if you need the whole block.
- `--fold-sep` customizes the separator (e.g., `,` or `\t`): `--fold --fold-sep ,`, `--fold --fold-sep \t`; `--no-fold-upper` preserves original case.
- The folded header always uses the original `<query>` token even if the input looks like a regex.

## 7. Version
- 3.2.3: Output contract refinement – header and tail now include server IPs (DNS failure -> `unknown`); aliases mapped before resolution to avoid false unknown cases. Folded output remains `<query> <UPPER_VALUE_...> <RIR>` (no server IP, for pipeline stability). Added ARIN connectivity tip (corrected): some ISPs block ARIN's IPv4 whois (port 43); IPv6 remains reachable. Prefer IPv6 or public IPv4 egress.
- 3.2.5: English-only help (removed bilingual --lang, simplified usage output), retains modularization baseline (wc_* modules), grep self-test hook (`-DWHOIS_GREP_TEST` + `WHOIS_GREP_TEST=1`), improved continuation heuristic, and adds documentation for `--debug-verbose`, `--selftest`, `--fold-unique`.
  - 3.2.6: Redirect logic modularized (wc_redirect), unified case-insensitive redirect flags, removed APNIC-only branch, minimal redirect-target validation (avoid local/private). IANA-first policy stabilizes authoritative resolution. Header: `via <alias-or-host> @ <ip|unknown>`; tail canonicalizes IP literals to RIR hostnames. Redirect selftests added (needs_redirect / is_authoritative_response / extract_refer_server). Optional GREP & SECLOG selftests remain behind compile-time switches.
- 3.2.2: Security hardening across nine areas; add `--security-log` (off by default, rate-limited). Highlights: safer memory helpers, improved signal handling, stricter input and server/redirect validation, connection flood monitoring, response sanitization/validation, thread-safe caches, and protocol anomaly detection. Also removes previous experimental RDAP features/switches to keep classic WHOIS-only behavior.
- 3.2.1: Add optional folded output `--fold` with `--fold-sep` and `--no-fold-upper`; docs on continuation-line keyword strategies.
- 3.2.6: Simplified version string (no `-dirty` by default; use `WHOIS_STRICT_VERSION=1` to re-enable strict dirty suffix behavior).
- 3.2.0: Batch mode, headers+RIR tail, non-blocking connect, timeouts, redirects; default retry pacing: interval=300ms, jitter=300ms.

## 8. Quick remote build + smoke test (Windows)

Assuming you have Git Bash installed and an Ubuntu VM prepared for cross-compilation (see `tools/remote/README_CN.md`).

- Run in Git Bash (default networked smoke test against 8.8.8.8):

```bash
cd /d/LZProjects/whois
./tools/remote/remote_build_and_test.sh -r 1
```

- Sync artifacts to an external folder and keep only the 7 whois-* binaries (replace the path accordingly):

```bash
./tools/remote/remote_build_and_test.sh -r 1 -s "/d/Your/LZProjects/lzispro/release/lzispro/whois" -P 1
```

- Customize smoke queries (space-separated):

```bash
SMOKE_QUERIES="8.8.8.8 example.com 1.1.1.1" ./tools/remote/remote_build_and_test.sh -r 1
```

- Invoke from PowerShell via Git Bash (mind paths and quotes):

```powershell
& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc "cd /d/LZProjects/whois && ./tools/remote/remote_build_and_test.sh -r 1 -s /d/Your/LZProjects/lzispro/release/lzispro/whois -P 1"
```

### Artifacts housekeeping

For switching download link styles (absolute GitHub URLs ↔ repository-relative paths), see `docs/RELEASE_LINK_STYLE.md`.

- Since v3.2.0, `out/artifacts/` has been added to `.gitignore` and is no longer tracked by Git; CI releases attach binaries on GitHub Releases.
- To clean up old local artifacts, use `tools/dev/prune_artifacts.ps1` (supports `-DryRun`).
