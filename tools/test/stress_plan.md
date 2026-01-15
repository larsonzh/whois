# Whois client stress plan (draft)

Purpose: long-run smoke to catch regressions in pacing/backoff, workbuf, and tag stability under heavier load.

## Scenarios
- **Long batch (stdin)**: 500+ mixed queries (IPv4/IPv6, known/unknown, private) via `whois-x86_64 -B` with default params; expect stable headers/tails and no stalls.
- **Debug/metrics pass**: same batch with `--debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first` to surface `[DNS-*]`, `[RETRY-*]`, `[DNS-BACKOFF]`, `[DNS-CACHE-SUM]`, `[NET-PROBE]`.
- **Workbuf stress**: include long lines, dense continuation, and CRLF cases; enable `--selftest-workbuf` and `-DWC_WORKBUF_ENABLE_STATS` build to check `[WORKBUF]`/`[WORKBUF-STATS]`.
- **Penalty focus**: seed penalties via `WHOIS_BATCH_DEBUG_PENALIZE='whois.arin.net,whois.ripe.net'` in batch strategies health-first/plan-b to exercise `[DNS-BACKOFF] action=skip|force-last` and batch tags.

## Commands (examples)
- Default long batch: `whois-x86_64 -B < long_batch.txt > /tmp/out.log 2> /tmp/err.log`
- Debug/metrics: `whois-x86_64 -B --debug --retry-metrics --dns-cache-stats --dns-family-mode interleave-v4-first < long_batch.txt > /tmp/out_dbg.log 2> /tmp/err_dbg.log`
- Workbuf: build with `-DWC_WORKBUF_ENABLE_STATS`, run `whois-x86_64 -B --selftest-workbuf < workbuf_mix.txt 2> /tmp/err_wb.log`

## Golden/guards
- Reuse `tools/test/golden_check.sh --require-tags "[DNS-CACHE-SUM],[NET-PROBE],[RETRY-METRICS]" -l <log>` after each run.
- For batch presets, call `tools/test/golden_check_batch_presets.sh <preset> --require-tags "[DNS-BACKOFF],[DNS-CAND]" -l <log>` as needed (via golden_check passthrough).

## Exit criteria
- No hangs; stdout headers/tails present; stderr contains required tags; `[WORKBUF-STATS]` growth stable vs baseline; `[DNS-BACKOFF]` fields intact.
