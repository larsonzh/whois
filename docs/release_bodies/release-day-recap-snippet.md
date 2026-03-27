# Release-Day Recap Snippet / 发版当日复盘片段

用于直接粘贴到 issue/comment 的最小复盘片段。
Use this file as a copy-ready recap snippet for issue/comment posts.

## Key-Value Template Block (CN/EN)

```text
STRICT_TS=<yyyyMMdd-HHmmss>
PREFLIGHT_TS=<yyyyMMdd-HHmmss|N/A>
CIDR_TS=<yyyyMMdd-HHmmss>
MATRIX_TS=<yyyyMMdd-HHmmss>
STEP47_TS=<yyyyMMdd-HHmmss>
RUN_TS=<yyyyMMdd-HHmmss|N/A>
FAILED_GATE=<gate-name|N/A>
EVIDENCE_PATH=<path|N/A>
CAUSE_NEXT=<one-line-cause+next-action|N/A>
```

## Example-Filled Block (2026-03-28)

```text
STRICT_TS=20260328-045150
PREFLIGHT_TS=20260328-045157
CIDR_TS=20260328-045439
MATRIX_TS=20260328-045523
STEP47_TS=20260328-054950
RUN_TS=N/A
FAILED_GATE=N/A
EVIDENCE_PATH=N/A
CAUSE_NEXT=N/A
```

## Example-Failed Block (2026-03-28)

```text
STRICT_TS=20260328-045150
PREFLIGHT_TS=20260328-045157
CIDR_TS=20260328-045439
MATRIX_TS=20260328-045523
STEP47_TS=20260328-054950
RUN_TS=20260328-061200
FAILED_GATE=preclass-p1-gate
EVIDENCE_PATH=out/artifacts/preclass_p1_matrix/20260328-061200/summary_group.txt
CAUSE_NEXT=threshold mismatch on external_public_v4; fix threshold file and rerun Step47 chain
```

## One-Paragraph Quick Comment (FAIL)

```text
[Release Recap][FAIL] run_ts=<yyyyMMdd-HHmmss>, failed_gate=<gate-name>, strict=<PASS/FAIL>, cidr=<PASS/FAIL>, matrix=<PASS/FAIL>, step47=<PASS/FAIL>, evidence=<path>, cause_next=<one-line-cause+next-action>
```

```text
[发版复盘][FAIL] run_ts=<yyyyMMdd-HHmmss>，failed_gate=<gate-name>，strict=<PASS/FAIL>，cidr=<PASS/FAIL>，matrix=<PASS/FAIL>，step47=<PASS/FAIL>，evidence=<path>，cause_next=<一句话原因+下一步动作>
```

## Issue/Comment Paste Template (CN)

```text
[Release Recap]
STRICT_TS=
PREFLIGHT_TS=
CIDR_TS=
MATRIX_TS=
STEP47_TS=
RUN_TS=
FAILED_GATE=
EVIDENCE_PATH=
CAUSE_NEXT=

Gates:
- Remote Strict: PASS/FAIL
- CIDR Bundle: PASS/FAIL
- Redirect Matrix 10x6: PASS/FAIL
- Step47 PreRelease: PASS/FAIL

Verdict: PASS/FAIL
Notes:
```

## Issue/Comment Paste Template (EN)

```text
[Release Recap]
STRICT_TS=
PREFLIGHT_TS=
CIDR_TS=
MATRIX_TS=
STEP47_TS=
RUN_TS=
FAILED_GATE=
EVIDENCE_PATH=
CAUSE_NEXT=

Gates:
- Remote Strict: PASS/FAIL
- CIDR Bundle: PASS/FAIL
- Redirect Matrix 10x6: PASS/FAIL
- Step47 PreRelease: PASS/FAIL

Verdict: PASS/FAIL
Notes:
```
