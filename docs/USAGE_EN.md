# whois client usage (English)

This document describes the built-in lightweight whois clients shipped with the project (C implementation, statically linked, zero external runtime deps). Binaries cover multiple architectures such as `whois-x86_64`, `whois-aarch64`, etc. Examples below use `whois-x86_64`.

Highlights:
- Smart redirects: non-blocking connect, timeouts, light retries, and referral following with loop guard (`-R`, disable with `-Q`).
- Pipeline batch input: stable header/tail contract; read from stdin (`-B`/implicit); great for BusyBox grep/awk flows.
- Conditional output engine: title projection (`-g`) → POSIX ERE filters (`--grep*`, line/block, optional continuation expansion) → folded summary (`--fold`).

Notes:
- Optional folded output `--fold` prints a single-line summary per query: `<query> <UPPER_VALUE_...> <RIR>`.
  - `--fold-sep <SEP>` sets the separator between folded tokens (default space; supports `\t`/`\n`/`\r`/`\s`)
  - `--no-fold-upper` preserves original case (default uppercases values and RIR)

## 1. Key features (3.2.0)
- Batch stdin: `-B/--batch` (or implicit when no positional arg and stdin is not a TTY)
- Header + authoritative RIR tail (enabled by default; disable with `-P/--plain`)
  - Header: `=== Query: <query> ===`, the query token sits at field `$3`
  - Tail: `=== Authoritative RIR: <server> ===`, after folding into one line it becomes the last field `$(NF)`
- Non-blocking connect + IO timeouts + light retry (default 2); automatic redirects (cap by `-R`, disable with `-Q`), loop guard

## 2. Command line

```
Usage: whois-<arch> [OPTIONS] <IP or domain>

Options:
  -h, --host HOST          Specify starting whois server (alias or domain, e.g. apnic / whois.apnic.net)
  -g, --title PATTERNS     Title filter (on header lines only): case-insensitive prefix match on key names; use '|' to separate multiple prefixes (e.g., inet|netname). Note: this is NOT a regular expression.
  -p, --port PORT          Port number (default 43)
  -b, --buffer-size SIZE   Response buffer size, supports 1K/1M/1G suffixes (default 512K)
  -r, --retries COUNT      Max retry times per single request (default 2)
  -t, --timeout SECONDS    Network timeout (default 5s)
  -i, --retry-interval-ms MS  Base sleep between retries in milliseconds (default 300)
  -J, --retry-jitter-ms MS    Extra random jitter in milliseconds (0..MS, default 300)
  -R, --max-redirects N    Max referral redirects to follow (default 5)
  -Q, --no-redirect        Do NOT follow redirects (only query the starting server)
  -B, --batch              Read queries from stdin (one per line); forbids positional query
  -P, --plain              Plain output (suppress header and RIR tail lines)
  -D, --debug              Debug logs to stderr
  --security-log           Enable security event logging to stderr (disabled by default)
  -l, --list               List built-in whois server aliases
  -v, --version            Show version
  -H, --help               Show help
```

Notes:
- If no positional query is provided and stdin is not a TTY, batch mode is enabled implicitly; `-B` enables it explicitly.
- With `-Q` (no redirect), the tail RIR just shows the actual queried server and may NOT be authoritative.
 - `-g` matches only on header lines whose first token ends with ':'; when a header matches, its continuation lines (starting with whitespace until the next header) are also included; without `-g`, the full body is passed through.
 - Important: `-g` uses case-insensitive prefix matching and is NOT a regular expression.

## 3. Output contract (for BusyBox pipelines)
- Header: `=== Query: <query> ===`, query is `$3`
- Tail: `=== Authoritative RIR: <server> ===`, after folding becomes `$(NF)`
- Private IP: body prints `"<ip> is a private IP address"` and RIR tail is `unknown`

Folding example (aligned with `func/lzispdata.sh` style):

```sh
... | grep -Ei '^(=== Query:|netname|mnt-|e-mail|=== Authoritative RIR:)' \
  | awk -v count=0 '/^=== Query/ {if (count==0) printf "%s", $3; else printf "\n%s", $3; count++; next} \
      /^=== Authoritative RIR:/ {printf " %s", toupper($4)} \
      (!/^=== Query:/ && !/^=== Authoritative RIR:/) {printf " %s", toupper($2)} END {printf "\n"}'
# Tip: after folding, `$(NF)` is the authoritative RIR (uppercase), suitable for filtering
```

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
- 0: success (in batch mode, individual failures are printed to stderr)
- non-zero: invalid args / no input / single query failed

## 6. Tips
- Prefer leaving sorting/dedup/aggregation to outer BusyBox scripts (grep/awk/sed)
- To stick to a fixed server and minimize instability from redirects, use `--host <rir> -Q`
- In automatic redirects mode, too small `-R` may lose authoritative info; too large may add latency; default 5 is typically enough
- Retry pacing: default `interval=300ms` and `jitter=300ms`, so each retry sleeps within `[300, 600]ms`, which helps mitigate bursty failures; tune via `-i/-J` if needed.

### Security logging (optional)

- Use `--security-log` to emit SECURITY events to stderr for diagnostics and hardening validation. Examples of events: input validation rejects, protocol anomalies, redirect target validation failures, response sanitization, and connection flood detection. This does not change the normal stdout output contract and is off by default.
- Security logs are rate-limited to avoid stderr flooding during attacks (roughly 20 events/sec with suppression summaries).

### Using an IPv4/IPv6 literal as server

- `--host` accepts aliases, hostnames, or raw IP literals (both IPv4 and IPv6).
- For IPv6, pass the literal without brackets; do not use `[2001:db8::1]`. If you need a custom port, use `-p`; the `host:port` syntax is not supported.
- Most shells do not require quoting IPv6 literals; if your shell misinterprets them, wrap with quotes.

Examples:

```sh
# Server as an IPv4 literal
whois-x86_64 --host 202.12.29.220 8.8.8.8

# Server as an IPv6 literal (default port 43)
whois-x86_64 --host 2001:dc3::35 8.8.8.8

# IPv6 server with custom port (use -p instead of [ip]:port)
whois-x86_64 --host 2001:67c:2e8:22::c100:68b -p 43 example.com
```

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
- 3.2.2: Security hardening across nine areas; add `--security-log` (off by default, rate-limited). Highlights: safer memory helpers, improved signal handling, stricter input and server/redirect validation, connection flood monitoring, response sanitization/validation, thread-safe caches, and protocol anomaly detection. Also removes previous experimental RDAP features/switches to keep classic WHOIS-only behavior.
- 3.2.1: Add optional folded output `--fold` with `--fold-sep` and `--no-fold-upper`; docs on continuation-line keyword strategies.
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

- Since v3.2.0, `out/artifacts/` has been added to `.gitignore` and is no longer tracked by Git; CI releases attach binaries on GitHub Releases.
- To clean up old local artifacts, use `tools/dev/prune_artifacts.ps1` (supports `-DryRun`).
