# whois client usage

Chinese version: `docs/USAGE_CN.md`

This document describes the built-in lightweight whois clients shipped with the project (C implementation, statically linked, zero external runtime deps). Binaries cover multiple architectures such as `whois-x86_64`, `whois-aarch64`, etc. Examples below use `whois-x86_64`.

NOTICE (v3.2.5+): output is English-only; the previous `--lang` option and `WHOIS_LANG` env have been removed to avoid mojibake on limited SSH terminals.

## Contents

- [1. Quick start](#1-quick-start)
- [2. Output contract](#2-output-contract)
- [3. Command-line reference](#3-command-line-reference)
- [4. Batch mode](#4-batch-mode)
- [5. Common examples](#5-common-examples)
- [6. Exit codes](#6-exit-codes)
- [7. Tips & troubleshooting](#7-tips--troubleshooting)
- [8. Related docs & integration](#8-related-docs--integration)

## 1. Quick start

Single query (follows referral redirects automatically, up to `-R`, default 6):

```sh
whois-x86_64 8.8.8.8
whois-x86_64 example.com
```

Pin a starting server and disable redirects:

```sh
whois-x86_64 --host apnic -Q 103.89.208.0
```

Batch queries (`-B` explicit, or implicit when stdin is not a TTY):

```sh
cat ip_list.txt | whois-x86_64 -B --host apnic
```

Key features: non-blocking connect, timeouts, and light retries; automatic referral following with loop guard; stable header/tail output contract; batch stdin input; conditional output engine (`-g` → `--grep*` → `--fold`); optional HTTP CONNECT proxy; DNS/IP family preference and negative caching; diagnostics/security logging.

The authoritative baseline for authority decisions, redirect ordering, and CIDR semantics is `docs/RFC-ipv4-ipv6-whois-lookup-rules.md`; proxy behavior is specified in `docs/RFC-proxy-access.md`.

## 2. Output contract

First, a quick glossary of terms used throughout this guide:

- **WHOIS** — a protocol/service to ask “who owns this IP/domain?”; traditionally plaintext TCP port 43. This client queries those servers.
- **RIR** — the five regional internet registries: ARIN (North America), APNIC (Asia-Pacific), RIPE NCC (Europe/Middle East), LACNIC (Latin America), AFRINIC (Africa). They allocate IP/AS numbers and keep the WHOIS records.
- **IANA** — the Internet Assigned Numbers Authority, which hands large blocks to the RIRs; many lookups start at or are hinted by IANA.
- **referral** — a reply such as “this address is managed by another RIR; ask that server”; the client follows it automatically (with a hop cap).
- **authoritative** — the server that really owns the record; the tail `=== Authoritative RIR: ... ===` reports the final verdict.
- **hop** — one “connect to a server and query” step; following referrals creates a multi-hop chain.
- **CIDR** — `192.0.2.0/24` denotes an address range (`/24` is the prefix length); same for IPv6 (e.g. `2001:db8::/32`).
- **Private IP** — RFC1918 ranges such as `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`; the client identifies them and prints `unknown` without going online.
- **Header and continuation lines** — WHOIS bodies look like `NetName: Foo`; indented lines under a header (until the next header) are its “block/continuation”. `-g`/`--grep` filter by this structure.
- **Fold** — compress filtered output into one line (`<query> VALUE1 VALUE2 ... RIR`) for easy awk/grep aggregation.
- **Batch** — one query per stdin line, each with independent output; great for `cat list | whois -B`.

### Output contract

- Header: `=== Query: <query> via <starting-server-label> @ <connected-ip-or-unknown> ===`
  - The query token is field `$3`; the label keeps the user-supplied alias or the mapped RIR hostname; the `@` segment always reflects the first successful connection IP (`unknown` when DNS fails).
- Tail: `=== Authoritative RIR: <authoritative-server> @ <its-ip|unknown|error> ===`
  - IP literals are mapped back to canonical RIR hostnames; known aliases/subdomains (e.g., `whois-jp1.apnic.net`) are normalized to the canonical host. A stderr `Error: Query failed for ...` line is emitted only when the tail is `error @ error`.
- Folded line: `<query> <UPPER_VALUE_1> <UPPER_VALUE_2> ... <RIR>` (no IP); after folding the authoritative RIR is the last field `$(NF)`.
- Private IP: body prints `<ip> is a private IP address` and the tail is `=== Authoritative RIR: unknown ===` (implicit queries may also show an `Address Status:` line).
- Additional hop: the first extra hop that is not driven by an explicit referral appears as `=== Additional query to ... ===` (not `=== Redirected query to ... ===`); this is expected.
- Empty-response warnings: `=== Warning: empty response from <host>, retrying ... ===` (stdout); they do not increment hop counts.
- stdout carries business output only; stderr carries diagnostics/metrics (`[RETRY-*]`, `[DNS-*]`, `[SELFTEST]`, `[INFO]`, etc.).

## 3. Command-line reference

```
Usage: whois-<arch> [OPTIONS] <IP or domain>
```

### 3.1 Meta

| Option | Description |
|--------|-------------|
| `-H, --help` | Show help and exit |
| `-v, --version` | Show version and exit |
| `-l, --list` | List built-in RIR servers |
| `--about` | Show features/modules overview |
| `--examples` | Show extended examples |

Note: pure meta options return immediately and skip runtime initialization (stdout/stderr contract unchanged).

### 3.2 Core query

| Option | Description |
|--------|-------------|
| `-h, --host HOST` | Starting WHOIS server (alias/domain/IP literal, e.g. `apnic`, `whois.apnic.net`, `202.12.29.220`) |
| `-p, --port PORT` | WHOIS port (default 43); `host:port` syntax is not supported |
| `-B, --batch` | Read queries from stdin (one per line; implicit when stdin is not a TTY) |
| `-R, --max-redirects N` | Max referral hops (default 6); alias `--max-hops`. Falls back to `unknown` when the cap forces a stop |
| `-Q, --no-redirect` | Same as `-R 1`: query only the starting server; fall back to `unknown @ unknown` on a referral |
| `-P, --plain` | Plain output: suppress header, RIR tail, and referral hints |
| `--show-non-auth-body` | Keep non-authoritative bodies before the authoritative hop |
| `--show-post-marker-body` | Keep bodies after the authoritative hop (combine with the previous to keep all) |
| `--hide-failure-body` | Hide rate-limit/denied body lines (default: keep) |
| `--cidr-strip` | For CIDR queries, send only the base IP; the header keeps the original CIDR |
| `-D, --debug` | Basic debug + TRACE to stderr |

Examples:

```sh
whois-x86_64 --host apnic -Q 103.89.208.0      # pin a starting RIR, no referral
whois-x86_64 -P 8.8.8.8                        # plain body only
whois-x86_64 --cidr-strip -h arin 1.1.1.0/24   # send base IP only
whois-x86_64 --show-non-auth-body --show-post-marker-body 1.1.1.1
```

### 3.3 Proxy (HTTP CONNECT / SOCKS)

A proxy is a relay server: the client asks the proxy to connect to the WHOIS server (port 43) on its behalf. Use one when your network cannot reach some RIRs directly (for example, an ISP blocks ARIN's port 43) or when a company/campus requires a shared egress.

#### Supported proxy types (current release)

| Type | URL example | Default port | Notes |
|------|-------------|--------------|-------|
| `http://` | `http://proxy.example:8080` | 8080 | HTTP CONNECT proxy: sends `CONNECT host:43`, then runs plaintext WHOIS inside the tunnel. Most common (corporate/shared) |
| `socks5://` | `socks5://proxy.example:1080` | 1080 | SOCKS5 with **local target resolution**: the client resolves the domain itself and hands the IP to the proxy |
| `socks5h://` | `socks5h://proxy.example:1080` | 1080 | SOCKS5 with **remote resolution**: the domain is sent to the proxy, which resolves and connects. Useful when local DNS is polluted/unreliable |
| `socks4://` | `socks4://proxy.example:1080` | 1080 | SOCKS4: IPv4 targets only (legacy) |
| `socks4a://` | `socks4a://proxy.example:1080` | 1080 | SOCKS4a: supports domains via proxy-side resolution, but still no IPv6 targets |

How to choose:
- Corporate/internal proxies are usually `http://` (ports 8080/3128).
- If you just need connectivity and local DNS is fine: `socks5://`.
- If local DNS is broken or you prefer not to expose the target: `socks5h://`.
- Because `socks5h://` / `socks4a://` delegate the domain to the proxy (whose chosen address family cannot be known), they conflict with `--ipv4-only`/`--ipv6-only`, family-mode, fallback switches, or `--rir-ip-pref`; combining them fails before lookup.

#### How to specify a proxy (including what `ALL_PROXY` is)

Priority (high to low):

1. `--proxy <url>` on the command line
2. `WHOIS_PROXY` environment variable
3. Only with `--proxy-env`: `ALL_PROXY` → `all_proxy`
4. Otherwise: direct connection

About `ALL_PROXY` / `all_proxy`: these are common, widely recognized “generic proxy” environment variables (curl, git, apt, etc. all honor them), set to something like `http://proxy.example:8080` or `socks5h://proxy.example:1080`. Uppercase `ALL_PROXY` is tried first, then lowercase `all_proxy`. This client does **not** read them by default—if your system happens to have `ALL_PROXY` set, you could be forced through a proxy without meaning to—so opt in explicitly with `--proxy-env`.

`HTTP_PROXY` / `HTTPS_PROXY` are never read: WHOIS is plaintext TCP (there is no HTTP-vs-HTTPS choice), and uppercase `HTTP_PROXY` carries a known CGI-injection ambiguity in POSIX environments.

`NO_PROXY` / `no_proxy` (also requires `--proxy-env`): comma-separated targets that must bypass the proxy. It is evaluated for every WHOIS hop. Supported forms: `*` (direct for everything), exact hostnames, leading-dot domain suffixes (e.g. `.internal` matches `a.internal`), IPv4 literals, bracketed IPv6 literals, and `host:port`. CIDR (e.g. `10.0.0.0/8`) and arbitrary globs are not supported.

```sh
# Bypass the proxy for localhost, internal domains, and one RIR
NO_PROXY='localhost,.internal,whois.iana.org' whois-x86_64 --proxy-env 1.1.1.1
```

#### Username / password (important)

For security:

- **Never put credentials in the CLI URL** `--proxy http://user:pass@...` — userinfo in a CLI proxy URL is rejected (credentials would remain in shell history and the process list).
- The supported way: dedicated environment variables `WHOIS_PROXY_USER` (username) and `WHOIS_PROXY_PASSWORD` (password). Both must be set and non-empty, otherwise startup fails.
- If the proxy URL comes from an environment variable (`WHOIS_PROXY` / `ALL_PROXY` / `all_proxy`), that URL may carry percent-encoded `user:pass@` (e.g. `http://my%20user:p%40ss@proxy:8080`) to share configuration with other tools.
- Setting both dedicated credentials and URL userinfo at the same time fails fast (ambiguity).
- For a **cleartext `http://` proxy** with credentials, you must also pass `--proxy-allow-insecure-auth`; otherwise it errors. Credentials on a cleartext proxy travel in plaintext—use only with trusted internal proxies.
- Credential files, interactive prompts, and OS keychains are not supported; avoid inheriting these environment variables into unnecessary child processes.

Examples:

```powershell
# PowerShell: set credentials first, then --proxy plus the cleartext-auth switch
$env:WHOIS_PROXY_USER = 'myuser'
$env:WHOIS_PROXY_PASSWORD = 'mypass'
whois-x86_64 --proxy http://10.0.0.246:8080 --proxy-allow-insecure-auth 8.8.8.8
```

```sh
# Git Bash / Linux
export WHOIS_PROXY_USER='myuser'
export WHOIS_PROXY_PASSWORD='mypass'
whois-x86_64 --proxy http://10.0.0.246:8080 --proxy-allow-insecure-auth 8.8.8.8
```

#### Proxy command-line options (item by item)

| Option | Description |
|--------|-------------|
| `--proxy URL` | Explicit proxy. Accepts only absolute `http://`/`socks5://`/`socks5h://`/`socks4://`/`socks4a://` URLs (host+port, no path/query/fragment; IPv6 proxies use brackets like `[::1]:1080`; default port per type: http=8080, socks*=1080). **Embedding `user:pass@` in the URL is forbidden** (see credentials below) |
| `--proxy-env` | Enables generic proxy env vars: reads `ALL_PROXY` → `all_proxy` and honors `NO_PROXY`/`no_proxy` bypasses. Off by default (so a system-wide proxy cannot silently hijack traffic); `HTTP_PROXY`/`HTTPS_PROXY` are never read |
| `--proxy-allow-insecure-auth` | Allows credentials on a **cleartext `http://` proxy**; without it, http-proxy + credentials fail before lookup (SOCKS proxies are not restricted this way) |
| `--proxy-family auto\|v4\|v6` | Controls only the **proxy endpoint's** address family (default `auto`). Use `--proxy-family v6` when the proxy has only an IPv6 address; conflicts with a numeric host in the URL fail before lookup |
| `-p, --port PORT` | Still the **WHOIS target port** (default 43), unrelated to the proxy; referrals may replace the target port independently |

Priority: `--proxy` > `WHOIS_PROXY` > (`--proxy-env` only) `ALL_PROXY` > `all_proxy` > direct.

#### SOCKS and HTTPS proxy usage

- **SOCKS**: just specify it, e.g. `whois-x86_64 --proxy socks5://10.0.0.246:1080 8.8.8.8`. For authentication, set `WHOIS_PROXY_USER`/`WHOIS_PROXY_PASSWORD` as above (SOCKS5 supports username/password; SOCKS4 sends USERID as the username and never carries a password).
- **HTTPS proxy (`https://`) — WP-13D under development, not enabled on master yet**: in a future release `https://host:443` means TLS between the client and the proxy, with `CONNECT` on top; WHOIS inside the tunnel stays plaintext. Certificate and hostname verification are mandatory (no insecure mode), the trust store defaults to an embedded Mozilla CA bundle, and a non-empty `SSL_CERT_FILE` can point to an enterprise private CA PEM (unreadable/empty/load-failure is fail-closed, never falling back to the embedded bundle). See `docs/RFC-proxy-access.md` for details.

### 3.4 Timeouts & retries

| Option | Description |
|--------|-------------|
| `--timeout SEC` | Socket timeout (default 5s) |
| `--retries N` | Retry count on transient errors (default 2) |
| `--retry-all-addrs` | Apply retries to every resolved IP (default: only first) |
| `--retry-interval-ms M` | Base interval between retries (default 300) |
| `--retry-jitter-ms J` | Additional random jitter 0..J ms (default 300) |
| `--rate-limit-retries N` | App-layer retries for temporary denied/rate-limit (default 2, 0..10); `permanently denied` is not retried |
| `--rate-limit-retry-interval-ms M` | Wait between app-layer retries (default 2500) |

### 3.5 Connect-level retry pacing (on by default, CLI-only)

| Option | Description |
|--------|-------------|
| `--pacing-disable` | Turn pacing off (not recommended) |
| `--pacing-interval-ms M` | Base wait (default 60) |
| `--pacing-jitter-ms J` | Random 0..J ms (default 40) |
| `--pacing-backoff-factor N` | Multiply wait per retry (default 2) |
| `--pacing-max-ms C` | Cap any single wait (default 400) |

Note: `[RETRY-METRICS] ... sleep_ms=` reflects cumulative pacing; render/output contracts are unaffected.

### 3.6 Buffers & caches

| Option | Description |
|--------|-------------|
| `-b, --buffer-size BYTES` | Response buffer size (default 512K; 1K/1M/1G suffixes) |
| `-d, --dns-cache N` | DNS cache entries (default 10) |
| `-c, --conn-cache N` | Connection cache entries (default 5) |
| `-T, --cache-timeout SEC` | Cache TTL (default 300) |
| `--cache-counter-sampling` | Emit cache-counter samples even without `--debug`; auto-enabled by any `--selftest*` |

### 3.7 DNS / IP family preference

In plain terms: WHOIS servers usually have both IPv4 and IPv6 addresses. `--ipv4-only`/`--ipv6-only` are strict “use one family only” constraints (they can fail if that family is unreachable); `--prefer-*` prefers one family but automatically falls back to the other, which is safer; `--rir-ip-pref` lets you set per-RIR policies (e.g. one RIR is only reachable over IPv4). Normally you do not need to set anything—the client probes local availability and picks a sensible order.

| Option | Description |
|--------|-------------|
| `--ipv4-only` / `--ipv6-only` | Force a single family for resolution and dialing (skips the canonical-host pre-dial) |
| `--prefer-ipv4` / `--prefer-ipv6` | Prefer one family (the other may still fall back) |
| `--prefer-ipv4-ipv6` / `--prefer-ipv6-ipv4` | First-hop preference plus a tilt toward the other family on later hops |
| `--rir-ip-pref SPEC` | Per-RIR family override, e.g. `arin=v4,ripe=v6` |
| `--dns-family-mode MODE` | Global candidate ordering: `interleave-v4-first`/`interleave-v6-first`/`seq-v4-then-v6`/`seq-v6-then-v4`/`ipv4-only-block`/`ipv6-only-block` |
| `--dns-family-mode-first/next` | First-hop / second+-hop overrides (same modes) |
| `--dns-neg-ttl SEC` | Negative DNS cache TTL (default 10) |
| `--no-dns-neg-cache` | Disable negative caching |
| `--no-dns-addrconfig` | Disable OS `AI_ADDRCONFIG` filter (default on) |
| `--dns-retry N` | DNS retries on `EAI_AGAIN` (default 3, 1..10) |
| `--dns-retry-interval-ms M` | DNS retry interval (default 100, 0..5000) |
| `--dns-max-candidates N` | Cap resolved dial candidates (default 12, 1..64) |
| `--max-host-addrs N` | Cap per-host dial attempts (default 0=unlimited, 1..64) |
| `--dns-backoff-window-ms N` | DNS backoff failure window (default 10000, 0=disable) |
| `--dns-append-known-ips` | Append built-in RIR known IPs to candidates |
| `--no-known-ip-fallback` | Disable known-IPv4 fallback |
| `--no-force-ipv4-fallback` | Disable forced-IPv4 fallback |
| `--no-iana-pivot` | Disable IANA pivot when a referral is missing |
| `--dns-no-fallback` | Disable both forced/known IPv4 extra fallbacks (debugging) |

Priority: `--ipv4-only/--ipv6-only` > `--rir-ip-pref` > `--dns-family-mode-*` > global `--prefer-*`.

**What is negative caching (DNS failure memory)?**

When a DNS resolution fails (for example, the name temporarily does not resolve), the client remembers the failure briefly (default 10s, adjustable with `--dns-neg-ttl`). While that memory is fresh, repeated lookups of the same name are skipped as “known failure” instead of waiting for the DNS timeout again, which speeds up batch/repeated queries and reduces pointless resolver traffic. It is a **short cache for failures only**: successful resolutions use the separate positive cache (`--dns-cache N` + `--cache-timeout`), and any successful resolution overwrites the negative entry. Normally you do not need to touch it; if a failing name seems skipped too aggressively, raise the TTL to observe, or run with `--no-dns-neg-cache` to re-verify the real resolution result.

Examples:

```sh
whois-x86_64 --ipv4-only 1.1.1.1
whois-x86_64 --prefer-ipv6 --dns-neg-ttl 30 8.8.8.8
whois-x86_64 --rir-ip-pref arin=v4,ripe=v6 8.8.8.8
```

### 3.8 Conditional output engine

Processing order is fixed: `-g` (title projection) → `--grep*` (line/block, optional continuation expansion) → `--pick` → `--fold`/body.

| Option | Description |
|--------|-------------|
| `-g, --title PATTERN` | Header prefix projection (case-insensitive; `|` separates prefixes; a matched header includes its continuation lines). **Not a regex** |
| `--grep REGEX` | POSIX ERE filter (case-insensitive) |
| `--grep-cs REGEX` | Case-sensitive version |
| `--grep-line` | Line mode |
| `--grep-block` | Block mode (default) |
| `--keep-continuation-lines` | Keep continuation lines in line mode (default) |
| `--no-keep-continuation-lines` | Drop continuation lines in line mode |
| `--fold` | Fold to one line: `<query> <UPPER_VALUE_...> <RIR>` |
| `--fold-sep STR` | Fold separator (default space; `\t`/`\n`/`\r`/`\s` supported) |
| `--no-fold-upper` | Preserve original case (default uppercases) |
| `--fold-unique` | De-duplicate folded tokens (first-occurrence order) |
| `--no-body` | Suppress the body; keep the query header, `Address Status:`, and authoritative tail (filters still run) |
| `--print-meta` | Append one TAB-separated `k=v` line per record: `query,rir,status,duration_ms,attempts,redirects` |
| `--print-chain` | Append `chain=server1>server2>...` per record (max 16 hops; `>truncated` beyond) |
| `--pick KEYS` | Append selected WHOIS header values (allowlist: `netname,country,inetnum,inet6num,origin,route,descr`; missing values stay `key=`) |
| `--pick-mode MODE` | `first` (default) or `join` (merge duplicates with `|`; continuation lines joined with `; `) |
| `--stats` | Append one batch summary line (success/error, classes, RIR distribution, p50/p95 ms) |

Conflicts: `--no-body` conflicts with `--plain` and every `--fold*` (fails before lookup); `--print-meta`/`--print-chain`/`--pick` conflict with `--plain`.

Examples:

```sh
# Title projection + block regex + fold
whois-x86_64 -g 'Org|Net|Country' --grep 'Google|ARIN' --fold 8.8.8.8

# Line-mode keyword hit expanded to the whole block
whois-x86_64 -g 'netname|e-mail' --grep 'cmcc' --grep-line --keep-continuation-lines 1.2.3.4

# Record boundaries + chain + field extraction (batch friendly)
printf '8.8.8.8\n1.1.1.1\n' | whois-x86_64 -B --no-body --print-chain --pick netname,country --stats
```

### 3.9 Diagnostics / security / selftests

| Option | Description |
|--------|-------------|
| `--debug-verbose` | Extra verbose debug (cache/redirect instrumentation) |
| `--retry-metrics` | Print retry stats to stderr (`[RETRY-METRICS*]`; diagnostics only) |
| `--dns-cache-stats` | Emit one `[DNS-CACHE-SUM] hits=<n> neg_hits=<n> misses=<n>` line at exit |
| `--security-log` | Security event logging to stderr (off by default; ~20 events/sec rate limit) |
| `--selftest` | Run internal selftests and exit (fold/redirect/lookup; non-zero on failure) |
| `--selftest-grep` / `--selftest-seclog` | Extended selftests (require `-DWHOIS_GREP_TEST` / `-DWHOIS_SECLOG_TEST`) |
| `--selftest-inject-empty` | Trigger the empty-response injection path (network required) |
| `--selftest-dns-negative` | Simulate negative-DNS caching |
| `--selftest-blackhole-iana` / `--selftest-blackhole-arin` | Blackhole IANA/ARIN candidates (simulate connect failures) |
| `--selftest-force-iana-pivot` | Force one IANA pivot (three-hop path) |
| `--selftest-fail-first-attempt` | Force the first attempt to fail once |
| `--selftest-force-suspicious Q` | Mark a query (or `*`) suspicious for pipeline testing |
| `--selftest-force-private Q` | Mark a query (or `*`) private for pipeline testing |
| `--selftest-registry` | Batch-strategy registry harness (no network) |
| `--selftest-workbuf` | Long-line/CRLF/high-continuation stress (`[WORKBUF]*`) |
| `--disable-address-preclass` | Hard-disable Step 4.7 preclass (legacy path) |
| `--enable-preclass-actions` | Enable P1 controlled actions (default off; needs `--enable-step47-trial`) |
| `--preclass-action-tier r0|r1` | P1 candidate tier (default `r0`) |
| `--preclass-action-list CSV` | Override the P1 candidate list |
| `--enable-step47-trial` | Enable the Step 4.7 trial gate (default off) |
| `--step47-trial-scope minimal|reserved|all` | Trial scope (default `minimal`) |
| `--enable-step47-early-unknown` | Enable early-unknown trial (default off; `reserved` scope only) |
| `--step47-early-unknown-list CSV` | Early-unknown candidate list |
| `--enable-preclass-first-hop` | Phase B classifier-preferred first hop (implicit queries default on; explicit `-h` bypasses) |
| `--enable-preclass-early-converge` | Phase C reserved/special early converge (default on; adds `Address Status:` and normalizes to `unknown @ unknown`) |

Note: enabling any `--selftest-*` fault toggle auto-runs the lookup selftest suite once before real queries (stderr shows `[LOOKUP_SELFTEST]`). `[SELFTEST] action=force-*` tags are stderr-only and independent of `--debug`. Recommended debug capture:

```sh
whois-x86_64 --debug --retry-metrics --dns-cache-stats --no-known-ip-fallback 8.8.8.8 2>debug.log
```

For operations/build/validation flows (remote smoke, Golden, redirect matrix, batch-strategy goldens, Step47 pre-release gates), see `docs/OPERATIONS_EN.md`.

## 4. Batch mode

- Explicit: `-B`; implicit when no positional query is given and stdin is not a TTY.
- Input is read line by line (line endings normalized to LF); each record keeps independent header/tail and filter chain.
- `--batch-strategy raw|health-first|plan-a|plan-b` selects an optional start-host accelerator (default `raw`).
  - `raw` (default): CLI host → guessed RIR → IANA; no penalty skipping, no cache reuse.
  - `health-first`: skips recently failed hosts; forces the last candidate when all are penalized.
  - `plan-a`: reuses the last authoritative RIR as a fast start; falls back on penalty.
  - `plan-b`: cache-first and penalty-aware; falls back to the first healthy candidate (or forces override/last).
  - Unknown names auto-fall back to `health-first` and print one `[DNS-BATCH] action=unknown-strategy ...` line.
- `--batch-interval-ms M` / `--batch-jitter-ms J`: interval and jitter (default 0).
- `--stats`: append one summary line at the end (aggregation-friendly). `WHOIS_BATCH_DEBUG_PENALIZE='host1,host2'` can pre-seed penalty windows (debug only).

Examples:

```sh
cat ip_list.txt | whois-x86_64 -B --host apnic
cat queries.txt | whois-x86_64 -B --batch-strategy plan-a --debug --retry-metrics
printf '8.8.8.8\n1.1.1.1\n' | whois-x86_64 -B --no-body --print-meta --stats
```

### Folding example (BusyBox-friendly)

For a grep/awk-based pipeline that mirrors the folded contract (aligned with `func/lzispdata.sh` style):

```sh
... | grep -Ei '^(=== Query:|netname|mnt-|e-mail|=== Authoritative RIR:)' \
  | awk -v count=0 '/^=== Query/ {if (count==0) printf "%s", $3; else printf "\n%s", $3; count++; next} \
      /^=== Authoritative RIR:/ {printf " %s", toupper($4)} \
      (!/^=== Query:/ && !/^=== Authoritative RIR:/) {printf " %s", toupper($2)} END {printf "\n"}'
# Tip: after folding, `$(NF)` is the authoritative RIR (uppercase).
```

## 5. Common examples

```sh
# Single (with auto redirects)
whois-x86_64 8.8.8.8

# Force starting RIR and disable redirects
whois-x86_64 --host apnic -Q 103.89.208.0

# Batch (explicit)
cat ip_list.txt | whois-x86_64 -B --host apnic

# Plain output (no header/tail)
whois-x86_64 -P 8.8.8.8

# Title projection (-g): matched headers plus continuation lines only
# Note: -g is a case-insensitive prefix match, NOT a regex
whois-x86_64 -g "Org|Net|Country" 8.8.8.8

# Block-mode regex (default, case-insensitive) on route/origin/descr headers
whois-x86_64 --grep '^(route|origin|descr):' 1.1.1.1

# Case-sensitive block regex
whois-x86_64 --grep-cs '^(Net(Name|Range)):' 8.8.8.8

# Combine -g and --grep: narrow fields first, then regex
whois-x86_64 -g "Org|Net" --grep 'Google|Mountain[[:space:]]+View' 8.8.8.8

# Line mode: only matched lines (headers/tail retained)
whois-x86_64 --grep 'Google' --grep-line 8.8.8.8

# Line mode + continuation expansion: any hit expands to the whole block
whois-x86_64 -g 'netname|e-mail' --grep 'cmcc' --grep-line --keep-continuation-lines 1.2.3.4

# Folded one-line summary (after -g/--grep*):
#   <query> <UPPER_VALUE_1> <UPPER_VALUE_2> ... <RIR>
whois-x86_64 -g 'netname|mnt-|e-mail' --grep 'CNC|UNICOM' --grep-line --fold 1.2.3.4

# Metadata / chain / pick (batch friendly)
printf '8.8.8.8\n1.1.1.1\n' | whois-x86_64 -B --no-body --print-meta --print-chain --pick netname,country --stats
```

## 6. Exit codes
- `0` (`WC_EXIT_SUCCESS`): success  
  - Single query: lookup pipeline finished successfully; even if the RIR reports "no data" (e.g. `no-such-domain-abcdef.whois-test.invalid`), the client still treats the run as a successful completion and returns 0.  
  - Batch mode: the process exit code reflects whether the batch as a whole ran to completion; individual per-line failures (network/lookup errors, suspicious/private IPs, etc.) are printed to stderr on a per‑query basis, but do not change the process exit code from 0.  
- `1` (`WC_EXIT_FAILURE`): generic failure  
  - CLI usage / parameter errors (e.g. invalid combinations such as `-B` plus a positional query, out‑of‑range numeric flags, missing required arguments) – the client prints an error message and the Usage block once, then exits with 1.  
  - Runtime failures for a single query where the client cannot obtain a valid response (e.g. dial/connect errors after retries, hard DNS failures, internal pipeline errors).  
- `130` (`WC_EXIT_SIGINT`): interrupted by SIGINT (Ctrl‑C)  
  - The client prints `[INFO] Terminated by user (Ctrl-C). Exiting...` to stderr, flushes pending cleanup hooks (including DNS/metrics stats), and then exits with 130. Scripts and tests may rely on this exact value.  

## 7. Tips & troubleshooting
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

### Errno quick reference (connect stage)

- Source: connect failures are obtained via `getsockopt(..., SO_ERROR)`/`errno`. Read-stage timeouts do not increment `[RETRY-ERRORS]` (but they do count as failures in `[RETRY-METRICS]`).
- Architecture variance: `ETIMEDOUT` is `110` on most arches and `145` on MIPS/MIPS64. Behavior matches symbolic constants, not numeric values.
- Tip: prefer `strerror(errno)` for human-readable diagnostics (e.g., "Connection timed out").

| Symbol       | Common value | MIPS/MIPS64 | Meaning                          |
|--------------|--------------|-------------|----------------------------------|
| ETIMEDOUT    | 110          | 145         | connect timeout                  |
| ECONNREFUSED | 111          | 111         | connection refused (closed/fw)   |
| EHOSTUNREACH | 113          | 113         | host unreachable (routing/ACL)   |

### DNS family & resolution notes

Family preference, per-RIR overrides, candidate ordering, negative caching, and fallback toggles are summarized in [§3.7](#37-dns--ip-family-preference); cache-stats and debug tags are covered in [§3.9](#39-diagnostics--security--selftests). Full background is in `docs/RFC-dns-phase2.md`/`docs/RFC-dns-phase4-ip-health.md`.

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
- Recommendation: prefer IPv6; or ensure your egress is a public IPv4 path not subject to blocking. If needed, specify ARIN's IPv6 literal via `--host`, or temporarily pin a starting server / disable redirects to aid troubleshooting. If your network policy allows, you can also use a proxy (`--proxy http://...` or `--proxy socks5://...`, see §3.3) to reach the ISP-blocked WHOIS service on your behalf.

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

### Troubleshooting: rate-limit / access denied

Another common case is the server explicitly rejecting or throttling the request, e.g. `%ERROR:201: access denied` or `rate limit exceeded`. Unlike an empty response, this is a rejection with content, and the client handles it as follows:

- **App-layer bounded retry**: `temporary denied / rate-limit` responses are retried within the same hop, with the count controlled by `--rate-limit-retries N` (default 2, 0..10) and the interval by `--rate-limit-retry-interval-ms M` (default 2500ms). `permanently denied` is never retried.
- **Still failing → non-authoritative redirect**: the client treats the rejection as non-authoritative and keeps searching other RIRs. If no ERX/IANA marker was ever seen and all RIRs are exhausted, authority falls back to `error`; otherwise the first ERX/IANA-marked RIR becomes authoritative.
- **Error line**: a stderr `Error: Query failed for ...` appears only when the final tail is `error @ error`; otherwise no failure line is produced.
- **Diagnostics**: under `--debug`, stderr shows `[RIR-RESP] action=denied|rate-limit ...`; app-layer retry tags are `[APP-RETRY]` (with `--retry-metrics`).
- **What to do**: if one RIR keeps rejecting your current egress (repeated `access denied` in batch/matrix runs): ① raise `--rate-limit-retries`/interval; ② switch that RIR to IPv6 with `--rir-ip-pref <rir>=v6` (if IPv6 is reachable); ③ change egress via `--proxy` (see §3.3); ④ first re-test the single target with `--host <rir> -Q` to confirm whether it is just a transient throttle.

### Selftests (3.2.7)

`--selftest` runs the internal fold/redirect/lookup suite and exits (non-zero on failure). Lookup checks cover the IANA-first hop, single-hop authority, and the empty-response injection path. `--selftest-inject-empty` exercises the injection path (network required); `--selftest-grep`/`--selftest-seclog` need the build-time macros `-DWHOIS_GREP_TEST` / `-DWHOIS_SECLOG_TEST`. DNS-specific labels (`dns-ipv6-only-candidates`, `dns-canonical-fallback`, `dns-fallback-enabled/disabled`) are advisory because they depend on the network. The full flag list is in [§3.9](#39-diagnostics--security--selftests); remote/Golden recipes live in `docs/OPERATIONS_EN.md`.

### Folded output

Use `--no-body` when only stable record boundaries are needed. It suppresses the final WHOIS body while preserving the query header, an applicable `Address Status:` line, and the authoritative tail. DNS, connection, retry, referral, authority resolution, and `-g`/`--grep*` processing still run normally.

```sh
whois-x86_64 --no-body --grep 'NetName' 8.8.8.8
printf '8.8.8.8\n1.1.1.1\n' | whois-x86_64 --no-body
```

`--no-body` may be combined with title/grep filters, body selectors, and batch mode. It fails before lookup when combined with `--plain`, `--fold`, `--fold-sep`, `--fold-unique`, or `--no-fold-upper`.

`--print-meta` appends one TAB-separated `k=v` metadata line per query record: `query=...`, `rir=...`, `status=success|error`, `duration_ms=...`, `attempts=...`, `redirects=...`; headers, body, tail, and exit codes remain unchanged. It combines with `-g`, `--grep*`, `--no-body`, `--fold`, and batch mode; combining it with `--plain` fails before lookup. With `--fold`, a lookup failure emits `<query> ERROR` followed by error metadata; without `--print-meta`, folded-failure behavior is unchanged (stderr only, empty stdout). Metadata values drop leading/trailing whitespace and collapse internal whitespace to one space; backslashes remain literal.

`--print-chain` appends `chain=server1>server2>...` to each query record, preserving the chronological order of logical WHOIS hops (DNS candidates and retries within one hop are not duplicated). Phase C convergence, invalid IP/CIDR, private-address rejection, and security rejection emit `chain=unknown`. At most 16 hops are retained; overflow appends `>truncated`. Chain precedes metadata; it combines with `--no-body`, `--fold`, `--print-meta`, `-g`/`--grep*`, and batch mode, but conflicts with `--plain`.

`--pick <k1,k2,...>` appends one TAB-separated line of selected WHOIS header values per record. The initial allowlist is `netname,country,inetnum,inet6num,origin,route,descr`. Matching is case-insensitive but exact; output preserves first-request order; missing or empty values remain present as `key=`. `--pick-mode first|join` defaults to `first`; `join` merges repeated headers with `|`, after continuation lines have been combined with `; `. Processing order is fixed as title -> grep -> pick -> fold/body. Pick combines with `--no-body`, `--fold`, chain/meta, and batch mode; `--plain` fails before lookup. Each field is capped at 64 KiB, with truncation ending in `...`.

WP-05 common commands:

```sh
# Keep record boundaries and show only the logical WHOIS chain
./whois-x86_64 --no-body --print-chain 8.8.8.8

# Extract fixed fields; missing values remain present as key=
./whois-x86_64 --no-body --pick netname,country,inetnum 8.8.8.8

# Join repeated fields and emit pick, chain, and metadata observations
./whois-x86_64 --no-body --pick descr,country --pick-mode join --print-chain --print-meta 1.1.1.1

# Apply title projection before extraction; filtered-out descr is empty
./whois-x86_64 -g 'NetName|Country' --pick netname,country,descr 8.8.8.8

# Append pick and chain after the folded business line; do not add --no-body
./whois-x86_64 -g 'NetName|Country' --fold --pick netname,country --print-chain 8.8.8.8

# Non-TTY stdin enters batch mode automatically
printf '8.8.8.8\n1.1.1.1\n10.0.0.8\n' |
  ./whois-x86_64 --no-body --pick netname,country --print-chain
```

`--stats` is batch-only (`-B` or non-TTY stdin) and appends one fixed TAB-separated summary line to stdout after every per-query record. Its fields cover total and success/error counts, lookup/rejected/internal error classes, fixed IANA/six-RIR/Verisign/unknown/error/other buckets, and exact nearest-rank p50/p95 latency in milliseconds. An empty batch emits an all-zero line; ordinary per-query failures still allow the batch to continue and enter the error counts. Stats combines with no-body, fold, filters, and pick/chain/meta, while a positional single query or `--plain` fails before lookup. The limit is 1,000,000 effective inputs per batch; overflow, allocation failure, or SIGINT never emits a partial summary.

```sh
# Explicit batch; the stats line follows every metadata line
printf '8.8.8.8\n1.1.1.1\n' |
  ./whois-x86_64 -B --no-body --print-meta --stats

# Non-TTY stdin selects batch mode automatically; stats follows folded records
printf '8.8.8.8\n1.1.1.1\n' |
  ./whois-x86_64 -g 'NetName|Country' --fold --stats
```

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

## 8. Related docs & integration

### Version

The version is injected at build time (prefers `VERSION.txt` in the repo root; generated by the remote build script), defaulting to `3.2.9`.

- 3.2.3: output contract refinement – header/tail include server IPs (DNS failure -> `unknown`); aliases mapped before resolution. Folded output remains `<query> <UPPER_VALUE_...> <RIR>` (no server IP). Added the ARIN connectivity tip (some ISPs block ARIN IPv4 whois on port 43; IPv6 stays reachable).
- 3.2.1: added optional folded output `--fold` with `--fold-sep` and `--no-fold-upper`; docs on continuation-line keyword strategies.
- 3.2.2: nine-area security hardening; added `--security-log` (off by default, rate-limited); removed experimental RDAP switches, keeping classic WHOIS-only behavior.
- 3.2.4: modular baseline (wc_* modules: title/grep/fold/output/seclog); grep selftest hook (compile macro + env), improved block-mode continuation heuristic; `--debug-verbose`, `--selftest`, `--fold-unique`.
- 3.2.5: English-only help (removed bilingual `--lang`, simplified usage output).
- 3.2.6: redirect logic modularized (wc_redirect), unified case-insensitive redirect flags, minimal redirect-target validation, IANA-first policy; version string simplified (no `-dirty` by default; `WHOIS_STRICT_VERSION=1` restores strict behavior).
- 3.2.0: batch mode, headers+RIR tail, non-blocking connect, timeouts, redirects; default retry pacing: interval=300ms, jitter=300ms.

### Build & smoke (ops)

Remote build, smoke, Golden checks, artifact publishing, and cleanup workflows belong to `docs/OPERATIONS_EN.md`; download-link style rules are in `docs/RELEASE_LINK_STYLE.md`. Since v3.2.0 `out/artifacts/` is gitignored and CI attaches binaries to GitHub Releases; local cleanup uses `tools/dev/prune_artifacts.ps1` (`-DryRun` supported).

### Related documentation

- Operations & release guide: `docs/OPERATIONS_EN.md` (Chinese: `docs/OPERATIONS_CN.md`)
- IPv4/IPv6 lookup rules contract: `docs/RFC-ipv4-ipv6-whois-lookup-rules.md`
- DNS design: `docs/RFC-dns-phase2.md`, `docs/RFC-dns-phase4-ip-health.md`
- Proxy access: `docs/RFC-proxy-access.md`
- lzispro integration (batch classification script `release/lzispro/func/lzispdata.sh`): see the lzispro README (environment variables `WHOIS_TITLE_GREP`, `WHOIS_GREP_REGEXP`, `WHOIS_GREP_MODE`, `WHOIS_KEEP_CONT`).
- Release flow: `docs/RELEASE_FLOW_EN.md` | `docs/RELEASE_FLOW_CN.md`

### Current feature status

- Enabled on master: direct connection, HTTP CONNECT proxy (`http://`), SOCKS4/4a/5/5h proxy, conditional output, batch strategies, DNS/IP family controls, diagnostics/selftests (see §3).
- Under development (not enabled): HTTPS proxy (`https://`, WP-13D) — TLS between the client and the proxy with CONNECT on top, mandatory certificate/hostname verification, embedded Mozilla CA trust store; see §9/§14 of `docs/RFC-proxy-access.md`.

