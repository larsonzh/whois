// meta.c - Help/Version/Usage metadata utilities for whois client
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wc/wc_meta.h"

#ifndef WHOIS_VERSION
#define WHOIS_VERSION "3.2.9"
#endif

static void print_common_header(const char* program_name) {
    printf("Usage: %s [OPTIONS] <IP or domain>\n\n", program_name ? program_name : "whois");
    printf("Lightweight static whois client: redirects follow, title projection, regex filtering, fold output.\n\n");
}

void wc_meta_print_usage(
    const char* program_name,
    int default_port,
    size_t default_buffer,
    int default_retries,
    int default_timeout_sec,
    int default_retry_interval_ms,
    int default_retry_jitter_ms,
    int default_max_redirects,
    int default_dns_cache_size,
    int default_connection_cache_size,
    int default_cache_timeout,
    int default_debug)
{
    (void)default_debug; // reserved for future conditional help verbosity
    print_common_header(program_name);
    printf("Core options:\n");
    printf("  -H, --help                Show this help message and exit\n");
    printf("  -v, --version             Show version and exit\n");
    printf("  -l, --list                List known RIR servers\n");
    printf("      --about               Show detailed information about features and modules\n");
    printf("      --examples            Show extended examples\n");
    printf("  -B, --batch               Batch mode: read queries from stdin (one per line)\n");
    printf("  -h, --host HOST           Start from specific whois server (name|domain|ip)\n");
    printf("  -p, --port PORT           Whois server port (default: %d)\n", default_port);
    printf("  -Q, --no-redirect         Do not follow referrals (default: follow up to %d)\n", default_max_redirects);
    printf("  -R, --max-hops N          Max referral hops (default: %d)\n", default_max_redirects);
    printf("  -P, --plain               Suppress header/tail lines (plain body only)\n");
    printf("  -D, --debug               Enable debug prints\n\n");

    printf("Timeouts & retries:\n");
    printf("      --timeout SEC         Socket timeout seconds (default: %d)\n", default_timeout_sec);
    printf("      --retries N           Retry count on transient errors (default: %d)\n", default_retries);
    printf("      --retry-all-addrs     Apply retries to every resolved IP (default: only first)\n");
    printf("      --retry-interval-ms M Base interval between retries in ms (default: %d)\n", default_retry_interval_ms);
    printf("      --retry-jitter-ms J   Additional random jitter in ms (default: %d)\n\n", default_retry_jitter_ms);

    printf("Connect retry pacing (ON by default; CLI-only):\n");
    printf("      --pacing-disable           Turn pacing off (not recommended)\n");
    printf("      --pacing-interval-ms M     Base wait between retries in ms (default: 60)\n");
    printf("      --pacing-jitter-ms J       Add random 0..J ms to each wait (default: 40)\n");
    printf("      --pacing-backoff-factor N  Multiply wait each retry (default: 2)\n");
    printf("      --pacing-max-ms C          Cap any single wait in ms (default: 400)\n\n");

    printf("Buffers & caches:\n");
    printf("  -b, --buffer-size BYTES   Response buffer size (default: %zu)\n", default_buffer);
    printf("  -d, --dns-cache N         DNS cache entries (default: %d)\n", default_dns_cache_size);
    printf("  -c, --conn-cache N        Connection cache entries (default: %d)\n", default_connection_cache_size);
    printf("  -T, --cache-timeout SEC   Cache TTL seconds (default: %d)\n\n", default_cache_timeout);
    printf("DNS/IP family preference:\n");
    printf("      --ipv4-only              Force IPv4 only resolution / dialing\n");
    printf("      --ipv6-only              Force IPv6 only resolution / dialing\n");
    printf("      --prefer-ipv4            Prefer IPv4 first then IPv6 (default: prefer IPv6)\n");
    printf("      --prefer-ipv6            Prefer IPv6 first then IPv4\n");
    printf("      --dns-neg-ttl SEC        Negative DNS cache TTL (default: 10)\n");
    printf("      --no-dns-neg-cache       Disable negative DNS caching\n");
    printf("      --no-dns-addrconfig      Turn off OS 'usable-on-this-host' filter (AI_ADDRCONFIG); normally keep enabled\n");
    printf("      --dns-retry N            DNS resolve retry attempts on EAI_AGAIN (default: 3)\n");
    printf("      --dns-retry-interval-ms M  Sleep between DNS retries in ms (default: 100)\n");
    printf("      --dns-max-candidates N   Cap number of resolved IPs to try (default: 12)\n");
    printf("      --no-known-ip-fallback   Disable known-IPv4 fallback when connect anomalies occur\n");
    printf("      --no-force-ipv4-fallback Disable forced-IPv4 fallback when empty-body/connect anomalies occur\n");
    printf("      --no-iana-pivot          Disable IANA pivot when referral is missing\n");
    printf("      --dns-no-fallback        Disable extra DNS fallback layers (forced IPv4 / known IPv4) for debugging\n\n");

    printf("Conditional output engine:\n");
    printf("  -g, --title PATTERN       Project selected headers (POSIX ERE, case-insensitive)\n");
    printf("      --grep REGEX          Filter lines or blocks by regex (case-insensitive)\n");
    printf("      --grep-cs REGEX       Case-sensitive grep\n");
    printf("      --grep-line           Line mode (default)\n");
    printf("      --grep-block          Block mode\n");
    printf("      --keep-cont           Keep continuation lines in line mode\n");
    printf("      --fold                Fold output: single line per query with selected fields\n");
    printf("      --fold-sep STR        Separator for folded output (default: space)\n");
    printf("      --no-fold-upper       Preserve original case in folded output (default: upper)\n");
    printf("      --fold-unique         De-duplicate tokens in folded output\n\n");

    printf("Diagnostics/Security:\n");
    printf("      --retry-metrics       Print retry stats to stderr (debug only; no behavior change)\n");
    printf("      --dns-cache-stats     Emit one DNS cache summary line to stderr at exit (diagnostics only)\n");
    printf("      --security-log        Enable security event logging to stderr\n");
    printf("      --debug-verbose       Extra verbose debug (cache/redirect instrumentation)\n");
    printf("      --selftest            Run internal self-tests and exit\n");
    printf("      --selftest-fail-first-attempt  Force first attempt to fail once (A/B pacing)\n");
    printf("      --selftest-inject-empty        Trigger empty-response injection path (lookup test)\n");
    printf("      --selftest-grep / --selftest-seclog  Extra selftests (require -DWHOIS_GREP_TEST / -DWHOIS_SECLOG_TEST)\n\n");
    printf("      --selftest-dns-negative       Simulate negative-DNS scenario for testing cache behavior\n");
    printf("      --selftest-blackhole-iana     Force IANA hop to connect to TEST-NET (simulate connect failure)\n");
    printf("      --selftest-blackhole-arin     Force ARIN hop to connect to TEST-NET (simulate connect failure)\n");
    printf("      --selftest-force-iana-pivot   Force using IANA as pivot even if referral exists (for 3-hop test)\n\n");

    printf("Examples:\n");
    printf("  %s --host apnic 103.89.208.0\n", program_name ? program_name : "whois");
    printf("  printf \"8.8.8.8\\n1.1.1.1\\n\" | %s -B -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold\n",
        program_name ? program_name : "whois");
    printf("  %s --examples   # show more\n\n", program_name ? program_name : "whois");
}

void wc_meta_print_version(void) {
    printf("whois client %s by larsonzh\n", WHOIS_VERSION);
}

const char* wc_meta_version_string(void) {
    return WHOIS_VERSION;
}

void wc_meta_print_about(void) {
    printf("whois client %s by larsonzh - features & modules\n\n", WHOIS_VERSION);
    printf("Core features:\n");
    printf("- Smart redirects with loop guard; non-blocking connect, timeouts, and light retries.\n");
    printf("- Stable header/tail output contract for BusyBox pipelines.\n");
    printf("- Conditional output engine: -g title projection → --grep line/block → --fold.\n\n");
    printf("Modules:\n");
    printf("- wc_title: header projection and normalization.\n");
    printf("- wc_grep: POSIX ERE filtering (line/block, continuation handling).\n");
    printf("- wc_fold: folded single-line summary builder.\n");
    printf("- wc_output: header/tail formatting helpers.\n");
    printf("- wc_seclog: optional security event logging.\n");
    printf("- wc_opts: CLI parsing and feature wiring.\n");
    printf("- wc_meta: help/version/about/examples.\n\n");
    printf("Notes:\n");
    printf("- Batch mode: explicit -B or implicit when stdin is not a TTY and no positional query given.\n");
    printf("- Private IP is reported as such and marks authoritative as unknown.\n");
    printf("- Connect-level retry pacing: default-on (interval=60, jitter=40, backoff=2, max=400).\n");
    printf("  Configure via CLI only: --pacing-* flags; disable with --pacing-disable.\n");
    printf("  Use --retry-metrics for diagnostics only; it prints [RETRY-METRICS*] to stderr.\n");
    printf("- DNS family preference flags: --ipv4-only / --ipv6-only / --prefer-ipv4 / --prefer-ipv6 (default).\n");
    printf("- Negative DNS cache: short TTL for name resolution failures (default 10s, disable with --no-dns-neg-cache).\n");
}

void wc_meta_print_examples(const char* program_name) {
    const char* prog = program_name ? program_name : "whois";
    printf("Extended examples (copy & try):\n\n");
    printf("# Single query with redirects\n");
    printf("%s 8.8.8.8\n\n", prog);
    printf("# Disable redirects and force APNIC\n");
    printf("%s --host apnic -Q 103.89.208.0\n\n", prog);
    printf("# Batch from stdin (explicit)\n");
    printf("printf \"8.8.8.8\\n1.1.1.1\\n\" | %s -B --host apnic\n\n", prog);
    printf("# Title projection + grep + fold\n");
    printf("%s -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold 8.8.8.8\n\n", prog);
    printf("# Verbose debug (stderr): extra redirect/cache traces\n");
    printf("%s --debug-verbose 8.8.8.8\n\n", prog);
    printf("# Block mode grep on route/origin/descr\n");
    printf("%s --grep '^(route|origin|descr):' 1.1.1.1\n\n", prog);
    printf("# Preserve case in folded output\n");
    printf("%s --fold --fold-sep , --no-fold-upper 8.8.8.8\n\n", prog);
}
