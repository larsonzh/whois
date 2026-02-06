// Options structure parsed from CLI; stable external contract
#ifndef WC_OPTS_H_
#define WC_OPTS_H_

#include <stdio.h>
#include <stdint.h>

#include "wc/wc_ip_pref.h"
#include "wc/wc_dns_family_mode.h"

typedef struct wc_opts_s {
    // High level flags (presentation / meta)
    int show_help;               // -H / --help
    int show_version;            // -v / --version
    int show_servers;            // -l / --list
    int show_about;              // --about
    int show_examples;           // --examples

    // Core behavior / I/O
    int batch_mode;              // -B or stdin !TTY auto-detected
    int explicit_batch;          // explicitly requested -B (used for positional arg validation)
    const char* host;            // --host <rir|domain|ip>
    int port;                    // -p <port>
    const char* batch_strategy;  // --batch-strategy <name>
    int batch_interval_ms;       // --batch-interval-ms (sleep between batch queries)
    int batch_jitter_ms;         // --batch-jitter-ms (random jitter added)
    int no_redirect;             // -Q disable referral following
    int max_hops;                // -R max referral hops (redirect limit)
    int plain_mode;              // -P suppress query headers
    int show_non_auth_body;       // --show-non-auth-body (include non-authoritative bodies)
    int show_post_marker_body;    // --show-post-marker-body (keep bodies after ERX/IANA marker)
    int show_failure_body;         // --show-failure-body (keep rate-limit/denied body lines)
    int debug;                   // -D enable debug prints
    int cidr_strip_query;        // --cidr-strip (strip /mask when sending CIDR queries)
    int cidr_fast_v4;            // --cidr-home-v4 (alias: --cidr-fast-v4) IPv4 CIDR two-phase lookup

    // Timeouts and retries (ms / counts)
    int timeout_sec;             // --timeout seconds
    int retries;                 // --retries
    int retry_interval_ms;       // --retry-interval-ms
    int retry_jitter_ms;         // --retry-jitter-ms
    int retry_all_addrs;         // --retry-all-addrs: apply retries to every resolved address (default: only first)
    int pacing_disable;          // --pacing-disable (1 disables pacing)
    int pacing_interval_ms;      // --pacing-interval-ms override
    int pacing_jitter_ms;        // --pacing-jitter-ms override
    int pacing_backoff_factor;   // --pacing-backoff-factor override
    int pacing_max_ms;           // --pacing-max-ms override
    int retry_metrics;           // --retry-metrics flag

    // Caches & buffers
    size_t buffer_size;          // --buffer-size / -b
    int dns_cache_size;          // --dns-cache / -d
    int connection_cache_size;   // --conn-cache / -c
    int cache_timeout;           // --cache-timeout / -T

    // Conditional output engine
    const char* title_pat;       // -g pattern (prefix, case-insensitive)
    const char* grep_pat;        // --grep / --grep-cs pattern
    int grep_case_sensitive;     // 0/1
    int grep_mode_block;         // 0: line, 1: block
    int keep_continuation;       // 0/1 for line mode
    int fold;                    // --fold
    const char* fold_sep;        // --fold-sep (allocated)
    int fold_upper;              // default 1; --no-fold-upper sets 0
    int fold_unique;             // --fold-unique (remove duplicate tokens)

    // Diagnostics / security
    int security_log;            // --security-log
    int debug_verbose;           // --debug-verbose
    int show_selftest;           // --selftest

    // Selftest / fault injection toggles
    int selftest_fail_first;         // --selftest-fail-first-attempt
    int selftest_inject_empty;       // --selftest-inject-empty
    int selftest_grep;               // --selftest-grep (requires build flag)
    int selftest_seclog;             // --selftest-seclog (requires build flag)
    int selftest_workbuf;            // --selftest-workbuf (stress long/CRLF/continuation paths)
    int selftest_dns_negative;       // --selftest-dns-negative
    int selftest_blackhole_iana;     // --selftest-blackhole-iana
    int selftest_blackhole_arin;     // --selftest-blackhole-arin
    int selftest_force_iana_pivot;   // --selftest-force-iana-pivot
    const char* selftest_force_suspicious; // --selftest-force-suspicious <query|*>
    const char* selftest_force_private;    // --selftest-force-private <query|*>
    int selftest_registry;           // --selftest-registry (batch strategy registry harness)

    // DNS / IP family preference & negative cache
    int ipv4_only;               // --ipv4-only (mutually exclusive with ipv6-only/prefer-*)
    int ipv6_only;               // --ipv6-only
    int prefer_ipv4;             // --prefer-ipv4
    int prefer_ipv6;             // --prefer-ipv6 (default ordering if none specified)
    wc_ip_pref_mode_t ip_pref_mode; // hop-aware preference selection
    wc_rir_ip_pref_t rir_pref_iana;     // --rir-ip-pref iana=v4|v6
    wc_rir_ip_pref_t rir_pref_arin;     // --rir-ip-pref arin=v4|v6
    wc_rir_ip_pref_t rir_pref_ripe;     // --rir-ip-pref ripe=v4|v6
    wc_rir_ip_pref_t rir_pref_apnic;    // --rir-ip-pref apnic=v4|v6
    wc_rir_ip_pref_t rir_pref_lacnic;   // --rir-ip-pref lacnic=v4|v6
    wc_rir_ip_pref_t rir_pref_afrinic;  // --rir-ip-pref afrinic=v4|v6
    wc_rir_ip_pref_t rir_pref_verisign; // --rir-ip-pref verisign=v4|v6
    wc_dns_family_mode_t dns_family_mode; // DNS candidate ordering mode (global default)
    wc_dns_family_mode_t dns_family_mode_first; // Optional override for first hop
    wc_dns_family_mode_t dns_family_mode_next;  // Optional override for 2nd+ hops
    int dns_family_mode_first_set; // 1 when CLI or preference sets first-hop mode explicitly
    int dns_family_mode_next_set;  // 1 when CLI or preference sets 2nd+ hop mode explicitly
    int dns_family_mode_set;       // 1 when global family mode explicitly set via CLI or preference
    int dns_neg_ttl;             // --dns-neg-ttl <sec> (short TTL for negative cache entries)
    int dns_neg_cache_disable;   // --no-dns-neg-cache

    // DNS resolver controls (Phase 1, CLI-only)
    int dns_addrconfig;          // default 1; --no-dns-addrconfig sets 0
    int dns_retry;               // attempts for getaddrinfo on EAI_AGAIN (default 3)
    int dns_retry_interval_ms;   // sleep between DNS retries (default 100ms)
    int dns_max_candidates;      // cap number of resolved IP candidates to try (default 12)
    int max_host_addrs;          // cap number of per-host resolved addresses to attempt (0=unbounded)
    int dns_backoff_window_ms;   // --dns-backoff-window-ms (0 = disable window)
    int dns_append_known_ips;    // --dns-append-known-ips

    // Fallback toggles (keep current behavior by default)
    int no_dns_known_fallback;   // disable known IPv4 fallback
    int no_dns_force_ipv4_fallback; // disable forced-IPv4 fallback
    int no_iana_pivot;           // disable IANA pivot when referral missing

    // DNS cache statistics (Phase 3, diagnostics only)
    int dns_cache_stats;         // --dns-cache-stats: print DNS cache summary at exit

    // Cache counter sampling (opt-in for non-debug runs)
    int cache_counter_sampling;  // --cache-counter-sampling

    // DNS strategy debug switch (Phase 2 D)
    int dns_no_fallback;         // --dns-no-fallback: disable extra DNS fallback paths (forced IPv4 / known IPv4)
} wc_opts_t;

// Initialize defaults into opts (does not allocate strings).
void wc_opts_init_defaults(wc_opts_t* opts);

// Parse CLI options, populate opts and adjust global modules (title/grep/fold/seclog).
// Returns 0 on success, non-zero on error (usage already printed).
int wc_opts_parse(int argc, char* argv[], wc_opts_t* opts);

// Free any heap allocations inside opts (currently fold_sep if set).
void wc_opts_free(wc_opts_t* opts);

#endif // WC_OPTS_H_
