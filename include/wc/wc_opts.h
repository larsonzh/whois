// Options structure parsed from CLI; stable external contract
#ifndef WC_OPTS_H_
#define WC_OPTS_H_

#include <stdio.h>
#include <stdint.h>

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
    int no_redirect;             // -Q disable referral following
    int max_hops;                // -R max referral hops (redirect limit)
    int plain_mode;              // -P suppress query headers
    int debug;                   // -D enable debug prints

    // Timeouts and retries (ms / counts)
    int timeout_sec;             // --timeout seconds
    int retries;                 // --retries
    int retry_interval_ms;       // --retry-interval-ms
    int retry_jitter_ms;         // --retry-jitter-ms
        int retry_all_addrs;        // --retry-all-addrs: apply retries to every resolved address (default: only first)

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

    // DNS / IP family preference & negative cache
    int ipv4_only;               // --ipv4-only (mutually exclusive with ipv6-only/prefer-*)
    int ipv6_only;               // --ipv6-only
    int prefer_ipv4;             // --prefer-ipv4
    int prefer_ipv6;             // --prefer-ipv6 (default ordering if none specified)
    int dns_neg_ttl;             // --dns-neg-ttl <sec> (short TTL for negative cache entries)
    int dns_neg_cache_disable;   // --no-dns-neg-cache

    // DNS resolver controls (Phase 1, CLI-only)
    int dns_addrconfig;          // default 1; --no-dns-addrconfig sets 0
    int dns_retry;               // attempts for getaddrinfo on EAI_AGAIN (default 3)
    int dns_retry_interval_ms;   // sleep between DNS retries (default 100ms)
    int dns_max_candidates;      // cap number of resolved IP candidates to try (default 12)

    // Fallback toggles (keep current behavior by default)
    int no_dns_known_fallback;   // disable known IPv4 fallback
    int no_dns_force_ipv4_fallback; // disable forced-IPv4 fallback
    int no_iana_pivot;           // disable IANA pivot when referral missing

    // DNS cache statistics (Phase 3, diagnostics only)
    int dns_cache_stats;         // --dns-cache-stats: print DNS cache summary at exit
} wc_opts_t;

// Initialize defaults into opts (does not allocate strings).
void wc_opts_init_defaults(wc_opts_t* opts);

// Parse CLI options, populate opts and adjust global modules (title/grep/fold/seclog).
// Returns 0 on success, non-zero on error (usage already printed).
int wc_opts_parse(int argc, char* argv[], wc_opts_t* opts);

// Free any heap allocations inside opts (currently fold_sep if set).
void wc_opts_free(wc_opts_t* opts);

#endif // WC_OPTS_H_
