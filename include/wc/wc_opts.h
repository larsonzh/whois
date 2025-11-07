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

    // Core behavior / I/O
    int batch_mode;              // -B or stdin !TTY auto-detected
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

    // Diagnostics / security
    int security_log;            // --security-log
} wc_opts_t;

// Initialize defaults into opts (does not allocate strings).
void wc_opts_init_defaults(wc_opts_t* opts);

// Parse CLI options, populate opts and adjust global modules (title/grep/fold/seclog).
// Returns 0 on success, non-zero on error (usage already printed).
int wc_opts_parse(int argc, char* argv[], wc_opts_t* opts);

// Free any heap allocations inside opts (currently fold_sep if set).
void wc_opts_free(wc_opts_t* opts);

#endif // WC_OPTS_H_
