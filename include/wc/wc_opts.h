// Options structure parsed from CLI; stable external contract
#ifndef WC_OPTS_H_
#define WC_OPTS_H_

#include <stdio.h>
#include <stdint.h>

typedef struct wc_opts_s {
    // I/O and behavior
    int batch_mode;              // -B or stdin !TTY
    const char* host;            // --host <rir|domain|ip>
    int no_redirect;             // -Q disable referral following
    int max_hops;                // -R max referral hops

    // Timeouts and retries (ms / counts)
    int timeout_sec;             // --timeout seconds
    int retries;                 // --retries
    int retry_interval_ms;       // --retry-interval-ms
    int retry_jitter_ms;         // --retry-jitter-ms

    // Conditional output engine
    const char* title_pat;       // -g pattern (prefix, case-insensitive)
    const char* grep_pat;        // --grep / --grep-cs pattern
    int grep_case_sensitive;     // 0/1
    int grep_mode_block;         // 0: line, 1: block
    int keep_continuation;       // 0/1 for line mode
    int fold;                    // --fold
    const char* fold_sep;        // --fold-sep
    int fold_upper;              // default 1; --no-fold-upper sets 0

    // Diagnostics
    int security_log;            // --security-log (stderr, rate-limited)
} wc_opts_t;

#endif // WC_OPTS_H_
