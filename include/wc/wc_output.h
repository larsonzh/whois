// SPDX-License-Identifier: MIT
#ifndef WC_OUTPUT_H
#define WC_OUTPUT_H

#include <stdio.h>

// Configure global debug toggle used by wc_output_log_message and callers
void wc_output_set_debug_enabled(int enabled);
int wc_output_is_debug_enabled(void);

// Header: plain mode (no via / IP information)
void wc_output_header_plain(const char* query);

// Header: include via host and IP if known
void wc_output_header_via_ip(const char* query,
    const char* via_host,
    const char* via_ip);

// Header: include via host but IP is unknown
void wc_output_header_via_unknown(const char* query,
    const char* via_host);

// Tail: authoritative unknown (no IP section)
void wc_output_tail_unknown_plain(void);

// Tail: authoritative unknown @ unknown
void wc_output_tail_unknown_unknown(void);

// Tail: authoritative with IP (or caller passes "unknown")
void wc_output_tail_authoritative_ip(const char* host,
    const char* ip);

// Generic logging helper implemented in core output module and used
// by multiple core modules (signal handling, query execution,
// cache/backoff, etc.).
void wc_output_log_message(const char* level, const char* format, ...);

#endif // WC_OUTPUT_H
