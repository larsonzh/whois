// SPDX-License-Identifier: MIT
#ifndef WC_OUTPUT_H
#define WC_OUTPUT_H

#include <stdio.h>

// Output contract helpers (no state; callers handle mode conditions)

// Header: basic
static inline void wc_output_header_plain(const char* query) {
    printf("=== Query: %s ===\n", query);
}

// Header: via X @ unknown
static inline void wc_output_header_via_unknown(const char* query, const char* via) {
    printf("=== Query: %s via %s @ unknown ===\n", query, via);
}

// Header: via X @ IP
static inline void wc_output_header_via_ip(const char* query, const char* via, const char* ip) {
    printf("=== Query: %s via %s @ %s ===\n", query, via, ip);
}

// Tail: authoritative with IP (or caller passes "unknown")
static inline void wc_output_tail_authoritative_ip(const char* name, const char* ip) {
    printf("=== Authoritative RIR: %s @ %s ===\n", name, ip);
}

// Tail: authoritative unknown (no IP section)
static inline void wc_output_tail_unknown_plain(void) {
    printf("=== Authoritative RIR: unknown ===\n");
}

// Tail: authoritative unknown @ unknown
static inline void wc_output_tail_unknown_unknown(void) {
    printf("=== Authoritative RIR: unknown @ unknown ===\n");
}

#endif // WC_OUTPUT_H
