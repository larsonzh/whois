// SPDX-License-Identifier: GPL-3.0-or-later
// Client-side utility helpers for whois CLI layer.
// Focused on small, reusable helpers that are logically tied
// to CLI/config parsing but do not belong to generic wc_util.

#ifndef WC_CLIENT_UTIL_H
#define WC_CLIENT_UTIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Parse human-friendly size strings like "10K", "5M", "2G" into bytes.
// Returns 0 on invalid/empty input, SIZE_MAX on overflow.
// Debug logging is controlled via wc_is_debug_enabled().
size_t wc_client_parse_size_with_unit(const char* str);

// Lightweight domain name syntax validator used by client/cache helpers.
// Returns non-zero if the domain is syntactically valid, 0 otherwise.
int wc_client_is_valid_domain_name(const char* domain);

#ifdef __cplusplus
}
#endif

#endif // WC_CLIENT_UTIL_H
