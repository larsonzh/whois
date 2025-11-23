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

// Returns non-zero when the string parses as a valid IPv4 or IPv6 literal.
int wc_client_is_valid_ip_address(const char* ip);

// Returns non-zero when the given string is an RFC 1918/4193/ULA/private IP.
int wc_client_is_private_ip(const char* ip);

// Basic sanity checks for DNS responses: rejects invalid/empty literals and
// warns about private ranges. Returns non-zero if the response should be used.
int wc_client_validate_dns_response(const char* ip);

#ifdef __cplusplus
}
#endif

#endif // WC_CLIENT_UTIL_H
