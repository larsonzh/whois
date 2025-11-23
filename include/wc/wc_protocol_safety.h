// SPDX-License-Identifier: GPL-3.0-or-later
// WHOIS protocol safety helpers.

#ifndef WC_PROTOCOL_SAFETY_H
#define WC_PROTOCOL_SAFETY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Validate raw response bytes for basic sanity (binary/control chars etc.).
int wc_protocol_validate_response_data(const char* data, size_t len);

// Perform structural WHOIS response validation (line length, content, bounds).
int wc_protocol_validate_whois_response(const char* response, size_t len);

// Detect tampering in line endings/null bytes.
int wc_protocol_check_response_integrity(const char* response, size_t len);

// Scan response for suspicious patterns/redirect anomalies.
int wc_protocol_detect_anomalies(const char* response);

// Detect possible query injection/reflection attempts.
int wc_protocol_detect_injection(const char* query, const char* response);

#ifdef __cplusplus
}
#endif

#endif // WC_PROTOCOL_SAFETY_H
