// SPDX-License-Identifier: MIT
// wc_ip_pref.h - IPv4/IPv6 preference helpers shared across modules
#ifndef WC_IP_PREF_H_
#define WC_IP_PREF_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WC_IP_PREF_MODE_AUTO_V6_FIRST = 0,
    WC_IP_PREF_MODE_FORCE_V4_FIRST = 1,
    WC_IP_PREF_MODE_FORCE_V6_FIRST = 2,
    WC_IP_PREF_MODE_V4_THEN_V6 = 3,
    WC_IP_PREF_MODE_V6_THEN_V4 = 4
} wc_ip_pref_mode_t;

// Returns 1 when the provided hop should prefer IPv4 before IPv6, 0 otherwise.
int wc_ip_pref_prefers_ipv4_first(wc_ip_pref_mode_t mode, int hop_index);

// Returns a short human-readable label for the mode (without hop suffix).
const char* wc_ip_pref_mode_name(wc_ip_pref_mode_t mode);

// Formats a logging label such as "v4-first" or "v4-then-v6-hop1".
void wc_ip_pref_format_label(wc_ip_pref_mode_t mode, int hop_index, char* buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif // WC_IP_PREF_H_
