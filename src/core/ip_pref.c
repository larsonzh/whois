// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <string.h>

#include "wc/wc_ip_pref.h"

static int wc_ip_pref_clamp_hop(int hop_index) {
    return (hop_index < 0) ? 0 : hop_index;
}

int wc_ip_pref_prefers_ipv4_first(wc_ip_pref_mode_t mode, int hop_index) {
    hop_index = wc_ip_pref_clamp_hop(hop_index);
    switch (mode) {
        case WC_IP_PREF_MODE_FORCE_V4_FIRST:
            return 1;
        case WC_IP_PREF_MODE_FORCE_V6_FIRST:
        case WC_IP_PREF_MODE_AUTO_V6_FIRST:
            return 0;
        case WC_IP_PREF_MODE_V4_THEN_V6:
            return (hop_index == 0) ? 1 : 0;
        case WC_IP_PREF_MODE_V6_THEN_V4:
            return (hop_index == 0) ? 0 : 1;
        default:
            return 0;
    }
}

const char* wc_ip_pref_mode_name(wc_ip_pref_mode_t mode) {
    switch (mode) {
        case WC_IP_PREF_MODE_FORCE_V4_FIRST: return "v4-first";
        case WC_IP_PREF_MODE_FORCE_V6_FIRST: return "v6-first";
        case WC_IP_PREF_MODE_V4_THEN_V6: return "v4-then-v6";
        case WC_IP_PREF_MODE_V6_THEN_V4: return "v6-then-v4";
        case WC_IP_PREF_MODE_AUTO_V6_FIRST:
        default:
            return "v6-first";
    }
}

void wc_ip_pref_format_label(wc_ip_pref_mode_t mode, int hop_index, char* buf, size_t buf_len) {
    if (!buf || buf_len == 0) {
        return;
    }
    buf[0] = '\0';
    hop_index = wc_ip_pref_clamp_hop(hop_index);
    const char* base = wc_ip_pref_mode_name(mode);
    if (mode == WC_IP_PREF_MODE_V4_THEN_V6 || mode == WC_IP_PREF_MODE_V6_THEN_V4) {
        snprintf(buf, buf_len, "%s-hop%d", base, hop_index);
    } else {
        snprintf(buf, buf_len, "%s", base);
    }
}
