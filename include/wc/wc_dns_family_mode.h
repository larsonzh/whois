// SPDX-License-Identifier: MIT
// wc_dns_family_mode.h - DNS family ordering modes (IPv4/IPv6)
#ifndef WC_DNS_FAMILY_MODE_H_
#define WC_DNS_FAMILY_MODE_H_

typedef enum {
    WC_DNS_FAMILY_MODE_INTERLEAVE_V6_FIRST = 0,
    WC_DNS_FAMILY_MODE_INTERLEAVE_V4_FIRST = 1,
    WC_DNS_FAMILY_MODE_SEQUENTIAL_V4_THEN_V6 = 2,
    WC_DNS_FAMILY_MODE_SEQUENTIAL_V6_THEN_V4 = 3
} wc_dns_family_mode_t;

#endif // WC_DNS_FAMILY_MODE_H_
