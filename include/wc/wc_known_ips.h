// SPDX-License-Identifier: MIT
#ifndef WC_KNOWN_IPS_H
#define WC_KNOWN_IPS_H

#include <stddef.h>

typedef struct {
    const char* ip;
    const char* host;
} wc_known_ip_entry_t;

// Central list of known WHOIS server IPs mapped to canonical hosts.
// Keep this list in sync when operators update server endpoints.
static const wc_known_ip_entry_t k_wc_known_ips[] = {
    // ARIN
    {"199.5.26.46", "whois.arin.net"},
    {"199.71.0.46", "whois.arin.net"},
    {"199.212.0.46", "whois.arin.net"},
    {"199.91.0.46", "whois.arin.net"},
    {"2001:500:13::46", "whois.arin.net"},
    {"2001:500:a9::46", "whois.arin.net"},
    {"2001:500:31::46", "whois.arin.net"},
    // APNIC
    {"203.119.102.24", "whois.apnic.net"},
    {"2001:dd8:8:701::24", "whois.apnic.net"},
    {"203.119.102.29", "whois.apnic.net"},
    {"2001:dd8:8:701::29", "whois.apnic.net"},
    {"203.119.0.147", "whois.apnic.net"},
    {"2001:dc0:c003::147", "whois.apnic.net"},
    {"202.12.28.136", "whois.apnic.net"},
    {"2001:dc0:1:0:4777::136", "whois.apnic.net"},
    {"207.148.30.186", "whois.apnic.net"},
    {"2001:19f0:5:3a2:5400:5ff:fe36:e789", "whois.apnic.net"},
    {"136.244.64.117", "whois.apnic.net"},
    {"2001:19f0:7401:8fd4:5400:5ff:fe35:cb0a", "whois.apnic.net"},
    // RIPE
    {"193.0.6.135", "whois.ripe.net"},
    {"2001:67c:2e8:22::c100:687", "whois.ripe.net"},
    // LACNIC
    {"190.112.52.16", "whois.lacnic.net"},
    {"2001:13c7:7020:210::16", "whois.lacnic.net"},
    {"200.3.14.137", "whois.lacnic.net"},
    {"2001:13c7:7002:4128::137", "whois.lacnic.net"},
    {"200.3.14.138", "whois.lacnic.net"},
    {"2001:13c7:7002:4128::138", "whois.lacnic.net"},
    {"200.3.14.139", "whois.lacnic.net"},
    {"2001:13c7:7002:4128::139", "whois.lacnic.net"},
    {"200.3.14.149", "whois.lacnic.net"},
    {"2001:13c7:7002:4128::149", "whois.lacnic.net"},
    {"200.3.14.150", "whois.lacnic.net"},
    {"2001:13c7:7002:4128::150", "whois.lacnic.net"},
    {"200.3.14.151", "whois.lacnic.net"},
    {"2001:13c7:7002:4128::151", "whois.lacnic.net"},
    {"168.121.184.15", "whois.lacnic.net"},
    {"2001:13c7:7001:110::15", "whois.lacnic.net"},
    {"168.121.184.16", "whois.lacnic.net"},
    {"2001:13c7:7001:110::16", "whois.lacnic.net"},
    {"168.121.184.28", "whois.lacnic.net"},
    {"2001:13c7:7001:110::28", "whois.lacnic.net"},
    {"168.121.184.41", "whois.lacnic.net"},
    {"2001:13c7:7001:110::41", "whois.lacnic.net"},
    // AFRINIC
    {"196.192.115.21", "whois.afrinic.net"},
    {"2001:42d0:2:601::21", "whois.afrinic.net"},
    {"196.192.115.22", "whois.afrinic.net"},
    {"2001:42d0:2:601::22", "whois.afrinic.net"},
    {"196.216.2.20", "whois.afrinic.net"},
    {"2001:42d0:0:201::20", "whois.afrinic.net"},
    {"196.216.2.21", "whois.afrinic.net"},
    {"2001:42d0:0:201::21", "whois.afrinic.net"},
    // IANA
    {"192.0.32.59", "whois.iana.org"},
    {"2620:0:2d0:200::59", "whois.iana.org"},
    {"192.0.47.59", "whois.iana.org"},
    {"2620:0:2830:200::59", "whois.iana.org"},
    // VERISIGN
    {"192.30.45.30", "whois.verisign-grs.com"},
    {"192.34.234.30", "whois.verisign-grs.com"},
    {"2620:74:20::30", "whois.verisign-grs.com"},
    {"2620:74:21::30", "whois.verisign-grs.com"},
};

static inline size_t wc_known_ip_count(void) {
    return sizeof(k_wc_known_ips) / sizeof(k_wc_known_ips[0]);
}

#endif // WC_KNOWN_IPS_H
